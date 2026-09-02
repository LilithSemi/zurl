//! The SSH transport layer, RFC 4253. One connection, from the
//! identification string to a stream of authenticated packets.
//!
//! **This is the bottom layer and nothing above it is here.** There is no
//! authentication, no channel, and no SFTP in this package. A caller sends
//! and reads payloads, and the first byte of each payload is the message
//! number of whatever layer sits on top. `zurl_ssh` registers no url
//! scheme, so nothing in this package is reachable from the command line
//! yet.
//!
//! What one `Transport` does:
//!
//! - Writes `SSH-2.0-` and reads the peer's line, past any notice it
//!   writes first.
//! - Runs `SSH_MSG_KEXINIT`, `curve25519-sha256`, and `SSH_MSG_NEWKEYS`.
//! - Verifies the server's `ssh-ed25519` signature over the exchange
//!   hash, and then **asks the caller's `Verifier` whether that key
//!   belongs to the host**.
//! - Frames, seals, and opens every packet after that.
//! - Answers `SSH_MSG_IGNORE`, `SSH_MSG_DEBUG`, `SSH_MSG_UNIMPLEMENTED`,
//!   and `SSH_MSG_EXT_INFO` itself, and reports `SSH_MSG_DISCONNECT` as a
//!   named fault.
//! - Runs a new key exchange when the byte count or the clock says so, and
//!   when the server asks for one.
//!
//! **Every byte after the identification string is attacker-controlled.**
//! The bounds are:
//!
//! | what | bound |
//! | --- | --- |
//! | one banner line | `version.max_line_bytes`, 255 |
//! | lines before the identification | `version.max_preamble_lines`, 64 |
//! | bytes before the identification | `version.max_preamble_bytes`, 8192 |
//! | one packet | `Options.max_packet_bytes`, 256 KiB |
//! | the server `KEXINIT` | `max_server_kexinit_bytes`, 8192 |
//! | the host key blob | `max_host_key_bytes`, 1024 |
//! | idle packets in a row | `max_idle_run` |
//! | payloads held across a rekey | `Options.max_packet_bytes` |
//! | a wait with no byte arriving | `Options.stall` |
//! | the rate of the whole connection | `Options.low_speed_limit` |
//!
//! ## CVE-2023-48795, and what this build does about it
//!
//! **No packet may be dropped while the traffic is in the clear.** RFC
//! 4253 section 11 lets a peer send `SSH_MSG_IGNORE` at any time, and
//! OpenSSH's strict key exchange forbids one inside a key exchange. This
//! build applies that rule to every server for the whole of the first key
//! exchange, whether or not the server named the marker:
//!
//! - the first packet a server sends must be `SSH_MSG_KEXINIT`
//!   (`readServerKexinit`), and
//! - `SSH_MSG_IGNORE`, `SSH_MSG_DEBUG`, and `SSH_MSG_UNIMPLEMENTED` are
//!   `error.StrictKexViolation` until the first `SSH_MSG_NEWKEYS`
//!   (`housekeepingIsViolation`).
//!
//! Together those close the injection window: an attacker between the two
//! sides cannot make this side count a packet it then drops, so the
//! attacker cannot delete a packet from the front of the session and keep
//! the sequence numbers lined up.
//!
//! **The sequence numbers go back to zero only when the server agreed to
//! the marker.** A reset this side made on its own would part company with
//! a server that kept counting, and the very next packet would fail its
//! tag.
//!
//! The other half of the answer is in `zurl_ssh.algorithms`: this build
//! offers `aes256-gcm@openssh.com` before
//! `chacha20-poly1305@openssh.com`, and the attack does not work against
//! AES-GCM.
//!
//! **A `Transport` must not move once it is running.** Every payload a
//! caller reads points into a buffer this value owns.

const Transport = @This();

const std = @import("std");
const zurl_net = @import("zurl-net");

const algorithms = @import("algorithms.zig");
const cipher = @import("cipher.zig");
const hostkey = @import("hostkey.zig");
const kex = @import("kex.zig");
const messages = @import("messages.zig");
const packet = @import("packet.zig");
const version = @import("version.zig");
const wire = @import("wire.zig");

const Io = std.Io;
const X25519 = std.crypto.dh.X25519;

/// The bound on a server's own `SSH_MSG_KEXINIT`.
///
/// A `KEXINIT` is ten name-lists. OpenSSH writes well under a kilobyte,
/// and this build has to keep the whole payload until the exchange hash
/// is built, so the bound is on a buffer this value owns.
pub const max_server_kexinit_bytes = 8192;

/// The bound on a host key blob.
///
/// An `ssh-ed25519` blob is 51 bytes. The bound is generous so that a
/// server which one day offers a larger key still gets a named refusal.
pub const max_host_key_bytes = 1024;

/// How many bytes one backlog entry costs past the payload it holds.
///
/// The four bytes are the length in front of it. See `backlog`.
pub const backlog_entry_head = 4;

/// The backlog room a run of `count` payloads of `payload_bytes` each
/// needs.
///
/// **A caller of the layer above sizes the backlog with this**, so that
/// the two numbers cannot drift apart. `zurl_ssh.Channel` calls it at
/// comptime for its own window and message size. See
/// `default_backlog_bytes`.
pub fn backlogBytesFor(count: usize, payload_bytes: usize) usize {
    return count * (backlog_entry_head + payload_bytes);
}

/// How many bytes of caller payload one key exchange may collect.
///
/// **A packet is the wrong unit here and a window is the right one.** A
/// key exchange this side starts must hold every payload the peer had
/// already sent, and a peer with a full channel receive window in flight
/// has sent a window and not a packet. 320 KiB holds one default
/// `zurl_ssh.Channel` window, which is 256 KiB carried in messages of
/// 32768 bytes, with the entry head and the channel message head on each
/// one. `Channel` checks the relationship at comptime and at `init`, so a
/// window that grows past this room is a named refusal and never a
/// transfer that dies at the first rekey.
pub const default_backlog_bytes: usize = 320 * 1024;

/// How many packets in a row may carry nothing a caller asked for.
///
/// `SSH_MSG_IGNORE` costs the peer one packet and this process one loop.
/// A peer that sends nothing else is not making progress, and a reader
/// with no bound would loop for as long as the peer keeps writing.
pub const max_idle_run = 256;

/// The software name in this build's identification string.
///
/// RFC 4253 section 4.2 forbids a space and a minus sign in this field.
pub const default_software = "zurl";

/// What one transport needs.
pub const Options = struct {
    /// The host and the port, as the caller named them. The `Verifier`
    /// gets both.
    peer: hostkey.Peer,
    /// **The trust decision, and it has no default.** A caller must write
    /// one. See `zurl_ssh.hostkey.Verifier` for why this package ships no
    /// "accept anything" value.
    verifier: hostkey.Verifier,
    /// The name in the identification string.
    software: []const u8 = default_software,
    /// The bound on one packet, in either direction.
    max_packet_bytes: u32 = packet.max_packet_bytes,
    /// The room for the payloads one key exchange collects. See
    /// `default_backlog_bytes`.
    backlog_bytes: usize = default_backlog_bytes,
    /// How long one read may wait with no byte arriving.
    stall: Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(120), .clock = .awake } },
    /// The slowest acceptable rate, in bytes each second, with both
    /// directions counted. Zero turns the rate rule off. This is curl's
    /// `--speed-limit`.
    ///
    /// **This is a different bound from `stall` and it catches a
    /// different peer.** `stall` says how long one read may wait with no
    /// byte arriving, and it starts again at every byte. A peer that
    /// writes one byte just before each wait runs out therefore passes
    /// `stall` forever. See `rateDeadline`.
    low_speed_limit: u64 = 0,
    /// How long the rate may stay under `low_speed_limit`, in seconds.
    /// Zero turns the rate rule off. This is curl's `--speed-time`.
    low_speed_time_s: u32 = 0,
    /// How many bytes may pass, both directions counted, before a new key
    /// exchange. OpenSSH's own default is the same 1 GiB.
    rekey_bytes: u64 = 1 << 30,
    /// How many seconds may pass before a new key exchange. OpenSSH's
    /// default is one hour.
    rekey_seconds: u32 = 3600,
};

/// Why a transport could not start.
pub const InitError = error{
    /// The process has no room for the packet buffers.
    OutOfMemory,
    /// `max_packet_bytes` is under the smallest packet the protocol has,
    /// or over what this build frames. A caller's own bug.
    PacketBoundInvalid,
};

/// Why the identification exchange or a key exchange stopped.
pub const KexError =
    version.ReadError ||
    version.BuildError ||
    algorithms.ParseError ||
    algorithms.NegotiateError ||
    kex.ParseError ||
    kex.SharedSecretError ||
    hostkey.VerifyError ||
    hostkey.TrustError ||
    ReadError ||
    WriteError ||
    error{
        /// The server's first packet was not `SSH_MSG_KEXINIT`. See the
        /// module comment.
        KexinitExpected,
        /// The server's `SSH_MSG_KEXINIT` is larger than
        /// `max_server_kexinit_bytes`.
        KexinitTooLong,
        /// The host key blob is larger than `max_host_key_bytes`.
        HostKeyTooLong,
        /// A packet arrived during the key exchange that does not belong
        /// there.
        KexMessageUnexpected,
        /// The peer sent a message that this build refuses inside a key
        /// exchange. See `housekeepingIsViolation`.
        StrictKexViolation,
        /// The ephemeral key pair could not be drawn. The entropy source
        /// gave a seed no key could be built from, again and again.
        EphemeralKeyFailed,
    };

/// Why a write stopped.
pub const WriteError = Io.Writer.Error || Io.RandomSecureError || error{
    /// The payload does not fit `max_packet_bytes`.
    PayloadTooLong,
};

/// Why a read stopped.
pub const ReadError = zurl_net.bounded.ExactError ||
    packet.FrameError ||
    cipher.AuthError ||
    error{
        /// A packet carried no payload at all, so it names no message.
        EmptyPacket,
        /// The peer sent `SSH_MSG_DISCONNECT`. `lastDisconnect` says why.
        PeerDisconnected,
        /// `max_idle_run` packets in a row carried nothing a caller asked
        /// for.
        TooManyIdlePackets,
        /// A key exchange collected more bytes of caller payload than the
        /// backlog holds. See `backlog`.
        RekeyBacklogFull,
        /// The connection stayed under `Options.low_speed_limit` for
        /// `Options.low_speed_time_s`. See `rateDeadline`.
        TransferTooSlow,
    };

/// Why `receive` stopped.
///
/// A read can start a key exchange, because a server may ask for one at
/// any time, so every key exchange fault is reachable from here.
pub const ReceiveError = ReadError || KexError;

/// Why `send` stopped.
pub const SendError = WriteError || KexError;

/// How many packets of each kind the peer sent that no caller asked for.
///
/// **Recovery is never silent.** Each of these messages is dropped on
/// purpose, and each one is counted here so that a caller can see it
/// happened.
pub const Counters = struct {
    ignore: u64 = 0,
    debug: u64 = 0,
    unimplemented: u64 = 0,
    ext_info: u64 = 0,
    /// How many key exchanges have finished, the first one counted.
    key_exchanges: u64 = 0,
    /// How many times a goodbye could not be written. `disconnect` is the
    /// one caller, and this is where its recovery is visible.
    disconnect_write_failed: u64 = 0,
};

/// What a peer said when it ended the connection.
pub const Disconnect = struct {
    reason: messages.DisconnectReason,
    /// The peer's own words, cut to fit. **Untrusted text**: it can hold
    /// any byte, and a caller that shows it to a person must make it safe
    /// first.
    description: []const u8,
};

/// How many bytes of a peer's disconnect message this keeps.
pub const max_disconnect_description_bytes = 256;

gpa: std.mem.Allocator,
io: Io,
channel: zurl_net.line.Channel,
options: Options,

/// Holds one packet as it is built. Owned.
send_frame: []u8,
/// Holds one packet as it arrives. Owned.
recv_frame: []u8,

/// The payloads a key exchange read and a caller has not taken yet.
/// Owned.
///
/// **A rekey does not stop the peer writing.** RFC 4253 section 9 says a
/// side that starts a key exchange may still receive the packets the
/// other side had already sent, and those packets belong to the caller.
/// They cannot be handed over from inside a rekey, because the caller is
/// in the middle of a `send`, so they wait here and the next `receive`
/// takes them, in order.
///
/// The form is a run of entries, each a 32-bit length and then the
/// payload. The buffer is the whole bound: a peer that writes more than
/// this while a key exchange runs is `error.RekeyBacklogFull`.
backlog: []u8,
/// How many bytes of `backlog` hold entries.
backlog_len: usize,
/// Where the next entry to hand out starts.
backlog_at: usize,

send_cipher: ?cipher.State,
recv_cipher: ?cipher.State,
send_sequence: u32,
recv_sequence: u32,

/// `V_C`, with no line ending.
client_version_storage: [version.max_line_bytes]u8,
client_version_len: usize,
/// `V_S`, with no line ending.
server_version_storage: [version.max_line_bytes]u8,
server_version_len: usize,

/// `I_C`, the payload of this build's own `SSH_MSG_KEXINIT`.
client_kexinit_storage: [algorithms.kexinit_bytes]u8,
client_kexinit_len: usize,
/// `I_S`, the payload of the server's.
server_kexinit_storage: [max_server_kexinit_bytes]u8,
server_kexinit_len: usize,

/// `K_S`, the host key blob the server presented.
host_key_storage: [max_host_key_bytes]u8,
host_key_len: usize,
host_key: ?hostkey.PublicKey,

/// `H` of the first key exchange, which never changes.
session_id: [kex.hash_bytes]u8,
has_session_id: bool,
/// What the last negotiation chose.
choice: ?algorithms.Choice,
/// Whether both sides asked for strict key exchange.
strict_kex: bool,

/// How many bytes have crossed the wire since the last key exchange, both
/// directions counted.
bytes_since_kex: u64,
/// When the last key exchange finished.
kex_finished_at: Io.Timestamp,

/// When the rate window opened. See `rateDeadline`.
rate_window_start: Io.Timestamp,
/// How many bytes have crossed the wire since that moment, both
/// directions counted.
rate_window_bytes: u64,

/// True once the first key exchange has finished.
established: bool,

counters: Counters,
disconnect_storage: [max_disconnect_description_bytes]u8,
disconnect_len: usize,
disconnect_reason: ?messages.DisconnectReason,

/// Starts a transport over `channel`.
///
/// Initializes `t` in place, and not as a returned value, because the
/// buffers a caller reads point into this struct and because the struct
/// is kilobytes.
///
/// This writes nothing to the peer. `handshake` does that.
pub fn init(
    t: *Transport,
    gpa: std.mem.Allocator,
    io: Io,
    channel: zurl_net.line.Channel,
    options: Options,
) InitError!void {
    // The smallest packet any cipher here can frame, and the largest this
    // build ever wants. A caller that names something outside that has a
    // bug of its own, and a silently clamped bound would hide it.
    if (options.max_packet_bytes < 64 or options.max_packet_bytes > packet.max_packet_bytes) {
        return error.PacketBoundInvalid;
    }
    // The backlog holds whole payloads, so a backlog under one packet
    // could not hold the first one. A caller that named one has a bug.
    if (options.backlog_bytes < backlog_entry_head + @as(usize, options.max_packet_bytes)) {
        return error.PacketBoundInvalid;
    }

    const frame_bytes = 4 + @as(usize, options.max_packet_bytes);
    const send_frame = gpa.alloc(u8, frame_bytes) catch return error.OutOfMemory;
    errdefer gpa.free(send_frame);
    const recv_frame = gpa.alloc(u8, frame_bytes) catch return error.OutOfMemory;
    errdefer gpa.free(recv_frame);
    const backlog = gpa.alloc(u8, options.backlog_bytes) catch return error.OutOfMemory;

    t.gpa = gpa;
    t.io = io;
    t.channel = channel;
    t.options = options;
    t.send_frame = send_frame;
    t.recv_frame = recv_frame;
    t.backlog = backlog;
    t.backlog_len = 0;
    t.backlog_at = 0;
    t.send_cipher = null;
    t.recv_cipher = null;
    t.send_sequence = 0;
    t.recv_sequence = 0;
    t.client_version_len = 0;
    t.server_version_len = 0;
    t.client_kexinit_len = 0;
    t.server_kexinit_len = 0;
    t.host_key_len = 0;
    t.host_key = null;
    t.session_id = @splat(0);
    t.has_session_id = false;
    t.choice = null;
    t.strict_kex = false;
    t.bytes_since_kex = 0;
    t.kex_finished_at = Io.Timestamp.now(io, .awake);
    t.rate_window_start = Io.Timestamp.now(io, .awake);
    t.rate_window_bytes = 0;
    t.established = false;
    t.counters = .{};
    t.disconnect_len = 0;
    t.disconnect_reason = null;
}

/// Releases the buffers and wipes the keys.
///
/// **The three buffers hold plaintext and they are wiped too.**
/// `recv_frame` holds the last packet this side opened, `send_frame` holds
/// the last one it built, and `backlog` holds whole payloads a key
/// exchange collected. A password on the way to a server and a file on the
/// way back both pass through them.
pub fn deinit(t: *Transport) void {
    if (t.send_cipher) |*c| c.deinit();
    if (t.recv_cipher) |*c| c.deinit();
    std.crypto.secureZero(u8, &t.session_id);
    std.crypto.secureZero(u8, t.send_frame);
    std.crypto.secureZero(u8, t.recv_frame);
    std.crypto.secureZero(u8, t.backlog);
    t.gpa.free(t.send_frame);
    t.gpa.free(t.recv_frame);
    t.gpa.free(t.backlog);
    t.* = undefined;
}

/// Whether a cipher is in place for the packets this side writes.
///
/// A test of the trust boundary reads it: a host key that was refused must
/// leave both directions in the clear, because a cipher in place says this
/// side answered a server it does not trust.
pub fn hasSendCipher(t: *const Transport) bool {
    return t.send_cipher != null;
}

/// Whether a cipher is in place for the packets this side reads.
pub fn hasRecvCipher(t: *const Transport) bool {
    return t.recv_cipher != null;
}

/// How many bytes of caller payload one key exchange may collect here.
///
/// The layer above compares its own window against this. See
/// `default_backlog_bytes`.
pub fn backlogCapacity(t: *const Transport) usize {
    return t.backlog.len;
}

/// `V_C`, the identification string this build sent, with no line ending.
pub fn clientVersion(t: *const Transport) []const u8 {
    return t.client_version_storage[0..t.client_version_len];
}

/// `V_S`, the identification string the server sent, with no line ending.
///
/// **Untrusted text.** It is printable US-ASCII, which `version.parse`
/// checks, and nothing more.
pub fn serverVersion(t: *const Transport) []const u8 {
    return t.server_version_storage[0..t.server_version_len];
}

/// The session identifier, which is `H` of the first key exchange.
///
/// Null before the first key exchange finishes. Every layer above the
/// transport binds its own signatures to this value.
pub fn sessionId(t: *const Transport) ?[]const u8 {
    if (!t.has_session_id) return null;
    return &t.session_id;
}

/// The host key blob the server presented, or null before it has.
pub fn hostKeyBlob(t: *const Transport) ?[]const u8 {
    if (t.host_key_len == 0) return null;
    return t.host_key_storage[0..t.host_key_len];
}

/// What the last negotiation chose, or null before there was one.
pub fn negotiated(t: *const Transport) ?algorithms.Choice {
    return t.choice;
}

/// Why the peer ended the connection, or null.
pub fn lastDisconnect(t: *const Transport) ?Disconnect {
    const reason = t.disconnect_reason orelse return null;
    return .{
        .reason = reason,
        .description = t.disconnect_storage[0..t.disconnect_len],
    };
}

/// Runs the identification exchange and the first key exchange.
///
/// On return the connection is encrypted and `sessionId` has a value.
pub fn handshake(t: *Transport) KexError!void {
    const line = try version.build(&t.client_version_storage, t.options.software);
    // `line` points into `client_version_storage`, and the stored form
    // drops the `CRLF`, because that is what the exchange hash takes.
    t.client_version_len = version.withoutLineEnding(line).len;
    try t.channel.writer.writeAll(line);
    try t.channel.flush(t.channel.ctx);

    // The rate bound holds here too. A server that drips its
    // identification string one byte at a time is the same peer as one
    // that drips a packet, and it is stopped before the key exchange
    // rather than after it.
    const server = try version.read(
        t.channel.reader,
        t.io,
        &t.server_version_storage,
        // The preamble and the identification line together, which is
        // every byte this call may wait for.
        t.readBound(version.max_preamble_bytes + version.max_line_bytes),
    );
    t.server_version_len = server.text.len;

    try t.runKex(null);
    t.established = true;
}

/// Whether the byte count or the clock says a new key exchange is due.
///
/// **Two bounds, and either one is enough.** A key that has protected a
/// great deal of traffic and a key that has been in place a long time are
/// both worth replacing, and a connection can hit either one first.
pub fn needsRekey(t: *const Transport) bool {
    if (!t.established) return false;
    if (t.bytes_since_kex >= t.options.rekey_bytes) return true;
    const elapsed = t.kex_finished_at.durationTo(Io.Timestamp.now(t.io, .awake));
    const limit = @as(i96, t.options.rekey_seconds) * std.time.ns_per_s;
    return elapsed.nanoseconds >= limit;
}

/// Runs a new key exchange now.
pub fn rekey(t: *Transport) KexError!void {
    return t.runKex(null);
}

/// Sends one payload.
///
/// The first byte of `payload` is the message number, which belongs to
/// the layer above this one.
///
/// **A key exchange runs first when one is due.** See `needsRekey`.
pub fn send(t: *Transport, payload: []const u8) SendError!void {
    if (t.needsRekey()) try t.runKex(null);
    return t.sendPacket(payload);
}

/// Reads one payload that a caller asked for.
///
/// The result points into a buffer this value owns, so it is good until
/// the next call.
///
/// **The transport's own messages never reach a caller.**
/// `SSH_MSG_IGNORE`, `SSH_MSG_DEBUG`, `SSH_MSG_UNIMPLEMENTED`, and
/// `SSH_MSG_EXT_INFO` are counted and dropped. `SSH_MSG_KEXINIT` runs a
/// new key exchange and then the read carries on.
/// `SSH_MSG_DISCONNECT` is `error.PeerDisconnected`, and
/// `lastDisconnect` says why.
///
/// **A key exchange runs first when one is due**, the same way `send` runs
/// one. A session that mostly reads spends the same key on the same
/// traffic, and the bound that replaces a key must not depend on the layer
/// above choosing to write. See `needsRekey`.
pub fn receive(t: *Transport) ReceiveError![]const u8 {
    // The backlog is emptied first. Its entries arrived before this call
    // and a key exchange that ran now would write over them.
    if (t.backlog_at == t.backlog_len and t.needsRekey()) try t.runKex(null);

    var idle: usize = 0;
    while (idle <= max_idle_run) : (idle += 1) {
        // A packet a key exchange collected comes before anything still
        // on the wire, because it arrived first. See `backlog`.
        if (t.popBacklog()) |held| return held;

        const payload = try t.readPacket();
        const id = messages.idOf(payload) orelse return error.EmptyPacket;
        switch (id) {
            .disconnect => {
                t.recordDisconnect(payload);
                return error.PeerDisconnected;
            },
            .ignore, .debug, .unimplemented, .ext_info => t.countHousekeeping(id),
            .kexinit => try t.runKex(payload),
            // **A key exchange message outside a key exchange is a
            // protocol violation, and it must not reach a caller.** RFC
            // 4250 section 4.1.2 keeps 20 to 49 for the negotiation and
            // the method, and `runKex` reads every one of them that
            // belongs to a running exchange. One that arrives here
            // belongs to no exchange at all.
            else => {
                if (isKexRange(id)) return error.KexMessageUnexpected;
                return payload;
            },
        }
    }
    return error.TooManyIdlePackets;
}

/// Sends `SSH_MSG_UNIMPLEMENTED` for the packet numbered `sequence`.
///
/// RFC 4253 section 11.4 asks a receiver to answer a message it does not
/// understand this way. The transport does not send it on its own,
/// because only the layer above knows which message numbers it wanted.
pub fn sendUnimplemented(t: *Transport, sequence: u32) SendError!void {
    var storage: [5]u8 = undefined;
    const payload = messages.writeUnimplemented(&storage, sequence) catch
        return error.PayloadTooLong;
    return t.sendPacket(payload);
}

/// The sequence number the next packet read will carry.
///
/// A caller that answers with `sendUnimplemented` needs the number of the
/// packet it is answering, which is this value less one.
pub fn receiveSequence(t: *const Transport) u32 {
    return t.recv_sequence;
}

/// Sends `SSH_MSG_DISCONNECT` and stops.
///
/// **A failure to write is counted and not returned.** The session is
/// over either way, and a caller that has decided to disconnect has
/// nothing left to do about a socket that has already gone.
/// `counters.disconnect_write_failed` is where that recovery is visible.
pub fn disconnect(
    t: *Transport,
    reason: messages.DisconnectReason,
    description: []const u8,
) void {
    var storage: [max_disconnect_description_bytes + 32]u8 = undefined;
    const cut = description[0..@min(description.len, max_disconnect_description_bytes)];
    const payload = messages.writeDisconnect(&storage, reason, cut) catch {
        t.counters.disconnect_write_failed += 1;
        return;
    };
    t.sendPacket(payload) catch {
        t.counters.disconnect_write_failed += 1;
    };
}

/// Runs one key exchange.
///
/// `received` is the server's `SSH_MSG_KEXINIT` when the server started
/// this exchange, and null when this side did.
fn runKex(t: *Transport, received: ?[]const u8) KexError!void {
    var cookie: [algorithms.cookie_bytes]u8 = undefined;
    try t.io.randomSecure(&cookie);
    const client_kexinit = algorithms.writeKexinit(&t.client_kexinit_storage, cookie) catch
        return error.PayloadTooLong;
    t.client_kexinit_len = client_kexinit.len;
    try t.sendPacket(client_kexinit);

    if (received) |payload| {
        if (payload.len > max_server_kexinit_bytes) return error.KexinitTooLong;
        @memcpy(t.server_kexinit_storage[0..payload.len], payload);
        t.server_kexinit_len = payload.len;
    } else {
        const payload = try t.readServerKexinit();
        if (payload.len > max_server_kexinit_bytes) return error.KexinitTooLong;
        @memcpy(t.server_kexinit_storage[0..payload.len], payload);
        t.server_kexinit_len = payload.len;
    }

    const server_kexinit = t.server_kexinit_storage[0..t.server_kexinit_len];
    const parsed = try algorithms.parseKexinit(server_kexinit);
    var choice = try algorithms.negotiate(parsed);

    // **Strict key exchange is agreed once and it stays agreed.**
    // OpenSSH's rule reads the marker in the first `SSH_MSG_KEXINIT`
    // only. A build that read it again would let a server turn the rule
    // off part way through a session, and the sequence number reset that
    // makes a dropped packet visible would go with it.
    if (t.has_session_id) {
        choice.strict_kex = t.strict_kex;
    } else {
        t.strict_kex = choice.strict_kex;
    }
    t.choice = choice;

    // RFC 4253 section 7.1: a server that guessed and guessed wrong has
    // already sent a packet that both sides must throw away.
    //
    // **The throw away goes through `readKexPacket` and never through
    // `readPacket`.** This is the one packet of a key exchange that
    // nothing reads, and a packet nobody reads is exactly the packet
    // CVE-2023-48795 needs: it moves `recv_sequence` on by one with no
    // rule looking at it. `readKexPacket` puts it under
    // `housekeepingIsViolation`, so a `SSH_MSG_IGNORE` here is
    // `error.StrictKexViolation` the way it is everywhere else in the
    // first key exchange, and under `max_idle_run` as well.
    if (parsed.first_kex_packet_follows and !guessWasRight(parsed, choice)) {
        _ = try t.readKexPacket();
    }

    // The ephemeral key pair. The seed comes from `io.randomSecure`,
    // which makes a syscall each time and keeps no state in this process.
    var pair: X25519.KeyPair = undefined;
    var attempts: usize = 0;
    while (true) : (attempts += 1) {
        if (attempts == 16) return error.EphemeralKeyFailed;
        var seed: [X25519.seed_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &seed);
        try t.io.randomSecure(&seed);
        pair = X25519.KeyPair.generateDeterministic(seed) catch continue;
        break;
    }
    defer std.crypto.secureZero(u8, &pair.secret_key);

    var init_storage: [kex.ecdh_init_bytes]u8 = undefined;
    const init_payload = kex.writeEcdhInit(&init_storage, pair.public_key) catch
        return error.PayloadTooLong;
    try t.sendPacket(init_payload);

    const reply_payload = try t.readKexPacket();
    const reply = try kex.parseEcdhReply(reply_payload);
    if (reply.host_key_blob.len > max_host_key_bytes) return error.HostKeyTooLong;

    var shared = try kex.sharedSecret(pair.secret_key, reply.server_public);
    defer std.crypto.secureZero(u8, &shared);

    const exchange_hash = kex.exchangeHash(.{
        .client_version = t.clientVersion(),
        .server_version = t.serverVersion(),
        .client_kexinit = t.client_kexinit_storage[0..t.client_kexinit_len],
        .server_kexinit = server_kexinit,
        .host_key_blob = reply.host_key_blob,
        .client_public = &pair.public_key,
        .server_public = reply.server_public,
        .shared_secret = &shared,
    });

    const key = try hostkey.parse(reply.host_key_blob, choice.host_key);
    try hostkey.verify(key, reply.signature_blob, &exchange_hash);

    // **The signature proves the peer holds the key. This asks whether
    // the key belongs to the host.** See `zurl_ssh.hostkey`.
    @memcpy(t.host_key_storage[0..reply.host_key_blob.len], reply.host_key_blob);
    t.host_key_len = reply.host_key_blob.len;
    t.host_key = key;
    try t.options.verifier.check(t.options.peer, key, t.hostKeyBlob().?);

    if (!t.has_session_id) {
        t.session_id = exchange_hash;
        t.has_session_id = true;
    }

    // The `SSH_MSG_NEWKEYS` this side sends goes out under the old
    // cipher, and every packet after it goes out under the new one. RFC
    // 4253 section 7.3 sets that order.
    try t.sendPacket(&.{@intFromEnum(messages.Id.newkeys)});
    t.installSendCipher(choice, exchange_hash, &shared);

    const answer = try t.readKexPacket();
    const answer_id = messages.idOf(answer) orelse return error.EmptyPacket;
    if (answer_id != .newkeys) return error.KexMessageUnexpected;
    t.installRecvCipher(choice, exchange_hash, &shared);

    t.bytes_since_kex = 0;
    t.kex_finished_at = Io.Timestamp.now(t.io, .awake);
    t.counters.key_exchanges += 1;
}

/// Reads until the server's `SSH_MSG_KEXINIT` arrives.
///
/// **The first exchange and a later one have different rules, and this is
/// where the difference lives.**
///
/// On the first exchange the server's first packet must be its
/// `SSH_MSG_KEXINIT` and nothing else is read. See the module comment for
/// why.
///
/// On a later exchange the peer was free to write until the moment it saw
/// this side's `SSH_MSG_KEXINIT`, so RFC 4253 section 9 says packets sent
/// before that point still arrive. They belong to the caller, and a
/// caller is in the middle of a `send`, so they go to `backlog` and the
/// next `receive` hands them over in order.
fn readServerKexinit(t: *Transport) KexError![]const u8 {
    var idle: usize = 0;
    while (idle <= max_idle_run) : (idle += 1) {
        const payload = try t.readPacket();
        const id = messages.idOf(payload) orelse return error.EmptyPacket;
        if (id == .disconnect) {
            t.recordDisconnect(payload);
            return error.PeerDisconnected;
        }
        if (id == .kexinit) return payload;
        if (!t.established) return error.KexinitExpected;

        switch (id) {
            .ignore, .debug, .unimplemented, .ext_info => {
                if (t.housekeepingIsViolation()) return error.StrictKexViolation;
                t.countHousekeeping(id);
            },
            else => try t.pushBacklog(payload),
        }
    }
    return error.TooManyIdlePackets;
}

/// Whether a server's guessed key exchange packet was the right one, RFC
/// 4253 section 7.1.
///
/// A guess is right when the first name on each of the server's two lists
/// is the one that was chosen.
fn guessWasRight(parsed: algorithms.Kexinit, choice: algorithms.Choice) bool {
    var kex_it = parsed.kex.iterator();
    const first_kex = kex_it.next() orelse return false;
    if (!std.mem.eql(u8, first_kex, choice.kex_name)) return false;

    var host_key_it = parsed.host_key.iterator();
    const first_host_key = host_key_it.next() orelse return false;
    return std.mem.eql(u8, first_host_key, hostkey.name(choice.host_key));
}

/// Whether a housekeeping message inside a key exchange is a violation.
///
/// **Two rules, and either one refuses.**
///
/// The first is OpenSSH's strict key exchange, which both sides agreed to.
/// It forbids `SSH_MSG_IGNORE`, `SSH_MSG_DEBUG`, and
/// `SSH_MSG_UNIMPLEMENTED` inside a key exchange, because a packet that is
/// dropped moves the sequence numbers apart without either side noticing.
///
/// The second holds whatever the server agreed to: **no packet may be
/// dropped while the traffic is still in the clear.** That window is the
/// first key exchange, from the identification string to
/// `SSH_MSG_NEWKEYS`, and it is the only window in a session where an
/// attacker between the two sides can write a packet that this side reads.
/// One `SSH_MSG_IGNORE` inserted there moves `recv_sequence` on by one,
/// and the attacker can then delete the first packet the server sends
/// under the new key with no MAC failing. That is the whole injection
/// primitive of CVE-2023-48795, and it costs nothing to close: no server
/// needs to send these three messages inside a key exchange.
///
/// After the first `SSH_MSG_NEWKEYS` every packet carries a tag, so a
/// rekey cannot be fed a packet from outside. The three messages are legal
/// there and are counted and skipped, under the `max_idle_run` bound that
/// `receive` keeps.
fn housekeepingIsViolation(t: *const Transport) bool {
    return t.strict_kex or t.recv_cipher == null;
}

/// Reads one packet during a key exchange.
///
/// See `housekeepingIsViolation` for the messages this refuses.
fn readKexPacket(t: *Transport) KexError![]const u8 {
    var idle: usize = 0;
    while (idle <= max_idle_run) : (idle += 1) {
        const payload = try t.readPacket();
        const id = messages.idOf(payload) orelse return error.EmptyPacket;
        switch (id) {
            .disconnect => {
                t.recordDisconnect(payload);
                return error.PeerDisconnected;
            },
            .ignore, .debug, .unimplemented => {
                if (t.housekeepingIsViolation()) return error.StrictKexViolation;
                t.countHousekeeping(id);
            },
            else => return payload,
        }
    }
    return error.TooManyIdlePackets;
}

/// Derives the keys of one direction and puts the cipher in place.
fn installSendCipher(
    t: *Transport,
    choice: algorithms.Choice,
    exchange_hash: [kex.hash_bytes]u8,
    shared: []const u8,
) void {
    if (t.send_cipher) |*old| old.deinit();
    t.send_cipher = t.deriveCipher(
        choice.cipher_client_to_server,
        exchange_hash,
        shared,
        .initial_iv_client_to_server,
        .encryption_key_client_to_server,
    );
    // **Strict key exchange puts the sequence number back to zero at
    // every `SSH_MSG_NEWKEYS`.** That is what makes a packet dropped from
    // the front of the session visible. See the module comment.
    if (t.strict_kex) t.send_sequence = 0;
}

fn installRecvCipher(
    t: *Transport,
    choice: algorithms.Choice,
    exchange_hash: [kex.hash_bytes]u8,
    shared: []const u8,
) void {
    if (t.recv_cipher) |*old| old.deinit();
    t.recv_cipher = t.deriveCipher(
        choice.cipher_server_to_client,
        exchange_hash,
        shared,
        .initial_iv_server_to_client,
        .encryption_key_server_to_client,
    );
    if (t.strict_kex) t.recv_sequence = 0;
}

/// Derives one direction's key and initialisation vector, RFC 4253
/// section 7.2.
///
/// The integrity keys, letters `E` and `F`, are not derived. Both ciphers
/// this build speaks are AEAD, so the MAC is part of the cipher and
/// nothing would read those two keys. A cipher added later that needs a
/// separate MAC adds them here.
fn deriveCipher(
    t: *const Transport,
    algorithm: cipher.Algorithm,
    exchange_hash: [kex.hash_bytes]u8,
    shared: []const u8,
    iv_purpose: kex.KeyPurpose,
    key_purpose: kex.KeyPurpose,
) cipher.State {
    var key_material: [cipher.max_key_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &key_material);
    var iv_material: [cipher.max_iv_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &iv_material);

    const key = key_material[0..cipher.keyBytes(algorithm)];
    const iv = iv_material[0..cipher.ivBytes(algorithm)];
    kex.deriveKey(key, shared, exchange_hash, key_purpose, &t.session_id);
    kex.deriveKey(iv, shared, exchange_hash, iv_purpose, &t.session_id);
    return .init(algorithm, key, iv);
}

/// Builds one packet, seals it when a cipher is in place, and writes it.
fn sendPacket(t: *Transport, payload: []const u8) WriteError!void {
    const block = if (t.send_cipher) |c| c.block() else packet.min_block_bytes;
    const length_is_aad = if (t.send_cipher) |c| cipher.lengthIsAad(c.algorithm) else false;

    if (payload.len > t.options.max_packet_bytes) return error.PayloadTooLong;
    const body = packet.bodyLen(payload.len, block, length_is_aad);
    if (body > t.options.max_packet_bytes) return error.PayloadTooLong;

    const padding_len = packet.paddingLen(payload.len, block, length_is_aad);
    var padding: [255]u8 = undefined;
    // RFC 4253 section 6 asks for random padding, in every packet and not
    // only in an encrypted one.
    try t.io.randomSecure(padding[0..padding_len]);

    const frame = t.send_frame[0 .. 4 + body];
    std.mem.writeInt(u32, frame[0..4], @intCast(body), .big);
    packet.writeBody(frame[4..], payload, padding[0..padding_len]);

    if (t.send_cipher) |*c| {
        var tag: [cipher.tag_bytes]u8 = undefined;
        c.seal(t.send_sequence, frame, &tag);
        try t.channel.writer.writeAll(frame);
        try t.channel.writer.writeAll(&tag);
        t.bytes_since_kex += frame.len + tag.len;
        // The rate window counts both directions. See `rateDeadline`: an
        // upload reads almost nothing, and a rule that watched only the
        // reads would fail it for a direction it is not using.
        t.chargeRate(frame.len + tag.len);
    } else {
        try t.channel.writer.writeAll(frame);
        t.bytes_since_kex += frame.len;
        t.chargeRate(frame.len);
    }
    try t.channel.flush(t.channel.ctx);
    t.send_sequence +%= 1;
}

/// Whether the rate rule is off, which is what a zero on either setting
/// says. See `rateDeadline`.
fn rateIsOff(t: *const Transport) bool {
    return t.options.low_speed_limit == 0 or t.options.low_speed_time_s == 0;
}

/// When a read of `wanted` bytes stops being fast enough, or null when
/// the rate rule is off.
///
/// **`Options.stall` bounds one wait and this bounds the connection.** A
/// duration handed to `zurl_net.bounded.readExact` starts again at every
/// byte that arrives, so a peer that writes one byte just before each
/// wait runs out holds this process for as long as it likes. That is the
/// byte drip, and curl's `--speed-limit` is the flag a user reaches for
/// to stop it. A deadline does not start again, so this one bound holds
/// over a whole packet and over the whole connection.
///
/// The rule is `zurl_stream.Stall.stalled`, read the other way round.
/// That rule fails a window once `low_speed_time_s` has passed and the
/// bytes in it are under `low_speed_limit` for each second elapsed.
///
/// **`wanted` is part of the answer and leaving it out would fail an
/// honest link.** When this read finishes, the window will hold
/// `rate_window_bytes + wanted` bytes, and those bytes have earned
/// `(bytes + wanted) / limit` seconds between them. A deadline worked out
/// from the bytes already in hand would hold a read of a 32 KiB packet to
/// the grace alone, and a link running at twice the rate the user asked
/// for would be refused for taking longer than that. With `wanted` in it,
/// the deadline is exactly the moment the rule would judge the window
/// too slow, and no reading of the packet size changes the answer.
///
/// The grace is the floor, because the rule gives a window that long
/// before it has enough evidence to judge anything.
///
/// The bytes of both directions count, the way curl compares the faster
/// of its upload and download rates. An upload that writes fast and
/// reads only a window adjustment now and then must not be failed for
/// the direction it is not using.
fn rateDeadline(t: *const Transport, wanted: usize) ?Io.Clock.Timestamp {
    if (t.rateIsOff()) return null;
    const bytes = @as(u128, t.rate_window_bytes) + @as(u128, wanted);
    const earned_ns = bytes * std.time.ns_per_s / t.options.low_speed_limit;
    const grace_ns = @as(u128, t.options.low_speed_time_s) * std.time.ns_per_s;
    const allow_ns: i96 = @intCast(@max(earned_ns, grace_ns));
    return t.rate_window_start.addDuration(.{ .nanoseconds = allow_ns }).withClock(.awake);
}

/// The bound on a read of `wanted` bytes: the stall bound, and the rate
/// bound when there is one. The lower of the two wins, because a flag
/// narrows a package bound and never widens it.
fn readBound(t: *const Transport, wanted: usize) Io.Timeout {
    const rate = t.rateDeadline(wanted) orelse return t.options.stall;
    const stall = t.options.stall.toTimestamp(t.io) orelse return .{ .deadline = rate };
    return .{
        .deadline = if (rate.raw.nanoseconds < stall.raw.nanoseconds) rate else stall,
    };
}

/// Moves the rate window on by `n` bytes.
///
/// A window that ran its whole grace and is still taking bytes starts
/// again, so that a fast first minute does not pay for an hour of drip.
/// Every byte in such a window arrived before the deadline
/// `rateDeadline` gave, so the rate held for it and the evidence is
/// spent.
fn chargeRate(t: *Transport, n: usize) void {
    t.rate_window_bytes += n;
    if (t.rateIsOff()) return;
    const now = Io.Timestamp.now(t.io, .awake);
    const elapsed = t.rate_window_start.durationTo(now);
    const grace_ns = @as(i96, t.options.low_speed_time_s) * std.time.ns_per_s;
    if (elapsed.nanoseconds < grace_ns) return;
    t.rate_window_start = now;
    t.rate_window_bytes = 0;
}

/// Fills `out`, under the stall bound and the rate bound, and counts the
/// bytes against the rate window.
fn readRated(t: *Transport, out: []u8) ReadError!void {
    zurl_net.bounded.readExact(
        t.channel.reader,
        t.io,
        out,
        t.readBound(out.len),
    ) catch |err| return t.readFault(err, out.len);
    t.chargeRate(out.len);
}

/// Names the bound that a read of `wanted` bytes ran out of.
///
/// **Recovery is never silent, and neither is a refusal.** `readBound`
/// hands one deadline to the read and the read cannot say which of the
/// two bounds made it, so the answer is worked out here: a rate deadline
/// that has passed is the bound that stopped the read, and it gets its
/// own name so a user reads back the flag they set.
fn readFault(t: *const Transport, err: zurl_net.bounded.ExactError, wanted: usize) ReadError {
    if (err != error.OperationTimedOut) return err;
    const rate = t.rateDeadline(wanted) orelse return err;
    const now = Io.Timestamp.now(t.io, .awake);
    if (rate.raw.nanoseconds <= now.nanoseconds) return error.TransferTooSlow;
    return err;
}

/// Reads one packet, opens it when a cipher is in place, and returns the
/// payload.
///
/// The result points into `recv_frame`.
fn readPacket(t: *Transport) ReadError![]const u8 {
    const block = if (t.recv_cipher) |c| c.block() else packet.min_block_bytes;
    const length_is_aad = if (t.recv_cipher) |c| cipher.lengthIsAad(c.algorithm) else false;

    var head: [4]u8 = undefined;
    try t.readRated(&head);

    // **This number is unauthenticated, and it decides how many bytes
    // this process then waits for.** So it is checked here, before one
    // byte of the body is read.
    const length = if (t.recv_cipher) |*c|
        c.readLength(t.recv_sequence, head)
    else
        std.mem.readInt(u32, &head, .big);
    try packet.checkLength(length, block, length_is_aad, t.options.max_packet_bytes);

    const frame = t.recv_frame[0 .. 4 + length];
    @memcpy(frame[0..4], &head);
    try t.readRated(frame[4..]);

    if (t.recv_cipher) |*c| {
        var tag: [cipher.tag_bytes]u8 = undefined;
        try t.readRated(&tag);
        try c.open(t.recv_sequence, frame, tag);
        t.bytes_since_kex += frame.len + tag.len;
    } else {
        t.bytes_since_kex += frame.len;
    }

    t.recv_sequence +%= 1;
    return packet.payloadOf(frame[4..]);
}

/// Whether `id` belongs to a key exchange, RFC 4250 section 4.1.2.
///
/// 20 to 29 are the negotiation and 30 to 49 belong to whichever method
/// the negotiation chose. None of them means anything between exchanges.
fn isKexRange(id: messages.Id) bool {
    const number = @intFromEnum(id);
    return number >= 20 and number <= 49;
}

/// Counts one message the transport answered by dropping it.
///
/// **Recovery is never silent.** Every message that goes no further than
/// this value passes through here, so a caller can always see how many
/// there were.
fn countHousekeeping(t: *Transport, id: messages.Id) void {
    switch (id) {
        .ignore => t.counters.ignore += 1,
        .debug => t.counters.debug += 1,
        .unimplemented => t.counters.unimplemented += 1,
        .ext_info => t.counters.ext_info += 1,
        else => {},
    }
}

/// Keeps a payload a key exchange read for the next `receive`.
///
/// The entry is a 32-bit length and then the bytes. The buffer is the
/// whole bound. See `backlog`.
fn pushBacklog(t: *Transport, payload: []const u8) ReadError!void {
    // Entries already handed out are dead weight, so the run slides down
    // before anything is refused for want of room.
    if (t.backlog_at != 0) {
        const live = t.backlog_len - t.backlog_at;
        std.mem.copyForwards(u8, t.backlog[0..live], t.backlog[t.backlog_at..t.backlog_len]);
        t.backlog_len = live;
        t.backlog_at = 0;
    }
    if (payload.len + 4 > t.backlog.len - t.backlog_len) return error.RekeyBacklogFull;

    std.mem.writeInt(u32, t.backlog[t.backlog_len..][0..4], @intCast(payload.len), .big);
    @memcpy(t.backlog[t.backlog_len + 4 ..][0..payload.len], payload);
    t.backlog_len += 4 + payload.len;
}

/// The next payload a key exchange kept, or null.
///
/// The result points into `backlog`, and it stays good until the next
/// key exchange writes there.
fn popBacklog(t: *Transport) ?[]const u8 {
    if (t.backlog_at == t.backlog_len) {
        t.backlog_at = 0;
        t.backlog_len = 0;
        return null;
    }
    const length = std.mem.readInt(u32, t.backlog[t.backlog_at..][0..4], .big);
    const payload = t.backlog[t.backlog_at + 4 ..][0..length];
    t.backlog_at += 4 + length;
    return payload;
}

/// Keeps what a peer said when it disconnected, cut to fit.
///
/// A payload this cannot read leaves the reason as `protocol_error` and
/// the description empty. The connection is over either way, and a
/// malformed goodbye is not worth a second error path.
fn recordDisconnect(t: *Transport, payload: []const u8) void {
    const parsed = messages.parseDisconnect(payload) catch {
        t.disconnect_reason = .protocol_error;
        t.disconnect_len = 0;
        return;
    };
    const take = @min(parsed.description.len, max_disconnect_description_bytes);
    @memcpy(t.disconnect_storage[0..take], parsed.description[0..take]);
    t.disconnect_len = take;
    t.disconnect_reason = parsed.reason;
}

const testing = std.testing;

test "a full channel window of messages fits the backlog a key exchange keeps" {
    // **This is the arithmetic of finding I3, driven rather than
    // asserted.** A peer may have a whole channel receive window in flight
    // when this side starts a key exchange, and every one of those
    // payloads has to wait in the backlog. The old backlog held one packet
    // of 262148 bytes and a full window needs 262248, so the last message
    // was `error.RekeyBacklogFull` and any transfer that passed
    // `rekey_bytes` with the window full died.
    //
    // The payloads here are `SSH_MSG_CHANNEL_DATA` messages of the largest
    // size a channel takes: one message number, one recipient channel, one
    // string length, and the data.
    const window_bytes: usize = 256 * 1024;
    const message_bytes: usize = 32768;
    const payload_bytes: usize = 9 + message_bytes;
    const in_flight = window_bytes / message_bytes;

    const backlog = try testing.allocator.alloc(u8, default_backlog_bytes);
    defer testing.allocator.free(backlog);
    const payload = try testing.allocator.alloc(u8, payload_bytes);
    defer testing.allocator.free(payload);
    @memset(payload, 0x5e);

    // Only the backlog fields are touched, so the rest of the value needs
    // no socket and no key exchange.
    var t: Transport = undefined;
    t.backlog = backlog;
    t.backlog_len = 0;
    t.backlog_at = 0;

    for (0..in_flight) |_| try t.pushBacklog(payload);
    try testing.expectEqual(backlogBytesFor(in_flight, payload_bytes), t.backlog_len);

    // Every one of them comes back, whole and in order.
    for (0..in_flight) |_| {
        const held = t.popBacklog() orelse return error.TestExpectedBacklogEntry;
        try testing.expectEqualSlices(u8, payload, held);
    }
    try testing.expectEqual(@as(?[]const u8, null), t.popBacklog());

    // And the bound is still a bound: a peer that writes past the window
    // gets a named refusal rather than a buffer that grows.
    t.backlog_len = 0;
    t.backlog_at = 0;
    var pushed: usize = 0;
    while (t.pushBacklog(payload)) |_| : (pushed += 1) {
        if (pushed > 1024) return error.TestExpectedBacklogFull;
    } else |err| try testing.expectEqual(error.RekeyBacklogFull, err);
    try testing.expect(pushed >= in_flight);
}

test "the key exchange range is 20 to 49 and nothing else" {
    // RFC 4250 section 4.1.2. A message inside this range that arrives
    // between exchanges is refused, and one outside it goes to a caller.
    for (0..256) |number| {
        const id: messages.Id = @enumFromInt(number);
        try testing.expectEqual(number >= 20 and number <= 49, isKexRange(id));
    }
    try testing.expect(isKexRange(.kexinit));
    try testing.expect(isKexRange(.newkeys));
    try testing.expect(isKexRange(.kex_ecdh_reply));
    try testing.expect(!isKexRange(.service_accept));
    try testing.expect(!isKexRange(.disconnect));
}

test "a guessed key exchange packet counts as right only when both first names match" {
    const choice: algorithms.Choice = .{
        .kex = .curve25519_sha256,
        .kex_name = algorithms.curve25519_sha256,
        .host_key = .ssh_ed25519,
        .cipher_client_to_server = .chacha20_poly1305_openssh,
        .cipher_server_to_client = .chacha20_poly1305_openssh,
        .strict_kex = true,
    };
    const base: algorithms.Kexinit = .{
        .cookie = @splat(0),
        .kex = .{ .text = algorithms.curve25519_sha256 },
        .host_key = .{ .text = "ssh-ed25519" },
        .cipher_client_to_server = .{ .text = "" },
        .cipher_server_to_client = .{ .text = "" },
        .mac_client_to_server = .{ .text = "" },
        .mac_server_to_client = .{ .text = "" },
        .compression_client_to_server = .{ .text = "" },
        .compression_server_to_client = .{ .text = "" },
        .languages_client_to_server = .{ .text = "" },
        .languages_server_to_client = .{ .text = "" },
        .first_kex_packet_follows = true,
    };
    try testing.expect(guessWasRight(base, choice));

    // The chosen method is on the list but not first, so the guess used
    // another one and the packet behind it must be thrown away.
    var second = base;
    second.kex = .{ .text = "sntrup761x25519-sha512," ++ algorithms.curve25519_sha256 };
    try testing.expect(!guessWasRight(second, choice));

    var other_host_key = base;
    other_host_key.host_key = .{ .text = "ssh-rsa,ssh-ed25519" };
    try testing.expect(!guessWasRight(other_host_key, choice));

    var empty = base;
    empty.kex = .{ .text = "" };
    try testing.expect(!guessWasRight(empty, choice));
}

test "the rate bound is off unless both of its settings name something" {
    var t: Transport = undefined;
    t.rate_window_start = .{ .nanoseconds = 0 };
    t.rate_window_bytes = 0;

    t.options = .{ .peer = .{ .host = "h", .port = 22 }, .verifier = undefined };
    try testing.expectEqual(@as(?Io.Clock.Timestamp, null), t.rateDeadline(64));

    t.options.low_speed_limit = 1000;
    try testing.expectEqual(@as(?Io.Clock.Timestamp, null), t.rateDeadline(64));

    t.options.low_speed_limit = 0;
    t.options.low_speed_time_s = 30;
    try testing.expectEqual(@as(?Io.Clock.Timestamp, null), t.rateDeadline(64));
}

test "the rate bound gives a window the grace first and the bytes it earned after" {
    // **This is `zurl_stream.Stall.stalled` read the other way round.**
    // That rule fails a window once the grace has passed and the bytes in
    // it are under the rate for each second elapsed. So the deadline is
    // the moment the window stops being able to pass, which is
    // `bytes / limit` seconds and never fewer than the grace.
    const ns_per_s = std.time.ns_per_s;
    var t: Transport = undefined;
    t.options = .{
        .peer = .{ .host = "h", .port = 22 },
        .verifier = undefined,
        .low_speed_limit = 1000,
        .low_speed_time_s = 30,
    };
    t.rate_window_start = .{ .nanoseconds = 5 * ns_per_s };

    // A four byte read on an empty window earns four milliseconds, which
    // is far under the grace, so the window gets the grace and no more. A
    // peer that drips one byte every 29 seconds is refused here, which is
    // the whole point: the stall bound would start again at every byte.
    t.rate_window_bytes = 0;
    try testing.expectEqual(
        @as(i96, (5 + 30) * ns_per_s),
        t.rateDeadline(4).?.raw.nanoseconds,
    );

    // 60000 bytes at 1000 each second earn 60 seconds, which is over the
    // grace, so the window holds that long instead.
    t.rate_window_bytes = 60_000;
    try testing.expectEqual(
        @as(i96, (5 + 60) * ns_per_s),
        t.rateDeadline(0).?.raw.nanoseconds,
    );

    // **The bytes this read is waiting for count too.** A read of 90000
    // bytes on an empty window has 90 seconds to finish, because those
    // bytes will have earned exactly that by the time they arrive. A
    // deadline that left them out would give this read the grace alone
    // and refuse a link running at three times the rate the user asked
    // for.
    t.rate_window_bytes = 0;
    try testing.expectEqual(
        @as(i96, (5 + 90) * ns_per_s),
        t.rateDeadline(90_000).?.raw.nanoseconds,
    );
}

test "the read bound takes the lower of the stall bound and the rate bound" {
    // A flag narrows a package bound and never widens it. The rate bound
    // here is one second and the stall bound is an hour, so the rate one
    // is the answer, and the other way round below.
    const ns_per_s = std.time.ns_per_s;
    var t: Transport = undefined;
    t.io = testing.io;
    t.options = .{
        .peer = .{ .host = "h", .port = 22 },
        .verifier = undefined,
        .stall = .{ .duration = .{ .raw = .fromSeconds(3600), .clock = .awake } },
        .low_speed_limit = 1000,
        .low_speed_time_s = 1,
    };
    t.rate_window_start = Io.Timestamp.now(testing.io, .awake);
    t.rate_window_bytes = 0;

    const near = t.readBound(4);
    try testing.expectEqual(
        @as(i96, t.rate_window_start.nanoseconds + ns_per_s),
        near.deadline.raw.nanoseconds,
    );

    // With the rate bound an hour out and the stall bound a second, the
    // stall bound is the lower one.
    t.options.stall = .{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } };
    t.options.low_speed_time_s = 3600;
    const far = t.readBound(4);
    try testing.expect(
        far.deadline.raw.nanoseconds < t.rate_window_start.nanoseconds + 3600 * ns_per_s,
    );

    // With no rate named at all, the stall bound is handed on as it was.
    t.options.low_speed_limit = 0;
    try testing.expectEqual(
        @as(i96, ns_per_s),
        t.readBound(4).duration.raw.nanoseconds,
    );
}

test "a rate window that ran its whole grace starts again" {
    // A fast first minute must not pay for an hour of drip. Every byte in
    // a window that ran its whole grace arrived before the deadline
    // `rateDeadline` gave, so the rate held for it and the evidence is
    // spent.
    const ns_per_s = std.time.ns_per_s;
    var t: Transport = undefined;
    t.io = testing.io;
    t.options = .{
        .peer = .{ .host = "h", .port = 22 },
        .verifier = undefined,
        .low_speed_limit = 1,
        .low_speed_time_s = 1,
    };

    // A window that opened an hour ago is past its grace, so this charge
    // starts a new one and the bytes go back to zero.
    const now = Io.Timestamp.now(testing.io, .awake);
    t.rate_window_start = .{ .nanoseconds = now.nanoseconds - 3600 * ns_per_s };
    t.rate_window_bytes = 4096;
    t.chargeRate(8);
    try testing.expectEqual(@as(u64, 0), t.rate_window_bytes);
    try testing.expect(t.rate_window_start.nanoseconds > now.nanoseconds - ns_per_s);

    // A window still inside its grace keeps its count.
    t.rate_window_start = Io.Timestamp.now(testing.io, .awake);
    t.rate_window_bytes = 0;
    t.chargeRate(8);
    try testing.expectEqual(@as(u64, 8), t.rate_window_bytes);
}
