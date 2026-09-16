//! A loopback RFC 4253 server for the tests of this package.
//!
//! **This is a test fixture, not a product.** It speaks enough of the
//! transport layer to complete a handshake and to echo packets after it:
//! the identification exchange, `SSH_MSG_KEXINIT`, `curve25519-sha256`,
//! an `ssh-ed25519` signature, and `SSH_MSG_NEWKEYS`. With
//! `Script.auth` set it also runs RFC 4252: the service request, `none`,
//! `publickey` in both phases, `password`, and `keyboard-interactive`. It
//! has no channels, because no layer above authentication is written yet.
//!
//! **The authentication phase is off by default.** `Script.auth` is null,
//! so every transport test sees the fixture it always saw.
//!
//! **No test in this package reaches the real network.** Every one that
//! needs a peer starts one of these on 127.0.0.1 with a port the
//! operating system assigns.
//!
//! **What this fixture proves, and what it cannot.** It builds the
//! exchange hash by writing the whole input into one buffer and hashing it
//! once, straight off the list in RFC 4253 section 8. `zurl_ssh.kex`
//! hashes the same fields one at a time. So a handshake that completes
//! here shows the two agree. It does **not** show that the list itself is
//! the one every other SSH implementation uses, because both sides of this
//! test are this repository. Only a handshake against a real server shows
//! that, and the report records one.
//!
//! The fixture shares `zurl_ssh.packet` and `zurl_ssh.cipher` with the
//! client it talks to, so a handshake here does not prove the framing
//! matches the specification either. Those two modules have their own
//! tests against fixed bytes, and the real server is what proves the
//! framing on the wire.
//!
//! **The padding this fixture writes is a constant.** RFC 4253 section 6
//! asks for random padding. The bytes are covered by the tag and read by
//! nobody, and a fixture with the same output on every run is easier to
//! debug.

const std = @import("std");
const zurl_net = @import("zurl-net");

const algorithms = @import("algorithms.zig");
const cipher = @import("cipher.zig");
const connection = @import("connection.zig");
const hostkey = @import("hostkey.zig");
const kex = @import("kex.zig");
const messages = @import("messages.zig");
const packet = @import("packet.zig");
const userauth = @import("userauth.zig");
const version = @import("version.zig");
const wire = @import("wire.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const X25519 = std.crypto.dh.X25519;
const testing = std.testing;

pub const Server = @This();

/// How large a packet this fixture frames. Test payloads are short.
pub const frame_bytes = 4 + 8192 + cipher.tag_bytes;

/// The seed of the fixture's host key. A constant, so every run presents
/// the same key and a test can pin its fingerprint.
const host_key_seed: [Ed25519.KeyPair.seed_length]u8 = @splat(0x51);

/// The seed of the key a `wrong_signing_key` run signs with.
const impostor_seed: [Ed25519.KeyPair.seed_length]u8 = @splat(0x52);

/// How long one read waits with no byte arriving.
const read_stall: std.Io.Timeout = .{
    .duration = .{ .raw = .fromSeconds(10), .clock = .awake },
};

/// What one run of the fixture does.
pub const Script = struct {
    /// Lines to write before the identification. RFC 4253 section 4.2
    /// lets a server write as many as it likes.
    preamble: []const u8 = "",
    /// The identification line, the line ending included.
    identification: []const u8 = "SSH-2.0-zurl_fixture\r\n",
    /// Whether to offer `kex-strict-s-v00@openssh.com`.
    strict_kex: bool = true,
    /// Leave the strict key exchange marker out of every
    /// `SSH_MSG_KEXINIT` after the first one, while this side keeps
    /// applying the rule.
    ///
    /// **A client must keep applying it too.** OpenSSH reads the marker
    /// in the first message only, so a client that read it again would
    /// stop resetting its sequence numbers here and the two sides would
    /// part company on the very next packet.
    drop_strict_on_rekey: bool = false,
    /// Send this payload once, right after the handshake. A test that
    /// drives a message out of its place uses it.
    stray_message: []const u8 = "",
    /// The key exchange names to offer, past the strict marker.
    kex_names: []const u8 = algorithms.curve25519_sha256,
    /// The host key names to offer.
    host_key_names: []const u8 = "ssh-ed25519",
    /// The cipher names to offer, in both directions.
    cipher_names: []const u8 = "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
    /// The compression names to offer.
    compression_names: []const u8 = "none",
    /// Sign something that is not the exchange hash. The client must
    /// refuse.
    forge_signature: bool = false,
    /// Present the real host key and sign with another. The client must
    /// refuse.
    wrong_signing_key: bool = false,
    /// Send an `SSH_MSG_IGNORE` and an `SSH_MSG_DEBUG` after the
    /// handshake, before the first echo.
    chatter: bool = false,
    /// Send an `SSH_MSG_IGNORE` in the middle of the key exchange, which
    /// strict key exchange forbids.
    chatter_in_kex: bool = false,
    /// Set `first_kex_packet_follows` in the server `SSH_MSG_KEXINIT` and
    /// send this payload straight after it, which is RFC 4253 section
    /// 7.1's guess. Empty sends none and clears the flag.
    ///
    /// **A test that uses it puts a wrong name first in `kex_names`**, so
    /// the client reads the guess as wrong and has to throw the packet
    /// away. That throw away is the one packet of the first key exchange
    /// that nothing else reads, and what it is allowed to be is the
    /// question.
    guessed_packet: []const u8 = "",
    /// How many payloads to read and write back.
    echo_count: usize = 1,
    /// Start a new key exchange after reading the payload for this echo
    /// and before writing it back, counting the echoes from zero.
    ///
    /// The order matters. A server that sent `SSH_MSG_KEXINIT` before it
    /// read would meet the client's data packet where it expected the
    /// client's own `SSH_MSG_KEXINIT`, and a fixture that has to queue a
    /// packet is a fixture with a state machine of its own.
    rekey_before_echo: ?usize = null,
    /// Send this payload after the client's `SSH_MSG_KEXINIT` arrives and
    /// before this side answers with its own.
    ///
    /// **RFC 4253 section 9 allows exactly this.** A peer writes until it
    /// sees the other side's `SSH_MSG_KEXINIT`, so a client that starts a
    /// rekey must expect the packets that were already on their way.
    data_before_rekey: []const u8 = "",
    /// Say goodbye with this text instead of echoing anything.
    disconnect_instead: ?[]const u8 = null,
    /// Write these bytes in place of the first packet after the
    /// handshake. A test that drives a bad packet uses it.
    raw_after_handshake: ?[]const u8 = null,
    /// Run an RFC 4252 exchange after the handshake, or null to run none.
    ///
    /// **Null is what every transport test uses**, so the fixture behaves
    /// exactly as it did before authentication was written.
    auth: ?AuthScript = null,
    /// Run an RFC 4254 connection phase after a login that worked, or null
    /// to run none.
    ///
    /// **Null is what every transport and authentication test uses**, so
    /// the fixture behaves exactly as it did before channels were
    /// written. It needs `auth` too: a channel before a login is a
    /// channel no real server opens.
    connection: ?ConnectionScript = null,
};

/// What the fixture serves once a channel is open.
pub const ChannelService = enum {
    /// Write nothing and read nothing. The test drives the close.
    idle,
    /// Write `ConnectionScript.body`, then end of file.
    write_body,
    /// Read every byte the client writes until its end of file, and count
    /// them. `Server.received` is the count.
    sink,
    /// Speak the SFTP subsystem, version 3, over the channel.
    ///
    /// **It is written here with `wire.Writer` and not with
    /// `zurl_sftp.protocol`.** `zurl-ssh` cannot import `zurl-sftp`, which
    /// imports it, and that is a gain rather than a cost: a fixture built
    /// out of the client's own writers would agree with a client that
    /// framed every packet the same wrong way.
    sftp,
    /// Speak the old rcp protocol a remote `scp` speaks.
    ///
    /// **It is written here by hand for the same reason the SFTP service
    /// is.** `zurl-ssh` cannot import `zurl-scp`, which imports it, so this
    /// fixture agrees with no bug in the client's own writers.
    scp,
};

/// What the fixture's RFC 4254 phase does.
///
/// **This is a fixture and it decides nothing a real server decides.** It
/// takes one channel and it serves one thing on it.
pub const ConnectionScript = struct {
    /// Refuse the channel open with this reason, or null to open it.
    refuse_open: ?connection.OpenFailureReason = null,
    /// The window the fixture gives the client, in bytes.
    ///
    /// **A small one is the point of several tests.** A client that never
    /// read a `SSH_MSG_CHANNEL_WINDOW_ADJUST` would stop here and never
    /// start again.
    window_bytes: u32 = 64 * 1024,
    /// The largest message the fixture takes.
    max_packet_bytes: u32 = 32768,
    /// Refuse the `exec` or `subsystem` request.
    refuse_request: bool = false,
    /// The request name the fixture accepts. Anything else is refused.
    accept_request: []const u8 = "subsystem",
    /// Send a `SSH_MSG_GLOBAL_REQUEST` that wants a reply, before the
    /// channel open. OpenSSH sends `hostkeys-00@openssh.com` here.
    global_request: bool = false,
    /// Offer a channel of the fixture's own after the open, which the
    /// client must refuse.
    offer_channel: bool = false,
    /// Write this on `SSH_MSG_CHANNEL_EXTENDED_DATA` before the body.
    stderr_text: []const u8 = "",
    /// What the fixture writes for `write_body`.
    body: []const u8 = "",
    /// How many bytes of `body` go in one message.
    body_chunk_bytes: usize = 4096,
    /// The exit status to send before the close, or null to send none.
    exit_status: ?u32 = null,
    /// What the fixture serves.
    service: ChannelService = .idle,
    /// Send a `SSH_MSG_CHANNEL_REQUEST` the client does not act on, so
    /// that the drop is exercised.
    stray_request: bool = false,
    /// Send this many of those before each chunk of `body`.
    ///
    /// **This is the byte-for-packets trade a client must bound.** A
    /// server that sends a run of these, then one byte, then another run,
    /// buys the run with the byte for as long as it likes, unless the
    /// client counts the runs over the whole channel and not over one
    /// `read`. See `zurl_ssh.Channel.max_idle_steps`.
    stray_requests_per_chunk: usize = 0,
    /// Send one `SSH_MSG_CHANNEL_DATA` after the `SSH_MSG_CHANNEL_CLOSE`.
    /// RFC 4254 section 5.3 forbids it and the client must refuse it.
    data_after_close: bool = false,
    /// What the `sftp` service answers with. See `SftpScript`.
    sftp: SftpScript = .{},
    /// What the `scp` service answers with. See `ScpScript`.
    scp: ScpScript = .{},
};

/// What the fixture's rcp service does.
///
/// **This is a fixture and it holds one file.** It writes one `C` line and
/// one body, or it takes one upload, which is what a remote `scp` in source
/// mode or in sink mode does for one url.
pub const ScpScript = struct {
    /// Take an upload rather than write a file. This is `scp -t`.
    receive: bool = false,
    /// The mode the fixture writes on its `C` line.
    mode: []const u8 = "0644",
    /// The name the fixture writes on its `C` line.
    name: []const u8 = "f.txt",
    /// What the file holds.
    contents: []const u8 = "",
    /// Write a `T` line before the `C` line, which is what `-p` asks for.
    send_times: bool = true,
    /// Write this many extra `T` lines before the `C` line.
    ///
    /// **A control line that names no file moves nothing.** A client that
    /// bounded only the file would read these for as long as this side
    /// wrote them.
    extra_time_lines: usize = 0,
    /// The size the fixture writes on its `C` line, or null to write the
    /// real length of `contents`.
    ///
    /// **A size that does not match the body is the interesting case.** A
    /// client that read the size and then read until the channel ended
    /// would read the status byte as file content.
    size_override: ?[]const u8 = null,
    /// A whole control line to write in place of the `C` line, with no
    /// newline. A test that drives a malformed line sets it.
    control_line: ?[]const u8 = null,
    /// Write a `\x01` warning with this text before the `C` line.
    warning: ?[]const u8 = null,
    /// Write a `\x02` fatal message with this text and stop.
    fatal: ?[]const u8 = null,
    /// How many bytes of the body go in one channel message.
    body_chunk_bytes: usize = 4096,
    /// Leave the status byte off the end of the file, which a server that
    /// died in the middle would.
    omit_end_status: bool = false,
};

/// What the fixture's SFTP subsystem does.
///
/// **This is a fixture and it holds one file.** It answers `SSH_FXP_OPEN`
/// for the one path it was given and `SSH_FX_NO_SUCH_FILE` for every
/// other, which is enough to drive a client's own paths.
pub const SftpScript = struct {
    /// The version to answer `SSH_FXP_INIT` with.
    version: u32 = 3,
    /// The path the fixture holds.
    path: []const u8 = "/f.txt",
    /// What that path holds.
    contents: []const u8 = "",
    /// The status to answer an `SSH_FXP_OPEN` of `path` with, or null to
    /// open it.
    open_status: ?u32 = null,
    /// How many bytes the fixture answers one `SSH_FXP_READ` with, at
    /// most.
    ///
    /// **A short answer is not an end.** Section 6.4 of the draft allows
    /// it, and a client that took one for the end of the file would
    /// truncate every download from a server that gives short answers.
    read_chunk_bytes: usize = 1 << 30,
    /// The entries a directory listing answers with, as name and longname
    /// pairs.
    entries: []const [2][]const u8 = &.{},
    /// Take an upload and keep it. `Server.uploaded` is what arrived.
    accept_write: bool = false,
};

/// What the fixture's RFC 4252 phase does.
///
/// **This is a fixture and it decides nothing a real server decides.** It
/// takes one user, one password, and one public key, and it answers every
/// other credential with a failure.
pub const AuthScript = struct {
    /// The account the fixture accepts.
    user: []const u8 = "alice",
    /// The name-list the fixture writes in every failure.
    methods: []const u8 = "publickey,password,keyboard-interactive",
    /// The password the fixture accepts, or null to accept none.
    password: ?[]const u8 = null,
    /// The public key blob the fixture accepts, or null to accept none.
    public_key: ?[]const u8 = null,
    /// Accept the `none` method, which is an account with no credential.
    accept_none: bool = false,
    /// Say goodbye instead of accepting `ssh-userauth`.
    refuse_service: bool = false,
    /// The service name to write in the accept. Null writes the one that
    /// was asked for, and an empty string writes no name at all, which
    /// some servers do.
    service_name: ?[]const u8 = null,
    /// A banner to write after the service accept. Empty writes none.
    banner: []const u8 = "",
    /// How many times to write it.
    banner_count: usize = 1,
    /// Answer a `publickey` query with a failure, so the client never
    /// signs anything.
    refuse_public_key_query: bool = false,
    /// Answer a `publickey` query with `SSH_MSG_USERAUTH_SUCCESS`, which
    /// RFC 4252 section 7 does not allow. The client must refuse it: a
    /// yes to a question nobody proved the answer to is a login with no
    /// signature made.
    answer_public_key_query_with_success: bool = false,
    /// Echo a key in the `SSH_MSG_USERAUTH_PK_OK` that is not the one the
    /// client sent.
    forge_public_key_ok: bool = false,
    /// Answer the first `password` request with
    /// `SSH_MSG_USERAUTH_PASSWD_CHANGEREQ`.
    password_change: bool = false,
    /// Answer the first method that would work with a failure that says
    /// partial success, so a second method has to run.
    partial_success: bool = false,
    /// How many `SSH_MSG_USERAUTH_INFO_REQUEST` rounds one
    /// `keyboard-interactive` attempt takes. Every round but the last one
    /// carries no prompt at all, which is what RFC 4256 section 3.3 calls
    /// an informational message.
    interactive_rounds: usize = 1,
    /// How many prompts the last `SSH_MSG_USERAUTH_INFO_REQUEST` carries.
    interactive_prompts: u32 = 1,
    /// Whether those prompts ask to be echoed.
    interactive_echo: bool = false,
    /// How many requests the fixture reads before it gives up.
    max_requests: usize = 16,
};

server: std.Io.net.Server,
task: std.Io.Future(void),
script: Script,
host_key: Ed25519.KeyPair,
host_key_blob_storage: [64]u8,
host_key_blob_len: usize,

reader: ?*std.Io.Reader,
writer: ?*std.Io.Writer,
send_cipher: ?cipher.State,
recv_cipher: ?cipher.State,
send_sequence: u32,
recv_sequence: u32,
strict_kex: bool,
kex_count: u32,
session_id: [kex.hash_bytes]u8,
has_session_id: bool,

client_version_storage: [version.max_line_bytes]u8,
client_version_len: usize,
client_kexinit_storage: [4096]u8,
client_kexinit_len: usize,
server_kexinit_storage: [1024]u8,
server_kexinit_len: usize,

in_frame: [frame_bytes]u8,
out_frame: [frame_bytes]u8,

/// Whether the login worked, so the connection phase knows to run.
authenticated: bool,

/// The channel number the client chose, echoed back in every message the
/// fixture sends about the channel.
client_channel: u32,
/// How many bytes the fixture may still send on the channel.
client_window: u32,
/// The largest message the client takes.
client_max_packet: u32,
/// How many bytes the client may still send.
local_window: u32,
/// Whether the client has sent `SSH_MSG_CHANNEL_CLOSE`.
client_closed: bool,
/// How many bytes of channel data the client wrote. `ChannelService.sink`
/// fills it, and so does an SFTP upload. A test reads it.
received: std.atomic.Value(u64),

/// Holds the SFTP bytes that have arrived and that no packet has taken.
sftp_storage: [64 * 1024]u8,
sftp_len: usize,
sftp_at: usize,
/// Holds one outgoing `SSH_FXP_DATA` while it is built.
sftp_out_storage: [64 * 1024]u8,
/// Holds what an SFTP or an scp upload wrote.
upload_storage: [64 * 1024]u8,

/// Holds the command an `exec` request carried.
///
/// **This is what a test reads to prove what reached the far side.** A
/// quoting rule is only worth what the bytes on the wire say, so the bytes
/// are kept and compared rather than trusted.
exec_command_storage: [max_exec_command_bytes]u8,
exec_command_len: usize,

/// Holds the name and the value the last `env` request carried, for the
/// reason `exec_command_storage` holds the command: a test reads the wire
/// rather than trust the builder that wrote it. See `envName` and
/// `envValue`.
env_name_storage: [max_env_name_bytes]u8,
env_name_len: usize,
env_value_storage: [max_env_value_bytes]u8,
env_value_len: usize,

/// The name of the first fault the fixture's own task hit, or null.
///
/// **A fixture that fails silently makes a client look broken.** A test
/// that ends in a surprise reads this first.
failure: ?[]const u8,
finished: std.atomic.Value(bool),
accept_count: std.atomic.Value(usize),

/// Starts listening on loopback and runs `script` against one connection.
///
/// Initializes `s` in place, because the task holds `&s.server` for its
/// whole life and because the struct is kilobytes.
///
/// Returns `error.SkipZigTest` in a build with no concurrency. The server
/// and its client cannot both make progress on one task.
///
/// `s` and every slice in `script` must outlive the server.
pub fn start(s: *Server, script: Script) !void {
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    s.server = try address.listen(testing.io, .{ .reuse_address = true });
    errdefer s.server.deinit(testing.io);

    s.script = script;
    s.host_key = try Ed25519.KeyPair.generateDeterministic(host_key_seed);
    var blob: wire.Writer = .init(&s.host_key_blob_storage);
    try blob.string("ssh-ed25519");
    try blob.string(&s.host_key.public_key.toBytes());
    s.host_key_blob_len = blob.written().len;

    s.reader = null;
    s.writer = null;
    s.send_cipher = null;
    s.recv_cipher = null;
    s.send_sequence = 0;
    s.recv_sequence = 0;
    s.strict_kex = false;
    s.kex_count = 0;
    s.has_session_id = false;
    s.client_version_len = 0;
    s.client_kexinit_len = 0;
    s.server_kexinit_len = 0;
    s.authenticated = false;
    s.client_channel = 0;
    s.client_window = 0;
    s.client_max_packet = 0;
    s.local_window = 0;
    s.client_closed = false;
    s.received = .init(0);
    s.sftp_len = 0;
    s.sftp_at = 0;
    s.exec_command_len = 0;
    s.env_name_len = 0;
    s.env_value_len = 0;
    s.failure = null;
    s.finished = .init(false);
    s.accept_count = .init(0);

    s.task = testing.io.concurrent(run, .{s}) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
}

/// Stops the task and releases the listening socket. Every test that
/// calls `start` must call this.
pub fn stop(s: *Server) void {
    s.task.cancel(testing.io);
    s.server.deinit(testing.io);
}

/// The port the operating system assigned.
pub fn port(s: *const Server) u16 {
    return s.server.socket.address.getPort();
}

/// The host key blob this fixture presents.
pub fn hostKeyBlob(s: *const Server) []const u8 {
    return s.host_key_blob_storage[0..s.host_key_blob_len];
}

/// Waits until the fixture task has let go of its connection.
pub fn awaitDone(s: *const Server) void {
    const step: std.Io.Timeout = .{
        .duration = .{ .raw = .fromMilliseconds(1), .clock = .awake },
    };
    var steps: usize = 0;
    while (!s.finished.load(.acquire) and steps < 10_000) : (steps += 1) {
        step.sleep(testing.io) catch return;
    }
}

/// What an SFTP upload wrote into this fixture.
///
/// **Not thread safe while the task runs.** A test reads it after
/// `awaitDone`, the way it reads `failure`.
pub fn uploaded(s: *const Server) []const u8 {
    const at = s.received.load(.acquire);
    return s.upload_storage[0..@intCast(at)];
}

/// The command the client's `exec` request carried, byte for byte.
///
/// **Not thread safe while the task runs.** A test reads it after
/// `awaitDone`, the way it reads `failure`. An empty answer says no `exec`
/// request arrived.
pub fn execCommand(s: *const Server) []const u8 {
    return s.exec_command_storage[0..s.exec_command_len];
}

/// The name the last `env` request carried, or empty when none arrived.
pub fn envName(s: *const Server) []const u8 {
    return s.env_name_storage[0..s.env_name_len];
}

/// The value the last `env` request carried, or empty when none arrived.
pub fn envValue(s: *const Server) []const u8 {
    return s.env_value_storage[0..s.env_value_len];
}

/// A verifier that trusts this fixture's own host key and nothing else.
///
/// **This is a pin, and not an "accept anything".** It compares the blob
/// the server presented against the one this fixture holds, so a test
/// that changes the key sees a refusal. A real caller writes a verifier
/// of the same shape over `known_hosts`.
pub fn verifier(s: *Server) hostkey.Verifier {
    return .{ .ctx = s, .decide = decidePinned };
}

fn decidePinned(
    ctx: ?*anyopaque,
    peer: hostkey.Peer,
    key: hostkey.PublicKey,
    blob: []const u8,
) hostkey.TrustError!void {
    _ = peer;
    _ = key;
    const s: *Server = @ptrCast(@alignCast(ctx.?));
    const pinned = s.hostKeyBlob();
    if (blob.len != pinned.len) return error.HostKeyChanged;
    if (std.crypto.timing_safe.compare(u8, blob, pinned, .big) != .eq) {
        return error.HostKeyChanged;
    }
}

/// A verifier that refuses every key.
///
/// A test that proves a refused key ends the connection uses it.
pub const refusing_verifier: hostkey.Verifier = .{ .decide = decideRefuse };

fn decideRefuse(
    ctx: ?*anyopaque,
    peer: hostkey.Peer,
    key: hostkey.PublicKey,
    blob: []const u8,
) hostkey.TrustError!void {
    _ = ctx;
    _ = peer;
    _ = key;
    _ = blob;
    return error.HostKeyRejected;
}

/// One side of a loopback connection, as a reader, a writer, and the
/// `Channel` a `Transport` runs over.
///
/// **Must not move once `connect` has run.** The `Channel` holds pointers
/// into this value.
pub const Endpoint = struct {
    stream: std.Io.net.Stream,
    read_storage: [frame_bytes]u8,
    write_storage: [frame_bytes]u8,
    reader: std.Io.net.Stream.Reader,
    writer: std.Io.net.Stream.Writer,

    /// Opens a connection to a fixture on loopback.
    pub fn connect(e: *Endpoint, peer_port: u16) !void {
        var address = try std.Io.net.IpAddress.parse("127.0.0.1", peer_port);
        e.stream = try address.connect(testing.io, .{ .mode = .stream });
        e.reader = .init(e.stream, testing.io, &e.read_storage);
        e.writer = .init(e.stream, testing.io, &e.write_storage);
    }

    /// Closes the connection.
    pub fn close(e: *Endpoint) void {
        e.stream.close(testing.io);
    }

    /// The channel a `Transport` runs over.
    pub fn channel(e: *Endpoint) zurl_net.line.Channel {
        return .{
            .reader = &e.reader.interface,
            .writer = &e.writer.interface,
            .ctx = e,
            .flush = flush,
        };
    }

    fn flush(ctx: ?*anyopaque) std.Io.Writer.Error!void {
        const e: *Endpoint = @ptrCast(@alignCast(ctx.?));
        return e.writer.interface.flush();
    }
};

fn run(s: *Server) void {
    s.runFallible() catch |err| {
        s.failure = @errorName(err);
    };
    s.finished.store(true, .release);
}

fn runFallible(s: *Server) !void {
    const stream = try s.server.accept(testing.io);
    defer stream.close(testing.io);
    s.accept_count.store(s.accept_count.load(.monotonic) + 1, .release);

    var read_storage: [frame_bytes]u8 = undefined;
    var write_storage: [frame_bytes]u8 = undefined;
    var stream_reader: std.Io.net.Stream.Reader = .init(stream, testing.io, &read_storage);
    var stream_writer: std.Io.net.Stream.Writer = .init(stream, testing.io, &write_storage);
    s.reader = &stream_reader.interface;
    s.writer = &stream_writer.interface;
    defer {
        s.reader = null;
        s.writer = null;
    }

    // The identification exchange. The notices go first, which is what a
    // server with a legal banner does.
    if (s.script.preamble.len != 0) try s.writer.?.writeAll(s.script.preamble);
    try s.writer.?.writeAll(s.script.identification);
    try s.writer.?.flush();

    var client_line: [version.max_line_bytes]u8 = undefined;
    const client = try version.read(s.reader.?, testing.io, &client_line, read_stall);
    @memcpy(s.client_version_storage[0..client.text.len], client.text);
    s.client_version_len = client.text.len;

    try s.runKexServer(null);

    if (s.script.auth) |auth_script| {
        try s.runAuth(auth_script);
        // **A channel only runs after a login that worked.** A real
        // server opens none before one, so a fixture that did would let a
        // client pass a test no server would let it pass.
        if (s.authenticated) {
            if (s.script.connection) |connection_script| try s.runConnection(connection_script);
        }
        // The write side closes first, so a client that is still writing
        // does not meet a reset. The echo loop below belongs to the
        // transport tests, which run no authentication.
        stream.shutdown(testing.io, .send) catch {};
        return;
    }

    if (s.script.raw_after_handshake) |bytes| {
        try s.writer.?.writeAll(bytes);
        try s.writer.?.flush();
        // Drain until the client gives up, so the fixture does not send a
        // reset over the bytes it just wrote.
        stream.shutdown(testing.io, .send) catch {};
        return;
    }

    if (s.script.disconnect_instead) |text| {
        var storage: [512]u8 = undefined;
        const payload = try messages.writeDisconnect(&storage, .by_application, text);
        try s.sendPacket(payload);
        stream.shutdown(testing.io, .send) catch {};
        return;
    }

    if (s.script.stray_message.len != 0) try s.sendPacket(s.script.stray_message);

    if (s.script.chatter) {
        try s.sendPacket("\x02\x00\x00\x00\x04kiss");
        try s.sendPacket("\x04\x00\x00\x00\x00\x04talk\x00\x00\x00\x00");
    }

    for (0..s.script.echo_count) |i| {
        const payload = try s.readClientPacket();
        // The echo is copied out, because a key exchange reuses the read
        // frame the payload points into.
        var echo_storage: [1024]u8 = undefined;
        if (payload.len > echo_storage.len) return error.FixtureEchoTooLong;
        @memcpy(echo_storage[0..payload.len], payload);

        if (s.script.rekey_before_echo == i) try s.runKexServer(null);
        try s.sendPacket(echo_storage[0..payload.len]);
    }

    // The write side closes first, so a client that is still writing does
    // not meet a reset.
    stream.shutdown(testing.io, .send) catch {};
}

/// Reads one packet, and runs a new key exchange when the client asks for
/// one.
fn readClientPacket(s: *Server) ![]const u8 {
    var rounds: usize = 0;
    while (rounds < 8) : (rounds += 1) {
        const payload = try s.recvPacket();
        const id = messages.idOf(payload) orelse return error.FixtureEmptyPacket;
        if (id == .kexinit) {
            try s.runKexServer(payload);
            continue;
        }
        return payload;
    }
    return error.FixtureTooManyKeyExchanges;
}

/// Runs one key exchange from the server's side.
///
/// `received` is the client's `SSH_MSG_KEXINIT` when the client started
/// this exchange, and null when this side did.
fn runKexServer(s: *Server, received: ?[]const u8) !void {
    // The client has already sent its `SSH_MSG_KEXINIT` and this side has
    // not answered yet, which is the one moment RFC 4253 section 9 lets a
    // data packet cross a key exchange.
    if (received != null and s.script.data_before_rekey.len != 0) {
        try s.sendPacket(s.script.data_before_rekey);
    }

    const server_kexinit = try s.writeServerKexinit();
    s.server_kexinit_len = server_kexinit.len;
    try s.sendPacket(server_kexinit);

    // The guess, RFC 4253 section 7.1. See `Script.guessed_packet`.
    if (s.script.guessed_packet.len != 0) try s.sendPacket(s.script.guessed_packet);

    const client_kexinit = if (received) |payload| payload else blk: {
        const payload = try s.recvPacket();
        if (messages.idOf(payload) != messages.Id.kexinit) return error.FixtureKexinitExpected;
        break :blk payload;
    };
    if (client_kexinit.len > s.client_kexinit_storage.len) return error.FixtureKexinitTooLong;
    @memcpy(s.client_kexinit_storage[0..client_kexinit.len], client_kexinit);
    s.client_kexinit_len = client_kexinit.len;

    const parsed = try algorithms.parseKexinit(s.client_kexinit_storage[0..s.client_kexinit_len]);
    // Latched on the first exchange, the way OpenSSH latches it. See
    // `Script.drop_strict_on_rekey`.
    if (s.kex_count == 0) {
        s.strict_kex = s.script.strict_kex and parsed.kex.contains(algorithms.strict_kex_client);
    }

    // The client's list decides, RFC 4253 section 7.1, so the fixture
    // walks the client's names against its own offer.
    const chosen_c2s = try chooseCipher(parsed.cipher_client_to_server, s.script.cipher_names);
    const chosen_s2c = try chooseCipher(parsed.cipher_server_to_client, s.script.cipher_names);

    if (s.script.chatter_in_kex) try s.sendPacket("\x02\x00\x00\x00\x03bad");

    const init_payload = try s.recvPacket();
    var init_reader: wire.Reader = .init(init_payload);
    if (try init_reader.byte() != @intFromEnum(messages.Id.kex_ecdh_init)) {
        return error.FixtureEcdhInitExpected;
    }
    const client_public = try init_reader.string();
    if (client_public.len != kex.public_bytes) return error.FixtureClientPublicMalformed;

    // A different ephemeral key for each exchange, so a rekey really does
    // change the keys.
    var seed: [X25519.seed_length]u8 = @splat(0x60);
    seed[0] +%= @intCast(s.kex_count);
    const pair = try X25519.KeyPair.generateDeterministic(seed);
    const shared = try X25519.scalarmult(pair.secret_key, client_public[0..kex.public_bytes].*);

    const exchange_hash = try s.buildExchangeHash(.{
        .client_kexinit = s.client_kexinit_storage[0..s.client_kexinit_len],
        .server_kexinit = s.server_kexinit_storage[0..s.server_kexinit_len],
        .client_public = client_public,
        .server_public = &pair.public_key,
        .shared_secret = &shared,
    });

    const signed = if (s.script.forge_signature)
        [_]u8{0x00} ** kex.hash_bytes
    else
        exchange_hash;
    const signing_key = if (s.script.wrong_signing_key)
        try Ed25519.KeyPair.generateDeterministic(impostor_seed)
    else
        s.host_key;
    const signature = try signing_key.sign(&signed, null);

    var reply_storage: [512]u8 = undefined;
    var reply: wire.Writer = .init(&reply_storage);
    try reply.byte(@intFromEnum(messages.Id.kex_ecdh_reply));
    try reply.string(s.hostKeyBlob());
    try reply.string(&pair.public_key);
    var signature_storage: [128]u8 = undefined;
    var signature_writer: wire.Writer = .init(&signature_storage);
    try signature_writer.string("ssh-ed25519");
    try signature_writer.string(&signature.toBytes());
    try reply.string(signature_writer.written());
    try s.sendPacket(reply.written());

    if (!s.has_session_id) {
        s.session_id = exchange_hash;
        s.has_session_id = true;
    }

    try s.sendPacket(&.{@intFromEnum(messages.Id.newkeys)});
    if (s.send_cipher) |*old| old.deinit();
    s.send_cipher = s.deriveCipher(
        chosen_s2c,
        exchange_hash,
        &shared,
        .initial_iv_server_to_client,
        .encryption_key_server_to_client,
    );
    if (s.strict_kex) s.send_sequence = 0;

    const answer = try s.recvPacket();
    if (messages.idOf(answer) != messages.Id.newkeys) return error.FixtureNewkeysExpected;
    if (s.recv_cipher) |*old| old.deinit();
    s.recv_cipher = s.deriveCipher(
        chosen_c2s,
        exchange_hash,
        &shared,
        .initial_iv_client_to_server,
        .encryption_key_client_to_server,
    );
    if (s.strict_kex) s.recv_sequence = 0;

    s.kex_count += 1;
}

/// Runs the RFC 4252 phase from the server's side.
///
/// **This fixture verifies the `publickey` signature for real.** It builds
/// the blob of RFC 4252 section 7 by hand, straight off the list, and
/// checks the client's signature over it with the client's own public key.
/// `zurl_ssh.userauth.writeSignatureBlob` builds the same blob a different
/// way, so an attempt is accepted only when the two agree. See the module
/// comment for what that does and does not prove.
fn runAuth(s: *Server, script: AuthScript) !void {
    const request = try s.recvPacket();
    var r: wire.Reader = .init(request);
    if (try r.byte() != @intFromEnum(userauth.Id.service_request)) {
        return error.FixtureServiceRequestExpected;
    }
    if (!std.mem.eql(u8, try r.string(), userauth.service_userauth)) {
        return error.FixtureWrongService;
    }

    if (script.refuse_service) {
        var storage: [256]u8 = undefined;
        const payload = try messages.writeDisconnect(
            &storage,
            .service_not_available,
            "this fixture runs no userauth",
        );
        try s.sendPacket(payload);
        return;
    }

    var accept_storage: [128]u8 = undefined;
    var accept: wire.Writer = .init(&accept_storage);
    try accept.byte(@intFromEnum(userauth.Id.service_accept));
    const named = script.service_name orelse userauth.service_userauth;
    // An empty name writes no field at all, which is what some servers do
    // and what `userauth.parseServiceAccept` allows.
    if (named.len != 0) try accept.string(named);
    try s.sendPacket(accept.written());

    for (0..script.banner_count) |_| {
        if (script.banner.len == 0) break;
        try s.sendBanner(script.banner);
    }

    var partial_used = false;
    var change_sent = false;
    var rounds: usize = 0;
    while (rounds < script.max_requests) : (rounds += 1) {
        const payload = try s.recvPacket();
        var rr: wire.Reader = .init(payload);
        if (try rr.byte() != @intFromEnum(userauth.Id.request)) {
            return error.FixtureAuthRequestExpected;
        }
        const user = try rr.string();
        const wanted = try rr.string();
        const method = try rr.string();
        if (!std.mem.eql(u8, wanted, userauth.service_connection)) {
            return error.FixtureWrongRequestedService;
        }
        const user_ok = std.mem.eql(u8, user, script.user);

        if (std.mem.eql(u8, method, "none")) {
            if (user_ok and script.accept_none) return s.sendAuthSuccess();
            try s.sendAuthFailure(script.methods, false);
            continue;
        }

        if (std.mem.eql(u8, method, "publickey")) {
            const signed = try rr.boolean();
            const algorithm = try rr.string();
            const blob = try rr.string();

            if (!signed) {
                if (script.refuse_public_key_query) {
                    try s.sendAuthFailure(script.methods, false);
                    continue;
                }
                if (script.answer_public_key_query_with_success) {
                    return s.sendAuthSuccess();
                }
                var storage: [1024]u8 = undefined;
                var w: wire.Writer = .init(&storage);
                try w.byte(@intFromEnum(userauth.Id.method_specific));
                try w.string(algorithm);
                // A forged echo names the fixture's own host key, which
                // the client never sent.
                try w.string(if (script.forge_public_key_ok) s.hostKeyBlob() else blob);
                try s.sendPacket(w.written());
                continue;
            }

            const signature_blob = try rr.string();
            if (!rr.atEnd()) return error.FixtureAuthRequestTrailing;

            const named_key = script.public_key orelse &[_]u8{};
            const accepted = user_ok and
                script.public_key != null and
                std.mem.eql(u8, blob, named_key) and
                try s.checkSignature(user, algorithm, blob, signature_blob);
            if (accepted) {
                if (script.partial_success and !partial_used) {
                    partial_used = true;
                    try s.sendAuthFailure(script.methods, true);
                    continue;
                }
                return s.sendAuthSuccess();
            }
            try s.sendAuthFailure(script.methods, false);
            continue;
        }

        if (std.mem.eql(u8, method, "password")) {
            // This build never asks to change a password, so a request
            // that says it does is a client fault.
            if (try rr.boolean()) return error.FixturePasswordChangeSent;
            const password = try rr.string();

            if (script.password_change and !change_sent) {
                change_sent = true;
                var storage: [256]u8 = undefined;
                var w: wire.Writer = .init(&storage);
                try w.byte(@intFromEnum(userauth.Id.method_specific));
                try w.string("your password has expired");
                try w.string("");
                try s.sendPacket(w.written());
                continue;
            }

            const named_password = script.password orelse &[_]u8{};
            const accepted = user_ok and
                script.password != null and
                std.mem.eql(u8, password, named_password);
            if (accepted) {
                if (script.partial_success and !partial_used) {
                    partial_used = true;
                    try s.sendAuthFailure(script.methods, true);
                    continue;
                }
                return s.sendAuthSuccess();
            }
            try s.sendAuthFailure(script.methods, false);
            continue;
        }

        if (std.mem.eql(u8, method, "keyboard-interactive")) {
            _ = try rr.string();
            _ = try rr.string();

            var matched = user_ok and script.password != null;
            if (script.interactive_prompts == 0) matched = false;
            var round: usize = 0;
            while (round < script.interactive_rounds) : (round += 1) {
                const last = round + 1 == script.interactive_rounds;
                const prompts: u32 = if (last) script.interactive_prompts else 0;
                try s.sendInfoRequest(prompts, script.interactive_echo);

                const answer = try s.recvPacket();
                var ar: wire.Reader = .init(answer);
                if (try ar.byte() != @intFromEnum(userauth.Id.info_response)) {
                    return error.FixtureInfoResponseExpected;
                }
                const count = try ar.uint32();
                if (count != prompts) matched = false;
                for (0..count) |_| {
                    const given = try ar.string();
                    const named_password = script.password orelse &[_]u8{};
                    if (!std.mem.eql(u8, given, named_password)) matched = false;
                }
            }

            if (matched) {
                if (script.partial_success and !partial_used) {
                    partial_used = true;
                    try s.sendAuthFailure(script.methods, true);
                    continue;
                }
                return s.sendAuthSuccess();
            }
            try s.sendAuthFailure(script.methods, false);
            continue;
        }

        return error.FixtureUnknownAuthMethod;
    }
    return error.FixtureTooManyAuthRequests;
}

/// Checks a `publickey` signature the way a server does.
///
/// The blob is built here from the list in RFC 4252 section 7, and not
/// with `zurl_ssh.userauth`. A signature verifies only when the client
/// built the same bytes.
///
/// A signature that does not verify is `false` and never an error, because
/// a wrong signature is the client's answer and not a fixture fault.
fn checkSignature(
    s: *Server,
    user: []const u8,
    algorithm: []const u8,
    blob: []const u8,
    signature_blob: []const u8,
) !bool {
    // The algorithm name goes into the signed blob, so the fixture has to
    // check it. Without this a client could write any name it liked there
    // and still be accepted, and the tests would not pin the one field
    // that names the signature scheme.
    if (!std.mem.eql(u8, algorithm, "ssh-ed25519")) return false;

    var storage: [4096]u8 = undefined;
    var w: wire.Writer = .init(&storage);
    try w.string(&s.session_id);
    try w.byte(@intFromEnum(userauth.Id.request));
    try w.string(user);
    try w.string(userauth.service_connection);
    try w.string("publickey");
    try w.boolean(true);
    try w.string(algorithm);
    try w.string(blob);

    // The user's public key has the same wire form as a host key, so the
    // host key reader is what reads it.
    const key = hostkey.parse(blob, .ssh_ed25519) catch return false;
    hostkey.verify(key, signature_blob, w.written()) catch return false;
    return true;
}

/// Writes one `SSH_MSG_USERAUTH_BANNER`.
fn sendBanner(s: *Server, text: []const u8) !void {
    var storage: [userauth.max_banner_bytes + 64]u8 = undefined;
    var w: wire.Writer = .init(&storage);
    try w.byte(@intFromEnum(userauth.Id.banner));
    try w.string(text);
    try w.string("");
    try s.sendPacket(w.written());
}

/// Writes one `SSH_MSG_USERAUTH_INFO_REQUEST` with `prompts` questions.
fn sendInfoRequest(s: *Server, prompts: u32, echo: bool) !void {
    var storage: [1024]u8 = undefined;
    var w: wire.Writer = .init(&storage);
    try w.byte(@intFromEnum(userauth.Id.method_specific));
    try w.string("zurl fixture");
    try w.string("");
    try w.string("");
    try w.uint32(prompts);
    for (0..prompts) |_| {
        try w.string("Password:");
        try w.boolean(echo);
    }
    try s.sendPacket(w.written());
}

/// Writes a `SSH_MSG_USERAUTH_SUCCESS`.
fn sendAuthSuccess(s: *Server) !void {
    try s.sendPacket(&.{@intFromEnum(userauth.Id.success)});
    s.authenticated = true;
}

/// The fixture's own channel number. It differs from the client's on
/// purpose: RFC 4254 section 5.1 gives each side its own numbering, and a
/// fixture that used the same number for both would let a client that
/// echoed the wrong one pass.
const fixture_channel: u32 = 7;

/// Runs the RFC 4254 phase.
fn runConnection(s: *Server, script: ConnectionScript) !void {
    if (script.global_request) {
        // OpenSSH sends `hostkeys-00@openssh.com` right here, and it asks
        // for a reply. A client that never answered would leave a real
        // server waiting.
        var storage: [128]u8 = undefined;
        var w: wire.Writer = .init(&storage);
        try w.byte(@intFromEnum(connection.Id.global_request));
        try w.string("hostkeys-00@openssh.com");
        try w.boolean(true);
        try s.sendPacket(w.written());
    }

    // **The client answers the global request while this side is waiting
    // for the open**, so the answer arrives first. A fixture that took the
    // first packet as the open would report a fault for a client that did
    // exactly the right thing.
    const open_payload = try s.awaitConnection(.channel_open);
    var r: wire.Reader = .init(open_payload);
    _ = try r.byte();
    const channel_type = try r.string();
    if (!std.mem.eql(u8, channel_type, connection.session_channel_type)) {
        return error.FixtureChannelTypeUnexpected;
    }
    s.client_channel = try r.uint32();
    s.client_window = try r.uint32();
    s.client_max_packet = try r.uint32();
    s.local_window = script.window_bytes;

    if (script.refuse_open) |reason| {
        var storage: [256]u8 = undefined;
        const payload = try connection.writeOpenFailure(
            &storage,
            s.client_channel,
            reason,
            "this fixture was told to refuse",
        );
        try s.sendPacket(payload);
        return;
    }

    var storage: [64]u8 = undefined;
    var w: wire.Writer = .init(&storage);
    try w.byte(@intFromEnum(connection.Id.channel_open_confirmation));
    try w.uint32(s.client_channel);
    try w.uint32(fixture_channel);
    try w.uint32(script.window_bytes);
    try w.uint32(script.max_packet_bytes);
    try s.sendPacket(w.written());

    if (script.offer_channel) {
        // A client that took a channel it never asked for would carry a
        // forwarding it did not want.
        var offer_storage: [128]u8 = undefined;
        var offer: wire.Writer = .init(&offer_storage);
        try offer.byte(@intFromEnum(connection.Id.channel_open));
        try offer.string("x11");
        try offer.uint32(99);
        try offer.uint32(1024);
        try offer.uint32(1024);
        try s.sendPacket(offer.written());
    }

    // The request. `exec` and `subsystem` are read the same way, because
    // the grammar of the two is the same past the name.
    // The client's refusal of the channel this side offered arrives here,
    // for the reason the open above records.
    // **A real server refuses the requests it does not take and reads the
    // next one.** OpenSSH answers an `env` request from `AcceptEnv`, which
    // names nothing by default, and then runs the `exec` that follows it.
    // So this reads requests until one matches `accept_request`, and a name
    // that does not match gets `SSH_MSG_CHANNEL_FAILURE` and no more.
    //
    // `refuse_request` is the other shape: that one refuses whatever
    // arrives and stops, which is the server that will not do the thing at
    // all.
    var requests_read: usize = 0;
    while (true) {
        if (requests_read >= max_channel_requests) return error.FixtureTooManyRequests;
        requests_read += 1;

        const request_payload = try s.awaitConnection(.channel_request);
        const head = try connection.parseRequestHead(request_payload);
        if (head.recipient_channel != fixture_channel) return error.FixtureWrongChannel;
        const wanted = std.mem.eql(u8, head.request, script.accept_request);

        // **The command an `exec` request carried is kept, byte for byte.**
        // A quoting rule is worth only what the wire says, so a test
        // compares these bytes rather than trust the builder that wrote
        // them.
        if (std.mem.eql(u8, head.request, connection.exec_request)) {
            var command_reader: wire.Reader = .init(head.rest);
            const command = try command_reader.string();
            if (command.len > s.exec_command_storage.len) return error.FixtureExecCommandTooLong;
            @memcpy(s.exec_command_storage[0..command.len], command);
            s.exec_command_len = command.len;
        }

        // **The name and the value an `env` request carried are kept too**,
        // and for the same reason: a test that trusted the builder would
        // pass on a builder that wrote the two strings the wrong way round.
        if (std.mem.eql(u8, head.request, connection.env_request)) {
            var env_reader: wire.Reader = .init(head.rest);
            const name = try env_reader.string();
            const value = try env_reader.string();
            if (name.len > s.env_name_storage.len) return error.FixtureEnvNameTooLong;
            if (value.len > s.env_value_storage.len) return error.FixtureEnvValueTooLong;
            @memcpy(s.env_name_storage[0..name.len], name);
            s.env_name_len = name.len;
            @memcpy(s.env_value_storage[0..value.len], value);
            s.env_value_len = value.len;
        }

        if (head.want_reply) {
            const id: connection.Id = if (script.refuse_request or !wanted)
                .channel_failure
            else
                .channel_success;
            var reply_storage: [16]u8 = undefined;
            var reply: wire.Writer = .init(&reply_storage);
            try reply.byte(@intFromEnum(id));
            try reply.uint32(s.client_channel);
            try s.sendPacket(reply.written());
        }

        if (script.refuse_request) return;
        if (wanted) break;
    }

    if (script.stray_request) try s.sendStrayRequests(1);

    if (script.stderr_text.len != 0) try s.sendExtendedData(script.stderr_text);

    switch (script.service) {
        .idle => {},
        .write_body => try s.writeBody(script),
        .sink => try s.sinkBody(),
        .sftp => try s.runSftp(script),
        .scp => try s.runScp(script),
    }

    if (script.exit_status) |code| {
        var exit_storage: [64]u8 = undefined;
        var exit: wire.Writer = .init(&exit_storage);
        try exit.byte(@intFromEnum(connection.Id.channel_request));
        try exit.uint32(s.client_channel);
        try exit.string(connection.exit_status_request);
        try exit.boolean(false);
        try exit.uint32(code);
        try s.sendPacket(exit.written());
    }

    var eof_storage: [16]u8 = undefined;
    try s.sendPacket(try connection.writeEof(&eof_storage, s.client_channel));
    var close_storage: [16]u8 = undefined;
    try s.sendPacket(try connection.writeClose(&close_storage, s.client_channel));

    if (script.data_after_close) {
        // RFC 4254 section 5.3 forbids this. See
        // `ConnectionScript.data_after_close`.
        var late_storage: [frame_bytes]u8 = undefined;
        try s.sendPacket(try connection.writeData(&late_storage, s.client_channel, "late"));
    }

    // **The socket stays open until the client closes the channel.** A
    // real server waits for the other half of RFC 4254 section 5.3, and a
    // fixture that closed here would meet the client's last
    // `SSH_MSG_CHANNEL_WINDOW_ADJUST` with a reset. That reads as a client
    // fault and is not one: the client is still draining bytes this side
    // already wrote.
    var rounds: usize = 0;
    while (rounds < 4096 and !s.client_closed) : (rounds += 1) {
        const payload = s.recvConnectionPacket() catch return;
        s.applyClientMessage(payload) catch return;
    }
}

/// Sends `count` channel requests for a name the client does not act on.
///
/// Each one costs the client a read and moves nothing, which is what
/// `zurl_ssh.Channel.max_idle_steps` bounds.
fn sendStrayRequests(s: *Server, count: usize) !void {
    var sent: usize = 0;
    while (sent < count) : (sent += 1) {
        var storage: [64]u8 = undefined;
        var w: wire.Writer = .init(&storage);
        try w.byte(@intFromEnum(connection.Id.channel_request));
        try w.uint32(s.client_channel);
        try w.string("keepalive@openssh.com");
        try w.boolean(false);
        try s.sendPacket(w.written());
    }
}

/// Writes `script.body` in chunks, waiting for window when it runs out.
///
/// **This is the half of the flow control the client is tested against.**
/// A client that never wrote a `SSH_MSG_CHANNEL_WINDOW_ADJUST` would stop
/// this loop for good with a window smaller than the body.
fn writeBody(s: *Server, script: ConnectionScript) !void {
    var at: usize = 0;
    while (at < script.body.len) {
        try s.sendStrayRequests(script.stray_requests_per_chunk);
        while (s.client_window == 0) {
            const payload = try s.recvConnectionPacket();
            try s.applyClientMessage(payload);
        }
        const room = @min(@as(usize, s.client_window), @as(usize, s.client_max_packet));
        const take = @min(script.body.len - at, @min(room, script.body_chunk_bytes));
        var storage: [frame_bytes]u8 = undefined;
        const payload = try connection.writeData(
            &storage,
            s.client_channel,
            script.body[at..][0..take],
        );
        try s.sendPacket(payload);
        s.client_window -= @intCast(take);
        at += take;
    }
}

/// Reads everything the client writes until its end of file, counting it
/// and giving the window back.
fn sinkBody(s: *Server) !void {
    var total: u64 = 0;
    while (true) {
        const payload = try s.recvConnectionPacket();
        const id = connection.idOf(payload);
        if (id == .channel_close) {
            s.client_closed = true;
            break;
        }
        if (id == .channel_eof) break;
        if (id == .channel_data) {
            const got = try connection.parseData(payload);
            total += got.bytes.len;
            s.received.store(total, .release);
            try s.creditClient(@intCast(got.bytes.len));
            continue;
        }
        try s.applyClientMessage(payload);
    }
}

/// The longest `exec` command this fixture keeps.
///
/// 8 KiB, which is longer than every path a test sends and longer than any
/// path a person types. **A longer command is
/// `error.FixtureExecCommandTooLong` and never a command cut short**, so a
/// test that compared a truncated copy would fail as a fixture fault rather
/// than pass on half the bytes.
pub const max_exec_command_bytes: usize = 8 * 1024;

/// How many channel requests the fixture reads before it gives up.
///
/// **A server that refuses a request reads the next one**, so this loop
/// has to turn more than once and therefore has to stop. A real client
/// sends one or two: an `env` the server may refuse, and the `exec` that
/// follows it. Eight is far above that and still ends a test that would
/// otherwise wait for a request nobody sends.
pub const max_channel_requests: usize = 8;

/// The largest `env` name and value this fixture keeps. `GIT_PROTOCOL` and
/// `version=2` are the ones a real client sends, and both are tiny.
pub const max_env_name_bytes: usize = 256;
pub const max_env_value_bytes: usize = 1024;

/// Stages channel bytes for the rcp service.
///
/// The rcp protocol is a byte stream inside a byte stream: a control line
/// ends on a newline and a file ends on a count, and neither ends on a
/// `SSH_MSG_CHANNEL_DATA` boundary. This holds the bytes that arrived and
/// that no read has taken.
const ScpStream = struct {
    server: *Server,
    storage: [8 * 1024]u8 = undefined,
    len: usize = 0,
    at: usize = 0,

    /// Reads one byte, or null when the client sent its end of file.
    fn readByte(t: *ScpStream) !?u8 {
        if (t.at == t.len) {
            try t.fill();
            if (t.at == t.len) return null;
        }
        const byte = t.storage[t.at];
        t.at += 1;
        return byte;
    }

    /// Reads one line into `out`, with the newline cut off.
    fn readLine(t: *ScpStream, out: []u8) ![]const u8 {
        var at: usize = 0;
        while (true) {
            const byte = (try t.readByte()) orelse return error.FixtureScpEarlyEnd;
            if (byte == '\n') return out[0..at];
            if (at == out.len) return error.FixtureScpLineTooLong;
            out[at] = byte;
            at += 1;
        }
    }

    /// Reads exactly `out.len` bytes.
    fn readExact(t: *ScpStream, out: []u8) !void {
        var at: usize = 0;
        while (at < out.len) {
            const byte = (try t.readByte()) orelse return error.FixtureScpEarlyEnd;
            out[at] = byte;
            at += 1;
        }
    }

    /// Reads one round of channel data, giving the window back.
    fn fill(t: *ScpStream) !void {
        t.at = 0;
        t.len = 0;
        while (t.len == 0) {
            const payload = try t.server.recvConnectionPacket();
            const id = connection.idOf(payload);
            if (id == .channel_eof) return;
            if (id == .channel_close) {
                t.server.client_closed = true;
                return;
            }
            if (id != .channel_data) {
                try t.server.applyClientMessage(payload);
                continue;
            }
            const got = try connection.parseData(payload);
            if (got.bytes.len > t.storage.len) return error.FixtureScpBufferFull;
            @memcpy(t.storage[0..got.bytes.len], got.bytes);
            t.len = got.bytes.len;
            try t.server.creditClient(@intCast(got.bytes.len));
        }
    }
};

/// Runs the rcp protocol a remote `scp` speaks.
///
/// **Every byte here is written by hand.** See `ChannelService.scp`.
fn runScp(s: *Server, script: ConnectionScript) !void {
    var stream: ScpStream = .{ .server = s };
    if (script.scp.receive) return s.runScpSink(script, &stream);
    return s.runScpSource(script, &stream);
}

/// `scp -pf`: writes one file to the client.
fn runScpSource(s: *Server, script: ConnectionScript, stream: *ScpStream) !void {
    const scp = script.scp;

    // A remote `scp -f` writes nothing until the client says it is ready.
    const ready = (try stream.readByte()) orelse return error.FixtureScpEarlyEnd;
    if (ready != 0) return error.FixtureScpBadAck;

    if (scp.fatal) |text| {
        try s.writeScp("\x02");
        try s.writeScp(text);
        try s.writeScp("\n");
        return;
    }

    if (scp.warning) |text| {
        try s.writeScp("\x01");
        try s.writeScp(text);
        try s.writeScp("\n");
        return;
    }

    var times: usize = 0;
    const time_lines: usize = if (scp.send_times) 1 + scp.extra_time_lines else 0;
    while (times < time_lines) : (times += 1) {
        try s.writeScp("T1788675695 0 1788675718 0\n");
        const ack = (try stream.readByte()) orelse return error.FixtureScpEarlyEnd;
        if (ack != 0) return error.FixtureScpBadAck;
    }

    var line_storage: [1024]u8 = undefined;
    const line = if (scp.control_line) |raw|
        raw
    else blk: {
        var size_storage: [24]u8 = undefined;
        const size = if (scp.size_override) |text|
            text
        else
            try std.fmt.bufPrint(&size_storage, "{d}", .{scp.contents.len});
        break :blk try std.fmt.bufPrint(
            &line_storage,
            "C{s} {s} {s}",
            .{ scp.mode, size, scp.name },
        );
    };
    try s.writeScp(line);
    try s.writeScp("\n");

    const ack = (try stream.readByte()) orelse return error.FixtureScpEarlyEnd;
    if (ack != 0) return error.FixtureScpBadAck;

    var at: usize = 0;
    while (at < scp.contents.len) {
        const take = @min(scp.contents.len - at, scp.body_chunk_bytes);
        try s.writeScp(scp.contents[at..][0..take]);
        at += take;
    }

    if (scp.omit_end_status) return;
    try s.writeScp("\x00");

    // The client answers the end of the file, and a real `scp` waits for
    // that byte before it exits.
    _ = try stream.readByte();
}

/// `scp -t`: takes one file from the client.
fn runScpSink(s: *Server, script: ConnectionScript, stream: *ScpStream) !void {
    const scp = script.scp;

    try s.writeScp("\x00");

    var line_storage: [1024]u8 = undefined;
    const line = try stream.readLine(&line_storage);
    if (line.len == 0 or line[0] != 'C') return error.FixtureScpNotAFileLine;

    if (scp.fatal) |text| {
        try s.writeScp("\x02");
        try s.writeScp(text);
        try s.writeScp("\n");
        return;
    }

    // `C<mode> <size> <name>`. The fixture reads the size, because the size
    // is what says when the body ends.
    var fields = std.mem.splitScalar(u8, line[1..], ' ');
    _ = fields.next() orelse return error.FixtureScpNotAFileLine;
    const size_text = fields.next() orelse return error.FixtureScpNotAFileLine;
    const size = std.fmt.parseInt(usize, size_text, 10) catch
        return error.FixtureScpNotAFileLine;
    if (size > s.upload_storage.len) return error.FixtureUploadTooLong;

    try s.writeScp("\x00");
    try stream.readExact(s.upload_storage[0..size]);
    s.received.store(size, .release);

    const end = (try stream.readByte()) orelse return error.FixtureScpEarlyEnd;
    if (end != 0) return error.FixtureScpBadAck;
    try s.writeScp("\x00");

    // The client sends its end of file next, and the caller's loop reads
    // it once this returns.
}

/// Writes `bytes` on the channel, waiting for window when it runs out.
fn writeScp(s: *Server, bytes: []const u8) !void {
    var at: usize = 0;
    while (at < bytes.len) {
        while (s.client_window == 0) {
            const payload = try s.recvConnectionPacket();
            try s.applyClientMessage(payload);
        }
        const room = @min(@as(usize, s.client_window), @as(usize, s.client_max_packet));
        const take = @min(bytes.len - at, room);
        var storage: [frame_bytes]u8 = undefined;
        const payload = try connection.writeData(
            &storage,
            s.client_channel,
            bytes[at..][0..take],
        );
        try s.sendPacket(payload);
        s.client_window -= @intCast(take);
        at += take;
    }
}

/// The SFTP packet types this fixture reads and writes.
const fxp_init = 1;
const fxp_version = 2;
const fxp_open = 3;
const fxp_close = 4;
const fxp_read = 5;
const fxp_write = 6;
const fxp_fstat = 8;
const fxp_opendir = 11;
const fxp_readdir = 12;
const fxp_realpath = 16;
const fxp_stat = 17;
const fxp_status = 101;
const fxp_handle = 102;
const fxp_data = 103;
const fxp_name = 104;
const fxp_attrs = 105;

const fx_ok = 0;
const fx_eof = 1;
const fx_no_such_file = 2;

/// The handle the fixture hands out for a file.
const file_handle = "fixture-file";
/// The handle the fixture hands out for a directory.
const directory_handle = "fixture-dir";

/// Runs the SFTP subsystem over the channel.
///
/// **Every packet here is written by hand with `wire.Writer`.** See
/// `ChannelService.sftp` for why.
fn runSftp(s: *Server, script: ConnectionScript) !void {
    const sftp = script.sftp;
    var listed = false;

    while (true) {
        const body = s.readSftpPacket() catch |err| switch (err) {
            // The client closed the channel, which is how a session ends.
            error.FixtureChannelEnded => return,
            else => return err,
        };
        if (body.len == 0) return error.FixtureEmptySftpPacket;

        var r: wire.Reader = .init(body);
        const kind = try r.byte();
        if (kind == fxp_init) {
            var storage: [64]u8 = undefined;
            var w: wire.Writer = .init(&storage);
            try w.byte(fxp_version);
            try w.uint32(sftp.version);
            try s.sendSftpPacket(w.written());
            continue;
        }

        const id = try r.uint32();
        switch (kind) {
            fxp_open => {
                const path = try r.string();
                if (sftp.open_status) |status| {
                    try s.sendSftpStatus(id, status, "the fixture was told to refuse");
                } else if (std.mem.eql(u8, path, sftp.path)) {
                    try s.sendSftpHandle(id, file_handle);
                } else {
                    try s.sendSftpStatus(id, fx_no_such_file, "no such file");
                }
            },
            fxp_opendir => {
                const path = try r.string();
                if (std.mem.eql(u8, path, sftp.path)) {
                    listed = false;
                    try s.sendSftpHandle(id, directory_handle);
                } else {
                    try s.sendSftpStatus(id, fx_no_such_file, "no such directory");
                }
            },
            fxp_readdir => {
                _ = try r.string();
                if (listed or sftp.entries.len == 0) {
                    try s.sendSftpStatus(id, fx_eof, "end of listing");
                } else {
                    listed = true;
                    try s.sendSftpNames(id, sftp.entries);
                }
            },
            fxp_realpath => {
                const path = try r.string();
                try s.sendSftpNames(id, &.{.{ path, path }});
            },
            fxp_stat, fxp_fstat => {
                if (kind == fxp_stat) _ = try r.string() else _ = try r.string();
                try s.sendSftpAttributes(id, sftp.contents.len, 0o100644);
            },
            fxp_read => {
                _ = try r.string();
                const offset = try r.uint64();
                const want = try r.uint32();
                if (offset >= sftp.contents.len) {
                    try s.sendSftpStatus(id, fx_eof, "end of file");
                    continue;
                }
                const left = sftp.contents.len - @as(usize, @intCast(offset));
                const take = @min(@min(left, want), sftp.read_chunk_bytes);
                try s.sendSftpData(id, sftp.contents[@intCast(offset)..][0..take]);
            },
            fxp_write => {
                _ = try r.string();
                _ = try r.uint64();
                const data = try r.string();
                if (!sftp.accept_write) {
                    try s.sendSftpStatus(id, fx_no_such_file, "this fixture takes no upload");
                    continue;
                }
                const at = s.received.load(.acquire);
                if (at + data.len > s.upload_storage.len) return error.FixtureUploadTooLong;
                @memcpy(s.upload_storage[@intCast(at)..][0..data.len], data);
                s.received.store(at + data.len, .release);
                try s.sendSftpStatus(id, fx_ok, "");
            },
            fxp_close => {
                _ = try r.string();
                try s.sendSftpStatus(id, fx_ok, "");
            },
            else => try s.sendSftpStatus(id, fx_no_such_file, "the fixture does not answer this"),
        }
    }
}

/// Reads one whole SFTP packet off the channel and returns its body.
fn readSftpPacket(s: *Server) ![]const u8 {
    try s.fillSftp(4);
    const declared = std.mem.readInt(u32, s.sftp_storage[s.sftp_at..][0..4], .big);
    if (declared == 0 or declared > s.sftp_storage.len - 4) return error.FixtureSftpLength;
    try s.fillSftp(4 + @as(usize, declared));
    const body = s.sftp_storage[s.sftp_at + 4 ..][0..declared];
    s.sftp_at += 4 + @as(usize, declared);
    return body;
}

/// Reads channel data until the SFTP buffer holds `want` bytes.
fn fillSftp(s: *Server, want: usize) !void {
    while (s.sftp_len - s.sftp_at < want) {
        if (s.sftp_at != 0) {
            std.mem.copyForwards(u8, s.sftp_storage[0..], s.sftp_storage[s.sftp_at..s.sftp_len]);
            s.sftp_len -= s.sftp_at;
            s.sftp_at = 0;
        }
        const payload = try s.recvConnectionPacket();
        const id = connection.idOf(payload) orelse return error.FixtureEmptyPacket;
        if (id == .channel_close) {
            s.client_closed = true;
            return error.FixtureChannelEnded;
        }
        if (id == .channel_eof) return error.FixtureChannelEnded;
        if (id != .channel_data) {
            try s.applyClientMessage(payload);
            continue;
        }
        const got = try connection.parseData(payload);
        if (got.bytes.len > s.sftp_storage.len - s.sftp_len) return error.FixtureSftpBufferFull;
        @memcpy(s.sftp_storage[s.sftp_len..][0..got.bytes.len], got.bytes);
        s.sftp_len += got.bytes.len;
        try s.creditClient(@intCast(got.bytes.len));
    }
}

/// Writes one SFTP packet, in `SSH_MSG_CHANNEL_DATA` messages that fit the
/// client's window and its message size.
fn sendSftpPacket(s: *Server, body: []const u8) !void {
    var head: [4]u8 = undefined;
    std.mem.writeInt(u32, &head, @intCast(body.len), .big);

    var at: usize = 0;
    const whole = 4 + body.len;
    while (at < whole) {
        while (s.client_window == 0) {
            const payload = try s.recvConnectionPacket();
            try s.applyClientMessage(payload);
        }
        const room = @min(@as(usize, s.client_window), @as(usize, s.client_max_packet));
        const take = @min(whole - at, room);

        var storage: [frame_bytes]u8 = undefined;
        var w: wire.Writer = .init(&storage);
        try w.byte(@intFromEnum(connection.Id.channel_data));
        try w.uint32(s.client_channel);
        try w.uint32(@intCast(take));
        var wrote: usize = 0;
        while (wrote < take) : (wrote += 1) {
            const index = at + wrote;
            try w.byte(if (index < 4) head[index] else body[index - 4]);
        }
        try s.sendPacket(w.written());
        s.client_window -= @intCast(take);
        at += take;
    }
}

fn sendSftpStatus(s: *Server, id: u32, status: u32, message: []const u8) !void {
    var storage: [512]u8 = undefined;
    var w: wire.Writer = .init(&storage);
    try w.byte(fxp_status);
    try w.uint32(id);
    try w.uint32(status);
    try w.string(message);
    try w.string("");
    try s.sendSftpPacket(w.written());
}

fn sendSftpHandle(s: *Server, id: u32, handle: []const u8) !void {
    var storage: [128]u8 = undefined;
    var w: wire.Writer = .init(&storage);
    try w.byte(fxp_handle);
    try w.uint32(id);
    try w.string(handle);
    try s.sendSftpPacket(w.written());
}

fn sendSftpData(s: *Server, id: u32, data: []const u8) !void {
    if (data.len + 9 > s.sftp_out_storage.len) return error.FixtureSftpDataTooLong;
    var w: wire.Writer = .init(&s.sftp_out_storage);
    try w.byte(fxp_data);
    try w.uint32(id);
    try w.string(data);
    try s.sendSftpPacket(w.written());
}

fn sendSftpAttributes(s: *Server, id: u32, size: usize, mode: u32) !void {
    var storage: [64]u8 = undefined;
    var w: wire.Writer = .init(&storage);
    try w.byte(fxp_attrs);
    try w.uint32(id);
    // `SSH_FILEXFER_ATTR_SIZE` and `SSH_FILEXFER_ATTR_PERMISSIONS`.
    try w.uint32(0x0000_0005);
    try w.uint64(size);
    try w.uint32(mode);
    try s.sendSftpPacket(w.written());
}

fn sendSftpNames(s: *Server, id: u32, entries: []const [2][]const u8) !void {
    var storage: [4096]u8 = undefined;
    var w: wire.Writer = .init(&storage);
    try w.byte(fxp_name);
    try w.uint32(id);
    try w.uint32(@intCast(entries.len));
    for (entries) |entry| {
        try w.string(entry[0]);
        try w.string(entry[1]);
        // An ATTRS with no flag set.
        try w.uint32(0);
    }
    try s.sendSftpPacket(w.written());
}

/// Gives the client back the room its data spent.
fn creditClient(s: *Server, taken: u32) !void {
    if (taken > s.local_window) return error.FixtureClientPastWindow;
    s.local_window -= taken;
    if (s.local_window > s.script.connection.?.window_bytes / 2) return;
    const add = s.script.connection.?.window_bytes - s.local_window;
    var storage: [16]u8 = undefined;
    try s.sendPacket(try connection.writeWindowAdjust(&storage, s.client_channel, add));
    s.local_window += add;
}

fn sendExtendedData(s: *Server, text: []const u8) !void {
    var storage: [4096]u8 = undefined;
    var w: wire.Writer = .init(&storage);
    try w.byte(@intFromEnum(connection.Id.channel_extended_data));
    try w.uint32(s.client_channel);
    try w.uint32(@intFromEnum(connection.ExtendedDataType.stderr));
    try w.string(text);
    try s.sendPacket(w.written());
}

/// Applies a message that arrived while the fixture was waiting for
/// something else.
fn applyClientMessage(s: *Server, payload: []const u8) !void {
    const id = connection.idOf(payload) orelse return error.FixtureEmptyPacket;
    switch (id) {
        .channel_window_adjust => {
            const got = try connection.parseWindowAdjust(payload);
            if (got.recipient_channel != fixture_channel) return error.FixtureWrongChannel;
            s.client_window +%= got.add;
        },
        .channel_data => {
            const got = try connection.parseData(payload);
            try s.creditClient(@intCast(got.bytes.len));
        },
        .channel_close => s.client_closed = true,
        .channel_eof, .channel_failure, .request_failure => {},
        else => return error.FixtureUnexpectedConnectionMessage,
    }
}

/// Reads until a packet of type `wanted` arrives.
///
/// A client answers a global request and refuses an offered channel while
/// this side is waiting for something else, and both of those are exactly
/// what a client should do. They are read and dropped here.
fn awaitConnection(s: *Server, wanted: connection.Id) ![]const u8 {
    var rounds: usize = 0;
    while (rounds < 16) : (rounds += 1) {
        const payload = try s.recvConnectionPacket();
        const id = connection.idOf(payload) orelse return error.FixtureEmptyPacket;
        if (id == wanted) return payload;
        switch (id) {
            .request_failure, .request_success, .channel_open_failure => continue,
            else => return error.FixtureUnexpectedConnectionMessage,
        }
    }
    return error.FixtureTooManyPackets;
}

/// Reads one packet of the connection phase, running a key exchange when
/// the client asks for one.
fn recvConnectionPacket(s: *Server) ![]const u8 {
    var rounds: usize = 0;
    while (rounds < 64) : (rounds += 1) {
        const payload = try s.recvPacket();
        const id = messages.idOf(payload) orelse return error.FixtureEmptyPacket;
        if (id == .kexinit) {
            try s.runKexServer(payload);
            continue;
        }
        return payload;
    }
    return error.FixtureTooManyPackets;
}

/// Writes a `SSH_MSG_USERAUTH_FAILURE`.
fn sendAuthFailure(s: *Server, methods: []const u8, partial: bool) !void {
    var storage: [1024]u8 = undefined;
    var w: wire.Writer = .init(&storage);
    try w.byte(@intFromEnum(userauth.Id.failure));
    try w.string(methods);
    try w.boolean(partial);
    try s.sendPacket(w.written());
}

/// The first name on `theirs` that `ours` also names.
fn chooseCipher(theirs: wire.NameList, ours: []const u8) !cipher.Algorithm {
    const offer: wire.NameList = .{ .text = ours };
    var it = theirs.iterator();
    while (it.next()) |candidate| {
        if (offer.contains(candidate)) {
            return cipher.fromName(candidate) orelse return error.FixtureCipherUnknown;
        }
    }
    return error.FixtureNoCommonCipher;
}

/// What changes between one exchange hash and the next.
const HashParts = struct {
    client_kexinit: []const u8,
    server_kexinit: []const u8,
    client_public: []const u8,
    server_public: []const u8,
    shared_secret: []const u8,
};

/// Builds the exchange hash by writing the whole input into one buffer.
///
/// **This is the independent path.** `zurl_ssh.kex.exchangeHash` hashes
/// the same fields one at a time, and a handshake completes only when the
/// two agree. See the module comment for what that does and does not
/// prove.
fn buildExchangeHash(s: *Server, parts: HashParts) ![kex.hash_bytes]u8 {
    var storage: [16384]u8 = undefined;
    var w: wire.Writer = .init(&storage);
    try w.string(s.client_version_storage[0..s.client_version_len]);
    try w.string(version.withoutLineEnding(s.script.identification));
    try w.string(parts.client_kexinit);
    try w.string(parts.server_kexinit);
    try w.string(s.hostKeyBlob());
    try w.string(parts.client_public);
    try w.string(parts.server_public);
    try w.mpint(parts.shared_secret);

    var digest: [kex.hash_bytes]u8 = undefined;
    Sha256.hash(w.written(), &digest, .{});
    return digest;
}

fn deriveCipher(
    s: *const Server,
    algorithm: cipher.Algorithm,
    exchange_hash: [kex.hash_bytes]u8,
    shared: []const u8,
    iv_purpose: kex.KeyPurpose,
    key_purpose: kex.KeyPurpose,
) cipher.State {
    var key_material: [cipher.max_key_bytes]u8 = undefined;
    var iv_material: [cipher.max_iv_bytes]u8 = undefined;
    const key = key_material[0..cipher.keyBytes(algorithm)];
    const iv = iv_material[0..cipher.ivBytes(algorithm)];
    kex.deriveKey(key, shared, exchange_hash, key_purpose, &s.session_id);
    kex.deriveKey(iv, shared, exchange_hash, iv_purpose, &s.session_id);
    return .init(algorithm, key, iv);
}

/// Builds this fixture's `SSH_MSG_KEXINIT` from its script.
fn writeServerKexinit(s: *Server) ![]u8 {
    var w: wire.Writer = .init(&s.server_kexinit_storage);
    try w.byte(@intFromEnum(messages.Id.kexinit));
    try w.bytes(&[_]u8{0x5c} ** algorithms.cookie_bytes);
    const offer_marker = s.script.strict_kex and
        !(s.script.drop_strict_on_rekey and s.kex_count != 0);
    if (offer_marker) {
        try w.nameList(&.{ s.script.kex_names, algorithms.strict_kex_server });
    } else {
        try w.nameList(&.{s.script.kex_names});
    }
    try w.nameList(&.{s.script.host_key_names});
    try w.nameList(&.{s.script.cipher_names});
    try w.nameList(&.{s.script.cipher_names});
    try w.nameList(&.{});
    try w.nameList(&.{});
    try w.nameList(&.{s.script.compression_names});
    try w.nameList(&.{s.script.compression_names});
    try w.nameList(&.{});
    try w.nameList(&.{});
    try w.boolean(s.script.guessed_packet.len != 0);
    try w.uint32(0);
    return w.written();
}

fn sendPacket(s: *Server, payload: []const u8) !void {
    const writer = s.writer orelse return error.FixtureNotConnected;
    const block = if (s.send_cipher) |c| c.block() else packet.min_block_bytes;
    const aad = if (s.send_cipher) |c| cipher.lengthIsAad(c.algorithm) else false;
    const body = packet.bodyLen(payload.len, block, aad);
    if (4 + body + cipher.tag_bytes > s.out_frame.len) return error.FixturePacketTooLong;

    const padding_len = packet.paddingLen(payload.len, block, aad);
    var padding: [255]u8 = @splat(0xa5);
    const frame = s.out_frame[0 .. 4 + body];
    std.mem.writeInt(u32, frame[0..4], @intCast(body), .big);
    packet.writeBody(frame[4..], payload, padding[0..padding_len]);

    if (s.send_cipher) |*c| {
        var tag: [cipher.tag_bytes]u8 = undefined;
        c.seal(s.send_sequence, frame, &tag);
        try writer.writeAll(frame);
        try writer.writeAll(&tag);
    } else {
        try writer.writeAll(frame);
    }
    try writer.flush();
    s.send_sequence +%= 1;
}

fn recvPacket(s: *Server) ![]const u8 {
    const reader = s.reader orelse return error.FixtureNotConnected;
    const block = if (s.recv_cipher) |c| c.block() else packet.min_block_bytes;
    const aad = if (s.recv_cipher) |c| cipher.lengthIsAad(c.algorithm) else false;

    var head: [4]u8 = undefined;
    try zurl_net.bounded.readExact(reader, testing.io, &head, read_stall);
    const length = if (s.recv_cipher) |*c|
        c.readLength(s.recv_sequence, head)
    else
        std.mem.readInt(u32, &head, .big);
    try packet.checkLength(length, block, aad, packet.max_packet_bytes);
    if (4 + length > s.in_frame.len) return error.FixturePacketTooLong;

    const frame = s.in_frame[0 .. 4 + length];
    @memcpy(frame[0..4], &head);
    try zurl_net.bounded.readExact(reader, testing.io, frame[4..], read_stall);
    if (s.recv_cipher) |*c| {
        var tag: [cipher.tag_bytes]u8 = undefined;
        try zurl_net.bounded.readExact(reader, testing.io, &tag, read_stall);
        try c.open(s.recv_sequence, frame, tag);
    }
    s.recv_sequence +%= 1;
    return packet.payloadOf(frame[4..]);
}
