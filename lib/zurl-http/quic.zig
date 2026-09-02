//! One QUIC connection over a UDP socket: the datagram loop, the packet
//! builder, and the join between the handshake, loss recovery, and the
//! stream table.
//!
//! `zurl-quic` reads and writes packets, `zurl-quic-tls` runs the
//! handshake, and `zurl-quic/Streams.zig` holds the streams. None of them
//! opens a socket. **This file is the one that does**, and it is the only
//! file in the HTTP/3 path that touches the network.
//!
//! ## UDP has no connection, so this file makes one
//!
//! A stream socket refuses a byte from anybody but the peer. A datagram
//! socket does not: it hands over whatever arrived, with a source address
//! the sender wrote. Two rules answer that, and both are here:
//!
//! 1. **A datagram from another address is dropped and never processed.**
//!    `receive` compares the source against the address this connection
//!    dialed, before a byte reaches the packet parser. The same fault was
//!    found in the TFTP fetcher at the P2 review, where the first datagram
//!    from anybody became the peer.
//! 2. **A packet that does not open under this connection's keys is
//!    dropped.** RFC 9001 section 5.3 makes that the real authentication:
//!    an address is guessable and an AEAD tag is not. `Session.failedOpen`
//!    counts every one, and it stops the connection at the integrity limit
//!    of RFC 9001 section 6.6.
//!
//! The first rule is cheap and the second is the one that decides. Neither
//! is enough alone: the address check keeps an off-path sender from
//! spending this side's cycles on trial decryptions, and the tag check is
//! what makes a spoofed source useless.
//!
//! ## Retransmission
//!
//! Every packet this side sends is recorded with the frames it carried,
//! in `records`. An `ACK` frame resolves the records it names, and a loss
//! puts their frames back in the queue they came from. **A stream's bytes
//! and the handshake's bytes go back into the same kind of buffer**: a
//! `zurl_quic.SendBuffer`, which holds what is not acknowledged and hands
//! out the next run to send. So there is one retransmission rule and not
//! two, and the CRYPTO stream of each level uses it as well.
//!
//! ## What is not here
//!
//! No HTTP. `h3.zig` is the engine above, and it speaks to this file
//! through streams alone. No connection migration, no path validation, no
//! 0-RTT, and no server side.

const std = @import("std");
const Io = std.Io;
const quic = @import("zurl-quic");
const quic_tls = @import("zurl-quic-tls");

const packet = quic.packet;
const protection = quic.protection;
const header_protection = quic.header_protection;
const frame = quic.frame;
const loss = quic.loss;
const stream_mod = quic.stream;
const transport_parameters = quic.transport_parameters;

/// The largest datagram this side sends.
///
/// **1350 bytes, not 1500.** RFC 9000 section 14 makes 1200 the size every
/// path must carry and leaves anything larger to path discovery, which
/// this build does not do. 1350 leaves room for an IPv6 header, a UDP
/// header, and a tunnel, which is the number most QUIC clients settle on
/// for the same reason.
pub const max_datagram_out: usize = 1350;

/// The largest datagram this side reads.
///
/// A peer that sends more than this has its datagram cut by the operating
/// system, and `IncomingMessage.Flags.trunc` says so. A cut packet fails
/// its AEAD tag, so it is dropped anyway; the flag lets it be counted as
/// the fault it is rather than as a forged packet.
pub const max_datagram_in: usize = 1500;

/// How many connection id bytes this side gives itself.
///
/// Eight is what RFC 9000 section 5.1 suggests and what every QUIC client
/// uses. It goes in the Source Connection Id of the client's Initial
/// packets and comes back as the Destination Connection Id of every packet
/// the server sends.
pub const connection_id_len: usize = 8;

/// How many sent packets this side remembers the frames of.
///
/// **A packet whose record is gone cannot be put back on the wire**, so
/// this is a hard bound on what may be in flight and not a cache. The
/// builder stops when the store is full, which is the same backpressure
/// the congestion window gives.
pub const max_records: usize = 256;

/// How many retransmittable frames one packet may carry.
///
/// A packet holds an `ACK`, one `STREAM` run, and a few window updates.
/// Eight is above what the builder can put in one.
pub const max_frames_per_packet: usize = 8;

/// How many `PATH_RESPONSE` frames one connection writes.
///
/// RFC 9000 section 8.2.2 makes an answer to a `PATH_CHALLENGE` mandatory
/// for every endpoint, and this side must answer whether or not it
/// migrates: a server that probes the path and hears nothing decides the
/// path is dead and stops sending. So the answer is written, and it is
/// counted here because a peer that challenges for ever would otherwise
/// make this side write for ever.
///
/// Each challenge arrives in a packet the peer had to seal, so this is not
/// free work for the peer the way an empty frame is. A server probes a
/// path a few times over the life of a transfer, so this number is far
/// past any honest peer. Past it a challenge is dropped and counted rather
/// than answered, and the connection carries on.
pub const max_path_responses: u64 = 1024;

/// The answer this side owes a `PATH_CHALLENGE`, RFC 9000 section 8.2.2.
///
/// **A client that never migrates still has to answer.** Section 8.2.2
/// makes the `PATH_RESPONSE` mandatory for every endpoint that receives a
/// challenge, and the reason is the peer's and not this side's: a server
/// probes the path after a NAT rebinding, and a server that hears nothing
/// decides the path is dead and stops sending. The transfer would then
/// stall until the idle timer with nothing to report.
///
/// **One slot and not a queue.** Section 8.2.2 says an endpoint answers
/// the challenge it received. A peer that sends a second challenge before
/// the first answer went out has said the newer data is the one it waits
/// for, so the newer data replaces the older. A queue would let the peer
/// choose how much memory this side holds.
///
/// **A lost answer is not sent again.** Section 13.3 keeps
/// `PATH_RESPONSE` out of the frames an endpoint retransmits: the peer
/// challenges again instead. So the frame is written and never tracked
/// for loss recovery.
pub const PathResponder = struct {
    /// The data of the challenge that still needs an answer, or null when
    /// none is owed. RFC 9000 section 19.17 makes it eight octets the
    /// peer chose.
    pending: ?[frame.path_data_len]u8 = null,
    /// How many answers went out. See `max_path_responses`.
    sent: u64 = 0,
    /// How many challenges were dropped because the bound was reached. A
    /// drop that nothing counts is a drop nobody can see.
    dropped: u64 = 0,

    /// Takes one `PATH_CHALLENGE`, or drops it once the bound is reached.
    pub fn onChallenge(self: *PathResponder, data: [frame.path_data_len]u8) void {
        if (self.sent >= max_path_responses) {
            self.dropped +|= 1;
            return;
        }
        self.pending = data;
    }

    /// The answer this side owes, or null when it owes none.
    pub fn owed(self: PathResponder) ?[frame.path_data_len]u8 {
        return self.pending;
    }

    /// Records that the answer `owed` named is on the wire.
    pub fn onSent(self: *PathResponder) void {
        self.pending = null;
        self.sent +|= 1;
    }
};

/// True when `datagram` ends in `token`, which RFC 9000 section 10.3
/// makes it a Stateless Reset.
///
/// **The caller decides when to ask.** Section 10.3.1 compares the token
/// only after the datagram is known not to be processable, so a packet
/// that opens is never read as a reset.
///
/// The comparison is constant time, because the token is a secret and a
/// peer on the path must not learn it one octet at a time. RFC 9000
/// section 21.11.
fn statelessResetMatches(
    datagram: []const u8,
    token: [transport_parameters.stateless_reset_token_len]u8,
) bool {
    if (datagram.len < min_stateless_reset_bytes) return false;
    const tail = datagram[datagram.len - token.len ..][0..token.len];
    return std.crypto.timing_safe.eql([token.len]u8, tail.*, token);
}

/// The smallest datagram that can be a Stateless Reset, RFC 9000 section
/// 10.3: one header byte, at least four unpredictable bytes, and the
/// sixteen byte token.
pub const min_stateless_reset_bytes: usize = 21;

/// How many bytes of CRYPTO stream each level may hold unacknowledged.
///
/// The client hello is at most `Handshake.max_client_hello`, and the
/// client Finished is at most `Handshake.max_finished`. Neither grows.
pub const crypto_buffer_len = [_]usize{ 2048, 0, 512, 256 };

/// How long one datagram wait may be when no timer is nearer, in
/// milliseconds.
///
/// **A wait is never open ended.** The loss detection timer wakes the
/// connection to retransmit, and a wait that ran past it would leave a
/// lost packet on the floor until the peer sent something.
pub const poll_slice_ms: i64 = 20;

/// Every fault a QUIC connection can report.
pub const Error = error{
    /// No UDP socket, or the socket refused the datagram.
    CouldNotConnect,
    /// The peer stopped answering.
    OperationTimedOut,
    /// The peer closed the connection, or broke the protocol.
    ConnectionClosed,
    /// The handshake did not complete, and the reason is in
    /// `Connection.cause`.
    HandshakeFailed,
    /// The peer's certificate did not verify.
    PeerFailedVerification,
    /// The peer did not choose `h3`, or chose a protocol that was not
    /// offered.
    AlpnMismatch,
    /// A read or a write on the socket failed for a reason with no better
    /// name.
    TransportFailed,
    /// This side has no room for another stream.
    TooManyStreams,
    /// The peer's limits leave no room to open the streams HTTP/3 needs.
    StreamLimitReached,
    /// The caller cancelled the task this connection runs on.
    ///
    /// **This is what `-m`/`--max-time` needs.** A bound on a whole
    /// transfer cancels the task that runs it, and a connection that read
    /// no cancel would run to the end and report a success the bound was
    /// supposed to stop. See `Connection.checkCancel`.
    Canceled,
};

/// A record of one packet that went out, and the frames it carried.
const Record = struct {
    space: loss.Space,
    number: u64,
    live: bool = false,
    frames: [max_frames_per_packet]Tracked = undefined,
    len: usize = 0,
};

/// One frame worth putting back on the wire.
///
/// A frame with no entry here is one that carries no state: an `ACK` is
/// replaced by the next `ACK`, and `PADDING` carries nothing at all. RFC
/// 9002 section 6.5 lists exactly which frames a sender puts back, and
/// this union is that list for the frames this build sends.
const Tracked = union(enum) {
    crypto: struct { level: protection.Level, offset: u64, len: u32 },
    stream: struct { id: u64, offset: u64, len: u32, fin: bool },
    reset_stream: u64,
    stop_sending: u64,
    max_data,
    max_stream_data: u64,
    max_streams: frame.StreamKind,
    ping,
};

/// What the caller must supply to open a connection.
pub const Options = struct {
    io: Io,
    gpa: std.mem.Allocator,
    /// Where to send. The connection reads datagrams from this address
    /// and from no other.
    address: Io.net.IpAddress,
    /// The name the peer certificate must carry, and the name the client
    /// hello puts in its server name extension.
    host: []const u8,
    /// Whether to check that name. False is `-k`/`--insecure`.
    verify_host: bool,
    /// Which roots the peer certificate chain must reach.
    trust: Trust,
    /// The protocols the ALPN extension offers. RFC 9001 section 8.1
    /// makes it mandatory, so an empty list is refused.
    alpn: []const []const u8,
    /// The caller's stream slots, each already holding its two buffers.
    slots: []quic.Streams.Stream,
    /// The connection receive window this side advertises. At or above
    /// the sum of the receiving buffers in `slots`.
    recv_window: u64,
    /// How many unidirectional streams the peer may open. HTTP/3 needs
    /// three: the control stream and the two QPACK streams. The fourth is
    /// room for one reserved type a conformant server greases with.
    ///
    /// **Peer streams and local streams share one slot pool**, so this
    /// number plus `local_slot_reserve` below must fit in `slots`. A
    /// larger number would let a peer that stays inside the limit this
    /// side advertised take every slot, and then this side could not open
    /// its own request stream. `Streams.init` refuses the sum, so a later
    /// edit that breaks the budget fails at `open` and not in the field.
    peer_uni_streams: u64 = 4,
    /// How long the handshake may take, in milliseconds.
    handshake_timeout_ms: i64 = 30_000,
    /// How long one exchange may wait with no datagram at all, in
    /// milliseconds. This is also the `max_idle_timeout` this side
    /// announces. RFC 9000 section 10.1.
    idle_timeout_ms: u64 = 120_000,
    /// Where `open` writes `Connection.cause` when the handshake fails.
    ///
    /// **A failed `open` frees the connection, and the sentence with it.**
    /// The error name alone does not say which check refused the peer, and
    /// four different certificate faults are one error name, so a caller
    /// that reports a fault needs the sentence. Null for a caller that
    /// reports none. The text is a constant of this build, so it outlives
    /// the connection it came from.
    cause_out: ?*?[]const u8 = null,
    /// A flag the caller raises when this transfer must stop.
    ///
    /// **This is what `-m`/`--max-time` needs over QUIC.** See
    /// `Connection.checkCancel` for why the caller's own cancel does not
    /// reach a datagram wait. Null for a caller that bounds nothing, and
    /// the connection then answers only to its own timeouts.
    ///
    /// Borrowed, and the caller must keep it alive for the whole life of
    /// the connection.
    stop: ?*const std.atomic.Value(bool) = null,
};

/// A wait of `ms` milliseconds on the monotonic clock.
pub fn waitFor(ms: i64) Io.Timeout {
    return .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
}

/// Which roots the peer certificate chain must reach.
///
/// The same three arms `zurl_net.Connection.TrustCheck` has, and they mean
/// the same three things: `.none` accepts any chain, `.self_signed`
/// accepts a chain that ends in itself, and `.bundle` is the only one that
/// authenticates the peer. The store is borrowed for the length of the
/// handshake and never after, so one bundle serves every connection.
pub const Trust = union(enum) {
    none,
    self_signed,
    bundle: Bundle,

    pub const Bundle = struct {
        lock: *Io.RwLock,
        bundle: *std.crypto.Certificate.Bundle,
    };
};

/// How many bytes a packet header of `level` takes, with the packet number
/// included.
///
/// **The Length field is counted at four bytes always**, because
/// `writeHeaderInto` writes it at four bytes always. RFC 9000 section 16
/// allows a longer spelling of a small number, and one fixed width is what
/// lets the header length be worked out before the payload exists.
pub fn headerLenFor(level: protection.Level, dcid_len: usize, scid_len: usize, pn_len: usize) usize {
    return switch (level) {
        // 1 first byte, 4 version, 1 + dcid, 1 + scid, 1 token length, and
        // the 4 byte Length field.
        .initial => 1 + 4 + 1 + dcid_len + 1 + scid_len + 1 + 4 + pn_len,
        // The same without the token length. RFC 9000 sections 17.2.3 and
        // 17.2.4.
        .handshake, .zero_rtt => 1 + 4 + 1 + dcid_len + 1 + scid_len + 4 + pn_len,
        // RFC 9000 section 17.3: no version, no source connection id, no
        // length. The payload runs to the end of the datagram.
        .application => 1 + dcid_len + pn_len,
    };
}

/// What one packet header holds.
pub const Header = struct {
    level: protection.Level,
    out: []u8,
    dcid: packet.ConnectionId,
    scid: packet.ConnectionId,
    number: u64,
    pn_len: u3,
    /// How many payload bytes follow, before the AEAD tag.
    body_len: usize,
    /// The Key Phase bit of a short header. RFC 9001 section 6.
    key_phase: u1 = 0,
};

/// Writes one packet header and returns how many bytes it took.
///
/// The returned length runs through the end of the Packet Number field,
/// which is exactly the additional authenticated data RFC 9001 section 5.3
/// seals the payload with, and `header_len - pn_len` is the offset header
/// protection is applied at.
///
/// Asserts the buffer is long enough and that the packet is inside the
/// bounds a caller of this file always meets.
pub fn writeHeaderInto(h: Header) usize {
    std.debug.assert(h.pn_len >= 1 and h.pn_len <= 4);
    std.debug.assert(h.out.len >= headerLenFor(h.level, h.dcid.len, h.scid.len, h.pn_len));
    var at: usize = 0;
    if (h.level == .application) {
        // RFC 9000 section 17.3. The fixed bit, the key phase, and the
        // packet number length. The two reserved bits stay zero, which
        // RFC 9000 requires and which the receiving side checks.
        const phase: u8 = @as(u8, h.key_phase) * packet.key_phase_bit;
        h.out[0] = packet.fixed_bit | phase | (@as(u8, h.pn_len) - 1);
        at = 1;
        @memcpy(h.out[at..][0..h.dcid.len], h.dcid.slice());
        at += h.dcid.len;
    } else {
        const long_type: u8 = @intFromEnum(h.level.longType().?);
        h.out[0] = packet.header_form_bit | packet.fixed_bit | (long_type << 4) | (@as(u8, h.pn_len) - 1);
        at = 1;
        std.mem.writeInt(u32, h.out[at..][0..4], @intFromEnum(packet.Version.v1), .big);
        at += 4;
        h.out[at] = h.dcid.len;
        at += 1;
        @memcpy(h.out[at..][0..h.dcid.len], h.dcid.slice());
        at += h.dcid.len;
        h.out[at] = h.scid.len;
        at += 1;
        @memcpy(h.out[at..][0..h.scid.len], h.scid.slice());
        at += h.scid.len;
        if (h.level == .initial) {
            // This build sends no token. RFC 9000 section 17.2.2 still
            // needs the length field.
            h.out[at] = 0x00;
            at += 1;
        }
        // The Length field covers the packet number and everything after
        // it. **Four bytes always.** RFC 9000 section 16 spells a four
        // byte varint with the two high bits `10`, which is the
        // `0x8000_0000` below; the eight byte spelling is `11`, and
        // writing that prefix here made every packet unreadable to a peer.
        const length: u64 = h.pn_len + h.body_len + protection.tag_len;
        std.debug.assert(length < (1 << 30));
        std.mem.writeInt(u32, h.out[at..][0..4], @as(u32, @intCast(length)) | 0x8000_0000, .big);
        at += 4;
    }
    const written = packet.encodePacketNumber(
        @ptrCast(h.out[at..][0..packet.max_packet_number_len]),
        h.number,
        h.pn_len,
    );
    at += written.len;
    std.debug.assert(at == headerLenFor(h.level, h.dcid.len, h.scid.len, h.pn_len));
    return at;
}

/// One QUIC connection.
pub const Connection = struct {
    io: Io,
    gpa: std.mem.Allocator,
    socket: Io.net.Socket,
    peer: Io.net.IpAddress,

    handshake: quic_tls.Handshake,
    recovery: quic.Recovery,
    streams: quic.Streams,

    /// The Destination Connection Id every packet this side sends
    /// carries. It starts as the random identifier that seeded the
    /// Initial keys, and becomes the server's Source Connection Id once
    /// one arrives.
    dcid: packet.ConnectionId,
    /// This side's own identifier, which the peer puts in every packet it
    /// sends here.
    scid: packet.ConnectionId,
    /// The Source Connection Id of a long header that has not opened yet.
    /// `openAndRead` adopts it once the packet opens, so one spoofed
    /// Initial cannot move where this side sends. RFC 9000 section 7.2.
    pending_scid: ?packet.ConnectionId = null,
    /// The probe a loss detection timeout asked for, until a datagram
    /// carries it.
    ///
    /// **A probe passes the congestion window.** RFC 9002 section 7 says
    /// so, because the window is full exactly when the connection has
    /// stopped and a probe is what restarts it. Without this field
    /// `buildDatagram` gated every send on `canSend`, so a full window
    /// meant `onTimeout` built nothing and the connection deadlocked.
    /// The anti-amplification budget still holds through `canSendProbe`.
    probe_pending: ?quic.Recovery.Probe = null,
    /// How many probe datagrams the armed probe still owes. RFC 9002
    /// section 6.2.4 allows two.
    probe_datagrams_left: u8 = 0,
    /// How many probe datagrams this connection sent. IronStyle: a
    /// recovery that nothing counts is a recovery nobody can see.
    probes_sent: u64 = 0,
    /// The answer this side owes a `PATH_CHALLENGE`. See `PathResponder`.
    path: PathResponder = .{},
    /// When the last key update was taken from the peer, or null when the
    /// previous generation of read keys is already gone. RFC 9001 section
    /// 6.3 holds those keys for about three probe timeouts.
    key_update_at: ?loss.Instant = null,
    /// How many key updates this side took from the peer, and how many it
    /// started because the AEAD confidentiality limit came near.
    key_updates_taken: u64 = 0,
    key_updates_started: u64 = 0,
    /// Whether a packet the server protected has opened, which is what
    /// validates the server's address for this side.
    server_seen: bool = false,
    /// Whether `HANDSHAKE_DONE` has arrived.
    confirmed: bool = false,
    /// Whether the peer closed, and the codes it named.
    closed: ?Closed = null,
    /// Whether this side has written a `CONNECTION_CLOSE`.
    close_sent: bool = false,

    /// The CRYPTO stream of each level, held the same way a QUIC stream's
    /// bytes are so one retransmission rule serves both.
    crypto: [4]?quic.SendBuffer = .{ null, null, null, null },
    /// The largest packet number opened in each space, for the truncated
    /// packet number of RFC 9000 section 17.1.
    largest_recv: [loss.Space.count]?u64 = .{ null, null, null },

    records: []Record,
    /// How many packets could not be sent because every record was busy.
    records_full: u64 = 0,
    /// How many datagrams came from an address this connection never
    /// dialed.
    foreign_datagrams: u64 = 0,
    /// How many datagrams arrived cut short by the receive buffer.
    truncated_datagrams: u64 = 0,
    /// How many packets did not open under this connection's keys.
    undecryptable_packets: u64 = 0,
    /// How many packets opened under this connection's keys.
    ///
    /// `processDatagram` reads this to tell a datagram that carried
    /// nothing this side could open from one that did, which is the test
    /// RFC 9000 section 10.3.1 puts in front of the Stateless Reset
    /// comparison.
    packets_opened: u64 = 0,
    /// How many Stateless Resets this connection recognised. At most one,
    /// because the first one ends the connection.
    stateless_resets: u64 = 0,
    /// How many Retry packets were dropped, because the integrity tag did
    /// not check or because a packet from the server had already opened.
    ///
    /// **A discard that nothing counts is a discard nobody can see.** One
    /// forged Retry costs the sender no cryptography, so a client that
    /// drops them silently cannot tell a quiet path from a path with an
    /// attacker on it.
    discarded_retries: u64 = 0,
    /// How many datagrams arrived from the peer this connection dialed.
    ///
    /// **Zero says the peer never answered at all**, which is what
    /// `runHandshake` reads to tell "there is no QUIC here" from "the
    /// peer answered and then went quiet". A datagram counts once it
    /// passed the source address check, whether a packet inside it opened
    /// or not: an address that answers with rubbish is still an address
    /// that answers.
    peer_datagrams: u64 = 0,
    /// The caller's stop flag, or null. See `Options.stop`.
    stop: ?*const std.atomic.Value(bool) = null,

    /// Why the connection failed, when the error name alone does not say.
    /// A constant of this build or text this side wrote, never the peer's.
    cause: ?[]const u8 = null,

    /// The buffers the handshake reassembles CRYPTO frames into.
    initial_buffer: []u8,
    handshake_buffer: []u8,
    application_buffer: []u8,
    crypto_storage: []u8,
    datagram_in: []u8,
    datagram_out: []u8,
    payload: []u8,
    tail: []u8,
    plaintext: []u8,
    lost_numbers: []u64,
    ack_scratch: []u8,

    /// What the peer said when it closed.
    pub const Closed = struct {
        application: bool,
        code: u64,
        reason_len: usize,
        reason_storage: [128]u8,

        /// The reason phrase, with every byte a terminal could act on
        /// turned into a question mark. See `frame.sanitizeReason`.
        pub fn reason(self: *const Closed) []const u8 {
            return self.reason_storage[0..self.reason_len];
        }
    };

    /// Opens a connection and runs the handshake to completion.
    ///
    /// The caller owns the returned connection and must call `deinit`.
    pub fn open(options: Options) Error!*Connection {
        if (options.alpn.len == 0) return error.AlpnMismatch;

        const gpa = options.gpa;
        const self = gpa.create(Connection) catch return error.TransportFailed;
        var landed = false;
        defer if (!landed) gpa.destroy(self);

        var entropy: [quic_tls.Handshake.entropy_len + 2 * connection_id_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &entropy);
        options.io.randomSecure(&entropy) catch return error.TransportFailed;

        const odcid = packet.ConnectionId.init(
            entropy[quic_tls.Handshake.entropy_len..][0..connection_id_len],
        ) catch unreachable;
        const scid = packet.ConnectionId.init(
            entropy[quic_tls.Handshake.entropy_len + connection_id_len ..][0..connection_id_len],
        ) catch unreachable;

        // Every buffer this connection needs, in one allocation each and
        // none of them sized from a number the peer chose.
        const initial_buffer = gpa.alloc(u8, 4096) catch return error.TransportFailed;
        errdefer gpa.free(initial_buffer);
        const handshake_buffer = gpa.alloc(u8, 32 * 1024) catch return error.TransportFailed;
        errdefer gpa.free(handshake_buffer);
        const application_buffer = gpa.alloc(u8, 8192) catch return error.TransportFailed;
        errdefer gpa.free(application_buffer);
        const crypto_storage = gpa.alloc(u8, sum(crypto_buffer_len)) catch return error.TransportFailed;
        errdefer gpa.free(crypto_storage);
        const datagram_in = gpa.alloc(u8, max_datagram_in) catch return error.TransportFailed;
        errdefer gpa.free(datagram_in);
        const datagram_out = gpa.alloc(u8, max_datagram_out) catch return error.TransportFailed;
        errdefer gpa.free(datagram_out);
        const payload = gpa.alloc(u8, max_datagram_out) catch return error.TransportFailed;
        errdefer gpa.free(payload);
        const tail = gpa.alloc(u8, max_datagram_out) catch return error.TransportFailed;
        errdefer gpa.free(tail);
        const plaintext = gpa.alloc(u8, max_datagram_in) catch return error.TransportFailed;
        errdefer gpa.free(plaintext);
        const lost_numbers = gpa.alloc(u64, quic.Recovery.max_sent_packets) catch return error.TransportFailed;
        errdefer gpa.free(lost_numbers);
        const ack_scratch = gpa.alloc(u8, quic.AckRanges.max_range_bytes) catch return error.TransportFailed;
        errdefer gpa.free(ack_scratch);
        const records = gpa.alloc(Record, max_records) catch return error.TransportFailed;
        errdefer gpa.free(records);
        for (records) |*record| record.* = .{ .space = .initial, .number = 0 };

        var window_sum: u64 = 0;
        for (options.slots) |*slot| window_sum += slot.recv.buffer.len;

        const parameters: transport_parameters.Parameters = .{
            .initial_max_data = options.recv_window,
            .initial_max_stream_data_bidi_local = if (options.slots.len > 0) options.slots[0].recv.buffer.len else 0,
            .initial_max_stream_data_bidi_remote = 0,
            .initial_max_stream_data_uni = if (options.slots.len > 0) options.slots[0].recv.buffer.len else 0,
            // RFC 9114 section 6.1: a server never opens a bidirectional
            // stream to a client, so this side allows none. A server that
            // tries gets STREAM_LIMIT_ERROR from `Streams`.
            .initial_max_streams_bidi = 0,
            .initial_max_streams_uni = options.peer_uni_streams,
            .max_idle_timeout = options.idle_timeout_ms,
            .max_udp_payload_size = max_datagram_in,
            .initial_source_connection_id = scid,
            .active_connection_id_limit = 2,
        };

        const handshake = quic_tls.Handshake.init(.{
            .host = if (options.verify_host) .{ .explicit = options.host } else .no_verification,
            // The three arms are the vendored TLS client's own three, and
            // the chain walk that reads them is that client's code. See
            // `zurl-quic-tls`: no certificate rule lives in this package.
            .ca = switch (options.trust) {
                .none => .no_verification,
                .self_signed => .self_signed,
                .bundle => |trust| .{ .bundle = .{
                    .gpa = gpa,
                    .io = options.io,
                    .lock = trust.lock,
                    .bundle = trust.bundle,
                } },
            },
            .alpn_protocols = options.alpn,
            .parameters = parameters,
            .entropy = entropy[0..quic_tls.Handshake.entropy_len],
            .realtime_now = Io.Clock.real.now(options.io),
            .original_destination_connection_id = odcid,
            .initial_buffer = initial_buffer,
            .handshake_buffer = handshake_buffer,
            .application_buffer = application_buffer,
        }) catch return error.HandshakeFailed;

        var local: Io.net.IpAddress = switch (options.address) {
            .ip4 => .{ .ip4 = .unspecified(0) },
            .ip6 => .{ .ip6 = .unspecified(0) },
        };
        const socket = local.bind(options.io, .{ .mode = .dgram }) catch
            return error.CouldNotConnect;
        errdefer socket.close(options.io);

        self.* = .{
            .io = options.io,
            .gpa = gpa,
            .socket = socket,
            .peer = options.address,
            .handshake = handshake,
            .recovery = .init(.{
                .role = .client,
                .max_datagram_size = max_datagram_out,
            }),
            .streams = quic.Streams.init(.{
                .role = .client,
                .slots = options.slots,
                .recv_window = options.recv_window,
                // **The two local limits are the ones this side just
                // announced**, so the table refuses exactly what the
                // transport parameters refused. RFC 9114 section 6.1
                // gives a server no bidirectional stream to a client, and
                // RFC 9114 section 6.2 needs three unidirectional ones.
                .local_max_streams_bidi = 0,
                .local_max_streams_uni = options.peer_uni_streams,
                // Slots this side keeps for itself: the control stream,
                // the two QPACK streams, and the request. A peer that
                // fills its own limit cannot take these.
                .local_slot_reserve = 4,
                // Every peer limit starts at nothing and the peer's own
                // transport parameters raise it, in
                // `applyPeerParameters`. A server that names none gets a
                // client that opens no stream, which is right: RFC 9000
                // section 4.6 makes the parameter the permission.
            }) catch return error.TransportFailed,
            .dcid = odcid,
            .scid = scid,
            .initial_buffer = initial_buffer,
            .handshake_buffer = handshake_buffer,
            .application_buffer = application_buffer,
            .crypto_storage = crypto_storage,
            .datagram_in = datagram_in,
            .datagram_out = datagram_out,
            .payload = payload,
            .tail = tail,
            .plaintext = plaintext,
            .lost_numbers = lost_numbers,
            .ack_scratch = ack_scratch,
            .records = records,
            .stop = options.stop,
        };
        var at: usize = 0;
        for (crypto_buffer_len, 0..) |len, index| {
            if (len == 0) continue;
            self.crypto[index] = .init(crypto_storage[at..][0..len]);
            at += len;
        }

        // **The sentence this connection wrote for its own fault, kept
        // before the connection is torn down.** A handshake that failed
        // frees everything on the way out, `self.cause` with it, and the
        // error name alone does not say which check refused the peer. The
        // caller above reports the sentence, the way it reports the one
        // `zurl_net` writes for a TLS hop.
        self.runHandshake(options.handshake_timeout_ms) catch |err| {
            if (options.cause_out) |slot| slot.* = self.cause;
            return err;
        };
        landed = true;
        return self;
    }

    fn sum(values: [4]usize) usize {
        var total: usize = 0;
        for (values) |value| total += value;
        return total;
    }

    pub fn deinit(self: *Connection) void {
        const gpa = self.gpa;
        self.handshake.deinit();
        self.socket.close(self.io);
        gpa.free(self.initial_buffer);
        gpa.free(self.handshake_buffer);
        gpa.free(self.application_buffer);
        gpa.free(self.crypto_storage);
        gpa.free(self.datagram_in);
        gpa.free(self.datagram_out);
        gpa.free(self.payload);
        gpa.free(self.tail);
        gpa.free(self.plaintext);
        gpa.free(self.lost_numbers);
        gpa.free(self.ack_scratch);
        gpa.free(self.records);
        gpa.destroy(self);
    }

    fn now(self: *const Connection) loss.Instant {
        return @intCast(Io.Clock.awake.now(self.io).nanoseconds);
    }

    fn fail(self: *Connection, err: Error, cause: []const u8) Error {
        if (self.cause == null) self.cause = cause;
        return err;
    }

    /// Reports whether the caller has cancelled the task this connection
    /// runs on.
    ///
    /// **A QUIC wait is a stopping point, and it has to be one by hand.**
    /// `-m`/`--max-time` races a transfer against a sleep and ends the
    /// transfer when the sleep wins, and the read loop of this file waits
    /// for a datagram in slices of `poll_slice_ms` and loops. A loop that
    /// never asked would answer a bound that had passed with a whole
    /// transfer and exit 0, which is a bound that never fires. Measured
    /// before this call existed: `--http3 --max-time 0.05` fetched 1.3 MB
    /// in 0.89 seconds and exited 0, where the same page over HTTP/2
    /// exited 28.
    ///
    /// **Two questions, because one of them is not answered here.** A
    /// datagram wait runs through `Io.operateTimeout`, which hands the
    /// read to another unit of concurrency, so the cancel the caller made
    /// lands on a task this thread is not the one blocked in: measured, a
    /// `--max-time` cancel reached a blocked TCP read and never reached
    /// this loop. `Options.stop` is what closes that gap, and
    /// `Io.checkCancel` stays because a caller that cancels with no flag
    /// still deserves an answer.
    ///
    /// Every slice of every wait asks both, so the answer is at most one
    /// slice old.
    fn checkCancel(self: *Connection) Error!void {
        if (self.stop) |flag| {
            if (flag.load(.acquire)) {
                return self.fail(error.Canceled, "the caller stopped the transfer");
            }
        }
        self.io.checkCancel() catch return self.fail(
            error.Canceled,
            "the caller cancelled the task this connection runs on",
        );
    }

    /// The fault a socket write on this connection reports.
    ///
    /// **A datagram socket is connectionless, and the peer still answers
    /// for itself.** Linux passes an ICMP destination-unreachable back to
    /// the next operation on the socket that sent it, so `ConnectionRefused`
    /// on a `sendto` means the port is closed and not that this side's
    /// socket broke. The four names below all say the same thing: the peer
    /// is not reachable at this address. curl calls that "could not
    /// connect" and exits 7, measured against `curl --http3-only
    /// https://example.com/`, which is a host that refuses UDP 443.
    ///
    /// Every other fault is this side's socket or this build, which is
    /// `TransportFailed`.
    fn sendFault(self: *Connection, err: anyerror) Error {
        return switch (err) {
            error.ConnectionRefused,
            error.NetworkUnreachable,
            error.HostUnreachable,
            error.NetworkDown,
            => self.fail(error.CouldNotConnect, "the quic peer is not reachable at that address"),
            else => self.fail(error.TransportFailed, "zurl did not write a quic datagram"),
        };
    }

    /// The fault a socket read on this connection reports.
    ///
    /// The mirror of `sendFault`, and the same four names mean the same
    /// thing: an ICMP answer to a datagram this side sent, handed back on
    /// the read rather than on the write.
    fn receiveFault(self: *Connection, err: anyerror) Error {
        return switch (err) {
            error.ConnectionRefused,
            error.NetworkUnreachable,
            error.HostUnreachable,
            error.NetworkDown,
            => self.fail(error.CouldNotConnect, "the quic peer is not reachable at that address"),
            else => self.fail(error.TransportFailed, "zurl did not read a quic datagram"),
        };
    }

    // ---------------------------------------------------------------
    // The handshake
    // ---------------------------------------------------------------

    fn runHandshake(self: *Connection, timeout_ms: i64) Error!void {
        const deadline = waitFor(timeout_ms).toDeadline(self.io);
        while (!self.handshake.isComplete()) {
            try self.flush();
            self.receiveOne(deadline) catch |err| {
                // **A peer that answered nothing at all could not be
                // connected to, and did not time out.** UDP has no
                // handshake of its own, so a closed port, a dropped
                // datagram, and a host that is not there all look the same
                // from here: the deadline passes with nothing back. curl
                // reports that as `Could not connect to server` and exits
                // 7, measured against `curl --http3-only
                // https://example.com/`, and this reports the same name so
                // the exit code matches.
                //
                // A peer that answered and then went quiet keeps
                // `OperationTimedOut`, which is a different fault and a
                // different exit code: something is there and it stopped.
                if (err == error.OperationTimedOut and self.peer_datagrams == 0) {
                    // The cause is written over rather than added to,
                    // because `receiveOne` already wrote the sentence for
                    // the fault this line has just renamed.
                    self.cause = "the quic peer answered no datagram at all";
                    return error.CouldNotConnect;
                }
                return err;
            };
            // **A connection the peer closed before it was up was never
            // made.** RFC 9000 section 10.2 lets a server answer an
            // Initial packet with a `CONNECTION_CLOSE`, and that is how a
            // host with a UDP 443 listener but no HTTP/3 for this request
            // says no: `https://example.com/` answers exactly this way,
            // measured. curl calls it `Could not connect to server` and
            // exits 7, so this reports the name that gives the same exit
            // code. A peer that closes a connection that *is* up is
            // `ConnectionClosed`, which is a different fault and is
            // reported where it happens.
            if (self.closed != null) {
                return self.fail(
                    error.CouldNotConnect,
                    "the quic peer closed the connection before the handshake finished",
                );
            }
        }
        // The client's Finished still has to go out, and so does the
        // first flight of HTTP/3 control streams the caller will write.
        try self.flush();

        const chosen = self.handshake.alpnProtocol() orelse
            return self.fail(error.AlpnMismatch, "the server answered the ALPN offer with nothing, and RFC 9001 section 8.1 requires an answer");
        _ = chosen;

        const peer = self.handshake.peerParameters() orelse
            return self.fail(error.HandshakeFailed, "the server sent no transport parameters");
        self.applyPeerParameters(peer);
    }

    fn applyPeerParameters(self: *Connection, peer: transport_parameters.Parameters) void {
        self.streams.send_flow.limit = peer.initial_max_data;
        self.streams.peer_max_stream_data_bidi_remote = peer.initial_max_stream_data_bidi_remote;
        self.streams.peer_max_stream_data_bidi_local = peer.initial_max_stream_data_bidi_local;
        self.streams.peer_max_stream_data_uni = peer.initial_max_stream_data_uni;
        self.streams.peer_stream_limit = .{ peer.initial_max_streams_bidi, peer.initial_max_streams_uni };
    }

    /// The protocol the peer chose out of the ALPN offer, or null.
    pub fn alpnProtocol(self: *const Connection) ?[]const u8 {
        return self.handshake.alpnProtocol();
    }

    /// The peer's transport parameters, or null before they arrived.
    pub fn peerParameters(self: *const Connection) ?transport_parameters.Parameters {
        return self.handshake.peerParameters();
    }

    // ---------------------------------------------------------------
    // Sending
    // ---------------------------------------------------------------

    /// Moves every CRYPTO byte the handshake has ready into the send
    /// buffer of its level, so it is retransmitted like any stream byte.
    fn drainHandshake(self: *Connection) void {
        for ([_]protection.Level{ .initial, .handshake, .application }) |level| {
            const buffer = &(self.crypto[@intFromEnum(level)] orelse continue);
            const pending = self.handshake.pendingCrypto(level);
            if (pending.len == 0) continue;
            const taken = buffer.push(pending);
            if (taken > 0) self.handshake.markCryptoSent(level, taken);
        }
    }

    /// Writes everything that is due, in as many datagrams as it takes.
    pub fn flush(self: *Connection) Error!void {
        self.drainHandshake();
        var datagrams: usize = 0;
        while (datagrams < 64) : (datagrams += 1) {
            try self.checkCancel();
            const len = try self.buildDatagram();
            if (len == 0) return;
            self.socket.send(self.io, &self.peer, self.datagram_out[0..len]) catch |err|
                return self.sendFault(err);
            self.recovery.onDatagramSent(len);
            // The probe is spent once its datagrams are on the wire, so
            // the next flush meets the congestion window again. RFC 9002
            // section 6.2.4 allows two packets.
            if (self.probe_pending != null) {
                self.probes_sent +|= 1;
                self.probe_datagrams_left -|= 1;
                if (self.probe_datagrams_left == 0) self.probe_pending = null;
            }
        }
        // A probe that built nothing must not gate the next flush.
        self.probe_pending = null;
        self.probe_datagrams_left = 0;
    }

    /// Builds one datagram, coalescing a packet from each level that has
    /// something to say. Returns how many bytes it wrote.
    ///
    /// The order is Initial, Handshake, then application, because a short
    /// header carries no length and so must be last. RFC 9000 section
    /// 12.2.
    fn buildDatagram(self: *Connection) Error!usize {
        // A probe passes the congestion window and only the
        // anti-amplification budget. RFC 9002 section 7. Everything else
        // meets both.
        const gate = if (self.probe_pending != null)
            self.recovery.canSendProbe(max_datagram_out)
        else
            self.recovery.canSend(max_datagram_out);
        if (!gate and !self.close_sent) return 0;

        // The two later levels are built first, into scratch, so the
        // Initial packet knows how much padding the datagram still needs.
        // RFC 9000 section 14.1 makes a client expand every datagram that
        // carries an Initial packet to 1200 bytes.
        var tail_len: usize = 0;
        for ([_]protection.Level{ .handshake, .application }) |level| {
            // RFC 9002 section 6.2.2.1: a client pads the datagram of a
            // probe so the server earns the anti-amplification budget it
            // needs to answer. The floor goes on the probe's own level,
            // and the Initial arm below already pads for itself.
            const floor: usize = floor: {
                const probe = self.probe_pending orelse break :floor 0;
                if (!probe.pad or probe.space != loss.Space.fromLevel(level)) break :floor 0;
                if (tail_len >= loss.min_initial_datagram_bytes) break :floor 0;
                break :floor loss.min_initial_datagram_bytes - tail_len;
            };
            tail_len += try self.buildPacket(level, self.tail[tail_len..], floor);
        }

        // The tail already holds bytes, so the Initial packet gets the
        // room the tail leaves and not the whole buffer. A bound that
        // lives in another function in another file is not a bound. Today
        // `dropInitialKeys` runs the moment handshake keys appear, so the
        // Initial keys and the handshake keys are never both there and
        // `tail_len` is always zero here. Retry and 0-RTT both break that,
        // and each one would make the copy below write past the buffer.
        if (tail_len > self.datagram_out.len) {
            return self.fail(error.TransportFailed, "a quic datagram tail grew past the datagram buffer");
        }
        const head_room = self.datagram_out[0 .. self.datagram_out.len - tail_len];

        var head_len: usize = 0;
        if (self.handshake.session.writeKeys(.initial) != null) {
            const wanted = loss.min_initial_datagram_bytes;
            const floor = if (tail_len + 64 < wanted) wanted - tail_len else 0;
            head_len = try self.buildPacket(.initial, head_room, floor);
        }
        if (head_len == 0 and tail_len == 0) return 0;

        std.debug.assert(head_len <= head_room.len);
        @memcpy(self.datagram_out[head_len..][0..tail_len], self.tail[0..tail_len]);
        return head_len + tail_len;
    }

    /// Builds one packet at `level` into `out`, or writes nothing and
    /// returns zero when the level has nothing to send.
    ///
    /// `pad_to` is the smallest packet this one may be, which is how a
    /// client's Initial packet reaches the 1200 byte floor.
    fn buildPacket(self: *Connection, level: protection.Level, out: []u8, pad_to: usize) Error!usize {
        const keys = self.handshake.session.writeKeys(level) orelse return 0;
        const space = loss.Space.fromLevel(level);

        var record = self.freeRecord() orelse {
            self.records_full += 1;
            return 0;
        };
        record.* = .{ .space = space, .number = 0 };

        // The header is written before the payload is sealed, and its
        // length depends on the packet number, which depends on nothing
        // in the payload. So the payload is built first into scratch and
        // the header second.
        var writer: std.Io.Writer = .fixed(self.payload);
        const room = self.payloadRoom(level, out.len);
        if (room == 0) return 0;
        var acked = false;
        const filled = self.fillPayload(level, &writer, record, room, &acked) catch
            return self.fail(error.TransportFailed, "zurl could not build a quic packet");
        if (filled == .nothing) return 0;

        // RFC 9000 section 14.1's floor is met with PADDING frames inside
        // the payload, because a byte after the AEAD tag is not part of
        // the packet.
        var body = writer.buffered();

        // **The header protection sample has a floor of its own, and it
        // bites a small packet.** RFC 9001 section 5.4.2: the sample runs
        // from four bytes past the start of the packet number and is
        // sixteen bytes long, so a sender must make sure the packet
        // number, the payload, and the AEAD tag together reach twenty
        // bytes. An acknowledgment alone is smaller than that, and the
        // packet would go out unprotected or not at all.
        //
        // The packet number width is not known yet, so the floor is
        // worked out for the narrowest one. A wider number makes the
        // packet longer, so a packet padded for one byte of number is
        // long enough for four.
        const sample_floor = header_protection.sample_gap + header_protection.sample_len;
        const narrowest_pn: usize = 1;
        if (narrowest_pn + body.len + protection.tag_len < sample_floor) {
            const want = sample_floor - protection.tag_len - narrowest_pn - body.len;
            @memset(self.payload[body.len..][0..want], 0x00);
            body = self.payload[0 .. body.len + want];
        }

        if (pad_to > 0) {
            const overhead = self.headerLen(level, 0) + protection.tag_len;
            if (body.len + overhead < pad_to) {
                const want = @min(pad_to - overhead - body.len, self.payload.len - body.len);
                @memset(self.payload[body.len..][0..want], 0x00);
                body = self.payload[0 .. body.len + want];
            }
        }
        if (body.len == 0) return 0;

        // RFC 9001 section 6.6: the AEAD confidentiality limit is what
        // `KeyUpdateRequired` reports, and the answer is a key update and
        // not a dead connection. The old text said the packet numbers ran
        // out, which is a different limit and was never the one that
        // fired here.
        const number = self.handshake.session.nextPacketNumber(level) catch |err| number: {
            if (err == error.KeyUpdateRequired) {
                self.handshake.session.update() catch
                    return self.fail(error.TransportFailed, "this connection reached its aead limit and could not update its keys");
                self.key_updates_started +|= 1;
                break :number self.handshake.session.nextPacketNumber(level) catch
                    return self.fail(error.TransportFailed, "this connection reached its aead limit and could not update its keys");
            }
            return self.fail(error.TransportFailed, "this connection used up its packet numbers");
        };
        record.number = number;

        const pn_len = packet.encodedPacketNumberLen(number, self.recovery.stateConst(space).largest_acked);
        const header_len = self.writeHeader(level, out, number, pn_len, body.len);
        if (header_len + body.len + protection.tag_len > out.len) return 0;

        keys.seal(
            out[header_len..][0 .. body.len + protection.tag_len],
            body,
            out[0..header_len],
            number,
        );
        const pn_offset = header_len - pn_len;
        header_protection.apply(out[0 .. header_len + body.len + protection.tag_len], pn_offset, &keys) catch
            return self.fail(error.TransportFailed, "a quic packet was too short to protect its header");

        const total = header_len + body.len + protection.tag_len;
        record.live = true;
        self.recovery.onPacketSent(space, .{
            .number = number,
            .sent_time = self.now(),
            .size = @intCast(total),
            .ack_eliciting = filled == .eliciting,
            // **An acknowledgment-only packet is not in flight.** RFC 9002
            // section 2 says so, and the reason is that nothing will ever
            // acknowledge it: a peer answers no `ACK` with an `ACK`. A
            // build that counted one would add to the congestion window's
            // in-flight total on every packet and never take it off, so
            // the window would fill and the connection would stop sending
            // with nothing lost and nothing to report.
            .in_flight = filled == .eliciting,
        }) catch {
            // Nothing may be sent that cannot be recovered. The record
            // goes back and the caller waits for an acknowledgment.
            record.live = false;
            return 0;
        };
        if (filled != .eliciting) {
            record.live = false;
            record.len = 0;
        }
        if (acked) self.recovery.onAckSent(space);
        return total;
    }

    const Filled = enum { nothing, ack_only, eliciting };

    fn payloadRoom(self: *const Connection, level: protection.Level, out_len: usize) usize {
        const overhead = self.headerLen(level, 0) + protection.tag_len;
        if (out_len <= overhead) return 0;
        return @min(out_len - overhead, self.payload.len);
    }

    fn fillPayload(
        self: *Connection,
        level: protection.Level,
        writer: *std.Io.Writer,
        record: *Record,
        room: usize,
        acked: *bool,
    ) !Filled {
        var filled: Filled = .nothing;
        const space = loss.Space.fromLevel(level);

        // A close is the only thing a closing connection writes.
        if (self.close_sent) return .nothing;

        // RFC 9000 section 13.2: the acknowledgment first, so a packet
        // that is cut short still carries it.
        //
        // **Only when one is due.** `AckRanges` says when: at once for an
        // ack-eliciting Initial or Handshake packet, at once for a second
        // ack-eliciting packet or one out of order, and at this side's own
        // `max_ack_delay` otherwise. Writing one into every packet instead
        // would answer an `ACK` with an `ACK`, which RFC 9000 section
        // 13.2.1 forbids, and would spend the path on nothing.
        if (self.recovery.ackDue(space, self.now())) {
            const shift: u6 = if (self.handshake.peerParameters()) |p| p.ackDelayShift() else 3;
            if (self.recovery.buildAck(space, self.now(), shift, self.ack_scratch)) |ack| {
                const before = writer.buffered().len;
                frame.encode(.{ .ack = ack }, writer) catch {
                    writer.end = before;
                };
                if (writer.buffered().len != before) {
                    filled = .ack_only;
                    acked.* = true;
                }
            } else |_| {}
        }

        // The handshake bytes of this level.
        if (self.crypto[@intFromEnum(level)]) |*buffer| {
            while (buffer.next(std.math.maxInt(u64), room)) |chunk| {
                if (chunk.data.len == 0) break;
                const overhead = 1 + 8 + 8;
                if (writer.buffered().len + chunk.data.len + overhead > room) {
                    const fits = room -| (writer.buffered().len + overhead);
                    if (fits == 0) break;
                    const cut = chunk.data[0..fits];
                    frame.encode(.{ .crypto = .{ .offset = chunk.offset, .data = cut } }, writer) catch break;
                    buffer.onSent(chunk.offset, cut.len, false);
                    self.track(record, .{ .crypto = .{ .level = level, .offset = chunk.offset, .len = @intCast(cut.len) } });
                    filled = .eliciting;
                    break;
                }
                frame.encode(.{ .crypto = .{ .offset = chunk.offset, .data = chunk.data } }, writer) catch break;
                buffer.onSent(chunk.offset, chunk.data.len, false);
                self.track(record, .{ .crypto = .{ .level = level, .offset = chunk.offset, .len = @intCast(chunk.data.len) } });
                filled = .eliciting;
                if (record.len == max_frames_per_packet) break;
            }
        }

        if (level != .application) return filled;

        // **The answer to a path challenge, and it goes out first.** RFC
        // 9000 section 8.2.2: an endpoint sends the `PATH_RESPONSE` as
        // soon as it can, because the peer is timing the round trip.
        // Section 13.3 keeps it out of the retransmission table: a lost
        // answer is not sent again, the peer challenges again instead, so
        // this frame is written and never tracked in `record`.
        if (self.path.owed()) |data| {
            const before = writer.buffered().len;
            if (frame.encode(.{ .path_response = data }, writer)) |_| {
                self.path.onSent();
                filled = .eliciting;
            } else |_| {
                // No room in this packet. The answer stays owed and the
                // next packet carries it.
                writer.end = before;
            }
        }

        // The connection and stream windows, which must go out before the
        // peer runs out of room.
        if (self.streams.takeMaxData()) |value| {
            frame.encode(.{ .max_data = value }, writer) catch {};
            self.track(record, .max_data);
            filled = .eliciting;
        }
        for ([_]frame.StreamKind{ .bidirectional, .unidirectional }) |kind| {
            if (self.streams.takeMaxStreams(kind)) |f| {
                frame.encode(.{ .max_streams = f }, writer) catch {};
                self.track(record, .{ .max_streams = kind });
                filled = .eliciting;
            }
        }
        for (self.streams.slots) |*slot| {
            if (!slot.in_use) continue;
            if (self.streams.takeMaxStreamData(slot)) |f| {
                frame.encode(.{ .max_stream_data = f }, writer) catch {};
                self.track(record, .{ .max_stream_data = slot.id });
                filled = .eliciting;
            }
            if (self.streams.takeStopSending(slot)) |f| {
                frame.encode(.{ .stop_sending = f }, writer) catch {};
                self.track(record, .{ .stop_sending = slot.id });
                filled = .eliciting;
            }
            if (self.streams.takeReset(slot)) |f| {
                frame.encode(.{ .reset_stream = f }, writer) catch {};
                self.track(record, .{ .reset_stream = slot.id });
                filled = .eliciting;
            }
        }

        // And the stream data itself, which takes whatever is left.
        while (record.len < max_frames_per_packet) {
            const overhead = 1 + 8 + 8 + 8;
            const used = writer.buffered().len;
            if (used + overhead >= room) break;
            const budget = room - used - overhead;
            const outgoing = self.streams.nextSend(budget) orelse break;
            frame.encode(.{ .stream = .{
                .stream_id = outgoing.slot.id,
                .offset = outgoing.chunk.offset,
                .data = outgoing.chunk.data,
                .fin = outgoing.chunk.fin,
                .explicit_offset = true,
                .explicit_length = true,
            } }, writer) catch break;
            self.streams.onSent(outgoing.slot, outgoing.chunk);
            self.track(record, .{ .stream = .{
                .id = outgoing.slot.id,
                .offset = outgoing.chunk.offset,
                .len = @intCast(outgoing.chunk.data.len),
                .fin = outgoing.chunk.fin,
            } });
            filled = .eliciting;
            if (outgoing.chunk.data.len == 0 and outgoing.chunk.fin) break;
        }

        return filled;
    }

    fn track(self: *Connection, record: *Record, what: Tracked) void {
        _ = self;
        if (record.len == max_frames_per_packet) return;
        record.frames[record.len] = what;
        record.len += 1;
    }

    fn freeRecord(self: *Connection) ?*Record {
        for (self.records) |*record| {
            if (!record.live) return record;
        }
        return null;
    }

    fn headerLen(self: *const Connection, level: protection.Level, pn_len: usize) usize {
        return headerLenFor(level, self.dcid.len, self.scid.len, pn_len);
    }

    fn writeHeader(
        self: *Connection,
        level: protection.Level,
        out: []u8,
        number: u64,
        pn_len: u3,
        body_len: usize,
    ) usize {
        return writeHeaderInto(.{
            .level = level,
            .out = out,
            .dcid = self.dcid,
            .scid = self.scid,
            .number = number,
            .pn_len = pn_len,
            .body_len = body_len,
            .key_phase = self.handshake.session.keyPhase() orelse 0,
        });
    }

    // ---------------------------------------------------------------
    // Receiving
    // ---------------------------------------------------------------

    /// Waits for one datagram and processes every packet in it.
    ///
    /// A datagram from another source address is dropped and the wait
    /// starts again, so a sender that guessed the port cannot end the
    /// wait either.
    fn receiveOne(self: *Connection, timeout: Io.Timeout) Error!void {
        const deadline = timeout.toDeadline(self.io);
        while (true) {
            try self.checkCancel();
            const wait = self.nextWait();
            const message = self.socket.receiveTimeout(self.io, self.datagram_in, wait) catch |err| switch (err) {
                error.Timeout => {
                    if (self.expired(deadline)) return self.fail(
                        error.OperationTimedOut,
                        "the quic peer did not answer",
                    );
                    try self.onTimeout();
                    continue;
                },
                error.ConcurrencyUnavailable => return self.fail(
                    error.TransportFailed,
                    "this build has no concurrency, so a quic read cannot be bounded",
                ),
                else => |rest| return self.receiveFault(rest),
            };

            // **The source address check.** UDP hands over whatever
            // arrived. A datagram from anybody else is dropped before a
            // byte reaches the packet parser, and it does not end the
            // wait.
            if (!sameAddress(self.peer, message.from)) {
                self.foreign_datagrams += 1;
                continue;
            }
            if (message.flags.trunc) {
                // The packet lost its tail, so its AEAD tag cannot pass.
                // Counting it says the receive buffer was too small
                // rather than that a peer forged a packet.
                self.truncated_datagrams += 1;
                continue;
            }

            self.peer_datagrams +|= 1;
            self.recovery.onDatagramReceived(message.data.len);
            try self.processDatagram(message.data);
            return;
        }
    }

    fn expired(self: *const Connection, deadline: Io.Timeout) bool {
        return switch (deadline) {
            .none, .duration => false,
            .deadline => |at| Io.Clock.awake.now(self.io).nanoseconds >= at.raw.nanoseconds,
        };
    }

    /// How long the next datagram wait may be.
    ///
    /// The shorter of one poll slice and the loss detection timer, so a
    /// retransmission is never held up by a peer that went quiet.
    fn nextWait(self: *const Connection) Io.Timeout {
        const slice = poll_slice_ms * std.time.ns_per_ms;
        const timer = self.recovery.nextTimeout() orelse return waitFor(poll_slice_ms);
        const current = self.now();
        const gap: u64 = if (timer > current) timer - current else 0;
        // **The floor of one millisecond is what stops a busy loop.** A
        // timer already due gives a gap of zero, and a wait of zero
        // returns at once, so the loop would spin between the timer and
        // the socket with nothing arriving.
        const nanoseconds: i96 = @intCast(@max(@min(gap, @as(u64, slice)), std.time.ns_per_ms));
        return .{ .duration = .{ .raw = .fromNanoseconds(nanoseconds), .clock = .awake } };
    }

    fn onTimeout(self: *Connection) Error!void {
        const timeout = self.recovery.onLossDetectionTimeout(self.now(), self.lost_numbers) catch
            return self.fail(error.TransportFailed, "the loss detection buffer was too small");
        switch (timeout) {
            .idle => {},
            .lost => |lost| {
                for (self.lost_numbers[0..lost.count]) |number| self.onPacketLost(lost.space, number);
            },
            .probe => |probe| {
                // RFC 9002 section 6.2.4: a probe is one or two
                // ack-eliciting packets. Anything outstanding goes out
                // again, and a `PING` goes out when nothing is.
                //
                // The probe is armed for the space the timer named, and
                // it passes the congestion window. RFC 9002 section 7
                // says a probe ignores the window on purpose, because the
                // window is full exactly when the connection has stopped
                // and a probe is what restarts it. The anti-amplification
                // budget still holds, which `canSendProbe` is.
                self.probe_pending = probe;
                self.probe_datagrams_left = @max(probe.packets, 1);
                self.armProbe(probe.space);
            },
        }
        try self.flush();
    }

    /// Makes sure the next packet in `space` carries something the peer
    /// must acknowledge.
    ///
    /// Only that space is armed. Arming all three re-sent handshake bytes
    /// on every application probe, which the peer had already taken.
    fn armProbe(self: *Connection, space: loss.Space) void {
        for ([_]protection.Level{ .initial, .handshake, .application }) |level| {
            if (loss.Space.fromLevel(level) != space) continue;
            const buffer = &(self.crypto[@intFromEnum(level)] orelse continue);
            if (buffer.base < buffer.sent) buffer.onLost(buffer.base, @intCast(buffer.sent - buffer.base), false);
        }
        if (space != .application) return;
        for (self.streams.slots) |*slot| {
            if (!slot.in_use) continue;
            if (slot.send.base < slot.send.sent) {
                self.streams.onLost(slot, slot.send.base, @intCast(slot.send.sent - slot.send.base), false);
            }
        }
    }

    /// Processes every packet in one datagram, and reads a datagram that
    /// nothing in it opened as a possible Stateless Reset.
    ///
    /// **The order is the one RFC 9000 section 10.3.1 asks for.** The
    /// token is compared only after the datagram is known not to be
    /// processable, so a packet that opens is never read as a reset.
    fn processDatagram(self: *Connection, datagram: []u8) Error!void {
        const opened_before = self.packets_opened;
        try self.processPackets(datagram);
        if (self.packets_opened != opened_before) return;
        try self.checkStatelessReset(datagram);
    }

    /// Ends the connection when `datagram` carries the peer's Stateless
    /// Reset Token in its last sixteen octets.
    ///
    /// **A Stateless Reset is how a peer that lost its state says so.**
    /// RFC 9000 section 10.3: the peer can no longer open or seal a
    /// packet for this connection, so the only thing it can send that
    /// this side will believe is the token it handed over while it still
    /// had the keys. Without this check the datagram is one more
    /// undecryptable packet and the transfer waits for the idle timer
    /// with nothing to report.
    ///
    /// **The token is the one the transport parameters carried**, which
    /// RFC 9000 section 10.3.1 ties to the connection id in use. This
    /// build never migrates and never retires a connection id, so the
    /// server's first id is the only one ever in use and its token is the
    /// only one that can apply. See the `new_connection_id` arm of
    /// `readFrame` for why the tokens that arrive later are not kept.
    ///
    /// A server may send no `stateless_reset_token` at all, and then no
    /// reset from it can be told from noise. That is the peer's choice
    /// and RFC 9000 section 18.2 allows it.
    fn checkStatelessReset(self: *Connection, datagram: []const u8) Error!void {
        const parameters = self.handshake.peerParameters() orelse return;
        const token = parameters.stateless_reset_token orelse return;
        if (!statelessResetMatches(datagram, token)) return;
        self.stateless_resets +|= 1;
        return self.fail(
            error.ConnectionClosed,
            "the server sent a stateless reset, which says it no longer holds the state for this connection",
        );
    }

    fn processPackets(self: *Connection, datagram: []u8) Error!void {
        var at: usize = 0;
        while (at < datagram.len) {
            const rest = datagram[at..];
            // RFC 9000 section 12.2: a zero first byte ends the
            // datagram, because a real packet always has the fixed bit.
            if (rest[0] == 0x00) return;
            const consumed = try self.processPacket(rest);
            if (consumed == 0) return;
            at += consumed;
        }
    }

    fn processPacket(self: *Connection, bytes: []u8) Error!usize {
        return switch (packet.form(bytes[0])) {
            .long => self.processLong(bytes),
            .short => self.processShort(bytes),
        };
    }

    fn processLong(self: *Connection, bytes: []u8) Error!usize {
        const parsed = packet.parseLong(bytes) catch |err| {
            // `parseLong` refuses every version but 1, so a Version
            // Negotiation packet arrives here and nowhere else. RFC 9000
            // section 6.2 says the client either picks a version from the
            // list or gives up, and this build speaks only version 1. So
            // the connection stops with a reason a user can read, rather
            // than dropping the packet and waiting for the idle timer.
            //
            // The packet is not authenticated, so three things are
            // checked before it is allowed to end the connection. It must
            // name this side's own connection id, no packet may have
            // opened yet, and the list must not hold version 1. RFC 9000
            // section 6.2 asks for the last of those by name, because a
            // list holding the version the client already sent is a
            // forgery.
            if (err == error.UnsupportedVersion and !self.server_seen) {
                if (packet.parseVersionNegotiation(bytes)) |vn| {
                    if (vn.dcid.eql(&self.scid) and !vn.has(.v1)) {
                        self.cause = "the server does not speak QUIC version 1";
                        return self.fail(error.HandshakeFailed, "the server sent a Version Negotiation packet and this build speaks only QUIC version 1");
                    }
                } else |_| {}
            }
            self.undecryptable_packets += 1;
            return 0;
        };
        // The packet must name this side's own connection id.
        if (!parsed.dcid.eql(&self.scid)) {
            self.undecryptable_packets += 1;
            return parsed.packetLen(bytes);
        }

        switch (parsed.body) {
            .retry => {
                // **A Retry is checked before anything acts on it.** See
                // `retryVerdict`. The whole packet is the input, because
                // the integrity tag covers every byte before it.
                const whole = bytes[0..parsed.packetLen(bytes)];
                switch (retryVerdict(
                    self.handshake.original_destination_connection_id,
                    whole,
                    parsed.scid,
                    self.server_seen,
                )) {
                    .discard => {
                        // RFC 9000 section 17.2.5.2: the packet is
                        // dropped and the connection carries on as though
                        // it never arrived, the same as a packet that
                        // does not open.
                        self.undecryptable_packets += 1;
                        self.discarded_retries += 1;
                        return whole.len;
                    },
                    .verified => return self.fail(
                        error.HandshakeFailed,
                        "the server asked for a Retry, and this build sends no second Initial packet",
                    ),
                }
            },
            .zero_rtt => {
                // A server never sends one. RFC 9001 section 4.6.
                self.undecryptable_packets += 1;
                return parsed.packetLen(bytes);
            },
            .initial, .handshake => {},
        }

        const level: protection.Level = switch (parsed.body) {
            .initial => .initial,
            .handshake => .handshake,
            else => unreachable,
        };
        // The server's own connection id, which every later packet this
        // side sends must name. RFC 9000 section 7.2.
        //
        // A long header is not authenticated when it is parsed, so the id
        // is only kept here and adopted in `openAndRead` after the packet
        // really opens. One spoofed Initial with any source id would
        // otherwise send every later packet of the handshake to a
        // connection id the server does not hold. The Initial keys come
        // from the original destination id and not from this one, so
        // waiting costs the open nothing.
        if (!self.server_seen) self.pending_scid = parsed.scid;

        const length: usize = switch (parsed.body) {
            .initial => |i| @intCast(i.length),
            .handshake => |h| @intCast(h.length),
            else => unreachable,
        };
        const packet_len = parsed.pn_offset + length;
        if (packet_len > bytes.len) {
            self.undecryptable_packets += 1;
            return 0;
        }
        try self.openAndRead(bytes[0..packet_len], parsed.pn_offset, level, length);
        return packet_len;
    }

    fn processShort(self: *Connection, bytes: []u8) Error!usize {
        const parsed = packet.parseShort(bytes, self.scid.len) catch {
            self.undecryptable_packets += 1;
            return 0;
        };
        if (!parsed.dcid.eql(&self.scid)) {
            self.undecryptable_packets += 1;
            return 0;
        }
        // The key phase bit is under header protection, so it is read
        // after `remove` and not here.
        try self.openAndRead(bytes, parsed.pn_offset, .application, bytes.len - parsed.pn_offset);
        return bytes.len;
    }

    /// Removes header protection, opens the payload, and reads its
    /// frames.
    ///
    /// The key phase is under header protection, so it is read here after
    /// `remove` and never taken from the caller.
    fn openAndRead(
        self: *Connection,
        bytes: []u8,
        pn_offset: usize,
        level: protection.Level,
        length: usize,
    ) Error!void {
        var keys = self.handshake.session.readKeys(level) orelse {
            // The keys for this level are not ready, or were dropped. RFC
            // 9000 section 5.7 lets a packet arrive before its keys, and
            // this build drops it rather than buffer it: the peer
            // retransmits.
            self.undecryptable_packets += 1;
            return;
        };

        const pn_len = header_protection.remove(bytes, pn_offset, &keys) catch {
            self.undecryptable_packets += 1;
            return;
        };
        const truncated = packet.readPacketNumber(bytes[pn_offset..], pn_len) catch {
            self.undecryptable_packets += 1;
            return;
        };
        const space = loss.Space.fromLevel(level);
        const number = packet.decodePacketNumber(
            self.largest_recv[space.index()] orelse 0,
            truncated,
            @as(u6, pn_len) * 8,
        );

        // The key phase is legible now, and RFC 9001 section 6.3 needs
        // the packet number beside it: a packet whose phase is not the
        // current one is either the peer starting an update or a
        // reordered packet from the generation before. The number is what
        // tells the two apart, so the choice runs here and not above.
        //
        // Nothing moves yet. Anybody can set the bit, so the session
        // moves only after the packet really opens.
        var generation: ?quic_tls.Session.ReadGeneration = null;
        var phase: u1 = 0;
        if (level == .application) {
            phase = @intCast((bytes[0] & packet.key_phase_bit) >> 2);
            generation = self.handshake.session.readGeneration(phase, number);
            if (self.handshake.session.readKeysForPacket(phase, number)) |for_phase| keys = for_phase;
        }

        const header = bytes[0 .. pn_offset + pn_len];
        if (length < pn_len) {
            self.undecryptable_packets += 1;
            return;
        }
        const sealed = bytes[pn_offset + pn_len ..][0 .. length - pn_len];
        const opened = keys.open(self.plaintext, sealed, header, number) catch {
            self.undecryptable_packets += 1;
            self.handshake.session.failedOpen() catch
                return self.fail(error.ConnectionClosed, "too many quic packets failed to open, which RFC 9001 section 6.6 makes a limit");
            return;
        };
        // The packet opened, so this datagram carried something this side
        // could read. `processDatagram` reads this count.
        self.packets_opened +|= 1;

        // RFC 9000 sections 17.2 and 17.3: the reserved bits are zero
        // once header protection is off. A packet that sets one is a
        // connection error of type PROTOCOL_VIOLATION, and nothing in
        // `zurl-quic` checks it, so it is checked here.
        const reserved: u8 = if (level == .application) packet.short_reserved_mask else packet.long_reserved_mask;
        if (bytes[0] & reserved != 0) {
            return self.fail(error.ConnectionClosed, "the server set a reserved bit in a packet header");
        }

        if (self.largest_recv[space.index()] == null or number > self.largest_recv[space.index()].?) {
            self.largest_recv[space.index()] = number;
        }
        if (!self.server_seen) {
            self.server_seen = true;
            // The packet opened, so the source connection id in its
            // header came from somebody who holds the keys.
            if (self.pending_scid) |scid| {
                self.dcid = scid;
                self.handshake.setServerConnectionId(scid);
                self.pending_scid = null;
            }
            self.recovery.validateAddress();
        }

        // The packet opened, so the key phase bit it carried is the
        // peer's and not an attacker's. RFC 9001 section 6.2: only a
        // packet of the **next** generation starts an update. A reordered
        // packet of the previous generation must not, which is why
        // `readGeneration` answers with three values and not two.
        if (generation) |which| {
            if (which == .next) {
                self.handshake.session.acceptPeerUpdate(phase) catch
                    return self.fail(error.ConnectionClosed, "the server started a key update this build could not follow");
                self.key_update_at = self.now();
                self.key_updates_taken +|= 1;
            }
            self.handshake.session.recordOpened(phase, number);
        }

        // RFC 9001 section 6.3 holds the previous generation for about
        // three probe timeouts, so a reordered packet still opens. After
        // that the keys are zeroed and dropped.
        if (self.key_update_at) |at| {
            const keep = self.recovery.rtt.ptoBase() *| 3;
            if (self.now() -| at >= keep) {
                self.handshake.session.discardPreviousReadKeys();
                self.key_update_at = null;
            }
        }

        try self.readFrames(level, number, self.plaintext[0..opened]);
    }

    fn readFrames(self: *Connection, level: protection.Level, number: u64, payload: []const u8) Error!void {
        const space = loss.Space.fromLevel(level);

        // RFC 9000 section 12.3: a receiver discards a packet whose
        // number it already processed. The range set already knows the
        // answer, so the question is asked **before** the frames take
        // effect and not after. Reassembly and the monotone window frames
        // absorb a replay today, and the first frame handler that stops
        // being idempotent would not.
        if (self.recovery.stateConst(space).ack.contains(number)) {
            _ = self.recovery.onPacketReceived(space, number, false, self.now());
            return;
        }

        var eliciting = false;
        var decoder: frame.Decoder = .init(payload);
        while (true) {
            const maybe = decoder.next() catch
                return self.fail(error.ConnectionClosed, "the server sent a quic frame this build could not read");
            const f = maybe orelse break;
            if (f.elicitsAck()) eliciting = true;
            try self.readFrame(level, f);
            if (self.closed != null) break;
        }
        _ = self.recovery.onPacketReceived(space, number, eliciting, self.now());
    }

    fn readFrame(self: *Connection, level: protection.Level, f: frame.Frame) Error!void {
        const space = loss.Space.fromLevel(level);

        // RFC 9000 section 12.4 Table 3. An Initial or a Handshake packet
        // carries only PADDING, PING, ACK, CRYPTO and a transport
        // CONNECTION_CLOSE. Anything else is PROTOCOL_VIOLATION.
        //
        // This is not a nicety. Initial keys come from the destination
        // connection id alone, and that id travels in the clear, so
        // anybody who reads the client's first datagram can seal a packet
        // this side will open. For an Initial packet the frame table
        // **is** the authentication boundary. Without it one forged
        // packet closes the connection with an application
        // CONNECTION_CLOSE, or runs `HANDSHAKE_DONE` before the handshake
        // finishes, or puts bytes in the reassembly buffer that the
        // HTTP/3 engine later reads as the peer's control stream.
        if (level != .application and !allowedBeforeOneRtt(f)) {
            return self.fail(
                error.ConnectionClosed,
                "the server sent a quic frame that its encryption level does not allow",
            );
        }

        switch (f) {
            .padding, .ping => {},
            .ack => |ack| try self.onAck(space, ack),
            .crypto => |c| {
                self.handshake.provideCrypto(level, c.offset, c.data) catch |err| {
                    self.cause = handshakeCause(err);
                    return switch (err) {
                        error.TlsAlpnMissing,
                        error.TlsAlpnProtocolNotOffered,
                        => error.AlpnMismatch,
                        error.CertificateHostMismatch,
                        error.CertificateExpired,
                        error.CertificateSignatureInvalid,
                        error.CertificateIssuerNotFound,
                        error.TlsCertificateNotVerified,
                        error.SignatureVerificationFailed,
                        // The RFC 5280 chain rules of `verifyIssued`. A
                        // forged leaf signed by a certificate that is not
                        // a certificate authority is a refused
                        // certificate, which is exit 60, and not a
                        // handshake that did not agree, which is exit 35.
                        error.CertificateIssuerNotCa,
                        error.CertificateIssuerCannotSignCertificates,
                        error.CertificateNotForServerAuth,
                        error.CertificateNameNotPermitted,
                        error.CertificatePathLengthExceeded,
                        error.CertificateChainTooLong,
                        // The cryptographic floor and the two reading
                        // rules of the bounded certificate walk. Each one
                        // refuses a certificate, so each one is exit 60
                        // and not a handshake that did not agree.
                        error.CertificateSignatureAlgorithmWeak,
                        error.CertificatePublicKeyTooWeak,
                        error.CertificateHasDuplicateExtension,
                        error.CertificateSignatureAlgorithmMismatch,
                        error.CertificateNotYetValid,
                        error.CertificateIssuerMismatch,
                        => error.PeerFailedVerification,
                        else => error.HandshakeFailed,
                    };
                };
                // The Initial keys are dropped once the handshake keys
                // exist, which RFC 9001 section 4.9.1 asks for.
                if (self.handshake.session.handshake != null and self.handshake.session.initial != null) {
                    self.handshake.session.dropInitialKeys();
                    self.recovery.discardSpace(.initial, self.now());
                    self.recovery.onHandshakeKeys();
                    self.dropRecords(.initial);
                }
            },
            .handshake_done => {
                // RFC 9001 section 4.1.2: this is what confirms the
                // handshake for a client.
                if (!self.confirmed) {
                    self.confirmed = true;
                    self.handshake.session.handshakeDone();
                    self.recovery.onHandshakeConfirmed(self.now());
                    self.recovery.discardSpace(.handshake, self.now());
                    self.dropRecords(.handshake);
                }
            },
            .new_token => {},
            // **Discarded on purpose, and the reason is written down so
            // that the next reader does not have to find it again.**
            //
            // A `NEW_CONNECTION_ID` frame offers a connection id this side
            // may send to, with a Stateless Reset Token that belongs to
            // that id. RFC 9000 section 10.3.1 says a token applies only
            // to the connection id that is in use. This build never
            // migrates, never probes a second path, and never retires the
            // server's first id, so no id this frame offers is ever in
            // use and no token it carries can ever apply. Keeping them
            // would be a table this side reads from nowhere.
            //
            // **The Stateless Reset this build can see is still seen.**
            // The token for the id that *is* in use arrives in the
            // server's transport parameters, and `checkStatelessReset`
            // compares every unreadable datagram against it. That closes
            // the case this frame would otherwise have covered.
            //
            // `retire_connection_id` names an id this side handed out. A
            // client that offers one id has nothing this frame can retire,
            // and the frame is not a fault.
            //
            // What is left open, and it is a feature and not a defect:
            // this side does not count the ids the peer offers against the
            // `active_connection_id_limit` it advertised, so a peer that
            // offers more than two is not answered with
            // CONNECTION_ID_LIMIT_ERROR. The frames are read and dropped,
            // so the cost of one is the cost of parsing it and nothing is
            // stored. The decoder already bounds the id length at 20 and
            // refuses `retire_prior_to` above `sequence_number`.
            .new_connection_id, .retire_connection_id => {},
            .path_challenge => |data| {
                // **RFC 9000 section 8.2.2 makes the answer mandatory,
                // and this build answers.** A client that never migrates
                // still gets challenged: a server probes the path after a
                // NAT rebinding, and a server that hears no
                // `PATH_RESPONSE` decides the path is dead and stops
                // sending. The transfer would then stall until the idle
                // timer with nothing to report.
                //
                // The answer is queued and not written here. `readFrame`
                // runs inside the read of one datagram, and a write from
                // inside a read would put a packet on the wire in the
                // middle of parsing another. `fillPayload` picks it up on
                // the next `flush`.
                self.path.onChallenge(data);
            },
            .path_response => {},
            .stream => |s| self.streams.onStream(s) catch |err| return self.streamFault(err),
            .reset_stream => |r| self.streams.onResetStream(r) catch |err| return self.streamFault(err),
            .stop_sending => |s| self.streams.onStopSending(s) catch |err| return self.streamFault(err),
            .max_data => |value| self.streams.onMaxData(value),
            .max_stream_data => |m| self.streams.onMaxStreamData(m) catch |err| return self.streamFault(err),
            .max_streams => |m| self.streams.onMaxStreams(m) catch |err| return self.streamFault(err),
            .data_blocked, .stream_data_blocked, .streams_blocked => {
                // The peer says a window of this side's is in its way.
                // The window updates already go out as the caller reads,
                // so there is nothing more to do than not close.
            },
            .connection_close => |c| {
                var closed: Closed = .{
                    .application = c.application,
                    .code = c.error_code,
                    .reason_len = 0,
                    .reason_storage = undefined,
                };
                closed.reason_len = frame.sanitizeReason(c.reason, &closed.reason_storage).len;
                self.closed = closed;
            },
        }
    }

    /// Whether RFC 9000 section 12.4 Table 3 lets `f` ride in an Initial
    /// or a Handshake packet.
    ///
    /// The table is read here and not in `zurl-quic/frame.zig`, because
    /// that file decodes a frame and takes no view of where it may sit.
    fn allowedBeforeOneRtt(f: frame.Frame) bool {
        return switch (f) {
            .padding, .ping, .ack, .crypto => true,
            // Only the transport form, 0x1c. RFC 9000 section 19.19 keeps
            // the application form, 0x1d, out of these two levels,
            // because no application data exists yet to close.
            .connection_close => |c| !c.application,
            else => false,
        };
    }

    fn streamFault(self: *Connection, err: quic.Streams.Error) Error {
        const code = quic.Streams.errorCode(err);
        return self.fail(error.ConnectionClosed, code.name());
    }

    fn onAck(self: *Connection, space: loss.Space, ack: frame.Ack) Error!void {
        const shift: u6 = if (self.handshake.peerParameters()) |p| p.ackDelayShift() else 3;
        const outcome = self.recovery.onAckReceived(
            space,
            ack,
            self.now(),
            shift,
            self.lost_numbers,
        ) catch |err| return switch (err) {
            error.AckedUnsentPacket => self.fail(error.ConnectionClosed, "the server acknowledged a packet this side never sent"),
            else => self.fail(error.ConnectionClosed, "the server sent an ACK frame this build could not read"),
        };

        // The acknowledged records, walked from the frame's own ranges.
        // `Recovery` reports how many were newly acknowledged and not
        // which, and only this side knows what each packet carried.
        //
        // **The walk stops where `Recovery`'s walk stops.** `Recovery`
        // uses the first `max_ack_ranges` ranges of a frame, and a walk
        // here that went further would clear a record that `Recovery`
        // still holds. `Recovery` would then declare that packet lost,
        // `onPacketLost` would find a dead record, and the bytes would
        // never go out again. One bound, read from the one place that
        // owns it.
        //
        // `onAckReceived` already pulled every range of the frame and
        // refused a subtraction that runs below zero, so `next` cannot
        // fail here. It is still not swallowed: an error means the two
        // walks disagree about the same bytes, and that is a fault worth
        // reporting.
        var it = ack.iterator();
        var walked: usize = 0;
        while (walked < quic.Recovery.max_ack_ranges) : (walked += 1) {
            const maybe = it.next() catch
                return self.fail(error.ConnectionClosed, "the server sent an ACK frame whose ranges read two different ways");
            const range = maybe orelse break;
            for (self.records) |*record| {
                if (!record.live or record.space != space) continue;
                if (record.number < range.smallest or record.number > range.largest) continue;
                self.applyAcked(record);
            }
        }
        // RFC 9001 section 6.1 bars a second key update until a packet
        // this side sent in the new phase is acknowledged. Nothing else
        // clears `update_pending`, so without this one update is all a
        // connection could ever run.
        if (space == .application and outcome.newly_acked > 0) {
            self.handshake.session.confirmUpdate();
        }

        for (self.lost_numbers[0..outcome.lost]) |number| self.onPacketLost(space, number);
    }

    fn applyAcked(self: *Connection, record: *Record) void {
        for (record.frames[0..record.len]) |tracked| switch (tracked) {
            .crypto => |c| {
                if (self.crypto[@intFromEnum(c.level)]) |*buffer| buffer.onAcked(c.offset, c.len, false);
            },
            .stream => |s| {
                if (self.streams.get(s.id)) |slot| self.streams.onAcked(slot, s.offset, s.len, s.fin);
            },
            .reset_stream => |id| {
                if (self.streams.get(id)) |slot| self.streams.onResetAcked(slot);
            },
            .stop_sending, .max_data, .max_stream_data, .max_streams, .ping => {},
        };
        record.live = false;
        record.len = 0;
    }

    fn onPacketLost(self: *Connection, space: loss.Space, number: u64) void {
        for (self.records) |*record| {
            if (!record.live or record.space != space or record.number != number) continue;
            for (record.frames[0..record.len]) |tracked| switch (tracked) {
                .crypto => |c| {
                    if (self.crypto[@intFromEnum(c.level)]) |*buffer| buffer.onLost(c.offset, c.len, false);
                },
                .stream => |s| {
                    if (self.streams.get(s.id)) |slot| self.streams.onLost(slot, s.offset, s.len, s.fin);
                },
                .reset_stream => |id| {
                    if (self.streams.get(id)) |slot| slot.pending_reset = slot.peer_stop_code orelse 0;
                },
                .stop_sending => |id| {
                    if (self.streams.get(id)) |slot| slot.pending_stop = slot.pending_stop orelse 0;
                },
                // A window update that was lost is replaced by the next
                // one, which names a larger number. RFC 9000 section
                // 13.3.
                .max_data, .max_stream_data, .max_streams, .ping => {},
            };
            record.live = false;
            record.len = 0;
        }
    }

    fn dropRecords(self: *Connection, space: loss.Space) void {
        for (self.records) |*record| {
            if (record.live and record.space == space) {
                record.live = false;
                record.len = 0;
            }
        }
    }

    // ---------------------------------------------------------------
    // The stream interface the engine above uses
    // ---------------------------------------------------------------

    /// Opens a stream of `kind`.
    pub fn openStream(self: *Connection, kind: stream_mod.Kind) Error!*quic.Streams.Stream {
        return self.streams.open(kind) catch |err| switch (err) {
            error.NoStreamSlot => error.TooManyStreams,
            error.StreamLimitError => error.StreamLimitReached,
            else => error.TransportFailed,
        };
    }

    /// Writes onto a stream, sending as much as the windows allow.
    ///
    /// Returns how many bytes it took. A return below `bytes.len` means
    /// the send buffer is full and the caller must pump the connection
    /// before it writes again.
    pub fn write(self: *Connection, slot: *quic.Streams.Stream, bytes: []const u8) Error!usize {
        const taken = self.streams.write(slot, bytes);
        try self.flush();
        return taken;
    }

    /// Closes the sending half of a stream.
    pub fn finishStream(self: *Connection, slot: *quic.Streams.Stream) Error!void {
        self.streams.finish(slot);
        try self.flush();
    }

    /// Takes readable bytes off a stream, waiting for the network when
    /// there are none.
    ///
    /// Returns zero when the stream has ended.
    pub fn read(self: *Connection, slot: *quic.Streams.Stream, out: []u8, timeout_ms: i64) Error!usize {
        const deadline = waitFor(timeout_ms).toDeadline(self.io);
        while (true) {
            const moved = self.streams.read(slot, out);
            if (moved > 0) {
                try self.flush();
                return moved;
            }
            if (slot.recv_state.finished() or slot.recv_state.reset()) return 0;
            if (self.closed != null) return self.fail(error.ConnectionClosed, "the peer closed the connection");
            try self.flush();
            try self.receiveOne(deadline);
        }
    }

    /// Runs one round of the loop: sends what is due, then waits for a
    /// datagram.
    pub fn pump(self: *Connection, timeout_ms: i64) Error!void {
        try self.flush();
        try self.receiveOne(waitFor(timeout_ms).toDeadline(self.io));
    }

    /// Writes a `CONNECTION_CLOSE` frame carrying an application error
    /// code. RFC 9000 section 19.19.
    pub fn close(self: *Connection, code: u64, reason: []const u8) void {
        if (self.close_sent or self.closed != null) return;
        const keys = self.handshake.session.writeKeys(.application) orelse return;
        const number = self.handshake.session.nextPacketNumber(.application) catch return;

        var writer: std.Io.Writer = .fixed(self.payload);
        frame.encode(.{ .connection_close = .{
            .application = true,
            .error_code = code,
            .frame_type = null,
            .reason = reason,
        } }, &writer) catch return;
        const body = writer.buffered();

        const pn_len = packet.encodedPacketNumberLen(number, null);
        const header_len = self.writeHeader(.application, self.datagram_out, number, pn_len, body.len);
        if (header_len + body.len + protection.tag_len > self.datagram_out.len) return;
        keys.seal(
            self.datagram_out[header_len..][0 .. body.len + protection.tag_len],
            body,
            self.datagram_out[0..header_len],
            number,
        );
        const total = header_len + body.len + protection.tag_len;
        header_protection.apply(self.datagram_out[0..total], header_len - pn_len, &keys) catch return;
        self.socket.send(self.io, &self.peer, self.datagram_out[0..total]) catch {};
        self.close_sent = true;
    }
};

/// What a client does with one Retry packet. RFC 9000 section 17.2.5.2.
const RetryVerdict = enum {
    /// The packet is dropped and the connection carries on as though it
    /// never arrived.
    discard,
    /// The integrity tag checked and the Retry came before any packet
    /// from the server, so the real server sent it.
    verified,
};

/// Decides what to do with one whole Retry packet.
///
/// **A Retry is not protected by any connection key, so this is the only
/// thing that tells the server from anybody on the path.** A Retry
/// carries no packet number and no AEAD payload, so the open that
/// authenticates every other packet does not run on it. RFC 9000 section
/// 17.2.5.2 gives a client two rules instead, and both are here:
///
/// 1. A Retry whose Retry Integrity Tag does not check is discarded. Only
///    somebody who saw the client's first Initial packet can write the
///    tag, because the tag covers the Destination Connection ID of that
///    packet and the packet is the only place that id appears.
/// 2. A Retry that arrives after a packet from the server has opened is
///    discarded, whatever the tag says. A Retry answers a first Initial
///    packet, so one that comes later answers nothing.
///
/// The connection id the tag is computed over is `odcid`, the Destination
/// Connection ID of the client's **first** Initial packet, and not the id
/// the connection sends to now. The two are the same until the server's
/// Source Connection ID is adopted, and after that only `odcid` gives the
/// tag the RFC prints.
///
/// The check runs through `quic_tls.Handshake.VerifiedRetry.verify`,
/// which is the type that states the rule: the check is its constructor,
/// and `Handshake.Options.retry_source_connection_id` takes nothing else.
/// The value it returns is what a build that answered a Retry would pass
/// to a second handshake. This build sends no second Initial packet, so
/// the value is dropped and the caller ends the connection with a reason
/// a user can read.
fn retryVerdict(
    odcid: packet.ConnectionId,
    retry: []const u8,
    scid: packet.ConnectionId,
    server_seen: bool,
) RetryVerdict {
    if (server_seen) return .discard;
    _ = quic_tls.Handshake.VerifiedRetry.verify(odcid.slice(), retry, scid) catch
        return .discard;
    return .verified;
}

fn handshakeCause(err: anyerror) []const u8 {
    return switch (err) {
        error.TlsAlpnMissing => "the server sent no ALPN extension, and RFC 9001 section 8.1 requires one",
        error.TlsAlpnProtocolNotOffered => "the server chose an ALPN protocol that was never offered",
        error.CertificateHostMismatch => "the certificate does not name this host",
        error.CertificateExpired => "the certificate has expired",
        error.CertificateIssuerNotFound => "the certificate chain reaches no trusted root",
        error.CertificateIssuerNotCa => "a certificate in the chain signed the one below it and is not a certificate authority",
        error.CertificateIssuerCannotSignCertificates => "a certificate authority in the chain does not allow its key to sign a certificate",
        error.CertificateNotForServerAuth => "a certificate in the chain carries an extended key usage that does not allow it to stand for a TLS server",
        error.CertificateNameNotPermitted => "a certificate authority in the chain is not allowed to answer for this host name",
        error.CertificateSignatureAlgorithmWeak => "a certificate in the chain is signed with SHA-1 or MD5, whose collision resistance is broken",
        error.CertificatePublicKeyTooWeak => "a certificate in the chain carries an RSA key below the 2048 bit floor",
        error.CertificateHasDuplicateExtension => "the certificate carries one extension twice, so its meaning is not decided",
        error.CertificateSignatureAlgorithmMismatch => "the certificate names one signature algorithm in two places, and the two disagree",
        error.CertificatePathLengthExceeded => "a certificate authority in the chain sits above more certificates than it allows",
        error.CertificateChainTooLong => "the certificate chain holds more certificates than zurl walks",
        // **What this name means on the QUIC path.**
        // `zurl_tls.Client.quic.verifyCertificate` reports it after it has
        // read every certificate the server sent and reached no trusted
        // root with any of them, so the sentence has to say that and not
        // that the server sent nothing. Measured against
        // `--http3 --cacert <a root that issued nothing here>`: the server
        // sent a whole chain and this is the name that came back.
        error.TlsCertificateNotVerified => "the certificate chain reaches no trusted root",
        error.SignatureVerificationFailed => "the certificate verify signature did not check out",
        error.TlsConnectionIdMismatch => "the server echoed a connection id that does not match",
        error.TlsTransportParametersMissing => "the server sent no quic transport parameters",
        error.TlsHelloRetryRequest => "the server asked for a second client hello, which this build does not send",
        else => "the quic tls handshake did not complete",
    };
}

/// Whether two addresses name the same host **and the same port**.
///
/// The port used to be left out, on a reading of RFC 9000 section 9. That
/// section is about migration, and this build does not migrate. RFC 9000
/// section 9 asks a client to discard a packet from any address it was
/// not told about, and the port is part of the address a client dialled.
/// One comparison closes the door on a peer that answers from another
/// port on the same host, so it is closed. An attacker who can spoof the
/// address can spoof the port too, so this is depth and not a wall.
fn sameAddress(a: Io.net.IpAddress, b: Io.net.IpAddress) bool {
    return switch (a) {
        .ip4 => |left| switch (b) {
            .ip4 => |right| std.mem.eql(u8, &left.bytes, &right.bytes) and left.port == right.port,
            .ip6 => false,
        },
        .ip6 => |left| switch (b) {
            .ip4 => false,
            .ip6 => |right| std.mem.eql(u8, &left.bytes, &right.bytes) and left.port == right.port,
        },
    };
}

const testing = std.testing;

test "a datagram from another address is not the peer" {
    // The same class of fault the TFTP fetcher had at the P2 review: the
    // first datagram from anybody became the peer.
    const peer: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 443 } };
    const same_host_other_port: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 4433 } };
    const other_host: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 443 } };

    // The port is part of the address this side dialled, so another port
    // on the same host is another peer.
    try testing.expect(!sameAddress(peer, same_host_other_port));
    try testing.expect(sameAddress(peer, peer));
    try testing.expect(!sameAddress(peer, other_host));

    // An IPv6 address never matches an IPv4 one, whatever the bytes hold.
    const six: Io.net.IpAddress = .{ .ip6 = .loopback(443) };
    try testing.expect(!sameAddress(peer, six));
    try testing.expect(!sameAddress(six, peer));
    try testing.expect(sameAddress(six, six));
}

/// Seals `payload` into `out` at `level` under `keys`, the way
/// `buildPacket` does, and returns the whole packet.
///
/// The steps are the send recipe of RFC 9001 section 5: write the header,
/// seal the payload with the header as additional data, then apply header
/// protection over the packet number.
fn sealForTest(
    out: []u8,
    level: protection.Level,
    dcid: packet.ConnectionId,
    scid: packet.ConnectionId,
    number: u64,
    payload: []const u8,
    keys: *const protection.Keys,
) ![]u8 {
    const pn_len = packet.encodedPacketNumberLen(number, null);
    const header_len = writeHeaderInto(.{
        .level = level,
        .out = out,
        .dcid = dcid,
        .scid = scid,
        .number = number,
        .pn_len = pn_len,
        .body_len = payload.len,
    });
    keys.seal(out[header_len..][0 .. payload.len + protection.tag_len], payload, out[0..header_len], number);
    const total = header_len + payload.len + protection.tag_len;
    try header_protection.apply(out[0..total], header_len - pn_len, keys);
    return out[0..total];
}

test "an Initial packet this file builds is one a server can read back" {
    // **This is the send path, checked against the read path of the same
    // package.** The Initial keys of RFC 9001 section 5.2 need no
    // handshake, so a client key set and the matching server key set are
    // both derivable here, and a server is exactly what opens a packet
    // this file wrote.
    //
    // The bug this test exists for: the Length field was spelled with the
    // two high bits `11`, which is an eight byte varint, where four bytes
    // wants `10`. Every packet was unreadable and the peer answered
    // nothing at all.
    const dcid: packet.ConnectionId = try .init(&.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 });
    const scid: packet.ConnectionId = try .init(&.{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 });
    const client_keys = quic.initial.clientKeys(dcid.slice());
    var server_keys = quic.initial.serverKeys(dcid.slice());
    // A server opens a client's packet with the client's own key set.
    server_keys = client_keys;

    var payload: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&payload);
    try frame.encode(.{ .crypto = .{ .offset = 0, .data = "hello handshake" } }, &writer);
    try frame.encode(.{ .ping = {} }, &writer);
    const body = writer.buffered();

    var datagram: [256]u8 = undefined;
    const built = try sealForTest(&datagram, .initial, dcid, scid, 2, body, &client_keys);

    // The read path, exactly as `processLong` runs it.
    const parsed = try packet.parseLong(built);
    try testing.expectEqual(packet.Version.v1, parsed.version);
    try testing.expect(parsed.dcid.eql(&dcid));
    try testing.expect(parsed.scid.eql(&scid));
    try testing.expectEqual(built.len, parsed.packetLen(built));

    const pn_len = try header_protection.remove(built, parsed.pn_offset, &server_keys);
    // The reserved bits are zero once header protection is off. RFC 9000
    // section 17.2.
    try testing.expectEqual(@as(u8, 0), built[0] & packet.long_reserved_mask);
    const truncated = try packet.readPacketNumber(built[parsed.pn_offset..], pn_len);
    const number = packet.decodePacketNumber(0, truncated, @as(u6, pn_len) * 8);
    try testing.expectEqual(@as(u64, 2), number);

    const length: usize = @intCast(parsed.body.initial.length);
    const aad = built[0 .. parsed.pn_offset + pn_len];
    const sealed = built[parsed.pn_offset + pn_len ..][0 .. length - pn_len];
    var opened: [256]u8 = undefined;
    const n = try server_keys.open(&opened, sealed, aad, number);
    try testing.expectEqualSlices(u8, body, opened[0..n]);

    var decoder: frame.Decoder = .init(opened[0..n]);
    const first = (try decoder.next()).?;
    try testing.expectEqualStrings("hello handshake", first.crypto.data);
    try testing.expectEqual(frame.Frame.ping, (try decoder.next()).?);
    try testing.expect(try decoder.next() == null);
}

test "a short header packet is read back with the key phase the sender set" {
    const dcid: packet.ConnectionId = try .init(&.{ 0xaa, 0xbb, 0xcc, 0xdd });
    const secret = [_]u8{0x2b} ** 32;
    const keys: protection.Keys = .fromSecret(.aes_128_gcm, &secret);

    for ([_]u1{ 0, 1 }) |phase| {
        var payload: [32]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&payload);
        try frame.encode(.{ .stream = .{
            .stream_id = 0,
            .offset = 0,
            .data = "abc",
            .fin = true,
            .explicit_offset = true,
            .explicit_length = true,
        } }, &writer);
        const body = writer.buffered();

        var datagram: [128]u8 = undefined;
        const pn_len = packet.encodedPacketNumberLen(7, null);
        const header_len = writeHeaderInto(.{
            .level = .application,
            .out = &datagram,
            .dcid = dcid,
            .scid = .empty,
            .number = 7,
            .pn_len = pn_len,
            .body_len = body.len,
            .key_phase = phase,
        });
        keys.seal(datagram[header_len..][0 .. body.len + protection.tag_len], body, datagram[0..header_len], 7);
        const total = header_len + body.len + protection.tag_len;
        try header_protection.apply(datagram[0..total], header_len - pn_len, &keys);

        const built = datagram[0..total];
        try testing.expectEqual(packet.Form.short, packet.form(built[0]));
        const parsed = try packet.parseShort(built, dcid.len);
        try testing.expect(parsed.dcid.eql(&dcid));

        const read_pn_len = try header_protection.remove(built, parsed.pn_offset, &keys);
        try testing.expectEqual(@as(u8, 0), built[0] & packet.short_reserved_mask);
        // The key phase is legible only once header protection is off,
        // which is why `openAndRead` reads it there and not before.
        try testing.expectEqual(phase, @as(u1, @intCast((built[0] & packet.key_phase_bit) >> 2)));

        const truncated = try packet.readPacketNumber(built[parsed.pn_offset..], read_pn_len);
        const number = packet.decodePacketNumber(0, truncated, @as(u6, read_pn_len) * 8);
        const aad = built[0 .. parsed.pn_offset + read_pn_len];
        const sealed = built[parsed.pn_offset + read_pn_len ..];
        var opened: [128]u8 = undefined;
        const n = try keys.open(&opened, sealed, aad, number);

        var decoder: frame.Decoder = .init(opened[0..n]);
        const f = (try decoder.next()).?;
        try testing.expectEqualStrings("abc", f.stream.data);
        try testing.expect(f.stream.fin);
    }
}

test "a client Initial datagram reaches the 1200 byte floor with padding inside the packet" {
    // RFC 9000 section 14.1. The padding goes in the payload, because a
    // byte after the AEAD tag is not part of the packet and a receiver
    // stops at the first zero first byte.
    const dcid: packet.ConnectionId = try .init(&.{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 });
    const scid: packet.ConnectionId = try .init(&.{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 });
    const keys = quic.initial.clientKeys(dcid.slice());

    const overhead = headerLenFor(.initial, dcid.len, scid.len, 0) + protection.tag_len;
    var payload: [max_datagram_out]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&payload);
    try frame.encode(.{ .crypto = .{ .offset = 0, .data = "a client hello would be here" } }, &writer);
    const want = loss.min_initial_datagram_bytes - overhead - writer.buffered().len;
    @memset(payload[writer.buffered().len..][0..want], 0x00);
    const body = payload[0 .. writer.buffered().len + want];

    var datagram: [max_datagram_out]u8 = undefined;
    const built = try sealForTest(&datagram, .initial, dcid, scid, 0, body, &keys);
    try testing.expect(built.len >= loss.min_initial_datagram_bytes);
    // And the whole datagram is still one packet, so a server reads it in
    // one pass.
    const parsed = try packet.parseLong(built);
    try testing.expectEqual(built.len, parsed.packetLen(built));
}

test "the header length is worked out before the payload and matches what was written" {
    // The builder needs the header length before it knows the payload, so
    // `headerLenFor` must be exact for every packet number width.
    const dcid: packet.ConnectionId = try .init(&.{ 0x01, 0x02 });
    const scid: packet.ConnectionId = try .init(&.{ 0x03, 0x04, 0x05 });
    var out: [64]u8 = undefined;
    for ([_]protection.Level{ .initial, .handshake, .application }) |level| {
        for ([_]u3{ 1, 2, 3, 4 }) |pn_len| {
            const written = writeHeaderInto(.{
                .level = level,
                .out = &out,
                .dcid = dcid,
                .scid = scid,
                .number = 1,
                .pn_len = pn_len,
                .body_len = 10,
            });
            try testing.expectEqual(headerLenFor(level, dcid.len, scid.len, pn_len), written);
        }
    }
}

test "the datagram bounds are the ones RFC 9000 section 14 asks for" {
    // A client must be able to send 1200 bytes on every path, and this
    // build sends more than that and less than a typical link allows.
    try testing.expect(max_datagram_out >= loss.min_initial_datagram_bytes);
    try testing.expect(max_datagram_out <= 1500);
    try testing.expect(max_datagram_in >= max_datagram_out);
}

test "an Initial or a Handshake packet carries only the frames RFC 9000 table 3 allows" {
    // Finding F7. Initial keys come from the destination connection id,
    // and that id travels in the clear, so anybody who reads the client's
    // first datagram can seal a packet this side will open. The frame
    // table is the boundary that stops such a packet doing anything.
    const allowed = [_]frame.Frame{
        .{ .padding = 1 },
        .ping,
        .{ .ack = .{
            .largest_acknowledged = 0,
            .ack_delay = 0,
            .ack_range_count = 0,
            .first_ack_range = 0,
            .ranges = &.{},
            .ecn = null,
        } },
        .{ .crypto = .{ .offset = 0, .data = &.{} } },
        .{ .connection_close = .{
            .application = false,
            .error_code = 0,
            .frame_type = 0,
            .reason = "",
        } },
    };
    for (allowed) |f| try testing.expect(Connection.allowedBeforeOneRtt(f));

    // Each of these does real damage at Initial level. The application
    // close kills the connection on one forged packet. `HANDSHAKE_DONE`
    // drops the handshake space before the handshake finishes. The
    // STREAM frame puts peer bytes in the reassembly buffer that the
    // HTTP/3 engine later reads as the peer's control stream.
    const refused = [_]frame.Frame{
        .{ .connection_close = .{
            .application = true,
            .error_code = 0,
            .frame_type = null,
            .reason = "",
        } },
        .handshake_done,
        .{ .stream = .{ .stream_id = 3, .offset = 0, .data = &.{}, .fin = false } },
        .{ .max_data = 0 },
        .{ .new_token = .{ .token = &.{} } },
        .{ .path_response = @splat(0) },
        .{ .retire_connection_id = 0 },
    };
    for (refused) |f| try testing.expect(!Connection.allowedBeforeOneRtt(f));
}

test "the replay gate asks the same question the range set answers" {
    // Finding F13. RFC 9000 section 12.3 discards a packet whose number
    // was already processed. `readFrames` used to record the number
    // **after** the frames took effect and throw the verdict away, so a
    // replayed packet was processed twice. It now asks `contains` before
    // any frame runs, so the gate must give exactly the answer `record`
    // would have given.
    const options: quic.AckRanges.RecordOptions = .{
        .ack_eliciting = true,
        .handshake_space = false,
        .max_ack_delay = 25 * std.time.ns_per_ms,
    };

    var set: quic.AckRanges = .{};
    var mirror: quic.AckRanges = .{};

    // A run with gaps, out of order, so the walk crosses several ranges.
    const arrivals = [_]u64{ 0, 1, 2, 9, 4, 5, 12, 11, 3, 20 };
    for (arrivals) |number| {
        _ = set.record(number, 0, options);
        _ = mirror.record(number, 0, options);
    }

    var number: u64 = 0;
    while (number <= 24) : (number += 1) {
        const gate = set.contains(number);
        // What the old code learned only after the damage was done.
        const verdict = mirror.record(number, 0, options);
        try testing.expectEqual(gate, verdict == .duplicate);
    }
}

test "a probe passes the congestion window and never the amplification budget" {
    // Finding F19. `buildDatagram` gated every send on `canSend`, which
    // applies the congestion window, so a full window meant `onTimeout`
    // built nothing and the connection deadlocked. RFC 9002 section 7
    // says a probe ignores the window on purpose.
    var recovery: quic.Recovery = .init(.{
        .role = .client,
        .max_datagram_size = max_datagram_out,
        .peer_max_ack_delay = 25 * std.time.ns_per_ms,
    });

    // Nothing has opened yet, so the anti-amplification budget is what a
    // client starts with and both gates pass.
    try testing.expect(recovery.canSend(max_datagram_out));
    try testing.expect(recovery.canSendProbe(max_datagram_out));

    // Fill the congestion window.
    var number: u64 = 0;
    while (recovery.canSend(max_datagram_out)) : (number += 1) {
        try recovery.onPacketSent(.application, .{
            .number = number,
            .sent_time = 0,
            .size = max_datagram_out,
            .ack_eliciting = true,
            .in_flight = true,
        });
        recovery.onDatagramSent(max_datagram_out);
        if (number > 512) break;
    }

    // The window is shut and the probe still goes out.
    try testing.expect(!recovery.canSend(max_datagram_out));
    try testing.expect(recovery.canSendProbe(max_datagram_out));
}

test "a path challenge is answered, and the answer is the peer's own eight octets" {
    // RFC 9000 section 8.2.2. The old code read the frame and discarded
    // it while a comment said it answered. A server that probes the path
    // and hears nothing decides the path is dead and stops sending.
    var responder: PathResponder = .{};
    try testing.expectEqual(@as(?[frame.path_data_len]u8, null), responder.owed());

    const data: [frame.path_data_len]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    responder.onChallenge(data);
    try testing.expectEqual(data, responder.owed().?);

    // A second challenge before the first answer went out replaces it,
    // because that is the one the peer is now timing.
    const newer: [frame.path_data_len]u8 = .{ 9, 9, 9, 9, 9, 9, 9, 9 };
    responder.onChallenge(newer);
    try testing.expectEqual(newer, responder.owed().?);

    // The answer goes out once and is not owed again. Section 13.3 keeps
    // `PATH_RESPONSE` out of the retransmission table.
    responder.onSent();
    try testing.expectEqual(@as(?[frame.path_data_len]u8, null), responder.owed());
    try testing.expectEqual(@as(u64, 1), responder.sent);
    try testing.expectEqual(@as(u64, 0), responder.dropped);

    // The frame this builds is the one RFC 9000 section 19.18 writes, and
    // it carries the data back unchanged.
    var out: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&out);
    try frame.encode(.{ .path_response = newer }, &writer);
    var decoder: frame.Decoder = .init(writer.buffered());
    const decoded = (try decoder.next()).?;
    try testing.expectEqual(newer, decoded.path_response);
}

test "a peer that challenges for ever is dropped at the bound instead of answered for ever" {
    // The answer is work this side does for the peer, so it is counted.
    var responder: PathResponder = .{};
    var rounds: u64 = 0;
    while (rounds < max_path_responses) : (rounds += 1) {
        responder.onChallenge(@splat(@truncate(rounds)));
        try testing.expect(responder.owed() != null);
        responder.onSent();
    }
    try testing.expectEqual(max_path_responses, responder.sent);

    // Past the bound a challenge is dropped and counted, and the
    // connection carries on.
    responder.onChallenge(@splat(0xaa));
    try testing.expectEqual(@as(?[frame.path_data_len]u8, null), responder.owed());
    try testing.expectEqual(@as(u64, 1), responder.dropped);
}

test "the live path challenge arm queues an answer and the packet builder writes it" {
    // The finding was that the frame arm discarded the challenge while
    // its comment said it answered. The needles are built at run time, so
    // this test's own text is not what it finds.
    const source = @embedFile("quic.zig");

    var arm_buf: [48]u8 = undefined;
    const arm = std.fmt.bufPrint(&arm_buf, ".path_{s} => |data| {c}", .{ "challenge", '{' }) catch unreachable;
    const arm_at = std.mem.indexOf(u8, source, arm) orelse return error.ArmNotFound;

    var end_buf: [48]u8 = undefined;
    const end = std.fmt.bufPrint(&end_buf, ".path_{s} => {c}{c}", .{ "response", '{', '}' }) catch unreachable;
    const end_at = std.mem.indexOfPos(u8, source, arm_at, end) orelse return error.EndNotFound;

    var take_buf: [48]u8 = undefined;
    const take = std.fmt.bufPrint(&take_buf, "self.path.on{s}(data)", .{"Challenge"}) catch unreachable;
    _ = std.mem.indexOf(u8, source[arm_at..end_at], take) orelse return error.ChallengeNotQueued;

    // And the builder writes the frame and clears what it owes.
    var fill_buf: [48]u8 = undefined;
    const fill = std.fmt.bufPrint(&fill_buf, "fn fill{s}(", .{"Payload"}) catch unreachable;
    const fill_at = std.mem.indexOf(u8, source, fill) orelse return error.BuilderNotFound;

    var owed_buf: [48]u8 = undefined;
    const owed = std.fmt.bufPrint(&owed_buf, "self.path.{s}()", .{"owed"}) catch unreachable;
    const owed_at = std.mem.indexOfPos(u8, source, fill_at, owed) orelse return error.AnswerNeverBuilt;

    var sent_buf: [48]u8 = undefined;
    const sent = std.fmt.bufPrint(&sent_buf, "self.path.on{s}()", .{"Sent"}) catch unreachable;
    const sent_at = std.mem.indexOfPos(u8, source, owed_at, sent) orelse return error.AnswerNeverCounted;
    try testing.expect(owed_at < sent_at);
}

test "a datagram ending in the peer's reset token is a stateless reset" {
    // RFC 9000 section 10.3. Without this comparison a peer that lost its
    // state cannot say so, and the transfer waits for the idle timer.
    const token: [transport_parameters.stateless_reset_token_len]u8 = .{
        0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
        0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
    };

    // The shortest datagram section 10.3 allows: one header byte, four
    // unpredictable bytes, and the token.
    var shortest: [min_stateless_reset_bytes]u8 = @splat(0);
    shortest[0] = 0x40;
    shortest[min_stateless_reset_bytes - token.len ..].* = token;
    try testing.expect(statelessResetMatches(&shortest, token));

    // One octet shorter cannot be a reset, whatever it holds.
    try testing.expect(!statelessResetMatches(shortest[1..], token));
    try testing.expect(!statelessResetMatches(&token, token));
    try testing.expect(!statelessResetMatches(&.{}, token));

    // A longer datagram is read from its end, because section 10.3 puts
    // the token last and the bytes in front of it are chosen to look like
    // a short header packet.
    var longer: [200]u8 = @splat(0x5a);
    longer[200 - token.len ..].* = token;
    try testing.expect(statelessResetMatches(&longer, token));

    // One octet of the token wrong is not a reset.
    var wrong = longer;
    wrong[199] ^= 0x01;
    try testing.expect(!statelessResetMatches(&wrong, token));
    // And neither is a datagram that carries the token anywhere but last.
    var moved: [200]u8 = @splat(0x5a);
    moved[100..][0..token.len].* = token;
    try testing.expect(!statelessResetMatches(&moved, token));
}

test "a stateless reset is read only after nothing in the datagram opened" {
    // RFC 9000 section 10.3.1 puts the comparison after the datagram is
    // known not to be processable, so a packet that opens is never read
    // as a reset. The order lives in `processDatagram`, and a test that
    // could not see the order would not see it move. The needles are
    // built at run time, the way the Retry test above builds its own, so
    // this test's text is not what it finds.
    const source = @embedFile("quic.zig");

    var name_buf: [64]u8 = undefined;
    const name = std.fmt.bufPrint(&name_buf, "fn process{s}(self: *Connection", .{"Datagram"}) catch unreachable;
    const at = std.mem.indexOf(u8, source, name) orelse return error.FunctionNotFound;

    var end_buf: [64]u8 = undefined;
    const end = std.fmt.bufPrint(&end_buf, "fn check{s}(self: *Connection", .{"StatelessReset"}) catch unreachable;
    const end_at = std.mem.indexOfPos(u8, source, at, end) orelse return error.CheckNotFound;
    const body = source[at..end_at];

    // The packets are processed first.
    var run_buf: [64]u8 = undefined;
    const run = std.fmt.bufPrint(&run_buf, "self.process{s}(datagram)", .{"Packets"}) catch unreachable;
    const run_at = std.mem.indexOf(u8, body, run) orelse return error.PacketsNotProcessed;

    // Then the count of opened packets gates the comparison.
    var gate_buf: [64]u8 = undefined;
    const gate = std.fmt.bufPrint(&gate_buf, "self.packets_{s} != opened_before", .{"opened"}) catch unreachable;
    const gate_at = std.mem.indexOf(u8, body, gate) orelse return error.GateMissing;

    // And only then is the token compared.
    var call_buf: [64]u8 = undefined;
    const call = std.fmt.bufPrint(&call_buf, "self.check{s}(datagram)", .{"StatelessReset"}) catch unreachable;
    const call_at = std.mem.indexOf(u8, body, call) orelse return error.CheckNotCalled;

    try testing.expect(run_at < gate_at);
    try testing.expect(gate_at < call_at);
}

/// The Retry packet of RFC 9001 appendix A.4, integrity tag included.
/// `zurl-quic/rfc9001_test.zig` checks the tag itself against the same
/// vector, and this file checks what the live path does with it.
const a4_retry = [_]u8{
    0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50,
    0x2a, 0x42, 0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2,
    0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f, 0x0f,
    0x24, 0x96, 0xba,
};

/// The Destination Connection ID of the client's first Initial packet in
/// RFC 9001 appendix A. The tag above is computed over this id, and the
/// id is in no packet the Retry carries.
const a4_odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

test "a Retry verifies only with the integrity tag RFC 9001 appendix A.4 printed" {
    const odcid: packet.ConnectionId = try .init(&a4_odcid);
    const parsed = try packet.parseLong(&a4_retry);
    try testing.expectEqual(packet.LongType.retry, @as(packet.LongType, parsed.body));
    try testing.expectEqual(
        RetryVerdict.verified,
        retryVerdict(odcid, &a4_retry, parsed.scid, false),
    );

    // One changed octet anywhere breaks the tag, so the packet is
    // dropped. The walk covers the first byte, the two connection ids,
    // the token, and the tag itself.
    for (0..a4_retry.len) |at| {
        var broken = a4_retry;
        broken[at] ^= 0x01;
        // A changed length byte can stop the packet being a Retry this
        // side can read at all, and that is a discard as well.
        const verdict = if (packet.parseLong(&broken)) |p|
            retryVerdict(odcid, &broken, p.scid, false)
        else |_|
            RetryVerdict.discard;
        try testing.expectEqual(RetryVerdict.discard, verdict);
    }

    // The tag is tied to the client's own first Initial packet, so the
    // same Retry checked against another id does not verify. That is what
    // stops anybody on the path restarting a handshake with a connection
    // id of their own choosing.
    const other: packet.ConnectionId = try .init(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try testing.expectEqual(
        RetryVerdict.discard,
        retryVerdict(other, &a4_retry, parsed.scid, false),
    );
}

test "a forged Retry with an all zero integrity tag is discarded and the connection carries on" {
    // The security review reproduced this against a release build: one
    // 39 byte datagram, written by anybody who saw the client's first
    // Initial packet in the clear, ended every HTTP/3 request at exit 35.
    // The tag was never read. RFC 9000 section 17.2.5.2 discards the
    // packet instead.
    const odcid: packet.ConnectionId = try .init(&a4_odcid);

    // The Source Connection ID the client put in its own Initial packet,
    // which travels in the clear and is the only value the attacker needs.
    const client_scid = [_]u8{ 0x5f, 0x4c, 0xbf, 0x4f, 0xa3, 0x12, 0x38, 0x82 };

    var forged: [39]u8 = @splat(0);
    forged[0] = 0xf0; // long header, fixed bit, and type 3, a Retry
    forged[1..5].* = .{ 0x00, 0x00, 0x00, 0x01 }; // version 1
    forged[5] = client_scid.len;
    forged[6..14].* = client_scid;
    forged[14] = 4;
    forged[15..19].* = .{ 0xde, 0xad, 0xbe, 0xef }; // any Source Connection ID
    forged[19..23].* = .{ 'A', 'A', 'A', 'A' }; // the Retry Token
    // The last 16 bytes are the integrity tag, and they are all zero.

    const parsed = try packet.parseLong(&forged);
    try testing.expectEqual(packet.LongType.retry, @as(packet.LongType, parsed.body));
    try testing.expectEqualStrings("AAAA", parsed.body.retry.token);
    try testing.expect(parsed.dcid.eql(&(try packet.ConnectionId.init(&client_scid))));

    try testing.expectEqual(
        RetryVerdict.discard,
        retryVerdict(odcid, &forged, parsed.scid, false),
    );
}

test "a Retry that comes after a packet from the server is discarded even when its tag checks" {
    // RFC 9000 section 17.2.5.2. A Retry answers a first Initial packet,
    // so one that arrives after the server has been heard answers
    // nothing. Without this rule the packet stays effective for the whole
    // life of the connection, after the handshake is confirmed and after
    // the Initial keys are gone.
    const odcid: packet.ConnectionId = try .init(&a4_odcid);
    const parsed = try packet.parseLong(&a4_retry);
    try testing.expectEqual(
        RetryVerdict.verified,
        retryVerdict(odcid, &a4_retry, parsed.scid, false),
    );
    try testing.expectEqual(
        RetryVerdict.discard,
        retryVerdict(odcid, &a4_retry, parsed.scid, true),
    );
}

test "the live Retry path calls the integrity check" {
    // The finding was that `processLong` ended the connection on a Retry
    // packet nothing had authenticated, and that `verifyRetry` had no
    // caller outside a test. This test is the shape of "both certificate
    // walks call the one chain rule" in `zurl-tls/Client.zig`: the
    // needles are built at run time, so this test's own text is not what
    // it finds.
    const source = @embedFile("quic.zig");

    var arm_buf: [32]u8 = undefined;
    const arm = std.fmt.bufPrint(&arm_buf, ".{s} => {c}", .{ "retry", '{' }) catch unreachable;
    const arm_at = std.mem.indexOf(u8, source, arm) orelse return error.RetryArmNotFound;

    var end_buf: [32]u8 = undefined;
    const end = std.fmt.bufPrint(&end_buf, ".{s} => {c}", .{ "zero_rtt", '{' }) catch unreachable;
    const end_at = std.mem.indexOfPos(u8, source, arm_at, end) orelse return error.ZeroRttArmNotFound;
    const body = source[arm_at..end_at];

    // The verdict is asked for, and it is asked for before anything ends
    // the connection.
    var call_buf: [32]u8 = undefined;
    const call = std.fmt.bufPrint(&call_buf, "{s}{s}(", .{ "retry", "Verdict" }) catch unreachable;
    const call_at = std.mem.indexOf(u8, body, call) orelse return error.CheckNotCalled;

    var fail_buf: [32]u8 = undefined;
    const fails = std.fmt.bufPrint(&fail_buf, "self.{s}(", .{"fail"}) catch unreachable;
    const fail_at = std.mem.indexOf(u8, body, fails) orelse return error.NoFailInArm;
    try testing.expect(call_at < fail_at);

    // And the arm counts the packet it drops, so a discard is visible.
    var count_buf: [48]u8 = undefined;
    const counted = std.fmt.bufPrint(&count_buf, "{s}_retries += 1", .{"discarded"}) catch unreachable;
    const counted_at = std.mem.indexOf(u8, body, counted) orelse return error.DiscardNotCounted;
    try testing.expect(counted_at < fail_at);

    // The check itself goes through the one wrapper, in one place, so
    // there is no second path that could skip it.
    var verify_buf: [64]u8 = undefined;
    const verify = std.fmt.bufPrint(&verify_buf, "{s}.{s}.{s}(", .{
        "Handshake",
        "VerifiedRetry",
        "verify",
    }) catch unreachable;
    var seen: usize = 0;
    var index: usize = 0;
    while (std.mem.indexOfPos(u8, source, index, verify)) |at| {
        seen += 1;
        index = at + verify.len;
    }
    try testing.expectEqual(@as(usize, 1), seen);
}
