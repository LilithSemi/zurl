//! The HTTP/3 half of the engine, RFC 9114.
//!
//! `h1.zig` owns the policy of a transfer: it validates the headers, it
//! walks the redirect chain, it keeps every secret inside the origin the
//! url names, it asks the cookie jar once for each hop, and it owns the
//! connection pool. All of that is protocol independent, and this file
//! repeats none of it. **`Open` is the same shape `h2.Open` is**, field
//! for field where the fields mean the same thing, so the caller that
//! joins the headers with the hop's secrets is the caller that does it for
//! HTTP/2, and there is no second copy of the credential rule.
//!
//! ## The credential rule, reused and not copied
//!
//! `Open.headers` is "the caller's headers and this hop's secrets, already
//! joined". That sentence is `h2.Open.headers`'s, word for word, and it is
//! the whole of the arrangement: `engine.origin_bound_headers` is honoured
//! in `h1.openOnce`, which is the one place that reads it. **This file
//! writes the joined list as it was given and holds no rule of its own
//! about which header belongs to which origin.** It compares no header
//! name against `Authorization` or `Cookie`, and it never reads
//! `engine.origin_bound_headers`. A rule added there reaches HTTP/3 with
//! no change here, exactly as it reaches HTTP/2.
//!
//! One name in that area does appear here, and it is not the rule: the
//! response reader passes every `set-cookie` field to the cookie jar, the
//! way `h1` and `h2` do, and the jar owns every policy about it.
//!
//! ## What this file owns
//!
//! The wire above QUIC: the three unidirectional streams RFC 9114 section
//! 6.2 asks a client to open, the `SETTINGS` frame on the control stream,
//! one request as one bidirectional stream, and the `HEADERS` and `DATA`
//! frames on it. `quic.zig` is the connection under it, `zurl-h3` is the
//! framing, and `zurl-qpack` is the field compression.
//!
//! ## What is left out, and said so
//!
//! - **No server push.** This build sends no `MAX_PUSH_ID`, so RFC 9114
//!   section 7.2.7 allows the server none. A `PUSH_PROMISE` frame or a
//!   push stream is H3_ID_ERROR. curl does the same.
//! - **No 0-RTT and no session resumption**, which `zurl-quic-tls` does
//!   not offer either.
//! - **No connection reuse across requests.** One transfer opens one QUIC
//!   connection and closes it, where `h1` pools a TCP connection. A pool
//!   needs an idle timer and a path check that this build has not written.

const std = @import("std");
const Io = std.Io;
const zurl_core = @import("zurl-core");
const zurl_h3 = @import("zurl-h3");
const zurl_qpack = @import("zurl-qpack");
const zurl_quic = @import("zurl-quic");
const engine = @import("engine.zig");
const quic = @import("quic.zig");

const h3_frame = zurl_h3.frame;
const testing = std.testing;

/// The ALPN protocol name of HTTP/3. RFC 9114 section 3.1.
pub const alpn_name = zurl_h3.alpn_name;

/// The receive window this side gives each stream, in octets.
///
/// The same number `zurl-http/h2.zig` gives an HTTP/2 stream, and for the
/// same reason: the room goes back at half the window as the octets
/// arrive, so the peer keeps this much in flight the whole time.
pub const stream_window_len: u64 = 256 * 1024;

/// How many QUIC streams one connection holds at once.
///
/// Three for this side's own unidirectional streams, three for the peer's,
/// one for the request, and one spare for a unidirectional stream of a
/// type this build abandons.
pub const streams_max: usize = 8;

/// The connection receive window.
///
/// **The sum of every stream window, which is what stops a stalled reader
/// from deadlocking the connection.** `zurl_quic.Streams.init` refuses a
/// smaller number, so this is not a comment that can go stale.
pub const connection_window_len: u64 = streams_max * stream_window_len;

/// How many octets one stream may hold written and unacknowledged.
pub const send_buffer_len: usize = 64 * 1024;

/// The largest response field section this engine reads, in octets,
/// counted the way RFC 9114 section 7.2.4.1 counts one: the name, the
/// value, and 32 more for every field.
///
/// The same bound `zurl-http/h2.zig` puts on an HTTP/2 field section. **It
/// is what this side announces as `SETTINGS_MAX_FIELD_SECTION_SIZE`, and
/// `zurl_qpack.Decoder` is what enforces it**, against the decoded fields
/// and with the same 32 octets of overhead the setting names. So the
/// number this side promises and the number it checks are one quantity.
pub const header_list_len_max: usize = 300 * 1024;

/// The largest QPACK field block this engine buffers off a stream, in
/// octets.
///
/// **This bounds the compressed octets on the wire, which are not the
/// field section size.** RFC 9204 writes every length as a prefixed
/// integer that a peer may pad with continuation octets, so a block can
/// take more room on the wire than the fields inside it account for. This
/// number is what stops one allocation from growing with a frame length a
/// peer chose; `header_list_len_max` is what stops the decoded list from
/// growing. The two are equal here because every representation RFC 9204
/// defines writes a field line in fewer octets than the 32 the section
/// size already adds for it, so a block holding a legal section fits.
pub const field_block_len_max: usize = header_list_len_max;

/// The largest payload this engine buffers off the control stream.
///
/// A `SETTINGS` frame is a few pairs and a `GOAWAY` is one varint. A peer
/// that sends a longer one of a type this side acts on is refused rather
/// than given memory for it.
///
/// **The bound is on what this side buffers and on nothing else.** A frame
/// of a type this build does not know is stepped over whatever its length,
/// which RFC 9114 section 9 requires and section 7.2.8 makes ordinary
/// traffic, so its payload never reaches this buffer.
pub const control_payload_len_max: usize = 4 * 1024;

/// How many octets of a payload this engine steps over it reads at once.
///
/// A frame this side does not act on costs one fixed buffer and no
/// allocation, whatever length the peer named.
const skip_chunk_len: usize = 512;

/// How many octets of a peer's QPACK encoder stream may wait for the rest
/// of their instruction.
pub const encoder_stream_len_max: usize = 4 * 1024;

/// How many frames one response may carry that move nothing.
///
/// A peer can send reserved frames of zero length for ever. The same bound
/// `zurl-http/h2.zig` puts on idle HTTP/2 frames.
pub const idle_frames_max: usize = 1024;

/// How many octets of frames it ignores one response steps over.
///
/// **A count of frames is not a bound over HTTP/3.** An HTTP/2 frame
/// carries a 24-bit length and `zurl_h2.FrameReader` refuses one past the
/// 16384 this side advertises, so 1024 ignored frames cost 16 MB and no
/// more. RFC 9114 section 7.1 replaced that length with a QUIC varint, so
/// **one** ignored frame may declare 2^62-1 octets. `idle_frames_max`
/// counts it once. Without this bound a server declared that length, then
/// trickled the payload one octet to a round trip, and `skip` read it for
/// ever: no octet reached the body, the progress meter, or
/// `--max-filesize`, and the QUIC idle timer never fired because the peer
/// was sending.
///
/// **A frame of an unknown type is still ignored, and that is the point.**
/// RFC 9114 section 9 requires it whatever the length, and section 7.2.8
/// has a conformant peer send reserved types on purpose, so refusing the
/// type would close the connection over legal traffic. What is bounded is
/// what one ignored frame may cost this side, which is the length it
/// declares. A peer past the ceiling gets `error.ExcessiveLoad`, the local
/// answer H3_EXCESSIVE_LOAD is written for.
///
/// **What a peer buys with the octets this bounds.** Nothing it can read
/// and nothing this side keeps: the payload goes through one fixed
/// `skip_chunk_len` sink and is dropped. The cost to the peer is one octet
/// on the wire for each octet counted here, so the ceiling is the whole of
/// what a hostile peer wins, and it wins it once for each transfer.
///
/// **What an honest peer's worst case is.** A reserved frame of RFC 9114
/// section 7.2.8 is a grease frame. Every one measured is empty or a few
/// octets, and a peer sends one or two for each connection, so an honest
/// response spends single-figure octets of this. The ceiling is
/// `idle_frames_max` sinks full, 512 KB, which is more than an honest peer
/// has ever asked a client to throw away.
pub const skip_octets_max: u64 = idle_frames_max * skip_chunk_len;

// **How long one wait of this engine may take with no octet arriving is
// `Session.read_timeout`, and this file holds no number of its own.** It
// used to hold `exchange_timeout_ms`, a constant of 120 seconds handed to
// every `quic.Connection.pump` call, and two things were wrong with that.
// It answered no flag, so `--speed-time 2` waited two minutes. And it was
// a bound on one datagram wait inside a loop that turned up to
// `idle_frames_max` times, so a peer that answered one empty datagram
// every two minutes held a transfer for days while each single wait stayed
// inside its bound. The ceiling is now `engine.default_read_timeout_s`,
// which `h1` and `h2` keep as well, `--speed-time` narrows it through
// `engine.readTimeoutFor`, and `Session.readDeadline` is what makes one
// bound cover a whole wait.

/// The content codings this engine offers and can decode, in the order it
/// writes them.
///
/// Written out here and not imported, because `h1.zig` imports this file
/// and the layering runs one way. See `h1.accept_encoding_value` for the
/// order, and for why `br` is not in it. The test *"the accept-encoding
/// value matches the one h1 sends"* holds the two together.
pub const accept_encoding_value = "deflate, gzip, zstd";

const body_chunk_len: usize = 16 * 1024;
const decompress_buffer_len = std.compress.flate.max_window_len;

/// The window this engine gives a zstd stream. 8 MiB, the ceiling RFC 8878
/// section 3.1.1.1.2 sets for a zstd stream that travels as a content
/// coding, and the value `std.http.Decompress` builds its decoder with.
const zstd_window_len = std.compress.zstd.default_window_len;

/// Scratch space for one zstd stream: the window, plus room for one whole
/// block. Allocated where the head really said zstd, and freed with the
/// exchange, because 8.1 MiB may not sit in every exchange.
const zstd_buffer_len = zstd_window_len + std.compress.zstd.block_size_max;
const transfer_buffer_len = 8192;
/// RFC 9114 section 4.3.2 makes `:status` exactly three digits.
/// `engine.status_text_len` is the number, because `h2` writes the same
/// status line from the same width.
const status_text_len: usize = engine.status_text_len;

/// How a finished exchange hands its connection back.
///
/// The same seam `h2.Peer` is, so the caller above keeps one shape.
pub const Peer = struct {
    ctx: *anyopaque,
    handle: *anyopaque,
    release: *const fn (ctx: *anyopaque, handle: *anyopaque, keep: bool) void,
};

/// Where a response head block goes, and what comes back out.
///
/// The same seam `h2.HeadLog` is.
pub const HeadLog = struct {
    ctx: *anyopaque,
    record: *const fn (ctx: *anyopaque, head: []const u8) std.mem.Allocator.Error!void,
    kept: *const fn (ctx: *anyopaque) Kept,

    pub const Kept = struct {
        all: ?[]const u8,
        final: ?[]const u8,
        dropped: bool,
    };
};

/// Every fault this engine can meet, before it is mapped onto the seam's
/// own error set.
pub const Fault = quic.Error || zurl_h3.Connection.Error || h3_frame.Error ||
    zurl_qpack.Decoder.Error || zurl_quic.Streams.Error || error{
    /// The peer's answer is not an HTTP/3 message.
    MalformedResponse,
    /// The peer answered in a content coding this request never offered.
    ///
    /// Kept apart from `MalformedResponse` because the head is legal
    /// HTTP/3 and nothing on the wire failed. See
    /// `engine.OpenError.BadContentEncoding`.
    BadContentEncoding,
    /// The response head passed `field_block_len_max`, or the decoded
    /// field section passed `header_list_len_max`.
    ResponseHeadTooLarge,
    /// The request field section is larger than the peer said it takes.
    ///
    /// RFC 9114 section 7.2.4.1: `SETTINGS_MAX_FIELD_SECTION_SIZE` is the
    /// peer's promise about what it reads, so a request past it would be
    /// refused on arrival. This side refuses it before a byte goes out and
    /// names the reason.
    RequestHeadTooLarge,
    /// The peer sent frames that moved nothing until the budget ran out.
    PeerStalled,
    /// The request body source could not be read.
    BodySourceFailed,
    /// The request body source produced a length other than the one it
    /// announced.
    BodyLengthMismatch,
    /// A write on the connection failed.
    WriteFailed,
    /// The peer's response head carries a NUL octet.
    ///
    /// Kept apart from `MalformedResponse` because QPACK carried the
    /// octets without complaint and the field section decoded: the fault
    /// is what one field holds. See `engine.refuseNulInHead`.
    WeirdServerReply,
};

/// Maps one fault of this engine onto the name the seam reports.
///
/// Public because the caller that opens a session reports a connect fault
/// through the same seam, and a second mapping there could drift from this
/// one. `h1.connectH3` is that caller.
pub fn openError(fault: Fault) engine.OpenError {
    return switch (fault) {
        error.OutOfMemory => error.OutOfMemory,
        error.CouldNotConnect => error.CouldNotConnect,
        error.OperationTimedOut => error.OperationTimedOut,
        // The caller stopped this transfer, so the caller decides what to
        // report. `-m`/`--max-time` is the one that does it today.
        error.Canceled => error.Canceled,
        error.PeerFailedVerification => error.PeerFailedVerification,
        // A response head that carries a NUL reaches no consumer of a
        // header value. See `engine.refuseNulInHead`.
        error.WeirdServerReply => error.WeirdServerReply,
        error.AlpnMismatch => error.SslConnectError,
        error.HandshakeFailed => error.SslConnectError,
        error.BodySourceFailed => error.ReadError,
        // Nothing on the wire failed, so this keeps its own name all the
        // way to the exit code.
        error.BadContentEncoding => error.BadContentEncoding,
        // The request never went out, so the name a user reads is the one
        // a send that did not happen carries.
        error.RequestHeadTooLarge => error.WriteError,
        error.WriteFailed, error.BodyLengthMismatch => error.WriteError,
        // The bounds on a response head keep the name `h1` gives its own,
        // so a user reads one answer whichever protocol replied.
        error.ResponseHeadTooLarge,
        error.HeaderListTooLarge,
        error.TooManyHeaderFields,
        => error.ResponseHeadTooLarge,
        // Everything else is a peer that did not answer HTTP/3, which is
        // `ReadError` and **exit 26**, `CURLE_READ_ERROR`. That is what
        // `h2.openError` does with the frame layer and HPACK faults for
        // the same reason. curl answers several of these with 56, and this
        // build puts no name on 56, so the two differ in the code and
        // agree in the refusal. See `h2.openError`.
        else => error.ReadError,
    };
}

/// The RFC 9114 section 8.1 code a `CONNECTION_CLOSE` carries for `fault`,
/// or null when this build has no code that says what happened.
///
/// **The mapping itself lives in `zurl_h3.Connection.errorCode` and is not
/// repeated here.** This function does one thing: it says which faults of
/// this engine are faults that RFC 9114 names. A fault that reaches the
/// `else` is one of this build's own bounds, a read or a write that
/// failed, or an allocation that did not: real, but not a thing the RFC
/// gives the peer a number for, and a number this side invented would
/// describe a fault the peer did not commit.
///
/// `MalformedResponse` is the one fault mapped outside that set. RFC 9114
/// section 4.1.2 gives a malformed message `H3_MESSAGE_ERROR`, and
/// `zurl_h3.Connection.Error` has no member for it because nothing in that
/// package reads a message.
fn connectionErrorCode(fault: Fault) ?zurl_h3.ErrorCode {
    const named: zurl_h3.Connection.Error = switch (fault) {
        error.MalformedResponse => return .message_error,
        error.FrameUnexpected => error.FrameUnexpected,
        error.MissingSettings => error.MissingSettings,
        error.SettingsError => error.SettingsError,
        error.FrameError => error.FrameError,
        error.StreamCreationError => error.StreamCreationError,
        error.ClosedCriticalStream => error.ClosedCriticalStream,
        error.IdError => error.IdError,
        error.ExcessiveLoad => error.ExcessiveLoad,
        else => return null,
    };
    return zurl_h3.Connection.errorCode(named);
}

/// One HTTP/3 connection: the QUIC connection under it, the three
/// unidirectional streams RFC 9114 asks for, and the field decoder.
pub const Session = struct {
    gpa: std.mem.Allocator,
    conn: *quic.Connection,
    rules: zurl_h3.Connection,
    decoder: zurl_qpack.Decoder,

    slots: []zurl_quic.Streams.Stream,
    roles: []Role,
    stream_storage: []u8,

    /// This side's own unidirectional streams. RFC 9114 section 6.2.
    control: *zurl_quic.Streams.Stream,
    qpack_encoder: *zurl_quic.Streams.Stream,
    qpack_decoder: *zurl_quic.Streams.Stream,

    /// Scratch for one control stream payload, and where the reader
    /// stopped inside it.
    control_payload: []u8,
    control_parse: ControlParse = .{},
    /// Where the stream type reader stopped on each slot, so a type that
    /// arrives in pieces is read once and not twice. One entry for each
    /// slot in `slots`, at the same index.
    type_parse: []TypeParse,
    /// Scratch for the part of a QPACK encoder instruction that has not
    /// all arrived.
    encoder_pending: []u8,
    encoder_pending_len: usize = 0,

    /// The largest request stream the peer said it might act on, or null.
    goaway: ?u64 = null,
    /// Whether the connection met a fault it cannot recover from.
    broken: bool = false,
    /// Whether a wait on this connection reached its deadline.
    ///
    /// **Latched, and it never goes back.** The peer stopped writing at a
    /// place nothing here knows, so the connection can serve no further
    /// request. `usable` reads it, which keeps the connection away from a
    /// caller that would send on it again.
    read_timed_out: bool = false,
    /// How long one wait on this connection may take with no octet
    /// arriving.
    ///
    /// **The bound is on one wait and never on the transfer.** `fill`
    /// comes back as soon as the peer delivers an octet, and each call
    /// starts the clock again, so a download over a slow link runs for as
    /// long as it needs and is bounded by `--max-time` and by the rate
    /// rule in `zurl_stream.Stall`. Only a wait that delivers nothing at
    /// all reaches the deadline. That is the rule `h1` keeps around
    /// `receiveHead` and each body read, and the rule `h2` keeps around
    /// one frame read.
    ///
    /// **It covers the whole wait and not one datagram of it.**
    /// `quic.Connection.pump` takes a length in milliseconds and gives up
    /// on one datagram, and the loops below turn up to `idle_frames_max`
    /// times. So the loops carry a deadline, `readDeadline` makes one, and
    /// `pumpUntil` gives `pump` only what is left of it.
    ///
    /// `--speed-time` narrows it through `engine.readTimeoutFor`. See
    /// `engine.default_read_timeout_s` for the ceiling a transfer that
    /// named no flag gets.
    read_timeout: Io.Timeout = engine.default_read_timeout,

    /// What one stream in the table is for.
    pub const Role = enum {
        /// The slot is free, or holds a stream this session has not
        /// classified yet.
        idle,
        /// One of this side's own unidirectional streams.
        local,
        /// The request stream of the exchange that is running.
        request,
        peer_control,
        peer_qpack_encoder,
        peer_qpack_decoder,
        /// A unidirectional stream of a type this build does not read.
        abandoned,
    };

    /// What this side announces in its `SETTINGS` frame.
    ///
    /// **The QPACK table capacity is zero on purpose.** RFC 9204 section
    /// 2.1 then lets no peer insert into a dynamic table for this side's
    /// decoder, so no field section can name an entry that has not
    /// arrived, and `zurl_qpack.Decoder` never has to park one. It is the
    /// same reasoning that makes `blocked_streams` zero, and both are the
    /// decoder's own promise: saying a number and not honouring it is
    /// worse than saying zero.
    pub fn wanted() zurl_h3.Settings {
        return .{
            .qpack_max_table_capacity = 0,
            .qpack_blocked_streams = zurl_qpack.blocked_streams_max,
            .max_field_section_size = header_list_len_max,
        };
    }

    /// Opens a QUIC connection to `options.address` and brings the HTTP/3
    /// connection up on it.
    pub fn connect(gpa: std.mem.Allocator, options: ConnectOptions) Fault!*Session {
        const self = try gpa.create(Session);
        var landed = false;
        defer if (!landed) gpa.destroy(self);

        const slots = try gpa.alloc(zurl_quic.Streams.Stream, streams_max);
        errdefer gpa.free(slots);
        const roles = try gpa.alloc(Role, streams_max);
        errdefer gpa.free(roles);
        const per_slot = send_buffer_len + stream_window_len;
        const stream_storage = try gpa.alloc(u8, per_slot * streams_max);
        errdefer gpa.free(stream_storage);
        const control_payload = try gpa.alloc(u8, control_payload_len_max);
        errdefer gpa.free(control_payload);
        const encoder_pending = try gpa.alloc(u8, encoder_stream_len_max);
        errdefer gpa.free(encoder_pending);
        const type_parse = try gpa.alloc(TypeParse, streams_max);
        errdefer gpa.free(type_parse);
        for (type_parse) |*parse| parse.* = .{};

        for (slots, roles, 0..) |*slot, *role, index| {
            const base = stream_storage[index * per_slot ..];
            slot.* = .init(base[0..send_buffer_len], base[send_buffer_len..][0..stream_window_len]);
            role.* = .idle;
        }

        const conn = try quic.Connection.open(.{
            .io = options.io,
            .gpa = gpa,
            .address = options.address,
            .host = options.host,
            .verify_host = options.verify_host,
            .trust = options.trust,
            .alpn = &.{alpn_name},
            .slots = slots,
            .recv_window = connection_window_len,
            .handshake_timeout_ms = options.handshake_timeout_ms,
            .cause_out = options.cause_out,
            .stop = options.stop,
        });
        errdefer conn.deinit();

        // RFC 9001 section 8.1 makes ALPN mandatory, and RFC 9114 section
        // 3.1 makes `h3` the name. A peer that chose anything else is not
        // speaking HTTP/3, and no byte of a request may go to it.
        const chosen = conn.alpnProtocol() orelse return error.AlpnMismatch;
        if (!std.mem.eql(u8, chosen, alpn_name)) return error.AlpnMismatch;

        self.* = .{
            .gpa = gpa,
            .conn = conn,
            .rules = .init(.client, wanted()),
            .decoder = .init(.{
                .table_capacity_max = 0,
                .header_list_size_max = header_list_len_max,
            }),
            .slots = slots,
            .roles = roles,
            .stream_storage = stream_storage,
            .control_payload = control_payload,
            .type_parse = type_parse,
            .encoder_pending = encoder_pending,
            .control = undefined,
            .qpack_encoder = undefined,
            .qpack_decoder = undefined,
            .read_timeout = options.read_timeout,
        };

        try self.openLocalStreams();
        landed = true;
        return self;
    }

    pub const ConnectOptions = struct {
        io: Io,
        address: Io.net.IpAddress,
        host: []const u8,
        verify_host: bool,
        trust: quic.Trust,
        /// How long the QUIC handshake may take, in milliseconds. The
        /// caller's `--connect-timeout` when there is one, because a
        /// handshake is how this transport reaches a peer.
        handshake_timeout_ms: i64 = 30_000,
        /// How long one wait on the open connection may take with no octet
        /// arriving. The caller's `--speed-limit` and `--speed-time`
        /// through `engine.readTimeoutFor`, because a peer that goes quiet
        /// after the handshake meets no other bound. See
        /// `Session.read_timeout`.
        read_timeout: Io.Timeout = engine.default_read_timeout,
        /// Where a failed handshake writes the sentence for its own fault.
        /// See `quic.Options.cause_out`.
        cause_out: ?*?[]const u8 = null,
        /// A flag the caller raises when this transfer must stop. This is
        /// what `-m`/`--max-time` needs. See `quic.Options.stop`.
        stop: ?*const std.atomic.Value(bool) = null,
    };

    /// Opens the three unidirectional streams of RFC 9114 section 6.2 and
    /// writes the `SETTINGS` frame on the control stream.
    ///
    /// **`SETTINGS` is the first frame this side writes**, which is the
    /// same rule this side holds the peer to. RFC 9114 section 6.2.1.
    fn openLocalStreams(self: *Session) Fault!void {
        self.control = try self.openLocalUni(.control);
        self.qpack_encoder = try self.openLocalUni(.qpack_encoder);
        self.qpack_decoder = try self.openLocalUni(.qpack_decoder);

        var payload: [128]u8 = undefined;
        const body = zurl_h3.settings.encode(wanted(), &payload);
        var head: [h3_frame.max_header_bytes]u8 = undefined;
        const written = h3_frame.writeHeader(.settings, body.len, &head);
        try self.writeAll(self.control, written);
        try self.writeAll(self.control, body);
        _ = self.conn.flush() catch return error.WriteFailed;
    }

    fn openLocalUni(self: *Session, t: zurl_h3.stream_type.Type) Fault!*zurl_quic.Streams.Stream {
        const slot = try self.conn.openStream(.unidirectional);
        self.roles[self.indexOf(slot)] = .local;
        var prefix: [zurl_h3.stream_type.max_bytes]u8 = undefined;
        try self.writeAll(slot, zurl_h3.stream_type.write(t, &prefix));
        return slot;
    }

    fn indexOf(self: *const Session, slot: *const zurl_quic.Streams.Stream) usize {
        const base = @intFromPtr(self.slots.ptr);
        const at = @intFromPtr(slot);
        std.debug.assert(at >= base);
        const index = (at - base) / @sizeOf(zurl_quic.Streams.Stream);
        std.debug.assert(index < self.slots.len);
        return index;
    }

    /// When the wait that starts now must give up.
    ///
    /// An absolute instant and not a length, so a loop that waits several
    /// times shares one bound. See `Session.read_timeout`.
    fn readDeadline(self: *const Session) Io.Timeout {
        return self.read_timeout.toDeadline(self.conn.io);
    }

    /// One `quic.Connection.pump`, given only what is left of `deadline`.
    ///
    /// **This is what makes the bound cover the whole wait.** `pump` takes
    /// a length in milliseconds and gives up on one datagram, so a loop
    /// that handed it the whole bound each turn multiplied the bound by
    /// the number of turns. A peer answering one empty datagram at a time
    /// bought `idle_frames_max` whole bounds that way.
    ///
    /// A deadline already passed is reported here rather than spent on one
    /// more wait, and it latches the session: the peer stopped writing at
    /// a place nothing here knows, so no further request may go on this
    /// connection.
    fn pumpUntil(self: *Session, deadline: Io.Timeout) Fault!void {
        const left = engine.readTimeoutMilliseconds(self.conn.io, deadline) orelse {
            // No bound was asked for. `pump` waits for as long as the peer
            // likes, which is what `.none` means.
            return self.conn.pump(0);
        };
        self.conn.pump(left) catch |err| {
            if (err == error.OperationTimedOut) {
                self.read_timed_out = true;
                self.broken = true;
            }
            return err;
        };
    }

    /// Writes every byte of `bytes` onto `slot`, pumping the connection
    /// whenever the send buffer is full.
    ///
    /// **The wait for room is bounded, because the peer is what opens
    /// it.** A flow-control window opens on a `MAX_STREAM_DATA` frame from
    /// the peer, so a peer that stops sending one holds this loop exactly
    /// as a peer that stops sending a response holds `fill`. The deadline
    /// starts again on every octet the connection took, so a peer that
    /// keeps opening room never reaches it.
    fn writeAll(self: *Session, slot: *zurl_quic.Streams.Stream, bytes: []const u8) Fault!void {
        var at: usize = 0;
        var idle: usize = 0;
        var deadline = self.readDeadline();
        while (at < bytes.len) {
            const taken = try self.conn.write(slot, bytes[at..]);
            at += taken;
            if (taken != 0) {
                idle = 0;
                deadline = self.readDeadline();
                continue;
            }
            // The window or the buffer is full. The peer opens both, so
            // this side reads rather than spin.
            idle += 1;
            if (idle > idle_frames_max) return error.PeerStalled;
            try self.pumpUntil(deadline);
            try self.service();
        }
    }

    pub fn deinit(self: *Session) void {
        const gpa = self.gpa;
        self.conn.deinit();
        self.decoder.deinit(gpa);
        gpa.free(self.slots);
        gpa.free(self.roles);
        gpa.free(self.stream_storage);
        gpa.free(self.control_payload);
        gpa.free(self.type_parse);
        gpa.free(self.encoder_pending);
        gpa.destroy(self);
    }

    /// Reads everything that arrived on a stream that is not the request
    /// stream: the peer's control stream and its two QPACK streams.
    ///
    /// **This runs whenever the exchange waits.** A peer that opened its
    /// control stream and then waited for this side to read it would
    /// otherwise hold a window that never opens.
    pub fn service(self: *Session) Fault!void {
        return self.serviceExcept(null);
    }

    /// Reads every stream but the one the caller is reading.
    ///
    /// **One body serves this and `service`, and that is the point.** The
    /// two were written apart and drifted: `service` reported a peer that
    /// closed its control stream or a QPACK stream as
    /// `H3_CLOSED_CRITICAL_STREAM`, and this one, which is the loop that
    /// runs for the whole of a request and a response, did not. `service`
    /// runs only from `writeAll` when a send window is full, which for a
    /// small request never happens, so the rule was written down and never
    /// reached. The two now differ in one argument and in nothing else.
    fn serviceOthers(self: *Session, except: *const zurl_quic.Streams.Stream) Fault!void {
        return self.serviceExcept(self.indexOf(except));
    }

    /// The body of `service` and `serviceOthers`. `reading` is the slot the
    /// caller is reading, which this loop leaves alone, or null.
    fn serviceExcept(self: *Session, reading: ?usize) Fault!void {
        for (self.slots, self.roles, 0..) |*slot, *role, index| {
            if (reading) |skip_index| {
                if (index == skip_index) continue;
            }
            if (!slot.in_use) continue;
            if (role.* == .request or role.* == .local) continue;
            if (role.* == .idle) {
                // A stream the peer opened that has not said what it is.
                if (zurl_quic.stream.isLocal(slot.id, .client)) continue;
                if (zurl_quic.stream.kindOf(slot.id) != .unidirectional) {
                    // RFC 9114 section 6.1: a server opens no
                    // bidirectional stream to a client. `Streams` already
                    // refuses one, because this side advertises a limit of
                    // zero, so nothing can reach here.
                    return error.StreamStateError;
                }
                try self.classify(slot, role);
                if (role.* == .idle) continue;
            }
            try self.drain(slot, role.*);
            if (slot.recv_state.finished() and role.* != .abandoned) {
                // RFC 9114 section 6.2.1 and RFC 9204 section 4.2: these
                // streams live for the whole connection.
                try self.rules.onPeerUniStreamClosed(slot.id);
            }
        }
    }

    /// Where the stream type reader stopped on one slot, so it can start
    /// again.
    ///
    /// **The bytes already taken are kept here and nowhere else.**
    /// `Streams.read` consumes what it hands back, so a reader that held
    /// the part of a type it had read in a local would lose it the moment
    /// the rest of the type had not arrived, and would then read the
    /// remainder as a whole type of its own. RFC 9114 section 6.2.3
    /// reserved types are `0x1f * N + 0x21`, and every one above `N = 0`
    /// needs two varint bytes or more, so a conformant peer greasing the
    /// connection reaches this every time it splits one across packets.
    pub const TypeParse = struct {
        /// Which stream the part belongs to. A slot is reused, so the
        /// identifier is what says the part is still this stream's.
        id: u64 = 0,
        bytes: [zurl_h3.stream_type.max_bytes]u8 = undefined,
        /// How many bytes of the type have arrived. Never past
        /// `bytes.len`, which is the longest varint there is.
        len: usize = 0,
    };

    /// Reads the type off the front of a unidirectional stream the peer
    /// opened, once enough of it has arrived.
    ///
    /// Returns with the slot still `.idle` when only part of the type has
    /// arrived. The part is kept in `type_parse`, so the next call carries
    /// on from where this one stopped.
    fn classify(self: *Session, slot: *zurl_quic.Streams.Stream, role: *Role) Fault!void {
        const parse = &self.type_parse[self.indexOf(slot)];
        // A slot is reused for another stream, and a part left behind by
        // the last one is not part of this one.
        if (parse.id != slot.id) parse.len = 0;
        parse.id = slot.id;

        while (parse.len < parse.bytes.len) {
            const n = self.conn.streams.read(slot, parse.bytes[parse.len..][0..1]);
            if (n == 0) return;
            parse.len += 1;
            const read = zurl_h3.stream_type.read(parse.bytes[0..parse.len]) orelse continue;
            parse.len = 0;
            const what = try self.rules.onPeerUniStream(slot.id, read.type);
            role.* = switch (what) {
                .control => .peer_control,
                .qpack_encoder => .peer_qpack_encoder,
                .qpack_decoder => .peer_qpack_decoder,
                // RFC 9114 section 6.2: a type this build does not
                // read is abandoned, and the peer is asked to stop.
                .abandon => abandon: {
                    self.conn.streams.stopSending(
                        slot,
                        @intFromEnum(zurl_h3.ErrorCode.stream_creation_error),
                    );
                    break :abandon .abandoned;
                },
            };
            return;
        }
        // **`parse.bytes` is `varint.max_bytes` long, and a varint is at
        // most that many bytes, so the loop above reads a whole one before
        // it runs out of room.** `varint.decode` reads the length off the
        // two top bits of the first byte, so eight bytes in hand can never
        // be `error.Truncated`, and every byte read above is kept in
        // `parse.bytes`.
        //
        // It was `unreachable`, which is undefined behaviour in
        // ReleaseFast and ReleaseSmall: the build a user runs would fall
        // off the end of this function with `role` still `.idle`. The
        // proof above is about another package's constant, so a change to
        // `varint.max_bytes` could break it without a line of this file
        // moving. A named fault costs nothing and the peer is told: RFC
        // 9114 section 6.2 gives a stream this side cannot read
        // `H3_STREAM_CREATION_ERROR`, which `connectionErrorCode` already
        // maps.
        return error.StreamCreationError;
    }

    fn drain(self: *Session, slot: *zurl_quic.Streams.Stream, role: Role) Fault!void {
        switch (role) {
            .peer_control => try self.readControl(slot),
            .peer_qpack_encoder => try self.readEncoderStream(slot),
            .peer_qpack_decoder, .abandoned => {
                // Nothing this side acts on. The octets are taken so the
                // window keeps moving and the peer is never blocked on a
                // stream nobody reads.
                var sink: [skip_chunk_len]u8 = undefined;
                while (self.conn.streams.read(slot, &sink) != 0) {}
            },
            .idle, .local, .request => {},
        }
    }

    /// Reads whatever has arrived on the peer's control stream, and
    /// returns.
    ///
    /// **This never waits.** The control stream lives for the whole
    /// connection and ends only when the connection does, so a reader that
    /// waited for its next frame would wait for ever and the request
    /// stream beside it would never be read. `ControlParse` is what lets
    /// the reader stop in the middle of a frame and start again when more
    /// octets arrive.
    fn readControl(self: *Session, slot: *zurl_quic.Streams.Stream) Fault!void {
        const parse = &self.control_parse;
        var frames: usize = 0;
        while (frames < idle_frames_max) {
            if (parse.kind == null) {
                if (parse.head_len == parse.head.len) return error.FrameError;
                const got = self.conn.streams.read(slot, parse.head[parse.head_len..][0..1]);
                if (got == 0) return;
                parse.head_len += 1;
                const header = (try h3_frame.readHeader(parse.head[0..parse.head_len])) orelse continue;
                // **The disposition is read before the length is
                // bounded.** RFC 9114 section 9 requires a frame type this
                // build does not know to be ignored whatever its length,
                // and section 7.2.8 has a conformant peer send one on
                // purpose, so only a frame this side buffers has to fit
                // `control_payload`. A cap that ran first would close the
                // connection over legal traffic.
                parse.disposition = try self.rules.onControlFrame(header.kind);
                if (parse.disposition == .act and header.length > control_payload_len_max) {
                    return error.ExcessiveLoad;
                }
                parse.kind = header.kind;
                parse.remaining = header.length;
                parse.filled = 0;
                parse.head_len = 0;
            }

            if (parse.disposition == .skip) {
                // The payload goes through a fixed sink, so a length the
                // peer chose costs this side no memory at all.
                var sink: [skip_chunk_len]u8 = undefined;
                while (parse.filled < parse.remaining) {
                    const want: usize = @intCast(@min(parse.remaining - parse.filled, sink.len));
                    const got = self.conn.streams.read(slot, sink[0..want]);
                    if (got == 0) return;
                    parse.filled += got;
                }
                parse.kind = null;
                parse.filled = 0;
                parse.remaining = 0;
                frames += 1;
                continue;
            }

            const want: usize = @intCast(parse.remaining - parse.filled);
            if (want > 0) {
                const at: usize = @intCast(parse.filled);
                const got = self.conn.streams.read(slot, self.control_payload[at..][0..want]);
                if (got == 0) return;
                parse.filled += got;
                if (parse.filled < parse.remaining) continue;
            }

            const kind = parse.kind.?;
            const payload = self.control_payload[0..@intCast(parse.filled)];
            parse.kind = null;
            parse.filled = 0;
            parse.remaining = 0;
            frames += 1;

            switch (kind) {
                .settings => try self.rules.onSettings(payload),
                .goaway => {
                    const id = try h3_frame.readSingleVarint(payload);
                    try self.rules.onGoaway(id);
                    self.goaway = id;
                },
                .max_push_id => {
                    const id = try h3_frame.readSingleVarint(payload);
                    try self.rules.onMaxPushId(id);
                },
                else => {},
            }
        }
        // A peer that sent this many control frames in one pass is not
        // answering, it is spending this side's time.
        return error.PeerStalled;
    }

    /// Where the control stream reader stopped, so it can start again.
    pub const ControlParse = struct {
        head: [h3_frame.max_header_bytes]u8 = undefined,
        head_len: usize = 0,
        /// The frame being read, or null between frames.
        kind: ?h3_frame.Kind = null,
        remaining: u64 = 0,
        /// How many payload octets have arrived. **A `u64` and not a
        /// `usize`**, because a payload this side steps over is as long as
        /// the peer said and is never bounded by a buffer.
        filled: u64 = 0,
        disposition: zurl_h3.Connection.Disposition = .skip,
    };

    fn readEncoderStream(self: *Session, slot: *zurl_quic.Streams.Stream) Fault!void {
        while (true) {
            const room = self.encoder_pending.len - self.encoder_pending_len;
            if (room == 0) return error.InstructionTooLong;
            const n = self.conn.streams.read(slot, self.encoder_pending[self.encoder_pending_len..]);
            if (n == 0) break;
            self.encoder_pending_len += n;
            const used = try self.decoder.readEncoderStream(
                self.gpa,
                self.encoder_pending[0..self.encoder_pending_len],
            );
            if (used > 0) {
                std.mem.copyForwards(
                    u8,
                    self.encoder_pending[0 .. self.encoder_pending_len - used],
                    self.encoder_pending[used..self.encoder_pending_len],
                );
                self.encoder_pending_len -= used;
            }
        }
    }

    /// Reads one whole frame header off `slot`, or null when the stream
    /// ended cleanly between frames.
    ///
    /// **One byte at a time**, because a frame header is two variable
    /// length integers and reading more would take octets of a payload
    /// this side has nowhere to put yet. A header is at most sixteen
    /// bytes, so the loop is bounded by the format.
    fn readFrameHeader(self: *Session, slot: *zurl_quic.Streams.Stream) Fault!?h3_frame.Header {
        var head: [h3_frame.max_header_bytes]u8 = undefined;
        var len: usize = 0;
        while (len < head.len) {
            const n = try self.fill(slot, head[len..][0..1]);
            if (n == 0) {
                // A stream that ended between frames is a clean end. One
                // that ended inside a header is a cut frame.
                if (len == 0) return null;
                return error.FrameError;
            }
            len += 1;
            if (try h3_frame.readHeader(head[0..len])) |header| return header;
        }
        return error.FrameError;
    }

    /// Fills `out` exactly, and reports false when the stream ended first.
    fn readExactly(self: *Session, slot: *zurl_quic.Streams.Stream, out: []u8) Fault!bool {
        var at: usize = 0;
        while (at < out.len) {
            const n = try self.fill(slot, out[at..]);
            if (n == 0) return false;
            at += n;
        }
        return true;
    }

    /// Takes readable octets off `slot`, pumping the connection and
    /// servicing every other stream while there are none.
    ///
    /// **This is the one place this engine waits for a response, and the
    /// deadline is on one call of it.** The call comes back as soon as the
    /// peer delivers an octet, so the clock starts again on every octet
    /// and a slow download runs for as long as it needs. A peer that
    /// accepted the connection, answered a head and then went quiet
    /// reaches the deadline and ends the transfer with
    /// `error.OperationTimedOut`, which is exit 28, the answer `h1` and
    /// `h2` give the same peer. See `Session.read_timeout`.
    ///
    /// **`idle_frames_max` alone never covered that peer.** It bounds a
    /// peer that keeps sending datagrams which carry nothing for this
    /// stream, and it runs down one unit for each datagram. A peer that
    /// sends none spends none of it, so the loop waited on `pump` and
    /// nothing else stood in the way.
    fn fill(self: *Session, slot: *zurl_quic.Streams.Stream, out: []u8) Fault!usize {
        var idle: usize = 0;
        const deadline = self.readDeadline();
        while (true) {
            const moved = self.conn.streams.read(slot, out);
            if (moved > 0) {
                _ = self.conn.flush() catch return error.WriteFailed;
                return moved;
            }
            if (slot.recv_state.reset()) return error.MalformedResponse;
            if (slot.recv_state.finished()) return 0;
            if (self.conn.closed != null) return error.ConnectionClosed;
            idle += 1;
            if (idle > idle_frames_max) return error.PeerStalled;
            try self.pumpUntil(deadline);
            try self.serviceOthers(slot);
        }
    }

    /// How large a QPACK dynamic table this side's own encoder would
    /// build, before the peer's promise is read.
    ///
    /// **Zero, because `zurl_qpack.encoder` inserts nothing.** It names
    /// every field line out of the static table or writes it whole, so it
    /// needs no dynamic table and sends no encoder stream instruction.
    const encoder_table_capacity: u64 = 0;

    /// How large a QPACK dynamic table this side may build for its own
    /// encoder on this connection.
    ///
    /// RFC 9204 section 3.2.2: the peer's `SETTINGS_QPACK_MAX_TABLE_CAPACITY`
    /// is the ceiling, and a peer that named zero, or that has not named
    /// one yet, allows no table at all. The answer is zero either way in
    /// this build, and the peer's number is read all the same: a later
    /// encoder that does insert takes its capacity from here, and a peer
    /// that allows none must keep getting none.
    pub fn qpackTableCapacity(self: *const Session) u64 {
        const allowed = if (self.rules.peer_settings) |peer| peer.qpack_max_table_capacity else 0;
        return @min(allowed, encoder_table_capacity);
    }

    /// The largest field section the peer said it reads, or null when it
    /// named none or has not sent its `SETTINGS` yet.
    ///
    /// RFC 9114 section 7.2.4.1. Null is "no limit named", which is the
    /// default the RFC gives, and is not the same as a limit of zero.
    pub fn peerFieldSectionMax(self: *const Session) ?u64 {
        const peer = self.rules.peer_settings orelse return null;
        return peer.max_field_section_size;
    }

    /// Whether this connection may still carry a request.
    pub fn usable(self: *const Session) bool {
        if (self.broken) return false;
        // **A connection whose wait reached its deadline never serves
        // another request.** `pumpUntil` sets `broken` beside this latch
        // today, so the line above already answers false. It is written
        // out all the same, because the two say different things:
        // `broken` is a connection this side gave up on, and this is the
        // one shape where the peer may still be there and still be sending
        // octets nobody framed. A later arm that cleared `broken` would
        // reopen the hole.
        if (self.read_timed_out) return false;
        if (self.conn.closed != null) return false;
        return true;
    }

    /// Ends the connection because `err` happened on it, and marks it
    /// unusable.
    ///
    /// **This is `h2.Session.abort`, said for HTTP/3.** Two things were
    /// written and never wired together. `broken` was declared and read by
    /// `usable` and set by nothing, so a session that met a fatal fault
    /// still called itself usable and only `conn.closed` stood between it
    /// and the next request. `zurl_h3.Connection.errorCode` computes the
    /// RFC 9114 section 8.1 code for every fault this build reports and
    /// had no caller, so a peer saw an idle timeout where it should have
    /// read a protocol error. A declared field nothing sets and a function
    /// nobody calls both read as rules that are enforced.
    ///
    /// **Every fault marks the session, and only some send a code.** A
    /// fault leaves the connection at a place this side cannot describe,
    /// so refusing to reuse it costs one dial and can leak nothing. A
    /// `CONNECTION_CLOSE` goes out only for the faults RFC 9114 gives a
    /// code to, because a code this side invented would tell the peer
    /// something that did not happen.
    ///
    /// Best effort, like `h2.Session.abort`: the fault is already on its
    /// way to the caller, and `quic.Connection.close` writes nothing once
    /// the connection is closed or a close has gone out.
    fn abort(self: *Session, err: Fault) void {
        self.broken = true;
        const code = connectionErrorCode(err) orelse return;
        self.conn.close(@intFromEnum(code), "");
    }
};

/// What one request needs from the caller, beyond the session it runs on.
///
/// **Every field means what the field of the same name on `h2.Open`
/// means.** That is the point: `h1` builds one of these the same way it
/// builds the other, so the header validation, the redirect chain, the
/// credential rule, and the cookie jar all run once and serve both.
pub const Open = struct {
    gpa: std.mem.Allocator,
    session: *Session,
    method: std.http.Method,
    /// The request target, which `:scheme`, `:path`, and the query come
    /// from.
    uri: std.Uri,
    /// The `:authority` value, the host and the port together, with the
    /// brackets an IPv6 address needs.
    authority: []const u8,
    /// The `user-agent` value. An empty one sends no field at all.
    user_agent: []const u8,
    /// Whether this request offers a compressed body, and therefore which
    /// content codings the answer may carry. See
    /// `engine.Request.accept_encoding`, which holds the whole rule.
    ///
    /// `h1.sendOnH3` fills it, and it already folded in a caller's own
    /// `Accept-Encoding` header.
    accept_encoding: bool,
    /// The caller's headers and this hop's secrets, already joined by
    /// `h1.openOnce`. **That join is where `engine.origin_bound_headers`
    /// is honoured, and this file never sees the rule at all.**
    headers: []const std.http.Header,
    body: ?engine.Body,
    /// This hop's url, which the cookie jar answers for.
    url: zurl_core.Url,
    cookies: ?engine.CookieJar,
    log: HeadLog,
    peer: Peer,
    /// Set true as soon as the peer answers any frame on this request's
    /// stream.
    answered: *bool,
    /// Set true as soon as one octet of the request body has gone out.
    body_sent: *bool,
};

/// Sends one request on `o.session` and reads the response head.
///
/// The caller owns the returned `engine.Exchange` and must call `close` on
/// it exactly once.
pub fn open(o: Open) engine.OpenError!*engine.Exchange {
    return openInner(o) catch |err| {
        // **One place, because a fault leaves by one door.** Marking the
        // session here and in `Exchange.bodyFault` covers every fault this
        // engine reports, which is what a mark placed at each fault site
        // would have to be kept in step with for ever. See `Session.abort`.
        o.session.abort(err);
        return openError(err);
    };
}

fn openInner(o: Open) Fault!*engine.Exchange {
    const gpa = o.gpa;
    const session = o.session;

    if (session.goaway) |limit| {
        // RFC 9114 section 5.2: the server named the largest request it
        // might act on, so a new one on this connection would be thrown
        // away. The caller opens another connection.
        _ = limit;
        return error.PeerStalled;
    }

    const exchange = try gpa.create(Exchange);
    var landed = false;
    defer if (!landed) gpa.destroy(exchange);

    const slot = try session.conn.openStream(.bidirectional);
    session.roles[session.indexOf(slot)] = .request;
    errdefer session.roles[session.indexOf(slot)] = .idle;

    exchange.* = .{
        .interface = .{ .ptr = exchange, .vtable = &Exchange.exchange_vtable },
        .gpa = gpa,
        .session = session,
        .peer = o.peer,
        .slot = slot,
        .message = .{},
        .head_value = undefined,
        .content_length = null,
        .content_encoding = .identity,
        .body_received = 0,
        .body_taken = false,
        .body_partial = false,
        .body_ended = false,
        .body_fault = null,
        .frame_remaining = 0,
        .idle_frames = 0,
        .skipped_octets = 0,
        .pending = &.{},
        .chunk = undefined,
        .raw = undefined,
        .transfer_buffer = undefined,
        .body = undefined,
        .body_source = undefined,
        .decompress = undefined,
        .decompress_buffer = undefined,
        .zstd_buffer = null,
        .trailer_text = null,
        .chain_storage = null,
    };

    try writeRequest(o, exchange);
    try readHead(o, exchange);

    o.answered.* = true;
    landed = true;
    return &exchange.interface;
}

/// Builds and writes the `HEADERS` frame, and the body behind it.
fn writeRequest(o: Open, exchange: *Exchange) Fault!void {
    const gpa = o.gpa;
    const session = o.session;

    // The generated text of one request, in one allocation. The field list
    // below points into the finished buffer, so it is built first.
    var scratch: std.ArrayList(u8) = .empty;
    defer scratch.deinit(gpa);

    const path_span = try appendPath(gpa, &scratch, o.uri);
    var length_span: Span = .{ .at = 0, .len = 0 };
    if (o.body) |source| {
        if (source.len) |length| length_span = try appendPrint(gpa, &scratch, "{d}", .{length});
    }

    const name_spans = try gpa.alloc(Span, o.headers.len);
    defer gpa.free(name_spans);
    for (o.headers, name_spans) |header, *place| {
        // RFC 9114 section 4.2: every field name on the wire is lower
        // case. `h1.validateHeaderName` already refused a name that is not
        // an RFC 9110 token, so nothing here can lower-case a name into
        // something a peer reads as two fields.
        place.* = try appendLower(gpa, &scratch, header.name);
    }

    var fields: std.ArrayList(zurl_qpack.Field) = .empty;
    defer fields.deinit(gpa);

    // **The four pseudo headers, in this order, before every ordinary
    // field.** RFC 9114 section 4.3.1.
    try fields.append(gpa, .{ .name = ":method", .value = @tagName(o.method) });
    try fields.append(gpa, .{ .name = ":scheme", .value = o.uri.scheme });
    try fields.append(gpa, .{ .name = ":authority", .value = o.authority });
    try fields.append(gpa, .{ .name = ":path", .value = span(scratch, path_span) });

    if (o.user_agent.len != 0) {
        try fields.append(gpa, .{ .name = "user-agent", .value = o.user_agent });
    }
    // **No offer, no field.** The rule `h1.writeRequestHead` writes, said
    // again for QPACK. A caller that wrote its own `accept-encoding` gets
    // that one and no second copy.
    if (o.accept_encoding and !headersOfferEncoding(o.headers)) {
        try fields.append(gpa, .{ .name = "accept-encoding", .value = accept_encoding_value });
    }

    if (o.body) |source| {
        // A known length is announced and an unknown one is not. HTTP/3
        // frames its own body with the QUIC stream's `FIN`, so there is no
        // chunked transfer coding and no framing field a request must
        // carry.
        if (source.len != null) {
            try fields.append(gpa, .{ .name = "content-length", .value = span(scratch, length_span) });
        }
        if (source.content_type) |value| {
            try fields.append(gpa, .{ .name = "content-type", .value = value });
        }
    }

    for (o.headers, name_spans) |header, name_span| {
        try fields.append(gpa, .{ .name = span(scratch, name_span), .value = header.value });
    }

    // **The peer said how large a field section it reads, so this side
    // does not send a larger one.** RFC 9114 section 7.2.4.1. A request
    // past the number would be refused on arrival, and the caller reads a
    // clearer reason here than a status the peer chose. The section size
    // is the uncompressed one the setting names, not the octets the
    // encoder writes.
    if (session.peerFieldSectionMax()) |limit| {
        if (fieldSectionSize(fields.items) > limit) return error.RequestHeadTooLarge;
    }

    const block = try zurl_qpack.encoder.encodeAlloc(gpa, fields.items, .{});
    defer gpa.free(block);

    var head: [h3_frame.max_header_bytes]u8 = undefined;
    try session.writeAll(exchange.slot, h3_frame.writeHeader(.headers, block.len, &head));
    try session.writeAll(exchange.slot, block);

    if (o.body) |source| {
        // The flag goes up before the first read of the source and not
        // after it. A send that got no further than the first chunk has
        // still moved the source, so every send after this one needs
        // `engine.Body.rewind`.
        o.body_sent.* = true;
        try sendBody(o, exchange, source);
    }
    try session.conn.finishStream(exchange.slot);
}

/// The size of a field section, the way RFC 9114 section 7.2.4.1 counts
/// one: the name, the value, and 32 more for every field.
///
/// **This is the quantity `SETTINGS_MAX_FIELD_SECTION_SIZE` names**, and
/// it is not the number of octets QPACK writes for the same fields. The
/// addition is on `u64` over lengths that are already in memory, so it
/// cannot overflow.
fn fieldSectionSize(fields: []const zurl_qpack.Field) u64 {
    var total: u64 = 0;
    for (fields) |item| {
        total += @as(u64, item.name.len) + item.value.len + zurl_qpack.field.entry_overhead;
    }
    return total;
}

/// Writes the request body as `DATA` frames.
///
/// **This is where a body larger than the peer's window would deadlock,
/// and where it does not.** `Session.writeAll` pumps the connection
/// whenever the send buffer or a window is full, so the `MAX_DATA` and
/// `MAX_STREAM_DATA` frames that open the window are read on the way.
fn sendBody(o: Open, exchange: *Exchange, source: engine.Body) Fault!void {
    var buffer: [body_chunk_len]u8 = undefined;
    var written: u64 = 0;

    while (true) {
        const want: usize = if (source.len) |length| want: {
            const left = length - written;
            if (left == 0) break :want 0;
            break :want @intCast(@min(left, buffer.len));
        } else buffer.len;
        if (want == 0) break;

        const n = source.read(source.ctx, &buffer, want);
        if (n < 0) return error.BodySourceFailed;
        const count: usize = @intCast(n);
        // A source that answered with more than it was asked for has
        // written past the end of `buffer` already. Nothing here can undo
        // that, so this fails the request.
        if (count > want) return error.BodyLengthMismatch;
        if (count == 0) break;

        var head: [h3_frame.max_header_bytes]u8 = undefined;
        try o.session.writeAll(exchange.slot, h3_frame.writeHeader(.data, count, &head));
        try o.session.writeAll(exchange.slot, buffer[0..count]);
        written += count;
    }

    if (source.len) |length| {
        // The peer was told exactly how many octets to read. A body that
        // stopped short leaves it waiting for octets that never come.
        if (written != length) return error.BodyLengthMismatch;
    }
}

/// Reads frames off the request stream until the final response head is
/// whole.
fn readHead(o: Open, exchange: *Exchange) Fault!void {
    const session = o.session;
    var idle: usize = 0;

    while (true) {
        if (idle >= idle_frames_max) return error.PeerStalled;
        const header = (try session.readFrameHeader(exchange.slot)) orelse
            return error.MalformedResponse;
        // **The peer has acted on this request**, whatever the frame turns
        // out to be. The caller reads this to decide whether the same
        // request may go out a second time, and a frame that arrived and
        // then failed to parse is still a request the peer acted on.
        // `h2` sets the same flag at the same moment and for the same
        // reason. Set here and not at the end of `openInner`, because a
        // head that arrives malformed is exactly the case a retry must
        // not cover.
        o.answered.* = true;

        if (header.kind != .headers) {
            const disposition = try exchange.message.onFrame(header.kind, false);
            std.debug.assert(disposition == .skip);
            // The frame costs one unit of the count and its length costs
            // the octet ceiling. See `skip_octets_max` for why the count
            // alone bounds nothing here.
            try skip(session, exchange.slot, header.length, &exchange.skipped_octets);
            idle += 1;
            continue;
        }

        if (header.length > field_block_len_max) return error.ResponseHeadTooLarge;
        const len: usize = @intCast(header.length);
        const block = try o.gpa.alloc(u8, len);
        defer o.gpa.free(block);
        if (!try session.readExactly(exchange.slot, block)) return error.MalformedResponse;

        var section = try session.decoder.decodeSection(o.gpa, block);
        defer section.deinit(o.gpa);

        try validateResponseFields(section.list);
        const status = try readStatus(section.list);
        const informational = status >= 100 and status < 200;
        _ = try exchange.message.onFrame(.headers, informational);
        if (informational) {
            idle += 1;
            continue;
        }

        try finishHead(o, exchange, status, section.list);
        return;
    }
}

/// Steps over the payload of a frame this build does not act on.
///
/// `spent` is the octets this transfer has already thrown away, and it
/// carries over every frame of the transfer, the head and the body
/// together. See `skip_octets_max` for what the ceiling buys and costs.
///
/// **The length is charged before a single octet is read.** The declared
/// length is exactly what this reads, so charging it up front is the same
/// bound as charging each sink, and it stops a peer that declares 2^62-1
/// octets at once rather than after 512 KB of its trickle.
fn skip(
    session: *Session,
    slot: *zurl_quic.Streams.Stream,
    length: u64,
    spent: *u64,
) Fault!void {
    std.debug.assert(spent.* <= skip_octets_max);
    if (length > skip_octets_max - spent.*) return error.ExcessiveLoad;
    spent.* += length;

    var left = length;
    var sink: [skip_chunk_len]u8 = undefined;
    while (left > 0) {
        const want: usize = @intCast(@min(left, sink.len));
        const n = try session.fill(slot, sink[0..want]);
        if (n == 0) return error.MalformedResponse;
        left -= n;
    }
}

fn finishHead(o: Open, exchange: *Exchange, status: u16, fields: zurl_qpack.FieldList) Fault!void {
    // **A `HEAD` response carries no body octet, whatever its head says.**
    // RFC 9110 section 9.3.2. `h1` and `h2` report zero for the same
    // reason, and this reports zero too.
    const head_request = o.method == .HEAD;

    // **The field is read and checked whatever the method was.** A `HEAD`
    // response reports zero, and a `HEAD` response whose `content-length`
    // is malformed is still a malformed response, so the check runs before
    // the number is thrown away.
    const announced = try readContentLength(fields);
    exchange.content_length = if (head_request) 0 else announced;
    exchange.content_encoding = if (head_request)
        .identity
    else
        try readContentEncoding(fields, o.accept_encoding);

    // **The zstd window is taken here, where a fault still has a way out.**
    // `bodyReaderImpl` answers a `*std.Io.Reader` and has no error to
    // return. The same rule `h1.openOnce` keeps.
    if (exchange.content_encoding == .zstd) {
        exchange.zstd_buffer = try o.gpa.alloc(u8, zstd_buffer_len);
    }

    try recordHead(o, status, fields);

    // Every `set-cookie` of this hop goes to the jar, and the jar owns
    // every rule about it. The engine keeps no cookie of its own.
    if (o.cookies) |jar| {
        for (fields.fields.items) |item| {
            if (!std.mem.eql(u8, item.name, "set-cookie")) continue;
            jar.receive(jar.ptr, o.url, item.value);
        }
    }

    // The field list is freed when this call returns, and `Head.location`
    // and `Head.www_authenticate` outlive it, so both are copied into the
    // exchange.
    if (fields.get("location")) |value| exchange.location = try o.gpa.dupe(u8, value);
    if (pickChallenge(fields)) |value| exchange.challenge = try o.gpa.dupe(u8, value);

    const kept = o.log.kept(o.log.ctx);
    exchange.head_value = .{
        .status = status,
        // Every response this engine reads arrived on a QUIC stream, so
        // there is no other answer to give.
        .wire_version = .http_3,
        .content_length = exchange.content_length,
        // HTTP/3 frames its own body: the QUIC stream's `FIN` ends it.
        // There is no chunked transfer coding, and a `transfer-encoding`
        // field is a malformed response, which `validateResponseFields`
        // already refused.
        .transfer_encoding = .none,
        .location = exchange.location,
        .www_authenticate = exchange.challenge,
        // This engine keeps the whole decoded field list or none of it, so
        // no single challenge is ever dropped for its size.
        .www_authenticate_oversize = false,
        .credential_withheld = false,
        .body_decoded = exchange.content_encoding != .identity,
        .headers = kept.all,
        .final_headers = kept.final,
        .headers_oversize = kept.dropped,
        .effective_url = null,
    };
}

/// Writes the response head into the engine's log, the way `curl -D`
/// writes it over HTTP/3.
///
/// `HTTP/3 200 `, with the trailing space and no reason phrase, then one
/// line for each ordinary field, then the empty line. HTTP/3 has no reason
/// phrase to write, so the version and the status go out alone, which is
/// what curl writes for HTTP/2 as well.
fn recordHead(o: Open, status: u16, fields: zurl_qpack.FieldList) Fault!void {
    // **The status is three characters wide, so the count and the write
    // agree for every status the peer can send.** RFC 9114 section 4.3.2
    // makes `:status` exactly three digits, so `007` is a status of 7 that
    // the peer wrote in three characters. A line that printed the number
    // at its natural width would write two characters fewer than the block
    // was sized for, and the two octets left over are heap this side never
    // wrote.
    var digits: [status_text_len]u8 = undefined;
    writeStatusDigits(status, &digits);

    const status_line_len = "HTTP/3 ".len + status_text_len + " \r\n".len;
    var len: usize = status_line_len;
    for (fields.fields.items) |item| {
        if (item.name.len != 0 and item.name[0] == ':') continue;
        len += item.name.len + ": ".len + item.value.len + "\r\n".len;
    }
    len += "\r\n".len;

    const block = try o.gpa.alloc(u8, len);
    defer o.gpa.free(block);

    var w: std.Io.Writer = .fixed(block);
    // **Every write below fits, because `len` counted each one over the
    // same list, with the same filter, at the same width.** The status
    // line is `status_line_len` octets whatever the status, which is what
    // `engine.writeStatusDigits` is for. So a write that did not fit would
    // be an arithmetic error in the loop above and never a peer's octets,
    // which is what makes an assert the right answer here and not an error
    // a caller handles. The assert after the loop is what proves the two
    // agree, and it runs in a debug build, where such an error is found.
    w.writeAll("HTTP/3 ") catch unreachable;
    w.writeAll(&digits) catch unreachable;
    w.writeAll(" \r\n") catch unreachable;
    for (fields.fields.items) |item| {
        if (item.name.len != 0 and item.name[0] == ':') continue;
        w.writeAll(item.name) catch unreachable;
        w.writeAll(": ") catch unreachable;
        w.writeAll(item.value) catch unreachable;
        w.writeAll("\r\n") catch unreachable;
    }
    w.writeAll("\r\n") catch unreachable;
    std.debug.assert(w.buffered().len == len);

    try o.log.record(o.log.ctx, block);
}

/// Writes `status` as exactly `status_text_len` digits.
///
/// `engine.writeStatusDigits` is the rule, because `h2.recordHead` sizes
/// its own status line the same way and got the width wrong while this one
/// had it right. Named here because this file's tests call it.
const writeStatusDigits = engine.writeStatusDigits;

/// The names RFC 9114 section 4.2 takes out of use, which are the ones
/// that frame an HTTP/1.1 message.
fn connectionSpecific(name: []const u8) bool {
    const refused = [_][]const u8{
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
    };
    for (refused) |one| {
        if (std.mem.eql(u8, name, one)) return true;
    }
    return false;
}

/// Refuses a decoded field section that carries a NUL octet.
///
/// **QPACK carries a NUL without complaint, so this is the layer that has
/// to refuse it.** RFC 9114 section 4.2 leaves the octet out of no field
/// value, and a Huffman-coded string holds it as readily as any other
/// byte. The rule itself is `engine.refuseNulInHead`, which all three
/// engines ask, and the reason it belongs in the engine and not in the
/// program above the library is written there.
///
/// Both halves of a field are read. A name is checked as well as a value,
/// because a name reaches a `-D` file the same way a value does.
/// `h2.refuseNulInFields` is the same function for the same reason.
fn refuseNulInFields(list: zurl_qpack.FieldList) Fault!void {
    for (list.fields.items) |item| {
        try engine.refuseNulInHead(item.name);
        try engine.refuseNulInHead(item.value);
    }
}

/// Checks the shape RFC 9114 section 4.2 and section 4.3 put on a response
/// field list.
///
/// **The name rule is `engine.headerNameIsToken` and the value rule is
/// `engine.headerValueHasControl`, the two rules
/// `h2.validateResponseFields` asks and the two rules
/// `h1.validateHeaderName` and `h1.validateHeaderValue` ask of a
/// request.** One rule each, asked in three engines, so none of them can
/// drift. Over HTTP/1.1 a CR or an LF cannot survive inside a name or a
/// value, because the head parser split the head on CRLF to find them.
/// Over HTTP/3 both are opaque octet strings, so a peer writes any byte it
/// likes, and `recordHead` would then write fields the server never sent
/// into a user's `-D` file. A field named
/// `x-a\r\nset-cookie: injected=1` did exactly that until the name met
/// more than a check for an upper-case letter. The test
/// "h2 and h3 read the one field name rule" holds the two engines to the
/// one rule.
///
/// **A NUL is named before either of them.** `engine.headerValueHasControl`
/// answers true for a NUL, so such a value was already refused here, as
/// `MalformedResponse` and exit 56. curl 8.21.0 answers the same response
/// with `Nul byte in header` and exit 8, which is a code of its own, so
/// `refuseNulInFields` runs first and keeps that name. See
/// `engine.refuseNulInHead`.
fn validateResponseFields(list: zurl_qpack.FieldList) Fault!void {
    try refuseNulInFields(list);
    var seen_ordinary = false;
    var seen_status = false;
    for (list.fields.items) |item| {
        if (item.name.len == 0) return error.MalformedResponse;
        if (engine.headerValueHasControl(item.value)) return error.MalformedResponse;
        if (item.name[0] == ':') {
            if (seen_ordinary) return error.MalformedResponse;
            // A response carries `:status` and no other pseudo header.
            if (!std.mem.eql(u8, item.name, ":status")) return error.MalformedResponse;
            // **Once, and no more.** RFC 9114 section 4.3 gives a pseudo
            // header one appearance, and `h2.validateResponseFields`
            // refuses a repeat for the same reason: `readStatus` takes the
            // first, so a second one was read by nobody and reached a
            // caller inside a head this engine had called legal.
            if (seen_status) return error.MalformedResponse;
            seen_status = true;
            continue;
        }
        seen_ordinary = true;
        // RFC 9114 section 4.2: a field name is a `tchar` run with no
        // upper-case letter in it. That refuses a CR, an LF, a NUL, a
        // space and a colon, which are the octets that turn one field into
        // two lines of the rendered block. It also lets every lookup below
        // compare byte for byte.
        if (!engine.headerNameIsToken(item.name, .lower)) return error.MalformedResponse;
        if (connectionSpecific(item.name)) return error.MalformedResponse;
    }
}

/// The status of a response field list.
///
/// RFC 9114 section 4.3.2 makes `:status` exactly three digits, so anything
/// else is a malformed response and never a status this engine guesses at.
fn readStatus(list: zurl_qpack.FieldList) Fault!u16 {
    const text = list.get(":status") orelse return error.MalformedResponse;
    if (text.len != status_text_len) return error.MalformedResponse;
    for (text) |byte| {
        if (!std.ascii.isDigit(byte)) return error.MalformedResponse;
    }
    return std.fmt.parseInt(u16, text, 10) catch return error.MalformedResponse;
}

/// Whether `headers` already carries an `accept-encoding` field of the
/// caller's own, so this engine writes none of its own beside it. The rule
/// `h1.headersOfferEncoding` holds, said again for this engine's own head
/// builder. It raises no offer: only `--compressed` does that.
fn headersOfferEncoding(headers: []const std.http.Header) bool {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "accept-encoding")) return true;
    }
    return false;
}

/// The length the response head announces, out of every `content-length`
/// field it carries.
///
/// **The rule is `h2.contentLengthField`, which `h1` keeps too.** This
/// engine took the first field of that name, read a value that is not a
/// number as no length at all, and never compared a second field with the
/// first. RFC 9110 section 8.6 makes a head with two differing lengths
/// malformed, and `h1` already refused one through
/// `std.http.Client.Response.Head.parse`.
fn readContentLength(fields: zurl_qpack.FieldList) Fault!?u64 {
    var seen: ?u64 = null;
    for (fields.fields.items) |item| {
        if (!std.mem.eql(u8, item.name, "content-length")) continue;
        seen = engine.contentLengthField(seen, item.value) catch return error.MalformedResponse;
    }
    return seen;
}

/// What the peer's `content-encoding` field means to this build.
///
/// **The rule lives in `engine.contentEncoding` and this engine keeps none
/// of its own.** This function read any token it did not recognise as
/// `identity`, which handed a caller the compressed octets of a
/// `content-encoding: br` answer as if they were the body. All three
/// engines now ask one function, so the answer cannot differ by protocol.
fn readContentEncoding(
    fields: zurl_qpack.FieldList,
    accept_encoding: bool,
) Fault!std.http.ContentEncoding {
    return engine.contentEncoding(fields.get("content-encoding"), accept_encoding);
}

fn pickChallenge(fields: zurl_qpack.FieldList) ?[]const u8 {
    var first: ?[]const u8 = null;
    for (fields.fields.items) |item| {
        if (!std.mem.eql(u8, item.name, "www-authenticate")) continue;
        if (zurl_core.auth.hasDigestChallenge(item.value)) return item.value;
        if (first == null) first = item.value;
    }
    return first;
}

/// A piece of the request scratch buffer, held as an offset because the
/// buffer moves while it grows.
const Span = struct { at: usize, len: usize };

fn span(scratch: std.ArrayList(u8), s: Span) []const u8 {
    return scratch.items[s.at..][0..s.len];
}

fn appendPath(
    gpa: std.mem.Allocator,
    scratch: *std.ArrayList(u8),
    uri: std.Uri,
) std.mem.Allocator.Error!Span {
    const at = scratch.items.len;
    var w: std.Io.Writer.Allocating = .fromArrayList(gpa, scratch);
    defer scratch.* = w.writer.toArrayList();
    uri.writeToStream(&w.writer, .{ .path = true, .query = true }) catch return error.OutOfMemory;
    if (w.writer.end == at) w.writer.writeAll("/") catch return error.OutOfMemory;
    return .{ .at = at, .len = w.writer.end - at };
}

fn appendPrint(
    gpa: std.mem.Allocator,
    scratch: *std.ArrayList(u8),
    comptime fmt: []const u8,
    args: anytype,
) std.mem.Allocator.Error!Span {
    const at = scratch.items.len;
    var w: std.Io.Writer.Allocating = .fromArrayList(gpa, scratch);
    defer scratch.* = w.writer.toArrayList();
    w.writer.print(fmt, args) catch return error.OutOfMemory;
    return .{ .at = at, .len = w.writer.end - at };
}

fn appendLower(
    gpa: std.mem.Allocator,
    scratch: *std.ArrayList(u8),
    text: []const u8,
) std.mem.Allocator.Error!Span {
    const at = scratch.items.len;
    try scratch.ensureUnusedCapacity(gpa, text.len);
    for (text) |byte| scratch.appendAssumeCapacity(std.ascii.toLower(byte));
    return .{ .at = at, .len = text.len };
}

/// One request and its response, open for reading the body.
const Exchange = struct {
    interface: engine.Exchange,
    gpa: std.mem.Allocator,
    /// Borrowed. The session owns it and outlives this exchange.
    session: *Session,
    peer: Peer,
    slot: *zurl_quic.Streams.Stream,
    /// The frame order of RFC 9114 section 4.1 for this stream.
    message: zurl_h3.Connection.Message,
    head_value: engine.Head,
    /// Owned copies of the two head values that outlive the field list.
    location: ?[]u8 = null,
    challenge: ?[]u8 = null,
    content_length: ?u64,
    content_encoding: std.http.ContentEncoding,
    body_received: u64,
    body_taken: bool,
    body_partial: bool,
    body_ended: bool,
    body_fault: ?Fault,
    /// How many octets of the current `DATA` frame have not been read.
    frame_remaining: u64,
    idle_frames: usize,
    /// How many octets of frames this build ignores this transfer has
    /// thrown away.
    ///
    /// **One count for the head and the body together.** `readHead` and
    /// `rawChunk` both step over the same kinds of frame, so a peer that
    /// had a fresh ceiling for each of them would buy twice the octets.
    /// See `skip_octets_max`.
    skipped_octets: u64,
    /// Body octets read and not yet handed to the caller. They point into
    /// `chunk`.
    pending: []const u8,
    chunk: [body_chunk_len]u8,
    raw: std.Io.Reader,
    transfer_buffer: [transfer_buffer_len]u8,
    body: std.Io.Reader,
    body_source: *std.Io.Reader,
    decompress: std.http.Decompress,
    decompress_buffer: [decompress_buffer_len]u8,
    /// The window a zstd answer decodes through, or null for every other
    /// answer. Owned, `zstd_buffer_len` octets, freed by `close`.
    zstd_buffer: ?[]u8,
    trailer_text: ?[]u8,
    chain_storage: ?[]u8,

    const exchange_vtable: engine.Exchange.VTable = .{
        .head = headImpl,
        .bodyReader = bodyReaderImpl,
        .check = checkImpl,
        .close = closeImpl,
        .adoptChain = adoptChainImpl,
        .withheldCredential = withheldCredentialImpl,
        .trailers = trailersImpl,
    };

    const raw_vtable: std.Io.Reader.VTable = .{ .stream = rawStream, .discard = rawDiscard };
    const body_vtable: std.Io.Reader.VTable = .{ .stream = bodyStream, .discard = bodyDiscard };

    fn headImpl(ptr: *anyopaque) engine.Head {
        const self: *Exchange = @ptrCast(@alignCast(ptr));
        return self.head_value;
    }

    fn trailersImpl(ptr: *anyopaque) ?[]const u8 {
        const self: *Exchange = @ptrCast(@alignCast(ptr));
        return self.trailer_text;
    }

    fn adoptChainImpl(ptr: *anyopaque, storage: []u8, url: []const u8) void {
        const self: *Exchange = @ptrCast(@alignCast(ptr));
        self.chain_storage = storage;
        self.head_value.effective_url = url;
    }

    fn withheldCredentialImpl(ptr: *anyopaque) void {
        const self: *Exchange = @ptrCast(@alignCast(ptr));
        self.head_value.credential_withheld = true;
    }

    fn bodyReaderImpl(ptr: *anyopaque, buffer: []u8) *std.Io.Reader {
        const self: *Exchange = @ptrCast(@alignCast(ptr));
        // One exchange has one body. A second reader would restart the
        // framing over a stream that already moved.
        std.debug.assert(!self.body_taken);
        self.body_taken = true;

        self.raw = .{ .vtable = &raw_vtable, .buffer = &self.transfer_buffer, .seek = 0, .end = 0 };
        // The zstd window when the answer is zstd, and the flate window
        // otherwise. `readHead` took the first one where the head said so.
        const window = self.zstd_buffer orelse &self.decompress_buffer;
        self.body_source = self.decompress.init(&self.raw, window, self.content_encoding);
        self.body = .{ .vtable = &body_vtable, .buffer = buffer, .seek = 0, .end = 0 };
        return &self.body;
    }

    /// The next run of body octets, or the end of the body.
    fn rawChunk(self: *Exchange) std.Io.Reader.Error![]const u8 {
        if (self.pending.len != 0) return self.pending;
        if (self.body_ended) return self.endOfBody();

        while (true) {
            if (self.idle_frames >= idle_frames_max) return self.bodyFault(error.PeerStalled);

            if (self.frame_remaining == 0) {
                const header = self.session.readFrameHeader(self.slot) catch |err|
                    return self.bodyFault(err);
                const found = header orelse {
                    self.body_ended = true;
                    return self.endOfBody();
                };
                const informational = false;
                const disposition = self.message.onFrame(found.kind, informational) catch |err|
                    return self.bodyFault(err);
                switch (found.kind) {
                    .data => {
                        std.debug.assert(disposition == .act);
                        self.frame_remaining = found.length;
                        if (found.length == 0) {
                            self.idle_frames += 1;
                            continue;
                        }
                    },
                    .headers => {
                        // The trailer section. RFC 9114 section 4.1: the
                        // body has ended.
                        self.readTrailers(found.length) catch |err| return self.bodyFault(err);
                        self.body_ended = true;
                        return self.endOfBody();
                    },
                    else => {
                        std.debug.assert(disposition == .skip);
                        skip(self.session, self.slot, found.length, &self.skipped_octets) catch |err|
                            return self.bodyFault(err);
                        self.idle_frames += 1;
                        continue;
                    },
                }
            }

            const want: usize = @intCast(@min(self.frame_remaining, self.chunk.len));
            const moved = self.session.fill(self.slot, self.chunk[0..want]) catch |err|
                return self.bodyFault(err);
            if (moved == 0) {
                // The stream ended inside a `DATA` frame, so the body is
                // cut short whatever the head announced.
                self.body_partial = true;
                return self.bodyFault(error.MalformedResponse);
            }
            self.frame_remaining -= moved;
            try self.countBody(moved);
            self.pending = self.chunk[0..moved];
            return self.pending;
        }
    }

    /// Reads the trailer section and renders it the way `curl -D` writes
    /// it: one `name: value\r\n` for each field, and nothing else.
    fn readTrailers(self: *Exchange, length: u64) Fault!void {
        if (length > field_block_len_max) return error.ResponseHeadTooLarge;
        const len: usize = @intCast(length);
        const block = try self.gpa.alloc(u8, len);
        defer self.gpa.free(block);
        if (!try self.session.readExactly(self.slot, block)) return error.MalformedResponse;

        var section = try self.session.decoder.decodeSection(self.gpa, block);
        defer section.deinit(self.gpa);
        try validateResponseFields(section.list);

        var total: usize = 0;
        for (section.list.fields.items) |item| {
            if (item.name.len != 0 and item.name[0] == ':') continue;
            total += item.name.len + ": ".len + item.value.len + "\r\n".len;
        }
        if (total == 0) return;

        const text = try self.gpa.alloc(u8, total);
        errdefer self.gpa.free(text);
        var w: std.Io.Writer = .fixed(text);
        // **Every write below fits, because `total` counted each one over
        // the same list, with the same filter, at the same width.** So a
        // write that did not fit would be an arithmetic error in the loop
        // above and never a peer's octets, which is what makes an assert
        // the right answer here and not an error a caller handles. The
        // assert after the loop is what proves the two agree, and it runs
        // in a debug build, where such an error is found.
        for (section.list.fields.items) |item| {
            if (item.name.len != 0 and item.name[0] == ':') continue;
            w.writeAll(item.name) catch unreachable;
            w.writeAll(": ") catch unreachable;
            w.writeAll(item.value) catch unreachable;
            w.writeAll("\r\n") catch unreachable;
        }
        std.debug.assert(w.buffered().len == total);
        self.trailer_text = text;
    }

    /// Counts `octets` of body against the length the head announced, and
    /// fails the transfer when they run past it.
    ///
    /// **The bound is `h2.bodyWithinContentLength`, and
    /// `h2.Exchange.countBody` asks the same one.** RFC 9114 section 4.1.2
    /// makes a body whose length disagrees with `content-length`
    /// malformed. This engine counted only upward, so `endOfBody` caught a
    /// body that came out short and nothing caught one that came out long.
    ///
    /// The fault is `MalformedResponse` and not `PartialFile`, for the
    /// reason `h2.Exchange.countBody` gives: `engine.BodyError` names only
    /// a body that stopped short, and this body did the opposite. The
    /// caller reads `ReadError`, which is exit 56.
    fn countBody(self: *Exchange, octets: usize) std.Io.Reader.Error!void {
        self.body_received += octets;
        engine.bodyWithinContentLength(self.content_length, self.body_received) catch
            return self.bodyFault(error.MalformedResponse);
    }

    fn endOfBody(self: *Exchange) std.Io.Reader.Error {
        if (self.content_length) |announced| {
            if (self.body_received < announced) {
                self.body_partial = true;
                return error.ReadFailed;
            }
        }
        return error.EndOfStream;
    }

    fn bodyFault(self: *Exchange, fault: Fault) std.Io.Reader.Error {
        self.body_fault = fault;
        if (self.content_length) |announced| {
            if (self.body_received < announced) self.body_partial = true;
        }
        // The body stopped on a fault, so the connection is at a place
        // nothing here can describe. See `Session.abort`, which is the
        // other door out of `open`.
        self.session.abort(fault);
        return error.ReadFailed;
    }

    fn rawStream(
        io_reader: *std.Io.Reader,
        w: *std.Io.Writer,
        limit: std.Io.Limit,
    ) std.Io.Reader.StreamError!usize {
        const self: *Exchange = @alignCast(@fieldParentPtr("raw", io_reader));
        const chunk = try self.rawChunk();
        const take = limit.sliceConst(chunk);
        try w.writeAll(take);
        self.pending = chunk[take.len..];
        return take.len;
    }

    fn rawDiscard(io_reader: *std.Io.Reader, limit: std.Io.Limit) std.Io.Reader.Error!usize {
        const self: *Exchange = @alignCast(@fieldParentPtr("raw", io_reader));
        const chunk = try self.rawChunk();
        const take = limit.minInt(chunk.len);
        self.pending = chunk[take..];
        return take;
    }

    fn bodyStream(
        io_reader: *std.Io.Reader,
        w: *std.Io.Writer,
        limit: std.Io.Limit,
    ) std.Io.Reader.StreamError!usize {
        const self: *Exchange = @alignCast(@fieldParentPtr("body", io_reader));
        return self.body_source.stream(w, limit);
    }

    fn bodyDiscard(io_reader: *std.Io.Reader, limit: std.Io.Limit) std.Io.Reader.Error!usize {
        const self: *Exchange = @alignCast(@fieldParentPtr("body", io_reader));
        return self.body_source.discard(limit);
    }

    fn checkImpl(ptr: *anyopaque) engine.BodyError!void {
        const self: *Exchange = @ptrCast(@alignCast(ptr));
        // **The deadline is reported before the short body.** A body the
        // peer stopped feeding is also a body that never reached its
        // announced length, so both can stand together and the one that
        // says why is this one. A caller told `PartialFile` looks for a
        // truncated file; a caller told `OperationTimedOut` looks at the
        // peer that went quiet. `h1.Exchange.check` and
        // `h2.Exchange.check` order the two the same way.
        if (self.body_fault) |fault| {
            if (fault == error.OperationTimedOut) return error.OperationTimedOut;
        }
        if (self.body_partial) return error.PartialFile;
    }

    fn closeImpl(ptr: *anyopaque) void {
        const self: *Exchange = @ptrCast(@alignCast(ptr));
        const session = self.session;

        // RFC 9114 section 4.1: a client that stops reading a response
        // asks the server to stop sending, so the server is not left
        // spending its window on octets nobody reads.
        if (!self.body_ended and !self.slot.recv_state.finished()) {
            session.conn.streams.stopSending(
                self.slot,
                @intFromEnum(zurl_h3.ErrorCode.request_cancelled),
            );
            session.conn.flush() catch {};
        }
        session.roles[session.indexOf(self.slot)] = .idle;

        if (self.location) |value| self.gpa.free(value);
        if (self.challenge) |value| self.gpa.free(value);
        if (self.trailer_text) |text| self.gpa.free(text);
        if (self.chain_storage) |storage| self.gpa.free(storage);
        // Null for every answer that was not zstd. See `zstd_buffer_len`.
        if (self.zstd_buffer) |buffer| self.gpa.free(buffer);
        // This build opens one QUIC connection for one transfer, so a
        // connection is never kept. See the file comment.
        self.peer.release(self.peer.ctx, self.peer.handle, false);
        self.gpa.destroy(self);
    }
};

const h3_test_server = @import("h3_test_server.zig");

/// One loopback HTTP/3 client, and the two seams `open` needs.
const TestClient = struct {
    gpa: std.mem.Allocator,
    session: *Session,
    head_block: ?[]u8 = null,
    answered: bool = false,
    body_sent: bool = false,
    released: bool = false,

    /// Opens a session with the engine's own read ceiling, which is the
    /// bound an ordinary transfer runs under. A test that waits on a peer
    /// which went quiet calls `connectWith` and names a short one, so the
    /// test ends in its own time and not in five minutes.
    fn connect(self: *TestClient, gpa: std.mem.Allocator, server_port: u16) !void {
        return self.connectWith(gpa, server_port, engine.default_read_timeout);
    }

    fn connectWith(
        self: *TestClient,
        gpa: std.mem.Allocator,
        server_port: u16,
        read_timeout: Io.Timeout,
    ) !void {
        self.* = .{ .gpa = gpa, .session = undefined };
        self.session = Session.connect(gpa, .{
            .io = testing.io,
            .address = .{ .ip4 = .loopback(server_port) },
            .host = h3_test_server.host_name,
            // **The host name walk and the certificate's own signature
            // both run.** Only the trust root is left out, which is what
            // `.self_signed` means. The fixture's certificate carries
            // `zurl.test` as its common name.
            .verify_host = true,
            .trust = .self_signed,
            .read_timeout = read_timeout,
        }) catch |err| {
            if (self.head_block) |block| gpa.free(block);
            return err;
        };
    }

    fn deinit(self: *TestClient) void {
        self.session.deinit();
        if (self.head_block) |block| self.gpa.free(block);
    }

    fn keepHead(ctx: *anyopaque, head: []const u8) std.mem.Allocator.Error!void {
        const self: *TestClient = @ptrCast(@alignCast(ctx));
        if (self.head_block) |block| self.gpa.free(block);
        self.head_block = try self.gpa.dupe(u8, head);
    }

    fn keptHeads(ctx: *anyopaque) HeadLog.Kept {
        const self: *TestClient = @ptrCast(@alignCast(ctx));
        return .{ .all = self.head_block, .final = self.head_block, .dropped = false };
    }

    fn release(ctx: *anyopaque, handle: *anyopaque, keep: bool) void {
        _ = handle;
        _ = keep;
        const self: *TestClient = @ptrCast(@alignCast(ctx));
        self.released = true;
    }

    const Request = struct {
        method: std.http.Method = .GET,
        path: []const u8 = "/",
        /// False, the same default `engine.Request.accept_encoding` has, so
        /// a test that says nothing sends the head a plain `curl` sends.
        accept_encoding: bool = false,
        headers: []const std.http.Header = &.{},
        body: ?engine.Body = null,
    };

    fn send(self: *TestClient, request: Request) !*engine.Exchange {
        return open(try self.args(request));
    }

    /// `send`, answering the name this engine gives a fault rather than
    /// the name the seam reports.
    ///
    /// `openError` puts nearly every fault under `engine.OpenError.ReadError`,
    /// so a test of one bound cannot tell it from any other failure of the
    /// same transfer. A test of a bound reads the name here.
    fn sendRaw(self: *TestClient, request: Request) Fault!*engine.Exchange {
        return openInner(self.args(request) catch return error.OutOfMemory);
    }

    fn args(self: *TestClient, request: Request) !Open {
        const uri: std.Uri = .{
            .scheme = "https",
            .user = null,
            .password = null,
            .host = .{ .raw = h3_test_server.host_name },
            .port = null,
            .path = .{ .percent_encoded = request.path },
            .query = null,
            .fragment = null,
        };
        return .{
            .gpa = self.gpa,
            .session = self.session,
            .method = request.method,
            .uri = uri,
            .authority = h3_test_server.host_name,
            .user_agent = "zurl/0.1",
            .accept_encoding = request.accept_encoding,
            .headers = request.headers,
            .body = request.body,
            .url = try zurl_core.url.parse("https://" ++ h3_test_server.host_name ++ "/"),
            .cookies = null,
            .log = .{ .ctx = self, .record = keepHead, .kept = keptHeads },
            .peer = .{ .ctx = self, .handle = self, .release = release },
            .answered = &self.answered,
            .body_sent = &self.body_sent,
        };
    }
};

fn readBody(exchange: *engine.Exchange) ![]u8 {
    var buffer: [4096]u8 = undefined;
    const reader = exchange.bodyReader(&buffer);
    return reader.allocRemaining(testing.allocator, .unlimited);
}

/// A body source over a fixed slice, for a test that uploads.
const TestBody = struct {
    bytes: []const u8,
    at: usize = 0,

    fn read(ctx: *anyopaque, buffer: [*]u8, len: usize) callconv(.c) isize {
        const self: *TestBody = @ptrCast(@alignCast(ctx));
        const take = @min(len, self.bytes.len - self.at);
        @memcpy(buffer[0..take], self.bytes[self.at..][0..take]);
        self.at += take;
        return @intCast(take);
    }

    fn rewind(ctx: *anyopaque) callconv(.c) bool {
        const self: *TestBody = @ptrCast(@alignCast(ctx));
        self.at = 0;
        return true;
    }

    fn source(self: *TestBody) engine.Body {
        return .{
            .len = self.bytes.len,
            .ctx = self,
            .read = read,
            .rewind = rewind,
            .content_type = "text/plain",
        };
    }
};

test "a GET over HTTP/3 reaches the status, the head log, and the body" {
    var server: h3_test_server = undefined;
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-type", .value = "text/plain" },
            .{ .name = "content-length", .value = "5" },
        },
        .body = "hello",
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var exchange = try client.send(.{ .path = "/thing?q=1" });
    defer exchange.close();

    const head = exchange.head();
    try testing.expectEqual(@as(u16, 200), head.status);
    try testing.expectEqual(@as(?u64, 5), head.content_length);
    try testing.expectEqual(std.http.TransferEncoding.none, head.transfer_encoding);
    try testing.expect(!head.body_decoded);

    // The head block goes to the log the way `curl -D` writes it over
    // HTTP/3: the version and the status, with no reason phrase.
    const block = head.final_headers.?;
    try testing.expect(std.mem.startsWith(u8, block, "HTTP/3 200 \r\n"));
    try testing.expect(std.mem.indexOf(u8, block, "content-type: text/plain\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, block, "\r\n\r\n"));
    // No pseudo header reaches the block.
    try testing.expect(std.mem.indexOf(u8, block, ":status") == null);

    const body = try readBody(exchange);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("hello", body);

    // And the request the server read is the request this side built.
    const request = server.requestHead(0).?;
    try testing.expect(std.mem.indexOf(u8, request, ":method: GET\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, request, ":scheme: https\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, request, ":path: /thing?q=1\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, request, ":authority: zurl.test\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, request, "user-agent: zurl/0.1\r\n") != null);
    // **No offer, no field.** This request named no `--compressed`, so it
    // writes no `accept-encoding` at all, which is what curl writes.
    try testing.expect(std.mem.indexOf(u8, request, "accept-encoding") == null);
}

test "an offer writes one accept-encoding field over HTTP/3" {
    // The other half of the rule above, and the value is the one `h1` and
    // `h2` write, so a peer answers all three engines with the same body.
    var server: h3_test_server = undefined;
    try server.start(&.{.{
        .fields = &.{.{ .name = ":status", .value = "204" }},
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var exchange = try client.send(.{ .accept_encoding = true });
    exchange.close();

    const request = server.requestHead(0).?;
    try testing.expect(std.mem.indexOf(
        u8,
        request,
        "accept-encoding: " ++ accept_encoding_value ++ "\r\n",
    ) != null);
    try testing.expectEqual(
        @as(usize, 1),
        std.mem.count(u8, request, "accept-encoding: "),
    );
}

test "a caller's own accept-encoding field is the only one HTTP/3 writes" {
    // Two offers on one request name two sets, and a peer may answer
    // either. `h1.sendOnH3` raises the flag from the same field.
    var server: h3_test_server = undefined;
    try server.start(&.{.{
        .fields = &.{.{ .name = ":status", .value = "204" }},
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var exchange = try client.send(.{
        .accept_encoding = true,
        .headers = &.{.{ .name = "accept-encoding", .value = "gzip" }},
    });
    exchange.close();

    const request = server.requestHead(0).?;
    try testing.expect(std.mem.indexOf(u8, request, "accept-encoding: gzip\r\n") != null);
    try testing.expectEqual(
        @as(usize, 1),
        std.mem.count(u8, request, "accept-encoding: "),
    );
}

test "a caller header reaches the peer with a lower case name" {
    var server: h3_test_server = undefined;
    try server.start(&.{.{
        .fields = &.{.{ .name = ":status", .value = "204" }},
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var exchange = try client.send(.{ .headers = &.{
        .{ .name = "X-Marker", .value = "one" },
        .{ .name = "accept", .value = "text/plain" },
    } });
    defer exchange.close();
    try testing.expectEqual(@as(u16, 204), exchange.head().status);

    // RFC 9114 section 4.2: every field name on the wire is lower case.
    const request = server.requestHead(0).?;
    try testing.expect(std.mem.indexOf(u8, request, "x-marker: one\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, request, "X-Marker") == null);
    try testing.expect(std.mem.indexOf(u8, request, "accept: text/plain\r\n") != null);
}

test "a request body goes out as DATA frames behind the head" {
    var server: h3_test_server = undefined;
    try server.start(&.{.{
        .fields = &.{.{ .name = ":status", .value = "201" }},
        .body = "made",
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var source: TestBody = .{ .bytes = "name=zurl&kind=quic" };
    var exchange = try client.send(.{
        .method = .POST,
        .path = "/submit",
        .body = source.source(),
    });
    defer exchange.close();

    try testing.expectEqual(@as(u16, 201), exchange.head().status);
    try testing.expect(client.body_sent);

    const request = server.requestHead(0).?;
    try testing.expect(std.mem.indexOf(u8, request, ":method: POST\r\n") != null);
    // A known length is announced. HTTP/3 frames its own body, so there is
    // no chunked transfer coding to fall back on.
    try testing.expect(std.mem.indexOf(u8, request, "content-length: 19\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, request, "content-type: text/plain\r\n") != null);
    try testing.expectEqualStrings("name=zurl&kind=quic", server.requestBody(0).?);

    const body = try readBody(exchange);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("made", body);
}

test "a body that arrives in many DATA frames reads back whole" {
    const long = "0123456789" ** 300;
    var server: h3_test_server = undefined;
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "3000" },
        },
        .body = long,
        // Small frames, so the reader crosses a frame boundary many times
        // and crosses packet boundaries with them.
        .data_chunk = 64,
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var exchange = try client.send(.{});
    defer exchange.close();
    try testing.expectEqual(@as(?u64, 3000), exchange.head().content_length);

    const body = try readBody(exchange);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings(long, body);
    try exchange.check();
}

test "a trailer section reads back the way curl writes one" {
    var server: h3_test_server = undefined;
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-type", .value = "text/plain" },
        },
        .body = "body",
        .trailers = &.{
            .{ .name = "grpc-status", .value = "0" },
            .{ .name = "x-end", .value = "yes" },
        },
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var exchange = try client.send(.{});
    defer exchange.close();

    // **Read after the body and not before.** A trailer arrives behind the
    // last body octet, which is the whole point of one.
    try testing.expect(exchange.trailers() == null);
    const body = try readBody(exchange);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("body", body);

    const text = exchange.trailers().?;
    try testing.expectEqualStrings("grpc-status: 0\r\nx-end: yes\r\n", text);
    // The trailer fields are not part of the head block.
    try testing.expect(std.mem.indexOf(u8, exchange.head().final_headers.?, "grpc-status") == null);
}

test "a trailer section takes the field rules the head takes" {
    // `readTrailers` renders `name: value\r\n` the way `recordHead` does,
    // so a forged name in a trailer is the same attack by a shorter road.
    // Each case here is a whole transfer, so this covers the routing and
    // not the rule alone.
    const cases = [_]zurl_qpack.Field{
        .{ .name = "x-a\r\nset-cookie: injected=1", .value = "ok" },
        .{ .name = "x-a b", .value = "ok" },
        .{ .name = "X-Upper", .value = "ok" },
        .{ .name = "x-t", .value = "ok\r\nset-cookie: t=1" },
    };
    for (cases) |field| {
        var server: h3_test_server = undefined;
        try server.start(&.{.{
            .fields = &.{.{ .name = ":status", .value = "200" }},
            .body = "body",
            .trailers = &.{field},
        }});
        defer server.stop();

        var client: TestClient = undefined;
        try client.connect(testing.allocator, server.port());
        defer client.deinit();

        var exchange = try client.send(.{});
        defer exchange.close();

        // The head is whole and good. The trailer is what fails, and it
        // fails while the body is read, which is where it arrives.
        try testing.expectEqual(@as(u16, 200), exchange.head().status);
        try testing.expectError(error.ReadFailed, readBody(exchange));
        // Nothing of the forged section reaches the caller.
        try testing.expectEqual(@as(?[]const u8, null), exchange.trailers());
    }
}

test "a peer that opens two control streams closes the connection" {
    // RFC 9114 section 6.2.1. Two control streams carry two `SETTINGS`
    // frames, and this side would have to choose which one describes the
    // peer.
    var server: h3_test_server = undefined;
    try server.startWith(&.{.{
        .fields = &.{.{ .name = ":status", .value = "200" }},
    }}, .{ .duplicate_control_stream = true });
    defer server.stop();

    var client: TestClient = undefined;
    client.connect(testing.allocator, server.port()) catch |err| {
        // The fault may land while the connection is coming up.
        try testing.expectEqual(error.StreamCreationError, err);
        return;
    };
    defer client.deinit();
    try testing.expectError(error.ReadError, client.send(.{}));
}

test "a control stream whose first frame is not SETTINGS closes the connection" {
    // RFC 9114 section 6.2.1 makes any other first frame
    // H3_MISSING_SETTINGS, and that holds for a frame type this build does
    // not know as well.
    var server: h3_test_server = undefined;
    try server.startWith(&.{.{
        .fields = &.{.{ .name = ":status", .value = "200" }},
    }}, .{ .skip_settings = true, .goaway = 0 });
    defer server.stop();

    var client: TestClient = undefined;
    client.connect(testing.allocator, server.port()) catch |err| {
        try testing.expectEqual(error.MissingSettings, err);
        return;
    };
    defer client.deinit();
    try testing.expectError(error.ReadError, client.send(.{}));
}

test "a unidirectional stream of a reserved type is abandoned and the request still runs" {
    // RFC 9114 section 6.2.3 has a peer open one on purpose, so a client
    // that closed the connection over it would refuse a conformant peer.
    var server: h3_test_server = undefined;
    try server.startWith(&.{.{
        .fields = &.{.{ .name = ":status", .value = "200" }},
        .body = "still here",
    }}, .{ .grease_stream = true });
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var exchange = try client.send(.{});
    defer exchange.close();
    try testing.expectEqual(@as(u16, 200), exchange.head().status);
    const body = try readBody(exchange);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("still here", body);
    try testing.expect(client.session.rules.abandoned_streams >= 1);
}

test "a reserved frame on the request stream is ignored and the request still runs" {
    // RFC 9114 section 9: a frame of a type this build does not know is
    // ignored. The bound beside it must not refuse the grease frame a
    // conformant peer of section 7.2.8 sends, so this one declares eight
    // octets and sends eight.
    var server: h3_test_server = undefined;
    try server.startWith(&.{.{
        .fields = &.{.{ .name = ":status", .value = "200" }},
        .body = "still here",
    }}, .{ .grease_request_frame = .{ .declared = 8, .sent = 8 } });
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var exchange = try client.send(.{});
    defer exchange.close();
    try testing.expectEqual(@as(u16, 200), exchange.head().status);
    const body = try readBody(exchange);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("still here", body);
}

test "a reserved frame longer than the skip ceiling is refused" {
    // **A count of frames bounds nothing over HTTP/3.** RFC 9114 section
    // 7.1 frames carry a QUIC varint length, so one ignored frame may
    // declare 2^62-1 octets and `idle_frames_max` counts it once. The peer
    // then trickled the payload and `skip` read it for ever, with no octet
    // reaching the body, the progress meter, or `--max-filesize`.
    //
    // The frame below declares the largest length a varint holds and sends
    // no octet of it. The ceiling is on the length the peer declares, so
    // the frame is refused before one octet of it is read, and the fault
    // is `ExcessiveLoad` and not the `MalformedResponse` a stream that
    // ended early would give. `sendRaw` is what tells the two apart:
    // `openError` puts both under `ReadError`.
    const declared: u64 = (1 << 62) - 1;
    try testing.expect(declared > skip_octets_max);

    var server: h3_test_server = undefined;
    try server.startWith(&.{.{
        .fields = &.{.{ .name = ":status", .value = "200" }},
        .body = "never read",
    }}, .{ .grease_request_frame = .{ .declared = declared, .sent = 0 } });
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    try testing.expectError(error.ExcessiveLoad, client.sendRaw(.{}));
    // And the seam a user reads still names a read failure.
    try testing.expectEqual(engine.OpenError.ReadError, openError(error.ExcessiveLoad));
}

test "a reserved stream type split across datagrams is read once and not twice" {
    // RFC 9114 section 6.2.3 reserved types are `0x1f * N + 0x21`, and
    // every one above `N = 0` takes two varint bytes or more. The fixture
    // sends `0x1f * 529 + 0x21`, whose four bytes are `80 00 40 30`, one
    // to a datagram, which is what a conformant greasing server does on a
    // busy path.
    //
    // A reader that kept the part of the type it had already taken in a
    // local would lose it the moment the rest had not arrived, and would
    // then read `0x00` on its own as a whole type: the control stream. The
    // peer already opened one, so the connection would close with
    // H3_STREAM_CREATION_ERROR over legal traffic.
    var server: h3_test_server = undefined;
    try server.startWith(&.{.{
        .fields = &.{.{ .name = ":status", .value = "200" }},
        .body = "still here",
    }}, .{ .split_grease_stream = true });
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var exchange = try client.send(.{});
    defer exchange.close();
    try testing.expectEqual(@as(u16, 200), exchange.head().status);
    const body = try readBody(exchange);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("still here", body);

    // The whole four byte type read as one reserved type, so the stream
    // was abandoned and no second control stream was ever seen.
    try testing.expect(client.session.rules.abandoned_streams >= 1);
    try testing.expectEqual(@as(?u64, 3), client.session.rules.peer_control_stream);
}

test "a reserved control frame longer than the control buffer is stepped over" {
    // RFC 9114 section 9 requires an unknown frame type to be ignored
    // whatever its length, and section 7.2.8 has a conformant peer send a
    // reserved type on purpose. So the length of a frame this side does
    // not read is bounded by nothing this side promised, and buffering it
    // before reading the disposition would close the connection over legal
    // traffic. 5120 octets is past `control_payload_len_max`.
    const grease_len = 5 * 1024;
    try testing.expect(grease_len > control_payload_len_max);

    var server: h3_test_server = undefined;
    try server.startWith(&.{.{
        .fields = &.{.{ .name = ":status", .value = "200" }},
        .body = "read anyway",
    }}, .{ .grease_control_frame = grease_len });
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var exchange = try client.send(.{});
    defer exchange.close();
    try testing.expectEqual(@as(u16, 200), exchange.head().status);
    const body = try readBody(exchange);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("read anyway", body);

    // The frame was counted and its payload was never held.
    try testing.expect(client.session.rules.ignored_frames >= 1);
    // And the `SETTINGS` frame in front of it still described the peer, so
    // the reader kept its place across the frame it stepped over.
    try testing.expect(client.session.rules.peer_settings != null);
}

test "a status with a leading zero is written as the three digits the peer sent" {
    // RFC 9114 section 4.3.2 makes `:status` exactly three digits, so
    // `007` is a status of 7 that the peer wrote in three characters. A
    // head block sized for three characters and written with one would
    // leave two octets of heap this side never wrote in a user's `-D`
    // file.
    var server: h3_test_server = undefined;
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "007" },
            .{ .name = "x-note", .value = "odd" },
        },
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var exchange = try client.send(.{});
    defer exchange.close();
    try testing.expectEqual(@as(u16, 7), exchange.head().status);

    const block = exchange.head().final_headers.?;
    try testing.expect(std.mem.startsWith(u8, block, "HTTP/3 007 \r\n"));
    try testing.expect(std.mem.indexOf(u8, block, "x-note: odd\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, block, "\r\n\r\n"));
}

test "the status line is three digits wide for every status a response can carry" {
    // The width the head block counts and the width the line writes are
    // one number, whatever the digits are.
    var digits: [status_text_len]u8 = undefined;
    for ([_]struct { status: u16, text: []const u8 }{
        .{ .status = 0, .text = "000" },
        .{ .status = 7, .text = "007" },
        .{ .status = 99, .text = "099" },
        .{ .status = 100, .text = "100" },
        .{ .status = 200, .text = "200" },
        .{ .status = 503, .text = "503" },
        .{ .status = 999, .text = "999" },
    }) |one| {
        writeStatusDigits(one.status, &digits);
        try testing.expectEqualStrings(one.text, &digits);
    }
}

test "a request field section larger than the peer accepts is refused before it goes out" {
    // RFC 9114 section 7.2.4.1: `SETTINGS_MAX_FIELD_SECTION_SIZE` is the
    // peer's promise about what it reads. A request past it would be
    // refused on arrival, so this side does not send it and says why.
    var server: h3_test_server = undefined;
    try server.start(&.{.{ .fields = &.{.{ .name = ":status", .value = "200" }} }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    // The fixture names a section size of its own, so the first request
    // goes out and the peer's `SETTINGS` frame is read on the way.
    var exchange = try client.send(.{});
    try testing.expectEqual(@as(u16, 200), exchange.head().status);
    exchange.close();
    try testing.expect(client.session.peerFieldSectionMax() != null);

    // Narrow what the peer accepts to 32 octets. The four pseudo headers
    // alone are past it, since RFC 9114 adds 32 for every field before it
    // counts a name or a value at all.
    client.session.rules.peer_settings.?.max_field_section_size = 32;
    try testing.expectError(error.WriteError, client.send(.{}));
    // Nothing of the refused request reached the peer.
    try testing.expectEqual(@as(usize, 1), server.requests());
}

test "the size of a field section is the one RFC 9114 counts and not the octets on the wire" {
    // Section 7.2.4.1: the name, the value, and 32 more for each field.
    try testing.expectEqual(@as(u64, 0), fieldSectionSize(&.{}));
    try testing.expectEqual(@as(u64, 32 + 7 + 3), fieldSectionSize(&.{
        .{ .name = ":status", .value = "200" },
    }));
    try testing.expectEqual(@as(u64, 2 * 32 + 7 + 3 + 6 + 3), fieldSectionSize(&.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "x-note", .value = "odd" },
    }));
    // The 32 octets are the overhead the field module already names, so
    // the two cannot drift apart.
    try testing.expectEqual(@as(usize, 32), zurl_qpack.field.entry_overhead);
}

test "the peer's SETTINGS are read and its QPACK table capacity is honoured" {
    // The peer allows a table of 4096 octets. This build's encoder inserts
    // nothing, so it still builds none: RFC 9204 section 3.2.2 makes the
    // peer's number a ceiling and not an instruction.
    var server: h3_test_server = undefined;
    try server.startWith(&.{.{
        .fields = &.{.{ .name = ":status", .value = "200" }},
    }}, .{ .settings = .{
        .qpack_max_table_capacity = 4096,
        .qpack_blocked_streams = 0,
        .max_field_section_size = 65536,
    } });
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var exchange = try client.send(.{});
    defer exchange.close();
    try testing.expectEqual(@as(u16, 200), exchange.head().status);

    // The peer's frame was read, stored, and is what the two answers
    // below come from.
    const peer = client.session.rules.peer_settings.?;
    try testing.expectEqual(@as(u64, 4096), peer.qpack_max_table_capacity);
    try testing.expectEqual(@as(?u64, 65536), client.session.peerFieldSectionMax());
    try testing.expectEqual(@as(u64, 0), client.session.qpackTableCapacity());

    // A peer that allows none gets none, which is the half that matters.
    client.session.rules.peer_settings = .{ .qpack_max_table_capacity = 0 };
    try testing.expectEqual(@as(u64, 0), client.session.qpackTableCapacity());
}

test "a credential the caller joined into the header list reaches the peer unchanged" {
    // **This is what stops the rule above from being vacuous.**
    // `h1.openOnce` joins the caller's headers with this hop's secrets and
    // hands one list down, and `Open.headers` is that list. So what this
    // engine owes a credential is to carry it to the origin the caller
    // named, once, byte for byte, and to add none of its own.
    //
    // The cross-origin half of the rule is `h1.openOnce`'s, because the
    // redirect chain lives above this engine. `--http3` has a route from
    // the command line now, so that half is driven through this engine as
    // well: see `h1.test "a cross-origin redirect over HTTP/3 withholds
    // the credential"` and the `--location-trusted` test beside it. Both
    // walk a real chain over a real QUIC connection.
    //
    // The name is built from two pieces so the source scan below still
    // finds no copy of the rule in this file.
    const name = "Author" ++ "ization";
    const value = "Bearer 0123456789";

    var server: h3_test_server = undefined;
    try server.start(&.{.{ .fields = &.{.{ .name = ":status", .value = "200" }} }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var exchange = try client.send(.{ .headers = &.{.{ .name = name, .value = value }} });
    defer exchange.close();
    try testing.expectEqual(@as(u16, 200), exchange.head().status);

    // It arrived with the lower case name RFC 9114 section 4.2 puts on the
    // wire, with the value the caller gave, and exactly once.
    var lowered: [64]u8 = undefined;
    var needle: [128]u8 = undefined;
    const line = try std.fmt.bufPrint(&needle, "{s}: {s}\r\n", .{
        std.ascii.lowerString(&lowered, name),
        value,
    });
    const request = server.requestHead(0).?;
    var count: usize = 0;
    var at: usize = 0;
    while (std.mem.indexOfPos(u8, request, at, line)) |found| {
        count += 1;
        at = found + line.len;
    }
    try testing.expectEqual(@as(usize, 1), count);
}

test "a GOAWAY the peer sent stops the next request on that connection" {
    var server: h3_test_server = undefined;
    try server.startWith(&.{.{
        .fields = &.{.{ .name = ":status", .value = "200" }},
        .body = "last",
    }}, .{ .goaway = 0 });
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var exchange = try client.send(.{});
    const body = try readBody(exchange);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("last", body);
    exchange.close();

    // RFC 9114 section 5.2: the server named the largest request it might
    // act on, so a new one on this connection would be thrown away.
    try testing.expectEqual(@as(?u64, 0), client.session.goaway);
    try testing.expectError(error.ReadError, client.send(.{}));
}

test "a HEAD request reports no body whatever the head announced" {
    // RFC 9110 section 9.3.2. `h1` and `h2` report zero for the same
    // reason, so a caller reads one answer whichever protocol replied.
    var server: h3_test_server = undefined;
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "12345" },
        },
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var exchange = try client.send(.{ .method = .HEAD });
    defer exchange.close();
    try testing.expectEqual(@as(?u64, 0), exchange.head().content_length);
    const body = try readBody(exchange);
    defer testing.allocator.free(body);
    try testing.expectEqual(@as(usize, 0), body.len);
}

test "a response that stops before its content length and goes quiet reaches the read deadline" {
    // **The peer sends part of the body and then neither ends the stream
    // nor closes the connection.** A QUIC stream ends on a FIN, so the
    // octets that did arrive are all there is and nothing says the body is
    // over. Two faults describe this response and both are true: the body
    // is shorter than the length it announced, and the peer stopped
    // writing. `check` reports the second, because that is the one that
    // says why. `h1.Exchange.check` and `h2.Exchange.check` order the two
    // the same way.
    var server: h3_test_server = undefined;
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "100" },
        },
        .body = "short",
        .cut_body = true,
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connectWith(testing.allocator, server.port(), readTimeoutMs(200));
    defer client.deinit();

    var exchange = try client.send(.{});
    defer exchange.close();
    try testing.expectEqual(@as(?u64, 100), exchange.head().content_length);

    // **A floor and never a ceiling.** The deadline says the wait may not
    // run past 200 milliseconds; a loaded machine may take longer to
    // notice, and that is not a failure. What a shorter wait would mean is
    // that the bound fired before the peer had its chance.
    const started = Io.Timestamp.now(testing.io, .awake);
    try testing.expectError(error.ReadFailed, readBody(exchange));
    try testing.expectError(error.OperationTimedOut, exchange.check());
    try testing.expect(elapsedNs(started) >= 200 * std.time.ns_per_ms);
}

/// How many nanoseconds have passed since `started`.
fn elapsedNs(started: Io.Timestamp) i128 {
    return started.durationTo(Io.Timestamp.now(testing.io, .awake)).nanoseconds;
}

/// A `read_timeout` of `ms` milliseconds, for the tests above.
fn readTimeoutMs(ms: i64) Io.Timeout {
    return .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
}

test "the settings this side announces say what its decoder can honour" {
    // RFC 9204 section 2.1: a table capacity of zero means no peer can
    // insert, so no field section can name an entry that has not arrived.
    // Saying a number and not honouring it is worse than saying zero.
    const s = Session.wanted();
    try testing.expectEqual(@as(u64, 0), s.qpack_max_table_capacity);
    try testing.expectEqual(@as(u64, 0), s.qpack_blocked_streams);
    try testing.expectEqual(@as(u64, zurl_qpack.blocked_streams_max), s.qpack_blocked_streams);
    try testing.expectEqual(@as(?u64, header_list_len_max), s.max_field_section_size);

    // **The number this side announces is the number its decoder
    // enforces.** RFC 9114 section 7.2.4.1 counts a field section as the
    // name, the value, and 32 more for each field, and `zurl_qpack.Decoder`
    // counts the same quantity, so the promise and the check are one
    // number rather than two that share a constant. The bound on the
    // compressed octets is a different quantity and carries a name of its
    // own.
    var decoder: zurl_qpack.Decoder = .init(.{
        .table_capacity_max = 0,
        .header_list_size_max = header_list_len_max,
    });
    defer decoder.deinit(testing.allocator);
    try testing.expectEqual(s.max_field_section_size.?, @as(u64, decoder.limits.header_list_size_max));
    try testing.expect(field_block_len_max >= header_list_len_max);

    // And they survive a round trip through the frame this side writes.
    var payload: [128]u8 = undefined;
    const body = zurl_h3.settings.encode(s, &payload);
    const back = try zurl_h3.settings.decode(body);
    try testing.expectEqual(s.qpack_max_table_capacity, back.qpack_max_table_capacity);
    try testing.expectEqual(s.max_field_section_size, back.max_field_section_size);
}

test "the connection window covers every stream window, so no reader can deadlock" {
    // The same comparison `zurl_quic.Streams.init` makes. It is here as
    // well so a change to either constant fails a test rather than a
    // connection.
    try testing.expectEqual(streams_max * stream_window_len, connection_window_len);

    var send_storage: [streams_max][16]u8 = undefined;
    var recv_storage: [streams_max][16]u8 = undefined;
    var slots: [streams_max]zurl_quic.Streams.Stream = undefined;
    for (&slots, 0..) |*slot, index| {
        slot.* = .init(&send_storage[index], &recv_storage[index]);
    }
    _ = try zurl_quic.Streams.init(.{
        .role = .client,
        .slots = &slots,
        .recv_window = streams_max * 16,
    });
    try testing.expectError(error.ConnectionWindowTooSmall, zurl_quic.Streams.init(.{
        .role = .client,
        .slots = &slots,
        .recv_window = streams_max * 16 - 1,
    }));
}

test "this engine never names an origin bound header" {
    // **The credential rule is reused and not copied.** `h1.openOnce`
    // joins the caller's headers with this hop's secrets and hands one
    // list down, and `Open.headers` is that list. So this file must hold
    // no copy of the rule, and this test is what says so: the source of
    // this file names neither header and never reads the array that names
    // them.
    //
    // **What this proves and what it does not.** It proves the absence of
    // a second copy of the rule, which no behavioural test can prove. It
    // says nothing about what happens to a credential. Three tests say
    // that: the one above, which drives a credential through this engine
    // to the loopback fixture and reads it back whole, and the two in
    // `h1.zig` that walk a cross-origin redirect chain over a real QUIC
    // connection and read the credential off the wire at each hop.
    const source = @embedFile("h3.zig");

    // No name of the set appears as a string this file could compare a
    // header against.
    var needle: [64]u8 = undefined;
    for (engine.origin_bound_headers) |name| {
        const quoted = std.fmt.bufPrint(&needle, "\"{s}\"", .{name}) catch unreachable;
        try testing.expect(std.mem.indexOf(u8, source, quoted) == null);
        const lowered = std.ascii.lowerString(needle[quoted.len..], quoted);
        try testing.expect(std.mem.indexOf(u8, source, lowered) == null);
    }

    // And no call asks whether a name is in the set. The one function in
    // the seam that answers that question is named below a character at a
    // time, so this test's own text is not what it finds.
    const call = "isOrigin" ++ "Bo" ++ "und";
    try testing.expect(std.mem.indexOf(u8, source, call) == null);
    // `h2.zig` does not ask it either, and `h1.zig` does. One caller
    // serves all three engines, which is the arrangement this test is
    // about.
    try testing.expect(std.mem.indexOf(u8, @embedFile("h2.zig"), call) == null);
    try testing.expect(std.mem.indexOf(u8, @embedFile("h1.zig"), call) != null);
}

test "a response field list with an upper case name or a control byte is malformed" {
    const gpa = testing.allocator;
    var list: zurl_qpack.FieldList = .empty;
    defer list.deinit(gpa);
    try list.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
    try list.append(gpa, try gpa.dupe(u8, "Content-Type"), try gpa.dupe(u8, "text/plain"), false);
    try testing.expectError(error.MalformedResponse, validateResponseFields(list));

    var injected: zurl_qpack.FieldList = .empty;
    defer injected.deinit(gpa);
    try injected.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
    try injected.append(
        gpa,
        try gpa.dupe(u8, "x-note"),
        try gpa.dupe(u8, "ok\r\nset-cookie: session=attacker"),
        false,
    );
    try testing.expectError(error.MalformedResponse, validateResponseFields(injected));

    var framing: zurl_qpack.FieldList = .empty;
    defer framing.deinit(gpa);
    try framing.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
    try framing.append(gpa, try gpa.dupe(u8, "transfer-encoding"), try gpa.dupe(u8, "chunked"), false);
    try testing.expectError(error.MalformedResponse, validateResponseFields(framing));

    var good: zurl_qpack.FieldList = .empty;
    defer good.deinit(gpa);
    try good.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
    try good.append(gpa, try gpa.dupe(u8, "content-type"), try gpa.dupe(u8, "text/plain"), false);
    try validateResponseFields(good);
    try testing.expectEqual(@as(u16, 200), try readStatus(good));
}

test "a response field name holding CR, LF, NUL, a space, or a colon is a malformed response" {
    // The other half of the forgery, and the same defect `h2` carried.
    // QPACK carries a name as an opaque octet string, so a peer writes any
    // byte it likes into one, and `recordHead` writes `name: value\r\n`
    // into the `-D` block. A name of `x-a\r\nset-cookie: injected=1`
    // reached a user's file as a `set-cookie` line the server never sent,
    // and `Response.headerIn` read it back as a real header.
    //
    // RFC 9114 section 4.2 makes a name a `tchar` run, which is the rule
    // `engine.headerNameIsToken` holds for all three engines.
    const gpa = testing.allocator;

    const forged = [_][]const u8{
        "x-a\r\nset-cookie: injected=1",
        "x-a\nset-cookie: injected=1",
        "x-a\rset-cookie: injected=1",
        "x-a b",
        "x-a:b",
        "x-a\x7f",
        "x-a\xc3\xa9",
        "x-a(b)",
    };
    for (forged) |name| {
        var list: zurl_qpack.FieldList = .empty;
        defer list.deinit(gpa);
        try list.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
        try list.append(gpa, try gpa.dupe(u8, name), try gpa.dupe(u8, "ok"), false);
        try testing.expectError(error.MalformedResponse, validateResponseFields(list));
    }

    // **A NUL keeps a name of its own.** It is a control octet, so
    // `engine.headerValueHasControl` and `engine.headerNameIsToken` would
    // both answer it as `MalformedResponse` and exit 56. curl 8.21.0
    // answers the same response with `Nul byte in header` and exit 8, so
    // `refuseNulInFields` runs first. Both halves of a field are read.
    // See `engine.refuseNulInHead`.
    for ([_][]const u8{ "x-a\x00b", "x-ok" }, [_][]const u8{ "ok", "a\x00b" }) |name, value| {
        var list: zurl_qpack.FieldList = .empty;
        defer list.deinit(gpa);
        try list.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
        try list.append(gpa, try gpa.dupe(u8, name), try gpa.dupe(u8, value), false);
        try testing.expectError(error.WeirdServerReply, validateResponseFields(list));
    }

    // **And every legal `tchar` still passes.** A rule that refused one of
    // these would refuse a server that works today.
    {
        var list: zurl_qpack.FieldList = .empty;
        defer list.deinit(gpa);
        try list.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
        try list.append(gpa, try gpa.dupe(u8, "!#$%&'*+-.^_`|~"), try gpa.dupe(u8, "ok"), false);
        try list.append(gpa, try gpa.dupe(u8, "x-request-id-0123456789"), try gpa.dupe(u8, "ok"), false);
        try validateResponseFields(list);
    }
}

test "a pseudo header after an ordinary field is malformed, and so is one that is not :status" {
    const gpa = testing.allocator;
    var late: zurl_qpack.FieldList = .empty;
    defer late.deinit(gpa);
    try late.append(gpa, try gpa.dupe(u8, "content-type"), try gpa.dupe(u8, "text/plain"), false);
    try late.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
    try testing.expectError(error.MalformedResponse, validateResponseFields(late));

    var wrong: zurl_qpack.FieldList = .empty;
    defer wrong.deinit(gpa);
    try wrong.append(gpa, try gpa.dupe(u8, ":method"), try gpa.dupe(u8, "GET"), false);
    try testing.expectError(error.MalformedResponse, validateResponseFields(wrong));
}

test "a status that is not three digits is a malformed response" {
    const gpa = testing.allocator;
    for ([_][]const u8{ "20", "2000", "20x", "", " 200" }) |text| {
        var list: zurl_qpack.FieldList = .empty;
        defer list.deinit(gpa);
        try list.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, text), false);
        try testing.expectError(error.MalformedResponse, readStatus(list));
    }
    var missing: zurl_qpack.FieldList = .empty;
    defer missing.deinit(gpa);
    try testing.expectError(error.MalformedResponse, readStatus(missing));
}

test "this engine asks the one rule, and keeps none of its own" {
    // **The defect a rule per engine produced.** `readContentEncoding`
    // here read an unknown token as `identity` and handed the caller
    // compressed octets at exit 0, while `h1` reported a read error for
    // the same head. Neither matched curl. The rule now lives in
    // `engine.contentEncoding` and all three engines ask it, so the
    // answers cannot differ by protocol again.
    const gpa = testing.allocator;

    // With no offer the field is ignored, whatever it names.
    for ([_][]const u8{ "gzip", "zstd", "br", "compress", "exotic" }) |coding| {
        var list: zurl_qpack.FieldList = .empty;
        defer list.deinit(gpa);
        try list.append(
            gpa,
            try gpa.dupe(u8, "content-encoding"),
            try gpa.dupe(u8, coding),
            false,
        );
        try testing.expectEqual(
            std.http.ContentEncoding.identity,
            try readContentEncoding(list, false),
        );
    }

    // With the offer, the three this build decodes come back by name and
    // the rest are refused.
    for ([_]struct { []const u8, ?std.http.ContentEncoding }{
        .{ "gzip", .gzip },
        .{ "deflate", .deflate },
        .{ "zstd", .zstd },
        .{ "identity", .identity },
        .{ "br", null },
        .{ "compress", null },
        .{ "gzip, br", null },
    }) |row| {
        const text, const want = row;
        var list: zurl_qpack.FieldList = .empty;
        defer list.deinit(gpa);
        try list.append(
            gpa,
            try gpa.dupe(u8, "content-encoding"),
            try gpa.dupe(u8, text),
            false,
        );
        if (want) |coding| {
            try testing.expectEqual(coding, try readContentEncoding(list, true));
        } else {
            try testing.expectError(
                error.BadContentEncoding,
                readContentEncoding(list, true),
            );
        }
    }

    // No field at all, and a field the peer left empty, are both the plain
    // body and not a refusal.
    var missing: zurl_qpack.FieldList = .empty;
    defer missing.deinit(gpa);
    try testing.expectEqual(
        std.http.ContentEncoding.identity,
        try readContentEncoding(missing, true),
    );

    var blank: zurl_qpack.FieldList = .empty;
    defer blank.deinit(gpa);
    try blank.append(gpa, try gpa.dupe(u8, "content-encoding"), try gpa.dupe(u8, ""), false);
    try testing.expectEqual(
        std.http.ContentEncoding.identity,
        try readContentEncoding(blank, true),
    );
}

test "the ALPN name is the one RFC 9114 registers and the one zurl-net offers" {
    const zurl_net = @import("zurl-net");
    try testing.expectEqualStrings("h3", alpn_name);
    try testing.expectEqual(@as(usize, 1), zurl_net.Connection.alpn_http_3.len);
    try testing.expectEqualStrings(alpn_name, zurl_net.Connection.alpn_http_3[0]);

    // And no TLS offer over TCP names it: a stream socket cannot carry
    // HTTP/3, so a peer that chose it there would leave the connection
    // with no protocol either side can use.
    for ([_][]const []const u8{
        zurl_net.Connection.alpn_default,
        zurl_net.Connection.alpn_http_1_1,
        zurl_net.Connection.alpn_http_2,
    }) |list| {
        for (list) |name| try testing.expect(!std.mem.eql(u8, name, alpn_name));
    }
}

test "content-length is a bound over HTTP/3 too, and a longer body fails" {
    // The same rule `h2.Exchange.countBody` keeps, asked here through
    // `h2.bodyWithinContentLength`. RFC 9114 section 4.1.2 makes a body
    // whose length disagrees with `content-length` malformed. This engine
    // counted only upward, so a body that came out long met nothing.
    const gpa = testing.allocator;

    var server: h3_test_server = undefined;
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "2" },
        },
        .body = "abcdefgh",
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(gpa, server.port());
    defer client.deinit();

    var exchange = try client.send(.{});
    defer exchange.close();
    try testing.expectEqual(@as(?u64, 2), exchange.head().content_length);

    var buffer: [4096]u8 = undefined;
    const reader = exchange.bodyReader(&buffer);
    try testing.expectError(error.ReadFailed, reader.allocRemaining(gpa, .unlimited));
    // Not `PartialFile`: the body ran long, not short. See
    // `Exchange.countBody`.
    try exchange.check();
}

test "a body that exactly fills its content-length over HTTP/3 still passes" {
    const gpa = testing.allocator;

    var server: h3_test_server = undefined;
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "8" },
        },
        .body = "abcdefgh",
        .data_chunk = 2,
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(gpa, server.port());
    defer client.deinit();

    var exchange = try client.send(.{});
    defer exchange.close();
    const body = try readBody(exchange);
    defer gpa.free(body);
    try testing.expectEqualStrings("abcdefgh", body);
    try exchange.check();
}

test "the content-length field rules are the ones h2 and h1 keep" {
    // **One function, three engines.** `h2.contentLengthField` is the rule,
    // and this engine names it rather than keep a copy. A second copy is
    // the whole defect: this engine read a value that is not a number as
    // no length at all, and `h1` refused the same head.
    const gpa = testing.allocator;

    var differ: zurl_qpack.FieldList = .empty;
    defer differ.deinit(gpa);
    try differ.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
    try differ.append(gpa, try gpa.dupe(u8, "content-length"), try gpa.dupe(u8, "2"), false);
    try differ.append(gpa, try gpa.dupe(u8, "content-length"), try gpa.dupe(u8, "8"), false);
    try testing.expectError(error.MalformedResponse, readContentLength(differ));

    var agree: zurl_qpack.FieldList = .empty;
    defer agree.deinit(gpa);
    try agree.append(gpa, try gpa.dupe(u8, "content-length"), try gpa.dupe(u8, "2"), false);
    try agree.append(gpa, try gpa.dupe(u8, "content-length"), try gpa.dupe(u8, "2"), false);
    try testing.expectEqual(@as(?u64, 2), try readContentLength(agree));

    for ([_][]const u8{ "banana", "", "+2", "-1", "0x10" }) |text| {
        var bad: zurl_qpack.FieldList = .empty;
        defer bad.deinit(gpa);
        try bad.append(gpa, try gpa.dupe(u8, "content-length"), try gpa.dupe(u8, text), false);
        try testing.expectError(error.MalformedResponse, readContentLength(bad));
    }

    var none: zurl_qpack.FieldList = .empty;
    defer none.deinit(gpa);
    try testing.expectEqual(@as(?u64, null), try readContentLength(none));
}

test "two content-length fields that disagree end an HTTP/3 transfer" {
    var server: h3_test_server = undefined;
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "2" },
            .{ .name = "content-length", .value = "8" },
        },
        .body = "ab",
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    try testing.expectError(error.MalformedResponse, client.sendRaw(.{}));
}

test "a repeated :status is a malformed response over HTTP/3" {
    // RFC 9114 section 4.3 gives a pseudo header one appearance, and
    // `h2.validateResponseFields` refuses a repeat for the same reason.
    const gpa = testing.allocator;

    var twice: zurl_qpack.FieldList = .empty;
    defer twice.deinit(gpa);
    try twice.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
    try twice.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
    try twice.append(gpa, try gpa.dupe(u8, "x-thing"), try gpa.dupe(u8, "ok"), false);
    try testing.expectError(error.MalformedResponse, validateResponseFields(twice));

    var once: zurl_qpack.FieldList = .empty;
    defer once.deinit(gpa);
    try once.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
    try validateResponseFields(once);

    // A trailer section carries no pseudo header at all and passes.
    var trailer: zurl_qpack.FieldList = .empty;
    defer trailer.deinit(gpa);
    try trailer.append(gpa, try gpa.dupe(u8, "x-checksum"), try gpa.dupe(u8, "abc"), false);
    try validateResponseFields(trailer);
}

test "a repeated :status on the wire never reaches an HTTP/3 caller" {
    var server: h3_test_server = undefined;
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = ":status", .value = "200" },
        },
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    try testing.expectError(error.MalformedResponse, client.sendRaw(.{}));
}

test "a peer that ends its control stream is refused on the path a transfer takes" {
    // **RFC 9114 section 6.2.1: the control stream lives for the whole
    // connection**, so a `FIN` on it is H3_CLOSED_CRITICAL_STREAM. The
    // rule was written in `Session.service` and not in the loop that runs
    // for the whole of a request and a response, and `service` runs only
    // from `writeAll` when a send window is full, which a small request
    // never fills. So the rule was on the record and never reached. One
    // loop now serves both. See `Session.serviceExcept`.
    var server: h3_test_server = undefined;
    try server.startWith(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "2" },
        },
        .body = "ab",
    }}, .{ .close_control_stream = true });
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    // `sendRaw` and not `send`, because `openError` puts nearly every
    // fault under `ReadError` and this test is about which fault it is.
    try testing.expectError(error.ClosedCriticalStream, client.sendRaw(.{}));
}

test "a fault marks the session and sends the code RFC 9114 gives it" {
    // `broken` was declared, read by `usable`, and set by nothing, so a
    // session that met a fatal fault still called itself usable.
    // `zurl_h3.Connection.errorCode` computed the right code and had no
    // caller, so the peer saw an idle timeout instead of a protocol error.
    // `Session.abort` is where the two meet.
    // The peer ends its control stream, which is H3_CLOSED_CRITICAL_STREAM
    // and lands inside the request rather than while the connection comes
    // up, so the session is still there to be asked about afterwards.
    var server: h3_test_server = undefined;
    try server.startWith(&.{.{
        .fields = &.{.{ .name = ":status", .value = "200" }},
    }}, .{ .close_control_stream = true });
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    // `send` and not `sendRaw`: `open` is the door the mark is set at, and
    // `sendRaw` calls `openInner` under it.
    try testing.expectError(error.ReadError, client.send(.{}));
    try testing.expect(client.session.broken);
    try testing.expect(!client.session.usable());
    // A `CONNECTION_CLOSE` went out, so the peer reads a protocol error
    // rather than waiting for an idle timeout.
    try testing.expect(client.session.conn.close_sent);
}

test "every fault RFC 9114 names maps to its own code, and the rest to none" {
    // The mapping itself is `zurl_h3.Connection.errorCode`. This holds the
    // one decision that belongs to the engine: which of its faults the RFC
    // gives the peer a number for.
    try testing.expectEqual(
        @as(?zurl_h3.ErrorCode, .closed_critical_stream),
        connectionErrorCode(error.ClosedCriticalStream),
    );
    try testing.expectEqual(
        @as(?zurl_h3.ErrorCode, .missing_settings),
        connectionErrorCode(error.MissingSettings),
    );
    try testing.expectEqual(
        @as(?zurl_h3.ErrorCode, .frame_unexpected),
        connectionErrorCode(error.FrameUnexpected),
    );
    try testing.expectEqual(
        @as(?zurl_h3.ErrorCode, .excessive_load),
        connectionErrorCode(error.ExcessiveLoad),
    );
    // RFC 9114 section 4.1.2 gives a malformed message its own code, and
    // `zurl_h3.Connection.Error` has no member for it because nothing in
    // that package reads a message.
    try testing.expectEqual(
        @as(?zurl_h3.ErrorCode, .message_error),
        connectionErrorCode(error.MalformedResponse),
    );
    // A bound of this build's own, a write that failed, and an allocation
    // that did not are real faults that the RFC gives the peer no number
    // for. A number invented here would name a fault the peer did not
    // commit.
    for ([_]Fault{
        error.OutOfMemory,
        error.WriteFailed,
        error.PeerStalled,
        error.ResponseHeadTooLarge,
        error.BadContentEncoding,
        error.RequestHeadTooLarge,
    }) |quiet| {
        try testing.expectEqual(@as(?zurl_h3.ErrorCode, null), connectionErrorCode(quiet));
    }
}
