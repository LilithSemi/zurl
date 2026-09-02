//! The HTTP/2 half of the engine, RFC 9113.
//!
//! `h1.zig` owns the policy of a transfer: it validates the headers, it
//! walks the redirect chain, it keeps every secret inside the origin the
//! url names, it asks the cookie jar once for each hop, and it owns the
//! connection pool. All of that is protocol independent, and this file
//! repeats none of it.
//!
//! This file owns the wire. It takes a connection whose ALPN answer was
//! `h2`, it writes the connection preface and the first `SETTINGS` frame,
//! it sends one request as one stream, and it reads the answer back. It
//! reports the answer through `engine.Exchange`, which is the same seam
//! `h1` reports through, so the front package sees one shape.
//!
//! **The protocol is chosen after the handshake, not before it.** A client
//! learns which protocol it speaks only when the peer answers the ALPN
//! offer, and only the code that owns the dial can read that answer. So
//! `h1.sendOn` reads `zurl_net.Connection.alpnProtocol` and calls `open`
//! here for an `h2` answer. A peer that answers `http/1.1`, and a peer
//! that answers nothing at all, take the HTTP/1.1 path they always took.
//!
//! **One request at a time on one connection.** RFC 9113 lets a client run
//! many streams at once, and this build runs one. That is legal and it
//! interoperates: the stream identifier goes up by two for each request,
//! and the connection serves a second request when the first one finished.
//! A client that runs one transfer at a time, which `zurl.Client` does,
//! gains nothing from more.
//!
//! **This file imports no `h1`.** `h1` calls in, and nothing calls back
//! out except through the two small seams below, `Peer` and `HeadLog`. A
//! test can fill both in a few lines, which is what lets the HTTP/2 tests
//! run over a plain loopback socket and never over TLS.

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_net = @import("zurl-net");
const zurl_h2 = @import("zurl-h2");
const zurl_hpack = @import("zurl-hpack");
const engine = @import("engine.zig");
const testing = std.testing;

/// The ALPN protocol name of HTTP/2. RFC 9113 section 3.1.
pub const alpn_name = "h2";

/// Whether the peer chose HTTP/2 on `c`.
///
/// A plain connection has no ALPN and answers false, so a cleartext url
/// keeps the HTTP/1.1 path. `zurl_net.Connection` refuses any protocol
/// name outside the list that was offered, so this comparison needs no
/// second check of its own.
pub fn negotiated(c: *const zurl_net.Connection) bool {
    const chosen = c.alpnProtocol() orelse return false;
    return std.mem.eql(u8, chosen, alpn_name);
}

/// The flow-control window this side gives the peer on the connection, in
/// octets. RFC 9113 section 6.9.
///
/// The RFC default is 65535, which bounds a download to one window for
/// each round trip. This side advertises a larger one and gives the room
/// back as the octets arrive, so a fast link is not held to the round-trip
/// time.
///
/// **This is also the bound on what the session buffers.** A `DATA` frame
/// for the stream whose owner is reading goes straight to that owner and
/// its room goes back at once. A frame for another open stream is copied
/// into that stream's inbox, and its room goes back only when that
/// stream's own owner takes it. So the octets held inside this process
/// never pass this number, and the flow-control window is what holds them
/// down rather than a bound written beside it. See `Stream.inbox` and
/// `Session.creditReceive`.
pub const window_len: u31 = 1024 * 1024;

/// The flow-control window this side gives the peer on each stream, in
/// octets. RFC 9113 section 6.9.2, sent as `SETTINGS_INITIAL_WINDOW_SIZE`.
///
/// **Smaller than the connection window, because several streams share
/// the connection.** One stream that stopped being read may hold at most
/// this many octets in its inbox, so a full table of stalled streams
/// cannot take more room than the connection window allows anyway. A
/// single download is not slowed by the number: the room goes back at
/// half the window as the octets arrive, so the peer keeps this much in
/// flight the whole time.
pub const stream_window_len: u31 = 256 * 1024;

/// How many octets may arrive on the connection before this side gives the
/// room back with a `WINDOW_UPDATE`.
///
/// Half the window. A smaller number spends more frames on updates, and a
/// larger one lets the peer run out of room before the update reaches it.
const window_update_at: u32 = window_len / 2;

/// The same threshold for one stream. Half of `stream_window_len`.
const stream_window_update_at: u32 = stream_window_len / 2;

/// How many streams one connection carries at once, whatever the peer
/// allows.
///
/// **This side's own ceiling, and the peer's number is read on top of
/// it.** `SETTINGS_MAX_CONCURRENT_STREAMS` is the peer's answer and it may
/// be larger or smaller; `Session.concurrentMax` takes the smaller of the
/// two, so a peer that names 1000 never gets more than this and a peer
/// that names 2 never gets more than 2.
///
/// The table is a fixed array of this length on the `Session`, so the
/// number is a memory cost paid once for each connection and never for
/// each request.
pub const streams_max: usize = 32;

/// The value this side sends as `SETTINGS_MAX_CONCURRENT_STREAMS`.
///
/// The peer opens no stream here: `SETTINGS_ENABLE_PUSH` is 0, so the only
/// streams a peer could open are pushed ones and there are none. The
/// number therefore describes nothing the peer may do, and RFC 9113
/// section 6.5.2 says a sender that has no limit should leave the setting
/// out. curl 8.21.0 sends 100 anyway, measured on the wire; this side
/// leaves it out, which is what the RFC asks for and what the peer already
/// knows from `ENABLE_PUSH`.
const advertised_concurrent_max: ?u32 = null;

/// The largest frame payload this side accepts, in octets.
///
/// The RFC 9113 section 6.5.2 default, and the size of the one buffer
/// `zurl_h2.FrameReader` allocates. A frame above it is refused on its
/// 9-octet header, before one octet of payload is read.
pub const frame_len_max: u24 = 16384;

/// How large a decoded response header list may be, in octets, counted the
/// way RFC 9113 section 6.5.2 counts it: the name, the value, and 32 bytes
/// of overhead for each field.
///
/// **This is the same number `h1.head_len_max` keeps**, so a user meets one
/// bound on a response head whichever protocol answered. The two are not
/// the same measurement, and they cannot be: HTTP/1.1 counts the octets of
/// the head on the wire, and HTTP/2 counts the header list after HPACK
/// decompressed it. A block of a few hundred octets can decode into a list
/// far larger than itself, which is why the bound belongs after the decode
/// and not before it.
///
/// This side sends the number as `SETTINGS_MAX_HEADER_LIST_SIZE`, so a peer
/// is told the bound rather than left to find it.
///
/// A list past this is `error.ResponseHeadTooLarge`, which is the name
/// `h1` reports for its own head bound and is exit 56.
pub const header_list_len_max: usize = 300 * 1024;

/// The shortest header field this file counts on when it sizes
/// `header_fields_max`. Sixteen octets leaves generous room under an
/// ordinary field, whose name, value, and overhead come to far more.
const header_field_len_min: usize = 16;

/// How many fields one response header list may carry.
///
/// Derived from `header_list_len_max` the same way `h1.head_fields_max` is
/// derived from `h1.head_len_max`, so the two engines refuse a head of
/// nothing but tiny fields at the same count. The octet bound bites first
/// for every ordinary head, and this one bounds the work of a walk over the
/// list.
pub const header_fields_max: usize = header_list_len_max / header_field_len_min;

/// The HPACK dynamic table this side lets the peer fill, in octets. The RFC
/// 7541 default, and the number this side sends as
/// `SETTINGS_HEADER_TABLE_SIZE`.
const header_table_len: u32 = 4096;

/// How many octets of the request body go into one `DATA` frame.
///
/// The engine holds one of these on the stack of the call that sends the
/// body, so a body of any size costs this much memory and no more. That is
/// what lets `-T` stream a file larger than this machine's memory.
const body_chunk_len: usize = 16 * 1024;

/// Scratch space for the flate sliding window, which is what `gzip` and
/// `deflate` decode through. The same buffer `h1` holds, for the same
/// reason.
const decompress_buffer_len = std.compress.flate.max_window_len;

/// The window this engine gives a zstd stream. 8 MiB, the ceiling RFC 8878
/// section 3.1.1.1.2 sets for a zstd stream that travels as a content
/// coding, and the value `std.http.Decompress` builds its decoder with.
const zstd_window_len = std.compress.zstd.default_window_len;

/// Scratch space for one zstd stream: the window, plus room for one whole
/// block. The same size `h1` takes, and taken the same way, allocated where
/// the head really said zstd and freed with the exchange.
const zstd_buffer_len = zstd_window_len + std.compress.zstd.block_size_max;

/// Scratch space between the frame reader and any content decoding.
const transfer_buffer_len = 8192;

/// The `accept-encoding` value this engine sends, and the whole set of
/// content codings it reads. The same value `h1` advertises, so a peer
/// answers both engines with the same body. See `h1.accept_encoding_value`
/// for the order, and for why `br` is not in it.
///
/// Written out here and not imported, because `h1.zig` imports this file
/// and the layering runs one way. The test *"the accept-encoding value
/// matches the one h1 sends"* holds the two together.
pub const accept_encoding_value = "deflate, gzip, zstd";

/// How many frames that carry no progress one transfer reads before it
/// stops waiting.
///
/// A peer that answers a request with `PING`, `SETTINGS`, and unknown
/// frames forever would otherwise hold the transfer open with nothing to
/// read.
///
/// **The budget covers the whole transfer and never one call.** The count
/// lives in `Exchange.idle_frames`, and it only grows. A per-call counter
/// let a peer alternate 1023 frames that carry nothing with one body octet,
/// which reached the bound never. An ordinary connection reads a handful of
/// such frames over a whole response, so this is far above what any peer
/// worth talking to sends.
///
/// **With several streams open, the budget counts a frame that helped
/// nobody.** A frame for another stream on the same connection is not idle:
/// it moved that transfer along, and the waiting transfer read it only
/// because one task reads the connection for all of them. Charging it to
/// the waiter would end a healthy transfer on a busy connection after 1024
/// frames of someone else's body. `Session.progress` counts every frame
/// that advanced any stream, and a waiter that sees the count move puts its
/// own budget back to zero. So the bound still stops a peer that answers
/// with `PING` forever, and no longer stops a peer that is answering.
///
/// **What the peer buys with a frame this bound counts.** One turn of the
/// read loop. The frame must be legal, it costs the peer at least nine
/// octets on the wire, and it leaves this side with no allocation and no
/// state. At 1024 turns a transfer stops with `PeerStalled`, so a hostile
/// peer holds one `zurl` process for 1024 frames and no longer.
///
/// **What an honest peer's worst case is.** An answer on an idle
/// connection reads two or three such frames: the peer's `SETTINGS`, its
/// acknowledgement of this side's own, and one `WINDOW_UPDATE`. A long
/// upload adds one `WINDOW_UPDATE` for each window the peer opens, and a
/// keep-alive `PING` every few seconds adds one each. A response with a
/// trailer section adds one. Nothing measured comes near 1024, and any
/// peer that does is answering nobody. See `Session.progress` for the rule
/// that decides which frames this budget counts.
const idle_frames_max: usize = 1024;

/// How many informational (1xx) response heads this side reads before it
/// gives up on a peer.
///
/// The same bound `h1.continue_heads_max` keeps for a `100 Continue` over
/// HTTP/1.1, and for the same reason: RFC 9110 section 15.2 tells a client
/// to read past an informational head and wait for the real status, and a
/// loop with no bound hangs on a peer that never sends one.
const informational_heads_max: usize = 8;

/// The largest status code text a peer may send in `:status`. RFC 9113
/// section 8.3.2 makes it exactly three digits.
/// `engine.status_text_len` is the number, because `h3` writes the same
/// status line from the same width.
const status_text_len: usize = engine.status_text_len;

/// Where an exchange hands its connection back when it closes.
///
/// The engine that owns the connection pool is `h1`, and this file must
/// not know that type. So the owner passes two opaque handles and one
/// function, and `Exchange.close` calls it exactly once.
///
/// `keep` is what `Exchange.reusable` decided. A false answer must close
/// the connection: an HTTP/2 stream that did not finish leaves octets the
/// next request would read.
pub const Peer = struct {
    /// The pool, or whatever else owns the connection.
    ctx: *anyopaque,
    /// The connection inside that owner.
    handle: *anyopaque,
    release: *const fn (ctx: *anyopaque, handle: *anyopaque, keep: bool) void,
};

/// Where an exchange records the response head it read, and where it reads
/// the whole chain's heads back.
///
/// The log belongs to the engine and not to one exchange, because a
/// redirect chain closes each hop before it opens the next one, and only
/// something that outlives every hop can hold what every hop said. `h1`
/// owns that log already, and this seam is how an HTTP/2 hop writes into
/// the same one.
pub const HeadLog = struct {
    ctx: *anyopaque,
    /// Records one response head block, byte for byte as `-D` writes it.
    record: *const fn (ctx: *anyopaque, head: []const u8) std.mem.Allocator.Error!void,
    /// What the log holds now.
    kept: *const fn (ctx: *anyopaque) Kept,

    /// The blocks a log holds, and whether a bound dropped them.
    pub const Kept = struct {
        /// Every block of the chain, in order. Null when the log holds
        /// none.
        all: ?[]const u8 = null,
        /// The last block, which is the head of the response this exchange
        /// describes. A subslice of `all`.
        final: ?[]const u8 = null,
        /// Whether a bound dropped the blocks. See
        /// `engine.Head.headers_oversize`.
        dropped: bool = false,
    };
};

/// Every fault this file can meet before it reaches an `engine.OpenError`.
///
/// The peer's octets are untrusted, so every one of these is a named error
/// and none is an assert. `openError` and `bodyFault` are the two places
/// that turn one of these into a name the seam knows.
pub const Fault = zurl_h2.Error || zurl_hpack.Decoder.Error || std.Io.Reader.Error ||
    error{
        /// A write to the peer did not succeed.
        WriteFailed,
        /// The peer's answer is not a legal HTTP/2 response: no `:status`,
        /// a `:status` that is not three digits, a field name that carries
        /// an upper-case letter, a connection-specific field, a pseudo
        /// header after an ordinary one, or `DATA` before any head.
        MalformedResponse,
        /// The peer answered in a content coding this request never
        /// offered.
        ///
        /// Kept apart from `MalformedResponse` because the head is legal
        /// HTTP/2 and nothing on the wire failed. The one bad field is
        /// `content-encoding`, and the user who reads this looks at the
        /// server. See `engine.OpenError.BadContentEncoding`.
        BadContentEncoding,
        /// The peer refused this stream with `RST_STREAM`.
        StreamReset,
        /// The peer ended the connection with `GOAWAY` before it answered
        /// this request.
        ConnectionEnded,
        /// The peer sent a `PUSH_PROMISE`. This client sends
        /// `SETTINGS_ENABLE_PUSH` of 0, so a promise is a connection error
        /// of type `PROTOCOL_ERROR`. RFC 9113 section 8.4.
        PushRefused,
        /// The peer sent a frame on a stream that has never been open on
        /// this connection. RFC 9113 section 5.1 makes every frame but
        /// `PRIORITY` a connection error of type `PROTOCOL_ERROR` in that
        /// state. See `Session.idleStream`.
        IdleStream,
        /// The peer sent more frames that carried no progress than
        /// `idle_frames_max` allows.
        PeerStalled,
        /// The peer sent more informational heads than
        /// `informational_heads_max` allows.
        TooManyInformationalHeads,
        /// `engine.Body.read` reported a fault.
        BodySourceFailed,
        /// `engine.Body.read` produced a different number of octets than
        /// `engine.Body.len` announced.
        BodyLengthMismatch,
        /// The connection already carries as many streams as it may. See
        /// `Session.hasRoom` and `streams_max`.
        ///
        /// A caller that reads `Session.hasRoom` first never meets this,
        /// and `h1` does read it: a connection with no free stream is left
        /// in the pool and a new one is dialled. It is here so a caller
        /// that did not is told, rather than sending a stream the peer will
        /// refuse.
        TooManyStreams,
        /// The peer sent no frame for as long as this engine waits on one
        /// read of the connection.
        ///
        /// **A count of idle frames is not a bound on a peer that sends
        /// nothing at all.** `idle_frames_max` bounds a peer that keeps
        /// sending frames which move nothing, and it never runs down for a
        /// peer that accepts the connection, answers a head, and then goes
        /// quiet: no frame arrives, so no unit of the budget is spent and
        /// the read waits for ever. `Session.read_timeout` is the bound
        /// that covers it. See `Session.read`.
        OperationTimedOut,
        /// Something outside this transfer stopped the read.
        ///
        /// `-m`/`--max-time` is what does it today. The caller decides
        /// what to report, the same way `h3.openError` treats it.
        Canceled,
        /// The peer's response head carries a NUL octet.
        ///
        /// Kept apart from `MalformedResponse` because HPACK carried the
        /// octets without complaint and the field list decoded: the fault
        /// is what one field holds. See `engine.refuseNulInHead`.
        WeirdServerReply,
    };

/// The `engine.OpenError` that `fault` means to a caller.
///
/// Every fault of the frame layer, of HPACK, and of this file is a peer
/// that did not answer HTTP/2, which is `ReadError` and **exit 26**,
/// `CURLE_READ_ERROR`, per the table in `zurl_core.errors`. curl answers
/// several of these with 56, `CURLE_RECV_ERROR`, and this build has no
/// name on 56 today, so the two differ in the code and agree in the
/// refusal.
///
/// The bounds on a response head are the exception. Those keep the name
/// `h1` gives its own head bound, so a user reads one answer whichever
/// protocol replied.
fn openError(fault: Fault) engine.OpenError {
    return switch (fault) {
        error.OutOfMemory => error.OutOfMemory,
        error.WriteFailed, error.BodyLengthMismatch => error.WriteError,
        // The peer went quiet inside one read of the connection. It keeps
        // its own name all the way to the exit code, which is 28, the
        // answer `h1` gives the same peer.
        error.OperationTimedOut => error.OperationTimedOut,
        // The caller stopped this transfer, so the caller decides what to
        // report. `-m`/`--max-time` is the one that does it today.
        error.Canceled => error.Canceled,
        // A response head that carries a NUL reaches no consumer of a
        // header value. See `engine.refuseNulInHead`.
        error.WeirdServerReply => error.WeirdServerReply,
        // Nothing on the wire failed, so this keeps its own name all the
        // way to the exit code.
        error.BadContentEncoding => error.BadContentEncoding,
        // The bounds on a response head. `HeaderListTooLarge` and
        // `TooManyHeaderFields` are the decoded list; `HeaderBlockTooLarge`
        // and `ContinuationFlood` are the octets on the wire that carried
        // it. All four say the same thing to a user: the head is larger
        // than this engine reads.
        error.HeaderListTooLarge,
        error.TooManyHeaderFields,
        error.HeaderBlockTooLarge,
        error.ContinuationFlood,
        => error.ResponseHeadTooLarge,
        else => error.ReadError,
    };
}

/// One flow-control window and the state of one request stream.
const Stream = struct {
    id: u31,
    /// The room this side may still fill on this stream. RFC 9113 section
    /// 6.9.
    send_room: zurl_h2.Window,
    /// Octets that arrived on this stream and whose room has not been
    /// given back yet.
    recv_owed: u32 = 0,
    /// Whether the response head block is whole and decoded.
    head_ready: bool = false,
    /// Whether the peer ended its side of the stream.
    ended: bool = false,
    /// Whether this side ended its side.
    sent_end: bool = false,
    /// The code the peer reset this stream with, or null.
    reset: ?zurl_h2.ErrorCode = null,
    /// How many informational heads arrived before the answer.
    informational: usize = 0,
    /// Whether a trailer section arrived. See `trailer_fields`.
    trailers: bool = false,
    /// Whether the peer answered any frame on this stream.
    ///
    /// **This is what stops a served request going out twice.** A frame on
    /// stream 0, such as a `SETTINGS` or a `PING`, says nothing about the
    /// request, so only a frame on this stream sets it.
    answered: bool = false,
    /// The decoded response head, owned. `engine.Head.location` and
    /// `engine.Head.www_authenticate` point into it, so it lives until
    /// `Exchange.close`.
    fields: ?zurl_hpack.FieldList = null,
    /// The decoded trailer section, owned, or null when the peer sent
    /// none.
    ///
    /// RFC 9113 section 8.1 allows a header block after the body. The
    /// fields are kept and not dropped, because `curl -D` writes them after
    /// the head block. Measured against curl 8.21.0. See `renderTrailers`.
    trailer_fields: ?zurl_hpack.FieldList = null,
    /// Body octets that arrived while another stream's owner was reading
    /// the connection.
    ///
    /// **The flow-control window is what bounds this.** The room these
    /// octets took goes back only when this stream's own owner takes them
    /// out, so a stream nobody reads holds at most one stream window, and
    /// every inbox on one connection together holds at most one connection
    /// window. See `Session.creditReceive`.
    ///
    /// `inbox_at` is how far the owner has read. The octets before it are
    /// spent and their room is already back.
    inbox: std.ArrayList(u8) = .empty,
    inbox_at: usize = 0,
    /// The octets this stream's owner took out of `inbox` and has not
    /// finished handing to its caller. Shared sessions only.
    ///
    /// **A reader that appends to a list an owner is reading from can move
    /// that list.** `inbox` grows, and a growth reallocates, so a slice of
    /// it that an owner already handed out would point at freed memory the
    /// moment another task read one more `DATA` frame. So an owner of a
    /// shared session does not read out of `inbox` at all: it swaps the
    /// whole list into this field under the session lock, and the reader
    /// then appends to the empty list that came back. The swap moves two
    /// pointers and copies no octet, and the two buffers are reused for
    /// the whole life of the stream.
    ///
    /// **The room these octets took is still owed to the peer.** It goes
    /// back at the next swap, through `Session.creditTaken`, and at
    /// `Session.forget` for a stream that closed with octets still here.
    taken: std.ArrayList(u8) = .empty,
    /// Whether `Session.streams` holds the address of this stream.
    ///
    /// False before `Session.adopt` and after `Session.forget`. A frame
    /// that names a stream which is not live is applied to the connection
    /// and to nothing else.
    live: bool = false,

    /// The octets an owner has not taken out of the inbox yet.
    fn buffered(self: *const Stream) []const u8 {
        return self.inbox.items[self.inbox_at..];
    }

    fn deinit(self: *Stream, gpa: std.mem.Allocator) void {
        self.inbox.deinit(gpa);
        self.taken.deinit(gpa);
        if (self.fields) |*fields| fields.deinit(gpa);
        if (self.trailer_fields) |*fields| fields.deinit(gpa);
        self.fields = null;
        self.trailer_fields = null;
    }
};

/// What one frame meant to the exchange that is waiting.
const Step = union(enum) {
    /// Nothing this exchange waits for. Read again.
    idle,
    /// No frame was read. Another task holds the read of a shared session,
    /// and it applied a frame while this one waited. The caller looks at
    /// its own stream again and then asks for another step.
    ///
    /// **It is not an idle frame.** Nothing was read here, so it spends no
    /// part of the `idle_frames_max` budget: that budget bounds a peer that
    /// sends frames which answer nobody, and a wait is not such a frame.
    waited,
    /// The response head block is whole.
    head,
    /// Body octets. They point into the frame reader's buffer and stay
    /// valid until the next read, so nothing may read another frame while
    /// a caller still holds them.
    ///
    /// **A shared session never answers with this.** The frame buffer is
    /// one buffer for the whole connection, and another task may read the
    /// next frame into it as soon as this one lets the lock go. So a shared
    /// session puts the waiter's own octets in its inbox, the way it puts
    /// every other stream's octets there, and answers `.idle`. See
    /// `Session.shared`.
    data: []const u8,
    /// The peer ended its side of the stream.
    ended,
};

/// One HTTP/2 connection: the frame reader, the HPACK tables, the two
/// flow-control windows, the open streams, and the stream counter.
///
/// **This belongs to the connection and not to one request.** The HPACK
/// dynamic table is built by every block that crossed the connection, and a
/// decoder that lost one block can never read another. The windows and the
/// stream counter are connection state in the same way. So the owner of the
/// connection owns this, and hands the same one to each request it sends.
///
/// **Several requests may be open on one session at once.** RFC 9113
/// section 5.1.1 gives each an odd identifier going up by two, and every
/// frame carries the identifier it belongs to. `streams` is where a frame
/// finds the request it is for. A request that is the only one open reads
/// exactly the frames it did before this table existed; a request that
/// shares the connection reads the others' frames too, applies them where
/// they belong, and carries on waiting for its own.
///
/// **Two tasks may drive a shared session, and only a shared one.**
/// `shared` is the whole switch. A session nobody shared takes no lock and
/// runs exactly the code it ran before this field existed, which is what
/// keeps one url on one connection as cheap as it was. A session that
/// `markShared` has been called on takes `lock` at every entry, and `step`
/// is where the two tasks meet:
///
/// - **One task reads at a time.** `reading` says whether a task is inside
///   the blocking frame read. A second task that wants a frame waits on
///   `wake` instead of reading, so two tasks never pull from one socket.
/// - **The lock is released while that read blocks, and only then.** Every
///   other line of this file runs under it. So a task that is waiting for
///   an answer does not stop a task that has a request ready to write, and
///   the request goes out while the answer is still on its way.
/// - **A write and a read may therefore run at once.** That is safe because
///   `zurl_net.Connection.shareBetweenTasks` gives the TLS session a write
///   lock: the one place the read path writes the state the write path uses
///   is a TLS 1.3 `key_update`, and that lock closes it.
///
/// What the lock protects is every field below, every write to the
/// connection, and the frame reader's one buffer. The buffer is why a
/// shared session never answers `Step.data`: see `Stream.taken`.
pub const Session = struct {
    gpa: std.mem.Allocator,
    /// The `std.Io` that `lock` and `wake` run on. It is the connection's
    /// own, so a session and the socket under it always agree.
    io: std.Io,
    /// Whether two tasks may drive this session. See the note above.
    ///
    /// False at `create`, and `markShared` is the one way it becomes true.
    /// It never goes back: a connection several tasks have seen cannot be
    /// made private again.
    shared: bool,
    /// Guards every field of this session, every write to the connection,
    /// and the frame reader's buffer. Untaken while `shared` is false.
    lock: std.Io.Mutex,
    /// Wakes the tasks that are waiting for the reader to apply a frame.
    wake: std.Io.Condition,
    /// Whether a task is inside the blocking frame read now.
    ///
    /// It is set and cleared under `lock`, and it stays true while the lock
    /// is not held, which is exactly what makes it the read's own lock.
    reading: bool,
    /// How many stream slots a caller has claimed and not opened yet.
    ///
    /// **A shared connection is chosen before the stream is opened.**
    /// `h1.Pool` reads `hasRoom` to decide whether one more request may
    /// join this connection, and `openInner` opens the stream some time
    /// after that. Without this counter two tasks could both read room for
    /// the last slot and one of them would then fail. `reserve` and
    /// `unreserve` are the pair, and `openInner` spends a reservation
    /// rather than check the room again.
    reserved: usize,
    /// Borrowed. It must outlive this session, which is what
    /// heap-allocating both of them gives.
    conn: *zurl_net.Connection,
    frames: zurl_h2.FrameReader,
    decoder: zurl_hpack.Decoder,
    /// What the peer asked for, starting at the RFC 9113 section 6.5.2
    /// defaults.
    peer_settings: zurl_h2.Settings,
    /// The room this side may still fill on the connection.
    send_room: zurl_h2.Window,
    /// Octets that arrived on the connection and whose room has not been
    /// given back yet.
    recv_owed: u32,
    /// The streams open on this connection, borrowed from their exchanges.
    ///
    /// A null slot is free. `adopt` fills one and `forget` empties it, and
    /// nothing else writes the array. The order says nothing: `find` walks
    /// the whole table, which is `streams_max` compares and is cheaper than
    /// keeping an index in order.
    streams: [streams_max]?*Stream,
    /// How many slots of `streams` are filled. `find` does not need it;
    /// `roomToSend` divides the connection window by it.
    open_count: usize,
    /// How many frames this connection has read that moved some stream
    /// along.
    ///
    /// A waiting exchange keeps the number it last saw. When it moves, that
    /// exchange puts its own idle budget back to zero, because the
    /// connection is answering somebody even though it is not answering
    /// this request yet. See `idle_frames_max`.
    ///
    /// **It is written in one place, `apply`, and from what `advanced`
    /// answers.** Each arm of the frame switch used to add to this itself,
    /// and every arm that did so refunded the idle budget it had just
    /// spent. A trailer `HEADERS` frame was the worst of them: RFC 9113
    /// section 8.1 puts no count on a trailer section, so a peer sent the
    /// nine octets `00 00 00 01 04 00 00 00 01` for ever, each one both
    /// spending one unit of the budget and giving it straight back, and
    /// the transfer never ended. A `WINDOW_UPDATE`, a repeated
    /// `RST_STREAM`, and a `DATA` frame of no octets were all the same
    /// shape. So no arm writes this now. `apply` reads `advanced` on both
    /// sides of the switch, and a frame that left every bound of every
    /// stream where it found them counts as idle, whatever its type and
    /// whether or not anybody has written that type yet.
    progress: u64,
    /// How many body octets this connection has handed to a live stream.
    ///
    /// One of the quantities `advanced` sums. It is octets and not frames
    /// because a `DATA` frame of zero octets is legal, RFC 9113 section
    /// 6.1, and moves no bound any reader keeps.
    body_octets: u64,
    /// The identifier the next request takes. Odd, and going up by two,
    /// per RFC 9113 section 5.1.1.
    next_stream_id: u31,
    /// The code the peer sent in a `GOAWAY`, or null.
    goaway_code: ?zurl_h2.ErrorCode,
    /// The last stream the peer said it would process. Read beside
    /// `goaway_code`.
    goaway_last_stream: u31,
    /// Whether this connection can serve no further request. Set by a
    /// `GOAWAY`, by any connection error, and by a stream counter that ran
    /// out.
    broken: bool,
    /// Whether something was written and not sent yet.
    dirty: bool,
    /// Where a header block is joined over `HEADERS` and every
    /// `CONTINUATION` behind it.
    block: std.ArrayList(u8),
    /// Which stream the open header block belongs to.
    block_stream_id: u31,
    /// Whether the frame that opened the block carried `END_STREAM`.
    block_end_stream: bool,
    /// Whether the first header block, which carries the dynamic table
    /// size update, has gone out.
    table_update_sent: bool,
    /// How long one read of this connection may wait with no frame
    /// arriving.
    ///
    /// **The bound is on the connection and not on one stream, and that is
    /// what makes it right for a multiplexed transport.** `read` is the
    /// one place this engine waits for the peer, and it comes back for a
    /// frame of any stream. So a connection that is answering somebody
    /// starts the clock again on every frame, and a deadline can only be
    /// reached when nothing at all arrived for any stream. A bound on one
    /// stream would fire while another stream on the same connection was
    /// still being served, which would close a connection that is working.
    ///
    /// **One connection carries one bound.** `Engine.read_timeout` is
    /// written from `--speed-limit` and `--speed-time`, which are
    /// properties of the run and not of a url, so every transfer of one
    /// `zurl.Client` asks for the same number. The session takes it at
    /// `create` and keeps it, because two tasks sharing one socket cannot
    /// give one read two deadlines.
    ///
    /// `.none` waits for as long as the peer likes. See
    /// `engine.default_read_timeout_s`.
    read_timeout: std.Io.Timeout,
    /// How many reads ran with no bound because this build could not watch
    /// a clock while the read was in flight.
    ///
    /// Saturating. `h1.Engine.read_bounds_dropped` says why a build with
    /// no concurrency counts this rather than refuse the read.
    read_bounds_dropped: usize,
    /// Whether a read of this connection reached its deadline.
    ///
    /// **Latched, and it never goes back.** The peer stopped writing at a
    /// place nothing here knows and the raced read was canceled part way
    /// through a frame, so whatever the peer writes next would arrive in
    /// front of the next request. `usableLocked` reads it, which keeps the
    /// connection out of `h1.Pool`.
    read_timed_out: bool,

    /// The settings this side advertises.
    ///
    /// `enable_push` of false is the refusal of server push, and it is the
    /// whole of it: a `PUSH_PROMISE` that arrives anyway is a connection
    /// error. RFC 9113 section 8.4.
    pub fn wanted() zurl_h2.Settings {
        return .{
            .header_table_size = header_table_len,
            .enable_push = false,
            .max_concurrent_streams = advertised_concurrent_max,
            .initial_window_size = stream_window_len,
            .max_frame_size = frame_len_max,
            .max_header_list_size = header_list_len_max,
        };
    }

    /// How many streams this side may have open at once.
    ///
    /// **The smaller of this side's table and the peer's own number.** RFC
    /// 9113 section 5.1.2 makes `SETTINGS_MAX_CONCURRENT_STREAMS` a bound
    /// the sender of the setting will enforce, and a client that opens one
    /// stream past it gets a `REFUSED_STREAM` or a connection error. A peer
    /// that names nothing is treated as unbounded, which the RFC says it is,
    /// and this side's own table is then the whole answer.
    pub fn concurrentMax(self: *const Session) usize {
        const mine: usize = streams_max;
        const theirs = self.peer_settings.max_concurrent_streams orelse return mine;
        return @min(mine, @as(usize, theirs));
    }

    /// Whether one more stream may open on this connection now.
    ///
    /// `usable` answers whether the connection is fit at all. This answers
    /// whether it has room at this moment, which changes as streams close.
    pub fn hasRoom(self: *Session) bool {
        self.acquire();
        defer self.release();
        return self.hasRoomLocked();
    }

    /// How many reads of this connection ran with no bound at all.
    ///
    /// Zero on every ordinary build. A build with no second unit of
    /// concurrency cannot watch a clock while a read is in flight, and
    /// refusing the read would leave such a build with no HTTP/2 at all,
    /// so the read runs unbounded and this counts it. Recovery is never
    /// silent, and this is the record of one that has no other trace.
    /// `h1.Engine.readBoundsDropped` answers the same question for the
    /// HTTP/1.1 engine.
    pub fn readBoundsDropped(self: *Session) usize {
        self.acquire();
        defer self.release();
        return self.read_bounds_dropped;
    }

    /// `hasRoom` for a caller that holds the lock already. A slot a caller
    /// has claimed through `reserve` is not free.
    fn hasRoomLocked(self: *const Session) bool {
        return self.open_count + self.reserved < self.concurrentMax();
    }

    /// Puts `stream` in the table, so a frame that names its identifier
    /// finds it.
    ///
    /// The caller has already checked `hasRoom`, which is this build's own
    /// job and so an assert. `forget` is the one way back out.
    fn adopt(self: *Session, stream: *Stream) void {
        std.debug.assert(!stream.live);
        std.debug.assert(self.open_count < streams_max);
        for (&self.streams) |*slot| {
            if (slot.* != null) continue;
            slot.* = stream;
            stream.live = true;
            self.open_count += 1;
            return;
        }
        // **`open_count` counted a free slot, so one exists, and this is
        // what the build does if it ever does not.** `adopt` and `forget`
        // are the only writers of `streams` and of `open_count`, and they
        // move the two together, so the assert above is the real proof.
        // That assert is removed in ReleaseFast and ReleaseSmall, and
        // `unreachable` under it left the release build running off the
        // end of the loop with `stream.live` still false. A panic keeps
        // the fault loud in every build and never carries on into memory
        // nothing wrote. It is still a fault of this file's own
        // arithmetic and never a peer's octets, which is why it stays an
        // assert and does not become an error a caller handles.
        @panic("h2: the stream table has no free slot and open_count said it had one");
    }

    /// Takes `stream` out of the table and gives back the room its inbox
    /// still holds.
    ///
    /// **The room has to go back.** The octets in an inbox spent the peer's
    /// connection window and were never credited, because the owner had not
    /// read them. An owner that closed without reading them would otherwise
    /// leave the window smaller for every stream after it, and a connection
    /// that lost its whole window stops.
    fn forget(self: *Session, stream: *Stream) void {
        if (!stream.live) return;
        for (&self.streams) |*slot| {
            const held = slot.* orelse continue;
            if (held != stream) continue;
            slot.* = null;
            break;
        }
        stream.live = false;
        std.debug.assert(self.open_count > 0);
        self.open_count -= 1;
        self.dropInbox(stream);
    }

    /// The open stream with this identifier, or null.
    fn find(self: *Session, id: u31) ?*Stream {
        if (id == 0) return null;
        for (self.streams) |slot| {
            const stream = slot orelse continue;
            if (stream.id == id) return stream;
        }
        return null;
    }

    /// Whether `id` names a stream that has never been open on this
    /// connection, which RFC 9113 section 5.1 calls the idle state.
    ///
    /// **`find` answering null is not the same question.** A stream this
    /// side opened, read to its end, and gave back is gone from the table
    /// too, and section 5.1 lets a peer send `RST_STREAM` or
    /// `WINDOW_UPDATE` on such a stream: the frame was already on the wire
    /// when this side closed it. Refusing every frame `find` could not
    /// place would turn that race into a failed transfer. curl 8.21.0
    /// accepts a `RST_STREAM` on a stream it has just finished, exit 0,
    /// and refuses one on a stream nobody opened, exit 16. Both measured.
    ///
    /// The two states are told apart by the counter, not by the table:
    /// `next_stream_id` is the next identifier this side will hand out, so
    /// an odd identifier at or above it has never been used. An even
    /// identifier is a server-initiated stream, and this side sent
    /// `SETTINGS_ENABLE_PUSH` of 0 and refuses a `PUSH_PROMISE`, so no
    /// even stream is ever open here either.
    fn idleStream(self: *const Session, id: u31) bool {
        if (id == 0) return false;
        if (id % 2 == 0) return true;
        return id >= self.next_stream_id;
    }

    /// Ends the connection because a frame arrived on an idle stream.
    ///
    /// RFC 9113 section 5.1: in the idle state a receiver takes any frame
    /// but `HEADERS` and `PRIORITY` as a connection error of type
    /// `PROTOCOL_ERROR`, and a client takes a `HEADERS` that way too,
    /// because only a client opens a client-initiated stream. This engine
    /// dropped such a frame instead, which cost the peer nothing and left
    /// a rule of the RFC unenforced.
    fn refuseIdleStream(self: *Session) Fault {
        self.abort(.protocol_error);
        return error.IdleStream;
    }

    /// Drops what a stream's inbox holds and gives the connection window
    /// back for it.
    ///
    /// The stream window is not credited: the stream is over, so a window
    /// on it means nothing and a `WINDOW_UPDATE` for it would name a stream
    /// the peer has already closed.
    fn dropInbox(self: *Session, stream: *Stream) void {
        // **Both buffers owe the peer room.** The inbox holds what arrived
        // and nobody read. `taken` holds what this stream's owner swapped
        // out of the inbox and did not finish, and its room has not gone
        // back either: `creditTaken` runs at the next swap, and a stream
        // that closes has no next swap. See `Stream.taken`.
        const held = stream.buffered().len + stream.taken.items.len;
        stream.inbox.clearRetainingCapacity();
        stream.inbox_at = 0;
        stream.taken.clearRetainingCapacity();
        if (held == 0) return;
        // Best effort. A write that fails leaves the connection unfit for
        // reuse, which `Exchange.reusable` reads off the connection itself.
        self.creditConnection(@intCast(held)) catch {};
    }

    /// Opens a session on `conn` and writes the client preface, the first
    /// `SETTINGS` frame, and the `WINDOW_UPDATE` that raises the connection
    /// window.
    ///
    /// Nothing is flushed here and nothing is waited for. RFC 9113 section
    /// 3.4 lets a client send its first request before the server answers,
    /// so the request goes out under the same flush as the preface and the
    /// exchange costs one round trip and not two.
    ///
    /// On the heap, because `Exchange` and the connection pool both hold
    /// the address and neither may move it.
    pub fn create(
        gpa: std.mem.Allocator,
        conn: *zurl_net.Connection,
        /// How long one read of this connection may wait with no frame
        /// arriving. `h1.Engine.read_timeout` is what the pool hands over.
        /// See `Session.read_timeout`.
        read_timeout: std.Io.Timeout,
    ) (std.mem.Allocator.Error || error{WriteFailed})!*Session {
        const self = try gpa.create(Session);
        errdefer gpa.destroy(self);

        self.* = .{
            .gpa = gpa,
            .io = conn.io,
            .shared = false,
            .lock = .init,
            .wake = .init,
            .reading = false,
            .reserved = 0,
            .conn = conn,
            .frames = try .init(gpa, .{ .max_frame_size = frame_len_max }),
            .decoder = .init(.{
                // The table this side told the peer about, and no other
                // number. A decoder that allowed a larger one would hold
                // memory this side never advertised.
                .table_capacity_max = header_table_len,
                .header_list_size_max = header_list_len_max,
                .field_count_max = header_fields_max,
            }),
            .peer_settings = .initial,
            .send_room = .{},
            .recv_owed = 0,
            .streams = @splat(null),
            .open_count = 0,
            .progress = 0,
            .body_octets = 0,
            .next_stream_id = 1,
            .goaway_code = null,
            .goaway_last_stream = 0,
            .broken = false,
            .dirty = false,
            .block = .empty,
            .block_stream_id = 0,
            .block_end_stream = false,
            .table_update_sent = false,
            .read_timeout = read_timeout,
            .read_bounds_dropped = 0,
            .read_timed_out = false,
        };
        errdefer self.frames.deinit(gpa);
        errdefer self.decoder.deinit(gpa);

        const w = conn.writer();
        zurl_h2.preface.writeClientFlight(w, wanted()) catch return error.WriteFailed;
        // `SETTINGS_INITIAL_WINDOW_SIZE` moves the window of a stream and
        // never the window of the connection. RFC 9113 section 6.9.2 says
        // so, so the connection window is raised with an explicit
        // `WINDOW_UPDATE` and with nothing else.
        try self.writeWindowUpdate(0, window_len - @as(u32, zurl_h2.window.size_initial));
        return self;
    }

    /// Frees the session.
    ///
    /// **Every stream must have been forgotten first.** A `Stream` belongs
    /// to its `Exchange`, so a session that still held one would be holding
    /// the address of memory the exchange freed. `h1.Pool.close` destroys a
    /// session only after every exchange on it has closed, which is the
    /// same order an HTTP/1.1 connection is closed in.
    /// Lets two tasks drive this session from here on.
    ///
    /// Call it once, before any second task can reach the session, and
    /// never on a session that already carries a stream of another task.
    /// `h1.Pool` calls it on the connection it is about to publish for
    /// sharing, while it still holds the pool lock and before any other
    /// task has the address.
    ///
    /// It also gives the connection under the session its own write lock,
    /// which is what lets a read and a write run at once. See
    /// `zurl_net.Connection.shareBetweenTasks`.
    pub fn markShared(self: *Session) void {
        self.shared = true;
        self.conn.shareBetweenTasks();
    }

    /// Takes the session lock, or does nothing for a session nobody shares.
    ///
    /// **Uncancelable.** Every caller of this takes the lock to leave the
    /// session in a state the next task can read. A task that stopped while
    /// it held the lock would leave the connection with a half written
    /// frame on it. A cancel is honoured at the read or the write inside,
    /// which is where it can be honoured safely.
    fn acquire(self: *Session) void {
        if (!self.shared) return;
        self.lock.lockUncancelable(self.io);
    }

    /// Gives the session lock back. The mirror of `acquire`.
    fn release(self: *Session) void {
        if (!self.shared) return;
        self.lock.unlock(self.io);
    }

    /// Claims one stream slot for a request that is about to open, and
    /// says whether it got one.
    ///
    /// The caller must call `unreserve` for every true answer that does not
    /// reach `open`. See `reserved`.
    pub fn reserve(self: *Session) bool {
        self.acquire();
        defer self.release();
        if (!self.usableLocked()) return false;
        if (self.open_count + self.reserved >= self.concurrentMax()) return false;
        self.reserved += 1;
        return true;
    }

    /// Gives one claimed stream slot back. See `reserve`.
    pub fn unreserve(self: *Session) void {
        self.acquire();
        defer self.release();
        std.debug.assert(self.reserved > 0);
        self.reserved -= 1;
    }

    pub fn destroy(self: *Session) void {
        std.debug.assert(self.open_count == 0);
        const gpa = self.gpa;
        self.frames.deinit(gpa);
        self.decoder.deinit(gpa);
        self.block.deinit(gpa);
        gpa.destroy(self);
    }

    /// Whether a further request may open a stream on this connection.
    ///
    /// This is about the connection and not about the moment: `hasRoom`
    /// answers whether there is a free stream slot right now. A caller that
    /// wants to send needs both.
    pub fn usable(self: *Session) bool {
        self.acquire();
        defer self.release();
        return self.usableLocked();
    }

    /// `usable` for a caller that holds the lock already.
    fn usableLocked(self: *const Session) bool {
        if (self.broken) return false;
        // **A connection whose read reached its deadline never goes back
        // in the pool.** `broken` is set beside this latch today, so the
        // line above already answers false. It is written out all the same,
        // because the two say different things: `broken` is a connection
        // this side gave up on, and this is the one shape where the socket
        // may still be open and still be producing octets nobody framed.
        // A later arm that cleared `broken` would reopen the hole.
        if (self.read_timed_out) return false;
        if (self.goaway_code != null) return false;
        // **The identifiers ran out.** RFC 9113 section 5.1.1 makes them
        // odd and going up by two, and 2147483647 is the largest. A client
        // that used them all must open a new connection, which is what a
        // false answer here buys: `h1.Pool` never hands this connection
        // out again, and the next request dials.
        if (self.next_stream_id > zurl_h2.frame.stream_id_max - 2) return false;
        return true;
    }

    /// Sends everything written and not sent yet.
    ///
    /// **`Connection.flush` and never `writer().flush()`.** An encrypted
    /// connection holds the plaintext in one buffer and the ciphertext in
    /// the next, and a flush of the writer alone leaves the whole request
    /// inside this process.
    fn flushWrites(self: *Session) error{WriteFailed}!void {
        if (!self.dirty) return;
        self.conn.flush() catch return error.WriteFailed;
        self.dirty = false;
    }

    fn writeAll(self: *Session, bytes: []const u8) error{WriteFailed}!void {
        self.conn.writer().writeAll(bytes) catch return error.WriteFailed;
        self.dirty = true;
    }

    fn writeWindowUpdate(self: *Session, id: u31, increment: u32) error{WriteFailed}!void {
        // An increment of zero is a fault on the wire, RFC 9113 section
        // 6.9, so it is never written. A caller reaching this with nothing
        // owed is ordinary, not a mistake.
        if (increment == 0) return;
        var out: [zurl_h2.frame.header_len + zurl_h2.WindowUpdate.payload_len]u8 = undefined;
        const frame_payload: zurl_h2.WindowUpdate = .{ .increment = @intCast(increment) };
        try self.writeAll(frame_payload.encode(id, &out));
    }

    fn writeRstStream(self: *Session, id: u31, code: zurl_h2.ErrorCode) error{WriteFailed}!void {
        var out: [zurl_h2.frame.header_len + zurl_h2.RstStream.payload_len]u8 = undefined;
        const frame_payload: zurl_h2.RstStream = .{ .error_code = code };
        try self.writeAll(frame_payload.encode(id, &out));
    }

    /// Ends the connection with a `GOAWAY` and marks it unusable.
    ///
    /// Best effort. The fault that brought this call is already on its way
    /// to the caller, and a write that fails on a connection that is
    /// already over adds nothing. The connection is marked either way, so
    /// nothing sends a second request on it.
    fn abort(self: *Session, code: zurl_h2.ErrorCode) void {
        self.broken = true;
        var out: [zurl_h2.frame.header_len + zurl_h2.Goaway.fixed_len]u8 = undefined;
        // This client opens no server stream and answers no push, so the
        // last stream it processed is always 0.
        const frame_payload: zurl_h2.Goaway = .{ .last_stream_id = 0, .error_code = code };
        self.writeAll(frame_payload.encode(&out)) catch return;
        self.flushWrites() catch return;
    }

    /// Writes one header block as a `HEADERS` frame and as many
    /// `CONTINUATION` frames as the peer's `SETTINGS_MAX_FRAME_SIZE` needs.
    ///
    /// An empty block still writes one `HEADERS` frame, because the frame
    /// and not the block is what opens the stream.
    fn writeHeaderBlock(
        self: *Session,
        id: u31,
        block: []const u8,
        end_stream: bool,
    ) error{WriteFailed}!void {
        // The peer's number and never this side's. RFC 9113 section 6.5.2:
        // a sender keeps to the size the receiver advertised.
        const room: usize = self.peer_settings.max_frame_size;
        std.debug.assert(room >= zurl_h2.settings.max_frame_size_min);

        var at: usize = 0;
        var first = true;
        while (true) {
            const take = @min(room, block.len - at);
            const last = at + take == block.len;

            var flags: u8 = 0;
            if (last) flags |= zurl_h2.flag.end_headers;
            if (first and end_stream) flags |= zurl_h2.flag.end_stream;

            var head: [zurl_h2.frame.header_len]u8 = undefined;
            (zurl_h2.Header{
                .length = @intCast(take),
                .type = if (first) .headers else .continuation,
                .flags = flags,
                .stream_id = id,
            }).encode(&head);
            try self.writeAll(&head);
            if (take != 0) try self.writeAll(block[at..][0..take]);

            at += take;
            first = false;
            if (last) break;
        }
    }

    /// Writes one `DATA` frame. The caller must have taken the octets out
    /// of both flow-control windows already, which is this build's own job
    /// and so an assert.
    fn writeData(
        self: *Session,
        id: u31,
        bytes: []const u8,
        end_stream: bool,
    ) error{WriteFailed}!void {
        std.debug.assert(bytes.len <= self.peer_settings.max_frame_size);
        var head: [zurl_h2.frame.header_len]u8 = undefined;
        (zurl_h2.Header{
            .length = @intCast(bytes.len),
            .type = .data,
            .flags = if (end_stream) zurl_h2.flag.end_stream else 0,
            .stream_id = id,
        }).encode(&head);
        try self.writeAll(&head);
        if (bytes.len != 0) try self.writeAll(bytes);
    }

    /// Gives the peer back room on the connection.
    ///
    /// The update goes out once the owed count passes half the window, so
    /// an ordinary download spends one `WINDOW_UPDATE` for every half
    /// window and not one for every frame.
    fn creditConnection(self: *Session, octets: u32) error{WriteFailed}!void {
        self.recv_owed += octets;
        if (self.recv_owed < window_update_at) return;
        try self.writeWindowUpdate(0, self.recv_owed);
        self.recv_owed = 0;
    }

    /// Gives the peer back room on one stream.
    ///
    /// A stream the peer has ended gets none: the window of a closed stream
    /// means nothing, and an update naming it is octets spent for no
    /// reason.
    fn creditStream(self: *Session, stream: *Stream) error{WriteFailed}!void {
        if (stream.recv_owed < stream_window_update_at) return;
        if (stream.ended or stream.reset != null) {
            stream.recv_owed = 0;
            return;
        }
        try self.writeWindowUpdate(stream.id, stream.recv_owed);
        stream.recv_owed = 0;
    }

    /// Records that the octets of one `DATA` frame arrived, and gives back
    /// whatever room is no longer held.
    ///
    /// RFC 9113 section 6.9.1 counts the whole `DATA` payload, the pad
    /// length octet and the padding included, so `octets` is the frame's
    /// own length and never the payload the parser handed back.
    ///
    /// **Room goes back when the octets are spent, not when they arrive.**
    /// That is the difference multiplexing makes. Octets handed straight to
    /// the caller that asked for them are spent at once and their room goes
    /// back at once, which is what a single stream on a connection sees and
    /// what it always saw. Octets copied into another stream's inbox are
    /// not spent: they sit in this process, and their room stays with them
    /// until that stream's owner reads them. So the peer's own flow control
    /// is what bounds the memory here, and no second bound is needed beside
    /// it. See `Stream.inbox`.
    ///
    /// A frame for a stream that is not open at all is spent immediately.
    /// There is nobody to hold it for, and a window that is never given
    /// back stops the connection.
    ///
    /// `held` is how many of `octets` went into an inbox. **It is the
    /// payload and never the frame length**, because RFC 9113 section 6.9.1
    /// counts the pad length octet and the padding in the window and an
    /// inbox holds neither. The difference is spent on arrival: nobody is
    /// holding it, so nothing would ever give it back.
    fn creditReceive(
        self: *Session,
        octets: u32,
        target: ?*Stream,
        held: usize,
    ) error{WriteFailed}!void {
        std.debug.assert(held <= octets);
        const stream = target orelse {
            std.debug.assert(held == 0);
            try self.creditConnection(octets);
            return;
        };
        // The stream window is credited on arrival either way. It bounds
        // what one stream may hold, and the inbox is already inside that
        // bound: a stream may never buffer more than its own window,
        // because the peer may not send more than its own window.
        stream.recv_owed += octets;
        try self.creditStream(stream);
        try self.creditConnection(octets - @as(u32, @intCast(held)));
    }

    /// Gives back the connection room for octets an owner has just taken
    /// out of its inbox.
    fn creditTaken(self: *Session, octets: usize) error{WriteFailed}!void {
        if (octets == 0) return;
        try self.creditConnection(@intCast(octets));
    }

    /// Adds one header block fragment to the block being joined.
    ///
    /// `zurl_h2.FrameReader` already refuses a block past
    /// `zurl_h2.continuation.limits.block_octets_max`, on the frame headers
    /// alone. This checks the same bound over the octets that are actually
    /// kept, so the memory this file holds is bounded by this file and not
    /// only by the layer under it.
    fn appendBlock(self: *Session, fragment: []const u8) Fault!void {
        const bound = zurl_h2.continuation.limits.block_octets_max;
        if (self.block.items.len + fragment.len > bound) {
            self.abort(.enhance_your_calm);
            return error.HeaderBlockTooLarge;
        }
        try self.block.appendSlice(self.gpa, fragment);
    }

    /// Reads one frame, applies it to the stream it names, and says what it
    /// meant to `waiter`.
    ///
    /// Every frame of the connection comes through here, whichever stream
    /// it names, because the settings, the windows, and the HPACK table are
    /// connection state that one request may not skip.
    ///
    /// **A frame for another open stream is applied there and reported as
    /// `.idle` here.** That is the whole of multiplexing on the read side.
    /// The waiting exchange reads a frame that was not for it, the stream
    /// it was for moves along, and the waiter carries on. `Session.progress`
    /// counts such a frame, so the waiter's idle budget is not spent on
    /// somebody else's answer. See `idle_frames_max`.
    ///
    /// **A frame for a stream that is not open is applied to the connection
    /// alone.** A peer may send on a stream this side has already reset or
    /// closed, and RFC 9113 section 5.1 allows it for a short while after a
    /// `RST_STREAM`. The window still has to go back.
    fn step(self: *Session, waiter: *Stream) Fault!Step {
        // Whatever this side wrote goes out before it waits for an answer.
        // A `SETTINGS` acknowledgement or a `PING` reply left in a buffer
        // is a peer waiting for octets that are inside this process.
        //
        // **On a shared session it goes out before the wait below, not
        // after it.** A task that wrote a request and then found another
        // task inside the read would otherwise leave that request in a
        // buffer until the other task came back, which is exactly the
        // stall that sharing a connection has to avoid.
        try self.flushWrites();

        if (!self.shared) return self.apply(self.read(), waiter);

        // **Another task holds the read.** Wait for it to apply a frame and
        // then look again. The frame may have been for this stream, and the
        // answer is then in this stream's inbox: the caller checks that
        // before it asks for another step.
        if (self.reading) {
            self.wake.wait(self.io, &self.lock) catch return error.ReadFailed;
            return .waited;
        }

        // **The lock is let go for the read and for nothing else.** This is
        // the whole of what one task gains from another: while this task
        // waits for octets, a task with a request ready takes the lock,
        // writes it, flushes it, and comes back here to wait too.
        //
        // `reading` is what keeps a second task out of the socket. It is
        // written under the lock and read under the lock, and it stays true
        // over the one stretch where the lock is not held.
        self.reading = true;
        self.lock.unlock(self.io);
        const got = self.read();
        self.lock.lockUncancelable(self.io);
        self.reading = false;
        // Every waiter looks again, because one frame can free more than
        // one of them: a `SETTINGS` moves every stream's send window, and a
        // `GOAWAY` ends every stream at once.
        self.wake.broadcast(self.io);
        return self.apply(got, waiter);
    }

    /// What one frame read answered: the frame, or the deadline, or a
    /// cancel. See `engine.RacedRead`.
    const ReadAnswer = engine.RacedRead(zurl_h2.FrameReader.NextError!zurl_h2.payload.Frame);

    /// Reads one frame off the connection, and stops waiting after
    /// `read_timeout` with no frame arriving.
    ///
    /// **It changes nothing but the dropped-bound count, and it takes no
    /// lock.** This is the one call of a shared session that runs with the
    /// lock let go, so a line here that wrote session state would race with
    /// every other task. The answer, fault and all, is handed to `apply`,
    /// which runs under the lock again and is where the latch is written.
    ///
    /// **The deadline is on this one read and never on the transfer.** A
    /// read ends as soon as any frame of any stream arrives, so a
    /// connection that keeps delivering starts the clock again every time
    /// and a slow download is bounded by `--max-time` and by the rate rule
    /// in `zurl_stream.Stall`, never by this. Only a connection that
    /// delivers nothing at all reaches the deadline. See
    /// `Session.read_timeout`.
    fn read(self: *Session) ReadAnswer {
        return engine.raceRead(
            self.io,
            self.read_timeout,
            &self.read_bounds_dropped,
            zurl_h2.FrameReader.NextError!zurl_h2.payload.Frame,
            readTask,
            .{self},
        );
    }

    /// One frame read, as its own task.
    fn readTask(self: *Session) zurl_h2.FrameReader.NextError!zurl_h2.payload.Frame {
        return self.frames.next(self.conn.reader());
    }

    /// Everything on this connection that a reader's bound can see move.
    ///
    /// **This is the rule that says what progress is, and it is written
    /// once.** Every loop in this file that waits for a peer keeps a
    /// budget of frames that carry nothing, and every one of them puts its
    /// budget back when this number moves. So the number has to count the
    /// work and not the frames: a peer that can move it for free buys an
    /// unbounded wait, which is what a run of trailer `HEADERS` frames
    /// used to buy.
    ///
    /// Each term is a bound some reader keeps:
    ///
    /// - `body_octets`, which is what `Exchange.rawChunk` hands out and
    ///   what `content-length` counts.
    /// - `head_ready`, which is what `readHead` waits for.
    /// - `ended` and `reset`, which are the two ways a stream finishes.
    /// - `trailers`, which is what `Exchange.trailers` answers with.
    /// - `informational`, which `informational_heads_max` already bounds
    ///   at eight for each stream.
    ///
    /// Every one of them moves a bounded number of times for each stream:
    /// five booleans that never go back, eight informational heads, and
    /// the body octets, which the flow-control window and
    /// `--max-filesize` both bound. A peer buys no turn of any read loop
    /// without paying one of those, and a frame type nobody has written
    /// yet is idle by default rather than by an arm remembering to say so.
    fn advanced(self: *const Session) u64 {
        var total: u64 = self.body_octets;
        for (self.streams) |slot| {
            const stream = slot orelse continue;
            total += @intFromBool(stream.head_ready);
            total += @intFromBool(stream.ended);
            total += @intFromBool(stream.reset != null);
            total += @intFromBool(stream.trailers);
            total += stream.informational;
        }
        return total;
    }

    /// Applies what `read` answered, counts whether the frame moved
    /// anything, and says what it meant to `waiter`.
    ///
    /// **The count is taken here and never inside an arm.** See
    /// `Session.progress` for the defect that rule closes.
    fn apply(
        self: *Session,
        answer: ReadAnswer,
        waiter: *Stream,
    ) Fault!Step {
        const before = self.advanced();
        const meant = try self.applyFrame(answer, waiter);
        // A frame that left every bound where it found them is idle, and
        // the waiter's budget keeps the unit it spent on it.
        if (self.advanced() != before) self.progress += 1;
        return meant;
    }

    /// The frame switch itself. `apply` is the only caller.
    ///
    /// The caller holds the session lock. Splitting this from `read` is
    /// what lets the lock be let go over the read alone: every field this
    /// touches, the frame reader's buffer included, is written here.
    fn applyFrame(
        self: *Session,
        answer: ReadAnswer,
        waiter: *Stream,
    ) Fault!Step {
        const read_result = switch (answer) {
            .done => |result| result,
            // **The connection went quiet, and it is finished.** The read
            // was canceled part way through a frame, so the octets that
            // did arrive are gone and whatever the peer writes next would
            // be read as the head of a frame it is not. Nothing is written
            // to the peer either: a `GOAWAY` on a socket whose read just
            // stopped tells nobody anything, and `abort` would wait on the
            // same peer that stopped answering.
            .timed_out => {
                self.read_timed_out = true;
                self.broken = true;
                return error.OperationTimedOut;
            },
            // Something outside the transfer stopped this read. The
            // connection is at the same unknown place a deadline leaves
            // it, so it is broken too, and the name says who stopped it.
            .canceled => {
                self.broken = true;
                return error.Canceled;
            },
        };
        const got = read_result catch |err| switch (err) {
            error.ReadFailed, error.EndOfStream => {
                self.broken = true;
                return err;
            },
            else => |protocol_fault| {
                const fault = zurl_h2.classify(protocol_fault, 0);
                self.abort(fault.code);
                return protocol_fault;
            },
        };

        const id = got.header.stream_id;
        if (id == waiter.id) waiter.answered = true;
        // The stream this frame belongs to, or null for a connection frame
        // and for a stream that is no longer open.
        const target = self.find(id);

        switch (got.payload) {
            .settings => |s| {
                if (s.ack) return .idle;
                const before: i32 = self.peer_settings.initial_window_size;
                _ = s.applyTo(&self.peer_settings) catch |err| {
                    self.abort(zurl_h2.classify(err, 0).code);
                    return err;
                };
                // RFC 9113 section 6.9.2: a new `INITIAL_WINDOW_SIZE` moves
                // the send window of **every** open stream by the
                // difference, not only the one that is waiting. A build
                // with one stream could read the setting into that stream
                // alone; a build with several has to walk the table, or a
                // stream that was not waiting would send on a window the
                // peer has already shrunk.
                const after: i32 = self.peer_settings.initial_window_size;
                if (after != before) {
                    const delta = after - before;
                    for (self.streams) |slot| {
                        const each = slot orelse continue;
                        each.send_room.applyInitialSizeChange(delta) catch |err| {
                            self.abort(.flow_control_error);
                            return err;
                        };
                    }
                }
                zurl_h2.preface.writeSettingsAck(self.conn.writer()) catch return error.WriteFailed;
                self.dirty = true;
                return .idle;
            },
            .ping => |p| {
                // An acknowledgement answers a `PING` this side sent, and
                // this side sends none. A request needs no reply.
                if (p.ack) return .idle;
                var out: [zurl_h2.frame.header_len + zurl_h2.Ping.payload_len]u8 = undefined;
                try self.writeAll(p.reply().encode(&out));
                return .idle;
            },
            .goaway => |g| {
                self.goaway_code = g.error_code;
                self.goaway_last_stream = g.last_stream_id;
                // No further stream may open, whatever the code says.
                self.broken = true;
                // A stream above the last one the peer named was never
                // processed, so the request never ran and a caller may send
                // it again. `waiter.answered` stays false for it.
                if (waiter.id > g.last_stream_id) return error.ConnectionEnded;
                // A graceful `GOAWAY` lets the streams below the mark
                // finish. Any other code ends them.
                if (g.error_code != .no_error) return error.ConnectionEnded;
                return .idle;
            },
            .rst_stream => |r| {
                const stream = target orelse {
                    if (self.idleStream(id)) return self.refuseIdleStream();
                    return .idle;
                };
                // A stream ends once. A second `RST_STREAM` on the same
                // stream leaves `advanced` where it was, so a peer cannot
                // reset one stream over and over to hold another one open.
                stream.reset = r.error_code;
                if (stream != waiter) return .idle;
                return error.StreamReset;
            },
            .window_update => |u| {
                if (id == 0) {
                    self.send_room.increase(u.increment) catch |err| {
                        self.abort(.flow_control_error);
                        return err;
                    };
                    return .idle;
                }
                const stream = target orelse {
                    if (self.idleStream(id)) return self.refuseIdleStream();
                    return .idle;
                };
                stream.send_room.increase(u.increment) catch |err| {
                    // RFC 9113 section 6.9.1: a flow-control fault on a
                    // stream is a stream error, so the stream ends and the
                    // connection lives.
                    self.writeRstStream(stream.id, .flow_control_error) catch {};
                    stream.reset = .flow_control_error;
                    if (stream != waiter) return .idle;
                    return err;
                };
                // **A window that opens is not progress on its own.** The
                // sender that was waiting for it reads the window itself
                // and stops waiting: see `roomToSend`. A reader of a body
                // gains nothing from it, so a peer that sends nothing but
                // `WINDOW_UPDATE` spends the idle budget and never
                // refunds it.
                return .idle;
            },
            .headers => |h| {
                self.block.clearRetainingCapacity();
                self.block_stream_id = id;
                self.block_end_stream = h.end_stream;
                try self.appendBlock(h.block);
                if (!h.end_headers) return .idle;
                return self.finishBlock(waiter);
            },
            .continuation => |c| {
                try self.appendBlock(c.block);
                if (!c.end_headers) return .idle;
                return self.finishBlock(waiter);
            },
            .data => |d| {
                const stream = target orelse {
                    // A stream that was never open takes no body octet.
                    // The connection ends, so no room is given back: there
                    // is nobody left to give it to.
                    if (self.idleStream(id)) return self.refuseIdleStream();
                    // Nobody owns this stream. The octets are dropped and
                    // their room goes straight back, because a window that
                    // is never given back stops the connection.
                    try self.creditReceive(got.header.length, null, 0);
                    return .idle;
                };
                if (!stream.head_ready) {
                    // RFC 9113 section 8.1: a response starts with a
                    // `HEADERS` frame. Body octets before one are not a
                    // response this client can read.
                    try self.creditReceive(got.header.length, stream, 0);
                    self.abort(.protocol_error);
                    return error.MalformedResponse;
                }
                if (d.end_stream) stream.ended = true;
                // **The octets are the progress, not the frame.** RFC 9113
                // section 6.1 allows a `DATA` frame with nothing in it, so
                // a frame counted here would let a peer send nine octets
                // for ever and hold this reader open. See
                // `Session.advanced`.
                self.body_octets += d.data.len;

                if (stream != waiter or self.shared) {
                    // **Octets nobody can take right now, so they are
                    // copied.** They point into the frame reader's one
                    // buffer, which the next read overwrites. Two shapes
                    // reach this:
                    //
                    // - Another stream's octets. That stream's owner is not
                    //   here to take them.
                    // - Any octets at all on a shared session, the waiter's
                    //   own included. The waiter would carry the slice out
                    //   past the lock, and another task may read the next
                    //   frame into that same buffer as soon as it does. See
                    //   `Stream.taken` for how the owner gets them back
                    //   without a second copy.
                    //
                    // The room for the copied octets stays with them, and
                    // the padding beside them is spent now: see
                    // `creditReceive`.
                    if (d.data.len != 0) try stream.inbox.appendSlice(self.gpa, d.data);
                    try self.creditReceive(got.header.length, stream, d.data.len);
                    return .idle;
                }

                // The waiter's own octets. They go straight out of the
                // frame buffer to the caller, so nothing is copied and the
                // room goes back at once.
                try self.creditReceive(got.header.length, stream, 0);
                if (d.data.len == 0) return if (stream.ended) .ended else .idle;
                return .{ .data = d.data };
            },
            .push_promise => {
                // This side sent `SETTINGS_ENABLE_PUSH` of 0, so RFC 9113
                // section 8.4 makes a promise a connection error. The block
                // inside it is never decoded, and the connection ends, so
                // the HPACK tables never have to agree again.
                self.abort(.protocol_error);
                return error.PushRefused;
            },
            // RFC 9113 section 5.3.1 deprecated the priority scheme it
            // defined, and RFC 9218 replaced it with a header field a
            // client sends only when it has something to ask for. curl
            // 8.21.0 sends neither: measured on the wire, its whole client
            // flight is the preface, one `SETTINGS`, one `WINDOW_UPDATE`,
            // and the request. So a `PRIORITY` frame is read and ignored,
            // and nothing here sends one.
            //
            // **`Session.idleStream` is not asked here, and that is the
            // RFC.** Section 5.1 names `PRIORITY` as the one frame a
            // receiver takes on an idle stream without a fault, because a
            // sender may rank a stream it has not opened yet. curl 8.21.0
            // reads a `PRIORITY` on a stream nobody opened and finishes
            // the transfer, exit 0, measured.
            .priority => return .idle,
            // RFC 9113 section 4.1: a frame of a type a receiver does not
            // know must be ignored. `zurl_h2.FrameReader` counts it.
            .unknown => return .idle,
        }
    }

    /// Decodes the header block that just finished and says what it was.
    ///
    /// **Every block is decoded, even one for a stream nobody owns.** HPACK
    /// carries a table that both sides build from every block on the
    /// connection, so a block that is not decoded leaves the two tables out
    /// of step and no later block on that connection means anything. That
    /// is the reason this runs before the stream is looked up and not
    /// after.
    fn finishBlock(self: *Session, waiter: *Stream) Fault!Step {
        defer self.block.clearRetainingCapacity();

        var list = self.decoder.decode(self.gpa, self.block.items) catch |err| {
            // The decode stopped part way, so this side's table no longer
            // matches the peer's. RFC 7541 section 4.2 leaves no way back
            // from that, so the connection ends.
            if (err != error.OutOfMemory) self.abort(.compression_error);
            self.broken = true;
            return err;
        };
        var keep = false;
        defer if (!keep) list.deinit(self.gpa);

        const end_stream = self.block_end_stream;
        const stream = self.find(self.block_stream_id) orelse {
            // **The block was decoded first, and that is deliberate.** The
            // HPACK table must keep step with the peer's whatever happens
            // to the block, and the decode above is where that is paid.
            // Only the placing of the decoded list is refused here.
            if (self.idleStream(self.block_stream_id)) return self.refuseIdleStream();
            return .idle;
        };

        if (stream.head_ready) {
            // **A header block after the head is the trailer section.** RFC
            // 9113 section 8.1 allows one. The fields are kept, because
            // `curl -D` writes them after the head block, measured against
            // curl 8.21.0. See `renderTrailers`.
            //
            // A second trailer section is not legal and this keeps the
            // first: the list already held is not replaced, and the new one
            // is dropped by the `defer` above.
            //
            // **A trailer section takes the same field rules the head
            // takes.** This branch used to return before the check below,
            // so a trailer field was the one field list on this connection
            // that met no rule at all. `renderTrailers` writes it as
            // `name: value\r\n` into the block a caller reads, exactly as
            // `recordHead` writes the head, so a trailer was the shorter
            // road to the same forgery. The list is dropped on an error,
            // because `keep` is still false here.
            //
            // **A trailer section ends the stream, and one that does not
            // is malformed.** RFC 9113 section 8.1: a `HEADERS` frame that
            // arrives after the final status and carries no `END_STREAM`
            // makes the response malformed. curl 8.21.0 answers such a
            // frame with `Violation in HTTP messaging rule` and resets the
            // stream, measured against a listener that sent one. Refusing
            // it here is also what leaves a peer no way to send trailer
            // sections one after another: the first one ends the stream,
            // and any other one is this fault.
            if (!end_stream) {
                self.abort(.protocol_error);
                return error.MalformedResponse;
            }
            try validateResponseFields(list);
            stream.trailers = true;
            if (stream.trailer_fields == null) {
                stream.trailer_fields = list;
                keep = true;
            }
            stream.ended = true;
            if (stream != waiter) return .idle;
            return .ended;
        }

        try validateResponseFields(list);
        const status = try readStatus(list);

        // RFC 9110 section 15.2: an informational head is not the answer. A
        // client reads past it and waits for the real status.
        if (status < 200) {
            stream.informational += 1;
            if (stream.informational > informational_heads_max) {
                self.abort(.enhance_your_calm);
                return error.TooManyInformationalHeads;
            }
            return .idle;
        }

        stream.fields = list;
        keep = true;
        stream.head_ready = true;
        if (end_stream) stream.ended = true;
        if (stream != waiter) return .idle;
        return .head;
    }
};

/// Whether `name` is a field a peer may not send over HTTP/2.
///
/// RFC 9113 section 8.2.2 names them. Each one frames an HTTP/1.1 message,
/// and HTTP/2 frames its own, so a peer that sends one is describing a
/// message that is not the one on the wire.
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
/// **HPACK carries a NUL without complaint, so this is the layer that has
/// to refuse it.** RFC 9113 section 8.2.1 leaves the octet out of no field
/// value, and a Huffman-coded string holds it as readily as any other
/// byte. The rule itself is `engine.refuseNulInHead`, which all three
/// engines ask, and the reason it belongs in the engine and not in the
/// program above the library is written there.
///
/// Both halves of a field are read. A name is checked as well as a value,
/// because a name reaches a `-D` file the same way a value does.
fn refuseNulInFields(list: zurl_hpack.FieldList) Fault!void {
    for (list.fields.items) |item| {
        try engine.refuseNulInHead(item.name);
        try engine.refuseNulInHead(item.value);
    }
}

/// Checks the shape RFC 9113 section 8.3 puts on a response header list.
///
/// A field name must be a lower-case RFC 9110 token, a pseudo header must
/// come before every ordinary field, `:status` must be the only pseudo
/// header a response carries, no connection-specific field may appear at
/// all, and no field value may carry a byte that a header value cannot
/// hold. A list that breaks any of these is a malformed response, which is
/// a peer that did not answer HTTP/2.
///
/// **The name rule and the value rule are both here because HTTP/2 has no
/// natural one.** Over HTTP/1.1 a CR or an LF cannot survive inside a name
/// or a value, because the head parser split the head on CRLF to find them
/// in the first place. Over HTTP/2 both are opaque octet strings, so a peer
/// writes any byte it likes. `recordHead` then writes `name: value\r\n`
/// into the `-D` block, and one field of
/// `x-note: ok\r\nSet-Cookie: session=attacker` reached a user's file as
/// three fields the server never sent. `Response.headers` carried the same
/// value. The name half of that attack, a field named
/// `x-a\r\nset-cookie: injected=1`, stayed open after the value half was
/// closed, because the name met only a check for an upper-case letter.
///
/// The two rules are `engine.headerNameIsToken` and
/// `engine.headerValueHasControl`, which are the rules
/// `h1.validateHeaderName` and `h1.validateHeaderValue` ask of a request.
/// One rule each, asked in all three engines, so none of them can drift
/// from the others. **`h3.validateResponseFields` asks the same two, and
/// the test "h2 and h3 read the one field name rule" holds that.**
///
/// **A NUL is named before either of them.** `engine.headerValueHasControl`
/// answers true for a NUL, so such a value was already refused here, as
/// `MalformedResponse` and exit 56. curl 8.21.0 answers the same response
/// with `Nul byte in header` and exit 8, which is a code of its own, so
/// `refuseNulInFields` runs first and keeps that name. See
/// `engine.refuseNulInHead`.
fn validateResponseFields(list: zurl_hpack.FieldList) Fault!void {
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
            // **Once, and no more.** RFC 9113 section 8.3 gives a pseudo
            // header one appearance. `readStatus` takes the first, so a
            // second one was read by nobody and reached a caller as part
            // of a head this engine had called legal. curl 8.21.0 answers
            // two `:status` fields with `Invalid HTTP header field was
            // received` and exit 92, measured.
            if (seen_status) return error.MalformedResponse;
            seen_status = true;
            continue;
        }
        seen_ordinary = true;
        // RFC 9113 section 8.2.1: a field name is a `tchar` run with no
        // upper-case letter in it. That refuses a CR, an LF, a NUL, a
        // space and a colon, which are the octets that turn one field into
        // two lines of the rendered block. It also lets every lookup below
        // compare byte for byte.
        if (!engine.headerNameIsToken(item.name, .lower)) return error.MalformedResponse;
        if (connectionSpecific(item.name)) return error.MalformedResponse;
    }
}

/// The status of a response header list.
///
/// RFC 9113 section 8.3.2 makes `:status` exactly three digits, so anything
/// else is a malformed response and never a status this engine guesses at.
fn readStatus(list: zurl_hpack.FieldList) Fault!u16 {
    const text = list.get(":status") orelse return error.MalformedResponse;
    if (text.len != status_text_len) return error.MalformedResponse;
    for (text) |byte| {
        if (!std.ascii.isDigit(byte)) return error.MalformedResponse;
    }
    return std.fmt.parseInt(u16, text, 10) catch return error.MalformedResponse;
}

/// What one request needs from the caller, beyond the session it runs on.
///
/// Every slice is borrowed and must outlive the call to `open`. `h1`
/// already validated `headers`, already refused every name of
/// `engine.refused_headers`, and already decided which secrets this hop
/// carries, so nothing here repeats any of it.
pub const Open = struct {
    gpa: std.mem.Allocator,
    session: *Session,
    method: std.http.Method,
    /// The request target, which `:scheme`, `:path`, and the query come
    /// from. `h1.requestUri` built it, so both engines ask for the same
    /// resource.
    uri: std.Uri,
    /// The `:authority` value, the host and the port together, with the
    /// brackets an IPv6 address needs.
    ///
    /// The caller renders it, because `h1.writeAuthority` is the one place
    /// that rule lives and a second copy of it here could drift from the
    /// `host:` line HTTP/1.1 writes.
    authority: []const u8,
    /// The `user-agent` value. An empty one sends no field at all, which
    /// is what `curl -A ""` does.
    user_agent: []const u8,
    /// Whether this request offers a compressed body, and therefore which
    /// content codings the answer may carry. See
    /// `engine.Request.accept_encoding`, which holds the whole rule.
    ///
    /// `h1.sendOnH2` fills it, and it already folded in a caller's own
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
    /// stream. See `Stream.answered`.
    answered: *bool,
    /// Set true as soon as one octet of the request body has gone out.
    body_sent: *bool,
    /// Whether the caller already claimed a stream slot with
    /// `Session.reserve`.
    ///
    /// **A caller that shares a connection must claim before it opens.**
    /// The pool reads `Session.hasRoom` to pick the connection, and the
    /// stream opens some time after that. Two tasks that both read room for
    /// the last slot would both come here and one would be refused. A claim
    /// closes that window, and this field is what tells `openInner` to
    /// spend one rather than read the room again.
    ///
    /// False for a caller that holds the connection alone, which is every
    /// caller that took it out of the idle list.
    reserved: bool = false,
};

/// Sends one request on `o.session` and reads the response head.
///
/// The caller owns the returned `engine.Exchange` and must call `close` on
/// it exactly once. On a fault nothing is returned and the connection is
/// the caller's to close: an HTTP/2 connection that failed part way through
/// a request has an unknown number of octets still on it.
pub fn open(o: Open) engine.OpenError!*engine.Exchange {
    return openInner(o, .fresh) catch |err| openError(err);
}

/// Reads the answer to a request that already went out as HTTP/1.1, on the
/// stream an `Upgrade: h2c` handshake opened.
///
/// **No request is written here.** RFC 7540 section 3.2: the request that
/// carried the `Upgrade` field *is* stream 1, and the client half of it is
/// already closed, because the whole request went out over HTTP/1.1 before
/// the `101`. So this side sends the connection preface, which
/// `Session.create` has already written, and then reads. A `HEADERS` frame
/// from this side would be a second request on a stream that is not open
/// for one.
///
/// `o.body` must be null. The body, if there was one, went out on HTTP/1.1
/// behind the request head, which is what curl does: measured, `curl
/// --http2 -d k=v http://host/path` wrote the upgrade fields, a
/// `Content-Length: 3`, and the three body octets, all as HTTP/1.1.
///
/// The caller owns the returned `engine.Exchange` and must call `close` on
/// it exactly once.
pub fn openUpgraded(o: Open) engine.OpenError!*engine.Exchange {
    std.debug.assert(o.body == null);
    return openInner(o, .upgraded) catch |err| openError(err);
}

/// How the stream an `openInner` call reads was opened.
const Origin = enum {
    /// This side writes the request and then reads the answer. Every
    /// ordinary request.
    fresh,
    /// The request already went out as HTTP/1.1 and this side only reads.
    /// The `Upgrade: h2c` handshake, RFC 7540 section 3.2.
    upgraded,
};

fn openInner(o: Open, from: Origin) Fault!*engine.Exchange {
    const gpa = o.gpa;
    const session = o.session;

    // **The whole of this runs under the session lock on a shared
    // session.** The request goes out, the stream joins the table, and the
    // head comes back, and every one of those reads or writes state the
    // other tasks share. `Session.step` is what lets the lock go while it
    // waits for octets, so another task with a request ready is not held
    // up by the wait here.
    session.acquire();
    defer session.release();

    // **The connection is full.** RFC 9113 section 5.1.2: a peer names
    // `SETTINGS_MAX_CONCURRENT_STREAMS` and a client that opens one past it
    // gets the stream refused. The caller asked for a stream on a
    // connection that has none free, which `h1` avoids by reading
    // `Session.hasRoom` before it takes a connection out of the pool. A
    // caller that did not is told rather than left to send a stream the
    // peer will refuse.
    //
    // A caller that claimed a slot through `Session.reserve` spends the
    // claim here instead. The room was answered when the claim was made,
    // and reading it again would be a second answer to a question two
    // tasks already agreed on. See `Session.reserved`.
    if (o.reserved) {
        std.debug.assert(session.reserved > 0);
        session.reserved -= 1;
    } else if (!session.hasRoomLocked()) return error.TooManyStreams;

    const exchange = try gpa.create(Exchange);
    var landed = false;
    defer if (!landed) gpa.destroy(exchange);

    const id = session.next_stream_id;
    // The counter goes up before the first octet, so a request that failed
    // never leaves the identifier free for a second one. `Session.usable`
    // is what refuses a connection whose counter ran out.
    session.next_stream_id += 2;

    exchange.* = .{
        .interface = .{ .ptr = exchange, .vtable = &Exchange.exchange_vtable },
        .gpa = gpa,
        .session = session,
        .peer = o.peer,
        .stream = .{
            .id = id,
            // A new stream starts at the peer's `INITIAL_WINDOW_SIZE`. RFC
            // 9113 section 6.9.2.
            .send_room = .init(session.peer_settings.initial_window_size),
            // **An upgraded stream is already half closed on this side.**
            // RFC 7540 section 3.2: the request went out whole as
            // HTTP/1.1, so nothing more may be sent on stream 1 and
            // `Exchange.close` must not reset a stream this side finished.
            .sent_end = from == .upgraded,
        },
        .head_value = undefined,
        .content_length = null,
        .content_encoding = .identity,
        .body_received = 0,
        .body_taken = false,
        .body_partial = false,
        .framing_finished = false,
        .body_overrun = false,
        .body_fault = null,
        .idle_frames = 0,
        .pending = &.{},
        .raw = undefined,
        .transfer_buffer = undefined,
        .body = undefined,
        .body_source = undefined,
        .decompress = undefined,
        .decompress_buffer = undefined,
        .zstd_buffer = null,
        .trailer_text = null,
        // `h1.followChain` sets this on the exchange that ends a chain.
        .chain_storage = null,
    };
    // **The stream joins the table before the first octet goes out.** A
    // frame that names this identifier can arrive as soon as the request
    // has, and a stream the session cannot find gets its `DATA` dropped and
    // its `HEADERS` thrown away. So the table is filled first and emptied
    // on every path out.
    session.adopt(&exchange.stream);

    // The decoded head belongs to the exchange from here on, so every
    // return below frees it through `release`.
    defer o.answered.* = exchange.stream.answered;
    errdefer {
        session.forget(&exchange.stream);
        exchange.stream.deinit(gpa);
    }

    switch (from) {
        .fresh => try writeRequest(o, &exchange.stream),
        // Nothing goes out. The request is already on the wire as
        // HTTP/1.1, and the preface behind it is what `Session.create`
        // wrote. See `openUpgraded`.
        .upgraded => {},
    }
    try readHead(o, exchange);

    landed = true;
    return &exchange.interface;
}

/// Builds and writes the request header block, and the body behind it.
fn writeRequest(o: Open, stream: *Stream) Fault!void {
    const gpa = o.gpa;
    const session = o.session;

    // **The generated text of one request, in one allocation.** The path,
    // the content length, and a lower-case copy of every caller header
    // name are built here first, and the field list below points into the
    // finished buffer. Two passes, because a buffer that grew while the
    // fields pointed into it would leave them pointing at freed memory.
    var scratch: std.ArrayList(u8) = .empty;
    defer scratch.deinit(gpa);

    const path_span = try appendPath(gpa, &scratch, o.uri);

    var length_span: Span = .{ .at = 0, .len = 0 };
    if (o.body) |source| {
        if (source.len) |length| length_span = try appendPrint(gpa, &scratch, "{d}", .{length});
    }

    const name_spans = try gpa.alloc(Span, o.headers.len);
    defer gpa.free(name_spans);
    for (o.headers, name_spans) |header, *slot| {
        // RFC 9113 section 8.2.1: every field name on the wire is lower
        // case. `h1.validateHeaderName` already refused a name that is not
        // an RFC 9110 token, so nothing here can lower-case a name into
        // something a peer reads as two fields.
        slot.* = try appendLower(gpa, &scratch, header.name);
    }

    // The jar answers for this hop, and the value it wrote is a header
    // value like any other. `h1.openOnce` already validated it and already
    // joined it into `o.headers`, so nothing here reads the jar.

    var fields: std.ArrayList(zurl_hpack.Field) = .empty;
    defer fields.deinit(gpa);

    // **The four pseudo headers, in this order, before every ordinary
    // field.** RFC 9113 section 8.3.1.
    try fields.append(gpa, .{ .name = ":method", .value = @tagName(o.method) });
    try fields.append(gpa, .{ .name = ":scheme", .value = o.uri.scheme });
    try fields.append(gpa, .{ .name = ":authority", .value = o.authority });
    try fields.append(gpa, .{ .name = ":path", .value = span(scratch, path_span) });

    if (o.user_agent.len != 0) {
        try fields.append(gpa, .{ .name = "user-agent", .value = o.user_agent });
    }
    // **No offer, no field.** The rule `h1.writeRequestHead` writes, said
    // again for HPACK. A request that named no `--compressed` asks the peer
    // for the plain body curl would have got, and a caller that wrote its
    // own `accept-encoding` gets that one and no second copy.
    if (o.accept_encoding and !headersOfferEncoding(o.headers)) {
        try fields.append(gpa, .{ .name = "accept-encoding", .value = accept_encoding_value });
    }

    if (o.body) |source| {
        // **A known length is announced and an unknown one is not.**
        // HTTP/2 frames its own body: the `END_STREAM` flag ends it, so
        // there is no chunked transfer coding to fall back on and no
        // framing field a request must carry. A `content-length` on a
        // known-length body is what curl sends, and it lets a peer refuse
        // an upload before it reads one octet.
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

    const block = try zurl_hpack.encoder.encodeAlloc(gpa, fields.items, .{
        .coding = .huffman_when_shorter,
        // **Sent once, on the first block of the connection.** This
        // encoder never indexes, so the table the peer keeps for it stays
        // empty. An update of zero says so and lets the peer free the
        // memory. An update on every block would be octets spent to repeat
        // it.
        .table_size_update = if (session.table_update_sent) null else 0,
    });
    defer gpa.free(block);
    session.table_update_sent = true;

    const no_body = o.body == null;
    try session.writeHeaderBlock(stream.id, block, no_body);
    if (no_body) {
        stream.sent_end = true;
        return;
    }

    // The flag goes up before the first read of the source and not after
    // it. A send that got no further than the first chunk has still moved
    // the source, so every send after this one needs `engine.Body.rewind`.
    // `h1.sendOn` raises the same flag at the same moment.
    o.body_sent.* = true;
    try sendBody(o, stream, o.body.?);
}

/// Writes the request body as `DATA` frames, and ends the stream behind it.
///
/// **This is where a body larger than the peer's window would deadlock, and
/// where it does not.** The peer opens room with a `WINDOW_UPDATE`, and a
/// sender that only wrote would never read one. So the loop below reads a
/// frame whenever there is no room, through `Session.step`, which answers
/// every `WINDOW_UPDATE`, every `SETTINGS`, and every `PING` on the way.
/// The room is the smaller of the connection window and the stream window,
/// because RFC 9113 section 6.9.1 bounds a `DATA` frame by both.
///
/// **A peer may answer before the body finishes.** RFC 9113 section 8.1
/// allows it, and a `404` for a large upload is the ordinary case. The loop
/// stops writing as soon as the head arrives and never sends `END_STREAM`.
/// `Exchange.close` then sends `RST_STREAM`, which is what section 8.1 asks
/// a client to do when it stops sending a request body.
fn sendBody(o: Open, stream: *Stream, source: engine.Body) Fault!void {
    const session = o.session;
    var buffer: [body_chunk_len]u8 = undefined;
    var written: u64 = 0;

    while (true) {
        // A known length bounds the ask as well as the total, so a source
        // that keeps producing octets cannot make this loop run forever.
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

        var at: usize = 0;
        while (at < count) {
            const room = try roomToSend(session, stream);
            // The peer answered while this side was still sending. Stop,
            // and leave the stream open for `close` to reset.
            if (room == 0) return;
            const take = @min(count - at, room);
            // `consume` checks the window itself now, and takes the wide
            // type, so no cast stands between the count and the check.
            try session.send_room.consume(take);
            try stream.send_room.consume(take);
            try session.writeData(stream.id, buffer[at..][0..take], false);
            at += take;
        }
        written += count;
    }

    if (source.len) |length| {
        // The peer was told exactly how many octets to read. A body that
        // stopped short leaves it waiting for octets that never come.
        if (written != length) return error.BodyLengthMismatch;
    }

    try session.writeData(stream.id, &.{}, true);
    stream.sent_end = true;
}

/// How many octets the next `DATA` frame may carry, waiting for room when
/// there is none.
///
/// Zero says the peer answered the request while this side was still
/// sending, and the caller must stop.
///
/// **The connection window is shared, so one stream may not take it all.**
/// RFC 9113 section 6.9.1 bounds a `DATA` frame by the stream window and by
/// the connection window together, and nothing in the RFC says how several
/// senders on one connection should divide the second one. A sender that
/// took the whole connection window for one upload would leave every other
/// stream on that connection with nothing until its own body ended, which
/// is starvation and not flow control. So a stream takes at most an even
/// share of the connection window, `available / open_count`, with one frame
/// as the floor: an even share that rounds to nothing would stop every
/// stream instead of slowing them.
///
/// With one stream open the share is the whole window, which is what a
/// single request always saw.
fn roomToSend(session: *Session, stream: *Stream) Fault!usize {
    var idle: usize = 0;
    var seen = session.progress;
    while (true) {
        if (stream.head_ready) return 0;
        const share = shareOfConnection(session);
        const room = @min(share, stream.send_room.available);
        if (room > 0) {
            // A frame carries no more than the peer's own frame size.
            return @min(@as(usize, @intCast(room)), @as(usize, session.peer_settings.max_frame_size));
        }
        if (idle >= idle_frames_max) return error.PeerStalled;
        idle += 1;
        switch (try session.step(stream)) {
            // The peer opened the window, or answered, or said something
            // this exchange does not act on. Either way the windows above
            // are read again.
            .idle, .head => {},
            // Another task read a frame while this one waited. The windows
            // above are read again, and the budget goes back: nothing was
            // read here. See `Step.waited`.
            .waited => idle -= 1,
            // RFC 9113 section 8.1: a response starts with `HEADERS`.
            // Nothing else can reach a stream with no head yet, and
            // `Session.step` already refused it.
            .data, .ended => return error.MalformedResponse,
        }
        // A frame that moved some stream along is not an idle frame. See
        // `idle_frames_max`.
        if (session.progress != seen) {
            seen = session.progress;
            idle = 0;
        }
    }
}

/// The share of the connection send window one stream may take now.
///
/// See `roomToSend` for why the window is divided at all. The floor is one
/// frame, so a window smaller than the number of open streams still lets
/// each of them send.
fn shareOfConnection(session: *Session) i32 {
    const available = session.send_room.available;
    if (available <= 0) return available;
    const sharers = @max(session.open_count, 1);
    if (sharers == 1) return available;
    const floor: i32 = session.peer_settings.max_frame_size;
    const even = @divTrunc(available, @as(i32, @intCast(@min(sharers, std.math.maxInt(i32)))));
    return @min(available, @max(even, floor));
}

/// Reads frames until the response head is whole, then fills
/// `engine.Head`.
fn readHead(o: Open, exchange: *Exchange) Fault!void {
    const session = o.session;
    const stream = &exchange.stream;

    var idle: usize = 0;
    var seen = session.progress;
    while (!stream.head_ready) {
        if (idle >= idle_frames_max) return error.PeerStalled;
        switch (try session.step(stream)) {
            .head => {},
            .idle => idle += 1,
            // Another task read a frame while this one waited. Nothing was
            // read here, so no idle budget is spent. See `Step.waited`.
            .waited => {},
            // A response starts with `HEADERS`, and `Session.step` refuses
            // body octets before one, so neither of these is reachable.
            .data, .ended => return error.MalformedResponse,
        }
        // A frame that answered another stream on this connection is not an
        // idle frame. See `idle_frames_max`.
        if (session.progress != seen) {
            seen = session.progress;
            idle = 0;
        }
    }

    const fields = stream.fields.?;
    const status = try readStatus(fields);

    // **A `HEAD` response carries no body octet, whatever its head says.**
    // RFC 9110 section 9.3.2. The `content-length` on it describes a body
    // that is not coming, so a caller that took the number would draw a
    // progress meter that never fills. `h1` reports zero for the same
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

    // The head goes to the log the way `curl -D` writes it, before
    // anything else reads it.
    try recordHead(o, status, fields);

    // **Every `set-cookie` of this hop goes to the jar, and the jar owns
    // every rule about it.** The engine keeps no cookie of its own and
    // reads no field of the value: which host may set which domain is one
    // rule, written once, in `zurl_core.cookie`. The url is this hop's
    // own, which `h1.followChain` rewrote for each hop.
    if (o.cookies) |jar| {
        for (fields.fields.items) |item| {
            if (!std.mem.eql(u8, item.name, "set-cookie")) continue;
            jar.receive(jar.ptr, o.url, item.value);
        }
    }

    const kept = o.log.kept(o.log.ctx);
    exchange.head_value = .{
        .status = status,
        // Every response this engine reads arrived in HTTP/2 frames.
        .wire_version = .http_2,
        .content_length = exchange.content_length,
        // HTTP/2 frames its own body with `END_STREAM`. There is no
        // chunked transfer coding, and a `transfer-encoding` field is a
        // malformed response, which `validateResponseFields` already
        // refused.
        .transfer_encoding = .none,
        .location = fields.get("location"),
        .www_authenticate = pickChallenge(fields),
        // This engine keeps the whole decoded field list or none of it, so
        // no single challenge is ever dropped for its size. A head too
        // large is `ResponseHeadTooLarge` and reaches no caller at all.
        .www_authenticate_oversize = false,
        // `h1.Exchange.open` sets this on the exchange it sends again
        // without the credential. One send of one request withholds
        // nothing.
        .credential_withheld = false,
        .body_decoded = exchange.content_encoding != .identity,
        .headers = kept.all,
        .final_headers = kept.final,
        .headers_oversize = kept.dropped,
        // `h1.followChain` sets this on the exchange that ends a chain.
        .effective_url = null,
    };
}

/// The `HTTP2-Settings` field value for an `Upgrade: h2c` request.
///
/// RFC 7540 section 3.2.1: the payload of the `SETTINGS` frame this side
/// would have sent, in base64url with no padding. The peer reads it as the
/// client's settings for the connection it is about to switch to, so the
/// entries here and the entries `Session.create` writes are the same
/// entries, from the one call to `Session.wanted`.
///
/// Measured against curl 8.21.0: `curl --http2 http://host/path` sent
/// `HTTP2-Settings: AAMAAABkAAQAAQAAAAIAAAAA`, which is exactly this
/// encoding of curl's own three entries. zurl's entries differ in value,
/// because the two clients ask for different windows, and the encoding is
/// the same.
///
/// The text is written into `out` and the written part is returned.
/// `engine.http2_settings_len_max` is a buffer that always fits: the
/// payload is at most `zurl_h2.settings.payload_len_max` octets and
/// base64 grows it by four thirds.
pub fn settingsUpgradeText(out: []u8) []const u8 {
    var payload: [zurl_h2.settings.payload_len_max]u8 = undefined;
    const changes = Session.wanted().changesFrom(.initial);
    const bytes = changes.encode(&payload);

    const coder = std.base64.url_safe_no_pad.Encoder;
    std.debug.assert(out.len >= coder.calcSize(bytes.len));
    return coder.encode(out, bytes);
}

/// Whether a `101` response really switched to HTTP/2.
///
/// RFC 7540 section 3.2: the answer to an `Upgrade: h2c` request is `101`
/// with an `Upgrade` field naming `h2c`. A `101` naming anything else
/// switched to a protocol this build does not speak, and a `101` with no
/// `Upgrade` field at all named nothing. Neither is HTTP/2, and neither may
/// be read as if it were: the octets after such a head are whatever that
/// other protocol writes.
///
/// The comparison ignores case, because RFC 9110 section 7.8 makes a
/// protocol name case insensitive, and it ignores the space and the commas
/// around it, because the field is a list.
pub fn upgradedToH2c(upgrade_field: ?[]const u8) bool {
    const value = upgrade_field orelse return false;
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |raw| {
        const one = std.mem.trim(u8, raw, " \t");
        if (std.ascii.eqlIgnoreCase(one, "h2c")) return true;
    }
    return false;
}

/// Renders a trailer section the way `curl -D` writes it.
///
/// One `name: value\r\n` for each field, in the order they arrived. No
/// status line before them, because a trailer section is not a response
/// head, and no empty line after them, because nothing follows. Measured
/// against curl 8.21.0: a response carrying `grpc-status: 0` and
/// `x-end: yes` behind its body left exactly those two lines at the end of
/// the `-D` file, with no blank line closing them.
///
/// A pseudo header may not appear in a trailer section, RFC 9113 section
/// 8.1, and one that did would describe a message and not a trailer. The
/// same rule the head render keeps: a name starting with a colon is left
/// out.
///
/// The block is built in one allocation of a size counted first, so nothing
/// here grows a buffer while it writes. The field list is already bounded
/// by `header_list_len_max`, so the block is bounded with it.
fn renderTrailers(
    gpa: std.mem.Allocator,
    fields: zurl_hpack.FieldList,
) std.mem.Allocator.Error!?[]u8 {
    var len: usize = 0;
    var count: usize = 0;
    for (fields.fields.items) |item| {
        if (item.name.len != 0 and item.name[0] == ':') continue;
        len += item.name.len + ": ".len + item.value.len + "\r\n".len;
        count += 1;
    }
    // A trailer section of nothing but pseudo headers, or of nothing at
    // all, is not a trailer a caller can be shown. An empty block would
    // reach `-D` as no octets, which is the same as null, so this says so
    // rather than allocate a slice of length zero and hand it over.
    if (count == 0) return null;

    const block = try gpa.alloc(u8, len);
    errdefer gpa.free(block);

    var w: std.Io.Writer = .fixed(block);
    // **Every write below fits, because `len` counted each one over the
    // same list, with the same filter, at the same width.** So a write that
    // did not fit would be an arithmetic error in the loop above and never
    // a peer's octets, which is what makes an assert the right answer here
    // and not an error a caller handles. The assert after the loop is what
    // proves the two agree, and it runs in a debug build, where such an
    // error is found.
    for (fields.fields.items) |item| {
        if (item.name.len != 0 and item.name[0] == ':') continue;
        w.writeAll(item.name) catch unreachable;
        w.writeAll(": ") catch unreachable;
        w.writeAll(item.value) catch unreachable;
        w.writeAll("\r\n") catch unreachable;
    }
    std.debug.assert(w.buffered().len == len);
    return block;
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
/// The rule is `contentLengthField`, which `h1` and `h3` keep too. This
/// engine took the first field of that name and never looked at a second,
/// so a head of `content-length: 2` and `content-length: 8` reached a
/// caller as a legal head.
fn readContentLength(fields: zurl_hpack.FieldList) Fault!?u64 {
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
/// `identity`, which handed the caller the compressed octets of a
/// `content-encoding: br` answer as if they were the body, while `h1`
/// reported a read error for the same head. Three engines deciding apart
/// is how that came about, so all three now ask one function.
fn readContentEncoding(
    fields: zurl_hpack.FieldList,
    accept_encoding: bool,
) Fault!std.http.ContentEncoding {
    return engine.contentEncoding(fields.get("content-encoding"), accept_encoding);
}

/// The `www-authenticate` value a caller answers, out of the ones a
/// response carried.
///
/// **The first header that offers `Digest`, and the first of any kind when
/// none does.** A server that lists `Basic` in one field and `Digest` in
/// the next would otherwise get a `Basic` answer, which sends the password
/// in reversible base64 to a server that had offered a scheme where the
/// password never travels.
///
/// `h1.Exchange.sendOn` holds this same rule over an HTTP/1.1 head. The two
/// cannot be one call: an HTTP/1.1 head is a block of octets walked with
/// `std.http.HeaderIterator`, and an HTTP/2 head is a decoded field list,
/// so the loops read different shapes. The rule they share is
/// `zurl_core.auth.hasDigestChallenge`, which is one function and is called
/// from both.
fn pickChallenge(fields: zurl_hpack.FieldList) ?[]const u8 {
    var first: ?[]const u8 = null;
    for (fields.fields.items) |item| {
        if (!std.mem.eql(u8, item.name, "www-authenticate")) continue;
        if (zurl_core.auth.hasDigestChallenge(item.value)) return item.value;
        if (first == null) first = item.value;
    }
    return first;
}

/// Writes the response head into the engine's log, the way `curl -D`
/// writes it over HTTP/2.
///
/// `HTTP/2 200 `, with the trailing space and no reason phrase, then one
/// line for each ordinary field, then the empty line. Measured against curl
/// 8.21.0: HTTP/2 has no reason phrase to write, so curl writes the version
/// and the status alone.
///
/// The block is built in one allocation of a size computed first, so
/// nothing here grows a buffer while it writes. The field list is already
/// bounded by `header_list_len_max`, so the block is bounded with it.
fn recordHead(o: Open, status: u16, fields: zurl_hpack.FieldList) Fault!void {
    // **The status is written at exactly three characters, so the count
    // and the write agree for every status the peer can send.** RFC 9113
    // section 8.3.2 makes `:status` exactly three digits, and `readStatus`
    // refuses anything else, so a peer that sent `007` means a status of 7
    // that it wrote in three characters. `{d}` printed that number at its
    // natural width, one character, while the block above was sized for
    // three. The two octets left over were heap this side never wrote, and
    // the assert that caught the mismatch is removed in ReleaseFast and
    // ReleaseSmall, so a release build handed those octets to the head log
    // and from there to a `-D` file. `h3.recordHead` closed the same
    // defect with the same writer, which is why one is shared now.
    var digits: [status_text_len]u8 = undefined;
    engine.writeStatusDigits(status, &digits);

    const status_line_len = "HTTP/2 ".len + status_text_len + " \r\n".len;
    var len: usize = status_line_len;
    for (fields.fields.items) |item| {
        if (item.name.len != 0 and item.name[0] == ':') continue;
        len += item.name.len + ": ".len + item.value.len + "\r\n".len;
    }
    len += "\r\n".len;

    const block = try o.gpa.alloc(u8, len);
    defer o.gpa.free(block);

    var w: std.Io.Writer = .fixed(block);
    // **Every write below fits, because `len` counted each one at the
    // width it is written at.** The status line is `status_line_len`
    // octets whatever the status, and each field adds its own two slices
    // and the four octets around them. So a write that did not fit would
    // be an arithmetic error in the loop above and never a peer's octets,
    // which is what makes an assert the right answer and not an error.
    //
    // The assert below is the one that proves it, and it is the assert a
    // release build removes. So the count and the write are held together
    // by the shared writer above rather than by the assert alone.
    w.writeAll("HTTP/2 ") catch unreachable;
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

/// A piece of the request scratch buffer, held as an offset because the
/// buffer moves while it grows.
const Span = struct { at: usize, len: usize };

fn span(scratch: std.ArrayList(u8), s: Span) []const u8 {
    return scratch.items[s.at..][0..s.len];
}

/// Appends the request target: the path and the query, and never the
/// fragment. RFC 9113 section 8.3.1 keeps a fragment out of `:path`, the
/// same way RFC 9112 keeps one out of a request line.
///
/// A target with no path names the root. RFC 9113 section 8.3.1 says
/// `:path` may not be empty for an `http` or `https` url.
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
///
/// Heap-allocated, because it must outlive the frame that opened it and
/// because `body` and `raw` hold the address of fields inside it. `close`
/// is its only path back to the allocator, and the only thing that hands
/// the connection back.
const Exchange = struct {
    interface: engine.Exchange,
    gpa: std.mem.Allocator,
    /// Borrowed. The connection owns it, and it outlives this exchange.
    session: *Session,
    peer: Peer,
    stream: Stream,
    head_value: engine.Head,
    content_length: ?u64,
    content_encoding: std.http.ContentEncoding,
    /// How many body octets arrived, before any content decoding. Checked
    /// against `content_length` at the end of the body.
    body_received: u64,
    body_taken: bool,
    /// Whether the transfer stopped before its announced content length.
    /// `check` reports this as `error.PartialFile`.
    body_partial: bool,
    /// Whether `finishFraming` ran. It runs once, at the end of the
    /// content stream, and a later read of the same ended reader must not
    /// start it again.
    framing_finished: bool,
    /// Whether the peer sent body octets after the content decoding ended.
    ///
    /// Those octets stay on the connection, so the connection must not go
    /// back to the pool. See `finishFraming`.
    body_overrun: bool,
    /// Why a body read failed, when one did.
    ///
    /// A `std.Io.Reader` has a closed error set and reports every failure
    /// as `error.ReadFailed`, so the reason would be lost without this.
    /// Recovery is never silent: `bodyCause` hands the name back.
    body_fault: ?Fault,
    /// How many frames that carried no progress this exchange has read.
    ///
    /// **A field and not a local, so the count covers the transfer.** It
    /// used to start at zero on every call of `rawChunk`, so a peer that
    /// sent 1023 `PING` frames, then one body octet, then 1023 more, never
    /// reached `idle_frames_max` at all. The bound was real for a peer that
    /// stopped making progress, and absent for a peer that made one byte of
    /// progress at a time. Now it only grows, so the whole transfer carries
    /// one budget. See `idle_frames_max`.
    idle_frames: usize,
    /// Body octets that arrived and were not handed to the caller yet.
    ///
    /// **They point into the frame reader's buffer.** Nothing may read
    /// another frame while this is not empty, which `rawChunk` is the one
    /// place that keeps.
    pending: []const u8,
    /// The reader that pulls `DATA` frames. Any content decoding sits in
    /// front of it.
    raw: std.Io.Reader,
    transfer_buffer: [transfer_buffer_len]u8,
    /// The reader `bodyReader` hands out.
    body: std.Io.Reader,
    /// What `body` reads from: `raw`, with any content decoding in front.
    body_source: *std.Io.Reader,
    decompress: std.http.Decompress,
    decompress_buffer: [decompress_buffer_len]u8,
    /// The window a zstd answer decodes through, or null for every other
    /// answer. Owned, `zstd_buffer_len` octets, freed by `close`. See
    /// `zstd_buffer_len` for why it is not inline.
    zstd_buffer: ?[]u8,
    /// The rendered trailer section, or null before the first ask and when
    /// the peer sent none. Owned. See `trailersImpl`.
    trailer_text: ?[]u8,
    /// The scratch a redirect chain walked in, when this exchange answered
    /// the hop that ended one.
    ///
    /// `engine.Head.effective_url` points into it, so the memory has to
    /// live as long as this exchange does. Null when this exchange
    /// answered the url the caller named. Freed by `close`.
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

    /// The trailer section, rendered on the first call and kept after it.
    ///
    /// **Rendered here and not when the block arrived.** A trailer section
    /// arrives inside a body read, and a body read reports one error name
    /// and has nowhere to put an allocation fault. So the fields are kept
    /// as they were decoded, and the text is built when a caller asks for
    /// it, where a failure can be answered with null.
    ///
    /// Null covers three cases and a caller reads them the same way: the
    /// peer sent no trailer, the body has not ended yet, and the render ran
    /// out of memory. The first two are the ordinary ones. See
    /// `engine.Exchange.trailers`.
    fn trailersImpl(ptr: *anyopaque) ?[]const u8 {
        const self: *Exchange = @ptrCast(@alignCast(ptr));
        if (self.trailer_text) |text| return text;
        const fields = self.stream.trailer_fields orelse return null;
        const text = renderTrailers(self.gpa, fields) catch return null;
        self.trailer_text = text;
        return text;
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

    const raw_vtable: std.Io.Reader.VTable = .{ .stream = rawStream, .discard = rawDiscard };
    const body_vtable: std.Io.Reader.VTable = .{ .stream = bodyStream, .discard = bodyDiscard };

    fn headImpl(ptr: *anyopaque) engine.Head {
        const self: *Exchange = @ptrCast(@alignCast(ptr));
        return self.head_value;
    }

    fn bodyReaderImpl(ptr: *anyopaque, buffer: []u8) *std.Io.Reader {
        const self: *Exchange = @ptrCast(@alignCast(ptr));
        // One exchange has one body. A second reader would restart the
        // framing over a stream that already moved.
        std.debug.assert(!self.body_taken);
        self.body_taken = true;

        self.raw = .{
            .vtable = &raw_vtable,
            .buffer = &self.transfer_buffer,
            .seek = 0,
            .end = 0,
        };
        self.body_source = self.decompress.init(
            &self.raw,
            // The zstd window when the answer is zstd, and the flate
            // window otherwise. `openInner` took the first one where the
            // head said so.
            self.zstd_buffer orelse &self.decompress_buffer,
            self.content_encoding,
        );
        self.body = .{
            .vtable = &body_vtable,
            .buffer = buffer,
            .seek = 0,
            .end = 0,
        };
        return &self.body;
    }

    /// The next run of body octets, or the end of the body.
    ///
    /// **The inbox is read before the connection is.** That order is what
    /// keeps several streams on one connection from deadlocking. Octets
    /// sitting in an inbox hold the connection window down, and the window
    /// only opens again when their owner takes them. An owner that read a
    /// frame first, with its own octets already waiting, could sit on a
    /// closed window that nobody else can open. Reading the inbox first
    /// means a stream never waits for a frame while holding octets of its
    /// own, so some stream can always make room. See `Session.creditReceive`.
    ///
    /// The octets of a frame point into the frame reader's buffer, so this
    /// reads no further frame while the caller still holds some. Octets out
    /// of the inbox are this exchange's own memory and have no such rule,
    /// but they are handed back the same way so one path serves both.
    fn rawChunk(self: *Exchange) std.Io.Reader.Error![]const u8 {
        if (self.pending.len != 0) return self.pending;
        if (self.session.shared) return self.rawChunkShared();
        return self.rawChunkOwned();
    }

    /// `rawChunk` for a session two tasks drive.
    ///
    /// **The frame buffer never leaves the lock.** A shared session copies
    /// every `DATA` payload into the stream it belongs to, this stream
    /// included, so what this hands out is the stream's own memory and not
    /// the connection's. The hand-over costs two pointer moves: see
    /// `Stream.taken`.
    fn rawChunkShared(self: *Exchange) std.Io.Reader.Error![]const u8 {
        const session = self.session;
        session.acquire();
        defer session.release();

        var seen = session.progress;
        while (true) {
            // The buffer this owner handed out last is spent. Its room goes
            // back once, here, and the empty list is reused as the next
            // inbox. Doing it here and not on each read keeps one
            // `WINDOW_UPDATE` for a whole buffer.
            if (self.stream.taken.items.len != 0) {
                const spent = self.stream.taken.items.len;
                self.stream.taken.clearRetainingCapacity();
                session.creditTaken(spent) catch |err| return self.bodyFault(err);
            }
            if (self.stream.inbox.items.len != 0) {
                std.mem.swap(std.ArrayList(u8), &self.stream.taken, &self.stream.inbox);
                self.stream.inbox_at = 0;
                try self.countBody(self.stream.taken.items.len);
                self.pending = self.stream.taken.items;
                return self.pending;
            }
            if (self.stream.ended) return self.endOfBody();

            if (self.idle_frames >= idle_frames_max) return self.bodyFault(error.PeerStalled);
            switch (session.step(&self.stream) catch |err| return self.bodyFault(err)) {
                // **A shared session hands no frame buffer out, so nothing
                // reaches this today.** See `Step.data`. The octets are
                // kept rather than dropped, because a body that lost a
                // frame is a fault nobody would see: it would come out
                // short and the length check would call the peer a liar.
                .data => |bytes| self.stream.inbox.appendSlice(session.gpa, bytes) catch
                    return self.bodyFault(error.OutOfMemory),
                // The end is read off the stream at the top of this loop,
                // after the last of the inbox has gone out.
                .ended => {},
                // Another task read a frame. Nothing was read here, so no
                // idle budget is spent. See `Step.waited`.
                .waited => {},
                .idle, .head => self.idle_frames += 1,
            }
            // A frame that moved another stream along is not an idle frame
            // for this one. See `idle_frames_max`.
            if (session.progress != seen) {
                seen = session.progress;
                self.idle_frames = 0;
            }
        }
    }

    /// `rawChunk` for a session this task owns alone. Byte for byte what
    /// this engine did before a session could be shared.
    fn rawChunkOwned(self: *Exchange) std.Io.Reader.Error![]const u8 {
        const held = self.stream.buffered();
        if (held.len != 0) {
            // Handed out whole. `pending` carries whatever the caller does
            // not take this time, so the mark goes to the end here and the
            // room goes back once, below, when `pending` has run out.
            self.stream.inbox_at = self.stream.inbox.items.len;
            try self.countBody(held.len);
            self.pending = held;
            return held;
        }
        // Everything the inbox held has been taken, so the room for it goes
        // back and the list starts again from empty. Doing this here and
        // not on each read keeps one `WINDOW_UPDATE` for a whole inbox.
        if (self.stream.inbox.items.len != 0) {
            const spent = self.stream.inbox.items.len;
            self.stream.inbox.clearRetainingCapacity();
            self.stream.inbox_at = 0;
            self.session.creditTaken(spent) catch |err| return self.bodyFault(err);
        }

        if (self.stream.ended) return self.endOfBody();

        var seen = self.session.progress;
        while (true) {
            if (self.idle_frames >= idle_frames_max) return self.bodyFault(error.PeerStalled);
            const got = self.session.step(&self.stream) catch |err| return self.bodyFault(err);
            switch (got) {
                .data => |bytes| {
                    try self.countBody(bytes.len);
                    self.pending = bytes;
                    return bytes;
                },
                .ended => return self.endOfBody(),
                // **A session this task owns alone has no second task to
                // wait for, and this arm is what happens if one appears.**
                // `Session.step` answers `.waited` only where `shared` is
                // true, and `rawChunk` sends a shared session to
                // `rawChunkShared`, so nothing reaches this today. It used
                // to be `unreachable`, which is undefined behaviour in
                // ReleaseFast and ReleaseSmall: a later arm that answered
                // `.waited` from an unshared session would run off the
                // switch in the build a user runs. Counting it as an idle
                // frame is what `rawChunkShared` does with a real wait,
                // and it keeps the loop bounded by `idle_frames_max`
                // whatever the answer. See `Step.waited`.
                .waited => self.idle_frames += 1,
                // A second head is the trailer section, which
                // `Session.finishBlock` already took. Anything else here
                // carried no body octet.
                //
                // The count never goes back to zero for a connection that
                // is answering nobody. One body octet must not buy another
                // whole budget of frames that carry none.
                .idle, .head => self.idle_frames += 1,
            }
            // A frame that moved another stream along is not an idle frame
            // for this one. See `idle_frames_max`.
            if (self.session.progress != seen) {
                seen = self.session.progress;
                self.idle_frames = 0;
            }
        }
    }

    /// Counts `octets` of body against the length the head announced, and
    /// fails the transfer when they run past it.
    ///
    /// **The bound is the one rule `bodyWithinContentLength` holds, and
    /// `h3.Exchange.countBody` asks the same one.** This engine used to
    /// count only upward, and `endOfBody` asked whether the body had come
    /// out short. A body that came out long met nothing at all, so a head
    /// of `content-length: 2` and eight octets of `DATA` handed a caller
    /// all eight and exited 0, while `h1` handed the same caller two.
    ///
    /// The count is taken where the octets go out to the caller, not where
    /// they arrive. What is buffered before that is bounded by the
    /// flow-control window, which is this side's own number, so nothing
    /// grows without a bound either way, and one place to count beats
    /// three.
    ///
    /// **The fault is `MalformedResponse` and not `PartialFile`.** RFC
    /// 9113 section 8.1.1 makes it a stream error, `engine.BodyError`
    /// names only a body that stopped short, and this body did the
    /// opposite. So `check` stays quiet and the caller reads `ReadError`,
    /// which is exit 56 and the answer every other malformed HTTP/2
    /// response gets from this engine. curl 8.21.0 gives 92 for the same
    /// response, which is a code this build has no name for.
    fn countBody(self: *Exchange, octets: usize) std.Io.Reader.Error!void {
        self.body_received += octets;
        engine.bodyWithinContentLength(self.content_length, self.body_received) catch
            return self.bodyFault(error.MalformedResponse);
    }

    /// Answers the end of the transfer.
    ///
    /// A peer that announced a content length and stopped before it has cut
    /// the body, so the stream ends with a failure and `check` names it.
    /// The count is of octets before any content decoding, which is what
    /// `content-length` counts.
    fn endOfBody(self: *Exchange) std.Io.Reader.Error {
        if (self.content_length) |announced| {
            if (self.body_received < announced) {
                self.body_partial = true;
                return error.ReadFailed;
            }
        }
        return error.EndOfStream;
    }

    /// Turns a fault of the session into the one name a `std.Io.Reader`
    /// can report, and records why, so `check` can say more than
    /// `ReadFailed`.
    ///
    /// **Every fault is a failure, and the end of the connection is one of
    /// them.** An HTTP/2 body ends on the `END_STREAM` flag and on nothing
    /// else, so a peer that dropped the connection part way through did
    /// not end the body: it cut it. `endOfBody` is the one path that
    /// answers a clean end, and it is reached only from `Step.ended`.
    fn bodyFault(self: *Exchange, fault: Fault) std.Io.Reader.Error {
        // **The fault is kept, not dropped.** A `std.Io.Reader` reports
        // one name for every failure, so the reason would be lost here.
        // `bodyCause` is where a caller reads it back.
        self.body_fault = fault;
        if (self.content_length) |announced| {
            if (self.body_received < announced) self.body_partial = true;
        }
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

    /// Reads the frames that are left after the content decoding ended.
    ///
    /// **A content decoder ends at the end of its own stream, and not at
    /// the end of the HTTP/2 stream.** `gzip` and `deflate` stop at the
    /// last octet of the compressed member and ask for nothing more. A
    /// peer that carries `END_STREAM` on a frame after that member
    /// therefore leaves `Stream.ended` false, although the answer is
    /// whole. `reusable` reads `Stream.ended`, so the connection would be
    /// closed and the next request would pay a fresh handshake.
    ///
    /// The Cloudflare edge answers in exactly that shape: one `DATA`
    /// frame carries the compressed body and no flag, and one empty
    /// `DATA` frame carries `END_STREAM` after it. A trailer section has
    /// the same shape, because it arrives in a `HEADERS` frame that comes
    /// after the last body octet.
    ///
    /// So this reads on until the framing ends the stream. It is bounded
    /// the way every other body read is: by `idle_frames_max`, and by the
    /// faults the session reports. It runs only where the content stream
    /// ended cleanly, so a body a caller abandoned still closes its
    /// connection.
    ///
    /// **No body octet is discarded here.** A peer that sends body octets
    /// after the compressed member disagrees with its own content
    /// encoding. Those octets are left where they are and `body_overrun`
    /// keeps the connection out of the pool, because a pooled connection
    /// with unread octets would hand them to the next request.
    fn finishFraming(self: *Exchange) void {
        if (self.framing_finished) return;
        self.framing_finished = true;
        // **Octets the content decoding never asked for are already
        // here.** They sit in the raw reader's own buffer, or in the run
        // this exchange handed out last and the decoder did not take
        // whole. Either one says the peer sent more body than its own
        // content encoding used.
        if (self.raw.bufferedLen() != 0 or self.pending.len != 0) {
            self.body_overrun = true;
            return;
        }
        while (!self.stream.ended) {
            // `rawChunk` hands out no empty run: it answers octets, or it
            // reports the end of the stream, or it reports a fault. Both
            // reports are recorded already, and both end the loop.
            const chunk = self.rawChunk() catch return;
            self.pending = chunk[chunk.len..];
            self.body_overrun = true;
            return;
        }
    }

    fn bodyStream(
        io_reader: *std.Io.Reader,
        w: *std.Io.Writer,
        limit: std.Io.Limit,
    ) std.Io.Reader.StreamError!usize {
        const self: *Exchange = @alignCast(@fieldParentPtr("body", io_reader));
        return self.body_source.stream(w, limit) catch |err| {
            if (err == error.EndOfStream) self.finishFraming();
            return err;
        };
    }

    fn bodyDiscard(io_reader: *std.Io.Reader, limit: std.Io.Limit) std.Io.Reader.Error!usize {
        const self: *Exchange = @alignCast(@fieldParentPtr("body", io_reader));
        return self.body_source.discard(limit) catch |err| {
            if (err == error.EndOfStream) self.finishFraming();
            return err;
        };
    }

    fn checkImpl(ptr: *anyopaque) engine.BodyError!void {
        const self: *Exchange = @ptrCast(@alignCast(ptr));
        // **The deadline is reported before the short body.** A body the
        // peer stopped feeding is also a body that never reached its
        // announced length, so both can stand together and the one that
        // says why is this one. A caller told `PartialFile` looks for a
        // truncated file; a caller told `OperationTimedOut` looks at the
        // peer that went quiet. `h1.Exchange.check` orders the two the
        // same way.
        if (self.body_fault) |fault| {
            if (fault == error.OperationTimedOut) return error.OperationTimedOut;
        }
        if (self.body_partial) return error.PartialFile;
    }

    /// Why a body read failed, when the reason has a name of its own.
    ///
    /// `check` answers the one fault the seam names, which is a transfer
    /// that stopped before its announced length. This is the whole set,
    /// for a caller that wants the frame-layer or HPACK name behind a
    /// `ReadFailed`.
    fn bodyCause(self: *const Exchange) ?Fault {
        return self.body_fault;
    }

    /// Whether the connection may serve another request.
    ///
    /// **Every one of these is a rule that keeps one response out of the
    /// next one.** A false answer costs a dial. A wrong true answer hands
    /// the next request octets of this one.
    ///
    /// - The session must be usable: no `GOAWAY`, no connection error, and
    ///   a stream counter with room left.
    /// - The peer must have ended the stream, and must not have reset it.
    ///   A stream the peer left open still has frames on the way, and the
    ///   next request would read them before its own answer.
    ///
    ///   A `RST_STREAM` this side sent after a whole answer is not such a
    ///   case: the peer has nothing left to send on that stream, so the
    ///   connection is at the start of the next one.
    /// - A short transfer is not an end.
    /// - Body octets that arrived after the content decoding ended are
    ///   still on the connection. See `finishFraming`.
    /// - A read or a write that failed leaves the connection at a place
    ///   nothing here knows. `zurl_net.Connection` keeps both faults, so
    ///   this reads them rather than guess.
    /// The caller holds the session lock. `closeImpl` is the one caller.
    fn reusable(self: *const Exchange) bool {
        if (!self.session.usableLocked()) return false;
        if (!self.stream.ended) return false;
        if (self.stream.reset != null) return false;
        if (self.body_partial) return false;
        if (self.body_overrun) return false;
        if (self.session.conn.readError() != null) return false;
        if (self.session.conn.writeError() != null) return false;
        return true;
    }

    fn closeImpl(ptr: *anyopaque) void {
        const self: *Exchange = @ptrCast(@alignCast(ptr));
        const session = self.session;

        // **The session lock is let go before `peer.release`.** The pool
        // takes its own lock inside that call, and the pool takes the
        // session lock while it holds it: it reads `usable` and `hasRoom`
        // to decide whether a connection may carry one more stream. So the
        // order is always the pool's lock and then the session's, and a
        // close that held the session's while it asked for the pool's would
        // be the one path that ran the two the other way round.
        session.acquire();

        // **A stream that either side left open is reset.** RFC 9113
        // section 8.1 asks a client that stops sending a request body, or
        // that stops reading a response, to send `RST_STREAM`. Two shapes
        // reach this:
        //
        // - The caller stopped reading the body, so the peer is still
        //   spending its window on octets nobody reads.
        // - The peer answered while the request body was still going out,
        //   which section 8.1 allows. This side then never sent
        //   `END_STREAM`, so the stream stays open on this side even
        //   though the answer is whole, and it holds a slot the peer
        //   counts against `SETTINGS_MAX_CONCURRENT_STREAMS`.
        //
        // Best effort. A write that fails leaves the connection unfit for
        // reuse, which `reusable` reads off the connection itself.
        const unfinished = !self.stream.ended or !self.stream.sent_end;
        if (unfinished and self.stream.reset == null and !self.session.broken) {
            self.session.writeRstStream(self.stream.id, .cancel) catch {};
            self.session.flushWrites() catch {};
        }

        const keep = self.reusable();
        // **The stream leaves the table before the exchange leaves memory.**
        // The session holds this stream's address, so a session that still
        // held it would apply the next frame that names the identifier to
        // freed memory. `forget` also gives back the room the inbox holds,
        // which the peer would otherwise never see again.
        self.session.forget(&self.stream);
        session.release();

        self.stream.deinit(self.gpa);
        if (self.trailer_text) |text| self.gpa.free(text);
        if (self.chain_storage) |storage| self.gpa.free(storage);
        // Null for every answer that was not zstd, which is nearly all of
        // them. See `zstd_buffer_len`.
        if (self.zstd_buffer) |buffer| self.gpa.free(buffer);
        self.peer.release(self.peer.ctx, self.peer.handle, keep);
        self.gpa.destroy(self);
    }
};

const h2_test_server = @import("h2_test_server.zig");

/// One loopback HTTP/2 client, and the two seams `open` needs.
///
/// **No TLS and no network.** `h1` reaches HTTP/2 through the ALPN answer
/// of a handshake, and a test may open no such session. So a test dials the
/// frame fixture over cleartext and drives `open` itself, which is what
/// makes the whole engine reachable offline.
const TestClient = struct {
    conn: zurl_net.Connection,
    session: *Session,
    /// The head log, which stands for `h1.Engine.head_log`.
    heads: [16 * 1024]u8,
    heads_used: usize,
    heads_final: usize,
    heads_dropped: bool,
    /// What `Exchange.close` decided, and whether it decided at all.
    released: bool,
    kept: bool,
    answered: bool,
    body_sent: bool,

    /// Opens a session with the engine's own read ceiling, which is the
    /// bound an ordinary transfer runs under. A test of the deadline calls
    /// `connectWith` and names a short one.
    fn connect(self: *TestClient, gpa: std.mem.Allocator, port: u16) !void {
        return self.connectWith(gpa, port, engine.default_read_timeout);
    }

    fn connectWith(
        self: *TestClient,
        gpa: std.mem.Allocator,
        port: u16,
        read_timeout: std.Io.Timeout,
    ) !void {
        self.heads_used = 0;
        self.heads_final = 0;
        self.heads_dropped = false;
        self.released = false;
        self.kept = false;
        self.answered = false;
        self.body_sent = false;

        const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
        const stream = try address.connect(testing.io, .{ .mode = .stream });
        errdefer stream.close(testing.io);
        try self.conn.init(gpa, testing.io, stream, .{ .read_buffer_len = 64 * 1024 });
        errdefer self.conn.deinit();
        self.session = try Session.create(gpa, &self.conn, read_timeout);
    }

    fn deinit(self: *TestClient) void {
        self.session.destroy();
        self.conn.deinit();
    }

    fn recordImpl(ctx: *anyopaque, head: []const u8) std.mem.Allocator.Error!void {
        const self: *TestClient = @ptrCast(@alignCast(ctx));
        if (self.heads_used + head.len > self.heads.len) {
            // The whole log goes, never a part of a head. `h1.logHead`
            // answers a head past its own bound the same way.
            self.heads_used = 0;
            self.heads_dropped = true;
            return;
        }
        self.heads_final = self.heads_used;
        @memcpy(self.heads[self.heads_used..][0..head.len], head);
        self.heads_used += head.len;
    }

    fn keptImpl(ctx: *anyopaque) HeadLog.Kept {
        const self: *TestClient = @ptrCast(@alignCast(ctx));
        if (self.heads_dropped or self.heads_used == 0) {
            return .{ .all = null, .final = null, .dropped = self.heads_dropped };
        }
        return .{
            .all = self.heads[0..self.heads_used],
            .final = self.heads[self.heads_final..self.heads_used],
            .dropped = false,
        };
    }

    fn releaseImpl(ctx: *anyopaque, handle: *anyopaque, keep: bool) void {
        _ = handle;
        const self: *TestClient = @ptrCast(@alignCast(ctx));
        self.released = true;
        self.kept = keep;
    }

    fn log(self: *TestClient) HeadLog {
        return .{ .ctx = self, .record = recordImpl, .kept = keptImpl };
    }

    fn peer(self: *TestClient) Peer {
        // The connection is the test's, not the pool's, so `release`
        // records the answer and closes nothing. `deinit` is what closes.
        return .{ .ctx = self, .handle = self, .release = releaseImpl };
    }

    /// Sends one request and reads its head.
    fn send(self: *TestClient, o: Send) engine.OpenError!*engine.Exchange {
        return open(.{
            .gpa = testing.allocator,
            .session = self.session,
            .method = o.method,
            .uri = testUri(o.path),
            .authority = "127.0.0.1",
            .user_agent = o.user_agent,
            .accept_encoding = o.accept_encoding,
            .headers = o.headers,
            .body = o.body,
            .url = testUrl(),
            .cookies = o.cookies,
            .log = self.log(),
            .peer = self.peer(),
            .answered = &self.answered,
            .body_sent = &self.body_sent,
        });
    }

    const Send = struct {
        method: std.http.Method = .GET,
        path: []const u8 = "/",
        user_agent: []const u8 = "zurl/test",
        /// False, the same default `engine.Request.accept_encoding` has, so
        /// a test that says nothing sends the head a plain `curl` sends.
        accept_encoding: bool = false,
        headers: []const std.http.Header = &.{},
        body: ?engine.Body = null,
        cookies: ?engine.CookieJar = null,
    };
};

fn testUri(path: []const u8) std.Uri {
    return .{
        .scheme = "http",
        .user = null,
        .password = null,
        .host = .{ .raw = "127.0.0.1" },
        .port = null,
        .path = .{ .percent_encoded = path },
        .query = null,
        .fragment = null,
    };
}

fn testUrl() zurl_core.Url {
    return zurl_core.url.parse("http://127.0.0.1/") catch unreachable;
}

/// Reads a whole response body through the seam a caller reads it through.
fn readBody(exchange: *engine.Exchange) ![]u8 {
    var buffer: [4096]u8 = undefined;
    const reader = exchange.bodyReader(&buffer);
    return reader.allocRemaining(testing.allocator, .unlimited);
}

test "a GET over HTTP/2 reaches the status, the head log, and the body" {
    var server: h2_test_server.H2TestServer = undefined;
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
    const head = exchange.head();
    try testing.expectEqual(@as(u16, 200), head.status);
    try testing.expectEqual(@as(?u64, 5), head.content_length);
    try testing.expectEqual(std.http.TransferEncoding.none, head.transfer_encoding);
    try testing.expect(!head.body_decoded);

    // **The head block, the way `curl -D` writes it over HTTP/2.** The
    // status line carries no reason phrase, because HTTP/2 has none, and
    // the pseudo header is not a line.
    try testing.expectEqualStrings(
        "HTTP/2 200 \r\ncontent-type: text/plain\r\ncontent-length: 5\r\n\r\n",
        head.final_headers.?,
    );
    try testing.expectEqualStrings(head.final_headers.?, head.headers.?);
    try testing.expect(!head.headers_oversize);

    const body = try readBody(exchange);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("hello", body);
    try exchange.check();

    exchange.close();
    try testing.expect(client.released);
    // A stream the peer ended cleanly leaves the connection fit for a
    // second request.
    try testing.expect(client.kept);
    try testing.expect(client.answered);

    // **The four pseudo headers, in the order RFC 9113 section 8.3.1
    // names, before every ordinary field.**
    const sent = server.requestHead(0).?;
    try testing.expect(std.mem.startsWith(
        u8,
        sent,
        ":method: GET\r\n:scheme: http\r\n:authority: 127.0.0.1\r\n:path: /thing?q=1\r\n",
    ));
    try testing.expectEqualStrings("zurl/test", server.requestField(0, "user-agent").?);
    // **No offer, no field.** This request named no `--compressed`, so it
    // sends no `accept-encoding` at all, which is what curl sends. The
    // test asserted `gzip, deflate` here while zurl offered on every
    // request; measured against curl 8.21.0 on a loopback listener, a
    // plain `curl` writes no such header.
    try testing.expectEqual(@as(?[]const u8, null), server.requestField(0, "accept-encoding"));
}

test "an offer writes one accept-encoding field, and only with the offer" {
    // The other half of the rule above. `--compressed` reaches this engine
    // as `Open.accept_encoding`, and the field it writes is the one `h1`
    // writes on an HTTP/1.1 head, so a peer answers both engines with the
    // same body.
    var server: h2_test_server.H2TestServer = undefined;
    try server.start(&.{.{ .fields = &.{.{ .name = ":status", .value = "204" }} }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var exchange = try client.send(.{ .accept_encoding = true });
    exchange.close();

    try testing.expectEqualStrings(
        accept_encoding_value,
        server.requestField(0, "accept-encoding").?,
    );
}

test "this engine gives the same answer h1 gives, on both sides of the offer" {
    // **The defect a rule per engine produced.** This engine read an
    // unknown token as `identity` and handed the caller compressed octets
    // at exit 0, while `h1` reported a read error for the same head.
    // Neither matched curl. `engine.contentEncoding` is now the one rule
    // and this engine keeps none of its own.
    const gpa = testing.allocator;
    for ([_][]const u8{ "br", "gzip, br", "exotic", "compress" }) |coding| {
        // With the offer: refused by name, which is curl's exit 61.
        {
            var server: h2_test_server.H2TestServer = undefined;
            try server.start(&.{.{
                .fields = &.{
                    .{ .name = ":status", .value = "200" },
                    .{ .name = "content-encoding", .value = coding },
                },
                .body = "ABCD",
            }});
            defer server.stop();

            var client: TestClient = undefined;
            try client.connect(gpa, server.port());
            defer client.deinit();

            try testing.expectError(
                error.BadContentEncoding,
                client.send(.{ .accept_encoding = true }),
            );
        }

        // Without it: the octets reach the caller as the peer sent them,
        // which is what curl writes out at exit 0.
        {
            var server: h2_test_server.H2TestServer = undefined;
            try server.start(&.{.{
                .fields = &.{
                    .{ .name = ":status", .value = "200" },
                    .{ .name = "content-encoding", .value = coding },
                },
                .body = "ABCD",
            }});
            defer server.stop();

            var client: TestClient = undefined;
            try client.connect(gpa, server.port());
            defer client.deinit();

            var exchange = try client.send(.{});
            defer exchange.close();
            try testing.expect(!exchange.head().body_decoded);

            const body = try readBody(exchange);
            defer gpa.free(body);
            try testing.expectEqualStrings("ABCD", body);
        }
    }

    // And a field the peer left empty is the plain body, not a refusal.
    try testing.expectEqual(
        std.http.ContentEncoding.identity,
        try readContentEncoding(.empty, true),
    );
}

test "a caller's own accept-encoding field is the only one that goes out" {
    // Two offers on one request name two sets, and a peer may answer
    // either. `h1.sendOnH2` raises the flag from the same header, which is
    // why this passes both.
    var server: h2_test_server.H2TestServer = undefined;
    try server.start(&.{.{ .fields = &.{.{ .name = ":status", .value = "204" }} }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var exchange = try client.send(.{
        .accept_encoding = true,
        .headers = &.{.{ .name = "accept-encoding", .value = "gzip" }},
    });
    exchange.close();

    const sent = server.requestHead(0).?;
    try testing.expectEqualStrings("gzip", server.requestField(0, "accept-encoding").?);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sent, "accept-encoding: "));
}

test "a caller header goes out lower case, and its value goes out as it was written" {
    // RFC 9113 section 8.2.1: a field name on the wire is lower case, and a
    // peer must treat an upper-case one as malformed. A caller writes `-H
    // 'X-Thing: A'` as readily as `-H 'x-thing: A'`.
    var server: h2_test_server.H2TestServer = undefined;
    try server.start(&.{.{ .fields = &.{.{ .name = ":status", .value = "204" }} }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var exchange = try client.send(.{ .headers = &.{
        .{ .name = "X-Thing", .value = "MixedValue" },
        .{ .name = "Authorization", .value = "Basic abc" },
    } });
    defer exchange.close();
    try testing.expectEqual(@as(u16, 204), exchange.head().status);

    try testing.expectEqualStrings("MixedValue", server.requestField(0, "x-thing").?);
    // The value keeps its case. Only the name is folded.
    try testing.expectEqualStrings("Basic abc", server.requestField(0, "authorization").?);
    try testing.expectEqual(@as(?[]const u8, null), server.requestField(0, "X-Thing"));
}

/// A request body that answers from one slice, so a test can send more
/// octets than one flow-control window holds.
const TestBody = struct {
    text: []const u8,
    at: usize = 0,

    fn source(self: *TestBody) engine.Body {
        return .{
            .len = self.text.len,
            .ctx = self,
            .read = readImpl,
            .rewind = rewindImpl,
            .content_type = "application/octet-stream",
        };
    }

    fn readImpl(ctx: *anyopaque, buffer: [*]u8, len: usize) callconv(.c) isize {
        const self: *TestBody = @ptrCast(@alignCast(ctx));
        const take = @min(len, self.text.len - self.at);
        @memcpy(buffer[0..take], self.text[self.at..][0..take]);
        self.at += take;
        return @intCast(take);
    }

    fn rewindImpl(ctx: *anyopaque) callconv(.c) bool {
        const self: *TestBody = @ptrCast(@alignCast(ctx));
        self.at = 0;
        return true;
    }
};

test "a request body larger than the flow-control window goes out whole and never deadlocks" {
    // **This is the deadlock.** A connection window starts at 65535 and a
    // sender that only wrote would never read the `WINDOW_UPDATE` that
    // opens it. The body below is larger than that window, and the peer
    // asks for a stream window smaller again, so the send loop must read
    // frames in the middle of writing.
    const gpa = testing.allocator;
    const payload = try gpa.alloc(u8, 100_000);
    defer gpa.free(payload);
    for (payload, 0..) |*byte, i| byte.* = @intCast('a' + i % 26);

    var settings: zurl_h2.Settings = .initial;
    settings.initial_window_size = 16384;

    var server: h2_test_server.H2TestServer = undefined;
    try server.startWith(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "201" },
            .{ .name = "content-length", .value = "2" },
        },
        .body = "ok",
    }}, .{ .settings = settings });
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(gpa, server.port());
    defer client.deinit();

    var body: TestBody = .{ .text = payload };
    var exchange = try client.send(.{ .method = .POST, .body = body.source() });
    try testing.expectEqual(@as(u16, 201), exchange.head().status);
    try testing.expect(client.body_sent);

    const answer = try readBody(exchange);
    defer gpa.free(answer);
    try testing.expectEqualStrings("ok", answer);
    exchange.close();

    // Every octet arrived, in order, and the peer read exactly what was
    // announced. The fixture keeps the front of a body this size, so the
    // count and the front are what a test can assert on.
    try testing.expectEqualStrings("100000", server.requestField(0, "content-length").?);
    try testing.expectEqualStrings(
        "application/octet-stream",
        server.requestField(0, "content-type").?,
    );
    try testing.expectEqual(@as(?u64, 100_000), server.requestBodyLen(0));
    const front = server.requestBody(0).?;
    try testing.expect(front.len > 16_000);
    try testing.expectEqualSlices(u8, payload[0..front.len], front);
}

test "a peer that answers while the body is going out stops the send and is read" {
    // **RFC 9113 section 8.1 allows an answer before the request ends**,
    // and a `413` for a large upload is the ordinary case. A client that
    // kept writing would spend the whole body on a peer that already
    // refused it, and one that waited for its own `END_STREAM` to be
    // accepted would wait for a window nobody is going to open.
    const gpa = testing.allocator;
    const payload = try gpa.alloc(u8, 80_000);
    defer gpa.free(payload);
    @memset(payload, 'z');

    var settings: zurl_h2.Settings = .initial;
    settings.initial_window_size = 8192;

    var server: h2_test_server.H2TestServer = undefined;
    try server.startWith(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "413" },
            .{ .name = "content-length", .value = "7" },
        },
        .body = "too big",
        .answer_early = true,
    }}, .{ .settings = settings });
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(gpa, server.port());
    defer client.deinit();

    var body: TestBody = .{ .text = payload };
    var exchange = try client.send(.{ .method = .POST, .body = body.source() });
    try testing.expectEqual(@as(u16, 413), exchange.head().status);

    const answer = try readBody(exchange);
    defer gpa.free(answer);
    try testing.expectEqualStrings("too big", answer);

    // The send stopped short of the announced length, so this side never
    // sent `END_STREAM` and `close` sends `RST_STREAM` in its place.
    try testing.expect(server.requestBodyLen(0).? < payload.len);
    exchange.close();
}

test "a PING from the peer is answered with the same eight octets" {
    var server: h2_test_server.H2TestServer = undefined;
    try server.startWith(
        &.{.{ .fields = &.{.{ .name = ":status", .value = "200" }} }},
        .{ .ping_first = true },
    );
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var exchange = try client.send(.{});
    try testing.expectEqual(@as(u16, 200), exchange.head().status);
    // The reply went out under the flush that came before the next read,
    // so the fixture has it by the time the head is here.
    exchange.close();
    try testing.expect(server.pingReplies() >= 1);
}

test "a PUSH_PROMISE is a connection error, because this client refuses push" {
    // RFC 9113 section 8.4: a client that sent `SETTINGS_ENABLE_PUSH` of 0
    // answers a promise with a connection error. Refusing is the whole
    // point: a promise this client cannot use is memory and window spent
    // on a stream nobody asked for.
    var server: h2_test_server.H2TestServer = undefined;
    try server.startWith(
        &.{.{ .fields = &.{.{ .name = ":status", .value = "200" }} }},
        .{ .push_first = true },
    );
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    try testing.expectError(error.ReadError, client.send(.{}));
    // The connection is over, so nothing may send a second request on it.
    try testing.expect(!client.session.usable());
}

test "a GOAWAY above this stream says the request never ran, so it may go out again" {
    var server: h2_test_server.H2TestServer = undefined;
    try server.startWith(
        &.{.{ .fields = &.{.{ .name = ":status", .value = "200" }} }},
        .{ .goaway = .no_error, .goaway_last_stream = 0 },
    );
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    try testing.expectError(error.ReadError, client.send(.{}));
    // **The peer named stream 0 as the last one it would process, and this
    // request opened stream 1.** So the peer acted on nothing, and a
    // caller with a retry of its own may send the request again.
    try testing.expect(!client.answered);
    try testing.expect(!client.session.usable());
}

test "a RST_STREAM ends the request and says the peer answered it" {
    var server: h2_test_server.H2TestServer = undefined;
    try server.startWith(
        &.{.{ .fields = &.{.{ .name = ":status", .value = "200" }} }},
        .{ .reset = .refused_stream },
    );
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    try testing.expectError(error.ReadError, client.send(.{}));
    // A frame arrived on this request's own stream, so the peer saw the
    // request. A retry would ask it to act twice.
    try testing.expect(client.answered);
}

test "a gzip body is decoded, and the head says so" {
    // The same content encodings `h1` reads, over the same
    // `std.http.Decompress`. A peer answers both engines with one body.
    const gpa = testing.allocator;

    // `Compress.init` asserts the output holds more than eight octets, so
    // the buffer starts with room rather than empty.
    var packed_body: std.Io.Writer.Allocating = try .initCapacity(gpa, 4096);
    defer packed_body.deinit();
    {
        const window = try gpa.alloc(u8, std.compress.flate.max_window_len);
        defer gpa.free(window);
        var deflate = try std.compress.flate.Compress.init(
            &packed_body.writer,
            window,
            .gzip,
            .default,
        );
        try deflate.writer.writeAll("compressed payload");
        try deflate.finish();
    }

    var server: h2_test_server.H2TestServer = undefined;
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-encoding", .value = "gzip" },
        },
        .body = packed_body.written(),
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(gpa, server.port());
    defer client.deinit();

    // The offer, which the default no longer makes: a request with no
    // `accept-encoding` field reads `identity` and nothing else, so this
    // gzip answer would be `error.BadContentEncoding` without it.
    var exchange = try client.send(.{ .accept_encoding = true });
    try testing.expect(exchange.head().body_decoded);

    const body = try readBody(exchange);
    defer gpa.free(body);
    try testing.expectEqualStrings("compressed payload", body);
    exchange.close();
}

/// One gzip member over `text`, for a test of a compressed answer.
///
/// The caller owns what comes back. `Compress.init` asserts the output
/// holds more than eight octets, so the buffer starts with room.
fn gzipAlloc(gpa: std.mem.Allocator, text: []const u8) ![]u8 {
    var packed_body: std.Io.Writer.Allocating = try .initCapacity(gpa, 4096);
    errdefer packed_body.deinit();
    const window = try gpa.alloc(u8, std.compress.flate.max_window_len);
    defer gpa.free(window);
    var deflate = try std.compress.flate.Compress.init(&packed_body.writer, window, .gzip, .default);
    try deflate.writer.writeAll(text);
    try deflate.finish();
    return packed_body.toOwnedSlice();
}

test "a gzip body whose END_STREAM came on a frame of its own keeps the connection" {
    // **A content decoder ends at the end of its own stream.** `gzip`
    // stops at the last octet of the compressed member and asks the frame
    // reader for nothing more, so a peer that carries `END_STREAM` on an
    // empty `DATA` frame after that member left `Stream.ended` false and
    // `reusable` closed a connection the peer was ready to serve again.
    //
    // Measured on the wire: every answer from `www.cloudflare.com` has
    // this shape, and zurl opened one connection for each of four
    // sequential requests where curl opened one for all four. See
    // `Exchange.finishFraming`.
    const gpa = testing.allocator;
    const packed_body = try gzipAlloc(gpa, "compressed payload");
    defer gpa.free(packed_body);

    var server: h2_test_server.H2TestServer = undefined;
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-encoding", .value = "gzip" },
        },
        .body = packed_body,
        .end_stream_alone = true,
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(gpa, server.port());
    defer client.deinit();

    var exchange = try client.send(.{ .accept_encoding = true });
    const body = try readBody(exchange);
    defer gpa.free(body);
    try testing.expectEqualStrings("compressed payload", body);
    try exchange.check();
    exchange.close();
    try testing.expect(client.kept);
}

test "a trailer after a gzip body is read, and the connection is kept" {
    // The same defect over the other frame that can carry `END_STREAM`
    // after the last body octet. A trailer section arrives in a `HEADERS`
    // frame, and a client that stopped at the end of the compressed
    // member read neither the trailer nor the end of the stream.
    const gpa = testing.allocator;
    const packed_body = try gzipAlloc(gpa, "compressed payload");
    defer gpa.free(packed_body);

    var server: h2_test_server.H2TestServer = undefined;
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-encoding", .value = "gzip" },
        },
        .body = packed_body,
        .trailers = &.{.{ .name = "x-checksum", .value = "abc" }},
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(gpa, server.port());
    defer client.deinit();

    var exchange = try client.send(.{ .accept_encoding = true });
    const body = try readBody(exchange);
    defer gpa.free(body);
    try testing.expectEqualStrings("compressed payload", body);
    try testing.expectEqualStrings("x-checksum: abc\r\n", exchange.trailers().?);
    exchange.close();
    try testing.expect(client.kept);
}

test "body octets after the gzip member stay unread, and the connection goes" {
    // **The end of a content stream is not a promise that the peer sent
    // nothing else.** A peer that writes octets after the compressed
    // member disagrees with its own content encoding, and the decoder
    // never reads them. They are left where they are, and the connection
    // is closed rather than pooled: a pooled connection with unread
    // octets would hand them to the next request.
    //
    // The two shapes reach the two places such octets can sit. In one
    // `DATA` frame with the member, they are already inside this process
    // when the decoder stops. In a `DATA` frame of their own, they are
    // still on the connection and the read that looks for `END_STREAM`
    // finds them.
    const gpa = testing.allocator;
    const packed_body = try gzipAlloc(gpa, "compressed payload");
    defer gpa.free(packed_body);
    const with_tail = try std.mem.concat(gpa, u8, &.{ packed_body, "AAAAAAAAAAAAAAAA" });
    defer gpa.free(with_tail);

    for ([_]usize{ 16384, packed_body.len }) |chunk| {
        var server: h2_test_server.H2TestServer = undefined;
        try server.start(&.{.{
            .fields = &.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-encoding", .value = "gzip" },
            },
            .body = with_tail,
            .data_chunk = chunk,
        }});
        defer server.stop();

        var client: TestClient = undefined;
        try client.connect(gpa, server.port());
        defer client.deinit();

        var exchange = try client.send(.{ .accept_encoding = true });
        const body = try readBody(exchange);
        defer gpa.free(body);
        try testing.expectEqualStrings("compressed payload", body);
        exchange.close();
        try testing.expect(!client.kept);
    }
}

test "a gzip body the caller abandoned still closes the connection" {
    // The rule the fix must not weaken. `finishFraming` runs only where
    // the content stream ended, so a caller that stopped part way through
    // leaves the stream open and the connection goes.
    const gpa = testing.allocator;
    const packed_body = try gzipAlloc(gpa, "compressed payload, long enough to arrive in pieces");
    defer gpa.free(packed_body);

    var server: h2_test_server.H2TestServer = undefined;
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-encoding", .value = "gzip" },
        },
        .body = packed_body,
        // One octet a frame, so the peer still has frames to send when
        // the caller stops reading.
        .data_chunk = 1,
        .end_stream_alone = true,
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(gpa, server.port());
    defer client.deinit();

    var exchange = try client.send(.{ .accept_encoding = true });
    var buffer: [4096]u8 = undefined;
    const reader = exchange.bodyReader(&buffer);
    var taken: [4]u8 = undefined;
    try reader.readSliceAll(&taken);
    try testing.expectEqualStrings("comp", &taken);
    exchange.close();
    try testing.expect(!client.kept);
}

test "a body that stops before its content length is a partial file" {
    // The same answer `h1` gives a transfer that stopped short. A caller
    // that took the octets would write a file that reads exactly like a
    // whole one.
    var server: h2_test_server.H2TestServer = undefined;
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "100" },
        },
        .body = "short",
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var exchange = try client.send(.{});
    try testing.expectEqual(@as(?u64, 100), exchange.head().content_length);

    try testing.expectError(error.ReadFailed, readBody(exchange));
    try testing.expectError(error.PartialFile, exchange.check());
    exchange.close();
    // A cut transfer never goes back to the pool.
    try testing.expect(!client.kept);
}

test "a peer that alternates idle frames with one body octet still reaches the bound" {
    // **The budget covers the transfer and never one call.** `idle` used
    // to be a local of `rawChunk`, starting at zero on every call, so a
    // peer that sent a run of frames carrying no progress, then one body
    // octet, then another run, never reached `idle_frames_max` at all. The
    // bound was real for a peer that stopped and absent for a peer that
    // made one byte of progress at a time.
    //
    // The fixture below writes 400 `PING` frames before each of four
    // `DATA` frames of one octet. No single call sees more than 400, and
    // the transfer sees 1600, so the count has to carry across calls for
    // this to end at all.
    const gpa = testing.allocator;

    var server: h2_test_server.H2TestServer = undefined;
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "4" },
        },
        .body = "abcd",
        .data_chunk = 1,
        .pings_before_chunk = 400,
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(gpa, server.port());
    defer client.deinit();

    var exchange = try client.send(.{});
    try testing.expectEqual(@as(u16, 200), exchange.head().status);

    // The read ends, which is the whole point: a per-call budget let this
    // run for as long as the peer cared to keep sending. `bodyFault`
    // records `PeerStalled` and, because fewer octets arrived than the
    // announced length, `check` reports the cut body.
    try testing.expectError(error.ReadFailed, readBody(exchange));
    try testing.expectError(error.PartialFile, exchange.check());
    exchange.close();
    // A transfer that ended this way never goes back to the pool.
    try testing.expect(!client.kept);
}

test "a run of trailer HEADERS frames with no end is refused" {
    // **A trailer section used to refund the budget it spent.** The arm
    // added one to `Session.progress` for every trailer block, and
    // `rawChunk` puts its own count back to zero whenever that number
    // moves, so nine octets bought one turn of the read loop and gave the
    // unit straight back. The loop never ended: measured, `zurl` was still
    // reading when a twenty second timeout fired, with memory flat.
    //
    // Two rules end it now. RFC 9113 section 8.1 makes a `HEADERS` frame
    // after the final status and without `END_STREAM` malformed, which is
    // this frame, and `Session.advanced` no longer counts a second trailer
    // section as progress even where one is legal.
    const gpa = testing.allocator;

    var server: h2_test_server.H2TestServer = undefined;
    try server.start(&.{.{
        .fields = &.{.{ .name = ":status", .value = "200" }},
        .flood = .trailer_headers,
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(gpa, server.port());
    defer client.deinit();

    var exchange = try client.send(.{});
    try testing.expectEqual(@as(u16, 200), exchange.head().status);

    // The read ends, and it ends with a fault and not with a short body.
    try testing.expectError(error.ReadFailed, readBody(exchange));
    exchange.close();
    try testing.expect(!client.kept);
}

test "a run of DATA frames of no octets is refused" {
    // **The same refund, from the arm beside the trailer one.** RFC 9113
    // section 6.1 allows a `DATA` frame with nothing in it, and the arm
    // counted the frame rather than the octets, so nine octets bought a
    // turn of the loop here too. This is the case the trailer fix would
    // have left open, and it is the one that proves the rule and not the
    // frame type: `Session.advanced` counts the body octets, and a frame
    // that carries none moves nothing.
    const gpa = testing.allocator;

    var server: h2_test_server.H2TestServer = undefined;
    try server.start(&.{.{
        .fields = &.{.{ .name = ":status", .value = "200" }},
        .flood = .empty_data,
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(gpa, server.port());
    defer client.deinit();

    var exchange = try client.send(.{});
    try testing.expectEqual(@as(u16, 200), exchange.head().status);

    try testing.expectError(error.ReadFailed, readBody(exchange));
    exchange.close();
    try testing.expect(!client.kept);
}

test "a trailer section is read and the body still ends cleanly" {
    // RFC 9113 section 8.1 allows a header block after the body. **Every
    // block is decoded, because HPACK carries a table both sides build**,
    // and a block that is not decoded leaves the two out of step.
    var server: h2_test_server.H2TestServer = undefined;
    try server.start(&.{.{
        .fields = &.{.{ .name = ":status", .value = "200" }},
        .body = "with trailers",
        .trailers = &.{.{ .name = "x-checksum", .value = "abc" }},
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var exchange = try client.send(.{});
    const body = try readBody(exchange);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("with trailers", body);
    // **No trailer field reaches the head block.** curl keeps them out of
    // the head too: measured, `%header{}` answered empty for a trailer
    // field and `%{size_header}` counted the head block alone.
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, exchange.head().final_headers.?, "x-checksum"),
    );
    // **And the trailer reaches the caller through its own seam.** One
    // field line, with no status line before it and no empty line after
    // it, which is what curl 8.21.0 appends to a `-D` file.
    try testing.expectEqualStrings("x-checksum: abc\r\n", exchange.trailers().?);
    exchange.close();
    try testing.expect(client.kept);
}

test "a trailer section takes the field rules the head takes" {
    // **The trailer branch of `finishBlock` returned before the check.** A
    // trailer section was the one field list on this connection that met
    // no rule at all, so a field named `x-a\r\nset-cookie: injected=1`, or
    // a field whose value carried a CR and an LF, went straight into the
    // block `renderTrailers` builds and a caller reads back.
    //
    // Each case here is a whole transfer, so this covers the routing and
    // not the rule alone.
    const cases = [_]zurl_hpack.Field{
        .{ .name = "x-a\r\nset-cookie: injected=1", .value = "ok" },
        .{ .name = "x-a b", .value = "ok" },
        .{ .name = "X-Upper", .value = "ok" },
        .{ .name = "x-t", .value = "ok\r\nset-cookie: t=1" },
        .{ .name = "connection", .value = "close" },
    };
    for (cases) |field| {
        var server: h2_test_server.H2TestServer = undefined;
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
        // The head is whole and good. The trailer is what fails, and it
        // fails while the body is read, which is where it arrives.
        try testing.expectEqual(@as(u16, 200), exchange.head().status);
        try testing.expectError(error.ReadFailed, readBody(exchange));
        // Nothing of the forged section reaches the caller.
        try testing.expectEqual(@as(?[]const u8, null), exchange.trailers());
        exchange.close();
        try testing.expect(!client.kept);
    }
}

test "a response with no trailer section reports none" {
    var server: h2_test_server.H2TestServer = undefined;
    try server.start(&.{.{
        .fields = &.{.{ .name = ":status", .value = "200" }},
        .body = "plain",
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var exchange = try client.send(.{});
    const body = try readBody(exchange);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("plain", body);
    try testing.expectEqual(@as(?[]const u8, null), exchange.trailers());
    exchange.close();
}

test "a trailer section of several fields keeps the order the peer sent" {
    // Measured against curl 8.21.0 with `grpc-status: 0` and `x-end: yes`
    // behind a body: the `-D` file ended with those two lines, in that
    // order, and with no blank line after them.
    var server: h2_test_server.H2TestServer = undefined;
    try server.start(&.{.{
        .fields = &.{.{ .name = ":status", .value = "200" }},
        .body = "hello\n",
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
    // **Nothing before the body ends.** A trailer arrives behind the last
    // body octet, so a caller that asks before then is told there is none.
    try testing.expectEqual(@as(?[]const u8, null), exchange.trailers());
    const body = try readBody(exchange);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("hello\n", body);
    try testing.expectEqualStrings(
        "grpc-status: 0\r\nx-end: yes\r\n",
        exchange.trailers().?,
    );
    // Asked twice, rendered once, and the same text both times.
    try testing.expectEqualStrings(
        "grpc-status: 0\r\nx-end: yes\r\n",
        exchange.trailers().?,
    );
    exchange.close();
}

test "the HTTP2-Settings value carries the settings this side sends" {
    // RFC 7540 section 3.2.1: the field is the payload of the `SETTINGS`
    // frame this side would have sent, in base64url with no padding. The
    // two must not drift apart, or a peer that upgraded would run under
    // settings the client never meant.
    var out: [engine.http2_settings_len_max]u8 = undefined;
    const text = settingsUpgradeText(&out);

    // No padding and the url alphabet, which is what the RFC asks for and
    // what curl sends.
    try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, text, '='));
    try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, text, '+'));
    try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, text, '/'));

    // It decodes back to the entries `Session.wanted` names, and to those
    // entries alone.
    var decoded: [zurl_h2.settings.payload_len_max]u8 = undefined;
    const coder = std.base64.url_safe_no_pad.Decoder;
    const len = try coder.calcSizeForSlice(text);
    try coder.decode(decoded[0..len], text);

    var read: zurl_h2.Settings = .initial;
    _ = try read.apply(decoded[0..len]);
    const wanted = Session.wanted();
    try testing.expectEqual(wanted.enable_push, read.enable_push);
    try testing.expectEqual(wanted.initial_window_size, read.initial_window_size);
    try testing.expectEqual(wanted.max_header_list_size, read.max_header_list_size);
    // Three entries differ from the defaults, so three go out, which is
    // the same count the first `SETTINGS` frame carries.
    try testing.expectEqual(
        @as(usize, 3 * zurl_h2.settings.entry_len),
        len,
    );
}

test "a 101 is read as HTTP/2 only when it names h2c" {
    // RFC 7540 section 3.2: the answer to an `Upgrade: h2c` request names
    // `h2c`. Anything else switched to a protocol this build cannot read,
    // and the octets behind such a head are that protocol's own.
    try testing.expect(upgradedToH2c("h2c"));
    // RFC 9110 section 7.8 makes a protocol name case insensitive.
    try testing.expect(upgradedToH2c("H2C"));
    // The field is a list, so the name may sit anywhere in it and may
    // carry space around the commas.
    try testing.expect(upgradedToH2c("websocket, h2c"));
    try testing.expect(upgradedToH2c(" h2c , foo"));

    // A `101` that named something else, or nothing at all.
    try testing.expect(!upgradedToH2c("websocket"));
    try testing.expect(!upgradedToH2c("h2"));
    try testing.expect(!upgradedToH2c("h2cx"));
    try testing.expect(!upgradedToH2c(""));
    try testing.expect(!upgradedToH2c(null));
}

test "renderTrailers writes field lines and leaves a pseudo header out" {
    const gpa = testing.allocator;

    // A trailer of nothing at all is no trailer to show.
    var empty: zurl_hpack.FieldList = .empty;
    defer empty.deinit(gpa);
    try testing.expectEqual(@as(?[]u8, null), try renderTrailers(gpa, empty));

    // RFC 9113 section 8.1: a pseudo header may not appear in a trailer
    // section. One that did would describe a message and not a trailer, so
    // it is left out the same way the head render leaves it out. A section
    // of nothing else is then no section at all.
    var one: zurl_hpack.FieldList = .empty;
    defer one.deinit(gpa);
    try one.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
    try testing.expectEqual(@as(?[]u8, null), try renderTrailers(gpa, one));

    var two: zurl_hpack.FieldList = .empty;
    defer two.deinit(gpa);
    try two.append(gpa, try gpa.dupe(u8, "grpc-status"), try gpa.dupe(u8, "0"), false);
    try two.append(gpa, try gpa.dupe(u8, "x-end"), try gpa.dupe(u8, "yes"), false);
    const text = (try renderTrailers(gpa, two)).?;
    defer gpa.free(text);
    try testing.expectEqualStrings("grpc-status: 0\r\nx-end: yes\r\n", text);
}

test "two streams are open on one connection at once, and neither reads the other's body" {
    // **This is multiplexing.** RFC 9113 section 5.1.1 gives each request
    // an odd identifier going up by two, and every frame names the one it
    // belongs to. The server here keeps both open and writes their bodies
    // interleaved, so the client reads frames for stream 3 while it is
    // waiting on stream 1 and the other way round.
    //
    // Getting this wrong puts one transfer's octets in the other's body,
    // which is the failure this test exists to catch.
    var server: h2_test_server.H2TestServer = undefined;
    try server.startWith(&.{
        .{
            .fields = &.{.{ .name = ":status", .value = "200" }},
            .body = "first-body-first-body",
            .head_only_first = true,
        },
        .{
            .fields = &.{.{ .name = ":status", .value = "201" }},
            .body = "second-body",
        },
    }, .{ .interleave = true, .requests_per_connection = 2 });
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    // The first request. Its head is in, its body is not.
    const one = try client.send(.{ .path = "/one" });
    try testing.expectEqual(@as(u16, 200), one.head().status);
    try testing.expectEqual(@as(usize, 1), client.session.open_count);

    // **The second request goes out while the first is still open.** The
    // connection now carries two streams, which is what the whole change
    // is for. Before it, this call would have read stream 1's body frames
    // as if they answered stream 3.
    const two = try client.send(.{ .path = "/two" });
    try testing.expectEqual(@as(u16, 201), two.head().status);
    try testing.expectEqual(@as(usize, 2), client.session.open_count);
    try testing.expectEqual(@as(u31, 1), @as(*Exchange, @ptrCast(@alignCast(one.ptr))).stream.id);
    try testing.expectEqual(@as(u31, 3), @as(*Exchange, @ptrCast(@alignCast(two.ptr))).stream.id);

    // Each body is whole and is its own. Reading the first walks past the
    // second's frames, which go to that stream's inbox rather than into
    // this body.
    const first_body = try readBody(one);
    defer testing.allocator.free(first_body);
    try testing.expectEqualStrings("first-body-first-body", first_body);

    // And the second body comes out of the inbox, because it arrived while
    // the first stream's owner held the connection.
    const second_body = try readBody(two);
    defer testing.allocator.free(second_body);
    try testing.expectEqualStrings("second-body", second_body);

    // One accept, so both requests really did share one connection.
    try testing.expectEqual(@as(usize, 1), server.accepts());

    one.close();
    try testing.expectEqual(@as(usize, 1), client.session.open_count);
    two.close();
    // **Every stream left the table.** A session that still held one would
    // be holding the address of memory the exchange freed.
    try testing.expectEqual(@as(usize, 0), client.session.open_count);
}

/// One transfer of the two-task test below, and the answer it read.
const SharedRun = struct {
    client: *TestClient,
    path: []const u8,
    /// Each task writes its own flags. Two tasks that shared one would be
    /// two writers of one bool, which is the race this test is about.
    answered: bool = false,
    body_sent: bool = false,
    status: u16 = 0,
    body: ?[]u8 = null,
    fault: ?anyerror = null,

    /// Sends one request on the shared session and reads the whole answer.
    ///
    /// It returns `void`, because `Io.concurrent` gives a task nowhere to
    /// report to. The fault is kept and the caller raises it.
    fn run(self: *SharedRun) void {
        const exchange = open(.{
            .gpa = testing.allocator,
            .session = self.client.session,
            .method = .GET,
            .uri = testUri(self.path),
            .authority = "127.0.0.1",
            .user_agent = "zurl/test",
            .accept_encoding = false,
            .headers = &.{},
            .body = null,
            .url = testUrl(),
            .cookies = null,
            .log = self.client.log(),
            .peer = self.client.peer(),
            .answered = &self.answered,
            .body_sent = &self.body_sent,
        }) catch |err| {
            self.fault = err;
            return;
        };
        defer exchange.close();
        self.status = exchange.head().status;
        self.body = readBody(exchange) catch |err| {
            self.fault = err;
            return;
        };
    }

    /// Whether this task read the body that belongs to the status it got.
    ///
    /// **This is the cross-talk check.** Two tasks race for the two
    /// answers, so which one gets which is not fixed. What must hold is
    /// that a task which read status 200 read the 200 body whole, and a
    /// task which read status 201 read the 201 body whole. A build that
    /// handed one task the other's octets fails here whichever way the
    /// race went.
    fn check(self: *const SharedRun) !void {
        if (self.fault) |err| return err;
        const body = self.body orelse return error.NoBody;
        switch (self.status) {
            200 => try testing.expectEqualStrings("a" ** 400, body),
            201 => try testing.expectEqualStrings("b" ** 400, body),
            else => return error.UnexpectedStatus,
        }
    }

    fn deinit(self: *SharedRun) void {
        if (self.body) |body| testing.allocator.free(body);
    }
};

test "two tasks drive one shared session, and neither reads the other's body" {
    // **This is the whole of what sharing a connection has to get right.**
    // One task is inside the blocking frame read while the other writes a
    // request and then waits, and the frames that come back name both
    // streams. Every octet must reach the stream it names.
    //
    // A single-threaded build cannot run two tasks at once, so it cannot
    // put this question. Everything below is offline either way.
    if (@import("builtin").single_threaded) return error.SkipZigTest;

    var server: h2_test_server.H2TestServer = undefined;
    try server.startWith(&.{
        .{
            .fields = &.{.{ .name = ":status", .value = "200" }},
            .body = "a" ** 400,
            .head_only_first = true,
        },
        .{
            .fields = &.{.{ .name = ":status", .value = "201" }},
            .body = "b" ** 400,
        },
    }, .{ .interleave = true, .requests_per_connection = 2 });
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();
    // Without this the session takes no lock and hands the frame buffer
    // out, and two tasks on it would interleave two HPACK decodes.
    client.session.markShared();
    try testing.expect(client.session.shared);

    var first: SharedRun = .{ .client = &client, .path = "/one" };
    defer first.deinit();
    var second: SharedRun = .{ .client = &client, .path = "/two" };
    defer second.deinit();

    // The second task runs beside this one. A build that could not give a
    // task is a regression here and not an expected limit: the line above
    // already returned for a single-threaded build.
    var future = try testing.io.concurrent(SharedRun.run, .{&second});
    SharedRun.run(&first);
    future.await(testing.io);

    try first.check();
    try second.check();
    // The two tasks read the two different answers, so neither one read
    // the same script entry twice.
    try testing.expect(first.status != second.status);

    // One accept, so both transfers really did ride one socket.
    try testing.expectEqual(@as(usize, 1), server.accepts());
    // Every stream left the table, so the session holds no address of an
    // exchange that has gone.
    try testing.expectEqual(@as(usize, 0), client.session.open_count);
}

test "a claimed stream slot is not free until the request opens" {
    // `h1.Pool` picks a connection and the stream opens some time after
    // that. Without a claim, two tasks could both read room for the last
    // slot and one of them would then be refused a stream it was promised.
    var session: Session = undefined;
    session.peer_settings = .initial;
    session.peer_settings.max_concurrent_streams = 2;
    session.open_count = 0;
    session.reserved = 0;
    session.streams = @splat(null);
    session.broken = false;
    session.goaway_code = null;
    session.next_stream_id = 1;
    session.shared = false;

    try testing.expect(session.hasRoom());
    try testing.expect(session.reserve());
    try testing.expectEqual(@as(usize, 1), session.reserved);
    // One slot left, and it is the claimed one that is gone.
    try testing.expect(session.hasRoom());
    try testing.expect(session.reserve());
    try testing.expect(!session.hasRoom());
    // A third caller is refused rather than promised a stream that is not
    // there.
    try testing.expect(!session.reserve());

    session.unreserve();
    try testing.expect(session.hasRoom());
    session.unreserve();
    try testing.expectEqual(@as(usize, 0), session.reserved);

    // A connection that is not fit promises nothing, whatever room it has.
    session.broken = true;
    try testing.expect(!session.reserve());
    session.broken = false;
    session.goaway_code = .no_error;
    try testing.expect(!session.reserve());
}

test "one connection serves a second request, on the next odd stream" {
    // RFC 9113 section 5.1.1: a client identifier is odd and goes up. The
    // session, the HPACK tables, and the windows all carry over, which is
    // what makes the second request cost no preface and no handshake.
    var server: h2_test_server.H2TestServer = undefined;
    try server.startWith(&.{
        .{ .fields = &.{.{ .name = ":status", .value = "200" }}, .body = "one" },
        .{ .fields = &.{.{ .name = ":status", .value = "200" }}, .body = "two" },
    }, .{ .requests_per_connection = 2 });
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var first = try client.send(.{ .path = "/first" });
    const first_body = try readBody(first);
    defer testing.allocator.free(first_body);
    try testing.expectEqualStrings("one", first_body);
    first.close();
    try testing.expect(client.kept);

    var second = try client.send(.{ .path = "/second" });
    const second_body = try readBody(second);
    defer testing.allocator.free(second_body);
    try testing.expectEqualStrings("two", second_body);
    second.close();

    try testing.expectEqualStrings("/first", server.requestField(0, ":path").?);
    try testing.expectEqualStrings("/second", server.requestField(1, ":path").?);
    // One connection, two streams: 1 then 3.
    try testing.expectEqual(@as(usize, 1), server.accepts());
    try testing.expectEqual(@as(u31, 5), client.session.next_stream_id);
}

test "a HEAD answer reports no body octet, whatever its content length says" {
    // RFC 9110 section 9.3.2. The same answer `h1` gives, so `-I` draws the
    // same progress over either protocol.
    var server: h2_test_server.H2TestServer = undefined;
    try server.start(&.{.{ .fields = &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "4096" },
    } }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var exchange = try client.send(.{ .method = .HEAD });
    try testing.expectEqual(@as(?u64, 0), exchange.head().content_length);
    const body = try readBody(exchange);
    defer testing.allocator.free(body);
    try testing.expectEqual(@as(usize, 0), body.len);
    exchange.close();
}

/// A cookie jar that records what it was asked and what it was told.
const TestJar = struct {
    received: [4][256]u8 = undefined,
    received_lens: [4]usize = @splat(0),
    count: usize = 0,

    fn interface(self: *TestJar) engine.CookieJar {
        return .{ .ptr = self, .send = sendFn, .receive = receiveFn };
    }

    fn sendFn(ptr: *anyopaque, url: zurl_core.Url, out: []u8) ?[]const u8 {
        _ = ptr;
        _ = url;
        _ = out;
        return null;
    }

    fn receiveFn(ptr: *anyopaque, url: zurl_core.Url, set_cookie: []const u8) void {
        _ = url;
        const self: *TestJar = @ptrCast(@alignCast(ptr));
        if (self.count == self.received.len) return;
        const take = @min(set_cookie.len, self.received[self.count].len);
        @memcpy(self.received[self.count][0..take], set_cookie[0..take]);
        self.received_lens[self.count] = take;
        self.count += 1;
    }
};

test "every set-cookie of an HTTP/2 response reaches the jar, in the order it arrived" {
    // The engine keeps no cookie of its own and reads no field of the
    // value. Which host may set which domain is one rule, written once, in
    // `zurl_core.cookie`, and both engines call the same jar.
    var server: h2_test_server.H2TestServer = undefined;
    try server.start(&.{.{ .fields = &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "set-cookie", .value = "a=1; Path=/" },
        .{ .name = "set-cookie", .value = "b=2; Path=/" },
    } }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    var jar: TestJar = .{};
    var exchange = try client.send(.{ .cookies = jar.interface() });
    defer exchange.close();

    try testing.expectEqual(@as(usize, 2), jar.count);
    try testing.expectEqualStrings("a=1; Path=/", jar.received[0][0..jar.received_lens[0]]);
    try testing.expectEqualStrings("b=2; Path=/", jar.received[1][0..jar.received_lens[1]]);
}

test "the ALPN name is the one RFC 9113 registers" {
    try testing.expectEqualStrings("h2", alpn_name);
}

test "a plain connection negotiated no protocol, so it never takes the HTTP/2 path" {
    // `negotiated` is the whole of the protocol choice. A false answer here
    // is what keeps every cleartext url on `h1`.
    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try address.listen(testing.io, .{ .reuse_address = true });
    defer server.deinit(testing.io);

    const stream = try (std.Io.net.IpAddress{ .ip4 = .loopback(server.socket.address.getPort()) })
        .connect(testing.io, .{ .mode = .stream });
    var accepted = try server.accept(testing.io);
    defer accepted.close(testing.io);

    var c: zurl_net.Connection = undefined;
    try c.init(testing.allocator, testing.io, stream, .{ .read_buffer_len = 1024 });
    defer c.deinit();

    try testing.expectEqual(@as(?[]const u8, null), c.alpnProtocol());
    try testing.expect(!negotiated(&c));
}

test "the settings this side advertises refuse push and name every bound" {
    const s = Session.wanted();
    // `ENABLE_PUSH` of 0 is the refusal, and it is the whole of it. A
    // `PUSH_PROMISE` that arrives anyway is a connection error, which
    // `Session.step` reports as `error.PushRefused`.
    try testing.expect(!s.enable_push);
    // **The stream window and not the connection window.** RFC 9113
    // section 6.9.2: `SETTINGS_INITIAL_WINDOW_SIZE` names the window of a
    // stream, and the connection window is raised by a `WINDOW_UPDATE`
    // instead. The two numbers differ now that several streams share one
    // connection: see `stream_window_len`.
    try testing.expectEqual(stream_window_len, s.initial_window_size);
    try testing.expect(stream_window_len < window_len);
    try testing.expectEqual(frame_len_max, s.max_frame_size);
    try testing.expectEqual(@as(?u32, header_list_len_max), s.max_header_list_size);
    try testing.expectEqual(header_table_len, s.header_table_size);
    // **No `MAX_CONCURRENT_STREAMS`.** The peer opens no stream here, so a
    // number would bound nothing. See `advertised_concurrent_max`.
    try testing.expectEqual(@as(?u32, null), s.max_concurrent_streams);

    // Three parameters differ from the RFC 9113 section 6.5.2 defaults, so
    // the first `SETTINGS` frame carries three entries and no more. The
    // table size and the frame size are already the defaults, and a client
    // that names a default spends octets to say nothing.
    const changes = s.changesFrom(.initial);
    try testing.expectEqual(@as(usize, 3), changes.len);
}

test "a session honours the peer's SETTINGS_MAX_CONCURRENT_STREAMS" {
    var session: Session = undefined;
    session.peer_settings = .initial;
    session.open_count = 0;
    session.streams = @splat(null);
    // Nobody shares this one, so `hasRoom` takes no lock, and no caller has
    // claimed a slot. See `Session.shared` and `Session.reserved`.
    session.shared = false;
    session.reserved = 0;

    // A peer that names nothing is unbounded, RFC 9113 section 5.1.2, so
    // this side's own table is the whole answer.
    try testing.expectEqual(@as(?u32, null), session.peer_settings.max_concurrent_streams);
    try testing.expectEqual(streams_max, session.concurrentMax());

    // A peer that names fewer wins.
    session.peer_settings.max_concurrent_streams = 2;
    try testing.expectEqual(@as(usize, 2), session.concurrentMax());
    try testing.expect(session.hasRoom());
    session.open_count = 2;
    try testing.expect(!session.hasRoom());

    // A peer that names more does not: this side's table is a bound of its
    // own, and a slot that does not exist cannot be filled.
    session.peer_settings.max_concurrent_streams = 1000;
    try testing.expectEqual(streams_max, session.concurrentMax());
    session.open_count = streams_max;
    try testing.expect(!session.hasRoom());
    session.open_count = streams_max - 1;
    try testing.expect(session.hasRoom());
}

test "a connection whose stream identifiers ran out is not reused" {
    // RFC 9113 section 5.1.1: a client stream identifier is odd and goes
    // up, and 2147483647 is the largest there is. A client that used them
    // all must open a new connection. `usable` is what says so, and
    // `Exchange.reusable` reads it, so such a connection is closed instead
    // of going back to the pool and the next request dials.
    var session: Session = undefined;
    session.broken = false;
    session.goaway_code = null;
    // Nobody shares this one, so `usable` takes no lock. See
    // `Session.shared`.
    session.shared = false;

    session.next_stream_id = 1;
    try testing.expect(session.usable());

    // The largest identifier that still leaves room for one more request.
    session.next_stream_id = zurl_h2.frame.stream_id_max - 2;
    try testing.expect(session.usable());

    // One past it. Taking this one would leave the counter with nowhere to
    // go, so the connection is finished rather than wrapped.
    session.next_stream_id = zurl_h2.frame.stream_id_max - 1;
    try testing.expect(!session.usable());
    session.next_stream_id = zurl_h2.frame.stream_id_max;
    try testing.expect(!session.usable());

    // The other two reasons a connection is finished, which are unchanged.
    session.next_stream_id = 1;
    session.broken = true;
    try testing.expect(!session.usable());
    session.broken = false;
    session.goaway_code = .no_error;
    try testing.expect(!session.usable());
}

test "the stream table adopts, finds, and forgets" {
    var session: Session = undefined;
    session.gpa = testing.allocator;
    session.peer_settings = .initial;
    session.streams = @splat(null);
    session.open_count = 0;
    session.recv_owed = 0;

    var one: Stream = .{ .id = 1, .send_room = .init(65535) };
    var three: Stream = .{ .id = 3, .send_room = .init(65535) };
    defer one.deinit(testing.allocator);
    defer three.deinit(testing.allocator);

    session.adopt(&one);
    session.adopt(&three);
    try testing.expectEqual(@as(usize, 2), session.open_count);
    try testing.expectEqual(@as(?*Stream, &one), session.find(1));
    try testing.expectEqual(@as(?*Stream, &three), session.find(3));
    // Stream 0 is the connection and never a request. Stream 5 was never
    // opened.
    try testing.expectEqual(@as(?*Stream, null), session.find(0));
    try testing.expectEqual(@as(?*Stream, null), session.find(5));

    session.forget(&one);
    try testing.expectEqual(@as(usize, 1), session.open_count);
    try testing.expectEqual(@as(?*Stream, null), session.find(1));
    try testing.expectEqual(@as(?*Stream, &three), session.find(3));
    // Forgetting twice is not a fault. `Exchange.close` runs once, but a
    // stream that never reached the table must not take a slot away.
    session.forget(&one);
    try testing.expectEqual(@as(usize, 1), session.open_count);

    session.forget(&three);
    try testing.expectEqual(@as(usize, 0), session.open_count);
}

test "the connection window is held only for the octets an inbox holds" {
    // **The bound on what this side buffers is the peer's own flow
    // control.** Room for octets handed straight to a caller goes back at
    // once; room for octets copied into another stream's inbox stays with
    // them until that stream's owner takes them. So every inbox on one
    // connection together holds at most one connection window.
    //
    // The pad length octet and the padding count in the window, RFC 9113
    // section 6.9.1, and an inbox holds neither. Their room has to go back
    // on arrival, or a padded body would leak a little window on every
    // frame until the connection stopped.
    var session: Session = undefined;
    session.gpa = testing.allocator;
    session.peer_settings = .initial;
    session.streams = @splat(null);
    session.open_count = 0;
    session.recv_owed = 0;
    session.dirty = false;

    var stream: Stream = .{ .id = 1, .send_room = .init(65535) };
    defer stream.deinit(testing.allocator);
    stream.head_ready = true;

    // A frame of 100 octets whose payload is 90, so 10 octets of padding.
    // 90 go to the inbox and 10 are spent now.
    try stream.inbox.appendSlice(testing.allocator, &[_]u8{'x'} ** 90);
    try session.creditReceive(100, &stream, 90);
    try testing.expectEqual(@as(u32, 10), session.recv_owed);
    // The stream window is credited for the whole frame either way: it
    // bounds what one stream may hold, and the inbox is inside that bound.
    try testing.expectEqual(@as(u32, 100), stream.recv_owed);

    // The owner takes the 90 out, and their room goes back with them.
    session.recv_owed = 0;
    try session.creditTaken(stream.inbox.items.len);
    try testing.expectEqual(@as(u32, 90), session.recv_owed);

    // Octets handed straight to the waiter hold nothing back.
    session.recv_owed = 0;
    try session.creditReceive(50, &stream, 0);
    try testing.expectEqual(@as(u32, 50), session.recv_owed);

    // And a frame for a stream nobody owns is spent at once, because there
    // is nobody to hold it for.
    session.recv_owed = 0;
    try session.creditReceive(40, null, 0);
    try testing.expectEqual(@as(u32, 40), session.recv_owed);
}

test "one stream takes the whole connection window and several share it" {
    var session: Session = undefined;
    session.peer_settings = .initial;
    session.streams = @splat(null);
    session.send_room = .init(120000);

    // One stream open, so the share is everything. This is what a single
    // request always saw.
    session.open_count = 1;
    try testing.expectEqual(@as(i32, 120000), shareOfConnection(&session));

    // Four streams open, so each takes a quarter. A sender that took the
    // whole window would starve the other three until its own body ended.
    session.open_count = 4;
    try testing.expectEqual(@as(i32, 30000), shareOfConnection(&session));

    // **One frame is the floor.** An even share that rounds below a frame
    // would stop every stream instead of slowing them, so the floor is the
    // peer's own frame size.
    session.send_room = .init(1000);
    session.open_count = 32;
    try testing.expectEqual(
        @as(i32, 1000),
        shareOfConnection(&session),
    );

    // A window that is closed stays closed, whatever the share works out
    // to. The caller then reads a frame and looks again.
    session.send_room = .init(0);
    try testing.expectEqual(@as(i32, 0), shareOfConnection(&session));
}

test "the head bound matches the one h1 keeps, and is reachable inside the field bound" {
    // The two engines must refuse a response head at the same size, or a
    // user meets a different limit for the same server depending on which
    // protocol answered. 300 KiB is `h1.head_len_max`.
    try testing.expectEqual(@as(usize, 300 * 1024), header_list_len_max);
    // A bound that cannot be reached is worse than no bound: a reader
    // believes the count is checked when nothing checks it. The smallest
    // field costs 32 octets of overhead alone.
    try testing.expect(header_fields_max * zurl_hpack.field.entry_overhead > header_list_len_max);
}

test "every fault of the frame layer and of HPACK reaches a name the seam knows" {
    // Recovery is never silent, so no fault may fall through to a panic or
    // to a name that says nothing. The three head bounds keep the name
    // `h1` gives its own head bound.
    try testing.expectEqual(engine.OpenError.ResponseHeadTooLarge, openError(error.HeaderListTooLarge));
    try testing.expectEqual(engine.OpenError.ResponseHeadTooLarge, openError(error.TooManyHeaderFields));
    try testing.expectEqual(engine.OpenError.ResponseHeadTooLarge, openError(error.HeaderBlockTooLarge));
    try testing.expectEqual(engine.OpenError.ResponseHeadTooLarge, openError(error.ContinuationFlood));
    try testing.expectEqual(engine.OpenError.WriteError, openError(error.WriteFailed));
    try testing.expectEqual(engine.OpenError.WriteError, openError(error.BodyLengthMismatch));
    try testing.expectEqual(engine.OpenError.OutOfMemory, openError(error.OutOfMemory));
    // Everything else is a peer that did not answer HTTP/2.
    try testing.expectEqual(engine.OpenError.ReadError, openError(error.MalformedResponse));
    try testing.expectEqual(engine.OpenError.ReadError, openError(error.PushRefused));
    try testing.expectEqual(engine.OpenError.ReadError, openError(error.StreamReset));
    try testing.expectEqual(engine.OpenError.ReadError, openError(error.ConnectionEnded));
    try testing.expectEqual(engine.OpenError.ReadError, openError(error.PeerStalled));
    try testing.expectEqual(engine.OpenError.ReadError, openError(error.BodySourceFailed));
    try testing.expectEqual(engine.OpenError.ReadError, openError(error.TooManyInformationalHeads));
    // Every fault of the frame layer lands somewhere. The set is closed,
    // so a new one that nothing maps would fail this walk rather than
    // reach a user as a name that says nothing.
    inline for (@typeInfo(Fault).error_set.?) |member| {
        const mapped = openError(@field(anyerror, member.name));
        try testing.expect(mapped != engine.OpenError.Unexpected);
    }
}

test "a response field list is checked against the shape RFC 9113 section 8.3 names" {
    const gpa = testing.allocator;

    // An upper-case field name. Section 8.2.1 makes it malformed, and it
    // is what every lookup in this file counts on.
    {
        var list: zurl_hpack.FieldList = .empty;
        defer list.deinit(gpa);
        try list.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
        try list.append(gpa, try gpa.dupe(u8, "Content-Type"), try gpa.dupe(u8, "text/plain"), false);
        try testing.expectError(error.MalformedResponse, validateResponseFields(list));
    }

    // A connection-specific field. Section 8.2.2.
    for ([_][]const u8{ "connection", "transfer-encoding", "keep-alive", "upgrade", "proxy-connection" }) |name| {
        var list: zurl_hpack.FieldList = .empty;
        defer list.deinit(gpa);
        try list.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
        try list.append(gpa, try gpa.dupe(u8, name), try gpa.dupe(u8, "x"), false);
        try testing.expectError(error.MalformedResponse, validateResponseFields(list));
    }

    // A pseudo header after an ordinary field. Section 8.3.
    {
        var list: zurl_hpack.FieldList = .empty;
        defer list.deinit(gpa);
        try list.append(gpa, try gpa.dupe(u8, "date"), try gpa.dupe(u8, "x"), false);
        try list.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
        try testing.expectError(error.MalformedResponse, validateResponseFields(list));
    }

    // A pseudo header a response may not carry. Section 8.3.2.
    {
        var list: zurl_hpack.FieldList = .empty;
        defer list.deinit(gpa);
        try list.append(gpa, try gpa.dupe(u8, ":method"), try gpa.dupe(u8, "GET"), false);
        try testing.expectError(error.MalformedResponse, validateResponseFields(list));
    }

    // A legal list passes.
    {
        var list: zurl_hpack.FieldList = .empty;
        defer list.deinit(gpa);
        try list.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "204"), false);
        try list.append(gpa, try gpa.dupe(u8, "date"), try gpa.dupe(u8, "x"), false);
        try validateResponseFields(list);
        try testing.expectEqual(@as(u16, 204), try readStatus(list));
    }
}

test "a response field value holding CR, LF, or NUL is a malformed response" {
    // The forgery. HTTP/2 carries a value as an opaque octet string, so a
    // peer writes any byte it likes, and `recordHead` writes
    // `name: value\r\n` into the `-D` block. One field of
    // `x-note: ok\r\nSet-Cookie: session=attacker` reached a user's file as
    // three fields the server never sent.
    //
    // HTTP/1.1 cannot do this, because the head parser split the head on
    // CRLF to find the value. So this is the check that makes the two
    // engines answer one question one way.
    const gpa = testing.allocator;

    const forged = [_][]const u8{
        "ok\r\nSet-Cookie: session=attacker",
        "ok\nSet-Cookie: session=attacker",
        "ok\rSet-Cookie: session=attacker",
        "ok\x7f",
    };
    for (forged) |value| {
        var list: zurl_hpack.FieldList = .empty;
        defer list.deinit(gpa);
        try list.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
        try list.append(gpa, try gpa.dupe(u8, "x-note"), try gpa.dupe(u8, value), false);
        try testing.expectError(error.MalformedResponse, validateResponseFields(list));
    }

    // **A NUL is refused too, and it keeps a name of its own.** It is a
    // control octet, so `engine.headerValueHasControl` would answer it as
    // `MalformedResponse` and exit 56. curl 8.21.0 answers the same
    // response with `Nul byte in header` and exit 8, so
    // `refuseNulInFields` runs first and this is the name a user reads.
    // See `engine.refuseNulInHead`.
    {
        var list: zurl_hpack.FieldList = .empty;
        defer list.deinit(gpa);
        try list.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
        try list.append(gpa, try gpa.dupe(u8, "x-note"), try gpa.dupe(u8, "ok\x00more"), false);
        try testing.expectError(error.WeirdServerReply, validateResponseFields(list));
    }

    // A pseudo header value takes the same rule. `:status` reaches the
    // status line of the `-D` block.
    {
        var list: zurl_hpack.FieldList = .empty;
        defer list.deinit(gpa);
        try list.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "20\r0"), false);
        try testing.expectError(error.MalformedResponse, validateResponseFields(list));
    }

    // A tab, a space, and a byte at or above 0x80 all stay. RFC 9110
    // section 5.5 keeps them, and both curl and `h1` pass them through.
    {
        var list: zurl_hpack.FieldList = .empty;
        defer list.deinit(gpa);
        try list.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
        try list.append(gpa, try gpa.dupe(u8, "x-note"), try gpa.dupe(u8, "a\tb c\xc3\xa9"), false);
        try validateResponseFields(list);
    }
}

test "a response field name holding CR, LF, NUL, a space, or a colon is a malformed response" {
    // The other half of the forgery. HPACK carries a name as an opaque
    // octet string, so a peer writes any byte it likes into one, and
    // `recordHead` writes `name: value\r\n` into the `-D` block. A name of
    // `x-a\r\nset-cookie: injected=1` reached a user's file as a
    // `set-cookie` line the server never sent, and `Response.headerIn`
    // read it back as a real header.
    //
    // The value half of this was closed first. The name half stayed open
    // because a name met one rule, "no upper-case letter". RFC 9113
    // section 8.2.1 makes a name a `tchar` run, and that is the rule
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
        var list: zurl_hpack.FieldList = .empty;
        defer list.deinit(gpa);
        try list.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
        try list.append(gpa, try gpa.dupe(u8, name), try gpa.dupe(u8, "ok"), false);
        try testing.expectError(error.MalformedResponse, validateResponseFields(list));
    }

    // A NUL in a name is refused with the name curl gives it, the same as
    // a NUL in a value. See `engine.refuseNulInHead`.
    {
        var list: zurl_hpack.FieldList = .empty;
        defer list.deinit(gpa);
        try list.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
        try list.append(gpa, try gpa.dupe(u8, "x-a\x00b"), try gpa.dupe(u8, "ok"), false);
        try testing.expectError(error.WeirdServerReply, validateResponseFields(list));
    }

    // **And every legal `tchar` still passes.** A rule that refused one of
    // these would refuse a server that works today.
    {
        var list: zurl_hpack.FieldList = .empty;
        defer list.deinit(gpa);
        try list.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
        try list.append(gpa, try gpa.dupe(u8, "!#$%&'*+-.^_`|~"), try gpa.dupe(u8, "ok"), false);
        try list.append(gpa, try gpa.dupe(u8, "x-request-id-0123456789"), try gpa.dupe(u8, "ok"), false);
        try validateResponseFields(list);
    }
}

test "a :status that is not three digits is a malformed response" {
    const gpa = testing.allocator;
    const cases = [_][]const u8{ "", "20", "2000", "20x", " 200", "abc" };
    for (cases) |text| {
        var list: zurl_hpack.FieldList = .empty;
        defer list.deinit(gpa);
        try list.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, text), false);
        try testing.expectError(error.MalformedResponse, readStatus(list));
    }

    // A list with no `:status` at all is malformed too, and never a status
    // this engine guesses at.
    var empty: zurl_hpack.FieldList = .empty;
    defer empty.deinit(gpa);
    try testing.expectError(error.MalformedResponse, readStatus(empty));
}

test "the digest challenge wins over a basic one, whichever order they arrived in" {
    // The same rule `h1` keeps over an HTTP/1.1 head. A `Basic` answer to a
    // server that offered `Digest` sends the password in reversible base64.
    const gpa = testing.allocator;

    var basic_first: zurl_hpack.FieldList = .empty;
    defer basic_first.deinit(gpa);
    try basic_first.append(gpa, try gpa.dupe(u8, "www-authenticate"), try gpa.dupe(u8, "Basic realm=\"a\""), false);
    try basic_first.append(gpa, try gpa.dupe(u8, "www-authenticate"), try gpa.dupe(u8, "Digest realm=\"a\", nonce=\"n\""), false);
    try testing.expect(std.mem.startsWith(u8, pickChallenge(basic_first).?, "Digest"));

    var basic_only: zurl_hpack.FieldList = .empty;
    defer basic_only.deinit(gpa);
    try basic_only.append(gpa, try gpa.dupe(u8, "www-authenticate"), try gpa.dupe(u8, "Basic realm=\"a\""), false);
    try testing.expect(std.mem.startsWith(u8, pickChallenge(basic_only).?, "Basic"));

    var none: zurl_hpack.FieldList = .empty;
    defer none.deinit(gpa);
    try testing.expectEqual(@as(?[]const u8, null), pickChallenge(none));
}

test "content-length is a bound, and a body longer than it fails the transfer" {
    // **The defect this closes.** This engine read `content-length` only
    // as a lower bound, for the short-transfer check, and never tested a
    // body upward. A head of `content-length: 2` and eight octets of
    // `DATA` handed a caller all eight and exited 0, while `h1` handed the
    // same caller two: one binary, two answers, on the rule that decides
    // how many octets a caller receives.
    //
    // Measured against curl 8.21.0 over a scripted HTTP/2 listener: the
    // same response gives `error -505: Protocol error`, exit 92, and no
    // body at all. RFC 9113 section 8.1.1 makes it malformed.
    const gpa = testing.allocator;

    var server: h2_test_server.H2TestServer = undefined;
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
    try testing.expectError(
        error.ReadFailed,
        reader.allocRemaining(gpa, .unlimited),
    );

    // **Not `PartialFile`.** The body did not stop short, it ran long, so
    // `check` stays quiet and the caller reads the generic read fault,
    // which is exit 56. See `Exchange.countBody`.
    try exchange.check();
}

test "a body that exactly fills its content-length still passes" {
    // The bound must not refuse the ordinary case. `received == announced`
    // is inside it.
    const gpa = testing.allocator;

    var server: h2_test_server.H2TestServer = undefined;
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "8" },
        },
        .body = "abcdefgh",
        // In four frames, so the count is folded four times and the bound
        // is asked four times.
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

test "two content-length fields that disagree are a malformed response" {
    // RFC 9110 section 8.6. This engine took the first and never looked at
    // the second, so `content-length: 2` and `content-length: 8` reached a
    // caller as a legal head. Measured: curl 8.21.0 answers this with exit
    // 92 over HTTP/2 and exit 8 over HTTP/1.1, and
    // `std.http.Client.Response.Head.parse`, which is what `h1` reads,
    // answers `error.HttpHeadersInvalid`.
    var server: h2_test_server.H2TestServer = undefined;
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

    try testing.expectError(error.ReadError, client.send(.{}));
}

test "two content-length fields that agree name one length" {
    // **The laxer of curl's two readings, on purpose.** RFC 9110 section
    // 8.6 lets a recipient either refuse a repeated `content-length` or
    // collapse two identical values into one. Measured: nghttp2 refuses
    // it, exit 92, and curl's own HTTP/1.1 parser accepts it, exit 0. A
    // curl replacement may not refuse a response curl serves, so the
    // reading `h1` already keeps through `std` is the one all three
    // engines keep.
    const gpa = testing.allocator;

    var server: h2_test_server.H2TestServer = undefined;
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "2" },
            .{ .name = "content-length", .value = "2" },
        },
        .body = "ab",
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(gpa, server.port());
    defer client.deinit();

    var exchange = try client.send(.{});
    defer exchange.close();
    try testing.expectEqual(@as(?u64, 2), exchange.head().content_length);
    const body = try readBody(exchange);
    defer gpa.free(body);
    try testing.expectEqualStrings("ab", body);
}

test "a content-length that is not a number is a malformed response" {
    // This engine read such a field as no length at all, so the transfer
    // went through unbounded while `h1` refused the same head. Measured:
    // curl 8.21.0 gives 92 over HTTP/2 and 8 over HTTP/1.1, and `std`
    // answers `error.InvalidContentLength`.
    for ([_][]const u8{ "banana", "", "-1", "2 ", "0x10", "1e3", "+2" }) |text| {
        var server: h2_test_server.H2TestServer = undefined;
        try server.start(&.{.{
            .fields = &.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-length", .value = text },
            },
            .body = "ab",
        }});
        defer server.stop();

        var client: TestClient = undefined;
        try client.connect(testing.allocator, server.port());
        defer client.deinit();

        try testing.expectError(error.ReadError, client.send(.{}));
    }
}

test "a HEAD response with a malformed content-length is still malformed" {
    // The field is checked before the number is thrown away. A `HEAD`
    // response reports zero octets, which is not a reason to stop reading
    // its head.
    var server: h2_test_server.H2TestServer = undefined;
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "2" },
            .{ .name = "content-length", .value = "8" },
        },
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    try testing.expectError(error.ReadError, client.send(.{ .method = .HEAD }));
}

test "the two content-length rules read one way for every engine" {
    // `contentLengthField` and `bodyWithinContentLength` are the rules
    // `h1`, this engine, and `h3` all keep. They live here only until they
    // move to `engine.zig` beside `contentEncoding`.
    try testing.expectEqual(@as(u64, 0), try engine.contentLengthField(null, "0"));
    try testing.expectEqual(@as(u64, 5), try engine.contentLengthField(null, "5"));
    // A leading zero is still a decimal number, and `std` reads it too.
    try testing.expectEqual(@as(u64, 5), try engine.contentLengthField(null, "05"));
    try testing.expectEqual(@as(u64, 5), try engine.contentLengthField(5, "5"));
    try testing.expectError(error.BadContentLength, engine.contentLengthField(5, "6"));
    // `05` and `5` name the same length, so they are not a disagreement.
    try testing.expectEqual(@as(u64, 5), try engine.contentLengthField(5, "05"));
    // **`std.fmt.parseInt` would take the first three of these**, which is
    // why the grammar is counted here and not left to it. curl 8.21.0
    // refuses `+2` on both of its engines, measured.
    for ([_][]const u8{ "+1", "0x1", "0b1", "", " 1", "1 ", "-1", "banana", "1,1", "1.0" }) |bad| {
        try testing.expectError(error.BadContentLength, engine.contentLengthField(null, bad));
    }
    // A run of digits wider than the type is refused and never wrapped.
    try testing.expectError(
        error.BadContentLength,
        engine.contentLengthField(null, "99999999999999999999999999"),
    );

    // A head that announced nothing is bounded by the end of the stream
    // alone, which is the only framing there is then.
    try engine.bodyWithinContentLength(null, std.math.maxInt(u64));
    try engine.bodyWithinContentLength(2, 0);
    try engine.bodyWithinContentLength(2, 2);
    try testing.expectError(error.BodyLongerThanContentLength, engine.bodyWithinContentLength(2, 3));
    try testing.expectError(error.BodyLongerThanContentLength, engine.bodyWithinContentLength(0, 1));
}

test "a repeated :status is a malformed response" {
    // RFC 9113 section 8.3 gives a pseudo header one appearance.
    // `readStatus` takes the first, so a second reached a caller unread
    // inside a head this engine had called legal. Measured: curl 8.21.0
    // answers two `:status` fields with `Invalid HTTP header field was
    // received` and exit 92.
    const gpa = testing.allocator;

    var list: zurl_hpack.FieldList = .empty;
    defer list.deinit(gpa);
    try list.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
    try list.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
    try list.append(gpa, try gpa.dupe(u8, "x-thing"), try gpa.dupe(u8, "ok"), false);
    try testing.expectError(error.MalformedResponse, validateResponseFields(list));

    // Two that differ are refused for the same reason and not a different
    // one. Nothing here compares the values.
    var differ: zurl_hpack.FieldList = .empty;
    defer differ.deinit(gpa);
    try differ.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
    try differ.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "404"), false);
    try testing.expectError(error.MalformedResponse, validateResponseFields(differ));

    // One is still one. A trailer section, which carries no pseudo header
    // at all, passes the same check.
    var once: zurl_hpack.FieldList = .empty;
    defer once.deinit(gpa);
    try once.append(gpa, try gpa.dupe(u8, ":status"), try gpa.dupe(u8, "200"), false);
    try validateResponseFields(once);

    var trailer: zurl_hpack.FieldList = .empty;
    defer trailer.deinit(gpa);
    try trailer.append(gpa, try gpa.dupe(u8, "x-checksum"), try gpa.dupe(u8, "abc"), false);
    try validateResponseFields(trailer);
}

test "a repeated :status on the wire never reaches a caller" {
    var server: h2_test_server.H2TestServer = undefined;
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "0" },
        },
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(testing.allocator, server.port());
    defer client.deinit();

    try testing.expectError(error.ReadError, client.send(.{}));
}

test "a frame on a stream that was never open ends the connection" {
    // RFC 9113 section 5.1: in the idle state a receiver takes every frame
    // but `PRIORITY` as a connection error of type `PROTOCOL_ERROR`. This
    // engine dropped them, which cost the peer nothing. Measured against
    // curl 8.21.0 over a scripted listener: `HEADERS`, `RST_STREAM`,
    // `DATA` and `WINDOW_UPDATE` on a stream nobody opened each give exit
    // 16, and the connection ends.
    for ([_]h2_test_server.IdleFrame{ .headers, .rst_stream, .data, .window_update }) |kind| {
        var server: h2_test_server.H2TestServer = undefined;
        try server.startWith(&.{.{
            .fields = &.{.{ .name = ":status", .value = "200" }},
        }}, .{ .idle_stream_frame = kind });
        defer server.stop();

        var client: TestClient = undefined;
        try client.connect(testing.allocator, server.port());
        defer client.deinit();

        try testing.expectError(error.ReadError, client.send(.{}));
        try testing.expect(!client.session.usable());
    }
}

test "a PRIORITY on a stream that was never open is read and dropped" {
    // The one exception section 5.1 names, because a sender may rank a
    // stream it has not opened yet. curl 8.21.0 finishes the transfer,
    // exit 0, measured.
    const gpa = testing.allocator;

    var server: h2_test_server.H2TestServer = undefined;
    try server.startWith(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "2" },
        },
        .body = "ab",
    }}, .{ .idle_stream_frame = .priority });
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(gpa, server.port());
    defer client.deinit();

    var exchange = try client.send(.{});
    defer exchange.close();
    const body = try readBody(exchange);
    defer gpa.free(body);
    try testing.expectEqualStrings("ab", body);
}

test "a RST_STREAM on a stream this side has finished is not an idle stream" {
    // **`find` answering null is not the same question as idle.** A stream
    // read to its end is gone from the table too, and section 5.1 lets a
    // peer reset it: the frame was already on the wire when this side
    // closed it. Refusing it would turn that race into a failed transfer.
    // curl 8.21.0 accepts it, exit 0, measured.
    const gpa = testing.allocator;

    var server: h2_test_server.H2TestServer = undefined;
    try server.startWith(&.{
        .{
            .fields = &.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-length", .value = "2" },
            },
            .body = "ab",
        },
        .{
            .fields = &.{
                .{ .name = ":status", .value = "204" },
            },
        },
    }, .{ .reset_closed_stream = true, .requests_per_connection = 2 });
    defer server.stop();

    var client: TestClient = undefined;
    try client.connect(gpa, server.port());
    defer client.deinit();

    {
        var exchange = try client.send(.{});
        defer exchange.close();
        const body = try readBody(exchange);
        defer gpa.free(body);
        try testing.expectEqualStrings("ab", body);
    }

    // The reset for the finished stream arrives while this one is open,
    // and it must not end the connection.
    var second = try client.send(.{});
    defer second.close();
    try testing.expectEqual(@as(u16, 204), second.head().status);
}

test "idleStream tells a stream nobody opened from one that is over" {
    var session: Session = undefined;
    session.next_stream_id = 5;

    // Stream 0 is the connection and is never idle.
    try testing.expect(!session.idleStream(0));
    // 1 and 3 were handed out, so they are closed and not idle.
    try testing.expect(!session.idleStream(1));
    try testing.expect(!session.idleStream(3));
    // 5 is the next one out, and nothing has used it yet.
    try testing.expect(session.idleStream(5));
    try testing.expect(session.idleStream(7));
    // An even identifier is a server-initiated stream. This side sends
    // `SETTINGS_ENABLE_PUSH` of 0 and refuses a `PUSH_PROMISE`, so one is
    // never open here.
    try testing.expect(session.idleStream(2));
    try testing.expect(session.idleStream(4));
}

/// How many nanoseconds have passed since `started`.
fn elapsedNs(started: std.Io.Timestamp) i128 {
    return started.durationTo(std.Io.Timestamp.now(testing.io, .awake)).nanoseconds;
}

/// A `read_timeout` of `ms` milliseconds, for the tests below.
fn readTimeoutMs(ms: i64) std.Io.Timeout {
    return .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
}

test "a peer that accepts the connection and answers no frame reaches the read deadline" {
    // **The shape this bound was written for.** The server completes the
    // TCP connect, reads the whole request, and then writes nothing at
    // all. It never closes, so there is no `EndOfStream` to read.
    //
    // Nothing in this engine ended such a transfer before the deadline
    // existed. `idle_frames_max` bounds a peer that sends frames which
    // move nothing, and it runs down one unit for each frame; a peer that
    // sends none spends none of it. `--connect-timeout` covers the dial
    // and stops there, and on a pooled connection even the dial is over.
    // So this test never returned at all before `Session.read_timeout`.
    var server: h2_test_server.H2TestServer = undefined;
    try server.startWith(
        &.{.{ .fields = &.{.{ .name = ":status", .value = "200" }} }},
        .{ .stall = .before_head },
    );
    defer server.stop();

    var client: TestClient = undefined;
    try client.connectWith(testing.allocator, server.port(), readTimeoutMs(200));
    defer client.deinit();

    // **A floor and never a ceiling.** The deadline says the wait may not
    // run past 200 milliseconds. A loaded machine may take longer to
    // notice, which is not a failure. A shorter wait would mean the bound
    // fired before the peer had its chance.
    const started = std.Io.Timestamp.now(testing.io, .awake);
    try testing.expectError(error.OperationTimedOut, client.send(.{}));
    try testing.expect(elapsedNs(started) >= 200 * std.time.ns_per_ms);

    // The connection is finished. It carries no further request, so the
    // pool above this engine dials rather than hand it out again. See
    // `Session.usableLocked`.
    try testing.expect(client.session.read_timed_out);
    try testing.expect(!client.session.usable());
}

test "a peer that answers a head and then goes quiet reaches the read deadline" {
    // The body half of the same peer. The head is whole, so the transfer
    // is under way and only the body read waits. `--speed-limit` and
    // `--speed-time` describe exactly this, and `zurl_stream.Stall` cannot
    // report it: that watchdog measures a read once the read comes back,
    // and this read never does.
    var server: h2_test_server.H2TestServer = undefined;
    try server.startWith(&.{.{ .fields = &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "100" },
    } }}, .{ .stall = .after_head });
    defer server.stop();

    var client: TestClient = undefined;
    try client.connectWith(testing.allocator, server.port(), readTimeoutMs(200));
    defer client.deinit();

    var exchange = try client.send(.{});
    defer exchange.close();
    try testing.expectEqual(@as(u16, 200), exchange.head().status);
    try testing.expectEqual(@as(?u64, 100), exchange.head().content_length);

    const started = std.Io.Timestamp.now(testing.io, .awake);
    try testing.expectError(error.ReadFailed, readBody(exchange));
    // **The deadline is reported and not the short body.** Both are true
    // of this response, and the one that says why the transfer ended is
    // the peer that went quiet. `h1.Exchange.check` orders the two the
    // same way.
    try testing.expectError(error.OperationTimedOut, exchange.check());
    try testing.expect(elapsedNs(started) >= 200 * std.time.ns_per_ms);

    try testing.expect(client.session.read_timed_out);
    try testing.expect(!client.session.usable());
}

test "the read deadline is on one read and not on the transfer" {
    // **A transfer that keeps delivering runs for as long as it needs.**
    // The bound is 200 milliseconds and the body arrives in chunks the
    // server writes one after another, so the whole read takes longer than
    // the bound and every single read inside it is far shorter. A bound on
    // the transfer would end this download; a bound on one read does not.
    // That is why curl ships `--speed-limit` and `--speed-time` as a pair
    // rather than one total.
    const gpa = testing.allocator;
    const body = "0123456789" ** 400;
    var server: h2_test_server.H2TestServer = undefined;
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "4000" },
        },
        .body = body,
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connectWith(testing.allocator, server.port(), readTimeoutMs(200));
    defer client.deinit();

    var exchange = try client.send(.{});
    defer exchange.close();
    const got = try readBody(exchange);
    defer gpa.free(got);
    try testing.expectEqualStrings(body, got);
    try exchange.check();
    try testing.expect(!client.session.read_timed_out);
}

test "a frame for another stream on the same connection starts the deadline again" {
    // **The deadline is on the connection read and never on one stream,
    // which is what makes it right for a multiplexed transport.**
    // `Session.read` comes back for a frame of any stream, so a connection
    // that is answering somebody starts the clock again on every frame. A
    // bound kept per stream would fire on the stream that is waiting while
    // the connection was busy serving the other one, and would close a
    // connection that is working.
    //
    // `Options.interleave` writes the second stream's whole body between
    // the two halves of the first stream's body, so the first exchange is
    // inside a read while frames for the second arrive. The bound is 200
    // milliseconds and neither exchange reaches it.
    const gpa = testing.allocator;
    var server: h2_test_server.H2TestServer = undefined;
    try server.startWith(&.{
        .{
            .fields = &.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-length", .value = "4" },
            },
            .body = "abcd",
            .head_only_first = true,
        },
        .{
            .fields = &.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-length", .value = "2" },
            },
            .body = "ok",
        },
    }, .{ .interleave = true, .requests_per_connection = 2 });
    defer server.stop();

    var client: TestClient = undefined;
    try client.connectWith(testing.allocator, server.port(), readTimeoutMs(200));
    defer client.deinit();
    client.session.markShared();

    var first = try client.send(.{});
    defer first.close();
    var second = try client.send(.{ .path = "/second" });
    defer second.close();

    const second_body = try readBody(second);
    defer gpa.free(second_body);
    try testing.expectEqualStrings("ok", second_body);

    const first_body = try readBody(first);
    defer gpa.free(first_body);
    try testing.expectEqualStrings("abcd", first_body);

    try testing.expect(!client.session.read_timed_out);
    try testing.expect(client.session.usable());
}

test "an ordinary build bounds every read, so no bound is ever dropped" {
    // **The count is the record of a recovery that has no other trace.** A
    // build with no second unit of concurrency cannot watch a clock while
    // a read is in flight, so `engine.raceRead` runs the read unbounded
    // and counts it here rather than refuse a transfer this build could
    // otherwise make. This suite runs on a build that has the
    // concurrency, so the answer is zero, and a build where it is not
    // zero has a bound nobody is keeping. See `Session.readBoundsDropped`.
    var server: h2_test_server.H2TestServer = undefined;
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "2" },
        },
        .body = "ok",
    }});
    defer server.stop();

    var client: TestClient = undefined;
    try client.connectWith(testing.allocator, server.port(), readTimeoutMs(2000));
    defer client.deinit();

    var exchange = try client.send(.{});
    defer exchange.close();
    const body = try readBody(exchange);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("ok", body);
    try testing.expectEqual(@as(usize, 0), client.session.readBoundsDropped());
}
