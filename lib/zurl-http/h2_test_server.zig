//! A loopback HTTP/2 server for tests.
//!
//! This is a test fixture, not a product. `test_server.zig` speaks plain
//! HTTP/1.1 over a socket, and no HTTP/2 test can use it: HTTP/2 carries a
//! connection preface, a `SETTINGS` exchange, and framed headers, and none
//! of that is a line of text. So this fixture speaks frames.
//!
//! **It speaks HTTP/2 with prior knowledge, over cleartext.** A real zurl
//! transfer reaches HTTP/2 through the ALPN answer of a TLS handshake, and
//! a test may not open a TLS session against a real peer. RFC 9113 section
//! 3.3 lets a client that already knows the peer speaks HTTP/2 send the
//! preface straight away, which is what a test does here. The frames on the
//! wire are the same frames a TLS session would carry, so everything this
//! fixture proves about the engine holds over TLS too.
//!
//! No test may reach the real network. Every server this fixture starts
//! listens on 127.0.0.1 with an OS-assigned port.
//!
//! `start` takes a script of replies, served in order. `startWith` takes
//! the settings the server advertises and the faults it injects, which is
//! what a test of flow control, of `GOAWAY`, of `PING`, or of server push
//! needs.

const std = @import("std");
const zurl_h2 = @import("zurl-h2");
const zurl_hpack = @import("zurl-hpack");
const test_server = @import("test_server.zig");
const testing = std.testing;

pub const H2TestServer = @This();

/// How many requests one server keeps a record of.
pub const capture_max = 4;

/// How large one captured request, the rendered head and the body together,
/// may be. A request longer than this keeps its first `capture_bytes`
/// octets.
pub const capture_bytes = 16384;

/// The read buffer of one connection. It holds a frame of the default
/// `SETTINGS_MAX_FRAME_SIZE` with room to spare.
const read_buffer_len = 32 * 1024;
const write_buffer_len = 32 * 1024;

/// One scripted reply.
pub const Response = struct {
    /// The response fields, `:status` first, exactly as they go out. Every
    /// name must already be lower case, because that is what RFC 9113
    /// section 8.2.1 puts on the wire.
    fields: []const zurl_hpack.Field,
    /// The response body.
    body: []const u8 = "",
    /// The fields of a trailer section, or none. RFC 9113 section 8.1.
    trailers: []const zurl_hpack.Field = &.{},
    /// How many octets of the body go into one `DATA` frame. A small
    /// number is what makes a test of a body that arrives in pieces.
    data_chunk: usize = 16384,
    /// How many `PING` frames go out before each `DATA` frame.
    ///
    /// A `PING` carries no body octet, so it is a frame that makes no
    /// progress. This is the peer that alternates a run of such frames
    /// with one octet of progress, which is what a per-call idle budget
    /// could never catch.
    pings_before_chunk: usize = 0,
    /// Whether the reply goes out before the request body has ended.
    ///
    /// RFC 9113 section 8.1 allows it, and a `413` for a large upload is
    /// the ordinary case. A client must stop sending and read the answer.
    answer_early: bool = false,
    /// Whether this reply's head goes out on its own, leaving the body for
    /// `serveInterleaved` to write later.
    ///
    /// This is what lets two streams be open at once. See
    /// `Options.interleave`.
    head_only_first: bool = false,
    /// Whether `END_STREAM` goes out on an empty `DATA` frame of its own,
    /// after the last frame that carries a body octet.
    ///
    /// **This is the shape the Cloudflare edge answers in, and it is what
    /// a content decoder cannot see.** `gzip` and `deflate` end at the
    /// last octet of the compressed member, so a client that stops
    /// reading there never reads this frame and never learns that the
    /// stream ended. See `h2.Exchange.finishFraming`.
    ///
    /// RFC 9113 section 6.1 allows a `DATA` frame with no octet in it.
    /// `trailers` carries the flag instead when a reply has both.
    end_stream_alone: bool = false,
    /// A frame the server writes after the head, over and over, and never
    /// with `END_STREAM`. Null for a reply that ends.
    ///
    /// This is the hostile peer of `h2.Session.advanced`: every frame
    /// below is legal, costs the server nine octets, and moves no bound a
    /// client keeps. A client that counted one of them as progress put its
    /// own idle budget back on every frame and read them for ever.
    flood: ?Flood = null,
};

/// The stream identifier `Options.idle_stream_frame` names.
///
/// It is odd, so it is a client-initiated identifier, and it is above the
/// first few a client hands out, so a client that has opened one or two
/// streams has still never opened this one. That is what makes it idle in
/// the sense of RFC 9113 section 5.1.
pub const idle_stream_id: u31 = 4097;

/// A frame a server can write on an idle stream. See
/// `Options.idle_stream_frame`.
pub const IdleFrame = enum {
    headers,
    rst_stream,
    priority,
    data,
    window_update,
};

/// A frame shape a server can send without end. See `Response.flood`.
pub const Flood = enum {
    /// A trailer section: a `HEADERS` frame with `END_HEADERS`, an empty
    /// block, and no `END_STREAM`.
    trailer_headers,
    /// A `DATA` frame of no octets and no `END_STREAM`.
    empty_data,
};

/// Where a stalling server stops writing. See `Options.stall`.
pub const Stall = enum {
    /// The request is read in full and no frame of an answer goes out.
    /// This is the head phase of a transfer.
    before_head,
    /// The response `HEADERS` goes out with no `END_STREAM`, so the client
    /// has a whole head and a body still to come, and no `DATA` follows.
    /// This is the body phase of a transfer.
    after_head,
};

/// What `startWith` takes beyond the script.
pub const Options = struct {
    host: []const u8 = "127.0.0.1",
    /// What the server puts in its own `SETTINGS` frame.
    ///
    /// A small `initial_window_size` is what makes a test of flow control:
    /// a client with a body larger than the window must wait for a
    /// `WINDOW_UPDATE` and must not deadlock waiting.
    settings: zurl_h2.Settings = .initial,
    /// How many requests one accepted connection serves.
    requests_per_connection: ?usize = 1,
    /// Whether the server sends a `PING` before its first reply. A client
    /// must answer it with a `PING` that carries the same eight octets.
    ping_first: bool = false,
    /// A `PUSH_PROMISE` the server sends before its reply. A client that
    /// sent `SETTINGS_ENABLE_PUSH` of 0 must refuse the connection.
    push_first: bool = false,
    /// A `GOAWAY` the server sends instead of a reply.
    goaway: ?zurl_h2.ErrorCode = null,
    /// The last stream identifier the `GOAWAY` names.
    goaway_last_stream: u31 = 0,
    /// A `RST_STREAM` the server sends instead of a reply.
    reset: ?zurl_h2.ErrorCode = null,
    /// Whether the server sends `HEADERS` and then stops, leaving the body
    /// shorter than the `content-length` it announced.
    cut_body: bool = false,
    /// Where the server stops writing, or null for a server that answers
    /// in full.
    ///
    /// **It stalls and it never closes.** A server that closes the socket
    /// gives the client `EndOfStream`, which every engine already reports.
    /// The shape that had no bound at all is the peer that holds an open
    /// connection and writes nothing, so this server goes quiet and stays
    /// there: `run` parks in `discardRemaining` until the client goes
    /// away or `stop` cancels the task. See `h2.Session.read_timeout`.
    stall: ?Stall = null,
    /// A frame the server writes on a stream that the client never
    /// opened, before its reply, or null for none.
    ///
    /// **RFC 9113 section 5.1 calls such a stream idle**, and a receiver
    /// takes every frame but `PRIORITY` on one as a connection error of
    /// type `PROTOCOL_ERROR`. The identifier is `idle_stream_id`, which is
    /// above every one a client under test hands out.
    idle_stream_frame: ?IdleFrame = null,
    /// Whether the server writes a `RST_STREAM` for the stream it
    /// answered last, just before it answers the next one.
    ///
    /// **This is not the idle case and must be accepted.** The client has
    /// read that stream to its end and let it go by then, so the frame
    /// names a stream that is closed and not one that was never open.
    /// Section 5.1 allows it: the reset was already on the wire when this
    /// side closed the stream. curl 8.21.0 finishes such a transfer with
    /// exit 0, measured. The script must hold two replies or more and
    /// `requests_per_connection` must allow them on one connection.
    reset_closed_stream: bool = false,
    /// Whether the server keeps two streams open at once and writes their
    /// bodies interleaved.
    ///
    /// **This is the shape a multiplexing client has to read.** The script
    /// must hold exactly two replies, the first with `head_only_first` set,
    /// and the exchange runs like this:
    ///
    /// 1. read the first request, on stream 1
    /// 2. write its `HEADERS`, with no `END_STREAM`, so the client's head
    ///    read returns while the body is still coming
    /// 3. read the second request, on stream 3
    /// 4. write the second `HEADERS`, then one `DATA` for stream 1, then
    ///    the whole of stream 3's body, then the rest of stream 1's body
    ///
    /// Step 4 is what makes the client buffer: while it waits for stream
    /// 1's body it reads frames for stream 3, which belong to an exchange
    /// that is not the one asking. See `h2.Stream.inbox`.
    interleave: bool = false,
};

server: std.Io.net.Server,
task: std.Io.Future(void),
options: Options,
/// The rendered request head of each request, then the request body behind
/// it.
capture_storage: [capture_max][capture_bytes]u8,
capture_head_lens: [capture_max]usize,
capture_lens: [capture_max]usize,
/// How many body octets each request carried, counted whether or not they
/// fit `capture_storage`. A test of a body larger than one slot asserts on
/// this count and on the part of the body that fits.
capture_body_lens: [capture_max]u64,
capture_count: std.atomic.Value(usize),
accept_count: std.atomic.Value(usize),
/// How many `PING` replies the client sent. A test of the `PING` answer
/// reads this.
ping_replies: std.atomic.Value(usize),

/// Starts a server that serves `script` in order, one request for each
/// entry, then stops accepting.
pub fn start(self: *H2TestServer, script: []const Response) !void {
    return self.startWith(script, .{});
}

/// The same as `start`, with every choice this fixture offers spelled out.
pub fn startWith(self: *H2TestServer, script: []const Response, options: Options) !void {
    std.debug.assert(script.len <= capture_max);

    var address = try std.Io.net.IpAddress.parse(options.host, 0);
    self.server = try address.listen(testing.io, .{ .reuse_address = true });
    errdefer self.server.deinit(testing.io);

    self.options = options;
    self.capture_head_lens = @splat(0);
    self.capture_lens = @splat(0);
    self.capture_body_lens = @splat(0);
    self.capture_count = .init(0);
    self.accept_count = .init(0);
    self.ping_replies = .init(0);

    self.task = testing.io.concurrent(run, .{ self, script }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
}

/// Stops the server task and releases the listening socket.
pub fn stop(self: *H2TestServer) void {
    self.task.cancel(testing.io);
    self.server.deinit(testing.io);
}

pub fn port(self: *const H2TestServer) u16 {
    return self.server.socket.address.getPort();
}

pub fn accepts(self: *const H2TestServer) usize {
    return self.accept_count.load(.acquire);
}

pub fn pingReplies(self: *const H2TestServer) usize {
    return self.ping_replies.load(.acquire);
}

/// The request head of request `index`, rendered one field to a line as
/// `name: value\r\n`, the pseudo headers included and in the order they
/// arrived.
///
/// Rendered rather than kept as a field list, so a test asserts on it with
/// the same helpers an HTTP/1.1 test uses, `test_server.countHeaders` among
/// them.
pub fn requestHead(self: *const H2TestServer, index: usize) ?[]const u8 {
    if (index >= self.capture_count.load(.acquire)) return null;
    return self.capture_storage[index][0..self.capture_head_lens[index]];
}

/// The request body of request `index`, or null when the server has not
/// answered that many requests yet.
///
/// A body longer than one capture slot keeps its front. Read
/// `requestBodyLen` beside this for the count that was really sent.
pub fn requestBody(self: *const H2TestServer, index: usize) ?[]const u8 {
    if (index >= self.capture_count.load(.acquire)) return null;
    const slot = &self.capture_storage[index];
    return slot[self.capture_head_lens[index]..self.capture_lens[index]];
}

/// How many body octets request `index` carried, whether or not they fit
/// the capture slot.
pub fn requestBodyLen(self: *const H2TestServer, index: usize) ?u64 {
    if (index >= self.capture_count.load(.acquire)) return null;
    return self.capture_body_lens[index];
}

/// The value of `name` in the head of request `index`, or null.
pub fn requestField(self: *const H2TestServer, index: usize, name: []const u8) ?[]const u8 {
    const head = self.requestHead(index) orelse return null;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        // A pseudo header opens with a colon, so the name runs past it.
        const at = if (colon == 0) std.mem.indexOfScalarPos(u8, line, 1, ':') orelse continue else colon;
        if (!std.mem.eql(u8, line[0..at], name)) continue;
        return std.mem.trim(u8, line[at + 1 ..], " \t");
    }
    return null;
}

/// One connection's worth of state.
const Peer = struct {
    self: *H2TestServer,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    /// The socket reader and the socket writer behind `reader` and
    /// `writer`. They hold the cause behind `error.ReadFailed` and
    /// `error.WriteFailed`, which is what `canceled` reads.
    stream_reader: *const std.Io.net.Stream.Reader,
    stream_writer: *const std.Io.net.Stream.Writer,
    frames: zurl_h2.FrameReader,
    decoder: zurl_hpack.Decoder,
    /// The header block being joined.
    block: std.ArrayList(u8),
    /// The stream the client opened for the request now being read.
    stream_id: u31,
    /// The stream the last reply went out on, or 0 before the first one.
    /// See `Options.reset_closed_stream`.
    answered_stream_id: u31 = 0,
    /// Whether the client ended its side of that stream.
    request_ended: bool,
    /// Whether a whole header block has arrived for that stream.
    head_ready: bool,
    /// How many body octets arrived and have not been credited back.
    owed: u32,

    fn deinit(p: *Peer, gpa: std.mem.Allocator) void {
        p.frames.deinit(gpa);
        p.decoder.deinit(gpa);
        p.block.deinit(gpa);
    }

    fn write(p: *Peer, bytes: []const u8) !void {
        try p.writer.writeAll(bytes);
    }

    fn flush(p: *Peer) !void {
        try p.writer.flush();
    }

    /// Whether `stop` has canceled the task that serves this connection.
    /// See `test_server.taskCanceled` for why a canceled task must return
    /// at once.
    fn canceled(p: *const Peer) bool {
        return test_server.taskCanceled(p.stream_reader, p.stream_writer);
    }
};

fn run(self: *H2TestServer, script: []const Response) void {
    const gpa = testing.allocator;
    var next: usize = 0;
    while (next < script.len) {
        const stream = self.server.accept(testing.io) catch return;
        defer stream.close(testing.io);
        self.accept_count.store(self.accept_count.load(.monotonic) + 1, .release);

        var read_buffer: [read_buffer_len]u8 = undefined;
        var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
        var write_buffer: [write_buffer_len]u8 = undefined;
        var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);

        var peer: Peer = .{
            .self = self,
            .reader = &reader.interface,
            .writer = &writer.interface,
            .stream_reader = &reader,
            .stream_writer = &writer,
            .frames = zurl_h2.FrameReader.init(gpa, .{ .max_frame_size = 16384 }) catch return,
            .decoder = .init(.{}),
            .block = .empty,
            .stream_id = 0,
            .request_ended = false,
            .head_ready = false,
            .owed = 0,
        };
        defer peer.deinit(gpa);

        var left: usize = self.options.requests_per_connection orelse script.len;
        serve(self, &peer, script, &next, &left) catch {};
        if (peer.canceled()) return;

        // **The client is still reading the reply.** An operating system
        // resets a socket that is closed with octets still unread on it,
        // and the reply this server just wrote is thrown away with them.
        // A client that answers a `SETTINGS` frame writes its
        // acknowledgement after the reply is already on the way, so those
        // octets are always there.
        //
        // So this waits for the client to end the connection. `stop`
        // cancels the task, so a test that never connects again ends the
        // suite rather than hanging it.
        _ = peer.reader.discardRemaining() catch {};
        if (peer.canceled()) return;
    }
}

fn serve(
    self: *H2TestServer,
    peer: *Peer,
    script: []const Response,
    next: *usize,
    left: *usize,
) !void {
    const gpa = testing.allocator;

    // The client preface, then this side's own `SETTINGS` frame, which RFC
    // 9113 section 3.4 makes the first frame a server sends.
    try zurl_h2.preface.readClient(peer.reader);
    {
        var entries: [zurl_h2.settings.payload_len_max]u8 = undefined;
        const changes = self.options.settings.changesFrom(.initial);
        var out: [zurl_h2.frame.header_len + zurl_h2.settings.payload_len_max]u8 = undefined;
        const frame_payload: zurl_h2.SettingsFrame = .{
            .ack = false,
            .entries = changes.encode(&entries),
        };
        try peer.write(frame_payload.encode(&out));
        try peer.flush();
    }

    if (self.options.interleave) return serveInterleaved(self, peer, script, next, left);

    while (next.* < script.len and left.* > 0) {
        peer.stream_id = 0;
        peer.request_ended = false;
        peer.head_ready = false;

        const reply = script[next.*];
        var answered = false;

        // Read until the request is whole, or until an early answer is due.
        while (!peer.request_ended) {
            if (reply.answer_early and peer.head_ready and !answered) break;
            try readOne(self, peer, next.*, gpa);
        }

        if (self.options.push_first) {
            var out: [zurl_h2.frame.header_len + 4 + 8]u8 = undefined;
            const promise: zurl_h2.PushPromise = .{
                .promised_stream_id = 2,
                .block = "\x82",
                .end_headers = true,
            };
            try peer.write(promise.encode(peer.stream_id, &out));
            try peer.flush();
            // The promise stands in for the reply, so this script entry is
            // used up. Without that count, `run` goes back to `accept` for
            // a connection no test ever makes, and only `stop` can end it.
            next.* += 1;
            left.* -= 1;
            return;
        }

        if (self.options.goaway) |code| {
            var out: [zurl_h2.frame.header_len + zurl_h2.Goaway.fixed_len]u8 = undefined;
            const bye: zurl_h2.Goaway = .{
                .last_stream_id = self.options.goaway_last_stream,
                .error_code = code,
            };
            try peer.write(bye.encode(&out));
            try peer.flush();
            // The `GOAWAY` stands in for the reply, so this script entry
            // is used up. See the `push_first` arm above.
            next.* += 1;
            left.* -= 1;
            return;
        }

        if (self.options.reset) |code| {
            var out: [zurl_h2.frame.header_len + zurl_h2.RstStream.payload_len]u8 = undefined;
            const rst: zurl_h2.RstStream = .{ .error_code = code };
            try peer.write(rst.encode(peer.stream_id, &out));
            try peer.flush();
            next.* += 1;
            left.* -= 1;
            continue;
        }

        if (self.options.ping_first) {
            var out: [zurl_h2.frame.header_len + zurl_h2.Ping.payload_len]u8 = undefined;
            const ping: zurl_h2.Ping = .{ .opaque_data = .{ 1, 2, 3, 4, 5, 6, 7, 8 } };
            try peer.write(ping.encode(&out));
            try peer.flush();
            // The reply is read here and not after the answer, because
            // after the answer this server drains the socket without
            // reading a frame off it. The wait is bounded, so a client
            // that answers nothing ends the test rather than hanging it.
            const before = self.ping_replies.load(.monotonic);
            var waited: usize = 0;
            while (self.ping_replies.load(.monotonic) == before and waited < 16) : (waited += 1) {
                readOne(self, peer, next.*, gpa) catch break;
            }
            if (peer.canceled()) return;
        }

        // **The server goes quiet here and writes nothing more.** The
        // script entry is used up, so `run` leaves the accept loop and
        // parks in `discardRemaining`, which holds the connection open
        // until the client goes away or `stop` cancels the task. See
        // `Options.stall`.
        if (self.options.stall) |where| {
            switch (where) {
                .before_head => {},
                .after_head => {
                    const block = try zurl_hpack.encoder.encodeAlloc(gpa, reply.fields, .{});
                    defer gpa.free(block);
                    try writeBlock(peer, peer.stream_id, .headers, block, false);
                    try peer.flush();
                },
            }
            next.* += 1;
            left.* -= 1;
            return;
        }

        try writeReply(peer, reply, gpa);
        answered = true;

        // A reply that went out early still has to take the rest of the
        // request body off the socket, or the next request would read it.
        while (!peer.request_ended) {
            readOne(self, peer, next.*, gpa) catch break;
        }
        if (peer.canceled()) return;

        next.* += 1;
        left.* -= 1;
    }
}

/// Serves two requests with both streams open at once. See
/// `Options.interleave` for the order of the frames.
fn serveInterleaved(
    self: *H2TestServer,
    peer: *Peer,
    script: []const Response,
    next: *usize,
    left: *usize,
) !void {
    const gpa = testing.allocator;
    std.debug.assert(script.len == 2);
    std.debug.assert(script[0].head_only_first);

    // The first request, on stream 1.
    peer.stream_id = 0;
    peer.request_ended = false;
    peer.head_ready = false;
    while (!peer.request_ended) try readOne(self, peer, 0, gpa);
    const first_stream = peer.stream_id;
    next.* += 1;

    // Its head alone. No `END_STREAM`, so the client reads a head and then
    // has a body still to come, which is what leaves this stream open
    // while the next one opens.
    {
        const block = try zurl_hpack.encoder.encodeAlloc(gpa, script[0].fields, .{});
        defer gpa.free(block);
        try writeBlock(peer, first_stream, .headers, block, false);
        try peer.flush();
    }

    // The second request, on stream 3.
    peer.stream_id = 0;
    peer.request_ended = false;
    peer.head_ready = false;
    while (!peer.request_ended) try readOne(self, peer, 1, gpa);
    const second_stream = peer.stream_id;
    next.* += 1;
    left.* = 0;

    // The second head, then one chunk of the first body, then the whole
    // second body, then the rest of the first body. The client is inside a
    // read for one stream while frames for the other arrive, which is the
    // whole point of this script.
    {
        const block = try zurl_hpack.encoder.encodeAlloc(gpa, script[1].fields, .{});
        defer gpa.free(block);
        try writeBlock(peer, second_stream, .headers, block, false);
    }

    const first_body = script[0].body;
    const split = first_body.len / 2;
    try writeData(peer, first_stream, first_body[0..split], false);
    try writeData(peer, second_stream, script[1].body, true);
    try writeData(peer, first_stream, first_body[split..], true);
    try peer.flush();

    // Whatever the client sends behind its requests, such as a `SETTINGS`
    // acknowledgement, is taken off the socket by `run`.
}

/// Writes one `DATA` frame.
fn writeData(peer: *Peer, stream_id: u31, bytes: []const u8, end_stream: bool) !void {
    var head: [zurl_h2.frame.header_len]u8 = undefined;
    (zurl_h2.Header{
        .length = @intCast(bytes.len),
        .type = .data,
        .flags = if (end_stream) zurl_h2.flag.end_stream else 0,
        .stream_id = stream_id,
    }).encode(&head);
    try peer.write(&head);
    if (bytes.len != 0) try peer.write(bytes);
}

/// Reads one frame and applies it.
fn readOne(self: *H2TestServer, peer: *Peer, slot: usize, gpa: std.mem.Allocator) !void {
    const got = try peer.frames.next(peer.reader);
    switch (got.payload) {
        .settings => |s| {
            if (s.ack) return;
            var ignored: zurl_h2.Settings = .initial;
            _ = try s.applyTo(&ignored);
            try zurl_h2.preface.writeSettingsAck(peer.writer);
            try peer.flush();
        },
        .ping => |p| {
            if (p.ack) {
                self.ping_replies.store(self.ping_replies.load(.monotonic) + 1, .release);
                return;
            }
            var out: [zurl_h2.frame.header_len + zurl_h2.Ping.payload_len]u8 = undefined;
            try peer.write(p.reply().encode(&out));
            try peer.flush();
        },
        .headers => |h| {
            peer.stream_id = got.header.stream_id;
            peer.block.clearRetainingCapacity();
            try peer.block.appendSlice(gpa, h.block);
            if (h.end_stream) peer.request_ended = true;
            if (h.end_headers) try finishHead(peer, slot, gpa);
        },
        .continuation => |c| {
            try peer.block.appendSlice(gpa, c.block);
            if (c.end_headers) try finishHead(peer, slot, gpa);
        },
        .data => |d| {
            capture(&peer.self.capture_storage[slot], &peer.self.capture_lens[slot], d.data);
            peer.self.capture_body_lens[slot] += d.data.len;
            peer.self.capture_count.store(slot + 1, .release);
            // The room goes straight back, on the connection and on the
            // stream, which is what lets a client send a body larger than
            // one window.
            peer.owed += got.header.length;
            if (peer.owed != 0) {
                var out: [zurl_h2.frame.header_len + zurl_h2.WindowUpdate.payload_len]u8 = undefined;
                const update: zurl_h2.WindowUpdate = .{ .increment = @intCast(peer.owed) };
                try peer.write(update.encode(0, &out));
                try peer.write(update.encode(got.header.stream_id, &out));
                try peer.flush();
                peer.owed = 0;
            }
            if (d.end_stream) peer.request_ended = true;
        },
        .rst_stream => peer.request_ended = true,
        .goaway => return error.EndOfStream,
        else => {},
    }
}

/// Decodes the header block that just finished and records it.
fn finishHead(peer: *Peer, slot: usize, gpa: std.mem.Allocator) !void {
    var list = try peer.decoder.decode(gpa, peer.block.items);
    defer list.deinit(gpa);
    peer.block.clearRetainingCapacity();
    peer.head_ready = true;

    const storage = &peer.self.capture_storage[slot];
    var used: usize = 0;
    for (list.fields.items) |item| {
        capture(storage, &used, item.name);
        capture(storage, &used, ": ");
        capture(storage, &used, item.value);
        capture(storage, &used, "\r\n");
    }
    capture(storage, &used, "\r\n");
    peer.self.capture_head_lens[slot] = used;
    peer.self.capture_lens[slot] = used;
    peer.self.capture_count.store(slot + 1, .release);
}

fn writeReply(peer: *Peer, reply: Response, gpa: std.mem.Allocator) !void {
    if (peer.self.options.idle_stream_frame) |kind| try writeIdleFrame(peer, kind, gpa);
    if (peer.self.options.reset_closed_stream and peer.answered_stream_id != 0) {
        var out: [zurl_h2.frame.header_len + zurl_h2.RstStream.payload_len]u8 = undefined;
        const rst: zurl_h2.RstStream = .{ .error_code = .cancel };
        try peer.write(rst.encode(peer.answered_stream_id, &out));
        try peer.flush();
    }
    peer.answered_stream_id = peer.stream_id;

    const block = try zurl_hpack.encoder.encodeAlloc(gpa, reply.fields, .{});
    defer gpa.free(block);

    // An empty `DATA` frame of its own carries the flag, so the head must
    // not carry it and neither must the last frame with octets in it.
    const tail_alone = reply.end_stream_alone and reply.trailers.len == 0;
    // A flood never ends the stream, so no frame of this reply carries the
    // flag.
    const flooding = reply.flood != null;
    const no_body = reply.body.len == 0 and reply.trailers.len == 0 and !tail_alone and !flooding;
    try writeBlock(peer, peer.stream_id, .headers, block, no_body);

    var at: usize = 0;
    while (at < reply.body.len) {
        var sent_pings: usize = 0;
        while (sent_pings < reply.pings_before_chunk) : (sent_pings += 1) {
            var ping_out: [zurl_h2.frame.header_len + zurl_h2.Ping.payload_len]u8 = undefined;
            const ping: zurl_h2.Ping = .{ .opaque_data = .{ 1, 2, 3, 4, 5, 6, 7, 8 } };
            try peer.write(ping.encode(&ping_out));
        }

        const chunk = @min(reply.data_chunk, reply.body.len - at);
        const last = at + chunk == reply.body.len;
        var head: [zurl_h2.frame.header_len]u8 = undefined;
        (zurl_h2.Header{
            .length = @intCast(chunk),
            .type = .data,
            .flags = if (last and reply.trailers.len == 0 and !tail_alone and !flooding)
                zurl_h2.flag.end_stream
            else
                0,
            .stream_id = peer.stream_id,
        }).encode(&head);
        try peer.write(&head);
        try peer.write(reply.body[at..][0..chunk]);
        at += chunk;
    }

    if (tail_alone) {
        var head: [zurl_h2.frame.header_len]u8 = undefined;
        (zurl_h2.Header{
            .length = 0,
            .type = .data,
            .flags = zurl_h2.flag.end_stream,
            .stream_id = peer.stream_id,
        }).encode(&head);
        try peer.write(&head);
    }

    if (reply.trailers.len != 0) {
        const trailer_block = try zurl_hpack.encoder.encodeAlloc(gpa, reply.trailers, .{});
        defer gpa.free(trailer_block);
        try writeBlock(peer, peer.stream_id, .headers, trailer_block, true);
    }

    try peer.flush();
    if (reply.flood) |kind| try writeFlood(peer, kind);
}

/// Writes one frame on `idle_stream_id`. See `Options.idle_stream_frame`.
fn writeIdleFrame(peer: *Peer, kind: IdleFrame, gpa: std.mem.Allocator) !void {
    const id = idle_stream_id;
    switch (kind) {
        .headers => {
            const block = try zurl_hpack.encoder.encodeAlloc(gpa, &.{
                .{ .name = ":status", .value = "200" },
            }, .{});
            defer gpa.free(block);
            try writeBlock(peer, id, .headers, block, true);
        },
        .rst_stream => {
            var out: [zurl_h2.frame.header_len + zurl_h2.RstStream.payload_len]u8 = undefined;
            const rst: zurl_h2.RstStream = .{ .error_code = .cancel };
            try peer.write(rst.encode(id, &out));
        },
        .priority => {
            // RFC 9113 section 6.3: five octets, a stream dependency and a
            // weight. The scheme is deprecated and the values mean
            // nothing to a client that reads the frame and drops it.
            var head: [zurl_h2.frame.header_len]u8 = undefined;
            (zurl_h2.Header{ .length = 5, .type = .priority, .flags = 0, .stream_id = id }).encode(&head);
            try peer.write(&head);
            try peer.write(&[_]u8{ 0, 0, 0, 0, 15 });
        },
        .data => {
            var head: [zurl_h2.frame.header_len]u8 = undefined;
            (zurl_h2.Header{ .length = 2, .type = .data, .flags = 0, .stream_id = id }).encode(&head);
            try peer.write(&head);
            try peer.write("xy");
        },
        .window_update => {
            var out: [zurl_h2.frame.header_len + zurl_h2.WindowUpdate.payload_len]u8 = undefined;
            const update: zurl_h2.WindowUpdate = .{ .increment = 100 };
            try peer.write(update.encode(id, &out));
        },
    }
    try peer.flush();
}

/// Writes one frame shape until the client goes away or `stop` cancels
/// this task. See `Response.flood`.
fn writeFlood(peer: *Peer, kind: Flood) !void {
    var head: [zurl_h2.frame.header_len]u8 = undefined;
    while (!peer.canceled()) {
        (zurl_h2.Header{
            .length = 0,
            .type = switch (kind) {
                .trailer_headers => .headers,
                .empty_data => .data,
            },
            .flags = switch (kind) {
                .trailer_headers => zurl_h2.flag.end_headers,
                .empty_data => 0,
            },
            .stream_id = peer.stream_id,
        }).encode(&head);
        // A client that stopped reading leaves this write to fail, which
        // is how the flood ends.
        try peer.write(&head);
        try peer.flush();
    }
}

fn writeBlock(
    peer: *Peer,
    stream_id: u31,
    first_type: zurl_h2.Type,
    block: []const u8,
    end_stream: bool,
) !void {
    const room: usize = 16384;
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
            .type = if (first) first_type else .continuation,
            .flags = flags,
            .stream_id = stream_id,
        }).encode(&head);
        try peer.write(&head);
        if (take != 0) try peer.write(block[at..][0..take]);
        at += take;
        first = false;
        if (last) break;
    }
}

/// Appends as much of `text` as fits past `at.*`. A record longer than the
/// slot is truncated, not dropped: this is a record for a test to read.
fn capture(slot: *[capture_bytes]u8, at: *usize, text: []const u8) void {
    const n = @min(slot.len - at.*, text.len);
    @memcpy(slot[at.*..][0..n], text[0..n]);
    at.* += n;
}

test "the fixture completes a preface, answers SETTINGS, and replies to one request" {
    // The fixture itself, proved with a client written by hand. Everything
    // the HTTP/2 engine tests assert rests on this, so a fixture that
    // answered nothing would make them pass for the wrong reason.
    const gpa = testing.allocator;

    var server: H2TestServer = undefined;
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "2" },
        },
        .body = "hi",
    }});
    defer server.stop();

    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(server.port()) };
    const stream = try address.connect(testing.io, .{ .mode = .stream });
    defer stream.close(testing.io);

    var write_buffer: [4096]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);
    try zurl_h2.preface.writeClientFlight(&writer.interface, .initial);

    const fields = [_]zurl_hpack.Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "x" },
        .{ .name = ":path", .value = "/hello" },
    };
    const block = try zurl_hpack.encoder.encodeAlloc(gpa, &fields, .{});
    defer gpa.free(block);

    var head: [zurl_h2.frame.header_len]u8 = undefined;
    (zurl_h2.Header{
        .length = @intCast(block.len),
        .type = .headers,
        .flags = zurl_h2.flag.end_headers | zurl_h2.flag.end_stream,
        .stream_id = 1,
    }).encode(&head);
    try writer.interface.writeAll(&head);
    try writer.interface.writeAll(block);
    try writer.interface.flush();

    var read_buffer: [4096]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    var frames = try zurl_h2.FrameReader.init(gpa, .{});
    defer frames.deinit(gpa);
    var decoder: zurl_hpack.Decoder = .init(.{});
    defer decoder.deinit(gpa);

    var status: ?u16 = null;
    var body: [16]u8 = undefined;
    var body_len: usize = 0;
    var frames_read: usize = 0;
    while (frames_read < 16) : (frames_read += 1) {
        const got = try frames.next(&reader.interface);
        switch (got.payload) {
            .headers => |h| {
                var list = try decoder.decode(gpa, h.block);
                defer list.deinit(gpa);
                status = try std.fmt.parseInt(u16, list.get(":status").?, 10);
            },
            .data => |d| {
                @memcpy(body[body_len..][0..d.data.len], d.data);
                body_len += d.data.len;
                if (d.end_stream) break;
            },
            else => {},
        }
    }

    try testing.expectEqual(@as(?u16, 200), status);
    try testing.expectEqualStrings("hi", body[0..body_len]);
    try testing.expectEqualStrings("/hello", server.requestField(0, ":path").?);
    try testing.expectEqualStrings("GET", server.requestField(0, ":method").?);
    try testing.expectEqual(@as(usize, 1), server.accepts());
}
