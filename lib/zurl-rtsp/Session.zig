//! One RTSP dialogue: the sequence numbers, and one reply off a socket.
//!
//! **`CSeq` is what ties a reply to a request, and this file is where that
//! tie is checked.** RFC 2326 section 12.17 puts a `CSeq` in every request
//! and in every reply, and a server must echo the number it was sent. A
//! session that read a reply with another number and carried on would be
//! reading the answer to one request as the answer to another, so a
//! mismatch here is `error.SequenceMismatch` and the session ends. That is
//! a protocol error and not something to skip past.
//!
//! **This is not the same question as connection reuse.** RTSP runs
//! several requests over one connection and a server may answer them out
//! of order, but this build sends one request at a time and reads its
//! reply before it sends another, so exactly one number is outstanding.
//! Checking it is one comparison, and it closes the whole shape.
//!
//! The read is bounded three ways, and each bound is named where it is
//! kept: one line by `reply.max_line_bytes`, the head together by
//! `reply.max_head_bytes`, and the body by the ceiling the caller passes
//! to `reply.head`. `zurl_net.bounded` keeps the stall bound on every one
//! of them, so a server that writes nothing does not hold this process.
//!
//! **This file holds no socket.** It reads and writes through a
//! `zurl_net.line.Channel`, which is a reader, a writer, and a flush, so a
//! test drives a whole dialogue over two buffers.

const Session = @This();

const std = @import("std");

const zurl_net = @import("zurl-net");

const reply = @import("reply.zig");

const Io = std.Io;

/// The number the first request of a session carries.
///
/// One, which is what curl writes: measured through a relay to a real
/// mediamtx 1.18.2, curl's first request line was followed by `CSeq: 1`.
pub const first_cseq: u64 = 1;

/// How many requests one session may send.
///
/// **A bound on round trips.** A session here sends one request, so this
/// number is never met. It is a bound anyway, because a counter with no
/// ceiling is a counter that wraps, and a wrapped `CSeq` would tie a reply
/// to a request that is not the one in play.
pub const max_requests: u64 = 1_000_000;

/// Every fault reading one reply can report.
pub const ReceiveError = zurl_net.bounded.LineError || reply.Error || error{
    /// The reply carries a `CSeq` that is not the one the request sent.
    /// See the module comment.
    SequenceMismatch,
    /// The server started an interleaved binary frame. See
    /// `interleave_marker`.
    InterleavedData,
    /// The head block this session built holds no line feed, so the status
    /// line has no end. See `receive`.
    HeadWithoutLineFeed,
};

/// The byte RFC 2326 section 10.12 gives an interleaved binary frame.
///
/// **Interleaved data is out of scope for this build, and it is refused by
/// name rather than read as text.** A server sends `$`, a channel byte,
/// and a two byte length, and then that many octets of RTP, all on the
/// control connection. This build never asks for it: it sends no
/// `Transport` naming `interleaved=`, so no server should send one. A
/// server that does anyway would otherwise have its binary frame read as
/// a status line, which is how a reader turns a media packet into a
/// header block.
pub const interleave_marker: u8 = '$';

/// Every fault sending one request can report.
pub const SendError = Io.Writer.Error;

/// One reply, read whole except for its body.
///
/// `head_block` and every slice inside `head` point into this session's
/// own storage, so they are valid until the next `receive`.
pub const Reply = struct {
    status: reply.Status,
    head: reply.Head,
    /// The status line and the header lines, each ending with a `CRLF`,
    /// and the empty line that ends the head.
    ///
    /// **This is what `-i` prints and what `Response.headers` carries.**
    /// curl treats an RTSP reply head the way it treats an HTTP one,
    /// measured: `curl -s -i rtsp://host/stream` printed
    /// `RTSP/1.0 200 OK`, the headers, and a blank line.
    head_block: []const u8,
};

io: Io,
/// Where this dialogue reads and writes. Undefined until `begin`.
channel: zurl_net.line.Channel,
/// How long one read may wait with no byte arriving.
stall: Io.Timeout,
/// The number the next request carries.
next_cseq: u64,
/// Holds one head line as it arrives.
line_storage: [reply.max_line_bytes]u8,
/// Holds every head line of the reply in play, joined.
head_storage: [reply.max_head_bytes]u8,
head_len: usize,

/// Starts `s` in place.
///
/// In place, and not a value returned, because the storage above is tens
/// of kilobytes and the head a caller holds points into it.
pub fn init(s: *Session, io: Io, channel: zurl_net.line.Channel, stall: Io.Timeout) void {
    s.io = io;
    s.channel = channel;
    s.stall = stall;
    s.next_cseq = first_cseq;
    s.head_len = 0;
}

/// Points the dialogue at another reader and writer, keeping the numbers.
///
/// Nothing in this build calls it yet: RTSP has no upgrade like FTP's
/// `AUTH TLS`. It is here because the numbers are the session's and not
/// the socket's, so a reader can see that the two are separate.
pub fn retarget(s: *Session, channel: zurl_net.line.Channel) void {
    s.channel = channel;
}

/// The number the next request carries.
///
/// Fails rather than wraps. See `max_requests`.
pub fn takeCseq(s: *Session) error{TooManyRequests}!u64 {
    if (s.next_cseq > max_requests) return error.TooManyRequests;
    const number = s.next_cseq;
    s.next_cseq += 1;
    return number;
}

/// Writes one request head, with its body when it has one, and flushes.
pub fn send(s: *Session, request_head: []const u8, body: []const u8) SendError!void {
    try s.channel.writer.writeAll(request_head);
    if (body.len != 0) try s.channel.writer.writeAll(body);
    try s.channel.flush(s.channel.ctx);
}

/// Reads one whole reply head and checks its `CSeq` against `expect`.
///
/// The body is not read here: `head.content_length` says how many octets
/// follow, already bounded against `max_body_bytes`, and the caller reads
/// them with `readBody`.
pub fn receive(s: *Session, expect: u64, max_body_bytes: u64) ReceiveError!Reply {
    s.head_len = 0;

    // **The one peek this file makes**, and it is what keeps a binary
    // frame from being read as a status line. See `interleave_marker`.
    try zurl_net.bounded.waitForBytes(s.channel.reader, s.io, s.stall);
    if (s.channel.reader.buffered()[0] == interleave_marker) return error.InterleavedData;

    const first = try zurl_net.bounded.readLine(
        s.channel.reader,
        s.io,
        &s.line_storage,
        s.stall,
    );
    // **Read once here to refuse a peer that is not speaking RTSP**, so a
    // whole head is never collected off one that is not. The status this
    // returns points into `line_storage`, which the next line overwrites,
    // so the one the caller gets is read again off the head block below.
    _ = try reply.status(first);
    try s.appendLine(first);

    while (true) {
        const raw = try zurl_net.bounded.readLine(
            s.channel.reader,
            s.io,
            &s.line_storage,
            s.stall,
        );
        try s.appendLine(raw);
        // The empty line ends the head. Its `CRLF` is already in the block
        // above, so the block a caller reads holds the blank line the way
        // curl prints it.
        if (raw.len == 0) break;
    }

    const block = s.head_storage[0..s.head_len];
    // The status line is in the block too, and `reply.head` reads header
    // lines, so the first line is left out of what it parses. The status
    // is read off the block rather than off `line_storage`, so the reason
    // phrase the caller holds outlives the lines that came after it.
    //
    // **A named fault and not an unwrap.** `appendLine` puts a `CRLF`
    // after every line it adds, and it ran for the status line above, so
    // the block holds a line feed today. `.?` on an empty optional is
    // undefined behaviour in a ReleaseFast or a ReleaseSmall build, which
    // is the build that ships, and the two slices below take their bounds
    // from this number. Only a change inside this file can make it empty,
    // so this reads as a read fault and never as a fault of the server.
    const first_end = std.mem.indexOfScalar(u8, block, '\n') orelse
        return error.HeadWithoutLineFeed;
    const line_status = try reply.status(std.mem.trimEnd(u8, block[0..first_end], "\r"));
    const headers_only = block[first_end + 1 ..];
    const read = try reply.head(headers_only, max_body_bytes);

    // **The tie between a reply and its request.** See the module comment.
    if (read.cseq != expect) return error.SequenceMismatch;

    return .{ .status = line_status, .head = read, .head_block = block };
}

/// Reads exactly `len` octets of body into `out`.
///
/// `out.len` must be `len`. The caller allocates it, after `receive` has
/// already bounded `len` against the caller's own ceiling.
pub fn readBody(s: *Session, out: []u8) zurl_net.bounded.ExactError!void {
    if (out.len == 0) return;
    return zurl_net.bounded.readExact(s.channel.reader, s.io, out, s.stall);
}

/// Adds one head line, with its `CRLF` put back, to the block.
fn appendLine(s: *Session, line: []const u8) error{HeadTooLarge}!void {
    if (line.len + 2 > s.head_storage.len - s.head_len) return error.HeadTooLarge;
    @memcpy(s.head_storage[s.head_len..][0..line.len], line);
    s.head_len += line.len;
    s.head_storage[s.head_len] = '\r';
    s.head_storage[s.head_len + 1] = '\n';
    s.head_len += 2;
}

/// Names the fault, for a message to a user.
pub fn describe(err: ReceiveError) []const u8 {
    return switch (err) {
        error.SequenceMismatch => "the rtsp server answered with a CSeq that belongs to no request zurl sent, so there is no telling which request the reply answers",
        error.InterleavedData => "the rtsp server started an interleaved binary frame, RFC 2326 section 10.12, and this build of zurl reads none: it asks for no interleaved transport, so a frame here belongs to no request it sent",
        error.HeadWithoutLineFeed => "zurl collected an rtsp reply head that has no end to its status line, which is a defect in zurl and not in the reply",
        error.EndOfStream => "the rtsp server closed the connection in the middle of a reply",
        error.LineTooLong => "the rtsp server sent a reply line longer than zurl reads",
        error.OutOfMemory => "zurl ran out of memory reading an rtsp reply",
        error.StreamTooLong => "the rtsp server sent more than zurl reads",
        error.ReadFailed => "zurl did not read from the rtsp server",
        error.OperationTimedOut => "the rtsp server sent no byte for as long as zurl waits",
        error.ReadTimeoutUnsupported => "this build has no concurrency, so an rtsp read cannot be bounded, and an unbounded one would wait for a server that may never answer",
        error.Canceled => "the rtsp read was stopped from outside",
        error.BadStatusLine,
        error.BadStatusCode,
        error.BadVersion,
        error.BadHeaderLine,
        error.NoSequenceNumber,
        error.BadSequenceNumber,
        error.BadContentLength,
        error.BodyTooLarge,
        error.HeadTooLarge,
        => reply.describe(@errorCast(err)),
    };
}

const testing = std.testing;

/// A channel over two fixed buffers, for a test with no socket at all.
const Loop = struct {
    reader: Io.Reader,
    writer: Io.Writer,
    sent: [4096]u8,

    fn init(l: *Loop, incoming: []const u8) void {
        l.reader = .fixed(incoming);
        l.writer = .fixed(&l.sent);
    }

    fn channel(l: *Loop) zurl_net.line.Channel {
        return .{ .reader = &l.reader, .writer = &l.writer, .ctx = null, .flush = noFlush };
    }

    fn written(l: *Loop) []const u8 {
        return l.writer.buffered();
    }

    fn noFlush(ctx: ?*anyopaque) Io.Writer.Error!void {
        _ = ctx;
    }
};

/// A `Session` and a `Loop`, both on the heap, so neither moves.
const Fixture = struct {
    session: Session,
    loop: Loop,

    fn start(incoming: []const u8) !*Fixture {
        const f = try testing.allocator.create(Fixture);
        f.loop.init(incoming);
        f.session.init(testing.io, f.loop.channel(), .none);
        return f;
    }

    fn stop(f: *Fixture) void {
        testing.allocator.destroy(f);
    }
};

test "a reply reads its status, its head block, and its length" {
    // The reply mediamtx sent curl, measured, with a body added.
    const wire =
        "RTSP/1.0 200 OK\r\n" ++
        "CSeq: 1\r\n" ++
        "Server: gortsplib\r\n" ++
        "Content-Length: 4\r\n" ++
        "\r\n" ++
        "body";

    const f = try Fixture.start(wire);
    defer f.stop();

    const answer = try f.session.receive(1, 1024);
    try testing.expectEqual(@as(u16, 200), answer.status.code);
    try testing.expectEqualStrings("OK", answer.status.reason);
    try testing.expectEqual(@as(u64, 4), answer.head.content_length);
    // **The head block is what `-i` prints**, with the blank line on the
    // end, which is the shape curl printed.
    try testing.expectEqualStrings(
        "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: gortsplib\r\nContent-Length: 4\r\n\r\n",
        answer.head_block,
    );

    var body: [4]u8 = undefined;
    try f.session.readBody(&body);
    try testing.expectEqualStrings("body", &body);
}

test "a reply carrying another request's CSeq ends the session" {
    // **The check this file exists for.** A session that carried on would
    // read the answer to one request as the answer to another.
    const f = try Fixture.start("RTSP/1.0 200 OK\r\nCSeq: 9\r\n\r\n");
    defer f.stop();

    try testing.expectError(error.SequenceMismatch, f.session.receive(1, 1024));
    try testing.expect(std.mem.indexOf(
        u8,
        describe(error.SequenceMismatch),
        "belongs to no request",
    ) != null);
}

test "a reply with no CSeq is a protocol error and not a reply this session guesses about" {
    const f = try Fixture.start("RTSP/1.0 200 OK\r\nServer: x\r\n\r\n");
    defer f.stop();
    try testing.expectError(error.NoSequenceNumber, f.session.receive(1, 1024));
}

test "the numbers start at one and count up, which is what curl writes" {
    // Measured: curl's first request carried `CSeq: 1`.
    const f = try Fixture.start("");
    defer f.stop();

    try testing.expectEqual(@as(u64, 1), try f.session.takeCseq());
    try testing.expectEqual(@as(u64, 2), try f.session.takeCseq());
    try testing.expectEqual(@as(u64, 3), try f.session.takeCseq());
}

test "the number fails rather than wraps" {
    // A wrapped `CSeq` would tie a reply to a request that is not the one
    // in play, which is the whole shape the mismatch check closes.
    const f = try Fixture.start("");
    defer f.stop();

    f.session.next_cseq = max_requests;
    try testing.expectEqual(max_requests, try f.session.takeCseq());
    try testing.expectError(error.TooManyRequests, f.session.takeCseq());
}

test "send writes the head and the body in one flush" {
    const f = try Fixture.start("");
    defer f.stop();

    try f.session.send("GET_PARAMETER rtsp://h/s RTSP/1.0\r\nCSeq: 1\r\n\r\n", "packets_received\r\n");
    try testing.expectEqualStrings(
        "GET_PARAMETER rtsp://h/s RTSP/1.0\r\nCSeq: 1\r\n\r\npackets_received\r\n",
        f.loop.written(),
    );
}

test "a reply head longer than the bound is refused rather than collected" {
    // **The second of the two head bounds.** One line bound cannot catch a
    // head of many short lines, and a head that never ends is a head a
    // server can use to fill this process.
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(testing.allocator);
    try wire.appendSlice(testing.allocator, "RTSP/1.0 200 OK\r\nCSeq: 1\r\n");
    var written: usize = 0;
    while (written < reply.max_head_bytes + 1024) : (written += 12) {
        try wire.appendSlice(testing.allocator, "X-Pad: pad\r\n");
    }

    const f = try Fixture.start(wire.items);
    defer f.stop();
    try testing.expectError(error.HeadTooLarge, f.session.receive(1, 1024));
}

test "a head line longer than the bound ends the session" {
    // **The first of the two head bounds.** A server that writes a line
    // and never ends it cannot be resynchronised on, so the session ends.
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(testing.allocator);
    try wire.appendSlice(testing.allocator, "RTSP/1.0 200 OK\r\nX-Long: ");
    try wire.appendNTimes(testing.allocator, 'v', reply.max_line_bytes + 16);

    const f = try Fixture.start(wire.items);
    defer f.stop();
    try testing.expectError(error.LineTooLong, f.session.receive(1, 1024));
}

test "an announced body past the ceiling is refused before any of it is read" {
    const f = try Fixture.start("RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 99999\r\n\r\n");
    defer f.stop();
    try testing.expectError(error.BodyTooLarge, f.session.receive(1, 1024));
}

test "an interleaved binary frame is refused rather than read as a status line" {
    // **What this closes.** Without the peek, `$` and the RTP octets after
    // it go through `readLine`, and whatever happens to hold a line ending
    // becomes a header block. This build asks for no interleaved
    // transport, so a frame here answers no request it sent.
    const f = try Fixture.start(&[_]u8{ '$', 0x00, 0x00, 0x04 } ++ [_]u8{ 0x80, 0x60, 0x00, 0x01 });
    defer f.stop();
    try testing.expectError(error.InterleavedData, f.session.receive(1, 1024));
}

test "a server that closes in the middle of a head is a fault and not an empty reply" {
    const f = try Fixture.start("RTSP/1.0 200 OK\r\nCSeq: 1\r\n");
    defer f.stop();
    try testing.expectError(error.EndOfStream, f.session.receive(1, 1024));
}

test "every fault has a sentence, and none of them is empty" {
    const every = [_]ReceiveError{
        error.SequenceMismatch,
        error.InterleavedData,
        error.HeadWithoutLineFeed,
        error.EndOfStream,
        error.LineTooLong,
        error.OutOfMemory,
        error.StreamTooLong,
        error.ReadFailed,
        error.OperationTimedOut,
        error.ReadTimeoutUnsupported,
        error.Canceled,
        error.BadStatusLine,
        error.BadStatusCode,
        error.BadVersion,
        error.BadHeaderLine,
        error.NoSequenceNumber,
        error.BadSequenceNumber,
        error.BadContentLength,
        error.BodyTooLarge,
        error.HeadTooLarge,
    };
    for (every) |err| {
        try testing.expect(describe(err).len != 0);
        for (every) |other| {
            if (err == other) continue;
            try testing.expect(!std.mem.eql(u8, describe(err), describe(other)));
        }
    }
}
