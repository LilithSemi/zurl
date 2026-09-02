//! A loopback RTSP 1.0 server for the tests of this package.
//!
//! This is a test fixture, not a product. It reads one request head, logs
//! every byte of it, and answers with whatever a `Script` names. It
//! validates nothing: a test that pins the bytes a request carries has to
//! see those bytes as they arrived.
//!
//! **No test in this package reaches the real network.** Every one that
//! needs a peer starts one of these on 127.0.0.1, with a port the
//! operating system assigns.
//!
//! **The fixture can answer with a reply no client should accept.**
//! `Script.cseq` writes a sequence number of the caller's own choosing,
//! `Script.raw` writes bytes with no framing at all, and
//! `Script.content_length` can announce more body than it sends. Those
//! three are what the checks in `zurl_rtsp.Session` and `zurl_rtsp.reply`
//! exist for, and a fixture that could not produce them would leave all
//! three untested against a socket.

const std = @import("std");
const testing = std.testing;

pub const Server = @This();

/// How many bytes of the request log this keeps.
pub const log_bytes = 8192;

/// What the fixture answers.
///
/// Every field has the answer a working server gives, so a test names only
/// the one it wants to bend.
pub const Script = struct {
    /// The status line, with no line ending.
    status: []const u8 = "RTSP/1.0 200 OK",
    /// The `CSeq` the reply carries. Null echoes the one the request sent,
    /// which is what a server does.
    cseq: ?u64 = null,
    /// Whether to write a `CSeq` at all. RFC 2326 section 12.17 makes one
    /// required, and a test proves the client refuses a reply without one.
    write_cseq: bool = true,
    /// Header lines to add, each with no line ending.
    headers: []const []const u8 = &.{},
    /// The body. A `Content-Length` is written for it.
    body: []const u8 = "",
    /// A `Content-Length` to announce in place of the real one. Null
    /// announces `body.len`.
    content_length: ?u64 = null,
    /// Bytes to write in place of the whole reply. Null writes the reply
    /// the fields above describe.
    raw: ?[]const u8 = null,
    /// Whether to close the socket without answering at all.
    close_without_answer: bool = false,
};

server: std.Io.net.Server,
task: std.Io.Future(void),
script: Script,
/// Every byte the client wrote. Read through `log` after `wait`.
log_storage: [log_bytes]u8,
log_len: usize,
/// Set when the task has finished writing `log_storage`.
done: std.atomic.Value(bool),
/// How many connections the fixture accepted. A test that proves a url was
/// refused before any dial asserts this is zero.
accept_count: std.atomic.Value(usize),

/// Starts listening on loopback and starts a task that runs one exchange.
///
/// Initializes `s` in place, so the task can hold `&s.server` for its
/// whole life.
///
/// Returns `error.SkipZigTest` in a build with no concurrency at all. The
/// server and its client cannot both make progress on one task.
///
/// `s` and every slice inside `script` must outlive the server.
pub fn start(s: *Server, script: Script) !void {
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    s.server = try address.listen(testing.io, .{ .reuse_address = true });
    errdefer s.server.deinit(testing.io);

    s.script = script;
    s.log_len = 0;
    s.done = .init(false);
    s.accept_count = .init(0);

    s.task = testing.io.concurrent(run, .{s}) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
}

/// Starts a server that accepts one connection, writes nothing at all, and
/// holds the socket open.
///
/// **This is the peer the read bound exists for.** The connect succeeds,
/// so the dial is over, and then the reply never arrives.
pub fn startSilent(s: *Server) !void {
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    s.server = try address.listen(testing.io, .{ .reuse_address = true });
    errdefer s.server.deinit(testing.io);

    s.script = .{};
    s.log_len = 0;
    s.done = .init(false);
    s.accept_count = .init(0);

    s.task = testing.io.concurrent(runSilent, .{s}) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
}

/// The port the operating system assigned to the listener.
pub fn port(s: *const Server) u16 {
    return s.server.socket.address.getPort();
}

/// How many connections the client opened.
pub fn connections(s: *const Server) usize {
    return s.accept_count.load(.acquire);
}

/// Every byte the client sent.
///
/// Call `wait` first for a complete log.
pub fn log(s: *const Server) []const u8 {
    if (!s.done.load(.acquire)) return "";
    return s.log_storage[0..s.log_len];
}

/// Waits for the exchange to finish.
pub fn wait(s: *Server) void {
    s.task.await(testing.io);
}

/// Stops the server task and releases the listening socket. Every test
/// that calls `start` must call this, normally through `defer`.
pub fn stop(s: *Server) void {
    s.task.cancel(testing.io);
    s.server.deinit(testing.io);
}

fn runSilent(s: *Server) void {
    const stream = s.server.accept(testing.io) catch return;
    defer stream.close(testing.io);
    _ = s.accept_count.fetchAdd(1, .release);
    s.done.store(true, .release);

    const hold: std.Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(60), .clock = .awake } };
    hold.sleep(testing.io) catch {};
}

fn run(s: *Server) void {
    const stream = s.server.accept(testing.io) catch return;
    defer stream.close(testing.io);
    _ = s.accept_count.fetchAdd(1, .release);

    var read_buffer: [8192]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    var write_buffer: [8192]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);

    serve(s, &reader.interface, &writer.interface) catch {};
    s.done.store(true, .release);
}

fn serve(s: *Server, reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
    var request_cseq: u64 = 0;
    var content_length: u64 = 0;

    // The head, one line at a time, up to the empty line.
    while (true) {
        const raw = try reader.takeDelimiterInclusive('\n');
        record(s, raw);
        const line = std.mem.trimEnd(u8, raw, "\r\n");
        if (line.len == 0) break;

        if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
            const name = std.mem.trim(u8, line[0..colon], " \t");
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (std.ascii.eqlIgnoreCase(name, "CSeq")) {
                request_cseq = std.fmt.parseInt(u64, value, 10) catch 0;
            } else if (std.ascii.eqlIgnoreCase(name, "Content-Length")) {
                content_length = std.fmt.parseInt(u64, value, 10) catch 0;
            }
        }
    }

    // The body, when the request announced one, so the log holds it.
    if (content_length != 0 and content_length < 4096) {
        var body: [4096]u8 = undefined;
        const held = body[0..@intCast(content_length)];
        try reader.readSliceAll(held);
        record(s, held);
    }

    if (s.script.close_without_answer) return;

    if (s.script.raw) |bytes| {
        try writer.writeAll(bytes);
        try writer.flush();
        // The raw bytes stand in for the whole reply, so the client is
        // left to refuse them and the socket stays open while it does.
        const hold: std.Io.Timeout = .{
            .duration = .{ .raw = .fromSeconds(60), .clock = .awake },
        };
        hold.sleep(testing.io) catch {};
        return;
    }

    try writer.writeAll(s.script.status);
    try writer.writeAll("\r\n");
    if (s.script.write_cseq) {
        try writer.print("CSeq: {d}\r\n", .{s.script.cseq orelse request_cseq});
    }
    for (s.script.headers) |one| {
        try writer.writeAll(one);
        try writer.writeAll("\r\n");
    }
    if (s.script.body.len != 0 or s.script.content_length != null) {
        try writer.print(
            "Content-Length: {d}\r\n",
            .{s.script.content_length orelse s.script.body.len},
        );
    }
    try writer.writeAll("\r\n");
    try writer.writeAll(s.script.body);
    try writer.flush();
}

fn record(s: *Server, bytes: []const u8) void {
    const room = s.log_storage.len - s.log_len;
    const n = @min(room, bytes.len);
    @memcpy(s.log_storage[s.log_len..][0..n], bytes[0..n]);
    s.log_len += n;
}

test "the fixture answers the request curl sends, and records every byte" {
    var server: Server = undefined;
    try server.start(.{
        .headers = &.{
            "Public: DESCRIBE, ANNOUNCE, SETUP, PLAY, RECORD, PAUSE, GET_PARAMETER, TEARDOWN",
            "Server: gortsplib",
        },
    });
    defer server.stop();

    var address = try std.Io.net.IpAddress.parse("127.0.0.1", server.port());
    const stream = try address.connect(testing.io, .{ .mode = .stream });
    defer stream.close(testing.io);

    var read_buffer: [4096]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    var write_buffer: [1024]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);

    // The request curl wrote, measured through a relay to mediamtx 1.18.2.
    const sent = "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: curl/8.21.0\r\n\r\n";
    try writer.interface.writeAll(sent);
    try writer.interface.flush();

    // The reply mediamtx wrote, measured.
    var got: [128]u8 = undefined;
    var at: usize = 0;
    while (at < got.len) {
        const line = try reader.interface.takeDelimiterInclusive('\n');
        @memcpy(got[at..][0..line.len], line);
        at += line.len;
        if (std.mem.eql(u8, line, "\r\n")) break;
    }
    try testing.expectEqualStrings(
        "RTSP/1.0 200 OK\r\n" ++
            "CSeq: 1\r\n" ++
            "Public: DESCRIBE, ANNOUNCE, SETUP, PLAY, RECORD, PAUSE, GET_PARAMETER, TEARDOWN\r\n" ++
            "Server: gortsplib\r\n" ++
            "\r\n",
        got[0..at],
    );

    server.wait();
    try testing.expectEqualStrings(sent, server.log());
    try testing.expectEqual(@as(usize, 1), server.connections());
}

test "the fixture can answer with a CSeq that belongs to no request" {
    // **The fixture the sequence check needs.** Without this, the tie
    // between a reply and its request is tested against a buffer and never
    // against a socket.
    var server: Server = undefined;
    try server.start(.{ .cseq = 4242 });
    defer server.stop();

    var address = try std.Io.net.IpAddress.parse("127.0.0.1", server.port());
    const stream = try address.connect(testing.io, .{ .mode = .stream });
    defer stream.close(testing.io);

    var read_buffer: [4096]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    var write_buffer: [1024]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);

    try writer.interface.writeAll("OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n");
    try writer.interface.flush();

    _ = try reader.interface.takeDelimiterInclusive('\n');
    const second = try reader.interface.takeDelimiterInclusive('\n');
    try testing.expectEqualStrings("CSeq: 4242\r\n", second);
}

test "the fixture can announce more body than it sends" {
    var server: Server = undefined;
    try server.start(.{ .body = "short", .content_length = 500 });
    defer server.stop();

    var address = try std.Io.net.IpAddress.parse("127.0.0.1", server.port());
    const stream = try address.connect(testing.io, .{ .mode = .stream });
    defer stream.close(testing.io);

    var read_buffer: [4096]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    var write_buffer: [1024]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);

    try writer.interface.writeAll("OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n");
    try writer.interface.flush();

    var saw_length = false;
    while (true) {
        const line = try reader.interface.takeDelimiterInclusive('\n');
        if (std.mem.startsWith(u8, line, "Content-Length: 500")) saw_length = true;
        if (std.mem.eql(u8, line, "\r\n")) break;
    }
    try testing.expect(saw_length);
}
