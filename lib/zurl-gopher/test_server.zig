//! A loopback RFC 1436 server for the tests of this package.
//!
//! This is a test fixture, not a product. It reads one request line,
//! writes one answer, and closes. It validates nothing: a test that pins
//! the bytes a request carries has to see those bytes as they arrived.
//!
//! **No test in this package reaches the real network.** Every one that
//! needs a peer starts one of these on 127.0.0.1 with a port the operating
//! system assigns.
//!
//! The server closes after it writes, because that is how a gopher answer
//! ends: RFC 1436 puts no length on the wire, and the client reads until
//! the peer closes.
//!
//! **This fixture speaks no TLS**, so it serves `gopher` and never
//! `gophers`. A TLS session needs a certificate and a key, which this
//! repository has no fixture for. The `gophers` tests therefore check the
//! options a session opens with, at `Fetcher.tlsOptions`, which is the one
//! function that decides them.

const std = @import("std");
const testing = std.testing;

pub const Server = @This();

/// How many bytes of one request this fixture keeps. A gopher request is
/// one line, so this is far past any of them.
pub const capture_bytes = 8192;

server: std.Io.net.Server,
task: std.Io.Future(void),
/// The request line the client wrote. Filled by the server task before it
/// answers, read through `received`.
capture_storage: [capture_bytes]u8,
capture_len: usize,
/// How many connections the server accepted. A test that proves a url was
/// refused before any dial asserts this is zero.
accept_count: std.atomic.Value(usize),
/// Set after the task has filled `capture_storage`, so `received` never
/// reads a half-written record.
captured: std.atomic.Value(bool),

/// Starts listening on loopback and starts a task that answers one
/// connection with `answer` and then closes it.
///
/// Initializes `s` in place, rather than returning a `Server` by value, so
/// the task can hold `&s.server` for its whole life.
///
/// Returns `error.SkipZigTest` in a build with no concurrency at all. The
/// server and its client cannot both make progress on one task.
///
/// `s` and `answer` must outlive the server.
pub fn start(s: *Server, answer: []const u8) !void {
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    s.server = try address.listen(testing.io, .{ .reuse_address = true });
    errdefer s.server.deinit(testing.io);

    s.capture_len = 0;
    s.accept_count = .init(0);
    s.captured = .init(false);

    s.task = testing.io.concurrent(run, .{ s, answer }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
}

/// Starts a server that accepts one connection, writes nothing at all, and
/// holds the socket open.
///
/// **This is the peer a read bound exists for, and the peer a handshake
/// bound exists for.** The connect succeeds, so the dial is over. A plain
/// `gopher` client then waits for an answer that never comes. A `gophers`
/// client waits for a ServerHello that never comes. Neither wait ends
/// without a bound.
///
/// The task sleeps, which `stop` cancels, so this fixture leaves nothing
/// running.
pub fn startSilent(s: *Server) !void {
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    s.server = try address.listen(testing.io, .{ .reuse_address = true });
    errdefer s.server.deinit(testing.io);

    s.capture_len = 0;
    s.accept_count = .init(0);
    s.captured = .init(false);

    s.task = testing.io.concurrent(runSilent, .{s}) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
}

fn runSilent(s: *Server) void {
    const stream = s.server.accept(testing.io) catch return;
    defer stream.close(testing.io);
    s.accept_count.store(s.accept_count.load(.monotonic) + 1, .release);
    s.captured.store(true, .release);

    // Well past the bound any test here asks for, and cancelable, so
    // `stop` ends this task at once.
    const hold: std.Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(60), .clock = .awake } };
    hold.sleep(testing.io) catch {};
}

/// The request line the client wrote, or an empty slice when the server
/// has not read one yet.
pub fn received(s: *const Server) []const u8 {
    if (!s.captured.load(.acquire)) return "";
    return s.capture_storage[0..s.capture_len];
}

/// How many connections the client opened on this server.
pub fn connections(s: *const Server) usize {
    return s.accept_count.load(.acquire);
}

/// The port the operating system assigned.
pub fn port(s: *const Server) u16 {
    return s.server.socket.address.getPort();
}

/// Stops the server task and releases the listening socket. Every test
/// that calls `start` must call this, normally through `defer`.
///
/// The task is canceled, not joined. A test that opens no connection
/// leaves `run` inside `accept`, where a plain join waits forever.
pub fn stop(s: *Server) void {
    s.task.cancel(testing.io);
    s.server.deinit(testing.io);
}

fn run(s: *Server, answer: []const u8) void {
    const stream = s.server.accept(testing.io) catch return;
    defer stream.close(testing.io);
    s.accept_count.store(s.accept_count.load(.monotonic) + 1, .release);

    var read_buffer: [4096]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    var write_buffer: [4096]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);

    // **One line and no more.** A gopher client writes its selector and
    // then waits, without closing its own side, so a server that read to
    // the end of the socket would wait for a close the client is waiting
    // for too.
    const line = reader.interface.takeDelimiterInclusive('\n') catch "";
    const n = @min(s.capture_storage.len, line.len);
    @memcpy(s.capture_storage[0..n], line[0..n]);
    s.capture_len = n;
    s.captured.store(true, .release);

    writer.interface.writeAll(answer) catch return;
    writer.interface.flush() catch return;
}

test "the fixture answers one request and records the line it read" {
    var server: Server = undefined;
    try server.start("0Row\t/x\t127.0.0.1\t70\r\n.\r\n");
    defer server.stop();

    var address = try std.Io.net.IpAddress.parse("127.0.0.1", server.port());
    const stream = try address.connect(testing.io, .{ .mode = .stream });
    defer stream.close(testing.io);

    var write_buffer: [128]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);
    try writer.interface.writeAll("/probe\r\n");
    try writer.interface.flush();

    var read_buffer: [128]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    const answer = try reader.interface.allocRemaining(testing.allocator, .limited(1024));
    defer testing.allocator.free(answer);

    try testing.expectEqualStrings("0Row\t/x\t127.0.0.1\t70\r\n.\r\n", answer);
    try testing.expectEqualStrings("/probe\r\n", server.received());
    try testing.expectEqual(@as(usize, 1), server.connections());
}
