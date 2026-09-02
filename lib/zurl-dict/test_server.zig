//! A loopback RFC 2229 server for the tests of this package.
//!
//! This is a test fixture, not a product. It reads the command lines a
//! client sends until it sees `QUIT`, writes a script back, and closes.
//! It parses nothing else and validates nothing: a test that pins the
//! bytes a request carries has to see those bytes as they arrived.
//!
//! **No test in this package reaches the real network.** Every one that
//! needs a peer starts one of these on 127.0.0.1 with a port the operating
//! system assigns.
//!
//! The server closes the connection after it writes the script, because
//! that is how a dict answer ends: RFC 2229 has no length on the wire, and
//! the client reads until the peer closes.

const std = @import("std");
const testing = std.testing;

pub const Server = @This();

/// How many bytes of one request this fixture keeps. A dict session is
/// three short lines, so this is far past any of them. A request longer
/// than this keeps its first `capture_bytes` bytes, because a record a
/// test reads is worth more truncated than dropped.
pub const capture_bytes = 8192;

server: std.Io.net.Server,
task: std.Io.Future(void),
/// The bytes the client wrote, in order. Filled by the server task before
/// it answers, read through `received`.
capture_storage: [capture_bytes]u8,
capture_len: usize,
/// How many connections the server accepted. Published with a release
/// store, read through `connections`.
///
/// A test that proves a url was refused before any dial asserts this is
/// zero.
accept_count: std.atomic.Value(usize),
/// Set after the task has filled `capture_storage`, so `received` never
/// reads a half-written record.
captured: std.atomic.Value(bool),

/// Starts listening on loopback and starts a task that answers one
/// connection with `script`, in order, and then closes it.
///
/// Initializes `s` in place, rather than returning a `Server` by value, so
/// the task can hold `&s.server` for its whole life.
///
/// Returns `error.SkipZigTest` in a build with no concurrency at all. The
/// server and its client cannot both make progress on one task, so a test
/// that needs this fixture cannot run there. `zurl-http/test_server.zig`
/// degrades the same way.
///
/// `s` and `script` must outlive the server.
pub fn start(s: *Server, script: []const []const u8) !void {
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    s.server = try address.listen(testing.io, .{ .reuse_address = true });
    errdefer s.server.deinit(testing.io);

    s.capture_len = 0;
    s.accept_count = .init(0);
    s.captured = .init(false);

    s.task = testing.io.concurrent(run, .{ s, script }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
}

/// Starts a server that accepts one connection, writes nothing at all, and
/// holds the socket open.
///
/// **This is the peer a read bound exists for.** The dial succeeds, so
/// `--connect-timeout` is spent. A dict answer ends only when the peer
/// closes, so the protocol itself never ends this. Only a bound on the read
/// does.
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

/// The bytes the client wrote, or an empty slice when the server has not
/// read a whole request yet.
///
/// Read it after the transfer under test has finished. The task fills this
/// before it writes a byte back, so a test that already has its answer
/// also has the request that asked for it.
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

fn run(s: *Server, script: []const []const u8) void {
    const stream = s.server.accept(testing.io) catch return;
    defer stream.close(testing.io);
    s.accept_count.store(s.accept_count.load(.monotonic) + 1, .release);

    var read_buffer: [4096]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    var write_buffer: [4096]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);

    // **The read stops at `QUIT` and not at the end of the socket.** A
    // dict client writes its whole session and then waits for the answer
    // without closing its own side, so a server that read to the end of
    // the socket would wait for a close that the client is waiting for
    // too. `QUIT` is the last line every session this package builds
    // writes, so it is the end of the request.
    //
    // A read that fails is a client that went away. The script still runs,
    // and the write below then fails and ends the task.
    while (true) {
        const line = reader.interface.takeDelimiterInclusive('\n') catch break;
        capture(s, line);
        if (std.ascii.eqlIgnoreCase(std.mem.trimEnd(u8, line, "\r\n"), "QUIT")) break;
    }
    s.captured.store(true, .release);

    for (script) |chunk| {
        writer.interface.writeAll(chunk) catch return;
        writer.interface.flush() catch return;
    }
}

fn capture(s: *Server, text: []const u8) void {
    const n = @min(s.capture_storage.len - s.capture_len, text.len);
    @memcpy(s.capture_storage[s.capture_len..][0..n], text[0..n]);
    s.capture_len += n;
}

test "the fixture answers one session and records what it read" {
    var server: Server = undefined;
    try server.start(&.{ "220 ready\r\n", "250 ok\r\n" });
    defer server.stop();

    var address = try std.Io.net.IpAddress.parse("127.0.0.1", server.port());
    const stream = try address.connect(testing.io, .{ .mode = .stream });
    defer stream.close(testing.io);

    var write_buffer: [128]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);
    try writer.interface.writeAll("CLIENT probe\r\nQUIT\r\n");
    try writer.interface.flush();

    var read_buffer: [128]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    const answer = try reader.interface.allocRemaining(testing.allocator, .limited(1024));
    defer testing.allocator.free(answer);

    try testing.expectEqualStrings("220 ready\r\n250 ok\r\n", answer);
    try testing.expectEqualStrings("CLIENT probe\r\nQUIT\r\n", server.received());
    try testing.expectEqual(@as(usize, 1), server.connections());
}
