//! A loopback RFC 854 server for the tests of this package.
//!
//! This is a test fixture, not a product. It writes a greeting, reads what
//! the client answers, writes a second run of octets, and closes. It
//! validates nothing: a test that pins the octets a client wrote has to
//! see those octets as they arrived, escaping and all.
//!
//! **No test in this package reaches the real network.** Every one that
//! needs a peer starts one of these on 127.0.0.1 with a port the operating
//! system assigns.
//!
//! The two writes are what a telnet dialogue needs. A real server sends
//! its option negotiation first, waits for the answer, and only then
//! writes the login prompt, so a fixture with one write could not prove
//! that zurl answers **while** it reads.
//!
//! The server closes after the second write, because that is how a telnet
//! session ends: RFC 854 puts no length on the wire.

const std = @import("std");
const zurl_net = @import("zurl-net");
const testing = std.testing;

pub const Server = @This();

/// How many octets of what the client wrote this fixture keeps.
pub const capture_bytes = 8192;

/// How long one read waits with no octet arriving. A client that writes
/// nothing must not hold the fixture task forever.
const read_stall: std.Io.Timeout = .{
    .duration = .{ .raw = .fromSeconds(10), .clock = .awake },
};

/// What one run of the fixture does.
pub const Script = struct {
    /// The octets to write as soon as the connection opens. A real telnet
    /// server opens with its option negotiation.
    greeting: []const u8 = "",
    /// The octets to write after the client has answered the greeting.
    answer: []const u8 = "",
    /// How many octets to wait for before writing `answer`.
    ///
    /// **A count and not a clock.** A wait measured in milliseconds ends
    /// early on a loaded machine, and the capture then holds the client's
    /// answer in whichever order the scheduler produced. Ten `zig build
    /// test` runs at once is exactly that machine. A count makes the
    /// capture the same on every run.
    ///
    /// Zero for a script whose client answers nothing before the second
    /// write. The drain at the end still collects whatever it writes
    /// after that.
    expect_bytes: usize = 0,
};

server: std.Io.net.Server,
task: std.Io.Future(void),
script: Script,
/// What the client wrote. Read through `received`.
capture_storage: [capture_bytes]u8,
capture_len: usize,
/// How many connections the server accepted. A test that proves a body was
/// refused before any dial asserts this is zero.
accept_count: std.atomic.Value(usize),
/// Set after the task has finished with the connection.
finished: std.atomic.Value(bool),

/// Starts listening on loopback and starts a task that runs `script`
/// against one connection.
///
/// Initializes `s` in place, rather than returning a `Server` by value, so
/// the task can hold `&s.server` for its whole life.
///
/// Returns `error.SkipZigTest` in a build with no concurrency at all. The
/// server and its client cannot both make progress on one task.
///
/// `s` and every slice in `script` must outlive the server.
pub fn start(s: *Server, script: Script) !void {
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    s.server = try address.listen(testing.io, .{ .reuse_address = true });
    errdefer s.server.deinit(testing.io);

    s.script = script;
    s.capture_len = 0;
    s.accept_count = .init(0);
    s.finished = .init(false);

    s.task = testing.io.concurrent(run, .{s}) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
}

/// The octets the client wrote, exactly as they arrived.
pub fn received(s: *const Server) []const u8 {
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

/// Waits until the server task has let go of its connection.
///
/// **A test that reads `received` must call this first.** The client
/// returns as soon as the peer closes, and the server task is a separate
/// task that may not have recorded its last read yet. Without this wait, a
/// test asserts against a capture that is still being filled in.
///
/// The wait is bounded. A task that never finishes leaves the capture
/// where it was, and the test then fails on the capture rather than hang.
pub fn awaitDone(s: *const Server) void {
    const step: std.Io.Timeout = .{
        .duration = .{ .raw = .fromMilliseconds(1), .clock = .awake },
    };
    var steps: usize = 0;
    while (!s.finished.load(.acquire) and steps < 5000) : (steps += 1) {
        step.sleep(testing.io) catch return;
    }
}

/// Starts a server that accepts one connection, writes nothing at all, and
/// holds the socket open.
///
/// **This is the peer a read bound exists for.** The connect succeeds, so
/// the dial is over, and the client then waits for octets that never come.
pub fn startSilent(s: *Server) !void {
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    s.server = try address.listen(testing.io, .{ .reuse_address = true });
    errdefer s.server.deinit(testing.io);

    s.script = .{};
    s.capture_len = 0;
    s.accept_count = .init(0);
    s.finished = .init(false);

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
    s.finished.store(true, .release);

    const hold: std.Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(60), .clock = .awake } };
    hold.sleep(testing.io) catch {};
}

/// Stops the server task and releases the listening socket. Every test
/// that calls `start` must call this, normally through `defer`.
pub fn stop(s: *Server) void {
    s.task.cancel(testing.io);
    s.server.deinit(testing.io);
}

fn run(s: *Server) void {
    const stream = s.server.accept(testing.io) catch return;
    defer stream.close(testing.io);
    s.accept_count.store(s.accept_count.load(.monotonic) + 1, .release);

    var read_buffer: [8192]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    var write_buffer: [8192]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);

    writeAll(&writer.interface, s.script.greeting) catch return;

    // The client's answer to the greeting, by count. See
    // `Script.expect_bytes`.
    while (s.capture_len < s.script.expect_bytes) {
        if (!collect(s, &reader.interface)) break;
    }

    writeAll(&writer.interface, s.script.answer) catch {};

    // **The write side closes first, and the read side stays open.** The
    // client answers a negotiation as it reads, so it may still have
    // octets to write when this fixture has said everything it has to
    // say. A fixture that closed both sides here would send a reset, and
    // the client would report a read fault for a session that worked.
    // This shutdown is the end of the answer, and the drain below takes
    // whatever the client wrote for it.
    stream.shutdown(testing.io, .send) catch {};
    while (collect(s, &reader.interface)) {}

    s.finished.store(true, .release);
}

/// Takes whatever the client has written into the capture, and reports
/// whether anything arrived.
///
/// False for the end of the stream, for a read fault, and for a capture
/// that is already full. Each of the three means this fixture has nothing
/// more to record.
fn collect(s: *Server, reader: *std.Io.Reader) bool {
    if (s.capture_len == s.capture_storage.len) return false;
    zurl_net.bounded.waitForBytes(reader, testing.io, read_stall) catch return false;
    const held = reader.buffered();
    const take = @min(held.len, s.capture_storage.len - s.capture_len);
    @memcpy(s.capture_storage[s.capture_len..][0..take], held[0..take]);
    s.capture_len += take;
    reader.toss(take);
    return take != 0;
}

fn writeAll(writer: *std.Io.Writer, text: []const u8) !void {
    if (text.len == 0) return;
    try writer.writeAll(text);
    try writer.flush();
}

test "the fixture writes its greeting, records the answer, and writes the rest" {
    var server: Server = undefined;
    try server.start(.{
        .greeting = "\xff\xfd\x18",
        .answer = "after\r\n",
        .expect_bytes = 3,
    });
    defer server.stop();

    var address = try std.Io.net.IpAddress.parse("127.0.0.1", server.port());
    const stream = try address.connect(testing.io, .{ .mode = .stream });
    defer stream.close(testing.io);

    var read_buffer: [256]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    var greeting: [3]u8 = undefined;
    try zurl_net.bounded.readExact(&reader.interface, testing.io, &greeting, read_stall);
    try testing.expectEqualSlices(u8, "\xff\xfd\x18", &greeting);

    var write_buffer: [128]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);
    try writer.interface.writeAll("\xff\xfc\x18");
    try writer.interface.flush();

    const rest = try reader.interface.allocRemaining(testing.allocator, .limited(256));
    defer testing.allocator.free(rest);
    try testing.expectEqualStrings("after\r\n", rest);

    server.awaitDone();
    try testing.expectEqualSlices(u8, "\xff\xfc\x18", server.received());
    try testing.expectEqual(@as(usize, 1), server.connections());
}
