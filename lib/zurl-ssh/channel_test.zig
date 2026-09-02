//! End to end tests of `zurl_ssh.Channel` against the loopback fixture.
//!
//! These live in their own file for the reason `handshake_test.zig` gives:
//! the client and the fixture would otherwise import each other's module.
//!
//! **No test in this file reaches the real network.** Every one starts a
//! `test_server` on 127.0.0.1 with a port the operating system assigns.
//!
//! What these prove: that a channel opens and closes, that a transfer
//! larger than the peer's window goes through whole and does not stop for
//! good, that standard error stays out of the body, that an exit status
//! reaches the caller, and that every refusal happens where it should.
//!
//! **The flow control test is the one that matters.** The fixture's window
//! is set smaller than the body on purpose, so the transfer only finishes
//! if the client reads the `SSH_MSG_CHANNEL_WINDOW_ADJUST` messages while
//! it is receiving, and only if the client writes its own while it is
//! sending. A build with either half missing stops in this file and the
//! test times out rather than passing quietly.

const std = @import("std");

const Authenticator = @import("Authenticator.zig");
const Channel = @import("Channel.zig");
const Transport = @import("Transport.zig");
const connection = @import("connection.zig");
const privatekey = @import("privatekey.zig");
const test_server = @import("test_server.zig");

const testing = std.testing;

/// One fixture, one transport, one authenticator, and one channel.
///
/// Every one is on the heap, because each holds pointers into the last and
/// none of them may move.
const Fixture = struct {
    server: *test_server,
    endpoint: *test_server.Endpoint,
    transport: *Transport,
    authenticator: *Authenticator,
    channel: *Channel,
    stderr: *StderrCollector,

    fn start(
        script: test_server.ConnectionScript,
        options: Channel.Options,
    ) !Fixture {
        const stderr = try testing.allocator.create(StderrCollector);
        errdefer testing.allocator.destroy(stderr);
        stderr.* = .{};

        const server = try testing.allocator.create(test_server);
        errdefer testing.allocator.destroy(server);
        try server.start(.{
            .auth = .{ .accept_none = true, .methods = "none" },
            .connection = script,
        });
        errdefer server.stop();

        const endpoint = try testing.allocator.create(test_server.Endpoint);
        errdefer testing.allocator.destroy(endpoint);
        try endpoint.connect(server.port());
        errdefer endpoint.close();

        const transport = try testing.allocator.create(Transport);
        errdefer testing.allocator.destroy(transport);
        try transport.init(testing.allocator, testing.io, endpoint.channel(), .{
            .peer = .{ .host = "fixture.test", .port = 22 },
            .verifier = server.verifier(),
        });
        errdefer transport.deinit();

        const authenticator = try testing.allocator.create(Authenticator);
        errdefer testing.allocator.destroy(authenticator);
        authenticator.init(transport, .{ .user = "alice" });
        errdefer authenticator.deinit();

        const channel = try testing.allocator.create(Channel);
        errdefer testing.allocator.destroy(channel);
        var wired = options;
        wired.stderr = stderr.sink();
        try channel.init(testing.allocator, transport, wired);

        return .{
            .server = server,
            .endpoint = endpoint,
            .transport = transport,
            .authenticator = authenticator,
            .channel = channel,
            .stderr = stderr,
        };
    }

    fn stop(f: Fixture) void {
        f.channel.deinit(testing.allocator);
        testing.allocator.destroy(f.channel);
        f.authenticator.deinit();
        testing.allocator.destroy(f.authenticator);
        f.transport.deinit();
        testing.allocator.destroy(f.transport);
        f.endpoint.close();
        testing.allocator.destroy(f.endpoint);
        f.server.stop();
        testing.allocator.destroy(f.server);
        f.stderr.text.deinit(testing.allocator);
        testing.allocator.destroy(f.stderr);
    }

    /// Runs the handshake, the login, and the channel open.
    fn run(f: Fixture) !void {
        try f.transport.handshake();
        try f.authenticator.authenticate();
        return f.channel.open();
    }

    /// Reads the whole channel until the peer's end of file.
    ///
    /// **A fixture that failed first is named here.** Without this a
    /// fixture fault reaches the test as a broken pipe on the client's
    /// next write, which reads as a client bug and is not one.
    fn readAll(f: Fixture) ![]u8 {
        errdefer if (f.server.failure) |name| {
            std.debug.print("\nthe fixture failed first: {s}\n", .{name});
        };
        var collected: std.ArrayList(u8) = .empty;
        errdefer collected.deinit(testing.allocator);
        var chunk: [4096]u8 = undefined;
        while (true) {
            const taken = try f.channel.read(&chunk);
            if (taken == 0) break;
            try collected.appendSlice(testing.allocator, chunk[0..taken]);
        }
        return collected.toOwnedSlice(testing.allocator);
    }
};

const StderrCollector = struct {
    text: std.ArrayList(u8) = .empty,

    fn sink(collector: *StderrCollector) Channel.StderrSink {
        return .{ .ctx = collector, .write = show };
    }

    fn show(ctx: ?*anyopaque, text: []const u8) void {
        const collector: *StderrCollector = @ptrCast(@alignCast(ctx.?));
        collector.text.appendSlice(testing.allocator, text) catch {};
    }
};

test "a session channel opens, carries a subsystem request, and closes" {
    var f = try Fixture.start(.{
        .service = .write_body,
        .body = "hello over a channel\n",
        .exit_status = 0,
    }, .{});
    defer f.stop();

    try f.run();
    try f.channel.requestSubsystem("subsystem");

    const body = try f.readAll();
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("hello over a channel\n", body);

    try f.channel.close();
    try testing.expectEqual(@as(?u32, 0), f.channel.exitStatus());
    try testing.expect(f.server.failure == null);
}

test "a body larger than the peer's window goes through whole and never stops" {
    // **This is the deadlock test.** The fixture gives 8 KiB of window for
    // a 256 KiB body, so the transfer only finishes if the client writes a
    // `SSH_MSG_CHANNEL_WINDOW_ADJUST` as it reads. A build that credited
    // nothing stops here and the test never returns.
    var body: [256 * 1024]u8 = undefined;
    for (&body, 0..) |*byte, i| byte.* = @truncate(i *% 31);

    var f = try Fixture.start(.{
        .service = .write_body,
        .body = &body,
        .window_bytes = 8 * 1024,
        .max_packet_bytes = 2048,
        .body_chunk_bytes = 2048,
    }, .{ .window_bytes = 8 * 1024, .max_packet_bytes = 2048 });
    defer f.stop();

    try f.run();
    try f.channel.requestSubsystem("subsystem");

    const got = try f.readAll();
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, &body, got);
    // The credits really happened, rather than the window happening to be
    // large enough after all.
    try testing.expect(f.channel.counters.window_credits > 0);

    try f.channel.close();
    try testing.expect(f.server.failure == null);
}

test "a send larger than the window this side was given goes out whole" {
    // The other half of the same rule. The fixture gives a small window
    // and refills it as it reads, and `roomToSend` has to wait for each
    // refill by reading rather than by writing.
    var body: [128 * 1024]u8 = undefined;
    for (&body, 0..) |*byte, i| byte.* = @truncate(i *% 17);

    var f = try Fixture.start(.{
        .service = .sink,
        .window_bytes = 4 * 1024,
        .max_packet_bytes = 1024,
    }, .{ .window_bytes = 16 * 1024, .max_packet_bytes = 1024 });
    defer f.stop();

    try f.run();
    try f.channel.requestSubsystem("subsystem");

    try f.channel.write(&body);
    try f.channel.sendEof();
    try f.channel.close();

    try testing.expectEqual(@as(u64, body.len), f.server.received.load(.acquire));
    try testing.expect(f.channel.counters.window_adjusts > 0);
    try testing.expect(f.server.failure == null);
}

test "extended data reaches the stderr sink and never the body" {
    // A remote command that writes a warning must not put it in the file
    // the user asked for.
    var f = try Fixture.start(.{
        .service = .write_body,
        .body = "the file\n",
        .stderr_text = "scp: warning: something\n",
    }, .{});
    defer f.stop();

    try f.run();
    try f.channel.requestSubsystem("subsystem");

    const body = try f.readAll();
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("the file\n", body);
    try testing.expectEqualStrings("scp: warning: something\n", f.stderr.text.items);

    try f.channel.close();
}

test "an exit status reaches the caller, and a channel with none says so" {
    {
        var f = try Fixture.start(.{
            .service = .write_body,
            .body = "",
            .exit_status = 1,
        }, .{});
        defer f.stop();

        try f.run();
        try f.channel.requestSubsystem("subsystem");
        const body = try f.readAll();
        defer testing.allocator.free(body);
        try f.channel.close();
        // **A remote command that failed must not read as a good
        // transfer.** The body is empty either way, so the status is the
        // only thing that says which happened.
        try testing.expectEqual(@as(?u32, 1), f.channel.exitStatus());
    }
    {
        var f = try Fixture.start(.{ .service = .write_body, .body = "" }, .{});
        defer f.stop();

        try f.run();
        try f.channel.requestSubsystem("subsystem");
        const body = try f.readAll();
        defer testing.allocator.free(body);
        try f.channel.close();
        try testing.expectEqual(@as(?u32, null), f.channel.exitStatus());
    }
}

test "a server that will not open a channel says why, and the client stops" {
    var f = try Fixture.start(.{
        .refuse_open = .administratively_prohibited,
    }, .{});
    defer f.stop();

    try f.transport.handshake();
    try f.authenticator.authenticate();
    try testing.expectError(error.ChannelOpenRefused, f.channel.open());

    const failure = f.channel.openFailure() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(
        connection.OpenFailureReason.administratively_prohibited,
        failure.reason,
    );
    try testing.expectEqualStrings("this fixture was told to refuse", failure.description);
}

test "a server that refuses the subsystem is a refusal and never a silent transfer" {
    // OpenSSH with no `Subsystem sftp` line answers exactly this, and a
    // client that carried on would read nothing and report success.
    var f = try Fixture.start(.{ .refuse_request = true }, .{});
    defer f.stop();

    try f.run();
    try testing.expectError(
        error.ChannelRequestRefused,
        f.channel.requestSubsystem("subsystem"),
    );
}

test "a request name the server does not know is refused by that name" {
    var f = try Fixture.start(.{ .accept_request = "exec" }, .{});
    defer f.stop();

    try f.run();
    try testing.expectError(
        error.ChannelRequestRefused,
        f.channel.requestSubsystem("subsystem"),
    );
}

test "an exec request runs over the same channel a subsystem request would" {
    var f = try Fixture.start(.{
        .accept_request = "exec",
        .service = .write_body,
        .body = "C0644 5 f.txt\n",
        .exit_status = 0,
    }, .{});
    defer f.stop();

    try f.run();
    var buffer: [256]u8 = undefined;
    try f.channel.requestExec(&buffer, "scp -pf '/tmp/f.txt'");

    const body = try f.readAll();
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("C0644 5 f.txt\n", body);
    try f.channel.close();
    try testing.expectEqual(@as(?u32, 0), f.channel.exitStatus());
}

test "a global request that wants a reply is answered, and a channel offer is refused" {
    // A server that asked for a reply and never heard one would wait, and
    // a client that took a channel it never asked for would carry a
    // forwarding nobody wanted.
    var f = try Fixture.start(.{
        .global_request = true,
        .offer_channel = true,
        .service = .write_body,
        .body = "still works\n",
    }, .{});
    defer f.stop();

    try f.run();
    try f.channel.requestSubsystem("subsystem");

    const body = try f.readAll();
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("still works\n", body);

    try testing.expectEqual(@as(u64, 1), f.channel.counters.global_requests_refused);
    try testing.expectEqual(@as(u64, 1), f.channel.counters.peer_opens_refused);
    try f.channel.close();
    try testing.expect(f.server.failure == null);
}

test "a channel request this build does not act on is counted and dropped" {
    var f = try Fixture.start(.{
        .stray_request = true,
        .service = .write_body,
        .body = "body\n",
        .exit_status = 3,
    }, .{});
    defer f.stop();

    try f.run();
    try f.channel.requestSubsystem("subsystem");

    const body = try f.readAll();
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("body\n", body);
    try f.channel.close();

    try testing.expect(f.channel.counters.requests_dropped > 0);
    // The dropped request did not become the exit status.
    try testing.expectEqual(@as(?u32, 3), f.channel.exitStatus());
}

test "a caller that writes after its own end of file is its own bug" {
    var f = try Fixture.start(.{ .service = .sink }, .{});
    defer f.stop();

    try f.run();
    try f.channel.requestSubsystem("subsystem");
    try f.channel.write("one");
    try f.channel.sendEof();
    try testing.expectError(error.ChannelStateInvalid, f.channel.write("two"));
    try f.channel.close();
}

test "channel data after the peer's own close never reaches the body" {
    // RFC 4254 section 5.3: a side that has sent `SSH_MSG_CHANNEL_CLOSE`
    // sends nothing more on the channel. The fixture writes the body, the
    // end of file, the close, and then one more data message.
    //
    // **The late message is refused in `apply` and this test cannot drive
    // that arm.** Every read loop in this file's subject stops at the
    // peer's close: `read` answers zero, `roomToSend` answers
    // `error.ChannelClosed`, and `close` has what it was waiting for. So
    // the late bytes are never read at all, and what a test can prove
    // from outside is the property that matters to a caller, which is
    // that they never become body. The named refusal covers the one route
    // that does reach it, which is a payload the transport held across a
    // key exchange and hands back after the close. See `Channel.apply`.
    var f = try Fixture.start(.{
        .service = .write_body,
        .body = "before the close",
        .data_after_close = true,
    }, .{});
    defer f.stop();

    try f.run();
    try f.channel.requestSubsystem("subsystem");

    const body = try f.readAll();
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("before the close", body);

    try f.channel.close();
    try testing.expect(f.channel.atEnd());
    // The bytes the fixture wrote after its close are not in the count
    // either, so nothing took them and dropped them in silence.
    try testing.expectEqual(@as(u64, "before the close".len), f.channel.counters.data_bytes);
}

test "the no-progress budget is a total over the channel and not one per read" {
    // **A budget that started again at every call was no budget.** The
    // fixture sends a run of channel requests the client drops, then one
    // chunk of body, then another run, and so on. Every run used to cost
    // the peer nothing, because the byte between them gave the client a
    // whole fresh budget: 1024 packets bought one byte, for ever.
    //
    // The runs here add up to more than `Channel.max_idle_steps` while no
    // single run comes near it, so a build that counts per call finishes
    // this transfer and a build that counts the channel refuses it.
    const per_chunk = Channel.max_idle_steps / 4;
    var body: [8]u8 = @splat('x');

    var f = try Fixture.start(.{
        .service = .write_body,
        .body = &body,
        .body_chunk_bytes = 1,
        .stray_requests_per_chunk = per_chunk,
    }, .{});
    defer f.stop();

    try f.run();
    try f.channel.requestSubsystem("subsystem");

    const got = f.readAll();
    if (got) |taken| {
        testing.allocator.free(taken);
        return error.TestExpectedPeerStalled;
    } else |err| {
        try testing.expectEqual(error.PeerStalled, err);
    }
    try testing.expect(f.channel.counters.idle_steps > Channel.max_idle_steps);
}

test "a message that carries data is not counted against the no-progress budget" {
    // The other half of the rule above. A long transfer sends far more
    // than `max_idle_steps` packets, and none of them may be counted,
    // because a total that counted them would stop every large download.
    var body: [64 * 1024]u8 = undefined;
    for (&body, 0..) |*byte, i| byte.* = @truncate(i *% 7);

    var f = try Fixture.start(.{
        .service = .write_body,
        .body = &body,
        .body_chunk_bytes = 32,
        .window_bytes = 8 * 1024,
        .max_packet_bytes = 2048,
    }, .{ .window_bytes = 8 * 1024, .max_packet_bytes = 2048 });
    defer f.stop();

    try f.run();
    try f.channel.requestSubsystem("subsystem");

    const got = try f.readAll();
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, &body, got);
    // 2048 data messages went by, twice the budget, and the count stayed
    // where an honest session leaves it.
    try testing.expect(f.channel.counters.idle_steps <= Channel.max_idle_steps);

    try f.channel.close();
}
