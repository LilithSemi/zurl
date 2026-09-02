//! End to end tests of `zurl_mqtt.Fetcher`, against the loopback broker.
//!
//! Every test here opens a socket on 127.0.0.1 and none reaches the real
//! network. What each one proves is the bytes a transfer put on that
//! socket and the answer it made of what came back.
//!
//! The wire bytes each test pins were measured off curl 8.21.0 through a
//! `socat -x -v` relay in front of a real mosquitto 2.1.2. Where this
//! build and curl differ, the test says so and names what was measured.

const std = @import("std");
const testing = std.testing;

const zurl_core = @import("zurl-core");

const Fetcher = @import("Fetcher.zig");
const packet = @import("packet.zig");
const Session = @import("Session.zig");
const test_server = @import("test_server.zig");

/// A url for the fixture's own port.
fn urlFor(storage: []u8, port: u16, path: []const u8) !zurl_core.Url {
    const text = try std.fmt.bufPrint(storage, "mqtt://127.0.0.1:{d}{s}", .{ port, path });
    return Fetcher.parseMqttUrl(text);
}

/// A `Source` over a fixed slice, for a publish.
const Payload = struct {
    bytes: []const u8,
    at: usize = 0,

    fn source(p: *Payload) Fetcher.Source {
        return .{ .len = p.bytes.len, .ctx = p, .read = readFn };
    }

    fn readFn(ctx: *anyopaque, buffer: [*]u8, len: usize) callconv(.c) isize {
        const p: *Payload = @ptrCast(@alignCast(ctx));
        const take = @min(len, p.bytes.len - p.at);
        @memcpy(buffer[0..take], p.bytes[p.at..][0..take]);
        p.at += take;
        return @intCast(take);
    }
};

/// A `Source` that reports a fault on its first read.
const BrokenPayload = struct {
    fn source(b: *BrokenPayload) Fetcher.Source {
        return .{ .len = null, .ctx = b, .read = readFn };
    }

    fn readFn(ctx: *anyopaque, buffer: [*]u8, len: usize) callconv(.c) isize {
        _ = ctx;
        _ = buffer;
        _ = len;
        return -1;
    }
};

test "a publish sends the four packets curl sends, in curl's order" {
    // Measured: `curl -d 'hello world' mqtt://127.0.0.1/zurl/test` put
    // `10 18 ...MQTT...` then `30 16 00 09 "zurl/test" "hello world"` and
    // then `e0 00` on the wire, and read one `20 02 00 00` in between.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/zurl/test");

    var payload: Payload = .{ .bytes = "hello world" };
    const body = try f.open(url, .{ .payload = payload.source() }, null);
    try testing.expect(body.published);
    try testing.expectEqual(@as(u64, 0), body.length);
    try testing.expectEqual(@as(u32, 0), body.messages);
    try testing.expect(!body.authenticated);

    server.wait();
    const sent = server.log();
    // The CONNECT, with the twelve byte identifier this build writes.
    try testing.expectEqualSlices(u8, &.{
        0x10, 0x18, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x0c,
    }, sent[0..14]);
    try testing.expectEqualStrings("zurl", sent[14..18]);
    // Then the PUBLISH, byte for byte as curl wrote it.
    try testing.expectEqualSlices(u8, &.{
        0x30, 0x16, 0x00, 0x09, 'z', 'u', 'r', 'l', '/', 't', 'e', 's', 't',
        'h',  'e',  'l',  'l',  'o', ' ', 'w', 'o', 'r', 'l', 'd',
    }, sent[26..50]);
    // And the DISCONNECT.
    try testing.expectEqualSlices(u8, &.{ 0xe0, 0x00 }, sent[50..52]);
}

test "a subscribe sends the subscribe curl sends and writes what curl writes" {
    // Measured: the SUBSCRIBE was `82 0d 00 01 00 08 "zurl/sub" 00`, and
    // one delivered message printed `00 08 "zurl/sub" "payload-one"` on
    // standard output, which is the whole variable header of the PUBLISH.
    var server: test_server.Server = undefined;
    try server.start(.{ .messages = &.{
        .{ .topic = "zurl/sub", .payload = "payload-one" },
    } });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/zurl/sub");

    const body = try f.open(url, .{}, null);
    try testing.expect(!body.published);
    try testing.expectEqual(@as(u32, 1), body.messages);

    const written = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(written);
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x00, 0x08 } ++ "zurl/sub".* ++ "payload-one".*,
        written,
    );

    server.wait();
    const sent = server.log();
    try testing.expectEqualSlices(u8, &.{
        0x82, 0x0d, 0x00, 0x01, 0x00, 0x08, 'z', 'u', 'r', 'l', '/', 's', 'u', 'b', 0x00,
    }, sent[26..41]);
}

test "a subscribe reads the number of messages it was asked for, and no more" {
    // **The divergence from curl, and it is the one this package's default
    // rests on.** curl's subscribe runs until somebody stops it: measured,
    // `curl --max-time 5 mqtt://host/topic` printed both messages and
    // exited 28. This build reads a named count and ends by itself.
    var server: test_server.Server = undefined;
    try server.start(.{ .messages = &.{
        .{ .topic = "t", .payload = "one" },
        .{ .topic = "t", .payload = "two" },
        .{ .topic = "t", .payload = "three" },
    } });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/t");

    const body = try f.open(url, .{ .message_count = 2 }, null);
    try testing.expectEqual(@as(u32, 2), body.messages);

    const written = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(written);
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x00, 0x01, 't' } ++ "one".* ++ [_]u8{ 0x00, 0x01, 't' } ++ "two".*,
        written,
    );
}

test "the default reads one message, which is what this build ships" {
    var server: test_server.Server = undefined;
    try server.start(.{ .messages = &.{
        .{ .topic = "t", .payload = "one" },
        .{ .topic = "t", .payload = "two" },
    } });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/t");

    const body = try f.open(url, .{}, null);
    try testing.expectEqual(Fetcher.default_message_count, body.messages);
    try testing.expectEqual(@as(u32, 1), body.messages);
}

test "a credential reaches the connect as curl writes it" {
    // Measured: `-u alice:s3cret` turned the flag byte from `02` into `c2`
    // and put `00 05 "alice" 00 06 "s3cret"` on the end of the CONNECT.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/t/a");

    var payload: Payload = .{ .bytes = "body-A" };
    const body = try f.open(url, .{
        .payload = payload.source(),
        .credentials = .{ .user = "alice", .password = "s3cret" },
        .client_id = "zurljAM5vLqk",
    }, null);
    try testing.expect(body.authenticated);

    server.wait();
    const sent = server.log();
    try testing.expectEqual(@as(u8, 0xc2), sent[9]);
    try testing.expect(std.mem.indexOf(u8, sent, "alice") != null);
    try testing.expect(std.mem.indexOf(u8, sent, "s3cret") != null);
}

test "a refused connect is exit 8, which is curl's own code" {
    // Measured against a mosquitto 2.1.2 with `allow_anonymous false`:
    // curl exited 8 for a publish and 8 for a subscribe, and the broker
    // had answered `20 02 00 05`, which is `not authorized`.
    var server: test_server.Server = undefined;
    try server.start(.{ .connack_code = 5 });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/t/deny");

    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(error.WeirdServerReply, f.open(url, .{}, &d));
    try testing.expectEqual(@as(?u32, 8), d.curl_code);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "authorize") != null);
}

test "a refused subscription is reported and not read past" {
    var server: test_server.Server = undefined;
    try server.start(.{ .suback_code = packet.suback_failure });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/t/nope");

    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(error.WeirdServerReply, f.open(url, .{}, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "refused the topic filter") != null);
}

test "a broker that answers a subscribe with PINGRESP for ever is refused" {
    // **The packet that costs two bytes and moves no bound.** A subscribe
    // counts messages and bytes, and `d0 00` adds to neither: the loop
    // reads it, adds nothing, and goes round again. The stall bound never
    // fires, because bytes keep arriving, and `--max-time` is off by
    // default.
    //
    // The fixture writes one PINGRESP more than the bound and no message
    // at all, so the refusal arrives after a known number of packets and
    // not after a wait.
    var server: test_server.Server = undefined;
    try server.start(.{ .pingresps_before_messages = Fetcher.max_empty_packets + 1 });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/t");

    var d: zurl_core.Diagnostics = .{};
    // Nothing else can end this transfer: the size bound counts no byte of
    // a PINGRESP and the message count never moves.
    try testing.expectError(error.WeirdServerReply, f.open(url, .{}, &d));
    try testing.expectEqual(@as(?u32, 8), d.curl_code);
    // The message names what the broker did, so a user reads it and knows
    // the fault is at the other end.
    try testing.expect(std.mem.indexOf(u8, d.message.?, "carry no message") != null);
}

test "a few PINGRESP packets before a message do not fail a subscribe" {
    // **The bound is a count and never a refusal of the first one.** MQTT
    // 3.1.1 section 3.13 makes a PINGRESP a legal packet at any time, so a
    // broker that sends a handful and then delivers is keeping the rules
    // and must be read.
    var server: test_server.Server = undefined;
    try server.start(.{
        .pingresps_before_messages = 8,
        .messages = &.{.{ .topic = "t", .payload = "one" }},
    });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/t");

    const body = try f.open(url, .{}, null);
    try testing.expectEqual(@as(u32, 1), body.messages);

    const written = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(written);
    // A PINGRESP adds nothing, so the answer is the one message.
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x00, 0x01, 't' } ++ "one".*,
        written,
    );
}

test "a SUBACK for a request nobody sent is a protocol error" {
    // The identifier is what ties an answer to a request. An answer that
    // carries somebody else's is an answer to a question this session
    // never asked.
    var server: test_server.Server = undefined;
    try server.start(.{ .suback_id = 4242 });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/t/x");

    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(error.WeirdServerReply, f.open(url, .{}, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "packet identifier") != null);
}

test "an answer to the connect that is not a CONNACK is refused by name" {
    var server: test_server.Server = undefined;
    try server.start(.{ .connack_type = @intFromEnum(packet.Type.pingresp) });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/t/x");

    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(error.WeirdServerReply, f.open(url, .{}, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "PINGRESP") != null);
}

test "a hostile remaining length on a live socket is refused, not read" {
    // **The bound this package exists to keep, against a real socket.**
    // `30 ff ff ff ff 7f` is a fifth continuation byte, which an unbounded
    // reader would follow forever.
    var server: test_server.Server = undefined;
    try server.start(.{ .raw_after_suback = &.{ 0x30, 0xff, 0xff, 0xff, 0xff, 0x7f } });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/t/x");

    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(error.WeirdServerReply, f.open(url, .{}, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "variable byte integer") != null);
}

test "a length that is legal and enormous is refused before anything is allocated" {
    // `ff ff ff 7f` is a legal encoding of 268 435 455. A reader that took
    // it and allocated would ask this process for 256 MiB on five bytes.
    var server: test_server.Server = undefined;
    try server.start(.{ .raw_after_suback = &.{ 0x30, 0xff, 0xff, 0xff, 0x7f } });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/t/x");

    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(error.WeirdServerReply, f.open(url, .{}, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "larger than zurl reads") != null);
}

test "a broker that closes after the connect is a fault and not an empty answer" {
    var server: test_server.Server = undefined;
    try server.start(.{ .close_after_connack = true });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/t/x");

    // **Two answers, and both are the same fault told two ways.** The
    // broker's close and this client's SUBSCRIBE cross on the wire, so the
    // write reaches a socket that is closing or the read reaches one that
    // already closed, depending on which the kernel finished first. Either
    // is the transfer ending because the broker went away, and pinning one
    // of the two would be a test that fails on a loaded machine.
    var d: zurl_core.Diagnostics = .{};
    const err = f.open(url, .{}, &d);
    try testing.expect(err == error.WeirdServerReply or err == error.WriteError);
    try testing.expect(d.message != null);
}

test "a broker that says nothing at all is bounded by the read timeout" {
    // **The peer the read bound exists for.** The connect succeeds, so the
    // dial is over, and then the CONNACK never arrives.
    var server: test_server.Server = undefined;
    try server.startSilent();
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/t/x");

    var d: zurl_core.Diagnostics = .{};
    const brief: std.Io.Timeout = .{
        .duration = .{ .raw = .fromMilliseconds(150), .clock = .awake },
    };
    const err = f.open(url, .{ .read_timeout = brief }, &d);
    try testing.expectError(error.OperationTimedOut, err);
    try testing.expectEqual(@as(?u32, 28), d.curl_code);
}

test "a topic this build will not send opens no socket at all" {
    // **The refusal runs before the dial**, so a url a user mistyped sends
    // no credential anywhere. Measured: curl publishes to `t/#` and exits
    // 0, so a user of curl is told a message was sent that the broker must
    // throw away.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;

    var payload: Payload = .{ .bytes = "x" };
    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(error.InvalidUrl, f.open(
        try urlFor(&storage, server.port(), "/t/%23"),
        .{ .payload = payload.source() },
        &d,
    ));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "wildcard") != null);

    var again: Payload = .{ .bytes = "x" };
    try testing.expectError(error.InvalidUrl, f.open(
        try urlFor(&storage, server.port(), "/t/%00x"),
        .{ .payload = again.source() },
        &d,
    ));

    try testing.expectError(error.InvalidUrl, f.open(
        try urlFor(&storage, server.port(), "/"),
        .{},
        &d,
    ));

    try testing.expectEqual(@as(usize, 0), server.connections());
}

test "a message count outside the bound is refused before the dial" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/t/x");

    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(error.InvalidUrl, f.open(url, .{ .message_count = 0 }, &d));
    try testing.expectError(
        error.InvalidUrl,
        f.open(url, .{ .message_count = Fetcher.max_message_count + 1 }, &d),
    );
    try testing.expectEqual(@as(usize, 0), server.connections());
}

test "a payload larger than this build publishes is refused before the dial" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/t/x");

    var payload: Payload = .{ .bytes = "x" };
    var oversize = payload.source();
    // A source that lies about its own length is refused on the count it
    // named, before a byte of it is read.
    oversize.len = Fetcher.max_publish_bytes + 1;

    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(error.FileSizeExceeded, f.open(url, .{ .payload = oversize }, &d));
    try testing.expectEqual(@as(?u32, 63), d.curl_code);
    try testing.expectEqual(@as(usize, 0), server.connections());
}

test "a payload that cannot be read costs no connection" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/t/x");

    var broken: BrokenPayload = .{};
    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(error.ReadError, f.open(url, .{ .payload = broken.source() }, &d));
    try testing.expectEqual(@as(usize, 0), server.connections());
}

test "the collected answer is bounded, and no byte of an oversize one is returned" {
    var server: test_server.Server = undefined;
    try server.start(.{ .messages = &.{
        .{ .topic = "t", .payload = "aaaaaaaaaa" },
        .{ .topic = "t", .payload = "bbbbbbbbbb" },
    } });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/t");

    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(error.FileSizeExceeded, f.open(url, .{
        .message_count = 2,
        // One message is thirteen bytes with its topic count, so two do
        // not fit in twenty.
        .max_response_bytes = 20,
    }, &d));
    try testing.expectEqual(@as(?u32, 63), d.curl_code);
}

test "a message delivered above QoS 0 is named rather than passed off as acknowledged" {
    // This build sends no PUBACK, so the broker delivers the message
    // again. A user who is told nothing would not know.
    var server: test_server.Server = undefined;
    try server.start(.{ .messages = &.{
        .{ .topic = "t", .payload = "once", .qos = 1 },
    } });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/t");

    var d: zurl_core.Diagnostics = .{};
    const body = try f.open(url, .{}, &d);
    try testing.expectEqual(@as(u32, 1), body.messages);
    try testing.expect(d.message != null);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "arrive again") != null);
}

test "a fetcher runs one transfer after another and never holds two answers" {
    // **Two fixtures, and not one used twice.** A fixture accepts one
    // connection and its task then returns, so a second dial at the same
    // port connects to a listener nobody is reading and waits out the
    // whole read bound. That is a test that hangs for five minutes and
    // then passes, which is worse than no test at all.
    var first_server: test_server.Server = undefined;
    try first_server.start(.{ .messages = &.{.{ .topic = "t", .payload = "first" }} });
    defer first_server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const first = try f.open(try urlFor(&storage, first_server.port(), "/t"), .{}, null);
    const held = try first.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(held);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01, 't' } ++ "first".*, held);

    var second_server: test_server.Server = undefined;
    try second_server.start(.{ .messages = &.{.{ .topic = "t", .payload = "second" }} });
    defer second_server.stop();

    var more: [64]u8 = undefined;
    const second = try f.open(try urlFor(&more, second_server.port(), "/t"), .{}, null);
    const now = try second.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(now);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01, 't' } ++ "second".*, now);
    // The first answer is gone, not held beside the second.
    try testing.expectEqual(@as(u64, now.len), second.length);
}

test "a transfer that fails frees whatever the last one held" {
    // The second `open` here reaches a fixture that refuses the connect,
    // so it returns an error. What this proves is that the answer the
    // first transfer held was freed on the way in and is not leaked: the
    // testing allocator reports one if it were.
    var good: test_server.Server = undefined;
    try good.start(.{ .messages = &.{.{ .topic = "t", .payload = "kept" }} });
    defer good.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    _ = try f.open(try urlFor(&storage, good.port(), "/t"), .{}, null);

    var bad: test_server.Server = undefined;
    try bad.start(.{ .connack_code = 5 });
    defer bad.stop();

    var more: [64]u8 = undefined;
    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(
        error.WeirdServerReply,
        f.open(try urlFor(&more, bad.port(), "/t"), .{}, &d),
    );
}

test "the dispatch entry reports what curl reports for an mqtt url" {
    // curl prints `000` for `%{http_code}`, measured.
    try testing.expectEqual(@as(u16, 0), Fetcher.status);
}

test "--connect-to moves an mqtt dial and --resolve reaches this package too" {
    // The defect this closes: this package read no `connect_to`, so a
    // user who named either flag got a dial to the url's own host and no
    // diagnostic. curl 8.21.0 applies both to `mqtt` and `mqtts`,
    // measured.
    //
    // **No test here touches a resolver.** The url names `127.0.0.2:1`,
    // which refuses at once, so the flag is the only thing that can reach
    // the broker.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    const url = try Fetcher.parseMqttUrl("mqtt://127.0.0.2:1/zurl/test");

    var first: Payload = .{ .bytes = "hello world" };
    var bare: zurl_core.Diagnostics = .{};
    try testing.expectError(
        error.CouldNotConnect,
        f.open(url, .{ .payload = first.source() }, &bare),
    );
    try testing.expectEqual(@as(usize, 0), server.connections());

    var second: Payload = .{ .bytes = "hello world" };
    const body = try f.open(url, .{
        .payload = second.source(),
        .connect_to = &.{.{
            .from_host = "127.0.0.2",
            .from_port = 1,
            .to_host = "127.0.0.1",
            .to_port = server.port(),
        }},
    }, null);
    try testing.expect(body.published);
    try testing.expectEqual(@as(usize, 1), server.connections());
}
