//! End to end tests of `zurl_rtsp.Fetcher`, against the loopback server.
//!
//! Every test here opens a socket on 127.0.0.1 and none reaches the real
//! network. What each one proves is the bytes a transfer put on that
//! socket and the answer it made of what came back.
//!
//! The wire bytes each test pins were measured off curl 8.21.0 through a
//! `socat -x -v` relay in front of a real mediamtx 1.18.2. Where this
//! build and curl differ, the test says so and names what was measured.

const std = @import("std");
const testing = std.testing;

const zurl_core = @import("zurl-core");

const Fetcher = @import("Fetcher.zig");
const reply = @import("reply.zig");
const Session = @import("Session.zig");
const test_server = @import("test_server.zig");

/// A url for the fixture's own port.
fn urlFor(storage: []u8, port: u16, path: []const u8) !zurl_core.Url {
    const text = try std.fmt.bufPrint(storage, "rtsp://127.0.0.1:{d}{s}", .{ port, path });
    return Fetcher.parseRtspUrl(text);
}

/// A `Source` over a fixed slice, for a request body.
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

test "the default transfer sends the request curl sends, byte for byte" {
    // Measured: `curl rtsp://127.0.0.1:8554/stream` put
    // `OPTIONS * RTSP/1.0`, `CSeq: 1`, a `User-Agent`, and an empty line
    // on the wire. The path of the url was nowhere in the request.
    var server: test_server.Server = undefined;
    try server.start(.{
        .headers = &.{"Server: gortsplib"},
    });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/stream");

    const answer = try f.open(url, .{}, null);
    try testing.expectEqual(@as(u16, 200), answer.status);
    try testing.expectEqual(@as(u64, 0), answer.length);
    try testing.expectEqual(@as(u64, 1), answer.cseq);
    // **The head reaches `-i`**, the way curl prints it.
    try testing.expectEqualStrings(
        "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: gortsplib\r\n\r\n",
        answer.head,
    );

    server.wait();
    try testing.expectEqualStrings(
        "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: zurl/0.1\r\n\r\n",
        server.log(),
    );
}

test "a DESCRIBE names the stream and reads the description back" {
    // curl's command line cannot send this at all: measured,
    // `curl -X DESCRIBE rtsp://host/stream` put `OPTIONS *` on the wire.
    const sdp = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=zurl\r\nm=video 0 RTP/AVP 96\r\n";

    var server: test_server.Server = undefined;
    try server.start(.{
        .headers = &.{"Content-Type: application/sdp"},
        .body = sdp,
    });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/stream");

    const answer = try f.open(url, .{ .method_name = "DESCRIBE" }, null);
    try testing.expectEqual(@as(u16, 200), answer.status);
    try testing.expectEqual(@as(u64, sdp.len), answer.length);

    const body = try answer.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings(sdp, body);

    server.wait();
    try testing.expect(std.mem.startsWith(u8, server.log(), "DESCRIBE rtsp://127.0.0.1:"));
    try testing.expect(std.mem.indexOf(u8, server.log(), "Accept: application/sdp\r\n") != null);
}

test "a SETUP reply hands its session identifier back for the next run" {
    // One transfer is one request, so a `SETUP` and the `PLAY` after it are
    // two runs of zurl, and the identifier travels between them.
    var server: test_server.Server = undefined;
    try server.start(.{
        .headers = &.{
            "Session: 12345678;timeout=60",
            "Transport: RTP/AVP;unicast;client_port=4588-4589;server_port=6256-6257",
        },
    });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/stream");

    const answer = try f.open(url, .{
        .method_name = "SETUP",
        .stream_uri = "rtsp://127.0.0.1/stream/trackID=0",
        .transport = "RTP/AVP;unicast;client_port=4588-4589",
    }, null);
    // The identifier is the part before the `;`, so the next request does
    // not send the timeout as part of it.
    try testing.expectEqualStrings("12345678", answer.session.?);

    server.wait();
    try testing.expect(std.mem.startsWith(
        u8,
        server.log(),
        "SETUP rtsp://127.0.0.1/stream/trackID=0 RTSP/1.0\r\n",
    ));
    try testing.expect(std.mem.indexOf(
        u8,
        server.log(),
        "Transport: RTP/AVP;unicast;client_port=4588-4589\r\n",
    ) != null);
}

test "a reply carrying another request's CSeq is a protocol error" {
    // **The tie between a reply and its request, on a live socket.** A
    // session that carried on would read the answer to one request as the
    // answer to another.
    var server: test_server.Server = undefined;
    try server.start(.{ .cseq = 4242 });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/stream");

    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(error.WeirdServerReply, f.open(url, .{}, &d));
    try testing.expectEqual(@as(?u32, 8), d.curl_code);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "belongs to no request") != null);
}

test "a reply with no CSeq is refused rather than guessed about" {
    // RFC 2326 section 12.17 makes one required in every reply.
    var server: test_server.Server = undefined;
    try server.start(.{ .write_cseq = false });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/stream");

    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(error.WeirdServerReply, f.open(url, .{}, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "no CSeq") != null);
}

test "an interleaved binary frame is refused rather than read as a reply" {
    // **What `Session.interleave_marker` closes, on a live socket.** This
    // build asks for no interleaved transport, so a `$` here belongs to no
    // request it sent.
    var server: test_server.Server = undefined;
    try server.start(.{ .raw = &[_]u8{ '$', 0x00, 0x00, 0x04, 0x80, 0x60, 0x00, 0x01 } });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/stream");

    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(error.WeirdServerReply, f.open(url, .{}, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "interleaved") != null);
}

test "a reply that is not RTSP at all is refused by name" {
    var server: test_server.Server = undefined;
    try server.start(.{ .status = "HTTP/1.1 200 OK" });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/stream");

    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(error.WeirdServerReply, f.open(url, .{}, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "not RTSP/1.0") != null);
}

test "an announced body past the bound is refused before any of it is read" {
    var server: test_server.Server = undefined;
    try server.start(.{ .body = "x", .content_length = 99_999 });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/stream");

    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(
        error.FileSizeExceeded,
        f.open(url, .{ .max_body_bytes = 1024 }, &d),
    );
    try testing.expectEqual(@as(?u32, 63), d.curl_code);
}

test "a body shorter than its announced length is PartialFile and not a whole answer" {
    // A caller that got the bytes anyway would have a truncated
    // description and no sign that it was cut.
    var server: test_server.Server = undefined;
    try server.start(.{ .body = "short", .content_length = 500 });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/stream");

    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(error.PartialFile, f.open(url, .{}, &d));
    try testing.expectEqual(@as(?u32, 18), d.curl_code);
}

test "a failing status reaches the caller, and -f turns it into an error" {
    // Without `-f` the status is reported and the body still arrives,
    // which is what curl does for an HTTP url.
    var server: test_server.Server = undefined;
    try server.start(.{ .status = "RTSP/1.0 404 Not Found", .body = "gone" });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/nosuch");

    const answer = try f.open(url, .{}, null);
    try testing.expectEqual(@as(u16, 404), answer.status);
    const body = try answer.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("gone", body);
}

test "-f turns a failing status into exit 22, which is curl's code" {
    var server: test_server.Server = undefined;
    try server.start(.{ .status = "RTSP/1.0 461 Unsupported Transport" });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/stream");

    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(
        error.HttpReturnedError,
        f.open(url, .{ .fail_on_error = true }, &d),
    );
    try testing.expectEqual(@as(?u32, 22), d.curl_code);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "461") != null);
}

test "a body reaches the wire for the two methods that take one" {
    var server: test_server.Server = undefined;
    try server.start(.{ .body = "barparam: barstuff\r\n" });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/stream");

    var payload: Payload = .{ .bytes = "packets_received\r\n" };
    const answer = try f.open(url, .{
        .method_name = "GET_PARAMETER",
        .body = payload.source(),
        .session_id = "12345678",
    }, null);
    try testing.expectEqual(@as(u16, 200), answer.status);

    server.wait();
    try testing.expect(std.mem.indexOf(u8, server.log(), "Content-Length: 18\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, server.log(), "packets_received\r\n"));
}

test "a body beside a method that takes none opens no socket" {
    // **The refusal runs before the dial.** A server that read a body
    // after a `PLAY` would be reading the request after this one.
    // Measured: curl sends `-d` nowhere for rtsp at all, and still exits
    // 0.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/stream");

    var payload: Payload = .{ .bytes = "x" };
    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(error.InvalidUrl, f.open(url, .{
        .method_name = "PLAY",
        .body = payload.source(),
    }, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "GET_PARAMETER") != null);
    try testing.expectEqual(@as(usize, 0), server.connections());
}

test "a flag that would forge a header opens no socket" {
    // **The injection refusal, on the path a real transfer takes.** A CR
    // in `--rtsp-session-id` would write a header the user did not name,
    // and the refusal costs no connection and sends no credential.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/stream");

    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(error.InvalidUrl, f.open(url, .{
        .method_name = "PLAY",
        .session_id = "1\r\nRange: npt=0-",
    }, &d));
    try testing.expectError(error.InvalidUrl, f.open(url, .{
        .method_name = "SETUP",
        .transport = "RTP/AVP\r\nSession: stolen",
    }, &d));
    try testing.expectError(error.InvalidUrl, f.open(url, .{
        .method_name = "DESCRIBE",
        .stream_uri = "rtsp://h/s\r\nTEARDOWN rtsp://h/s RTSP/1.0",
    }, &d));
    try testing.expectError(error.InvalidUrl, f.open(url, .{
        .headers = &.{.{ .name = "X", .value = "a\r\nSession: stolen" }},
    }, &d));

    try testing.expectEqual(@as(usize, 0), server.connections());
}

test "a method this build does not send is exit 4, and opens no socket" {
    // **The refusal runs before the dial**, so a `-X ANNOUNCE` that a user
    // typed by mistake reaches no server and sends no credential. curl's
    // command line cannot send any of these at all: it writes `OPTIONS *`
    // whatever `-X` says, measured.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/stream");

    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(
        error.NotBuiltIn,
        f.open(url, .{ .method_name = "ANNOUNCE" }, &d),
    );
    try testing.expectEqual(@as(?u32, 4), d.curl_code);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "changes what a server holds") != null);

    try testing.expectError(
        error.NotBuiltIn,
        f.open(url, .{ .method_name = "FROBNICATE" }, &d),
    );
    try testing.expectEqual(@as(usize, 0), server.connections());

    // However it is typed, a method this build does send still runs.
    const answer = try f.open(url, .{ .method_name = "options" }, null);
    try testing.expectEqual(@as(u16, 200), answer.status);
}

test "a SETUP with no transport opens no socket" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/stream");

    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(error.InvalidUrl, f.open(url, .{ .method_name = "SETUP" }, &d));
    try testing.expectEqual(@as(usize, 0), server.connections());
}

test "a credential goes in a header and never in the request line" {
    // Measured: curl put `Authorization: Basic dTpw` in the head and the
    // request line held no credential at all.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var text: [96]u8 = undefined;
    const url = try Fetcher.parseRtspUrl(try std.fmt.bufPrint(
        &text,
        "rtsp://u:p@127.0.0.1:{d}/stream",
        .{server.port()},
    ));

    _ = try f.open(url, .{ .method_name = "DESCRIBE" }, null);

    server.wait();
    const sent = server.log();
    try testing.expect(std.mem.indexOf(u8, sent, "Authorization: Basic dTpw\r\n") != null);
    // The request line is the first line, and it holds no credential.
    const first = sent[0 .. std.mem.indexOfScalar(u8, sent, '\r') orelse sent.len];
    try testing.expect(std.mem.indexOf(u8, first, "u:p") == null);
    try testing.expect(std.mem.indexOf(u8, first, "@") == null);
}

test "a caller's own headers reach the wire, which is what curl carries too" {
    // Measured: `-H 'Accept: application/sdp' -H 'Require: x'` both went
    // out.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/stream");

    _ = try f.open(url, .{
        .headers = &.{
            .{ .name = "Require", .value = "x" },
            .{ .name = "X-Note", .value = "hello" },
        },
    }, null);

    server.wait();
    try testing.expect(std.mem.indexOf(u8, server.log(), "Require: x\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, server.log(), "X-Note: hello\r\n") != null);
}

test "a server that says nothing at all is bounded by the read timeout" {
    // **The peer the read bound exists for.** The connect succeeds, so the
    // dial is over, and then the reply never arrives.
    var server: test_server.Server = undefined;
    try server.startSilent();
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/stream");

    var d: zurl_core.Diagnostics = .{};
    const brief: std.Io.Timeout = .{
        .duration = .{ .raw = .fromMilliseconds(150), .clock = .awake },
    };
    try testing.expectError(
        error.OperationTimedOut,
        f.open(url, .{ .read_timeout = brief }, &d),
    );
    try testing.expectEqual(@as(?u32, 28), d.curl_code);
}

test "a server that closes without answering is a fault and not an empty reply" {
    var server: test_server.Server = undefined;
    try server.start(.{ .close_without_answer = true });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/stream");

    // **Two answers, and both are the same fault told two ways.** The
    // server's close and this client's request cross on the wire, so the
    // write reaches a socket that is closing or the read reaches one that
    // already closed, depending on which the kernel finished first.
    // Pinning one of the two would be a test that fails on a loaded
    // machine.
    var d: zurl_core.Diagnostics = .{};
    const err = f.open(url, .{}, &d);
    try testing.expect(err == error.WeirdServerReply or err == error.WriteError);
    try testing.expect(d.message != null);
}

test "a head of many short lines is read whole, which one line bound alone would not do" {
    // **The case the head bound exists for, from the other side.** A head
    // of a hundred short lines is legal, and this proves it is read rather
    // than refused. `Session.zig`'s own test drives the same shape past
    // the bound and proves it is refused there.
    var padding: [128][]const u8 = undefined;
    var lines: [128][40]u8 = undefined;
    for (&padding, &lines, 0..) |*slot, *room, i| {
        slot.* = try std.fmt.bufPrint(room, "X-Pad-{d}: {s}", .{ i, "p" ** 24 });
    }

    var server: test_server.Server = undefined;
    try server.start(.{ .headers = &padding });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const url = try urlFor(&storage, server.port(), "/stream");

    // The whole head here is about five kilobytes, so it fits the real
    // bound. What this proves is that a head of many lines is read at all,
    // which is the case the line bound alone would let through.
    const answer = try f.open(url, .{}, null);
    try testing.expectEqual(@as(u16, 200), answer.status);
    try testing.expect(answer.head.len > 4096);
}

test "a fetcher runs one transfer after another and its numbers start over" {
    // Each transfer opens its own connection, so each starts at `CSeq: 1`.
    // curl does the same, measured.
    var first: test_server.Server = undefined;
    try first.start(.{});
    defer first.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var storage: [64]u8 = undefined;
    const one = try f.open(try urlFor(&storage, first.port(), "/a"), .{}, null);
    try testing.expectEqual(@as(u64, 1), one.cseq);
    first.wait();
    try testing.expect(std.mem.indexOf(u8, first.log(), "CSeq: 1\r\n") != null);

    var second: test_server.Server = undefined;
    try second.start(.{});
    defer second.stop();

    var more: [64]u8 = undefined;
    const two = try f.open(try urlFor(&more, second.port(), "/b"), .{}, null);
    try testing.expectEqual(@as(u64, 1), two.cseq);
    second.wait();
    try testing.expect(std.mem.indexOf(u8, second.log(), "CSeq: 1\r\n") != null);
}

test "the numbers this package promises are the numbers it keeps" {
    // The refusal lives in `zurl_rtsp.method` and not inside a `Fetcher`,
    // so a caller can report it before it ever asks for a transfer.
    const method = @import("method.zig");
    try testing.expect(method.refusal("ANNOUNCE") != null);
    try testing.expect(method.refusal("RECORD") != null);
    try testing.expectEqual(@as(?[]const u8, null), method.refusal("TEARDOWN"));

    // curl's first request carried `CSeq: 1`, measured.
    try testing.expectEqual(@as(u64, 1), Session.first_cseq);
    try testing.expectEqual(@as(usize, 65_536), reply.max_head_bytes);
    try testing.expectEqual(@as(?u16, 554), Fetcher.default_port);
}

test "--connect-to moves an rtsp dial and --resolve reaches this package too" {
    // The defect this closes: this package read no `connect_to`, so a
    // user who named either flag got a dial to the url's own host and no
    // diagnostic. curl 8.21.0 applies both to `rtsp`, measured.
    //
    // **No test here touches a resolver.** The url names `127.0.0.2:1`,
    // which refuses at once, so the flag is the only thing that can reach
    // the fixture.
    var server: test_server.Server = undefined;
    try server.start(.{ .headers = &.{"Server: gortsplib"} });
    defer server.stop();

    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    const url = try Fetcher.parseRtspUrl("rtsp://127.0.0.2:1/stream");

    var bare: zurl_core.Diagnostics = .{};
    try testing.expectError(error.CouldNotConnect, f.open(url, .{}, &bare));
    try testing.expectEqual(@as(usize, 0), server.connections());

    const answer = try f.open(url, .{ .connect_to = &.{.{
        .from_host = "127.0.0.2",
        .from_port = 1,
        .to_host = "127.0.0.1",
        .to_port = server.port(),
    }} }, null);
    try testing.expectEqual(@as(u16, 200), answer.status);
    try testing.expectEqual(@as(usize, 1), server.connections());
}
