//! End to end tests for the `zurl` binary.
//!
//! Every other test file in this project tests one part. This one tests
//! the product: it spawns the installed binary, points it at the loopback
//! fixture, and reads the bytes the binary really wrote.
//!
//! The tests here aim at the seams **between** the features. A test that
//! proves one flag belongs beside that flag's own code, in `src/main.zig`
//! or in `src/cli/`. A test that proves two flags do not corrupt each
//! other belongs here.
//!
//! Three rules hold for every test in this file.
//!
//! No test reaches the network. `zurl-http`'s `test_server` listens on
//! 127.0.0.1 with a port the OS assigns, and every url points at it.
//!
//! No test asserts an upper bound on time. A loaded machine makes such an
//! assertion fail for a reason that has nothing to do with zurl, and this
//! is the suite that proves the phase. A timing assertion here is a floor.
//!
//! A build with no concurrency cannot start the fixture. `TestServer.start`
//! returns `error.SkipZigTest` there, so a test that needs a server skips
//! instead of failing. The tests that need no server still run in that
//! build.

const std = @import("std");
const testing = std.testing;

/// The fixtures that spawn the installed binary. `src/main.zig` shares the
/// same file, so the two suites run the same binary in the same
/// environment. Two spawn helpers would be two different environments, and
/// a test that ran in the wrong one would prove the wrong thing.
const harness = @import("testing.zig");

/// The CLI's root file, for the one number this file asserts on and the
/// program itself declares. The fixtures come from `harness`, so this is
/// the only reason left to name `main.zig` here.
const cli = @import("../main.zig");

/// The loopback fixtures of the three protocol packages this build carries
/// beyond HTTP. Each package exports its own, for the reason
/// `zurl-http/test_server.zig` is exported: a second copy here would drift
/// from the one the package tests itself with.
const zurl_dict = @import("zurl-dict");
const zurl_gopher = @import("zurl-gopher");
const zurl_ws = @import("zurl-ws");
const zurl_telnet = @import("zurl-telnet");
const zurl_tftp = @import("zurl-tftp");
const zurl_ftp = @import("zurl-ftp");
const zurl_pop3 = @import("zurl-pop3");
const zurl_imap = @import("zurl-imap");
const zurl_smtp = @import("zurl-smtp");

const test_server = harness.test_server;
const proxy_test_server = harness.proxy_test_server;
const runZurl = harness.runZurl;
const runZurlIn = harness.runZurlIn;
const loopbackUrl = harness.loopbackUrl;
const loopbackUrlAt = harness.loopbackUrlAt;
const closedPort = harness.closedPort;
const afterMeter = harness.afterMeter;
const SandboxDir = harness.SandboxDir;
const usage_error_code = cli.usage_error_code;

/// A response that carries `body` with a correct `Content-Length`.
///
/// The fixture writes back exactly what a caller gives it, so a head that
/// announces the wrong length is a test that measures the wrong thing.
fn ok(comptime body: []const u8) []const u8 {
    return std.fmt.comptimePrint(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\n" ++
            "Connection: close\r\n\r\n{s}",
        .{ body.len, body },
    );
}

test "a plain get writes the body to stdout" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{ok("hello world\n")});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{url});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("hello world\n", result.stdout);
    // The meter is the whole of standard error. Nothing else belongs there
    // on a transfer that succeeded.
    try testing.expectEqualStrings("", try afterMeter(result.stderr));
}

test "-o writes the body to a file and stdout stays empty" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{ok("payload")});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-o", "body.bin", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("", result.stdout);
    try testing.expectEqualStrings("", try afterMeter(result.stderr));

    const written = try sandbox.work.readFileAlloc(testing.io, "body.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(written);
    try testing.expectEqualStrings("payload", written);
}

test "-f makes a 404 a non-zero exit with the curl code" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\nConnection: close\r\n\r\ngone!",
    });
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-f", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    // `CURLE_HTTP_RETURNED_ERROR` is 22.
    try testing.expectEqual(std.process.Child.Term{ .exited = 22 }, result.term);
    // curl 8.21.0 writes no body for a refused status, and neither does
    // zurl. A caller that pipes the output must not get the error page.
    try testing.expectEqualStrings("", result.stdout);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "404") != null);
}

test "a 404 without -f exits 0 and writes the body" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\nConnection: close\r\n\r\ngone!",
    });
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{url});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    // The status is the server's answer, not a transfer fault. Only `-f`
    // makes it one.
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("gone!", result.stdout);
}

test "--limit-rate slows a transfer measurably" {
    // The throttle is a token bucket that starts full, so a body of `n`
    // bytes at `rate` bytes each second takes at least (n - rate) / rate
    // seconds. 12288 bytes at 4096 bytes each second is two seconds.
    //
    // **The assertion is a floor and never a ceiling.** The floor is one
    // second, half of the arithmetic minimum. A machine cannot go under
    // it, however fast it is, because the wait comes from the clock. An
    // upper bound would fail on a loaded machine for no fault of zurl's.
    const rate = 4096;
    const body = "x" ** 12288;

    var server: test_server.TestServer = undefined;
    try server.start(&.{ok(body)});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const started = std.Io.Timestamp.now(testing.io, .awake);
    const result = try runZurl(&.{ "--limit-rate", "4k", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);
    const elapsed = started.durationTo(std.Io.Timestamp.now(testing.io, .awake));

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    // The throttle must not lose or duplicate a byte while it waits.
    try testing.expectEqual(@as(usize, body.len), result.stdout.len);
    try testing.expectEqualStrings(body, result.stdout);

    const floor_ns: i96 = 1 * std.time.ns_per_s;
    if (elapsed.nanoseconds < floor_ns) {
        std.debug.print(
            "a {d} byte body at {d} bytes each second finished in {d}ms\n",
            .{ body.len, rate, @divTrunc(elapsed.nanoseconds, std.time.ns_per_ms) },
        );
        return error.TestUnexpectedResult;
    }
}

test "-w prints the status after the body" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{ok("body\n")});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-w", "status=%{http_code}\n", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    // The order matters. curl 8.21.0 writes the body first and the format
    // after it, so a caller that reads the last line reads the report.
    try testing.expectEqualStrings("body\nstatus=200\n", result.stdout);
    try testing.expectEqualStrings("", try afterMeter(result.stderr));
}

test "a bad url exits with the curl code for a malformed url" {
    // `CURLE_URL_MALFORMAT` is 3. The authority is empty, so the url does
    // not parse and nothing connects.
    const result = try runZurl(&.{"http://"});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 3 }, result.term);
    try testing.expectEqualStrings("", result.stdout);
    // No meter, because no transfer reached a server.
    try testing.expect(std.mem.indexOf(u8, result.stderr, "(3)") != null);
}

/// A host name of 254 characters, one over the bound an encoded name
/// holds.
///
/// **Every character of it is one a host name allows.** RFC 1035 section
/// 2.3.4 holds an encoded name to 255 octets, which is 253 written
/// characters, so the only thing wrong with this name is how long it is.
/// A dot goes in at every 64th place, because a label holds at most 63
/// characters.
const over_long_host = name: {
    var text: [254]u8 = undefined;
    for (&text, 0..) |*byte, i| byte.* = if ((i + 1) % 64 == 0) '.' else 'a';
    break :name text;
};

test "a host name longer than dns holds exits with the curl code for a name that did not resolve" {
    // **curl exits 6 for this, and zurl exited 3.** Measured against curl
    // 8.21.0 with names of 253, 254, 255, and 300 characters, on `http`
    // and on `ftp`: every one of them is `CURLE_COULDNT_RESOLVE_HOST`.
    //
    // The reason curl is right is that the name is a good host name. The
    // url that carries it is well formed, and only the lookup is
    // impossible, so the fault belongs to the resolver and not to the
    // url. See `zurl_net.tcp.Host.InitError.HostNameTooLong`.
    const result = try runZurl(&.{ "-s", "-S", "http://" ++ over_long_host ++ "/" });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 6 }, result.term);
    try testing.expectEqualStrings("", result.stdout);
    // The sentence is what sends the user to shorten the name. The exit
    // code alone says only that some name did not resolve.
    try testing.expect(std.mem.indexOf(u8, result.stderr, "(6)") != null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "longer") != null);
}

test "a host name longer than dns holds exits 6 on a scheme that is not http" {
    // The bound sits in `zurl_net.tcp.Host.init`, which every protocol
    // package dials through, so one engine proves nothing about the rest.
    // These two reach it from two different files.
    const urls = [_][]const u8{
        "ftp://" ++ over_long_host ++ "/x",
        "dict://" ++ over_long_host ++ ":2628/d:zurl",
    };
    for (urls) |url| {
        const result = try runZurl(&.{ "-s", "-S", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 6 }, result.term);
        try testing.expectEqualStrings("", result.stdout);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "(6)") != null);
    }
}

test "a host that is not a name keeps the curl code for a malformed url" {
    // **The pair this split exists for.** A name over the bound is exit 6
    // and text that is not a host name at all is exit 3, and the two must
    // not drift into one another. An underscore is not a character a host
    // name allows, and this url is otherwise the same shape as the one
    // above it.
    const urls = [_][]const u8{
        "ftp://ho_st.example/x",
        "dict://ho_st.example:2628/d:zurl",
    };
    for (urls) |url| {
        const result = try runZurl(&.{ "-s", "-S", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 3 }, result.term);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "(3)") != null);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "neither an address nor a name") != null);
    }
}

test "--cacert naming a missing file exits with a clear message" {
    // curl 8.21.0 exits 2 for this, not with a transfer code: it reads the
    // file when it parses the flag, before any transfer starts. The url
    // below would fail at the network if the check ever moved, so this
    // also proves the check runs first.
    const result = try runZurl(&.{ "--cacert", "/nonexistent/zurl-e2e-ca.pem", "https://example.com/" });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = usage_error_code }, result.term);
    try testing.expectEqualStrings("", result.stdout);
    // The message must name both the flag and the path. A message with
    // neither leaves the user guessing which of several file flags failed.
    try testing.expect(std.mem.indexOf(u8, result.stderr, "--cacert") != null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "/nonexistent/zurl-e2e-ca.pem") != null);
}

test "-o and -D and -w each write their own sink, and none corrupts another" {
    // Three sinks are live at once: the body goes to a file, the head goes
    // to another file, and the report goes to standard output. Each part
    // has its own tests. This one proves they stay apart.
    const head = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 7\r\n" ++
        "Connection: close\r\n\r\n";

    var server: test_server.TestServer = undefined;
    try server.start(&.{head ++ "payload"});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{
        "-o", "body.bin",
        "-D", "head.txt",
        "-w", "%{http_code}:%{size_download}",
        url,
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    // Standard output holds the report alone. Neither file's bytes leaked
    // into it, and the report did not go into either file.
    try testing.expectEqualStrings("200:7", result.stdout);
    try testing.expectEqualStrings("", try afterMeter(result.stderr));

    const written_head = try sandbox.work.readFileAlloc(testing.io, "head.txt", testing.allocator, .limited(1024));
    defer testing.allocator.free(written_head);
    try testing.expectEqualStrings(head, written_head);

    const written_body = try sandbox.work.readFileAlloc(testing.io, "body.bin", testing.allocator, .limited(1024));
    defer testing.allocator.free(written_body);
    try testing.expectEqualStrings("payload", written_body);
}

test "the meter draws while a body goes to standard output, and the body stays byte for byte" {
    // The meter writes to standard error and the body writes to standard
    // output. A meter that ever wrote a byte into the body would corrupt
    // every piped download, and a text body would hide it. This body is
    // every byte value from 0 through 255, so a lost, a doubled, or a
    // translated byte shows up.
    const body = comptime blk: {
        var bytes: [256]u8 = undefined;
        for (&bytes, 0..) |*byte, index| byte.* = @intCast(index);
        break :blk bytes;
    };
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 256\r\nConnection: close\r\n\r\n" ++ body;

    var server: test_server.TestServer = undefined;
    try server.start(&.{response});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{url});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualSlices(u8, &body, result.stdout);
    // The meter really drew, so the two streams were live together.
    try testing.expectEqualStrings("", try afterMeter(result.stderr));
}

test "-Z with -O writes every file, which is the one shape that runs in parallel" {
    // `-O` gives each url a file of its own. Every other output shape has
    // one destination for all the urls, so `parallelBlocker` sends those
    // down the one at a time path. This shape is the only one that really
    // overlaps, so it is the only one that can lose a transfer.
    //
    // Three servers, because one `TestServer` accepts one connection at a
    // time and would serialise what this test wants to overlap. Each
    // `start` has its own `defer`, so a later `start` that fails cannot
    // leak the servers before it.
    var server_a: test_server.TestServer = undefined;
    try server_a.start(&.{ok("alpha")});
    defer server_a.stop();

    var server_b: test_server.TestServer = undefined;
    try server_b.start(&.{ok("bravo")});
    defer server_b.stop();

    var server_c: test_server.TestServer = undefined;
    try server_c.start(&.{ok("charlie")});
    defer server_c.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url_a = try loopbackUrlAt(&server_a, "/alpha.bin");
    defer testing.allocator.free(url_a);
    const url_b = try loopbackUrlAt(&server_b, "/bravo.bin");
    defer testing.allocator.free(url_b);
    const url_c = try loopbackUrlAt(&server_c, "/charlie.bin");
    defer testing.allocator.free(url_c);

    const result = try runZurlIn(sandbox.work, &.{
        "-Z", "-O", url_a, "-O", url_b, "-O", url_c,
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("", result.stdout);
    // No meter and no note. `-Z` draws no meter while transfers overlap,
    // and nothing forced this run down to one transfer at a time.
    try testing.expectEqualStrings("", result.stderr);

    const wanted = [_]struct { name: []const u8, body: []const u8 }{
        .{ .name = "alpha.bin", .body = "alpha" },
        .{ .name = "bravo.bin", .body = "bravo" },
        .{ .name = "charlie.bin", .body = "charlie" },
    };
    for (wanted) |want| {
        const written = try sandbox.work.readFileAlloc(testing.io, want.name, testing.allocator, .limited(64));
        defer testing.allocator.free(written);
        try testing.expectEqualStrings(want.body, written);
    }
}

test "a flag on the command line overrides the same flag in a config file" {
    // curl reads a config file as if its lines stood where the `-K` stands,
    // so a later command line flag wins. A config file that could not be
    // overridden would make a user edit a file to change one run.
    var server: test_server.TestServer = undefined;
    try server.start(&.{ok("ok")});
    defer server.stop();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{
        .sub_path = "zurl.conf",
        .data = "user-agent config-agent/1\n",
    });
    const config_path = try std.fmt.allocPrint(
        testing.allocator,
        ".zig-cache/tmp/{s}/zurl.conf",
        .{tmp.sub_path},
    );
    defer testing.allocator.free(config_path);

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-K", config_path, "-A", "command-line-agent/2", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    const head = server.requestHead(0).?;
    try testing.expect(std.mem.indexOf(u8, head, "command-line-agent/2") != null);
    // The config file's value must be gone, not merely second. Two
    // `User-Agent` lines would let the server read the one the user
    // replaced.
    try testing.expect(std.mem.indexOf(u8, head, "config-agent/1") == null);
    try testing.expectEqual(@as(usize, 1), test_server.countHeaders(head, "User-Agent"));
}

test "-L follows a redirect chain to the body, and no -L stops at the first hop" {
    // Two hops, not one. A follower that handled the first `Location` and
    // then stopped would pass a single hop test and fail every real
    // redirect chain.
    const first = "HTTP/1.1 302 Found\r\nLocation: /second\r\nContent-Length: 4\r\n" ++
        "Connection: close\r\n\r\nhop1";
    const second = "HTTP/1.1 302 Found\r\nLocation: /third\r\nContent-Length: 4\r\n" ++
        "Connection: close\r\n\r\nhop2";
    const third = ok("arrived");

    var followed: test_server.TestServer = undefined;
    try followed.start(&.{ first, second, third });
    defer followed.stop();

    const follow_url = try loopbackUrlAt(&followed, "/first");
    defer testing.allocator.free(follow_url);

    const with_flag = try runZurl(&.{ "-L", follow_url });
    defer testing.allocator.free(with_flag.stdout);
    defer testing.allocator.free(with_flag.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, with_flag.term);
    // Only the last body reaches standard output. The bodies of the hops
    // are not part of what the user asked for.
    try testing.expectEqualStrings("arrived", with_flag.stdout);

    const third_head = followed.requestHead(2).?;
    try testing.expect(std.mem.startsWith(u8, third_head, "GET /third "));

    // The same first hop, with no `-L`. A second server, because the one
    // above has used up its script.
    var stopped: test_server.TestServer = undefined;
    try stopped.start(&.{first});
    defer stopped.stop();

    const stop_url = try loopbackUrlAt(&stopped, "/first");
    defer testing.allocator.free(stop_url);

    const without_flag = try runZurl(&.{stop_url});
    defer testing.allocator.free(without_flag.stdout);
    defer testing.allocator.free(without_flag.stderr);

    // curl treats a redirect it was not told to follow as a finished
    // transfer: exit 0, and the 302's own body on standard output.
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, without_flag.term);
    try testing.expectEqualStrings("hop1", without_flag.stdout);
    try testing.expectEqual(@as(?[]const u8, null), stopped.requestHead(1));
}

test "a file url reads a local file, and a missing one carries curl's own code" {
    // The product, over the protocol package this build registers beside
    // the built-in HTTP one. No server runs at all, so this test also
    // runs in a build with no concurrency.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    try sandbox.work.writeFile(testing.io, .{
        .sub_path = "local.txt",
        .data = "read from disk\n",
    });

    var path_storage: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir_path = path_storage[0..try sandbox.work.realPath(testing.io, &path_storage)];

    const url = try std.fmt.allocPrint(testing.allocator, "file://{s}/local.txt", .{dir_path});
    defer testing.allocator.free(url);

    const read = try runZurlIn(sandbox.work, &.{ "-s", url });
    defer testing.allocator.free(read.stdout);
    defer testing.allocator.free(read.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, read.term);
    try testing.expectEqualStrings("read from disk\n", read.stdout);

    // Nothing registered the scheme before this work, so this url was
    // exit 3 at the url parser and never reached a protocol at all.
    const missing = try std.fmt.allocPrint(testing.allocator, "file://{s}/nope.txt", .{dir_path});
    defer testing.allocator.free(missing);

    const failed = try runZurlIn(sandbox.work, &.{ "-s", "-S", missing });
    defer testing.allocator.free(failed.stdout);
    defer testing.allocator.free(failed.stderr);
    // 37 is `CURLE_FILE_COULDNT_READ_FILE`, which is what curl 8.21.0
    // exits with for a `file://` url that names nothing.
    try testing.expectEqual(std.process.Child.Term{ .exited = 37 }, failed.term);
    try testing.expectEqualStrings("", failed.stdout);
    try testing.expect(std.mem.indexOf(u8, failed.stderr, "nope.txt") != null);
}

test "-D on a protocol that reports no head is refused by name and not as a write fault" {
    // **The name, and not only the refusal.** `-D` and `-I` on a protocol
    // with no `Response.headers` used to exit 23, `CURLE_WRITE_ERROR`, and
    // no write had gone wrong at all: this build has no head for that
    // protocol. A user who reads a write fault looks at the file system.
    // 4 is `CURLE_NOT_BUILT_IN`, which is what a feature this build does
    // not carry answers with.
    //
    // `file://` is the protocol with no peer, so this test starts no
    // server and runs in a build with no concurrency. Every other protocol
    // outside http answers the same way, through the same line in
    // `run.zig`.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    try sandbox.work.writeFile(testing.io, .{
        .sub_path = "local.txt",
        .data = "read from disk\n",
    });

    var path_storage: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir_path = path_storage[0..try sandbox.work.realPath(testing.io, &path_storage)];
    const url = try std.fmt.allocPrint(testing.allocator, "file://{s}/local.txt", .{dir_path});
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-s", "-S", "-D", "head.txt", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 4 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "no response headers") != null);

    // And no half written head was left behind. The file itself is made
    // when the plan is built, before any transfer runs, so it is there and
    // it is empty.
    const head = try sandbox.work.statFile(testing.io, "head.txt", .{});
    try testing.expectEqual(@as(u64, 0), head.size);

    // `-i` is the flag that writes no head and fails nothing, which is the
    // other half of the rule.
    const shown = try runZurlIn(sandbox.work, &.{ "-s", "-i", url });
    defer testing.allocator.free(shown.stdout);
    defer testing.allocator.free(shown.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, shown.term);
    try testing.expectEqualStrings("read from disk\n", shown.stdout);
}

test "a redirect into file:// is refused and the file never reaches the output" {
    // **The security rule.** Without it any http server can answer
    // `location: file:///etc/passwd`, and a client that follows it reads
    // a local file and, under `-o`, writes it where the user can be made
    // to send it on. curl 8.21.0 refuses the same redirect with exit 1
    // and `Protocol "file" is disabled (in redirect)`; its
    // `--proto-redir` default is `http,https,ftp,ftps`, and `file` is not
    // in it. `zurl_core.redirect` is that default.
    //
    // The file is real and its contents are distinctive, so this test
    // fails loudly if the refusal ever stops working: a build that
    // followed the redirect would put `SECRET-FILE-CONTENTS` on standard
    // output.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const secret = "SECRET-FILE-CONTENTS\n";
    try sandbox.root.writeFile(testing.io, .{ .sub_path = "secret.txt", .data = secret });

    var path_storage: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir_path = path_storage[0..try sandbox.root.realPath(testing.io, &path_storage)];

    // The file really is readable by this url, so the refusal is the only
    // thing between the server and the contents.
    const file_url = try std.fmt.allocPrint(testing.allocator, "file://{s}/secret.txt", .{dir_path});
    defer testing.allocator.free(file_url);

    const direct = try runZurlIn(sandbox.work, &.{ "-s", file_url });
    defer testing.allocator.free(direct.stdout);
    defer testing.allocator.free(direct.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, direct.term);
    try testing.expectEqualStrings(secret, direct.stdout);

    const redirect = try std.fmt.allocPrint(
        testing.allocator,
        "HTTP/1.1 302 Found\r\nLocation: {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        .{file_url},
    );
    defer testing.allocator.free(redirect);

    var server: test_server.TestServer = undefined;
    try server.start(&.{redirect});
    defer server.stop();

    const url = try loopbackUrlAt(&server, "/start");
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-s", "-S", "-L", "-o", "stolen.bin", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    // Exit 1 is `CURLE_UNSUPPORTED_PROTOCOL`, the number curl gives the
    // same refusal.
    try testing.expectEqual(std.process.Child.Term{ .exited = 1 }, result.term);
    // The contents reach neither stream.
    try testing.expect(std.mem.indexOf(u8, result.stdout, "SECRET-FILE-CONTENTS") == null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "SECRET-FILE-CONTENTS") == null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "UnsupportedProtocol") != null);
    // The sentence says which rule refused it. The name alone leaves a
    // user looking at the url they typed, which is not the cause, and the
    // cause is always that `--proto-redir` does not name the scheme.
    try testing.expect(std.mem.indexOf(u8, result.stderr, "--proto-redir does not name") != null);
    // And no file: `-o` is the shape that hands the contents back on
    // disk, so the working directory must hold nothing at all. The
    // sandbox root holds `secret.txt` and `work`, so only `work` is
    // checked here.
    var written = sandbox.work.iterate();
    try testing.expectEqual(@as(?std.Io.Dir.Entry, null), try written.next(testing.io));
}

test "--proto-redir narrows the redirect rule, and the file still never reaches the output" {
    // The same shape as the test above, driven by the flag instead of the
    // default. Several runs over one loopback server that answers
    // `location: file://.../secret.txt`:
    //
    // - `--proto-redir -all,http` refuses it, the way the default does.
    // - `--proto-redir +file` is the user asking for exactly that target,
    //   and zurl follows it and reads the file, which is what curl does.
    //   Four more spellings of the same request are checked beside it.
    // - `--proto -all,http` beside `--proto-redir +file` refuses it
    //   again: a target a server chose has to pass both lists.
    // - `--proto-redir -all` never starts, because the list leaves no
    //   protocol enabled.
    //
    // The control comes first: a refusal proves nothing when the fixture
    // cannot deliver the file anyway, so this reads the file directly and
    // gets the contents before any of the three runs.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const secret = "SECRET-FILE-CONTENTS\n";
    try sandbox.root.writeFile(testing.io, .{ .sub_path = "secret.txt", .data = secret });

    var path_storage: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir_path = path_storage[0..try sandbox.root.realPath(testing.io, &path_storage)];

    const file_url = try std.fmt.allocPrint(testing.allocator, "file://{s}/secret.txt", .{dir_path});
    defer testing.allocator.free(file_url);

    const direct = try runZurlIn(sandbox.work, &.{ "-s", file_url });
    defer testing.allocator.free(direct.stdout);
    defer testing.allocator.free(direct.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, direct.term);
    try testing.expectEqualStrings(secret, direct.stdout);

    const redirect = try std.fmt.allocPrint(
        testing.allocator,
        "HTTP/1.1 302 Found\r\nLocation: {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        .{file_url},
    );
    defer testing.allocator.free(redirect);

    {
        var server: test_server.TestServer = undefined;
        try server.start(&.{redirect});
        defer server.stop();
        const url = try loopbackUrlAt(&server, "/start");
        defer testing.allocator.free(url);

        const result = try runZurlIn(sandbox.work, &.{
            "-s", "-S", "-L", "--proto-redir", "-all,http", "-o", "stolen.bin", url,
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 1 }, result.term);
        try testing.expect(std.mem.indexOf(u8, result.stdout, "SECRET-FILE-CONTENTS") == null);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "SECRET-FILE-CONTENTS") == null);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "UnsupportedProtocol") != null);

        var written = sandbox.work.iterate();
        try testing.expectEqual(@as(?std.Io.Dir.Entry, null), try written.next(testing.io));
    }

    // **The opt-in, which the user has to write.** With `--proto-redir
    // +file` curl follows the redirect and prints the file, and zurl now
    // does the same. The engine stops the chain, hands the target back,
    // and `zurl.Client.perform` dispatches it to the `file` protocol.
    //
    // Every spelling that puts `file` in the set asks for this, and each
    // was measured against curl 8.21.0 over the same loopback server:
    // `+file`, `=file`, a bare `file`, `all`, and `+FILE`. All five read
    // the file for both programs.
    //
    // The test above is the other half, and neither half stands alone: a
    // build that followed every redirect would pass this one and fail
    // that one.
    for ([_][]const u8{ "+file", "=file", "file", "all", "+FILE" }) |list| {
        var server: test_server.TestServer = undefined;
        try server.start(&.{redirect});
        defer server.stop();
        const url = try loopbackUrlAt(&server, "/start");
        defer testing.allocator.free(url);

        const result = try runZurlIn(sandbox.work, &.{
            "-s", "-S", "-L", "--proto-redir", list, url,
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try testing.expectEqualStrings(secret, result.stdout);
    }

    // And `-w %{url_effective}` names the file, not the url that
    // redirected, because the transfer really ended there.
    {
        var server: test_server.TestServer = undefined;
        try server.start(&.{redirect});
        defer server.stop();
        const url = try loopbackUrlAt(&server, "/start");
        defer testing.allocator.free(url);

        const result = try runZurlIn(sandbox.work, &.{
            "-s", "-S",               "-L", "--proto-redir", "+file", "-o", "/dev/null",
            "-w", "%{url_effective}", url,
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try testing.expectEqualStrings(file_url, result.stdout);
    }

    // **`--proto` narrows the same redirect.** A target a server chose has
    // to pass both lists. curl refuses this pair with
    // `Protocol "file" is disabled (in redirect)` and exit 1, measured,
    // and accepts it once `--proto` names `file` as well.
    {
        var server: test_server.TestServer = undefined;
        try server.start(&.{redirect});
        defer server.stop();
        const url = try loopbackUrlAt(&server, "/start");
        defer testing.allocator.free(url);

        const result = try runZurlIn(sandbox.work, &.{
            "-s", "-S", "-L", "--proto", "-all,http", "--proto-redir", "+file", "-o", "stolen.bin", url,
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 1 }, result.term);
        try testing.expect(std.mem.indexOf(u8, result.stdout, "SECRET-FILE-CONTENTS") == null);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "SECRET-FILE-CONTENTS") == null);

        var written = sandbox.work.iterate();
        try testing.expectEqual(@as(?std.Io.Dir.Entry, null), try written.next(testing.io));
    }
    {
        var server: test_server.TestServer = undefined;
        try server.start(&.{redirect});
        defer server.stop();
        const url = try loopbackUrlAt(&server, "/start");
        defer testing.allocator.free(url);

        const result = try runZurlIn(sandbox.work, &.{
            "-s", "-S", "-L", "--proto", "-all,http,file", "--proto-redir", "+file", url,
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try testing.expectEqualStrings(secret, result.stdout);
    }

    // A list that leaves nothing enabled is a usage fault, and the run
    // exits before it opens a socket at all. curl answers the same list
    // with exit 2 and `option --proto-redir: is badly used here`.
    {
        const result = try runZurlIn(sandbox.work, &.{
            "-s", "-S", "-L", "--proto-redir", "-all", "http://127.0.0.1:1/start",
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 2 }, result.term);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "--proto-redir") != null);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "no protocol enabled") != null);
    }
}

test "--proto refuses a scheme, and the transfer never opens anything" {
    // `--proto` is read before the dispatch table, so a url the user
    // turned off never reaches a protocol that could open it. curl 8.21.0
    // answers the same shape with exit 1 and `Protocol "file" is
    // disabled`, and exit 1 is `CURLE_UNSUPPORTED_PROTOCOL` for both.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const secret = "SECRET-FILE-CONTENTS\n";
    try sandbox.root.writeFile(testing.io, .{ .sub_path = "secret.txt", .data = secret });

    var path_storage: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir_path = path_storage[0..try sandbox.root.realPath(testing.io, &path_storage)];
    const file_url = try std.fmt.allocPrint(testing.allocator, "file://{s}/secret.txt", .{dir_path});
    defer testing.allocator.free(file_url);

    // The control first: with no `--proto` the url reads the file.
    const permitted = try runZurlIn(sandbox.work, &.{ "-s", file_url });
    defer testing.allocator.free(permitted.stdout);
    defer testing.allocator.free(permitted.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, permitted.term);
    try testing.expectEqualStrings(secret, permitted.stdout);

    // And with the flag, the same url fails and prints nothing of it.
    const refused = try runZurlIn(sandbox.work, &.{ "-s", "-S", "--proto", "-all,http", file_url });
    defer testing.allocator.free(refused.stdout);
    defer testing.allocator.free(refused.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 1 }, refused.term);
    try testing.expectEqualStrings("", refused.stdout);
    try testing.expect(std.mem.indexOf(u8, refused.stderr, "SECRET-FILE-CONTENTS") == null);
    try testing.expect(std.mem.indexOf(u8, refused.stderr, "UnsupportedProtocol") != null);

    // A list that leaves nothing enabled exits 2 before any transfer.
    const empty = try runZurlIn(sandbox.work, &.{ "-s", "-S", "--proto", "-all", file_url });
    defer testing.allocator.free(empty.stdout);
    defer testing.allocator.free(empty.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 2 }, empty.term);
    try testing.expect(std.mem.indexOf(u8, empty.stderr, "no protocol enabled") != null);
}

test "every --tlsv1.x flag is accepted by the binary, and a bad list is not" {
    // A script that curl runs must not stop at zurl's argument parser.
    // These four flags do not need a server to prove they parse: a url
    // that cannot connect reaches exit 7, and a flag that was refused
    // would reach exit 2 instead.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const port = try closedPort();
    const url = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/x", .{port});
    defer testing.allocator.free(url);

    for ([_][]const u8{ "-1", "--tlsv1", "--tlsv1.0", "--tlsv1.1", "--tlsv1.2", "--tlsv1.3" }) |flag| {
        const result = try runZurlIn(sandbox.work, &.{ "-s", "-S", flag, "--connect-timeout", "2", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 7 }, result.term);
    }
}

test "every --tls-max value is accepted by the binary, and a bad one is not" {
    // curl takes five values here, and a script that names any of them
    // must not stop at zurl's argument parser. A url that cannot connect
    // reaches exit 7, and a value that was refused reaches exit 2.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const port = try closedPort();
    const url = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/x", .{port});
    defer testing.allocator.free(url);

    for ([_][]const u8{ "1.0", "1.1", "1.2", "1.3", "default" }) |value| {
        const result = try runZurlIn(sandbox.work, &.{
            "-s", "-S", "--tls-max", value, "--connect-timeout", "2", url,
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 7 }, result.term);
    }

    // curl answers each of these with exit 2 and
    // `option --tls-max: is badly used here`. Measured.
    for ([_][]const u8{ "1.4", "", "1" }) |value| {
        const result = try runZurlIn(sandbox.work, &.{ "-s", "-S", "--tls-max", value, url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 2 }, result.term);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "--tls-max") != null);
    }

    // A `--tlsv1.x` above the ceiling never opens a socket. curl reports
    // the same pair while it parses, exits 2, and names whichever of the
    // two flags came last. Measured in both orders.
    {
        const result = try runZurlIn(sandbox.work, &.{
            "-s", "-S", "--tls-max", "1.2", "--tlsv1.3", url,
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 2 }, result.term);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "--tlsv1.3") != null);
    }
    {
        const result = try runZurlIn(sandbox.work, &.{
            "-s", "-S", "--tlsv1.3", "--tls-max", "1.2", url,
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 2 }, result.term);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "--tls-max") != null);
    }
    // And `--tls-max 1.0 --tlsv1.0` is **not** that pair: curl runs it and
    // fails at the handshake with 35, so zurl must reach the transfer too.
    {
        const result = try runZurlIn(sandbox.work, &.{
            "-s", "-S", "--tls-max", "1.0", "--tlsv1.0", "--connect-timeout", "2", url,
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 7 }, result.term);
    }
}

test "a --tls-max below the floor fails the TLS connection and names the conflict" {
    // The rule the flag must never break: a ceiling under the floor is a
    // named failure, and never a quiet success on a version the user
    // excluded. curl 8.21.0 fails the same flag with 35, because its
    // OpenSSL refuses TLS 1.0 and TLS 1.1 at its default security level.
    //
    // The fixture is the loopback HTTP server. It answers a TLS client
    // hello with plain text, so a run with no flag also fails, and that
    // is the control: only the flagged run names the floor.
    var server: test_server.TestServer = undefined;
    try server.start(&.{ ok("never read"), ok("never read") });
    defer server.stop();

    const url = try std.fmt.allocPrint(testing.allocator, "https://127.0.0.1:{d}/x", .{server.port()});
    defer testing.allocator.free(url);

    for ([_][]const u8{ "1.0", "1.1" }) |value| {
        const result = try runZurl(&.{ "-s", "-S", "--tls-max", value, url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        // 35 is `CURLE_SSL_CONNECT_ERROR`, the code curl gives the same
        // command line.
        try testing.expectEqual(std.process.Child.Term{ .exited = 35 }, result.term);
        try testing.expectEqualStrings("", result.stdout);
        // The sentence says which rule refused it. A bare 35 leaves the
        // user looking at the server.
        try testing.expect(std.mem.indexOf(u8, result.stderr, "--tls-max") != null);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "TLS 1.2 floor") != null);
    }

    // The control: with no ceiling the same server still fails, and for
    // another reason, so the sentence above is the flag's own and not the
    // fixture's.
    {
        const result = try runZurl(&.{ "-s", "-S", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expect(!std.meta.eql(std.process.Child.Term{ .exited = 0 }, result.term));
        try testing.expect(std.mem.indexOf(u8, result.stderr, "TLS 1.2 floor") == null);
    }
}

test "--proto-default names the scheme of a url that carries none" {
    // Three runs prove the flag really changes the scheme, and not just
    // the text of a message.
    //
    // - A schemeless loopback url runs as `http` with no flag, which is
    //   the guess zurl already made.
    // - The same url with `--proto-default https` fails at the TLS
    //   handshake, because the fixture speaks no TLS. Only a real change
    //   of scheme can do that.
    // - An absolute path with `--proto-default file` reads the file, and
    //   the same path with no flag is `InvalidUrl`. curl matches every
    //   row: measured, `curl --proto-default file /etc/hostname` prints
    //   the file and `curl /etc/hostname` exits 3.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const secret = "PROTO-DEFAULT-FILE-CONTENTS\n";
    try sandbox.root.writeFile(testing.io, .{ .sub_path = "d.txt", .data = secret });
    var path_storage: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir_path = path_storage[0..try sandbox.root.realPath(testing.io, &path_storage)];
    const file_path = try std.fmt.allocPrint(testing.allocator, "{s}/d.txt", .{dir_path});
    defer testing.allocator.free(file_path);

    {
        var server: test_server.TestServer = undefined;
        try server.start(&.{ok("plain http")});
        defer server.stop();
        const bare = try std.fmt.allocPrint(testing.allocator, "127.0.0.1:{d}/x", .{server.port()});
        defer testing.allocator.free(bare);

        const result = try runZurlIn(sandbox.work, &.{ "-s", "-S", bare });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try testing.expectEqualStrings("plain http", result.stdout);
    }
    {
        var server: test_server.TestServer = undefined;
        try server.start(&.{ok("plain http")});
        defer server.stop();
        const bare = try std.fmt.allocPrint(testing.allocator, "127.0.0.1:{d}/x", .{server.port()});
        defer testing.allocator.free(bare);

        const result = try runZurlIn(sandbox.work, &.{ "-s", "-S", "--proto-default", "https", bare });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        // 35 is `CURLE_SSL_CONNECT_ERROR`: the transfer really tried to
        // speak TLS to a server that speaks none.
        try testing.expectEqual(std.process.Child.Term{ .exited = 35 }, result.term);
        try testing.expectEqualStrings("", result.stdout);
    }
    {
        const result = try runZurlIn(sandbox.work, &.{ "-s", "-S", "--proto-default", "file", file_path });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try testing.expectEqualStrings(secret, result.stdout);
    }
    {
        const result = try runZurlIn(sandbox.work, &.{ "-s", "-S", file_path });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 3 }, result.term);
        try testing.expectEqualStrings("", result.stdout);
    }
}

test "a --proto-default name nobody knows exits 1, and --proto still narrows the scheme it names" {
    // Two exit codes, both curl's own. An unknown name is exit 1 and
    // `a specified protocol is unsupported by libcurl`, checked before
    // any transfer even when every url spells its own scheme. An empty
    // name is exit 2. Measured against curl 8.21.0.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    {
        const result = try runZurlIn(sandbox.work, &.{
            "-s", "-S", "--proto-default", "nosuchproto", "http://127.0.0.1:1/x",
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 1 }, result.term);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "--proto-default") != null);
    }
    {
        const result = try runZurlIn(sandbox.work, &.{
            "-s", "-S", "--proto-default", "", "http://127.0.0.1:1/x",
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 2 }, result.term);
    }
    // `--proto-default https` beside a `--proto` list with no https: the
    // flag picks the scheme and the list then refuses it. curl answers
    // exit 1 and `Protocol "https" is disabled`. Measured.
    {
        const result = try runZurlIn(sandbox.work, &.{
            "-s", "-S", "--proto-default", "https", "--proto", "-all,http", "127.0.0.1:1/x",
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 1 }, result.term);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "UnsupportedProtocol") != null);
    }
    // And with a list that names https the same url reaches the connect
    // instead, which is exit 7.
    {
        const port = try closedPort();
        const bare = try std.fmt.allocPrint(testing.allocator, "127.0.0.1:{d}/x", .{port});
        defer testing.allocator.free(bare);
        const result = try runZurlIn(sandbox.work, &.{
            "-s",                "-S", "--proto-default", "https", "--proto", "-all,https",
            "--connect-timeout", "2",  bare,
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 7 }, result.term);
    }
}

test "an IPv6 literal url works from the command line, and every report of it keeps the brackets" {
    // The product, over `::1`, which is loopback and reaches no network.
    //
    // `http://[::1]:PORT/` exited 3 with `InvalidUrl` before this: the
    // dial ran the host through a name check that refuses every colon.
    //
    // The three readers of a url text are checked together, because the
    // engine holds the host with no brackets and each one has to put them
    // back on its own: the `host:` line the peer receives, the
    // `%{url_effective}` a script reads, and the failure message.
    var server: test_server.TestServer = undefined;
    server.startOn("::1", &.{
        "HTTP/1.1 302 Found\r\nLocation: /second\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ok("arrived"),
    }) catch |err| switch (err) {
        // A machine with the IPv6 stack turned off cannot bind `::1`.
        error.AddressFamilyUnsupported, error.AddressUnavailable => return error.SkipZigTest,
        else => |e| return e,
    };
    defer server.stop();

    const url = try std.fmt.allocPrint(testing.allocator, "http://[::1]:{d}/first", .{server.port()});
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-L", "-w", "[%{url_effective}]", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    const want_url = try std.fmt.allocPrint(testing.allocator, "arrived[http://[::1]:{d}/second]", .{server.port()});
    defer testing.allocator.free(want_url);
    try testing.expectEqualStrings(want_url, result.stdout);

    // The bytes on the wire, and not the parsed value. The parsed host
    // carries no brackets at all, so only the head the peer received can
    // say whether the engine put them back.
    const want_host = try std.fmt.allocPrint(testing.allocator, "host: [::1]:{d}\r\n", .{server.port()});
    defer testing.allocator.free(want_host);
    for (0..2) |hop| {
        try testing.expect(std.mem.indexOf(u8, server.requestHead(hop).?, want_host) != null);
    }
}

test "-O over an IPv6 literal takes its name from the path and never from the host" {
    // The `-O` name comes from the last path segment. The host is not part
    // of it, so an address changes nothing here, and a build that read the
    // host would write a file named after an address full of colons.
    var server: test_server.TestServer = undefined;
    server.startOn("::1", &.{ok("payload")}) catch |err| switch (err) {
        error.AddressFamilyUnsupported, error.AddressUnavailable => return error.SkipZigTest,
        else => |e| return e,
    };
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try std.fmt.allocPrint(testing.allocator, "http://[::1]:{d}/dir/a.bin", .{server.port()});
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-O", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    const written = try sandbox.work.readFileAlloc(testing.io, "a.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(written);
    try testing.expectEqualStrings("payload", written);
}

test "a failure message for an IPv6 literal names the address and leaks no password" {
    // The message reads the host, not the authority, so it carries no
    // brackets. curl 8.21.0 writes `Failed to connect to ::1:9`, which is
    // the same bare address. `Diagnostics.record` masks the password of
    // every url it stores, and an address changes nothing about that rule.
    // A port on `::1` that nothing listens on, held for the life of this
    // process, so a connect to it is refused with no live server
    // anywhere. `closedPort` takes the host because the IPv4 helper
    // cannot stand in: a port that is free on 127.0.0.1 says nothing
    // about `::1`.
    const port = test_server.closedPort("::1") catch |err| switch (err) {
        error.AddressFamilyUnsupported, error.AddressUnavailable => return error.SkipZigTest,
        else => |e| return e,
    };

    const url = try std.fmt.allocPrint(testing.allocator, "http://bob:hunter2@[::1]:{d}/x", .{port});
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-S", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    // 7 is `CURLE_COULDNT_CONNECT`. Nothing listens on that port.
    try testing.expectEqual(std.process.Child.Term{ .exited = 7 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "::1") != null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "hunter2") == null);
}

test "-d sends a body the shipped binary really wrote, and -G moves it to the query" {
    // The seam this file exists for: `Args` chose the method, `body.zig`
    // built the bytes, and the engine framed them. Only a run of the real
    // binary proves all three agree.
    //
    // Both rows measured against curl 8.21.0 on a loopback listener:
    // `-d 'a=1&b=2'` sends `POST /x` with `Content-Length: 7`, and
    // `-d 'a=1' -G` sends `GET /x?a=1` with no framing header at all.
    var server: test_server.TestServer = undefined;
    try server.start(&.{ ok("one"), ok("two") });
    defer server.stop();

    const url = try loopbackUrlAt(&server, "/x");
    defer testing.allocator.free(url);

    const post = try runZurl(&.{ "-s", "-d", "a=1&b=2", url });
    defer testing.allocator.free(post.stdout);
    defer testing.allocator.free(post.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, post.term);

    const post_head = server.requestHead(0).?;
    try testing.expect(std.mem.startsWith(u8, post_head, "POST /x HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, post_head, "content-length: 7\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, post_head, "content-type: application/x-www-form-urlencoded\r\n") != null);
    try testing.expectEqualStrings("a=1&b=2", server.requestBody(0).?);

    const get = try runZurl(&.{ "-s", "-d", "a=1", "-G", url });
    defer testing.allocator.free(get.stdout);
    defer testing.allocator.free(get.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, get.term);

    const get_head = server.requestHead(1).?;
    try testing.expect(std.mem.startsWith(u8, get_head, "GET /x?a=1 HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, get_head, "content-length") == null);
    try testing.expect(std.mem.indexOf(u8, get_head, "content-type") == null);
    try testing.expectEqualStrings("", server.requestBody(1).?);
}

test "-T uploads a file the binary opened, and -I writes the head to standard output" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{ ok("one"), ok("two") });
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();
    try sandbox.work.writeFile(testing.io, .{ .sub_path = "up.txt", .data = "hello world\n" });

    const url = try loopbackUrlAt(&server, "/x");
    defer testing.allocator.free(url);

    const upload = try runZurlIn(sandbox.work, &.{ "-s", "-T", "up.txt", url });
    defer testing.allocator.free(upload.stdout);
    defer testing.allocator.free(upload.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, upload.term);

    const upload_head = server.requestHead(0).?;
    try testing.expect(std.mem.startsWith(u8, upload_head, "PUT /x HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, upload_head, "content-length: 12\r\n") != null);
    // Measured: `curl -T file URL` sends no `Content-Type` at all.
    try testing.expect(std.mem.indexOf(u8, upload_head, "content-type") == null);
    try testing.expectEqualStrings("hello world\n", server.requestBody(0).?);

    // `-I` asks for the head alone and prints it, which is what curl does.
    // Measured: the bytes on standard output are the response head, CRLF
    // endings and the blank line included, and nothing else.
    const head = try runZurl(&.{ "-s", "-I", url });
    defer testing.allocator.free(head.stdout);
    defer testing.allocator.free(head.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, head.term);
    try testing.expect(std.mem.startsWith(u8, head.stdout, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.endsWith(u8, head.stdout, "\r\n\r\n"));
    // The body of the response never reaches standard output.
    try testing.expect(std.mem.indexOf(u8, head.stdout, "two") == null);
    try testing.expect(std.mem.startsWith(u8, server.requestHead(1).?, "HEAD /x HTTP/1.1\r\n"));
}

test "a 302 drops the body and a 307 keeps it, through the shipped binary" {
    // The rule that keeps a body out of a place it does not belong. Both
    // rows measured against curl 8.21.0 with `-L -d 'a=1&b=2'`.
    const moved = "HTTP/1.1 302 Found\r\nLocation: /moved\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    const kept = "HTTP/1.1 307 Temporary Redirect\r\nLocation: /moved\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

    {
        var server: test_server.TestServer = undefined;
        try server.start(&.{ moved, ok("done") });
        defer server.stop();

        const url = try loopbackUrlAt(&server, "/x");
        defer testing.allocator.free(url);

        const result = try runZurl(&.{ "-s", "-L", "-d", "a=1&b=2", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

        const second = server.requestHead(1).?;
        try testing.expect(std.mem.startsWith(u8, second, "GET /moved HTTP/1.1\r\n"));
        try testing.expect(std.mem.indexOf(u8, second, "content-length") == null);
        try testing.expect(std.mem.indexOf(u8, second, "content-type") == null);
        try testing.expectEqualStrings("", server.requestBody(1).?);
    }

    {
        var server: test_server.TestServer = undefined;
        try server.start(&.{ kept, ok("done") });
        defer server.stop();

        const url = try loopbackUrlAt(&server, "/x");
        defer testing.allocator.free(url);

        const result = try runZurl(&.{ "-s", "-L", "-d", "a=1&b=2", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

        const second = server.requestHead(1).?;
        try testing.expect(std.mem.startsWith(u8, second, "POST /moved HTTP/1.1\r\n"));
        try testing.expect(std.mem.indexOf(u8, second, "content-length: 7\r\n") != null);
        try testing.expectEqualStrings("a=1&b=2", server.requestBody(1).?);
    }
}

test "-m stops a transfer that the peer never answers, and reports curl's own code" {
    // **The whole point of `-m` on a flaky link.** The listener accepts
    // and answers nothing, so the connect works and the read after it
    // never returns. A bound checked between reads could not end this;
    // only the race inside `boundedTransfer` can.
    //
    // Nothing accepts on this socket, so the client's connect is taken by
    // the backlog and no task is needed on this side. The test therefore
    // runs in a build with no concurrency too, where the binary itself
    // says it cannot enforce the bound.
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try address.listen(testing.io, .{ .reuse_address = true });
    defer listener.deinit(testing.io);

    const url = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.1:{d}/never",
        .{listener.socket.address.ip4.port},
    );
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-m", "1", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    // `CURLE_OPERATION_TIMEDOUT` is 28, and curl 8.21.0 answers the same
    // shape with the same number, measured.
    if (std.mem.indexOf(u8, result.stderr, "the time limit was not enforced") != null) {
        // This build could not start a second task. It said so, which is
        // the contract, and there is no bound left to assert on.
        return;
    }
    try testing.expectEqual(std.process.Child.Term{ .exited = 28 }, result.term);
    try testing.expectEqualStrings("", result.stdout);
    // One message, and it names the bound rather than whatever call the
    // cancel happened to land on.
    try testing.expect(std.mem.indexOf(u8, result.stderr, "-m limit") != null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "(28)") != null);
}

test "-m 0 asks for no bound, and a transfer inside its bound keeps its own answer" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{ ok("payload"), ok("payload") });
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    // A bound that no transfer on loopback can reach. This is a floor,
    // not an upper bound on time: the assertion is the exit code and the
    // body, never how long the run took.
    const bounded = try runZurl(&.{ "-s", "-m", "600", url });
    defer testing.allocator.free(bounded.stdout);
    defer testing.allocator.free(bounded.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, bounded.term);
    try testing.expectEqualStrings("payload", bounded.stdout);

    // Measured: `curl --max-time 0` waits for as long as the peer does.
    const unbounded = try runZurl(&.{ "-s", "-m", "0", url });
    defer testing.allocator.free(unbounded.stdout);
    defer testing.allocator.free(unbounded.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, unbounded.term);
    try testing.expectEqualStrings("payload", unbounded.stdout);
}

test "--create-dirs makes the tree an -o path names, and without it the url fails" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{ ok("payload"), ok("payload") });
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const made = try runZurlIn(sandbox.work, &.{ "-s", "--create-dirs", "-o", "a/b/c.txt", url });
    defer testing.allocator.free(made.stdout);
    defer testing.allocator.free(made.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, made.term);

    const written = try sandbox.work.readFileAlloc(testing.io, "a/b/c.txt", testing.allocator, .limited(64));
    defer testing.allocator.free(written);
    try testing.expectEqualStrings("payload", written);

    // Without the flag the directory is not created, and curl 8.21.0
    // answers the same shape with 23, `CURLE_WRITE_ERROR`.
    const missing = try runZurlIn(sandbox.work, &.{ "-s", "-o", "d/e/f.txt", url });
    defer testing.allocator.free(missing.stdout);
    defer testing.allocator.free(missing.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 23 }, missing.term);
}

test "--no-clobber keeps the file that is there and writes the next name in the series" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{ ok("fresh"), ok("fresh") });
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    try sandbox.work.writeFile(testing.io, .{ .sub_path = "body.bin", .data = "original" });

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const first = try runZurlIn(sandbox.work, &.{ "-s", "--no-clobber", "-o", "body.bin", url });
    defer testing.allocator.free(first.stdout);
    defer testing.allocator.free(first.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, first.term);

    const second = try runZurlIn(sandbox.work, &.{ "-s", "--no-clobber", "-o", "body.bin", url });
    defer testing.allocator.free(second.stdout);
    defer testing.allocator.free(second.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, second.term);

    // Measured against curl 8.21.0: three runs onto one existing name
    // leave the name untouched and write `.1`, `.2`, and `.3`.
    const kept = try sandbox.work.readFileAlloc(testing.io, "body.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(kept);
    try testing.expectEqualStrings("original", kept);

    const one = try sandbox.work.readFileAlloc(testing.io, "body.bin.1", testing.allocator, .limited(64));
    defer testing.allocator.free(one);
    try testing.expectEqualStrings("fresh", one);

    const two = try sandbox.work.readFileAlloc(testing.io, "body.bin.2", testing.allocator, .limited(64));
    defer testing.allocator.free(two);
    try testing.expectEqualStrings("fresh", two);
}

test "-O refuses a symbolic link at the destination, and -o still writes through one" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{ ok("PWNED"), ok("PWNED") });
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    try sandbox.work.writeFile(testing.io, .{ .sub_path = "victim.txt", .data = "VICTIM" });
    sandbox.work.symLink(testing.io, "victim.txt", "tgt.bin", .{}) catch |err| switch (err) {
        // A platform that needs a privilege to make a symbolic link has
        // nothing this rule can be shown on.
        error.AccessDenied, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };

    const url = try loopbackUrlAt(&server, "/tgt.bin");
    defer testing.allocator.free(url);

    // **`-O` takes its name from the url, which is attacker-chosen.** A
    // link already at that name would send the body to a file no part of
    // the command line named. Measured against curl 8.21.0 on this exact
    // shape: curl exits 0 and `victim.txt` becomes the body. zurl refuses.
    const remote = try runZurlIn(sandbox.work, &.{ "-s", "-S", "-O", url });
    defer testing.allocator.free(remote.stdout);
    defer testing.allocator.free(remote.stderr);
    // `CURLE_WRITE_ERROR` is 23, the code every other refusal to write a
    // `-O` name earns.
    try testing.expectEqual(std.process.Child.Term{ .exited = 23 }, remote.term);

    const kept = try sandbox.work.readFileAlloc(testing.io, "victim.txt", testing.allocator, .limited(64));
    defer testing.allocator.free(kept);
    try testing.expectEqualStrings("VICTIM", kept);

    // **`-o` keeps curl's answer, because the user typed the path.**
    // `-o /dev/stdout` is a symbolic link on Linux and a script that names
    // it must keep working.
    const typed = try runZurlIn(sandbox.work, &.{ "-s", "-o", "tgt.bin", url });
    defer testing.allocator.free(typed.stdout);
    defer testing.allocator.free(typed.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, typed.term);

    const followed = try sandbox.work.readFileAlloc(testing.io, "victim.txt", testing.allocator, .limited(64));
    defer testing.allocator.free(followed);
    try testing.expectEqualStrings("PWNED", followed);
}

test "a response header with a NUL in it ends the transfer with curl's own exit 8" {
    // Measured against curl 8.21.0 with a loopback server answering this
    // exact head: `curl: (8) Nul byte in header`, exit 8, no body written,
    // and an `--etag-save` file left empty. 8 is
    // `CURLE_WEIRD_SERVER_REPLY`.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nETag: \"a\x00b\"\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
    });
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-s", "-S", "-o", "body.bin", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 8 }, result.term);
    try testing.expectEqualStrings("", result.stdout);
    // The octet is stopped before any consumer of a header value reads it,
    // so nothing at all was written.
    try sandbox.expectNothingWritten();
}

test "--fail-with-body writes the error body and still exits 22, where -f writes nothing" {
    const failing = "HTTP/1.1 404 Not Found\r\nContent-Length: 8\r\nConnection: close\r\n\r\nFAILBODY";

    var server: test_server.TestServer = undefined;
    try server.start(&.{ failing, failing });
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const with_body = try runZurlIn(sandbox.work, &.{ "-s", "--fail-with-body", "-o", "err.txt", url });
    defer testing.allocator.free(with_body.stdout);
    defer testing.allocator.free(with_body.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 22 }, with_body.term);

    const body = try sandbox.work.readFileAlloc(testing.io, "err.txt", testing.allocator, .limited(64));
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("FAILBODY", body);

    // `-f` earns the same 22 and creates no file at all, which is the
    // whole difference between the two flags. Measured against curl.
    const plain = try runZurlIn(sandbox.work, &.{ "-s", "-f", "-o", "gone.txt", url });
    defer testing.allocator.free(plain.stdout);
    defer testing.allocator.free(plain.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 22 }, plain.term);
    try testing.expectError(
        error.FileNotFound,
        sandbox.work.readFileAlloc(testing.io, "gone.txt", testing.allocator, .limited(64)),
    );
}

test "--fail-early stops after the first url that failed, and without it every url runs" {
    const failing = "HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\nConnection: close\r\n\r\ngone";

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    {
        var server: test_server.TestServer = undefined;
        try server.start(&.{ failing, ok("second") });
        defer server.stop();

        const url = try loopbackUrl(&server);
        defer testing.allocator.free(url);

        const stopped = try runZurlIn(sandbox.work, &.{
            "-s", "-f", "--fail-early", "-o", "a.txt", "-o", "b.txt", url, url,
        });
        defer testing.allocator.free(stopped.stdout);
        defer testing.allocator.free(stopped.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 22 }, stopped.term);
        // The second url never ran, so the server saw one request and the
        // second destination was never created.
        try testing.expectEqual(@as(usize, 1), server.accepts());
        try testing.expectError(
            error.FileNotFound,
            sandbox.work.readFileAlloc(testing.io, "b.txt", testing.allocator, .limited(64)),
        );
    }

    {
        var server: test_server.TestServer = undefined;
        try server.start(&.{ failing, ok("second") });
        defer server.stop();

        const url = try loopbackUrl(&server);
        defer testing.allocator.free(url);

        const both = try runZurlIn(sandbox.work, &.{
            "-s", "-f", "-o", "c.txt", "-o", "d.txt", url, url,
        });
        defer testing.allocator.free(both.stdout);
        defer testing.allocator.free(both.stderr);

        try testing.expectEqual(@as(usize, 2), server.accepts());
        const written = try sandbox.work.readFileAlloc(testing.io, "d.txt", testing.allocator, .limited(64));
        defer testing.allocator.free(written);
        try testing.expectEqualStrings("second", written);
    }
}

test "-C - asks for the rest of a file it already holds, and a peer that ignores the range fails" {
    const partial = "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 5-9/10\r\n" ++
        "Content-Length: 5\r\nConnection: close\r\n\r\n56789";

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    {
        var server: test_server.TestServer = undefined;
        try server.start(&.{partial});
        defer server.stop();

        try sandbox.work.writeFile(testing.io, .{ .sub_path = "part.bin", .data = "01234" });

        const url = try loopbackUrl(&server);
        defer testing.allocator.free(url);

        const result = try runZurlIn(sandbox.work, &.{ "-s", "-C", "-", "-o", "part.bin", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

        // The header on the wire, which is what curl sends for the same
        // file: measured, `Range: bytes=5-`.
        try testing.expectEqual(@as(usize, 1), test_server.countHeaders(server.requestHead(0).?, "range"));
        try testing.expect(std.mem.indexOf(u8, server.requestHead(0).?, "bytes=5-\r\n") != null);

        const whole = try sandbox.work.readFileAlloc(testing.io, "part.bin", testing.allocator, .limited(64));
        defer testing.allocator.free(whole);
        try testing.expectEqualStrings("0123456789", whole);
    }

    {
        var server: test_server.TestServer = undefined;
        try server.start(&.{ok("0123456789")});
        defer server.stop();

        try sandbox.work.writeFile(testing.io, .{ .sub_path = "ignored.bin", .data = "01234" });

        const url = try loopbackUrl(&server);
        defer testing.allocator.free(url);

        const result = try runZurlIn(sandbox.work, &.{ "-s", "-C", "-", "-o", "ignored.bin", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        // `CURLE_RANGE_ERROR` is 33, and the file keeps what it held.
        // Measured against curl 8.21.0 with a server that answers 200 to
        // a `Range` request.
        try testing.expectEqual(std.process.Child.Term{ .exited = 33 }, result.term);
        const kept = try sandbox.work.readFileAlloc(testing.io, "ignored.bin", testing.allocator, .limited(64));
        defer testing.allocator.free(kept);
        try testing.expectEqualStrings("01234", kept);
    }
}

test "-C - refuses a 206 whose Content-Range is not the range that was asked for" {
    // **The exit code is half of what this measures. The other half is
    // that the file did not change.**
    //
    // `-C` seeks to the local size and writes the body there, so a body
    // that is not the bytes from that position leaves a file that is
    // neither the old content nor the new one. Nothing later can find that
    // damage, so each shape here asserts the five bytes the file held are
    // the five bytes it still holds.
    //
    // Measured against curl 8.21.0 with a loopback server and a local file
    // of five bytes. curl refuses the first two shapes with exit 33 and
    // takes the other three, and on all three of those it appends ten
    // bytes to the file. This build refuses all five.
    const Shape = struct {
        /// The destination, which also names the shape under test.
        name: []const u8,
        /// The `Content-Range` line, or an empty string for a head that
        /// carries none.
        range: []const u8,
    };
    const refused = [_]Shape{
        .{ .name = "no-range.bin", .range = "" },
        .{ .name = "wrong-start.bin", .range = "Content-Range: bytes 0-9/10\r\n" },
        .{ .name = "malformed.bin", .range = "Content-Range: bytes garbage\r\n" },
        .{ .name = "not-bytes.bin", .range = "Content-Range: items 5-9/10\r\n" },
        .{ .name = "no-first.bin", .range = "Content-Range: bytes */10\r\n" },
    };

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    for (refused) |shape| {
        const answer = try std.fmt.allocPrint(
            testing.allocator,
            "HTTP/1.1 206 Partial Content\r\n{s}Content-Length: 10\r\nConnection: close\r\n\r\n0123456789",
            .{shape.range},
        );
        defer testing.allocator.free(answer);

        var server: test_server.TestServer = undefined;
        try server.start(&.{answer});
        defer server.stop();

        try sandbox.work.writeFile(testing.io, .{ .sub_path = shape.name, .data = "AAAAA" });

        const url = try loopbackUrl(&server);
        defer testing.allocator.free(url);

        const result = try runZurlIn(sandbox.work, &.{ "-s", "-C", "-", "-o", shape.name, url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        // `CURLE_RANGE_ERROR` is 33, the same code the `200` case earns.
        try testing.expectEqual(std.process.Child.Term{ .exited = 33 }, result.term);

        const kept = try sandbox.work.readFileAlloc(testing.io, shape.name, testing.allocator, .limited(64));
        defer testing.allocator.free(kept);
        // Byte for byte. A file that grew by even one byte is the fault.
        try testing.expectEqualStrings("AAAAA", kept);
    }
}

test "-C - resumes on a correct 206 and writes nothing at all on a 416" {
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    {
        // The control for the test above: the same offset, a
        // `Content-Range` that names it, and the body lands. Without this
        // a refusal of every answer would pass every other assertion.
        const correct = "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 5-9/10\r\n" ++
            "Content-Length: 5\r\nConnection: close\r\n\r\n56789";

        var server: test_server.TestServer = undefined;
        try server.start(&.{correct});
        defer server.stop();

        try sandbox.work.writeFile(testing.io, .{ .sub_path = "good.bin", .data = "AAAAA" });

        const url = try loopbackUrl(&server);
        defer testing.allocator.free(url);

        const result = try runZurlIn(sandbox.work, &.{ "-s", "-C", "-", "-o", "good.bin", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

        const whole = try sandbox.work.readFileAlloc(testing.io, "good.bin", testing.allocator, .limited(64));
        defer testing.allocator.free(whole);
        try testing.expectEqualStrings("AAAAA56789", whole);
    }

    {
        // **`416` is the answer to a file that is already whole, and it
        // carries a body of the server's own choosing.** That body is not
        // a part of the entity, so none of it reaches the file. Measured
        // against curl 8.21.0: exit 0 and the file untouched, though curl
        // with `-i` does append the head to it and this build appends
        // nothing.
        const refused = "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */5\r\n" ++
            "Content-Length: 10\r\nConnection: close\r\n\r\nXXXXXXXXXX";

        var server: test_server.TestServer = undefined;
        try server.start(&.{refused});
        defer server.stop();

        try sandbox.work.writeFile(testing.io, .{ .sub_path = "whole.bin", .data = "AAAAA" });

        const url = try loopbackUrl(&server);
        defer testing.allocator.free(url);

        const result = try runZurlIn(sandbox.work, &.{ "-C", "-", "-o", "whole.bin", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

        const kept = try sandbox.work.readFileAlloc(testing.io, "whole.bin", testing.allocator, .limited(64));
        defer testing.allocator.free(kept);
        try testing.expectEqualStrings("AAAAA", kept);

        // Recovery is never silent: a run that wrote nothing and exited 0
        // says why on standard error.
        try testing.expect(std.mem.indexOf(u8, result.stderr, "no bytes past 5") != null);
    }
}

test "-C - with no such file asks for the whole body and sends no range header" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{ok("0123456789")});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-s", "-C", "-", "-o", "fresh.bin", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    // Measured: curl sends no `Range` at all for a file it cannot
    // measure, and asks for the whole body.
    try testing.expectEqual(@as(usize, 0), test_server.countHeaders(server.requestHead(0).?, "range"));

    const whole = try sandbox.work.readFileAlloc(testing.io, "fresh.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(whole);
    try testing.expectEqualStrings("0123456789", whole);
}

test "-k is the only way a url reaches a peer this build did not verify" {
    // The end to end half of the `-k` proof. No TLS fixture exists here,
    // so this asserts the seam the binary itself holds: the flag parses,
    // it changes nothing about a plain `http` transfer, and a build that
    // never got the flag speaks for itself in `--help`.
    //
    // The measured half lives in the task report: `zurl
    // https://expired.badssl.com/` exits 60 and `zurl -k` on the same url
    // exits 0, and curl 8.21.0 answers both the same way.
    var server: test_server.TestServer = undefined;
    try server.start(&.{ ok("plain"), ok("plain") });
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    for ([_][]const u8{ "-k", "--insecure" }) |spelling| {
        const result = try runZurl(&.{ "-s", spelling, url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try testing.expectEqualStrings("plain", result.stdout);
    }
}

test "-C with --no-clobber is a usage fault, the way curl refuses the same pair" {
    // The two flags contradict each other: one adds to the file the
    // command line named and the other never touches it. Measured against
    // curl 8.21.0: the pair prints `option --no-clobber: is badly used
    // here` and exits 2 before any transfer.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const port = try closedPort();
    const url = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/x", .{port});
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-C", "-", "--no-clobber", "-o", "f.bin", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = usage_error_code }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "--no-clobber") != null);
    // The refusal comes before any transfer, so nothing was opened and
    // nothing was written.
    try sandbox.expectNothingWritten();
}

test "a cookie set on one hop is sent on the next hop of the same host" {
    // **The round trip that makes cookies worth having.** The first hop
    // answers with a `Set-Cookie` and a `Location` on the same host, and
    // the second hop carries the cookie. Measured against curl 8.21.0 on
    // a loopback listener, which sends exactly `Cookie: hop=one` there.
    //
    // A `Cookie` that the caller wrote takes the other path and would be
    // withheld here. The jar keeps this one because the jar knows the
    // domain it belongs to. See `zurl_http.engine.CookieJar`.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /second\r\nContent-Length: 0\r\n" ++
            "Connection: close\r\nSet-Cookie: hop=one\r\n\r\n",
        ok("arrived"),
    });
    defer server.stop();

    const url = try loopbackUrlAt(&server, "/first");
    defer testing.allocator.free(url);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const jar_path = try std.fmt.allocPrint(
        testing.allocator,
        ".zig-cache/tmp/{s}/round.jar",
        .{tmp.sub_path},
    );
    defer testing.allocator.free(jar_path);

    const result = try runZurl(&.{ "-L", "-c", jar_path, url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("arrived", result.stdout);

    const first = server.requestHead(0).?;
    const second = server.requestHead(1).?;
    // Nothing on the first hop, because nothing had been set yet.
    try testing.expectEqual(@as(usize, 0), std.mem.count(u8, first, "ookie:"));
    try testing.expect(std.mem.indexOf(u8, second, "Cookie: hop=one\r\n") != null);

    // And the jar the run wrote holds it, ready for the next invocation.
    const written = try tmp.dir.readFileAlloc(testing.io, "round.jar", testing.allocator, .limited(4096));
    defer testing.allocator.free(written);
    try testing.expect(std.mem.indexOf(u8, written, "\t0\thop\tone\n") != null);
}

test "a cookie does not follow a redirect to another host" {
    // **The rule that decides whether a cookie is a credential or a
    // giveaway.** A server that answers with a `Location` naming a host of
    // its choosing must not be able to send this run's session there.
    //
    // 127.0.0.0/8 is all loopback, so `127.0.0.2` is a second host name
    // that reaches this machine and never the network. Measured against
    // curl 8.21.0 with the same two hosts: the second request carried no
    // `Cookie` header at all.
    var first_server: test_server.TestServer = undefined;
    var second_server: test_server.TestServer = undefined;
    second_server.startWith(&.{ok("arrived")}, .{ .host = "127.0.0.2" }) catch |err| switch (err) {
        error.AddressFamilyUnsupported, error.AddressUnavailable => return error.SkipZigTest,
        else => |e| return e,
    };
    defer second_server.stop();

    const target = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.2:{d}/second",
        .{second_server.port()},
    );
    defer testing.allocator.free(target);
    const redirect = try std.fmt.allocPrint(
        testing.allocator,
        "HTTP/1.1 302 Found\r\nLocation: {s}\r\nContent-Length: 0\r\n" ++
            "Connection: close\r\nSet-Cookie: hop=one\r\n\r\n",
        .{target},
    );
    defer testing.allocator.free(redirect);

    // **Two responses from the first host, not one.** `-b 'sent=byflag'`
    // is a `Cookie` the caller wrote, so it travels as a secret. The
    // engine answers a followable redirect on such a request by sending
    // that request again with no secret at all, and only then follows the
    // chain. So the first host answers the probe and answers the resend.
    // See `zurl_http.h1.Exchange.open`.
    try first_server.start(&.{ redirect, redirect });
    defer first_server.stop();

    const url = try loopbackUrlAt(&first_server, "/first");
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-L", "-b", "sent=byflag", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("arrived", result.stdout);

    // The cookie the first host set never reached the second host, and
    // neither did the text the command line named. The jar withholds the
    // first by its domain rule, and the engine withholds the second
    // because a `Cookie` the caller wrote is origin bound.
    const crossed = second_server.requestHead(0).?;
    try testing.expectEqual(@as(usize, 0), std.mem.count(u8, crossed, "ookie:"));
    try testing.expect(std.mem.indexOf(u8, crossed, "hop=one") == null);
    try testing.expect(std.mem.indexOf(u8, crossed, "byflag") == null);
}

test "a jar written by one run is read back by the next one" {
    // `-c` then `-b`, which is how a login and the request after it are
    // usually written in a script.
    var first_server: test_server.TestServer = undefined;
    try first_server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n" ++
            "Connection: close\r\nSet-Cookie: sid=zz9; Path=/\r\n\r\nlogin",
    });
    defer first_server.stop();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const jar_path = try std.fmt.allocPrint(
        testing.allocator,
        ".zig-cache/tmp/{s}/session.jar",
        .{tmp.sub_path},
    );
    defer testing.allocator.free(jar_path);

    const login_url = try loopbackUrlAt(&first_server, "/login");
    defer testing.allocator.free(login_url);

    const login = try runZurl(&.{ "-c", jar_path, login_url });
    defer testing.allocator.free(login.stdout);
    defer testing.allocator.free(login.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, login.term);

    // A second server, because the first has used up its script. It is on
    // the same host, so the cookie belongs to it.
    var second_server: test_server.TestServer = undefined;
    try second_server.start(&.{ok("page")});
    defer second_server.stop();

    const page_url = try loopbackUrlAt(&second_server, "/page");
    defer testing.allocator.free(page_url);

    const page = try runZurl(&.{ "-b", jar_path, page_url });
    defer testing.allocator.free(page.stdout);
    defer testing.allocator.free(page.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, page.term);
    try testing.expect(std.mem.indexOf(u8, second_server.requestHead(0).?, "Cookie: sid=zz9\r\n") != null);
}

test "a Secure cookie crosses the loopback and never a cleartext hop elsewhere" {
    // **The loopback half of the rule, measured against curl 8.21.0.** A
    // `Secure` cookie of a jar reached `http://127.0.0.1` under curl and
    // was withheld from a plain `http` hop to a name that resolves to the
    // same address, because RFC 6265bis counts loopback as a trustworthy
    // origin. zurl matches curl, so a jar written against a local test
    // server behaves the same way under both programs.
    //
    // The other half of the rule, a `Secure` cookie withheld from a
    // cleartext hop to any host off the loopback, is proved in
    // `lib/zurl/Jar.zig` and in `lib/zurl-core/cookie.zig`. No test here
    // can reach it: every address this suite may bind is loopback.
    var server: test_server.TestServer = undefined;
    try server.start(&.{ok("body")});
    defer server.stop();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{
        .sub_path = "secure.jar",
        .data = "127.0.0.1\tFALSE\t/\tTRUE\t0\tsec\tsvalue\n" ++
            "www.example.test\tFALSE\t/\tTRUE\t0\televsewhere\tevalue\n",
    });
    const jar_path = try std.fmt.allocPrint(
        testing.allocator,
        ".zig-cache/tmp/{s}/secure.jar",
        .{tmp.sub_path},
    );
    defer testing.allocator.free(jar_path);

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-b", jar_path, url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    const head = server.requestHead(0).?;
    try testing.expect(std.mem.indexOf(u8, head, "Cookie: sec=svalue\r\n") != null);
    // The other host's cookie is not here, and the domain rule is why.
    try testing.expect(std.mem.indexOf(u8, head, "evalue") == null);
}

/// Returns `body` with the random half of every boundary rewritten to
/// `B`, so two runs of the same command line compare equal.
///
/// The boundary is 24 dashes and 22 random characters, so this finds the
/// dashes and blanks what follows. Nothing else in a form body holds that
/// many dashes in a row.
fn normalizeBoundary(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    const dashes = "-" ** 24;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var rest = body;
    while (std.mem.indexOf(u8, rest, dashes)) |at| {
        // The delimiter writes two more dashes in front of the boundary,
        // so walk back over every dash this run of them holds.
        var start = at;
        while (start > 0 and rest[start - 1] == '-') start -= 1;
        try out.appendSlice(allocator, rest[0..start]);
        var end = at + dashes.len;
        while (end < rest.len and rest[end] == '-') end += 1;
        try out.appendSlice(allocator, "--BOUNDARY");
        // The 22 random characters. A shorter run means the bytes ran out,
        // which the assertions below catch on their own.
        const skip = @min(22, rest.len - end);
        rest = rest[end + skip ..];
    }
    try out.appendSlice(allocator, rest);
    return out.toOwnedSlice(allocator);
}

test "-F sends a form the shipped binary built, with a literal and a file part" {
    // The seam this file exists for. `Args` chose the method, `form.zig`
    // read the syntax and opened the file, `multipart` drew the boundary
    // and wrote the framing, and the engine counted the length. Only a run
    // of the real binary proves all four agree.
    //
    // Measured against curl 8.21.0 on a loopback listener. curl sent the
    // same two parts, in the same order, with the same header lines.
    var server: test_server.TestServer = undefined;
    try server.start(&.{ok("one")});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();
    try sandbox.work.writeFile(testing.io, .{ .sub_path = "a.txt", .data = "hello\nworld\n" });

    const url = try loopbackUrlAt(&server, "/x");
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-s", "-F", "who=me", "-F", "file=@a.txt", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    const head = server.requestHead(0).?;
    try testing.expect(std.mem.startsWith(u8, head, "POST /x HTTP/1.1\r\n"));
    // The framing is a content-length, never the chunked coding: every
    // part has a length before the body goes out.
    try testing.expect(std.mem.indexOf(u8, head, "transfer-encoding") == null);
    try testing.expect(std.mem.indexOf(u8, head, "content-type: multipart/form-data; boundary=") != null);

    const body_bytes = server.requestBody(0).?;
    const normalized = try normalizeBoundary(testing.allocator, body_bytes);
    defer testing.allocator.free(normalized);

    try testing.expectEqualStrings(
        "--BOUNDARY\r\nContent-Disposition: form-data; name=\"who\"\r\n\r\nme\r\n" ++
            "--BOUNDARY\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n" ++
            "Content-Type: text/plain\r\n\r\nhello\nworld\n\r\n" ++
            "--BOUNDARY--\r\n",
        normalized,
    );

    // The announced length is the length that arrived. A body framed with
    // the wrong count leaves the peer reading the next request as the tail
    // of this one.
    const marker = "content-length: ";
    const at = std.mem.indexOf(u8, head, marker).? + marker.len;
    const end = std.mem.indexOfScalarPos(u8, head, at, '\r').?;
    const announced = try std.fmt.parseInt(usize, head[at..end], 10);
    try testing.expectEqual(body_bytes.len, announced);
}

test "--form-string sends its argument literally where -F would open a file" {
    // The one rule that divides the two flags, measured against curl
    // 8.21.0: `--form-string 'n=@a.txt'` sends the six characters and
    // opens nothing.
    var server: test_server.TestServer = undefined;
    try server.start(&.{ ok("one"), ok("two") });
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();
    try sandbox.work.writeFile(testing.io, .{ .sub_path = "a.txt", .data = "SECRET\n" });

    const url = try loopbackUrlAt(&server, "/x");
    defer testing.allocator.free(url);

    const literal = try runZurlIn(sandbox.work, &.{ "-s", "--form-string", "n=@a.txt", url });
    defer testing.allocator.free(literal.stdout);
    defer testing.allocator.free(literal.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, literal.term);

    const literal_body = try normalizeBoundary(testing.allocator, server.requestBody(0).?);
    defer testing.allocator.free(literal_body);
    try testing.expectEqualStrings(
        "--BOUNDARY\r\nContent-Disposition: form-data; name=\"n\"\r\n\r\n@a.txt\r\n--BOUNDARY--\r\n",
        literal_body,
    );
    // The file was never opened, so nothing of it reached the wire.
    try testing.expect(std.mem.indexOf(u8, server.requestBody(0).?, "SECRET") == null);

    // `-F 'n=<a.txt'` sends the content of the same file with no filename
    // and no content type, measured.
    const contents = try runZurlIn(sandbox.work, &.{ "-s", "-F", "n=<a.txt", url });
    defer testing.allocator.free(contents.stdout);
    defer testing.allocator.free(contents.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, contents.term);

    const contents_body = try normalizeBoundary(testing.allocator, server.requestBody(1).?);
    defer testing.allocator.free(contents_body);
    try testing.expectEqualStrings(
        "--BOUNDARY\r\nContent-Disposition: form-data; name=\"n\"\r\n\r\nSECRET\n\r\n--BOUNDARY--\r\n",
        contents_body,
    );
}

test "a field name with a newline in it forges no part header through the binary" {
    // **The injection proof, end to end.** `zurl.multipart` proves it for
    // every one of the 256 byte values, and `src/cli/form.zig` proves the
    // CLI reaches that code. This proves the shipped binary does too, on
    // the bytes a peer really reads.
    var server: test_server.TestServer = undefined;
    try server.start(&.{ok("one")});
    defer server.stop();

    const url = try loopbackUrlAt(&server, "/x");
    defer testing.allocator.free(url);

    const result = try runZurl(&.{
        "-s",
        "-F",
        "a\r\nContent-Disposition: form-data; name=\"forged\"\r\n\r\nowned\r\n--x=value",
        url,
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    const body_bytes = server.requestBody(0).?;
    const normalized = try normalizeBoundary(testing.allocator, body_bytes);
    defer testing.allocator.free(normalized);

    // One part, so two delimiters and no more. A forged header would show
    // up as a third.
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, normalized, "--BOUNDARY"));
    // The name holds the text `Content-Disposition` twice over, once as
    // the header this file wrote and once inside the quoted name. Only the
    // one behind a real CRLF is a header line, and there is one of those.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, normalized, "\r\nContent-Disposition"));
    // The text is on the wire, and every CR and LF of it is encoded.
    try testing.expect(std.mem.indexOf(u8, normalized, "%0D%0AContent-Disposition") != null);
    try testing.expect(std.mem.indexOf(u8, body_bytes, "\r\nContent-Disposition: form-data; name=\"forged\"") == null);
}

test "-F with -d is a usage fault, the way curl refuses the same pair" {
    // curl 8.21.0 exits 2 for this, before any socket. No server starts
    // here, because the parse ends the run.
    const result = try runZurl(&.{ "-F", "a=1", "-d", "b=2", "http://example.com/" });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = usage_error_code }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "one HTTP request method") != null);
}

test "a file part streams, and the bytes on the wire are the bytes on disk" {
    // The part that must not read the file into memory. The engine asks
    // for 16 KiB at a time, so a file larger than one ask proves the loop
    // and the offset both work.
    var server: test_server.TestServer = undefined;
    try server.start(&.{ok("one")});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    var written: [4000]u8 = undefined;
    for (&written, 0..) |*byte, i| byte.* = @as(u8, @intCast(i % 26)) + 'a';
    try sandbox.work.writeFile(testing.io, .{ .sub_path = "big.dat", .data = &written });

    const url = try loopbackUrlAt(&server, "/x");
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-s", "-F", "f=@big.dat", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    const body_bytes = server.requestBody(0).?;
    try testing.expect(std.mem.indexOf(u8, body_bytes, &written) != null);
    // A file with no known extension goes out as the default type,
    // measured.
    try testing.expect(std.mem.indexOf(u8, body_bytes, "Content-Type: application/octet-stream\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, body_bytes, "filename=\"big.dat\"") != null);
}

test "a 307 sends the same form body again, file part and all" {
    // **The rewind rule, on the body that has the most to lose by it.** A
    // form body reads a file at an offset, so the second send has to start
    // that file over as well as the framing. A body that started in the
    // middle would reach the peer with the right length and the wrong
    // bytes, which no status code would report.
    const kept = "HTTP/1.1 307 Temporary Redirect\r\nLocation: /moved\r\n" ++
        "Content-Length: 0\r\nConnection: close\r\n\r\n";

    var server: test_server.TestServer = undefined;
    try server.start(&.{ kept, ok("done") });
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();
    try sandbox.work.writeFile(testing.io, .{ .sub_path = "a.txt", .data = "hello\nworld\n" });

    const url = try loopbackUrlAt(&server, "/x");
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-s", "-L", "-F", "who=me", "-F", "f=@a.txt", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    const second = server.requestHead(1).?;
    try testing.expect(std.mem.startsWith(u8, second, "POST /moved HTTP/1.1\r\n"));

    // Byte for byte the same body, the boundary included. One body, one
    // boundary, however many times it goes out.
    try testing.expectEqualStrings(server.requestBody(0).?, server.requestBody(1).?);
    try testing.expect(std.mem.indexOf(u8, server.requestBody(1).?, "hello\nworld\n") != null);
}

/// A response the `--retry` family treats as transient. `503` is one of
/// the six statuses curl sends the request again for, measured.
const unavailable = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 5\r\n" ++
    "Connection: close\r\n\r\nnope\n";

test "--retry sends the request again after a 503 and keeps only the answer that worked" {
    // **The row curl also retries.** Measured against curl 8.21.0 on a
    // loopback server that logged each request: `--retry 2` against a
    // server answering `503` sent three requests, at 0, 1, and 3 seconds.
    // This is the same shape with one try, so the suite pays one second.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    var server: test_server.TestServer = undefined;
    try server.start(&.{ unavailable, ok("second") });
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    // A file that is already there. A try that asked for another must
    // leave it exactly as it was, so the bytes below can only be the
    // second answer.
    try sandbox.work.writeFile(testing.io, .{ .sub_path = "out.bin", .data = "old" });

    const result = try runZurlIn(sandbox.work, &.{
        "-s", "--retry", "1", "--retry-delay", "1", "-o", "out.bin", url,
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    // Two requests went out, which is the one retry the flag asked for.
    try testing.expectEqual(@as(usize, 2), server.accepts());

    const written = try sandbox.work.readFileAlloc(testing.io, "out.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(written);
    // The 503 body never reached the file, and neither did the bytes that
    // were there before.
    try testing.expectEqualStrings("second", written);
}

test "a 404 is never retried, and --retry-all-errors alone does not change that" {
    // **The row curl deliberately does not retry.** Measured: `--retry 2`
    // and `--retry 2 --retry-all-errors` each sent one request for a
    // `404`, because the transfer succeeded and `404` is not one of the
    // six transient statuses. Retrying it would repeat a request the
    // server already answered, for nothing.
    const missing = "HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\nConnection: close\r\n\r\ngone\n";

    const rows = [_][]const []const u8{
        &.{ "-s", "--retry", "2", "--retry-delay", "1" },
        &.{ "-s", "--retry", "2", "--retry-delay", "1", "--retry-all-errors" },
    };
    for (rows) |flags| {
        var server: test_server.TestServer = undefined;
        try server.start(&.{missing});
        defer server.stop();

        const url = try loopbackUrl(&server);
        defer testing.allocator.free(url);

        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(testing.allocator);
        try argv.appendSlice(testing.allocator, flags);
        try argv.append(testing.allocator, url);

        const result = try runZurl(argv.items);
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        // No `-f`, so a `404` is exit 0 and the body is written, which is
        // what curl does.
        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try testing.expectEqualStrings("gone\n", result.stdout);
        try testing.expectEqual(@as(usize, 1), server.accepts());
    }
}

test "a refused connection is retried only when --retry-connrefused asks for it" {
    // Measured against curl 8.21.0 against a closed port: `--retry 2`
    // alone made one attempt, and `--retry 2 --retry-connrefused` made
    // three. The assertion on time is a floor, never a ceiling.
    const dead = try closedPort();
    var url_buffer: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buffer, "http://127.0.0.1:{d}/", .{dead});

    {
        const result = try runZurl(&.{ "-s", "--retry", "2", "--retry-delay", "1", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        // `CURLE_COULDNT_CONNECT` is 7.
        try testing.expectEqual(std.process.Child.Term{ .exited = 7 }, result.term);

        // **No bound on time here, in either direction.** The assertion
        // used to read `elapsed.nanoseconds < ns_per_s`, a ceiling over a
        // whole `std.process.run`: a fork, an exec, a dynamic load, an
        // argument parse, a refused connect, an exit, and the parent
        // draining two pipes. The file header forbids a ceiling, and this
        // one failed on a slow single-core board with correct code. It
        // also passed for a retry that ran with no delay, so it did not
        // prove what its name says. The arm below proves the same rule
        // from the other side, with a floor, which is the direction that
        // can only be crossed by a retry that really happened.
    }

    {
        const started = std.Io.Timestamp.now(testing.io, .awake);
        const result = try runZurl(&.{
            "-s", "--retry", "1", "--retry-delay", "1", "--retry-connrefused", url,
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        const elapsed = started.durationTo(std.Io.Timestamp.now(testing.io, .awake));

        try testing.expectEqual(std.process.Child.Term{ .exited = 7 }, result.term);
        // The one retry waited a second, so the run cannot have been
        // shorter than that. This is a floor and not a bound.
        try testing.expect(elapsed.nanoseconds >= @as(i96, 900 * std.time.ns_per_ms));
    }
}

test "-r puts the byte range on the wire, and -C beside it is a usage fault" {
    // Measured against curl 8.21.0: `-r 0-4` sends `Range: bytes=0-4`,
    // and `-r 0-99 -C 5` exits 2 before any socket opens.
    const partial = "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-4/10\r\n" ++
        "Content-Length: 5\r\nConnection: close\r\n\r\n01234";

    var server: test_server.TestServer = undefined;
    try server.start(&.{partial});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-r", "0-4", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("01234", result.stdout);

    const head = server.requestHead(0).?;
    try testing.expectEqual(@as(usize, 1), test_server.countHeaders(head, "range"));
    try testing.expect(std.mem.indexOf(u8, head, "bytes=0-4\r\n") != null);

    const refused = try runZurl(&.{ "-s", "-r", "0-99", "-C", "5", url });
    defer testing.allocator.free(refused.stdout);
    defer testing.allocator.free(refused.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = usage_error_code }, refused.term);
    try testing.expect(std.mem.indexOf(u8, refused.stderr, "--range") != null);
}

test "--resolve sends the request to another address and keeps the url's own host line" {
    // **The drop-in proof for `--resolve`, through the shipped binary.**
    // The url names a host that resolves nowhere, so nothing but the flag
    // can reach the fixture, and the `host:` line must still be the name
    // the user typed. Measured against curl 8.21.0, which sends
    // `Host: example.invalid:PORT` for the same command line.
    var server: test_server.TestServer = undefined;
    try server.start(&.{ok("reached")});
    defer server.stop();

    const port = server.port();
    var url_buffer: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buffer, "http://example.invalid:{d}/x", .{port});
    var entry_buffer: [64]u8 = undefined;
    const entry = try std.fmt.bufPrint(&entry_buffer, "example.invalid:{d}:127.0.0.1", .{port});

    const result = try runZurl(&.{ "-s", "--resolve", entry, url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("reached", result.stdout);

    const head = server.requestHead(0).?;
    var host_buffer: [64]u8 = undefined;
    const host_line = try std.fmt.bufPrint(&host_buffer, "host: example.invalid:{d}\r\n", .{port});
    try testing.expect(std.mem.indexOf(u8, head, host_line) != null);
    try testing.expect(std.mem.indexOf(u8, head, "127.0.0.1") == null);

    // The same url with no flag reaches nothing, so the transfer above
    // ran only because the flag moved the dial.
    const alone = try runZurl(&.{ "-s", url });
    defer testing.allocator.free(alone.stdout);
    defer testing.allocator.free(alone.stderr);
    try testing.expect(alone.term.exited != 0);
    try testing.expectEqualStrings("", alone.stdout);
}

test "a raw at in the userinfo opens no socket, so one url names one host" {
    // **The differential proof, through the shipped binary.**
    // `--connect-to ::127.0.0.1:PORT` sends every dial to the fixture and
    // leaves the `host:` line alone, so the line the fixture reads is the
    // host the url chose. That is how the divergence was measured against
    // curl 8.21.0:
    //
    // ```
    // http://a@b:c@evil.test/            curl exit 3, zurl reached evil.test
    // http://target.test<LF>@evil.test/  curl exit 3, zurl reached evil.test
    // ```
    //
    // The authority splits at the last `@`, so `a@b` read as a host to a
    // person and `evil.test` was the host that got dialed. curl refuses a
    // raw `@` in the userinfo, because RFC 3986 gives the userinfo none.
    var server: test_server.TestServer = undefined;
    try server.start(&.{ok("reached")});
    defer server.stop();

    const port = server.port();
    var entry_buffer: [64]u8 = undefined;
    const entry = try std.fmt.bufPrint(&entry_buffer, "::127.0.0.1:{d}", .{port});

    const refused = [_][]const u8{
        "http://a@b:c@evil.test/",
        "http://a@b@evil.test/",
        "http://evil.test\n@other.test/",
    };
    for (refused) |url| {
        const result = try runZurl(&.{ "-s", "-S", "--connect-to", entry, url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 3 }, result.term);
        try testing.expectEqualStrings("", result.stdout);
        // The fixture heard nothing, so the dial never happened.
        try testing.expect(server.requestHead(0) == null);
    }

    // The same flag with a url that names one host does reach the
    // fixture, so the rows above failed on the url and not on the flag.
    var good_buffer: [64]u8 = undefined;
    const good = try std.fmt.bufPrint(&good_buffer, "http://a%40b:c@good.test:{d}/", .{port});
    const allowed = try runZurl(&.{ "-s", "--connect-to", entry, good });
    defer testing.allocator.free(allowed.stdout);
    defer testing.allocator.free(allowed.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, allowed.term);
    try testing.expectEqualStrings("reached", allowed.stdout);

    const head = server.requestHead(0).?;
    var host_buffer: [64]u8 = undefined;
    const host_line = try std.fmt.bufPrint(&host_buffer, "host: good.test:{d}\r\n", .{port});
    try testing.expect(std.mem.indexOf(u8, head, host_line) != null);
}

test "an IPv6 zone id stays off the host line" {
    // RFC 6874 section 3: a zone id names an interface of the local host,
    // so it has no meaning to a peer and must not go on the wire. curl
    // 8.21.0 sends `Host: [fe80::1]` for both spellings of the zone,
    // measured off a loopback listener, and zurl sent the zone with it.
    //
    // `--connect-to` moves the dial and leaves the `host:` line alone, so
    // this reaches the fixture without needing a link-local interface.
    var server: test_server.TestServer = undefined;
    try server.start(&.{ ok("reached"), ok("reached") });
    defer server.stop();

    const port = server.port();
    var entry_buffer: [64]u8 = undefined;
    const entry = try std.fmt.bufPrint(&entry_buffer, "::127.0.0.1:{d}", .{port});

    const spellings = [_][]const u8{ "%25eth0", "%eth0" };
    for (spellings, 0..) |zone, i| {
        var url_buffer: [64]u8 = undefined;
        const url = try std.fmt.bufPrint(&url_buffer, "http://[fe80::1{s}]:{d}/", .{ zone, port });

        const result = try runZurl(&.{ "-s", "--connect-to", entry, url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

        const head = server.requestHead(i).?;
        var host_buffer: [64]u8 = undefined;
        const host_line = try std.fmt.bufPrint(&host_buffer, "host: [fe80::1]:{d}\r\n", .{port});
        try testing.expect(std.mem.indexOf(u8, head, host_line) != null);
        // The brackets stay, and the zone does not.
        try testing.expect(std.mem.indexOf(u8, head, "eth0") == null);
    }
}

test "a --resolve entry that does not read exits 49, which is curl's own code" {
    // Measured: `curl --resolve bogus URL` prints `Could not parse
    // CURLOPT_RESOLVE entry 'bogus'` and exits 49. No socket opens under
    // either program.
    const result = try runZurl(&.{ "-s", "--resolve", "bogus", "http://127.0.0.1:1/" });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = cli.setopt_syntax_error_code }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "bogus") != null);
    try testing.expectEqualStrings("", result.stdout);
}

test "-e sends the Referer, and ;auto names the previous hop on a redirect" {
    // Measured against curl 8.21.0. See the `.referer` arm of
    // `Args.applyEffect` for every row.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /second\r\nContent-Length: 0\r\n\r\n",
        ok("landed"),
    });
    defer server.stop();

    const url = try loopbackUrlAt(&server, "/first");
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-L", "-e", "http://written.test/;auto", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("landed", result.stdout);

    // The first request carries the url the user wrote.
    const first = server.requestHead(0).?;
    try testing.expectEqual(@as(usize, 1), test_server.countHeaders(first, "referer"));
    try testing.expect(std.mem.indexOf(u8, first, "http://written.test/") != null);

    // The second carries the first hop's url, and the user's own value is
    // gone.
    const second = server.requestHead(1).?;
    try testing.expectEqual(@as(usize, 1), test_server.countHeaders(second, "referer"));
    try testing.expect(std.mem.indexOf(u8, second, "http://written.test/") == null);
    var line_buffer: [96]u8 = undefined;
    const line = try std.fmt.bufPrint(
        &line_buffer,
        "Referer: http://127.0.0.1:{d}/first\r\n",
        .{server.port()},
    );
    try testing.expect(std.mem.indexOf(u8, second, line) != null);
}

test "--parallel-max outside its range is named on standard error and the run still works" {
    // curl puts a value outside 1 to 300 back to its own default and says
    // nothing. zurl keeps the exit code and every transfer and adds one
    // line, because recovery is never silent.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    var server: test_server.TestServer = undefined;
    try server.start(&.{ ok("one"), ok("two") });
    defer server.stop();

    const first = try loopbackUrlAt(&server, "/a");
    defer testing.allocator.free(first);
    const second = try loopbackUrlAt(&server, "/b");
    defer testing.allocator.free(second);

    const result = try runZurlIn(sandbox.work, &.{
        "-S", "-s", "-Z", "--parallel-max", "5000", "-O", "-O", first, second,
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "--parallel-max") != null);

    // Both files still landed, so the note cost the run nothing.
    const a = try sandbox.work.readFileAlloc(testing.io, "a", testing.allocator, .limited(16));
    defer testing.allocator.free(a);
    const b = try sandbox.work.readFileAlloc(testing.io, "b", testing.allocator, .limited(16));
    defer testing.allocator.free(b);
    try testing.expectEqual(@as(usize, 3), a.len);
    try testing.expectEqual(@as(usize, 3), b.len);

    // A number inside the range earns no note at all. Its own server,
    // because the one above has served its whole script and would leave
    // this run waiting for an answer that never comes.
    var quiet_server: test_server.TestServer = undefined;
    try quiet_server.start(&.{ ok("one"), ok("two") });
    defer quiet_server.stop();

    const third = try loopbackUrlAt(&quiet_server, "/c");
    defer testing.allocator.free(third);
    const fourth = try loopbackUrlAt(&quiet_server, "/d");
    defer testing.allocator.free(fourth);

    const clean = try runZurlIn(sandbox.work, &.{
        "-S", "-s", "-Z", "--parallel-max", "2", "-O", "-O", third, fourth,
    });
    defer testing.allocator.free(clean.stdout);
    defer testing.allocator.free(clean.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, clean.term);
    try testing.expect(std.mem.indexOf(u8, clean.stderr, "--parallel-max") == null);
}

test "--parallel-max-host bounds the run and says which flag decided the count" {
    // **zurl reads the flag as a bound on the whole run, which is
    // stricter than curl's per-host bound.** Each worker holds one
    // connection at a time, so capping the workers keeps the promise for
    // every host whatever the url list holds. The narrower reading is
    // never silent: the run says so, and both files still land.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    var server: test_server.TestServer = undefined;
    try server.start(&.{ ok("one"), ok("two") });
    defer server.stop();

    const first = try loopbackUrlAt(&server, "/a");
    defer testing.allocator.free(first);
    const second = try loopbackUrlAt(&server, "/b");
    defer testing.allocator.free(second);

    const result = try runZurlIn(sandbox.work, &.{
        "-S", "-s", "-Z", "--parallel-max-host", "1", "-O", "-O", first, second,
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "--parallel-max-host") != null);

    const a = try sandbox.work.readFileAlloc(testing.io, "a", testing.allocator, .limited(16));
    defer testing.allocator.free(a);
    const b = try sandbox.work.readFileAlloc(testing.io, "b", testing.allocator, .limited(16));
    defer testing.allocator.free(b);
    try testing.expectEqual(@as(usize, 3), a.len);
    try testing.expectEqual(@as(usize, 3), b.len);

    // A cap wider than the run needs decides nothing, so it earns no note.
    var quiet_server: test_server.TestServer = undefined;
    try quiet_server.start(&.{ ok("one"), ok("two") });
    defer quiet_server.stop();

    const third = try loopbackUrlAt(&quiet_server, "/c");
    defer testing.allocator.free(third);
    const fourth = try loopbackUrlAt(&quiet_server, "/d");
    defer testing.allocator.free(fourth);

    const clean = try runZurlIn(sandbox.work, &.{
        "-S", "-s", "-Z", "--parallel-max-host", "8", "-O", "-O", third, fourth,
    });
    defer testing.allocator.free(clean.stdout);
    defer testing.allocator.free(clean.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, clean.term);
    try testing.expect(std.mem.indexOf(u8, clean.stderr, "--parallel-max-host") == null);
}

test "--rate holds a serial run back, and no flag does not" {
    // **The flag does something, and this proves it does.** A rate of
    // four each second puts a quarter of a second between the start of
    // one transfer and the start of the next, so three urls carry two
    // such gaps. The bound below is well under that, so a slow machine
    // cannot fail this run, and it is far above what the same three urls
    // take with no flag: they are loopback transfers of three bytes each.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    var server: test_server.TestServer = undefined;
    try server.start(&.{ ok("one"), ok("two"), ok("thr") });
    defer server.stop();

    const first = try loopbackUrlAt(&server, "/a");
    defer testing.allocator.free(first);
    const second = try loopbackUrlAt(&server, "/b");
    defer testing.allocator.free(second);
    const third = try loopbackUrlAt(&server, "/c");
    defer testing.allocator.free(third);

    const started = std.Io.Timestamp.now(testing.io, .awake);
    const result = try runZurlIn(sandbox.work, &.{
        "-s", "--rate", "4/s", "-O", "-O", "-O", first, second, third,
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);
    const elapsed = started.durationTo(std.Io.Timestamp.now(testing.io, .awake));

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    // Two gaps of 250 ms are 500 ms. 300 ms leaves room for a machine
    // whose clock or scheduler is coarse, and still cannot pass with no
    // wait at all.
    const floor_ns: i96 = 300 * std.time.ns_per_ms;
    if (elapsed.nanoseconds < floor_ns) {
        std.debug.print(
            "--rate 4/s over three urls took {d} ms, which is no wait at all\n",
            .{@divTrunc(elapsed.nanoseconds, std.time.ns_per_ms)},
        );
        return error.TestUnexpectedResult;
    }

    // And every url still ran, so the pacing cost the run nothing but
    // time.
    for ([_][]const u8{ "a", "b", "c" }) |name| {
        const written = try sandbox.work.readFileAlloc(testing.io, name, testing.allocator, .limited(16));
        defer testing.allocator.free(written);
        try testing.expectEqual(@as(usize, 3), written.len);
    }
}

test "a dict url reaches the server and every byte of the answer reaches standard output" {
    // The whole path through the binary: the flag parser, the client, the
    // dispatch table, and `zurl-dict`. The bytes on the wire are curl's
    // own three lines, and the bytes on standard output are every byte the
    // server wrote, banner and all, which is what curl writes too.
    var server: zurl_dict.test_server.Server = undefined;
    try server.start(&.{
        "220 test.example dictd 1.0 <1.2.3@test>\r\n",
        "250 ok\r\n",
        "150 1 definitions retrieved\r\n151 \"hello\" wn \"WordNet\"\r\nhello\r\n.\r\n250 ok\r\n",
        "221 bye\r\n",
    });
    defer server.stop();

    const url = try std.fmt.allocPrint(
        testing.allocator,
        "dict://127.0.0.1:{d}/d:hello",
        .{server.port()},
    );
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-S", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings(
        "CLIENT " ++ zurl_dict.request.client_id ++ "\r\nDEFINE ! hello\r\nQUIT\r\n",
        server.received(),
    );
    try testing.expectEqualStrings(
        "220 test.example dictd 1.0 <1.2.3@test>\r\n" ++
            "250 ok\r\n" ++
            "150 1 definitions retrieved\r\n151 \"hello\" wn \"WordNet\"\r\nhello\r\n.\r\n250 ok\r\n" ++
            "221 bye\r\n",
        result.stdout,
    );
}

test "a gopher url reaches the server and the whole menu reaches standard output" {
    var server: zurl_gopher.test_server.Server = undefined;
    try server.start("0About\t/about.txt\t127.0.0.1\t70\r\n1Sub\t/sub\t127.0.0.1\t70\r\n.\r\n");
    defer server.stop();

    const url = try std.fmt.allocPrint(
        testing.allocator,
        "gopher://127.0.0.1:{d}/1/",
        .{server.port()},
    );
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-S", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    // The request line drops the leading slash and the item type, which is
    // what curl sends for the same url.
    try testing.expectEqualStrings("/\r\n", server.received());
    try testing.expectEqualStrings(
        "0About\t/about.txt\t127.0.0.1\t70\r\n1Sub\t/sub\t127.0.0.1\t70\r\n.\r\n",
        result.stdout,
    );
}

test "a ws url upgrades and its frame payloads reach standard output" {
    var frames: [256]u8 = undefined;
    var at: usize = 0;
    at += zurl_ws.test_server.serverFrame(frames[at..], .text, "frame one ", true).len;
    at += zurl_ws.test_server.serverFrame(frames[at..], .binary, "frame two", true).len;
    at += zurl_ws.test_server.serverFrame(frames[at..], .close, "\x03\xe8", true).len;

    var server: zurl_ws.test_server.Server = undefined;
    try server.start(.{ .frames = frames[0..at], .expect_client_frames = 1 });
    defer server.stop();

    const url = try std.fmt.allocPrint(
        testing.allocator,
        "ws://127.0.0.1:{d}/chat",
        .{server.port()},
    );
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-S", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("frame one frame two", result.stdout);
    try testing.expect(std.mem.startsWith(u8, server.received(), "GET /chat HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, server.received(), "\r\nUpgrade: websocket\r\n") != null);

    // **The close the binary sent back is masked.** RFC 6455 section 5.1
    // asks a client to mask every frame, and this reads the octets a
    // server would read.
    server.awaitDone();
    try testing.expectEqual(@as(usize, 1), server.clientFrames());
    try testing.expect(server.clientMasked(0));
}

test "a ws server that answers a wrong Sec-WebSocket-Accept gets exit 8" {
    // Without this check the handshake proves nothing: a client would
    // upgrade to whatever answered 101.
    var frames: [64]u8 = undefined;
    const written = zurl_ws.test_server.serverFrame(&frames, .text, "never read", true);

    var server: zurl_ws.test_server.Server = undefined;
    try server.start(.{
        .accept = .{ .text = "AAAAAAAAAAAAAAAAAAAAAAAAAAA=" },
        .frames = written,
    });
    defer server.stop();

    const url = try std.fmt.allocPrint(
        testing.allocator,
        "ws://127.0.0.1:{d}/chat",
        .{server.port()},
    );
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-S", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 8 }, result.term);
    try testing.expectEqualStrings("", result.stdout);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "Sec-WebSocket-Accept") != null);
}

test "a telnet url answers the negotiation and writes the data octets out" {
    var server: zurl_telnet.test_server.Server = undefined;
    try server.start(.{
        .greeting = "\xff\xfd\x18login: ",
        .answer = "\xff\xfb\x01welcome\r\n",
        // The refusal and the four offers, five lines of three octets.
        // The `IAC WILL ECHO` in the second write draws three more, which
        // the fixture takes in its drain.
        .expect_bytes = 15,
    });
    defer server.stop();

    const url = try std.fmt.allocPrint(
        testing.allocator,
        "telnet://127.0.0.1:{d}",
        .{server.port()},
    );
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-S", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    // Every command is taken out, and the data reaches standard output.
    // Measured against curl 8.21.0 on the same shape of session.
    try testing.expectEqualStrings("login: welcome\r\n", result.stdout);

    // The five lines curl writes for the same greeting, and then the
    // refusal of the `IAC WILL ECHO` that the second write carried. The
    // offer goes out once and never again.
    server.awaitDone();
    try testing.expectEqualSlices(
        u8,
        "\xff\xfc\x18" ++ "\xff\xfb\x00" ++ "\xff\xfd\x00" ++
            "\xff\xfb\x03" ++ "\xff\xfd\x03" ++ "\xff\xfe\x01",
        server.received(),
    );
}

test "a telnet body reaches the peer with every IAC octet doubled" {
    // **The escape this protocol turns on.** `\xff\xfd\x18` is
    // `IAC DO TERMINAL-TYPE`, so a body that reached the peer unescaped
    // would send a negotiation the command line never asked for.
    // Measured against curl 8.21.0: standard input of
    // `he<FF>llo<CRLF>bye<CRLF>` reached a loopback server as
    // `he<FF><FF>llo<CRLF>bye<CRLF>`.
    var server: zurl_telnet.test_server.Server = undefined;
    // The body is 7 octets and one of them is escaped, so 8 arrive.
    try server.start(.{ .greeting = "", .answer = "ok\r\n", .expect_bytes = 8 });
    defer server.stop();

    const url = try std.fmt.allocPrint(
        testing.allocator,
        "telnet://127.0.0.1:{d}",
        .{server.port()},
    );
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-S", "--data-binary", "he\xff\xfd\x18llo", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("ok\r\n", result.stdout);

    server.awaitDone();
    try testing.expectEqualSlices(u8, "he\xff\xff\xfd\x18llo", server.received());
}

test "a tftp url downloads the whole file through the installed binary" {
    // Three blocks, so the block acknowledgement and the short last block
    // both run inside the real binary and not only inside a unit test.
    const payload = "tftp payload " ** 100;
    var server: zurl_tftp.test_server.Server = undefined;
    try server.start(.{ .file = payload });
    defer server.stop();

    const url = try std.fmt.allocPrint(
        testing.allocator,
        "tftp://127.0.0.1:{d}/boot.bin",
        .{server.port()},
    );
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-S", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings(payload, result.stdout);
    // The read request is byte for byte curl's own default request.
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01 } ++
        "boot.bin\x00octet\x00tsize\x000\x00blksize\x00512\x00timeout\x006\x00".*, server.request());
}

test "an ftp url downloads the whole file through the installed binary" {
    // The whole path through the binary: the flag parser, the client, the
    // dispatch table, and `zurl-ftp`. The command order is curl's own,
    // measured against curl 8.21.0 on a loopback RFC 959 server.
    const payload = "ftp payload line\n" ** 40;
    var server: zurl_ftp.test_server.Server = undefined;
    try server.start(.{ .body = payload });
    defer server.stop();

    const url = try std.fmt.allocPrint(
        testing.allocator,
        "ftp://127.0.0.1:{d}/pub/f.txt",
        .{server.port()},
    );
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-S", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings(payload, result.stdout);

    server.wait();
    try testing.expectEqualStrings(
        "USER anonymous\nPASS ftp@example.com\nCWD pub\nEPSV\nTYPE I\nSIZE f.txt\nRETR f.txt\nQUIT",
        server.commands(),
    );
}

test "an ftp directory url lists, and -l asks the server for the names alone" {
    {
        var server: zurl_ftp.test_server.Server = undefined;
        try server.start(.{});
        defer server.stop();

        const url = try std.fmt.allocPrint(testing.allocator, "ftp://127.0.0.1:{d}/", .{server.port()});
        defer testing.allocator.free(url);

        const result = try runZurl(&.{ "-s", "-S", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try testing.expect(std.mem.indexOf(u8, result.stdout, "-rw-r--r--") != null);

        server.wait();
        try testing.expect(std.mem.indexOf(u8, server.commands(), "TYPE A\nLIST") != null);
    }
    {
        var server: zurl_ftp.test_server.Server = undefined;
        try server.start(.{});
        defer server.stop();

        const url = try std.fmt.allocPrint(testing.allocator, "ftp://127.0.0.1:{d}/", .{server.port()});
        defer testing.allocator.free(url);

        const result = try runZurl(&.{ "-s", "-S", "-l", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        // The fixture writes `f.txt\r\nsub\r\n`. A listing is `TYPE A`, so
        // the receiver writes this system's line ending. curl writes the
        // same bytes for the same fixture, measured.
        try testing.expectEqualStrings("f.txt\nsub\n", result.stdout);

        server.wait();
        try testing.expect(std.mem.indexOf(u8, server.commands(), "TYPE A\nNLST") != null);
    }
}

test "a PASV answer naming another address is ignored, and the transfer still runs" {
    // **The security test, through the whole binary.** The fixture listens
    // on 127.0.0.1 and answers `227 ... (203,0,113,7,...)`. A client that
    // dialed the answer would reach a machine nobody asked it to reach and
    // this transfer would never finish. curl ignores the address by
    // default too, measured: `--ftp-skip-pasv-ip` has been on by default
    // since 7.74.0, and the same fixture with `--no-ftp-skip-pasv-ip`
    // hangs on 203.0.113.7 until the command is killed.
    var server: zurl_ftp.test_server.Server = undefined;
    try server.start(.{
        .epsv = false,
        .pasv_address = .{ 203, 0, 113, 7 },
        .body = "the data connection went to the control host\n",
    });
    defer server.stop();

    const url = try std.fmt.allocPrint(testing.allocator, "ftp://127.0.0.1:{d}/f.txt", .{server.port()});
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-S", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("the data connection went to the control host\n", result.stdout);
}

test "a multi-line ftp greeting does not put the session one answer out of step" {
    // A reader that stopped at the first line would read the rest of the
    // greeting as the answer to `USER`, and every answer after it would
    // belong to the command before it.
    var server: zurl_ftp.test_server.Server = undefined;
    try server.start(.{
        .greeting = &.{
            "220-Welcome to the fixture",
            "  line two, and 220 is not the end",
            "230 Not a real code either",
            "220-still open",
            "220 Ready",
        },
        .body = "the whole body arrived\n",
    });
    defer server.stop();

    const url = try std.fmt.allocPrint(testing.allocator, "ftp://127.0.0.1:{d}/f.txt", .{server.port()});
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-S", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("the whole body arrived\n", result.stdout);
}

test "-C on an ftp url sends REST and appends to the file already there" {
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    var server: zurl_ftp.test_server.Server = undefined;
    try server.start(.{ .body = "0123456789abcdef" });
    defer server.stop();

    try sandbox.work.writeFile(testing.io, .{ .sub_path = "part.bin", .data = "0123456789" });

    const url = try std.fmt.allocPrint(testing.allocator, "ftp://127.0.0.1:{d}/f.txt", .{server.port()});
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-s", "-S", "-C", "-", "-o", "part.bin", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    const whole = try sandbox.work.readFileAlloc(testing.io, "part.bin", testing.allocator, .limited(1024));
    defer testing.allocator.free(whole);
    try testing.expectEqualStrings("0123456789abcdef", whole);

    server.wait();
    try testing.expect(std.mem.indexOf(u8, server.commands(), "REST 10\nRETR f.txt") != null);
}

test "each ftp answer the server refuses carries curl's own exit code" {
    const rows = [_]struct {
        script: zurl_ftp.test_server.Script,
        path: []const u8,
        code: u8,
    }{
        // Every number below was measured from curl 8.21.0 against a
        // loopback server answering the same reply.
        .{ .script = .{ .pass = "530 Login incorrect" }, .path = "/f.txt", .code = 67 },
        .{ .script = .{ .cwd = "550 No such directory" }, .path = "/a/f.txt", .code = 9 },
        .{ .script = .{ .type = "500 TYPE refused" }, .path = "/f.txt", .code = 17 },
        .{ .script = .{ .transfer_refused = "550 No such file" }, .path = "/f.txt", .code = 78 },
        .{ .script = .{ .transfer_end = "426 Transfer aborted" }, .path = "/f.txt", .code = 18 },
        .{
            .script = .{ .epsv = false, .pasv_reply = "227 Entering Passive Mode blah blah" },
            .path = "/f.txt",
            .code = 14,
        },
        .{ .script = .{ .auth = "504 AUTH not supported" }, .path = "/f.txt", .code = 64 },
    };

    for (rows, 0..) |row, i| {
        var server: zurl_ftp.test_server.Server = undefined;
        try server.start(row.script);
        defer server.stop();

        const url = try std.fmt.allocPrint(
            testing.allocator,
            "ftp://127.0.0.1:{d}{s}",
            .{ server.port(), row.path },
        );
        defer testing.allocator.free(url);

        // The last row is the only one that asks for TLS.
        const result = if (row.code == 64)
            try runZurl(&.{ "-s", "-S", "--ssl-reqd", "--connect-timeout", "5", url })
        else
            try runZurl(&.{ "-s", "-S", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        testing.expectEqual(std.process.Child.Term{ .exited = row.code }, result.term) catch |err| {
            std.debug.print("row {d} said: {s}\n", .{ i, result.stderr });
            return err;
        };
        try testing.expectEqualStrings("", result.stdout);
    }
}

test "-r on an ftp url answers the open ended form and refuses the rest by name" {
    {
        var server: zurl_ftp.test_server.Server = undefined;
        try server.start(.{ .body = "0123456789" });
        defer server.stop();

        const url = try std.fmt.allocPrint(testing.allocator, "ftp://127.0.0.1:{d}/f.txt", .{server.port()});
        defer testing.allocator.free(url);

        const result = try runZurl(&.{ "-s", "-S", "-r", "4-", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try testing.expectEqualStrings("456789", result.stdout);
    }
    {
        // **A range FTP cannot answer is refused before any command goes
        // out.** curl answers `-r 5-15` by reading eleven bytes and then
        // sending `ABOR` to get the control connection back, measured.
        // zurl refuses instead: see `zurl_ftp.Fetcher.restFromRange`.
        var server: zurl_ftp.test_server.Server = undefined;
        try server.start(.{});
        defer server.stop();

        const url = try std.fmt.allocPrint(testing.allocator, "ftp://127.0.0.1:{d}/f.txt", .{server.port()});
        defer testing.allocator.free(url);

        const result = try runZurl(&.{ "-s", "-S", "-r", "5-15", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 33 }, result.term);
        try testing.expectEqualStrings("", result.stdout);
        try testing.expectEqual(@as(usize, 0), server.connections());
    }
}

test "a -u credential does not follow a redirect out of http into ftp" {
    // **The hole this closes.** `ftp` and `ftps` are in the default
    // `--proto-redir` list, so a redirect out of HTTP into FTP is a
    // transfer zurl will run, exactly as curl runs it. Without this rule
    // the `-u` password would go to whichever ftp peer the server named,
    // which is a password sent to a host the user never typed.
    //
    // Measured against curl 8.21.0 on the same two fixtures:
    //   curl -u alice:s3cret -L                 -> USER anonymous
    //   curl -u alice:s3cret -L --location-trusted -> USER alice
    // zurl answers both the same way.
    const cases = [_]struct { trusted: bool, want: []const u8 }{
        .{ .trusted = false, .want = "USER anonymous\nPASS ftp@example.com\n" },
        .{ .trusted = true, .want = "USER alice\nPASS s3cret\n" },
    };

    for (cases) |case| {
        var ftp: zurl_ftp.test_server.Server = undefined;
        try ftp.start(.{ .body = "the ftp peer answered\n" });
        defer ftp.stop();

        const ftp_url = try std.fmt.allocPrint(
            testing.allocator,
            "ftp://127.0.0.1:{d}/f.txt",
            .{ftp.port()},
        );
        defer testing.allocator.free(ftp_url);

        const redirect = try std.fmt.allocPrint(
            testing.allocator,
            "HTTP/1.1 302 Found\r\nLocation: {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            .{ftp_url},
        );
        defer testing.allocator.free(redirect);

        // **Two copies of the same answer, and the engine needs both.**
        // With a credential and no `--location-trusted`, `h1.Exchange.open`
        // sends the chain once with the secret, sees a redirect, and then
        // sends the whole chain again with no secret at all. So a fixture
        // that scripted one answer would leave the second request waiting
        // for one that never came. The `--location-trusted` case walks the
        // chain once and leaves the second copy unread.
        var server: test_server.TestServer = undefined;
        try server.start(&.{ redirect, redirect });
        defer server.stop();

        const url = try loopbackUrlAt(&server, "/start");
        defer testing.allocator.free(url);

        const result = if (case.trusted)
            try runZurl(&.{ "-s", "-S", "-L", "--location-trusted", "-u", "alice:s3cret", url })
        else
            try runZurl(&.{ "-s", "-S", "-L", "-u", "alice:s3cret", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try testing.expectEqualStrings("the ftp peer answered\n", result.stdout);

        ftp.wait();
        try testing.expect(std.mem.startsWith(u8, ftp.commands(), case.want));
        // The password reaches neither stream, whichever way the flag went.
        try testing.expect(std.mem.indexOf(u8, result.stderr, "s3cret") == null);
    }
}

test "-w reports an ftp transfer the way curl reports one" {
    // Measured: `curl -w 'code=%{http_code} size=%{size_download}'` on an
    // `ftp://` url prints `code=000` and the size of the file.
    var server: zurl_ftp.test_server.Server = undefined;
    try server.start(.{ .body = "hello ftp body\n" });
    defer server.stop();

    const url = try std.fmt.allocPrint(testing.allocator, "ftp://127.0.0.1:{d}/f.txt", .{server.port()});
    defer testing.allocator.free(url);

    const result = try runZurl(&.{
        "-s", "-S", "-o", "/dev/null", "-w", "code=%{http_code} size=%{size_download}\n", url,
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("code=000 size=15\n", result.stdout);
}

test "--compressed writes the Accept-Encoding header, and a plain run writes none" {
    // **The flag and the header, read off the wire by the binary a user
    // runs.** Measured against curl 8.21.0 on a loopback listener:
    //
    // ```
    // curl:              (no Accept-Encoding header at all)
    // curl --compressed: Accept-Encoding: deflate, gzip, br, zstd
    // ```
    //
    // zurl wrote `accept-encoding: gzip, deflate` either way, so a server
    // could compress for zurl where it sent curl the plain body, and the
    // flag chose nothing. `br` is absent here and stays absent: nothing in
    // this build decodes it, and asking for octets it must then refuse is
    // worse than not asking.
    var server: test_server.TestServer = undefined;
    try server.startWith(
        &.{
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        },
        .{},
    );
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const plain = try runZurl(&.{ "-s", "-S", "--out-null", url });
    defer testing.allocator.free(plain.stdout);
    defer testing.allocator.free(plain.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, plain.term);

    const compressed = try runZurl(&.{ "-s", "-S", "--out-null", "--compressed", url });
    defer testing.allocator.free(compressed.stdout);
    defer testing.allocator.free(compressed.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, compressed.term);

    const first = server.requestHead(0).?;
    const second = server.requestHead(1).?;
    try testing.expectEqual(@as(usize, 0), test_server.countHeaders(first, "accept-encoding"));
    try testing.expectEqual(@as(usize, 1), test_server.countHeaders(second, "accept-encoding"));
    try testing.expect(std.mem.indexOf(
        u8,
        second,
        "accept-encoding: deflate, gzip, zstd\r\n",
    ) != null);
    try testing.expect(std.mem.indexOf(u8, second, "br") == null);
}

test "every content-encoding row matches curl's measured exit code and octets" {
    // **The whole rule, one row per measurement, pinned to curl 8.21.0 on
    // a loopback listener.** The exit code alone would not catch a wrong
    // answer here, because decoded and raw both exit 0. So each row also
    // pins what was written: `payload` is 7 octets decoded, and the gzip
    // member on the wire is 27.
    //
    // ```text
    // curl --compressed        answer gzip    exit 0, wrote 7  (decoded)
    // curl --compressed        answer br      exit 61          (no decoder here)
    // curl --compressed        answer exotic  exit 61
    // curl                     answer gzip    exit 0, wrote 27 (raw)
    // curl                     answer br      exit 0, wrote 4  (raw)
    // curl                     answer exotic  exit 0, wrote 4  (raw)
    // curl -H Accept-Encoding  answer gzip    exit 0, wrote 27 (raw)
    // ```
    //
    // The `br` rows are where this build and this machine's curl part
    // company, and only because that curl carries brotli. A curl built
    // without it answers 61, which is what `exotic` shows: curl's rule is
    // whether it has a decoder, not whether the coding was offered.
    const gzip_member = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x03\x2b\x48\xac\xcc\xc9\x4f\x4c" ++
        "\x01\x00\x15\x6a\x2c\x42\x07\x00\x00\x00";
    const gzip_body = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 27\r\n" ++
        "Connection: close\r\n\r\n" ++ gzip_member;
    const br_body = "HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nContent-Length: 4\r\n" ++
        "Connection: close\r\n\r\nABCD";
    const exotic_body = "HTTP/1.1 200 OK\r\nContent-Encoding: exotic\r\nContent-Length: 4\r\n" ++
        "Connection: close\r\n\r\nABCD";

    const Row = struct {
        /// What the peer answers.
        response: []const u8,
        /// The flag under test, or null for a run that names none.
        flag: ?[]const u8,
        /// curl's measured exit code, which is this build's too.
        exit: u8,
        /// The octets written out, and empty for a run that writes none.
        wrote: []const u8,
    };

    const rows = [_]Row{
        .{ .response = gzip_body, .flag = "--compressed", .exit = 0, .wrote = "payload" },
        .{ .response = br_body, .flag = "--compressed", .exit = 61, .wrote = "" },
        .{ .response = exotic_body, .flag = "--compressed", .exit = 61, .wrote = "" },
        .{ .response = gzip_body, .flag = null, .exit = 0, .wrote = gzip_member },
        .{ .response = br_body, .flag = null, .exit = 0, .wrote = "ABCD" },
        .{ .response = exotic_body, .flag = null, .exit = 0, .wrote = "ABCD" },
        // A caller's own offer puts a header on the wire and asks for no
        // decoding, which is what curl does with it.
        .{ .response = gzip_body, .flag = "-HAccept-Encoding: gzip", .exit = 0, .wrote = gzip_member },
    };

    for (rows) |row| {
        var server: test_server.TestServer = undefined;
        try server.start(&.{row.response});
        defer server.stop();

        const url = try loopbackUrl(&server);
        defer testing.allocator.free(url);

        const result = if (row.flag) |flag|
            try runZurl(&.{ "-s", "-S", flag, url })
        else
            try runZurl(&.{ "-s", "-S", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = row.exit }, result.term);
        try testing.expectEqualStrings(row.wrote, result.stdout);
        // A refusal says why on stderr, and a success says nothing there.
        try testing.expectEqual(row.exit != 0, result.stderr.len != 0);
    }
}

test "--compressed decodes a gzip answer, and -w counts the decoded octets" {
    // **`%{size_download}` counts what zurl wrote out**, which is what
    // curl counts: measured against curl 8.21.0, `curl --compressed -o
    // file -w '%{size_download}'` over a gzip answer printed the decoded
    // length, not the 27 octets the peer announced.
    const gzip_body = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 27\r\n" ++
        "Connection: close\r\n\r\n" ++
        "\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x03\x2b\x48\xac\xcc\xc9\x4f\x4c\x01\x00\x15\x6a\x2c\x42\x07\x00\x00\x00";

    var server: test_server.TestServer = undefined;
    try server.start(&.{gzip_body});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{
        "-s", "-S", "--compressed", "-w", ":%{size_download}", url,
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    // The decoded body, then the count of its octets. Seven, not 27.
    try testing.expectEqualStrings("payload:7", result.stdout);
}

test "--compressed decodes a zstd answer, and -w counts the decoded octets" {
    // The coding this build added beside gzip and deflate.
    // `std.compress.zstd` ships a decoder, so it needed no C library:
    // zurl carries none beyond libc.
    const gpa = testing.allocator;
    const frame = try test_server.zstdFrame(gpa, &.{ "zstd ", "payload" }, &.{});
    defer gpa.free(frame);

    const header = try std.fmt.allocPrint(
        gpa,
        "HTTP/1.1 200 OK\r\nContent-Encoding: zstd\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
        .{frame.len},
    );
    defer gpa.free(header);
    const reply = try std.mem.concat(gpa, u8, &.{ header, frame });
    defer gpa.free(reply);

    var server: test_server.TestServer = undefined;
    try server.start(&.{reply});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer gpa.free(url);

    const result = try runZurl(&.{
        "-s", "-S", "--compressed", "-w", ":%{size_download}", url,
    });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("zstd payload:12", result.stdout);
}

test "--proto can name a protocol this build added, the way curl does" {
    // Measured against curl 8.21.0 on this machine:
    //   curl --proto -all,dict dict://127.0.0.1:1/d:x  -> exit 7, connects
    //   zurl --proto -all,dict dict://127.0.0.1:1/d:x  -> exit 2, refused
    // `-all` emptied the set, `dict` was a name the list could not read
    // and added nothing, the set was then empty, and the parser reported a
    // usage fault for a working curl command line.
    //
    // Port 1 on loopback accepts nothing, so exit 7 says the transfer got
    // as far as the dial, which is the whole point.
    const result = try runZurl(&.{ "-s", "-S", "--proto", "-all,dict", "dict://127.0.0.1:1/d:x" });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 7 }, result.term);

    // And the safe direction still holds: a list that leaves dict out
    // refuses the same url before any dial.
    const refused = try runZurl(&.{ "-s", "-S", "--proto", "-all,http", "dict://127.0.0.1:1/d:x" });
    defer testing.allocator.free(refused.stdout);
    defer testing.allocator.free(refused.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 1 }, refused.term);
    try testing.expect(std.mem.indexOf(u8, refused.stderr, "UnsupportedProtocol") != null);
}

test "the default redirect list reaches no dict, gopher, gophers, or tftp url" {
    // **The rule this build must keep for every new scheme.** A protocol
    // package registered with the client is reachable from a url the user
    // typed, and from a redirect only where `--proto-redir` names it.
    // `zurl_core.redirect.redirect_default` is an allowlist of names, and
    // none of these four is written down in it, so a `location:` header
    // naming one is refused before anything opens a socket for it.
    //
    // `--proto-redir` can name any of them, which is what curl does. The
    // help text used to promise that a redirect reaches them at no time at
    // all, and `--proto-redir all` reached `gopher://` even then.
    //
    // curl 8.21.0 refuses the same shape with exit 1 and
    // `Protocol "gopher" is disabled (in redirect)`.
    const targets = [_][]const u8{
        "dict://127.0.0.1:1/d:hello",
        "gopher://127.0.0.1:1/1/",
        "gophers://127.0.0.1:1/1/",
        "tftp://127.0.0.1:1/x",
    };
    for (targets) |target| {
        const redirect = try std.fmt.allocPrint(
            testing.allocator,
            "HTTP/1.1 302 Found\r\nLocation: {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            .{target},
        );
        defer testing.allocator.free(redirect);

        var server: test_server.TestServer = undefined;
        try server.start(&.{redirect});
        defer server.stop();

        const url = try loopbackUrlAt(&server, "/start");
        defer testing.allocator.free(url);

        const result = try runZurl(&.{ "-s", "-S", "-L", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        // Exit 1 is `CURLE_UNSUPPORTED_PROTOCOL`, the number curl gives
        // the same refusal.
        try testing.expectEqual(std.process.Child.Term{ .exited = 1 }, result.term);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "UnsupportedProtocol") != null);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "--proto-redir does not name") != null);
        // The target was never opened, so nothing of it reaches the
        // output.
        try testing.expectEqualStrings("", result.stdout);
    }
}

test "a peer that refuses a connection carries curl's own exit 7 for dict and gopher" {
    // Measured: `curl dict://127.0.0.1:1/d:hello` and
    // `curl gopher://127.0.0.1:1/1/` each exit 7, and
    // `curl gophers://127.0.0.1:1/1/` does too.
    const urls = [_][]const u8{
        "dict://127.0.0.1:1/d:hello",
        "gopher://127.0.0.1:1/1/",
        "gophers://127.0.0.1:1/1/",
    };
    for (urls) |url| {
        const result = try runZurl(&.{ "-s", "-S", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 7 }, result.term);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "CouldNotConnect") != null);
    }
}

test "a malformed url on a new scheme carries curl's own exit 3" {
    // Measured: `curl dict://`, `curl gopher://`, and `curl tftp://` each
    // exit 3 with `URL rejected: No host part in the URL`, and a port that
    // is not a number exits 3 as well.
    const urls = [_][]const u8{
        "dict://",
        "gopher://",
        "gophers://",
        "tftp://",
        "dict://127.0.0.1:notaport/d:x",
        "gopher://127.0.0.1:99999/1/",
        "tftp://[bad/x",
    };
    for (urls) |url| {
        const result = try runZurl(&.{ "-s", "-S", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 3 }, result.term);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "InvalidUrl") != null);
    }
}

test "a percent escaped line ending in a url of any new scheme is refused with exit 3" {
    // **The injection refusal, through the whole binary.** One url for
    // each protocol, each one carrying the bytes that would forge a second
    // line or a second field. No socket opens for any of them, so the
    // refusal happens before the network and not after it.
    const urls = [_][]const u8{
        "dict://127.0.0.1:1/d:a%0d%0aQUIT",
        "gopher://127.0.0.1:1/1a%0d%0ab",
        "gophers://127.0.0.1:1/1a%0d%0ab",
        "tftp://127.0.0.1:1/a%00b",
        // An FTP url can forge a command from the path and from the
        // credential, so both shapes are here.
        "ftp://127.0.0.1:1/a%0d%0aQUIT",
        "ftp://127.0.0.1:1/dir%0d%0aRETR%20secret/f.txt",
        "ftps://127.0.0.1:1/a%0d%0aDELE%20important",
        "ftp://u:p%0d%0aQUIT@127.0.0.1:1/f.txt",
        "ftp://a%0d%0aPASS%20x:p@127.0.0.1:1/f.txt",
    };
    for (urls) |url| {
        const result = try runZurl(&.{ "-s", "-S", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 3 }, result.term);
        try testing.expectEqualStrings("", result.stdout);
    }
}

test "-w reports a dict and a gopher transfer the way curl reports one" {
    // Measured: `curl -w 'code=%{http_code} size=%{size_download}'` prints
    // `code=000` for both, and the size of the whole answer.
    var server: zurl_gopher.test_server.Server = undefined;
    try server.start("0Row\t/x\t127.0.0.1\t70\r\n.\r\n");
    defer server.stop();

    const url = try std.fmt.allocPrint(
        testing.allocator,
        "gopher://127.0.0.1:{d}/1/",
        .{server.port()},
    );
    defer testing.allocator.free(url);

    const result = try runZurl(&.{
        "-s", "-S", "-o", "/dev/null", "-w", "code=%{http_code} size=%{size_download}\n", url,
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("code=000 size=25\n", result.stdout);
}

test "-x sends a plain http request through a proxy, in the absolute form" {
    // The product end of the proxy path: the real binary, a real socket,
    // and the bytes the proxy read.
    var proxy: proxy_test_server.ProxyTestServer = undefined;
    try proxy.start(.{ .kind = .http_proxy }, &.{ok("through the proxy")});
    defer proxy.stop();

    const proxy_url = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.1:{d}",
        .{proxy.port()},
    );
    defer testing.allocator.free(proxy_url);

    const result = try runZurl(&.{ "-s", "-S", "-x", proxy_url, "http://example.test/path?q=1" });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("through the proxy", result.stdout);
    try testing.expectEqualStrings(
        "GET http://example.test/path?q=1 HTTP/1.1",
        proxy_test_server.firstLine(proxy.requestHead()),
    );
}

test "http_proxy in the environment sends the request through the proxy" {
    var proxy: proxy_test_server.ProxyTestServer = undefined;
    try proxy.start(.{ .kind = .http_proxy }, &.{ok("from the environment")});
    defer proxy.stop();

    const proxy_url = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.1:{d}",
        .{proxy.port()},
    );
    defer testing.allocator.free(proxy_url);

    const result = try harness.runZurlWithEnv(
        &.{.{ .name = "http_proxy", .value = proxy_url }},
        &.{ "-s", "-S", "http://example.test/x" },
    );
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("from the environment", result.stdout);
}

test "no_proxy excludes a host, and the transfer reaches the origin instead" {
    // **Both halves in one test.** The origin fixture answers, and the
    // proxy fixture is a port that refuses every connect. A `no_proxy`
    // entry that failed to match would fail the transfer instead of
    // answering it, so the exit code alone is the proof.
    var origin: test_server.TestServer = undefined;
    try origin.start(&.{ok("straight to the origin")});
    defer origin.stop();

    const dead = try closedPort();
    const proxy_url = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}", .{dead});
    defer testing.allocator.free(proxy_url);

    const url = try loopbackUrlAt(&origin, "/x");
    defer testing.allocator.free(url);

    const result = try harness.runZurlWithEnv(&.{
        .{ .name = "http_proxy", .value = proxy_url },
        .{ .name = "no_proxy", .value = "127.0.0.1" },
    }, &.{ "-s", "-S", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("straight to the origin", result.stdout);
}

test "a host outside no_proxy still goes to the proxy, so the exclusion is not blanket" {
    // The mirror of the test above. A `no_proxy` that excluded everything
    // would pass that one alone, and this one catches it: the origin
    // fixture never accepts, and the proxy answers.
    var proxy: proxy_test_server.ProxyTestServer = undefined;
    try proxy.start(.{ .kind = .http_proxy }, &.{ok("through the proxy")});
    defer proxy.stop();

    const proxy_url = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.1:{d}",
        .{proxy.port()},
    );
    defer testing.allocator.free(proxy_url);

    const result = try harness.runZurlWithEnv(&.{
        .{ .name = "http_proxy", .value = proxy_url },
        .{ .name = "no_proxy", .value = "other.test" },
    }, &.{ "-s", "-S", "http://example.test/x" });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("through the proxy", result.stdout);
}

test "--socks5-hostname fetches through a socks proxy that resolves the host" {
    var proxy: proxy_test_server.ProxyTestServer = undefined;
    try proxy.start(.{ .kind = .socks5 }, &.{ok("through socks")});
    defer proxy.stop();

    const at = try std.fmt.allocPrint(testing.allocator, "127.0.0.1:{d}", .{proxy.port()});
    defer testing.allocator.free(at);

    const result = try runZurl(&.{
        "-s", "-S", "--socks5-hostname", at, "http://example.test:8080/x",
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("through socks", result.stdout);
    // The proxy resolved the name, which is the whole of `socks5h`.
    try testing.expectEqualStrings("example.test", proxy.target());
    try testing.expectEqual(@as(u16, 8080), proxy.targetPort());
    // And the request inside it kept the origin form: a SOCKS proxy reads
    // no HTTP at all.
    try testing.expectEqualStrings(
        "GET /x HTTP/1.1",
        proxy_test_server.firstLine(proxy.requestHead()),
    );
}

test "-U sends the credential to the proxy, and -u sends its own to the origin" {
    // **The credential rule, read off both sides of one real run.** The
    // proxy fixture demands a SOCKS5 credential, so the handshake proves
    // the proxy got its own, and the captured request proves the origin got
    // the other one and nothing of the proxy's.
    var proxy: proxy_test_server.ProxyTestServer = undefined;
    try proxy.start(.{
        .kind = .socks5,
        .socks_user = "bob",
        .socks_password = "proxypw",
    }, &.{ok("both credentials kept apart")});
    defer proxy.stop();

    const at = try std.fmt.allocPrint(testing.allocator, "127.0.0.1:{d}", .{proxy.port()});
    defer testing.allocator.free(at);

    const result = try runZurl(&.{
        "-s",                    "-S",
        "--socks5-hostname",     at,
        "-U",                    "bob:proxypw",
        "-u",                    "alice:originpw",
        "http://example.test/x",
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("both credentials kept apart", result.stdout);

    // The proxy saw its own credential and nothing of the origin's.
    const handshake = proxy.handshake();
    try testing.expect(std.mem.indexOf(u8, handshake, "proxypw") != null);
    try testing.expect(std.mem.indexOf(u8, handshake, "originpw") == null);
    try testing.expect(std.mem.indexOf(u8, handshake, "alice") == null);

    // The origin saw its own credential, once, and no proxy header at all.
    const head = proxy.requestHead();
    try testing.expectEqual(@as(usize, 1), test_server.countAuthorizationHeaders(head));
    try testing.expectEqual(@as(usize, 0), test_server.countHeaders(head, "Proxy-Authorization"));
    try testing.expect(std.mem.indexOf(u8, head, "proxypw") == null);
    // base64("alice:originpw"), which is the value that must be there.
    try testing.expect(std.mem.indexOf(u8, head, "YWxpY2U6b3JpZ2lucHc=") != null);
}

test "a proxy scheme this build does not speak exits with curl's own code" {
    // Measured against curl 8.21.0: `-x ftp://127.0.0.1` prints
    // `Unsupported proxy scheme` and exits 7.
    const result = try runZurl(&.{ "-s", "-S", "-x", "ftp://127.0.0.1", "http://example.test/x" });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 7 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "scheme") != null);
    // The sentence quotes no proxy url: one can carry a credential.
    try testing.expect(std.mem.indexOf(u8, result.stderr, "127.0.0.1") == null);
}

test "--proxy-digest stops the run instead of answering with Basic" {
    // A downgrade would put the password on the wire in reversible base64,
    // in cleartext, to a proxy that had offered a scheme where the password
    // never travels. The run stops and says so.
    const result = try runZurl(&.{ "-s", "-S", "--proxy-digest", "http://example.test/x" });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = usage_error_code }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "--proxy-digest") != null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "Basic") != null);
}

// --- The three mail protocols ---

test "a pop3 retrieval writes the message out with its dot-stuffing taken off" {
    var server: zurl_pop3.test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    const url = try std.fmt.allocPrint(
        testing.allocator,
        "pop3://127.0.0.1:{d}/1",
        .{server.port()},
    );
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-S", "-u", "alice:s3cret", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    // The fixture doubled the period on `.hidden`, and the client took it
    // off. This is byte for byte what curl 8.21.0 writes for the same
    // message, measured.
    try testing.expectEqualStrings("Subject: hi\r\n\r\nbody line\r\n.hidden\r\n", result.stdout);

    server.wait();
    // **The `CAPA` line is new, and this assertion changed with SASL.** A
    // SASL login has to know what the server offers, and RFC 1939 gives a
    // greeting no room to name a capability. This fixture answers `-ERR`,
    // so the login falls back to `USER` and `PASS` exactly as it always
    // did. See `zurl_pop3.Fetcher.saslLogin`.
    try testing.expectEqualStrings(
        "CAPA\nUSER alice\nPASS s3cret\nRETR 1\nQUIT",
        server.commands(),
    );
}

test "a pop3 url with no path lists the mailbox" {
    var server: zurl_pop3.test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    const url = try std.fmt.allocPrint(testing.allocator, "pop3://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-S", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("1 200\r\n2 120\r\n", result.stdout);

    server.wait();
    // No credential was named, so no `USER` went out, which is what curl
    // does, measured.
    try testing.expectEqualStrings("LIST\nQUIT", server.commands());
}

test "a CR in a pop3 url is refused before any connection opens" {
    var server: zurl_pop3.test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    const url = try std.fmt.allocPrint(
        testing.allocator,
        "pop3://127.0.0.1:{d}/1%0d%0aDELE%202",
        .{server.port()},
    );
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-S", "-u", "alice:s3cret", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    // curl refuses the same url with the same code, measured, but only
    // after it has opened the connection and logged in.
    try testing.expectEqual(std.process.Child.Term{ .exited = 3 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "control byte") != null);
    try testing.expectEqual(@as(usize, 0), server.connections());
}

test "an imap fetch writes only the octets of the literal" {
    var server: zurl_imap.test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    const url = try std.fmt.allocPrint(
        testing.allocator,
        "imap://127.0.0.1:{d}/INBOX;UID=1",
        .{server.port()},
    );
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-S", "-u", "alice:s3cret", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    // Byte for byte what curl 8.21.0 writes for the same answer, measured.
    try testing.expectEqualStrings("Subject: hi\r\n\r\nbody\r\n", result.stdout);

    server.wait();
    try testing.expectEqualStrings(
        "A001 LOGIN alice s3cret\nA002 SELECT INBOX\nA003 UID FETCH 1 BODY[]\nA004 LOGOUT",
        server.commands(),
    );
}

test "-X on an imap url is a whole command line and not an HTTP method" {
    var server: zurl_imap.test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    const url = try std.fmt.allocPrint(
        testing.allocator,
        "imap://127.0.0.1:{d}/INBOX",
        .{server.port()},
    );
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-S", "-u", "a:b", "-X", "FETCH 1 BODY[HEADER]", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    server.wait();
    try testing.expectEqualStrings(
        "A001 LOGIN a b\nA002 SELECT INBOX\nA003 FETCH 1 BODY[HEADER]\nA004 LOGOUT",
        server.commands(),
    );
}

test "-X on an http url still refuses a method zurl does not know" {
    // **The rule the deferred refusal must not break.** `-X` on anything
    // but a mail url is a method, and a value that is not one is exit 2
    // before any socket, exactly as it was.
    const result = try runZurl(&.{ "-s", "-S", "-X", "FETCH 1 BODY[]", "http://example.test/x" });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = usage_error_code }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "not a method zurl knows") != null);
}

test "a quote in an imap mailbox name cannot close its own argument" {
    var server: zurl_imap.test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    const url = try std.fmt.allocPrint(
        testing.allocator,
        "imap://127.0.0.1:{d}/My%22%20INBOX;UID=1",
        .{server.port()},
    );
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-S", "-u", "a:b", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    server.wait();
    // Without the escape the wire would read `SELECT "My" INBOX"`, and the
    // server would take `INBOX` as an argument the url never named. curl
    // escapes it the same way, measured.
    try testing.expect(std.mem.indexOf(
        u8,
        server.commands(),
        "A002 SELECT \"My\\\" INBOX\"",
    ) != null);
}

test "an smtp send delivers a message whose body holds a line of one period" {
    // **The dot-stuffing proof, through the installed binary.** The
    // fixture ends the `DATA` phase at an unstuffed period line and logs
    // whatever follows as commands, so a binary that did not stuff would
    // leave `RCPT TO:<evil@x>` in the command log and a short message in
    // the body.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const author = "Subject: hi\r\n\r\nline one\r\n.\r\nRCPT TO:<evil@x>\r\nline three\r\n";
    try sandbox.work.writeFile(testing.io, .{ .sub_path = "msg.txt", .data = author });

    var server: zurl_smtp.test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    const url = try std.fmt.allocPrint(
        testing.allocator,
        "smtp://127.0.0.1:{d}/mail.example.com",
        .{server.port()},
    );
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{
        "-s",          "-S",
        "--mail-from", "a@b.example",
        "--mail-rcpt", "c@d.example",
        "-T",          "msg.txt",
        url,
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("", result.stdout);

    server.wait();
    // The message arrived byte for byte as its author wrote it.
    try testing.expectEqualStrings(author, server.body());
    // And the line that could have been a command is not in the command
    // log.
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, server.commands(), "evil@x"),
    );
    try testing.expect(std.mem.indexOf(u8, server.commands(), "EHLO mail.example.com") != null);
}

test "an smtp body written with bare line feeds is stuffed too" {
    // curl stuffs only after a `CRLF`, so this body reaches a server from
    // curl with a bare period line in the middle of it, and the server
    // reads the rest as commands. Measured against curl 8.21.0.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    try sandbox.work.writeFile(testing.io, .{
        .sub_path = "msg.txt",
        .data = "line one\n.\nRCPT TO:<evil@x>\nline three\n",
    });

    var server: zurl_smtp.test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    const url = try std.fmt.allocPrint(testing.allocator, "smtp://127.0.0.1:{d}/h", .{server.port()});
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{
        "-s",          "-S",
        "--mail-from", "a@b",
        "--mail-rcpt", "c@d",
        "-T",          "msg.txt",
        url,
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    server.wait();
    try testing.expectEqualStrings(
        "line one\r\n.\r\nRCPT TO:<evil@x>\r\nline three\r\n",
        server.body(),
    );
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, server.commands(), "evil@x"),
    );
}

test "a CR in --mail-rcpt or in --mail-from is refused before any connection opens" {
    // **curl 8.21.0 sends both of these**, and the second line reaches the
    // server as another `RCPT TO`, so the message goes to somebody the
    // command line never named. Measured.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();
    try sandbox.work.writeFile(testing.io, .{ .sub_path = "msg.txt", .data = "hi\r\n" });

    const forged = "c@d>\r\nRCPT TO:<evil@x";

    for ([_][]const u8{ "--mail-rcpt", "--mail-from" }) |flag| {
        var server: zurl_smtp.test_server.Server = undefined;
        try server.start(.{});
        defer server.stop();

        const url = try std.fmt.allocPrint(testing.allocator, "smtp://127.0.0.1:{d}/h", .{server.port()});
        defer testing.allocator.free(url);

        const result = if (std.mem.eql(u8, flag, "--mail-rcpt"))
            try runZurlIn(sandbox.work, &.{
                "-s",          "-S",
                "--mail-from", "a@b",
                "--mail-rcpt", forged,
                "-T",          "msg.txt",
                url,
            })
        else
            try runZurlIn(sandbox.work, &.{
                "-s",          "-S",
                "--mail-from", forged,
                "--mail-rcpt", "c@d",
                "-T",          "msg.txt",
                url,
            });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 3 }, result.term);
        try testing.expect(std.mem.indexOf(u8, result.stderr, flag) != null);
        // The forged text is not printed back at the terminal either.
        try testing.expect(std.mem.indexOf(u8, result.stderr, "evil@x") == null);
        try testing.expectEqual(@as(usize, 0), server.connections());
    }
}

test "each mail answer the server refuses carries curl's own exit code" {
    // Every number below was measured from curl 8.21.0 against a loopback
    // fixture answering the same reply.
    {
        const rows = [_]struct { script: zurl_pop3.test_server.Script, code: u8 }{
            .{ .script = .{ .pass = "-ERR wrong password" }, .code = 67 },
            .{ .script = .{ .retr_refused = "-ERR no such message" }, .code = 8 },
            .{ .script = .{}, .code = 64 },
        };
        for (rows, 0..) |row, i| {
            var server: zurl_pop3.test_server.Server = undefined;
            try server.start(row.script);
            defer server.stop();

            const url = try std.fmt.allocPrint(
                testing.allocator,
                "pop3://127.0.0.1:{d}/1",
                .{server.port()},
            );
            defer testing.allocator.free(url);

            // The last row is the only one that asks for TLS, and this
            // fixture speaks none, so the refusal of `STLS` is the fault.
            const result = if (row.code == 64)
                try runZurl(&.{ "-s", "-S", "-u", "a:b", "--ssl-reqd", "-k", "--connect-timeout", "5", url })
            else
                try runZurl(&.{ "-s", "-S", "-u", "a:b", url });
            defer testing.allocator.free(result.stdout);
            defer testing.allocator.free(result.stderr);

            testing.expectEqual(std.process.Child.Term{ .exited = row.code }, result.term) catch |err| {
                std.debug.print("pop3 row {d} said: {s}\n", .{ i, result.stderr });
                return err;
            };
        }
    }
    {
        const rows = [_]struct {
            script: zurl_imap.test_server.Script,
            path: []const u8,
            code: u8,
        }{
            .{ .script = .{ .login = "NO wrong password" }, .path = "/INBOX;UID=1", .code = 67 },
            .{ .script = .{ .select = "NO no such mailbox" }, .path = "/INBOX;UID=1", .code = 67 },
            .{ .script = .{ .fetch = "NO no such message" }, .path = "/INBOX;UID=1", .code = 78 },
            .{ .script = .{ .list = "NO cannot list" }, .path = "/", .code = 21 },
        };
        for (rows, 0..) |row, i| {
            var server: zurl_imap.test_server.Server = undefined;
            try server.start(row.script);
            defer server.stop();

            const url = try std.fmt.allocPrint(
                testing.allocator,
                "imap://127.0.0.1:{d}{s}",
                .{ server.port(), row.path },
            );
            defer testing.allocator.free(url);

            const result = try runZurl(&.{ "-s", "-S", "-u", "a:b", url });
            defer testing.allocator.free(result.stdout);
            defer testing.allocator.free(result.stderr);

            testing.expectEqual(std.process.Child.Term{ .exited = row.code }, result.term) catch |err| {
                std.debug.print("imap row {d} said: {s}\n", .{ i, result.stderr });
                return err;
            };
        }
    }
    {
        var sandbox = try SandboxDir.init();
        defer sandbox.deinit();
        try sandbox.work.writeFile(testing.io, .{ .sub_path = "msg.txt", .data = "hi\r\n" });

        const rows = [_]struct { script: zurl_smtp.test_server.Script, code: u8 }{
            .{ .script = .{ .mail = "550 sender refused" }, .code = 55 },
            .{ .script = .{ .rcpt = "550 recipient refused" }, .code = 55 },
            .{ .script = .{ .data = "550 not now" }, .code = 55 },
            .{ .script = .{ .body_reply = "554 message rejected" }, .code = 8 },
        };
        for (rows, 0..) |row, i| {
            var server: zurl_smtp.test_server.Server = undefined;
            try server.start(row.script);
            defer server.stop();

            const url = try std.fmt.allocPrint(
                testing.allocator,
                "smtp://127.0.0.1:{d}/h",
                .{server.port()},
            );
            defer testing.allocator.free(url);

            const result = try runZurlIn(sandbox.work, &.{
                "-s",          "-S",
                "--mail-from", "a@b",
                "--mail-rcpt", "c@d",
                "-T",          "msg.txt",
                url,
            });
            defer testing.allocator.free(result.stdout);
            defer testing.allocator.free(result.stderr);

            testing.expectEqual(std.process.Child.Term{ .exited = row.code }, result.term) catch |err| {
                std.debug.print("smtp row {d} said: {s}\n", .{ i, result.stderr });
                return err;
            };
        }
    }
}

test "--ssl-reqd on a mail url sends no credential when the server refuses" {
    // **The rule this test exists for.** A transfer that asked for TLS and
    // carried on without it would put the password on the wire. Each
    // fixture speaks no TLS, so each refuses the upgrade command.
    {
        var server: zurl_pop3.test_server.Server = undefined;
        try server.start(.{});
        defer server.stop();

        const url = try std.fmt.allocPrint(testing.allocator, "pop3://127.0.0.1:{d}/1", .{server.port()});
        defer testing.allocator.free(url);

        const result = try runZurl(&.{
            "-s",         "-S", "-u",                "alice:s3cret",
            "--ssl-reqd", "-k", "--connect-timeout", "5",
            url,
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 64 }, result.term);
        server.wait();
        try testing.expectEqualStrings("STLS", server.commands());
    }
    {
        var server: zurl_imap.test_server.Server = undefined;
        try server.start(.{});
        defer server.stop();

        const url = try std.fmt.allocPrint(
            testing.allocator,
            "imap://127.0.0.1:{d}/INBOX;UID=1",
            .{server.port()},
        );
        defer testing.allocator.free(url);

        const result = try runZurl(&.{
            "-s",         "-S", "-u",                "alice:s3cret",
            "--ssl-reqd", "-k", "--connect-timeout", "5",
            url,
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 64 }, result.term);
        server.wait();
        try testing.expectEqualStrings("A001 STARTTLS", server.commands());
    }
    {
        var sandbox = try SandboxDir.init();
        defer sandbox.deinit();
        try sandbox.work.writeFile(testing.io, .{ .sub_path = "msg.txt", .data = "hi\r\n" });

        var server: zurl_smtp.test_server.Server = undefined;
        try server.start(.{});
        defer server.stop();

        const url = try std.fmt.allocPrint(testing.allocator, "smtp://127.0.0.1:{d}/h", .{server.port()});
        defer testing.allocator.free(url);

        const result = try runZurlIn(sandbox.work, &.{
            "-s",          "-S",  "--mail-from",       "a@b",
            "--mail-rcpt", "c@d", "-T",                "msg.txt",
            "--ssl-reqd",  "-k",  "--connect-timeout", "5",
            url,
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 64 }, result.term);
        server.wait();
        // RFC 3207 needs an `EHLO` before `STARTTLS`, and nothing else
        // went out.
        try testing.expectEqualStrings("EHLO h\nSTARTTLS", server.commands());
        try testing.expectEqualStrings("", server.body());
    }
}

test "a mail scheme is not in the default redirect list, and -u does not follow one into it" {
    // **Two rules, and the second one is what matters.** A redirect out of
    // HTTP into a mail protocol is refused by default, because
    // `redirect_default` names http, https, ftp, and ftps and no other. A
    // user who opts in with `--proto-redir` still does not send the
    // password: `Client.perform` takes the credential out of the options
    // at a protocol handoff unless `--location-trusted` says otherwise,
    // and a pop3 transfer with no credential logs in not at all.
    var pop3: zurl_pop3.test_server.Server = undefined;
    try pop3.start(.{});
    defer pop3.stop();

    const pop3_url = try std.fmt.allocPrint(
        testing.allocator,
        "pop3://127.0.0.1:{d}/1",
        .{pop3.port()},
    );
    defer testing.allocator.free(pop3_url);

    const redirect = try std.fmt.allocPrint(
        testing.allocator,
        "HTTP/1.1 302 Found\r\nLocation: {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        .{pop3_url},
    );
    defer testing.allocator.free(redirect);

    // The engine sends the chain twice for a credential with no
    // `--location-trusted`: once with the secret and once without.
    var server: test_server.TestServer = undefined;
    try server.start(&.{ redirect, redirect });
    defer server.stop();

    const url = try loopbackUrlAt(&server, "/start");
    defer testing.allocator.free(url);

    const result = try runZurl(&.{
        "-s", "-S", "-L", "--proto-redir", "+pop3", "-u", "alice:s3cret", url,
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("Subject: hi\r\n\r\nbody line\r\n.hidden\r\n", result.stdout);

    pop3.wait();
    // No `USER` and no `PASS` at all: the credential did not cross.
    try testing.expectEqualStrings("RETR 1\nQUIT", pop3.commands());
    try testing.expect(std.mem.indexOf(u8, result.stderr, "s3cret") == null);
}

test "a redirect into a mail scheme is refused without --proto-redir" {
    var pop3: zurl_pop3.test_server.Server = undefined;
    try pop3.start(.{});
    defer pop3.stop();

    const pop3_url = try std.fmt.allocPrint(
        testing.allocator,
        "pop3://127.0.0.1:{d}/1",
        .{pop3.port()},
    );
    defer testing.allocator.free(pop3_url);

    const redirect = try std.fmt.allocPrint(
        testing.allocator,
        "HTTP/1.1 302 Found\r\nLocation: {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        .{pop3_url},
    );
    defer testing.allocator.free(redirect);

    var server: test_server.TestServer = undefined;
    try server.start(&.{redirect});
    defer server.stop();

    const url = try loopbackUrlAt(&server, "/start");
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-S", "-L", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expect(result.term.exited != 0);
    try testing.expectEqual(@as(usize, 0), pop3.connections());
}

test "an smtp transfer with no recipient and one with no message are refused" {
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();
    try sandbox.work.writeFile(testing.io, .{ .sub_path = "msg.txt", .data = "hi\r\n" });

    var server: zurl_smtp.test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    const url = try std.fmt.allocPrint(testing.allocator, "smtp://127.0.0.1:{d}/h", .{server.port()});
    defer testing.allocator.free(url);

    {
        const result = try runZurlIn(sandbox.work, &.{
            "-s", "-S", "--mail-from", "a@b", "-T", "msg.txt", url,
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 3 }, result.term);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "--mail-rcpt") != null);
    }
    {
        const result = try runZurlIn(sandbox.work, &.{
            "-s", "-S", "--mail-from", "a@b", "--mail-rcpt", "c@d", url,
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 3 }, result.term);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "-T or -d") != null);
    }
    try testing.expectEqual(@as(usize, 0), server.connections());
}

test "-v prints the response head and never a credential" {
    // **The one guarantee a verbose mode has to keep.** A `-v` that leaked
    // a password would be worse than no verbose mode at all: it would put
    // the secret into a CI log, a journal, and a screen recording, and it
    // would do it on the run the user reached for when something was
    // already going wrong.
    //
    // Three credentials are in play here and none of them may appear: the
    // userinfo password in the url, the `-u` password, and the base64 of
    // the `Authorization` line zurl built from either.
    var server: test_server.TestServer = undefined;
    try server.start(&.{ok("body\n")});
    defer server.stop();

    const url = try std.fmt.allocPrint(
        testing.allocator,
        "http://alice:urlpassword@127.0.0.1:{d}/x",
        .{server.port()},
    );
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-v", "-s", "-u", "bob:flagpassword", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("body\n", result.stdout);

    // It says what it did: the method, the url with the password masked,
    // and the head the server sent.
    try testing.expect(std.mem.indexOf(u8, result.stderr, "* GET ") != null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "alice:***@") != null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "< HTTP/1.1 200 OK") != null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "< Content-Type: text/plain") != null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "* effective url: ") != null);

    // And no credential is anywhere in it. Not the two passwords, not the
    // base64 an `Authorization` line would carry, and no request header
    // marker at all: `-v` reads only what the server sent, which is what
    // makes the first three checks hold for every future header too.
    try testing.expect(std.mem.indexOf(u8, result.stderr, "urlpassword") == null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "flagpassword") == null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "Authorization") == null);
    // `Ym9iOmZsYWdwYXNzd29yZA==` is `bob:flagpassword` in base64.
    try testing.expect(std.mem.indexOf(u8, result.stderr, "Ym9iOmZsYWdwYXNzd29yZA") == null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "\n> ") == null);
    try testing.expect(!std.mem.startsWith(u8, result.stderr, "> "));
}

test "-v and -s together still print, which is what curl does" {
    // Measured against curl 8.21.0: `curl -v -s URL` writes the whole
    // verbose block. `-s` turns off the meter and the message a failed
    // transfer earns, and `-v` is a user asking to be told.
    var server: test_server.TestServer = undefined;
    try server.start(&.{ok("body\n")});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-v", "-s", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "< HTTP/1.1 200 OK") != null);
    // `-s` did its own half: no meter was drawn.
    try testing.expect(std.mem.indexOf(u8, result.stderr, "% Total") == null);
}

test "-i writes the response head before the body, and -o puts both in the file" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{ ok("body\n"), ok("body\n") });
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    {
        const result = try runZurl(&.{ "-i", "-s", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try testing.expect(std.mem.startsWith(u8, result.stdout, "HTTP/1.1 200 OK\r\n"));
        try testing.expect(std.mem.endsWith(u8, result.stdout, "\r\n\r\nbody\n"));
    }
    {
        // The head goes where the body goes, so an `-o` file holds both,
        // in that order and through one writer.
        const result = try runZurlIn(sandbox.work, &.{ "--show-headers", "-s", "-o", "both.bin", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try testing.expectEqualStrings("", result.stdout);

        const written = try sandbox.work.readFileAlloc(
            testing.io,
            "both.bin",
            testing.allocator,
            .limited(1024),
        );
        defer testing.allocator.free(written);
        try testing.expect(std.mem.startsWith(u8, written, "HTTP/1.1 200 OK\r\n"));
        try testing.expect(std.mem.endsWith(u8, written, "\r\n\r\nbody\n"));
    }
}

test "--stderr moves every message into the file it names" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{ok("body\n")});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-v", "-s", "--stderr", "log.txt", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    // The body still goes to standard output, and standard error is empty:
    // the messages went to the file instead.
    try testing.expectEqualStrings("body\n", result.stdout);
    try testing.expectEqualStrings("", result.stderr);

    const logged = try sandbox.work.readFileAlloc(
        testing.io,
        "log.txt",
        testing.allocator,
        .limited(4096),
    );
    defer testing.allocator.free(logged);
    try testing.expect(std.mem.indexOf(u8, logged, "* GET ") != null);
    try testing.expect(std.mem.indexOf(u8, logged, "< HTTP/1.1 200 OK") != null);
}

test "--output-dir puts the file under the directory and keeps the name" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{ok("payload")});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();
    try sandbox.work.createDirPath(testing.io, "downloads");

    const url = try loopbackUrlAt(&server, "/a.bin");
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-s", "--output-dir", "downloads", "-O", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    const written = try sandbox.work.readFileAlloc(
        testing.io,
        "downloads/a.bin",
        testing.allocator,
        .limited(64),
    );
    defer testing.allocator.free(written);
    try testing.expectEqualStrings("payload", written);
}

test "a flag this build cannot run stops the run before any socket opens" {
    // Refused by name, and the reason with it. Nothing dials: the check
    // runs before the `Client` exists, so a script that names one of these
    // never sends a request that was going to be wrong.
    //
    // The url points at a port nothing listens on, which is the proof
    // that no socket was opened: a run that reached the dial would exit 7
    // and not with the usage code.
    const url = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.1:{d}/x",
        .{try closedPort()},
    );
    defer testing.allocator.free(url);

    const Case = struct { argv: []const []const u8, name: []const u8, reason: []const u8 };
    const cases = [_]Case{
        .{ .argv = &.{ "--cert", "c.pem" }, .name = "--cert", .reason = "client certificate" },
        .{ .argv = &.{ "--pass", "hunter2" }, .name = "--pass", .reason = "client certificate" },
        .{ .argv = &.{ "--ciphers", "AES" }, .name = "--ciphers", .reason = "fixed suite list" },
        .{ .argv = &.{ "--curves", "X25519" }, .name = "--curves", .reason = "fixed curve list" },
        .{ .argv = &.{ "--trace", "t.txt" }, .name = "--trace", .reason = "no tap on the wire" },
        .{ .argv = &.{"--trace-ids"}, .name = "--trace-ids", .reason = "no tap on the wire" },
    };

    for (cases) |case| {
        var argv: [4][]const u8 = undefined;
        @memcpy(argv[0..case.argv.len], case.argv);
        argv[case.argv.len] = url;

        const result = try runZurl(argv[0 .. case.argv.len + 1]);
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = cli.usage_error_code }, result.term);
        try testing.expectEqualStrings("", result.stdout);
        try testing.expect(std.mem.indexOf(u8, result.stderr, case.name) != null);
        try testing.expect(std.mem.indexOf(u8, result.stderr, case.reason) != null);
    }

    // **And the passphrase never reached the message.** `--pass=hunter2`
    // is one argument, so a refusal that echoed argv would have written
    // the secret to standard error.
    const inline_pass = try runZurl(&.{ "--pass=hunter2", url });
    defer testing.allocator.free(inline_pass.stdout);
    defer testing.allocator.free(inline_pass.stderr);
    try testing.expect(std.mem.indexOf(u8, inline_pass.stderr, "hunter2") == null);
    try testing.expectEqual(
        std.process.Child.Term{ .exited = cli.usage_error_code },
        inline_pass.term,
    );
}

test "an unknown scheme exits 1 and a malformed url exits 3" {
    // The pair a script branches on. Measured against curl 8.21.0:
    //
    // ```
    // curl rtmp://host.invalid/          exit 1, Protocol "rtmp" not supported
    // curl nosuchscheme://host.invalid/  exit 1, Protocol not supported
    // curl ://host/                      exit 3, URL rejected
    // curl nosuch_x://host/              exit 3, an underscore is no scheme byte
    // curl http:///a                     a known scheme with no host
    // ```
    //
    // Before this, every row of the first pair was exit 3 here, so a
    // script could not tell "zurl was not built with that protocol" from
    // "you typed a bad url".
    const Case = struct { url: []const u8, code: u8, name: []const u8 };
    const cases = [_]Case{
        .{ .url = "rtmp://host.invalid/", .code = 1, .name = "UnsupportedProtocol" },
        .{ .url = "nosuchscheme://host.invalid/", .code = 1, .name = "UnsupportedProtocol" },
        // A named port never made the scheme known, so it is exit 1 too.
        .{ .url = "rtmp://host.invalid:1935/", .code = 1, .name = "UnsupportedProtocol" },
        // Every syntax rule answers first, whatever the scheme is.
        .{ .url = "://host/", .code = 3, .name = "InvalidUrl" },
        .{ .url = "nosuch_x://host/", .code = 3, .name = "InvalidUrl" },
        .{ .url = "http:///a", .code = 3, .name = "InvalidUrl" },
        .{ .url = "nosuch://host:99999/", .code = 3, .name = "InvalidUrl" },
    };

    for (cases) |case| {
        const result = try runZurl(&.{ "-s", "-S", case.url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = case.code }, result.term);
        try testing.expect(std.mem.indexOf(u8, result.stderr, case.name) != null);
    }
}

test "--disallow-username-in-url exits 67, and the password reaches neither stream" {
    // **The security rule of this flag, read off the real binary.** A url
    // is often written by somebody else: it comes from a redirect, from a
    // config file, or from a script argument. Such a url can carry
    // `user:password@` in front of the host, and a run that follows it
    // logs in as somebody the caller never chose. The flag says no url of
    // this run may carry one.
    //
    // **The refusal must not repeat the secret.** A message that echoed
    // the url would copy the password into every log and every terminal
    // recording the run reaches, which is the very leak the flag exists to
    // stop. `Args.resolveUsernameInUrl` sends the url through `safe.text`
    // for that reason, and only a run of the shipped binary proves the
    // masking survived every writer between there and standard error.
    //
    // curl 8.21.0 answers the same command line with exit 67,
    // `CURLE_LOGIN_DENIED`, and `URL rejected: Credentials was passed in
    // the URL when prohibited`. 67 is the number a script reads, so it is
    // the number zurl gives.
    //
    // The url names a port nothing listens on, so a build that reached the
    // dial would exit 7 and not 67. That is the proof no socket opened.
    const port = try closedPort();
    const url = try std.fmt.allocPrint(
        testing.allocator,
        "http://alice:s3cret@127.0.0.1:{d}/x",
        .{port},
    );
    defer testing.allocator.free(url);

    {
        const result = try runZurl(&.{ "-s", "-S", "--disallow-username-in-url", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 67 }, result.term);
        try testing.expectEqualStrings("", result.stdout);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "s3cret") == null);
        // The message still says which flag refused it and which url it
        // refused. A refusal that named neither leaves the user guessing.
        try testing.expect(std.mem.indexOf(u8, result.stderr, "--disallow-username-in-url") != null);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "alice") != null);
    }

    // **Every url of the run is checked, and not only the first.** A build
    // that refused one url at a time would fetch the clean url below and
    // only then refuse the other, and the caller asked that this run send
    // no credential at all. The clean url comes first and points at a live
    // server, so a fetch would be recorded.
    {
        var server: test_server.TestServer = undefined;
        try server.start(&.{ok("must never be fetched")});
        defer server.stop();

        const clean = try loopbackUrl(&server);
        defer testing.allocator.free(clean);

        const result = try runZurl(&.{ "-s", "-S", "--disallow-username-in-url", clean, url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 67 }, result.term);
        try testing.expectEqualStrings("", result.stdout);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "s3cret") == null);
        try testing.expectEqual(@as(?[]const u8, null), server.requestHead(0));
    }

    // **A password with no user name is a credential too.** curl refuses
    // `http://:pw@host/` the same way, measured, and a build that read the
    // user name alone would let this one through.
    {
        const bare = try std.fmt.allocPrint(
            testing.allocator,
            "http://:s3cret@127.0.0.1:{d}/x",
            .{port},
        );
        defer testing.allocator.free(bare);

        const result = try runZurl(&.{ "-s", "-S", "--disallow-username-in-url", bare });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 67 }, result.term);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "s3cret") == null);
    }

    // The control: with no flag the same url is not refused at all, and
    // the run reaches the dial instead, which is exit 7. Without this row
    // a build that refused the url for any other reason would pass.
    {
        const result = try runZurl(&.{ "-s", "-S", "--connect-timeout", "2", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 7 }, result.term);
        // And the failure message masks the password too, which is the
        // same rule on the other path out of the program.
        try testing.expect(std.mem.indexOf(u8, result.stderr, "s3cret") == null);
    }
}

test "--dump-ca-embed writes the bundle to standard output and runs no transfer" {
    // The flag a caller uses to hand this binary's own trust anchors to
    // another program. curl 8.21.0 writes the bundle it was built with and
    // fetches nothing, even for a command line that names a url. Measured.
    //
    // What comes out is the PEM file the build generated, so it carries a
    // comment line in front of each certificate the way curl's own
    // `ca-bundle.crt` does. The test therefore reads the certificates
    // inside it and not the first byte of the file.
    const alone = try runZurl(&.{"--dump-ca-embed"});
    defer testing.allocator.free(alone.stdout);
    defer testing.allocator.free(alone.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, alone.term);
    // No transfer ran, so no meter was drawn and no note was written.
    try testing.expectEqualStrings("", alone.stderr);

    const begins = std.mem.count(u8, alone.stdout, "-----BEGIN CERTIFICATE-----\n");
    const ends = std.mem.count(u8, alone.stdout, "-----END CERTIFICATE-----\n");
    try testing.expect(begins > 0);
    // One end for each beginning. A bundle cut short would still hold the
    // first marker, and a reader would then hang on a block that never
    // closed.
    try testing.expectEqual(begins, ends);

    // **A url on the command line changes nothing.** The flag answers
    // first and no socket opens, so the live server below is never asked
    // for anything, and the bytes are the same bytes as the run above.
    var server: test_server.TestServer = undefined;
    try server.start(&.{ok("must never be fetched")});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const beside = try runZurl(&.{ "--dump-ca-embed", url });
    defer testing.allocator.free(beside.stdout);
    defer testing.allocator.free(beside.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, beside.term);
    try testing.expectEqualStrings(alone.stdout, beside.stdout);
    try testing.expectEqualStrings("", beside.stderr);
    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(0));
}

test "--skip-existing leaves the file it finds and still fetches a url that writes no file" {
    // **The decision happens before the socket opens.** That is what
    // separates this flag from `--no-clobber`: a run that resumes a batch
    // download must not ask the server again for every file it already
    // holds. The one server here carries a single response, and the two
    // runs that skip must leave it unused.
    //
    // Measured against curl 8.21.0: with the file already there,
    // `--skip-existing -O URL` left the file byte for byte and exited 0.
    var server: test_server.TestServer = undefined;
    try server.start(&.{ok("from the server")});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const already = "already here, and untouched\n";
    try sandbox.work.writeFile(testing.io, .{ .sub_path = "a.bin", .data = already });

    const url = try loopbackUrlAt(&server, "/a.bin");
    defer testing.allocator.free(url);

    {
        const result = try runZurlIn(sandbox.work, &.{ "--skip-existing", "-O", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try testing.expectEqualStrings("", result.stdout);
        // IronStyle asks that recovery never stay silent, so the user
        // hears which url was left alone and why.
        try testing.expect(std.mem.indexOf(u8, result.stderr, "--skip-existing") != null);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "a.bin") != null);
        try testing.expectEqual(@as(?[]const u8, null), server.requestHead(0));

        const kept = try sandbox.work.readFileAlloc(testing.io, "a.bin", testing.allocator, .limited(128));
        defer testing.allocator.free(kept);
        try testing.expectEqualStrings(already, kept);
    }

    // `-s` silences the note, the way it silences every other note. The
    // file is still left alone and the server is still never asked.
    {
        const result = try runZurlIn(sandbox.work, &.{ "-s", "--skip-existing", "-O", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try testing.expectEqualStrings("", result.stdout);
        try testing.expectEqualStrings("", result.stderr);
        try testing.expectEqual(@as(?[]const u8, null), server.requestHead(0));

        const kept = try sandbox.work.readFileAlloc(testing.io, "a.bin", testing.allocator, .limited(128));
        defer testing.allocator.free(kept);
        try testing.expectEqualStrings(already, kept);
    }

    // **A url with no file to find still runs.** The body goes to standard
    // output here, so there is no path to look for, and the flag passes
    // the url through. This row also consumes the one response, so it
    // proves the two runs above really left it there.
    {
        const result = try runZurlIn(sandbox.work, &.{ "-s", "--skip-existing", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try testing.expectEqualStrings("from the server", result.stdout);
        try testing.expect(std.mem.startsWith(u8, server.requestHead(0).?, "GET /a.bin "));
    }
}

test "--out-null reads the whole body, writes it nowhere, and still reports the transfer" {
    // The flag a caller uses to measure a transfer without keeping it. The
    // body must still be read to its end, because a run that stopped
    // reading would report a size the peer never finished sending and
    // would leave the connection half read.
    //
    // Measured against curl 8.21.0: `--out-null -w '%{http_code}'` printed
    // the status, wrote no file, and put no body byte on standard output.
    {
        var server: test_server.TestServer = undefined;
        try server.start(&.{ok("payload")});
        defer server.stop();

        var sandbox = try SandboxDir.init();
        defer sandbox.deinit();

        const url = try loopbackUrlAt(&server, "/a.bin");
        defer testing.allocator.free(url);

        const result = try runZurlIn(sandbox.work, &.{
            "-s", "--out-null", "-w", "%{http_code}:%{size_download}", url,
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        // The report alone. No byte of `payload` is in it, and the byte
        // count says the seven bytes really were read and thrown away.
        try testing.expectEqualStrings("200:7", result.stdout);
        try testing.expectEqualStrings("", result.stderr);
        // The transfer really ran, so the server saw the request.
        try testing.expect(std.mem.startsWith(u8, server.requestHead(0).?, "GET /a.bin "));
        // And nothing was written anywhere, not under the name the url
        // carries and not under any other name.
        try sandbox.expectNothingWritten();
    }

    // **The last of `--out-null` and `--remote-name-all` wins.** Both fill
    // the one tail destination, so the pair reads in either order and the
    // later flag decides. A build where one of them always won would make
    // the order of a config file change the answer.
    {
        var server: test_server.TestServer = undefined;
        try server.start(&.{ok("payload")});
        defer server.stop();

        var sandbox = try SandboxDir.init();
        defer sandbox.deinit();

        const url = try loopbackUrlAt(&server, "/a.bin");
        defer testing.allocator.free(url);

        const result = try runZurlIn(sandbox.work, &.{
            "-s", "--remote-name-all", "--out-null", "-w", "%{http_code}", url,
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try testing.expectEqualStrings("200", result.stdout);
        try sandbox.expectNothingWritten();
    }
    {
        var server: test_server.TestServer = undefined;
        try server.start(&.{ok("payload")});
        defer server.stop();

        var sandbox = try SandboxDir.init();
        defer sandbox.deinit();

        const url = try loopbackUrlAt(&server, "/a.bin");
        defer testing.allocator.free(url);

        const result = try runZurlIn(sandbox.work, &.{
            "-s", "--out-null", "--remote-name-all", url,
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try testing.expectEqualStrings("", result.stdout);

        const written = try sandbox.work.readFileAlloc(testing.io, "a.bin", testing.allocator, .limited(64));
        defer testing.allocator.free(written);
        try testing.expectEqualStrings("payload", written);
    }
}

test "--remote-name-all gives every uncovered url its own file, and an explicit -o still wins" {
    // The flag turns the tail destination into `-O`, so a url the `-o`
    // list does not reach writes a file named from its own last path
    // element. Measured against curl 8.21.0 on a loopback listener:
    // `--remote-name-all URL1 URL2` wrote one file for each url, and
    // `-o named URL1 URL2` with the flag wrote `named` and one file.
    {
        var server: test_server.TestServer = undefined;
        try server.start(&.{ ok("alpha"), ok("bravo") });
        defer server.stop();

        var sandbox = try SandboxDir.init();
        defer sandbox.deinit();

        const url_a = try loopbackUrlAt(&server, "/alpha.bin");
        defer testing.allocator.free(url_a);
        const url_b = try loopbackUrlAt(&server, "/bravo.bin");
        defer testing.allocator.free(url_b);

        const result = try runZurlIn(sandbox.work, &.{ "-s", "--remote-name-all", url_a, url_b });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        // No body reaches standard output, which is the whole point of the
        // flag: a second url used to truncate what the first one wrote.
        try testing.expectEqualStrings("", result.stdout);

        const wanted = [_]struct { name: []const u8, body: []const u8 }{
            .{ .name = "alpha.bin", .body = "alpha" },
            .{ .name = "bravo.bin", .body = "bravo" },
        };
        for (wanted) |want| {
            const written = try sandbox.work.readFileAlloc(testing.io, want.name, testing.allocator, .limited(64));
            defer testing.allocator.free(written);
            try testing.expectEqualStrings(want.body, written);
        }
    }

    // **An explicit `-o` covers its own url and nothing else.** The `-o`
    // list is paired with the url list in order, so `-o named URL1 URL2`
    // sends URL1 to `named` and leaves URL2 to the tail the flag set. A
    // build where the flag overrode the list would ignore the name the
    // user typed.
    {
        var server: test_server.TestServer = undefined;
        try server.start(&.{ ok("alpha"), ok("bravo") });
        defer server.stop();

        var sandbox = try SandboxDir.init();
        defer sandbox.deinit();

        const url_a = try loopbackUrlAt(&server, "/alpha.bin");
        defer testing.allocator.free(url_a);
        const url_b = try loopbackUrlAt(&server, "/bravo.bin");
        defer testing.allocator.free(url_b);

        const result = try runZurlIn(sandbox.work, &.{
            "-s", "-o", "named.bin", "--remote-name-all", url_a, url_b,
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try testing.expectEqualStrings("", result.stdout);

        const named = try sandbox.work.readFileAlloc(testing.io, "named.bin", testing.allocator, .limited(64));
        defer testing.allocator.free(named);
        try testing.expectEqualStrings("alpha", named);

        const tail = try sandbox.work.readFileAlloc(testing.io, "bravo.bin", testing.allocator, .limited(64));
        defer testing.allocator.free(tail);
        try testing.expectEqualStrings("bravo", tail);

        // And the name the url carries was not used beside the name the
        // user typed. Two files for one url would double the download.
        try testing.expectError(
            error.FileNotFound,
            sandbox.work.statFile(testing.io, "alpha.bin", .{}),
        );
    }
}

test "--url-query adds to the query, and a -d body still goes out beside it" {
    // **This is the difference from `-G`.** `-G` moves the `-d` data into
    // the query and sends no body at all. `--url-query` adds to the query
    // and leaves the body where it was, so a caller can send a form and
    // still name a search term in the url.
    //
    // The argument is read exactly the way `--data-urlencode` reads its
    // own, so a space becomes `+` and an `&` becomes `%26`. Measured
    // against curl 8.21.0 on a loopback listener.
    var server: test_server.TestServer = undefined;
    try server.start(&.{ ok("one"), ok("two") });
    defer server.stop();

    // A url that already carries a query, so the separator is an `&` and
    // never a second `?`.
    const with_query = try loopbackUrlAt(&server, "/p?x=1");
    defer testing.allocator.free(with_query);

    const first = try runZurl(&.{ "-s", "--url-query", "ab=c d&e", with_query });
    defer testing.allocator.free(first.stdout);
    defer testing.allocator.free(first.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, first.term);

    const first_head = server.requestHead(0).?;
    // The name goes out as it was written and the content is encoded,
    // which is the `--data-urlencode` rule.
    try testing.expect(std.mem.startsWith(u8, first_head, "GET /p?x=1&ab=c+d%26e HTTP/1.1\r\n"));

    // **The body still goes out.** A `-d` beside the flag makes this a
    // POST with a real `Content-Length`, and the query is on the request
    // line at the same time.
    const plain = try loopbackUrlAt(&server, "/p");
    defer testing.allocator.free(plain);

    const second = try runZurl(&.{ "-s", "--url-query", "q=1", "-d", "k=v", plain });
    defer testing.allocator.free(second.stdout);
    defer testing.allocator.free(second.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, second.term);

    const second_head = server.requestHead(1).?;
    try testing.expect(std.mem.startsWith(u8, second_head, "POST /p?q=1 HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, second_head, "content-length: 3\r\n") != null);
    // The data stayed in the body and was not moved into the query, which
    // is what `-G` would have done with it.
    try testing.expectEqualStrings("k=v", server.requestBody(1).?);
    try testing.expect(std.mem.indexOf(u8, second_head, "k=v HTTP") == null);
}

test "--oauth2-bearer sends the token on the first request and outranks -u" {
    // A bearer token answers no challenge, so it goes out on the first
    // request: there is no bearer challenge to wait for. And it is the one
    // credential the caller named, so a `-u` beside it must not reach the
    // wire at all. Measured against curl 8.21.0: `--oauth2-bearer t -u a:b`
    // sent `Authorization: Bearer t` and sent no Basic value at any point.
    var server: test_server.TestServer = undefined;
    try server.start(&.{ ok("one"), ok("two") });
    defer server.stop();

    const url = try loopbackUrlAt(&server, "/x");
    defer testing.allocator.free(url);

    const alone = try runZurl(&.{ "-s", "--oauth2-bearer", "tok-123", url });
    defer testing.allocator.free(alone.stdout);
    defer testing.allocator.free(alone.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, alone.term);

    const alone_head = server.requestHead(0).?;
    try testing.expect(std.mem.indexOf(u8, alone_head, "Bearer tok-123") != null);
    // RFC 7235 allows one. A second line lets a server read the first and
    // ignore what the client meant to send.
    try testing.expectEqual(@as(usize, 1), test_server.countAuthorizationHeaders(alone_head));

    const beside = try runZurl(&.{
        "-s", "--oauth2-bearer", "tok-123", "-u", "alice:s3cret", url,
    });
    defer testing.allocator.free(beside.stdout);
    defer testing.allocator.free(beside.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, beside.term);

    const beside_head = server.requestHead(1).?;
    try testing.expect(std.mem.indexOf(u8, beside_head, "Bearer tok-123") != null);
    try testing.expectEqual(@as(usize, 1), test_server.countAuthorizationHeaders(beside_head));
    // base64("alice:s3cret"), the value a Basic line would have carried.
    // Neither the encoded form nor the cleartext reaches the peer.
    try testing.expect(std.mem.indexOf(u8, beside_head, "YWxpY2U6czNjcmV0") == null);
    try testing.expect(std.mem.indexOf(u8, beside_head, "s3cret") == null);
}

test "a flag this build refuses by name gives the reason, and never calls it unknown" {
    // **The difference between "zurl does not know that flag" and "zurl
    // knows it and will not do it".** The second one is a promise the
    // build cannot keep, so it stops the run rather than fail quietly.
    // A user who read `unknown flag` for one of these would go looking for
    // a typo that is not there.
    //
    // The url names a port nothing listens on, which proves no socket
    // opened: a run that reached the dial would exit 7 and not 2.
    const url = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.1:{d}/x",
        .{try closedPort()},
    );
    defer testing.allocator.free(url);

    const Case = struct { argv: []const []const u8, name: []const u8, reason: []const u8 };
    const cases = [_]Case{
        // `--ssl` carries on in the clear when a server refuses TLS, so a
        // credential goes out anyway. That is the one refusal here that is
        // a security rule and not a missing feature.
        .{ .argv = &.{"--ssl"}, .name = "--ssl", .reason = "carries on in the clear" },
        .{ .argv = &.{ "--telnet-option", "TTYPE=vt100" }, .name = "--telnet-option", .reason = "no telnet subnegotiation" },
        .{ .argv = &.{"--ftp-ssl-ccc"}, .name = "--ftp-ssl-ccc", .reason = "never takes TLS back off a control connection" },
    };

    for (cases) |case| {
        var argv: [3][]const u8 = undefined;
        @memcpy(argv[0..case.argv.len], case.argv);
        argv[case.argv.len] = url;

        const result = try runZurl(argv[0 .. case.argv.len + 1]);
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = cli.usage_error_code }, result.term);
        try testing.expectEqualStrings("", result.stdout);
        // The shape is `zurl: option '--name': sentence`.
        try testing.expect(std.mem.indexOf(u8, result.stderr, "option '") != null);
        try testing.expect(std.mem.indexOf(u8, result.stderr, case.name) != null);
        try testing.expect(std.mem.indexOf(u8, result.stderr, case.reason) != null);
        // **And never the other message.** The flag is known here.
        try testing.expect(std.mem.indexOf(u8, result.stderr, "unknown flag") == null);
    }

    // The other half of the rule, so the check above measures something:
    // a flag nobody knows really does read `unknown flag`.
    const unknown = try runZurl(&.{ "--no-such-flag-at-all", url });
    defer testing.allocator.free(unknown.stdout);
    defer testing.allocator.free(unknown.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = cli.usage_error_code }, unknown.term);
    try testing.expect(std.mem.indexOf(u8, unknown.stderr, "unknown flag") != null);
}

test "a flag this build accepts and ignores runs the transfer and changes no byte of it" {
    // **Accepted and inert is a claim about the wire, not about the exit
    // code.** Each flag below names a state this build is already in, so a
    // script that carries it must run and must send the same request as a
    // script that does not. A test that read the exit code alone would
    // pass for a flag that quietly added a header.
    //
    // The control runs first and every other run is compared to it byte
    // for byte.
    var server: test_server.TestServer = undefined;
    try server.start(&.{ ok("one"), ok("two"), ok("three"), ok("four") });
    defer server.stop();

    const url = try loopbackUrlAt(&server, "/x");
    defer testing.allocator.free(url);

    const control = try runZurl(&.{ "-s", url });
    defer testing.allocator.free(control.stdout);
    defer testing.allocator.free(control.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, control.term);
    try testing.expectEqualStrings("one", control.stdout);

    const control_head = server.requestHead(0).?;

    // `--path-as-is` asks that a `..` reach the server, and zurl never
    // squashes one. `--tcp-fastopen` asks for a TCP option this build does
    // not use. `--tcp-nodelay` asks for the state zurl is already in,
    // because Nagle is off here by default.
    const flags = [_][]const u8{ "--path-as-is", "--tcp-fastopen", "--tcp-nodelay" };
    for (flags, 1..) |flag, index| {
        const result = try runZurl(&.{ "-s", flag, url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try testing.expectEqualStrings("", result.stderr);
        // The head the peer received, and not the parsed request. Only the
        // bytes on the wire can say the flag added nothing.
        try testing.expectEqualStrings(control_head, server.requestHead(index).?);
    }
}

test "--post301 keeps the method and the body across a 301, and -L alone does not" {
    // **A kept body reaches whichever host the first server named**, so
    // keeping one is a deliberate choice by the user and never the
    // default. curl reads it the same way, and `-L` alone turns a POST
    // into a GET on a 301, a 302, and a 303.
    const moved = "HTTP/1.1 301 Moved Permanently\r\nLocation: /moved\r\n" ++
        "Content-Length: 0\r\nConnection: close\r\n\r\n";

    // Two runs on one server, four responses: the first hop and the target
    // of each run.
    var server: test_server.TestServer = undefined;
    try server.start(&.{ moved, ok("arrived"), moved, ok("arrived") });
    defer server.stop();

    const url = try loopbackUrlAt(&server, "/first");
    defer testing.allocator.free(url);

    const dropped = try runZurl(&.{ "-s", "-L", "-d", "a=1", url });
    defer testing.allocator.free(dropped.stdout);
    defer testing.allocator.free(dropped.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, dropped.term);
    try testing.expectEqualStrings("arrived", dropped.stdout);

    try testing.expect(std.mem.startsWith(u8, server.requestHead(0).?, "POST /first HTTP/1.1\r\n"));
    const dropped_hop = server.requestHead(1).?;
    try testing.expect(std.mem.startsWith(u8, dropped_hop, "GET /moved HTTP/1.1\r\n"));
    // The framing header goes with the body. A `Content-Length` left on a
    // request with no body lets a peer read the next request as this
    // request's body.
    try testing.expect(std.mem.indexOf(u8, dropped_hop, "content-length") == null);
    try testing.expectEqualStrings("", server.requestBody(1).?);

    const kept = try runZurl(&.{ "-s", "-L", "--post301", "-d", "a=1", url });
    defer testing.allocator.free(kept.stdout);
    defer testing.allocator.free(kept.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, kept.term);
    try testing.expectEqualStrings("arrived", kept.stdout);

    const kept_hop = server.requestHead(3).?;
    try testing.expect(std.mem.startsWith(u8, kept_hop, "POST /moved HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, kept_hop, "content-length: 3\r\n") != null);
    try testing.expectEqualStrings("a=1", server.requestBody(3).?);
}

test "--follow is -L, and it keeps no body of its own" {
    // The help line calls `--follow` the newer spelling of `-L`, and the
    // two answer the same for every command line that does not name `-X`.
    // Measured against curl 8.21.0 on a loopback pair: `--follow -d a=1`
    // sent `GET /moved` with no body, which is what `-L -d a=1` sends.
    //
    // **It is not the three `--post30x` flags.** Those keep a body across a
    // redirect and `--follow` never does, so a build that made the one
    // flag mean all four would send a body to a host the user did not
    // choose.
    const moved = "HTTP/1.1 302 Found\r\nLocation: /moved\r\n" ++
        "Content-Length: 0\r\nConnection: close\r\n\r\n";

    var server: test_server.TestServer = undefined;
    try server.start(&.{ moved, ok("arrived") });
    defer server.stop();

    const url = try loopbackUrlAt(&server, "/first");
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "--follow", "-d", "a=1", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    // The redirect really was followed, so the flag is the follower.
    try testing.expectEqualStrings("arrived", result.stdout);

    try testing.expect(std.mem.startsWith(u8, server.requestHead(0).?, "POST /first HTTP/1.1\r\n"));
    const hop = server.requestHead(1).?;
    try testing.expect(std.mem.startsWith(u8, hop, "GET /moved HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, hop, "content-length") == null);
    try testing.expectEqualStrings("", server.requestBody(1).?);
}

test "-u on an smtp url authenticates through the installed binary" {
    // **The refusal this task lifted, proved gone through the binary.**
    // `-u` on an `smtp://` url used to be exit 4 before any dial, because
    // this build had no `AUTH` command and sending the message
    // unauthenticated would have been a control that failed open. It now
    // runs a SASL exchange, and the credential reaches the server inside
    // the base64 of `AUTH PLAIN`.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    try sandbox.work.writeFile(testing.io, .{
        .sub_path = "msg.txt",
        .data = "Subject: hi\r\n\r\nhello\r\n",
    });

    var server: zurl_smtp.test_server.Server = undefined;
    try server.start(.{
        .ehlo = &.{ "250-fixture", "250-SIZE 1000000", "250-AUTH PLAIN", "250 8BITMIME" },
    });
    defer server.stop();

    const url = try std.fmt.allocPrint(
        testing.allocator,
        "smtp://127.0.0.1:{d}/mail.example.com",
        .{server.port()},
    );
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{
        "-s",          "-S",
        "-u",          "alice:s3cret",
        "--mail-from", "a@b.example",
        "--mail-rcpt", "c@d.example",
        "-T",          "msg.txt",
        url,
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("", result.stdout);

    server.wait();
    // Measured from curl 8.21.0 on a fixture offering `PLAIN` alone.
    try testing.expect(std.mem.indexOf(u8, server.commands(), "AUTH PLAIN") != null);
    try testing.expect(
        std.mem.indexOf(u8, server.commands(), "AGFsaWNlAHMzY3JldA==") != null,
    );
    // The password is nowhere on the wire in the clear.
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, server.commands(), "s3cret"),
    );
    try testing.expectEqualStrings("Subject: hi\r\n\r\nhello\r\n", server.body());
}

test "a refused smtp login sends no message, and the exit code says 67" {
    // **The failure the P2 review caught, closed through the binary.** A
    // login that failed must not turn into an unauthenticated send.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    try sandbox.work.writeFile(testing.io, .{ .sub_path = "msg.txt", .data = "hi\r\n" });

    var server: zurl_smtp.test_server.Server = undefined;
    try server.start(.{
        .ehlo = &.{ "250-fixture", "250-AUTH PLAIN", "250 8BITMIME" },
        .auth_reply = "535 authentication failed",
    });
    defer server.stop();

    const url = try std.fmt.allocPrint(
        testing.allocator,
        "smtp://127.0.0.1:{d}/h",
        .{server.port()},
    );
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{
        "-s",          "-S",
        "-u",          "alice:s3cret",
        "--mail-from", "a@b.example",
        "--mail-rcpt", "c@d.example",
        "-T",          "msg.txt",
        url,
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    // curl's own code for a refused mail login, measured.
    try testing.expectEqual(std.process.Child.Term{ .exited = 67 }, result.term);
    // The message never names the credential.
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, result.stderr, "s3cret"),
    );

    server.wait();
    // No `MAIL FROM` and no message.
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, server.commands(), "MAIL FROM"),
    );
    try testing.expectEqualStrings("", server.body());
}

test "--login-options and --sasl-ir reach a mail login through the binary" {
    // These two were refused by name at `Args` until SASL landed. The
    // proof that they carry behaviour is the wire: `--login-options`
    // picks the weaker of the two mechanisms offered, and `--sasl-ir`
    // puts the message on the `AUTH` line itself.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    try sandbox.work.writeFile(testing.io, .{ .sub_path = "msg.txt", .data = "hi\r\n" });

    var server: zurl_smtp.test_server.Server = undefined;
    try server.start(.{
        .ehlo = &.{ "250-fixture", "250-AUTH PLAIN LOGIN CRAM-MD5", "250 8BITMIME" },
    });
    defer server.stop();

    const url = try std.fmt.allocPrint(
        testing.allocator,
        "smtp://127.0.0.1:{d}/h",
        .{server.port()},
    );
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{
        "-s",              "-S",
        "-u",              "alice:s3cret",
        "--login-options", "AUTH=PLAIN",
        "--sasl-ir",       "--sasl-authzid",
        "admin",           "--mail-from",
        "a@b.example",     "--mail-rcpt",
        "c@d.example",     "-T",
        "msg.txt",         url,
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    server.wait();
    // One line, and the authzid is the first field of it. The same offer
    // with no `--login-options` draws `AUTH CRAM-MD5` from both programs.
    try testing.expect(
        std.mem.indexOf(u8, server.commands(), "AUTH PLAIN YWRtaW4AYWxpY2UAczNjcmV0") != null,
    );
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, server.commands(), "CRAM-MD5"),
    );
}

test "an imap login uses SASL when the greeting names a mechanism" {
    var server: zurl_imap.test_server.Server = undefined;
    try server.start(.{
        .greeting = "* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] fixture ready",
    });
    defer server.stop();

    const url = try std.fmt.allocPrint(
        testing.allocator,
        "imap://127.0.0.1:{d}/INBOX;UID=1",
        .{server.port()},
    );
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-S", "-u", "alice:s3cret", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("Subject: hi\r\n\r\nbody\r\n", result.stdout);

    server.wait();
    try testing.expect(
        std.mem.indexOf(u8, server.commands(), "AUTHENTICATE PLAIN") != null,
    );
    // No cleartext `LOGIN` at all.
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, server.commands(), "LOGIN alice"),
    );
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, server.commands(), "s3cret"),
    );
}

test "a pop3 login uses SASL when the CAPA answer names a mechanism" {
    var server: zurl_pop3.test_server.Server = undefined;
    try server.start(.{ .capa = "TOP\r\nUIDL\r\nSASL PLAIN\r\nUSER\r\n" });
    defer server.stop();

    const url = try std.fmt.allocPrint(
        testing.allocator,
        "pop3://127.0.0.1:{d}/1",
        .{server.port()},
    );
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-S", "-u", "alice:s3cret", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("Subject: hi\r\n\r\nbody line\r\n.hidden\r\n", result.stdout);

    server.wait();
    try testing.expect(std.mem.indexOf(u8, server.commands(), "AUTH PLAIN") != null);
    // No cleartext `USER` and no `PASS`.
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, server.commands(), "PASS "),
    );
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, server.commands(), "s3cret"),
    );
}

test "the body goes where the standard output description points, not to offset zero" {
    // **A process does not own the offset of a descriptor it inherited.**
    // `Io.File.Writer.init` selects `.positional`, which writes through
    // `pwrite` at an offset the writer counts from zero. Standard output
    // is not that: the shell sets its offset, and a second program may
    // share it. So `{ echo x; zurl url; } > log` wrote the body over the
    // shell's line, and the file read `ZURLBODYROM-SHELL` where curl
    // gives both lines whole.
    //
    // This test hands the child a file that already holds a prefix, with
    // the offset left past it, which is exactly what a shell does.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const prefix = "PREFIX-FROM-SHELL\n";
    const body = "hello world\n";

    var server: test_server.TestServer = undefined;
    try server.start(&.{ok(body)});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    var out = try sandbox.work.createFile(testing.io, "log", .{});
    defer out.close(testing.io);

    var write_buffer: [64]u8 = undefined;
    var out_writer = out.writerStreaming(testing.io, &write_buffer);
    try out_writer.interface.writeAll(prefix);
    try out_writer.interface.flush();

    const term = try harness.runZurlWithStdout(out, &.{ "-s", url });
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    const got = try sandbox.work.readFileAlloc(testing.io, "log", testing.allocator, .limited(1024));
    defer testing.allocator.free(got);

    // The prefix survives whole and the body follows it. A positional
    // write would have put the body at offset zero and eaten the prefix.
    try testing.expectEqualStrings(prefix ++ body, got);
}

test "a head that ends on two line feeds is read, and the body is written" {
    // **This head crashed the shipped binary.** `std.http.HeadParser` calls
    // it finished at 17 octets, and `std.http.HeaderIterator.init` then
    // unwraps a null looking for the carriage return it never held. A
    // build with safety checks stopped on `attempt to use null value`, and
    // a `ReleaseSmall` build exited 134, which is a crash. A server writes
    // 17 octets to reach it.
    //
    // The crash is closed by `engine.HeadFields`, which reads a head the
    // way `std.http.HeadParser` does. The transfer then succeeds, because
    // `h1.parseRefusedHead` puts a carriage return before each bare line
    // feed in a copy and reads that. Measured against curl 8.21.0 over a
    // loopback fixture: curl exits 0 and writes the body, so zurl does.
    //
    // The head here is 42 octets. That is not arbitrary: see the test
    // below on `std.http.HeadParser`, which frames only some bare line
    // feed heads and drops the rest.
    //
    // Any signal here is the crash coming back.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\nX-A: 1\nContent-Length: 4\n\nBODY"});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{url});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expect(result.term == .exited);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("BODY", result.stdout);
}

test "a head with no field at all and two line feeds is read" {
    // The shortest head that reached the crash, and the one a caller is
    // least likely to see: no field, so no `Content-Length`, and the body
    // ends when the connection closes. curl reads it and exits 0.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\n\nBODY"});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{url});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expect(result.term == .exited);
    try testing.expectEqualStrings("BODY", result.stdout);
}

test "a bare line feed head std frames wrongly is refused, and never crashes" {
    // **`std.http.HeadParser` frames only some heads that end on two line
    // feeds, and the length decides which.** Fed a buffer that holds the
    // head and the first octets of the body together, which is how a
    // socket delivers a small answer, `feed` misses the two line feeds and
    // reports `start` instead of `finished`. It then reads to the end of
    // the connection and `receiveHead` answers `HttpRequestTruncated`.
    //
    // Measured over head lengths 20 to 120, with a four octet body after
    // the head: 27 of 41 lengths are framed wrongly. The same head fed one
    // octet at a time is framed correctly, so the fault is in the bulk
    // path of `feed` and not in the head.
    //
    // This is the reason `-i` and the body cannot match curl for every
    // such head. The repair in `h1.parseRefusedHead` never runs, because
    // `receiveHead` gives it no head to repair. Closing the gap needs this
    // build to frame heads itself rather than through
    // `std.http.HeadParser`.
    //
    // curl 8.21.0 reads this answer and exits 0. zurl answers 26, a read
    // fault, which is honest: it did not read a head. **What matters here
    // is that it exits rather than faults.** If `std` is fixed, this test
    // fails and says so, and the answer becomes exit 0 with the body.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\nContent-Encoding: br\nContent-Length: 4\n\nBODY"});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{url});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expect(result.term == .exited);
    try testing.expectEqual(std.process.Child.Term{ .exited = 26 }, result.term);
}

test "a head dump shows the field name the peer wrote and not the hidden one" {
    // `parseRefusedHead` overwrites one octet of every `content-encoding`
    // field name so `std` stops matching it, and puts the octet back
    // before it returns. Without that, `-D` would show `xontent-encoding`,
    // which no server ever sent.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nContent-Length: 4\r\n\r\nBODY"});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-D", "head.txt", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    var buffer: [512]u8 = undefined;
    const dumped = try sandbox.work.readFile(testing.io, "head.txt", &buffer);
    try testing.expect(std.mem.indexOf(u8, dumped, "Content-Encoding: br") != null);
    try testing.expect(std.mem.indexOf(u8, dumped, "xontent") == null);
}

test "a redirect to a name longer than the encoding holds stops without a memory fault" {
    // **A server picks this name, so the bound is not the user's to keep.**
    // A written name of 255 characters filled the resolver's buffer in
    // `std.Io.Threaded` and the dot it writes next landed one past the
    // end. 254 characters reached a failed assertion in the same resolver.
    // Neither stops a build with no safety checks: the write happens.
    //
    // `zurl_net.tcp.Host.max_name_len` refuses both before `std` sees
    // them. See that constant for why 253 is the real bound.
    const long_name = ("a" ** 63) ++ "." ++ ("a" ** 63) ++ "." ++ ("a" ** 63) ++ "." ++ ("a" ** 63);
    try testing.expectEqual(@as(usize, 255), long_name.len);

    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 302 Found\r\nLocation: http://" ++ long_name ++
        "/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-L", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    // The transfer stops. What matters is that it stops with an exit code
    // and not with a signal.
    try testing.expect(result.term == .exited);
    try testing.expect(result.term.exited != 0);
}
