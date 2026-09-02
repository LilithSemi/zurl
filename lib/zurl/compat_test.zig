//! Proves the download path in this package satisfies the contract that
//! `curl_transport.zig`, the psyclyx/fix evaluator's libcurl adapter, used
//! to. `curl_transport.zig` is the file this package replaces.
//!
//! Each test below ports one property that adapter's own tests, or its
//! error mapping, pinned. The redirect test is a near-verbatim port. The
//! rest port `curl_transport.zig`'s mapping from a libcurl result code to a
//! fix fetch error:
//!
//! ```
//! if (response_code >= 400 and response_code < 500 and response_code != 408 and response_code != 429)
//!     return error.FetchClientError;
//! return switch (code) {
//!     CURLE_UNSUPPORTED_PROTOCOL, CURLE_URL_MALFORMAT => error.FetchInvalidUrl,
//!     CURLE_TOO_MANY_REDIRECTS => error.FetchTooManyRedirects,
//!     CURLE_PEER_FAILED_VERIFICATION, CURLE_SSL_CACERT_BADFILE => error.FetchTlsVerificationFailed,
//!     else => error.FetchTransient,
//! };
//! ```
//!
//! Every branch of that mapping has a test below:
//!
//! * `FetchClientError`, by a 403.
//! * `FetchTransient`, by a 408 and by a 429. Both statuses sit outside
//!   the client-error range check, so both fall to the `else` arm, which
//!   is the only way that name is reached.
//! * `FetchTooManyRedirects`, by three scripted redirects under a limit
//!   of two.
//! * `FetchInvalidUrl`, by a port that is not a number.
//! * `FetchTlsVerificationFailed`, by a real HTTPS transfer against
//!   `zurl-tls`'s loopback TLS server. That fixture runs a real TLS 1.3
//!   handshake and presents a certificate chain the test picks. Two tests
//!   use it: one presents a chain no trust store holds and the transfer
//!   must fail, and one gives the client that same server's root and the
//!   transfer must complete. Without the second, a client that refused
//!   every HTTPS url would pass the first.
//!
//! `FetchCacheWriteFailed` is the one member of the adapter's error set
//! that no libcurl result code produced. `curl_transport.zig` reported it
//! when its own cache write failed, which is a local fault and not a
//! transfer fault. `toFile` reports `error.WriteError` for the same fault,
//! and the last test below pins it.
//!
//! One behaviour differs from `curl_transport.zig`, and it is not papered
//! over here. `curl_transport.zig` set `CURLOPT_FAILONERROR`
//! unconditionally, so any 4xx or 5xx status ended the transfer.
//! `Transfer.Options.fail_on_error` defaults to false: a default `toFile`
//! publishes an error page like any other body. Every test below that
//! expects a status to fail the transfer passes `.fail_on_error = true`,
//! which is what a `fix` adapter built on this package must also do.
//!
//! zurl also reports one error, `error.HttpReturnedError`, for every
//! failing status, where `curl_transport.zig` branched on the status
//! itself. The status that branch needs still reaches the caller, through
//! `Diagnostics.status`, so the tests below assert on it directly rather
//! than inventing a status-aware error zurl does not have.
//!
//! No test here reaches the network. The HTTP tests use `zurl-http`'s
//! loopback server and the HTTPS tests use `zurl-tls`'s.

const std = @import("std");
const testing = std.testing;
const test_server = @import("zurl-http").test_server;
const tls_test_server = @import("zurl-tls").test_server;
const zurl_core = @import("zurl-core");
const Client = @import("Client.zig");
const download = @import("download.zig");
const Diagnostics = zurl_core.Diagnostics;

/// The reply every HTTPS test below scripts.
const ok_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

test "HTTP download follows redirects and streams decoded bytes" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /body\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/redirect", .{server.port()});
    defer testing.allocator.free(url_text);

    const result = try download.toFile(&client, url_text, tmp.dir, "output", .{}, null);
    try testing.expectEqual(@as(u64, 7), result.size);

    const contents = try tmp.dir.readFileAlloc(testing.io, "output", testing.allocator, .limited(64));
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("payload", contents);
}

test "a 4xx that is not 408 or 429 maps to FetchClientError's equivalent" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    var d: Diagnostics = .{};
    try testing.expectError(
        error.HttpReturnedError,
        download.toFile(&client, url_text, tmp.dir, "output", .{ .fail_on_error = true }, &d),
    );
    // 403 is neither 408 nor 429, so a fix adapter reading this status maps
    // it to FetchClientError, the same branch curl_transport.zig took.
    try testing.expectEqual(@as(u16, 403), d.status.?);
    try testing.expectError(error.FileNotFound, tmp.dir.access(testing.io, "output", .{}));
}

test "a 408 does not map to a client error" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    var d: Diagnostics = .{};
    try testing.expectError(
        error.HttpReturnedError,
        download.toFile(&client, url_text, tmp.dir, "output", .{ .fail_on_error = true }, &d),
    );
    // curl_transport.zig excluded 408 from the client-error range check, so
    // it fell to `else => error.FetchTransient`: a request timeout is worth
    // retrying. An adapter must keep that exclusion when it reads this
    // status, or it gives up on a server that only needed a retry.
    try testing.expectEqual(@as(u16, 408), d.status.?);
}

test "a 429 does not map to a client error" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    var d: Diagnostics = .{};
    try testing.expectError(
        error.HttpReturnedError,
        download.toFile(&client, url_text, tmp.dir, "output", .{ .fail_on_error = true }, &d),
    );
    // Same exclusion as 408: a rate-limited server is worth retrying, not
    // giving up on as a client error.
    try testing.expectEqual(@as(u16, 429), d.status.?);
}

test "too many redirects maps to TooManyRedirects" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    // Three scripted redirects, a limit of two: the third exceeds it.
    // zurl names this error.TooManyRedirects, curl_transport.zig's
    // FetchTooManyRedirects by another name; the mapping is a rename, not a
    // judgment call.
    try testing.expectError(
        error.TooManyRedirects,
        download.toFile(&client, url_text, tmp.dir, "output", .{ .redirects = .{ .follow = 2 } }, null),
    );
}

test "a malformed url maps to InvalidUrl" {
    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // The port is not a number, so zurl-core's url parser rejects it
    // before any connection is attempted. curl_transport.zig's
    // CURLE_URL_MALFORMAT maps here the same way, a rename with no
    // judgment call.
    try testing.expectError(
        error.InvalidUrl,
        download.toFile(&client, "http://example.com:not-a-port/", tmp.dir, "output", .{}, null),
    );
}

test "a certificate no trust store holds maps to FetchTlsVerificationFailed" {
    // The mapping this file exists for, and the one that had no test at
    // all until `zurl-tls`'s loopback TLS server arrived. The server
    // presents a self-signed leaf for the address the url names, so the
    // host name check passes and only the trust check refuses.
    var server: tls_test_server.TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{ .chain = .self_signed });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "https://127.0.0.1:{d}/",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    var d: Diagnostics = .{};
    // zurl names this error.PeerFailedVerification, which is
    // CURLE_PEER_FAILED_VERIFICATION by another name.
    // `curl_transport.zig` mapped that code, and CURLE_SSL_CACERT_BADFILE
    // beside it, to FetchTlsVerificationFailed.
    try testing.expectError(
        error.PeerFailedVerification,
        download.toFile(&client, url_text, tmp.dir, "output", .{}, &d),
    );
    // Nothing is published from a transfer that never authenticated the
    // peer, so a cache built on this call keeps whatever it already had.
    try testing.expectError(error.FileNotFound, tmp.dir.access(testing.io, "output", .{}));
    // The peer never got a request, because the client stopped inside the
    // handshake.
    try testing.expectEqual(@as(usize, 0), server.handshakes());
}

test "a certificate the trust store holds completes the same HTTPS transfer" {
    // The control for the test above. Without it, a client that refused
    // every https url would pass that one, and the mapping would be
    // pinned to the wrong cause.
    var server: tls_test_server.TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{ .chain = .ca_issued });
    defer server.stop();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var pem_buf: [tls_test_server.root_pem_max]u8 = undefined;
    const pem = try server.rootPem(&pem_buf);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "root.pem", .data = pem });
    const cacert = try tmp.dir.realPathFileAlloc(testing.io, "root.pem", testing.allocator);
    defer testing.allocator.free(cacert);

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "https://127.0.0.1:{d}/",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    const result = try download.toFile(&client, url_text, tmp.dir, "output", .{
        .ca = .{ .cacert = cacert },
    }, null);
    try testing.expectEqual(@as(u64, 2), result.size);
    try testing.expectEqual(@as(u16, 200), result.status);

    const contents = try tmp.dir.readFileAlloc(testing.io, "output", testing.allocator, .limited(64));
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("ok", contents);
    try testing.expectEqual(@as(usize, 1), server.handshakes());
}

test "a close-delimited https body that ends with no close_notify is not a whole body" {
    // **The end of a socket is not the end of a stream.** RFC 9112 section
    // 6.3 item 8 lets a response carry neither `Content-Length` nor a
    // chunked coding and end when the stream does. For that framing the
    // TLS `close_notify` alert is the only thing that tells a whole body
    // from a cut one, and somebody on the path writes a FIN as readily as
    // a server does.
    //
    // Measured against curl 8.21.0 over this fixture, one 100 octet body
    // in every row:
    //
    //     framing            close_notify   curl   zurl
    //     close-delimited    sent            0      0
    //     close-delimited    absent         56     26
    //     content-length     absent          0      0
    //     chunked            absent          0      0
    //
    // The two exit codes differ and the two answers do not: both clients
    // refuse the second row and take the other three. `zurl-core`'s name
    // for a failed read carries 26 where curl carries 56.
    //
    // **Rows 3 and 4 are why this test has four cases.** They are what
    // shows the rule costs nothing for a framed body: `std.http.Reader`
    // stops at the framed end, so it never reaches the missing alert.
    // Without them the fix would look like it refuses every server that
    // closes without saying so, which is common and which curl tolerates.
    const payload = "0123456789" ** 10;
    const Case = struct {
        name: []const u8,
        response: []const u8,
        skip_close_notify: bool,
        want: ?anyerror,
    };
    const cases = [_]Case{
        .{
            .name = "close-delimited, alert sent",
            .response = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" ++ payload,
            .skip_close_notify = false,
            .want = null,
        },
        .{
            .name = "close-delimited, alert absent",
            .response = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" ++ payload,
            .skip_close_notify = true,
            .want = error.ReadError,
        },
        .{
            .name = "content-length, alert absent",
            .response = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n" ++ payload,
            .skip_close_notify = true,
            .want = null,
        },
        .{
            .name = "chunked, alert absent",
            .response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" ++
                "64\r\n" ++ payload ++ "\r\n0\r\n\r\n",
            .skip_close_notify = true,
            .want = null,
        },
    };

    for (cases) |case| {
        errdefer std.debug.print("case: {s}\n", .{case.name});

        var server: tls_test_server.TlsTestServer = undefined;
        try server.startWith(&.{case.response}, .{
            .chain = .ca_issued,
            .skip_close_notify = case.skip_close_notify,
        });
        defer server.stop();

        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();

        var pem_buf: [tls_test_server.root_pem_max]u8 = undefined;
        const pem = try server.rootPem(&pem_buf);
        try tmp.dir.writeFile(testing.io, .{ .sub_path = "root.pem", .data = pem });
        const cacert = try tmp.dir.realPathFileAlloc(testing.io, "root.pem", testing.allocator);
        defer testing.allocator.free(cacert);

        var client: Client = .init(testing.allocator, testing.io);
        defer client.deinit();

        const url_text = try std.fmt.allocPrint(
            testing.allocator,
            "https://127.0.0.1:{d}/",
            .{server.port()},
        );
        defer testing.allocator.free(url_text);

        if (case.want) |want| {
            try testing.expectError(
                want,
                download.toFile(&client, url_text, tmp.dir, "output", .{
                    .ca = .{ .cacert = cacert },
                }, null),
            );
            // A body that may be short is not written out as though it
            // were whole. This is the half an exit code alone would miss.
            try testing.expectError(
                error.FileNotFound,
                tmp.dir.access(testing.io, "output", .{}),
            );
            continue;
        }

        const result = try download.toFile(&client, url_text, tmp.dir, "output", .{
            .ca = .{ .cacert = cacert },
        }, null);
        try testing.expectEqual(@as(u64, payload.len), result.size);

        const contents = try tmp.dir.readFileAlloc(
            testing.io,
            "output",
            testing.allocator,
            .limited(1024),
        );
        defer testing.allocator.free(contents);
        try testing.expectEqualStrings(payload, contents);
    }
}

test "a write the local filesystem refuses maps to FetchCacheWriteFailed" {
    // `FetchCacheWriteFailed` is the one member of the adapter's error set
    // that no libcurl result code produced. The adapter reported it when
    // its own cache write failed, so what an adapter over this package
    // reads is `toFile`'s own `error.WriteError`.
    var server: test_server.TestServer = undefined;
    try server.start(&.{ok_response});
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    // No directory named `missing` exists, so the staging file cannot be
    // created. The transfer itself is sound, which is the point: the fault
    // is local and it must not be reported as a transfer fault.
    var d: Diagnostics = .{};
    try testing.expectError(
        error.WriteError,
        download.toFile(&client, url_text, tmp.dir, "missing/output", .{}, &d),
    );
    try testing.expect(d.message != null);
}
