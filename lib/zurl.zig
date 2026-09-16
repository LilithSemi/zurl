//! zurl: the front package.
//!
//! This package imports `zurl-core`, `zurl-stream`, and every enabled
//! protocol package. No protocol package imports this one; that boundary
//! is what lets a protocol move to its own repository later.

const std = @import("std");

pub const Transfer = @import("zurl/Transfer.zig");
pub const Response = @import("zurl/Response.zig");
pub const protocol = @import("zurl/protocol.zig");
pub const body = @import("zurl/body.zig");
pub const request_body = @import("zurl/request_body.zig");
pub const multipart = @import("zurl/multipart.zig");
pub const authorize = @import("zurl/authorize.zig");
/// Turns a transfer's proxy options into what the engine sends. The proxy
/// credential is built here, and the origin's is built in `authorize`.
pub const proxy = @import("zurl/proxy.zig");
pub const Client = @import("zurl/Client.zig");
pub const download = @import("zurl/download.zig");
pub const Multi = @import("zurl/Multi.zig");
pub const Jar = @import("zurl/Jar.zig");

/// Every fault a transfer can report.
///
/// **A consumer needs this name to hold what `Client.perform` and
/// `download.toFile` answer**, because both are written `Error!Result`.
/// Without it a caller outside this repository has to reach into
/// `zurl-core` for a name the front package already promises, which is the
/// one thing the layering rule says it must not do.
///
/// Re-exported for the reason `embedded_ca_bundle_pem` and
/// `ConnectionPool` are: a caller reads the front package alone.
pub const Error = @import("zurl-core").Error;

/// Where a transfer records what went wrong, and the url, status and
/// message that go with it.
///
/// **A consumer needs this name to make one**, because `Client.perform`
/// and `download.toFile` both take `?*Diagnostics` and a caller that
/// cannot write `var d: zurl.Diagnostics = .{}` can only pass null, which
/// throws away every message this package writes.
///
/// `Diagnostics.status` holds the status where the fault carries one. See
/// `Transfer.Options.fail_on_error`, which turns a `4xx` or `5xx` into
/// `Error.HttpReturnedError` and records the status beside it.
pub const Diagnostics = @import("zurl-core").Diagnostics;

/// The trust bundle the build put into this binary, as PEM text.
///
/// This is what `zurl_core.ca.Source.embedded` names, and it is the store
/// a transfer verifies against when no `--cacert`, no `--capath`, and no
/// environment variable names another. `--dump-ca-embed` writes it out, so
/// a user can read the roots this binary trusts without trusting the
/// binary to describe them.
///
/// Re-exported here, and not reached through `zurl-tls`, so the CLI keeps
/// one package to talk to. The layering rule is that the CLI reads the
/// front package alone.
pub const embedded_ca_bundle_pem = @import("zurl-tls").bundle.embedded_pem;

/// A connection pool that more than one `Client` may use.
///
/// One `Client` runs one transfer at a time, so a caller that runs several
/// at once holds several clients. Each of them keeps a pool of its own
/// unless the caller hands them one of these, and a pool of its own means a
/// connection of its own to every host: eight parallel transfers to one
/// HTTP/2 host cost eight TCP connections and eight TLS handshakes where
/// one of each would do.
///
/// Make one with `createConnectionPool`, give it to each client with
/// `Client.shareConnections`, and free it with `destroyConnectionPool`
/// after every one of those clients is deinitialised.
///
/// Re-exported here for the reason `embedded_ca_bundle_pem` is: the CLI
/// reads the front package alone.
pub const ConnectionPool = @import("zurl-http").h1.SharedPool;

/// Makes a `ConnectionPool`. `io` must be the one every client that joins
/// it uses.
pub fn createConnectionPool(
    allocator: std.mem.Allocator,
    io: std.Io,
) std.mem.Allocator.Error!*ConnectionPool {
    return @import("zurl-http").h1.createSharedPool(allocator, io);
}

/// Frees a `ConnectionPool` and closes every connection it still holds.
///
/// Every client that joined the pool must be deinitialised first. Each of
/// them holds the pool, and this gives the caller's own hold back: the last
/// one out is what frees it.
pub fn destroyConnectionPool(pool: *ConnectionPool) void {
    @import("zurl-http").h1.destroySharedPool(pool);
}

/// What a proxy url says, which hosts reach no proxy, and which environment
/// variables name either one.
///
/// **This is not `zurl.proxy`, and the two are different jobs.**
/// `zurl.proxy` turns options that already hold a proxy into what the
/// engine sends, which is `resolve`, `Credential`, and `Resolved`. This one
/// holds the rules the text obeys before that: `parse`, `parseAs`, `Kind`,
/// `Spec`, `bypasses`, `Env`, and `fromEnv`.
///
/// **A consumer needs this name to write a proxy rule of its own.** curl
/// reads `http_proxy` and its family inside the library, so a program that
/// moves off curl loses every one of them at once and gets no diagnostic
/// for it. `proxyFromEnv` is the whole rule for a caller that wants it as
/// curl had it. This name is for a caller that wants a part of it: a proxy
/// url out of a config file, or a bypass list of its own.
///
/// Re-exported for the reason `Error` and `Diagnostics` are: a caller reads
/// the front package alone.
pub const proxy_rules = @import("zurl-core").proxy;

/// Fills a transfer's proxy options from the environment.
///
/// **This is the environment half of curl's rule, and a caller that
/// replaces a curl call needs it.** libcurl read `http_proxy`,
/// `https_proxy`, `all_proxy`, and `no_proxy` itself, so a program that
/// moves to this package and does not call this reaches every origin
/// directly and says nothing about it. `proxy_rules.fromEnv` holds the
/// order, and `proxy_rules.Env` holds the names and the measurement behind
/// them, `HTTP_PROXY` being deliberately absent.
///
/// **Only a field the environment named is written.** A variable that is
/// unset, and one set to the empty text, leave the field in `options` as it
/// was. So a caller that puts its own flags over the environment calls this
/// first and writes its own values after, which is the order the CLI uses:
/// a flag outranks the environment, and this function reads no flag.
///
/// Every text the options take borrows from `env`, the way the text after a
/// flag borrows from `argv`, so `env` must outlive `options`.
///
/// A proxy url that does not read is a fault the caller sees, and never a
/// quiet direct connection. `zurl_core.errors.curlCode` gives the two
/// members the exit codes curl answers with, which are 5 and 7.
pub fn proxyFromEnv(
    options: *Transfer.Options,
    env: *const std.process.Environ.Map,
) proxy_rules.ParseError!void {
    const from_env = try proxy_rules.fromEnv(env);
    if (from_env.http) |spec| options.proxy = spec;
    if (from_env.https) |spec| options.proxy_tls = spec;
    if (from_env.no_proxy.len != 0) options.no_proxy = from_env.no_proxy;
    if (from_env.every_protocol) options.proxy_every_protocol = true;
}

const testing = std.testing;

/// An environment map holding the names one test lists, and nothing else.
///
/// The caller must `deinit` it. A test that read the real environment would
/// answer one way on a developer's machine and another way in a build.
fn testEnv(pairs: []const [2][]const u8) !std.process.Environ.Map {
    var map: std.process.Environ.Map = .init(testing.allocator);
    errdefer map.deinit();
    for (pairs) |pair| try map.put(pair[0], pair[1]);
    return map;
}

test "the environment fills the proxy options of a transfer" {
    var env = try testEnv(&.{
        .{ "http_proxy", "http://127.0.0.1:3128" },
        .{ "https_proxy", "socks5h://127.0.0.2:1080" },
        .{ "no_proxy", "example.com" },
    });
    defer env.deinit();

    var options: Transfer.Options = .{};
    try proxyFromEnv(&options, &env);

    try testing.expectEqualStrings("127.0.0.1", options.proxy.?.host);
    try testing.expectEqual(@as(u16, 3128), options.proxy.?.port);
    try testing.expectEqual(proxy_rules.Kind.socks5h, options.proxy_tls.?.kind);
    try testing.expectEqualStrings("example.com", options.no_proxy);
    // Neither variable covers a protocol that is not HTTP.
    try testing.expect(!options.proxy_every_protocol);
}

test "all_proxy covers every protocol the way -x does" {
    var env = try testEnv(&.{.{ "all_proxy", "http://127.0.0.3:3130" }});
    defer env.deinit();

    var options: Transfer.Options = .{};
    try proxyFromEnv(&options, &env);
    try testing.expectEqualStrings("127.0.0.3", options.proxy.?.host);
    try testing.expectEqualStrings("127.0.0.3", options.proxy_tls.?.host);
    try testing.expect(options.proxy_every_protocol);
}

test "a field the environment did not name keeps the value the caller gave it" {
    // **This is what lets a caller put its own rule over the environment.**
    // A variable that is unset, and one set to the empty text, leave the
    // field as it was, so a caller writes its own values after this call
    // and a shell profile takes nothing back.
    var env = try testEnv(&.{
        .{ "http_proxy", "" },
        .{ "no_proxy", "" },
    });
    defer env.deinit();

    const mine = try proxy_rules.parse("http://127.0.0.9:9");
    var options: Transfer.Options = .{ .proxy = mine, .no_proxy = "mine.test" };
    try proxyFromEnv(&options, &env);

    try testing.expectEqualStrings("127.0.0.9", options.proxy.?.host);
    try testing.expectEqualStrings("mine.test", options.no_proxy);
    try testing.expectEqual(@as(?Transfer.ProxySpec, null), options.proxy_tls);
}

test "a proxy url in the environment that does not read is a fault" {
    // A stale shell profile must not become a direct connection that
    // nobody reports.
    var env = try testEnv(&.{.{ "http_proxy", "ftp://127.0.0.1" }});
    defer env.deinit();

    var options: Transfer.Options = .{};
    try testing.expectError(error.UnsupportedProxyScheme, proxyFromEnv(&options, &env));
}

test "the proxy spec of a transfer is the one the rules build" {
    // The two names are one type, so a spec the consumer parses reaches
    // `Transfer.Options` with no copy and no conversion.
    try testing.expect(Transfer.ProxySpec == proxy_rules.Spec);
    try testing.expect(proxy_rules == @import("zurl-core").proxy);
}

test {
    _ = Transfer;
    _ = Response;
    _ = protocol;
    _ = body;
    _ = request_body;
    _ = multipart;
    _ = authorize;
    _ = proxy;
    _ = Client;
    _ = download;
    _ = Multi;
    _ = Jar;
    _ = @import("zurl/compat_test.zig");
}
