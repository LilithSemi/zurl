//! A consumer of zurl, built the way a project outside this repository
//! builds one.
//!
//! **What this guards.** zurl exists to be imported through
//! `build.zig.zon`. A consumer writes `b.dependency("zurl", .{})` and then
//! `dep.module("zurl")`, and that call reads the map `b.addModule` fills
//! in. A module made with `b.createModule` is not in that map, and a
//! module this repository's own code reaches through a local variable
//! looks the same from inside. So the graph can stop being importable from
//! outside while every test in this repository still passes.
//!
//! `build.zig` builds this file against the modules it looks up **by
//! name**, the way a consumer does. A module that leaves the exported map
//! fails this build, and a public name that goes away fails the
//! compilation below.
//!
//! **This is a packaging guard and not a second test suite.** It names the
//! entry points a consumer needs and it exercises none of them. The
//! behaviour of each one is tested where it lives.

const std = @import("std");

const zurl = @import("zurl");
const zurl_core = @import("zurl-core");

test "a consumer reaches the transfer entry point" {
    // `Client.perform` is the one call a consumer makes to run a transfer.
    // Naming the function checks that the type, the field, and every type
    // in the signature are still reachable from outside.
    const perform: *const fn (
        *zurl.Client,
        []const u8,
        zurl.Transfer.Options,
        ?*zurl_core.Diagnostics,
    ) zurl_core.Error!zurl.Response = &zurl.Client.perform;
    try std.testing.expect(@intFromPtr(perform) != 0);

    // The client's own lifetime, which a consumer needs beside `perform`.
    const init: *const fn (std.mem.Allocator, std.Io) zurl.Client = &zurl.Client.init;
    const deinit: *const fn (*zurl.Client) void = &zurl.Client.deinit;
    try std.testing.expect(@intFromPtr(init) != 0);
    try std.testing.expect(@intFromPtr(deinit) != 0);
}

test "a consumer reaches the diagnostics and the exit codes" {
    // `Diagnostics` carries what went wrong, and `errors.curlCode` turns
    // an error into the number curl exits with. A consumer that replaces
    // a curl call needs both.
    var diagnostics: zurl_core.Diagnostics = .{};
    _ = &diagnostics;

    const code: *const fn (zurl_core.Error) u32 = &zurl_core.errors.curlCode;
    try std.testing.expectEqual(@as(u32, 3), code(error.InvalidUrl));
}

test "a consumer reaches the cookie rules and the suffix list" {
    // The cookie rules, and the list this build embeds. A consumer reads
    // the list through `zurl-core` and never links libpsl.
    try std.testing.expect(zurl_core.psl.isPublicSuffix("co.uk"));
    try std.testing.expect(!zurl_core.psl.isPublicSuffix("example.co.uk"));

    // The jar of the front package, which is where a consumer keeps
    // cookies between two transfers.
    const store: *const fn (*zurl.Jar, zurl_core.Url, []const u8, i64) void = &zurl.Jar.store;
    try std.testing.expect(@intFromPtr(store) != 0);
}

test "a consumer reaches the trust roots this build embeds" {
    // A static zurl carries its own roots, and a consumer must be able to
    // see that they are there.
    try std.testing.expect(zurl.embedded_ca_bundle_pem.len > 1024);
}

test "a consumer names a transfer's fault and its diagnostics through the front package alone" {
    // **The layering rule is that the CLI, and any consumer, reads the
    // front package alone.** Every test above this one reaches into
    // `zurl-core` for `Error` and `Diagnostics`, and that is what the rule
    // forbids: `download.toFile` is written `Error!Result` and takes a
    // `?*Diagnostics`, so a consumer that followed the rule had no name
    // for either and could only pass null, throwing away every message
    // this package writes.
    //
    // This test uses nothing but `zurl`, so it fails to compile if the
    // re-export goes away.
    var diagnostics: zurl.Diagnostics = .{};
    _ = &diagnostics;

    const to_file: *const fn (
        *zurl.Client,
        []const u8,
        std.Io.Dir,
        []const u8,
        zurl.Transfer.Options,
        ?*zurl.Diagnostics,
    ) zurl.Error!zurl.download.Result = &zurl.download.toFile;
    try std.testing.expect(@intFromPtr(to_file) != 0);

    // The two names are the ones `zurl-core` holds, and not copies of
    // them, so an error crossing the boundary compares equal.
    try std.testing.expect(zurl.Error == zurl_core.Error);
    try std.testing.expect(zurl.Diagnostics == zurl_core.Diagnostics);
}

test "a consumer fills a transfer's proxy from the environment through the front package alone" {
    // **libcurl read `http_proxy`, `https_proxy`, `all_proxy`, and
    // `no_proxy` itself.** A program that moves off curl and onto
    // `download.toFile` loses every one of them at once, reaches each
    // origin directly, and gets no diagnostic for it. So the front package
    // has to answer the whole rule, and a consumer must not have to copy
    // it.
    //
    // This test uses nothing but `zurl`, so it fails to compile if the
    // helper or the names behind it go away.
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("http_proxy", "http://127.0.0.1:3128");
    try env.put("all_proxy", "socks5h://127.0.0.2:1080");
    try env.put("no_proxy", "example.com");

    var options: zurl.Transfer.Options = .{};
    try zurl.proxyFromEnv(&options, &env);

    try std.testing.expectEqualStrings("127.0.0.1", options.proxy.?.host);
    try std.testing.expectEqual(@as(u16, 3128), options.proxy.?.port);
    // `all_proxy` answers for the scheme that named no variable of its own,
    // and it covers every protocol the way `-x` does.
    try std.testing.expectEqualStrings("127.0.0.2", options.proxy_tls.?.host);
    try std.testing.expect(options.proxy_every_protocol);
    try std.testing.expectEqualStrings("example.com", options.no_proxy);

    // And the parts of the rule, for a consumer that writes a variant of
    // its own: the spec type, the parser, the variable names, and the
    // bypass rule.
    const spec: zurl.Transfer.ProxySpec = try zurl.proxy_rules.parse("http://127.0.0.9:9");
    try std.testing.expectEqual(@as(u16, 9), spec.port);
    try std.testing.expectEqualStrings("http_proxy", zurl.proxy_rules.Env.http[0]);
    try std.testing.expect(zurl.proxy_rules.bypasses(options.no_proxy, "sub.example.com"));

    // A proxy url that does not read is a fault the consumer sees, and
    // never a quiet direct connection.
    try env.put("http_proxy", "ftp://127.0.0.1");
    try std.testing.expectError(
        error.UnsupportedProxyScheme,
        zurl.proxyFromEnv(&options, &env),
    );
}
