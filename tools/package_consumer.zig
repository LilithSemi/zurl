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
