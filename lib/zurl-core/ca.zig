//! The order in which zurl looks for certificate authorities.
//!
//! This module decides the order. It loads nothing and it opens no file, so
//! every rule below is a table test. `zurl-tls` does the loading.
//!
//! An explicit source, such as `--cacert`, replaces the built-in bundle
//! instead of adding to it, the way curl works. `.embedded` is the fallback
//! for when nothing else is named, so the list is never empty and a
//! transfer never runs with no roots.

const std = @import("std");

/// One place to look for certificate authorities.
pub const Source = union(enum) {
    /// A PEM file that holds one or more certificates.
    file: []const u8,
    /// A directory of PEM files.
    dir: []const u8,
    /// The trust store of the host operating system.
    native,
    /// The bundle that the build put into the binary.
    embedded,
};

/// The flags and environment values that decide the order.
///
/// Every slice borrows from the caller and must outlive the returned list.
pub const Inputs = struct {
    /// The `--cacert` flag.
    cacert: ?[]const u8 = null,
    /// The `--capath` flag.
    capath: ?[]const u8 = null,
    /// The `CURL_CA_BUNDLE` environment variable.
    curl_ca_bundle: ?[]const u8 = null,
    /// The `SSL_CERT_FILE` environment variable.
    ssl_cert_file: ?[]const u8 = null,
    /// The `SSL_CERT_DIR` environment variable.
    ssl_cert_dir: ?[]const u8 = null,
    /// The `--ca-native` flag.
    ca_native: bool = false,
};

/// The largest number of sources that `resolve` can return.
///
/// Five optional inputs, plus the native store, plus the embedded bundle.
pub const max_sources: usize = 7;

comptime {
    // Every field of `Inputs` contributes at most one source, and `.embedded`
    // always contributes one more. This fact is decidable at compile time, so
    // a mismatch fails the build instead of relying on a runtime check that a
    // release build could remove.
    const derived = @typeInfo(Inputs).@"struct".fields.len + 1;
    if (derived != max_sources)
        @compileError("max_sources must equal Inputs field count plus one for .embedded");
}

/// Fills `out` with the sources to try, in order, and returns the part of
/// `out` that holds them.
///
/// `.embedded` is appended only when no other source was named. An explicit
/// `cacert`, `capath`, `curl_ca_bundle`, `ssl_cert_file`, `ssl_cert_dir`, or
/// `ca_native` therefore replaces the built-in trust set instead of adding
/// to it. The list is never empty either way, because `.embedded` is
/// exactly the fallback for the case where nothing else was asked for.
pub fn resolve(in: Inputs, out: *[max_sources]Source) []Source {
    var count: usize = 0;

    if (in.cacert) |path| {
        out[count] = .{ .file = path };
        count += 1;
    }
    if (in.capath) |path| {
        out[count] = .{ .dir = path };
        count += 1;
    }
    if (in.curl_ca_bundle) |path| {
        out[count] = .{ .file = path };
        count += 1;
    }
    if (in.ssl_cert_file) |path| {
        out[count] = .{ .file = path };
        count += 1;
    }
    if (in.ssl_cert_dir) |path| {
        out[count] = .{ .dir = path };
        count += 1;
    }
    if (in.ca_native) {
        out[count] = .native;
        count += 1;
    }
    // An explicit source replaces the built-in bundle, the way curl's
    // --cacert and --capath do. `.embedded` is the fallback for when
    // nothing else was named, which is also what keeps this list from ever
    // coming back empty.
    if (count == 0) {
        out[count] = .embedded;
        count += 1;
    }

    return out[0..count];
}

test "the embedded bundle is the only source when nothing else is set" {
    var out: [max_sources]Source = undefined;
    const list = resolve(.{}, &out);
    try std.testing.expectEqual(@as(usize, 1), list.len);
    try std.testing.expectEqual(Source.embedded, list[0]);
}

test "cacert comes before every other source" {
    var out: [max_sources]Source = undefined;
    const list = resolve(.{
        .cacert = "/a.pem",
        .capath = "/certs",
        .curl_ca_bundle = "/b.pem",
        .ssl_cert_file = "/c.pem",
        .ca_native = true,
    }, &out);
    try std.testing.expectEqualStrings("/a.pem", list[0].file);
}

test "the order is cacert, capath, CURL_CA_BUNDLE, SSL_CERT_FILE, SSL_CERT_DIR, native" {
    var out: [max_sources]Source = undefined;
    const list = resolve(.{
        .cacert = "/a.pem",
        .capath = "/acerts",
        .curl_ca_bundle = "/b.pem",
        .ssl_cert_file = "/c.pem",
        .ssl_cert_dir = "/ccerts",
        .ca_native = true,
    }, &out);
    // Every named source is set, so .embedded is not appended.
    try std.testing.expectEqual(@as(usize, 6), list.len);
    try std.testing.expectEqualStrings("/a.pem", list[0].file);
    try std.testing.expectEqualStrings("/acerts", list[1].dir);
    try std.testing.expectEqualStrings("/b.pem", list[2].file);
    try std.testing.expectEqualStrings("/c.pem", list[3].file);
    try std.testing.expectEqualStrings("/ccerts", list[4].dir);
    try std.testing.expectEqual(Source.native, list[5]);
}

test "the native store appears only when the caller asks for it" {
    var out: [max_sources]Source = undefined;
    const without = resolve(.{}, &out);
    for (without) |source| try std.testing.expect(source != .native);

    var out2: [max_sources]Source = undefined;
    const with = resolve(.{ .ca_native = true }, &out2);
    try std.testing.expectEqual(Source.native, with[0]);
}

test "an environment value does not displace a flag" {
    var out: [max_sources]Source = undefined;
    const list = resolve(.{ .curl_ca_bundle = "/env.pem", .cacert = "/flag.pem" }, &out);
    try std.testing.expectEqualStrings("/flag.pem", list[0].file);
    try std.testing.expectEqualStrings("/env.pem", list[1].file);
}

test "ssl_cert_dir can appear with no ssl_cert_file set" {
    var out: [max_sources]Source = undefined;
    const list = resolve(.{ .ssl_cert_dir = "/d" }, &out);
    try std.testing.expectEqual(@as(usize, 1), list.len);
    try std.testing.expectEqualStrings("/d", list[0].dir);
}

test "ca_native false omits native even when every other source is set" {
    var out: [max_sources]Source = undefined;
    const list = resolve(.{
        .cacert = "/a.pem",
        .capath = "/acerts",
        .curl_ca_bundle = "/b.pem",
        .ssl_cert_file = "/c.pem",
        .ssl_cert_dir = "/ccerts",
    }, &out);
    for (list) |source| try std.testing.expect(source != .native);
    for (list) |source| try std.testing.expect(source != .embedded);
    try std.testing.expectEqual(@as(usize, 5), list.len);
}

test "an explicit cacert replaces the embedded bundle" {
    var out: [max_sources]Source = undefined;
    const list = resolve(.{ .cacert = "/a.pem" }, &out);
    try std.testing.expectEqual(@as(usize, 1), list.len);
    try std.testing.expectEqualStrings("/a.pem", list[0].file);
}

test "the native store also replaces the embedded bundle" {
    var out: [max_sources]Source = undefined;
    const list = resolve(.{ .ca_native = true }, &out);
    try std.testing.expectEqual(@as(usize, 1), list.len);
    try std.testing.expectEqual(Source.native, list[0]);
}

// The bound and the never-empty invariant are the two properties that keep
// zurl from ever running a transfer with no roots at all. `max_sources` is a
// compile-time array size, so an out-of-bounds write in `resolve` would be
// undefined behaviour rather than a caught error. This test walks every
// combination of the six inputs and checks that the list is never empty,
// never exceeds the bound, carries `.native` exactly when asked, carries
// exactly one entry per named source, and carries `.embedded` in exactly the
// one case where nothing else was named, instead of trusting any of that by
// inspection.
test "every combination of inputs fits in max_sources, is never empty, and carries embedded only when nothing else is named" {
    const combinations = 1 << 6;
    var i: u7 = 0;
    while (i < combinations) : (i += 1) {
        const in: Inputs = .{
            .cacert = if (i & 1 != 0) "/a" else null,
            .capath = if (i & 2 != 0) "/b" else null,
            .curl_ca_bundle = if (i & 4 != 0) "/c" else null,
            .ssl_cert_file = if (i & 8 != 0) "/d" else null,
            .ssl_cert_dir = if (i & 16 != 0) "/e" else null,
            .ca_native = i & 32 != 0,
        };
        var out: [max_sources]Source = undefined;
        const list = resolve(in, &out);

        // Never empty, and never past the compile-time bound.
        try std.testing.expect(list.len >= 1);
        try std.testing.expect(list.len <= max_sources);
        // `.native` tracks `ca_native` exactly.
        try std.testing.expectEqual(in.ca_native, hasNative(list));
        // `.embedded` appears in exactly the all-null case (`i == 0`), never
        // alongside a named source.
        try std.testing.expectEqual(i == 0, hasEmbedded(list));
        // Every named source contributes exactly one entry, so away from the
        // all-null case the list length is the number of inputs set.
        if (i != 0) try std.testing.expectEqual(@as(usize, @popCount(i)), list.len);
    }
    // `max_sources` (7) is a compile-time bound, not a value `resolve` can
    // reach at runtime: `.embedded` is the fallback for the all-null case
    // only, so the largest list any input can produce is all six named
    // sources with no `.embedded`, which is 6, one short of the bound. That
    // slack is what keeps the bound safe rather than exact.
    var out: [max_sources]Source = undefined;
    const all_named = resolve(.{
        .cacert = "/a",
        .capath = "/b",
        .curl_ca_bundle = "/c",
        .ssl_cert_file = "/d",
        .ssl_cert_dir = "/e",
        .ca_native = true,
    }, &out);
    try std.testing.expectEqual(@as(usize, max_sources - 1), all_named.len);
}

fn hasNative(list: []Source) bool {
    for (list) |source| {
        if (source == .native) return true;
    }
    return false;
}

fn hasEmbedded(list: []Source) bool {
    for (list) |source| {
        if (source == .embedded) return true;
    }
    return false;
}
