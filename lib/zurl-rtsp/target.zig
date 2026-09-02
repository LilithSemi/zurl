//! The uri an RTSP request line names.
//!
//! **RTSP writes a whole url on the request line and HTTP writes a path.**
//! RFC 2326 section 6.1 makes the target of a request an absolute
//! `rtsp://` url, so this file rebuilds one out of a `zurl_core.Url`. The
//! two places it differs from the url the user typed are named below, and
//! both matter.
//!
//! **The userinfo never reaches the request line.** A url may carry
//! `rtsp://user:pw@host/stream`, and the credential belongs in an
//! `Authorization` header where it can be left out of a log, not in a
//! request line that every proxy and every server writes down. curl builds
//! the same header from the same userinfo, measured: `-u u:p` reached the
//! wire as `Authorization: Basic dTpw` and the request line held no
//! credential.
//!
//! **The port is written only where it is not the default.** RFC 2326
//! section 3.2 gives `rtsp` port 554, and a target naming it back is the
//! same resource written longer. A server that compares the target of a
//! `SETUP` against the target of the `DESCRIBE` that named the track sees
//! one spelling this way.
//!
//! This file writes into a buffer the caller owns. It opens nothing.

const std = @import("std");

const zurl_core = @import("zurl-core");

/// The scheme every target this file writes carries.
pub const scheme = "rtsp";

/// The port RFC 2326 section 3.2 gives `rtsp`.
pub const default_port: u16 = 554;

/// How many bytes of target this package writes.
///
/// A stream uri is a host and a path, and a track uri adds a short suffix.
/// 2048 is generous for both, and it is the size of the buffer the
/// `Fetcher` keeps.
pub const max_target_bytes: usize = 2048;

/// Where a built target lives while a transfer runs.
pub const Storage = [max_target_bytes]u8;

/// Why a target could not be built.
pub const Error = error{
    /// The target does not fit `max_target_bytes`.
    TargetTooLong,
    /// The url names no host, so no absolute target can be written.
    NoHost,
};

/// Writes the absolute target `url` names into `out`.
///
/// The result points into `out`.
///
/// The query is kept and the fragment is dropped. A fragment is a part of
/// a url that never leaves the client, RFC 3986 section 3.5, and a query
/// on an RTSP url reaches the server the way it does on an HTTP one.
pub fn build(out: *Storage, url: zurl_core.Url) Error![]const u8 {
    if (url.host.len == 0) return error.NoHost;

    var at: usize = 0;
    try put(out, &at, scheme);
    try put(out, &at, "://");

    // **An IPv6 address gets its brackets back.** `zurl_core.Url.host`
    // holds `::1` for `rtsp://[::1]:554/s`, and the brackets are what tell
    // the colons inside the address apart from the colon before a port.
    const bracketed = std.mem.indexOfScalar(u8, url.host, ':') != null;
    if (bracketed) try put(out, &at, "[");
    try put(out, &at, url.host);
    if (bracketed) try put(out, &at, "]");

    if (url.port) |port| {
        if (port != default_port) {
            try put(out, &at, ":");
            var digits: [5]u8 = undefined;
            const text = std.fmt.bufPrint(&digits, "{d}", .{port}) catch
                return error.TargetTooLong;
            try put(out, &at, text);
        }
    }

    try put(out, &at, url.path);
    if (url.query) |query| {
        try put(out, &at, "?");
        try put(out, &at, query);
    }
    return out[0..at];
}

fn put(out: *Storage, at: *usize, text: []const u8) Error!void {
    if (text.len > out.len - at.*) return error.TargetTooLong;
    @memcpy(out[at.*..][0..text.len], text);
    at.* += text.len;
}

/// Names the fault, for a message to a user.
pub fn describe(err: Error) []const u8 {
    return switch (err) {
        error.TargetTooLong => "the rtsp request target this url names is longer than zurl writes",
        error.NoHost => "an rtsp url names a host, and this one names none",
    };
}

const testing = std.testing;

/// Parses `text` the way a `Client` with this package registered does.
fn parseUrl(text: []const u8) !zurl_core.Url {
    var schemes: zurl_core.url.Schemes = .empty;
    try schemes.add(.{ .name = scheme, .default_port = default_port });
    return zurl_core.url.parseWith(text, &schemes);
}

fn targetOf(out: *Storage, text: []const u8) ![]const u8 {
    return build(out, try parseUrl(text));
}

test "a target is an absolute url, which is where rtsp differs from http" {
    // RFC 2326 section 6.1. An HTTP request line writes `/stream`.
    var out: Storage = undefined;
    try testing.expectEqualStrings(
        "rtsp://example.test/stream",
        try targetOf(&out, "rtsp://example.test/stream"),
    );
    try testing.expectEqualStrings(
        "rtsp://example.test/a/b/c",
        try targetOf(&out, "rtsp://example.test/a/b/c"),
    );
}

test "the default port is left out and any other port is written" {
    // A target naming 554 back is the same resource written longer, and a
    // server that compares a SETUP target against a DESCRIBE target sees
    // one spelling this way.
    var out: Storage = undefined;
    try testing.expectEqualStrings(
        "rtsp://h/s",
        try targetOf(&out, "rtsp://h:554/s"),
    );
    try testing.expectEqualStrings(
        "rtsp://h/s",
        try targetOf(&out, "rtsp://h/s"),
    );
    try testing.expectEqualStrings(
        "rtsp://h:8554/s",
        try targetOf(&out, "rtsp://h:8554/s"),
    );
}

test "the userinfo never reaches the request line" {
    // **The credential goes in a header, not on a line every proxy writes
    // down.** curl builds the same header from the same userinfo,
    // measured.
    var out: Storage = undefined;
    const built = try targetOf(&out, "rtsp://alice:s3cret@h:8554/s");
    try testing.expectEqualStrings("rtsp://h:8554/s", built);
    try testing.expect(std.mem.indexOf(u8, built, "alice") == null);
    try testing.expect(std.mem.indexOf(u8, built, "s3cret") == null);
}

test "an IPv6 host gets its brackets back" {
    // Without them the colons inside the address run into the colon before
    // a port, and the target names a host nobody can resolve.
    var out: Storage = undefined;
    try testing.expectEqualStrings(
        "rtsp://[::1]:8554/s",
        try targetOf(&out, "rtsp://[::1]:8554/s"),
    );
    try testing.expectEqualStrings(
        "rtsp://[::1]/s",
        try targetOf(&out, "rtsp://[::1]:554/s"),
    );
}

test "the query is kept and the fragment is dropped" {
    // A fragment never leaves the client, RFC 3986 section 3.5.
    var out: Storage = undefined;
    try testing.expectEqualStrings(
        "rtsp://h/s?track=1",
        try targetOf(&out, "rtsp://h/s?track=1"),
    );
    try testing.expectEqualStrings(
        "rtsp://h/s",
        try targetOf(&out, "rtsp://h/s#top"),
    );
    try testing.expectEqualStrings(
        "rtsp://h/s?track=1",
        try targetOf(&out, "rtsp://h/s?track=1#top"),
    );
}

test "a url with no path writes the slash the parser supplies" {
    var out: Storage = undefined;
    try testing.expectEqualStrings("rtsp://h/", try targetOf(&out, "rtsp://h"));
    try testing.expectEqualStrings("rtsp://h/", try targetOf(&out, "rtsp://h/"));
}

test "a target longer than the bound is refused rather than cut" {
    // A cut target names a resource the user did not write.
    var out: Storage = undefined;
    var text: [max_target_bytes + 64]u8 = undefined;
    const head = "rtsp://h/";
    @memcpy(text[0..head.len], head);
    @memset(text[head.len..], 'z');
    try testing.expectError(error.TargetTooLong, targetOf(&out, &text));
}

test "every fault has a sentence of its own" {
    try testing.expect(describe(error.TargetTooLong).len != 0);
    try testing.expect(describe(error.NoHost).len != 0);
    try testing.expect(!std.mem.eql(
        u8,
        describe(error.TargetTooLong),
        describe(error.NoHost),
    ));
}
