//! Masks the userinfo password in a url, so no diagnostic can carry one.
//!
//! zurl prints a url in a failure message, and a url may hold a password.
//! A message that carried it would put the password in a CI log, a
//! journal, or a shell transcript. This module holds the one rule that
//! stops that, and two callers share it: `Diagnostics.record`, which masks
//! every url it stores, and the CLI's own printer for untrusted text.
//!
//! This module does no I/O and allocates nothing.

const std = @import("std");

/// The text that replaces a password.
pub const mask = "***";

/// The half-open byte range of a userinfo password within a url.
pub const Range = struct { start: usize, end: usize };

/// Finds the byte range in `text` that holds a userinfo password, if
/// `text` has one.
///
/// Mirrors `zurl_core.url.parse`'s own rule for the same reason it uses
/// one: the authority ends at the first `/`, `?`, or `#` after the scheme,
/// and userinfo within it ends at the *last* `@`, because a password may
/// contain one. This runs on raw, possibly unparsed text, so it does not
/// call `url.parse` itself: a url that fails to parse, such as a bad port,
/// must still have its password masked before it reaches a message.
///
/// When that rule finds nothing, a wider one runs. A password holding a
/// `/`, a `?`, or a `#` puts the `@` past where the authority appears to
/// end, so the rule above misses it and the password reached the message
/// whole. The wider rule masks from the first `:` after the scheme to the
/// *last* `@` anywhere in the text.
///
/// The wider rule can mask more than a password. `http://h:8080/a@b` has
/// no userinfo, yet it matches, and its masked form reads
/// `http://h:***@b`. That direction is the safe one: a diagnostic that
/// says less is a cost, and a diagnostic that leaks a password is a fault.
pub fn passwordRange(text: []const u8) ?Range {
    const authority_start = if (std.mem.indexOf(u8, text, "://")) |i| i + 3 else 0;

    var authority_end = text.len;
    for ([_]u8{ '/', '?', '#' }) |sep| {
        if (std.mem.indexOfScalarPos(u8, text, authority_start, sep)) |i| {
            authority_end = @min(authority_end, i);
        }
    }

    const authority = text[authority_start..authority_end];
    if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at_sign| {
        const userinfo = authority[0..at_sign];
        if (std.mem.indexOfScalar(u8, userinfo, ':')) |colon| {
            return .{ .start = authority_start + colon + 1, .end = authority_start + at_sign };
        }
    }

    const last_at = std.mem.lastIndexOfScalar(u8, text, '@') orelse return null;
    if (last_at <= authority_start) return null;
    const colon = std.mem.indexOfScalarPos(u8, text, authority_start, ':') orelse return null;
    if (colon >= last_at) return null;
    return .{ .start = colon + 1, .end = last_at };
}

/// Copies `text` into `out`, with any userinfo password replaced by
/// `mask`, and returns the copied range.
///
/// The result cannot alias `text`: replacing the password changes the
/// length, so a masked url needs storage of its own.
///
/// A url longer than `out` loses its tail, never its masked password,
/// because the password sits near the front, right after the scheme, and
/// this masks it before it copies anything past that point.
pub fn copy(out: []u8, text: []const u8) []const u8 {
    var at: usize = 0;
    if (passwordRange(text)) |r| {
        boundedCopy(out, &at, text[0..r.start]);
        boundedCopy(out, &at, mask);
        boundedCopy(out, &at, text[r.end..]);
    } else {
        boundedCopy(out, &at, text);
    }
    return out[0..at];
}

/// Appends as much of `text` as fits past `at.*` in `out`, and advances
/// `at.*` by however much that was. Never writes past `out.len`: a `text`
/// that does not fully fit is truncated, not refused, because this backs a
/// diagnostic message, not a value anything parses back.
fn boundedCopy(out: []u8, at: *usize, text: []const u8) void {
    const n = @min(out.len - at.*, text.len);
    @memcpy(out[at.*..][0..n], text[0..n]);
    at.* += n;
}

const testing = std.testing;

test "copy masks a password that holds a delimiter" {
    // The authority rule alone ends the authority at the first `/`, `?`,
    // or `#`, so a password holding one of those used to slip through it
    // whole. The wider rule catches these.
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings(
        "http://bob:***@example.com/x",
        copy(&buf, "http://bob:pa/ss@example.com/x"),
    );
    try testing.expectEqualStrings(
        "http://bob:***@example.com/x",
        copy(&buf, "http://bob:pa?ss@example.com/x"),
    );
    try testing.expectEqualStrings(
        "http://bob:***@example.com/x",
        copy(&buf, "http://bob:pa#ss@example.com/x"),
    );
    try testing.expectEqualStrings(
        "http://bob:***@example.com/x",
        copy(&buf, "http://bob:12/34@example.com/x"),
    );
}

test "copy masks more than a password rather than risk leaking one" {
    // Neither of these urls carries userinfo. The wider rule still fires,
    // because it cannot tell this shape from a password that holds a
    // delimiter. A diagnostic that says less is the price.
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings(
        "http://example.com:***@b",
        copy(&buf, "http://example.com:8080/a@b"),
    );
    // No colon after the scheme, so nothing matches and the text stands.
    try testing.expectEqualStrings(
        "http://example.com/a@b",
        copy(&buf, "http://example.com/a@b"),
    );
}

test "copy masks the password but keeps the rest of the url" {
    var buf: [128]u8 = undefined;
    const out = copy(&buf, "https://alice:s3cret@example.com:8443/a/b?q=1#top");
    try testing.expectEqualStrings("https://alice:***@example.com:8443/a/b?q=1#top", out);
}

test "copy leaves a url with no userinfo unchanged" {
    var buf: [64]u8 = undefined;
    const out = copy(&buf, "https://example.com/a");
    try testing.expectEqualStrings("https://example.com/a", out);
}

test "copy masks a password even in a url that fails to parse" {
    // A url reaches a diagnostic on the path that could not parse it, so
    // redaction cannot depend on the url being valid. A bad port is enough
    // to fail `url.parse` and must still mask.
    var buf: [64]u8 = undefined;
    const out = copy(&buf, "http://bob:hunter2@example.com:not-a-port/");
    try testing.expectEqualStrings("http://bob:***@example.com:not-a-port/", out);
}

test "copy reads an IPv6 authority by the same rule as any other" {
    // The colons of an address are not the colon of a userinfo. The
    // authority rule ends userinfo at the last `@`, and an address holds
    // none, so a url that names only an address stands as it is.
    var buf: [96]u8 = undefined;
    try testing.expectEqualStrings(
        "http://[::1]:8080/x",
        copy(&buf, "http://[::1]:8080/x"),
    );
    try testing.expectEqualStrings(
        "https://[2606:4700:4700::1111]/a?q=1",
        copy(&buf, "https://[2606:4700:4700::1111]/a?q=1"),
    );
    // A real password over an address is masked, and the address stands.
    try testing.expectEqualStrings(
        "http://bob:***@[::1]:8080/x",
        copy(&buf, "http://bob:hunter2@[::1]:8080/x"),
    );
    // The wider rule still masks more than a password, exactly as it does
    // for a name. `http://example.com:8080/a@b` reads the same way, and
    // saying less is the price of never leaking one.
    try testing.expectEqualStrings(
        "http://[:***@b",
        copy(&buf, "http://[::1]:8080/a@b"),
    );
}

test "copy keeps a user with no password unchanged" {
    var buf: [64]u8 = undefined;
    const out = copy(&buf, "https://alice@example.com/a");
    try testing.expectEqualStrings("https://alice@example.com/a", out);
}

test "copy truncates a url that does not fit, and still masks it" {
    var buf: [20]u8 = undefined;
    const out = copy(&buf, "http://bob:hunter2@example.com/a/very/long/path");
    try testing.expectEqualStrings("http://bob:***@examp", out);
    try testing.expect(std.mem.indexOf(u8, out, "hunter2") == null);
}
