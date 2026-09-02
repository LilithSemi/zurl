//! The map from a url to the one line a gopher request carries.
//!
//! This file reads text and writes text. It opens no socket and holds no
//! state, so every rule here is testable with a table.
//!
//! RFC 1436 gives the request one shape: the selector, then CRLF. There is
//! no header, no method, and no version. A type 7 search adds a TAB and
//! the search words to the same line, so the line can hold one TAB and
//! never a CR or an LF.
//!
//! **Every rule here was measured against curl 8.21.0**, with a listener
//! that captured the bytes and answered nothing.

const std = @import("std");
const zurl_core = @import("zurl-core");

/// How many bytes of url text this package reads for one selector.
///
/// A selector names a resource on a server, and a type 7 request adds the
/// words a user searched for. This bound is far past either. It exists
/// because the text comes from a url, which is untrusted input. curl keeps
/// no such bound.
pub const max_selector_bytes: usize = 4096;

/// How many bytes the whole request line comes to, the CRLF included.
pub const max_request_bytes: usize = max_selector_bytes + 2;

/// Joins the path and the query of `url` into `out`, the way curl builds
/// the text it takes the selector from.
///
/// curl reads the path and the query as one string: measured,
/// `gopher://h/1/dir?q` sends `/dir?q`, so the `?` and what follows it are
/// part of the selector. A fragment is not: `gopher://h/1/dir#f` sends
/// `/dir`, and `zurl_core.url.parse` has already cut the fragment off.
///
/// Returns `error.SelectorTooLong` when the two do not fit in `out`.
pub fn join(out: []u8, url: zurl_core.Url) error{SelectorTooLong}![]const u8 {
    const query = url.query orelse "";
    const total = url.path.len + if (url.query != null) 1 + query.len else 0;
    if (total > out.len) return error.SelectorTooLong;

    @memcpy(out[0..url.path.len], url.path);
    if (url.query == null) return out[0..url.path.len];
    out[url.path.len] = '?';
    @memcpy(out[url.path.len + 1 ..][0..query.len], query);
    return out[0..total];
}

/// The still-escaped selector text inside `joined`.
///
/// **A gopher url carries an item type that never goes on the wire.** The
/// path of `gopher://h/0/foo.txt` is `/0/foo.txt`: a `/`, the item type
/// `0`, and then the selector. curl drops the first two bytes and sends
/// the rest, measured:
///
/// | url path | sent |
/// | --- | --- |
/// | `/0/foo.txt` | `/foo.txt` |
/// | `/1/` | `/` |
/// | `/1/dir?q` | `/dir?q` |
/// | `/x` | the empty selector |
/// | `/` | the empty selector |
/// | `/a%20b` | `%20b`, which decodes to ` b` |
///
/// A text of two bytes or fewer is the empty selector. That is curl's own
/// rule and not a guess: `/x` is two bytes and sends nothing, and `/1/` is
/// three and sends `/`.
pub fn strip(joined: []const u8) []const u8 {
    if (joined.len <= 2) return "";
    return joined[2..];
}

/// The item type the url named, or null when the url named none.
///
/// The second byte of the path, which `strip` drops. A caller reports it;
/// nothing on the wire carries it. A url with a path of `/` or shorter
/// names no type.
///
/// Nothing in this package branches on the type. curl does not either: it
/// writes the same request line for `gopher://h/0/x` and `gopher://h/9/x`,
/// measured, and it writes the answer through with no transformation. The
/// type is a hint to whoever displays the answer.
pub fn itemType(joined: []const u8) ?u8 {
    if (joined.len < 2) return null;
    return joined[1];
}

/// Writes the request line for the escaped text `escaped_selector` into
/// `out`: the decoded selector, then CRLF.
///
/// **The decode runs before the check, and the check runs before the
/// write.** A url writes `%0d%0a` as five printable characters, which
/// `zurl_core.url.parse` accepts, so the only place a CR can appear is
/// after the decode. `zurl_core.url.hasFramingByte` is asked there, and a
/// url that holds one is refused whole.
///
/// **This is stricter than curl.** Measured: curl 8.21.0 sends
/// `gopher://h/1a%0d%0ab` as `<CR><LF>b<CR><LF>`, which is two request
/// lines where the url named one. A gopher server reads one line for one
/// request, so the second line is a request the user never wrote.
///
/// A TAB passes, and it must. RFC 1436 makes a type 7 request the
/// selector, a TAB, and the search words, so a client that refused a TAB
/// could send no search at all. curl sends `gopher://h/7/search%09term`
/// as `search<TAB>term`, measured, and so does this.
///
/// An escape that does not decode leaves the text alone, which is what
/// `zurl-file` and `zurl-dict` do with one too.
pub fn writeRequest(
    out: []u8,
    escaped_selector: []const u8,
) error{ SelectorTooLong, SelectorHasFramingByte }![]const u8 {
    if (escaped_selector.len + 2 > out.len) return error.SelectorTooLong;

    const decoded = zurl_core.url.percentDecode(
        out[0 .. out.len - 2],
        escaped_selector,
    ) catch |err| switch (err) {
        error.InvalidEscape => escape: {
            @memcpy(out[0..escaped_selector.len], escaped_selector);
            break :escape out[0..escaped_selector.len];
        },
        // The decoded form is never longer than the escaped form, and the
        // check above already refused a text that does not fit. A named
        // fault and not an `unreachable`, which a ReleaseFast build turns
        // into undefined behaviour.
        error.NoSpaceLeft => return error.SelectorTooLong,
    };

    if (zurl_core.url.hasFramingByte(decoded)) return error.SelectorHasFramingByte;

    out[decoded.len] = '\r';
    out[decoded.len + 1] = '\n';
    return out[0 .. decoded.len + 2];
}

const testing = std.testing;

/// The request line the path `path` produces, with no query.
fn requestFor(out: []u8, path: []const u8) ![]const u8 {
    var joined: [max_selector_bytes]u8 = undefined;
    const text = try join(&joined, .{
        .scheme = "gopher",
        .user = null,
        .password = null,
        .host = "example.com",
        .port = 70,
        .path = path,
        .query = null,
        .fragment = null,
    });
    return writeRequest(out, strip(text));
}

test "every request row measured against curl 8.21.0" {
    var out: [max_request_bytes]u8 = undefined;
    const rows = [_]struct { path: []const u8, want: []const u8 }{
        .{ .path = "/", .want = "\r\n" },
        .{ .path = "/x", .want = "\r\n" },
        .{ .path = "/1/", .want = "/\r\n" },
        .{ .path = "/0/foo.txt", .want = "/foo.txt\r\n" },
        .{ .path = "/1/dir", .want = "/dir\r\n" },
        // The escape decodes, and the space reaches the wire.
        .{ .path = "/a%20b", .want = " b\r\n" },
        // A TAB is data on this line: it is what a type 7 search sends.
        .{ .path = "/7/search%09term", .want = "/search\tterm\r\n" },
        .{ .path = "/1search%09term", .want = "search\tterm\r\n" },
        // An escape that does not decode stays as it reads.
        .{ .path = "/1/a%zzb", .want = "/a%zzb\r\n" },
    };
    for (rows) |row| {
        try testing.expectEqualStrings(row.want, try requestFor(&out, row.path));
    }
}

test "the query is part of the selector and the fragment is not" {
    // Measured: `gopher://h/1/dir?q` sends `/dir?q`, and
    // `gopher://h/1/dir#f` sends `/dir`. `zurl_core.url.parse` cuts the
    // fragment off before this file sees the url, so only the query
    // needs work here.
    var joined: [max_selector_bytes]u8 = undefined;
    const url: zurl_core.Url = .{
        .scheme = "gopher",
        .user = null,
        .password = null,
        .host = "example.com",
        .port = 70,
        .path = "/1/dir",
        .query = "q",
        .fragment = "f",
    };
    try testing.expectEqualStrings("/1/dir?q", try join(&joined, url));
    try testing.expectEqualStrings("/dir?q", strip(try join(&joined, url)));

    // An empty query still writes its `?`, because the url held one.
    var empty = url;
    empty.query = "";
    try testing.expectEqualStrings("/1/dir?", try join(&joined, empty));

    // And a url with no query writes none.
    var none = url;
    none.query = null;
    try testing.expectEqualStrings("/1/dir", try join(&joined, none));
}

test "a decoded framing byte is refused, where curl sends it" {
    // **The injection proof for this package.** Measured: curl 8.21.0
    // sends `gopher://h/1a%0d%0ab` as `<CR><LF>b<CR><LF>`, two request
    // lines from a url that named one. This refuses the url instead.
    var out: [max_request_bytes]u8 = undefined;
    const paths = [_][]const u8{
        "/1a%0d%0ab",
        "/1a%0db",
        "/1a%0ab",
        "/1a%00b",
        "/1%0d%0aGET / HTTP/1.0",
    };
    for (paths) |path| {
        try testing.expectError(error.SelectorHasFramingByte, requestFor(&out, path));
    }

    // And nothing else below 0x20 is refused, because nothing else ends
    // a line. curl sends each of them, and so does this.
    try testing.expectEqualStrings("a\x01b\r\n", try requestFor(&out, "/1a%01b"));
    try testing.expectEqualStrings("a\x1fb\r\n", try requestFor(&out, "/1a%1fb"));
}

test "the item type is reported and never sent" {
    var joined: [max_selector_bytes]u8 = undefined;
    const url: zurl_core.Url = .{
        .scheme = "gopher",
        .user = null,
        .password = null,
        .host = "example.com",
        .port = 70,
        .path = "/0/foo.txt",
        .query = null,
        .fragment = null,
    };
    const text = try join(&joined, url);
    try testing.expectEqual(@as(?u8, '0'), itemType(text));
    try testing.expectEqualStrings("/foo.txt", strip(text));

    try testing.expectEqual(@as(?u8, null), itemType("/"));
    try testing.expectEqual(@as(?u8, null), itemType(""));
    try testing.expectEqual(@as(?u8, '7'), itemType("/7"));
}

test "a selector past the bound is refused rather than cut" {
    var out: [64]u8 = undefined;
    var long: [64]u8 = undefined;
    @memset(&long, 'a');
    try testing.expectError(error.SelectorTooLong, writeRequest(&out, &long));

    // And the join has its own bound, for the same reason.
    var small: [4]u8 = undefined;
    try testing.expectError(error.SelectorTooLong, join(&small, .{
        .scheme = "gopher",
        .user = null,
        .password = null,
        .host = "example.com",
        .port = 70,
        .path = "/1/dir",
        .query = null,
        .fragment = null,
    }));
}

test "a selector of exactly the bound still fits the request line" {
    var out: [max_request_bytes]u8 = undefined;
    var selector: [max_selector_bytes]u8 = undefined;
    @memset(&selector, 'a');
    const line = try writeRequest(&out, selector[0 .. max_selector_bytes - 2]);
    try testing.expectEqual(max_selector_bytes, line.len);
    try testing.expectEqualStrings("\r\n", line[line.len - 2 ..]);
}
