//! What a `pop3://` url path names: one message, or the whole mailbox.
//!
//! Pure text. This module opens nothing and sends nothing, so every rule
//! here is testable with a table.
//!
//! **A url with no path lists and a url with a path retrieves.** That is
//! curl's own rule, measured against curl 8.21.0 on a loopback POP3
//! fixture: `pop3://h/` sends `LIST` and reads the body, and `pop3://h/1`
//! sends `RETR 1`. The path is the message number, which RFC 1939 calls
//! the message-number.
//!
//! **The order is decode, then check.** `zurl_core.url.parse` already
//! refuses a raw control byte in a path, so a percent escape is the only
//! way one can arrive, and it becomes a byte only at the decode here. A CR
//! or an LF in the message number would end the `RETR` line and write a
//! command of the url's own choosing, and `DELE` is a command it could
//! write. `command.write` refuses the same three bytes again at the
//! socket. This is the check that names the url instead of the command.
//!
//! **The whole path is one argument, slashes included.** RFC 1939 has no
//! directory, so there is nothing to split. curl sends the path as it
//! stands: measured, `pop3://h/abc` reaches the wire as `RETR abc`, so a
//! path that is not a number is the server's business and not this
//! module's.

const std = @import("std");
const zurl_core = @import("zurl-core");

/// How many bytes of a decoded message number this holds.
///
/// RFC 1939 sets no limit, and a real message number is a few digits. This
/// is far past any of them, and it is a bound because the number goes into
/// one command line and an unbounded one needs an unbounded buffer.
/// Passing it is `error.PathTooLong`.
pub const max_id_bytes = 256;

/// Why a url path was not read.
pub const ParseError = error{
    /// The decoded path is longer than `max_id_bytes`.
    PathTooLong,
    /// The path holds a percent escape that is not an escape.
    InvalidEscape,
    /// The decoded path holds a byte below 0x20.
    ///
    /// **This is the injection refusal.** A CR or an LF would end a
    /// command line and start one of the url's own, and `DELE` is a
    /// command that would then run. The other control bytes go with them
    /// because curl refuses the whole class in a url path.
    ///
    /// A DEL, 0x7f, is not in the class and is sent as it stands. It is
    /// not below 0x20 and it can frame nothing. `zurl-ftp` takes the same
    /// answer, and its report records that curl drops the byte instead.
    PathHasControlByte,
};

/// One url path, read.
///
/// **A `Target` must not move once `parse` has run.** `id` points into
/// `bytes`, which is a field of this value.
pub const Target = struct {
    /// The decoded path. `id` points into this.
    bytes: [max_id_bytes]u8,
    /// The message the url names, or an empty slice when it names none.
    id: []const u8,
    /// True when the url names no message, which is a listing.
    listing: bool,

    /// A `Target` that names nothing yet.
    pub const empty: Target = .{
        .bytes = undefined,
        .id = "",
        .listing = true,
    };

    /// Reads `path` into `t`.
    ///
    /// `path` is the url path as `zurl_core.url.parse` left it, still
    /// escaped and always starting with a `/`. The query and the fragment
    /// are not part of it.
    ///
    /// A path of `/` and a path of nothing both name the whole mailbox.
    pub fn parse(t: *Target, path: []const u8) ParseError!void {
        t.id = "";
        t.listing = true;

        if (path.len > t.bytes.len) return error.PathTooLong;
        const decoded = zurl_core.url.percentDecode(&t.bytes, path) catch
            return error.InvalidEscape;

        // **The refusal, after the decode.** See
        // `ParseError.PathHasControlByte`.
        if (zurl_core.url.hasControlByte(decoded)) return error.PathHasControlByte;

        // `zurl_core.url.parse` gives every url a path that starts with a
        // `/`, and a url that names no path at all gives an empty one.
        const body = if (std.mem.startsWith(u8, decoded, "/")) decoded[1..] else decoded;
        if (body.len == 0) return;

        t.id = body;
        t.listing = false;
    }
};

const testing = std.testing;

test "a url with no path names the whole mailbox" {
    var t: Target = .empty;
    for ([_][]const u8{ "", "/" }) |path| {
        try t.parse(path);
        try testing.expect(t.listing);
        try testing.expectEqualStrings("", t.id);
    }
}

test "a url with a path names one message" {
    var t: Target = .empty;
    try t.parse("/1");
    try testing.expect(!t.listing);
    try testing.expectEqualStrings("1", t.id);

    try t.parse("/12345");
    try testing.expectEqualStrings("12345", t.id);
}

test "the whole path is one argument, because RFC 1939 has no directory" {
    // Measured against curl 8.21.0: `pop3://h/abc` reaches the wire as
    // `RETR abc`, so what the path holds is the server's business.
    var t: Target = .empty;
    try t.parse("/abc");
    try testing.expectEqualStrings("abc", t.id);

    try t.parse("/a/b");
    try testing.expectEqualStrings("a/b", t.id);

    // A percent escape becomes a byte here, and a space is an ordinary
    // byte in an argument.
    try t.parse("/a%20b");
    try testing.expectEqualStrings("a b", t.id);
}

test "a path that could forge a command is refused, and no socket opens" {
    // **The injection proof at the url.** A `%0d%0a` in the path would
    // otherwise end the `RETR` line and put a `DELE` behind it, which
    // `QUIT` would then make permanent.
    var t: Target = .empty;
    const forged = [_][]const u8{
        "/1%0d%0aDELE%202",
        "/1%0aDELE%202",
        "/1%0dDELE%202",
        "/1%00",
        "/%0d%0a",
        "/%0a",
        "/%0d",
        "/%00",
        "/1%09two",
        "/1%0bx",
        "/1%1fx",
    };
    for (forged) |path| {
        try testing.expectError(error.PathHasControlByte, t.parse(path));
    }

    // A DEL is not in the class. It is not below 0x20 and it can frame
    // nothing, so it reaches the command line as the url wrote it.
    try t.parse("/1%7f");
    try testing.expectEqualStrings("1\x7f", t.id);
}

test "a percent escape that is not an escape is refused" {
    var t: Target = .empty;
    for ([_][]const u8{ "/%", "/%z1", "/%0", "/%gg" }) |path| {
        try testing.expectError(error.InvalidEscape, t.parse(path));
    }
}

test "a path longer than the bound is refused" {
    var t: Target = .empty;
    var path: [max_id_bytes + 2]u8 = undefined;
    @memset(&path, 'x');
    path[0] = '/';
    try testing.expectError(error.PathTooLong, t.parse(&path));

    // One at the bound is read. The decode never grows a path, so a path
    // of exactly the bound always fits.
    try t.parse(path[0..max_id_bytes]);
    try testing.expectEqual(@as(usize, max_id_bytes - 1), t.id.len);
}
