//! What an `ftp://` url path names: the directories to change into, and
//! the file to fetch or the directory to list.
//!
//! Pure text. This module opens nothing and sends nothing, so every rule
//! here is testable with a table.
//!
//! **The order is decode, then check, then split.** curl 8.21.0 does the
//! same, measured: `ftp://h/a%20b/c%2Fd.txt` reaches the wire from curl as
//! `CWD a b`, `CWD c`, `RETR d.txt`, so a `%2F` becomes a separator and
//! not a slash inside a name. A reader that split first and decoded after
//! would send `RETR c/d.txt` instead, which names a different file.
//!
//! **The check is between the other two, and it is the injection
//! refusal.** `zurl_core.url.parse` already refuses a raw control byte in
//! a path, so a percent escape is the only way one can arrive, and it
//! becomes a byte only at the decode above. A CR or an LF in a component
//! would end an `CWD` or a `RETR` line and write a command of the url's
//! choosing. `command.write` refuses the same three bytes again at the
//! socket, and this is the check that names the url instead of the
//! command.
//!
//! What this does not read: the `;type=a` and `;type=i` suffix of RFC
//! 1738. curl reads it and sets the representation type from it, measured.
//! zurl sends the suffix as part of the file name, and `--help` says so.

const std = @import("std");
const zurl_core = @import("zurl-core");

/// How many bytes of a decoded path this holds.
///
/// A path longer than this is `error.PathTooLong`. Every component of it
/// goes into one command line, and `command.max_command_bytes` bounds
/// that, so this is the smaller of the two bounds and it is the one a user
/// meets first.
pub const max_path_bytes = 1024;

/// How many directories one path may name.
///
/// Each one is its own `CWD` command and its own round trip, so a path of
/// a thousand components would be a thousand round trips from one url.
/// Past this is `error.TooManyComponents`.
pub const max_components = 64;

/// Why a url path was not read.
pub const ParseError = error{
    /// The decoded path is longer than `max_path_bytes`.
    PathTooLong,
    /// The path names more directories than `max_components`.
    TooManyComponents,
    /// The path holds a percent escape that is not an escape.
    InvalidEscape,
    /// The decoded path holds a byte below 0x20.
    ///
    /// **This is the injection refusal.** A CR or an LF would end a
    /// command line and start one of the url's own. The other control
    /// bytes go with them because curl refuses the whole class: measured,
    /// `ftp://h/a%09b.txt` and `ftp://h/a%00b.txt` both exit 3 with `path
    /// contains control characters`, and no `CWD` or `RETR` reaches the
    /// server.
    PathHasControlByte,
};

/// One url path, read.
///
/// **A `Target` must not move once `parse` has run.** `directories` and
/// `name` point into `bytes`, which is a field of this value.
pub const Target = struct {
    /// The decoded path. `directories` and `name` point into this.
    bytes: [max_path_bytes]u8,
    /// One entry for each directory to `CWD` into, in the order the
    /// commands go out. Only the first `directory_count` are filled.
    directories: [max_components][]const u8,
    directory_count: usize,
    /// The file to fetch, or an empty slice when the url names a
    /// directory.
    name: []const u8,
    /// True when the url names a directory, which is a path that ends
    /// with a `/`. Such a url is a listing and never a `RETR`.
    listing: bool,

    /// A `Target` that names nothing yet.
    pub const empty: Target = .{
        .bytes = undefined,
        .directories = undefined,
        .directory_count = 0,
        .name = "",
        .listing = false,
    };

    /// The directories to change into, in order.
    pub fn dirs(t: *const Target) []const []const u8 {
        return t.directories[0..t.directory_count];
    }

    /// Reads `path` into `t`.
    ///
    /// `path` is the url path as `zurl_core.url.parse` left it, still
    /// escaped and always starting with a `/`. The query and the fragment
    /// are not part of it, which is what curl does too: measured,
    /// `ftp://h/f.txt?x=1` and `ftp://h/f.txt#top` both reach the wire as
    /// `RETR f.txt`.
    ///
    /// **A leading `//` names an absolute path.** RFC 1738 makes the path
    /// of an `ftp://` url relative to the login directory, and a leading
    /// empty component the way out of it. curl writes `CWD /` for that
    /// component, measured with `ftp://h//a//f.txt`, which reaches the
    /// wire as `CWD /`, `CWD a`, `RETR f.txt`. So does this. Every other
    /// empty component is dropped, because `a//b` and `a/b` name one
    /// place.
    ///
    /// **A `.` or a `..` component is sent as the url wrote it.** curl
    /// removes both before it sends anything: measured,
    /// `ftp://h/../etc/passwd` reaches the wire from curl as `CWD etc`
    /// alone. zurl sends `CWD ..` and then `CWD etc`, which is the path
    /// the user typed. Both reach the same file on a server that has one,
    /// because `CWD ..` is the server's own way up. The difference is that
    /// a curl user cannot ask to go up at all, and a zurl user can.
    pub fn parse(t: *Target, path: []const u8) ParseError!void {
        t.directory_count = 0;
        t.name = "";
        t.listing = false;

        if (path.len > t.bytes.len) return error.PathTooLong;
        const decoded = zurl_core.url.percentDecode(&t.bytes, path) catch
            return error.InvalidEscape;

        // **The refusal, after the decode and before the split.** See
        // `ParseError.PathHasControlByte`.
        if (zurl_core.url.hasControlByte(decoded)) return error.PathHasControlByte;

        // `zurl_core.url.parse` gives every url a path that starts with a
        // `/`, so the first field of the split is always empty and it is
        // never a component.
        var fields: [max_components + 2][]const u8 = undefined;
        var field_count: usize = 0;
        var it = std.mem.splitScalar(u8, decoded, '/');
        while (it.next()) |field| {
            if (field_count == fields.len) return error.TooManyComponents;
            fields[field_count] = field;
            field_count += 1;
        }
        // A path of "" cannot arrive, and a path of "/" gives two empty
        // fields. Either way the loop above ran at least once.
        std.debug.assert(field_count >= 1);

        const last = fields[field_count - 1];
        t.listing = last.len == 0;
        t.name = last;

        var i: usize = 1;
        while (i + 1 < field_count) : (i += 1) {
            const field = fields[i];
            if (field.len == 0) {
                // The one empty component that means something: a path
                // that starts `//` is absolute from the server root.
                if (i == 1) try t.addDirectory("/");
                continue;
            }
            try t.addDirectory(field);
        }
    }

    fn addDirectory(t: *Target, text: []const u8) ParseError!void {
        if (t.directory_count == t.directories.len) return error.TooManyComponents;
        t.directories[t.directory_count] = text;
        t.directory_count += 1;
    }
};

const testing = std.testing;

/// Runs `Target.parse` and returns the directories joined with `|`, then
/// `>` and the name, so a table test reads as one string.
fn described(t: *Target, path: []const u8) ![]const u8 {
    try t.parse(path);
    const out = struct {
        var storage: [max_path_bytes * 2]u8 = undefined;
    };
    var at: usize = 0;
    for (t.dirs(), 0..) |dir, i| {
        if (i != 0) {
            out.storage[at] = '|';
            at += 1;
        }
        @memcpy(out.storage[at..][0..dir.len], dir);
        at += dir.len;
    }
    out.storage[at] = '>';
    at += 1;
    @memcpy(out.storage[at..][0..t.name.len], t.name);
    at += t.name.len;
    return out.storage[0..at];
}

test "a path names the directories to change into and the file to fetch" {
    var t: Target = .empty;
    const rows = [_]struct { path: []const u8, want: []const u8, listing: bool }{
        // Measured against curl 8.21.0 on a loopback RFC 959 server.
        .{ .path = "/f.txt", .want = ">f.txt", .listing = false },
        .{ .path = "/a/b/c.txt", .want = "a|b>c.txt", .listing = false },
        .{ .path = "/", .want = ">", .listing = true },
        .{ .path = "/a/b/", .want = "a|b>", .listing = true },
        .{ .path = "/a/", .want = "a>", .listing = true },
        // A leading `//` is the way out of the login directory.
        .{ .path = "//a//f.txt", .want = "/|a>f.txt", .listing = false },
        .{ .path = "//f.txt", .want = "/>f.txt", .listing = false },
        // Every other empty component is dropped.
        .{ .path = "/a//b/f.txt", .want = "a|b>f.txt", .listing = false },
        // Dot segments go out as the url wrote them. curl removes both.
        .{ .path = "/../etc/passwd", .want = "..|etc>passwd", .listing = false },
        .{ .path = "/a/./f.txt", .want = "a|.>f.txt", .listing = false },
    };
    for (rows) |row| {
        try testing.expectEqualStrings(row.want, try described(&t, row.path));
        try testing.expectEqual(row.listing, t.listing);
    }
}

test "the path is decoded before it is split, the way curl does it" {
    // **Measured**: `ftp://h/a%20b/c%2Fd.txt` reaches the wire from curl
    // 8.21.0 as `CWD a b`, `CWD c`, `SIZE d.txt`, `RETR d.txt`. So a
    // `%2F` is a separator and never a slash inside a name.
    var t: Target = .empty;
    try testing.expectEqualStrings("a b|c>d.txt", try described(&t, "/a%20b/c%2Fd.txt"));
    try testing.expectEqualStrings(">a b.txt", try described(&t, "/a%20b.txt"));
    // A decode runs once, so `%2520` gives the four characters `%20`.
    try testing.expectEqualStrings(">a%20b", try described(&t, "/a%2520b"));
    // A high byte passes through whole.
    try testing.expectEqualStrings(">\xc3\xa9", try described(&t, "/%c3%a9"));
    // A DEL is not a control byte below 0x20, so it reaches the command.
    // curl drops the byte and sends `ab.txt`, measured.
    try testing.expectEqualStrings(">a\x7fb.txt", try described(&t, "/a%7fb.txt"));
}

test "a control byte in the decoded path is refused, whatever the escape spelled" {
    // **The injection refusal.** Each of these would end a command line
    // and write one of its own behind it.
    var t: Target = .empty;
    const forged = [_][]const u8{
        "/a%0d%0aQUIT",
        "/a%0aQUIT",
        "/a%0db",
        "/a%00b",
        "/a%09b",
        "/%0d%0aDELE%20important",
        "/dir%0d%0aRETR%20secret/f.txt",
        "/a/b%0d%0aQUIT/c.txt",
        "/a%1fb",
        "/a%01b",
    };
    for (forged) |path| {
        try testing.expectError(error.PathHasControlByte, t.parse(path));
    }
}

test "an escape that is not an escape is refused by name" {
    var t: Target = .empty;
    try testing.expectError(error.InvalidEscape, t.parse("/a%zzb"));
    try testing.expectError(error.InvalidEscape, t.parse("/a%2"));
}

test "a path past its bound is refused, and one at the bound is read" {
    var t: Target = .empty;
    var path: [max_path_bytes + 1]u8 = undefined;
    @memset(&path, 'x');
    path[0] = '/';

    try t.parse(path[0..max_path_bytes]);
    try testing.expectEqual(@as(usize, max_path_bytes - 1), t.name.len);

    try testing.expectError(error.PathTooLong, t.parse(path[0 .. max_path_bytes + 1]));
}

test "a path with more directories than the bound is refused" {
    var t: Target = .empty;
    var path: [max_path_bytes]u8 = undefined;

    // `max_components` directories, then the name, is the largest path
    // this reads: "/d" that many times, and then "/f".
    var at: usize = 0;
    var i: usize = 0;
    while (i < max_components) : (i += 1) {
        path[at] = '/';
        path[at + 1] = 'd';
        at += 2;
    }
    @memcpy(path[at..][0..2], "/f");
    at += 2;
    try t.parse(path[0..at]);
    try testing.expectEqual(max_components, t.directory_count);
    try testing.expectEqualStrings("f", t.name);

    // One directory more does not fit.
    @memcpy(path[at..][0..2], "/g");
    try testing.expectError(error.TooManyComponents, t.parse(path[0 .. at + 2]));
}
