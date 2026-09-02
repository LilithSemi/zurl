//! The bytes one `dict://` transfer writes, and the url rules behind them.
//!
//! This file owns the map from a url path to an RFC 2229 session. It reads
//! text and writes text. It opens no socket, it reads no response, and it
//! holds no state, so every rule here is testable with a table.
//!
//! What it does not own: the dial, the read of the answer, and the bound
//! on that answer. `Fetcher.zig` owns all three.
//!
//! **Every rule here was measured against curl 8.21.0**, with a listener
//! that captured the bytes and answered nothing. The captures are in the
//! doc comment of each function.

const std = @import("std");
const zurl_core = @import("zurl-core");

const Writer = std.Io.Writer;

/// The text of the `CLIENT` line, which RFC 2229 makes a client send
/// first.
///
/// A constant, and not the transfer's user agent. curl 8.21.0 sends
/// `CLIENT libcurl 8.21.0` whatever `-A` names, measured with
/// `curl -A mybot/1 dict://...`, so `-A` changes nothing here either. The
/// text matches the default of `zurl.Transfer.Options.user_agent`, so a
/// dict server logs the same name an http server logs.
pub const client_id = "zurl/0.1";

/// The database a url that names none asks for.
///
/// `!` is RFC 2229's "the first database with a match". curl 8.21.0 sends
/// it for `dict://h/d:hello`, measured.
pub const default_database = "!";

/// The strategy a `MATCH` url that names none asks for.
///
/// `.` is RFC 2229's "the server's own default strategy". curl 8.21.0
/// sends it for `dict://h/m:hello`, measured.
pub const default_strategy = ".";

/// The word a url that names an empty one asks for.
///
/// curl 8.21.0 answers `dict://h/d:` with `DEFINE ! default`, measured. So
/// the empty word is not a fault and it is not an empty field: it is this
/// literal.
pub const default_word = "default";

/// How many bytes of decoded path this package reads.
///
/// A dict word, a database name, and a strategy name are all short. This
/// bound is far past any of them, and it exists because the path comes
/// from a url, which is untrusted input. curl keeps no such bound.
pub const max_path_bytes: usize = 2048;

/// How many bytes the whole session can come to.
///
/// The escape below can put a backslash in front of every byte of the
/// word, so a path at `max_path_bytes` can double. The rest is the
/// `CLIENT` line, the command name, and the `QUIT` line, which together
/// are under a hundred bytes.
pub const max_request_bytes: usize = 2 * max_path_bytes + 128;

/// Which command a path asks for.
pub const Kind = enum {
    /// `DEFINE`. The path starts `d:`, `define:`, or `lookup:`.
    define,
    /// `MATCH`. The path starts `m:`, `match:`, or `find:`.
    match,
    /// The path is the command line itself. See `writeCommand`.
    raw,
};

/// The prefixes that name a command, and the command each one names.
///
/// Read without regard to case: curl 8.21.0 answers `dict://h/D:hello` and
/// `dict://h/DEFINE:hello` with `DEFINE ! hello`, measured.
const prefixes = [_]struct { text: []const u8, kind: Kind }{
    .{ .text = "d:", .kind = .define },
    .{ .text = "define:", .kind = .define },
    .{ .text = "lookup:", .kind = .define },
    .{ .text = "m:", .kind = .match },
    .{ .text = "match:", .kind = .match },
    .{ .text = "find:", .kind = .match },
};

/// Which command `path` asks for, and the text after the prefix.
///
/// `path` has one leading `/` taken off already. See `writeSession`.
pub fn classify(path: []const u8) struct { kind: Kind, rest: []const u8 } {
    for (prefixes) |entry| {
        if (path.len >= entry.text.len and
            std.ascii.eqlIgnoreCase(path[0..entry.text.len], entry.text))
        {
            return .{ .kind = entry.kind, .rest = path[entry.text.len..] };
        }
    }
    return .{ .kind = .raw, .rest = path };
}

/// The `n`th `:` separated field of `text`, or an empty slice when there
/// are fewer than `n + 1` fields.
///
/// curl splits the text after the prefix on `:` and reads the fields by
/// position, so a field a url leaves out and a field a url writes empty
/// are one thing. Measured: `dict://h/d:hello:wn:5:extra` sends
/// `DEFINE wn hello`, so a field past the last one this command reads is
/// dropped and is not a fault.
pub fn field(text: []const u8, n: usize) []const u8 {
    var rest = text;
    var at: usize = 0;
    while (true) {
        const colon = std.mem.indexOfScalar(u8, rest, ':');
        const part = if (colon) |i| rest[0..i] else rest;
        if (at == n) return part;
        at += 1;
        const i = colon orelse return "";
        rest = rest[i + 1 ..];
    }
}

/// Writes `text` with the RFC 2229 escape in front of each byte that needs
/// one.
///
/// Section 2.2 of RFC 2229 gives a client a backslash escape for a
/// character a command line cannot carry plainly. curl 8.21.0 escapes a
/// byte at or below 0x20, a DEL, a single quote, a double quote, and a
/// backslash, measured: `dict://h/d:a%20b` sends `DEFINE ! a\ b`,
/// `d:%22quote%22` sends `DEFINE ! \"quote\"`, `d:back%5Cslash` sends
/// `DEFINE ! back\\slash`, and `d:a%7fb` sends `DEFINE ! a\<DEL>`.
///
/// **A byte below 0x20 never reaches here.** `writeSession` refuses the
/// whole url for one, so the escape covers a space, a DEL, and the three
/// punctuation marks alone. A backslash in front of a raw CR would not
/// stop the CR ending the line, which is why that byte is refused and not
/// escaped.
pub fn writeEscaped(w: *Writer, text: []const u8) Writer.Error!void {
    for (text) |byte| {
        switch (byte) {
            0x20, 0x7f, '\'', '"', '\\' => try w.writeByte('\\'),
            else => {},
        }
        try w.writeByte(byte);
    }
}

/// Writes the one command line that `path` asks for, with no line ending.
///
/// `path` is the decoded url path with one leading `/` taken off. Every
/// row below was measured against curl 8.21.0.
///
/// | path | command |
/// | --- | --- |
/// | `d:hello` | `DEFINE ! hello` |
/// | `d:hello:wn` | `DEFINE wn hello` |
/// | `d:hello:wn:5` | `DEFINE wn hello`, the count dropped |
/// | `d:` | `DEFINE ! default` |
/// | `m:hello` | `MATCH ! . hello` |
/// | `m:hello:wn:exact` | `MATCH wn exact hello` |
/// | `hello` | `hello` |
/// | `x:y:z` | `x y z` |
/// | `` | the empty line |
///
/// **The raw row is curl's own answer and not a fallback.** A path that
/// names no command is sent as the command, with each `:` turned into a
/// space. Measured: `dict://h/x:y:z` sends `x y z`. So a user reaches
/// `SHOW DB` with `dict://h/SHOW:DB`.
///
/// **zurl escapes the database and the strategy, and curl escapes the word
/// alone.** Measured: `dict://h/d:hello:w%20n` sends `DEFINE w n hello`
/// from curl, which is a `DEFINE` with a word of `n` and a count of
/// `hello`, so a space in a database name changes the command curl sends.
/// zurl writes `DEFINE w\ n hello` for the same url. Every database name
/// and every strategy name RFC 2229 allows is an atom with no space in it,
/// so the two agree for every real name.
pub fn writeCommand(w: *Writer, path: []const u8) Writer.Error!void {
    const parsed = classify(path);
    switch (parsed.kind) {
        .define => {
            try w.writeAll("DEFINE ");
            try writeEscaped(w, databaseOf(parsed.rest, 1));
            try w.writeByte(' ');
            try writeEscaped(w, wordOf(field(parsed.rest, 0)));
        },
        .match => {
            try w.writeAll("MATCH ");
            try writeEscaped(w, databaseOf(parsed.rest, 1));
            try w.writeByte(' ');
            try writeEscaped(w, strategyOf(parsed.rest, 2));
            try w.writeByte(' ');
            try writeEscaped(w, wordOf(field(parsed.rest, 0)));
        },
        // Each `:` becomes a space, and nothing else changes. The text is
        // the command the user wrote, so it carries no escape: an escape
        // here would change a command line the user built by hand.
        .raw => for (parsed.rest) |byte| {
            try w.writeByte(if (byte == ':') ' ' else byte);
        },
    }
}

/// The word to send, which is `default_word` when the url named an empty
/// one.
fn wordOf(word: []const u8) []const u8 {
    return if (word.len == 0) default_word else word;
}

/// The database to send, which is `default_database` when the url named
/// none or named an empty one.
fn databaseOf(text: []const u8, n: usize) []const u8 {
    const named = field(text, n);
    return if (named.len == 0) default_database else named;
}

/// The strategy to send, which is `default_strategy` when the url named
/// none or named an empty one.
fn strategyOf(text: []const u8, n: usize) []const u8 {
    const named = field(text, n);
    return if (named.len == 0) default_strategy else named;
}

/// Writes the whole session: the `CLIENT` line, the command, and `QUIT`.
///
/// `path` is the decoded url path. One leading `/` comes off here.
///
/// Measured against curl 8.21.0, the three lines and their order:
///
/// ```
/// CLIENT libcurl 8.21.0\r\n
/// DEFINE ! hello\r\n
/// QUIT\r\n
/// ```
///
/// `QUIT` goes out with the command and not after the answer. curl writes
/// all three in one go and then reads until the server closes, so one
/// write serves the whole transfer and the server closes on its own.
///
/// **A path of exactly `/` sends an empty command line.** Measured:
/// `dict://h/` sends `CLIENT ...\r\n\r\nQUIT\r\n`, and `dict://h//` sends
/// `/` as the command. So one `/` comes off and no more.
pub fn writeSession(w: *Writer, path: []const u8) Writer.Error!void {
    try w.writeAll("CLIENT " ++ client_id ++ "\r\n");
    const stripped = if (path.len > 0 and path[0] == '/') path[1..] else path;
    try writeCommand(w, stripped);
    try w.writeAll("\r\nQUIT\r\n");
}

const testing = std.testing;

/// The session `path` produces, into `out`.
fn session(out: []u8, path: []const u8) ![]const u8 {
    var w: Writer = .fixed(out);
    try writeSession(&w, path);
    return w.buffered();
}

test "the three lines curl writes, in curl's own order" {
    var out: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "CLIENT zurl/0.1\r\nDEFINE ! hello\r\nQUIT\r\n",
        try session(&out, "/d:hello"),
    );
}

test "every DEFINE row measured against curl 8.21.0" {
    var out: [256]u8 = undefined;
    const rows = [_]struct { path: []const u8, want: []const u8 }{
        .{ .path = "/d:hello", .want = "DEFINE ! hello" },
        .{ .path = "/D:hello", .want = "DEFINE ! hello" },
        .{ .path = "/define:hello", .want = "DEFINE ! hello" },
        .{ .path = "/DEFINE:hello", .want = "DEFINE ! hello" },
        .{ .path = "/lookup:hello", .want = "DEFINE ! hello" },
        .{ .path = "/d:hello:wn", .want = "DEFINE wn hello" },
        // The count is read and dropped, the way curl drops it.
        .{ .path = "/d:hello:wn:5", .want = "DEFINE wn hello" },
        .{ .path = "/d:hello:wn:5:extra", .want = "DEFINE wn hello" },
        .{ .path = "/d:hello:*", .want = "DEFINE * hello" },
        // An empty word is the literal `default`, not an empty field.
        .{ .path = "/d:", .want = "DEFINE ! default" },
        // An empty database falls back to `!`.
        .{ .path = "/d:hello:", .want = "DEFINE ! hello" },
    };
    for (rows) |row| {
        const text = try session(&out, row.path);
        const want = try std.fmt.allocPrint(
            testing.allocator,
            "CLIENT {s}\r\n{s}\r\nQUIT\r\n",
            .{ client_id, row.want },
        );
        defer testing.allocator.free(want);
        try testing.expectEqualStrings(want, text);
    }
}

test "every MATCH row measured against curl 8.21.0" {
    var out: [256]u8 = undefined;
    const rows = [_]struct { path: []const u8, want: []const u8 }{
        .{ .path = "/m:hello", .want = "MATCH ! . hello" },
        .{ .path = "/M:hello", .want = "MATCH ! . hello" },
        .{ .path = "/match:hello", .want = "MATCH ! . hello" },
        .{ .path = "/find:hello", .want = "MATCH ! . hello" },
        .{ .path = "/m:hello:wn:exact", .want = "MATCH wn exact hello" },
        // The count is dropped here too.
        .{ .path = "/m:hello:wn:exact:3", .want = "MATCH wn exact hello" },
        .{ .path = "/m:", .want = "MATCH ! . default" },
    };
    for (rows) |row| {
        var w: Writer = .fixed(&out);
        try writeCommand(&w, row.path[1..]);
        try testing.expectEqualStrings(row.want, w.buffered());
    }
}

test "a path that names no command is the command itself" {
    // curl's own answer, measured: the text goes out with each `:`
    // turned into a space. This is how a user reaches a command RFC 2229
    // has and this package does not name.
    var out: [256]u8 = undefined;
    const rows = [_]struct { path: []const u8, want: []const u8 }{
        .{ .path = "hello", .want = "hello" },
        .{ .path = "x:y", .want = "x y" },
        .{ .path = "x:y:z", .want = "x y z" },
        .{ .path = "SHOW:DB", .want = "SHOW DB" },
        .{ .path = "/", .want = "/" },
        .{ .path = "", .want = "" },
    };
    for (rows) |row| {
        var w: Writer = .fixed(&out);
        try writeCommand(&w, row.path);
        try testing.expectEqualStrings(row.want, w.buffered());
    }
}

test "one leading slash comes off the path and no more" {
    // Measured: `dict://h/` sends an empty command line, and
    // `dict://h//` sends `/`.
    var out: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "CLIENT " ++ client_id ++ "\r\n\r\nQUIT\r\n",
        try session(&out, "/"),
    );
    try testing.expectEqualStrings(
        "CLIENT " ++ client_id ++ "\r\n/\r\nQUIT\r\n",
        try session(&out, "//"),
    );
}

test "the RFC 2229 escape covers every byte curl escapes" {
    var out: [256]u8 = undefined;
    const rows = [_]struct { text: []const u8, want: []const u8 }{
        .{ .text = "a b", .want = "a\\ b" },
        .{ .text = "\"quote\"", .want = "\\\"quote\\\"" },
        .{ .text = "back\\slash", .want = "back\\\\slash" },
        .{ .text = "'q'", .want = "\\'q\\'" },
        .{ .text = "a\x7fb", .want = "a\\\x7fb" },
        // Nothing else is touched. A high byte is data, and curl sends
        // `dict://h/d:%c3%a9` as the two bytes with no escape.
        .{ .text = "hello", .want = "hello" },
        .{ .text = "\xc3\xa9", .want = "\xc3\xa9" },
        .{ .text = "a%zzb", .want = "a%zzb" },
    };
    for (rows) |row| {
        var w: Writer = .fixed(&out);
        try writeEscaped(&w, row.text);
        try testing.expectEqualStrings(row.want, w.buffered());
    }
}

test "a space in a database name cannot forge a field" {
    // This is the one place zurl writes different bytes than curl. curl
    // escapes the word alone, so `dict://h/d:hello:w%20n` reaches the
    // wire from curl as `DEFINE w n hello`, which is a `DEFINE` with the
    // word `n`. zurl escapes the database too, so the command still names
    // the database the url named.
    var out: [256]u8 = undefined;
    var w: Writer = .fixed(&out);
    try writeCommand(&w, "d:hello:w n");
    try testing.expectEqualStrings("DEFINE w\\ n hello", w.buffered());

    var w2: Writer = .fixed(&out);
    try writeCommand(&w2, "m:hello:wn:ex act");
    try testing.expectEqualStrings("MATCH wn ex\\ act hello", w2.buffered());
}

test "a field reads by position, and a missing one is empty" {
    try testing.expectEqualStrings("a", field("a:b:c", 0));
    try testing.expectEqualStrings("b", field("a:b:c", 1));
    try testing.expectEqualStrings("c", field("a:b:c", 2));
    try testing.expectEqualStrings("", field("a:b:c", 3));
    try testing.expectEqualStrings("", field("a:b:c", 99));
    try testing.expectEqualStrings("", field("", 0));
    try testing.expectEqualStrings("", field("a::c", 1));
    try testing.expectEqualStrings("a", field("a", 0));
}

test "classify names the command and hands back the rest" {
    try testing.expectEqual(Kind.define, classify("d:hello").kind);
    try testing.expectEqualStrings("hello", classify("d:hello").rest);
    try testing.expectEqual(Kind.match, classify("find:hello").kind);
    try testing.expectEqualStrings("hello", classify("find:hello").rest);
    try testing.expectEqual(Kind.raw, classify("hello").kind);
    try testing.expectEqualStrings("hello", classify("hello").rest);
    // A prefix is a prefix and not a whole word: `dx:` names no command.
    try testing.expectEqual(Kind.raw, classify("dx:hello").kind);
    try testing.expectEqual(Kind.raw, classify("").kind);
    // A path shorter than a prefix must not read past its end.
    try testing.expectEqual(Kind.raw, classify("d").kind);
    try testing.expectEqual(Kind.raw, classify("defin").kind);
}

test "a session that does not fit reports the write and never truncates" {
    // The bound is the caller's buffer. A fixed writer that runs out
    // reports it, so a truncated command can never reach a socket.
    var out: [8]u8 = undefined;
    var w: Writer = .fixed(&out);
    try testing.expectError(error.WriteFailed, writeSession(&w, "/d:hello"));
}

test "no decoded control byte can reach the command line" {
    // The proof that `Fetcher.open` refuses such a url before it reaches
    // this file. Here the rule itself is checked: every byte below 0x20
    // is one `zurl_core.url.hasControlByte` names, so the check in
    // `Fetcher.open` covers each one.
    for (0..0x20) |byte| {
        const one = [_]u8{@intCast(byte)};
        try testing.expect(zurl_core.url.hasControlByte(&one));
    }
    // And the escape leaves each of them alone, which is why the refusal
    // has to happen before the escape and not inside it.
    var out: [8]u8 = undefined;
    var w: Writer = .fixed(&out);
    try writeEscaped(&w, "\r\n");
    try testing.expectEqualStrings("\r\n", w.buffered());
}

test "the request bound leaves room for a path that escapes to twice its size" {
    // Every byte of a word can take a backslash, so a path at the bound
    // doubles. The session bound must hold that, plus the two fixed
    // lines.
    try testing.expect(max_request_bytes >= 2 * max_path_bytes);

    var out: [max_request_bytes]u8 = undefined;
    var path: [max_path_bytes]u8 = undefined;
    @memset(&path, ' ');
    path[0] = '/';
    path[1] = 'd';
    path[2] = ':';
    var w: Writer = .fixed(&out);
    try writeSession(&w, &path);
}
