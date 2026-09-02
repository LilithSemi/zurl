//! The RFC 1939 response grammar.
//!
//! POP3 answers with two words and not with a code. `+OK` says the command
//! worked and `-ERR` says it did not, and nothing else is an answer at
//! all. That is the whole of a single-line response.
//!
//! **A multi-line response is where the care goes.** RFC 1939 section 3
//! puts the body of `RETR`, `LIST`, `TOP`, `UIDL`, and `CAPA` after the
//! `+OK` line, and ends it with **a line holding one period and nothing
//! else**. A body line that would otherwise start with a period carries
//! two, which the sender adds and the receiver takes off. So:
//!
//! - A reader that took the first `.` it saw as the end would stop in the
//!   middle of a message whose own text has a line starting with a period,
//!   and would then read the rest of that message as answers to later
//!   commands.
//! - A reader that did not take the doubled period off would hand a user a
//!   message with a period the sender never wrote.
//!
//! `terminates` answers the first and `unstuff` answers the second. Both
//! are pure text and both are table tested.
//!
//! This module opens nothing and waits for nothing. It reads lines a
//! caller already read, with their line endings already taken off.

const std = @import("std");

/// One single-line response.
pub const Response = struct {
    /// True for `+OK`, false for `-ERR`.
    ok: bool,
    /// The text after `+OK` or `-ERR`, with the one space between them
    /// taken off. Empty when the line carried only the status word.
    ///
    /// Borrowed from the caller's line, so it lives only as long as that
    /// line does.
    text: []const u8,
};

/// A response this module could not read.
pub const ParseError = error{
    /// The line starts with neither `+OK` nor `-ERR`.
    ///
    /// A server that answers anything else is not speaking RFC 1939, and
    /// the session cannot go on: there is no way to tell which answer
    /// belongs to which command.
    ResponseMalformed,
};

/// The word an answer that worked starts with.
pub const ok_prefix = "+OK";

/// The word an answer that failed starts with.
pub const err_prefix = "-ERR";

/// Reads one single-line response.
///
/// `line` must already have its line ending taken off.
///
/// **The status word must stand alone.** `+OKAY` is not `+OK`, so the byte
/// after the word has to be a space or the end of the line. A reader that
/// matched a prefix alone would read a word it does not know as a success.
pub fn parse(line: []const u8) ParseError!Response {
    if (match(line, ok_prefix)) |text| return .{ .ok = true, .text = text };
    if (match(line, err_prefix)) |text| return .{ .ok = false, .text = text };
    return error.ResponseMalformed;
}

/// The text after `word`, or null when `line` does not start with `word`
/// as a whole word.
fn match(line: []const u8, word: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, line, word)) return null;
    const rest = line[word.len..];
    if (rest.len == 0) return "";
    if (rest[0] != ' ') return null;
    return rest[1..];
}

/// The word a SASL challenge line starts with.
///
/// RFC 5034 section 4: the server writes `+ <base64>` for each message it
/// wants from the client. That is a `+` on its own and never `+OK`, so a
/// reader that took the first `+` as a success would read a challenge as
/// the end of the login.
pub const challenge_prefix = "+";

/// The base64 of a SASL challenge line, or null when `line` is not one.
///
/// **A `+OK` is not a challenge**, and this is what keeps the two apart:
/// the byte after the `+` must be a space or the end of the line. RFC 5034
/// writes an empty challenge as `+ `, and a server that writes a bare `+`
/// means the same thing.
pub fn challenge(line: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, line, challenge_prefix)) return null;
    const rest = line[challenge_prefix.len..];
    if (rest.len == 0) return "";
    if (rest[0] != ' ') return null;
    return rest[1..];
}

/// Whether `line` ends a multi-line response.
///
/// **One period and nothing else.** A line of `..` is a body line whose
/// text is one period, and a line of `. ` is a body line too. Neither ends
/// the response. See the module comment for what a looser test would do.
pub fn terminates(line: []const u8) bool {
    return line.len == 1 and line[0] == '.';
}

/// Takes the added period off a body line.
///
/// RFC 1939 section 3: a sender that has a body line starting with a
/// period sends two, so the line cannot be read as the terminator. The
/// receiver takes one off. A line that does not start with a period is
/// returned as it arrived.
pub fn unstuff(line: []const u8) []const u8 {
    if (line.len != 0 and line[0] == '.') return line[1..];
    return line;
}

/// The APOP timestamp of a greeting, angle brackets included, or null when
/// the greeting carries none.
///
/// RFC 1939 section 7: a server that offers APOP ends its greeting with
/// `<process-id.clock@hostname>`. A client that has one sends
/// `APOP user digest`, where the digest is the MD5 of the timestamp
/// followed by the password, so **the password never crosses the
/// network**.
///
/// The timestamp is the last `<...>` on the line, and both brackets must
/// be there. A greeting with an unmatched bracket carries no timestamp,
/// and the session then uses `USER` and `PASS`.
///
/// **The text between the brackets must hold an `@` with a byte on each
/// side.** RFC 1939 section 7 gives the timestamp the RFC 822 `msg-id`
/// shape, `<process-id.clock@hostname>`, and that shape is the whole of
/// the replay protection: the clock and the host name are what make the
/// digest different on each connection. A bracket pair with no `@`, such
/// as `<a>`, is not a timestamp. It used to be accepted, and the client
/// then sent an `APOP` digest over a salt a server can hold constant.
///
/// curl 8.21.0 draws the same line. Its POP3 greeting reader keeps the
/// bracket text only when `strchr(timestamp, '@')` finds an `@`, and drops
/// APOP for the session when it does not. zurl asks for one byte on each
/// side of that `@` as well, because `<@h>` names no process and `<a@>`
/// names no host, and neither adds anything a constant salt does not.
///
/// A greeting this refuses is not a fault. The session falls back to
/// `USER` and `PASS`, which is what a greeting with no bracket pair at all
/// already does.
pub fn apopTimestamp(greeting: []const u8) ?[]const u8 {
    const close = std.mem.lastIndexOfScalar(u8, greeting, '>') orelse return null;
    const open = std.mem.lastIndexOfScalar(u8, greeting[0..close], '<') orelse return null;
    // An empty `<>` names no process and no clock, so it is not a
    // timestamp and a digest over it would be a constant.
    if (close - open < 2) return null;

    const inside = greeting[open + 1 .. close];
    const at = std.mem.indexOfScalar(u8, inside, '@') orelse return null;
    if (at == 0 or at + 1 == inside.len) return null;

    return greeting[open .. close + 1];
}

/// What a `STAT` answer says: how many messages there are and how many
/// bytes they hold.
pub const Stat = struct {
    count: u64,
    octets: u64,
};

/// Reads the two numbers of a `STAT` answer, RFC 1939 section 5.
///
/// Returns null when the text is not two numbers. A `STAT` nobody can read
/// is not a fault this package ends a session for: the number is
/// information and never a decision.
pub fn parseStat(text: []const u8) ?Stat {
    var it = std.mem.tokenizeScalar(u8, text, ' ');
    const count_text = it.next() orelse return null;
    const octets_text = it.next() orelse return null;
    const count = std.fmt.parseInt(u64, count_text, 10) catch return null;
    const octets = std.fmt.parseInt(u64, octets_text, 10) catch return null;
    return .{ .count = count, .octets = octets };
}

const testing = std.testing;

test "a +OK and a -ERR are read, and the text after them comes back" {
    {
        const r = try parse("+OK POP3 server ready");
        try testing.expect(r.ok);
        try testing.expectEqualStrings("POP3 server ready", r.text);
    }
    {
        const r = try parse("-ERR no such message");
        try testing.expect(!r.ok);
        try testing.expectEqualStrings("no such message", r.text);
    }
    {
        // The status word alone is a whole answer.
        const r = try parse("+OK");
        try testing.expect(r.ok);
        try testing.expectEqualStrings("", r.text);
    }
    {
        const r = try parse("-ERR");
        try testing.expect(!r.ok);
        try testing.expectEqualStrings("", r.text);
    }
}

test "a line that is neither +OK nor -ERR ends the session" {
    // **The status word must stand alone.** `+OKAY` would be a success for
    // a reader that matched a prefix, and every answer after it would then
    // belong to the wrong command.
    const bad = [_][]const u8{
        "",
        "+OKAY fine",
        "-ERROR bad",
        "OK ready",
        "+ok ready",
        "220 Ready",
        ".",
        "+",
        "-",
    };
    for (bad) |line| {
        try testing.expectError(error.ResponseMalformed, parse(line));
    }
}

test "only a line of one period ends a multi-line response" {
    // **The defect this test exists for.** A message whose own text has a
    // line starting with a period arrives with two, and a reader that
    // stopped at the first `.` it saw would cut the message and read the
    // rest of it as answers to later commands.
    try testing.expect(terminates("."));
    try testing.expect(!terminates(".."));
    try testing.expect(!terminates(". "));
    try testing.expect(!terminates(" ."));
    try testing.expect(!terminates(".\t"));
    try testing.expect(!terminates(""));
    try testing.expect(!terminates("...."));
    try testing.expect(!terminates(".hidden"));
}

test "a body line that starts with a period loses exactly one of them" {
    try testing.expectEqualStrings(".hidden", unstuff("..hidden"));
    try testing.expectEqualStrings(".", unstuff(".."));
    try testing.expectEqualStrings("..", unstuff("..."));
    try testing.expectEqualStrings("", unstuff("."));
    // A line that starts with anything else is untouched.
    try testing.expectEqualStrings("Subject: hi", unstuff("Subject: hi"));
    try testing.expectEqualStrings("", unstuff(""));
    try testing.expectEqualStrings("a.b", unstuff("a.b"));
}

test "the APOP timestamp is the last matched pair of angle brackets" {
    try testing.expectEqualStrings(
        "<1896.697170952@dbc.mtview.ca.us>",
        apopTimestamp("POP3 server ready <1896.697170952@dbc.mtview.ca.us>").?,
    );
    // The last pair wins, so free text with brackets in it cannot take the
    // place of the timestamp.
    try testing.expectEqualStrings("<b@h>", apopTimestamp("ready <a> and <b@h>").?);

    // No timestamp at all.
    try testing.expectEqual(@as(?[]const u8, null), apopTimestamp("POP3 server ready"));
    try testing.expectEqual(@as(?[]const u8, null), apopTimestamp("ready <unclosed"));
    try testing.expectEqual(@as(?[]const u8, null), apopTimestamp("ready unopened>"));
    // An empty pair names no process and no clock.
    try testing.expectEqual(@as(?[]const u8, null), apopTimestamp("ready <>"));
    try testing.expectEqual(@as(?[]const u8, null), apopTimestamp("ready ><"));
}

test "a bracket pair with no host part is not an APOP timestamp" {
    // **The defect this rule exists for.** A pair with one byte in it
    // passed the length check and became the salt of the `APOP` digest,
    // so a server could hold that salt constant across every connection
    // and take the replay protection out of the exchange. RFC 1939
    // section 7 asks for the RFC 822 `msg-id` shape, and curl 8.21.0
    // drops APOP for the session when the bracket text carries no `@`.
    try testing.expectEqual(@as(?[]const u8, null), apopTimestamp("+OK ready <a>"));
    try testing.expectEqual(@as(?[]const u8, null), apopTimestamp("+OK ready <1896.697170952>"));
    // An `@` with nothing on one side of it names no process or no host.
    try testing.expectEqual(@as(?[]const u8, null), apopTimestamp("+OK ready <@dbc.mtview.ca.us>"));
    try testing.expectEqual(@as(?[]const u8, null), apopTimestamp("+OK ready <1896.697170952@>"));
    try testing.expectEqual(@as(?[]const u8, null), apopTimestamp("+OK ready <@>"));

    // The shape RFC 1939 writes still reads, and so does the shortest one
    // that carries both halves.
    try testing.expectEqualStrings("<a@h>", apopTimestamp("+OK ready <a@h>").?);
    try testing.expectEqualStrings(
        "<1896.697170952@dbc.mtview.ca.us>",
        apopTimestamp("+OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>").?,
    );
}

test "a STAT answer gives two numbers, and anything else gives none" {
    const s = parseStat("2 320").?;
    try testing.expectEqual(@as(u64, 2), s.count);
    try testing.expectEqual(@as(u64, 320), s.octets);

    try testing.expectEqual(@as(u64, 0), parseStat("0 0").?.count);
    try testing.expectEqual(@as(u64, 320), parseStat("  2   320  extra").?.octets);

    try testing.expectEqual(@as(?Stat, null), parseStat(""));
    try testing.expectEqual(@as(?Stat, null), parseStat("2"));
    try testing.expectEqual(@as(?Stat, null), parseStat("two 320"));
    try testing.expectEqual(@as(?Stat, null), parseStat("2 -320"));
}

test "a SASL challenge is a + on its own, and never a +OK" {
    // **The defect this rule exists for.** A reader that took the first
    // `+` as a success would read a challenge as the end of the login,
    // and would then send the next command where the server was waiting
    // for a response.
    try testing.expectEqualStrings("", challenge("+ ").?);
    try testing.expectEqualStrings("", challenge("+").?);
    try testing.expectEqualStrings("PDE4OTY+", challenge("+ PDE4OTY+").?);

    try testing.expectEqual(@as(?[]const u8, null), challenge("+OK"));
    try testing.expectEqual(@as(?[]const u8, null), challenge("+OK logged in"));
    try testing.expectEqual(@as(?[]const u8, null), challenge("-ERR no"));
    try testing.expectEqual(@as(?[]const u8, null), challenge(""));
    try testing.expectEqual(@as(?[]const u8, null), challenge("PDE4OTY="));
}
