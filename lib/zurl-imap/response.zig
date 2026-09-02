//! The RFC 3501 response grammar.
//!
//! **IMAP is the one of the four line protocols where an answer names the
//! command it answers.** Every command a client sends carries a tag, and
//! the server ends that command with a line starting with the same tag.
//! Between the two it may write any number of untagged lines, and those
//! lines may belong to the command, or to a change in the mailbox that
//! nobody asked about. So a reader has to keep reading until it sees its
//! own tag, and it must never take an untagged line as the end.
//!
//! Three shapes of line arrive, and `readLine` tells them apart:
//!
//!     * 2 EXISTS                  untagged: data, and never an end
//!     + go ahead                  a continuation request
//!     A003 OK [READ-WRITE] done   tagged: the end of command A003
//!
//! **A tagged line ends a command only when the tag is the one that went
//! out.** A server that wrote `A002 OK` while `A003` was in flight is
//! answering an older command, and a reader that stopped there would read
//! the answer to `A003` as the answer to whatever came next.
//!
//! **The other half of the grammar is the literal.** RFC 3501 section 4.3
//! writes a string as `{n}` at the end of a line, followed by exactly `n`
//! octets, and those octets may hold a `CRLF`. So a `FETCH` answer is not
//! a line at all: it is a line, then a count of octets, then the rest of
//! the line. A reader that read it as lines would read a message body as a
//! run of answers, and every one of them would look untagged.
//! `literalLength` is what finds the count.
//!
//! This module opens nothing and waits for nothing. It reads lines a
//! caller already read, with their line endings already taken off.

const std = @import("std");

/// What one line of an answer is.
pub const Kind = enum {
    /// `* ...`. Data, and never the end of a command.
    untagged,
    /// `+ ...`. The server is waiting for the rest of a command.
    continuation,
    /// `<tag> ...`. The end of the command that carried `tag`.
    tagged,
};

/// The word a tagged line carries, and the word an untagged status line
/// carries.
pub const Status = enum {
    /// The command worked.
    ok,
    /// The command did not work, and the server is willing to go on.
    no,
    /// The command was not understood, or was sent at the wrong time.
    bad,
    /// The greeting of a server that has already authenticated this
    /// connection. Only ever untagged.
    preauth,
    /// The server is closing the connection. Only ever untagged.
    bye,

    /// Whether the word says the command worked.
    pub fn isPositive(s: Status) bool {
        return s == .ok or s == .preauth;
    }
};

/// One line of an answer, read.
pub const Line = struct {
    kind: Kind,
    /// The status word, or null for a line that carries none. An untagged
    /// line such as `* 2 EXISTS` carries no status word.
    status: ?Status,
    /// The text after the tag and the status word, or the whole line after
    /// the `*` or the `+` for a line with no status word.
    ///
    /// Borrowed from the caller's line.
    text: []const u8,
};

/// A line this module could not read.
pub const ParseError = error{
    /// The line starts with neither `*`, nor `+`, nor the tag that went
    /// out.
    ///
    /// **This is what keeps the session in step.** A line carrying another
    /// tag is the answer to another command, and a reader that took it
    /// would read every answer after it against the wrong command.
    ResponseMalformed,
    /// A tagged line carried no `OK`, `NO`, or `BAD`.
    ResponseMalformedTagged,
};

/// Reads one line of an answer, against the tag that went out.
///
/// `line` must already have its line ending taken off.
///
/// The tag is compared without regard to case, because RFC 3501 makes a
/// tag an atom and atoms are case insensitive. Every tag this package
/// sends is uppercase, so the comparison never has to decide anything in
/// practice, and it is written this way so a server that answers `a001`
/// does not desynchronise a session.
pub fn readLine(line: []const u8, tag: []const u8) ParseError!Line {
    if (std.mem.startsWith(u8, line, "* ")) return untaggedLine(line[2..]);
    // `*` on its own is a line with no data. It is still untagged.
    if (std.mem.eql(u8, line, "*")) return .{ .kind = .untagged, .status = null, .text = "" };
    if (std.mem.startsWith(u8, line, "+")) {
        const rest = line[1..];
        const text = if (rest.len != 0 and rest[0] == ' ') rest[1..] else rest;
        return .{ .kind = .continuation, .status = null, .text = text };
    }

    // **An empty tag matches no line at all.** `Control.readGreeting`
    // passes one, because a greeting answers no command. Without this
    // guard a line starting with a space would read as a tagged answer to
    // a command that was never sent.
    if (tag.len != 0 and
        line.len > tag.len and
        std.ascii.eqlIgnoreCase(line[0..tag.len], tag) and
        line[tag.len] == ' ')
    {
        const rest = line[tag.len + 1 ..];
        const split = splitWord(rest);
        const status = statusOf(split.word) orelse return error.ResponseMalformedTagged;
        // Only `OK`, `NO`, and `BAD` end a command. `BYE` and `PREAUTH`
        // are untagged words, and a server that wrote one with a tag is
        // not speaking RFC 3501 section 7.1.
        switch (status) {
            .ok, .no, .bad => {},
            .preauth, .bye => return error.ResponseMalformedTagged,
        }
        return .{ .kind = .tagged, .status = status, .text = split.rest };
    }

    return error.ResponseMalformed;
}

fn untaggedLine(rest: []const u8) Line {
    const split = splitWord(rest);
    if (statusOf(split.word)) |status| {
        return .{ .kind = .untagged, .status = status, .text = split.rest };
    }
    return .{ .kind = .untagged, .status = null, .text = rest };
}

fn splitWord(text: []const u8) struct { word: []const u8, rest: []const u8 } {
    const space = std.mem.indexOfScalar(u8, text, ' ') orelse
        return .{ .word = text, .rest = "" };
    return .{ .word = text[0..space], .rest = text[space + 1 ..] };
}

fn statusOf(word: []const u8) ?Status {
    if (std.ascii.eqlIgnoreCase(word, "OK")) return .ok;
    if (std.ascii.eqlIgnoreCase(word, "NO")) return .no;
    if (std.ascii.eqlIgnoreCase(word, "BAD")) return .bad;
    if (std.ascii.eqlIgnoreCase(word, "PREAUTH")) return .preauth;
    if (std.ascii.eqlIgnoreCase(word, "BYE")) return .bye;
    return null;
}

/// The octet count of a literal at the end of `line`, or null when the
/// line ends in no literal.
///
/// RFC 3501 section 4.3 writes `{n}` at the very end of the line, and RFC
/// 7888 adds `{n+}`, the non-synchronising form, which a server may use
/// when it announced `LITERAL+`. Either way `n` octets follow the line
/// ending.
///
/// **The brace must close the line and nothing may follow it.** A `{5}` in
/// the middle of a line is text, because a literal is by definition what
/// the line ends with. A reader that took a middle `{5}` as a count would
/// read five octets of the same line as a body and then read the rest of
/// the line as an answer.
///
/// A count with no digits, a count with a sign, or a count that does not
/// fit a `u32` is null, which reads the line as text. A caller that then
/// finds the octets on the wire ends the session at its own bound rather
/// than read a number it did not understand.
pub fn literalLength(line: []const u8) ?u32 {
    if (line.len < 3 or line[line.len - 1] != '}') return null;
    const open = std.mem.lastIndexOfScalar(u8, line, '{') orelse return null;
    var inside = line[open + 1 .. line.len - 1];
    // RFC 7888: the non-synchronising form ends the count with a `+`.
    if (inside.len != 0 and inside[inside.len - 1] == '+') inside = inside[0 .. inside.len - 1];
    if (inside.len == 0) return null;
    for (inside) |c| {
        if (!std.ascii.isDigit(c)) return null;
    }
    return std.fmt.parseInt(u32, inside, 10) catch null;
}

const testing = std.testing;

test "the three shapes of a line are told apart" {
    {
        const line = try readLine("* 2 EXISTS", "A003");
        try testing.expectEqual(Kind.untagged, line.kind);
        try testing.expectEqual(@as(?Status, null), line.status);
        try testing.expectEqualStrings("2 EXISTS", line.text);
    }
    {
        const line = try readLine("* OK [UIDVALIDITY 1] ready", "A003");
        try testing.expectEqual(Kind.untagged, line.kind);
        try testing.expectEqual(Status.ok, line.status.?);
        try testing.expectEqualStrings("[UIDVALIDITY 1] ready", line.text);
    }
    {
        const line = try readLine("+ go ahead", "A003");
        try testing.expectEqual(Kind.continuation, line.kind);
        try testing.expectEqualStrings("go ahead", line.text);
    }
    {
        const line = try readLine("A003 OK [READ-WRITE] done", "A003");
        try testing.expectEqual(Kind.tagged, line.kind);
        try testing.expectEqual(Status.ok, line.status.?);
        try testing.expectEqualStrings("[READ-WRITE] done", line.text);
    }
    {
        const line = try readLine("A003 NO no such mailbox", "A003");
        try testing.expectEqual(Kind.tagged, line.kind);
        try testing.expectEqual(Status.no, line.status.?);
    }
    {
        const line = try readLine("A003 BAD what", "A003");
        try testing.expectEqual(Status.bad, line.status.?);
    }
}

test "an untagged BYE and an untagged PREAUTH are read, and a tagged one is not" {
    const bye = try readLine("* BYE closing", "A003");
    try testing.expectEqual(Status.bye, bye.status.?);
    const preauth = try readLine("* PREAUTH already in", "A001");
    try testing.expectEqual(Status.preauth, preauth.status.?);
    try testing.expect(preauth.status.?.isPositive());

    // RFC 3501 section 7.1 makes both untagged words. A tagged one is not
    // an answer this package will act on.
    try testing.expectError(error.ResponseMalformedTagged, readLine("A003 BYE closing", "A003"));
    try testing.expectError(error.ResponseMalformedTagged, readLine("A003 PREAUTH x", "A003"));
}

test "a line carrying another tag ends nothing" {
    // **The defect this test exists for.** `A002 OK` while `A003` is in
    // flight is the answer to an older command, and a reader that took it
    // would read every answer after it against the wrong command.
    try testing.expectError(error.ResponseMalformed, readLine("A002 OK done", "A003"));
    try testing.expectError(error.ResponseMalformed, readLine("A0031 OK done", "A003"));
    try testing.expectError(error.ResponseMalformed, readLine("A00 OK done", "A003"));
    // A tag that is a prefix of the line but has no space after it is not
    // this tag either.
    try testing.expectError(error.ResponseMalformed, readLine("A003OK done", "A003"));
    try testing.expectError(error.ResponseMalformed, readLine("A003", "A003"));
    try testing.expectError(error.ResponseMalformed, readLine("", "A003"));
    try testing.expectError(error.ResponseMalformed, readLine("nonsense", "A003"));
}

test "an empty tag matches no line, which is what a greeting needs" {
    // A greeting answers no command, so no tag can match it. A line
    // starting with a space would otherwise read as a tagged answer.
    try testing.expectError(error.ResponseMalformed, readLine("A001 OK ready", ""));
    try testing.expectError(error.ResponseMalformed, readLine(" OK ready", ""));
    try testing.expectError(error.ResponseMalformed, readLine("", ""));
    // The untagged and continuation shapes still read.
    try testing.expectEqual(Kind.untagged, (try readLine("* OK ready", "")).kind);
    try testing.expectEqual(Kind.continuation, (try readLine("+ ready", "")).kind);
}

test "a tag is read without regard to case, because RFC 3501 makes it an atom" {
    const line = try readLine("a003 OK done", "A003");
    try testing.expectEqual(Kind.tagged, line.kind);
}

test "a tagged line with no status word is refused" {
    try testing.expectError(error.ResponseMalformedTagged, readLine("A003 WHAT done", "A003"));
    try testing.expectError(error.ResponseMalformedTagged, readLine("A003 ", "A003"));
}

test "an untagged line with no status word keeps the whole line as its text" {
    const line = try readLine("* LIST (\\HasNoChildren) \"/\" INBOX", "A003");
    try testing.expectEqual(@as(?Status, null), line.status);
    try testing.expectEqualStrings("LIST (\\HasNoChildren) \"/\" INBOX", line.text);

    // A bare `*` is a line with no data at all, and it is still untagged.
    const bare = try readLine("*", "A003");
    try testing.expectEqual(Kind.untagged, bare.kind);
    try testing.expectEqualStrings("", bare.text);
}

test "a literal count is the one at the end of the line" {
    try testing.expectEqual(@as(?u32, 21), literalLength("* 1 FETCH (BODY[] {21}"));
    try testing.expectEqual(@as(?u32, 0), literalLength("* 1 FETCH (BODY[] {0}"));
    // RFC 7888's non-synchronising form.
    try testing.expectEqual(@as(?u32, 21), literalLength("* 1 FETCH (BODY[] {21+}"));
    try testing.expectEqual(@as(?u32, 4294967295), literalLength("x {4294967295}"));
}

test "a brace that does not end the line is text and never a count" {
    // **The defect this rule exists for.** A reader that took a middle
    // `{5}` as a count would read five octets of the same line as a body
    // and read the rest of the line as an answer to a later command.
    try testing.expectEqual(@as(?u32, null), literalLength("* 1 FETCH ({5} more)"));
    try testing.expectEqual(@as(?u32, null), literalLength("* OK {5} bytes free"));
    try testing.expectEqual(@as(?u32, null), literalLength("* 1 FETCH (BODY[] {21})"));
}

test "a count nobody can read is no count at all" {
    const bad = [_][]const u8{
        "",
        "{}",
        "x {}",
        "x {+}",
        "x {-1}",
        "x {abc}",
        "x { 21}",
        "x {21 }",
        "x {99999999999999999999}",
        "x }",
        "x {21",
        "}",
        "{}}",
    };
    for (bad) |line| {
        try testing.expectEqual(@as(?u32, null), literalLength(line));
    }
}

test "the status words that mean the command worked" {
    try testing.expect(Status.ok.isPositive());
    try testing.expect(Status.preauth.isPositive());
    try testing.expect(!Status.no.isPositive());
    try testing.expect(!Status.bad.isPositive());
    try testing.expect(!Status.bye.isPositive());
}
