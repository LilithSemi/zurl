//! Turning a message body into the octets that go out during `DATA`.
//!
//! **This module holds the one rule that decides whether a message
//! arrives whole, and it is a security rule and not a formatting one.**
//!
//! RFC 5321 section 4.1.1.4 ends the `DATA` phase at a line holding one
//! period and nothing else. Section 4.5.2 therefore asks the sender to put
//! a second period in front of any body line that already starts with one,
//! and asks the receiver to take it off again. A sender that does not do
//! that hands the server a message that stops at the first such line, and
//! **every byte after it is read as an SMTP command**.
//!
//! That is not a truncated message. It is a command injection: the rest of
//! the body chooses what the server does next, and `RCPT TO` and `MAIL
//! FROM` are among the commands it can choose. Anybody who can put a line
//! into the body, which is anybody who can write a mail signature or a
//! quoted reply, can write those commands.
//!
//! **Measured against curl 8.21.0**, on a loopback SMTP fixture, with a
//! body of `line one<LF>.<LF>line two<LF>`:
//!
//!     curl   ...DATA, line one, `.`, and then the server read
//!            `line two` as a command
//!     zurl   ...DATA, line one, `..`, line two, `.`
//!
//! curl stuffs a period only when the line before it ended `CRLF`, so a
//! body written with bare line feeds walks straight through. This module
//! reads a bare `LF` as a line ending too, which is the other half of the
//! same rule: RFC 5321 section 2.3.8 puts `CRLF` on the wire, so a body
//! with bare line feeds has to be converted before it is stuffed, and a
//! sender that converts after stuffing has stuffed the wrong lines.
//!
//! **What this does, in order, for each line of the body:**
//!
//! 1. A line is the run of bytes up to the next `LF`. A `CR` directly
//!    before that `LF` belongs to the ending and not to the line.
//! 2. A line whose first byte is a period gets one more period.
//! 3. The line goes out with a `CRLF` ending, whatever ending it arrived
//!    with.
//! 4. After the last line, `.<CRLF>` ends the message.
//!
//! A `CR` that is not before an `LF` stays in the line as data. It cannot
//! frame anything: the `DATA` phase ends at `CRLF.CRLF` and a lone `CR`
//! begins no such run.
//!
//! This module does no I/O. It writes into a buffer the caller owns, and
//! `writtenLen` says how large that buffer has to be.

const std = @import("std");

/// How many bytes `write` produces for `body`.
///
/// Counted and not guessed, so the caller allocates once and `write`
/// cannot run out of room. The count is exact.
pub fn writtenLen(body: []const u8) usize {
    var total: usize = 0;
    var it: LineIterator = .init(body);
    while (it.next()) |line| {
        total += line.len + 2;
        if (line.len != 0 and line[0] == '.') total += 1;
    }
    // The `.<CRLF>` that ends the message.
    return total + 3;
}

/// Writes `body` into `out` as the octets of a `DATA` phase, and returns
/// them.
///
/// `out.len` must be at least `writtenLen(body)`. A caller that sizes the
/// buffer from that function cannot pass a short one, and a short one is
/// `error.MessageTooLong` rather than a message cut in half.
pub fn write(out: []u8, body: []const u8) error{MessageTooLong}![]u8 {
    if (out.len < writtenLen(body)) return error.MessageTooLong;

    var at: usize = 0;
    var it: LineIterator = .init(body);
    while (it.next()) |line| {
        // **The stuffing, and it is the whole point of this module.** See
        // the module comment for what a message without it does.
        if (line.len != 0 and line[0] == '.') {
            out[at] = '.';
            at += 1;
        }
        @memcpy(out[at..][0..line.len], line);
        at += line.len;
        out[at] = '\r';
        out[at + 1] = '\n';
        at += 2;
    }

    out[at] = '.';
    out[at + 1] = '\r';
    out[at + 2] = '\n';
    return out[0 .. at + 3];
}

/// Walks the lines of a body.
///
/// A line ends at an `LF`, and a `CR` directly before it belongs to the
/// ending. The last run of bytes is a line even when nothing ends it: a
/// body of `hello` is one line, which is what curl sends for one, measured.
///
/// An empty body has no lines at all, so a message with no body is
/// `.<CRLF>` and nothing before it.
const LineIterator = struct {
    body: []const u8,
    at: usize,

    fn init(body: []const u8) LineIterator {
        return .{ .body = body, .at = 0 };
    }

    fn next(it: *LineIterator) ?[]const u8 {
        if (it.at == it.body.len) return null;
        const rest = it.body[it.at..];
        const end = std.mem.indexOfScalar(u8, rest, '\n') orelse {
            it.at = it.body.len;
            return rest;
        };
        it.at += end + 1;
        var line = rest[0..end];
        if (line.len != 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
        return line;
    }
};

/// Takes the added period off a line, which is what a receiver owes.
///
/// This package sends messages and does not receive them, so nothing here
/// calls it. It is here because a rule with only one half written down is
/// a rule somebody gets wrong later, and because the round-trip test below
/// is what proves the stuffing is reversible.
pub fn unstuff(line: []const u8) []const u8 {
    if (line.len != 0 and line[0] == '.') return line[1..];
    return line;
}

const testing = std.testing;

/// Runs `write` into a buffer `writtenLen` sized, and returns it.
fn stuff(gpa: std.mem.Allocator, body: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, writtenLen(body));
    errdefer gpa.free(out);
    const written = try write(out, body);
    try testing.expectEqual(out.len, written.len);
    return out;
}

test "a body with no period line goes out as it arrived, with a CRLF ending" {
    const out = try stuff(testing.allocator, "Subject: hi\r\n\r\nbody line\r\n");
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("Subject: hi\r\n\r\nbody line\r\n.\r\n", out);
}

test "a line of one period is stuffed, and that is what keeps the message whole" {
    // **The injection proof of this package.** Without the second period
    // the server ends the `DATA` phase at the third line, and reads
    // `line two` as an SMTP command. Measured: curl 8.21.0 does exactly
    // that for the bare line feed form of this body.
    const out = try stuff(testing.allocator, "line one\r\n.\r\nline two\r\n");
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("line one\r\n..\r\nline two\r\n.\r\n", out);

    // **The message holds no `CRLF.CRLF` but the one at its end.** That
    // run is the only thing that ends the phase, so this is the property
    // the whole module exists for.
    const ending = "\r\n.\r\n";
    try testing.expectEqual(
        @as(?usize, out.len - ending.len),
        std.mem.indexOf(u8, out, ending),
    );
    try testing.expectEqual(
        @as(?usize, out.len - ending.len),
        std.mem.lastIndexOf(u8, out, ending),
    );
}

test "a bare line feed is a line ending too, and its period is stuffed" {
    // **This is where zurl and curl differ, and the difference is the
    // injection.** curl stuffs only after a `CRLF`, so the body below
    // reaches a server from curl with a bare `.` line in the middle of it.
    const out = try stuff(testing.allocator, "line one\n.\nline two\n");
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("line one\r\n..\r\nline two\r\n.\r\n", out);
}

test "a line that only starts with a period is stuffed as well" {
    // RFC 5321 section 4.5.2 stuffs by the first character of the line and
    // not by the whole line, because a receiver takes the first character
    // off whatever follows it.
    const out = try stuff(testing.allocator, ".hidden\r\n..already\r\n....\r\n");
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("..hidden\r\n...already\r\n.....\r\n.\r\n", out);

    // Round trip: a receiver that takes one period off each line gets the
    // author's own text back.
    var it = std.mem.splitSequence(u8, out[0 .. out.len - 3], "\r\n");
    var rebuilt: std.ArrayList(u8) = .empty;
    defer rebuilt.deinit(testing.allocator);
    while (it.next()) |line| {
        if (it.index == null and line.len == 0) break;
        try rebuilt.appendSlice(testing.allocator, unstuff(line));
        try rebuilt.appendSlice(testing.allocator, "\r\n");
    }
    try testing.expectEqualStrings(".hidden\r\n..already\r\n....\r\n", rebuilt.items);
}

test "a period that is not the first byte of a line is left alone" {
    const out = try stuff(testing.allocator, "a.b\r\nend. \r\n");
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("a.b\r\nend. \r\n.\r\n", out);
}

test "a body with no ending gets one, so the terminator stands on its own line" {
    // Measured: curl sends `no newline at end<CRLF>.<CRLF>` for a file
    // with no trailing newline.
    const out = try stuff(testing.allocator, "no newline at end");
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("no newline at end\r\n.\r\n", out);

    // And a body whose last line is a period gets both the stuffing and
    // the ending. Measured against curl for the `CRLF` form.
    const dotted = try stuff(testing.allocator, "x\r\n.");
    defer testing.allocator.free(dotted);
    try testing.expectEqualStrings("x\r\n..\r\n.\r\n", dotted);
}

test "an empty body is a message of no lines" {
    const out = try stuff(testing.allocator, "");
    defer testing.allocator.free(out);
    try testing.expectEqualStrings(".\r\n", out);
}

test "an empty line stays an empty line" {
    const out = try stuff(testing.allocator, "a\r\n\r\nb\r\n");
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("a\r\n\r\nb\r\n.\r\n", out);
}

test "a CR that is not before an LF is data and stays in the line" {
    // The `DATA` phase ends at `CRLF.CRLF`, and a lone `CR` begins no such
    // run, so nothing here can be framed by one.
    const out = try stuff(testing.allocator, "a\rb\r\nc\r");
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("a\rb\r\nc\r\r\n.\r\n", out);
}

test "writtenLen is exact, so the buffer is never short and never wasteful" {
    const bodies = [_][]const u8{
        "",
        "a",
        "a\r\n",
        "a\n",
        ".\r\n",
        ".",
        "..\r\n...\r\n",
        "line one\r\n.\r\nline two\r\n",
        "line one\n.\nline two\n",
        "\r\n\r\n\r\n",
        "\n\n\n",
        "a\rb",
        "Subject: hi\r\n\r\nbody\r\n.hidden\r\n",
    };
    for (bodies) |body| {
        const out = try stuff(testing.allocator, body);
        defer testing.allocator.free(out);
        try testing.expectEqual(writtenLen(body), out.len);
        // Every one of them ends the phase exactly once, at the end.
        const ending = "\r\n.\r\n";
        if (out.len > ending.len) {
            try testing.expectEqual(
                @as(?usize, out.len - ending.len),
                std.mem.lastIndexOf(u8, out, ending),
            );
            try testing.expectEqual(
                @as(?usize, out.len - ending.len),
                std.mem.indexOf(u8, out, ending),
            );
        }
    }
}

test "a buffer smaller than the message is refused rather than cut" {
    const body = "line one\r\n.\r\nline two\r\n";
    var small: [8]u8 = undefined;
    @memset(&small, 0xaa);
    try testing.expectError(error.MessageTooLong, write(&small, body));
    for (small) |byte| try testing.expectEqual(@as(u8, 0xaa), byte);

    // One byte short is still short.
    const exact = writtenLen(body);
    const out = try testing.allocator.alloc(u8, exact - 1);
    defer testing.allocator.free(out);
    try testing.expectError(error.MessageTooLong, write(out, body));
}

test "no body can put a second CRLF.CRLF inside the message" {
    // **The property, stated once over many shapes.** A body that could
    // end the phase early is a body that chooses the server's next
    // command.
    const attacks = [_][]const u8{
        "\r\n.\r\nMAIL FROM:<evil@x>\r\n",
        "\n.\nMAIL FROM:<evil@x>\n",
        "a\r\n.\r\nRCPT TO:<evil@x>\r\n",
        "a\n.\nRCPT TO:<evil@x>\n",
        ".\r\n",
        ".",
        "\r\n.",
        "x\r\n.\r\n",
        "x\r\n.\r\n.\r\n.\r\n",
        "\r\n\r\n.\r\n\r\n",
    };
    for (attacks) |body| {
        const out = try stuff(testing.allocator, body);
        defer testing.allocator.free(out);
        const ending = "\r\n.\r\n";
        const first = std.mem.indexOf(u8, out, ending);
        // A message shorter than the ending holds no run at all, and one
        // longer holds exactly one, at its end.
        if (out.len >= ending.len) {
            try testing.expectEqual(@as(?usize, out.len - ending.len), first);
        } else {
            try testing.expectEqual(@as(?usize, null), first);
        }
    }
}
