//! The reply grammar of a protocol that answers with a three digit code.
//!
//! FTP and SMTP spell an answer the same way, and the spelling is the part
//! that is easy to get wrong. RFC 959 section 4.2 and RFC 5321 section 4.2
//! both give a reply two forms:
//!
//!     220 Ready<CRLF>
//!
//!     220-Welcome<CRLF>
//!     any text at all<CRLF>
//!     220 Ready<CRLF>
//!
//! The second form starts with three digits and a hyphen. **It ends at the
//! first line that starts with the same three digits and a space**, and at
//! no other line. Every line between the two is free text, and a middle
//! line may itself start with three digits, with a hyphen, or with the
//! code of some other reply.
//!
//! **A parser that reads one line and stops desynchronises the whole
//! session.** It reads the banner of a multi-line greeting as the whole
//! greeting, then reads the rest of that greeting as the answer to the
//! next command, and every answer after it belongs to the command before
//! it. An FTP transfer then reads the reply to `PASS` as the reply to
//! `RETR`, and an SMTP session reads the reply to `MAIL FROM` as the reply
//! to `DATA` and sends a message body at a server that is not waiting for
//! one.
//!
//! This module holds the rule once, so the two protocol packages that need
//! it share one answer. POP3 and IMAP do not: POP3 answers `+OK` and
//! `-ERR`, and IMAP answers with a tag. Each of those two owns its own
//! grammar, in its own package.
//!
//! What this module does not do: it opens nothing, it waits for nothing,
//! and it holds no session state. It reads lines a caller already read, so
//! every rule here is a table test with no socket. `zurl_net.line.Session`
//! is what puts a bounded reader under it.

const std = @import("std");

/// How large one reply may grow.
///
/// Each protocol package names its own numbers, because the two do not
/// agree on what a large answer is: an SMTP `EHLO` answer lists every
/// extension a server has, and an FTP greeting is a banner.
pub const Limits = struct {
    /// How many lines of one reply to read.
    ///
    /// A server that writes a line with the code and a hyphen forever
    /// never finishes the reply, so the count is a bound and not a guess
    /// about what a real server writes. Passing it is
    /// `error.ReplyTooManyLines`.
    max_lines: usize,
    /// How many bytes of one whole reply to keep.
    ///
    /// **The line bound and the line count are not enough on their own.**
    /// A thousand-byte line, a hundred and twenty-eight times, is 128 KiB
    /// from one command, and a server may answer every command that way.
    /// This bounds the reply together, and it is the number that decides
    /// how much memory one session holds. Passing it is
    /// `error.ReplyTooLong`.
    max_reply_bytes: usize,
};

/// A reply that this module could not read.
pub const ParseError = error{
    /// The first line does not start with three digits and a separator.
    ReplyMalformed,
    /// The reply has more lines than `Limits.max_lines`.
    ReplyTooManyLines,
    /// The reply has more bytes than `Limits.max_reply_bytes`.
    ReplyTooLong,
};

/// One reply, already read whole.
pub const Reply = struct {
    /// The three digit code of the last line, which is the code of the
    /// reply. A multi-line reply repeats it on the first line.
    code: u16,
    /// The text of the reply, with the code and the separator taken off
    /// the first line and the last line, and the middle lines kept exactly
    /// as they arrived, joined with `\n`.
    ///
    /// Borrowed from the caller's own storage.
    text: []const u8,

    /// The first digit, which RFC 959 calls the completion class.
    ///
    /// 1 is a positive preliminary reply, 2 is a positive completion, 3 is
    /// a positive intermediate, 4 is a transient negative, and 5 is a
    /// permanent negative. RFC 5321 gives SMTP the same five classes.
    pub fn class(r: Reply) u8 {
        return @intCast(r.code / 100);
    }

    /// Whether the code says the command worked. 2yz alone.
    pub fn isPositive(r: Reply) bool {
        return r.class() == 2;
    }

    /// Whether the code asks for more. This is the answer `USER` gets when
    /// an FTP server wants a `PASS`, and the answer `DATA` gets when an
    /// SMTP server is ready for the message. 3yz.
    pub fn isIntermediate(r: Reply) bool {
        return r.class() == 3;
    }

    /// Whether the code says the command did not work, transiently or
    /// permanently. 4yz and 5yz.
    pub fn isNegative(r: Reply) bool {
        return r.class() == 4 or r.class() == 5;
    }
};

/// What one line of a reply says about the reply it belongs to.
pub const Line = struct {
    /// The three digit code the line starts with, or null when the line
    /// does not start with three digits and a separator.
    code: ?u16,
    /// True when the line starts with a code and a hyphen, which opens a
    /// multi-line reply.
    opens: bool,
    /// The text after the code and its separator, or the whole line when
    /// the line carries no code.
    text: []const u8,
};

/// Reads one line of a reply.
///
/// **The separator decides everything.** `nnn<SP>text` ends a reply.
/// `nnn-text` opens one, or is a middle line of one. Anything else is a
/// middle line and never an end, whatever it starts with. So a middle line
/// reading `230 Not a real code` cannot end a `220-` reply, because the
/// caller compares the code as well: see `Collector.push`.
///
/// `line` must already have its line ending taken off.
pub fn readLine(line: []const u8) Line {
    if (line.len < 4) return .{ .code = null, .opens = false, .text = line };
    for (line[0..3]) |c| {
        if (!std.ascii.isDigit(c)) return .{ .code = null, .opens = false, .text = line };
    }
    const code = (@as(u16, line[0] - '0') * 100) +
        (@as(u16, line[1] - '0') * 10) +
        @as(u16, line[2] - '0');
    return switch (line[3]) {
        ' ' => .{ .code = code, .opens = false, .text = line[4..] },
        '-' => .{ .code = code, .opens = true, .text = line[4..] },
        // A digit run of three and then something else is not a reply
        // code at all. `2500 files` is a line of text.
        else => .{ .code = null, .opens = false, .text = line },
    };
}

/// Collects the lines of one reply, under `limits`.
///
/// A caller reads one line, hands it here, and reads another while `push`
/// answers false. When `push` answers true the reply is whole and `finish`
/// returns it.
///
/// The text of every line goes into `storage`, which the caller owns and
/// which must outlive the `Reply`. A reply larger than `storage`, or than
/// `limits.max_reply_bytes`, is `error.ReplyTooLong`, and nothing partial
/// is returned.
///
/// `limits` is a comptime parameter so a protocol package names its own
/// bounds once, as a type, and every collector it builds carries them.
pub fn Collector(comptime limits: Limits) type {
    return struct {
        const Self = @This();

        /// The bounds this collector keeps.
        pub const bounds = limits;

        /// Where the text of the reply is built. The caller's own memory.
        storage: []u8,
        /// How much of `storage` is filled.
        len: usize,
        /// The code the first line named, once one has arrived.
        code: ?u16,
        /// True while a multi-line reply is still open.
        open: bool,
        /// How many lines have arrived.
        lines: usize,

        /// A collector over `storage`, with no line in it yet.
        pub fn init(storage: []u8) Self {
            return .{ .storage = storage, .len = 0, .code = null, .open = false, .lines = 0 };
        }

        /// Takes one line, and answers whether the reply is now whole.
        ///
        /// `line` must already have its line ending taken off, and the
        /// caller's reader keeps the bound on how long it may be. See
        /// `zurl_net.bounded.readLine`.
        pub fn push(c: *Self, line: []const u8) ParseError!bool {
            c.lines += 1;
            if (c.lines > limits.max_lines) return error.ReplyTooManyLines;

            const read = readLine(line);

            if (c.code == null) {
                // The first line is the only one that has to carry a code.
                // A server whose first line does not is speaking something
                // this package cannot read, and the session cannot go on.
                const code = read.code orelse return error.ReplyMalformed;
                c.code = code;
                c.open = read.opens;
                try c.append(read.text);
                return !c.open;
            }

            // **A middle line ends the reply only when its code matches
            // and its separator is a space.** Both halves are needed. A
            // middle line carrying another reply's code with a space would
            // otherwise end this reply early, and the rest of it would
            // then be read as the answer to the next command.
            if (!read.opens and read.code != null and read.code.? == c.code.?) {
                try c.appendLine(read.text);
                c.open = false;
                return true;
            }

            // Anything else is free text inside the reply. It is kept
            // whole, code and separator included, because the standards
            // give the middle lines no structure at all and a reader wants
            // what the server wrote.
            try c.appendLine(line);
            return false;
        }

        /// The reply this collected. Only meaningful after `push` answered
        /// true.
        pub fn finish(c: *const Self) Reply {
            return .{ .code = c.code orelse 0, .text = c.storage[0..c.len] };
        }

        fn append(c: *Self, text: []const u8) ParseError!void {
            const room = @min(c.storage.len, limits.max_reply_bytes);
            if (text.len > room - c.len) return error.ReplyTooLong;
            @memcpy(c.storage[c.len..][0..text.len], text);
            c.len += text.len;
        }

        fn appendLine(c: *Self, text: []const u8) ParseError!void {
            const room = @min(c.storage.len, limits.max_reply_bytes);
            if (c.len == room) return error.ReplyTooLong;
            c.storage[c.len] = '\n';
            c.len += 1;
            return c.append(text);
        }
    };
}

const testing = std.testing;

const TestCollector = Collector(.{ .max_lines = 8, .max_reply_bytes = 512 });

test "a one line reply is whole after one line" {
    var storage: [256]u8 = undefined;
    var c: TestCollector = .init(&storage);
    try testing.expect(try c.push("250 Ok"));
    const reply = c.finish();
    try testing.expectEqual(@as(u16, 250), reply.code);
    try testing.expectEqualStrings("Ok", reply.text);
    try testing.expect(reply.isPositive());
}

test "a multi-line reply ends only at its own code with a space" {
    // **The defect this module exists for.** Every middle line below would
    // end the reply for a parser that reads one line, or one that reads
    // any three digits and a space. An SMTP `EHLO` answer is exactly this
    // shape, and reading it short leaves the session one answer out of
    // step for the rest of the message.
    var storage: [512]u8 = undefined;
    var c: TestCollector = .init(&storage);
    try testing.expect(!try c.push("250-mail.example.com"));
    try testing.expect(!try c.push("250-PIPELINING"));
    // A middle line carrying another reply's code and a space.
    try testing.expect(!try c.push("220 Not the end"));
    try testing.expect(try c.push("250 STARTTLS"));

    const reply = c.finish();
    try testing.expectEqual(@as(u16, 250), reply.code);
    try testing.expectEqualStrings(
        "mail.example.com\n250-PIPELINING\n220 Not the end\nSTARTTLS",
        reply.text,
    );
}

test "a reply that never ends is refused at the line count" {
    var storage: [512]u8 = undefined;
    var c: TestCollector = .init(&storage);
    try testing.expect(!try c.push("250-open"));
    var i: usize = 1;
    while (i < TestCollector.bounds.max_lines) : (i += 1) {
        try testing.expect(!try c.push("x"));
    }
    try testing.expectError(error.ReplyTooManyLines, c.push("x"));
}

test "a reply longer than its bound is refused and nothing partial comes back" {
    // The storage is the smaller of the two bounds here.
    var small: [16]u8 = undefined;
    var c: TestCollector = .init(&small);
    try testing.expect(!try c.push("250-0123456789"));
    try testing.expectError(error.ReplyTooLong, c.push("0123456789"));

    // The byte bound is the smaller one here, and it stops the reply just
    // the same. A collector that read only `storage.len` would let a
    // package with generous storage keep a reply past its own bound.
    const Tight = Collector(.{ .max_lines = 8, .max_reply_bytes = 12 });
    var roomy: [512]u8 = undefined;
    var t: Tight = .init(&roomy);
    try testing.expect(!try t.push("250-0123456789"));
    try testing.expectError(error.ReplyTooLong, t.push("0123456789"));
}

test "a first line with no code at all is refused" {
    var storage: [64]u8 = undefined;
    for ([_][]const u8{ "hello there", "22 Ready", "2200 Ready", "220" }) |line| {
        var c: TestCollector = .init(&storage);
        try testing.expectError(error.ReplyMalformed, c.push(line));
    }
}

test "readLine tells the three shapes of a reply line apart" {
    {
        const line = readLine("250 Ok");
        try testing.expectEqual(@as(?u16, 250), line.code);
        try testing.expect(!line.opens);
        try testing.expectEqualStrings("Ok", line.text);
    }
    {
        const line = readLine("250-Ok");
        try testing.expectEqual(@as(?u16, 250), line.code);
        try testing.expect(line.opens);
        try testing.expectEqualStrings("Ok", line.text);
    }
    {
        // Three digits and then anything else is text, not a code.
        const line = readLine("2500 files");
        try testing.expectEqual(@as(?u16, null), line.code);
        try testing.expectEqualStrings("2500 files", line.text);
    }
    {
        const line = readLine("   text");
        try testing.expectEqual(@as(?u16, null), line.code);
    }
}

test "the completion class of a code is its first digit" {
    const rows = [_]struct { code: u16, class: u8 }{
        .{ .code = 150, .class = 1 },
        .{ .code = 250, .class = 2 },
        .{ .code = 354, .class = 3 },
        .{ .code = 421, .class = 4 },
        .{ .code = 550, .class = 5 },
    };
    for (rows) |row| {
        const reply: Reply = .{ .code = row.code, .text = "" };
        try testing.expectEqual(row.class, reply.class());
        try testing.expectEqual(row.class == 2, reply.isPositive());
        try testing.expectEqual(row.class == 3, reply.isIntermediate());
        try testing.expectEqual(row.class == 4 or row.class == 5, reply.isNegative());
    }
}
