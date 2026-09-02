//! The RFC 959 reply grammar, and the two answers that carry an address.
//!
//! This module owns how a reply is spelled and nothing about how it
//! arrives. It reads lines a caller already read, so every rule here is
//! testable with a table and no socket. `Control.zig` is what puts a
//! bounded reader under it.
//!
//! **A reply is one line or many, and getting that wrong desynchronises
//! the whole session.** RFC 959 section 4.2 spells a reply two ways:
//!
//!     220 Ready<CRLF>
//!
//!     220-Welcome<CRLF>
//!     any text at all<CRLF>
//!     220 Ready<CRLF>
//!
//! The second form starts with three digits and a hyphen. It ends at the
//! first line that starts with **the same** three digits and a space.
//! Every line between the two is free text, and a middle line may itself
//! start with three digits, with a hyphen, or with the code of some other
//! reply. A parser that reads one line and stops therefore reads the
//! banner of a multi-line greeting as the whole greeting, and then reads
//! the rest of that greeting as the answer to the next command. Every
//! answer after it belongs to the command before it, and the transfer
//! reads the reply to `PASS` as the reply to `RETR`.
//!
//! What this module does not do: it opens nothing, it waits for nothing,
//! and it holds no session state. It does not know which command a reply
//! answers.
//!
//! **The multi-line rule is shared with SMTP and lives in
//! `zurl_net.reply`.** RFC 5321 section 4.2 spells an SMTP reply the same
//! way RFC 959 spells this one, so the grammar is one module and each
//! protocol package names only its own bounds. What stays here is what
//! belongs to FTP alone: the `227`, the `229`, and the `213` answers.

const std = @import("std");
const zurl_net = @import("zurl-net");

/// How many lines of one reply this reads.
///
/// A greeting of a few lines is ordinary and a `FEAT` list of thirty is
/// not strange. A server that writes a line with the code and a hyphen
/// forever never finishes the reply, so the count is a bound and not a
/// guess about what a real server writes. Passing it is
/// `error.ReplyTooManyLines`.
pub const max_lines = 128;

/// How many bytes of one reply line this reads, the line ending counted.
///
/// RFC 959 sets no limit. A server that writes one line forever would
/// otherwise fill memory, so this bounds a line the way `max_lines` bounds
/// a reply. It is past every reply a real server writes: a `227` answer is
/// under 60 bytes and a directory banner is under 200.
pub const max_line_bytes = 1024;

/// How many bytes of one whole reply this keeps.
///
/// **The line bound and the line count are not enough on their own.** A
/// thousand-byte line, a hundred and twenty-eight times, is 128 KiB from
/// one command, and a server may answer every command that way. This
/// bounds the reply together, and it is the number that decides how much
/// memory one session holds. Passing it is `error.ReplyTooLong`.
pub const max_reply_bytes = 8192;

/// A reply that this module could not read.
///
/// The three names come from `zurl_net.reply`, which holds the grammar.
pub const ParseError = zurl_net.reply.ParseError;

/// One reply, already read whole. See `zurl_net.reply.Reply`.
///
/// A 3yz reply is the answer `USER` gets when the server wants a `PASS`,
/// and the answer `REST` gets.
pub const Reply = zurl_net.reply.Reply;

/// What one line of a reply says about the reply it belongs to. See
/// `zurl_net.reply.Line`.
pub const Line = zurl_net.reply.Line;

/// Reads one line of a reply. See `zurl_net.reply.readLine`.
pub const readLine = zurl_net.reply.readLine;

/// Collects the lines of one reply, under this package's own bounds.
///
/// **The multi-line rule itself lives in `zurl_net.reply`**, because SMTP
/// spells a reply exactly the same way and a second copy of that rule is a
/// second place to get it wrong. This package names the two numbers and
/// nothing else: an FTP banner and an SMTP extension list are not the same
/// size.
pub const Collector = zurl_net.reply.Collector(.{
    .max_lines = max_lines,
    .max_reply_bytes = max_reply_bytes,
});

/// A peer to open a data connection to.
///
/// The port always comes from the server. The address may or may not, and
/// `Fetcher` decides that: see `Fetcher.dataPort`. A `PASV` answer names
/// one and an `EPSV` answer does not, which is why the field is optional.
pub const DataPeer = struct {
    /// The four bytes of the IPv4 address the server named, or null when
    /// the answer named none.
    address: ?[4]u8,
    /// The port the server is listening on. Never zero: port zero names
    /// no listener, so a server that writes one is refused.
    port: u16,
};

/// A `PASV` or `EPSV` answer this module could not read.
pub const AddressError = error{
    /// A `227` answer that does not hold six numbers in brackets. curl
    /// answers this shape with exit 14, `CURLE_FTP_WEIRD_227_FORMAT`,
    /// measured.
    Weird227Format,
    /// A `229` answer that does not hold a port between three delimiters.
    Weird229Format,
};

/// Reads the six numbers of a `227` answer, RFC 959 section 4.1.2.
///
/// The answer reads `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)`, and
/// the text around the brackets is free. So this finds the last `(`, reads
/// six comma-separated numbers, and refuses anything else.
///
/// Each of the six must be 0 through 255, because the four address bytes
/// and the two port bytes are octets. A number outside that range is
/// `error.Weird227Format` and never a value taken modulo anything: a
/// server that writes 300 is not writing an address this client can read.
///
/// A port of zero is refused too. Port zero names no listener, so a server
/// that writes it is either broken or is asking this client to dial
/// something it cannot name.
pub fn parsePasv(text: []const u8) AddressError!DataPeer {
    const open = std.mem.lastIndexOfScalar(u8, text, '(') orelse return error.Weird227Format;
    const rest = text[open + 1 ..];
    const close = std.mem.indexOfScalar(u8, rest, ')') orelse return error.Weird227Format;

    var numbers: [6]u8 = undefined;
    var seen: usize = 0;
    var it = std.mem.splitScalar(u8, rest[0..close], ',');
    while (it.next()) |field| {
        if (seen == numbers.len) return error.Weird227Format;
        const trimmed = std.mem.trim(u8, field, " ");
        if (trimmed.len == 0) return error.Weird227Format;
        numbers[seen] = std.fmt.parseInt(u8, trimmed, 10) catch return error.Weird227Format;
        seen += 1;
    }
    if (seen != numbers.len) return error.Weird227Format;

    const port = (@as(u16, numbers[4]) << 8) | @as(u16, numbers[5]);
    if (port == 0) return error.Weird227Format;
    return .{
        .address = .{ numbers[0], numbers[1], numbers[2], numbers[3] },
        .port = port,
    };
}

/// Reads the port of a `229` answer, RFC 2428 section 3.
///
/// The answer reads `229 Entering Extended Passive Mode (|||port|)`. The
/// first character inside the brackets is the delimiter, and the field
/// before the port names an address family and the one before that a
/// network protocol. **RFC 2428 leaves both empty for the connection the
/// command arrived on**, which is the only form this reads: a server that
/// names another address in an `EPSV` answer is naming a peer this client
/// will not dial, for the reason `Fetcher.dataPort` gives for `PASV`.
///
/// A port of zero is refused, for the reason `parsePasv` gives.
pub fn parseEpsv(text: []const u8) AddressError!DataPeer {
    const open = std.mem.lastIndexOfScalar(u8, text, '(') orelse return error.Weird229Format;
    const rest = text[open + 1 ..];
    const close = std.mem.indexOfScalar(u8, rest, ')') orelse return error.Weird229Format;
    const inside = rest[0..close];
    if (inside.len < 4) return error.Weird229Format;

    const delimiter = inside[0];
    // The delimiter must be one of the four RFC 2428 allows, so a stray
    // `(` in free text cannot be read as the start of the field list.
    switch (delimiter) {
        '!', '@', '#', '$', '|' => {},
        else => return error.Weird229Format,
    }
    if (inside[inside.len - 1] != delimiter) return error.Weird229Format;

    var fields: [4][]const u8 = undefined;
    var seen: usize = 0;
    var it = std.mem.splitScalar(u8, inside[1 .. inside.len - 1], delimiter);
    while (it.next()) |field| {
        if (seen == fields.len) return error.Weird229Format;
        fields[seen] = field;
        seen += 1;
    }
    if (seen != 3) return error.Weird229Format;
    // The network protocol and the address family are both left empty by
    // every server this dials, and a server that fills them is naming a
    // peer this client does not take from it.
    if (fields[0].len != 0 or fields[1].len != 0) return error.Weird229Format;

    const port = std.fmt.parseInt(u16, fields[2], 10) catch return error.Weird229Format;
    if (port == 0) return error.Weird229Format;
    return .{ .address = null, .port = port };
}

/// Reads the byte count of a `213` answer to `SIZE`, RFC 3659 section 4.
///
/// Returns null when the text is not one number, because a size nobody can
/// read is not a fault: the transfer runs without one, and the progress
/// meter reports an unknown total. curl behaves the same way.
pub fn parseSize(text: []const u8) ?u64 {
    const trimmed = std.mem.trim(u8, text, " \t");
    if (trimmed.len == 0) return null;
    return std.fmt.parseInt(u64, trimmed, 10) catch null;
}

const testing = std.testing;

test "a one line reply is whole after one line" {
    var storage: [256]u8 = undefined;
    var c: Collector = .init(&storage);
    try testing.expect(try c.push("220 Ready"));
    const reply = c.finish();
    try testing.expectEqual(@as(u16, 220), reply.code);
    try testing.expectEqualStrings("Ready", reply.text);
    try testing.expect(reply.isPositive());
    try testing.expectEqual(@as(u8, 2), reply.class());
}

test "a multi-line reply ends only at its own code with a space" {
    // **The defect this test exists for.** Every middle line below would
    // end the reply for a parser that reads one line, or one that reads
    // any three digits and a space. The reply ends at `220 Ready` and
    // nowhere else.
    var storage: [512]u8 = undefined;
    var c: Collector = .init(&storage);
    try testing.expect(!try c.push("220-Welcome to the fixture"));
    try testing.expect(!try c.push("  line two, and 220 is not the end"));
    // A middle line carrying another reply's code and a space.
    try testing.expect(!try c.push("230 Not a real code either"));
    // A middle line carrying this reply's own code and a hyphen.
    try testing.expect(!try c.push("220-still going"));
    try testing.expect(try c.push("220 Ready"));

    const reply = c.finish();
    try testing.expectEqual(@as(u16, 220), reply.code);
    try testing.expectEqualStrings(
        "Welcome to the fixture\n  line two, and 220 is not the end\n230 Not a real code either\n220-still going\nReady",
        reply.text,
    );
}

test "a reply that never ends is refused at the line count" {
    var storage: [max_reply_bytes]u8 = undefined;
    var c: Collector = .init(&storage);
    try testing.expect(!try c.push("220-open"));
    var i: usize = 1;
    while (i < max_lines) : (i += 1) {
        try testing.expect(!try c.push("x"));
    }
    try testing.expectError(error.ReplyTooManyLines, c.push("x"));
}

test "a reply longer than its storage is refused and nothing partial comes back" {
    var storage: [16]u8 = undefined;
    var c: Collector = .init(&storage);
    try testing.expect(!try c.push("220-0123456789"));
    try testing.expectError(error.ReplyTooLong, c.push("0123456789"));
}

test "a first line with no code at all is refused" {
    var storage: [64]u8 = undefined;
    var c: Collector = .init(&storage);
    try testing.expectError(error.ReplyMalformed, c.push("hello there"));

    var c2: Collector = .init(&storage);
    try testing.expectError(error.ReplyMalformed, c2.push("22 Ready"));

    var c3: Collector = .init(&storage);
    try testing.expectError(error.ReplyMalformed, c3.push("2200 Ready"));

    var c4: Collector = .init(&storage);
    try testing.expectError(error.ReplyMalformed, c4.push("220"));
}

test "readLine tells the three shapes of a reply line apart" {
    {
        const line = readLine("220 Ready");
        try testing.expectEqual(@as(?u16, 220), line.code);
        try testing.expect(!line.opens);
        try testing.expectEqualStrings("Ready", line.text);
    }
    {
        const line = readLine("220-Ready");
        try testing.expectEqual(@as(?u16, 220), line.code);
        try testing.expect(line.opens);
        try testing.expectEqualStrings("Ready", line.text);
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
        .{ .code = 226, .class = 2 },
        .{ .code = 331, .class = 3 },
        .{ .code = 426, .class = 4 },
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

test "a 227 answer gives the four address bytes and the port" {
    const peer = try parsePasv("Entering Passive Mode (127,0,0,1,161,183)");
    try testing.expectEqual([4]u8{ 127, 0, 0, 1 }, peer.address.?);
    try testing.expectEqual(@as(u16, 161 * 256 + 183), peer.port);

    // The text around the brackets is free, and the last `(` wins.
    const other = try parsePasv("Passive (mode) is on (203,0,113,7,4,1)");
    try testing.expectEqual([4]u8{ 203, 0, 113, 7 }, other.address.?);
    try testing.expectEqual(@as(u16, 1025), other.port);
}

test "a 227 answer that is not six octets in brackets is refused" {
    const bad = [_][]const u8{
        "Entering Passive Mode blah blah",
        "Entering Passive Mode (127,0,0,1,161)",
        "Entering Passive Mode (127,0,0,1,161,183,9)",
        "Entering Passive Mode (127,0,0,1,161,300)",
        "Entering Passive Mode (127,0,0,1,161,-1)",
        "Entering Passive Mode (127,0,0,1,161,)",
        "Entering Passive Mode (127,0,0,1,161,x)",
        "Entering Passive Mode (127,0,0,1,161,183",
        // Port zero names no listener at all.
        "Entering Passive Mode (127,0,0,1,0,0)",
    };
    for (bad) |text| {
        try testing.expectError(error.Weird227Format, parsePasv(text));
    }
}

test "a 229 answer gives the port and never an address" {
    const peer = try parseEpsv("Entering Extended Passive Mode (|||37809|)");
    try testing.expectEqual(@as(?[4]u8, null), peer.address);
    try testing.expectEqual(@as(u16, 37809), peer.port);

    // Any of the four RFC 2428 delimiters.
    for ([_][]const u8{
        "Ok (!!!1025!)",
        "Ok (@@@1025@)",
        "Ok (###1025#)",
        "Ok ($$$1025$)",
    }) |text| {
        try testing.expectEqual(@as(u16, 1025), (try parseEpsv(text)).port);
    }
}

test "a 229 answer that names an address family or a protocol is refused" {
    // **RFC 2428 leaves both fields empty for the connection the command
    // arrived on.** A server that fills either one is naming a peer, and
    // this client takes no peer from a server. See `Fetcher.dataPort`.
    const bad = [_][]const u8{
        "Ok (|1|203.0.113.7|1025|)",
        "Ok (||203.0.113.7|1025|)",
        "Ok (|1||1025|)",
        "Ok (|||)",
        "Ok (|||0|)",
        "Ok (|||70000|)",
        "Ok (|||x|)",
        "Ok no brackets",
        "Ok (|||1025)",
        "Ok (aaa1025a)",
    };
    for (bad) |text| {
        try testing.expectError(error.Weird229Format, parseEpsv(text));
    }
}

test "a 213 answer gives the size, and anything else gives none" {
    try testing.expectEqual(@as(?u64, 45), parseSize("45"));
    try testing.expectEqual(@as(?u64, 45), parseSize(" 45 "));
    try testing.expectEqual(@as(?u64, 0), parseSize("0"));
    try testing.expectEqual(@as(?u64, null), parseSize(""));
    try testing.expectEqual(@as(?u64, null), parseSize("not a number"));
    try testing.expectEqual(@as(?u64, null), parseSize("45 bytes"));
    try testing.expectEqual(@as(?u64, null), parseSize("-1"));
}
