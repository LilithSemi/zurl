//! The old rcp protocol that a remote `scp` speaks. Pure bytes.
//!
//! Nothing here holds a socket, a channel, or a file. It reads and writes
//! the control lines and nothing else.
//!
//! # The protocol
//!
//! It is not written down anywhere authoritative, so it was read off the
//! wire against OpenSSH 10.5p1 and the transcript is in the report. One
//! side sends control lines and file bytes, and the other answers each
//! control line with one status byte.
//!
//! A download, which runs `scp -pf <path>` on the far side:
//!
//!     client -> server   \0                       start
//!     server -> client   T<mtime> 0 <atime> 0\n   the times, because of -p
//!     client -> server   \0
//!     server -> client   C0644 16 hello.txt\n     the mode, the size, the name
//!     client -> server   \0
//!     server -> client   <exactly 16 bytes>
//!     server -> client   \0                       the end of the file
//!     client -> server   \0
//!
//! An upload, which runs `scp -t <path>`:
//!
//!     server -> client   \0                       ready
//!     client -> server   C0644 14 up.txt\n
//!     server -> client   \0
//!     client -> server   <exactly 14 bytes>
//!     client -> server   \0
//!     server -> client   \0
//!
//! A status byte of 1 is a warning and 2 is fatal. Each is followed by text
//! and one newline, and **both carry the peer's own words**.
//!
//! # Every value on a control line is the peer's
//!
//! A `C` line carries a mode, a size, and a name, and the peer chose all
//! three. This file bounds each one before it is a number or a slice:
//!
//! | field | bound | what a wrong one would do |
//! | --- | --- | --- |
//! | the whole line | `max_line_bytes` | a line with no newline would read forever |
//! | the mode | 4 octal digits, `0` to `0o7777` | see below |
//! | the size | `max_size_digits` digits, and it must fit a `u64` | it decides how many bytes this side then reads |
//! | the name | `max_name_bytes`, no `/`, no `.`, no `..`, no control byte | see below |
//!
//! **The mode is read and never applied.** A file this build writes gets
//! the mode `src/cli/output.zig` gives every other file, under the process
//! umask. A server that answered `C4755` would otherwise hand a user a
//! setuid file they never asked for.
//!
//! **The name never chooses a file this build writes.** `-O` takes its name
//! from the url, which is what `src/cli/output.zig`'s `checkName` judges,
//! and that is the one function in zurl that decides such a thing. The name
//! on a `C` line reaches a counter and a diagnostic and nothing else. It is
//! still checked here, the way OpenSSH's own `scp` checks it, so that a
//! name holding a path separator stops the transfer rather than travel
//! further as a value nobody judged.

const std = @import("std");

/// The status byte that says "carry on".
pub const ack: u8 = 0;
/// The status byte in front of a warning. The transfer may carry on.
pub const warning: u8 = 1;
/// The status byte in front of a fatal message. The transfer is over.
pub const fatal: u8 = 2;

/// The longest control line this build reads, with no newline counted.
///
/// 1024. A `C` line is a mode, a size, and a name, and the name is bounded
/// on its own below. A message line is text the peer wrote, and this is the
/// bound on that. A line past it is `error.LineTooLong` rather than a read
/// that never ends.
pub const max_line_bytes: usize = 1024;

/// The longest file name this build takes off a `C` or a `D` line.
///
/// 255, which is `NAME_MAX` on Linux and the same number
/// `src/cli/output.zig` keeps for a name it writes. The name is never a
/// file here, and the bound is still the same one, because two numbers for
/// one idea is how they drift apart.
pub const max_name_bytes: usize = 255;

/// How many decimal digits a size may hold.
///
/// 20, which is the digit count of 2^64-1. A longer run of digits is
/// refused before it is a number, so no parse can wrap.
pub const max_size_digits: usize = 20;

/// How many octal digits a mode may hold.
///
/// 4. OpenSSH's `scp` writes `%04o` and every mode this build has seen is
/// four digits. The value is bounded again at `0o7777`.
pub const max_mode_digits: usize = 4;

/// The largest mode this build takes, which is every permission bit and the
/// three set-id bits.
pub const max_mode: u16 = 0o7777;

/// Why a control line will not read.
pub const ParseError = error{
    /// The line holds no byte at all.
    LineEmpty,
    /// The line starts with a byte this build does not name.
    LineTypeUnknown,
    /// The line is longer than `max_line_bytes`.
    LineTooLong,
    /// A `C` or a `D` line does not hold a mode, a size, and a name.
    LineMalformed,
    /// The mode is not one to four octal digits, or it is past `max_mode`.
    ModeInvalid,
    /// The size is not one to `max_size_digits` decimal digits, or it does
    /// not fit a `u64`.
    SizeInvalid,
    /// The name is empty, longer than `max_name_bytes`, or it holds a byte
    /// no single file name may hold.
    NameInvalid,
    /// A `T` line does not hold four decimal numbers.
    TimeInvalid,
};

/// What a `C` or a `D` line said.
pub const FileLine = struct {
    /// The permission bits the server named. **Read and never applied.**
    mode: u16,
    /// How many bytes the file holds. **This bounds a read, so a caller
    /// checks it against its own ceiling before it allocates.**
    size: u64,
    /// The file name the server named. **It is the server's text and it
    /// never names a file this build writes.** It points into the caller's
    /// own line buffer.
    name: []const u8,
};

/// What a `T` line said, RFC nothing: this is `scp`'s own.
pub const TimeLine = struct {
    modified_s: u64,
    modified_us: u64,
    accessed_s: u64,
    accessed_us: u64,
};

/// One control line, read.
pub const Line = union(enum) {
    /// `C<mode> <size> <name>`, which is one file about to arrive.
    file: FileLine,
    /// `D<mode> <size> <name>`, which is a directory about to be walked.
    /// **This build refuses one**, and the parser still names it so that
    /// the refusal says what arrived.
    directory: FileLine,
    /// `E`, which ends a directory.
    end_directory,
    /// `T<mtime> <mtime_us> <atime> <atime_us>`, which `-p` asks for.
    time: TimeLine,
};

/// Reads one control line.
///
/// `line` is the bytes of the line with **no newline on the end**. The
/// caller reads the line and cuts the newline, because the caller is the
/// one holding the bound on how far it will read.
///
/// The returned `name` points into `line`.
pub fn parseLine(line: []const u8) ParseError!Line {
    if (line.len == 0) return error.LineEmpty;
    if (line.len > max_line_bytes) return error.LineTooLong;
    return switch (line[0]) {
        'C' => .{ .file = try parseFileLine(line[1..]) },
        'D' => .{ .directory = try parseFileLine(line[1..]) },
        'E' => if (line.len == 1) .end_directory else error.LineMalformed,
        'T' => .{ .time = try parseTimeLine(line[1..]) },
        else => error.LineTypeUnknown,
    };
}

/// Reads `<mode> <size> <name>`, which is what follows a `C` or a `D`.
fn parseFileLine(rest: []const u8) ParseError!FileLine {
    const first_space = std.mem.indexOfScalar(u8, rest, ' ') orelse
        return error.LineMalformed;
    const mode = try parseMode(rest[0..first_space]);

    const after_mode = rest[first_space + 1 ..];
    const second_space = std.mem.indexOfScalar(u8, after_mode, ' ') orelse
        return error.LineMalformed;
    const size = try parseSize(after_mode[0..second_space]);

    const name = after_mode[second_space + 1 ..];
    try checkName(name);
    return .{ .mode = mode, .size = size, .name = name };
}

/// Reads the four numbers of a `T` line.
fn parseTimeLine(rest: []const u8) ParseError!TimeLine {
    var fields: [4]u64 = undefined;
    var at: usize = 0;
    var read: usize = 0;
    while (read < fields.len) : (read += 1) {
        if (at > rest.len) return error.TimeInvalid;
        const end = std.mem.indexOfScalarPos(u8, rest, at, ' ') orelse rest.len;
        fields[read] = parseSize(rest[at..end]) catch return error.TimeInvalid;
        at = end + 1;
    }
    // A fifth field is a line this build does not read, and a line it does
    // not read is not a line it acts on.
    if (at <= rest.len) return error.TimeInvalid;
    return .{
        .modified_s = fields[0],
        .modified_us = fields[1],
        .accessed_s = fields[2],
        .accessed_us = fields[3],
    };
}

/// Reads one to `max_mode_digits` octal digits.
pub fn parseMode(text: []const u8) ParseError!u16 {
    if (text.len == 0 or text.len > max_mode_digits) return error.ModeInvalid;
    var value: u16 = 0;
    for (text) |byte| {
        if (byte < '0' or byte > '7') return error.ModeInvalid;
        value = value * 8 + (byte - '0');
    }
    if (value > max_mode) return error.ModeInvalid;
    return value;
}

/// Reads one to `max_size_digits` decimal digits.
///
/// **The digit count is checked before the first digit is added**, so the
/// multiply below can never wrap, whatever the peer wrote.
pub fn parseSize(text: []const u8) ParseError!u64 {
    if (text.len == 0 or text.len > max_size_digits) return error.SizeInvalid;
    var value: u64 = 0;
    for (text) |byte| {
        if (byte < '0' or byte > '9') return error.SizeInvalid;
        const scaled = std.math.mul(u64, value, 10) catch return error.SizeInvalid;
        value = std.math.add(u64, scaled, byte - '0') catch return error.SizeInvalid;
    }
    return value;
}

/// Refuses a name that is not one plain entry name.
///
/// This is the check OpenSSH's own `scp` sink makes: no `/`, and never `.`
/// or `..`. zurl adds the control bytes, because a name with a CR in it
/// lets a later log line pretend to be a different line.
///
/// **A backslash is not refused, and that is measured rather than
/// assumed.** OpenSSH 10.5p1 vis-encodes a control byte in a name before it
/// writes the `C` line, and the escape it writes is a backslash: a file
/// named `a<LF>b` arrives as `C0644 11 a\^Jb`. A build that refused a
/// backslash would refuse OpenSSH's own escape, and a backslash is a legal
/// byte in a name on the far side anyway.
///
/// **The rule about a name becoming a local path lives in
/// `src/cli/output.zig`'s `checkName`**, which is the one function in zurl
/// that judges such a name, and it refuses a backslash there. No name from
/// this file reaches it, and none reaches the filesystem.
///
/// **The name is refused and never repaired.** A name this build changed is
/// not the name the server sent, and a caller comparing the two would be
/// comparing zurl's guess with the server's word.
pub fn checkName(name: []const u8) ParseError!void {
    if (name.len == 0 or name.len > max_name_bytes) return error.NameInvalid;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) {
        return error.NameInvalid;
    }
    for (name) |byte| {
        if (byte == '/') return error.NameInvalid;
        if (byte < 0x20 or byte == 0x7f) return error.NameInvalid;
    }
}

/// Writes a `C` line for an upload into `out`, with the newline.
///
/// **The name is a basename and not a path.** The path is already in the
/// `exec` command, which is what the measured transcript shows: curl sends
/// `scp -t '/srv/up_dst.txt'` and then `C0644 14 up_dst.txt`.
pub fn writeFileLine(
    out: []u8,
    mode: u16,
    size: u64,
    name: []const u8,
) (ParseError || error{NoSpaceLeft})![]u8 {
    if (mode > max_mode) return error.ModeInvalid;
    try checkName(name);
    return std.fmt.bufPrint(out, "C{o:0>4} {d} {s}\n", .{ mode, size, name });
}

/// The basename of `path`, which is what a `C` line carries.
///
/// A path that ends in a separator has no basename, and neither has one
/// that is `.` or `..`. Each is an empty answer, and the caller refuses it
/// by name rather than invent one.
pub fn baseName(path: []const u8) []const u8 {
    const cut = std.mem.lastIndexOfScalar(u8, path, '/') orelse return path;
    return path[cut + 1 ..];
}

const testing = std.testing;

test "a C line reads the mode, the size, and the name" {
    const got = try parseLine("C0644 16 hello.txt");
    try testing.expectEqual(@as(u16, 0o644), got.file.mode);
    try testing.expectEqual(@as(u64, 16), got.file.size);
    try testing.expectEqualStrings("hello.txt", got.file.name);
}

test "a name with a space in it is one name and not two fields" {
    // The name is everything past the second space, so a file called
    // `a b.txt` reads whole. A parser that split on every space would cut
    // it and report a name the server never sent.
    const got = try parseLine("C0644 3 a b.txt");
    try testing.expectEqualStrings("a b.txt", got.file.name);
}

test "a T line reads the four times -p asks for" {
    const got = try parseLine("T1788675695 0 1788675718 0");
    try testing.expectEqual(@as(u64, 1788675695), got.time.modified_s);
    try testing.expectEqual(@as(u64, 0), got.time.modified_us);
    try testing.expectEqual(@as(u64, 1788675718), got.time.accessed_s);
    try testing.expectEqual(@as(u64, 0), got.time.accessed_us);
}

test "a D line and an E line are named, so a refusal can say what arrived" {
    const got = try parseLine("D0755 0 sub");
    try testing.expectEqualStrings("sub", got.directory.name);
    try testing.expectEqual(Line.end_directory, try parseLine("E"));
    try testing.expectError(error.LineMalformed, parseLine("Ex"));
}

test "a line this build does not name is refused and never guessed at" {
    try testing.expectError(error.LineEmpty, parseLine(""));
    try testing.expectError(error.LineTypeUnknown, parseLine("X0644 1 a"));
    try testing.expectError(error.LineTypeUnknown, parseLine("c0644 1 a"));
}

test "a line past the bound is refused" {
    var long: [max_line_bytes + 1]u8 = undefined;
    @memset(&long, 'C');
    try testing.expectError(error.LineTooLong, parseLine(&long));
}

test "the mode is bounded, and a mode this build cannot read is refused" {
    try testing.expectEqual(@as(u16, 0o7777), try parseMode("7777"));
    try testing.expectEqual(@as(u16, 0), try parseMode("0"));
    // Eight is not an octal digit, five digits is one too many, and an
    // empty field is not a mode.
    try testing.expectError(error.ModeInvalid, parseMode("0648"));
    try testing.expectError(error.ModeInvalid, parseMode("07777"));
    try testing.expectError(error.ModeInvalid, parseMode(""));
    try testing.expectError(error.ModeInvalid, parseMode("-644"));
    try testing.expectError(error.ModeInvalid, parseLine("C 1 a"));
}

test "the size is bounded before it is a number, so no parse can wrap" {
    try testing.expectEqual(@as(u64, 0), try parseSize("0"));
    try testing.expectEqual(
        @as(u64, std.math.maxInt(u64)),
        try parseSize("18446744073709551615"),
    );
    // One past the largest u64 is 20 digits, so the digit count lets it in
    // and the multiply catches it.
    try testing.expectError(error.SizeInvalid, parseSize("18446744073709551616"));
    // 21 digits never reaches the multiply at all.
    try testing.expectError(error.SizeInvalid, parseSize("999999999999999999999"));
    try testing.expectError(error.SizeInvalid, parseSize(""));
    try testing.expectError(error.SizeInvalid, parseSize("-1"));
    try testing.expectError(error.SizeInvalid, parseSize("1 "));
    try testing.expectError(error.SizeInvalid, parseSize("0x10"));
}

test "a server's name may not hold a path separator or a control byte" {
    // **This is the check that keeps a server's name from being a path.**
    // OpenSSH's own `scp` makes it, and zurl adds the backslash and the
    // control bytes.
    try testing.expectError(error.NameInvalid, checkName("../etc/passwd"));
    try testing.expectError(error.NameInvalid, checkName("/etc/passwd"));
    try testing.expectError(error.NameInvalid, checkName("a/b"));
    try testing.expectError(error.NameInvalid, checkName(".."));
    try testing.expectError(error.NameInvalid, checkName("."));
    try testing.expectError(error.NameInvalid, checkName("a\x00b"));
    try testing.expectError(error.NameInvalid, checkName("a\rb"));
    try testing.expectError(error.NameInvalid, checkName("a\nb"));
    try testing.expectError(error.NameInvalid, checkName("a\x7f"));
    try testing.expectError(error.NameInvalid, checkName(""));

    var long: [max_name_bytes + 1]u8 = undefined;
    @memset(&long, 'a');
    try testing.expectError(error.NameInvalid, checkName(&long));
    try checkName(long[0..max_name_bytes]);

    // A name a person would actually meet still reads.
    try checkName("a b.txt");
    try checkName("it's.txt");
    try checkName("...");
    // A backslash reads, and it has to: OpenSSH 10.5p1 writes `a\^Jb` for a
    // file named `a<LF>b`, measured off the wire. A build that refused it
    // would refuse OpenSSH's own escape.
    try checkName("a\\b");
    try checkName("a\\^Jb");
}

test "a C line whose name is a path is refused whole" {
    try testing.expectError(error.NameInvalid, parseLine("C0644 1 ../../etc/passwd"));
    try testing.expectError(error.NameInvalid, parseLine("C0644 1 /etc/passwd"));
}

test "a C line missing a field is refused" {
    try testing.expectError(error.LineMalformed, parseLine("C0644"));
    try testing.expectError(error.LineMalformed, parseLine("C0644 16"));
    try testing.expectError(error.NameInvalid, parseLine("C0644 16 "));
}

test "a T line with the wrong field count is refused" {
    try testing.expectError(error.TimeInvalid, parseLine("T1 2 3"));
    try testing.expectError(error.TimeInvalid, parseLine("T1 2 3 4 5"));
    try testing.expectError(error.TimeInvalid, parseLine("Ta b c d"));
}

test "an upload writes the C line curl writes" {
    var storage: [max_line_bytes]u8 = undefined;
    try testing.expectEqualStrings(
        "C0644 14 up_dst.txt\n",
        try writeFileLine(&storage, 0o644, 14, "up_dst.txt"),
    );
    // The mode is always four digits, which is what OpenSSH's `%04o`
    // writes, so a server reading it never meets a short field.
    try testing.expectEqualStrings(
        "C0000 0 a\n",
        try writeFileLine(&storage, 0, 0, "a"),
    );
}

test "an upload will not write a name that is a path" {
    var storage: [max_line_bytes]u8 = undefined;
    try testing.expectError(
        error.NameInvalid,
        writeFileLine(&storage, 0o644, 1, "a/b"),
    );
    try testing.expectError(
        error.NameInvalid,
        writeFileLine(&storage, 0o644, 1, "a\nb"),
    );
    try testing.expectError(
        error.ModeInvalid,
        writeFileLine(&storage, 0o10000, 1, "a"),
    );
}

test "the basename is the part past the last separator" {
    try testing.expectEqualStrings("f.txt", baseName("/srv/f.txt"));
    try testing.expectEqualStrings("f.txt", baseName("f.txt"));
    try testing.expectEqualStrings("", baseName("/srv/"));
    try testing.expectEqualStrings("", baseName("/"));
}

test "a line this file reads round trips through the one it writes" {
    var storage: [max_line_bytes]u8 = undefined;
    const written = try writeFileLine(&storage, 0o600, 4096, "a b.txt");
    const got = try parseLine(written[0 .. written.len - 1]);
    try testing.expectEqual(@as(u16, 0o600), got.file.mode);
    try testing.expectEqual(@as(u64, 4096), got.file.size);
    try testing.expectEqualStrings("a b.txt", got.file.name);
}
