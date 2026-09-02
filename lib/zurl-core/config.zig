//! A parser for the curl config file format, which `.curlrc` and `--config`
//! both use.
//!
//! One option goes on each line. The leading dashes are optional. A value may
//! follow the name after a space or an equals sign. A quoted value may contain
//! escapes.
//!
//! This module does no I/O. The caller reads the file and passes the bytes.

const std = @import("std");

/// The longest option name this parser hands back.
///
/// A config file is untrusted input, and the name reaches a message on
/// standard error when zurl does not know it. Without a bound the name is
/// as long as the line, which `src/cli/Args.zig` bounds only at 1 MiB, so
/// one line could put a megabyte of the file's own bytes on standard
/// error and cost two allocations of that size on the way.
///
/// No option curl or zurl has comes near 128 bytes: curl's longest is
/// `proxy-tlsv1`-shaped, well under 32. A longer name therefore names no
/// option, and this parser refuses it rather than pass it on.
pub const max_option_name_bytes: usize = 128;

/// One option from a config file.
///
/// `name` always borrows from the input text. `value` borrows from the input
/// text when it is unquoted, and from the caller's buffer when it is quoted.
pub const Option = struct {
    /// The option name with no leading dashes. Never longer than
    /// `max_option_name_bytes`.
    name: []const u8,
    value: ?[]const u8,
    /// Which line of the file this option came from, counting from 1. A
    /// caller names it in a fault message, the way curl does.
    line: u32,
};

pub const Error = error{
    /// A quoted value has no closing quote before the end of its line.
    UnterminatedQuote,
    /// The decoded value does not fit the caller's buffer.
    NoSpaceLeft,
    /// An option name is longer than `max_option_name_bytes`, so it names
    /// no option any tool has.
    OptionNameTooLong,
};

/// Walks the options in a config file.
pub const Iterator = struct {
    text: []const u8,
    index: usize = 0,
    /// Which line `takeLine` returns next, counting from 1.
    ///
    /// A `u32` counts every line of a file far larger than any config
    /// file a caller reads. The count saturates rather than wraps, so a
    /// pathological file reports a wrong line number and never a wrapped
    /// one.
    line: u32 = 1,

    pub fn init(text: []const u8) Iterator {
        return .{ .text = text };
    }

    /// Returns the next option, or null at the end of the text.
    ///
    /// `out` holds the decoded form of a quoted value. Its content is only
    /// valid until the next call.
    ///
    /// A line this refuses is already consumed, so a caller that treats
    /// the fault as a warning can call `next` again and read the rest of
    /// the file.
    pub fn next(it: *Iterator, out: []u8) Error!?Option {
        while (it.index < it.text.len) {
            const at = it.line;
            const line = it.takeLine();
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0) continue;
            if (trimmed[0] == '#') continue;
            return try parseLine(trimmed, at, out);
        }
        return null;
    }

    /// Returns the next line and steps past its newline.
    fn takeLine(it: *Iterator) []const u8 {
        const start = it.index;
        while (it.index < it.text.len and it.text[it.index] != '\n') it.index += 1;
        const line = it.text[start..it.index];
        if (it.index < it.text.len) it.index += 1;
        it.line +|= 1;
        return line;
    }
};

/// Parses one non-empty, non-comment line. `at` is the line's own number.
fn parseLine(line: []const u8, at: u32, out: []u8) Error!Option {
    var rest = line;
    // curl accepts an option with one dash, two dashes, or none.
    while (rest.len > 0 and rest[0] == '-') rest = rest[1..];

    var name_end: usize = 0;
    while (name_end < rest.len and rest[name_end] != ' ' and
        rest[name_end] != '\t' and rest[name_end] != '=') name_end += 1;
    if (name_end > max_option_name_bytes) return error.OptionNameTooLong;
    const name = rest[0..name_end];

    var value_text = std.mem.trim(u8, rest[name_end..], " \t");
    if (value_text.len > 0 and value_text[0] == '=') {
        value_text = std.mem.trim(u8, value_text[1..], " \t");
    }
    if (value_text.len == 0) return .{ .name = name, .value = null, .line = at };

    if (value_text[0] != '"') return .{ .name = name, .value = value_text, .line = at };
    return .{ .name = name, .value = try unquote(value_text, out), .line = at };
}

/// Decodes a quoted value into `out`.
///
/// curl reads `\t`, `\n`, `\r`, `\v`, `\"`, and `\\`. Any other escape keeps
/// the character that follows the backslash.
fn unquote(text: []const u8, out: []u8) Error![]u8 {
    std.debug.assert(text.len > 0 and text[0] == '"');
    var written: usize = 0;
    var i: usize = 1;
    while (i < text.len) {
        const c = text[i];
        if (c == '"') return out[0..written];
        if (written == out.len) return error.NoSpaceLeft;
        if (c != '\\') {
            out[written] = c;
            written += 1;
            i += 1;
            continue;
        }
        if (i + 1 >= text.len) return error.UnterminatedQuote;
        out[written] = switch (text[i + 1]) {
            't' => '\t',
            'n' => '\n',
            'r' => '\r',
            'v' => 11,
            else => |other| other,
        };
        written += 1;
        i += 2;
    }
    return error.UnterminatedQuote;
}

test "next reads a long option with a value" {
    var it: Iterator = .init("--user-agent zurl/1.0\n");
    var buf: [64]u8 = undefined;
    const opt = (try it.next(&buf)).?;
    try std.testing.expectEqualStrings("user-agent", opt.name);
    try std.testing.expectEqualStrings("zurl/1.0", opt.value.?);
}

test "next accepts an option with no dashes" {
    var it: Iterator = .init("user-agent zurl/1.0\n");
    var buf: [64]u8 = undefined;
    const opt = (try it.next(&buf)).?;
    try std.testing.expectEqualStrings("user-agent", opt.name);
}

test "next accepts an equals sign between the name and the value" {
    var it: Iterator = .init("--max-time = 30\n");
    var buf: [64]u8 = undefined;
    const opt = (try it.next(&buf)).?;
    try std.testing.expectEqualStrings("max-time", opt.name);
    try std.testing.expectEqualStrings("30", opt.value.?);
}

test "next reads an option with no value" {
    var it: Iterator = .init("--silent\n");
    var buf: [64]u8 = undefined;
    const opt = (try it.next(&buf)).?;
    try std.testing.expectEqualStrings("silent", opt.name);
    try std.testing.expectEqual(@as(?[]const u8, null), opt.value);
}

test "next decodes the escapes in a quoted value" {
    var it: Iterator = .init("--header \"X-A: a\\tb\\\"c\\\\d\"\n");
    var buf: [64]u8 = undefined;
    const opt = (try it.next(&buf)).?;
    try std.testing.expectEqualStrings("X-A: a\tb\"c\\d", opt.value.?);
}

test "next skips comments and blank lines" {
    var it: Iterator = .init("# a comment\n\n--silent\n");
    var buf: [64]u8 = undefined;
    const opt = (try it.next(&buf)).?;
    try std.testing.expectEqualStrings("silent", opt.name);
    try std.testing.expectEqual(@as(?Option, null), try it.next(&buf));
}

test "next returns null at the end of the text" {
    var it: Iterator = .init("");
    var buf: [64]u8 = undefined;
    try std.testing.expectEqual(@as(?Option, null), try it.next(&buf));
}

test "next reports a quoted value that never closes" {
    var it: Iterator = .init("--header \"unterminated\n");
    var buf: [64]u8 = undefined;
    try std.testing.expectError(error.UnterminatedQuote, it.next(&buf));
}

test "next reports a value that does not fit the buffer" {
    var it: Iterator = .init("--header \"aaaaaaaaaa\"\n");
    var buf: [4]u8 = undefined;
    try std.testing.expectError(error.NoSpaceLeft, it.next(&buf));
}

test "next counts the line each option came from" {
    // A caller names the line in a fault message, so blank lines and
    // comments must count too, and the count must start at 1.
    var it: Iterator = .init("# a comment\n\n--silent\nuser-agent x\n\n-f\n");
    var buf: [64]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 3), (try it.next(&buf)).?.line);
    try std.testing.expectEqual(@as(u32, 4), (try it.next(&buf)).?.line);
    try std.testing.expectEqual(@as(u32, 6), (try it.next(&buf)).?.line);
    try std.testing.expectEqual(@as(?Option, null), try it.next(&buf));
}

test "an option name at the bound is accepted and one past it is refused" {
    // Both sides. A parser that refused every long name, or that refused
    // none, passes only one of these two.
    const at_bound = "-" ++ "Q" ** max_option_name_bytes ++ "\n";
    var accepted: Iterator = .init(at_bound);
    var buf: [64]u8 = undefined;
    const opt = (try accepted.next(&buf)).?;
    try std.testing.expectEqual(max_option_name_bytes, opt.name.len);

    const past_bound = "-" ++ "Q" ** (max_option_name_bytes + 1) ++ "\n";
    var refused: Iterator = .init(past_bound);
    try std.testing.expectError(error.OptionNameTooLong, refused.next(&buf));
}

test "a refused line does not stop the lines after it" {
    // A caller that treats a fault in the default config file as a
    // warning reads on. The iterator has already stepped past the line it
    // refused, so the next call returns the next option.
    const text = "-" ++ "Q" ** (max_option_name_bytes + 1) ++ "\n--silent\n";
    var it: Iterator = .init(text);
    var buf: [64]u8 = undefined;
    try std.testing.expectError(error.OptionNameTooLong, it.next(&buf));
    const opt = (try it.next(&buf)).?;
    try std.testing.expectEqualStrings("silent", opt.name);
    try std.testing.expectEqual(@as(u32, 2), opt.line);
}
