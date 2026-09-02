//! The one printer for untrusted text in a user-visible message.
//!
//! zurl echoes text it did not write: a flag the user typed, an option
//! name out of a config file, a `-w` variable name, a url a server or a
//! file named. Every one of those is attacker-shaped input, and printing
//! it raw costs four separate faults.
//!
//! - A userinfo password in a url reaches a CI log or a journal.
//! - A raw newline lets the text draw a second line that reads like one of
//!   zurl's own.
//! - A raw control byte moves a terminal's cursor, sets a colour, or rings
//!   a bell, so a file can forge what the terminal shows.
//! - An unbounded string turns one line into megabytes.
//!
//! `Text` closes all four in one place. **Every `{s}` of untrusted text in
//! a message zurl writes must be a `{f}` of a `Text` instead.** One rule,
//! one function: a second copy of it is how the next hole gets in, which
//! is the shape this file exists to stop. `src/cli/report.zig`,
//! `src/cli/writeout.zig`, `src/cli/Args.zig`, and `src/main.zig` are its
//! callers.
//!
//! Masking is applied to every string, not only to one the caller believes
//! is a url. A caller that had to decide is a caller that can decide
//! wrong, and masking text that carries no password costs a diagnostic
//! that says a little less. `zurl_core.redact` explains why that direction
//! is the safe one.
//!
//! **`controlLen` is the second thing this file owns, and it is one rule
//! too.** `Text` answers the question "may this byte reach a message",
//! which it answers with printable ASCII alone. Two other callers ask a
//! narrower question: "does this reach a terminal, or a file name, as a
//! control". `src/cli/output.zig` asks it of a file name a server chose,
//! and `src/cli/writeout.zig` asks it of a `-w` value a server chose.
//! Those two once carried their own rules, and the two rules did not say
//! the same thing: one refused a C0 byte and passed a UTF-8 encoded C1,
//! and the other refused nothing at all. One rule in one place is what
//! stops that drift.

const std = @import("std");
const zurl_core = @import("zurl-core");

const Writer = std.Io.Writer;

/// How many bytes of untrusted text one message shows by default.
///
/// Long enough for a flag, an option name, or a file path a person types,
/// and short enough that one line stays one line. A caller that shows a
/// value with a larger natural bound, such as a url, passes its own
/// `max_len`.
pub const default_max_len: usize = 256;

/// What a truncated value ends with, so a reader can tell a cut value from
/// a whole one.
pub const ellipsis = "...";

/// Untrusted text, ready to print with `{f}`.
///
/// Build one with `text` for the default bound, or with a struct literal
/// to set `max_len`.
pub const Text = struct {
    bytes: []const u8,
    /// How many bytes of `bytes` to show. What follows prints as
    /// `ellipsis`.
    max_len: usize = default_max_len,

    pub fn format(t: Text, w: *Writer) Writer.Error!void {
        var left = t.max_len;
        var truncated = false;
        if (zurl_core.redact.passwordRange(t.bytes)) |r| {
            try writeClean(w, t.bytes[0..r.start], &left, &truncated);
            try writeClean(w, zurl_core.redact.mask, &left, &truncated);
            try writeClean(w, t.bytes[r.end..], &left, &truncated);
        } else {
            try writeClean(w, t.bytes, &left, &truncated);
        }
        if (truncated) try w.writeAll(ellipsis);
    }
};

/// Untrusted `bytes`, bounded at `default_max_len`.
pub fn text(bytes: []const u8) Text {
    return .{ .bytes = bytes };
}

/// The longest control code point `controlLen` reports, in bytes.
///
/// A C0 byte and a DEL are one byte each. A C1 control spelled in UTF-8 is
/// two. Nothing this rule names is longer, so a caller that must hold one
/// whole code point needs a buffer of this size and no more.
pub const control_max_len: usize = 2;

/// How many bytes at the front of `bytes` spell one control code point, or
/// zero when they spell something else.
///
/// **This is the one rule for "a byte a server chose, that a terminal or a
/// file system must not get".** Three shapes count.
///
/// - A C0 byte, `0x00` through `0x1f`. A NUL ends a path for the operating
///   system, a CR or an LF draws a line of its own in a log, and an ESC
///   starts a sequence a terminal acts on.
/// - A DEL, `0x7f`.
/// - U+0080 through U+009F, the C1 controls, spelled in UTF-8 as `0xc2`
///   and one byte from `0x80` to `0x9f`. U+009B is CSI, which starts the
///   same sequences an ESC and a `[` start, so a terminal that reads UTF-8
///   acts on those two bytes exactly as it acts on an escape.
///
/// **A lone byte from `0x80` to `0xbf` is not a control here, and that is
/// deliberate.** Those are UTF-8 continuation bytes: the Japanese
/// character U+65E5 is `0xe6 0x97 0xa5`, whose middle byte is `0x97`.
/// A rule that refused every raw byte in the C1 numeric range would refuse
/// ordinary Japanese, Greek, and Cyrillic text. The rule reads the
/// encoding, not the number.
///
/// A caller walks `bytes` and advances by the answer when it is not zero,
/// and by one when it is.
pub fn controlLen(bytes: []const u8) usize {
    if (bytes.len == 0) return 0;
    switch (bytes[0]) {
        0x00...0x1f, 0x7f => return 1,
        0xc2 => {
            if (bytes.len < 2) return 0;
            return switch (bytes[1]) {
                0x80...0x9f => 2,
                else => 0,
            };
        },
        else => return 0,
    }
}

/// Writes `bytes` with every control code point replaced by one `?`.
///
/// This is `controlLen`'s printing half, for a caller that must show a
/// server's own text and not a diagnostic about it. `Text` is the rule for
/// a message, and it is stricter: it drops every byte outside printable
/// ASCII, so a UTF-8 name reaches a message as one `?` for each byte. That
/// is right for a message and wrong here, because what this writes goes
/// into a script's standard input, where a mangled url or media type is a
/// fault of its own.
///
/// So the two rules differ in what they keep and agree on what they refuse:
/// every control code point `controlLen` names becomes one `?`, whichever
/// of the two a caller uses.
///
/// **This bounds nothing.** The caller's value is already bounded by the
/// engine's own limit on a response head, and a `-w` value cut in the
/// middle would hand a script half a url that still reads like a whole
/// one. A bound belongs where the value is read, not here.
pub fn writeWithoutControls(w: *Writer, bytes: []const u8) Writer.Error!void {
    var index: usize = 0;
    var kept: usize = 0;
    while (index < bytes.len) {
        const len = controlLen(bytes[index..]);
        if (len == 0) {
            index += 1;
            continue;
        }
        try w.writeAll(bytes[kept..index]);
        try w.writeByte('?');
        index += len;
        kept = index;
    }
    try w.writeAll(bytes[kept..]);
}

/// Writes as much of `part` as `left.*` still allows, one printable byte
/// at a time, and reports through `truncated` whether anything was
/// dropped.
///
/// Every byte outside printable ASCII prints as `?`. The set is exactly
/// `std.ascii.isPrint`, so a space passes and a tab, a newline, an escape,
/// a DEL, and every byte over 0x7e do not. A UTF-8 name therefore prints
/// as one `?` for each of its bytes, which is a cost this takes on
/// purpose: no rule that keeps some non-ASCII bytes and drops others can
/// be stated in one line, and a message is not a place to reconstruct
/// text.
///
/// curl 8.21.0 echoes the raw bytes in the same messages. zurl is
/// stricter, and only in a message: what `-w` prints on standard output,
/// and the body itself, are untouched.
fn writeClean(w: *Writer, part: []const u8, left: *usize, truncated: *bool) Writer.Error!void {
    for (part) |byte| {
        if (left.* == 0) {
            truncated.* = true;
            return;
        }
        try w.writeByte(if (std.ascii.isPrint(byte)) byte else '?');
        left.* -= 1;
    }
}

const testing = std.testing;

fn render(buffer: []u8, t: Text) ![]const u8 {
    var w: Writer = .fixed(buffer);
    try w.print("{f}", .{t});
    return w.buffered();
}

test "printable ascii passes through unchanged" {
    var buffer: [128]u8 = undefined;
    try testing.expectEqualStrings("--compressed", try render(&buffer, text("--compressed")));
}

test "a control byte cannot reach the terminal" {
    var buffer: [128]u8 = undefined;
    try testing.expectEqualStrings(
        "ev?[31mIL?",
        try render(&buffer, text("ev\x1b[31mIL\x07")),
    );
}

test "a newline cannot draw a second line" {
    var buffer: [128]u8 = undefined;
    try testing.expectEqualStrings(
        "a?zurl: forged",
        try render(&buffer, text("a\nzurl: forged")),
    );
}

test "text past the bound is cut and marked" {
    var buffer: [512]u8 = undefined;
    const long = "Q" ** 300;
    const out = try render(&buffer, text(long));
    try testing.expectEqual(default_max_len + ellipsis.len, out.len);
    try testing.expect(std.mem.endsWith(u8, out, ellipsis));
}

test "text at the bound is whole and unmarked" {
    // The bound is checked from both sides. A printer that cut one byte
    // early, or that never cut at all, fails one of these two.
    var buffer: [512]u8 = undefined;
    const at_bound = "Q" ** default_max_len;
    const out = try render(&buffer, text(at_bound));
    try testing.expectEqualStrings(at_bound, out);
}

test "a caller may set a smaller bound" {
    var buffer: [128]u8 = undefined;
    try testing.expectEqualStrings(
        "abcd...",
        try render(&buffer, .{ .bytes = "abcdefgh", .max_len = 4 }),
    );
}

test "a userinfo password never reaches the message" {
    var buffer: [128]u8 = undefined;
    try testing.expectEqualStrings(
        "http://alice:***@example.com/x",
        try render(&buffer, text("http://alice:hunter2@example.com/x")),
    );
}

test "the bound counts the masked text, not the raw text" {
    // A password long enough to fill the bound must not push the rest of
    // the url out of the line: the mask is three bytes whatever the
    // password was.
    var buffer: [256]u8 = undefined;
    const long_password = "Q" ** 200;
    const out = try render(&buffer, text("http://a:" ++ long_password ++ "@example.com/x"));
    try testing.expectEqualStrings("http://a:***@example.com/x", out);
}

test "an empty string prints nothing" {
    var buffer: [16]u8 = undefined;
    try testing.expectEqualStrings("", try render(&buffer, text("")));
}

test "controlLen names a C0 byte, a DEL, and a UTF-8 C1 control" {
    try testing.expectEqual(@as(usize, 1), controlLen("\x00rest"));
    try testing.expectEqual(@as(usize, 1), controlLen("\x1brest"));
    try testing.expectEqual(@as(usize, 1), controlLen("\x1f"));
    try testing.expectEqual(@as(usize, 1), controlLen("\x7f"));
    // U+009B, the CSI a terminal acts on exactly as it acts on ESC `[`.
    try testing.expectEqual(@as(usize, 2), controlLen("\xc2\x9brest"));
    try testing.expectEqual(@as(usize, 2), controlLen("\xc2\x80"));
}

test "controlLen leaves ordinary text and UTF-8 alone" {
    try testing.expectEqual(@as(usize, 0), controlLen(""));
    try testing.expectEqual(@as(usize, 0), controlLen(" "));
    try testing.expectEqual(@as(usize, 0), controlLen("a"));
    try testing.expectEqual(@as(usize, 0), controlLen("\x7e"));
    // U+00E9, one past the C1 range, is the `é` of an ordinary name.
    try testing.expectEqual(@as(usize, 0), controlLen("\xc2\xa9"));
    try testing.expectEqual(@as(usize, 0), controlLen("\xc3\xa9"));
    // A lone continuation byte from the C1 numeric range. U+65E5 spells
    // `\xe6\x97\xa5`, so `0x97` in the middle of a name is Japanese text
    // and not a control.
    try testing.expectEqual(@as(usize, 0), controlLen("\x97"));
    try testing.expectEqual(@as(usize, 0), controlLen("\xe6\x97\xa5"));
    // A truncated two-byte sequence names no code point at all, so it is
    // not a control either.
    try testing.expectEqual(@as(usize, 0), controlLen("\xc2"));
}

fn cleaned(buffer: []u8, bytes: []const u8) ![]const u8 {
    var w: Writer = .fixed(buffer);
    try writeWithoutControls(&w, bytes);
    return w.buffered();
}

test "writeWithoutControls replaces one control code point with one question mark" {
    var buffer: [128]u8 = undefined;
    try testing.expectEqualStrings(
        "text/plain?[2J?[31mHACKED",
        try cleaned(&buffer, "text/plain\x1b[2J\x1b[31mHACKED"),
    );
    // Two bytes in, one `?` out, because the two bytes are one code point.
    try testing.expectEqualStrings("a?b", try cleaned(&buffer, "a\xc2\x9bb"));
    try testing.expectEqualStrings("a?b", try cleaned(&buffer, "a\x00b"));
}

test "writeWithoutControls keeps UTF-8 whole, where Text would not" {
    var buffer: [128]u8 = undefined;
    // A media type with a name in it must reach a script as the peer wrote
    // it. `Text` answers `??????` for these same bytes, on purpose.
    try testing.expectEqualStrings(
        "text/plain; name=\xe6\x97\xa5\xe6\x9c\xac",
        try cleaned(&buffer, "text/plain; name=\xe6\x97\xa5\xe6\x9c\xac"),
    );
    try testing.expectEqualStrings("", try cleaned(&buffer, ""));
}
