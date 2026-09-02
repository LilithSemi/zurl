//! RFC 4515, the string form of an LDAP search filter, and the BER it
//! becomes.
//!
//! **This file owns the escaping rule of this package.** A filter comes
//! out of a url, which is text a user or a redirect chose, and it reaches
//! the wire as a `Filter` of RFC 4511 section 4.5.1.7. `writeValue` states
//! the rule and enforces it, and it is the one function in this package
//! that turns filter text into an assertion value.
//!
//! ## The escaping rule, stated exactly
//!
//! > **Inside an assertion value, a byte is written either as itself or as
//! > a backslash and two hexadecimal digits. The five bytes NUL, `(`, `)`,
//! > `*`, and `\` may only be written escaped: a literal one is refused by
//! > name and never guessed at. A backslash that is not followed by two
//! > hexadecimal digits is refused. Every other byte, 0x01 through 0xff,
//! > is taken as itself. An escape produces exactly the one byte its two
//! > digits name. Nothing else is added and no byte is dropped.**
//!
//! That is RFC 4515 section 3, whose `UTF1SUBSET` production is `%x01-27 /
//! %x2B-5B / %x5D-7F`: it excludes exactly NUL, `(` 0x28, `)` 0x29, `*`
//! 0x2a, and `\` 0x5c, and the `escaped` production is `ESC HEX HEX`.
//!
//! ## Why the rule is enough
//!
//! Two directions, and both have to hold.
//!
//! **Nothing an escape produces can change the message.** BER writes an
//! octet string as a tag, a length, and then the bytes. There is no byte
//! that ends an octet string, so a decoded `\28` reaches the wire as one
//! `0x28` inside a counted string and is data there, the same as a letter.
//! `ber.Writer.writeElement` counts what it is given and writes that count
//! in front, so a value of any bytes at all costs one element.
//!
//! **Nothing a literal can do goes unrefused.** The risk is in the string
//! and not on the wire: a literal `(` or `)` inside a value would close
//! the item the parser is reading and open one the url wrote, so the
//! server would answer a different question. A literal `*` would turn an
//! equality match into a substring match. A literal NUL would end the
//! value for any reader that treats it as a terminator. Each of the four
//! is refused with its own name, so the parser never builds a tree that
//! the writer of the url chose and the reader of the url did not.
//!
//! The proof is in the tests below: `writeValue` is run over all 256 byte
//! values, escaped, and each one reaches the assertion value as itself and
//! as one filter node; and each of the five bytes written literally is
//! refused by name.
//!
//! ## What this file writes
//!
//! Every encoding here was read off curl 8.21.0 on the wire, through a
//! byte-logging relay to a real slapd 2.6.13. See the tests, which carry
//! the measured bytes.
//!
//! This file allocates nothing and does no I/O.

const std = @import("std");

const ber = @import("ber.zig");

/// How many bytes of filter text this reads.
///
/// 4096. A filter longer than this is not a filter a person wrote, and the
/// bound has to exist because the text comes out of a url and a url comes
/// from outside.
pub const max_filter_bytes: usize = 4096;

/// How deep an `and`, an `or`, or a `not` may nest.
///
/// **This is the bound on the one recursion in this package.** `writeItem`
/// calls itself for each arm of an `and`, an `or`, and a `not`, and a
/// filter of 100 000 opening parentheses would otherwise cost 100 000
/// frames. 16 is far past any filter a person writes and far below
/// anything that costs a stack. It is under `ber.max_depth`, so the BER
/// writer's own bound is never the one that trips first.
pub const max_depth: usize = 16;

/// How many bytes an attribute description may hold.
///
/// RFC 4512 section 2.5 writes one as a type and its options, and every
/// one in a published schema is well under this.
pub const max_attribute_bytes: usize = 256;

/// How many bytes one assertion value may hold, after the escapes are
/// decoded.
///
/// A bound on what one item of the filter sends, so a filter that fits
/// `max_filter_bytes` cannot still send one value larger than a server
/// will index.
pub const max_value_bytes: usize = 2048;

/// The context tag numbers RFC 4511 section 4.5.1.7 gives each arm of the
/// `Filter` choice.
pub const tag_and: u5 = 0;
pub const tag_or: u5 = 1;
pub const tag_not: u5 = 2;
pub const tag_equality: u5 = 3;
pub const tag_substrings: u5 = 4;
pub const tag_greater_or_equal: u5 = 5;
pub const tag_less_or_equal: u5 = 6;
pub const tag_present: u5 = 7;
pub const tag_approx: u5 = 8;
pub const tag_extensible: u5 = 9;

/// The context tag numbers a `SubstringFilter` gives each piece.
pub const tag_initial: u5 = 0;
pub const tag_any: u5 = 1;
pub const tag_final: u5 = 2;

/// The context tag numbers a `MatchingRuleAssertion` gives each field.
pub const tag_matching_rule: u5 = 1;
pub const tag_match_type: u5 = 2;
pub const tag_match_value: u5 = 3;
pub const tag_dn_attributes: u5 = 4;

/// Every fault reading a filter can report.
///
/// Each is its own name so a diagnostic can say which rule the filter
/// broke. A user who typed a filter needs to know which character was
/// wrong, not that "the filter is bad".
pub const ParseError = error{
    /// The text does not start with `(`, or an item does not end with `)`.
    Unbalanced,
    /// The text ran out in the middle of an item.
    Truncated,
    /// There is text after the closing parenthesis of the whole filter.
    TrailingText,
    /// An `and`, an `or`, or a `not` nests deeper than `max_depth`.
    NestingTooDeep,
    /// A `not` holds no filter, or more than one.
    NotNeedsOneFilter,
    /// The text is longer than `max_filter_bytes`.
    FilterTooLong,
    /// The attribute description is empty, longer than
    /// `max_attribute_bytes`, or holds a byte RFC 4512 section 2.5 gives
    /// no attribute description.
    BadAttribute,
    /// An item names no filter type at all: there is no `=` in it.
    MissingFilterType,
    /// **A literal `(` or `)` inside an assertion value.** RFC 4515
    /// section 3 writes each as `\28` and `\29`, and a literal one would
    /// close the item the parser is reading and open one the url chose.
    UnescapedParen,
    /// **A literal `*` inside an assertion value that is not a substring
    /// separator.** RFC 4515 writes it as `\2a`, and a literal one turns
    /// an equality match into a substring match.
    UnescapedAsterisk,
    /// **A literal NUL inside an assertion value.** RFC 4515 writes it as
    /// `\00`.
    UnescapedNul,
    /// A backslash that is not followed by two hexadecimal digits.
    BadEscape,
    /// One assertion value is longer than `max_value_bytes` once its
    /// escapes are decoded.
    ValueTooLong,
    /// A substring filter whose every piece is empty, so it asserts
    /// nothing. RFC 4511 gives `SubstringFilter` a size of at least one.
    EmptySubstring,
    /// An extensible match names no matching rule and no attribute, so
    /// there is nothing for the server to match against.
    BadExtensibleMatch,
};

/// The bytes a filter text may not carry at all.
///
/// A control byte in a filter is not a filter a person typed, and it
/// reaches a diagnostic and an attribute description if it is let through.
/// `zurl_core.url` already refuses a C0 byte and a DEL in a query, so this
/// is the second gate and not the first.
pub fn hasControlByte(text: []const u8) bool {
    for (text) |b| {
        if (b < 0x20 or b == 0x7f) return true;
    }
    return false;
}

/// Whether `b` may appear in an attribute description or in a matching
/// rule identifier.
///
/// RFC 4512 section 2.5 writes an attribute description as an attribute
/// type and its options: the type is a `descr`, which is a letter followed
/// by letters, digits, and hyphens, or a `numericoid`, which is digits and
/// dots; and each option follows a `;` and is a `keystring`. So the whole
/// set is exactly the letters, the digits, `-`, `.`, and `;`.
///
/// **This is the one definition of the rule, and it runs in both
/// directions.** Three callers read it and there is no second copy:
///
/// - `checkAttribute` below, for an attribute description in a filter
///   this build sends;
/// - `target.parseAttributes`, for the `?attributes?` list of a url;
/// - `ldif.checkAttribute`, for an attribute description a **server**
///   sent, on its way into the answer.
///
/// The third one is the one that matters most and it was missing from the
/// first draft of this package. `ldif.zig` bounded and sanitised the DN
/// and every value and wrote the attribute description raw, so a server
/// that answered with an attribute named `cn: real\nDN: cn=forged` drew a
/// whole entry the directory does not hold. The DN arm and the value arm
/// were hardened and tested and the attribute arm had neither. One rule
/// read from three places is what keeps the next direction from being the
/// one that is forgotten.
///
/// **It refuses rather than passes through.** libldap sends and prints
/// whatever text it was given, in both directions. No published schema
/// names an attribute outside this set, so refusing costs nothing real,
/// and the set is far narrower than "printable", which closes an escape
/// sequence into a terminal as well as a forged line.
pub fn isAttributeByte(b: u8) bool {
    return std.ascii.isAlphanumeric(b) or b == '-' or b == '.' or b == ';';
}

/// Writes the BER of the filter `text` names into `w`.
///
/// `w` is a `ber.Writer` of any capacity. Its own `error.NoRoom` and
/// `error.TooDeep` come back unchanged, so a filter that parses and does
/// not fit is told apart from one that does not parse.
///
/// **The whole text must be one filter.** `(a=1)(b=2)` is
/// `error.TrailingText` and never two filters joined by something this
/// function invented.
pub fn write(w: anytype, text: []const u8) (ParseError || @TypeOf(w.*).Error)!void {
    if (text.len > max_filter_bytes) return error.FilterTooLong;
    var at: usize = 0;
    try writeFilter(w, text, &at, 0);
    if (at != text.len) return error.TrailingText;
}

/// Writes one `(...)` filter starting at `at.*`, and moves `at.*` past its
/// closing parenthesis.
///
/// `depth` is how many `and`, `or`, and `not` containers this is inside.
/// See `max_depth`.
fn writeFilter(
    w: anytype,
    text: []const u8,
    at: *usize,
    depth: usize,
) (ParseError || @TypeOf(w.*).Error)!void {
    if (depth > max_depth) return error.NestingTooDeep;
    if (at.* >= text.len) return error.Truncated;
    if (text[at.*] != '(') return error.Unbalanced;
    at.* += 1;
    if (at.* >= text.len) return error.Truncated;

    switch (text[at.*]) {
        '&' => {
            at.* += 1;
            try writeList(w, text, at, depth, tag_and);
        },
        '|' => {
            at.* += 1;
            try writeList(w, text, at, depth, tag_or);
        },
        '!' => {
            at.* += 1;
            try w.beginElement(.context(tag_not, true));
            // **A `not` holds exactly one filter.** RFC 4515 section 3
            // writes `not = EXCLAMATION filter`, one and not a list. A
            // build that read a list here would send a `[2]` holding two
            // filters, which is not a `Filter` at all.
            if (at.* < text.len and text[at.*] == ')') return error.NotNeedsOneFilter;
            try writeFilter(w, text, at, depth + 1);
            if (at.* >= text.len or text[at.*] != ')') return error.NotNeedsOneFilter;
            try w.endElement();
            at.* += 1;
        },
        else => try writeItem(w, text, at),
    }
}

/// Writes an `and` or an `or`, and every filter inside it.
fn writeList(
    w: anytype,
    text: []const u8,
    at: *usize,
    depth: usize,
    tag: u5,
) (ParseError || @TypeOf(w.*).Error)!void {
    try w.beginElement(.context(tag, true));
    // **An empty list is written and not refused.** RFC 4526 gives `(&)`
    // the meaning "absolute true" and `(|)` the meaning "absolute false",
    // and curl 8.21.0 sends `a0 00` and `a1 00` for them, measured on the
    // wire.
    while (true) {
        if (at.* >= text.len) return error.Truncated;
        if (text[at.*] == ')') break;
        try writeFilter(w, text, at, depth + 1);
    }
    try w.endElement();
    at.* += 1;
}

/// Writes one `item`: a simple match, a present test, a substring match,
/// or an extensible match.
///
/// `at.*` points at the first byte after the opening parenthesis, and this
/// moves it past the closing one.
fn writeItem(
    w: anytype,
    text: []const u8,
    at: *usize,
) (ParseError || @TypeOf(w.*).Error)!void {
    // The item runs to the first `)` that is not inside an escape. An
    // escape is a backslash and two hexadecimal digits, and none of the
    // three is a `)`, so the first `)` from here ends the item.
    const close = std.mem.indexOfScalarPos(u8, text, at.*, ')') orelse return error.Truncated;
    const body = text[at.*..close];
    defer at.* = close + 1;

    const equals = std.mem.indexOfScalar(u8, body, '=') orelse return error.MissingFilterType;

    // **A colon in front of the first `=` is what names an extensible
    // match**, and only there. RFC 4515 section 3 puts a `:` in an
    // assertion value's own character set, so `(cn=a:b)` is an equality
    // match on the value `a:b` and never a match against the rule `b`. A
    // build that looked for a colon anywhere in the item would read that
    // url as a different question than the user asked.
    if (std.mem.indexOfScalar(u8, body[0..equals], ':') != null) {
        return writeExtensible(w, body);
    }
    if (equals == 0) return error.BadAttribute;

    // The byte before the `=` chooses the filter type. RFC 4515 section 3:
    // `~=` is approximate, `>=` is greater or equal, `<=` is less or
    // equal, and a bare `=` is equality or one of the two forms below it.
    const marker = body[equals - 1];
    const attribute_end = if (marker == '~' or marker == '>' or marker == '<') equals - 1 else equals;
    const attribute = body[0..attribute_end];
    const value = body[equals + 1 ..];
    try checkAttribute(attribute);

    switch (marker) {
        '~' => return writeAssertion(w, tag_approx, attribute, value),
        '>' => return writeAssertion(w, tag_greater_or_equal, attribute, value),
        '<' => return writeAssertion(w, tag_less_or_equal, attribute, value),
        else => {},
    }

    // **A `*` decides between three encodings**, and it is the one place a
    // literal `*` means anything. `(cn=*)` is a present test, `(cn=a*b)` is
    // a substring match, and anything else is an equality match.
    if (std.mem.indexOfScalar(u8, value, '*') == null) {
        return writeAssertion(w, tag_equality, attribute, value);
    }
    if (value.len == 1) {
        // `present` is `[7]` primitive holding the attribute description,
        // measured: `(objectClass=*)` goes out as `87 0b "objectClass"`.
        return w.writeElement(.context(tag_present, false), attribute);
    }
    return writeSubstrings(w, attribute, value);
}

/// Writes a `[3]`, `[5]`, `[6]`, or `[8]` `AttributeValueAssertion`.
///
/// The context tag replaces the `SEQUENCE` tag, which is what implicit
/// tagging means and what the wire shows: `(cn=a)` goes out as
/// `a3 07 04 02 "cn" 04 01 "a"` and never with a `30` inside the `a3`.
fn writeAssertion(
    w: anytype,
    tag: u5,
    attribute: []const u8,
    value: []const u8,
) (ParseError || @TypeOf(w.*).Error)!void {
    try w.beginElement(.context(tag, true));
    try w.writeElement(ber.octet_string, attribute);
    try writeValue(w, ber.octet_string, value);
    try w.endElement();
}

/// Writes a `[4]` `SubstringFilter`.
///
/// The value is split on every literal `*`. The first piece, when it is
/// not empty, is the `initial`; the last, when it is not empty, is the
/// `final`; and every piece between them that is not empty is an `any`.
/// An empty piece is dropped, which is what two `*` in a row mean.
///
/// Measured: `(cn=*a*b*c*)` goes out as
/// `a4 0f 04 02 "cn" 30 09 81 01 "a" 81 01 "b" 81 01 "c"`, and
/// `(cn=x*)` as `a4 09 04 02 "cn" 30 03 80 01 "x"`.
fn writeSubstrings(
    w: anytype,
    attribute: []const u8,
    value: []const u8,
) (ParseError || @TypeOf(w.*).Error)!void {
    // A value that is all separators asserts nothing at all, and RFC 4511
    // gives `SubstringFilter` a size of at least one.
    var written: usize = 0;
    var count: usize = 0;
    var counter = std.mem.splitScalar(u8, value, '*');
    while (counter.next()) |piece| {
        if (piece.len != 0) written += 1;
        count += 1;
    }
    if (written == 0) return error.EmptySubstring;

    try w.beginElement(.context(tag_substrings, true));
    try w.writeElement(ber.octet_string, attribute);
    try w.beginElement(ber.sequence);

    var it = std.mem.splitScalar(u8, value, '*');
    var index: usize = 0;
    while (it.next()) |piece| : (index += 1) {
        if (piece.len == 0) continue;
        const tag: u5 = if (index == 0)
            tag_initial
        else if (index == count - 1)
            tag_final
        else
            tag_any;
        try writeValue(w, .context(tag, false), piece);
    }

    try w.endElement();
    try w.endElement();
}

/// Writes a `[9]` `MatchingRuleAssertion`.
///
/// RFC 4515 section 3 writes it as `attr [:dn] [:rule] := value` or
/// `[:dn] :rule := value`, and RFC 4511 section 4.5.1.7 gives the fields
/// the tags `[1]` matchingRule, `[2]` type, `[3]` matchValue, and `[4]`
/// dnAttributes.
///
/// Measured: `(cn:caseIgnoreMatch:=x)` goes out as
/// `a9 18 81 0f "caseIgnoreMatch" 82 02 "cn" 83 01 "x"`, and
/// `(cn:dn:2.4.6.8:=z)` adds `84 01 ff` on the end.
fn writeExtensible(
    w: anytype,
    body: []const u8,
) (ParseError || @TypeOf(w.*).Error)!void {
    // The value starts after the one `:=`. Everything in front of it is
    // the attribute, the `dn` marker, and the matching rule, in that
    // order and each optional.
    const mark = std.mem.indexOf(u8, body, ":=") orelse return error.MissingFilterType;
    const head = body[0..mark];
    const value = body[mark + 2 ..];

    var attribute: []const u8 = "";
    var rule: []const u8 = "";
    var dn_attributes = false;

    var it = std.mem.splitScalar(u8, head, ':');
    // The first piece is the attribute description, and it may be empty.
    attribute = it.first();
    while (it.next()) |piece| {
        if (std.ascii.eqlIgnoreCase(piece, "dn")) {
            dn_attributes = true;
            continue;
        }
        // Only one matching rule may be named. A second is a filter
        // nobody meant.
        if (rule.len != 0) return error.BadExtensibleMatch;
        if (piece.len == 0) return error.BadExtensibleMatch;
        rule = piece;
    }

    // **A match against nothing is refused.** With no rule and no
    // attribute the server has neither a rule to apply nor a value to
    // apply it to, so the assertion cannot mean anything.
    if (attribute.len == 0 and rule.len == 0) return error.BadExtensibleMatch;
    if (attribute.len != 0) try checkAttribute(attribute);
    if (rule.len != 0) try checkAttribute(rule);

    try w.beginElement(.context(tag_extensible, true));
    if (rule.len != 0) try w.writeElement(.context(tag_matching_rule, false), rule);
    if (attribute.len != 0) try w.writeElement(.context(tag_match_type, false), attribute);
    try writeValue(w, .context(tag_match_value, false), value);
    // `DEFAULT FALSE`, so a false one is left out. curl leaves it out too,
    // measured: `(cn:caseIgnoreMatch:=x)` carries no `[4]` at all.
    if (dn_attributes) try w.writeBoolean(.context(tag_dn_attributes, false), true);
    try w.endElement();
}

/// Refuses an attribute description that RFC 4512 section 2.5 does not
/// name.
fn checkAttribute(attribute: []const u8) ParseError!void {
    if (attribute.len == 0) return error.BadAttribute;
    if (attribute.len > max_attribute_bytes) return error.BadAttribute;
    for (attribute) |b| {
        if (!isAttributeByte(b)) return error.BadAttribute;
    }
}

/// Writes one assertion value, with `text`'s escapes decoded.
///
/// **This is the one function in this package that turns filter text into
/// an assertion value, and it holds the escaping rule.** The module doc
/// comment states the rule; this is where it runs.
///
/// The decode happens into a stack buffer of `max_value_bytes` and never
/// into an allocation, so a value larger than the bound is refused before
/// any memory is asked for.
fn writeValue(
    w: anytype,
    tag: ber.Tag,
    text: []const u8,
) (ParseError || @TypeOf(w.*).Error)!void {
    var out: [max_value_bytes]u8 = undefined;
    const decoded = try decodeValue(&out, text);
    return w.writeElement(tag, decoded);
}

/// Decodes the escapes of `text` into `out`, and returns what was written.
///
/// Exported for the tests, which run it over every byte value. See
/// `writeValue`.
pub fn decodeValue(out: []u8, text: []const u8) ParseError![]u8 {
    var at: usize = 0;
    var written: usize = 0;
    while (at < text.len) {
        const b = text[at];
        switch (b) {
            // The five bytes the rule says may only appear escaped. Each
            // gets its own name, because a user who typed one needs to
            // know which one and how to write it.
            0x00 => return error.UnescapedNul,
            '(', ')' => return error.UnescapedParen,
            '*' => return error.UnescapedAsterisk,
            '\\' => {
                if (at + 2 >= text.len) return error.BadEscape;
                const hi = std.fmt.charToDigit(text[at + 1], 16) catch return error.BadEscape;
                const lo = std.fmt.charToDigit(text[at + 2], 16) catch return error.BadEscape;
                if (written == out.len) return error.ValueTooLong;
                out[written] = (@as(u8, hi) << 4) | lo;
                written += 1;
                at += 3;
            },
            else => {
                if (written == out.len) return error.ValueTooLong;
                out[written] = b;
                written += 1;
                at += 1;
            },
        }
    }
    return out[0..written];
}

const testing = std.testing;

/// A writer large enough for every filter in these tests.
const TestWriter = ber.Writer(8192, 24);

/// The bytes `text` becomes.
fn encode(w: *TestWriter, text: []const u8) ![]const u8 {
    w.reset();
    try write(w, text);
    try testing.expect(w.balanced());
    return w.written();
}

test "the escape of every byte value reaches the assertion value as itself" {
    // **The proof of the escaping rule, first direction.** For all 256
    // byte values, `\XX` decodes to exactly that byte, and that byte
    // reaches the BER assertion value with nothing added and nothing
    // dropped.
    var w: TestWriter = .init();
    var value: usize = 0;
    while (value < 256) : (value += 1) {
        const byte: u8 = @intCast(value);
        var text: [10]u8 = undefined;
        const filter = try std.fmt.bufPrint(&text, "(cn=A\\{x:0>2}B)", .{byte});

        const out = try encode(&w, filter);
        var c: ber.Cursor = .init(out);
        const item = try c.expect(.context(tag_equality, true));
        try testing.expect(c.atEnd());

        var fields = try c.enter(item);
        try testing.expectEqualStrings("cn", (try fields.expect(ber.octet_string)).content);
        const assertion = try fields.expect(ber.octet_string);
        try testing.expect(fields.atEnd());
        try testing.expectEqualSlices(u8, &.{ 'A', byte, 'B' }, assertion.content);
    }
}

test "an escaped byte never adds or removes a filter node" {
    // **The proof of the escaping rule, second direction.** Whatever bytes
    // a value holds, the filter is exactly one node. A byte that could
    // change the tree would show up here as a second node or a missing
    // one.
    var w: TestWriter = .init();
    var value: usize = 0;
    while (value < 256) : (value += 1) {
        var text: [9]u8 = undefined;
        const filter = try std.fmt.bufPrint(&text, "(cn=\\{x:0>2})", .{@as(u8, @intCast(value))});
        const out = try encode(&w, filter);

        var c: ber.Cursor = .init(out);
        var nodes: usize = 0;
        while (!c.atEnd()) : (nodes += 1) _ = try c.next();
        try testing.expectEqual(@as(usize, 1), nodes);
    }
}

test "a literal parenthesis, asterisk, or NUL in a value is refused by name" {
    // These are the four bytes that would change the tree the parser
    // builds, so each is refused and never guessed at.
    var out: [16]u8 = undefined;
    try testing.expectError(error.UnescapedNul, decodeValue(&out, &.{ 'a', 0x00, 'b' }));
    try testing.expectError(error.UnescapedParen, decodeValue(&out, "a(b"));
    try testing.expectError(error.UnescapedParen, decodeValue(&out, "a)b"));
    try testing.expectError(error.UnescapedAsterisk, decodeValue(&out, "a*b"));

    // The same four through a whole filter. An opening parenthesis inside
    // a value reaches `decodeValue` and is refused there.
    var w: TestWriter = .init();
    try testing.expectError(error.UnescapedParen, encode(&w, "(cn=a(b)"));
    // A literal `)` ends the item instead, so the text after it is text
    // no filter names. The refusal is still a refusal, and no second
    // filter is invented for it.
    try testing.expectError(error.TrailingText, encode(&w, "(cn=a)b)"));
    // The escaped spellings of the same four bytes all pass, and each
    // reaches the wire as one byte.
    _ = try encode(&w, "(cn=a\\28b)");
    _ = try encode(&w, "(cn=a\\29b)");
    _ = try encode(&w, "(cn=a\\2ab)");
    _ = try encode(&w, "(cn=a\\5cb)");
    _ = try encode(&w, "(cn=a\\00b)");
}

test "a backslash that is not two hexadecimal digits is refused" {
    var out: [16]u8 = undefined;
    try testing.expectError(error.BadEscape, decodeValue(&out, "\\"));
    try testing.expectError(error.BadEscape, decodeValue(&out, "\\2"));
    try testing.expectError(error.BadEscape, decodeValue(&out, "\\zz"));
    try testing.expectError(error.BadEscape, decodeValue(&out, "\\2z"));
    try testing.expectError(error.BadEscape, decodeValue(&out, "\\\\"));
    // Upper case digits are digits. RFC 4515 writes `HEX` as either case.
    try testing.expectEqualSlices(u8, &.{0x2a}, try decodeValue(&out, "\\2A"));
    try testing.expectEqualSlices(u8, &.{0x2a}, try decodeValue(&out, "\\2a"));
}

test "a value longer than max_value_bytes is refused before any memory is asked for" {
    var out: [max_value_bytes]u8 = undefined;
    const long = "x" ** (max_value_bytes + 1);
    try testing.expectError(error.ValueTooLong, decodeValue(&out, long));
    // Exactly the bound fits.
    const at_bound = "x" ** max_value_bytes;
    try testing.expectEqual(@as(usize, max_value_bytes), (try decodeValue(&out, at_bound)).len);
}

test "the filters curl sends reach the wire byte for byte" {
    // Every row was read off curl 8.21.0 through a byte-logging relay to
    // a real slapd 2.6.13. The bytes here are the filter alone, cut out
    // of the SearchRequest.
    const Case = struct { text: []const u8, want: []const u8 };
    const cases = [_]Case{
        .{ .text = "(objectClass=*)", .want = &([_]u8{ 0x87, 0x0b } ++ "objectClass".*) },
        .{ .text = "(cn=a)", .want = &.{ 0xa3, 0x07, 0x04, 0x02, 'c', 'n', 0x04, 0x01, 'a' } },
        .{ .text = "(cn>=a)", .want = &.{ 0xa5, 0x07, 0x04, 0x02, 'c', 'n', 0x04, 0x01, 'a' } },
        .{ .text = "(cn<=z)", .want = &.{ 0xa6, 0x07, 0x04, 0x02, 'c', 'n', 0x04, 0x01, 'z' } },
        .{
            .text = "(cn~=Ross)",
            .want = &([_]u8{ 0xa8, 0x0a, 0x04, 0x02, 'c', 'n', 0x04, 0x04 } ++ "Ross".*),
        },
        .{ .text = "(cn=)", .want = &.{ 0xa3, 0x06, 0x04, 0x02, 'c', 'n', 0x04, 0x00 } },
        .{
            .text = "(cn=*a*b*c*)",
            .want = &.{
                0xa4, 0x0f, 0x04, 0x02, 'c',  'n', 0x30, 0x09,
                0x81, 0x01, 'a',  0x81, 0x01, 'b', 0x81, 0x01,
                'c',
            },
        },
        .{
            .text = "(cn=x*)",
            .want = &.{ 0xa4, 0x09, 0x04, 0x02, 'c', 'n', 0x30, 0x03, 0x80, 0x01, 'x' },
        },
        .{
            .text = "(cn=*x)",
            .want = &.{ 0xa4, 0x09, 0x04, 0x02, 'c', 'n', 0x30, 0x03, 0x82, 0x01, 'x' },
        },
        .{
            .text = "(cn=a\\2ab)",
            .want = &.{ 0xa3, 0x09, 0x04, 0x02, 'c', 'n', 0x04, 0x03, 'a', 0x2a, 'b' },
        },
        .{
            .text = "(cn=a\\28b\\29c)",
            .want = &.{ 0xa3, 0x0b, 0x04, 0x02, 'c', 'n', 0x04, 0x05, 'a', 0x28, 'b', 0x29, 'c' },
        },
        .{
            .text = "(cn=\\c3\\a9)",
            .want = &.{ 0xa3, 0x08, 0x04, 0x02, 'c', 'n', 0x04, 0x02, 0xc3, 0xa9 },
        },
        .{
            .text = "(!(cn=a))",
            .want = &.{ 0xa2, 0x09, 0xa3, 0x07, 0x04, 0x02, 'c', 'n', 0x04, 0x01, 'a' },
        },
        // RFC 4526: an empty `and` is absolute true and an empty `or` is
        // absolute false. curl sends both, measured.
        .{ .text = "(&)", .want = &.{ 0xa0, 0x00 } },
        .{ .text = "(|)", .want = &.{ 0xa1, 0x00 } },
        .{
            .text = "(cn:caseIgnoreMatch:=x)",
            .want = &([_]u8{ 0xa9, 0x18, 0x81, 0x0f } ++ "caseIgnoreMatch".* ++
                [_]u8{ 0x82, 0x02, 'c', 'n', 0x83, 0x01, 'x' }),
        },
        .{
            .text = "(:caseExactMatch:=y)",
            .want = &([_]u8{ 0xa9, 0x13, 0x81, 0x0e } ++ "caseExactMatch".* ++
                [_]u8{ 0x83, 0x01, 'y' }),
        },
        .{
            .text = "(cn:dn:2.4.6.8:=z)",
            .want = &([_]u8{ 0xa9, 0x13, 0x81, 0x07 } ++ "2.4.6.8".* ++
                [_]u8{ 0x82, 0x02, 'c', 'n', 0x83, 0x01, 'z', 0x84, 0x01, 0xff }),
        },
    };

    var w: TestWriter = .init();
    for (cases) |case| {
        const out = try encode(&w, case.text);
        try testing.expectEqualSlices(u8, case.want, out);
    }
}

test "the nested filter curl sends reaches the wire byte for byte" {
    // `(&(objectClass=inetOrgPerson)(|(cn=Ross*)(!(sn=Entry))))`, read off
    // curl 8.21.0 on the wire.
    var w: TestWriter = .init();
    const out = try encode(&w, "(&(objectClass=inetOrgPerson)(|(cn=Ross*)(!(sn=Entry))))");
    const want = [_]u8{ 0xa0, 0x3d, 0xa3, 0x1c, 0x04, 0x0b } ++ "objectClass".* ++
        [_]u8{ 0x04, 0x0d } ++ "inetOrgPerson".* ++
        [_]u8{ 0xa1, 0x1d, 0xa4, 0x0c, 0x04, 0x02, 'c', 'n', 0x30, 0x06, 0x80, 0x04 } ++ "Ross".* ++
        [_]u8{ 0xa2, 0x0d, 0xa3, 0x0b, 0x04, 0x02, 's', 'n', 0x04, 0x05 } ++ "Entry".*;
    try testing.expectEqualSlices(u8, &want, out);
}

test "a filter nested past max_depth is refused, and one under it is not" {
    var w: TestWriter = .init();

    var deep: [4 * (max_depth + 4)]u8 = undefined;
    // `max_depth` nested `not` containers around one item is under the
    // bound, because the item itself opens none.
    var at: usize = 0;
    for (0..max_depth) |_| {
        @memcpy(deep[at..][0..2], "(!");
        at += 2;
    }
    @memcpy(deep[at..][0..6], "(cn=a)");
    at += 6;
    for (0..max_depth) |_| {
        deep[at] = ')';
        at += 1;
    }
    _ = try encode(&w, deep[0..at]);

    // One more is past it.
    at = 0;
    for (0..max_depth + 1) |_| {
        @memcpy(deep[at..][0..2], "(!");
        at += 2;
    }
    @memcpy(deep[at..][0..6], "(cn=a)");
    at += 6;
    for (0..max_depth + 1) |_| {
        deep[at] = ')';
        at += 1;
    }
    try testing.expectError(error.NestingTooDeep, encode(&w, deep[0..at]));
}

test "an unbalanced or trailing filter is refused" {
    var w: TestWriter = .init();
    try testing.expectError(error.Unbalanced, encode(&w, "cn=a"));
    try testing.expectError(error.Truncated, encode(&w, "(cn=a"));
    try testing.expectError(error.Truncated, encode(&w, "("));
    try testing.expectError(error.Truncated, encode(&w, "(&"));
    try testing.expectError(error.Truncated, encode(&w, "(&(cn=a)"));
    try testing.expectError(error.TrailingText, encode(&w, "(cn=a)(sn=b)"));
    try testing.expectError(error.TrailingText, encode(&w, "(cn=a) "));
    try testing.expectError(error.FilterTooLong, encode(&w, "x" ** (max_filter_bytes + 1)));
}

test "a not that holds no filter, or two, is refused" {
    var w: TestWriter = .init();
    try testing.expectError(error.NotNeedsOneFilter, encode(&w, "(!)"));
    try testing.expectError(error.NotNeedsOneFilter, encode(&w, "(!(cn=a)(sn=b))"));
}

test "an attribute description holding a byte RFC 4512 does not name is refused" {
    var w: TestWriter = .init();
    // libldap sends whatever the url held, so a build that passed these
    // through would put a byte of the url's choosing into the attribute
    // description on the wire.
    try testing.expectError(error.BadAttribute, encode(&w, "(c n=a)"));
    try testing.expectError(error.BadAttribute, encode(&w, "(c\\28n=a)"));
    try testing.expectError(error.BadAttribute, encode(&w, "(c+n=a)"));
    try testing.expectError(error.BadAttribute, encode(&w, "(=a)"));
    try testing.expectError(error.BadAttribute, encode(&w, "(" ++ "a" ** 300 ++ "=b)"));
    // The bytes RFC 4512 section 2.5 does name all pass.
    _ = try encode(&w, "(cn;lang-en=a)");
    _ = try encode(&w, "(2.5.4.3=a)");
    _ = try encode(&w, "(user-name=a)");
}

test "an item with no filter type at all is refused" {
    var w: TestWriter = .init();
    try testing.expectError(error.MissingFilterType, encode(&w, "(cn)"));
    try testing.expectError(error.MissingFilterType, encode(&w, "(cn:dn)"));
}

test "a substring that asserts nothing is refused" {
    var w: TestWriter = .init();
    try testing.expectError(error.EmptySubstring, encode(&w, "(cn=**)"));
    try testing.expectError(error.EmptySubstring, encode(&w, "(cn=***)"));
    // One star alone is a present test and not a substring, so it is not
    // this refusal.
    const present = try encode(&w, "(cn=*)");
    try testing.expectEqual(@as(u8, 0x87), present[0]);
}

test "an extensible match with neither a rule nor an attribute is refused" {
    var w: TestWriter = .init();
    try testing.expectError(error.BadExtensibleMatch, encode(&w, "(:=x)"));
    try testing.expectError(error.BadExtensibleMatch, encode(&w, "(:dn:=x)"));
    try testing.expectError(error.BadExtensibleMatch, encode(&w, "(cn:a:b:=x)"));
    try testing.expectError(error.BadExtensibleMatch, encode(&w, "(cn::=x)"));
}

test "a filter holding a control byte is caught before it is parsed" {
    try testing.expect(hasControlByte("(cn=a\rb)"));
    try testing.expect(hasControlByte("(cn=a\nb)"));
    try testing.expect(hasControlByte(&.{ '(', 'c', 'n', '=', 0x00, ')' }));
    try testing.expect(hasControlByte(&.{ '(', 'c', 'n', '=', 0x7f, ')' }));
    try testing.expect(!hasControlByte("(cn=a b)"));
    try testing.expect(!hasControlByte("(cn=\\0a)"));
}

test "a filter that parses and does not fit reports no room and never a wrong message" {
    // The two faults are told apart: a filter that does not parse is a
    // `ParseError`, and one that parses and overruns the writer is the
    // writer's own `error.NoRoom`.
    var small: ber.Writer(32, 8) = .init();
    try testing.expectError(error.NoRoom, write(&small, "(cn=" ++ "x" ** 64 ++ ")"));
}

test "the substring pieces take the tag their position gives them" {
    var w: TestWriter = .init();
    // `a*b*c` is initial, any, final.
    const out = try encode(&w, "(cn=a*b*c)");
    const want = [_]u8{
        0xa4, 0x0f, 0x04, 0x02, 'c',  'n', 0x30, 0x09,
        0x80, 0x01, 'a',  0x81, 0x01, 'b', 0x82, 0x01,
        'c',
    };
    try testing.expectEqualSlices(u8, &want, out);
}

test "an escaped asterisk in a substring piece stays inside that piece" {
    // The split runs on literal separators only, so `\2a` is a byte of a
    // piece and never a separator. Without that rule a user could not
    // search for a value holding a star at all.
    var w: TestWriter = .init();
    const out = try encode(&w, "(cn=a\\2ab*c)");
    const want = [_]u8{
        0xa4, 0x0e, 0x04, 0x02, 'c', 'n',  0x30, 0x08,
        0x80, 0x03, 'a',  0x2a, 'b', 0x82, 0x01, 'c',
    };
    try testing.expectEqualSlices(u8, &want, out);
}

test "a colon inside an assertion value stays a value byte" {
    // `(cn=a:b)` asks for the value `a:b`. A build that read any colon as
    // an extensible match would send the server a different question.
    var w: TestWriter = .init();
    const out = try encode(&w, "(cn=a:b)");
    const want = [_]u8{ 0xa3, 0x09, 0x04, 0x02, 'c', 'n', 0x04, 0x03, 'a', ':', 'b' };
    try testing.expectEqualSlices(u8, &want, out);
}
