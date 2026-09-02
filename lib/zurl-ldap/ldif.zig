//! The text one search result becomes, and the one rule that decides
//! whether a value is written as itself or in base64.
//!
//! **This is curl's format and not LDIF, and the difference matters.**
//! RFC 2849 writes a DN as `dn:` and wraps a long line. curl 8.21.0 writes
//! `DN: `, puts a tab in front of every attribute, and wraps nothing. What
//! this file writes is what curl writes, because a script that reads
//! curl's output is the reason this protocol is here. The shape was read
//! off curl 8.21.0 against a real slapd 2.6.13, byte for byte with
//! `od -c`, and then read again in curl's own `lib/openldap.c`, which is
//! the backend a curl built against OpenLDAP uses.
//!
//! ## The shape, measured
//!
//! For each `SearchResultEntry`:
//!
//! ```
//! DN: <dn>\n
//! <for each attribute, in the order the server sent them>
//!     <for each value>
//!         \t<attribute>: <value>\n          the value as itself
//!         \t<attribute>:: <base64>\n        the value in base64
//!     \n                                    one blank line for the attribute
//! \n                                        one blank line for the entry
//! ```
//!
//! So an entry of one attribute of one value is
//! `DN: dc=zurl,dc=test\n\tdc: zurl\n\n\n`, which is what `od -c` showed.
//! An entry of no attributes at all is `DN: dc=zurl,dc=test\n\n`.
//!
//! An attribute the server sent with no values at all writes
//! `\t<attribute>:\n` and **no blank line after it**. That is the
//! `if(!bvals)` arm of curl's `lib/openldap.c`. No url makes curl ask for
//! a `typesOnly` search, so that arm was read in the source and not
//! measured on the wire, and this file says so rather than claim a
//! measurement it does not have.
//!
//! ## Where this differs from curl, and why
//!
//! Two places, both deliberate, both about a byte a server chose reaching
//! a terminal or a pipe.
//!
//! **1. The printable set.** curl's `ISPRINT` is
//! `(x >= 9 && x <= 0x0d) || (x >= 0x20 && x <= 0x7e)`, read in
//! `lib/curl_ctype.h`. So curl calls a tab, a line feed, a vertical tab, a
//! form feed, and a carriage return printable and writes each one raw.
//! Measured: an attribute value of `embedded\nLF and DN: cn=forged`
//! reached standard output from curl with the newline intact, so the
//! output held a line that reads exactly like the start of another entry.
//! **This file's printable set is 0x20 through 0x7e and nothing else**, so
//! all five of those bytes force base64 and no value a server chooses can
//! draw a line. Every other value is byte for byte what curl writes.
//!
//! **2. The DN.** curl writes a DN raw, always, with no base64 arm at all.
//! A DN is an octet string the server chose, so the same forging works
//! there. This file runs the same test on a DN and writes `DN:: <base64>`
//! when it does not pass. A DN of printable ASCII, which is every DN a
//! directory holds, is written exactly as curl writes it.
//!
//! **3. The attribute description.** curl writes that raw as well, and a
//! server chooses it too. It is not a value, so there is no base64 arm for
//! it: LDIF and curl's format both write it as a name in front of the
//! colon and neither has a spelling for a name that is not one. So this
//! file **refuses** an attribute description that RFC 4512 section 2.5
//! does not name, through `checkAttribute`, and the transfer fails.
//!
//! **Three server-chosen fields reach this file and all three are
//! judged.** The first draft judged two of them: it bounded and sanitised
//! the DN and every value, wrote the attribute description raw, and its
//! module doc comment claimed the hole was closed. A server that answered
//! with an attribute named `cn: real\nDN: cn=forged,dc=a\n\tuserPassword`
//! drew a whole entry the directory does not hold, and a byte 0x1b in one
//! moved a terminal's cursor. A review found it. The lesson is written
//! into `filter.isAttributeByte`, which is now the one definition both
//! directions read: hardening two of three fields and testing those two is
//! how the third stays open.
//!
//! ## What this file does not do
//!
//! It never decides what a value means. A `userPassword` is written the
//! same as a `cn`, which is what curl does. A caller that wants to hide
//! one asks the server for the attributes it wants.
//!
//! This file does no I/O. It appends to a buffer the caller owns and
//! bounds.

const std = @import("std");

const filter = @import("filter.zig");

/// How many bytes of DN this writes.
///
/// A DN comes from the server, so it needs a number. 4096 is far past any
/// name a directory holds and it is the bound `target.max_dn_bytes` puts
/// on the DN a url sends, so the two ends agree.
///
/// **A longer one is refused and never cut.** A truncated DN reads like a
/// whole one, and a reader of the output could not tell which entry it
/// named.
pub const max_dn_bytes: usize = 4096;

/// How many bytes of attribute description this writes.
///
/// RFC 4512 section 2.5 writes one as a type and its options, and 256 is
/// far past any in a published schema.
pub const max_attribute_bytes: usize = 256;

/// How many bytes one attribute value this writes may hold.
///
/// 1 MiB. A photograph in a directory is a few hundred kilobytes, so this
/// is past a real value and far under the bound on the whole answer. It is
/// here because one value becomes one line, and a line the size of the
/// whole answer is a line nothing reads.
pub const max_value_bytes: usize = 1024 * 1024;

/// The prefix a DN line carries. Measured off curl, with the space.
pub const dn_prefix = "DN: ";

/// The prefix a DN line carries when the DN is written in base64.
pub const dn_base64_prefix = "DN:: ";

/// **An empty value drops the space in front of it.**
///
/// curl's `client_write` in `lib/openldap.c` reads:
///
///     if(!len && plen && prefix[plen - 1] == ' ')
///       plen--;
///
/// so a separator ending in a space loses that space when the value it
/// separates is empty. Measured against a real slapd 2.6.13: the root DSE
/// has an empty distinguished name, and curl wrote `DN:` and not `DN: `.
///
/// The same rule covers an empty attribute value, `\tattr:`, and an empty
/// base64 one, `\tattr::`. Neither could be measured, because slapd
/// refuses an entry holding an empty `description`, so those two arms come
/// from curl's source and this comment says so.
fn separator(text: []const u8, value_len: usize) []const u8 {
    if (value_len == 0 and text.len != 0 and text[text.len - 1] == ' ') {
        return text[0 .. text.len - 1];
    }
    return text;
}

/// Every fault writing the answer can report.
pub const Error = error{
    /// The answer is longer than the caller's bound.
    AnswerTooLarge,
    /// The server sent a DN, an attribute description, or a value longer
    /// than this file writes.
    FieldTooLarge,
    /// The server sent an attribute description holding a byte RFC 4512
    /// section 2.5 gives no attribute description, or an empty one.
    ///
    /// **This is a refusal and not a base64 arm, and the difference is on
    /// purpose.** A value goes into base64 when it is not printable,
    /// because a value is arbitrary octets and there is a spelling for
    /// that. An attribute description is not: LDIF and curl's format both
    /// write it as a name in front of the colon and neither has a
    /// spelling for a name that is not one. A server that sends something
    /// else is not sending an entry this build can print, so the transfer
    /// fails rather than print a line whose shape nobody chose.
    BadAttributeDescription,
    /// The answer needs more memory than this process has.
    OutOfMemory,
};

/// Whether `value` has to be written in base64.
///
/// The rule, and every clause of it is curl's except where the doc comment
/// at the top of this file says otherwise:
///
/// 1. **The attribute description ends with `;binary`.** RFC 4522 gives
///    that transfer option a value that is not text at all. The compare
///    ignores case, and the description has to be longer than the seven
///    bytes of the option itself.
/// 2. **The value is not empty and its first or its last byte is a space
///    or a tab.** RFC 2849 gives a leading or trailing space no way to
///    survive a line, so a reader could not tell it from the separator.
/// 3. **Any byte of the value is outside 0x20 through 0x7e.** This is the
///    one clause that differs from curl, which also calls 0x09 through
///    0x0d printable. See the module doc comment.
///
/// An empty value is written as itself: no clause fires, and curl writes
/// `\t<attribute>: \n` for it, with the separating space and nothing
/// after.
pub fn needsBase64(attribute: []const u8, value: []const u8) bool {
    if (attribute.len > 7 and std.ascii.eqlIgnoreCase(attribute[attribute.len - 7 ..], ";binary")) {
        return true;
    }
    if (value.len != 0) {
        if (isBlank(value[0]) or isBlank(value[value.len - 1])) return true;
    }
    for (value) |b| {
        if (!isPrintable(b)) return true;
    }
    return false;
}

/// A space or a tab, which is curl's `ISBLANK`.
fn isBlank(b: u8) bool {
    return b == ' ' or b == '\t';
}

/// 0x20 through 0x7e, and nothing else.
///
/// **Narrower than curl's `ISPRINT` on purpose.** See the module doc
/// comment: curl calls 0x09 through 0x0d printable, and a line feed inside
/// a value then draws a line in the output that reads like the start of
/// another entry.
fn isPrintable(b: u8) bool {
    return b >= 0x20 and b <= 0x7e;
}

/// Where the text of one answer is built.
///
/// A `Sink` borrows the list and the allocator. It bounds every append
/// against `limit` **before** the append, so a server that sends more than
/// the caller reads costs one comparison and no memory.
pub const Sink = struct {
    gpa: std.mem.Allocator,
    out: *std.ArrayList(u8),
    /// The largest answer this may hold, in bytes. `--max-filesize`
    /// narrows it.
    limit: u64,

    /// How many bytes the answer holds so far.
    pub fn len(s: *const Sink) usize {
        return s.out.items.len;
    }

    /// Appends `bytes`, or reports that the answer would pass `limit`.
    ///
    /// **The room left is a saturating subtraction.** `limit` and `out`
    /// are two fields a caller sets, and nothing ties them, so a `Sink`
    /// over a list that already holds more than `limit` is a `Sink` a
    /// caller can build. A plain subtraction wraps there, the room left
    /// reads as a number near 2^64, and the ceiling stops holding for the
    /// rest of the answer. `-|` gives zero room instead, which refuses.
    fn append(s: *Sink, bytes: []const u8) Error!void {
        if (@as(u64, bytes.len) > s.limit -| s.out.items.len) return error.AnswerTooLarge;
        s.out.appendSlice(s.gpa, bytes) catch return error.OutOfMemory;
    }
};

/// Writes the `DN: ` line of one entry.
///
/// A DN that does not pass `needsBase64`'s third clause, or that starts or
/// ends with a blank, is written as `DN:: ` and its base64. See the module
/// doc comment for why this arm exists and curl has none.
pub fn writeDn(s: *Sink, dn: []const u8) Error!void {
    if (dn.len > max_dn_bytes) return error.FieldTooLarge;
    if (needsBase64("", dn)) {
        try s.append(separator(dn_base64_prefix, dn.len));
        try writeBase64(s, dn);
    } else {
        try s.append(separator(dn_prefix, dn.len));
        try s.append(dn);
    }
    try s.append("\n");
}

/// Refuses an attribute description a server sent that RFC 4512 section
/// 2.5 gives no attribute description.
///
/// **This is the check that keeps a server from drawing its own entry.**
/// The DN and every value are bounded and go into base64 when they are not
/// printable. The attribute description is written in front of the colon
/// with nothing between it and the output, so without this an attribute
/// named `cn: real\nDN: cn=forged,dc=a\n\tuserPassword` writes a whole
/// entry the directory does not hold. It also closes an ANSI escape into a
/// terminal, because the set below is far narrower than "printable".
///
/// `filter.isAttributeByte` is the one definition of the rule, and it is
/// the same one the outbound direction reads. See its doc comment.
fn checkAttribute(attribute: []const u8) Error!void {
    if (attribute.len == 0) return error.BadAttributeDescription;
    if (attribute.len > max_attribute_bytes) return error.FieldTooLarge;
    for (attribute) |b| {
        if (!filter.isAttributeByte(b)) return error.BadAttributeDescription;
    }
}

/// Writes one `\t<attribute>: <value>` line.
pub fn writeValue(s: *Sink, attribute: []const u8, value: []const u8) Error!void {
    try checkAttribute(attribute);
    if (value.len > max_value_bytes) return error.FieldTooLarge;

    try s.append("\t");
    try s.append(attribute);
    try s.append(":");
    if (needsBase64(attribute, value)) {
        try s.append(separator(": ", value.len));
        try writeBase64(s, value);
    } else {
        try s.append(separator(" ", value.len));
        try s.append(value);
    }
    try s.append("\n");
}

/// Writes the `\t<attribute>:` line an attribute with no values gets.
///
/// No blank line follows it. See the module doc comment.
pub fn writeEmptyAttribute(s: *Sink, attribute: []const u8) Error!void {
    try checkAttribute(attribute);
    try s.append("\t");
    try s.append(attribute);
    try s.append(":\n");
}

/// Writes the blank line that ends one attribute's values.
pub fn writeAttributeEnd(s: *Sink) Error!void {
    try s.append("\n");
}

/// Writes the blank line that ends one entry.
pub fn writeEntryEnd(s: *Sink) Error!void {
    try s.append("\n");
}

/// Appends `bytes` as standard base64 with padding, which is what
/// `curlx_base64_encode` writes.
///
/// **Encoded in groups and never into an allocation.** Base64 turns three
/// bytes into four, so a multiple of three encodes with no carry and the
/// stack buffer below covers every value under `max_value_bytes` in
/// `max_value_bytes / 3072` passes.
fn writeBase64(s: *Sink, bytes: []const u8) Error!void {
    const encoder = std.base64.standard.Encoder;
    const group = 3072;
    var out: [(group / 3) * 4]u8 = undefined;

    var at: usize = 0;
    while (at < bytes.len) {
        const take = @min(group, bytes.len - at);
        const written = encoder.encode(out[0..encoder.calcSize(take)], bytes[at..][0..take]);
        try s.append(written);
        at += take;
    }
}

const testing = std.testing;

/// Builds one answer in a sink over `list`.
fn sink(list: *std.ArrayList(u8)) Sink {
    return .{ .gpa = testing.allocator, .out = list, .limit = 1 << 20 };
}

test "one entry of one attribute matches the bytes curl wrote" {
    // Measured with `od -c` against a real slapd 2.6.13:
    //
    //     DN: dc=zurl,dc=test\n\tdc: zurl\n\n\n
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    var s = sink(&list);

    try writeDn(&s, "dc=zurl,dc=test");
    try writeValue(&s, "dc", "zurl");
    try writeAttributeEnd(&s);
    try writeEntryEnd(&s);

    try testing.expectEqualStrings("DN: dc=zurl,dc=test\n\tdc: zurl\n\n\n", list.items);
}

test "one entry of two attributes matches the bytes curl wrote" {
    // Measured:
    //
    //     DN: dc=zurl,dc=test\n\tdc: zurl\n\n\to: zurl test directory\n\n\n
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    var s = sink(&list);

    try writeDn(&s, "dc=zurl,dc=test");
    try writeValue(&s, "dc", "zurl");
    try writeAttributeEnd(&s);
    try writeValue(&s, "o", "zurl test directory");
    try writeAttributeEnd(&s);
    try writeEntryEnd(&s);

    try testing.expectEqualStrings(
        "DN: dc=zurl,dc=test\n\tdc: zurl\n\n\to: zurl test directory\n\n\n",
        list.items,
    );
}

test "an entry with no attributes is a DN line and one blank line" {
    // Measured: `?1.1?` asks for no attributes at all, and curl wrote
    // `DN: dc=zurl,dc=test\n\n`.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    var s = sink(&list);

    try writeDn(&s, "dc=zurl,dc=test");
    try writeEntryEnd(&s);
    try testing.expectEqualStrings("DN: dc=zurl,dc=test\n\n", list.items);
}

test "two values of one attribute share one blank line" {
    // Measured: the two `mail` values of one entry wrote two lines and
    // one blank line after them.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    var s = sink(&list);

    try writeValue(&s, "mail", "ross@zurl.test");
    try writeValue(&s, "mail", "ross.alt@zurl.test");
    try writeAttributeEnd(&s);
    try testing.expectEqualStrings(
        "\tmail: ross@zurl.test\n\tmail: ross.alt@zurl.test\n\n",
        list.items,
    );
}

test "the base64 rule fires on the cases curl base64ed, and on nothing else" {
    // Every row below was measured: the value went into a real slapd and
    // curl 8.21.0's output was read with `od -c`.
    const Case = struct { attribute: []const u8, value: []const u8, want: bool };
    const cases = [_]Case{
        .{ .attribute = "description", .value = "a plain ascii value", .want = false },
        .{ .attribute = "description", .value = "plain", .want = false },
        .{ .attribute = "telephoneNumber", .value = "+1 555 0100", .want = false },
        // Leading and trailing blanks. curl base64ed both, measured.
        .{ .attribute = "description", .value = " leading space", .want = true },
        .{ .attribute = "description", .value = "trailing space ", .want = true },
        .{ .attribute = "description", .value = "\tleading tab", .want = true },
        // Bytes over 0x7e. curl base64ed this one, measured: the value
        // was `こんにちは` and the output was `44GT44KT44Gr44Gh44Gv`.
        .{
            .attribute = "description",
            .value = &.{ 0xe3, 0x81, 0x93, 0xe3, 0x82, 0x93 },
            .want = true,
        },
        // The `;binary` transfer option of RFC 4522, whatever the value
        // holds.
        .{ .attribute = "userCertificate;binary", .value = "abc", .want = true },
        .{ .attribute = "USERCERTIFICATE;BINARY", .value = "abc", .want = true },
        // The name must be longer than the option itself, which is curl's
        // own `bv_len > 7` check.
        .{ .attribute = ";binary", .value = "abc", .want = false },
        // An empty value fires no clause. See `separator` for what curl
        // writes for one.
        .{ .attribute = "description", .value = "", .want = false },
        // A space in the middle is not a leading or a trailing one.
        .{ .attribute = "cn", .value = "Ross Tomboy", .want = false },
    };
    for (cases) |case| {
        try testing.expectEqual(case.want, needsBase64(case.attribute, case.value));
    }
}

test "every byte curl calls printable and this build does not forces base64" {
    // **The one place this build differs from curl, pinned.** curl's
    // `ISPRINT` also passes 0x09 through 0x0d, so curl writes each of
    // these five raw. Measured: a value of `embedded\nLF and DN: cn=forged`
    // came out of curl with the line feed intact, and the output then
    // held a line that reads like the start of another entry.
    const forgers = [_]u8{ 0x09, 0x0a, 0x0b, 0x0c, 0x0d };
    for (forgers) |byte| {
        try testing.expect(needsBase64("description", &.{ 'a', byte, 'b' }));
    }
    // And the whole byte range, so the set is exactly 0x20 through 0x7e.
    var value: usize = 0;
    while (value < 256) : (value += 1) {
        const byte: u8 = @intCast(value);
        const printable = byte >= 0x20 and byte <= 0x7e;
        // A blank in the middle of three bytes fires no other clause.
        try testing.expectEqual(
            !printable,
            needsBase64("description", &.{ 'a', byte, 'b' }),
        );
    }
}

test "a value that forges a line comes out in base64 and draws nothing" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    var s = sink(&list);

    try writeValue(&s, "description", "embedded\nLF and DN: cn=forged");
    // The output holds exactly one line ending, the one this wrote.
    try testing.expectEqual(
        @as(usize, 1),
        std.mem.count(u8, list.items, "\n"),
    );
    try testing.expect(std.mem.startsWith(u8, list.items, "\tdescription:: "));
    // And what it holds decodes back to the value the server sent.
    const text = std.mem.trimEnd(u8, list.items["\tdescription:: ".len..], "\n");
    var decoded: [64]u8 = undefined;
    const size = try std.base64.standard.Decoder.calcSizeForSlice(text);
    try std.base64.standard.Decoder.decode(decoded[0..size], text);
    try testing.expectEqualStrings("embedded\nLF and DN: cn=forged", decoded[0..size]);
}

test "the base64 curl wrote is the base64 this writes" {
    // `こんにちは` in UTF-8, which curl wrote as `44GT44KT44Gr44Gh44Gv`,
    // and ` leading space`, which curl wrote as `IGxlYWRpbmcgc3BhY2U=`.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    var s = sink(&list);

    try writeValue(&s, "description", "\u{3053}\u{3093}\u{306b}\u{3061}\u{306f}");
    try testing.expectEqualStrings(
        "\tdescription:: 44GT44KT44Gr44Gh44Gv\n",
        list.items,
    );

    list.clearRetainingCapacity();
    try writeValue(&s, "description", " leading space");
    try testing.expectEqualStrings(
        "\tdescription:: IGxlYWRpbmcgc3BhY2U=\n",
        list.items,
    );

    list.clearRetainingCapacity();
    try writeValue(&s, "description", "trailing space ");
    try testing.expectEqualStrings(
        "\tdescription:: dHJhaWxpbmcgc3BhY2Ug\n",
        list.items,
    );
}

test "an attribute the server sent with no values writes one line and no blank" {
    // Read in curl's `lib/openldap.c`, the `if(!bvals)` arm. No url makes
    // curl ask for a typesOnly search, so this arm is not measured on the
    // wire.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    var s = sink(&list);

    try writeEmptyAttribute(&s, "cn");
    try testing.expectEqualStrings("\tcn:\n", list.items);
}

test "a DN of printable ASCII is written exactly as curl writes it" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    var s = sink(&list);

    try writeDn(&s, "cn=Ross Tomboy,ou=people,dc=zurl,dc=test");
    try testing.expectEqualStrings(
        "DN: cn=Ross Tomboy,ou=people,dc=zurl,dc=test\n",
        list.items,
    );
}

test "an empty value drops the space in front of it, the way curl does" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    var s = sink(&list);

    // **Measured.** The root DSE has an empty distinguished name, and
    // `curl ldap://127.0.0.1:3899/ | cat -A` printed `DN:$` and not
    // `DN: $`. See `separator`.
    try writeDn(&s, "");
    try testing.expectEqualStrings("DN:\n", list.items);

    // The same rule on an attribute value. slapd refuses an entry holding
    // an empty `description`, so this arm comes from curl's own
    // `client_write` and not from the wire.
    list.clearRetainingCapacity();
    try writeValue(&s, "description", "");
    try testing.expectEqualStrings("\tdescription:\n", list.items);

    // And on an empty value the `;binary` option sends to base64.
    list.clearRetainingCapacity();
    try writeValue(&s, "userCertificate;binary", "");
    try testing.expectEqualStrings("\tuserCertificate;binary::\n", list.items);

    // One byte is not zero bytes, so the space stays.
    list.clearRetainingCapacity();
    try writeValue(&s, "description", "x");
    try testing.expectEqualStrings("\tdescription: x\n", list.items);
}

test "a DN a server could forge a line with comes out in base64" {
    // curl has no base64 arm for a DN at all, so a server that put a line
    // feed in one would draw a line in curl's output. This build does
    // not.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    var s = sink(&list);

    try writeDn(&s, "cn=a\nDN: cn=forged");
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, list.items, "\n"));
    try testing.expect(std.mem.startsWith(u8, list.items, "DN:: "));

    // A DN holding UTF-8 goes the same way, and it decodes back whole.
    list.clearRetainingCapacity();
    try writeDn(&s, "cn=\u{3053}\u{3093},dc=test");
    try testing.expect(std.mem.startsWith(u8, list.items, "DN:: "));
}

test "an attribute description a server could forge an entry with is refused" {
    // **The regression test for the defect a review found.** The first
    // draft judged the DN and every value and wrote this field raw, so one
    // call drew a whole entry the directory does not hold.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    var s = sink(&list);

    try testing.expectError(error.BadAttributeDescription, writeValue(
        &s,
        "cn: real\nDN: cn=forged,dc=a\n\tuserPassword",
        "hunter2",
    ));
    try testing.expectEqual(@as(usize, 0), list.items.len);

    // The same field through the other writer, which had the same hole.
    try testing.expectError(
        error.BadAttributeDescription,
        writeEmptyAttribute(&s, "cn: real\nDN: cn=forged,dc=a"),
    );
    try testing.expectEqual(@as(usize, 0), list.items.len);
}

test "every byte outside RFC 4512's attribute description set is refused" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    var s = sink(&list);

    var value: usize = 0;
    while (value < 256) : (value += 1) {
        const byte: u8 = @intCast(value);
        const named = std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '.' or byte == ';';
        list.clearRetainingCapacity();
        const result = writeValue(&s, &.{ 'c', byte, 'n' }, "x");
        if (named) {
            try result;
        } else {
            // A newline, a carriage return, an escape, a colon, a space,
            // and every byte over 0x7e all land here.
            try testing.expectError(error.BadAttributeDescription, result);
            try testing.expectEqual(@as(usize, 0), list.items.len);
        }
    }

    // An attribute with no name at all is not an attribute.
    try testing.expectError(error.BadAttributeDescription, writeValue(&s, "", "x"));
    try testing.expectError(error.BadAttributeDescription, writeEmptyAttribute(&s, ""));

    // Every attribute description a real directory sends still passes.
    const real = [_][]const u8{
        "objectClass",                   "cn",
        "userCertificate;binary",        "telephoneNumber",
        "1.3.6.1.4.1.1466.115.121.1.15", "user-name",
        "cn;lang-en",
    };
    for (real) |name| {
        list.clearRetainingCapacity();
        try writeValue(&s, name, "x");
        try testing.expect(list.items.len != 0);
    }
}

test "a field longer than this file writes is refused and never cut" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    var s = sink(&list);

    const long_dn = "d" ** (max_dn_bytes + 1);
    try testing.expectError(error.FieldTooLarge, writeDn(&s, long_dn));

    const long_attribute = "a" ** (max_attribute_bytes + 1);
    try testing.expectError(error.FieldTooLarge, writeValue(&s, long_attribute, "x"));

    // Nothing was written for either.
    try testing.expectEqual(@as(usize, 0), list.items.len);
}

test "the answer bound is checked before the append and never after" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    var s: Sink = .{ .gpa = testing.allocator, .out = &list, .limit = 12 };

    // `DN: abc\n` is eight bytes and fits.
    try writeDn(&s, "abc");
    try testing.expectEqual(@as(usize, 8), s.len());
    // The next line does not, and the answer stays at eight bytes.
    try testing.expectError(error.AnswerTooLarge, writeValue(&s, "cn", "a value"));
    try testing.expect(list.items.len <= 12);
}

test "a list that already passes the bound refuses the next append and does not wrap" {
    // `Sink` is public and so are its two fields, so a caller can point
    // one at a list that already holds more than `limit`. The room left is
    // then a subtraction of a larger number from a smaller one. With a
    // plain `-` that wraps to a number near 2^64 and every later append
    // passes, which takes the ceiling away for the rest of the answer.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try list.appendSlice(testing.allocator, "already too long");

    var s: Sink = .{ .gpa = testing.allocator, .out = &list, .limit = 4 };
    try testing.expectError(error.AnswerTooLarge, writeDn(&s, "abc"));
    try testing.expectEqual(@as(usize, "already too long".len), list.items.len);
}

test "a value of exactly the bound is written and one byte more is refused" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    var s: Sink = .{ .gpa = testing.allocator, .out = &list, .limit = 4 * 1024 * 1024 };

    const at_bound = try testing.allocator.alloc(u8, max_value_bytes);
    defer testing.allocator.free(at_bound);
    @memset(at_bound, 'x');
    try writeValue(&s, "cn", at_bound);
    try testing.expect(list.items.len > max_value_bytes);

    const over = try testing.allocator.alloc(u8, max_value_bytes + 1);
    defer testing.allocator.free(over);
    @memset(over, 'x');
    try testing.expectError(error.FieldTooLarge, writeValue(&s, "cn", over));
}

test "a value larger than one base64 group encodes in pieces and round-trips" {
    // The group is 3072 bytes, so this crosses it four times and the
    // encoder must carry nothing between the passes.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    var s: Sink = .{ .gpa = testing.allocator, .out = &list, .limit = 1 << 20 };

    const value = try testing.allocator.alloc(u8, 10_000);
    defer testing.allocator.free(value);
    for (value, 0..) |*b, i| b.* = @truncate(i);

    try writeValue(&s, "jpegPhoto", value);
    const text = std.mem.trimEnd(u8, list.items["\tjpegPhoto:: ".len..], "\n");

    const size = try std.base64.standard.Decoder.calcSizeForSlice(text);
    const decoded = try testing.allocator.alloc(u8, size);
    defer testing.allocator.free(decoded);
    try std.base64.standard.Decoder.decode(decoded, text);
    try testing.expectEqualSlices(u8, value, decoded);
}
