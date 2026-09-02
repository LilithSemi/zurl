//! BER, the subset RFC 4511 needs, as bytes and nothing else.
//!
//! X.690 names the Basic Encoding Rules. RFC 4511 section 5.1 narrows them
//! for LDAP: only the definite length form, and the simplified BER of
//! X.690 clause 8.1.3.3. This file speaks that narrow subset and refuses
//! the rest by name.
//!
//! **This file owns the length rule and the nesting rule.** A length on
//! the wire is a number a peer chose, it decides how many bytes this
//! process then reads or copies, and lengths nest. Every check here runs
//! **before** an allocation or a copy, never after. See `readElement` for
//! the four refusals and `Cursor.enter` for the depth bound.
//!
//! What this file does not own: the meaning of any tag. A `[APPLICATION 3]`
//! is a `SearchRequest` to `message.zig` and an opaque element here. It
//! reads no LDAP structure and it writes none, so a change to RFC 4511
//! reaches `message.zig` and never this file.
//!
//! **Why this is not `std.crypto.codecs.asn1.der`.** That decoder is close
//! and it is not this. It refuses a long length form that a short form
//! could carry, which is a DER rule that BER does not keep, so a legal
//! LDAP peer would be refused. It decodes by reflection over Zig types
//! against universal tags, and LDAP is a CHOICE of `APPLICATION` and
//! `CONTEXT` tags that no Zig type expresses. It reads from a complete
//! slice, and an LDAP message arrives on a socket, so the envelope length
//! has to be bounded before a buffer exists to decode from. It carries no
//! caller-set bound on an element and none on nesting depth. Four
//! mismatches, so this file is its own.
//!
//! Nothing here allocates and nothing here does I/O. `Session.zig` reads
//! the envelope off the socket and hands a complete message here.

const std = @import("std");

/// The tag class of one element. X.690 clause 8.1.2.2.
pub const Class = enum(u2) {
    universal,
    application,
    context,
    private,
};

/// The tag of one element.
///
/// **The number is five bits and that is a refusal, not a shortcut.**
/// X.690 clause 8.1.2.4 writes a number of 31 or more over several bytes,
/// and RFC 4511 uses no such tag: the largest it names is `[APPLICATION
/// 25]`. A first byte whose low five bits are all set is therefore refused
/// by `readElement` rather than read, so no tag on the wire can make this
/// file read a byte it did not plan for.
pub const Tag = struct {
    class: Class,
    constructed: bool,
    number: u5,

    /// The one byte this tag writes. X.690 clause 8.1.2.
    pub fn byte(t: Tag) u8 {
        return (@as(u8, @intFromEnum(t.class)) << 6) |
            (@as(u8, @intFromBool(t.constructed)) << 5) |
            @as(u8, t.number);
    }

    /// The tag one byte names, or null for the multi-byte form this file
    /// refuses.
    pub fn fromByte(b: u8) ?Tag {
        const number: u5 = @truncate(b);
        if (number == 0x1f) return null;
        return .{
            .class = @enumFromInt(@as(u2, @truncate(b >> 6))),
            .constructed = (b & 0x20) != 0,
            .number = number,
        };
    }

    pub fn eql(a: Tag, b: Tag) bool {
        return a.class == b.class and a.constructed == b.constructed and a.number == b.number;
    }

    /// A universal tag, such as `sequence` or `octet_string`.
    pub fn universal(number: u5, constructed: bool) Tag {
        return .{ .class = .universal, .constructed = constructed, .number = number };
    }

    /// An `[APPLICATION n]` tag. Every LDAP protocol operation carries one.
    pub fn application(number: u5, constructed: bool) Tag {
        return .{ .class = .application, .constructed = constructed, .number = number };
    }

    /// A `[n]` tag. Every filter arm and the simple authentication choice
    /// carry one.
    pub fn context(number: u5, constructed: bool) Tag {
        return .{ .class = .context, .constructed = constructed, .number = number };
    }
};

/// The universal tag numbers this subset uses. X.690 clause 8.
pub const universal_boolean: u5 = 1;
pub const universal_integer: u5 = 2;
pub const universal_octet_string: u5 = 4;
pub const universal_enumerated: u5 = 10;
pub const universal_sequence: u5 = 16;
pub const universal_set: u5 = 17;

/// `SEQUENCE`, the tag every LDAP message and every list carries.
pub const sequence: Tag = .universal(universal_sequence, true);

/// `SET OF`, the tag a `PartialAttribute` carries around its values.
pub const set: Tag = .universal(universal_set, true);

/// `OCTET STRING`, the tag every name and every value carries.
pub const octet_string: Tag = .universal(universal_octet_string, false);

/// `INTEGER`.
pub const integer: Tag = .universal(universal_integer, false);

/// `ENUMERATED`, the tag a scope and a result code carry.
pub const enumerated: Tag = .universal(universal_enumerated, false);

/// `BOOLEAN`.
pub const boolean: Tag = .universal(universal_boolean, false);

/// How many length octets a long form may name.
///
/// **Four, and this is the first bound a hostile message meets.** X.690
/// clause 8.1.3.5 lets the long form name up to 126 length octets, which
/// describes a value larger than any address space. Four octets describe
/// 4 GiB, which is already far past `max_element_bytes` and past any
/// bound above this file, and it is the width the arithmetic below runs
/// in. A message that names more is `error.LengthTooLarge` and no byte of
/// it is read.
pub const max_length_octets: usize = 4;

/// The largest element this file will describe, in bytes.
///
/// **A second bound behind `max_length_octets`, and it is the one that
/// matters.** Four length octets still describe 4 GiB, and a caller that
/// trusted that number would try to hold it. 16 MiB is past every LDAP
/// message a directory sends: an entry with a photograph in it is a few
/// hundred kilobytes.
///
/// A caller with a smaller bound names its own. `Session.max_message_bytes`
/// is the bound on a whole message read from a socket, and it is smaller
/// than this.
pub const max_element_bytes: usize = 16 * 1024 * 1024;

/// How deep an element may nest.
///
/// **Nesting is the second attacker-controlled number in a BER message.**
/// A `SEQUENCE` holds a `SEQUENCE`, and a peer that writes 100 000 opening
/// headers costs a walker that follows them 100 000 frames. Nothing in
/// RFC 4511 nests more than six deep: a message holds an operation, which
/// holds a filter, which holds an `and` of an `or` of a `not` of an item.
/// 32 is far past that and far below anything that costs a stack.
///
/// `Cursor.enter` is the one function that increases depth, and it is the
/// one place this number is read.
pub const max_depth: usize = 32;

/// Every fault reading BER can report.
///
/// Each name is a separate refusal, so a diagnostic can say which rule the
/// peer broke rather than "bad BER".
pub const ReadError = error{
    /// The bytes ran out inside a header or inside a value. The element
    /// claimed more than the buffer holds.
    Truncated,
    /// The first tag byte named the multi-byte tag number form. See `Tag`.
    TagTooLarge,
    /// The length used the indefinite form, `0x80`.
    ///
    /// **Refused rather than supported.** RFC 4511 section 5.1 allows only
    /// the definite form. The indefinite form ends at a pair of zero
    /// octets somewhere later, so its length is not a number this file can
    /// check before it reads: the bound and the content would arrive
    /// together, which is exactly the shape every check here exists to
    /// avoid.
    IndefiniteLength,
    /// The length named more than `max_length_octets` octets, or `0xff`,
    /// which X.690 clause 8.1.3.5 reserves.
    LengthTooLarge,
    /// The element is longer than `max_element_bytes`, or longer than the
    /// bound the caller named.
    ElementTooLarge,
    /// The element nests deeper than `max_depth`.
    NestingTooDeep,
    /// The element is there and it is not the one the caller expected.
    UnexpectedTag,
    /// An `INTEGER`, an `ENUMERATED`, or a `BOOLEAN` does not hold a value
    /// this reads: no octets at all, more octets than the Zig type holds,
    /// or a `BOOLEAN` that is neither zero nor all ones.
    ValueOutOfRange,
    /// A constructed element was expected and a primitive one arrived, or
    /// the other way round.
    WrongForm,
};

/// One element: its tag, its content, and how many bytes it took whole.
pub const Element = struct {
    tag: Tag,
    /// The value octets. Borrows the buffer `readElement` read from.
    content: []const u8,
    /// The tag, the length, and the content together. A walker adds this
    /// to move past the element.
    total_len: usize,
};

/// Reads the element at the front of `bytes`.
///
/// **Every check runs before any slice is made.** In order: the tag byte
/// must name a number under 31; the length must not be the indefinite
/// form and must not name more than `max_length_octets` octets; the
/// length must not pass `max_element_bytes`; and the header and the
/// content together must fit inside `bytes`. Only then does the content
/// slice exist. A caller therefore cannot be handed a slice that points
/// past what it read from the peer.
///
/// The addition of the header length and the content length runs through
/// `std.math.add`, so a length near the top of a `usize` reports
/// `error.Truncated` rather than wrapping to a small number that would
/// pass the bounds check after it.
///
/// **A non-minimal long form is read and not refused.** X.690 clause
/// 8.1.3.3 lets BER write `0x82 0x00 0x05` where `0x05` would do, and RFC
/// 4511 section 5.1 restricts only the indefinite form. A decoder that
/// refused it would refuse a legal peer. DER forbids it, which is why
/// `std.crypto.codecs.asn1.der` cannot be used here.
pub fn readElement(bytes: []const u8) ReadError!Element {
    return readElementBounded(bytes, max_element_bytes);
}

/// `readElement`, with the caller's own bound on the content length.
///
/// `limit` is the largest content this element may hold. It never widens
/// `max_element_bytes`: the smaller of the two stands.
pub fn readElementBounded(bytes: []const u8, limit: usize) ReadError!Element {
    if (bytes.len < 2) return error.Truncated;

    const tag = Tag.fromByte(bytes[0]) orelse return error.TagTooLarge;

    const first = bytes[1];
    var header: usize = 2;
    var length: usize = 0;

    if (first < 0x80) {
        // The short form. X.690 clause 8.1.3.4.
        length = first;
    } else if (first == 0x80) {
        return error.IndefiniteLength;
    } else {
        // X.690 clause 8.1.3.5 c reserves `0xff`, so the count below is
        // never 127 and the refusal names it with the other wide counts.
        const count: usize = first & 0x7f;
        if (count > max_length_octets) return error.LengthTooLarge;
        if (bytes.len < 2 + count) return error.Truncated;

        var value: u64 = 0;
        for (bytes[2..][0..count]) |b| {
            value = (value << 8) | b;
        }
        // `count` is at most four, so `value` is at most 0xffffffff and
        // the cast below cannot lose a bit on any target this builds for.
        // The bound after it is what keeps the number usable.
        if (value > max_element_bytes) return error.ElementTooLarge;
        length = @intCast(value);
        header = 2 + count;
    }

    if (length > limit or length > max_element_bytes) return error.ElementTooLarge;

    const total = std.math.add(usize, header, length) catch return error.Truncated;
    if (total > bytes.len) return error.Truncated;

    return .{
        .tag = tag,
        .content = bytes[header..total],
        .total_len = total,
    };
}

/// Walks the elements of one container, and counts how deep it is.
///
/// A `Cursor` borrows the bytes it walks. It never copies and never
/// allocates, so every `Element` it hands back points into the message
/// buffer the session holds.
pub const Cursor = struct {
    /// What is left of this container.
    rest: []const u8,
    /// How many containers this cursor is inside. The outermost is zero.
    depth: usize,

    /// A cursor over `bytes`, at depth zero.
    pub fn init(bytes: []const u8) Cursor {
        return .{ .rest = bytes, .depth = 0 };
    }

    /// Whether every element of this container has been read.
    pub fn atEnd(c: Cursor) bool {
        return c.rest.len == 0;
    }

    /// Reads the next element and moves past it.
    ///
    /// `error.Truncated` when the container is already spent, so a caller
    /// that expected one more field reports a short message rather than
    /// read a field that is not there.
    pub fn next(c: *Cursor) ReadError!Element {
        if (c.rest.len == 0) return error.Truncated;
        const e = try readElement(c.rest);
        c.rest = c.rest[e.total_len..];
        return e;
    }

    /// Reads the next element and refuses it when its tag is not `want`.
    pub fn expect(c: *Cursor, want: Tag) ReadError!Element {
        const e = try c.next();
        if (!e.tag.eql(want)) return error.UnexpectedTag;
        return e;
    }

    /// Whether the next element carries `want`, without moving.
    ///
    /// Null when the container is spent or the next header does not read.
    /// A caller uses it for an optional field, which is what a
    /// `SearchResultDone` referral is.
    pub fn peekTag(c: Cursor) ?Tag {
        if (c.rest.len == 0) return null;
        const e = readElement(c.rest) catch return null;
        return e.tag;
    }

    /// A cursor over the content of `e`, one level deeper.
    ///
    /// **This is the one function that increases depth**, so
    /// `max_depth` is read here and nowhere else. A container past the
    /// bound is `error.NestingTooDeep` and none of its content is read.
    ///
    /// A primitive element holds no elements, so entering one is
    /// `error.WrongForm` rather than a walk over value octets that would
    /// read a text byte as a tag.
    pub fn enter(c: *const Cursor, e: Element) ReadError!Cursor {
        if (!e.tag.constructed) return error.WrongForm;
        if (c.depth + 1 > max_depth) return error.NestingTooDeep;
        return .{ .rest = e.content, .depth = c.depth + 1 };
    }
};

/// The signed integer `e` holds, as `T`.
///
/// X.690 clause 8.3: two's complement, big endian, at least one octet,
/// most significant first. An element with no octets, or with more octets
/// than `T` holds, is `error.ValueOutOfRange`.
///
/// **A non-minimal encoding is read and not refused**, for the reason
/// `readElement` gives: BER allows it and a directory that writes it is
/// still a directory.
pub fn integerValue(comptime T: type, e: Element) ReadError!T {
    if (e.tag.constructed) return error.WrongForm;
    const octets = e.content;
    if (octets.len == 0) return error.ValueOutOfRange;
    if (octets.len > @sizeOf(T)) {
        // More octets than `T` holds is still in range when every octet
        // past the first `@sizeOf(T)` is sign padding. Anything else is
        // a number this caller cannot hold.
        const pad: u8 = if (octets[0] & 0x80 != 0) 0xff else 0x00;
        const extra = octets.len - @sizeOf(T);
        for (octets[0..extra]) |b| {
            if (b != pad) return error.ValueOutOfRange;
        }
        // The sign of the kept octets must match the padding, or the
        // number changed when the padding was dropped.
        const kept_negative = octets[extra] & 0x80 != 0;
        if (kept_negative != (pad == 0xff)) return error.ValueOutOfRange;
        return readSigned(T, octets[extra..]);
    }
    return readSigned(T, octets);
}

/// Reads `octets`, which is no longer than `T`, as a two's complement big
/// endian number.
fn readSigned(comptime T: type, octets: []const u8) T {
    const negative = octets[0] & 0x80 != 0;
    var value: std.meta.Int(.unsigned, @bitSizeOf(T)) = if (negative)
        std.math.maxInt(std.meta.Int(.unsigned, @bitSizeOf(T)))
    else
        0;
    for (octets) |b| {
        value = (value << 8) | b;
    }
    return @bitCast(value);
}

/// The boolean `e` holds.
///
/// X.690 clause 8.2: one octet, zero for false and any other value for
/// true. DER narrows true to `0xff`; BER does not, and a peer that writes
/// `0x01` is a peer this reads.
pub fn booleanValue(e: Element) ReadError!bool {
    if (e.tag.constructed) return error.WrongForm;
    if (e.content.len != 1) return error.ValueOutOfRange;
    return e.content[0] != 0;
}

/// Builds one BER message inside a fixed buffer.
///
/// **A fixed buffer and not an allocator.** Every message this package
/// writes is a request, every request is bounded by the url that asked for
/// it, and a writer that could not run out of room would have no bound at
/// all. `capacity` is that bound, and a caller that overruns it gets
/// `error.NoRoom` with nothing written past the end.
///
/// The length of a container is not known until its content is written, so
/// `beginElement` writes one placeholder byte and `endElement` fills it
/// in. A content length past 127 needs a longer field, and `endElement`
/// moves the content along to make room. The move is bounded by
/// `capacity` and there is one for each container, so a message of `n`
/// containers costs `n` moves and never more.
pub fn Writer(comptime capacity: usize, comptime depth_bound: usize) type {
    comptime {
        if (capacity < 8) @compileError("ber.Writer: a capacity under 8 bytes holds no message");
        if (depth_bound == 0) @compileError("ber.Writer: a depth bound of zero opens nothing");
        if (depth_bound > max_depth) @compileError("ber.Writer: a depth bound past ber.max_depth");
    }
    return struct {
        const Self = @This();

        /// Every fault building a message can report.
        pub const Error = error{
            /// The message does not fit in `capacity`.
            NoRoom,
            /// More containers are open than `depth_bound` allows.
            TooDeep,
            /// `endElement` was called with no container open. A
            /// programmer error in this package, reported and not
            /// asserted so a caller of the module cannot crash a process.
            ///
            /// The name is not `Unbalanced`, which is what
            /// `filter.ParseError` calls a filter with the wrong
            /// parentheses. Zig merges two error sets by name, so one name
            /// for the two would give a caller of both one arm for a fault
            /// in a url and a fault in this file, which are two different
            /// sentences to a user.
            NothingOpen,
        };

        bytes: [capacity]u8,
        len: usize,
        /// Where each open container's length placeholder sits.
        open: [depth_bound]usize,
        depth: usize,

        /// A writer holding nothing.
        pub fn init() Self {
            return .{ .bytes = undefined, .len = 0, .open = undefined, .depth = 0 };
        }

        /// Empties the writer, so one value builds several messages.
        ///
        /// **The bytes are zeroed and not only forgotten.** A
        /// `BindRequest` carries a password, and the next message this
        /// writer builds is shorter than that one, so without the wipe the
        /// tail of the password would sit in this buffer for the rest of
        /// the transfer. The caller wipes it again when the transfer ends;
        /// this is what makes the window one message wide instead of one
        /// transfer wide.
        pub fn reset(w: *Self) void {
            std.crypto.secureZero(u8, w.bytes[0..w.len]);
            w.len = 0;
            w.depth = 0;
        }

        /// The message so far. Complete only when `depth` is zero.
        pub fn written(w: *const Self) []const u8 {
            return w.bytes[0..w.len];
        }

        /// Whether every container this writer opened is closed.
        pub fn balanced(w: *const Self) bool {
            return w.depth == 0;
        }

        /// Opens a constructed element. `endElement` closes it.
        pub fn beginElement(w: *Self, tag: Tag) Error!void {
            std.debug.assert(tag.constructed);
            if (w.depth == depth_bound) return error.TooDeep;
            if (w.len + 2 > capacity) return error.NoRoom;
            w.bytes[w.len] = tag.byte();
            // One placeholder byte. `endElement` widens it when the
            // content needs more than the short form.
            w.bytes[w.len + 1] = 0;
            w.open[w.depth] = w.len + 1;
            w.depth += 1;
            w.len += 2;
        }

        /// Closes the container `beginElement` opened last, and writes its
        /// real length.
        pub fn endElement(w: *Self) Error!void {
            if (w.depth == 0) return error.NothingOpen;
            w.depth -= 1;
            const at = w.open[w.depth];
            const content_len = w.len - (at + 1);
            if (content_len > max_element_bytes) return error.NoRoom;

            const extra = lengthFieldExtra(content_len);
            if (extra != 0) {
                if (w.len + extra > capacity) return error.NoRoom;
                // The content moves up to make room for the wider length
                // field. `copyBackwards` is what an overlapping move to a
                // higher address needs.
                std.mem.copyBackwards(
                    u8,
                    w.bytes[at + 1 + extra ..][0..content_len],
                    w.bytes[at + 1 ..][0..content_len],
                );
                w.len += extra;
            }
            writeLengthField(w.bytes[at..][0 .. 1 + extra], content_len);
        }

        /// Writes a whole primitive element: its tag, its length, and
        /// `content`.
        pub fn writeElement(w: *Self, tag: Tag, content: []const u8) Error!void {
            std.debug.assert(!tag.constructed);
            if (content.len > max_element_bytes) return error.NoRoom;
            const field = 1 + lengthFieldExtra(content.len);
            const total = std.math.add(usize, 1 + field, content.len) catch return error.NoRoom;
            if (w.len + total > capacity) return error.NoRoom;

            w.bytes[w.len] = tag.byte();
            writeLengthField(w.bytes[w.len + 1 ..][0..field], content.len);
            @memcpy(w.bytes[w.len + 1 + field ..][0..content.len], content);
            w.len += total;
        }

        /// Writes an `INTEGER` or an `ENUMERATED` holding `value`.
        ///
        /// The minimal two's complement form, which is what X.690 clause
        /// 8.3.2 asks for: no leading `0x00` in front of a byte whose top
        /// bit is clear, and no leading `0xff` in front of one whose top
        /// bit is set.
        pub fn writeInteger(w: *Self, tag: Tag, value: i64) Error!void {
            var octets: [8]u8 = undefined;
            std.mem.writeInt(i64, &octets, value, .big);

            var at: usize = 0;
            while (at + 1 < octets.len) : (at += 1) {
                const lead = octets[at];
                const next_top = octets[at + 1] & 0x80;
                if (lead == 0x00 and next_top == 0) continue;
                if (lead == 0xff and next_top != 0) continue;
                break;
            }
            return w.writeElement(tag, octets[at..]);
        }

        /// Writes a `BOOLEAN`.
        ///
        /// True is `0xff`. X.690 clause 8.2.2 lets BER write any non-zero
        /// octet, and `0xff` is the one DER allows, so a peer that reads
        /// either is satisfied.
        pub fn writeBoolean(w: *Self, tag: Tag, value: bool) Error!void {
            const octet: [1]u8 = .{if (value) 0xff else 0x00};
            return w.writeElement(tag, &octet);
        }
    };
}

/// How many octets past the first a length field needs for `length`.
///
/// Zero for the short form. One, two, three, or four for the long form,
/// which writes a count byte and then the length itself.
fn lengthFieldExtra(length: usize) usize {
    if (length < 0x80) return 0;
    if (length <= 0xff) return 1;
    if (length <= 0xffff) return 2;
    if (length <= 0xffffff) return 3;
    return 4;
}

/// Writes `length` into `field`, which is exactly the size
/// `lengthFieldExtra` asked for plus one.
fn writeLengthField(field: []u8, length: usize) void {
    std.debug.assert(field.len >= 1 and field.len <= 1 + max_length_octets);
    if (field.len == 1) {
        std.debug.assert(length < 0x80);
        field[0] = @intCast(length);
        return;
    }
    const count = field.len - 1;
    field[0] = @intCast(0x80 | count);
    var shift = count;
    var at: usize = 1;
    while (shift > 0) : (at += 1) {
        shift -= 1;
        field[at] = @truncate(length >> @intCast(shift * 8));
    }
}

const testing = std.testing;

test "a tag byte carries the class, the form, and the number" {
    try testing.expectEqual(@as(u8, 0x30), sequence.byte());
    try testing.expectEqual(@as(u8, 0x04), octet_string.byte());
    try testing.expectEqual(@as(u8, 0x02), integer.byte());
    try testing.expectEqual(@as(u8, 0x0a), enumerated.byte());
    try testing.expectEqual(@as(u8, 0x31), set.byte());
    // Measured off curl 8.21.0 on the wire: a BindRequest is
    // `[APPLICATION 0]` constructed, and simple authentication is `[0]`
    // primitive.
    try testing.expectEqual(@as(u8, 0x60), Tag.application(0, true).byte());
    try testing.expectEqual(@as(u8, 0x80), Tag.context(0, false).byte());
    try testing.expectEqual(@as(u8, 0x63), Tag.application(3, true).byte());
    try testing.expectEqual(@as(u8, 0x42), Tag.application(2, false).byte());
    try testing.expectEqual(@as(u8, 0xa9), Tag.context(9, true).byte());
    try testing.expectEqual(@as(u8, 0x87), Tag.context(7, false).byte());
}

test "every tag byte round-trips except the multi-byte number form" {
    var b: usize = 0;
    while (b < 256) : (b += 1) {
        const byte: u8 = @intCast(b);
        const tag = Tag.fromByte(byte) orelse {
            // The only refusal is the form whose low five bits are set.
            try testing.expectEqual(@as(u8, 0x1f), byte & 0x1f);
            continue;
        };
        try testing.expectEqual(byte, tag.byte());
    }
}

test "the indefinite length form is refused by name and never read" {
    // `0x80` opens a value that ends at two zero octets somewhere later,
    // so its length arrives with its content. That is the shape every
    // check in this file exists to refuse.
    try testing.expectError(error.IndefiniteLength, readElement(&.{ 0x30, 0x80, 0x00, 0x00 }));
}

test "a length octet count past four is refused before a byte is read" {
    // `0x85` says five length octets. Five octets describe more than 4
    // GiB, which no bound above this file would allow anyway.
    try testing.expectError(error.LengthTooLarge, readElement(&.{ 0x04, 0x85, 1, 2, 3, 4, 5 }));
    // `0xff` is reserved by X.690 clause 8.1.3.5 c, and it names 127
    // octets, so it lands in the same refusal.
    try testing.expectError(error.LengthTooLarge, readElement(&.{ 0x04, 0xff, 1 }));
}

test "a length that claims more than the buffer is refused, not trusted" {
    // This is the check that has to run before the content slice exists.
    try testing.expectError(error.Truncated, readElement(&.{ 0x04, 0x10, 'a', 'b' }));
    try testing.expectError(error.Truncated, readElement(&.{ 0x04, 0x82, 0xff, 0xff, 'a' }));
    // A long form whose own octets are cut short.
    try testing.expectError(error.Truncated, readElement(&.{ 0x04, 0x83, 0x00 }));
}

test "a length past max_element_bytes is refused whatever the buffer holds" {
    // Four length octets can describe 4 GiB. `max_element_bytes` is the
    // bound that keeps that number from reaching an allocation.
    try testing.expectError(
        error.ElementTooLarge,
        readElement(&.{ 0x04, 0x84, 0xff, 0xff, 0xff, 0xff }),
    );
    // One byte past the bound is still past it.
    const over = max_element_bytes + 1;
    const header = [_]u8{
        0x04,                          0x84,
        @truncate(over >> 24),         @truncate(over >> 16),
        @as(u8, @truncate(over >> 8)), @truncate(over),
    };
    try testing.expectError(error.ElementTooLarge, readElement(&header));
}

test "the multi-byte tag number form is refused by name" {
    try testing.expectError(error.TagTooLarge, readElement(&.{ 0x1f, 0x81, 0x00, 0x00 }));
}

test "a non-minimal long length form is read, because BER allows it" {
    // DER would refuse this and RFC 4511 does not. A decoder that refused
    // it would refuse a legal peer, which is one of the four reasons this
    // file is not `std.crypto.codecs.asn1.der`.
    const e = try readElement(&.{ 0x04, 0x81, 0x03, 'a', 'b', 'c' });
    try testing.expectEqualStrings("abc", e.content);
    try testing.expectEqual(@as(usize, 6), e.total_len);

    const wider = try readElement(&.{ 0x04, 0x84, 0x00, 0x00, 0x00, 0x03, 'a', 'b', 'c' });
    try testing.expectEqualStrings("abc", wider.content);
    try testing.expectEqual(@as(usize, 9), wider.total_len);
}

test "an element of zero length is read and holds nothing" {
    const e = try readElement(&.{ 0x04, 0x00 });
    try testing.expectEqual(@as(usize, 0), e.content.len);
    try testing.expectEqual(@as(usize, 2), e.total_len);
}

test "readElementBounded narrows the bound and never widens it" {
    const bytes = [_]u8{ 0x04, 0x05, 'h', 'e', 'l', 'l', 'o' };
    try testing.expectError(error.ElementTooLarge, readElementBounded(&bytes, 4));
    const e = try readElementBounded(&bytes, 5);
    try testing.expectEqualStrings("hello", e.content);
    // A limit past `max_element_bytes` does not raise the file's own
    // bound.
    try testing.expectError(
        error.ElementTooLarge,
        readElementBounded(&.{ 0x04, 0x84, 0xff, 0xff, 0xff, 0xff }, std.math.maxInt(usize)),
    );
}

test "a cursor walks a container and stops at its end" {
    // `30 08 04 01 61 04 03 62 63 64` is a SEQUENCE of two octet strings.
    const bytes = [_]u8{ 0x30, 0x08, 0x04, 0x01, 'a', 0x04, 0x03, 'b', 'c', 'd' };
    var outer: Cursor = .init(&bytes);
    const seq = try outer.expect(sequence);
    try testing.expect(outer.atEnd());

    var inner = try outer.enter(seq);
    try testing.expectEqual(@as(usize, 1), inner.depth);
    try testing.expectEqualStrings("a", (try inner.expect(octet_string)).content);
    try testing.expectEqualStrings("bcd", (try inner.expect(octet_string)).content);
    try testing.expect(inner.atEnd());
    try testing.expectError(error.Truncated, inner.next());
}

test "a cursor refuses an element whose tag is not the expected one" {
    var c: Cursor = .init(&.{ 0x04, 0x01, 'a' });
    try testing.expectError(error.UnexpectedTag, c.expect(sequence));
}

test "entering a primitive element is refused, so text is never read as tags" {
    // Without this an octet string holding `30 08 ...` would be walked as
    // a container, and a server would choose how many elements a caller
    // saw by writing text.
    var c: Cursor = .init(&.{ 0x04, 0x02, 0x30, 0x00 });
    const e = try c.next();
    try testing.expectError(error.WrongForm, c.enter(e));
}

test "nesting past max_depth is refused, and one level under it is not" {
    // A message of `max_depth + 4` opening headers, each an empty
    // SEQUENCE inside the last. A walker with no bound would follow every
    // one of them.
    const total = max_depth + 4;
    var bytes: [(max_depth + 4) * 2]u8 = undefined;
    for (0..total) |i| {
        bytes[i * 2] = 0x30;
        // Each level holds the two bytes of every level under it.
        bytes[i * 2 + 1] = @intCast((total - i - 1) * 2);
    }

    var c: Cursor = .init(&bytes);
    var level: usize = 0;
    while (level < max_depth) : (level += 1) {
        const e = try c.next();
        c = try c.enter(e);
        try testing.expectEqual(level + 1, c.depth);
    }
    // The next one is one past the bound.
    const deep = try c.next();
    try testing.expectError(error.NestingTooDeep, c.enter(deep));
}

test "integerValue reads the numbers LDAP puts on the wire" {
    // Measured off curl 8.21.0: a message id of 1, a version of 3, a
    // scope of 0, 1, or 2, and a size limit of 0.
    try testing.expectEqual(@as(i64, 0), try integerValue(i64, .{
        .tag = integer,
        .content = &.{0x00},
        .total_len = 3,
    }));
    try testing.expectEqual(@as(i64, 3), try integerValue(i64, .{
        .tag = integer,
        .content = &.{0x03},
        .total_len = 3,
    }));
    try testing.expectEqual(@as(i64, 127), try integerValue(i64, .{
        .tag = integer,
        .content = &.{0x7f},
        .total_len = 3,
    }));
    try testing.expectEqual(@as(i64, 128), try integerValue(i64, .{
        .tag = integer,
        .content = &.{ 0x00, 0x80 },
        .total_len = 4,
    }));
    try testing.expectEqual(@as(i64, -1), try integerValue(i64, .{
        .tag = integer,
        .content = &.{0xff},
        .total_len = 3,
    }));
    try testing.expectEqual(@as(i64, -128), try integerValue(i64, .{
        .tag = integer,
        .content = &.{0x80},
        .total_len = 3,
    }));
    try testing.expectEqual(@as(i64, 65535), try integerValue(i64, .{
        .tag = integer,
        .content = &.{ 0x00, 0xff, 0xff },
        .total_len = 5,
    }));
}

test "an integer with no octets, or too many for the type, is a runtime fault" {
    try testing.expectError(error.ValueOutOfRange, integerValue(i64, .{
        .tag = integer,
        .content = &.{},
        .total_len = 2,
    }));
    // Nine octets of real value do not fit an i64.
    try testing.expectError(error.ValueOutOfRange, integerValue(i64, .{
        .tag = integer,
        .content = &.{ 0x01, 2, 3, 4, 5, 6, 7, 8, 9 },
        .total_len = 11,
    }));
    // Nine octets whose lead is sign padding do fit.
    try testing.expectEqual(@as(i64, 1), try integerValue(i64, .{
        .tag = integer,
        .content = &.{ 0x00, 0, 0, 0, 0, 0, 0, 0, 1 },
        .total_len = 11,
    }));
    // A small type refuses a value it cannot hold.
    try testing.expectError(error.ValueOutOfRange, integerValue(i32, .{
        .tag = integer,
        .content = &.{ 0x01, 0, 0, 0, 0 },
        .total_len = 7,
    }));
}

test "an integer element must be primitive" {
    try testing.expectError(error.WrongForm, integerValue(i64, .{
        .tag = .universal(universal_integer, true),
        .content = &.{0x01},
        .total_len = 3,
    }));
}

test "booleanValue reads both spellings of true that BER allows" {
    try testing.expectEqual(false, try booleanValue(.{
        .tag = boolean,
        .content = &.{0x00},
        .total_len = 3,
    }));
    try testing.expectEqual(true, try booleanValue(.{
        .tag = boolean,
        .content = &.{0xff},
        .total_len = 3,
    }));
    // DER writes only `0xff`. BER allows any non-zero octet, and a peer
    // that writes `0x01` is a peer this reads.
    try testing.expectEqual(true, try booleanValue(.{
        .tag = boolean,
        .content = &.{0x01},
        .total_len = 3,
    }));
    try testing.expectError(error.ValueOutOfRange, booleanValue(.{
        .tag = boolean,
        .content = &.{},
        .total_len = 2,
    }));
    try testing.expectError(error.ValueOutOfRange, booleanValue(.{
        .tag = boolean,
        .content = &.{ 0x00, 0x00 },
        .total_len = 4,
    }));
}

test "the writer builds the anonymous BindRequest curl sends, byte for byte" {
    // Read off curl 8.21.0 through a byte-logging relay to a real slapd
    // 2.6.13:
    //
    //     30 0c 02 01 01 60 07 02 01 03 04 00 80 00
    var w: Writer(512, 8) = .init();
    try w.beginElement(sequence);
    try w.writeInteger(integer, 1);
    try w.beginElement(.application(0, true));
    try w.writeInteger(integer, 3);
    try w.writeElement(octet_string, "");
    try w.writeElement(.context(0, false), "");
    try w.endElement();
    try w.endElement();

    try testing.expect(w.balanced());
    try testing.expectEqualSlices(
        u8,
        &.{ 0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00 },
        w.written(),
    );
}

test "the writer builds the UnbindRequest curl sends, byte for byte" {
    // `30 05 02 01 03 42 00`, read off the same relay.
    var w: Writer(64, 4) = .init();
    try w.beginElement(sequence);
    try w.writeInteger(integer, 3);
    try w.writeElement(.application(2, false), "");
    try w.endElement();
    try testing.expectEqualSlices(
        u8,
        &.{ 0x30, 0x05, 0x02, 0x01, 0x03, 0x42, 0x00 },
        w.written(),
    );
}

test "a container whose content passes 127 bytes gets a wider length field" {
    // The placeholder is one byte, so this is the path where `endElement`
    // moves the content along. The content must survive the move byte for
    // byte.
    var w: Writer(1024, 4) = .init();
    const value = "x" ** 200;
    try w.beginElement(sequence);
    try w.writeElement(octet_string, value);
    try w.endElement();

    const out = w.written();
    // `30 81 cd 04 81 c8 <200 bytes>`
    try testing.expectEqual(@as(u8, 0x30), out[0]);
    try testing.expectEqual(@as(u8, 0x81), out[1]);
    try testing.expectEqual(@as(u8, 203), out[2]);
    try testing.expectEqual(@as(usize, 206), out.len);

    var c: Cursor = .init(out);
    const seq = try c.expect(sequence);
    var inner = try c.enter(seq);
    try testing.expectEqualStrings(value, (try inner.expect(octet_string)).content);
}

test "a container of over 65535 bytes still round-trips through the reader" {
    var w: Writer(200_000, 4) = .init();
    const value = "y" ** 70_000;
    try w.beginElement(sequence);
    try w.writeElement(octet_string, value);
    try w.endElement();

    var c: Cursor = .init(w.written());
    const seq = try c.expect(sequence);
    var inner = try c.enter(seq);
    try testing.expectEqualStrings(value, (try inner.expect(octet_string)).content);
}

test "a writer that runs out of room reports it and writes nothing past the end" {
    var w: Writer(16, 4) = .init();
    try w.beginElement(sequence);
    try testing.expectError(error.NoRoom, w.writeElement(octet_string, "x" ** 32));
    // The capacity is a bound and not a suggestion.
    try testing.expect(w.len <= 16);
}

test "a writer refuses to open more containers than its depth bound" {
    var w: Writer(256, 3) = .init();
    try w.beginElement(sequence);
    try w.beginElement(sequence);
    try w.beginElement(sequence);
    try testing.expectError(error.TooDeep, w.beginElement(sequence));
}

test "closing a container that was never opened is a fault and never a crash" {
    var w: Writer(64, 4) = .init();
    try testing.expectError(error.NothingOpen, w.endElement());
}

test "writeInteger writes the minimal two's complement form X.690 asks for" {
    const Case = struct { value: i64, want: []const u8 };
    const cases = [_]Case{
        .{ .value = 0, .want = &.{ 0x02, 0x01, 0x00 } },
        .{ .value = 1, .want = &.{ 0x02, 0x01, 0x01 } },
        .{ .value = 127, .want = &.{ 0x02, 0x01, 0x7f } },
        .{ .value = 128, .want = &.{ 0x02, 0x02, 0x00, 0x80 } },
        .{ .value = 255, .want = &.{ 0x02, 0x02, 0x00, 0xff } },
        .{ .value = 256, .want = &.{ 0x02, 0x02, 0x01, 0x00 } },
        .{ .value = -1, .want = &.{ 0x02, 0x01, 0xff } },
        .{ .value = -128, .want = &.{ 0x02, 0x01, 0x80 } },
        .{ .value = -129, .want = &.{ 0x02, 0x02, 0xff, 0x7f } },
    };
    for (cases) |case| {
        var w: Writer(64, 2) = .init();
        try w.writeInteger(integer, case.value);
        try testing.expectEqualSlices(u8, case.want, w.written());
        // What goes out must read back as the number that went in.
        var c: Cursor = .init(w.written());
        try testing.expectEqual(case.value, try integerValue(i64, try c.next()));
    }
}

test "writeBoolean writes the one spelling of true that DER also accepts" {
    var w: Writer(16, 2) = .init();
    try w.writeBoolean(boolean, true);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x01, 0xff }, w.written());
    w.reset();
    try w.writeBoolean(boolean, false);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x01, 0x00 }, w.written());
}

test "every length this writer writes is one this reader reads back" {
    // The boundaries of the four length field widths, and one on each
    // side of each of them.
    const lengths = [_]usize{ 0, 1, 126, 127, 128, 129, 254, 255, 256, 257, 65_534, 65_535, 65_536 };
    var storage: [70_000]u8 = undefined;
    for (&storage) |*b| b.* = 'z';

    for (lengths) |length| {
        var w: Writer(80_000, 4) = .init();
        try w.writeElement(octet_string, storage[0..length]);
        const e = try readElement(w.written());
        try testing.expectEqual(length, e.content.len);
        try testing.expectEqual(w.written().len, e.total_len);
        try testing.expectEqualSlices(u8, storage[0..length], e.content);
    }
}

test "reset lets one writer build a second message with nothing of the first left" {
    var w: Writer(128, 4) = .init();
    try w.beginElement(sequence);
    try w.writeElement(octet_string, "first");
    try w.endElement();
    const first_len = w.written().len;

    w.reset();
    try w.beginElement(sequence);
    try w.writeElement(octet_string, "first");
    try w.endElement();
    try testing.expectEqual(first_len, w.written().len);
    try testing.expect(w.balanced());
}
