//! The QPACK decoder: one encoder stream and one encoded field section at
//! a time, out come header fields.
//!
//! This file owns the five field line representations of RFC 9204 section
//! 4.5, the two index forms they use, and the bounds that make a decode
//! safe against the peer that wrote the section. It owns nothing below
//! that: the integers, the strings, the Huffman code, the static table,
//! the dynamic table, the prefix, and the encoder instructions each live
//! in their own file.
//!
//! **One decoder belongs to one connection.** It carries the dynamic table
//! that the peer's encoder stream built. A caller feeds it the encoder
//! stream with `readEncoderStream` and each field section with
//! `decodeSection`, and it answers with the decoder instructions the peer
//! is owed.
//!
//! **This decoder never blocks.** RFC 9204 section 2.1.2 lets a decoder
//! say how many streams may be blocked on a dynamic table entry that has
//! not arrived, and this one says zero. It sends
//! SETTINGS_QPACK_BLOCKED_STREAMS = 0, so a conformant encoder never
//! writes a Required Insert Count larger than what it knows this side has
//! taken in, and a section that does anyway is `error.Blocked` on the
//! spot.
//!
//! That is a client's choice to make, and it costs one round trip of
//! compression: the peer cannot reference an entry until this side has
//! acknowledged it. What it buys is that a field section is decoded or
//! refused by the octets in hand alone. There is no parked stream, no
//! timer, and no state that waits on an encoder stream that may never
//! deliver, so no field section can deadlock behind one.
//!
//! **An encoded field section is untrusted input.** These are the bounds
//! this build puts on one, and each has a test that reaches it:
//!
//! - `header_list_size_max` caps the whole decoded list, counted the way
//!   HTTP/3 counts SETTINGS_MAX_FIELD_SECTION_SIZE. This is what stops a
//!   decompression bomb, where one octet of index repeats a large dynamic
//!   table entry.
//! - `field_count_max` caps how many field lines one section gives back.
//! - The dynamic table's own ceiling caps a Set Dynamic Table Capacity,
//!   and the capacity caps every entry in it.
//! - `Limits.instruction_len_max` caps one encoder instruction.
//! - `integer.continuation_octets_max` caps an integer, and `Truncated`
//!   ends a decode that runs off the end of the section.
//!
//! **Nothing here allocates without a bound.** The list, and every name
//! and value in it, together stay under `header_list_size_max`. The
//! dynamic table stays under its own capacity. A string is refused against
//! the budget that is left before it is copied, so a length the peer wrote
//! never sizes an allocation on its own.

const std = @import("std");

const DynamicTable = @import("DynamicTable.zig");
const decoder_stream = @import("decoder_stream.zig");
const encoder_stream = @import("encoder_stream.zig");
const field = @import("field.zig");
const integer = @import("integer.zig");
const prefix = @import("prefix.zig");
const static_table = @import("static_table.zig");
const string = @import("string.zig");

const Allocator = std.mem.Allocator;
const Decoder = @This();

/// The largest decoded field section this build returns, in bytes.
///
/// The count is the sum of `Field.size` over the list, which is the name,
/// the value, and 32 bytes for each field line. That is the arithmetic of
/// SETTINGS_MAX_FIELD_SECTION_SIZE in RFC 9114 section 7.2.4.1, so a
/// caller can advertise this number and mean it.
///
/// **This is the bound that stops a decompression bomb.** A dynamic table
/// entry can be four kilobytes, and one octet of the section can name it,
/// so a short section would otherwise expand without limit. 64 KiB is far
/// more head than a real server sends, and it caps the expansion of a full
/// table at about a thousand to one.
pub const header_list_size_max: usize = 64 * 1024;

/// How many field lines one section may decode to.
///
/// `header_list_size_max` already bounds this at 2048, because a field
/// line costs at least 32 bytes. This is the tighter answer: a real
/// response carries tens of field lines, and a section with hundreds is a
/// peer spending this side's time rather than saying anything.
pub const field_count_max: usize = 256;

/// How many streams this side lets a peer block on the dynamic table.
///
/// Zero. See the note at the top of this file for what that buys and what
/// it costs. It is a constant and not an option, because a larger number
/// would need a decoder that can park a field section and wake it, and
/// this one cannot.
pub const blocked_streams_max: u64 = 0;

/// Every fault a decode can report.
///
/// The set is written out rather than built from the sets below it,
/// because it is the whole surface a caller has to handle and it belongs
/// in one place. `string.StringTooLong` is not here on purpose: the only
/// bound this file gives a string decode is the field section budget, so
/// that fault reaches a caller as `HeaderListTooLarge`.
pub const Error = error{
    /// The section ended in the middle of a representation.
    Truncated,
    /// An integer names a value larger than this build holds.
    IntegerOverflow,
    /// An integer continued past `integer.continuation_octets_max`.
    IntegerTooLong,
    /// A Huffman string has more than seven bits of pad.
    HuffmanPadTooLong,
    /// A Huffman string has a pad that is not the top of the EOS code.
    HuffmanPadInvalid,
    /// A Huffman string carries the EOS symbol.
    HuffmanEosSymbol,
    /// The folded Required Insert Count is one no conformant encoder could
    /// have written.
    InvalidRequiredInsertCount,
    /// The Base would fall below zero, or past the integer ceiling.
    InvalidBase,
    /// The section names a dynamic table entry this side has not taken in
    /// yet. This decoder sets SETTINGS_QPACK_BLOCKED_STREAMS to zero, so a
    /// conformant encoder never asks for this.
    Blocked,
    /// A representation named a static index the table does not hold.
    InvalidStaticIndex,
    /// A relative index counted back past the Base, or named an entry that
    /// was evicted. RFC 9204 section 2.2.3.
    InvalidDynamicIndex,
    /// A post-base index named an entry at or past the Required Insert
    /// Count.
    InvalidPostBaseIndex,
    /// The decoded field section reaches `Options.header_list_size_max`.
    HeaderListTooLarge,
    /// The section holds more than `Options.field_count_max` field lines.
    TooManyHeaderFields,
    /// One encoder instruction ran past `Limits.instruction_len_max`.
    InstructionTooLong,
    /// Set Dynamic Table Capacity named a size above the one this side
    /// agreed to.
    TableCapacityTooLarge,
    /// An insert named an entry larger than the table capacity.
    EntryTooLarge,
    /// The table has held as many inserts as this build counts.
    TableInsertCountOverflow,
    OutOfMemory,
};

/// The bounds one decoder works to.
pub const Options = struct {
    /// The largest dynamic table this side lets the peer use, which is
    /// what this side sends as SETTINGS_QPACK_MAX_TABLE_CAPACITY. Zero is
    /// the RFC's own default for the setting, and it means the peer may
    /// not insert at all. This build offers the same 4096 that HTTP/2
    /// offers for HPACK.
    table_capacity_max: DynamicTable.CapacityMax = 4096,
    /// The bound on one decoded field section, in bytes.
    header_list_size_max: usize = Decoder.header_list_size_max,
    /// The bound on how many field lines one section gives back.
    field_count_max: usize = Decoder.field_count_max,
};

table: DynamicTable,
limits: Options,
/// The peer's Known Received Count, RFC 9204 section 2.1.4: how many
/// inserts this side has already told the peer about, whether by an
/// Insert Count Increment or by a Section Acknowledgment.
reported_inserts: u64 = 0,

pub fn init(options: Options) Decoder {
    std.debug.assert(options.header_list_size_max >= field.entry_overhead);
    std.debug.assert(options.field_count_max >= 1);
    return .{
        .table = .init(.{ .capacity_max = options.table_capacity_max }),
        .limits = options,
    };
}

pub fn deinit(self: *Decoder, gpa: Allocator) void {
    self.table.deinit(gpa);
    self.* = undefined;
}

/// Reads whole encoder instructions from the front of `bytes`, and returns
/// how many octets it used.
///
/// What is left over is a part instruction. The caller keeps it and hands
/// it back with the octets that follow. This never waits: a peer that
/// stops part way through an instruction stalls its own stream and no
/// field section on any other.
pub fn readEncoderStream(self: *Decoder, gpa: Allocator, bytes: []const u8) Error!usize {
    const limits: encoder_stream.Limits = .forCapacity(self.limits.table_capacity_max);
    return encoder_stream.apply(gpa, &self.table, bytes, limits);
}

/// The Insert Count Increment the peer is owed, or null when it is owed
/// none, RFC 9204 section 4.4.3.
///
/// Taking it moves the Known Received Count, so a caller that takes one
/// and drops it leaves the peer behind for good. Take it only when the
/// instruction is going out.
pub fn takeInsertCountIncrement(self: *Decoder) ?decoder_stream.Instruction {
    if (self.table.inserted == self.reported_inserts) return null;
    const increment = self.table.inserted - self.reported_inserts;
    self.reported_inserts = self.table.inserted;
    return .{ .insert_count_increment = increment };
}

/// The Section Acknowledgment for a section this side finished, or null
/// when the section named no dynamic entry, RFC 9204 section 4.4.1.
///
/// A Required Insert Count of zero gets no acknowledgment, which is what
/// the RFC says. Any other one also moves the Known Received Count, so an
/// acknowledgment takes the place of an Insert Count Increment for every
/// entry the section needed. Take it only when the instruction is going
/// out.
///
/// One section gets one acknowledgment. The section is taken by pointer so
/// that this function can mark it, because RFC 9204 section 4.4.1 makes a
/// second acknowledgment for a section the encoder already closed a
/// QPACK_DECODER_STREAM_ERROR, and that error is one this side would be
/// aiming at its own peer.
pub fn takeSectionAcknowledgment(
    self: *Decoder,
    stream_id: u64,
    section: *Section,
) ?decoder_stream.Instruction {
    if (section.required_insert_count == 0) return null;
    if (section.acknowledged) return null;
    section.acknowledged = true;
    if (section.required_insert_count > self.reported_inserts) {
        self.reported_inserts = section.required_insert_count;
    }
    return .{ .section_acknowledgment = stream_id };
}

/// The Stream Cancellation for a stream this side gave up on, RFC 9204
/// section 4.4.2.
///
/// It reports no entry, so it moves no count. It only tells the peer that
/// the references that section held are gone.
pub fn streamCancellation(stream_id: u64) decoder_stream.Instruction {
    return .{ .stream_cancellation = stream_id };
}

/// One decoded field section.
pub const Section = struct {
    /// The field lines, in the order the peer wrote them.
    list: field.List,
    /// The Required Insert Count the prefix carried. RFC 9204 section
    /// 4.4.1: the peer is owed a Section Acknowledgment when this is above
    /// zero.
    required_insert_count: u64,
    /// The Base the prefix carried.
    base: u64,
    /// Whether `takeSectionAcknowledgment` has already given this
    /// section's acknowledgment out. One section owes the peer one
    /// acknowledgment and no more.
    acknowledged: bool = false,

    pub fn deinit(self: *Section, gpa: Allocator) void {
        self.list.deinit(gpa);
        self.* = undefined;
    }
};

/// Decodes one encoded field section into a list the caller owns.
///
/// The dynamic table is not changed by this call. RFC 9204 section 4.5
/// says a field line representation reads the tables and never writes
/// them, which is what lets a section be decoded whole or refused whole.
pub fn decodeSection(self: *Decoder, gpa: Allocator, section: []const u8) Error!Section {
    const head = try prefix.decode(section, self.table.inserted, self.table.maxEntries());

    // RFC 9204 section 2.1.2. This side allows no blocked stream, so a
    // section that names an entry this side has not taken in is refused
    // here rather than parked.
    if (head.prefix.required_insert_count > self.table.inserted) return error.Blocked;

    var list: field.List = .empty;
    errdefer list.deinit(gpa);

    var pos = head.len;
    while (pos < section.len) {
        const first = section[pos];
        if (first & 0x80 != 0) {
            // RFC 9204 section 4.5.2, indexed field line.
            const index = try integer.decode(6, section[pos..]);
            pos += index.len;
            const entry = try self.lookup(head.prefix, index.value, first & 0x40 != 0);
            try self.emit(gpa, &list, entry.name, entry.value, false);
        } else if (first & 0x40 != 0) {
            // RFC 9204 section 4.5.4, literal field line with name
            // reference.
            pos += try self.literal(gpa, &list, section[pos..], head.prefix, .name_reference);
        } else if (first & 0x20 != 0) {
            // RFC 9204 section 4.5.6, literal field line with literal
            // name.
            pos += try self.literal(gpa, &list, section[pos..], head.prefix, .literal_name);
        } else if (first & 0x10 != 0) {
            // RFC 9204 section 4.5.3, indexed field line with post-base
            // index.
            const index = try integer.decode(4, section[pos..]);
            pos += index.len;
            const entry = try self.postBase(head.prefix, index.value);
            try self.emit(gpa, &list, entry.name, entry.value, false);
        } else {
            // RFC 9204 section 4.5.5, literal field line with post-base
            // name reference.
            pos += try self.literal(gpa, &list, section[pos..], head.prefix, .post_base_name);
        }
    }

    return .{
        .list = list,
        .required_insert_count = head.prefix.required_insert_count,
        .base = head.prefix.base,
    };
}

/// Which of the three literal representations one field line is.
const Literal = enum {
    /// RFC 9204 section 4.5.4. '01', the N bit, the T bit, and a 4-bit
    /// name index.
    name_reference,
    /// RFC 9204 section 4.5.5. '0000', the N bit, and a 3-bit post-base
    /// name index.
    post_base_name,
    /// RFC 9204 section 4.5.6. '001', the N bit, and a 4-bit prefix name
    /// string.
    literal_name,
};

/// Reads one literal field line from the front of `bytes`, and returns how
/// many octets it used.
fn literal(
    self: *Decoder,
    gpa: Allocator,
    list: *field.List,
    bytes: []const u8,
    head: prefix.Prefix,
    kind: Literal,
) Error!usize {
    std.debug.assert(bytes.len > 0);
    const never_indexed = switch (kind) {
        .name_reference => bytes[0] & 0x20 != 0,
        .post_base_name => bytes[0] & 0x08 != 0,
        .literal_name => bytes[0] & 0x10 != 0,
    };

    // The name may take the whole of what is left of the list, less the 32
    // bytes the field line costs whatever it holds. The value gets
    // whatever the name leaves.
    const budget = try self.remaining(list.*);

    var pos: usize = 0;
    var name: []const u8 = undefined;
    var owned_name: ?[]u8 = null;
    defer if (owned_name) |text| gpa.free(text);

    switch (kind) {
        .name_reference => {
            const index = try integer.decode(4, bytes);
            pos = index.len;
            // Borrowed from a table. `emit` copies it, and nothing here
            // changes the dynamic table, so it stays valid.
            name = (try self.lookup(head, index.value, bytes[0] & 0x10 != 0)).name;
        },
        .post_base_name => {
            const index = try integer.decode(3, bytes);
            pos = index.len;
            name = (try self.postBase(head, index.value)).name;
        },
        .literal_name => {
            const decoded = try decodeString(4, gpa, bytes, budget);
            owned_name = decoded.text;
            name = decoded.text;
            pos = decoded.len;
        },
    }
    if (name.len > budget) return error.HeaderListTooLarge;

    const value = try decodeString(8, gpa, bytes[pos..], budget - name.len);
    defer gpa.free(value.text);
    pos += value.len;

    try self.emit(gpa, list, name, value.text, never_indexed);
    return pos;
}

/// Reads one string literal, and reports a string past `budget` as what it
/// is: the field section reaching its bound.
fn decodeString(
    comptime prefix_bits: u4,
    gpa: Allocator,
    bytes: []const u8,
    budget: usize,
) Error!string.Decoded {
    return string.decode(prefix_bits, gpa, bytes, budget) catch |err| switch (err) {
        error.StringTooLong => error.HeaderListTooLarge,
        else => |other| other,
    };
}

/// Puts one field line into `list`.
///
/// `name` and `value` are borrowed, and the copies are what the list
/// keeps, so a decoded field line stays right after a later encoder
/// instruction empties the table.
fn emit(
    self: *Decoder,
    gpa: Allocator,
    list: *field.List,
    name: []const u8,
    value: []const u8,
    never_indexed: bool,
) Error!void {
    if (list.fields.items.len >= self.limits.field_count_max) return error.TooManyHeaderFields;
    const budget = try self.remaining(list.*);
    if (name.len + value.len > budget) return error.HeaderListTooLarge;

    const name_copy = try gpa.dupe(u8, name);
    errdefer gpa.free(name_copy);
    const value_copy = try gpa.dupe(u8, value);
    errdefer gpa.free(value_copy);

    try list.append(gpa, name_copy, value_copy, never_indexed);
}

/// How many octets of name and value one more field line may carry.
fn remaining(self: Decoder, list: field.List) Error!usize {
    const spent = list.size + field.entry_overhead;
    if (spent > self.limits.header_list_size_max) return error.HeaderListTooLarge;
    return self.limits.header_list_size_max - spent;
}

/// The entry an indexed or a name reference names, RFC 9204 sections 4.5.2
/// and 4.5.4.
///
/// A static index is the index itself. A dynamic index is relative to the
/// Base: RFC 9204 section 3.2.5 says a relative index of 0 is the entry
/// whose absolute index is Base - 1.
fn lookup(self: Decoder, head: prefix.Prefix, index: u64, static: bool) Error!static_table.Entry {
    if (static) return static_table.get(index) orelse error.InvalidStaticIndex;

    if (index >= head.base) return error.InvalidDynamicIndex;
    const absolute = head.base - index - 1;
    return self.dynamic(head, absolute);
}

/// The entry a post-base index names, RFC 9204 sections 3.2.6, 4.5.3, and
/// 4.5.5.
///
/// A post-base index of 0 is the entry whose absolute index is the Base,
/// and the numbers run the same way as the absolute index from there.
fn postBase(self: Decoder, head: prefix.Prefix, index: u64) Error!static_table.Entry {
    const absolute = std.math.add(u64, head.base, index) catch
        return error.InvalidPostBaseIndex;
    // RFC 9204 section 2.2.3: a reference at or past the Required Insert
    // Count is a fault whatever the table holds, because the encoder
    // promised the section needed no more than that.
    if (absolute >= head.required_insert_count) return error.InvalidPostBaseIndex;
    const entry = self.table.get(absolute) orelse return error.InvalidPostBaseIndex;
    return .{ .name = entry.name, .value = entry.value };
}

/// The live dynamic entry at `absolute`, checked against the Required
/// Insert Count first.
///
/// RFC 9204 section 2.2.3: a reference at or past the Required Insert
/// Count is a fault, whatever the table happens to hold, because the
/// encoder promised the section needed no more than that.
fn dynamic(self: Decoder, head: prefix.Prefix, absolute: u64) Error!static_table.Entry {
    if (absolute >= head.required_insert_count) return error.InvalidDynamicIndex;
    const entry = self.table.get(absolute) orelse return error.InvalidDynamicIndex;
    return .{ .name = entry.name, .value = entry.value };
}

const testing = std.testing;

/// Decodes one section with a fresh decoder, for a test that needs no
/// dynamic table state carried in.
fn decodeOnce(gpa: Allocator, section: []const u8) Error!Section {
    var decoder: Decoder = .init(.{});
    defer decoder.deinit(gpa);
    return decoder.decodeSection(gpa, section);
}

/// A decoder holding the four entries RFC 9204 Appendix B builds, on the
/// 220 byte table the appendix sets.
fn exampleDecoder(gpa: Allocator) !Decoder {
    var decoder: Decoder = .init(.{ .table_capacity_max = 220 });
    errdefer decoder.deinit(gpa);

    const stream = [_]u8{ 0x3f, 0xbd, 0x01 } ++
        [_]u8{ 0xc0, 0x0f } ++ "www.example.com".* ++
        [_]u8{ 0xc1, 0x0c } ++ "/sample/path".* ++
        [_]u8{0x4a} ++ "custom-key".* ++ [_]u8{0x0c} ++ "custom-value".* ++
        [_]u8{0x02};
    const used = try decoder.readEncoderStream(gpa, &stream);
    std.debug.assert(used == stream.len);
    return decoder;
}

test "an indexed field line names a static entry" {
    const gpa = testing.allocator;
    var section = try decodeOnce(gpa, &.{ 0x00, 0x00, 0xd1 });
    defer section.deinit(gpa);

    try testing.expectEqual(@as(usize, 1), section.list.fields.items.len);
    try testing.expectEqualStrings(":method", section.list.fields.items[0].name);
    try testing.expectEqualStrings("GET", section.list.fields.items[0].value);
    try testing.expectEqual(@as(u64, 0), section.required_insert_count);
}

test "static index 0 is a real entry, unlike HPACK" {
    const gpa = testing.allocator;
    var section = try decodeOnce(gpa, &.{ 0x00, 0x00, 0xc0 });
    defer section.deinit(gpa);

    try testing.expectEqualStrings(":authority", section.list.fields.items[0].name);
    try testing.expectEqualStrings("", section.list.fields.items[0].value);
}

test "a static index past the table is a fault, in every representation" {
    const gpa = testing.allocator;
    // Indexed field line, static index 99.
    try testing.expectError(
        error.InvalidStaticIndex,
        decodeOnce(gpa, &.{ 0x00, 0x00, 0xff, 0x24 }),
    );
    // Literal field line with name reference, static index 99.
    try testing.expectError(
        error.InvalidStaticIndex,
        decodeOnce(gpa, &.{ 0x00, 0x00, 0x5f, 0x54, 0x00 }),
    );
    // A very large index, spread over a continuation.
    try testing.expectError(
        error.InvalidStaticIndex,
        decodeOnce(gpa, &.{ 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x0f }),
    );
}

test "a dynamic index in a section that names no dynamic entry is a fault" {
    const gpa = testing.allocator;
    // Required Insert Count 0 and Base 0, then a relative index of 0,
    // which counts back past the Base.
    try testing.expectError(
        error.InvalidDynamicIndex,
        decodeOnce(gpa, &.{ 0x00, 0x00, 0x80 }),
    );
    // The same for a name reference.
    try testing.expectError(
        error.InvalidDynamicIndex,
        decodeOnce(gpa, &.{ 0x00, 0x00, 0x40, 0x00 }),
    );
    // And for a post-base index, which points the other way.
    try testing.expectError(
        error.InvalidPostBaseIndex,
        decodeOnce(gpa, &.{ 0x00, 0x00, 0x10 }),
    );
    try testing.expectError(
        error.InvalidPostBaseIndex,
        decodeOnce(gpa, &.{ 0x00, 0x00, 0x00, 0x00 }),
    );
}

test "a relative index that counts back past the Base is a fault" {
    const gpa = testing.allocator;
    var decoder = try exampleDecoder(gpa);
    defer decoder.deinit(gpa);

    // Required Insert Count 4, Base 4. Relative index 3 is absolute 0, and
    // relative index 4 counts back past the Base.
    var good = try decoder.decodeSection(gpa, &.{ 0x05, 0x00, 0x83 });
    defer good.deinit(gpa);
    try testing.expectEqualStrings(":authority", good.list.fields.items[0].name);

    try testing.expectError(
        error.InvalidDynamicIndex,
        decoder.decodeSection(gpa, &.{ 0x05, 0x00, 0x84 }),
    );
    try testing.expectError(
        error.InvalidDynamicIndex,
        decoder.decodeSection(gpa, &.{ 0x05, 0x00, 0xbf, 0xff, 0xff, 0xff, 0x0f }),
    );
}

test "a post-base index at or past the Required Insert Count is a fault" {
    const gpa = testing.allocator;
    var decoder = try exampleDecoder(gpa);
    defer decoder.deinit(gpa);

    // Required Insert Count 4, Base 2, so post-base 0 and 1 are absolute 2
    // and 3, and post-base 2 would be absolute 4.
    var good = try decoder.decodeSection(gpa, &.{ 0x05, 0x81, 0x10, 0x11 });
    defer good.deinit(gpa);
    try testing.expectEqualStrings("custom-key", good.list.fields.items[0].name);
    try testing.expectEqualStrings(":authority", good.list.fields.items[1].name);

    try testing.expectError(
        error.InvalidPostBaseIndex,
        decoder.decodeSection(gpa, &.{ 0x05, 0x81, 0x12 }),
    );
    // A post-base index large enough to run the addition past the integer
    // ceiling.
    try testing.expectError(
        error.InvalidPostBaseIndex,
        decoder.decodeSection(gpa, &.{ 0x05, 0x81, 0x1f, 0xff, 0xff, 0xff, 0xff, 0x7f }),
    );
}

test "a reference to an evicted entry is a fault" {
    const gpa = testing.allocator;
    var decoder = try exampleDecoder(gpa);
    defer decoder.deinit(gpa);

    // RFC 9204 B.5 evicts absolute index 0.
    const stream = [_]u8{ 0x81, 0x0d } ++ "custom-value2".*;
    _ = try decoder.readEncoderStream(gpa, &stream);
    try testing.expectEqual(@as(u64, 1), decoder.table.dropped);

    // Required Insert Count 5, Base 5, relative index 4 is absolute 0.
    try testing.expectError(
        error.InvalidDynamicIndex,
        decoder.decodeSection(gpa, &.{ 0x06, 0x00, 0x84 }),
    );
}

test "a section that needs more inserts than this side has taken in is refused" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{ .table_capacity_max = 220 });
    defer decoder.deinit(gpa);
    _ = try decoder.readEncoderStream(gpa, &.{ 0x3f, 0xbd, 0x01 });

    // The encoder stream has not arrived, so this side has no entry. RFC
    // 9204 section 2.1.2: this decoder allows no blocked stream, so the
    // section is refused rather than parked.
    try testing.expectError(error.Blocked, decoder.decodeSection(gpa, &.{ 0x03, 0x81, 0x10 }));

    // The same section decodes once the encoder stream catches up.
    const stream = [_]u8{ 0xc0, 0x0f } ++ "www.example.com".* ++
        [_]u8{ 0xc1, 0x0c } ++ "/sample/path".*;
    _ = try decoder.readEncoderStream(gpa, &stream);

    var section = try decoder.decodeSection(gpa, &.{ 0x03, 0x81, 0x10 });
    defer section.deinit(gpa);
    try testing.expectEqualStrings("www.example.com", section.list.fields.items[0].value);
}

test "a Blocked section leaves the decoder able to take the next one" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{ .table_capacity_max = 220 });
    defer decoder.deinit(gpa);

    try testing.expectError(error.Blocked, decoder.decodeSection(gpa, &.{ 0x03, 0x81, 0x10 }));

    // A section that names no dynamic entry is decoded whatever came
    // before it, because a field line representation changes no table.
    var section = try decoder.decodeSection(gpa, &.{ 0x00, 0x00, 0xd1 });
    defer section.deinit(gpa);
    try testing.expectEqualStrings("GET", section.list.fields.items[0].value);
}

test "the N bit comes back on the field line it was written on" {
    const gpa = testing.allocator;
    // Literal field line with name reference, N set, static index 4, which
    // is content-length.
    var named = try decodeOnce(gpa, &.{ 0x00, 0x00, 0x74, 0x01, '7' });
    defer named.deinit(gpa);
    try testing.expect(named.list.fields.items[0].never_indexed);
    try testing.expectEqualStrings("content-length", named.list.fields.items[0].name);

    // Literal field line with literal name, N set. 0x37 is '001', the N
    // bit, H = 0, and a name length that fills the three bits under the
    // flag, so the rest of the eight follows in one more octet.
    const literal_name = [_]u8{ 0x00, 0x00, 0x37, 0x01 } ++ "password".* ++
        [_]u8{0x06} ++ "secret".*;
    var literal_field = try decodeOnce(gpa, &literal_name);
    defer literal_field.deinit(gpa);
    try testing.expect(literal_field.list.fields.items[0].never_indexed);
    try testing.expectEqualStrings("password", literal_field.list.fields.items[0].name);
    try testing.expectEqualStrings("secret", literal_field.list.fields.items[0].value);

    // The same two without the N bit.
    var plain = try decodeOnce(gpa, &.{ 0x00, 0x00, 0x54, 0x01, '7' });
    defer plain.deinit(gpa);
    try testing.expect(!plain.list.fields.items[0].never_indexed);
}

test "a post-base name reference carries its own N bit" {
    const gpa = testing.allocator;
    var decoder = try exampleDecoder(gpa);
    defer decoder.deinit(gpa);

    // Required Insert Count 4, Base 2. 0x08 is '0000', N set, post-base
    // name index 0, which is absolute 2, custom-key.
    var section = try decoder.decodeSection(gpa, &.{ 0x05, 0x81, 0x08, 0x03, 'n', 'e', 'w' });
    defer section.deinit(gpa);

    try testing.expectEqualStrings("custom-key", section.list.fields.items[0].name);
    try testing.expectEqualStrings("new", section.list.fields.items[0].value);
    try testing.expect(section.list.fields.items[0].never_indexed);

    // And without it.
    var plain = try decoder.decodeSection(gpa, &.{ 0x05, 0x81, 0x00, 0x03, 'n', 'e', 'w' });
    defer plain.deinit(gpa);
    try testing.expect(!plain.list.fields.items[0].never_indexed);
}

test "a section with a prefix and nothing after it decodes to an empty list" {
    const gpa = testing.allocator;
    var section = try decodeOnce(gpa, &.{ 0x00, 0x00 });
    defer section.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), section.list.fields.items.len);
    try testing.expectEqual(@as(usize, 0), section.list.size);
}

test "a section that ends in the middle of a representation is truncated" {
    const gpa = testing.allocator;
    try testing.expectError(error.Truncated, decodeOnce(gpa, &.{}));
    try testing.expectError(error.Truncated, decodeOnce(gpa, &.{0x00}));
    try testing.expectError(error.Truncated, decodeOnce(gpa, &.{ 0x00, 0x00, 0x54 }));
    try testing.expectError(error.Truncated, decodeOnce(gpa, &.{ 0x00, 0x00, 0x54, 0x03, 'a' }));
    try testing.expectError(error.Truncated, decodeOnce(gpa, &.{ 0x00, 0x00, 0x3f }));
}

test "a decoded field line survives the encoder instruction that evicts it" {
    const gpa = testing.allocator;
    var decoder = try exampleDecoder(gpa);
    defer decoder.deinit(gpa);

    var section = try decoder.decodeSection(gpa, &.{ 0x05, 0x00, 0x83 });
    defer section.deinit(gpa);
    try testing.expectEqualStrings(":authority", section.list.fields.items[0].name);

    const stream = [_]u8{ 0x81, 0x0d } ++ "custom-value2".*;
    _ = try decoder.readEncoderStream(gpa, &stream);
    try testing.expectEqual(@as(?DynamicTable.Entry, null), decoder.table.get(0));

    try testing.expectEqualStrings(":authority", section.list.fields.items[0].name);
    try testing.expectEqualStrings("www.example.com", section.list.fields.items[0].value);
}

test "a field section past the byte bound is refused" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{ .header_list_size_max = 100 });
    defer decoder.deinit(gpa);

    // A literal field line with a literal name of one octet and no value
    // costs 33 bytes. Three fit in 100 and four do not.
    const one = [_]u8{ 0x21, 'a', 0x00 };
    var section = try decoder.decodeSection(gpa, &([_]u8{ 0x00, 0x00 } ++ one ** 3));
    defer section.deinit(gpa);
    try testing.expectEqual(@as(usize, 99), section.list.size);

    try testing.expectError(
        error.HeaderListTooLarge,
        decoder.decodeSection(gpa, &([_]u8{ 0x00, 0x00 } ++ one ** 4)),
    );
}

test "one long string is refused against the same byte bound" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{ .header_list_size_max = 100 });
    defer decoder.deinit(gpa);

    // The budget for one field line is 100 less the 32 bytes of overhead.
    // A name of 60 leaves 8, which a value of 20 does not fit.
    const split = [_]u8{ 0x00, 0x00, 0x27, 53 } ++ [_]u8{'a'} ** 60 ++
        [_]u8{20} ++ [_]u8{'b'} ** 20;
    try testing.expectError(error.HeaderListTooLarge, decoder.decodeSection(gpa, &split));

    // A name of 200 is past the whole budget on its own.
    const single = [_]u8{ 0x00, 0x00, 0x27, 0xc1, 0x01 } ++ [_]u8{'a'} ** 200 ++ [_]u8{0};
    try testing.expectError(error.HeaderListTooLarge, decoder.decodeSection(gpa, &single));
}

test "a field section past the field count is refused" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{ .field_count_max = 4 });
    defer decoder.deinit(gpa);

    var section = try decoder.decodeSection(gpa, &([_]u8{ 0x00, 0x00 } ++ [_]u8{0xd1} ** 4));
    defer section.deinit(gpa);
    try testing.expectEqual(@as(usize, 4), section.list.fields.items.len);

    try testing.expectError(
        error.TooManyHeaderFields,
        decoder.decodeSection(gpa, &([_]u8{ 0x00, 0x00 } ++ [_]u8{0xd1} ** 5)),
    );
}

test "a decompression bomb stops at the byte bound" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{
        .table_capacity_max = 4096,
        .header_list_size_max = 64 * 1024,
        .field_count_max = 4096,
    });
    defer decoder.deinit(gpa);

    // One dynamic table entry of 4033 bytes, from about 4 KiB of encoder
    // stream.
    var seed: std.ArrayList(u8) = .empty;
    defer seed.deinit(gpa);
    try seed.appendSlice(gpa, &.{ 0x3f, 0xe1, 0x1f });
    try seed.appendSlice(gpa, &.{ 0x41, 'a', 0x7f, 0xa1, 0x1e });
    try seed.appendSlice(gpa, &([_]u8{'x'} ** 4000));
    _ = try decoder.readEncoderStream(gpa, seed.items);
    try testing.expectEqual(@as(usize, 4033), decoder.table.size);

    // Required Insert Count 1, Base 1, then 200 octets of relative index
    // 0. That would name 200 field lines of 4033 bytes, about 800 KiB out
    // of 200 octets in. The bound stops it well before that.
    var bomb: std.ArrayList(u8) = .empty;
    defer bomb.deinit(gpa);
    try bomb.appendSlice(gpa, &.{ 0x02, 0x00 });
    try bomb.appendSlice(gpa, &([_]u8{0x80} ** 200));

    try testing.expectError(error.HeaderListTooLarge, decoder.decodeSection(gpa, bomb.items));
}

test "an integer that never ends is refused, whichever representation carries it" {
    const gpa = testing.allocator;
    const forever = [_]u8{0x80} ** 32;
    inline for ([_]u8{ 0xff, 0x7f, 0x3f, 0x1f, 0x0f }) |first| {
        try testing.expectError(
            error.IntegerTooLong,
            decodeOnce(gpa, &([_]u8{ 0x00, 0x00, first } ++ forever)),
        );
    }
    // And the two integers of the prefix itself.
    try testing.expectError(error.IntegerTooLong, decodeOnce(gpa, &([_]u8{0xff} ++ forever)));
    try testing.expectError(
        error.IntegerTooLong,
        decodeOnce(gpa, &([_]u8{ 0x00, 0xff } ++ forever)),
    );
}

test "an index larger than this build holds is refused before it wraps" {
    const gpa = testing.allocator;
    const over = [_]u8{ 0x00, 0x00, 0xff, 0xff } ++ [_]u8{0xff} ** 7 ++ [_]u8{0x7f};
    try testing.expectError(error.IntegerOverflow, decodeOnce(gpa, &over));
}

test "a Huffman fault in a field section reaches the caller by name" {
    const gpa = testing.allocator;
    // A literal field line with a static name reference and a Huffman
    // value that carries the EOS symbol.
    try testing.expectError(
        error.HuffmanEosSymbol,
        decodeOnce(gpa, &.{ 0x00, 0x00, 0x54, 0x84, 0xff, 0xff, 0xff, 0xff }),
    );
    try testing.expectError(
        error.HuffmanPadInvalid,
        decodeOnce(gpa, &.{ 0x00, 0x00, 0x54, 0x81, 0b00000_110 }),
    );
    try testing.expectError(
        error.HuffmanPadTooLong,
        decodeOnce(gpa, &.{ 0x00, 0x00, 0x54, 0x82, 0x07, 0xff }),
    );
}

test "a prefix fault reaches the caller by name" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{ .table_capacity_max = 220 });
    defer decoder.deinit(gpa);

    // A folded Required Insert Count above twice MaxEntries.
    try testing.expectError(
        error.InvalidRequiredInsertCount,
        decoder.decodeSection(gpa, &.{ 0x0d, 0x00 }),
    );
    // A Base that would fall below zero.
    _ = try decoder.readEncoderStream(gpa, &.{ 0x3f, 0xbd, 0x01 });
    const stream = [_]u8{ 0xc0, 0x0f } ++ "www.example.com".*;
    _ = try decoder.readEncoderStream(gpa, &stream);
    try testing.expectError(error.InvalidBase, decoder.decodeSection(gpa, &.{ 0x02, 0x81 }));
}

test "the encoder stream and the field section are read apart from each other" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{ .table_capacity_max = 220 });
    defer decoder.deinit(gpa);

    // Half an instruction arrives. Nothing waits for the rest, and a field
    // section that needs no dynamic entry still decodes.
    const head = [_]u8{ 0x3f, 0xbd, 0x01 } ++ [_]u8{ 0xc0, 0x0f } ++ "www.exam".*;
    const used = try decoder.readEncoderStream(gpa, &head);
    try testing.expectEqual(@as(usize, 3), used);

    var section = try decoder.decodeSection(gpa, &.{ 0x00, 0x00, 0xd1 });
    defer section.deinit(gpa);
    try testing.expectEqualStrings("GET", section.list.fields.items[0].value);

    // The rest arrives, and the entry lands. What the first call did not
    // take is handed back in front of the octets that follow.
    const rest = [_]u8{ 0xc0, 0x0f } ++ "www.example.com".*;
    try testing.expectEqual(@as(usize, rest.len), try decoder.readEncoderStream(gpa, &rest));
    try testing.expectEqualStrings("www.example.com", decoder.table.get(0).?.value);
}

test "the insert count increment counts what arrived and clears when it is taken" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{ .table_capacity_max = 220 });
    defer decoder.deinit(gpa);

    const none: ?decoder_stream.Instruction = null;
    try testing.expectEqual(none, decoder.takeInsertCountIncrement());

    // Set Dynamic Table Capacity inserts nothing, so it reports nothing.
    _ = try decoder.readEncoderStream(gpa, &.{ 0x3f, 0xbd, 0x01 });
    try testing.expectEqual(none, decoder.takeInsertCountIncrement());

    const stream = [_]u8{ 0xc0, 0x0f } ++ "www.example.com".* ++
        [_]u8{ 0xc1, 0x0c } ++ "/sample/path".*;
    _ = try decoder.readEncoderStream(gpa, &stream);

    try testing.expectEqual(
        @as(?decoder_stream.Instruction, .{ .insert_count_increment = 2 }),
        decoder.takeInsertCountIncrement(),
    );
    try testing.expectEqual(none, decoder.takeInsertCountIncrement());
}

test "a section acknowledgment reports the entries the section needed" {
    const gpa = testing.allocator;
    var decoder = try exampleDecoder(gpa);
    defer decoder.deinit(gpa);
    try testing.expectEqual(@as(u64, 4), decoder.table.inserted);

    // A section that names no dynamic entry gets no acknowledgment, and
    // reports nothing.
    var plain = try decoder.decodeSection(gpa, &.{ 0x00, 0x00, 0xd1 });
    defer plain.deinit(gpa);
    try testing.expectEqual(
        @as(?decoder_stream.Instruction, null),
        decoder.takeSectionAcknowledgment(0, &plain),
    );
    try testing.expectEqual(@as(u64, 0), decoder.reported_inserts);

    // One that needs two entries reports those two, so the increment that
    // follows covers only what is left.
    var section = try decoder.decodeSection(gpa, &.{ 0x03, 0x81, 0x10, 0x11 });
    defer section.deinit(gpa);
    try testing.expectEqual(
        @as(?decoder_stream.Instruction, .{ .section_acknowledgment = 4 }),
        decoder.takeSectionAcknowledgment(4, &section),
    );
    try testing.expectEqual(@as(u64, 2), decoder.reported_inserts);
    try testing.expectEqual(
        @as(?decoder_stream.Instruction, .{ .insert_count_increment = 2 }),
        decoder.takeInsertCountIncrement(),
    );

    // A second acknowledgment of the same section is no instruction at
    // all. RFC 9204 section 4.4.1 makes an acknowledgment for a section
    // the encoder already closed a QPACK_DECODER_STREAM_ERROR, so a second
    // one here would be a fault this side aimed at its own peer.
    try testing.expectEqual(
        @as(?decoder_stream.Instruction, null),
        decoder.takeSectionAcknowledgment(4, &section),
    );
    try testing.expectEqual(@as(u64, 4), decoder.reported_inserts);
    try testing.expect(section.acknowledged);

    // A later section on the same stream still gets its own one. Trailers
    // follow headers on one request stream, and each owes the peer an
    // acknowledgment.
    var trailers = try decoder.decodeSection(gpa, &.{ 0x03, 0x81, 0x10, 0x11 });
    defer trailers.deinit(gpa);
    try testing.expectEqual(
        @as(?decoder_stream.Instruction, .{ .section_acknowledgment = 4 }),
        decoder.takeSectionAcknowledgment(4, &trailers),
    );
}

test "a stream cancellation reports no entry" {
    var out: [integer.encoded_len_max]u8 = undefined;
    const instruction = Decoder.streamCancellation(8);
    try testing.expectEqualSlices(u8, &.{0x48}, decoder_stream.write(instruction, &out));
}

test "an encoder stream fault reaches the caller by name" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{ .table_capacity_max = 220 });
    defer decoder.deinit(gpa);

    try testing.expectError(
        error.TableCapacityTooLarge,
        decoder.readEncoderStream(gpa, &.{ 0x3f, 0xe1, 0x1f }),
    );
    try testing.expectError(
        error.InvalidStaticIndex,
        decoder.readEncoderStream(gpa, &.{ 0xff, 0x24, 0x00 }),
    );
    try testing.expectError(
        error.InvalidDynamicIndex,
        decoder.readEncoderStream(gpa, &.{ 0x80, 0x00 }),
    );
}
