//! The encoder instructions of RFC 9204 section 4.3, in both directions.
//!
//! An encoder stream is a unidirectional QUIC stream of type 0x02 that
//! carries an unframed run of four instructions: Set Dynamic Table
//! Capacity, Insert with Name Reference, Insert with Literal Name, and
//! Duplicate. This file owns the wire format of all four. It owns nothing
//! else: it opens no stream, it reads no field section, and it never
//! decides when to send anything.
//!
//! **The stream is unframed, so an instruction can arrive in pieces.**
//! `apply` reads whole instructions and returns how many octets it used. A
//! part instruction at the end is left where it is, for the caller to hand
//! back with more octets after it. So a decoder never waits inside this
//! file, and a peer that stops sending part way through an instruction
//! stalls nothing but its own stream.
//!
//! **A part instruction is still bounded.** A caller has to hold the tail
//! `apply` did not take, so `Limits.instruction_len_max` says how long
//! that tail may get. Past that, the instruction is a fault and not a
//! wait.
//!
//! **Every instruction here came from a peer.** RFC 9204 section 6 calls a
//! fault in this stream QPACK_ENCODER_STREAM_ERROR, and every error below
//! is one of those. None is a panic and none is an unbounded allocation:
//! a string is refused against the room the table has left before it is
//! copied, so a length the peer wrote never sizes an allocation on its
//! own.

const std = @import("std");

const DynamicTable = @import("DynamicTable.zig");
const field = @import("field.zig");
const integer = @import("integer.zig");
const static_table = @import("static_table.zig");
const string = @import("string.zig");

const Allocator = std.mem.Allocator;

/// The bits above the prefix, RFC 9204 sections 4.3.1 through 4.3.4.
pub const set_capacity_pattern: u8 = 0x20;
pub const insert_named_pattern: u8 = 0x80;
pub const insert_named_static_flag: u8 = 0x40;
pub const insert_literal_pattern: u8 = 0x40;
pub const duplicate_pattern: u8 = 0x00;

/// The prefix widths of RFC 9204 sections 4.3.1 through 4.3.4.
const set_capacity_prefix_bits = 5;
const insert_named_prefix_bits = 6;
const insert_literal_name_prefix_bits = 6;
const duplicate_prefix_bits = 5;

/// The string prefix width of a value, which always starts on an octet.
const value_prefix_bits = 8;

/// Every fault reading this stream can report.
///
/// The set is written out rather than built from the sets below it,
/// because it is the whole surface a caller has to handle and it belongs
/// in one place. `string.StringTooLong` is not here on purpose: the only
/// bound a string decode gets here is the room the table has left, so that
/// fault reaches a caller as `EntryTooLarge`. One policy, one name.
pub const Error = error{
    /// The instruction ended in the middle of an integer or a string, and
    /// the octets after it are past `Limits.instruction_len_max`.
    InstructionTooLong,
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
    /// Set Dynamic Table Capacity named a size above the one this side
    /// agreed to.
    TableCapacityTooLarge,
    /// An insert named an entry larger than the table capacity.
    EntryTooLarge,
    /// A name reference named a static index the table does not hold.
    InvalidStaticIndex,
    /// A name reference or a duplicate named a dynamic entry that was
    /// never inserted or was already evicted. RFC 9204 section 2.2.3.
    InvalidDynamicIndex,
    /// The table has held as many inserts as this build counts.
    TableInsertCountOverflow,
    OutOfMemory,
};

pub const Limits = struct {
    /// How many octets one instruction may take.
    ///
    /// The caller holds the tail of a part instruction until the rest
    /// arrives, and this is what bounds that hold. An insert carries a
    /// name and a value that together must fit the table capacity, and
    /// Huffman coding cannot make a wire string more than about 3.75 times
    /// the text it decodes to, because the longest code in the table is 30
    /// bits and the shortest is 5. Four times the capacity plus a little
    /// covers every instruction a conformant encoder can write.
    instruction_len_max: usize,

    /// The bound `Decoder.Options` gives a table of `capacity_max` bytes.
    ///
    /// The parameter takes `DynamicTable.CapacityMax` and not a `usize`,
    /// so the multiply below cannot wrap whatever a build asks for. The
    /// comptime check proves that on the target being built.
    pub fn forCapacity(capacity_max: DynamicTable.CapacityMax) Limits {
        comptime std.debug.assert(4 * DynamicTable.capacity_max_limit + 64 <= std.math.maxInt(usize));
        return .{ .instruction_len_max = 4 * @as(usize, capacity_max) + 64 };
    }
};

/// Reads whole instructions from the front of `bytes` and applies them to
/// `table`, and returns how many octets it used.
///
/// What is left over is a part instruction. The caller keeps it and hands
/// it back with the octets that follow. A return of zero means no whole
/// instruction had arrived yet.
pub fn apply(
    gpa: Allocator,
    table: *DynamicTable,
    bytes: []const u8,
    limits: Limits,
) Error!usize {
    var pos: usize = 0;
    while (pos < bytes.len) {
        // One instruction may read no further than the bound, so an
        // instruction that runs past it looks the same as one that has not
        // finished arriving, and the check below tells the two apart.
        const left = bytes.len - pos;
        const window = bytes[pos..][0..@min(left, limits.instruction_len_max)];

        const used = one(gpa, table, window) catch |err| switch (err) {
            // The rest of this instruction has not arrived. That is not a
            // fault while it is short enough to keep waiting for.
            error.Truncated => {
                if (left > limits.instruction_len_max) return error.InstructionTooLong;
                return pos;
            },
            else => |other| return other,
        };
        pos += used;
    }
    return pos;
}

/// `Error`, and the one fault that means "wait for more octets" rather
/// than "end the connection".
const OneError = Error || error{Truncated};

/// Reads one instruction from the front of `bytes` and applies it, and
/// returns how many octets it used.
///
/// Nothing reaches `table` until the whole instruction has been read, so a
/// `Truncated` return leaves the table as it was.
fn one(gpa: Allocator, table: *DynamicTable, bytes: []const u8) OneError!usize {
    std.debug.assert(bytes.len > 0);
    const first = bytes[0];

    if (first & insert_named_pattern != 0) {
        // RFC 9204 section 4.3.2, insert with name reference.
        const index = try integer.decode(insert_named_prefix_bits, bytes);
        const name = try lookupName(table.*, index.value, first & insert_named_static_flag != 0);

        const value = try readValue(gpa, table.*, bytes[index.len..], name.len);
        defer gpa.free(value.text);

        try table.insert(gpa, name, value.text);
        return index.len + value.len;
    }
    if (first & insert_literal_pattern != 0) {
        // RFC 9204 section 4.3.3, insert with literal name.
        const name = try readName(gpa, table.*, bytes);
        defer gpa.free(name.text);

        const value = try readValue(gpa, table.*, bytes[name.len..], name.text.len);
        defer gpa.free(value.text);

        try table.insert(gpa, name.text, value.text);
        return name.len + value.len;
    }
    if (first & set_capacity_pattern != 0) {
        // RFC 9204 section 4.3.1, set dynamic table capacity.
        const capacity = try integer.decode(set_capacity_prefix_bits, bytes);
        try table.setCapacity(gpa, capacity.value);
        return capacity.len;
    }
    // RFC 9204 section 4.3.4, duplicate.
    const index = try integer.decode(duplicate_prefix_bits, bytes);
    const absolute = table.absoluteFromEncoderRelative(index.value) orelse
        return error.InvalidDynamicIndex;
    try table.duplicate(gpa, absolute);
    return index.len;
}

/// The name a reference names, borrowed from whichever table holds it.
///
/// A dynamic name stays valid until the next thing that changes the table.
/// `DynamicTable.insert` copies before it evicts, which is what makes an
/// insert that names the entry it drops safe.
fn lookupName(table: DynamicTable, index: u64, static: bool) Error![]const u8 {
    if (static) {
        const entry = static_table.get(index) orelse return error.InvalidStaticIndex;
        return entry.name;
    }
    const absolute = table.absoluteFromEncoderRelative(index) orelse
        return error.InvalidDynamicIndex;
    return table.get(absolute).?.name;
}

/// How many octets of name and value one new entry may carry.
///
/// The entry has to fit the capacity, so this is what a string decode is
/// given as its bound. A peer that names more is refused before anything
/// is allocated. A table that has taken no capacity yet has room for
/// nothing, which is what RFC 9204 section 3.2.2 says.
fn room(table: DynamicTable) Error!usize {
    if (table.capacity < field.entry_overhead) return error.EntryTooLarge;
    return table.capacity - field.entry_overhead;
}

/// Reads the literal name of an insert, against the room the table has.
fn readName(gpa: Allocator, table: DynamicTable, bytes: []const u8) OneError!string.Decoded {
    const left = try room(table);
    return string.decode(insert_literal_name_prefix_bits, gpa, bytes, left) catch |err|
        switch (err) {
            error.StringTooLong => error.EntryTooLarge,
            else => |other| other,
        };
}

/// Reads the value of an insert, against the room the name left.
fn readValue(
    gpa: Allocator,
    table: DynamicTable,
    bytes: []const u8,
    name_len: usize,
) OneError!string.Decoded {
    const left = try room(table);
    if (name_len > left) return error.EntryTooLarge;
    return string.decode(value_prefix_bits, gpa, bytes, left - name_len) catch |err|
        switch (err) {
            // The only bound a string gets here is the room in the table,
            // so a string past it is the entry being too large and nothing
            // else.
            error.StringTooLong => error.EntryTooLarge,
            else => |other| other,
        };
}

/// The number of octets `writeSetCapacity` writes.
pub fn setCapacityLen(capacity: u64) usize {
    return integer.encodedLen(set_capacity_prefix_bits, capacity);
}

/// Writes Set Dynamic Table Capacity, RFC 9204 section 4.3.1.
///
/// `out` must hold at least `integer.encoded_len_max` octets, which is the
/// caller's to get right and so is an assert.
pub fn writeSetCapacity(capacity: u64, out: []u8) []u8 {
    return integer.encode(set_capacity_prefix_bits, set_capacity_pattern, capacity, out);
}

/// Which table a name reference means.
pub const Table = enum { static, dynamic };

/// The number of octets `writeInsertWithNameReference` writes.
///
/// Which table the name comes from does not change the length: the 'T' bit
/// sits above the prefix either way.
pub fn insertWithNameReferenceLen(index: u64, value: []const u8, coding: string.Coding) usize {
    return integer.encodedLen(insert_named_prefix_bits, index) +
        string.encodedLen(value_prefix_bits, value, coding);
}

/// Writes Insert with Name Reference, RFC 9204 section 4.3.2.
///
/// `out` must hold at least `insertWithNameReferenceLen(...)` octets,
/// which is the caller's to get right and so is an assert.
pub fn writeInsertWithNameReference(
    table: Table,
    index: u64,
    value: []const u8,
    coding: string.Coding,
    out: []u8,
) []u8 {
    std.debug.assert(out.len >= insertWithNameReferenceLen(index, value, coding));
    const pattern: u8 = switch (table) {
        .static => insert_named_pattern | insert_named_static_flag,
        .dynamic => insert_named_pattern,
    };

    var scratch: [integer.encoded_len_max]u8 = undefined;
    const header = integer.encode(insert_named_prefix_bits, pattern, index, &scratch);
    @memcpy(out[0..header.len], header);

    const body = string.encode(value_prefix_bits, 0, value, coding, out[header.len..]);
    return out[0 .. header.len + body.len];
}

/// The number of octets `writeInsertWithLiteralName` writes.
pub fn insertWithLiteralNameLen(name: []const u8, value: []const u8, coding: string.Coding) usize {
    return string.encodedLen(insert_literal_name_prefix_bits, name, coding) +
        string.encodedLen(value_prefix_bits, value, coding);
}

/// Writes Insert with Literal Name, RFC 9204 section 4.3.3.
///
/// `out` must hold at least `insertWithLiteralNameLen(...)` octets, which
/// is the caller's to get right and so is an assert.
pub fn writeInsertWithLiteralName(
    name: []const u8,
    value: []const u8,
    coding: string.Coding,
    out: []u8,
) []u8 {
    std.debug.assert(out.len >= insertWithLiteralNameLen(name, value, coding));
    const written = string.encode(
        insert_literal_name_prefix_bits,
        insert_literal_pattern,
        name,
        coding,
        out,
    );
    const body = string.encode(value_prefix_bits, 0, value, coding, out[written.len..]);
    return out[0 .. written.len + body.len];
}

/// The number of octets `writeDuplicate` writes.
pub fn duplicateLen(index: u64) usize {
    return integer.encodedLen(duplicate_prefix_bits, index);
}

/// Writes Duplicate, RFC 9204 section 4.3.4.
///
/// `out` must hold at least `integer.encoded_len_max` octets, which is the
/// caller's to get right and so is an assert.
pub fn writeDuplicate(index: u64, out: []u8) []u8 {
    return integer.encode(duplicate_prefix_bits, duplicate_pattern, index, out);
}

const testing = std.testing;

/// A table with room for the worked examples of RFC 9204 Appendix B.
fn exampleTable(gpa: Allocator) !DynamicTable {
    var table: DynamicTable = .init(.{ .capacity_max = 220 });
    errdefer table.deinit(gpa);
    try table.setCapacity(gpa, 220);
    return table;
}

fn exampleLimits() Limits {
    return .forCapacity(220);
}

test "the instruction bound cannot wrap, whatever capacity a build asks for" {
    // `forCapacity` takes `DynamicTable.CapacityMax`, so the widest table
    // a build can ask for still gives a bound that grows with it.
    const widest = Limits.forCapacity(DynamicTable.capacity_max_limit);
    try testing.expectEqual(@as(usize, 4 * 65535 + 64), widest.instruction_len_max);
    try testing.expect(widest.instruction_len_max > DynamicTable.capacity_max_limit);

    try testing.expectEqual(@as(usize, 64), Limits.forCapacity(0).instruction_len_max);
    try testing.expectEqual(@as(usize, 16448), Limits.forCapacity(4096).instruction_len_max);
}

test "RFC 9204 B.2, set capacity 220 is three octets" {
    var out: [integer.encoded_len_max]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 0x3f, 0xbd, 0x01 }, writeSetCapacity(220, &out));
    try testing.expectEqual(@as(usize, 3), setCapacityLen(220));

    const gpa = testing.allocator;
    var table: DynamicTable = .init(.{ .capacity_max = 4096 });
    defer table.deinit(gpa);

    const used = try apply(gpa, &table, &.{ 0x3f, 0xbd, 0x01 }, .forCapacity(4096));
    try testing.expectEqual(@as(usize, 3), used);
    try testing.expectEqual(@as(usize, 220), table.capacity);
}

test "RFC 9204 B.2, two inserts with a static name reference" {
    const gpa = testing.allocator;
    var table = try exampleTable(gpa);
    defer table.deinit(gpa);

    const stream = [_]u8{ 0xc0, 0x0f } ++ "www.example.com".* ++
        [_]u8{ 0xc1, 0x0c } ++ "/sample/path".*;
    const used = try apply(gpa, &table, &stream, exampleLimits());

    try testing.expectEqual(@as(usize, stream.len), used);
    try testing.expectEqual(@as(u64, 2), table.inserted);
    try testing.expectEqualStrings(":authority", table.get(0).?.name);
    try testing.expectEqualStrings("www.example.com", table.get(0).?.value);
    try testing.expectEqualStrings(":path", table.get(1).?.name);
    try testing.expectEqualStrings("/sample/path", table.get(1).?.value);
    try testing.expectEqual(@as(usize, 106), table.size);

    var out: [64]u8 = undefined;
    try testing.expectEqual(
        @as(usize, 17),
        insertWithNameReferenceLen(0, "www.example.com", .raw),
    );
    try testing.expectEqualSlices(
        u8,
        stream[0..17],
        writeInsertWithNameReference(.static, 0, "www.example.com", .raw, &out),
    );
    try testing.expectEqualSlices(
        u8,
        stream[17..],
        writeInsertWithNameReference(.static, 1, "/sample/path", .raw, &out),
    );
}

test "RFC 9204 B.3, an insert with a literal name" {
    const gpa = testing.allocator;
    var table = try exampleTable(gpa);
    defer table.deinit(gpa);

    const stream = [_]u8{0x4a} ++ "custom-key".* ++ [_]u8{0x0c} ++ "custom-value".*;
    const used = try apply(gpa, &table, &stream, exampleLimits());

    try testing.expectEqual(@as(usize, stream.len), used);
    try testing.expectEqualStrings("custom-key", table.get(0).?.name);
    try testing.expectEqualStrings("custom-value", table.get(0).?.value);
    try testing.expectEqual(@as(usize, 54), table.size);

    var out: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, stream.len), insertWithLiteralNameLen("custom-key", "custom-value", .raw));
    try testing.expectEqualSlices(
        u8,
        &stream,
        writeInsertWithLiteralName("custom-key", "custom-value", .raw, &out),
    );
}

test "RFC 9204 B.4, a duplicate of relative index 2" {
    const gpa = testing.allocator;
    var table = try exampleTable(gpa);
    defer table.deinit(gpa);

    const setup = [_]u8{ 0xc0, 0x0f } ++ "www.example.com".* ++
        [_]u8{ 0xc1, 0x0c } ++ "/sample/path".* ++
        [_]u8{0x4a} ++ "custom-key".* ++ [_]u8{0x0c} ++ "custom-value".*;
    _ = try apply(gpa, &table, &setup, exampleLimits());
    try testing.expectEqual(@as(u64, 3), table.inserted);

    // Absolute Index = Insert Count(3) - Index(2) - 1 = 0.
    const used = try apply(gpa, &table, &.{0x02}, exampleLimits());
    try testing.expectEqual(@as(usize, 1), used);
    try testing.expectEqual(@as(u64, 4), table.inserted);
    try testing.expectEqualStrings(":authority", table.get(3).?.name);
    try testing.expectEqualStrings("www.example.com", table.get(3).?.value);
    try testing.expectEqual(@as(usize, 217), table.size);

    var out: [integer.encoded_len_max]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{0x02}, writeDuplicate(2, &out));
    try testing.expectEqual(@as(usize, 1), duplicateLen(2));
}

test "RFC 9204 B.5, an insert with a dynamic name reference evicts the oldest entry" {
    const gpa = testing.allocator;
    var table = try exampleTable(gpa);
    defer table.deinit(gpa);

    const setup = [_]u8{ 0xc0, 0x0f } ++ "www.example.com".* ++
        [_]u8{ 0xc1, 0x0c } ++ "/sample/path".* ++
        [_]u8{0x4a} ++ "custom-key".* ++ [_]u8{0x0c} ++ "custom-value".* ++
        [_]u8{0x02};
    _ = try apply(gpa, &table, &setup, exampleLimits());
    try testing.expectEqual(@as(u64, 4), table.inserted);
    try testing.expectEqual(@as(usize, 217), table.size);

    // Absolute Index = Insert Count(4) - Index(1) - 1 = 2, which is
    // custom-key.
    const stream = [_]u8{ 0x81, 0x0d } ++ "custom-value2".*;
    const used = try apply(gpa, &table, &stream, exampleLimits());

    try testing.expectEqual(@as(usize, stream.len), used);
    try testing.expectEqual(@as(u64, 5), table.inserted);
    try testing.expectEqual(@as(u64, 1), table.dropped);
    try testing.expectEqualStrings("custom-key", table.get(4).?.name);
    try testing.expectEqualStrings("custom-value2", table.get(4).?.value);
    try testing.expectEqual(@as(usize, 215), table.size);
    try testing.expectEqual(@as(?DynamicTable.Entry, null), table.get(0));

    var out: [64]u8 = undefined;
    try testing.expectEqualSlices(
        u8,
        &stream,
        writeInsertWithNameReference(.dynamic, 1, "custom-value2", .raw, &out),
    );
}

test "a part instruction is left where it is, and taken on the next call" {
    const gpa = testing.allocator;
    var table = try exampleTable(gpa);
    defer table.deinit(gpa);

    const stream = [_]u8{ 0xc0, 0x0f } ++ "www.example.com".*;
    var split: usize = 0;
    while (split < stream.len) : (split += 1) {
        var fresh = try exampleTable(gpa);
        defer fresh.deinit(gpa);

        const first = try apply(gpa, &fresh, stream[0..split], exampleLimits());
        try testing.expectEqual(@as(usize, 0), first);
        try testing.expectEqual(@as(u64, 0), fresh.inserted);

        const second = try apply(gpa, &fresh, &stream, exampleLimits());
        try testing.expectEqual(@as(usize, stream.len), second);
        try testing.expectEqual(@as(u64, 1), fresh.inserted);
    }
}

test "an empty read takes nothing and is not a fault" {
    const gpa = testing.allocator;
    var table = try exampleTable(gpa);
    defer table.deinit(gpa);

    try testing.expectEqual(@as(usize, 0), try apply(gpa, &table, &.{}, exampleLimits()));
}

test "an instruction longer than the bound is a fault and not a wait" {
    const gpa = testing.allocator;
    var table = try exampleTable(gpa);
    defer table.deinit(gpa);

    // An insert with a raw literal name that says it carries 150 octets
    // and then stops after 100. The name fits the table, so the length is
    // legal and the wait is legal, but the octets held reach past the
    // bound. A decoder that kept waiting would hold this for ever.
    const partial = [_]u8{ 0x5f, 0x77 } ++ [_]u8{'a'} ** 100;
    try testing.expectError(
        error.InstructionTooLong,
        apply(gpa, &table, &partial, .{ .instruction_len_max = 50 }),
    );

    // A Huffman literal name that says it carries 1032 octets. The table
    // has room for 188, and 1032 Huffman octets cannot decode to fewer
    // than 275, so this one is refused on the octet that finishes the
    // length and never waits at all.
    const impossible = [_]u8{ 0x7f, 0xe9, 0x07 } ++ [_]u8{'a'} ** 200;
    try testing.expectError(
        error.EntryTooLarge,
        apply(gpa, &table, &impossible, .{ .instruction_len_max = 100 }),
    );
    try testing.expectError(
        error.EntryTooLarge,
        apply(gpa, &table, impossible[0..3], exampleLimits()),
    );
}

test "a static name reference past the table is a fault" {
    const gpa = testing.allocator;
    var table = try exampleTable(gpa);
    defer table.deinit(gpa);

    // Static index 99, one past the last entry.
    try testing.expectError(
        error.InvalidStaticIndex,
        apply(gpa, &table, &.{ 0xff, 0x24, 0x00 }, exampleLimits()),
    );
    // A very large static index, spread over a continuation.
    try testing.expectError(
        error.InvalidStaticIndex,
        apply(gpa, &table, &.{ 0xff, 0xff, 0xff, 0xff, 0x0f, 0x00 }, exampleLimits()),
    );
}

test "a dynamic name reference to an entry that is not there is a fault" {
    const gpa = testing.allocator;
    var table = try exampleTable(gpa);
    defer table.deinit(gpa);

    // The table is empty, so no relative index names anything.
    try testing.expectError(
        error.InvalidDynamicIndex,
        apply(gpa, &table, &.{ 0x80, 0x00 }, exampleLimits()),
    );
    try testing.expectError(
        error.InvalidDynamicIndex,
        apply(gpa, &table, &.{0x00}, exampleLimits()),
    );
}

test "a dynamic reference to an evicted entry is a fault" {
    const gpa = testing.allocator;
    // Room for one entry of 34 bytes and no more.
    var table: DynamicTable = .init(.{ .capacity_max = 34 });
    defer table.deinit(gpa);
    try table.setCapacity(gpa, 34);

    _ = try apply(gpa, &table, &.{ 0x41, 'a', 0x01, '1' }, .forCapacity(34));
    _ = try apply(gpa, &table, &.{ 0x41, 'b', 0x01, '2' }, .forCapacity(34));
    try testing.expectEqual(@as(u64, 2), table.inserted);
    try testing.expectEqual(@as(u64, 1), table.dropped);

    // Relative index 1 is absolute index 0, which was evicted.
    try testing.expectError(
        error.InvalidDynamicIndex,
        apply(gpa, &table, &.{ 0x81, 0x01, '3' }, .forCapacity(34)),
    );
    try testing.expectError(
        error.InvalidDynamicIndex,
        apply(gpa, &table, &.{0x01}, .forCapacity(34)),
    );
}

test "a capacity above the agreed ceiling is a fault" {
    const gpa = testing.allocator;
    var table: DynamicTable = .init(.{ .capacity_max = 220 });
    defer table.deinit(gpa);

    // 0x3f 0xe1 0x1f is 4096.
    try testing.expectError(
        error.TableCapacityTooLarge,
        apply(gpa, &table, &.{ 0x3f, 0xe1, 0x1f }, exampleLimits()),
    );
    try testing.expectEqual(@as(usize, 0), table.capacity);
}

test "an entry larger than the capacity is a fault, and nothing is allocated for it" {
    const gpa = testing.allocator;
    // Room for one entry of 40 bytes, so a name and a value come to 8.
    var table: DynamicTable = .init(.{ .capacity_max = 40 });
    defer table.deinit(gpa);
    try table.setCapacity(gpa, 40);

    const long = [_]u8{0x49} ++ "aaaaaaaaa".* ++ [_]u8{0x00};
    try testing.expectError(error.EntryTooLarge, apply(gpa, &table, &long, .forCapacity(40)));

    const fits = [_]u8{0x44} ++ "aaaa".* ++ [_]u8{0x04} ++ "bbbb".*;
    _ = try apply(gpa, &table, &fits, .forCapacity(40));
    try testing.expectEqual(@as(u64, 1), table.inserted);
}

test "an insert against a table of no capacity is a fault" {
    const gpa = testing.allocator;
    var table: DynamicTable = .init(.{ .capacity_max = 4096 });
    defer table.deinit(gpa);

    // RFC 9204 section 3.2.2: the capacity starts at zero, so nothing may
    // be inserted before Set Dynamic Table Capacity arrives.
    try testing.expectError(
        error.EntryTooLarge,
        apply(gpa, &table, &.{ 0x41, 'a', 0x01, '1' }, .forCapacity(4096)),
    );
}

test "an integer that never ends is refused, whichever instruction carries it" {
    const gpa = testing.allocator;
    var table = try exampleTable(gpa);
    defer table.deinit(gpa);

    const forever = [_]u8{0x80} ** 32;
    inline for ([_]u8{ 0xff, 0x7f, 0x3f, 0x1f }) |first| {
        try testing.expectError(
            error.IntegerTooLong,
            apply(gpa, &table, &([_]u8{first} ++ forever), exampleLimits()),
        );
    }
}

test "a Huffman fault on the encoder stream reaches the caller by name" {
    const gpa = testing.allocator;
    var table = try exampleTable(gpa);
    defer table.deinit(gpa);

    // An insert with a static name reference and a Huffman value that
    // carries the EOS symbol.
    try testing.expectError(
        error.HuffmanEosSymbol,
        apply(gpa, &table, &.{ 0xc0, 0x84, 0xff, 0xff, 0xff, 0xff }, exampleLimits()),
    );
    try testing.expectError(
        error.HuffmanPadInvalid,
        apply(gpa, &table, &.{ 0xc0, 0x81, 0b00000_110 }, exampleLimits()),
    );
    try testing.expectError(
        error.HuffmanPadTooLong,
        apply(gpa, &table, &.{ 0xc0, 0x82, 0x07, 0xff }, exampleLimits()),
    );
}

test "an insert may name the entry it evicts, over the wire" {
    const gpa = testing.allocator;
    var table: DynamicTable = .init(.{ .capacity_max = 34 });
    defer table.deinit(gpa);
    try table.setCapacity(gpa, 34);

    _ = try apply(gpa, &table, &.{ 0x41, 'a', 0x01, '1' }, .forCapacity(34));
    // Relative index 0 is the entry this insert evicts. RFC 9204 section
    // 3.2.2 warns about it by name.
    _ = try apply(gpa, &table, &.{ 0x80, 0x01, '2' }, .forCapacity(34));

    try testing.expectEqual(@as(u64, 1), table.count());
    try testing.expectEqualStrings("a", table.get(1).?.name);
    try testing.expectEqualStrings("2", table.get(1).?.value);
}

test "what the writers write, apply reads back" {
    const gpa = testing.allocator;
    var table: DynamicTable = .init(.{ .capacity_max = 4096 });
    defer table.deinit(gpa);

    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(gpa);
    var out: [512]u8 = undefined;

    try stream.appendSlice(gpa, writeSetCapacity(4096, &out));
    inline for ([_]string.Coding{ .raw, .huffman_when_shorter }) |coding| {
        try stream.appendSlice(gpa, writeInsertWithNameReference(.static, 17, "PATCH", coding, &out));
        try stream.appendSlice(gpa, writeInsertWithLiteralName("custom-key", "custom-value", coding, &out));
        try stream.appendSlice(gpa, writeInsertWithNameReference(.dynamic, 0, "again", coding, &out));
        try stream.appendSlice(gpa, writeDuplicate(1, &out));
    }

    const used = try apply(gpa, &table, stream.items, .forCapacity(4096));
    try testing.expectEqual(stream.items.len, used);
    try testing.expectEqual(@as(u64, 8), table.inserted);
    try testing.expectEqualStrings(":method", table.get(0).?.name);
    try testing.expectEqualStrings("PATCH", table.get(0).?.value);
    try testing.expectEqualStrings("custom-key", table.get(1).?.name);
    try testing.expectEqualStrings("custom-key", table.get(2).?.name);
    try testing.expectEqualStrings("again", table.get(2).?.value);
    try testing.expectEqualStrings("custom-key", table.get(3).?.name);
    try testing.expectEqualStrings("custom-value", table.get(3).?.value);
}

test "a value length no table can hold is a fault at once, not a decode per octet" {
    // A part instruction is re-read from its start, so the work one octet
    // costs is the work of every field before it. A peer that names a
    // length no bound can hold, and then drips octets, would buy a full
    // Huffman decode and a heap allocation for each of those octets. The
    // bound check in `string.decode` runs on the declared length, so this
    // ends on the octet that completes the length and never waits.
    const gpa = testing.allocator;

    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(gpa);
    var out: [8192]u8 = undefined;

    try stream.appendSlice(gpa, writeSetCapacity(4096, &out));

    // 4000 octets of 'a'. The code for 'a' is five bits, so the name goes
    // on the wire as 2500 octets and leaves 64 octets of room behind it.
    try stream.appendSlice(gpa, string.encode(
        insert_literal_name_prefix_bits,
        insert_literal_pattern,
        "a" ** 4000,
        .huffman_when_shorter,
        &out,
    ));

    // A Huffman value of 60000 octets, which cannot decode to fewer than
    // 16000 and so can never fit the 64 octets left.
    var value_header: [integer.encoded_len_max]u8 = undefined;
    try stream.appendSlice(gpa, integer.encode(
        value_prefix_bits - 1,
        comptime string.huffmanFlag(value_prefix_bits),
        60000,
        &value_header,
    ));
    // What the peer drips after it, one QUIC STREAM frame per octet.
    try stream.appendSlice(gpa, &([_]u8{'x'} ** 256));

    var counted: std.testing.FailingAllocator = .init(gpa, .{});
    var table: DynamicTable = .init(.{ .capacity_max = 4096 });
    defer table.deinit(counted.allocator());

    // Five decodes of the name at most: the call that completes it, and
    // one for each of the four octets of the value length. Every drip
    // after that would add one more.
    const allocations_max = 32;

    var taken: usize = 0;
    var seen: usize = 0;
    var refused = false;
    while (seen < stream.items.len) {
        seen += 1;
        const used = apply(
            counted.allocator(),
            &table,
            stream.items[taken..seen],
            .forCapacity(4096),
        ) catch |err| {
            try testing.expectEqual(Error.EntryTooLarge, err);
            refused = true;
            break;
        };
        taken += used;
        try testing.expect(counted.allocations <= allocations_max);
    }

    try testing.expect(refused);
    try testing.expect(counted.allocations <= allocations_max);
    try testing.expectEqual(@as(u64, 0), table.inserted);
    // The fault landed on the octet that finished the length, so the 256
    // octets of drip after it were never read.
    try testing.expect(seen < stream.items.len - 200);
}

test "the stream is read one octet at a time and comes out the same" {
    const gpa = testing.allocator;
    var whole: DynamicTable = .init(.{ .capacity_max = 4096 });
    defer whole.deinit(gpa);
    var dripped: DynamicTable = .init(.{ .capacity_max = 4096 });
    defer dripped.deinit(gpa);

    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(gpa);
    var out: [512]u8 = undefined;
    try stream.appendSlice(gpa, writeSetCapacity(4096, &out));
    try stream.appendSlice(gpa, writeInsertWithLiteralName("custom-key", "custom-value", .raw, &out));
    try stream.appendSlice(gpa, writeInsertWithNameReference(.dynamic, 0, "second", .raw, &out));
    try stream.appendSlice(gpa, writeDuplicate(0, &out));

    _ = try apply(gpa, &whole, stream.items, .forCapacity(4096));

    var taken: usize = 0;
    var seen: usize = 0;
    while (seen < stream.items.len) {
        seen += 1;
        taken += try apply(gpa, &dripped, stream.items[taken..seen], .forCapacity(4096));
    }

    try testing.expectEqual(stream.items.len, taken);
    try testing.expectEqual(whole.inserted, dripped.inserted);
    try testing.expectEqual(whole.size, dripped.size);
    try testing.expectEqualStrings(whole.get(2).?.value, dripped.get(2).?.value);
}
