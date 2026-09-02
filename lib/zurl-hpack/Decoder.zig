//! The HPACK decoder: one header block in, one header list out.
//!
//! This file owns the five header field representations of RFC 7541
//! section 6, the shared index space of section 2.3.3, and the bounds that
//! make a decode safe against the peer that wrote the block. It owns
//! nothing below that: the integers, the strings, the Huffman code, the
//! static table, and the dynamic table each live in their own file.
//!
//! **One decoder belongs to one connection.** The dynamic table it holds
//! is built by every block that came before, so the same block decoded
//! with a fresh decoder decodes to something else. A caller that loses a
//! block, or that stops a decode part way, must not decode another on the
//! same decoder: this side's table and the peer's copy have parted, and
//! every later block is wrong. HTTP/2 says the same in RFC 9113 section
//! 4.3, where a header block that will not decode ends the connection.
//!
//! **A header block is untrusted input.** These are the bounds this build
//! puts on one, and each has a test that reaches it:
//!
//! - `header_list_size_max` caps the whole decoded list, counted the way
//!   HTTP/2 counts SETTINGS_MAX_HEADER_LIST_SIZE. This is what stops a
//!   decompression bomb, where one octet of index repeats a large dynamic
//!   table entry.
//! - `field_count_max` caps how many fields one block gives back.
//! - The dynamic table's own ceiling caps a size update.
//! - `integer.continuation_octets_max` caps an integer, and `Truncated`
//!   ends a decode that runs off the end of the block.
//!
//! **Nothing here allocates without a bound.** The list, and every name
//! and value in it, together stay under `header_list_size_max`. The
//! dynamic table stays under its own capacity. A string is refused against
//! the budget that is left before it is copied, so a length the peer wrote
//! never sizes an allocation on its own.

const std = @import("std");

const DynamicTable = @import("DynamicTable.zig");
const field = @import("field.zig");
const integer = @import("integer.zig");
const static_table = @import("static_table.zig");
const string = @import("string.zig");

const Allocator = std.mem.Allocator;
const Decoder = @This();

/// The largest decoded header list this build returns, in bytes.
///
/// The count is the sum of `Field.size` over the list, which is the name,
/// the value, and 32 bytes for each field. That is the arithmetic of
/// SETTINGS_MAX_HEADER_LIST_SIZE in RFC 9113 section 6.5.2, so a caller
/// can advertise this number and mean it.
///
/// **This is the bound that stops a decompression bomb.** A dynamic table
/// entry can be four kilobytes, and one octet of the block can name it, so
/// a short block would otherwise expand without limit. 64 KiB is far more
/// head than a real server sends, and it caps the expansion of a full
/// table at about a thousand to one.
pub const header_list_size_max: usize = 64 * 1024;

/// How many header fields one block may decode to.
///
/// `header_list_size_max` already bounds this at 2048, because a field
/// costs at least 32 bytes. This is the tighter answer: a real response
/// carries tens of header fields, and a block with hundreds is a peer
/// spending this side's time rather than saying anything.
pub const field_count_max: usize = 256;

/// Every fault a decode can report.
///
/// The set is written out rather than built from the sets below it,
/// because it is the whole surface a caller has to handle and it belongs
/// in one place. `string.StringTooLong` is not here on purpose: the only
/// bound this file gives a string decode is the header list budget, so
/// that fault reaches a caller as `HeaderListTooLarge`.
pub const Error = error{
    /// The block ended in the middle of a representation.
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
    /// A size update named a size above the one this side agreed to.
    TableSizeTooLarge,
    /// An indexed representation named index 0, or an index past the
    /// static and dynamic tables together.
    InvalidIndex,
    /// The decoded header list reaches `Options.header_list_size_max`.
    HeaderListTooLarge,
    /// The block holds more than `Options.field_count_max` fields.
    TooManyHeaderFields,
    /// A size update came after a header field. RFC 7541 section 4.2 says
    /// an update belongs at the start of a block.
    TableSizeUpdateOutOfOrder,
    OutOfMemory,
};

/// The bounds one decoder works to.
pub const Options = struct {
    /// The largest dynamic table this side lets the peer use, which is
    /// what this side sent as SETTINGS_HEADER_TABLE_SIZE.
    table_capacity_max: usize = DynamicTable.capacity_default,
    /// The bound on one decoded header list, in bytes.
    header_list_size_max: usize = Decoder.header_list_size_max,
    /// The bound on how many fields one block gives back.
    field_count_max: usize = Decoder.field_count_max,
};

table: DynamicTable,
limits: Options,

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

/// Decodes one header block into a list the caller owns.
///
/// On a fault the dynamic table is left as the fault found it. The peer's
/// copy has moved on, so the two no longer agree, and no later block on
/// this decoder means anything. See the note at the top of this file.
pub fn decode(self: *Decoder, gpa: Allocator, block: []const u8) Error!field.List {
    var list: field.List = .empty;
    errdefer list.deinit(gpa);

    // RFC 7541 section 4.2: a size update comes at the start of a block,
    // before any header field.
    var seen_field = false;

    var pos: usize = 0;
    while (pos < block.len) {
        const first = block[pos];
        if (first & 0x80 != 0) {
            // RFC 7541 section 6.1, indexed header field.
            const index = try integer.decode(7, block[pos..]);
            pos += index.len;
            const entry = try self.lookup(index.value);
            try self.emit(gpa, &list, entry.name, entry.value, .{});
            seen_field = true;
        } else if (first & 0x40 != 0) {
            // RFC 7541 section 6.2.1, literal with incremental indexing.
            pos += try self.literal(gpa, &list, block[pos..], 6, .{ .index_it = true });
            seen_field = true;
        } else if (first & 0x20 != 0) {
            // RFC 7541 section 6.3, dynamic table size update.
            if (seen_field) return error.TableSizeUpdateOutOfOrder;
            const size = try integer.decode(5, block[pos..]);
            pos += size.len;
            try self.table.setCapacity(gpa, size.value);
        } else {
            // RFC 7541 sections 6.2.2 and 6.2.3, literal without indexing
            // and literal never indexed. The two differ in one bit, and in
            // what a caller that re-encodes the field must do with it.
            const never_indexed = first & 0x10 != 0;
            pos += try self.literal(gpa, &list, block[pos..], 4, .{ .never_indexed = never_indexed });
            seen_field = true;
        }
    }
    return list;
}

/// How one literal representation differs from the next.
const LiteralKind = struct {
    /// Add the field to the dynamic table, RFC 7541 section 6.2.1.
    index_it: bool = false,
    /// Mark the field never indexed, RFC 7541 section 6.2.3.
    never_indexed: bool = false,
};

/// Reads one literal header field from the front of `bytes`, and returns
/// how many octets it used.
fn literal(
    self: *Decoder,
    gpa: Allocator,
    list: *field.List,
    bytes: []const u8,
    comptime index_prefix_bits: u4,
    kind: LiteralKind,
) Error!usize {
    const index = try integer.decode(index_prefix_bits, bytes);
    var pos = index.len;

    // The name may take the whole of what is left of the list, less the
    // 32 bytes the field costs whatever it holds. The value gets whatever
    // the name leaves.
    const budget = try self.remaining(list.*);

    var name: []const u8 = undefined;
    var owned_name: ?[]u8 = null;
    defer if (owned_name) |text| gpa.free(text);

    if (index.value == 0) {
        const decoded = try decodeString(gpa, bytes[pos..], budget);
        owned_name = decoded.text;
        name = decoded.text;
        pos += decoded.len;
    } else {
        // Borrowed from a table. `emit` copies it before anything can
        // evict the entry it points into.
        name = (try self.lookup(index.value)).name;
    }
    if (name.len > budget) return error.HeaderListTooLarge;

    const value = try decodeString(gpa, bytes[pos..], budget - name.len);
    defer gpa.free(value.text);
    pos += value.len;

    try self.emit(gpa, list, name, value.text, kind);
    return pos;
}

/// Reads one string literal, and reports a string past `budget` as what it
/// is: the header list reaching its bound.
fn decodeString(gpa: Allocator, bytes: []const u8, budget: usize) Error!string.Decoded {
    return string.decode(gpa, bytes, budget) catch |err| switch (err) {
        error.StringTooLong => error.HeaderListTooLarge,
        else => |other| other,
    };
}

/// Puts one field into `list`, and into the dynamic table when the
/// representation said to.
///
/// `name` and `value` are borrowed. The copies come first, so a name that
/// points into the dynamic table is safe even when this very call evicts
/// the entry it points into. The copies are also what the list keeps, so a
/// decoded field stays right after a later block empties the table.
fn emit(
    self: *Decoder,
    gpa: Allocator,
    list: *field.List,
    name: []const u8,
    value: []const u8,
    kind: LiteralKind,
) Error!void {
    if (list.fields.items.len >= self.limits.field_count_max) return error.TooManyHeaderFields;
    const budget = try self.remaining(list.*);
    if (name.len + value.len > budget) return error.HeaderListTooLarge;

    const name_copy = try gpa.dupe(u8, name);
    errdefer gpa.free(name_copy);
    const value_copy = try gpa.dupe(u8, value);
    errdefer gpa.free(value_copy);

    if (kind.index_it) try self.table.add(gpa, name_copy, value_copy);
    try list.append(gpa, name_copy, value_copy, kind.never_indexed);
}

/// How many octets of name and value one more field may carry.
fn remaining(self: Decoder, list: field.List) Error!usize {
    const spent = list.size + field.entry_overhead;
    if (spent > self.limits.header_list_size_max) return error.HeaderListTooLarge;
    return self.limits.header_list_size_max - spent;
}

/// The entry at `index` in the shared index space of RFC 7541 section
/// 2.3.3.
///
/// The name and the value are borrowed from the static table or from the
/// dynamic table, so they stay valid only until the next thing that
/// changes the dynamic table.
fn lookup(self: Decoder, index: u32) Error!static_table.Entry {
    if (static_table.get(index)) |entry| return entry;
    // `get` says null for index 0 and for every index above the static
    // table. Only the second of those can be a dynamic entry.
    if (index <= static_table.len) return error.InvalidIndex;
    const entry = self.table.get(index - static_table.len) orelse return error.InvalidIndex;
    return .{ .name = entry.name, .value = entry.value };
}

const testing = std.testing;

/// Decodes one block with a fresh decoder, for a test that needs no
/// dynamic table state carried in.
fn decodeOnce(gpa: Allocator, block: []const u8) Error!field.List {
    var decoder: Decoder = .init(.{});
    defer decoder.deinit(gpa);
    return decoder.decode(gpa, block);
}

test "an indexed header field names a static entry" {
    const gpa = testing.allocator;
    var list = try decodeOnce(gpa, &.{0x82});
    defer list.deinit(gpa);

    try testing.expectEqual(@as(usize, 1), list.fields.items.len);
    try testing.expectEqualStrings(":method", list.fields.items[0].name);
    try testing.expectEqualStrings("GET", list.fields.items[0].value);
}

test "index zero in an indexed header field is a fault" {
    try testing.expectError(error.InvalidIndex, decodeOnce(testing.allocator, &.{0x80}));
}

test "an index past both tables is a fault" {
    // 62 is the first dynamic index, and the table is empty.
    try testing.expectError(error.InvalidIndex, decodeOnce(testing.allocator, &.{0xbe}));
    // A very large index, spread over a continuation.
    try testing.expectError(
        error.InvalidIndex,
        decodeOnce(testing.allocator, &.{ 0xff, 0xff, 0xff, 0xff, 0x0f }),
    );
}

test "an index past both tables is a fault, whichever literal names it" {
    // 0x7e is a literal with incremental indexing, name index 62.
    try testing.expectError(error.InvalidIndex, decodeOnce(testing.allocator, &.{ 0x7e, 0x00 }));
    // 0x0f 0x33 is a literal without indexing, name index 15 + 51 = 66.
    try testing.expectError(error.InvalidIndex, decodeOnce(testing.allocator, &.{ 0x0f, 0x33, 0x00 }));
}

test "a size update at the start of a block is taken, and one after a field is not" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{ .table_capacity_max = 4096 });
    defer decoder.deinit(gpa);

    // 0x20 is a size update to zero, and 0x82 is a header field after it.
    var first = try decoder.decode(gpa, &.{ 0x20, 0x82 });
    defer first.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), decoder.table.capacity);
    try testing.expectEqual(@as(usize, 1), first.fields.items.len);

    // 0x3f 0xe1 0x1f is a size update back to 4096.
    var second = try decoder.decode(gpa, &.{ 0x3f, 0xe1, 0x1f, 0x82 });
    defer second.deinit(gpa);
    try testing.expectEqual(@as(usize, 4096), decoder.table.capacity);

    try testing.expectError(error.TableSizeUpdateOutOfOrder, decoder.decode(gpa, &.{ 0x82, 0x20 }));
}

test "a size update above the agreed ceiling is a fault" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{ .table_capacity_max = 256 });
    defer decoder.deinit(gpa);

    // 0x3f 0xe1 0x1f is 4096, which is past the 256 this side agreed to.
    try testing.expectError(error.TableSizeTooLarge, decoder.decode(gpa, &.{ 0x3f, 0xe1, 0x1f }));
    try testing.expectEqual(@as(usize, 256), decoder.table.capacity);

    // 256 itself is fine, and 257 is not.
    var list = try decoder.decode(gpa, &.{ 0x3f, 0xe1, 0x01 });
    defer list.deinit(gpa);
    try testing.expectEqual(@as(usize, 256), decoder.table.capacity);
    try testing.expectError(error.TableSizeTooLarge, decoder.decode(gpa, &.{ 0x3f, 0xe2, 0x01 }));
}

test "a size update of zero empties the table" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{});
    defer decoder.deinit(gpa);

    var first = try decoder.decode(gpa, &.{ 0x40, 0x01, 'a', 0x01, 'b' });
    defer first.deinit(gpa);
    try testing.expectEqual(@as(u32, 1), decoder.table.count());

    var second = try decoder.decode(gpa, &.{0x20});
    defer second.deinit(gpa);
    try testing.expectEqual(@as(u32, 0), decoder.table.count());
    try testing.expectEqual(@as(usize, 0), decoder.table.capacity);
}

test "a never indexed field comes back marked, and stays out of the table" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{});
    defer decoder.deinit(gpa);

    var list = try decoder.decode(gpa, &.{
        0x10, 0x08, 'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
        0x06, 's',  'e', 'c', 'r', 'e', 't',
    });
    defer list.deinit(gpa);

    try testing.expect(list.fields.items[0].never_indexed);
    try testing.expectEqualStrings("password", list.fields.items[0].name);
    try testing.expectEqualStrings("secret", list.fields.items[0].value);
    try testing.expectEqual(@as(u32, 0), decoder.table.count());
}

test "a field without indexing comes back unmarked, and stays out of the table" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{});
    defer decoder.deinit(gpa);

    var list = try decoder.decode(gpa, &.{ 0x04, 0x01, '/' });
    defer list.deinit(gpa);

    try testing.expect(!list.fields.items[0].never_indexed);
    try testing.expectEqualStrings(":path", list.fields.items[0].name);
    try testing.expectEqualStrings("/", list.fields.items[0].value);
    try testing.expectEqual(@as(u32, 0), decoder.table.count());
}

test "an empty block decodes to an empty list" {
    const gpa = testing.allocator;
    var list = try decodeOnce(gpa, &.{});
    defer list.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), list.fields.items.len);
    try testing.expectEqual(@as(usize, 0), list.size);
}

test "a block that ends in the middle of a representation is truncated" {
    const gpa = testing.allocator;
    try testing.expectError(error.Truncated, decodeOnce(gpa, &.{0x40}));
    try testing.expectError(error.Truncated, decodeOnce(gpa, &.{ 0x40, 0x03, 'a' }));
    try testing.expectError(error.Truncated, decodeOnce(gpa, &.{ 0x40, 0x01, 'a' }));
    try testing.expectError(error.Truncated, decodeOnce(gpa, &.{0x3f}));
}

test "a decoded field that points into the table survives its own eviction" {
    const gpa = testing.allocator;
    // Room for one entry of 34 bytes and no more.
    var decoder: Decoder = .init(.{ .table_capacity_max = 40 });
    defer decoder.deinit(gpa);

    var first = try decoder.decode(gpa, &.{ 0x40, 0x01, 'a', 0x01, '1' });
    defer first.deinit(gpa);
    try testing.expectEqualStrings("a", first.fields.items[0].name);

    // Index 62 names "a", and the same block then adds "b" and evicts it.
    var second = try decoder.decode(gpa, &.{ 0xbe, 0x40, 0x01, 'b', 0x01, '2' });
    defer second.deinit(gpa);

    try testing.expectEqualStrings("a", second.fields.items[0].name);
    try testing.expectEqualStrings("1", second.fields.items[0].value);
    try testing.expectEqualStrings("b", second.fields.items[1].name);
    try testing.expectEqual(@as(u32, 1), decoder.table.count());
    try testing.expectEqualStrings("b", decoder.table.get(1).?.name);
}

test "a literal that names a dynamic entry and evicts it in the same step is safe" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{ .table_capacity_max = 40 });
    defer decoder.deinit(gpa);

    var first = try decoder.decode(gpa, &.{ 0x40, 0x01, 'a', 0x01, '1' });
    defer first.deinit(gpa);

    // 0x7e is a literal with incremental indexing whose name index is 62,
    // the entry that adding this very field evicts.
    var second = try decoder.decode(gpa, &.{ 0x7e, 0x01, '2' });
    defer second.deinit(gpa);

    try testing.expectEqualStrings("a", second.fields.items[0].name);
    try testing.expectEqualStrings("2", second.fields.items[0].value);
    try testing.expectEqual(@as(u32, 1), decoder.table.count());
    try testing.expectEqualStrings("2", decoder.table.get(1).?.value);
}

test "a header list past the byte bound is refused" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{ .header_list_size_max = 100 });
    defer decoder.deinit(gpa);

    // A literal without indexing with a one octet name and no value costs
    // 33 bytes. Three fit in 100 and four do not.
    const one = [_]u8{ 0x00, 0x01, 'a', 0x00 };
    var list = try decoder.decode(gpa, &(one ** 3));
    defer list.deinit(gpa);
    try testing.expectEqual(@as(usize, 99), list.size);

    try testing.expectError(error.HeaderListTooLarge, decoder.decode(gpa, &(one ** 4)));
}

test "one long string is refused against the same byte bound" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{ .header_list_size_max = 100 });
    defer decoder.deinit(gpa);

    // The budget for one field is 100 less the 32 bytes of overhead. A
    // name of 60 leaves 8, which a value of 20 does not fit.
    const split = [_]u8{ 0x00, 60 } ++ [_]u8{'a'} ** 60 ++ [_]u8{20} ++ [_]u8{'b'} ** 20;
    try testing.expectError(error.HeaderListTooLarge, decoder.decode(gpa, &split));

    // A name of 200 is past the whole budget on its own.
    const single = [_]u8{ 0x00, 200 } ++ [_]u8{'a'} ** 200 ++ [_]u8{0};
    try testing.expectError(error.HeaderListTooLarge, decoder.decode(gpa, &single));
}

test "a header list past the field count is refused" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{ .field_count_max = 4 });
    defer decoder.deinit(gpa);

    var list = try decoder.decode(gpa, &([_]u8{0x82} ** 4));
    defer list.deinit(gpa);
    try testing.expectEqual(@as(usize, 4), list.fields.items.len);

    try testing.expectError(error.TooManyHeaderFields, decoder.decode(gpa, &([_]u8{0x82} ** 5)));
}

test "a decompression bomb stops at the byte bound" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{
        .table_capacity_max = 4096,
        .header_list_size_max = 64 * 1024,
        .field_count_max = 4096,
    });
    defer decoder.deinit(gpa);

    // One dynamic table entry of 4033 bytes, from 4006 octets of block.
    var seed: std.ArrayList(u8) = .empty;
    defer seed.deinit(gpa);
    try seed.appendSlice(gpa, &.{ 0x40, 0x01, 'a', 0x7f, 0xa1, 0x1e });
    try seed.appendSlice(gpa, &([_]u8{'x'} ** 4000));

    var first = try decoder.decode(gpa, seed.items);
    defer first.deinit(gpa);
    try testing.expectEqual(@as(usize, 4033), decoder.table.size);

    // 200 octets of index 62 would name 200 fields of 4033 bytes, which is
    // about 800 KiB out of 200 in. The bound stops it well before that.
    try testing.expectError(error.HeaderListTooLarge, decoder.decode(gpa, &([_]u8{0xbe} ** 200)));
}

test "an integer that never ends is refused, whichever representation carries it" {
    const gpa = testing.allocator;
    const forever = [_]u8{0x80} ** 32;
    try testing.expectError(error.IntegerTooLong, decodeOnce(gpa, &([_]u8{0xff} ++ forever)));
    try testing.expectError(error.IntegerTooLong, decodeOnce(gpa, &([_]u8{0x7f} ++ forever)));
    try testing.expectError(error.IntegerTooLong, decodeOnce(gpa, &([_]u8{0x3f} ++ forever)));
    try testing.expectError(error.IntegerTooLong, decodeOnce(gpa, &([_]u8{0x0f} ++ forever)));
}

test "an index larger than this build holds is refused before it wraps" {
    const gpa = testing.allocator;
    try testing.expectError(
        error.IntegerOverflow,
        decodeOnce(gpa, &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }),
    );
}

test "a Huffman fault in a header block reaches the caller by name" {
    const gpa = testing.allocator;
    // A literal without indexing with an indexed name, and a Huffman value
    // that carries the EOS symbol.
    try testing.expectError(
        error.HuffmanEosSymbol,
        decodeOnce(gpa, &.{ 0x04, 0x84, 0xff, 0xff, 0xff, 0xff }),
    );
    // The same shape, with a pad that is not the top of the EOS code.
    try testing.expectError(error.HuffmanPadInvalid, decodeOnce(gpa, &.{ 0x04, 0x81, 0b00000_110 }));
    // The same shape, with more than seven bits of pad.
    try testing.expectError(error.HuffmanPadTooLong, decodeOnce(gpa, &.{ 0x04, 0x82, 0x07, 0xff }));
}
