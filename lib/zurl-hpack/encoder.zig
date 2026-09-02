//! The HPACK encoder: one header list in, one header block out.
//!
//! **This encoder holds no dynamic table, because it never adds to one.**
//! That is the whole design, and it is a deliberate first step rather than
//! a missing one:
//!
//! - Every field goes out as an indexed header field when the static table
//!   carries the name and the value together, and as a literal header
//!   field without indexing otherwise, RFC 7541 sections 6.1 and 6.2.2. A
//!   sensitive field goes out as a literal never indexed, section 6.2.3.
//! - Nothing this encoder writes changes the peer's decoding table, so
//!   this side keeps no mirror of it and the two cannot drift apart. A
//!   dropped block, a reordered block, or a fault part way through one
//!   costs nothing, where an indexing encoder would have to end the
//!   connection.
//! - Every decoder reads what this writes. The representations it uses are
//!   the ones RFC 7541 requires of every implementation, so an encoder
//!   that indexes can be built on top of this later without changing what
//!   a peer must understand.
//!
//! The cost is size on the wire. A request that repeats the same header on
//! every hop sends it whole every time, where an indexing encoder would
//! send one octet. Huffman coding takes back some of that, and
//! `Options.table_size_update` takes back the peer's memory.
//!
//! This file owns the choice of representation and the writing of it. It
//! owns nothing below that, and it holds no state at all: there is no
//! `Encoder` type here because there is nothing for one to hold.

const std = @import("std");

const field = @import("field.zig");
const integer = @import("integer.zig");
const static_table = @import("static_table.zig");
const string = @import("string.zig");

const Allocator = std.mem.Allocator;

pub const Options = struct {
    /// Whether a name and a value go out Huffman coded.
    coding: string.Coding = .huffman_when_shorter,

    /// A dynamic table size update to put at the front of the block, RFC
    /// 7541 section 6.3.
    ///
    /// This encoder never indexes, so a peer that keeps a decoding table
    /// for it keeps an empty one. An update of zero on the first block of
    /// a connection tells the peer that, and lets it free the memory. Send
    /// it once. An update on every block is octets spent to say what the
    /// peer already knows.
    table_size_update: ?u32 = null,
};

/// The number of octets `encode` writes for `fields`.
pub fn encodedLen(fields: []const field.Field, options: Options) usize {
    var len: usize = 0;
    if (options.table_size_update) |size| len += integer.encodedLen(5, size);
    for (fields) |item| {
        switch (planFor(item)) {
            .indexed => |index| len += integer.encodedLen(7, index),
            .literal => |literal| {
                len += integer.encodedLen(4, literal.name_index);
                if (literal.name_index == 0) len += string.encodedLen(item.name, options.coding);
                len += string.encodedLen(item.value, options.coding);
            },
        }
    }
    return len;
}

/// Writes `fields` as one header block into the front of `out`, and
/// returns the octets it used.
///
/// `out` must hold at least `encodedLen(fields, options)` octets, which is
/// the caller's to get right and so is an assert.
pub fn encode(fields: []const field.Field, options: Options, out: []u8) []u8 {
    std.debug.assert(out.len >= encodedLen(fields, options));

    var pos: usize = 0;
    if (options.table_size_update) |size| {
        pos += writeInteger(5, size_update_pattern, size, out[pos..]);
    }
    for (fields) |item| {
        switch (planFor(item)) {
            .indexed => |index| pos += writeInteger(7, indexed_pattern, index, out[pos..]),
            .literal => |literal| {
                pos += writeInteger(4, literal.pattern, literal.name_index, out[pos..]);
                if (literal.name_index == 0) {
                    pos += string.encode(item.name, options.coding, out[pos..]).len;
                }
                pos += string.encode(item.value, options.coding, out[pos..]).len;
            },
        }
    }
    return out[0..pos];
}

/// Writes `fields` as one header block into memory this function allocates
/// from `gpa`. The caller owns the returned slice.
pub fn encodeAlloc(gpa: Allocator, fields: []const field.Field, options: Options) Allocator.Error![]u8 {
    const out = try gpa.alloc(u8, encodedLen(fields, options));
    errdefer gpa.free(out);
    const written = encode(fields, options, out);
    std.debug.assert(written.len == out.len);
    return out;
}

/// The bits above the prefix, RFC 7541 sections 6.1 through 6.3.
const indexed_pattern: u8 = 0x80;
const without_indexing_pattern: u8 = 0x00;
const never_indexed_pattern: u8 = 0x10;
const size_update_pattern: u8 = 0x20;

/// Which representation one field goes out as.
const Plan = union(enum) {
    /// The static table carries the name and the value together.
    indexed: u32,
    literal: struct {
        /// The static index of the name, or 0 for a literal name.
        name_index: u32,
        pattern: u8,
    },
};

fn planFor(item: field.Field) Plan {
    // A field the caller marked never indexed always goes out as one, even
    // when the static table carries its value. The marker is a request
    // that no table on the path holds this field, and the shortest
    // representation is not worth answering that request with a different
    // one.
    const pattern: u8 = if (item.never_indexed) never_indexed_pattern else without_indexing_pattern;
    switch (static_table.find(item.name, item.value)) {
        .full => |index| {
            if (item.never_indexed) return .{ .literal = .{ .name_index = index, .pattern = pattern } };
            return .{ .indexed = index };
        },
        .name => |index| return .{ .literal = .{ .name_index = index, .pattern = pattern } },
        .none => return .{ .literal = .{ .name_index = 0, .pattern = pattern } },
    }
}

/// Writes one integer into the front of `out`, and returns the octets it
/// used.
///
/// `integer.encode` needs room for the widest integer it can write, and
/// `out` here is what is left of a buffer sized to the exact answer, which
/// near the end is less. So the integer goes into a scratch buffer first.
fn writeInteger(comptime prefix_bits: u4, high_bits: u8, value: u32, out: []u8) usize {
    var scratch: [integer.encoded_len_max]u8 = undefined;
    const written = integer.encode(prefix_bits, high_bits, value, &scratch);
    @memcpy(out[0..written.len], written);
    return written.len;
}

const testing = std.testing;

/// Encodes into a buffer the test owns, so a test reads bytes and not an
/// allocation.
fn encodeInto(out: []u8, fields: []const field.Field, options: Options) []u8 {
    return encode(fields, options, out);
}

test "RFC 7541 C.2.2, a field whose name the static table carries goes out without indexing" {
    var out: [64]u8 = undefined;
    const fields = [_]field.Field{.{ .name = ":path", .value = "/sample/path" }};
    const want = [_]u8{ 0x04, 0x0c } ++ "/sample/path".*;

    try testing.expectEqualSlices(u8, &want, encodeInto(&out, &fields, .{ .coding = .raw }));
}

test "RFC 7541 C.2.3, a field the caller marks sensitive goes out never indexed" {
    var out: [64]u8 = undefined;
    const fields = [_]field.Field{
        .{ .name = "password", .value = "secret", .never_indexed = true },
    };
    const want = [_]u8{ 0x10, 0x08 } ++ "password".* ++ [_]u8{0x06} ++ "secret".*;

    try testing.expectEqualSlices(u8, &want, encodeInto(&out, &fields, .{ .coding = .raw }));
}

test "RFC 7541 C.2.4, a field the static table carries whole goes out as one octet" {
    var out: [64]u8 = undefined;
    const fields = [_]field.Field{.{ .name = ":method", .value = "GET" }};
    try testing.expectEqualSlices(u8, &.{0x82}, encodeInto(&out, &fields, .{ .coding = .raw }));
}

test "a request head goes out as RFC 7541 C.3.1, but without indexing the authority" {
    var out: [64]u8 = undefined;
    const fields = [_]field.Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "www.example.com" },
    };
    // C.3.1 writes 0x41 here, which is the same name index with the
    // incremental indexing pattern. This encoder never indexes, so it
    // writes 0x01 and the rest of the block is the same.
    const want = [_]u8{ 0x82, 0x86, 0x84, 0x01, 0x0f } ++ "www.example.com".*;

    try testing.expectEqualSlices(u8, &want, encodeInto(&out, &fields, .{ .coding = .raw }));
}

test "the same head Huffman coded is shorter and carries the C.4.1 value" {
    var out: [64]u8 = undefined;
    const fields = [_]field.Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "www.example.com" },
    };
    const want = [_]u8{
        0x82, 0x86, 0x84, 0x01, 0x8c, 0xf1, 0xe3, 0xc2,
        0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4,
        0xff,
    };

    try testing.expectEqualSlices(u8, &want, encodeInto(&out, &fields, .{}));
}

test "a name the static table does not carry goes out whole" {
    var out: [64]u8 = undefined;
    const fields = [_]field.Field{.{ .name = "custom-key", .value = "custom-value" }};
    const want = [_]u8{ 0x00, 0x0a } ++ "custom-key".* ++ [_]u8{0x0c} ++ "custom-value".*;

    try testing.expectEqualSlices(u8, &want, encodeInto(&out, &fields, .{ .coding = .raw }));
}

test "a size update goes at the front of the block and nowhere else" {
    var out: [64]u8 = undefined;
    const fields = [_]field.Field{.{ .name = ":method", .value = "GET" }};

    try testing.expectEqualSlices(
        u8,
        &.{ 0x20, 0x82 },
        encodeInto(&out, &fields, .{ .table_size_update = 0 }),
    );
    try testing.expectEqualSlices(
        u8,
        &.{ 0x3f, 0xe1, 0x1f, 0x82 },
        encodeInto(&out, &fields, .{ .table_size_update = 4096 }),
    );
}

test "an empty header list encodes to an empty block" {
    var out: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), encodedLen(&.{}, .{}));
    try testing.expectEqual(@as(usize, 0), encodeInto(&out, &.{}, .{}).len);
}

test "the length an encode reports is the length it writes" {
    var out: [1024]u8 = undefined;
    const fields = [_]field.Field{
        .{ .name = ":status", .value = "200" },
        .{ .name = "cache-control", .value = "private" },
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
        .{ .name = "custom-key", .value = "custom-value" },
        .{ .name = "authorization", .value = "Bearer abc", .never_indexed = true },
    };
    inline for ([_]string.Coding{ .raw, .huffman_when_shorter }) |coding| {
        const options: Options = .{ .coding = coding };
        try testing.expectEqual(encodedLen(&fields, options), encodeInto(&out, &fields, options).len);
    }
}

test "an allocated encode gives the same octets as one into a buffer" {
    const gpa = testing.allocator;
    var out: [256]u8 = undefined;
    const fields = [_]field.Field{
        .{ .name = ":method", .value = "POST" },
        .{ .name = "content-type", .value = "application/json" },
    };
    const allocated = try encodeAlloc(gpa, &fields, .{});
    defer gpa.free(allocated);

    try testing.expectEqualSlices(u8, encodeInto(&out, &fields, .{}), allocated);
}
