//! The QPACK encoder: one field list in, one encoded field section out.
//!
//! **This encoder holds no dynamic table, because it never inserts into
//! one.** That is the whole design, and it is a deliberate first step
//! rather than a missing one:
//!
//! - Every field line goes out as an indexed field line when the static
//!   table carries the name and the value together, and as a literal field
//!   line with a name reference or a literal name otherwise, RFC 9204
//!   sections 4.5.2, 4.5.4, and 4.5.6.
//! - The prefix is always a Required Insert Count of zero and a Base of
//!   zero, which is two zero octets. A section that names no dynamic entry
//!   may use any Base, and RFC 9204 section 4.5.1.2 says a Delta Base of
//!   zero is one of the shortest.
//! - Nothing this encoder writes needs an encoder stream, so this side
//!   sends none. RFC 9204 section 4.2 allows that in so many words: "An
//!   endpoint MAY avoid creating an encoder stream if it will not be
//!   used."
//! - Every decoder reads what this writes. The representations it uses are
//!   the ones RFC 9204 requires of every implementation, and a section
//!   with a Required Insert Count of zero blocks no stream on any peer,
//!   whatever that peer set for SETTINGS_QPACK_BLOCKED_STREAMS.
//!
//! The cost is size on the wire. A request that repeats the same field
//! line on every hop sends it whole every time, where an inserting encoder
//! would send one octet after the first. Huffman coding takes back some of
//! that.
//!
//! This file owns the choice of representation and the writing of it. It
//! owns nothing below that, and it holds no state at all: there is no
//! `Encoder` type here because there is nothing for one to hold.

const std = @import("std");

const field = @import("field.zig");
const integer = @import("integer.zig");
const prefix = @import("prefix.zig");
const static_table = @import("static_table.zig");
const string = @import("string.zig");

const Allocator = std.mem.Allocator;

/// The prefix every section this encoder writes carries: it names no
/// dynamic entry, so it needs none of the table.
const empty_prefix: prefix.Prefix = .{ .required_insert_count = 0, .base = 0 };

/// The bits above the prefix, RFC 9204 sections 4.5.2, 4.5.4, and 4.5.6.
const indexed_pattern: u8 = 0x80;
const indexed_static_flag: u8 = 0x40;
const name_reference_pattern: u8 = 0x40;
const name_reference_static_flag: u8 = 0x10;
const name_reference_never_flag: u8 = 0x20;
const literal_name_pattern: u8 = 0x20;
const literal_name_never_flag: u8 = 0x10;

/// The prefix widths of the same three representations.
const indexed_prefix_bits = 6;
const name_reference_prefix_bits = 4;
const literal_name_string_prefix_bits = 4;
const value_prefix_bits = 8;

pub const Options = struct {
    /// Whether a name and a value go out Huffman coded.
    coding: string.Coding = .huffman_when_shorter,
};

/// The number of octets `encode` writes for `fields`.
pub fn encodedLen(fields: []const field.Field, options: Options) usize {
    var len = prefix.encodedLen(empty_prefix, 0);
    for (fields) |item| {
        switch (planFor(item)) {
            .indexed => |index| len += integer.encodedLen(indexed_prefix_bits, index),
            .name_reference => |plan| {
                len += integer.encodedLen(name_reference_prefix_bits, plan.index);
                len += string.encodedLen(value_prefix_bits, item.value, options.coding);
            },
            .literal_name => {
                len += string.encodedLen(literal_name_string_prefix_bits, item.name, options.coding);
                len += string.encodedLen(value_prefix_bits, item.value, options.coding);
            },
        }
    }
    return len;
}

/// Writes `fields` as one encoded field section into the front of `out`,
/// and returns the octets it used.
///
/// `out` must hold at least `encodedLen(fields, options)` octets, which is
/// the caller's to get right and so is an assert.
pub fn encode(fields: []const field.Field, options: Options, out: []u8) []u8 {
    std.debug.assert(out.len >= encodedLen(fields, options));

    var pos = prefix.encode(empty_prefix, 0, out).len;
    for (fields) |item| {
        switch (planFor(item)) {
            .indexed => |index| pos += writeInteger(
                indexed_prefix_bits,
                indexed_pattern | indexed_static_flag,
                index,
                out[pos..],
            ),
            .name_reference => |plan| {
                pos += writeInteger(name_reference_prefix_bits, plan.pattern, plan.index, out[pos..]);
                pos += string.encode(value_prefix_bits, 0, item.value, options.coding, out[pos..]).len;
            },
            .literal_name => |pattern| {
                pos += string.encode(
                    literal_name_string_prefix_bits,
                    pattern,
                    item.name,
                    options.coding,
                    out[pos..],
                ).len;
                pos += string.encode(value_prefix_bits, 0, item.value, options.coding, out[pos..]).len;
            },
        }
    }
    return out[0..pos];
}

/// Writes `fields` as one encoded field section into memory this function
/// allocates from `gpa`. The caller owns the returned slice.
pub fn encodeAlloc(
    gpa: Allocator,
    fields: []const field.Field,
    options: Options,
) Allocator.Error![]u8 {
    const out = try gpa.alloc(u8, encodedLen(fields, options));
    errdefer gpa.free(out);
    const written = encode(fields, options, out);
    std.debug.assert(written.len == out.len);
    return out;
}

/// Which representation one field line goes out as.
const Plan = union(enum) {
    /// The static table carries the name and the value together.
    indexed: u64,
    /// The static table carries the name.
    name_reference: struct { index: u64, pattern: u8 },
    /// The static table carries neither.
    literal_name: u8,
};

fn planFor(item: field.Field) Plan {
    // A field line the caller marked never indexed always goes out as a
    // literal, even when the static table carries its value. The marker is
    // a request that no table on the path holds this field line, and the
    // shortest representation is not worth answering that request with a
    // different one.
    const never: u8 = if (item.never_indexed) name_reference_never_flag else 0;
    const literal_never: u8 = if (item.never_indexed) literal_name_never_flag else 0;

    switch (static_table.find(item.name, item.value)) {
        .full => |index| {
            if (!item.never_indexed) return .{ .indexed = index };
            return .{ .name_reference = .{
                .index = index,
                .pattern = name_reference_pattern | name_reference_static_flag | never,
            } };
        },
        .name => |index| return .{ .name_reference = .{
            .index = index,
            .pattern = name_reference_pattern | name_reference_static_flag | never,
        } },
        .none => return .{ .literal_name = literal_name_pattern | literal_never },
    }
}

/// Writes one integer into the front of `out`, and returns the octets it
/// used.
///
/// `integer.encode` needs room for the widest integer it can write, and
/// `out` here is what is left of a buffer sized to the exact answer, which
/// near the end is less. So the integer goes into a scratch buffer first.
fn writeInteger(comptime prefix_bits: u4, high_bits: u8, value: u64, out: []u8) usize {
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

test "RFC 9204 B.1, a literal field line with a static name reference" {
    var out: [64]u8 = undefined;
    const fields = [_]field.Field{.{ .name = ":path", .value = "/index.html" }};
    const want = [_]u8{ 0x00, 0x00, 0x51, 0x0b } ++ "/index.html".*;

    try testing.expectEqualSlices(u8, &want, encodeInto(&out, &fields, .{ .coding = .raw }));
    try testing.expectEqual(want.len, encodedLen(&fields, .{ .coding = .raw }));
}

test "a field line the static table carries whole goes out as one octet" {
    var out: [64]u8 = undefined;
    const fields = [_]field.Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "" },
    };
    const want = [_]u8{ 0x00, 0x00, 0xd1, 0xc1, 0xd7, 0xc0 };

    try testing.expectEqualSlices(u8, &want, encodeInto(&out, &fields, .{ .coding = .raw }));
}

test "a name the static table does not carry goes out whole" {
    var out: [64]u8 = undefined;
    const fields = [_]field.Field{.{ .name = "custom-key", .value = "custom-value" }};
    // 0x27 is '001', N = 0, H = 0, and a name length that fills the three
    // bits under the flag, so the rest of the ten follows in one more
    // octet.
    const want = [_]u8{ 0x00, 0x00, 0x27, 0x03 } ++ "custom-key".* ++
        [_]u8{0x0c} ++ "custom-value".*;

    try testing.expectEqualSlices(u8, &want, encodeInto(&out, &fields, .{ .coding = .raw }));
}

test "a field line the caller marks sensitive goes out with the N bit set" {
    var out: [64]u8 = undefined;

    // A name the static table carries, so a name reference with N set.
    const named = [_]field.Field{
        .{ .name = "authorization", .value = "Bearer abc", .never_indexed = true },
    };
    const want_named = [_]u8{ 0x00, 0x00, 0x7f, 0x45, 0x0a } ++ "Bearer abc".*;
    try testing.expectEqualSlices(u8, &want_named, encodeInto(&out, &named, .{ .coding = .raw }));

    // A name it does not, so a literal name with N set.
    const literal = [_]field.Field{
        .{ .name = "x-secret", .value = "s", .never_indexed = true },
    };
    const want_literal = [_]u8{ 0x00, 0x00, 0x37, 0x01 } ++ "x-secret".* ++
        [_]u8{0x01} ++ "s".*;
    try testing.expectEqualSlices(u8, &want_literal, encodeInto(&out, &literal, .{ .coding = .raw }));
}

test "a sensitive field line the static table carries whole is still a literal" {
    var out: [64]u8 = undefined;
    const fields = [_]field.Field{
        .{ .name = ":method", .value = "GET", .never_indexed = true },
    };
    // Static index 17 is :method GET. Without the marker this would be one
    // octet, 0xd1.
    const want = [_]u8{ 0x00, 0x00, 0x7f, 0x02, 0x03 } ++ "GET".*;

    try testing.expectEqualSlices(u8, &want, encodeInto(&out, &fields, .{ .coding = .raw }));
}

test "a Huffman coded section is shorter and still says the same thing" {
    var out: [128]u8 = undefined;
    const fields = [_]field.Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "www.example.com" },
    };
    const want = [_]u8{
        0x00, 0x00, 0xd1, 0xd7, 0xc1, 0x50, 0x8c, 0xf1,
        0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
        0x90, 0xf4, 0xff,
    };

    try testing.expectEqualSlices(u8, &want, encodeInto(&out, &fields, .{}));
    try testing.expect(want.len < encodedLen(&fields, .{ .coding = .raw }));
}

test "an empty field list encodes to the prefix alone" {
    var out: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 2), encodedLen(&.{}, .{}));
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00 }, encodeInto(&out, &.{}, .{}));
}

test "the length an encode reports is the length it writes" {
    var out: [1024]u8 = undefined;
    const fields = [_]field.Field{
        .{ .name = ":status", .value = "200" },
        .{ .name = "cache-control", .value = "private" },
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
        .{ .name = "custom-key", .value = "custom-value" },
        .{ .name = "authorization", .value = "Bearer abc", .never_indexed = true },
        .{ .name = "x-empty", .value = "" },
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

test "every section this encoder writes has a Required Insert Count of zero" {
    var out: [1024]u8 = undefined;
    const fields = [_]field.Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "custom-key", .value = "custom-value" },
        .{ .name = "authorization", .value = "Bearer abc", .never_indexed = true },
    };
    inline for ([_]string.Coding{ .raw, .huffman_when_shorter }) |coding| {
        const written = encodeInto(&out, &fields, .{ .coding = coding });
        // The prefix is two zero octets, so the section blocks no stream
        // on any peer.
        try testing.expectEqual(@as(u8, 0x00), written[0]);
        try testing.expectEqual(@as(u8, 0x00), written[1]);

        const head = try prefix.decode(written, 0, 0);
        try testing.expectEqual(@as(u64, 0), head.prefix.required_insert_count);
        try testing.expectEqual(@as(u64, 0), head.prefix.base);
    }
}
