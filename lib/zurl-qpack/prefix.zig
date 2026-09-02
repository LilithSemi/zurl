//! The encoded field section prefix, RFC 9204 section 4.5.1.
//!
//! Two integers sit in front of every encoded field section: the Required
//! Insert Count, which says how much of the dynamic table the section
//! needs, and the Base, which every relative index in the section counts
//! back from. This file owns both, in both directions, and the folding the
//! RFC puts on the first of them. It owns nothing else: it reads no field
//! line and it holds no table.
//!
//! **The Required Insert Count does not go on the wire as it is.** RFC
//! 9204 section 4.5.1.1 folds it modulo twice MaxEntries, so the prefix
//! stays short on a connection that runs for a long time. The decoder gets
//! it back from the fold, its own insert count, and MaxEntries, all three
//! of which are numbers this side already knows. `decodeInsertCount`
//! refuses every folded value a conformant encoder could not have written.
//!
//! **The Base is written as a difference.** A sign bit says which way, and
//! the value under it is the distance from the Required Insert Count. A
//! sign of 1 with a distance at or past the Required Insert Count would
//! put the Base below zero, which the RFC forbids in so many words, and
//! `decode` refuses it.

const std = @import("std");

const integer = @import("integer.zig");

/// The prefix width of the Required Insert Count, RFC 9204 section 4.5.1.
const insert_count_prefix_bits = 8;

/// The prefix width of the Delta Base. The bit above it is the sign.
const delta_base_prefix_bits = 7;

/// The sign bit of the Delta Base. Set means the Base is below the
/// Required Insert Count.
const sign_flag: u8 = 0x80;

pub const Error = integer.Error || error{
    /// The folded Required Insert Count is one no conformant encoder could
    /// have written. RFC 9204 section 4.5.1.1 says that is a
    /// QPACK_DECOMPRESSION_FAILED.
    InvalidRequiredInsertCount,
    /// The sign bit is set and the Delta Base is at or past the Required
    /// Insert Count, so the Base would be below zero. RFC 9204 section
    /// 4.5.1.2 forbids that.
    InvalidBase,
};

/// One field section prefix, with both numbers already worked out.
pub const Prefix = struct {
    /// How many entries the dynamic table must hold before this section
    /// can be decoded. Zero means the section names no dynamic entry.
    required_insert_count: u64,
    /// The absolute index that a relative index of 0 counts back from,
    /// plus one, and the absolute index a post-base index of 0 names.
    base: u64,
};

/// One decoded prefix and the octets it used.
pub const Decoded = struct {
    prefix: Prefix,
    len: usize,
};

/// Folds the Required Insert Count for the wire, RFC 9204 section 4.5.1.1.
///
/// `max_entries` must be above zero when `required` is, because a table
/// that can hold no entry cannot have been referenced. That is this side's
/// own arithmetic, so it is an assert.
pub fn encodeInsertCount(required: u64, max_entries: u64) u64 {
    if (required == 0) return 0;
    std.debug.assert(max_entries > 0);
    return (required % (2 * max_entries)) + 1;
}

/// Unfolds the Required Insert Count, RFC 9204 section 4.5.1.1.
///
/// `total_inserts` is how many entries this side's dynamic table has taken
/// in, and `max_entries` is MaxEntries. The two of them are what turn the
/// short number on the wire back into the long one.
pub fn decodeInsertCount(encoded: u64, total_inserts: u64, max_entries: u64) Error!u64 {
    if (encoded == 0) return 0;

    // A table that can hold no entry can be referenced by no section, so
    // any folded value above zero is one no conformant encoder wrote.
    if (max_entries == 0) return error.InvalidRequiredInsertCount;
    const full_range = 2 * max_entries;
    if (encoded > full_range) return error.InvalidRequiredInsertCount;

    const max_value = std.math.add(u64, total_inserts, max_entries) catch
        return error.InvalidRequiredInsertCount;

    // The largest value at or below `max_value` that the fold maps to
    // itself, and then the one the wire named inside that window.
    const max_wrapped = (max_value / full_range) * full_range;
    var required = max_wrapped + encoded - 1;
    if (required > max_value) {
        // The encoder's value wrapped one time fewer than this side
        // guessed, so step the window back. A window that cannot step back
        // means the wire named a value the encoder could not have held.
        if (required <= full_range) return error.InvalidRequiredInsertCount;
        required -= full_range;
    }
    // RFC 9204 section 4.5.1.1: a Required Insert Count of zero has to be
    // written as zero, so no other folded value may unfold to it.
    if (required == 0) return error.InvalidRequiredInsertCount;
    return required;
}

/// Reads the prefix at the front of `bytes`.
///
/// `total_inserts` and `max_entries` come from this side's dynamic table.
pub fn decode(bytes: []const u8, total_inserts: u64, max_entries: u64) Error!Decoded {
    const encoded = try integer.decode(insert_count_prefix_bits, bytes);
    const required = try decodeInsertCount(encoded.value, total_inserts, max_entries);

    var pos = encoded.len;
    if (pos >= bytes.len) return error.Truncated;
    const negative = bytes[pos] & sign_flag != 0;
    const delta = try integer.decode(delta_base_prefix_bits, bytes[pos..]);
    pos += delta.len;

    // RFC 9204 section 4.5.1.2.
    const base = if (negative) base: {
        if (delta.value >= required) return error.InvalidBase;
        break :base required - delta.value - 1;
    } else base: {
        const sum = std.math.add(u64, required, delta.value) catch return error.InvalidBase;
        // Every index in this package stays inside the integer ceiling of
        // RFC 9204 section 4.1.1, so a Base above it is refused here and
        // not at a cast further in.
        if (sum > integer.value_max) return error.InvalidBase;
        break :base sum;
    };

    return .{ .prefix = .{ .required_insert_count = required, .base = base }, .len = pos };
}

/// The number of octets `encode` writes for `prefix`.
pub fn encodedLen(prefix: Prefix, max_entries: u64) usize {
    const parts = split(prefix, max_entries);
    return integer.encodedLen(insert_count_prefix_bits, parts.encoded_insert_count) +
        integer.encodedLen(delta_base_prefix_bits, parts.delta_base);
}

/// Writes `prefix` into the front of `out`, and returns the octets it
/// used.
///
/// `out` must hold at least `encodedLen(prefix, max_entries)` octets,
/// which is the caller's to get right and so is an assert.
pub fn encode(prefix: Prefix, max_entries: u64, out: []u8) []u8 {
    std.debug.assert(out.len >= encodedLen(prefix, max_entries));
    const parts = split(prefix, max_entries);

    // Each integer goes into a scratch buffer first. `integer.encode`
    // needs room for the widest integer it can write, and `out` is allowed
    // to be exactly `encodedLen` long, which here is less.
    var scratch: [integer.encoded_len_max]u8 = undefined;
    const count = integer.encode(insert_count_prefix_bits, 0, parts.encoded_insert_count, &scratch);
    @memcpy(out[0..count.len], count);

    var pos = count.len;
    const flag: u8 = if (parts.negative) sign_flag else 0;
    const delta = integer.encode(delta_base_prefix_bits, flag, parts.delta_base, &scratch);
    @memcpy(out[pos..][0..delta.len], delta);
    pos += delta.len;
    return out[0..pos];
}

/// The three numbers the wire carries, worked out from the two a caller
/// gives.
const Parts = struct {
    encoded_insert_count: u64,
    negative: bool,
    delta_base: u64,
};

fn split(prefix: Prefix, max_entries: u64) Parts {
    const negative = prefix.base < prefix.required_insert_count;
    return .{
        .encoded_insert_count = encodeInsertCount(prefix.required_insert_count, max_entries),
        .negative = negative,
        .delta_base = if (negative)
            prefix.required_insert_count - prefix.base - 1
        else
            prefix.base - prefix.required_insert_count,
    };
}

const testing = std.testing;

test "RFC 9204 B.1, a section that names no dynamic entry has a prefix of two zeroes" {
    const got = try decode(&.{ 0x00, 0x00 }, 0, 0);
    try testing.expectEqual(@as(u64, 0), got.prefix.required_insert_count);
    try testing.expectEqual(@as(u64, 0), got.prefix.base);
    try testing.expectEqual(@as(usize, 2), got.len);

    var out: [16]u8 = undefined;
    const written = encode(.{ .required_insert_count = 0, .base = 0 }, 0, &out);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00 }, written);
}

test "RFC 9204 B.2, Required Insert Count 2 and Base 0 on a table of 220 bytes" {
    // MaxEntries is 220 / 32 = 6, so the fold is modulo 12. This side has
    // taken in the two inserts the encoder stream carried.
    const got = try decode(&.{ 0x03, 0x81 }, 2, 6);
    try testing.expectEqual(@as(u64, 2), got.prefix.required_insert_count);
    try testing.expectEqual(@as(u64, 0), got.prefix.base);
    try testing.expectEqual(@as(usize, 2), got.len);

    var out: [16]u8 = undefined;
    const written = encode(.{ .required_insert_count = 2, .base = 0 }, 6, &out);
    try testing.expectEqualSlices(u8, &.{ 0x03, 0x81 }, written);
}

test "RFC 9204 B.4, Required Insert Count 4 and Base 4 on the same table" {
    const got = try decode(&.{ 0x05, 0x00 }, 4, 6);
    try testing.expectEqual(@as(u64, 4), got.prefix.required_insert_count);
    try testing.expectEqual(@as(u64, 4), got.prefix.base);

    var out: [16]u8 = undefined;
    const written = encode(.{ .required_insert_count = 4, .base = 4 }, 6, &out);
    try testing.expectEqualSlices(u8, &.{ 0x05, 0x00 }, written);
}

test "RFC 9204 section 4.5.1.1, the worked example of a 100 byte table" {
    // "if the dynamic table is 100 bytes, then the Required Insert Count
    // will be encoded modulo 6. If a decoder has received 10 inserts, then
    // an encoded value of 4 indicates that the Required Insert Count is 9."
    const max_entries: u64 = 100 / 32;
    try testing.expectEqual(@as(u64, 3), max_entries);
    try testing.expectEqual(@as(u64, 4), encodeInsertCount(9, max_entries));
    try testing.expectEqual(@as(u64, 9), try decodeInsertCount(4, 10, max_entries));
}

test "RFC 9204 section 4.5.1.2, the worked example of a Base below the count" {
    // "with a Required Insert Count of 9, a decoder receives a Sign bit of
    // 1 and a Delta Base of 2. This sets the Base to 6."
    const got = try decode(&.{ 0x04, 0x82 }, 10, 3);
    try testing.expectEqual(@as(u64, 9), got.prefix.required_insert_count);
    try testing.expectEqual(@as(u64, 6), got.prefix.base);
}

test "the fold round-trips over a run that wraps the window many times" {
    const max_entries: u64 = 6;
    var required: u64 = 1;
    while (required <= 200) : (required += 1) {
        const encoded = encodeInsertCount(required, max_entries);
        try testing.expect(encoded >= 1);
        try testing.expect(encoded <= 2 * max_entries);

        // The fold is unambiguous over a window of `full_range` values
        // that ends at TotalInserts + MaxEntries. So a decoder can be
        // anywhere from exactly as far along as the section needs to one
        // short of MaxEntries further on.
        var inserts = required;
        while (inserts < required + max_entries) : (inserts += 1) {
            try testing.expectEqual(required, try decodeInsertCount(encoded, inserts, max_entries));
        }
    }
}

test "a prefix round-trips over a spread of counts and bases" {
    const max_entries: u64 = 6;
    var out: [32]u8 = undefined;
    var required: u64 = 0;
    while (required <= 40) : (required += 1) {
        var base: u64 = 0;
        while (base <= required + 8) : (base += 1) {
            const want: Prefix = .{ .required_insert_count = required, .base = base };
            const written = encode(want, max_entries, &out);
            try testing.expectEqual(encodedLen(want, max_entries), written.len);

            // A decoder that has taken in exactly what the section needs.
            const got = try decode(written, required, max_entries);
            try testing.expectEqual(want.required_insert_count, got.prefix.required_insert_count);
            try testing.expectEqual(want.base, got.prefix.base);
            try testing.expectEqual(written.len, got.len);
        }
    }
}

test "a folded count above twice MaxEntries is refused" {
    try testing.expectError(error.InvalidRequiredInsertCount, decodeInsertCount(13, 4, 6));
    try testing.expectError(
        error.InvalidRequiredInsertCount,
        decodeInsertCount(std.math.maxInt(u64), 4, 6),
    );
}

test "a folded count above zero against a table that holds nothing is refused" {
    try testing.expectError(error.InvalidRequiredInsertCount, decodeInsertCount(1, 0, 0));
    try testing.expectEqual(@as(u64, 0), try decodeInsertCount(0, 0, 0));
    try testing.expectError(
        error.InvalidRequiredInsertCount,
        decode(&.{ 0x01, 0x00 }, 0, 0),
    );
}

test "a folded count that would unfold to zero is refused" {
    // With MaxEntries 6 the window is 12. A decoder with no inserts has a
    // MaxValue of 6, so a folded value of 1 would unfold to 0, which the
    // RFC says must have been written as 0.
    try testing.expectError(error.InvalidRequiredInsertCount, decodeInsertCount(1, 0, 6));
    try testing.expectEqual(@as(u64, 1), try decodeInsertCount(2, 0, 6));
}

test "a folded count past what this side has received is refused" {
    // MaxEntries 6, so a decoder with two inserts can be asked for at most
    // eight. A folded value of 10 would name nine.
    try testing.expectEqual(@as(u64, 8), try decodeInsertCount(9, 2, 6));
    try testing.expectError(error.InvalidRequiredInsertCount, decodeInsertCount(10, 2, 6));
}

test "a Base that would fall below zero is refused" {
    // Required Insert Count 2, sign 1, Delta Base 2. RFC 9204 section
    // 4.5.1.2: "An endpoint MUST treat a field block with a Sign bit of 1
    // as invalid if the value of Required Insert Count is less than or
    // equal to the value of Delta Base."
    try testing.expectError(error.InvalidBase, decode(&.{ 0x03, 0x82 }, 2, 6));
    try testing.expectError(error.InvalidBase, decode(&.{ 0x03, 0x83 }, 2, 6));

    // One less is the largest Delta Base this count allows, and it puts
    // the Base at zero.
    const got = try decode(&.{ 0x03, 0x81 }, 2, 6);
    try testing.expectEqual(@as(u64, 0), got.prefix.base);
}

test "a Base at the largest integer this build holds still decodes" {
    var out: [32]u8 = undefined;
    const want: Prefix = .{ .required_insert_count = 0, .base = integer.value_max };
    const written = encode(want, 6, &out);

    const got = try decode(written, 0, 6);
    try testing.expectEqual(@as(u64, 0), got.prefix.required_insert_count);
    try testing.expectEqual(integer.value_max, got.prefix.base);
}

test "a Base past the largest integer this build holds is refused" {
    var scratch: [integer.encoded_len_max]u8 = undefined;
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(testing.allocator);
    try bytes.appendSlice(testing.allocator, integer.encode(8, 0, 2, &scratch));
    try bytes.appendSlice(testing.allocator, integer.encode(7, 0, integer.value_max, &scratch));

    // This side has taken in as many inserts as the integer coder counts,
    // so the Required Insert Count lands near the ceiling and the Delta
    // Base would push the Base past it.
    try testing.expectError(error.InvalidBase, decode(bytes.items, integer.value_max, 6));
}

test "a prefix that ends after the first integer is truncated" {
    try testing.expectError(error.Truncated, decode(&.{}, 0, 6));
    try testing.expectError(error.Truncated, decode(&.{0x00}, 0, 6));
    try testing.expectError(error.Truncated, decode(&.{ 0x03, 0xff }, 2, 6));
}
