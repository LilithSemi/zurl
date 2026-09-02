//! The prefixed integer of RFC 7541 section 5.1, as RFC 9204 section 4.1.1
//! uses it.
//!
//! An integer starts in the low bits of an octet whose high bits carry
//! something else, and it continues into whole octets when it does not
//! fit. This file owns that form in both directions. It owns nothing else:
//! it does not know what the high bits mean, it never allocates, and it
//! never reads past the slice it was given.
//!
//! **The form is HPACK's, and the ceiling is not.** RFC 9204 section 4.1.1
//! says a QPACK implementation must decode integers up to and including 62
//! bits, where `zurl-hpack/integer.zig` stops at 32. QPACK also uses
//! prefix widths HPACK never does, from three bits up to eight. So this
//! file restates the coder with its own bounds rather than sharing one
//! that would have to be widened for QPACK and would then be looser than
//! HPACK needs.
//!
//! **A decode reads untrusted bytes.** A peer can send a continuation that
//! never ends, or one that names a number larger than this build can hold.
//! `continuation_octets_max` and `value_max` refuse each of those, so a
//! decode always stops, and always stops with a name.

const std = @import("std");

/// The largest value a decode returns, and the largest an encode takes.
///
/// RFC 9204 section 4.1.1 requires 62 bits, which is also the ceiling of a
/// QUIC variable length integer, so no length or stream id that reaches
/// this coder can be larger. Every integer in an encoded field section is
/// an index, a length, or a table size, and the bounds in `Decoder.zig`
/// already cut each of those far below this. A peer that names a larger
/// number is refused here rather than at a cast further in.
pub const value_max: u64 = (@as(u64, 1) << 62) - 1;

/// How many continuation octets a decode reads before it gives up.
///
/// Nine octets carry 63 bits, which is enough for every value up to
/// `value_max`. The bound matters on its own, apart from `value_max`: an
/// octet of 0x80 adds nothing to the value, so a peer could send them
/// forever and never overflow. This is what stops that.
pub const continuation_octets_max: usize = 9;

/// The most octets one encoded integer takes.
pub const encoded_len_max: usize = 1 + continuation_octets_max;

pub const Error = error{
    /// The slice ended in the middle of an integer.
    Truncated,
    /// The value is larger than `value_max`.
    IntegerOverflow,
    /// The continuation ran past `continuation_octets_max`.
    IntegerTooLong,
};

/// One decoded integer and the octets it used.
pub const Decoded = struct {
    value: u64,
    len: usize,
};

/// Reads the integer at the front of `bytes` with a `prefix_bits`-bit
/// prefix. The bits above the prefix in the first octet are ignored.
pub fn decode(comptime prefix_bits: u4, bytes: []const u8) Error!Decoded {
    const prefix_mask = comptime prefixMask(prefix_bits);

    if (bytes.len == 0) return error.Truncated;
    var value: u64 = bytes[0] & prefix_mask;
    if (value < prefix_mask) return .{ .value = value, .len = 1 };

    // The prefix was all ones, so the rest of the value follows in seven
    // bits per octet, least significant group first, with the high bit set
    // on every octet but the last.
    var shift: u7 = 0;
    var octet_index: usize = 1;
    while (octet_index <= continuation_octets_max) : (octet_index += 1) {
        if (octet_index >= bytes.len) return error.Truncated;
        const octet = bytes[octet_index];
        // The sum is held in 128 bits so the widest shift this loop can
        // reach cannot wrap before the ceiling is checked.
        const sum = @as(u128, value) + (@as(u128, octet & 0x7f) << shift);
        if (sum > value_max) return error.IntegerOverflow;
        value = @intCast(sum);
        if (octet & 0x80 == 0) return .{ .value = value, .len = octet_index + 1 };
        shift += 7;
    }
    return error.IntegerTooLong;
}

/// The number of octets `encode` writes for `value`.
pub fn encodedLen(comptime prefix_bits: u4, value: u64) usize {
    const prefix_mask = comptime prefixMask(prefix_bits);
    if (value < prefix_mask) return 1;

    var rest: u64 = value - prefix_mask;
    var len: usize = 2;
    while (rest >= 128) : (len += 1) rest >>= 7;
    return len;
}

/// Writes `value` with a `prefix_bits`-bit prefix into the front of `out`,
/// and returns the octets it used.
///
/// `high_bits` is the representation pattern that sits above the prefix,
/// such as 0x80 for an indexed field line. It must carry no bit inside the
/// prefix, `value` must be no larger than `value_max`, and `out` must hold
/// at least `encoded_len_max` octets. All three are the caller's to get
/// right, so all three are asserts.
pub fn encode(comptime prefix_bits: u4, high_bits: u8, value: u64, out: []u8) []u8 {
    const prefix_mask = comptime prefixMask(prefix_bits);
    std.debug.assert(out.len >= encoded_len_max);
    std.debug.assert(high_bits & prefix_mask == 0);
    std.debug.assert(value <= value_max);

    if (value < prefix_mask) {
        out[0] = high_bits | @as(u8, @intCast(value));
        return out[0..1];
    }

    out[0] = high_bits | prefix_mask;
    var rest: u64 = value - prefix_mask;
    var len: usize = 1;
    while (rest >= 128) : (len += 1) {
        out[len] = @as(u8, @truncate(rest & 0x7f)) | 0x80;
        rest >>= 7;
    }
    out[len] = @intCast(rest);
    return out[0 .. len + 1];
}

/// The low `prefix_bits` bits, as the mask that reads them and as the
/// largest value the prefix alone can hold.
fn prefixMask(comptime prefix_bits: u4) u8 {
    comptime {
        if (prefix_bits < 1 or prefix_bits > 8) {
            @compileError("a qpack integer prefix is 1 to 8 bits, RFC 7541 section 5.1");
        }
        return @truncate((@as(u16, 1) << prefix_bits) - 1);
    }
}

const testing = std.testing;

test "RFC 7541 C.1.1, 10 in a 5-bit prefix is one octet" {
    var out: [encoded_len_max]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{0x0a}, encode(5, 0, 10, &out));

    const got = try decode(5, &.{0x0a});
    try testing.expectEqual(@as(u64, 10), got.value);
    try testing.expectEqual(@as(usize, 1), got.len);
}

test "RFC 7541 C.1.2, 1337 in a 5-bit prefix is three octets" {
    var out: [encoded_len_max]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 0x1f, 0x9a, 0x0a }, encode(5, 0, 1337, &out));

    const got = try decode(5, &.{ 0x1f, 0x9a, 0x0a });
    try testing.expectEqual(@as(u64, 1337), got.value);
    try testing.expectEqual(@as(usize, 3), got.len);
}

test "RFC 7541 C.1.3, 42 at an octet boundary is one octet" {
    var out: [encoded_len_max]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{0x2a}, encode(8, 0, 42, &out));

    const got = try decode(8, &.{0x2a});
    try testing.expectEqual(@as(u64, 42), got.value);
    try testing.expectEqual(@as(usize, 1), got.len);
}

test "RFC 9204 B.2, a set capacity of 220 in a 5-bit prefix" {
    var out: [encoded_len_max]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 0x1f, 0xbd, 0x01 }, encode(5, 0, 220, &out));
    try testing.expectEqual(@as(u64, 220), (try decode(5, &.{ 0x1f, 0xbd, 0x01 })).value);
}

test "the bits above the prefix are kept on an encode and ignored on a decode" {
    var out: [encoded_len_max]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{0x8a}, encode(7, 0x80, 10, &out));
    try testing.expectEqual(@as(u64, 10), (try decode(7, &.{0x8a})).value);
    try testing.expectEqual(@as(u64, 10), (try decode(7, &.{0x0a})).value);
}

test "a value that exactly fills the prefix still needs a continuation octet" {
    var out: [encoded_len_max]u8 = undefined;
    // 31 does not fit a 5-bit prefix, because all ones means "read on".
    try testing.expectEqualSlices(u8, &.{ 0x1f, 0x00 }, encode(5, 0, 31, &out));
    try testing.expectEqual(@as(u64, 31), (try decode(5, &.{ 0x1f, 0x00 })).value);
    try testing.expectEqual(@as(u64, 30), (try decode(5, &.{0x1e})).value);
}

test "every prefix width round-trips a spread of values" {
    var out: [encoded_len_max]u8 = undefined;
    const values = [_]u64{
        0,       1,       3,       4,             7,         8,
        15,      16,      30,      31,            127,       128,
        255,     256,     1337,    65535,         1 << 24,   1 << 31,
        1 << 32, 1 << 48, 1 << 61, value_max - 1, value_max,
    };
    inline for ([_]u4{ 1, 2, 3, 4, 5, 6, 7, 8 }) |bits| {
        for (values) |value| {
            const written = encode(bits, 0, value, &out);
            try testing.expectEqual(encodedLen(bits, value), written.len);
            const got = try decode(bits, written);
            try testing.expectEqual(value, got.value);
            try testing.expectEqual(written.len, got.len);
        }
    }
}

test "the 62 bit ceiling RFC 9204 section 4.1.1 asks for is reached" {
    var out: [encoded_len_max]u8 = undefined;
    // 2^62 - 1 is the largest value the RFC requires an implementation to
    // decode, and it is the largest this build holds.
    try testing.expectEqual(@as(u64, 0x3fff_ffff_ffff_ffff), value_max);
    const written = encode(8, 0, value_max, &out);
    try testing.expect(written.len <= encoded_len_max);
    try testing.expectEqual(value_max, (try decode(8, written)).value);
}

test "an integer that runs off the end of the slice is truncated, not read past" {
    try testing.expectError(error.Truncated, decode(5, &.{}));
    try testing.expectError(error.Truncated, decode(5, &.{0x1f}));
    try testing.expectError(error.Truncated, decode(5, &.{ 0x1f, 0x9a }));
}

test "a continuation that never ends is refused, not read forever" {
    const forever = [_]u8{0x1f} ++ [_]u8{0x80} ** 64;
    try testing.expectError(error.IntegerTooLong, decode(5, &forever));
}

test "a continuation of harmless zeroes still stops at the octet bound" {
    // Every octet adds nothing to the value, so no overflow ever fires.
    // Only the octet bound refuses this one.
    const zeroes = [_]u8{0x1f} ++ [_]u8{0x80} ** continuation_octets_max ++ [_]u8{0x00};
    try testing.expectError(error.IntegerTooLong, decode(5, &zeroes));
}

test "an integer larger than the bound is refused before it wraps" {
    // 0x1f then nine octets that carry 63 bits of ones, which is past
    // 2^62 - 1.
    const over = [_]u8{0x1f} ++ [_]u8{0xff} ** 8 ++ [_]u8{0x7f};
    try testing.expectError(error.IntegerOverflow, decode(5, &over));
}

test "the largest value this build holds decodes and the next one does not" {
    var out: [encoded_len_max]u8 = undefined;
    const written = encode(5, 0, value_max, &out);
    try testing.expectEqual(value_max, (try decode(5, written)).value);

    // One more than value_max, in the same shape.
    var over = [_]u8{0} ** encoded_len_max;
    @memcpy(over[0..written.len], written);
    over[written.len - 1] += 1;
    try testing.expectError(error.IntegerOverflow, decode(5, over[0..written.len]));
}
