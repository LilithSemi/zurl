//! HPACK integer coding, RFC 7541 section 5.1.
//!
//! An HPACK integer starts in the low bits of an octet whose high bits
//! carry something else, and it continues into whole octets when it does
//! not fit. This file owns that form in both directions. It owns nothing
//! else: it does not know what the high bits mean, it never allocates, and
//! it never reads past the slice it was given.
//!
//! **A decode reads untrusted bytes.** A peer can send a continuation that
//! never ends, or one that names a number larger than this build can hold.
//! `continuation_octets_max` and `value_max` refuse each of those, so a
//! decode always stops, and always stops with a name.

const std = @import("std");

/// The largest value a decode returns, and the largest an encode takes.
///
/// HPACK puts no ceiling on an integer. This build sets one, because every
/// integer in a header block is a length, an index, or a table size, and
/// each of those is already smaller than this by the bounds in
/// `Decoder.zig`. A peer that names a larger number is refused here rather
/// than at a cast further in.
pub const value_max: u32 = std.math.maxInt(u32);

/// How many continuation octets a decode reads before it gives up.
///
/// Five octets carry 35 bits, which is enough for every value up to
/// `value_max`. The bound matters on its own, apart from `value_max`: an
/// octet of 0x80 adds nothing to the value, so a peer could send them
/// forever and never overflow. This is what stops that.
pub const continuation_octets_max: usize = 5;

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
    value: u32,
    len: usize,
};

/// Reads the integer at the front of `bytes` with a `prefix_bits`-bit
/// prefix. The bits above the prefix in the first octet are ignored.
pub fn decode(comptime prefix_bits: u4, bytes: []const u8) Error!Decoded {
    const prefix_mask = comptime prefixMask(prefix_bits);

    if (bytes.len == 0) return error.Truncated;
    var value: u32 = bytes[0] & prefix_mask;
    if (value < prefix_mask) return .{ .value = value, .len = 1 };

    // The prefix was all ones, so the rest of the value follows in seven
    // bits per octet, least significant group first, with the high bit set
    // on every octet but the last.
    var shift: u6 = 0;
    var octet_index: usize = 1;
    while (octet_index <= continuation_octets_max) : (octet_index += 1) {
        if (octet_index >= bytes.len) return error.Truncated;
        const octet = bytes[octet_index];
        const sum = @as(u64, value) + (@as(u64, octet & 0x7f) << shift);
        if (sum > value_max) return error.IntegerOverflow;
        value = @intCast(sum);
        if (octet & 0x80 == 0) return .{ .value = value, .len = octet_index + 1 };
        shift += 7;
    }
    return error.IntegerTooLong;
}

/// The number of octets `encode` writes for `value`.
pub fn encodedLen(comptime prefix_bits: u4, value: u32) usize {
    const prefix_mask = comptime prefixMask(prefix_bits);
    if (value < prefix_mask) return 1;

    var rest: u32 = value - prefix_mask;
    var len: usize = 2;
    while (rest >= 128) : (len += 1) rest >>= 7;
    return len;
}

/// Writes `value` with a `prefix_bits`-bit prefix into the front of `out`,
/// and returns the octets it used.
///
/// `high_bits` is the representation pattern that sits above the prefix,
/// such as 0x80 for an indexed header field. It must carry no bit inside
/// the prefix, and `out` must hold at least `encoded_len_max` octets. Both
/// are the caller's to get right, so both are asserts.
pub fn encode(comptime prefix_bits: u4, high_bits: u8, value: u32, out: []u8) []u8 {
    const prefix_mask = comptime prefixMask(prefix_bits);
    std.debug.assert(out.len >= encoded_len_max);
    std.debug.assert(high_bits & prefix_mask == 0);

    if (value < prefix_mask) {
        out[0] = high_bits | @as(u8, @intCast(value));
        return out[0..1];
    }

    out[0] = high_bits | prefix_mask;
    var rest: u32 = value - prefix_mask;
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
            @compileError("an hpack integer prefix is 1 to 8 bits, RFC 7541 section 5.1");
        }
        return @truncate((@as(u16, 1) << prefix_bits) - 1);
    }
}

const testing = std.testing;

test "RFC 7541 C.1.1, 10 in a 5-bit prefix is one octet" {
    var out: [encoded_len_max]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{0x0a}, encode(5, 0, 10, &out));

    const got = try decode(5, &.{0x0a});
    try testing.expectEqual(@as(u32, 10), got.value);
    try testing.expectEqual(@as(usize, 1), got.len);
}

test "RFC 7541 C.1.2, 1337 in a 5-bit prefix is three octets" {
    var out: [encoded_len_max]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 0x1f, 0x9a, 0x0a }, encode(5, 0, 1337, &out));

    const got = try decode(5, &.{ 0x1f, 0x9a, 0x0a });
    try testing.expectEqual(@as(u32, 1337), got.value);
    try testing.expectEqual(@as(usize, 3), got.len);
}

test "RFC 7541 C.1.3, 42 at an octet boundary is one octet" {
    var out: [encoded_len_max]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{0x2a}, encode(8, 0, 42, &out));

    const got = try decode(8, &.{0x2a});
    try testing.expectEqual(@as(u32, 42), got.value);
    try testing.expectEqual(@as(usize, 1), got.len);
}

test "the bits above the prefix are kept on an encode and ignored on a decode" {
    var out: [encoded_len_max]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{0x8a}, encode(7, 0x80, 10, &out));
    try testing.expectEqual(@as(u32, 10), (try decode(7, &.{0x8a})).value);
    try testing.expectEqual(@as(u32, 10), (try decode(7, &.{0x0a})).value);
}

test "a value that exactly fills the prefix still needs a continuation octet" {
    var out: [encoded_len_max]u8 = undefined;
    // 31 does not fit a 5-bit prefix, because all ones means "read on".
    try testing.expectEqualSlices(u8, &.{ 0x1f, 0x00 }, encode(5, 0, 31, &out));
    try testing.expectEqual(@as(u32, 31), (try decode(5, &.{ 0x1f, 0x00 })).value);
    try testing.expectEqual(@as(u32, 30), (try decode(5, &.{0x1e})).value);
}

test "every prefix width round-trips a spread of values" {
    var out: [encoded_len_max]u8 = undefined;
    const values = [_]u32{ 0, 1, 30, 31, 127, 128, 255, 256, 1337, 65535, 1 << 24, value_max };
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
    try testing.expectError(
        error.IntegerTooLong,
        decode(5, &.{ 0x1f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 }),
    );
}

test "an integer larger than the bound is refused before it wraps" {
    // 0x1f then five octets that add up past 2^32.
    try testing.expectError(
        error.IntegerOverflow,
        decode(5, &.{ 0x1f, 0xff, 0xff, 0xff, 0xff, 0x7f }),
    );
}

test "the largest value this build holds decodes and the next one does not" {
    var out: [encoded_len_max]u8 = undefined;
    const written = encode(5, 0, value_max, &out);
    try testing.expectEqual(@as(u32, value_max), (try decode(5, written)).value);

    // One more than value_max, in the same shape.
    var over = [_]u8{0} ** encoded_len_max;
    @memcpy(over[0..written.len], written);
    over[written.len - 1] += 1;
    try testing.expectError(error.IntegerOverflow, decode(5, over[0..written.len]));
}
