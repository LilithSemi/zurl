//! QUIC's variable-length integer, RFC 9000 section 16.
//!
//! **This is the number format under every other file in this package, so
//! a wrong bound here is a wrong bound in every frame.** The two most
//! significant bits of the first byte name the length: `00` is one byte,
//! `01` is two, `10` is four, and `11` is eight. The value takes the
//! remaining bits, in network byte order. So one encoding holds 6, 14, 30,
//! or 62 bits of value, and the largest number QUIC can write is
//! 4 611 686 018 427 387 903.
//!
//! **A varint can claim 2^62, and almost every one of them is a length.**
//! A frame writes a count of octets as a varint, and the octets follow it.
//! Nothing in this file allocates and nothing in this file reads past the
//! bytes it was given, so a peer that writes an enormous number gets an
//! enormous number back and no memory. `Cursor.zig` is where that number
//! meets the bytes that are really there, and it is the file that refuses
//! the pair.
//!
//! **A varint may be longer than it needs to be, and this file allows
//! that.** Section 16 says values do not need the minimum number of
//! bytes, with one exception: the Frame Type field of section 12.4. So
//! `decode` reads `0x4025` as 37, the same as `0x25`, and `isMinimal`
//! reports the difference for the one caller that must refuse it.
//! `frame.zig` is that caller.
//!
//! Pure bytes. This file opens nothing, allocates nothing, and knows no
//! frame and no packet.

const std = @import("std");

/// How many bytes one encoded value may take. RFC 9000 section 16.
pub const max_bytes: usize = 8;

/// The largest value the eight byte form names, 2^62 - 1.
pub const max_value: u64 = (1 << 62) - 1;

/// Why a value could not be encoded.
pub const EncodeError = error{
    /// The value is past `max_value`, so no QUIC encoding of it exists.
    /// A caller reached here with a number of its own, so this is a bug
    /// above and not a fault on the wire.
    ValueTooLarge,
};

/// How many bytes the shortest encoding of `value` takes.
pub fn encodedLen(value: u64) EncodeError!usize {
    if (value > max_value) return error.ValueTooLarge;
    if (value < (1 << 6)) return 1;
    if (value < (1 << 14)) return 2;
    if (value < (1 << 30)) return 4;
    return 8;
}

/// Writes the shortest encoding of `value` into `out`, and returns the
/// bytes it wrote.
pub fn encode(out: *[max_bytes]u8, value: u64) EncodeError![]u8 {
    const len = try encodedLen(value);
    switch (len) {
        1 => out[0] = @intCast(value),
        2 => {
            std.mem.writeInt(u16, out[0..2], @intCast(value), .big);
            out[0] |= 0x40;
        },
        4 => {
            std.mem.writeInt(u32, out[0..4], @intCast(value), .big);
            out[0] |= 0x80;
        },
        8 => {
            std.mem.writeInt(u64, out[0..8], value, .big);
            out[0] |= 0xc0;
        },
        else => unreachable,
    }
    return out[0..len];
}

/// Writes the shortest encoding of `value` onto a stream.
pub fn write(w: *std.Io.Writer, value: u64) (EncodeError || std.Io.Writer.Error)!void {
    var out: [max_bytes]u8 = undefined;
    try w.writeAll(try encode(&out, value));
}

/// Why a run of bytes is not a variable-length integer.
pub const DecodeError = error{
    /// The first byte named a length, and fewer bytes than that are
    /// here. A datagram that stops in the middle of a number lands here.
    Truncated,
};

/// One value read off the front of a run of bytes.
pub const Decoded = struct {
    value: u64,
    /// How many bytes of the run the value took. Always 1, 2, 4, or 8.
    len: usize,

    /// True when no shorter encoding names the same value.
    ///
    /// **Only the Frame Type field needs this.** RFC 9000 section 12.4
    /// makes that one field minimal and leaves every other varint free to
    /// be longer than it needs. Two spellings of one frame type is the
    /// shape where this build and a middle box read one packet as two, so
    /// `frame.zig` refuses the longer one.
    pub fn isMinimal(self: Decoded) bool {
        const shortest = encodedLen(self.value) catch return false;
        return self.len == shortest;
    }
};

/// Reads one variable-length integer off the front of `bytes`.
///
/// Reads at most `max_bytes`, so a caller that hands over a whole
/// datagram still gets one number and not a walk.
pub fn decode(bytes: []const u8) DecodeError!Decoded {
    if (bytes.len == 0) return error.Truncated;

    // The two most significant bits are the base-2 logarithm of the
    // length, so the length is 1, 2, 4, or 8 and never anything else.
    const prefix: u2 = @intCast(bytes[0] >> 6);
    const len: usize = @as(usize, 1) << prefix;
    // **The bound, and it runs before any byte after the first is read.**
    if (bytes.len < len) return error.Truncated;

    // The prefix bits are not part of the value.
    var value: u64 = bytes[0] & 0x3f;
    for (bytes[1..len]) |byte| value = (value << 8) | byte;
    return .{ .value = value, .len = len };
}

const testing = std.testing;

test "the four sample encodings of RFC 9000 appendix A.1 decode to their values" {
    // The examples the appendix names, byte for byte.
    const eight = [_]u8{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c };
    try testing.expectEqual(@as(u64, 151_288_809_941_952_652), (try decode(&eight)).value);
    try testing.expectEqual(@as(usize, 8), (try decode(&eight)).len);

    const four = [_]u8{ 0x9d, 0x7f, 0x3e, 0x7d };
    try testing.expectEqual(@as(u64, 494_878_333), (try decode(&four)).value);
    try testing.expectEqual(@as(usize, 4), (try decode(&four)).len);

    const two = [_]u8{ 0x7b, 0xbd };
    try testing.expectEqual(@as(u64, 15_293), (try decode(&two)).value);
    try testing.expectEqual(@as(usize, 2), (try decode(&two)).len);

    const one = [_]u8{0x25};
    try testing.expectEqual(@as(u64, 37), (try decode(&one)).value);
    try testing.expectEqual(@as(usize, 1), (try decode(&one)).len);

    // The appendix names this pair on purpose: `0x4025` is 37 as well.
    const one_long = [_]u8{ 0x40, 0x25 };
    try testing.expectEqual(@as(u64, 37), (try decode(&one_long)).value);
    try testing.expectEqual(@as(usize, 2), (try decode(&one_long)).len);
}

test "the four sample encodings of RFC 9000 appendix A.1 encode back byte for byte" {
    // Every one but `0x4025`, which is the longer spelling of 37 and not
    // what an encoder writes.
    const cases = [_]struct { value: u64, bytes: []const u8 }{
        .{ .value = 151_288_809_941_952_652, .bytes = &.{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c } },
        .{ .value = 494_878_333, .bytes = &.{ 0x9d, 0x7f, 0x3e, 0x7d } },
        .{ .value = 15_293, .bytes = &.{ 0x7b, 0xbd } },
        .{ .value = 37, .bytes = &.{0x25} },
    };
    for (cases) |case| {
        var out: [max_bytes]u8 = undefined;
        try testing.expectEqualSlices(u8, case.bytes, try encode(&out, case.value));
        try testing.expectEqual(case.bytes.len, try encodedLen(case.value));
    }
}

test "each row of table 4 round trips at both ends of its range" {
    const cases = [_]struct { value: u64, len: usize }{
        .{ .value = 0, .len = 1 },
        .{ .value = 63, .len = 1 },
        .{ .value = 64, .len = 2 },
        .{ .value = 16_383, .len = 2 },
        .{ .value = 16_384, .len = 4 },
        .{ .value = 1_073_741_823, .len = 4 },
        .{ .value = 1_073_741_824, .len = 8 },
        .{ .value = max_value, .len = 8 },
    };
    for (cases) |case| {
        var out: [max_bytes]u8 = undefined;
        const written = try encode(&out, case.value);
        try testing.expectEqual(case.len, written.len);

        const read = try decode(written);
        try testing.expectEqual(case.value, read.value);
        try testing.expectEqual(case.len, read.len);
        try testing.expect(read.isMinimal());
    }
}

test "the largest value is 2^62 - 1 and one more has no encoding" {
    try testing.expectEqual(@as(u64, 4_611_686_018_427_387_903), max_value);
    var out: [max_bytes]u8 = undefined;
    try testing.expectError(error.ValueTooLarge, encode(&out, max_value + 1));
    try testing.expectError(error.ValueTooLarge, encodedLen(std.math.maxInt(u64)));
}

test "a run that stops inside a number is Truncated and never read past" {
    // **The bound this file exists for.** The first byte says how many
    // bytes follow, and a peer that sends fewer must not make this read
    // whatever is after the datagram.
    try testing.expectError(error.Truncated, decode(&.{}));
    try testing.expectError(error.Truncated, decode(&.{0x40}));
    try testing.expectError(error.Truncated, decode(&.{ 0x80, 0x00 }));
    try testing.expectError(error.Truncated, decode(&.{ 0x80, 0x00, 0x00 }));
    try testing.expectError(error.Truncated, decode(&.{ 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }));
}

test "a longer spelling decodes and reports that it is not minimal" {
    // Section 16 allows this everywhere but the Frame Type field, so the
    // decode succeeds and the caller that cares asks.
    const spellings = [_][]const u8{
        &.{0x00},
        &.{ 0x40, 0x00 },
        &.{ 0x80, 0x00, 0x00, 0x00 },
        &.{ 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    };
    for (spellings, 0..) |bytes, i| {
        const read = try decode(bytes);
        try testing.expectEqual(@as(u64, 0), read.value);
        try testing.expectEqual(i == 0, read.isMinimal());
    }
}

test "decode reads one number and leaves the rest of the run alone" {
    const run = [_]u8{ 0x7b, 0xbd, 0xde, 0xad, 0xbe, 0xef };
    const read = try decode(&run);
    try testing.expectEqual(@as(u64, 15_293), read.value);
    try testing.expectEqual(@as(usize, 2), read.len);
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, run[read.len..]);
}

test "every value a walk of the whole range reaches round trips" {
    // A walk and not a handful of cases: the carry between the length
    // classes is where an encoder goes wrong, and it goes wrong at the
    // boundaries a spot check misses. The step is not a power of two, so
    // the walk lands either side of each boundary.
    var value: u64 = 0;
    var seen: usize = 0;
    while (value <= max_value) {
        var out: [max_bytes]u8 = undefined;
        const written = try encode(&out, value);
        const read = try decode(written);
        try testing.expectEqual(value, read.value);
        try testing.expectEqual(written.len, read.len);
        seen += 1;

        const step: u64 = 1_000_003;
        if (value > max_value - step) break;
        value += step;
        // The walk would take too long at that step alone, so it climbs.
        value +|= value / 64;
    }
    try testing.expect(seen > 200);
}

test "write puts the shortest encoding onto a stream" {
    var buffer: [32]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buffer);
    try write(&w, 37);
    try write(&w, 15_293);
    try write(&w, 494_878_333);
    try testing.expectEqualSlices(
        u8,
        &.{ 0x25, 0x7b, 0xbd, 0x9d, 0x7f, 0x3e, 0x7d },
        w.buffered(),
    );
}
