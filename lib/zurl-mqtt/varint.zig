//! MQTT 3.1.1's variable byte integer, which is the remaining length field
//! of every packet.
//!
//! **This file holds the bound on the one number a peer chooses that
//! decides how many bytes this process then reads.** MQTT 3.1.1 section
//! 2.2.3 writes the length of everything after the fixed header as one to
//! four bytes, seven bits of value in each and the top bit saying that
//! another byte follows. Four bytes name 268 435 455 octets, which is 256
//! MiB less one. A reader that took that number and allocated would let
//! one packet header of five bytes ask this process for a quarter of a
//! gigabyte, and a reader that kept taking continuation bytes would let a
//! peer that never clears the top bit hold the read forever.
//!
//! So this file refuses three shapes, each by name:
//!
//! - **A fifth continuation byte is `error.TooManyBytes`.** Four is the
//!   whole of what section 2.2.3 allows, and the fifth byte is where an
//!   unbounded reader would loop.
//! - **A run that ends with the top bit still set is
//!   `error.Incomplete`.** The caller reads one byte at a time off a
//!   socket, so this is the answer for a run that is not finished yet and
//!   the caller decides whether to read another byte or stop.
//! - **An encoding longer than the value needs is `error.NotMinimal`.**
//!   `80 00` and `00` both name zero. Two spellings of one length is the
//!   shape where this process and a middle box disagree about where a
//!   packet ends, so only the shorter one is read.
//!
//! **This file bounds the encoding and never the packet.** A caller that
//! has a length still has to check it against its own ceiling before it
//! allocates. `zurl_mqtt.Session.max_packet_bytes` is that ceiling, and
//! `Session.receive` is where the check runs.
//!
//! Pure bytes. This file opens nothing, allocates nothing, and knows no
//! MQTT packet type at all.

const std = @import("std");

/// How many bytes one encoded value may take. MQTT 3.1.1 section 2.2.3.
pub const max_bytes: usize = 4;

/// The largest value four bytes name: 268 435 455 octets.
pub const max_value: u32 = 268_435_455;

/// Why a value could not be encoded.
pub const EncodeError = error{
    /// The value is past `max_value`, so no legal encoding of it exists.
    ValueTooLarge,
};

/// How many bytes `value` encodes into.
pub fn encodedLen(value: u32) EncodeError!usize {
    if (value > max_value) return error.ValueTooLarge;
    if (value < 128) return 1;
    if (value < 16_384) return 2;
    if (value < 2_097_152) return 3;
    return 4;
}

/// Writes `value` into `out` and returns the bytes it wrote.
///
/// The result is the minimal encoding, which is what `decode` reads back.
pub fn encode(out: *[max_bytes]u8, value: u32) EncodeError![]u8 {
    if (value > max_value) return error.ValueTooLarge;

    var left = value;
    var at: usize = 0;
    while (true) {
        var byte: u8 = @intCast(left % 128);
        left /= 128;
        if (left > 0) byte |= 0x80;
        out[at] = byte;
        at += 1;
        if (left == 0) break;
    }
    return out[0..at];
}

/// Why a run of bytes is not a variable byte integer.
pub const DecodeError = error{
    /// A fifth byte carried on from a fourth. See the module comment.
    TooManyBytes,
    /// The run ended with the top bit of its last byte still set, so more
    /// bytes belong to this value and none are here.
    Incomplete,
    /// The run names a value that fewer bytes would name. See the module
    /// comment.
    NotMinimal,
};

/// One value read off the front of a run of bytes.
pub const Decoded = struct {
    value: u32,
    /// How many bytes of the run the value took.
    len: usize,
};

/// Reads one variable byte integer off the front of `bytes`.
///
/// Reads at most `max_bytes`, whatever `bytes.len` is, so a caller that
/// hands over a whole packet still gets the bound.
pub fn decode(bytes: []const u8) DecodeError!Decoded {
    var value: u32 = 0;
    var multiplier: u32 = 1;
    var at: usize = 0;
    while (true) {
        // **The two bounds, and both run before the byte is used.** A run
        // that has no byte left is unfinished, and a run that already used
        // four bytes may not take a fifth.
        if (at == bytes.len) return error.Incomplete;
        if (at == max_bytes) return error.TooManyBytes;

        const byte = bytes[at];
        at += 1;
        value += @as(u32, byte & 0x7f) * multiplier;
        if (byte & 0x80 == 0) break;
        multiplier *= 128;
    }

    // **One value, one spelling.** See the module comment. Four bytes of
    // seven bits name `max_value` and no more, so `encodedLen` cannot
    // refuse a value that reached here.
    const minimal = encodedLen(value) catch unreachable;
    if (at != minimal) return error.NotMinimal;

    return .{ .value = value, .len = at };
}

const testing = std.testing;

test "the four boundaries of MQTT 3.1.1 section 2.2.3 round trip" {
    // The table in section 2.2.3, its first and last value on each row.
    const cases = [_]struct { value: u32, bytes: []const u8 }{
        .{ .value = 0, .bytes = &.{0x00} },
        .{ .value = 127, .bytes = &.{0x7f} },
        .{ .value = 128, .bytes = &.{ 0x80, 0x01 } },
        .{ .value = 16_383, .bytes = &.{ 0xff, 0x7f } },
        .{ .value = 16_384, .bytes = &.{ 0x80, 0x80, 0x01 } },
        .{ .value = 2_097_151, .bytes = &.{ 0xff, 0xff, 0x7f } },
        .{ .value = 2_097_152, .bytes = &.{ 0x80, 0x80, 0x80, 0x01 } },
        .{ .value = max_value, .bytes = &.{ 0xff, 0xff, 0xff, 0x7f } },
    };
    for (cases) |case| {
        var out: [max_bytes]u8 = undefined;
        try testing.expectEqualSlices(u8, case.bytes, try encode(&out, case.value));
        try testing.expectEqual(case.bytes.len, try encodedLen(case.value));

        const read = try decode(case.bytes);
        try testing.expectEqual(case.value, read.value);
        try testing.expectEqual(case.bytes.len, read.len);
    }
}

test "the length curl put on a 300 byte publish reads back as 305" {
    // Measured off curl 8.21.0 through a byte logging relay to a real
    // mosquitto 2.1.2: a 300 byte `--data-binary` on the topic `t/k` went
    // out as `30 b1 02 00 03 74 2f 6b` and then the payload. So `b1 02` is
    // 305, which is the two byte topic count, the three byte topic, and
    // the 300 byte payload.
    const read = try decode(&.{ 0xb1, 0x02 });
    try testing.expectEqual(@as(u32, 305), read.value);
    try testing.expectEqual(@as(usize, 2), read.len);
}

test "a fifth continuation byte is refused rather than read" {
    // **The hazard this file exists for.** Four bytes with the top bit set
    // ask for a fifth, and a reader with no bound here reads as many bytes
    // as the peer sends and never stops.
    try testing.expectError(error.TooManyBytes, decode(&.{ 0xff, 0xff, 0xff, 0xff, 0x7f }));
    try testing.expectError(error.TooManyBytes, decode(&.{ 0x80, 0x80, 0x80, 0x80, 0x00 }));

    // A run of nothing but continuation bytes, longer than any packet
    // header, is refused after the fourth and not after the last.
    const forever = [_]u8{0xff} ** 64;
    try testing.expectError(error.TooManyBytes, decode(&forever));
}

test "a run that has not finished is Incomplete, so a reader knows to read on" {
    // This is what a socket reader sees before the last byte arrives, and
    // it is a different answer from the bound above: one says read another
    // byte, the other says stop.
    try testing.expectError(error.Incomplete, decode(&.{}));
    try testing.expectError(error.Incomplete, decode(&.{0x80}));
    try testing.expectError(error.Incomplete, decode(&.{ 0x80, 0x80 }));
    try testing.expectError(error.Incomplete, decode(&.{ 0x80, 0x80, 0x80 }));
}

test "one length has one spelling" {
    // `80 00` names zero and so does `00`. Two spellings of one length is
    // where this process and a middle box read one stream as two.
    try testing.expectError(error.NotMinimal, decode(&.{ 0x80, 0x00 }));
    try testing.expectError(error.NotMinimal, decode(&.{ 0x81, 0x00 }));
    try testing.expectError(error.NotMinimal, decode(&.{ 0x80, 0x80, 0x00 }));
    try testing.expectError(error.NotMinimal, decode(&.{ 0xff, 0x80, 0x00 }));
    try testing.expectError(error.NotMinimal, decode(&.{ 0x80, 0x80, 0x80, 0x00 }));
}

test "a value past the four byte ceiling has no encoding at all" {
    var out: [max_bytes]u8 = undefined;
    try testing.expectError(error.ValueTooLarge, encode(&out, max_value + 1));
    try testing.expectError(error.ValueTooLarge, encodedLen(max_value + 1));
    try testing.expectError(error.ValueTooLarge, encode(&out, std.math.maxInt(u32)));
}

test "decode reads one value and leaves the rest of the run alone" {
    // A caller hands over the bytes it has, which is normally more than
    // one length. The result says how many bytes the length took, so the
    // caller knows where the packet body starts.
    const run = [_]u8{ 0x7f, 0xde, 0xad, 0xbe, 0xef };
    const read = try decode(&run);
    try testing.expectEqual(@as(u32, 127), read.value);
    try testing.expectEqual(@as(usize, 1), read.len);
}

test "every value the four byte form names round trips through both halves" {
    // A walk, and not a handful of cases: the carry between the seven bit
    // groups is where an encoder goes wrong, and it goes wrong only at the
    // boundaries a spot check misses.
    var value: u32 = 0;
    while (value <= max_value) {
        var out: [max_bytes]u8 = undefined;
        const written = try encode(&out, value);
        const read = try decode(written);
        try testing.expectEqual(value, read.value);
        try testing.expectEqual(written.len, read.len);

        // A step that is not a power of two, so the walk lands either side
        // of each boundary rather than on the same residue every time.
        value +|= 9_973;
        if (value > max_value) break;
    }
}
