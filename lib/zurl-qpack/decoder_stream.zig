//! The decoder instructions of RFC 9204 section 4.4, in both directions.
//!
//! A decoder stream is a unidirectional QUIC stream of type 0x03 that
//! carries an unframed run of three instructions back to the encoder:
//! Section Acknowledgment, Stream Cancellation, and Insert Count
//! Increment. This file owns the wire format of all three. It owns nothing
//! else: it opens no stream, it holds no table, and it never decides when
//! to send anything.
//!
//! Every instruction is one pattern and one integer, so nothing here
//! allocates and nothing here is longer than
//! `integer.encoded_len_max`. `read` takes whole instructions and leaves a
//! part one where it is, the way `encoder_stream.apply` does, so an
//! encoder never waits inside this file.
//!
//! **These come from a peer too.** RFC 9204 section 6 calls a fault in
//! this stream QPACK_DECODER_STREAM_ERROR. This side sends these
//! instructions rather than reads them, so `read` has no production
//! caller in this build. It is the wire coder and the round trip the
//! tests read back, and it is not the whole of what an encoder needs.
//!
//! **`read` holds no state, so it checks only what one instruction says
//! about itself.** It catches an Insert Count Increment of zero, because
//! the octets alone say that. It cannot catch a Section Acknowledgment for
//! a stream with no outstanding field section (RFC 9204 section 4.4.1) or
//! an Insert Count Increment that takes the Known Received Count past the
//! insert count (section 4.4.3), because both need the encoder's own
//! record of what it sent. An encoder that inserts must keep that record
//! and check those two rules over this file.

const std = @import("std");

const integer = @import("integer.zig");

/// The bits above the prefix, RFC 9204 sections 4.4.1 through 4.4.3.
pub const section_ack_pattern: u8 = 0x80;
pub const stream_cancel_pattern: u8 = 0x40;
pub const insert_count_increment_pattern: u8 = 0x00;

/// The prefix widths of RFC 9204 sections 4.4.1 through 4.4.3.
const section_ack_prefix_bits = 7;
const stream_cancel_prefix_bits = 6;
const insert_count_increment_prefix_bits = 6;

pub const Error = error{
    /// An integer names a value larger than this build holds.
    IntegerOverflow,
    /// An integer continued past `integer.continuation_octets_max`.
    IntegerTooLong,
    /// An Insert Count Increment of zero. RFC 9204 section 4.4.3 says an
    /// encoder must treat that as a QPACK_DECODER_STREAM_ERROR.
    ZeroInsertCountIncrement,
};

/// One decoder instruction.
pub const Instruction = union(enum) {
    /// The decoder finished a field section on this stream, RFC 9204
    /// section 4.4.1.
    section_acknowledgment: u64,
    /// The decoder gave up on this stream, RFC 9204 section 4.4.2.
    stream_cancellation: u64,
    /// The decoder took in this many more dynamic table entries, RFC 9204
    /// section 4.4.3.
    insert_count_increment: u64,
};

/// One decoded instruction and the octets it used.
pub const Decoded = struct {
    instruction: Instruction,
    len: usize,
};

/// Reads the instruction at the front of `bytes`, or null when it has not
/// all arrived.
///
/// A null answer is not a fault. An instruction is at most
/// `integer.encoded_len_max` octets, so the caller holds no more than that
/// while it waits for the rest.
///
/// This is the wire shape and nothing above it. The two rules of RFC 9204
/// sections 4.4.1 and 4.4.3 that compare an instruction against what the
/// encoder sent are the caller's, because this function keeps no record of
/// any stream and no insert count.
pub fn read(bytes: []const u8) Error!?Decoded {
    if (bytes.len == 0) return null;
    const first = bytes[0];

    if (first & section_ack_pattern != 0) {
        const got = try readInteger(section_ack_prefix_bits, bytes) orelse return null;
        return .{ .instruction = .{ .section_acknowledgment = got.value }, .len = got.len };
    }
    if (first & stream_cancel_pattern != 0) {
        const got = try readInteger(stream_cancel_prefix_bits, bytes) orelse return null;
        return .{ .instruction = .{ .stream_cancellation = got.value }, .len = got.len };
    }
    const got = try readInteger(insert_count_increment_prefix_bits, bytes) orelse return null;
    if (got.value == 0) return error.ZeroInsertCountIncrement;
    return .{ .instruction = .{ .insert_count_increment = got.value }, .len = got.len };
}

/// Reads one integer, and turns "it has not all arrived" into null rather
/// than into a fault.
fn readInteger(comptime prefix_bits: u4, bytes: []const u8) Error!?integer.Decoded {
    return integer.decode(prefix_bits, bytes) catch |err| switch (err) {
        error.Truncated => null,
        else => |other| other,
    };
}

/// The number of octets `write` writes for `instruction`.
pub fn writtenLen(instruction: Instruction) usize {
    return switch (instruction) {
        .section_acknowledgment => |id| integer.encodedLen(section_ack_prefix_bits, id),
        .stream_cancellation => |id| integer.encodedLen(stream_cancel_prefix_bits, id),
        .insert_count_increment => |n| integer.encodedLen(insert_count_increment_prefix_bits, n),
    };
}

/// Writes `instruction` into the front of `out`, and returns the octets it
/// used.
///
/// `out` must hold at least `integer.encoded_len_max` octets, and an
/// Insert Count Increment must be above zero. Both are the caller's to get
/// right, so both are asserts.
pub fn write(instruction: Instruction, out: []u8) []u8 {
    return switch (instruction) {
        .section_acknowledgment => |id| integer.encode(
            section_ack_prefix_bits,
            section_ack_pattern,
            id,
            out,
        ),
        .stream_cancellation => |id| integer.encode(
            stream_cancel_prefix_bits,
            stream_cancel_pattern,
            id,
            out,
        ),
        .insert_count_increment => |n| block: {
            std.debug.assert(n > 0);
            break :block integer.encode(
                insert_count_increment_prefix_bits,
                insert_count_increment_pattern,
                n,
                out,
            );
        },
    };
}

const testing = std.testing;

test "RFC 9204 B.2, a section acknowledgment for stream 4 is one octet" {
    var out: [integer.encoded_len_max]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{0x84}, write(.{ .section_acknowledgment = 4 }, &out));
    try testing.expectEqual(@as(usize, 1), writtenLen(.{ .section_acknowledgment = 4 }));

    const got = (try read(&.{0x84})).?;
    try testing.expectEqual(Instruction{ .section_acknowledgment = 4 }, got.instruction);
    try testing.expectEqual(@as(usize, 1), got.len);
}

test "RFC 9204 B.3, an insert count increment of one is one octet" {
    var out: [integer.encoded_len_max]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{0x01}, write(.{ .insert_count_increment = 1 }, &out));

    const got = (try read(&.{0x01})).?;
    try testing.expectEqual(Instruction{ .insert_count_increment = 1 }, got.instruction);
    try testing.expectEqual(@as(usize, 1), got.len);
}

test "RFC 9204 B.4, a stream cancellation for stream 8 is one octet" {
    var out: [integer.encoded_len_max]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{0x48}, write(.{ .stream_cancellation = 8 }, &out));

    const got = (try read(&.{0x48})).?;
    try testing.expectEqual(Instruction{ .stream_cancellation = 8 }, got.instruction);
    try testing.expectEqual(@as(usize, 1), got.len);
}

test "the three patterns do not run into each other at the edge of a prefix" {
    var out: [integer.encoded_len_max]u8 = undefined;

    // A stream id of 63 fills the 6-bit prefix of a stream cancellation,
    // and 64 needs a continuation octet.
    try testing.expectEqualSlices(u8, &.{0x7e}, write(.{ .stream_cancellation = 62 }, &out));
    try testing.expectEqualSlices(u8, &.{ 0x7f, 0x01 }, write(.{ .stream_cancellation = 64 }, &out));
    try testing.expectEqual(
        Instruction{ .stream_cancellation = 64 },
        (try read(&.{ 0x7f, 0x01 })).?.instruction,
    );

    // The same for an increment, which shares the width but not the
    // pattern.
    try testing.expectEqualSlices(u8, &.{0x3e}, write(.{ .insert_count_increment = 62 }, &out));
    try testing.expectEqualSlices(
        u8,
        &.{ 0x3f, 0x01 },
        write(.{ .insert_count_increment = 64 }, &out),
    );
    try testing.expectEqual(
        Instruction{ .insert_count_increment = 64 },
        (try read(&.{ 0x3f, 0x01 })).?.instruction,
    );

    // And a section acknowledgment, which has one more bit.
    try testing.expectEqualSlices(u8, &.{0xfe}, write(.{ .section_acknowledgment = 126 }, &out));
    try testing.expectEqualSlices(
        u8,
        &.{ 0xff, 0x01 },
        write(.{ .section_acknowledgment = 128 }, &out),
    );
}

test "every instruction round-trips over a spread of values" {
    var out: [integer.encoded_len_max]u8 = undefined;
    const values = [_]u64{ 0, 1, 4, 8, 61, 62, 63, 64, 126, 127, 128, 16383, 1 << 32, integer.value_max };
    for (values) |value| {
        const cases = [_]Instruction{
            .{ .section_acknowledgment = value },
            .{ .stream_cancellation = value },
            .{ .insert_count_increment = if (value == 0) 1 else value },
        };
        for (cases) |want| {
            const written = write(want, &out);
            try testing.expectEqual(writtenLen(want), written.len);

            const got = (try read(written)).?;
            try testing.expectEqual(want, got.instruction);
            try testing.expectEqual(written.len, got.len);
        }
    }
}

test "an instruction that has not all arrived is not a fault" {
    try testing.expectEqual(@as(?Decoded, null), try read(&.{}));
    try testing.expectEqual(@as(?Decoded, null), try read(&.{0xff}));
    try testing.expectEqual(@as(?Decoded, null), try read(&.{ 0x7f, 0x81 }));
}

test "an increment of zero is a fault, RFC 9204 section 4.4.3" {
    try testing.expectError(error.ZeroInsertCountIncrement, read(&.{0x00}));

    // One is fine, and so is the largest value the prefix holds on its
    // own, and so is the next one up.
    try testing.expectEqual(
        Instruction{ .insert_count_increment = 1 },
        (try read(&.{0x01})).?.instruction,
    );
    try testing.expectEqual(
        Instruction{ .insert_count_increment = 63 },
        (try read(&.{ 0x3f, 0x00 })).?.instruction,
    );

    // A stream cancellation for stream 0 is not the same octet, and is
    // fine.
    try testing.expectEqual(
        Instruction{ .stream_cancellation = 0 },
        (try read(&.{0x40})).?.instruction,
    );
}

test "an integer that never ends is refused, whichever instruction carries it" {
    const forever = [_]u8{0x80} ** 32;
    inline for ([_]u8{ 0xff, 0x7f, 0x3f }) |first| {
        try testing.expectError(error.IntegerTooLong, read(&([_]u8{first} ++ forever)));
    }
}

test "an integer larger than this build holds is refused before it wraps" {
    const over = [_]u8{ 0xff, 0xff } ++ [_]u8{0xff} ** 7 ++ [_]u8{0x7f};
    try testing.expectError(error.IntegerOverflow, read(&over));
}

test "a run of instructions is read one at a time" {
    const stream = [_]u8{ 0x84, 0x01, 0x48, 0x3f, 0x01 };
    var pos: usize = 0;
    var seen: [4]Instruction = undefined;
    var count: usize = 0;
    while (try read(stream[pos..])) |got| {
        seen[count] = got.instruction;
        count += 1;
        pos += got.len;
    }

    try testing.expectEqual(@as(usize, 4), count);
    try testing.expectEqual(Instruction{ .section_acknowledgment = 4 }, seen[0]);
    try testing.expectEqual(Instruction{ .insert_count_increment = 1 }, seen[1]);
    try testing.expectEqual(Instruction{ .stream_cancellation = 8 }, seen[2]);
    try testing.expectEqual(Instruction{ .insert_count_increment = 64 }, seen[3]);
}
