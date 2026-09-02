//! The unidirectional stream types of HTTP/3, RFC 9114 section 6.2 and
//! RFC 9204 section 4.2.
//!
//! **A unidirectional stream says what it is with its first byte.** The
//! first thing on the stream is a QUIC variable-length integer naming the
//! type, and everything after it belongs to that type. A stream whose type
//! this build does not know is abandoned rather than read, because reading
//! it would mean guessing what its bytes mean.

const std = @import("std");
const quic = @import("zurl-quic");

const varint = quic.varint;

/// The stream types this build knows.
pub const Type = enum(u64) {
    /// RFC 9114 section 6.2.1. One for each endpoint, for the whole
    /// connection.
    control = 0x00,
    /// RFC 9114 section 6.2.2. A server opens one for each push.
    push = 0x01,
    /// RFC 9204 section 4.2. The QPACK encoder stream.
    qpack_encoder = 0x02,
    /// RFC 9204 section 4.2. The QPACK decoder stream.
    qpack_decoder = 0x03,
    _,

    /// The name the RFC gives the type, or `"UNKNOWN"`.
    pub fn name(self: Type) []const u8 {
        return switch (self) {
            .control => "control",
            .push => "push",
            .qpack_encoder => "QPACK encoder",
            .qpack_decoder => "QPACK decoder",
            _ => if (isReserved(@intFromEnum(self))) "reserved" else "UNKNOWN",
        };
    }

    /// Whether this build reads the stream. A type it does not know is
    /// abandoned, which RFC 9114 section 6.2 requires.
    pub fn isKnown(self: Type) bool {
        return switch (self) {
            .control, .push, .qpack_encoder, .qpack_decoder => true,
            _ => false,
        };
    }
};

/// Whether `value` is a type RFC 9114 section 6.2.3 reserves for a peer to
/// open on purpose, to check that this side abandons it. The pattern is
/// `0x1f * N + 0x21`.
pub fn isReserved(value: u64) bool {
    if (value < 0x21) return false;
    return (value - 0x21) % 0x1f == 0;
}

/// The most bytes a stream type takes.
pub const max_bytes: usize = varint.max_bytes;

/// One stream type read off the front of a stream.
pub const Read = struct {
    type: Type,
    /// How many bytes of the stream the type took.
    len: usize,
};

/// Reads the type off the front of a unidirectional stream, or null when
/// the bytes in hand hold only part of it.
///
/// **A part of a type is a wait and not a fault.** RFC 9114 section 6.2
/// lets a peer open a stream and send its type in a later packet, and an
/// eight byte reserved type can arrive in eight datagrams.
pub fn read(bytes: []const u8) ?Read {
    const field = varint.decode(bytes) catch return null;
    return .{ .type = @enumFromInt(field.value), .len = field.len };
}

/// How many bytes `write` writes for `t`.
pub fn writtenLen(t: Type) usize {
    return varint.encodedLen(@intFromEnum(t)) catch unreachable;
}

/// Writes the type onto the front of a unidirectional stream.
pub fn write(t: Type, out: []u8) []u8 {
    std.debug.assert(out.len >= writtenLen(t));
    var scratch: [varint.max_bytes]u8 = undefined;
    const bytes = varint.encode(&scratch, @intFromEnum(t)) catch unreachable;
    @memcpy(out[0..bytes.len], bytes);
    return out[0..bytes.len];
}

const testing = std.testing;

test "the four types RFC 9114 and RFC 9204 name have the numbers they give" {
    try testing.expectEqual(@as(u64, 0x00), @intFromEnum(Type.control));
    try testing.expectEqual(@as(u64, 0x01), @intFromEnum(Type.push));
    try testing.expectEqual(@as(u64, 0x02), @intFromEnum(Type.qpack_encoder));
    try testing.expectEqual(@as(u64, 0x03), @intFromEnum(Type.qpack_decoder));
}

test "a type round trips and each of the four takes one byte" {
    var out: [max_bytes]u8 = undefined;
    for ([_]Type{ .control, .push, .qpack_encoder, .qpack_decoder }) |t| {
        const written = write(t, &out);
        try testing.expectEqual(@as(usize, 1), written.len);
        const back = read(written).?;
        try testing.expectEqual(t, back.type);
        try testing.expectEqual(@as(usize, 1), back.len);
        try testing.expect(back.type.isKnown());
    }
}

test "a part of a type is a wait and not a fault" {
    // A reserved type wide enough to need four bytes, arriving one byte
    // at a time.
    var out: [max_bytes]u8 = undefined;
    const written = write(@enumFromInt(0x1f * 100 + 0x21), &out);
    try testing.expect(written.len > 1);
    var at: usize = 0;
    while (at < written.len) : (at += 1) {
        try testing.expect(read(written[0..at]) == null);
    }
    try testing.expect(read(written) != null);
}

test "a reserved type is one this build abandons rather than reads" {
    for ([_]u64{ 0x21, 0x40, 0x5f }) |value| {
        try testing.expect(isReserved(value));
        const t: Type = @enumFromInt(value);
        try testing.expect(!t.isKnown());
        try testing.expectEqualStrings("reserved", t.name());
    }
    const unknown: Type = @enumFromInt(0x22);
    try testing.expect(!unknown.isKnown());
    try testing.expectEqualStrings("UNKNOWN", unknown.name());
}
