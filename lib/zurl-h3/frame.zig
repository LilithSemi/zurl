//! The HTTP/3 frame layer, RFC 9114 section 7.
//!
//! An HTTP/3 frame is a type, a length, and a payload, each number a QUIC
//! variable-length integer. There is no stream identifier in the frame:
//! the QUIC stream carries that, which is what makes HTTP/3 framing so
//! much smaller than HTTP/2's.
//!
//! **Reading a frame is two steps, and that is on purpose.**
//! `readHeader` gives the type and the length, and the caller then reads
//! the payload. A `DATA` frame's payload is a response body and may be
//! gigabytes, so nothing here buffers one. The payload readers below are
//! for the small frames alone, and each of them has a bound.
//!
//! ## Every number a peer chose, and what stops it
//!
//! | Input | Bound | Fault |
//! | --- | --- | --- |
//! | A frame type | The varint encoding | `Truncated` |
//! | A frame type RFC 9114 section 7.2.8 reserves | Refused | `FrameUnexpected` |
//! | A frame length | Read, never sized from. The caller bounds it | none here |
//! | A `GOAWAY`, `MAX_PUSH_ID` or `CANCEL_PUSH` payload | One varint, and nothing after it | `FrameError` |
//!
//! A frame length is **not** checked here against anything, because this
//! file does not hold the stream. `Connection.zig` holds the bound for
//! each frame it buffers, and a `DATA` frame is streamed rather than
//! buffered.

const std = @import("std");
const quic = @import("zurl-quic");

const varint = quic.varint;

/// The frame types RFC 9114 section 7.2 defines.
pub const Kind = enum(u64) {
    data = 0x00,
    headers = 0x01,
    cancel_push = 0x03,
    settings = 0x04,
    push_promise = 0x05,
    goaway = 0x07,
    max_push_id = 0x0d,
    _,

    /// The name RFC 9114 gives the type, or `"UNKNOWN"`.
    pub fn name(self: Kind) []const u8 {
        return switch (self) {
            .data => "DATA",
            .headers => "HEADERS",
            .cancel_push => "CANCEL_PUSH",
            .settings => "SETTINGS",
            .push_promise => "PUSH_PROMISE",
            .goaway => "GOAWAY",
            .max_push_id => "MAX_PUSH_ID",
            _ => if (isReserved(@intFromEnum(self))) "RESERVED" else "UNKNOWN",
        };
    }

    /// Whether this build acts on the type. A type it does not know is
    /// stepped over, which RFC 9114 section 9 requires.
    pub fn isKnown(self: Kind) bool {
        return switch (self) {
            .data, .headers, .cancel_push, .settings, .push_promise, .goaway, .max_push_id => true,
            _ => false,
        };
    }
};

/// The four frame types RFC 9114 section 7.2.8 takes out of use.
///
/// **These are HTTP/2's frame types**, and a peer that sends one is
/// either an HTTP/2 implementation pointed at an HTTP/3 connection or
/// something trying to make this side read an HTTP/2 frame. RFC 9114
/// makes each one a connection error of type H3_FRAME_UNEXPECTED, which
/// is stricter than ignoring an unknown type and is the point of the
/// rule.
pub const reserved_http2_types = [_]u64{ 0x02, 0x06, 0x08, 0x09 };

/// Whether `value` is one of `reserved_http2_types`.
pub fn isReservedHttp2(value: u64) bool {
    for (reserved_http2_types) |t| {
        if (value == t) return true;
    }
    return false;
}

/// Whether `value` is a type RFC 9114 section 7.2.8 reserves for a peer to
/// send on purpose, to check that this side ignores it.
///
/// The pattern is `0x1f * N + 0x21`. A frame of such a type is stepped
/// over like any other unknown type.
pub fn isReserved(value: u64) bool {
    if (value < 0x21) return false;
    return (value - 0x21) % 0x1f == 0;
}

/// How many bytes the longest frame header can take: two varints of eight
/// bytes each.
pub const max_header_bytes: usize = 2 * varint.max_bytes;

/// Every fault this file can report. Each one is a connection error in
/// RFC 9114 section 8.1, and the name says which code closes it.
pub const Error = error{
    /// The bytes in hand hold no whole varint. Not a fault on a stream:
    /// the caller waits for more. `readHeader` reports it as null and this
    /// name is for the payload readers, which are given a whole payload.
    Truncated,
    /// A frame type RFC 9114 section 7.2.8 takes out of use, or a frame on
    /// a stream that may not carry it. H3_FRAME_UNEXPECTED.
    FrameUnexpected,
    /// A frame payload is not the shape its type requires.
    /// H3_FRAME_ERROR.
    FrameError,
};

/// One frame header: what type follows and how long its payload is.
pub const Header = struct {
    kind: Kind,
    /// How many payload bytes follow. **A number the peer chose.** The
    /// caller bounds it against what it is willing to buffer.
    length: u64,
    /// How many bytes of the stream this header took.
    header_len: usize,
};

/// Reads a frame header out of the front of `bytes`.
///
/// Returns null when `bytes` holds part of a header, which on a stream
/// means the caller waits for more. `bytes` must be a contiguous run from
/// the start of a frame.
pub fn readHeader(bytes: []const u8) Error!?Header {
    const kind_field = varint.decode(bytes) catch return null;
    if (isReservedHttp2(kind_field.value)) return error.FrameUnexpected;
    const length_field = varint.decode(bytes[kind_field.len..]) catch return null;
    return .{
        .kind = @enumFromInt(kind_field.value),
        .length = length_field.value,
        .header_len = kind_field.len + length_field.len,
    };
}

/// How many bytes `writeHeader` writes for this type and length.
pub fn headerLen(kind: Kind, length: u64) usize {
    const type_len = varint.encodedLen(@intFromEnum(kind)) catch unreachable;
    const length_len = varint.encodedLen(length) catch unreachable;
    return type_len + length_len;
}

/// Writes a frame header into `out` and returns the part it wrote.
///
/// Asserts `out` is long enough and that both numbers fit a varint. A
/// caller that builds its own frame knows both, so neither is a runtime
/// fault.
pub fn writeHeader(kind: Kind, length: u64, out: []u8) []u8 {
    std.debug.assert(length <= varint.max_value);
    std.debug.assert(out.len >= headerLen(kind, length));
    var at: usize = 0;
    var scratch: [varint.max_bytes]u8 = undefined;
    const type_bytes = varint.encode(&scratch, @intFromEnum(kind)) catch unreachable;
    @memcpy(out[at..][0..type_bytes.len], type_bytes);
    at += type_bytes.len;
    const length_bytes = varint.encode(&scratch, length) catch unreachable;
    @memcpy(out[at..][0..length_bytes.len], length_bytes);
    at += length_bytes.len;
    return out[0..at];
}

/// The one varint a `GOAWAY`, a `MAX_PUSH_ID`, or a `CANCEL_PUSH` payload
/// holds. RFC 9114 sections 7.2.3, 7.2.6, and 7.2.7.
///
/// **Nothing may follow it.** Each of those frames has exactly one field,
/// and RFC 9114 makes a payload of any other length a connection error of
/// type H3_FRAME_ERROR.
pub fn readSingleVarint(payload: []const u8) Error!u64 {
    const field = varint.decode(payload) catch return error.FrameError;
    if (field.len != payload.len) return error.FrameError;
    return field.value;
}

/// How many bytes a frame with a one varint payload takes in total.
pub fn singleVarintLen(kind: Kind, value: u64) usize {
    const body = varint.encodedLen(value) catch unreachable;
    return headerLen(kind, body) + body;
}

/// Writes a whole `GOAWAY`, `MAX_PUSH_ID`, or `CANCEL_PUSH` frame.
pub fn writeSingleVarint(kind: Kind, value: u64, out: []u8) []u8 {
    std.debug.assert(out.len >= singleVarintLen(kind, value));
    const body_len = varint.encodedLen(value) catch unreachable;
    const head = writeHeader(kind, body_len, out);
    var scratch: [varint.max_bytes]u8 = undefined;
    const body = varint.encode(&scratch, value) catch unreachable;
    @memcpy(out[head.len..][0..body.len], body);
    return out[0 .. head.len + body.len];
}

const testing = std.testing;

test "a frame header is a type and a length, each a QUIC varint" {
    // RFC 9114 section 7.1. A HEADERS frame of 10 bytes is two octets of
    // header, because both numbers fit a one byte varint.
    var out: [max_header_bytes]u8 = undefined;
    const written = writeHeader(.headers, 10, &out);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x0a }, written);

    const read = (try readHeader(written)).?;
    try testing.expectEqual(Kind.headers, read.kind);
    try testing.expectEqual(@as(u64, 10), read.length);
    try testing.expectEqual(@as(usize, 2), read.header_len);
}

test "a long payload length takes a wider varint and reads back the same" {
    var out: [max_header_bytes]u8 = undefined;
    const written = writeHeader(.data, 1 << 30, &out);
    const read = (try readHeader(written)).?;
    try testing.expectEqual(Kind.data, read.kind);
    try testing.expectEqual(@as(u64, 1 << 30), read.length);
    try testing.expectEqual(written.len, read.header_len);

    // The largest length a varint can name round trips too, and nothing
    // here sizes anything from it.
    const big = writeHeader(.data, varint.max_value, &out);
    try testing.expectEqual(@as(u64, varint.max_value), (try readHeader(big)).?.length);
}

test "a part of a header is not a fault, it is a wait" {
    // A four byte length varint arriving one byte at a time.
    var out: [max_header_bytes]u8 = undefined;
    const written = writeHeader(.data, 1 << 20, &out);
    var at: usize = 0;
    while (at < written.len) : (at += 1) {
        try testing.expect(try readHeader(written[0..at]) == null);
    }
    try testing.expect(try readHeader(written) != null);
    try testing.expect(try readHeader(&.{}) == null);
}

test "the four HTTP/2 frame types are refused and never ignored" {
    // RFC 9114 section 7.2.8. Ignoring one would let an HTTP/2 frame walk
    // into an HTTP/3 stream and be stepped over as if it were harmless.
    for (reserved_http2_types) |t| {
        var out: [max_header_bytes]u8 = undefined;
        const written = writeHeader(@enumFromInt(t), 0, &out);
        try testing.expectError(error.FrameUnexpected, readHeader(written));
    }
    // The types either side of them are not refused.
    for ([_]u64{ 0x00, 0x01, 0x03, 0x04, 0x05, 0x07, 0x0a, 0x0d }) |t| {
        var out: [max_header_bytes]u8 = undefined;
        const written = writeHeader(@enumFromInt(t), 0, &out);
        try testing.expect(try readHeader(written) != null);
    }
}

test "a reserved frame type reads as a frame this build does not know" {
    // RFC 9114 section 7.2.8: a peer sends one on purpose, and this side
    // must step over it rather than close the connection.
    var out: [max_header_bytes]u8 = undefined;
    for ([_]u64{ 0x21, 0x40, 0x5f, 0x1f * 100 + 0x21 }) |t| {
        try testing.expect(isReserved(t));
        const written = writeHeader(@enumFromInt(t), 3, &out);
        const read = (try readHeader(written)).?;
        try testing.expect(!read.kind.isKnown());
        try testing.expectEqualStrings("RESERVED", read.kind.name());
        try testing.expectEqual(@as(u64, 3), read.length);
    }
    // A type nobody defined reads the same way.
    const unknown = writeHeader(@enumFromInt(0x22), 0, &out);
    try testing.expect(!(try readHeader(unknown)).?.kind.isKnown());
    try testing.expectEqualStrings("UNKNOWN", @as(Kind, @enumFromInt(0x22)).name());
}

/// Writes `value` as a varint of exactly `width` bytes.
///
/// RFC 9000 section 16 lets an encoding be longer than the value needs, so
/// a peer can spell any frame type this way. `varint.encode` writes the
/// shortest form, which is why a test that wants the longest form writes
/// its own bytes.
fn wideVarint(out: *[varint.max_bytes]u8, width: usize, value: u64) []u8 {
    std.debug.assert(width == 1 or width == 2 or width == 4 or width == 8);
    var index: usize = 0;
    while (index < width) : (index += 1) {
        const shift: u6 = @intCast(8 * (width - 1 - index));
        out[index] = @truncate(value >> shift);
    }
    out[0] |= switch (width) {
        2 => 0x40,
        4 => 0x80,
        8 => 0xc0,
        else => 0x00,
    };
    return out[0..width];
}

test "a frame type is read by its value and never by its bytes" {
    // **The single test that tells a value comparison from a byte
    // comparison.** RFC 9000 section 16 lets a peer spell type `0x02` as
    // eight bytes, and RFC 9114 section 7.2.8 says the four HTTP/2 types
    // close the connection. A build that matched the shortest spelling
    // would read the wide one as a type it does not know and step over an
    // HTTP/2 frame walking into an HTTP/3 stream.
    var wide: [varint.max_bytes]u8 = undefined;
    for (reserved_http2_types) |t| {
        for ([_]usize{ 2, 4, varint.max_bytes }) |width| {
            var bytes: [varint.max_bytes + 1]u8 = undefined;
            const head = wideVarint(&wide, width, t);
            @memcpy(bytes[0..head.len], head);
            // A zero length, so the whole header is present.
            bytes[head.len] = 0x00;
            try testing.expectError(error.FrameUnexpected, readHeader(bytes[0 .. head.len + 1]));
        }
    }

    // A reserved type spelled wide is still a reserved type, and its
    // length is still the length behind it.
    for ([_]u64{ 0x21, 0x40, 0x1f * 100 + 0x21 }) |t| {
        var bytes: [varint.max_bytes + 1]u8 = undefined;
        const head = wideVarint(&wide, varint.max_bytes, t);
        @memcpy(bytes[0..head.len], head);
        bytes[head.len] = 0x03;
        const read = (try readHeader(bytes[0 .. head.len + 1])).?;
        try testing.expect(!read.kind.isKnown());
        try testing.expectEqualStrings("RESERVED", read.kind.name());
        try testing.expectEqual(@as(u64, 3), read.length);
        try testing.expectEqual(head.len + 1, read.header_len);
    }

    // And a type this build acts on is still that type when it arrives
    // wide, so the value comparison holds in both directions.
    {
        var bytes: [varint.max_bytes + 1]u8 = undefined;
        const head = wideVarint(&wide, varint.max_bytes, @intFromEnum(Kind.headers));
        @memcpy(bytes[0..head.len], head);
        bytes[head.len] = 0x05;
        const read = (try readHeader(bytes[0 .. head.len + 1])).?;
        try testing.expectEqual(Kind.headers, read.kind);
        try testing.expectEqual(@as(u64, 5), read.length);
    }
}

test "a GOAWAY payload is one varint and nothing may follow it" {
    var out: [16]u8 = undefined;
    const written = writeSingleVarint(.goaway, 8, &out);
    const read = (try readHeader(written)).?;
    try testing.expectEqual(Kind.goaway, read.kind);
    try testing.expectEqual(@as(u64, 8), try readSingleVarint(written[read.header_len..]));

    // A trailing byte is H3_FRAME_ERROR, not something to ignore.
    try testing.expectError(error.FrameError, readSingleVarint(&.{ 0x08, 0x00 }));
    // So is an empty payload.
    try testing.expectError(error.FrameError, readSingleVarint(&.{}));
    // And so is a payload that stops inside its varint.
    try testing.expectError(error.FrameError, readSingleVarint(&.{0x40}));
}

test "MAX_PUSH_ID and CANCEL_PUSH round trip through the same pair" {
    var out: [16]u8 = undefined;
    for ([_]Kind{ .max_push_id, .cancel_push }) |kind| {
        for ([_]u64{ 0, 1, 63, 64, 1 << 30 }) |value| {
            const written = writeSingleVarint(kind, value, &out);
            try testing.expectEqual(singleVarintLen(kind, value), written.len);
            const read = (try readHeader(written)).?;
            try testing.expectEqual(kind, read.kind);
            try testing.expectEqual(value, try readSingleVarint(written[read.header_len..]));
        }
    }
}

test "the names are the names RFC 9114 table 4 prints" {
    try testing.expectEqualStrings("DATA", Kind.data.name());
    try testing.expectEqualStrings("HEADERS", Kind.headers.name());
    try testing.expectEqualStrings("SETTINGS", Kind.settings.name());
    try testing.expectEqualStrings("GOAWAY", Kind.goaway.name());
    try testing.expectEqualStrings("MAX_PUSH_ID", Kind.max_push_id.name());
    try testing.expectEqualStrings("CANCEL_PUSH", Kind.cancel_push.name());
    try testing.expectEqualStrings("PUSH_PROMISE", Kind.push_promise.name());
}
