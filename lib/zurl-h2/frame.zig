//! The 9-octet frame header of HTTP/2. RFC 9113 section 4.1.
//!
//! This file owns the fixed prefix that every frame starts with, and
//! nothing after it. It reads and writes the 24-bit length, the type, the
//! flags, the reserved bit, and the 31-bit stream identifier. It does not
//! read a payload, it does not know what a type means, and it holds no
//! state between frames.
//!
//! A header parse cannot fail. Every 9-octet pattern is a legal header:
//! the length fits 24 bits because the field is 24 bits, the type is
//! non-exhaustive because an unknown type must be ignored, and the stream
//! identifier drops the reserved bit because section 4.1 says a receiver
//! must ignore it. Every check that can fail needs the payload or the
//! negotiated settings, so it lives in `payload.zig` or in
//! `FrameReader.zig`.

const std = @import("std");

/// The octets before every payload. RFC 9113 section 4.1.
pub const header_len: usize = 9;

/// The largest number the 24-bit length field can hold.
///
/// This is not the largest frame a peer may send. That is
/// `SETTINGS_MAX_FRAME_SIZE`, which starts at 16384 and is never above
/// this. `FrameReader` refuses a length above the size it advertised, so
/// a frame this big only ever arrives when the receiver asked for it.
pub const length_max: u32 = (1 << 24) - 1;

/// The largest stream identifier. RFC 9113 section 5.1.1.
pub const stream_id_max: u32 = (1 << 31) - 1;

/// The frame types of RFC 9113 section 6.
///
/// The enum is non-exhaustive on purpose. Section 4.1 says a receiver
/// must ignore a frame of an unknown type, so an unknown type is a value
/// this build carries, not a fault it reports.
pub const Type = enum(u8) {
    data = 0x00,
    headers = 0x01,
    priority = 0x02,
    rst_stream = 0x03,
    settings = 0x04,
    push_promise = 0x05,
    ping = 0x06,
    goaway = 0x07,
    window_update = 0x08,
    continuation = 0x09,
    _,

    /// True when this build knows the type and will parse its payload.
    pub fn isKnown(t: Type) bool {
        return name(t) != null;
    }

    /// The name from RFC 9113 section 6, or null for a type this build
    /// does not know.
    pub fn name(t: Type) ?[]const u8 {
        return switch (t) {
            .data => "DATA",
            .headers => "HEADERS",
            .priority => "PRIORITY",
            .rst_stream => "RST_STREAM",
            .settings => "SETTINGS",
            .push_promise => "PUSH_PROMISE",
            .ping => "PING",
            .goaway => "GOAWAY",
            .window_update => "WINDOW_UPDATE",
            .continuation => "CONTINUATION",
            _ => null,
        };
    }

    /// True when the type carries a header block fragment, so the
    /// `CONTINUATION` rule of section 6.10 applies to it.
    pub fn carriesHeaderBlock(t: Type) bool {
        return t == .headers or t == .push_promise or t == .continuation;
    }
};

/// The flag bits, by the name each one has in RFC 9113 section 6.
///
/// One bit means two things across the types: 0x01 is `END_STREAM` on
/// `DATA` and `HEADERS`, and `ACK` on `SETTINGS` and `PING`. The masks are
/// separate names for that reason, so a call site says which meaning it
/// wants.
pub const flag = struct {
    /// `DATA` and `HEADERS`. RFC 9113 sections 6.1 and 6.2.
    pub const end_stream: u8 = 0x01;
    /// `SETTINGS` and `PING`. RFC 9113 sections 6.5 and 6.7.
    pub const ack: u8 = 0x01;
    /// `HEADERS`, `PUSH_PROMISE`, and `CONTINUATION`. RFC 9113 section
    /// 6.10.
    pub const end_headers: u8 = 0x04;
    /// `DATA`, `HEADERS`, and `PUSH_PROMISE`. RFC 9113 section 6.1.
    pub const padded: u8 = 0x08;
    /// `HEADERS`. RFC 9113 section 6.2.
    pub const priority: u8 = 0x20;
};

/// One parsed frame header.
pub const Header = struct {
    /// The payload length, in octets. Always at or below `length_max`,
    /// because the field is 24 bits wide.
    length: u32,
    type: Type,
    flags: u8,
    /// The stream identifier with the reserved bit already dropped.
    stream_id: u31,

    /// Reads a header out of 9 octets.
    ///
    /// This cannot fail. The reserved bit of octet 5 is dropped, which is
    /// what RFC 9113 section 4.1 requires of a receiver.
    pub fn parse(bytes: *const [header_len]u8) Header {
        return .{
            .length = std.mem.readInt(u24, bytes[0..3], .big),
            .type = @enumFromInt(bytes[3]),
            .flags = bytes[4],
            // The high bit of octet 5 is reserved. Section 4.1 says a
            // receiver must ignore it, so the mask drops it rather than
            // reporting it.
            .stream_id = @truncate(std.mem.readInt(u32, bytes[5..9], .big)),
        };
    }

    /// Writes the header into 9 octets. The reserved bit is written as 0,
    /// which section 4.1 requires of a sender.
    pub fn encode(self: Header, out: *[header_len]u8) void {
        // A length above the field width is this build's own bug, not a
        // peer's. Nothing outside can reach this path.
        std.debug.assert(self.length <= length_max);
        std.mem.writeInt(u24, out[0..3], @intCast(self.length), .big);
        out[3] = @intFromEnum(self.type);
        out[4] = self.flags;
        std.mem.writeInt(u32, out[5..9], @as(u32, self.stream_id), .big);
    }

    /// True when every bit of `mask` is set.
    pub fn has(self: Header, mask: u8) bool {
        return self.flags & mask == mask;
    }

    /// Reads a header off a stream.
    ///
    /// `readSliceAll` is used rather than `takeArray`, so this works over
    /// a reader whose buffer is smaller than a header.
    pub fn read(r: *std.Io.Reader) std.Io.Reader.Error!Header {
        var bytes: [header_len]u8 = undefined;
        try r.readSliceAll(&bytes);
        return parse(&bytes);
    }

    /// Writes a header onto a stream.
    pub fn write(self: Header, w: *std.Io.Writer) std.Io.Writer.Error!void {
        var bytes: [header_len]u8 = undefined;
        self.encode(&bytes);
        try w.writeAll(&bytes);
    }
};

const testing = std.testing;

test "a header round-trips through the 9 octets of RFC 9113 section 4.1" {
    // length 0x000406, type 0x04 SETTINGS, flags 0x00, stream 0.
    const bytes = [header_len]u8{ 0x00, 0x04, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const header = Header.parse(&bytes);
    try testing.expectEqual(@as(u32, 0x000406), header.length);
    try testing.expectEqual(Type.settings, header.type);
    try testing.expectEqual(@as(u8, 0x00), header.flags);
    try testing.expectEqual(@as(u31, 0), header.stream_id);

    var out: [header_len]u8 = undefined;
    header.encode(&out);
    try testing.expectEqualSlices(u8, &bytes, &out);
}

test "the length field is big-endian and 24 bits wide" {
    const bytes = [header_len]u8{ 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    try testing.expectEqual(length_max, Header.parse(&bytes).length);
    try testing.expectEqual(@as(u32, 16777215), length_max);
}

test "the reserved bit of the stream identifier is dropped, not reported" {
    // 0x80000001 is the reserved bit set over stream 1.
    const bytes = [header_len]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x01 };
    const header = Header.parse(&bytes);
    try testing.expectEqual(@as(u31, 1), header.stream_id);

    // An encode writes the reserved bit as 0, so the round trip clears it.
    var out: [header_len]u8 = undefined;
    header.encode(&out);
    try testing.expectEqual(@as(u8, 0x00), out[5]);
}

test "the largest stream identifier round-trips" {
    const bytes = [header_len]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff };
    const header = Header.parse(&bytes);
    try testing.expectEqual(@as(u31, stream_id_max), header.stream_id);

    var out: [header_len]u8 = undefined;
    header.encode(&out);
    try testing.expectEqualSlices(u8, &bytes, &out);
}

test "an unknown frame type parses into a value rather than a fault" {
    const bytes = [header_len]u8{ 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const header = Header.parse(&bytes);
    try testing.expect(!header.type.isKnown());
    try testing.expectEqual(@as(?[]const u8, null), header.type.name());
    try testing.expectEqual(@as(u8, 0xff), @intFromEnum(header.type));
}

test "every known type has its number and its name from RFC 9113 section 6" {
    const table = [_]struct { Type, u8, []const u8 }{
        .{ .data, 0x00, "DATA" },
        .{ .headers, 0x01, "HEADERS" },
        .{ .priority, 0x02, "PRIORITY" },
        .{ .rst_stream, 0x03, "RST_STREAM" },
        .{ .settings, 0x04, "SETTINGS" },
        .{ .push_promise, 0x05, "PUSH_PROMISE" },
        .{ .ping, 0x06, "PING" },
        .{ .goaway, 0x07, "GOAWAY" },
        .{ .window_update, 0x08, "WINDOW_UPDATE" },
        .{ .continuation, 0x09, "CONTINUATION" },
    };
    for (table) |row| {
        try testing.expect(row[0].isKnown());
        try testing.expectEqual(row[1], @intFromEnum(row[0]));
        try testing.expectEqualStrings(row[2], row[0].name().?);
    }
    // 0x0a is the first number past the table, so it is unknown.
    try testing.expect(!(@as(Type, @enumFromInt(0x0a))).isKnown());
}

test "only the three header-block types carry a fragment" {
    try testing.expect(Type.headers.carriesHeaderBlock());
    try testing.expect(Type.push_promise.carriesHeaderBlock());
    try testing.expect(Type.continuation.carriesHeaderBlock());
    try testing.expect(!Type.data.carriesHeaderBlock());
    try testing.expect(!Type.settings.carriesHeaderBlock());
    try testing.expect(!(@as(Type, @enumFromInt(0xff))).carriesHeaderBlock());
}

test "has asks for every bit of the mask" {
    const header: Header = .{
        .length = 0,
        .type = .headers,
        .flags = flag.end_stream | flag.end_headers,
        .stream_id = 1,
    };
    try testing.expect(header.has(flag.end_stream));
    try testing.expect(header.has(flag.end_headers));
    try testing.expect(header.has(flag.end_stream | flag.end_headers));
    try testing.expect(!header.has(flag.padded));
    try testing.expect(!header.has(flag.end_headers | flag.padded));
}

test "a header reads off a stream and writes back the same octets" {
    const bytes = [header_len]u8{ 0x00, 0x00, 0x08, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00 };
    var r: std.Io.Reader = .fixed(&bytes);
    const header = try Header.read(&r);
    try testing.expectEqual(Type.ping, header.type);
    try testing.expect(header.has(flag.ack));

    var out: [header_len]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try header.write(&w);
    try testing.expectEqualSlices(u8, &bytes, w.buffered());
}

test "a stream that ends inside a header reports the end, and does not read past" {
    var r: std.Io.Reader = .fixed(&[_]u8{ 0x00, 0x00, 0x08, 0x06 });
    try testing.expectError(error.EndOfStream, Header.read(&r));
}
