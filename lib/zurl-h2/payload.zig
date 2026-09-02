//! The payload of every frame type of RFC 9113 section 6.
//!
//! This file owns the octets after the 9-octet header. For each of the
//! ten types it reads a payload into a value and writes a value back into
//! a whole frame. It owns the padding rule of section 6.1, the stream
//! identifier rule of each type, and the length rule of each type.
//!
//! This file owns no state. It never reads from a socket, it never
//! allocates, and it never remembers the frame before this one. The
//! `CONTINUATION` order rule needs memory across frames, so it lives in
//! `continuation.zig`. The bound on a payload length needs the negotiated
//! settings, so it lives in `FrameReader.zig`.
//!
//! **Every slice in a parsed value points into the caller's payload
//! buffer.** Nothing here copies. A value is valid while the buffer it
//! came out of holds the frame, and no longer.
//!
//! **A payload is untrusted.** Every length rule and every stream rule is
//! a named error from `errors.Error`. Nothing here asserts on a peer's
//! octets, and nothing here reads past the slice it was given.

const std = @import("std");
const errors = @import("errors.zig");
const frame = @import("frame.zig");
const settings = @import("settings.zig");

const Error = errors.Error;
const ErrorCode = errors.ErrorCode;
const Header = frame.Header;
const flag = frame.flag;

/// One frame, header and payload together.
pub const Frame = struct {
    header: Header,
    payload: Payload,

    /// Reads a payload into a value.
    ///
    /// `bytes` must be exactly `header.length` octets. That is the
    /// caller's to get right, so it is an assert.
    ///
    /// A type this build does not know becomes `.unknown` rather than a
    /// fault. RFC 9113 section 4.1 says a receiver must ignore such a
    /// frame, and a value the caller can drop is how that is said here.
    pub fn parse(header: Header, bytes: []const u8) Error!Frame {
        std.debug.assert(bytes.len == header.length);
        return .{
            .header = header,
            .payload = switch (header.type) {
                .data => .{ .data = try Data.parse(header, bytes) },
                .headers => .{ .headers = try Headers.parse(header, bytes) },
                .priority => .{ .priority = try Priority.parseFrame(header, bytes) },
                .rst_stream => .{ .rst_stream = try RstStream.parse(header, bytes) },
                .settings => .{ .settings = try Settings.parse(header, bytes) },
                .push_promise => .{ .push_promise = try PushPromise.parse(header, bytes) },
                .ping => .{ .ping = try Ping.parse(header, bytes) },
                .goaway => .{ .goaway = try Goaway.parse(header, bytes) },
                .window_update => .{ .window_update = try WindowUpdate.parse(header, bytes) },
                .continuation => .{ .continuation = try Continuation.parse(header, bytes) },
                _ => .{ .unknown = bytes },
            },
        };
    }
};

/// The parsed payload of one frame.
pub const Payload = union(enum) {
    data: Data,
    headers: Headers,
    priority: Priority,
    rst_stream: RstStream,
    settings: Settings,
    push_promise: PushPromise,
    ping: Ping,
    goaway: Goaway,
    window_update: WindowUpdate,
    continuation: Continuation,
    /// A type this build does not know. The octets are kept so a caller
    /// can report them, and RFC 9113 section 4.1 says to ignore them.
    unknown: []const u8,
};

/// `DATA`. RFC 9113 section 6.1.
pub const Data = struct {
    data: []const u8,
    /// The `Pad Length` field, or null when the `PADDED` flag is clear.
    /// A `PADDED` frame with 0 octets of padding is not the same frame as
    /// one with no `PADDED` flag, so the two are told apart here.
    padding: ?u8 = null,
    end_stream: bool = false,

    pub fn parse(header: Header, bytes: []const u8) Error!Data {
        // Section 6.1: a DATA frame on stream 0 is a connection error.
        if (header.stream_id == 0) return error.StreamIdZero;
        const stripped = try stripPadding(header.has(flag.padded), bytes);
        return .{
            .data = stripped.body,
            .padding = stripped.padding,
            .end_stream = header.has(flag.end_stream),
        };
    }

    pub fn flags(self: Data) u8 {
        var bits: u8 = 0;
        if (self.end_stream) bits |= flag.end_stream;
        if (self.padding != null) bits |= flag.padded;
        return bits;
    }

    pub fn payloadLen(self: Data) usize {
        return paddedLen(self.data.len, self.padding);
    }

    pub fn frameLen(self: Data) usize {
        return frame.header_len + self.payloadLen();
    }

    pub fn encode(self: Data, stream_id: u31, out: []u8) []u8 {
        std.debug.assert(stream_id != 0);
        const body = writeHeader(.data, self.flags(), stream_id, self.payloadLen(), out);
        writePadded(self.data, self.padding, body);
        return out[0..self.frameLen()];
    }
};

/// The priority fields, both as the `PRIORITY` frame of RFC 9113 section
/// 6.3 and as the block inside a `HEADERS` with the `PRIORITY` flag.
///
/// RFC 9113 deprecates the scheme these fields carry. A receiver still
/// has to read them, because a peer may still send them, so they are
/// parsed and are then the engine's to ignore.
pub const Priority = struct {
    exclusive: bool,
    /// The stream this one depends on.
    dependency: u31,
    /// The weight as it goes on the wire. The weight the scheme uses is
    /// this number plus one, so the wire value 0 means a weight of 1.
    weight: u8,

    /// The octets the fields take, inside a frame or inside a `HEADERS`.
    pub const wire_len: usize = 5;

    pub fn parseFields(bytes: *const [wire_len]u8) Priority {
        const raw = std.mem.readInt(u32, bytes[0..4], .big);
        return .{
            .exclusive = raw & 0x8000_0000 != 0,
            .dependency = @truncate(raw),
            .weight = bytes[4],
        };
    }

    pub fn encodeFields(self: Priority, out: *[wire_len]u8) void {
        const exclusive_bit: u32 = if (self.exclusive) 0x8000_0000 else 0;
        std.mem.writeInt(u32, out[0..4], @as(u32, self.dependency) | exclusive_bit, .big);
        out[4] = self.weight;
    }

    pub fn parseFrame(header: Header, bytes: []const u8) Error!Priority {
        // Section 6.3: stream 0 is a connection error, and it is checked
        // before the length, because a wrong length here is only a
        // stream error.
        if (header.stream_id == 0) return error.StreamIdZero;
        if (bytes.len != wire_len) return error.PriorityLengthInvalid;
        return parseFields(bytes[0..wire_len]);
    }

    pub fn frameLen(_: Priority) usize {
        return frame.header_len + wire_len;
    }

    pub fn encode(self: Priority, stream_id: u31, out: []u8) []u8 {
        std.debug.assert(stream_id != 0);
        const body = writeHeader(.priority, 0, stream_id, wire_len, out);
        self.encodeFields(body[0..wire_len]);
        return out[0 .. frame.header_len + wire_len];
    }
};

/// `HEADERS`. RFC 9113 section 6.2.
pub const Headers = struct {
    /// The header block fragment. It is not a whole header block unless
    /// `end_headers` is set. See `continuation.zig`.
    block: []const u8,
    priority: ?Priority = null,
    padding: ?u8 = null,
    end_stream: bool = false,
    end_headers: bool = false,

    pub fn parse(header: Header, bytes: []const u8) Error!Headers {
        // Section 6.2: a HEADERS frame on stream 0 is a connection error.
        if (header.stream_id == 0) return error.StreamIdZero;
        const stripped = try stripPadding(header.has(flag.padded), bytes);

        var rest = stripped.body;
        var priority: ?Priority = null;
        if (header.has(flag.priority)) {
            if (rest.len < Priority.wire_len) return error.PayloadTruncated;
            priority = Priority.parseFields(rest[0..Priority.wire_len]);
            rest = rest[Priority.wire_len..];
        }

        return .{
            .block = rest,
            .priority = priority,
            .padding = stripped.padding,
            .end_stream = header.has(flag.end_stream),
            .end_headers = header.has(flag.end_headers),
        };
    }

    pub fn flags(self: Headers) u8 {
        var bits: u8 = 0;
        if (self.end_stream) bits |= flag.end_stream;
        if (self.end_headers) bits |= flag.end_headers;
        if (self.padding != null) bits |= flag.padded;
        if (self.priority != null) bits |= flag.priority;
        return bits;
    }

    pub fn payloadLen(self: Headers) usize {
        const priority_len: usize = if (self.priority == null) 0 else Priority.wire_len;
        return paddedLen(priority_len + self.block.len, self.padding);
    }

    pub fn frameLen(self: Headers) usize {
        return frame.header_len + self.payloadLen();
    }

    pub fn encode(self: Headers, stream_id: u31, out: []u8) []u8 {
        std.debug.assert(stream_id != 0);
        const body = writeHeader(.headers, self.flags(), stream_id, self.payloadLen(), out);

        var offset: usize = 0;
        if (self.padding) |pad_len| {
            body[0] = pad_len;
            offset = 1;
        }
        if (self.priority) |priority| {
            priority.encodeFields(body[offset..][0..Priority.wire_len]);
            offset += Priority.wire_len;
        }
        @memcpy(body[offset..][0..self.block.len], self.block);
        offset += self.block.len;
        if (self.padding) |pad_len| @memset(body[offset..][0..pad_len], 0);
        return out[0..self.frameLen()];
    }
};

/// `RST_STREAM`. RFC 9113 section 6.4.
pub const RstStream = struct {
    error_code: ErrorCode,

    pub const payload_len: usize = 4;

    pub fn parse(header: Header, bytes: []const u8) Error!RstStream {
        if (header.stream_id == 0) return error.StreamIdZero;
        if (bytes.len != payload_len) return error.RstStreamLengthInvalid;
        return .{ .error_code = .fromInt(std.mem.readInt(u32, bytes[0..4], .big)) };
    }

    pub fn frameLen(_: RstStream) usize {
        return frame.header_len + payload_len;
    }

    pub fn encode(self: RstStream, stream_id: u31, out: []u8) []u8 {
        std.debug.assert(stream_id != 0);
        const body = writeHeader(.rst_stream, 0, stream_id, payload_len, out);
        std.mem.writeInt(u32, body[0..4], self.error_code.int(), .big);
        return out[0 .. frame.header_len + payload_len];
    }
};

/// `SETTINGS`. RFC 9113 section 6.5.
///
/// The entries are kept as the octets they arrived in. Every one has had
/// its range checked by `parse`, so `applyTo` cannot report a range
/// fault. Keeping the octets rather than a decoded list means the frame
/// needs no allocator and no bound of its own: the payload length is
/// already bounded by `SETTINGS_MAX_FRAME_SIZE`.
pub const Settings = struct {
    ack: bool,
    entries: []const u8,

    pub fn parse(header: Header, bytes: []const u8) Error!Settings {
        // Section 6.5: a SETTINGS frame on a stream is a connection
        // error.
        if (header.stream_id != 0) return error.StreamIdNonZero;
        const ack = header.has(flag.ack);
        try settings.checkPayloadLen(bytes.len, ack);
        try settings.checkPayload(bytes);
        return .{ .ack = ack, .entries = bytes };
    }

    /// How many entries the frame carries.
    pub fn count(self: Settings) usize {
        return self.entries.len / settings.entry_len;
    }

    /// The entry at `index`. The caller must stay under `count`.
    pub fn get(self: Settings, index: usize) settings.Entry {
        std.debug.assert(index < self.count());
        const offset = index * settings.entry_len;
        return .parse(self.entries[offset..][0..settings.entry_len]);
    }

    /// Applies every entry onto `target`.
    ///
    /// `parse` already checked every range, so the only errors this can
    /// still report are the ones `Settings.apply` reports, and none of
    /// them can fire on a payload that came through `parse`.
    pub fn applyTo(self: Settings, target: *settings.Settings) Error!settings.Settings.Applied {
        return target.apply(self.entries);
    }

    pub fn frameLen(self: Settings) usize {
        return frame.header_len + self.entries.len;
    }

    pub fn encode(self: Settings, out: []u8) []u8 {
        std.debug.assert(!self.ack or self.entries.len == 0);
        const bits: u8 = if (self.ack) flag.ack else 0;
        const body = writeHeader(.settings, bits, 0, self.entries.len, out);
        @memcpy(body[0..self.entries.len], self.entries);
        return out[0..self.frameLen()];
    }
};

/// `PUSH_PROMISE`. RFC 9113 section 6.6.
pub const PushPromise = struct {
    promised_stream_id: u31,
    block: []const u8,
    padding: ?u8 = null,
    end_headers: bool = false,

    /// The octets of the promised stream identifier.
    pub const promised_len: usize = 4;

    pub fn parse(header: Header, bytes: []const u8) Error!PushPromise {
        // Section 6.6: a PUSH_PROMISE on stream 0 is a connection error.
        if (header.stream_id == 0) return error.StreamIdZero;
        const stripped = try stripPadding(header.has(flag.padded), bytes);
        if (stripped.body.len < promised_len) return error.PayloadTruncated;

        const raw = std.mem.readInt(u32, stripped.body[0..4], .big);
        return .{
            // The high bit is reserved. Section 6.6 says it is unused, so
            // it is dropped the way section 4.1 drops the one in the
            // frame header.
            .promised_stream_id = @truncate(raw),
            .block = stripped.body[promised_len..],
            .padding = stripped.padding,
            .end_headers = header.has(flag.end_headers),
        };
    }

    pub fn flags(self: PushPromise) u8 {
        var bits: u8 = 0;
        if (self.end_headers) bits |= flag.end_headers;
        if (self.padding != null) bits |= flag.padded;
        return bits;
    }

    pub fn payloadLen(self: PushPromise) usize {
        return paddedLen(promised_len + self.block.len, self.padding);
    }

    pub fn frameLen(self: PushPromise) usize {
        return frame.header_len + self.payloadLen();
    }

    pub fn encode(self: PushPromise, stream_id: u31, out: []u8) []u8 {
        std.debug.assert(stream_id != 0);
        const body = writeHeader(.push_promise, self.flags(), stream_id, self.payloadLen(), out);

        var offset: usize = 0;
        if (self.padding) |pad_len| {
            body[0] = pad_len;
            offset = 1;
        }
        std.mem.writeInt(u32, body[offset..][0..4], @as(u32, self.promised_stream_id), .big);
        offset += promised_len;
        @memcpy(body[offset..][0..self.block.len], self.block);
        offset += self.block.len;
        if (self.padding) |pad_len| @memset(body[offset..][0..pad_len], 0);
        return out[0..self.frameLen()];
    }
};

/// `PING`. RFC 9113 section 6.7.
pub const Ping = struct {
    /// The 8 octets the sender chose. A reply must send them back
    /// unchanged.
    opaque_data: [8]u8,
    ack: bool = false,

    pub const payload_len: usize = 8;

    pub fn parse(header: Header, bytes: []const u8) Error!Ping {
        // Section 6.7: a PING on a stream is a connection error, and it
        // is checked first, because a PING with the wrong length is also
        // a connection error and the stream rule is the plainer fault.
        if (header.stream_id != 0) return error.StreamIdNonZero;
        if (bytes.len != payload_len) return error.PingLengthInvalid;
        return .{ .opaque_data = bytes[0..payload_len].*, .ack = header.has(flag.ack) };
    }

    pub fn frameLen(_: Ping) usize {
        return frame.header_len + payload_len;
    }

    pub fn encode(self: Ping, out: []u8) []u8 {
        const bits: u8 = if (self.ack) flag.ack else 0;
        const body = writeHeader(.ping, bits, 0, payload_len, out);
        @memcpy(body[0..payload_len], &self.opaque_data);
        return out[0 .. frame.header_len + payload_len];
    }

    /// The reply to this `PING`, which carries the same octets back.
    pub fn reply(self: Ping) Ping {
        return .{ .opaque_data = self.opaque_data, .ack = true };
    }
};

/// `GOAWAY`. RFC 9113 section 6.8.
pub const Goaway = struct {
    last_stream_id: u31,
    error_code: ErrorCode,
    /// Whatever the peer chose to say. It carries no meaning the
    /// protocol defines, and it is not to be shown to a user without
    /// escaping.
    debug_data: []const u8 = &.{},

    /// The two fixed fields, before any debug data.
    pub const fixed_len: usize = 8;

    pub fn parse(header: Header, bytes: []const u8) Error!Goaway {
        // Section 6.8: a GOAWAY on a stream is a connection error.
        if (header.stream_id != 0) return error.StreamIdNonZero;
        if (bytes.len < fixed_len) return error.GoawayLengthInvalid;
        return .{
            .last_stream_id = @truncate(std.mem.readInt(u32, bytes[0..4], .big)),
            .error_code = .fromInt(std.mem.readInt(u32, bytes[4..8], .big)),
            .debug_data = bytes[fixed_len..],
        };
    }

    pub fn payloadLen(self: Goaway) usize {
        return fixed_len + self.debug_data.len;
    }

    pub fn frameLen(self: Goaway) usize {
        return frame.header_len + self.payloadLen();
    }

    pub fn encode(self: Goaway, out: []u8) []u8 {
        const body = writeHeader(.goaway, 0, 0, self.payloadLen(), out);
        std.mem.writeInt(u32, body[0..4], @as(u32, self.last_stream_id), .big);
        std.mem.writeInt(u32, body[4..8], self.error_code.int(), .big);
        @memcpy(body[fixed_len..][0..self.debug_data.len], self.debug_data);
        return out[0..self.frameLen()];
    }
};

/// `WINDOW_UPDATE`. RFC 9113 section 6.9.
pub const WindowUpdate = struct {
    increment: u31,

    pub const payload_len: usize = 4;

    /// The header is not read. RFC 9113 section 6.9 puts a
    /// `WINDOW_UPDATE` on stream 0 for the connection window and on a
    /// stream for that stream's window, so both are legal here. The
    /// stream only changes the scope of a fault, which
    /// `errors.classify` reads off the header itself.
    pub fn parse(_: Header, bytes: []const u8) Error!WindowUpdate {
        if (bytes.len != payload_len) return error.WindowUpdateLengthInvalid;
        const raw = std.mem.readInt(u32, bytes[0..4], .big);
        // The high bit is reserved. Section 6.9 says a receiver ignores
        // it, so the mask drops it.
        const increment: u31 = @truncate(raw);
        // Section 6.9: an increment of 0 is a fault. Its scope follows
        // the stream, which `errors.classify` reads off the header.
        if (increment == 0) return error.WindowUpdateZero;
        return .{ .increment = increment };
    }

    pub fn frameLen(_: WindowUpdate) usize {
        return frame.header_len + payload_len;
    }

    pub fn encode(self: WindowUpdate, stream_id: u31, out: []u8) []u8 {
        std.debug.assert(self.increment != 0);
        const body = writeHeader(.window_update, 0, stream_id, payload_len, out);
        std.mem.writeInt(u32, body[0..4], @as(u32, self.increment), .big);
        return out[0 .. frame.header_len + payload_len];
    }
};

/// `CONTINUATION`. RFC 9113 section 6.10.
pub const Continuation = struct {
    block: []const u8,
    end_headers: bool = false,

    pub fn parse(header: Header, bytes: []const u8) Error!Continuation {
        // Section 6.10: a CONTINUATION on stream 0 is a connection error.
        // Whether one is allowed here at all is the sequencer's rule, not
        // this one.
        if (header.stream_id == 0) return error.StreamIdZero;
        return .{ .block = bytes, .end_headers = header.has(flag.end_headers) };
    }

    pub fn flags(self: Continuation) u8 {
        return if (self.end_headers) flag.end_headers else 0;
    }

    pub fn frameLen(self: Continuation) usize {
        return frame.header_len + self.block.len;
    }

    pub fn encode(self: Continuation, stream_id: u31, out: []u8) []u8 {
        std.debug.assert(stream_id != 0);
        const body = writeHeader(.continuation, self.flags(), stream_id, self.block.len, out);
        @memcpy(body[0..self.block.len], self.block);
        return out[0..self.frameLen()];
    }
};

/// A payload with its padding taken off.
const Stripped = struct {
    body: []const u8,
    padding: ?u8,
};

/// Takes the padding off a `DATA`, `HEADERS`, or `PUSH_PROMISE` payload.
/// RFC 9113 section 6.1.
///
/// The `Pad Length` field is one octet, and the padding follows the
/// content. A `Pad Length` of the payload length or more leaves no room
/// for the length octet itself, and section 6.1 makes that a connection
/// error of type `PROTOCOL_ERROR`.
fn stripPadding(padded: bool, payload: []const u8) Error!Stripped {
    if (!padded) return .{ .body = payload, .padding = null };
    if (payload.len == 0) return error.PayloadTruncated;

    const pad_len = payload[0];
    if (@as(usize, pad_len) >= payload.len) return error.PadLengthTooLong;
    return .{ .body = payload[1 .. payload.len - pad_len], .padding = pad_len };
}

/// The payload octets a body of `body_len` takes once padded.
fn paddedLen(body_len: usize, padding: ?u8) usize {
    const pad = padding orelse return body_len;
    return 1 + body_len + pad;
}

/// Writes a `Pad Length`, a body, and the padding octets into `out`.
fn writePadded(body: []const u8, padding: ?u8, out: []u8) void {
    const pad_len = padding orelse {
        @memcpy(out[0..body.len], body);
        return;
    };
    out[0] = pad_len;
    @memcpy(out[1..][0..body.len], body);
    @memset(out[1 + body.len ..][0..pad_len], 0);
}

/// Writes a frame header into the front of `out` and returns the payload
/// room after it.
///
/// A caller that passes a buffer too small, or a payload above the 24-bit
/// field, is this build's own bug. Nothing a peer sends reaches here.
fn writeHeader(t: frame.Type, flags: u8, stream_id: u31, payload_len: usize, out: []u8) []u8 {
    std.debug.assert(payload_len <= frame.length_max);
    std.debug.assert(out.len >= frame.header_len + payload_len);
    const header: Header = .{
        .length = @intCast(payload_len),
        .type = t,
        .flags = flags,
        .stream_id = stream_id,
    };
    header.encode(out[0..frame.header_len]);
    return out[frame.header_len..][0..payload_len];
}

const testing = std.testing;

/// Parses a whole frame out of its octets, the way `FrameReader` does but
/// with no reader and no size bound.
fn parseWhole(bytes: []const u8) Error!Frame {
    const header = Header.parse(bytes[0..frame.header_len]);
    return Frame.parse(header, bytes[frame.header_len..][0..header.length]);
}

test "DATA round-trips through its octets" {
    const value: Data = .{ .data = "hello", .end_stream = true };
    var out: [64]u8 = undefined;
    const bytes = value.encode(1, &out);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x00, 0x05, // length 5
        0x00, // DATA
        0x01, // END_STREAM
        0x00, 0x00, 0x00, 0x01, // stream 1
        'h',  'e',  'l',  'l',
        'o',
    }, bytes);

    const got = try parseWhole(bytes);
    try testing.expectEqual(frame.Type.data, got.header.type);
    try testing.expectEqual(@as(u31, 1), got.header.stream_id);
    try testing.expectEqualSlices(u8, "hello", got.payload.data.data);
    try testing.expectEqual(true, got.payload.data.end_stream);
    try testing.expectEqual(@as(?u8, null), got.payload.data.padding);
}

test "a padded DATA round-trips, and the padding is not in the data" {
    const value: Data = .{ .data = "ok", .padding = 3 };
    var out: [64]u8 = undefined;
    const bytes = value.encode(3, &out);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x00, 0x06, // length: 1 pad-length octet, 2 data, 3 padding
        0x00, // DATA
        0x08, // PADDED
        0x00, 0x00, 0x00, 0x03, // stream 3
        0x03, // Pad Length
        'o',
        'k',
        0x00, 0x00, 0x00, // the padding octets
    }, bytes);

    const got = (try parseWhole(bytes)).payload.data;
    try testing.expectEqualSlices(u8, "ok", got.data);
    try testing.expectEqual(@as(?u8, 3), got.padding);
}

test "a PADDED DATA with no padding octets is not the same as an unpadded one" {
    var padded_out: [32]u8 = undefined;
    var plain_out: [32]u8 = undefined;
    const padded = (Data{ .data = "x", .padding = 0 }).encode(1, &padded_out);
    const plain = (Data{ .data = "x" }).encode(1, &plain_out);
    try testing.expect(!std.mem.eql(u8, padded, plain));

    try testing.expectEqual(@as(?u8, 0), (try parseWhole(padded)).payload.data.padding);
    try testing.expectEqual(@as(?u8, null), (try parseWhole(plain)).payload.data.padding);
}

test "a DATA on stream 0 is a fault" {
    const header: Header = .{ .length = 1, .type = .data, .flags = 0, .stream_id = 0 };
    try testing.expectError(error.StreamIdZero, Frame.parse(header, "x"));
    try testing.expectEqual(
        errors.Fault{ .code = .protocol_error, .scope = .connection },
        errors.classify(error.StreamIdZero, 0),
    );
}

test "padding longer than the payload is a connection error" {
    // Payload is 3 octets: a Pad Length of 3, then 2 octets. The padding
    // has no room for the length octet itself.
    const header: Header = .{
        .length = 3,
        .type = .data,
        .flags = frame.flag.padded,
        .stream_id = 1,
    };
    try testing.expectError(error.PadLengthTooLong, Frame.parse(header, &.{ 0x03, 'a', 'b' }));

    // A Pad Length equal to the payload length is the same fault.
    const two: Header = .{ .length = 2, .type = .data, .flags = frame.flag.padded, .stream_id = 1 };
    try testing.expectError(error.PadLengthTooLong, Frame.parse(two, &.{ 0x02, 'a' }));

    // One less is legal and leaves an empty body.
    const ok = try Frame.parse(two, &.{ 0x01, 0x00 });
    try testing.expectEqualSlices(u8, "", ok.payload.data.data);
    try testing.expectEqual(@as(?u8, 1), ok.payload.data.padding);

    try testing.expectEqual(
        errors.Fault{ .code = .protocol_error, .scope = .connection },
        errors.classify(error.PadLengthTooLong, 1),
    );
}

test "a PADDED frame with an empty payload has no room for the Pad Length octet" {
    const header: Header = .{
        .length = 0,
        .type = .data,
        .flags = frame.flag.padded,
        .stream_id = 1,
    };
    try testing.expectError(error.PayloadTruncated, Frame.parse(header, &.{}));
}

test "HEADERS round-trips through its octets" {
    const value: Headers = .{ .block = "\x82\x84", .end_stream = true, .end_headers = true };
    var out: [64]u8 = undefined;
    const bytes = value.encode(1, &out);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x00, 0x02, // length 2
        0x01, // HEADERS
        0x05, // END_STREAM and END_HEADERS
        0x00, 0x00, 0x00, 0x01, // stream 1
        0x82, 0x84, // an HPACK block of two indexed fields
    }, bytes);

    const got = (try parseWhole(bytes)).payload.headers;
    try testing.expectEqualSlices(u8, "\x82\x84", got.block);
    try testing.expect(got.end_stream);
    try testing.expect(got.end_headers);
    try testing.expectEqual(@as(?Priority, null), got.priority);
}

test "a HEADERS with padding and priority round-trips both" {
    const value: Headers = .{
        .block = "\x82",
        .priority = .{ .exclusive = true, .dependency = 5, .weight = 15 },
        .padding = 2,
        .end_headers = true,
    };
    var out: [64]u8 = undefined;
    const bytes = value.encode(7, &out);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x00, 0x09, // length: 1 pad-length, 5 priority, 1 block, 2 padding
        0x01, // HEADERS
        0x2c, // END_HEADERS, PADDED, PRIORITY
        0x00, 0x00, 0x00, 0x07, // stream 7
        0x02, // Pad Length
        0x80, 0x00, 0x00, 0x05, // exclusive, depends on stream 5
        0x0f, // weight 15 on the wire, so 16 in the scheme
        0x82, // the block
        0x00, 0x00, // the padding octets
    }, bytes);

    const got = (try parseWhole(bytes)).payload.headers;
    try testing.expectEqualSlices(u8, "\x82", got.block);
    try testing.expectEqual(@as(?u8, 2), got.padding);
    try testing.expectEqual(Priority{ .exclusive = true, .dependency = 5, .weight = 15 }, got.priority.?);
}

test "a HEADERS with the PRIORITY flag and too few octets is truncated" {
    const header: Header = .{
        .length = 4,
        .type = .headers,
        .flags = frame.flag.priority,
        .stream_id = 1,
    };
    try testing.expectError(
        error.PayloadTruncated,
        Frame.parse(header, &.{ 0x00, 0x00, 0x00, 0x01 }),
    );
}

test "a HEADERS on stream 0 is a fault" {
    const header: Header = .{ .length = 0, .type = .headers, .flags = 0x04, .stream_id = 0 };
    try testing.expectError(error.StreamIdZero, Frame.parse(header, &.{}));
}

test "PRIORITY round-trips through its five octets" {
    const value: Priority = .{ .exclusive = false, .dependency = 1, .weight = 0 };
    var out: [32]u8 = undefined;
    const bytes = value.encode(3, &out);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x00, 0x05, // length 5
        0x02, // PRIORITY
        0x00, // no flags
        0x00, 0x00, 0x00, 0x03, // stream 3
        0x00, 0x00, 0x00, 0x01, // depends on stream 1, not exclusive
        0x00, // weight 0 on the wire, so 1 in the scheme
    }, bytes);
    try testing.expectEqual(value, (try parseWhole(bytes)).payload.priority);
}

test "the exclusive bit is the high bit of the dependency word" {
    const value: Priority = .{ .exclusive = true, .dependency = frame.stream_id_max, .weight = 255 };
    var fields: [Priority.wire_len]u8 = undefined;
    value.encodeFields(&fields);
    try testing.expectEqualSlices(u8, &.{ 0xff, 0xff, 0xff, 0xff, 0xff }, &fields);
    try testing.expectEqual(value, Priority.parseFields(&fields));
}

test "a PRIORITY of the wrong length is a stream error, not a connection error" {
    const four: Header = .{ .length = 4, .type = .priority, .flags = 0, .stream_id = 1 };
    try testing.expectError(error.PriorityLengthInvalid, Frame.parse(four, &.{ 0, 0, 0, 0 }));
    const six: Header = .{ .length = 6, .type = .priority, .flags = 0, .stream_id = 1 };
    try testing.expectError(error.PriorityLengthInvalid, Frame.parse(six, &.{ 0, 0, 0, 0, 0, 0 }));

    try testing.expectEqual(
        errors.Fault{ .code = .frame_size_error, .scope = .stream },
        errors.classify(error.PriorityLengthInvalid, 1),
    );
}

test "a PRIORITY on stream 0 is a connection error, checked before the length" {
    const header: Header = .{ .length = 4, .type = .priority, .flags = 0, .stream_id = 0 };
    try testing.expectError(error.StreamIdZero, Frame.parse(header, &.{ 0, 0, 0, 0 }));
}

test "RST_STREAM round-trips through its four octets" {
    const value: RstStream = .{ .error_code = .cancel };
    var out: [32]u8 = undefined;
    const bytes = value.encode(5, &out);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x00, 0x04, // length 4
        0x03, // RST_STREAM
        0x00, // no flags
        0x00, 0x00, 0x00, 0x05, // stream 5
        0x00, 0x00, 0x00, 0x08, // CANCEL
    }, bytes);
    try testing.expectEqual(value, (try parseWhole(bytes)).payload.rst_stream);
}

test "an unknown RST_STREAM code is kept as it arrived" {
    const value: RstStream = .{ .error_code = .fromInt(0x1234) };
    var out: [32]u8 = undefined;
    const got = (try parseWhole(value.encode(5, &out))).payload.rst_stream;
    try testing.expectEqual(@as(u32, 0x1234), got.error_code.int());
    try testing.expectEqual(ErrorCode.internal_error, got.error_code.normalise());
}

test "a RST_STREAM of the wrong length is a fault" {
    const three: Header = .{ .length = 3, .type = .rst_stream, .flags = 0, .stream_id = 1 };
    try testing.expectError(error.RstStreamLengthInvalid, Frame.parse(three, &.{ 0, 0, 0 }));
    const five: Header = .{ .length = 5, .type = .rst_stream, .flags = 0, .stream_id = 1 };
    try testing.expectError(error.RstStreamLengthInvalid, Frame.parse(five, &.{ 0, 0, 0, 0, 0 }));
    const zero: Header = .{ .length = 0, .type = .rst_stream, .flags = 0, .stream_id = 1 };
    try testing.expectError(error.RstStreamLengthInvalid, Frame.parse(zero, &.{}));

    try testing.expectEqual(
        errors.Fault{ .code = .frame_size_error, .scope = .connection },
        errors.classify(error.RstStreamLengthInvalid, 1),
    );
}

test "a RST_STREAM on stream 0 is a fault" {
    const header: Header = .{ .length = 4, .type = .rst_stream, .flags = 0, .stream_id = 0 };
    try testing.expectError(error.StreamIdZero, Frame.parse(header, &.{ 0, 0, 0, 0 }));
}

test "SETTINGS round-trips through its octets" {
    const entries = [_]u8{
        0x00, 0x03, 0x00, 0x00, 0x00, 0x64, // MAX_CONCURRENT_STREAMS 100
        0x00, 0x04, 0x00, 0x00, 0xff, 0xff, // INITIAL_WINDOW_SIZE 65535
    };
    const value: Settings = .{ .ack = false, .entries = &entries };
    var out: [64]u8 = undefined;
    const bytes = value.encode(&out);
    try testing.expectEqualSlices(u8, &([_]u8{
        0x00, 0x00, 0x0c, // length 12
        0x04, // SETTINGS
        0x00, // no ACK
        0x00, 0x00, 0x00, 0x00, // stream 0
    } ++ entries), bytes);

    const got = (try parseWhole(bytes)).payload.settings;
    try testing.expectEqual(false, got.ack);
    try testing.expectEqual(@as(usize, 2), got.count());
    try testing.expectEqual(
        settings.Entry{ .id = .max_concurrent_streams, .value = 100 },
        got.get(0),
    );
    try testing.expectEqual(
        settings.Entry{ .id = .initial_window_size, .value = 65535 },
        got.get(1),
    );

    var target: settings.Settings = .initial;
    const applied = try got.applyTo(&target);
    try testing.expectEqual(@as(usize, 2), applied.taken);
    try testing.expectEqual(@as(?u32, 100), target.max_concurrent_streams);
}

test "a SETTINGS ACK round-trips and carries nothing" {
    const value: Settings = .{ .ack = true, .entries = &.{} };
    var out: [16]u8 = undefined;
    const bytes = value.encode(&out);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x00, 0x00, // length 0
        0x04, // SETTINGS
        0x01, // ACK
        0x00, 0x00, 0x00, 0x00, // stream 0
    }, bytes);

    const got = (try parseWhole(bytes)).payload.settings;
    try testing.expectEqual(true, got.ack);
    try testing.expectEqual(@as(usize, 0), got.count());
}

test "a SETTINGS length that is not a multiple of six is a fault" {
    inline for ([_]u24{ 1, 2, 3, 4, 5, 7, 11, 13 }) |len| {
        const header: Header = .{ .length = len, .type = .settings, .flags = 0, .stream_id = 0 };
        const bytes = [_]u8{0} ** len;
        try testing.expectError(error.SettingsLengthInvalid, Frame.parse(header, &bytes));
    }
    try testing.expectEqual(
        errors.Fault{ .code = .frame_size_error, .scope = .connection },
        errors.classify(error.SettingsLengthInvalid, 0),
    );
}

test "a SETTINGS ACK with a payload is a fault" {
    const header: Header = .{
        .length = 6,
        .type = .settings,
        .flags = frame.flag.ack,
        .stream_id = 0,
    };
    try testing.expectError(
        error.SettingsAckNotEmpty,
        Frame.parse(header, &.{ 0x00, 0x05, 0x00, 0x00, 0x40, 0x00 }),
    );
}

test "a SETTINGS on a stream is a fault" {
    const header: Header = .{ .length = 0, .type = .settings, .flags = 0, .stream_id = 1 };
    try testing.expectError(error.StreamIdNonZero, Frame.parse(header, &.{}));
    try testing.expectEqual(
        errors.Fault{ .code = .protocol_error, .scope = .connection },
        errors.classify(error.StreamIdNonZero, 1),
    );
}

test "a SETTINGS with a value outside its range is a fault at the parse" {
    const header: Header = .{ .length = 6, .type = .settings, .flags = 0, .stream_id = 0 };
    try testing.expectError(
        error.SettingsMaxFrameSizeInvalid,
        Frame.parse(header, &.{ 0x00, 0x05, 0x00, 0x00, 0x3f, 0xff }), // 16383
    );
    try testing.expectError(
        error.SettingsInitialWindowSizeInvalid,
        Frame.parse(header, &.{ 0x00, 0x04, 0x80, 0x00, 0x00, 0x00 }), // 2^31
    );
    try testing.expectError(
        error.SettingsEnablePushInvalid,
        Frame.parse(header, &.{ 0x00, 0x02, 0x00, 0x00, 0x00, 0x02 }),
    );
}

test "PUSH_PROMISE round-trips through its octets" {
    const value: PushPromise = .{
        .promised_stream_id = 2,
        .block = "\x82",
        .end_headers = true,
    };
    var out: [64]u8 = undefined;
    const bytes = value.encode(1, &out);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x00, 0x05, // length: 4 promised id, 1 block
        0x05, // PUSH_PROMISE
        0x04, // END_HEADERS
        0x00, 0x00, 0x00, 0x01, // stream 1
        0x00, 0x00, 0x00, 0x02, // promised stream 2
        0x82, // the block
    }, bytes);

    const got = (try parseWhole(bytes)).payload.push_promise;
    try testing.expectEqual(@as(u31, 2), got.promised_stream_id);
    try testing.expectEqualSlices(u8, "\x82", got.block);
    try testing.expect(got.end_headers);
}

test "a padded PUSH_PROMISE round-trips" {
    const value: PushPromise = .{ .promised_stream_id = 4, .block = "ab", .padding = 1 };
    var out: [64]u8 = undefined;
    const bytes = value.encode(1, &out);
    const got = (try parseWhole(bytes)).payload.push_promise;
    try testing.expectEqual(@as(u31, 4), got.promised_stream_id);
    try testing.expectEqualSlices(u8, "ab", got.block);
    try testing.expectEqual(@as(?u8, 1), got.padding);
}

test "a PUSH_PROMISE with no room for the promised identifier is truncated" {
    const header: Header = .{ .length = 3, .type = .push_promise, .flags = 0, .stream_id = 1 };
    try testing.expectError(error.PayloadTruncated, Frame.parse(header, &.{ 0, 0, 0 }));
}

test "a PUSH_PROMISE on stream 0 is a fault" {
    const header: Header = .{ .length = 4, .type = .push_promise, .flags = 0, .stream_id = 0 };
    try testing.expectError(error.StreamIdZero, Frame.parse(header, &.{ 0, 0, 0, 0 }));
}

test "PING round-trips through its eight octets" {
    const value: Ping = .{ .opaque_data = .{ 1, 2, 3, 4, 5, 6, 7, 8 } };
    var out: [32]u8 = undefined;
    const bytes = value.encode(&out);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x00, 0x08, // length 8
        0x06, // PING
        0x00, // no ACK
        0x00, 0x00, 0x00, 0x00, // stream 0
        1,    2,    3,    4,
        5,    6,    7,    8,
    }, bytes);
    try testing.expectEqual(value, (try parseWhole(bytes)).payload.ping);
}

test "a PING reply carries the same octets back with ACK set" {
    const value: Ping = .{ .opaque_data = .{ 9, 8, 7, 6, 5, 4, 3, 2 } };
    const reply = value.reply();
    try testing.expectEqual(value.opaque_data, reply.opaque_data);
    try testing.expect(reply.ack);

    var out: [32]u8 = undefined;
    const got = (try parseWhole(reply.encode(&out))).payload.ping;
    try testing.expectEqual(reply, got);
}

test "a PING that is not eight octets is a fault" {
    inline for ([_]u24{ 0, 1, 7, 9, 16 }) |len| {
        const header: Header = .{ .length = len, .type = .ping, .flags = 0, .stream_id = 0 };
        const bytes = [_]u8{0} ** len;
        try testing.expectError(error.PingLengthInvalid, Frame.parse(header, &bytes));
    }
    try testing.expectEqual(
        errors.Fault{ .code = .frame_size_error, .scope = .connection },
        errors.classify(error.PingLengthInvalid, 0),
    );
}

test "a PING on a stream is a fault" {
    const header: Header = .{ .length = 8, .type = .ping, .flags = 0, .stream_id = 1 };
    try testing.expectError(error.StreamIdNonZero, Frame.parse(header, &(.{0} ** 8)));
}

test "GOAWAY round-trips through its octets" {
    const value: Goaway = .{
        .last_stream_id = 3,
        .error_code = .no_error,
        .debug_data = "bye",
    };
    var out: [64]u8 = undefined;
    const bytes = value.encode(&out);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x00, 0x0b, // length: 8 fixed, 3 debug
        0x07, // GOAWAY
        0x00, // no flags
        0x00, 0x00, 0x00, 0x00, // stream 0
        0x00, 0x00, 0x00, 0x03, // last stream 3
        0x00, 0x00, 0x00, 0x00, // NO_ERROR
        'b',  'y',  'e',
    }, bytes);

    const got = (try parseWhole(bytes)).payload.goaway;
    try testing.expectEqual(@as(u31, 3), got.last_stream_id);
    try testing.expectEqual(ErrorCode.no_error, got.error_code);
    try testing.expectEqualSlices(u8, "bye", got.debug_data);
}

test "a GOAWAY with no debug data round-trips" {
    const value: Goaway = .{ .last_stream_id = 0, .error_code = .enhance_your_calm };
    var out: [32]u8 = undefined;
    const bytes = value.encode(&out);
    try testing.expectEqual(@as(usize, frame.header_len + 8), bytes.len);

    const got = (try parseWhole(bytes)).payload.goaway;
    try testing.expectEqual(ErrorCode.enhance_your_calm, got.error_code);
    try testing.expectEqualSlices(u8, "", got.debug_data);
}

test "the reserved bit of the GOAWAY last stream identifier is dropped" {
    const header: Header = .{ .length = 8, .type = .goaway, .flags = 0, .stream_id = 0 };
    const got = try Frame.parse(header, &.{ 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 });
    try testing.expectEqual(@as(u31, 1), got.payload.goaway.last_stream_id);
}

test "a GOAWAY shorter than eight octets is a fault" {
    inline for ([_]u24{ 0, 1, 4, 7 }) |len| {
        const header: Header = .{ .length = len, .type = .goaway, .flags = 0, .stream_id = 0 };
        const bytes = [_]u8{0} ** len;
        try testing.expectError(error.GoawayLengthInvalid, Frame.parse(header, &bytes));
    }
}

test "a GOAWAY on a stream is a fault" {
    const header: Header = .{ .length = 8, .type = .goaway, .flags = 0, .stream_id = 1 };
    try testing.expectError(error.StreamIdNonZero, Frame.parse(header, &(.{0} ** 8)));
}

test "WINDOW_UPDATE round-trips through its four octets" {
    const value: WindowUpdate = .{ .increment = 65535 };
    var out: [32]u8 = undefined;
    const bytes = value.encode(0, &out);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x00, 0x04, // length 4
        0x08, // WINDOW_UPDATE
        0x00, // no flags
        0x00, 0x00, 0x00, 0x00, // stream 0, so the connection window
        0x00, 0x00, 0xff, 0xff, // increment 65535
    }, bytes);
    try testing.expectEqual(value, (try parseWhole(bytes)).payload.window_update);

    // The same frame on a stream carries the stream's window.
    const on_stream = value.encode(1, &out);
    try testing.expectEqual(@as(u31, 1), (try parseWhole(on_stream)).header.stream_id);
}

test "a WINDOW_UPDATE of zero is a fault on the connection and on a stream" {
    const on_connection: Header = .{
        .length = 4,
        .type = .window_update,
        .flags = 0,
        .stream_id = 0,
    };
    try testing.expectError(error.WindowUpdateZero, Frame.parse(on_connection, &.{ 0, 0, 0, 0 }));
    const on_stream: Header = .{ .length = 4, .type = .window_update, .flags = 0, .stream_id = 1 };
    try testing.expectError(error.WindowUpdateZero, Frame.parse(on_stream, &.{ 0, 0, 0, 0 }));

    // The reserved bit alone still leaves an increment of 0.
    try testing.expectError(
        error.WindowUpdateZero,
        Frame.parse(on_stream, &.{ 0x80, 0x00, 0x00, 0x00 }),
    );

    // RFC 9113 section 6.9 makes the scope follow the stream.
    try testing.expectEqual(errors.Scope.connection, errors.classify(error.WindowUpdateZero, 0).scope);
    try testing.expectEqual(errors.Scope.stream, errors.classify(error.WindowUpdateZero, 1).scope);
}

test "a WINDOW_UPDATE of the wrong length is a fault" {
    inline for ([_]u24{ 0, 3, 5, 8 }) |len| {
        const header: Header = .{
            .length = len,
            .type = .window_update,
            .flags = 0,
            .stream_id = 1,
        };
        const bytes = [_]u8{0} ** len;
        try testing.expectError(error.WindowUpdateLengthInvalid, Frame.parse(header, &bytes));
    }
}

test "CONTINUATION round-trips through its octets" {
    const value: Continuation = .{ .block = "\x84", .end_headers = true };
    var out: [32]u8 = undefined;
    const bytes = value.encode(1, &out);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x00, 0x01, // length 1
        0x09, // CONTINUATION
        0x04, // END_HEADERS
        0x00, 0x00, 0x00, 0x01, // stream 1
        0x84, // the block
    }, bytes);

    const got = (try parseWhole(bytes)).payload.continuation;
    try testing.expectEqualSlices(u8, "\x84", got.block);
    try testing.expect(got.end_headers);
}

test "a CONTINUATION on stream 0 is a fault" {
    const header: Header = .{ .length = 0, .type = .continuation, .flags = 0x04, .stream_id = 0 };
    try testing.expectError(error.StreamIdZero, Frame.parse(header, &.{}));
}

test "an unknown frame type parses into its octets rather than a fault" {
    const header: Header = .{ .length = 3, .type = @enumFromInt(0x0a), .flags = 0xff, .stream_id = 9 };
    const got = try Frame.parse(header, "abc");
    try testing.expectEqualSlices(u8, "abc", got.payload.unknown);
    try testing.expectEqual(@as(u8, 0x0a), @intFromEnum(got.header.type));
}

test "an unknown frame type on stream 0 is still not a fault" {
    // Section 4.1 gives no stream rule for a type the receiver does not
    // know, because it does not know what the type means.
    const header: Header = .{ .length = 0, .type = @enumFromInt(0xff), .flags = 0, .stream_id = 0 };
    const got = try Frame.parse(header, &.{});
    try testing.expectEqualSlices(u8, "", got.payload.unknown);
}

test "every parsed slice points into the caller's buffer" {
    var buffer = [_]u8{ 'a', 'b', 'c' };
    const header: Header = .{ .length = 3, .type = .data, .flags = 0, .stream_id = 1 };
    const got = try Frame.parse(header, &buffer);
    try testing.expectEqual(@intFromPtr(&buffer), @intFromPtr(got.payload.data.data.ptr));
}
