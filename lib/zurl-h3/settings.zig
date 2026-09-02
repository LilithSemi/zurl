//! The `SETTINGS` frame payload, RFC 9114 section 7.2.4.
//!
//! The payload is a run of identifier and value pairs, each a QUIC
//! variable-length integer. There is no count and no padding: the payload
//! ends where the frame ends.
//!
//! **A setting is a promise, not a request.** RFC 9114 section 7.2.4.1
//! makes each value take effect the moment the peer reads it, and there is
//! no acknowledgment the way HTTP/2 has one. So a value here is what this
//! side will honour from the first byte of the connection, and this build
//! only names values it can honour whatever the peer does with them.

const std = @import("std");
const quic = @import("zurl-quic");

const varint = quic.varint;

/// The setting identifiers this build knows.
pub const Id = enum(u64) {
    /// RFC 9204 section 5. How large a QPACK dynamic table the peer may
    /// build for this side's decoder.
    qpack_max_table_capacity = 0x01,
    /// RFC 9114 section 7.2.4.1. The largest field section this side will
    /// take, counted the HTTP/2 way: name plus value plus 32 for each
    /// field.
    max_field_section_size = 0x06,
    /// RFC 9204 section 5. How many streams this side lets a field
    /// section block on the dynamic table.
    qpack_blocked_streams = 0x07,
    /// RFC 9220. Whether the peer may send an extended CONNECT.
    enable_connect_protocol = 0x08,
    _,
};

/// The four identifiers RFC 9114 section 7.2.4.1 takes out of use.
///
/// **These are HTTP/2's setting identifiers.** A peer that names one is
/// pointing an HTTP/2 implementation at an HTTP/3 connection, and RFC 9114
/// makes it a connection error of type H3_SETTINGS_ERROR rather than
/// something to ignore.
pub const reserved_http2_ids = [_]u64{ 0x02, 0x03, 0x04, 0x05 };

/// Whether `value` is one of `reserved_http2_ids`.
pub fn isReservedHttp2(value: u64) bool {
    for (reserved_http2_ids) |id| {
        if (value == id) return true;
    }
    return false;
}

/// Whether `value` is an identifier RFC 9114 section 7.2.4.1 reserves for
/// a peer to send on purpose. The pattern is `0x1f * N + 0x21`.
pub fn isReserved(value: u64) bool {
    if (value < 0x21) return false;
    return (value - 0x21) % 0x1f == 0;
}

/// Every fault a `SETTINGS` payload can carry.
pub const Error = error{
    /// The payload stops inside a varint, or names an identifier with no
    /// value behind it. RFC 9114 section 7.2.4, a H3_FRAME_ERROR.
    FrameError,
    /// An identifier RFC 9114 takes out of use, or an identifier that
    /// appears twice. RFC 9114 section 7.2.4, a H3_SETTINGS_ERROR.
    SettingsError,
    /// The payload names more pairs than `max_pairs`. RFC 9114 section
    /// 8.1, a H3_EXCESSIVE_LOAD.
    ///
    /// **The payload is not malformed.** A peer that names this many
    /// identifiers wrote a legal frame, and the refusal is this side's
    /// ceiling on the work of reading it, so the code says so.
    ExcessiveLoad,
};

/// How many pairs one payload may hold.
///
/// **The payload is bytes the peer chose and a pair is two bytes at its
/// smallest**, so a long payload holds many pairs, and each one costs a
/// pass over every identifier already read. That pass is what the ceiling
/// is for: the work grows with the square of the count.
///
/// RFC 9114 puts no ceiling on the count and section 7.2.4.1 asks a peer
/// to name reserved identifiers on purpose, so this number has to sit far
/// above anything an endpoint names rather than just above the four this
/// build knows. RFC 9114 defines one setting, RFC 9204 defines two, and
/// RFC 9220 defines one, so 256 leaves room for every one of them and 252
/// reserved identifiers beside them. A peer past it is refused with
/// H3_EXCESSIVE_LOAD, which says the reading stopped and not that the
/// frame was wrong.
pub const max_pairs: usize = 256;

/// The settings of one endpoint.
///
/// Every field carries the default RFC 9114 or RFC 9204 gives it, so a
/// peer that sends an empty `SETTINGS` frame is described exactly by this
/// struct with nothing set.
pub const Settings = struct {
    /// RFC 9204 section 5, default zero: no dynamic table at all.
    qpack_max_table_capacity: u64 = 0,
    /// RFC 9114 section 7.2.4.1, default unlimited, which is what null
    /// means. **Null and zero are not the same**: zero says no field
    /// section at all is acceptable, and a peer may legally send it.
    max_field_section_size: ?u64 = null,
    /// RFC 9204 section 5, default zero: no stream may block.
    qpack_blocked_streams: u64 = 0,
    /// RFC 9220, default false.
    enable_connect_protocol: bool = false,

    /// How many pairs this side names, which is what `encode` writes.
    ///
    /// A default value is written anyway, because a `SETTINGS` frame is
    /// read once and a reader that sees the number does not have to know
    /// the default.
    pub const written_pairs: usize = 3;
};

/// Reads a whole `SETTINGS` payload.
///
/// RFC 9114 section 7.2.4: an identifier this build does not know is
/// stepped over, and its value with it. An identifier that appears twice
/// is a connection error whether this build knows it or not.
pub fn decode(payload: []const u8) Error!Settings {
    var out: Settings = .{};
    var seen: [max_pairs]u64 = undefined;
    var seen_len: usize = 0;

    var at: usize = 0;
    while (at < payload.len) {
        if (seen_len == max_pairs) return error.ExcessiveLoad;
        const id_field = varint.decode(payload[at..]) catch return error.FrameError;
        at += id_field.len;
        const value_field = varint.decode(payload[at..]) catch return error.FrameError;
        at += value_field.len;

        if (isReservedHttp2(id_field.value)) return error.SettingsError;
        for (seen[0..seen_len]) |already| {
            if (already == id_field.value) return error.SettingsError;
        }
        seen[seen_len] = id_field.value;
        seen_len += 1;

        switch (@as(Id, @enumFromInt(id_field.value))) {
            .qpack_max_table_capacity => out.qpack_max_table_capacity = value_field.value,
            .max_field_section_size => out.max_field_section_size = value_field.value,
            .qpack_blocked_streams => out.qpack_blocked_streams = value_field.value,
            .enable_connect_protocol => {
                // RFC 9220: the value is 0 or 1 and no other number.
                if (value_field.value > 1) return error.SettingsError;
                out.enable_connect_protocol = value_field.value == 1;
            },
            // An identifier this build does not know, which includes
            // every reserved one. RFC 9114 section 7.2.4 steps over it.
            _ => {},
        }
    }
    return out;
}

/// How many bytes `encode` writes for `s`.
pub fn encodedLen(s: Settings) usize {
    var total: usize = 0;
    total += pairLen(.qpack_max_table_capacity, s.qpack_max_table_capacity);
    total += pairLen(.max_field_section_size, s.max_field_section_size orelse varint.max_value);
    total += pairLen(.qpack_blocked_streams, s.qpack_blocked_streams);
    return total;
}

fn pairLen(id: Id, value: u64) usize {
    const id_len = varint.encodedLen(@intFromEnum(id)) catch unreachable;
    const value_len = varint.encodedLen(value) catch unreachable;
    return id_len + value_len;
}

/// Writes the payload of a `SETTINGS` frame carrying `s`, and returns the
/// part of `out` it wrote.
///
/// **Three pairs, always the same three.** A `SETTINGS` frame goes out
/// once on the control stream, so there is nothing to gain by leaving a
/// default out, and a peer that reads all three needs no table of
/// defaults to know what this side does.
pub fn encode(s: Settings, out: []u8) []u8 {
    std.debug.assert(out.len >= encodedLen(s));
    var at: usize = 0;
    at += writePair(.qpack_max_table_capacity, s.qpack_max_table_capacity, out[at..]);
    at += writePair(.max_field_section_size, s.max_field_section_size orelse varint.max_value, out[at..]);
    at += writePair(.qpack_blocked_streams, s.qpack_blocked_streams, out[at..]);
    return out[0..at];
}

fn writePair(id: Id, value: u64, out: []u8) usize {
    var scratch: [varint.max_bytes]u8 = undefined;
    const id_bytes = varint.encode(&scratch, @intFromEnum(id)) catch unreachable;
    @memcpy(out[0..id_bytes.len], id_bytes);
    var at = id_bytes.len;
    const value_bytes = varint.encode(&scratch, value) catch unreachable;
    @memcpy(out[at..][0..value_bytes.len], value_bytes);
    at += value_bytes.len;
    return at;
}

const testing = std.testing;

/// Writes `value` as a varint of exactly `width` bytes.
///
/// RFC 9000 section 16 lets an encoding be longer than the value needs, so
/// a peer can spell any identifier this way. `varint.encode` writes the
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

test "an identifier is read by its value and never by its bytes" {
    // **The single test that tells a value comparison from a byte
    // comparison.** RFC 9000 section 16 lets a peer spell `0x02` as eight
    // bytes, and a build that matched the shortest spelling would read
    // that as an identifier it does not know and step over an HTTP/2
    // setting RFC 9114 section 7.2.4.1 refuses.
    var wide: [varint.max_bytes]u8 = undefined;
    for (reserved_http2_ids) |id| {
        var payload: [varint.max_bytes + 1]u8 = undefined;
        const bytes = wideVarint(&wide, varint.max_bytes, id);
        @memcpy(payload[0..bytes.len], bytes);
        payload[bytes.len] = 0x01;
        try testing.expectError(error.SettingsError, decode(payload[0 .. bytes.len + 1]));
    }

    // A known identifier spelled wide is still the identifier it names.
    {
        const bytes = wideVarint(&wide, varint.max_bytes, @intFromEnum(Id.max_field_section_size));
        var payload: [varint.max_bytes + 2]u8 = undefined;
        @memcpy(payload[0..bytes.len], bytes);
        payload[bytes.len] = 0x44;
        payload[bytes.len + 1] = 0x00;
        const s = try decode(payload[0 .. bytes.len + 2]);
        try testing.expectEqual(@as(?u64, 0x400), s.max_field_section_size);
    }

    // A reserved identifier spelled wide is still stepped over, and the
    // pair behind it is still read.
    {
        const bytes = wideVarint(&wide, varint.max_bytes, 0x1f * 3 + 0x21);
        var payload: [varint.max_bytes + 4]u8 = undefined;
        @memcpy(payload[0..bytes.len], bytes);
        payload[bytes.len] = 0x01;
        payload[bytes.len + 1] = 0x06;
        payload[bytes.len + 2] = 0x44;
        payload[bytes.len + 3] = 0x00;
        const s = try decode(payload[0 .. bytes.len + 4]);
        try testing.expectEqual(@as(?u64, 0x400), s.max_field_section_size);
    }

    // And the duplicate rule compares values as well: one byte and then
    // eight bytes naming 0x06 is the same identifier twice.
    {
        const bytes = wideVarint(&wide, varint.max_bytes, @intFromEnum(Id.max_field_section_size));
        var payload: [varint.max_bytes + 3]u8 = undefined;
        payload[0] = 0x06;
        payload[1] = 0x00;
        @memcpy(payload[2..][0..bytes.len], bytes);
        payload[2 + bytes.len] = 0x00;
        try testing.expectError(error.SettingsError, decode(payload[0 .. 3 + bytes.len]));
    }
}

test "an empty payload is every default and no fault" {
    // RFC 9114 section 7.2.4: a SETTINGS frame with no pairs is legal and
    // says the peer takes every default.
    const s = try decode(&.{});
    try testing.expectEqual(@as(u64, 0), s.qpack_max_table_capacity);
    try testing.expectEqual(@as(?u64, null), s.max_field_section_size);
    try testing.expectEqual(@as(u64, 0), s.qpack_blocked_streams);
    try testing.expect(!s.enable_connect_protocol);
}

test "the three settings this build writes read back byte for byte" {
    const s: Settings = .{
        .qpack_max_table_capacity = 4096,
        .max_field_section_size = 65536,
        .qpack_blocked_streams = 0,
    };
    var out: [64]u8 = undefined;
    const written = encode(s, &out);
    try testing.expectEqual(encodedLen(s), written.len);

    const back = try decode(written);
    try testing.expectEqual(s.qpack_max_table_capacity, back.qpack_max_table_capacity);
    try testing.expectEqual(s.max_field_section_size, back.max_field_section_size);
    try testing.expectEqual(s.qpack_blocked_streams, back.qpack_blocked_streams);
}

test "an identifier this build does not know is stepped over with its value" {
    // Identifier 0x4040, a two byte varint, with a four byte value, then
    // the setting this build does know.
    const payload = [_]u8{ 0x40, 0x40, 0x80, 0x00, 0x10, 0x00, 0x06, 0x44, 0x00 };
    const s = try decode(&payload);
    try testing.expectEqual(@as(?u64, 0x400), s.max_field_section_size);
}

test "a reserved identifier is stepped over and an HTTP/2 one is refused" {
    // RFC 9114 section 7.2.4.1. A peer sends 0x21 on purpose to check
    // that this side ignores it.
    const reserved = [_]u8{ 0x21, 0x01, 0x06, 0x44, 0x00 };
    const s = try decode(&reserved);
    try testing.expectEqual(@as(?u64, 0x400), s.max_field_section_size);

    // The four HTTP/2 identifiers are a connection error instead.
    for (reserved_http2_ids) |id| {
        const bad = [_]u8{ @intCast(id), 0x01 };
        try testing.expectError(error.SettingsError, decode(&bad));
    }
}

test "an identifier that appears twice is a connection error" {
    // RFC 9114 section 7.2.4: the second appearance is H3_SETTINGS_ERROR,
    // whether this build knows the identifier or not.
    const known = [_]u8{ 0x06, 0x40, 0x64, 0x06, 0x40, 0x65 };
    try testing.expectError(error.SettingsError, decode(&known));

    const unknown = [_]u8{ 0x21, 0x01, 0x21, 0x02 };
    try testing.expectError(error.SettingsError, decode(&unknown));
}

test "a payload that stops inside a pair is a frame error" {
    // An identifier with no value behind it.
    try testing.expectError(error.FrameError, decode(&.{0x06}));
    // A value that stops inside its varint.
    try testing.expectError(error.FrameError, decode(&.{ 0x06, 0x40 }));
    // An identifier that stops inside its own varint.
    try testing.expectError(error.FrameError, decode(&.{0x80}));
}

test "a payload naming more pairs than the bound allows is refused as excessive load" {
    // Distinct identifiers from 0x100 up, each spelled as a two byte
    // varint so the numbers stay one to a pair, and each with a one byte
    // value. None of them is one of the four HTTP/2 identifiers, so the
    // count is the only thing under test.
    var payload: [3 * (max_pairs + 1)]u8 = undefined;
    var index: usize = 0;
    while (index <= max_pairs) : (index += 1) {
        const id: u64 = 0x100 + index;
        payload[index * 3] = @intCast(0x40 | (id >> 8));
        payload[index * 3 + 1] = @intCast(id & 0xff);
        payload[index * 3 + 2] = 0x00;
    }
    // The payload is legal, so the code says this side stopped reading.
    try testing.expectError(error.ExcessiveLoad, decode(&payload));
    // One fewer is inside the bound.
    try testing.expectEqual(@as(?u64, null), (try decode(payload[0 .. max_pairs * 3])).max_field_section_size);

    // And the bound sits far above the number of settings the RFCs
    // define, so a peer greasing with reserved identifiers is never
    // refused for it. RFC 9114 section 7.2.4.1.
    try testing.expect(max_pairs >= 256);
}

test "the extended CONNECT setting takes 0 or 1 and no other number" {
    // RFC 9220.
    try testing.expect((try decode(&.{ 0x08, 0x01 })).enable_connect_protocol);
    try testing.expect(!(try decode(&.{ 0x08, 0x00 })).enable_connect_protocol);
    try testing.expectError(error.SettingsError, decode(&.{ 0x08, 0x02 }));
}

test "an unlimited field section size is not the same as a zero one" {
    // Null says the peer named nothing, so anything goes. Zero says the
    // peer named zero, which is a peer that will take no field section at
    // all, and a client that read the two the same way would send a
    // request the peer refuses.
    try testing.expectEqual(@as(?u64, null), (try decode(&.{})).max_field_section_size);
    try testing.expectEqual(@as(?u64, 0), (try decode(&.{ 0x06, 0x00 })).max_field_section_size);
}
