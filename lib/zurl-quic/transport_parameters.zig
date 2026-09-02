//! The transport parameters of QUIC, RFC 9000 section 18.
//!
//! **These are the limits each endpoint states once, before it sends
//! anything else.** They travel inside the TLS handshake, in the
//! `quic_transport_parameters` extension, as a run of identifier, length,
//! value triples. Everything QUIC bounds at the connection level starts
//! here: how much data may be in flight, how many streams may be open,
//! how long a peer may stay quiet, and which connection ids are in play.
//!
//! This file reads and writes those bytes and checks the rules section
//! 18.2 states about each value. It does not apply them: nothing here
//! counts a byte of flow control or opens a stream.
//!
//! ## What is bounded, and why each one matters
//!
//! Every value is a varint the peer chose, so every one can be 2^62.
//! Section 18.2 puts a real bound on five of them, and each bound is a
//! rule with a reason:
//!
//! - **`max_udp_payload_size` below 1200 is refused.** QUIC needs 1200
//!   bytes for a first packet, so a smaller value would make the
//!   handshake impossible and is a peer that is not speaking QUIC.
//! - **`ack_delay_exponent` above 20 is refused.** The exponent is a
//!   shift on a delay, and 2^20 microseconds is already a second.
//! - **`max_ack_delay` at or above 2^14 milliseconds is refused.**
//! - **`active_connection_id_limit` below 2 is refused.** A connection
//!   needs two ids to migrate at all.
//! - **A stream count above 2^60 is refused**, for the reason
//!   `frame.zig` refuses one: it names a stream id with no encoding.
//!
//! **A repeated identifier is refused.** Section 18 gives each parameter
//! one appearance, and two values for one limit is a packet this build
//! and the peer would read differently.
//!
//! **An identifier this build does not know is skipped, not refused.**
//! Section 18 requires that, and section 18.1 reserves a run of
//! identifiers to make sure implementations really do it. So a `Decoded`
//! carries what it recognised and nothing about what it stepped over.
//!
//! Nothing here allocates. A connection id and a token are held by value,
//! because they outlive the handshake buffer they arrived in.

const std = @import("std");

const Cursor = @import("Cursor.zig");
const packet = @import("packet.zig");
const varint = @import("varint.zig");

/// The identifiers of RFC 9000 section 18.2.
///
/// Non-exhaustive, because an identifier this build does not know is
/// skipped and not refused. Section 18.1 reserves `31 * N + 27` for
/// exactly that reason.
pub const Id = enum(u64) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    disable_active_migration = 0x0c,
    preferred_address = 0x0d,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,
    _,

    /// True when RFC 9000 section 18.1 sets the identifier aside to
    /// exercise the rule that an unknown one is ignored.
    pub fn isReserved(self: Id) bool {
        const n = @intFromEnum(self);
        return n >= 27 and (n - 27) % 31 == 0;
    }
};

/// The default `max_udp_payload_size`, and the largest a value may be.
/// RFC 9000 section 18.2.
pub const default_max_udp_payload_size: u64 = 65527;

/// The smallest `max_udp_payload_size` a peer may state. RFC 9000 section
/// 18.2: a smaller one cannot carry a first packet.
pub const min_max_udp_payload_size: u64 = 1200;

/// The default `ack_delay_exponent`. RFC 9000 section 18.2.
pub const default_ack_delay_exponent: u64 = 3;

/// The largest `ack_delay_exponent` a peer may state.
pub const max_ack_delay_exponent: u64 = 20;

/// The default `max_ack_delay`, in milliseconds. RFC 9000 section 18.2.
pub const default_max_ack_delay: u64 = 25;

/// One more than the largest `max_ack_delay` a peer may state.
pub const max_ack_delay_limit: u64 = 1 << 14;

/// The default `active_connection_id_limit`, and the smallest a peer may
/// state. RFC 9000 section 18.2.
pub const default_active_connection_id_limit: u64 = 2;

/// The largest stream count a peer may state, the same bound
/// `frame.max_stream_count` keeps.
pub const max_stream_count: u64 = 1 << 60;

/// How many bytes a Stateless Reset Token takes. RFC 9000 section 10.3.
pub const stateless_reset_token_len: usize = 16;

/// The server's preferred address. RFC 9000 section 18.2.
///
/// **A server offers this and a client may move to it.** Both address
/// families are in the structure, and an unused one is written as all
/// zeroes with a port of zero.
pub const PreferredAddress = struct {
    ipv4: [4]u8,
    ipv4_port: u16,
    ipv6: [16]u8,
    ipv6_port: u16,
    connection_id: packet.ConnectionId,
    stateless_reset_token: [stateless_reset_token_len]u8,

    /// How many bytes the fixed part takes: both addresses, both ports,
    /// the connection id length byte, and the reset token.
    pub const fixed_len: usize = 4 + 2 + 16 + 2 + 1 + stateless_reset_token_len;

    /// True when the server offered an IPv4 address at all.
    pub fn hasIpv4(self: *const PreferredAddress) bool {
        return self.ipv4_port != 0 or !std.mem.allEqual(u8, &self.ipv4, 0);
    }

    /// True when the server offered an IPv6 address at all.
    pub fn hasIpv6(self: *const PreferredAddress) bool {
        return self.ipv6_port != 0 or !std.mem.allEqual(u8, &self.ipv6, 0);
    }
};

/// Everything one endpoint stated. RFC 9000 section 18.2.
///
/// **A parameter that was absent keeps its default**, and section 18.2
/// makes that default zero unless it says otherwise. The five that have
/// another default carry it here, so a caller reads one value and never
/// asks whether the field arrived.
pub const Parameters = struct {
    /// Server only. The Destination Connection ID of the client's first
    /// Initial packet, which a client checks against what it sent.
    original_destination_connection_id: ?packet.ConnectionId = null,
    /// In milliseconds. Zero means no idle timeout at all.
    max_idle_timeout: u64 = 0,
    /// Server only.
    stateless_reset_token: ?[stateless_reset_token_len]u8 = null,
    max_udp_payload_size: u64 = default_max_udp_payload_size,
    initial_max_data: u64 = 0,
    initial_max_stream_data_bidi_local: u64 = 0,
    initial_max_stream_data_bidi_remote: u64 = 0,
    initial_max_stream_data_uni: u64 = 0,
    initial_max_streams_bidi: u64 = 0,
    initial_max_streams_uni: u64 = 0,
    ack_delay_exponent: u64 = default_ack_delay_exponent,
    /// In milliseconds.
    max_ack_delay: u64 = default_max_ack_delay,
    disable_active_migration: bool = false,
    /// Server only.
    preferred_address: ?PreferredAddress = null,
    active_connection_id_limit: u64 = default_active_connection_id_limit,
    /// The Source Connection ID the sender put in its first packet.
    initial_source_connection_id: ?packet.ConnectionId = null,
    /// Server only, and only after a Retry.
    retry_source_connection_id: ?packet.ConnectionId = null,

    /// The `ack_delay_exponent` as a shift a caller can use.
    ///
    /// Refused above 20 at decode, so this cannot make an undefined
    /// shift.
    pub fn ackDelayShift(self: Parameters) u6 {
        std.debug.assert(self.ack_delay_exponent <= max_ack_delay_exponent);
        return @intCast(self.ack_delay_exponent);
    }
};

/// Why a run of bytes is not a set of transport parameters.
pub const DecodeError = error{
    /// A parameter ran past the end of the extension.
    Truncated,
    /// One identifier appeared twice. RFC 9000 section 18 gives each one
    /// a single appearance.
    DuplicateParameter,
    /// A parameter whose value is a fixed width arrived at another width:
    /// a connection id above 20 bytes, a reset token that is not 16, a
    /// `disable_active_migration` that is not empty, or a preferred
    /// address that does not fit its own structure.
    BadParameterLength,
    /// A `max_udp_payload_size` below 1200.
    UdpPayloadSizeTooSmall,
    /// An `ack_delay_exponent` above 20.
    AckDelayExponentTooLarge,
    /// A `max_ack_delay` at or above 2^14 milliseconds.
    AckDelayTooLarge,
    /// An `active_connection_id_limit` below 2.
    ConnectionIdLimitTooSmall,
    /// A stream count above 2^60.
    StreamCountTooLarge,
};

/// Reads one set of transport parameters.
///
/// An identifier this build does not know is stepped over, which RFC 9000
/// section 18 requires. An identifier it does know may appear once.
pub fn decode(bytes: []const u8) DecodeError!Parameters {
    var out: Parameters = .{};
    var seen: std.EnumSet(KnownId) = .initEmpty();
    var c: Cursor = .init(bytes);

    while (!c.isEmpty()) {
        const id: Id = @enumFromInt(try c.takeVarint());
        const length = try c.takeVarint();
        // **The bound, and it runs before the value is read.** A peer can
        // write 2^62 here for a two byte extension.
        const value = try c.takeVarintLength(length);

        const known = knownId(id) orelse continue;
        if (seen.contains(known)) return error.DuplicateParameter;
        seen.insert(known);
        try readOne(&out, known, value);
    }

    return out;
}

/// The identifiers this build reads, as an exhaustive enum.
///
/// A second enum and not `Id`, because `Id` is non-exhaustive and
/// `std.EnumSet` needs a fixed set of names to hold "already seen".
const KnownId = enum {
    original_destination_connection_id,
    max_idle_timeout,
    stateless_reset_token,
    max_udp_payload_size,
    initial_max_data,
    initial_max_stream_data_bidi_local,
    initial_max_stream_data_bidi_remote,
    initial_max_stream_data_uni,
    initial_max_streams_bidi,
    initial_max_streams_uni,
    ack_delay_exponent,
    max_ack_delay,
    disable_active_migration,
    preferred_address,
    active_connection_id_limit,
    initial_source_connection_id,
    retry_source_connection_id,
};

/// The name for `id`, or null for an identifier this build steps over.
fn knownId(id: Id) ?KnownId {
    return switch (id) {
        .original_destination_connection_id => .original_destination_connection_id,
        .max_idle_timeout => .max_idle_timeout,
        .stateless_reset_token => .stateless_reset_token,
        .max_udp_payload_size => .max_udp_payload_size,
        .initial_max_data => .initial_max_data,
        .initial_max_stream_data_bidi_local => .initial_max_stream_data_bidi_local,
        .initial_max_stream_data_bidi_remote => .initial_max_stream_data_bidi_remote,
        .initial_max_stream_data_uni => .initial_max_stream_data_uni,
        .initial_max_streams_bidi => .initial_max_streams_bidi,
        .initial_max_streams_uni => .initial_max_streams_uni,
        .ack_delay_exponent => .ack_delay_exponent,
        .max_ack_delay => .max_ack_delay,
        .disable_active_migration => .disable_active_migration,
        .preferred_address => .preferred_address,
        .active_connection_id_limit => .active_connection_id_limit,
        .initial_source_connection_id => .initial_source_connection_id,
        .retry_source_connection_id => .retry_source_connection_id,
        _ => null,
    };
}

/// Reads one parameter's value into `out`, with the rule section 18.2
/// states about it.
fn readOne(out: *Parameters, id: KnownId, value: []const u8) DecodeError!void {
    switch (id) {
        .original_destination_connection_id => out.original_destination_connection_id = try takeConnectionId(value),
        .initial_source_connection_id => out.initial_source_connection_id = try takeConnectionId(value),
        .retry_source_connection_id => out.retry_source_connection_id = try takeConnectionId(value),
        .stateless_reset_token => {
            if (value.len != stateless_reset_token_len) return error.BadParameterLength;
            out.stateless_reset_token = value[0..stateless_reset_token_len].*;
        },
        .disable_active_migration => {
            // Section 18.2: the value is zero length. A value with bytes
            // in it is a parameter this build would be guessing about.
            if (value.len != 0) return error.BadParameterLength;
            out.disable_active_migration = true;
        },
        .preferred_address => out.preferred_address = try decodePreferredAddress(value),
        .max_idle_timeout => out.max_idle_timeout = try takeInteger(value),
        .initial_max_data => out.initial_max_data = try takeInteger(value),
        .initial_max_stream_data_bidi_local => out.initial_max_stream_data_bidi_local = try takeInteger(value),
        .initial_max_stream_data_bidi_remote => out.initial_max_stream_data_bidi_remote = try takeInteger(value),
        .initial_max_stream_data_uni => out.initial_max_stream_data_uni = try takeInteger(value),
        .initial_max_streams_bidi => out.initial_max_streams_bidi = try takeStreamCount(value),
        .initial_max_streams_uni => out.initial_max_streams_uni = try takeStreamCount(value),
        .max_udp_payload_size => {
            const size = try takeInteger(value);
            if (size < min_max_udp_payload_size) return error.UdpPayloadSizeTooSmall;
            out.max_udp_payload_size = size;
        },
        .ack_delay_exponent => {
            const exponent = try takeInteger(value);
            if (exponent > max_ack_delay_exponent) return error.AckDelayExponentTooLarge;
            out.ack_delay_exponent = exponent;
        },
        .max_ack_delay => {
            const delay = try takeInteger(value);
            if (delay >= max_ack_delay_limit) return error.AckDelayTooLarge;
            out.max_ack_delay = delay;
        },
        .active_connection_id_limit => {
            const limit = try takeInteger(value);
            if (limit < default_active_connection_id_limit) return error.ConnectionIdLimitTooSmall;
            out.active_connection_id_limit = limit;
        },
    }
}

/// Reads an integer parameter, which is one varint that fills the value.
///
/// A value with bytes left after the varint is malformed. Reading only
/// the front of it would let a peer hide a second number where this
/// build never looks.
fn takeInteger(value: []const u8) DecodeError!u64 {
    var c: Cursor = .init(value);
    const number = try c.takeVarint();
    if (!c.isEmpty()) return error.BadParameterLength;
    return number;
}

fn takeStreamCount(value: []const u8) DecodeError!u64 {
    const count = try takeInteger(value);
    if (count > max_stream_count) return error.StreamCountTooLarge;
    return count;
}

fn takeConnectionId(value: []const u8) DecodeError!packet.ConnectionId {
    return packet.ConnectionId.init(value) catch error.BadParameterLength;
}

/// Reads a Preferred Address value. RFC 9000 section 18.2.
fn decodePreferredAddress(value: []const u8) DecodeError!PreferredAddress {
    var c: Cursor = .init(value);
    const ipv4 = (try c.takeArray(4)).*;
    const ipv4_port = std.mem.readInt(u16, try c.takeArray(2), .big);
    const ipv6 = (try c.takeArray(16)).*;
    const ipv6_port = std.mem.readInt(u16, try c.takeArray(2), .big);

    // The length is one byte, so a peer can claim 255. Section 17.2 caps
    // it at 20 in this version.
    const cid_len = try c.takeByte();
    if (cid_len > packet.max_connection_id_len) return error.BadParameterLength;
    const connection_id = try takeConnectionId(try c.take(cid_len));
    const token = (try c.takeArray(stateless_reset_token_len)).*;

    // Nothing may follow the structure. A trailing byte is a value this
    // build and the peer would read differently.
    if (!c.isEmpty()) return error.BadParameterLength;

    return .{
        .ipv4 = ipv4,
        .ipv4_port = ipv4_port,
        .ipv6 = ipv6,
        .ipv6_port = ipv6_port,
        .connection_id = connection_id,
        .stateless_reset_token = token,
    };
}

/// Why a set of transport parameters could not be written.
pub const EncodeError = varint.EncodeError || std.Io.Writer.Error;

/// Writes `p` onto a stream.
///
/// **Only what differs from the default is written.** RFC 9000 section
/// 18.2 gives every absent parameter a default, so writing a default
/// value costs bytes in the first flight and says nothing. The three that
/// are always written are the ones with no useful default at all.
///
/// A value this build cannot say is an assert. A caller reaching here
/// with a stream count above 2^60 built something QUIC has no encoding
/// for.
pub fn encode(p: Parameters, w: *std.Io.Writer) EncodeError!void {
    std.debug.assert(p.ack_delay_exponent <= max_ack_delay_exponent);
    std.debug.assert(p.max_ack_delay < max_ack_delay_limit);
    std.debug.assert(p.initial_max_streams_bidi <= max_stream_count);
    std.debug.assert(p.initial_max_streams_uni <= max_stream_count);
    std.debug.assert(p.active_connection_id_limit >= default_active_connection_id_limit);
    std.debug.assert(p.max_udp_payload_size >= min_max_udp_payload_size);

    if (p.original_destination_connection_id) |cid| {
        try writeBytes(w, .original_destination_connection_id, cid.slice());
    }
    try writeIntegerUnlessDefault(w, .max_idle_timeout, p.max_idle_timeout, 0);
    if (p.stateless_reset_token) |token| {
        try writeBytes(w, .stateless_reset_token, &token);
    }
    try writeIntegerUnlessDefault(
        w,
        .max_udp_payload_size,
        p.max_udp_payload_size,
        default_max_udp_payload_size,
    );
    try writeIntegerUnlessDefault(w, .initial_max_data, p.initial_max_data, 0);
    try writeIntegerUnlessDefault(
        w,
        .initial_max_stream_data_bidi_local,
        p.initial_max_stream_data_bidi_local,
        0,
    );
    try writeIntegerUnlessDefault(
        w,
        .initial_max_stream_data_bidi_remote,
        p.initial_max_stream_data_bidi_remote,
        0,
    );
    try writeIntegerUnlessDefault(w, .initial_max_stream_data_uni, p.initial_max_stream_data_uni, 0);
    try writeIntegerUnlessDefault(w, .initial_max_streams_bidi, p.initial_max_streams_bidi, 0);
    try writeIntegerUnlessDefault(w, .initial_max_streams_uni, p.initial_max_streams_uni, 0);
    try writeIntegerUnlessDefault(
        w,
        .ack_delay_exponent,
        p.ack_delay_exponent,
        default_ack_delay_exponent,
    );
    try writeIntegerUnlessDefault(w, .max_ack_delay, p.max_ack_delay, default_max_ack_delay);
    if (p.disable_active_migration) try writeBytes(w, .disable_active_migration, &.{});
    if (p.preferred_address) |address| try writePreferredAddress(w, address);
    try writeIntegerUnlessDefault(
        w,
        .active_connection_id_limit,
        p.active_connection_id_limit,
        default_active_connection_id_limit,
    );
    if (p.initial_source_connection_id) |cid| {
        try writeBytes(w, .initial_source_connection_id, cid.slice());
    }
    if (p.retry_source_connection_id) |cid| {
        try writeBytes(w, .retry_source_connection_id, cid.slice());
    }
}

fn writeIntegerUnlessDefault(
    w: *std.Io.Writer,
    id: Id,
    value: u64,
    default: u64,
) EncodeError!void {
    if (value == default) return;
    try varint.write(w, @intFromEnum(id));
    try varint.write(w, try varint.encodedLen(value));
    try varint.write(w, value);
}

fn writeBytes(w: *std.Io.Writer, id: Id, value: []const u8) EncodeError!void {
    try varint.write(w, @intFromEnum(id));
    try varint.write(w, value.len);
    try w.writeAll(value);
}

fn writePreferredAddress(w: *std.Io.Writer, address: PreferredAddress) EncodeError!void {
    std.debug.assert(address.connection_id.len <= packet.max_connection_id_len);
    try varint.write(w, @intFromEnum(Id.preferred_address));
    try varint.write(w, PreferredAddress.fixed_len + address.connection_id.len);
    try w.writeAll(&address.ipv4);
    try w.writeInt(u16, address.ipv4_port, .big);
    try w.writeAll(&address.ipv6);
    try w.writeInt(u16, address.ipv6_port, .big);
    try w.writeByte(address.connection_id.len);
    try w.writeAll(address.connection_id.slice());
    try w.writeAll(&address.stateless_reset_token);
}

const testing = std.testing;

test "an empty extension gives every default of RFC 9000 section 18.2" {
    // **The five parameters whose default is not zero.** A caller reads
    // one value and never asks whether the field arrived.
    const p = try decode(&.{});
    try testing.expectEqual(@as(u64, 65527), p.max_udp_payload_size);
    try testing.expectEqual(@as(u64, 3), p.ack_delay_exponent);
    try testing.expectEqual(@as(u64, 25), p.max_ack_delay);
    try testing.expectEqual(@as(u64, 2), p.active_connection_id_limit);
    try testing.expect(!p.disable_active_migration);

    // And the ones whose default is zero or absent.
    try testing.expectEqual(@as(u64, 0), p.max_idle_timeout);
    try testing.expectEqual(@as(u64, 0), p.initial_max_data);
    try testing.expectEqual(@as(u64, 0), p.initial_max_streams_bidi);
    try testing.expectEqual(@as(?[16]u8, null), p.stateless_reset_token);
    try testing.expect(p.preferred_address == null);
    try testing.expect(p.initial_source_connection_id == null);
}

test "a client's first flight round trips through its own bytes" {
    // The shape a client sends: flow control, stream limits, an idle
    // timeout, and the source connection id it put in its first packet.
    const cid = try packet.ConnectionId.init(&.{ 0xde, 0xad, 0xbe, 0xef });
    const sent: Parameters = .{
        .max_idle_timeout = 30_000,
        .initial_max_data = 1_048_576,
        .initial_max_stream_data_bidi_local = 262_144,
        .initial_max_stream_data_bidi_remote = 262_144,
        .initial_max_stream_data_uni = 262_144,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 100,
        .active_connection_id_limit = 4,
        .initial_source_connection_id = cid,
        .disable_active_migration = true,
    };

    var buffer: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buffer);
    try encode(sent, &w);
    const read = try decode(w.buffered());
    try testing.expectEqualDeep(sent, read);
}

test "a server's first flight round trips, preferred address and all" {
    const p: Parameters = .{
        .original_destination_connection_id = try packet.ConnectionId.init(&.{ 1, 2, 3, 4, 5, 6, 7, 8 }),
        .initial_source_connection_id = try packet.ConnectionId.init(&.{ 9, 10 }),
        .retry_source_connection_id = try packet.ConnectionId.init(&.{11}),
        .stateless_reset_token = @splat(0xab),
        .max_udp_payload_size = 1452,
        .initial_max_data = 1 << 20,
        .ack_delay_exponent = 10,
        .max_ack_delay = 100,
        .preferred_address = .{
            .ipv4 = .{ 192, 0, 2, 1 },
            .ipv4_port = 443,
            .ipv6 = @splat(0),
            .ipv6_port = 0,
            .connection_id = try packet.ConnectionId.init(&.{ 0xaa, 0xbb }),
            .stateless_reset_token = @splat(0xcd),
        },
    };

    var buffer: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buffer);
    try encode(p, &w);
    const read = try decode(w.buffered());
    try testing.expectEqualDeep(p, read);

    try testing.expect(read.preferred_address.?.hasIpv4());
    try testing.expect(!read.preferred_address.?.hasIpv6());
    try testing.expectEqual(@as(u16, 443), read.preferred_address.?.ipv4_port);
}

test "a default value is left out of the encoding" {
    // Writing a default costs bytes in the first flight and says nothing.
    var buffer: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buffer);
    try encode(.{}, &w);
    try testing.expectEqual(@as(usize, 0), w.buffered().len);

    // One parameter away from the defaults writes one triple: the
    // identifier, the length, and the value.
    var second: std.Io.Writer = .fixed(&buffer);
    try encode(.{ .initial_max_data = 5 }, &second);
    try testing.expectEqualSlices(u8, &.{ 0x04, 0x01, 0x05 }, second.buffered());
}

test "an identifier this build does not know is stepped over" {
    // RFC 9000 section 18 requires that, and section 18.1 sets aside
    // `31 * N + 27` to make sure implementations really do it.
    const bytes = [_]u8{
        // Reserved identifier 27, with three bytes of anything.
        0x1b, 0x03, 0xaa, 0xbb, 0xcc,
        // initial_max_data of 5.
        0x04, 0x01, 0x05,
        // Reserved identifier 58, with no value.
        0x40, 0x3a,
        0x00,
    };
    const p = try decode(&bytes);
    try testing.expectEqual(@as(u64, 5), p.initial_max_data);

    try testing.expect((@as(Id, @enumFromInt(27))).isReserved());
    try testing.expect((@as(Id, @enumFromInt(58))).isReserved());
    try testing.expect(!(@as(Id, @enumFromInt(0x04))).isReserved());
}

test "one identifier twice is refused" {
    // RFC 9000 section 18 gives each parameter one appearance. Two values
    // for one limit is a packet this build and the peer read differently.
    const bytes = [_]u8{ 0x04, 0x01, 0x05, 0x04, 0x01, 0x06 };
    try testing.expectError(error.DuplicateParameter, decode(&bytes));

    // An unknown identifier twice is fine, because neither is read.
    const unknown = [_]u8{ 0x1b, 0x00, 0x1b, 0x00 };
    _ = try decode(&unknown);
}

test "a length past the end of the extension is refused" {
    // **The bound this file argues for.** The peer writes 2^62 as a
    // parameter length and sends nothing after it.
    const huge = [_]u8{ 0x04, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    try testing.expectError(error.Truncated, decode(&huge));
    // And a plain one that names four bytes with two present.
    try testing.expectError(error.Truncated, decode(&.{ 0x04, 0x04, 0x01, 0x02 }));
    // A triple that stops after the identifier.
    try testing.expectError(error.Truncated, decode(&.{0x04}));
}

test "each bound of RFC 9000 section 18.2 refuses the value past it" {
    // max_udp_payload_size below 1200 makes the handshake impossible.
    try testing.expectError(
        error.UdpPayloadSizeTooSmall,
        decode(&.{ 0x03, 0x02, 0x44, 0xaf }),
    );
    // 1200 itself is legal.
    try testing.expectEqual(
        @as(u64, 1200),
        (try decode(&.{ 0x03, 0x02, 0x44, 0xb0 })).max_udp_payload_size,
    );

    // ack_delay_exponent above 20.
    try testing.expectError(error.AckDelayExponentTooLarge, decode(&.{ 0x0a, 0x01, 21 }));
    try testing.expectEqual(@as(u64, 20), (try decode(&.{ 0x0a, 0x01, 20 })).ack_delay_exponent);

    // max_ack_delay at or above 2^14 milliseconds.
    try testing.expectError(
        error.AckDelayTooLarge,
        decode(&.{ 0x0b, 0x04, 0x80, 0x00, 0x40, 0x00 }),
    );
    try testing.expectEqual(
        @as(u64, 16383),
        (try decode(&.{ 0x0b, 0x02, 0x7f, 0xff })).max_ack_delay,
    );

    // active_connection_id_limit below 2 leaves no room to migrate.
    try testing.expectError(error.ConnectionIdLimitTooSmall, decode(&.{ 0x0e, 0x01, 0x01 }));
    try testing.expectError(error.ConnectionIdLimitTooSmall, decode(&.{ 0x0e, 0x01, 0x00 }));
    try testing.expectEqual(
        @as(u64, 2),
        (try decode(&.{ 0x0e, 0x01, 0x02 })).active_connection_id_limit,
    );

    // A stream count above 2^60 names a stream id with no encoding.
    try testing.expectError(
        error.StreamCountTooLarge,
        decode(&.{ 0x08, 0x08, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }),
    );
    try testing.expectEqual(
        max_stream_count,
        (try decode(&.{ 0x08, 0x08, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })).initial_max_streams_bidi,
    );
}

test "a fixed width value at the wrong width is refused" {
    // A reset token that is not 16 bytes.
    try testing.expectError(error.BadParameterLength, decode(&.{ 0x02, 0x02, 0xaa, 0xbb }));
    // disable_active_migration with bytes in it, which section 18.2 gives
    // no meaning to at all.
    try testing.expectError(error.BadParameterLength, decode(&.{ 0x0c, 0x01, 0x01 }));
    // A connection id above the 20 bytes of section 17.2.
    var long = [_]u8{ 0x0f, 21 } ++ ([_]u8{0xaa} ** 21);
    try testing.expectError(error.BadParameterLength, decode(&long));
    // An integer with a byte left over after its varint, where a peer
    // could hide a second number.
    try testing.expectError(error.BadParameterLength, decode(&.{ 0x04, 0x02, 0x05, 0x06 }));
}

test "a preferred address that does not fit its own structure is refused" {
    // The structure is 25 fixed bytes plus the connection id, so a value
    // shorter than that names no address.
    const short = [_]u8{ 0x0d, 0x04, 1, 2, 3, 4 };
    try testing.expectError(error.Truncated, decode(&short));

    // A connection id length of 21 is past the cap of section 17.2.
    var value: [1 + 1 + PreferredAddress.fixed_len + 21]u8 = @splat(0);
    value[0] = 0x0d;
    value[1] = PreferredAddress.fixed_len + 21;
    value[2 + 4 + 2 + 16 + 2] = 21;
    try testing.expectError(error.BadParameterLength, decode(&value));
}

test "the ack delay exponent is a shift the decode already bounded" {
    const p = try decode(&.{ 0x0a, 0x01, 20 });
    try testing.expectEqual(@as(u6, 20), p.ackDelayShift());
    const q: Parameters = .{};
    try testing.expectEqual(@as(u6, 3), q.ackDelayShift());
}
