//! QUIC packet headers, RFC 9000 section 17.
//!
//! This file owns the bytes in front of a packet payload: the first byte
//! and its flags, the version, the two connection ids, the token and the
//! length of a long header, and the packet number in both forms. It owns
//! nothing after the header. It decrypts no payload, it reads no frame,
//! and it keeps no connection state.
//!
//! ## The header is read in two passes, and this file is the first
//!
//! **Some of the first byte is encrypted.** RFC 9001 section 5.4 protects
//! the low four bits of a long header first byte and the low five bits of
//! a short header one, and the Packet Number field with them. So the
//! Packet Number Length is not readable until header protection is
//! removed, and header protection cannot be removed until the header is
//! parsed far enough to know where the packet number starts.
//!
//! `parseLong` and `parseShort` therefore stop **in front of** the packet
//! number and report `pn_offset`, which is exactly what
//! `header_protection.zig` needs. The caller removes protection, then
//! reads the packet number with `readPacketNumber` and decodes it with
//! `decodePacketNumber`. Nothing here ever trusts the protected bits.
//!
//! ## The version-invariant part comes first
//!
//! RFC 8999 fixes the first byte's high bit, the version, and the two
//! connection ids for every QUIC version there will ever be. Everything
//! after that belongs to version 1. `parseInvariant` reads the part that
//! is always true, so a datagram carrying a version this build does not
//! speak is still readable far enough to answer it. `parseLong` reads the
//! version 1 shape and refuses any other version by name.
//!
//! ## What is bounded here
//!
//! A connection id length is one byte, so a peer can claim 255. RFC 9000
//! section 17.2 caps it at 20 in this version, and `ConnectionId.init`
//! refuses anything longer. The Length and Token Length fields are
//! varints, and `Cursor` checks each against the bytes that arrived.
//! Nothing in this file allocates.

const std = @import("std");

const Cursor = @import("Cursor.zig");
const varint = @import("varint.zig");

/// The QUIC version numbers this build names. RFC 9000 section 15.
///
/// Non-exhaustive, because a datagram can carry any 32-bit number here
/// and a receiver has to read the invariant fields of it either way.
pub const Version = enum(u32) {
    /// A Version Negotiation packet, RFC 9000 section 17.2.1. This is not
    /// a version. It is the value that says the long header carries a
    /// list of versions instead of a packet.
    negotiation = 0x0000_0000,
    /// QUIC version 1, RFC 9000.
    v1 = 0x0000_0001,
    /// QUIC version 2, RFC 9369. Named so a reader can tell it apart from
    /// a random number. This package does not speak it.
    v2 = 0x6b33_43cf,
    _,

    /// True when this package can read the packet after the invariant
    /// fields.
    pub fn isSupported(self: Version) bool {
        return self == .v1;
    }

    /// True when the number matches the `0x?a?a?a?a` pattern RFC 9000
    /// section 15 reserves to force version negotiation.
    ///
    /// A peer sends one of these on purpose, so it is a value and never a
    /// fault.
    pub fn isReserved(self: Version) bool {
        return @intFromEnum(self) & 0x0f0f_0f0f == 0x0a0a_0a0a;
    }
};

/// The longest connection id QUIC version 1 allows. RFC 9000 section
/// 17.2.
pub const max_connection_id_len: usize = 20;

/// One connection id, held by value.
///
/// **By value and not by slice**, because a connection id outlives the
/// datagram it arrived in: a `NEW_CONNECTION_ID` frame hands over an id
/// the connection then uses for the rest of its life. A slice into a
/// datagram buffer would dangle the moment the buffer was reused.
pub const ConnectionId = struct {
    bytes: [max_connection_id_len]u8,
    len: u8,

    /// The zero-length connection id, which a peer that wants no routing
    /// label uses.
    pub const empty: ConnectionId = .{ .bytes = @splat(0), .len = 0 };

    /// Why a run of bytes is not a connection id.
    pub const Error = error{
        /// Longer than the 20 bytes RFC 9000 section 17.2 allows.
        ConnectionIdTooLong,
    };

    /// Copies `from` into a connection id.
    pub fn init(from: []const u8) Error!ConnectionId {
        if (from.len > max_connection_id_len) return error.ConnectionIdTooLong;
        var out: ConnectionId = .{ .bytes = @splat(0), .len = @intCast(from.len) };
        @memcpy(out.bytes[0..from.len], from);
        return out;
    }

    /// The bytes of the id.
    ///
    /// Takes a pointer, so the result points at the caller's own value
    /// and never at a temporary.
    pub fn slice(self: *const ConnectionId) []const u8 {
        return self.bytes[0..self.len];
    }

    /// True when both name the same id.
    pub fn eql(self: *const ConnectionId, other: *const ConnectionId) bool {
        return std.mem.eql(u8, self.slice(), other.slice());
    }
};

/// The high bit of the first byte. RFC 8999 section 5.
pub const header_form_bit: u8 = 0x80;

/// The second bit of the first byte. RFC 9000 section 17.2 requires it
/// set on every packet of version 1 but a Version Negotiation packet.
pub const fixed_bit: u8 = 0x40;

/// The two bits that carry the Packet Number Length, in both header
/// forms. RFC 9000 sections 17.2 and 17.3.
pub const packet_number_length_mask: u8 = 0x03;

/// The Reserved Bits of a long header. RFC 9000 section 17.2 says a
/// receiver must treat a packet with either set as a connection error of
/// type PROTOCOL_VIOLATION, **after** header protection is removed.
pub const long_reserved_mask: u8 = 0x0c;

/// The Reserved Bits of a short header. RFC 9000 section 17.3.1.
pub const short_reserved_mask: u8 = 0x18;

/// The Spin Bit of a short header. RFC 9000 section 17.4.
pub const spin_bit: u8 = 0x20;

/// The Key Phase bit of a short header. RFC 9001 section 6.
pub const key_phase_bit: u8 = 0x04;

/// Which of the two header shapes a first byte names.
pub const Form = enum { long, short };

/// The header shape `first_byte` names. RFC 8999 section 5.
pub fn form(first_byte: u8) Form {
    return if (first_byte & header_form_bit != 0) .long else .short;
}

/// The four long header packet types of QUIC version 1. RFC 9000 section
/// 17.2.
///
/// These numbers belong to version 1 alone. Version 2 renumbers them, so
/// a caller must know the version before it reads this.
pub const LongType = enum(u2) {
    initial = 0,
    zero_rtt = 1,
    handshake = 2,
    retry = 3,

    /// The name RFC 9000 gives the type.
    pub fn name(self: LongType) []const u8 {
        return switch (self) {
            .initial => "Initial",
            .zero_rtt => "0-RTT",
            .handshake => "Handshake",
            .retry => "Retry",
        };
    }
};

/// The long header type bits of a first byte, read as a version 1 type.
///
/// The caller must have checked the version first. Nothing in the two
/// bits says which version numbering they belong to.
pub fn longType(first_byte: u8) LongType {
    return @enumFromInt(@as(u2, @truncate(first_byte >> 4)));
}

/// How many bytes the Packet Number field takes. RFC 9000 section 17.1.
///
/// **Only call this after header protection is removed.** The two bits
/// are protected, so the answer is meaningless before that.
pub fn packetNumberLen(first_byte: u8) u3 {
    return @as(u3, @intCast(first_byte & packet_number_length_mask)) + 1;
}

/// The longest Packet Number field. RFC 9000 section 17.1.
pub const max_packet_number_len: usize = 4;

/// The largest packet number QUIC has. RFC 9000 section 12.3.
pub const max_packet_number: u64 = (1 << 62) - 1;

/// Why a datagram is not a packet header.
pub const ParseError = error{
    /// A field ran past the end of the datagram.
    Truncated,
    /// The first byte named the other header form. A caller that asked
    /// for a long header got a short one, or the other way round.
    WrongHeaderForm,
    /// A connection id longer than the 20 bytes of RFC 9000 section 17.2.
    ConnectionIdTooLong,
    /// The Fixed Bit of RFC 9000 section 17.2 was zero. Such a packet is
    /// not a version 1 packet and must be discarded.
    FixedBitNotSet,
    /// The long header carried a version this package does not speak. The
    /// invariant fields are still readable with `parseInvariant`.
    UnsupportedVersion,
    /// The Length field of a long header named more bytes than arrived,
    /// or fewer than one packet number.
    BadLength,
    /// A Version Negotiation packet whose version list is empty or is not
    /// a whole number of versions.
    BadVersionList,
    /// A Retry packet with no room for its 16-byte integrity tag.
    BadRetry,
    /// A Version Negotiation packet was asked for a version it does not
    /// list.
    NoSuchVersion,
};

/// The part of a long header that every QUIC version shares. RFC 8999
/// section 5.1.
///
/// A receiver can read this much of a datagram carrying any version at
/// all, which is what it needs to answer with a Version Negotiation
/// packet.
pub const Invariant = struct {
    first_byte: u8,
    version: Version,
    dcid: ConnectionId,
    scid: ConnectionId,
    /// The bytes after the source connection id. Points into the input.
    rest: []const u8,
    /// How many bytes the invariant part took, so `rest` starts here.
    header_len: usize,
};

/// Reads the version-invariant fields of a long header. RFC 8999.
///
/// This refuses nothing about the version, because a receiver must read
/// these fields whatever the version says. It does refuse a connection id
/// longer than 20 bytes, which RFC 8999 allows up to 255 and RFC 9000
/// section 17.2 caps: this package speaks version 1 and holds a
/// connection id by value, so a longer one has nowhere to go.
pub fn parseInvariant(datagram: []const u8) ParseError!Invariant {
    var c: Cursor = .init(datagram);
    const first_byte = try c.takeByte();
    if (form(first_byte) != .long) return error.WrongHeaderForm;

    const version: Version = @enumFromInt(std.mem.readInt(u32, try c.takeArray(4), .big));

    const dcid_len = try c.takeByte();
    const dcid = try ConnectionId.init(try c.take(dcid_len));
    const scid_len = try c.takeByte();
    const scid = try ConnectionId.init(try c.take(scid_len));

    return .{
        .first_byte = first_byte,
        .version = version,
        .dcid = dcid,
        .scid = scid,
        .rest = c.rest(),
        .header_len = c.at,
    };
}

/// One long header of QUIC version 1, parsed up to the Packet Number
/// field. RFC 9000 section 17.2.
pub const Long = struct {
    /// Still carrying its protected low bits, for every type but Retry.
    first_byte: u8,
    version: Version,
    dcid: ConnectionId,
    scid: ConnectionId,
    body: Body,
    /// Where the Packet Number field starts in the datagram.
    ///
    /// This is what header protection samples from. Zero for a Retry
    /// packet, which carries no packet number at all.
    pn_offset: usize,
    /// The packet number and payload together, still protected. Empty for
    /// a Retry packet.
    ///
    /// **`parseLong` cut this slice out of the datagram it read**, and
    /// `takeCheckedLength` had already bounded the Length field by the
    /// bytes that arrived. Nothing re-slices a caller's buffer here, so
    /// there is no invariant left for a caller to break.
    protected: []const u8,
    /// How many bytes of the datagram this packet takes, the payload
    /// included, as `parseLong` measured it.
    whole_len: usize,

    /// The fields after the two connection ids, by type.
    pub const Body = union(LongType) {
        initial: Initial,
        zero_rtt: Protected,
        handshake: Protected,
        retry: Retry,
    };

    /// An Initial packet. RFC 9000 section 17.2.2.
    pub const Initial = struct {
        /// The address validation token. Empty when the client has none.
        /// Points into the datagram.
        token: []const u8,
        /// The Length field: the packet number and the payload together.
        /// Already checked against the bytes that arrived.
        length: u64,
    };

    /// A 0-RTT or Handshake packet. RFC 9000 sections 17.2.3 and 17.2.4.
    pub const Protected = struct {
        /// The Length field: the packet number and the payload together.
        /// Already checked against the bytes that arrived.
        length: u64,
    };

    /// A Retry packet. RFC 9000 section 17.2.5.
    pub const Retry = struct {
        /// Points into the datagram.
        token: []const u8,
        /// The last 16 bytes of the packet. RFC 9001 section 5.8 says how
        /// to check it, and `initial.retryIntegrityTag` is that check.
        integrity_tag: *const [retry_integrity_tag_len]u8,
    };

    /// The packet number and payload together, still protected. Empty for
    /// a Retry packet.
    pub fn protectedBody(self: Long) []const u8 {
        return self.protected;
    }

    /// How many bytes of the datagram this packet takes, the payload
    /// included. A datagram can hold several packets one after another.
    ///
    /// **The length is bounded by `datagram` and never trusted past
    /// it.** `parseLong` measured this packet against the datagram it
    /// read, so a caller that passes that same datagram gets the whole
    /// packet. A caller that passes a shorter one gets the bytes that
    /// exist, which ends the coalescing walk rather than reads past the
    /// end.
    pub fn packetLen(self: Long, datagram: []const u8) usize {
        return @min(self.whole_len, datagram.len);
    }
};

/// The Retry Integrity Tag of RFC 9000 section 17.2.5, in bytes.
pub const retry_integrity_tag_len: usize = 16;

/// Reads one QUIC version 1 long header, up to the Packet Number field.
///
/// The Packet Number Length bits of `first_byte` are still protected, so
/// this reports `pn_offset` and reads no packet number. See the module
/// comment.
///
/// **The Length field is checked against the bytes that arrived**, and
/// against the one byte a packet number needs at least. A packet whose
/// Length names more than the datagram holds is `error.BadLength` and
/// nothing of it is returned.
pub fn parseLong(datagram: []const u8) ParseError!Long {
    const inv = try parseInvariant(datagram);
    if (inv.first_byte & fixed_bit == 0) return error.FixedBitNotSet;
    if (!inv.version.isSupported()) return error.UnsupportedVersion;

    var c: Cursor = .init(inv.rest);
    const long_type = longType(inv.first_byte);

    const body: Long.Body = switch (long_type) {
        .initial => body: {
            const token_len = try c.takeVarint();
            const token = try c.takeVarintLength(token_len);
            break :body .{ .initial = .{
                .token = token,
                .length = try takeCheckedLength(&c),
            } };
        },
        .zero_rtt => .{ .zero_rtt = .{ .length = try takeCheckedLength(&c) } },
        .handshake => .{ .handshake = .{ .length = try takeCheckedLength(&c) } },
        .retry => body: {
            // A Retry packet has no Length field. Everything to the last
            // 16 bytes is the token, and those 16 are the tag.
            if (c.remaining() < retry_integrity_tag_len) return error.BadRetry;
            const token = try c.take(c.remaining() - retry_integrity_tag_len);
            break :body .{ .retry = .{
                .token = token,
                .integrity_tag = try c.takeArray(retry_integrity_tag_len),
            } };
        },
    };

    const pn_offset: usize = if (long_type == .retry) 0 else inv.header_len + c.at;
    // **The two slices are cut here, against the datagram this function
    // read.** `takeCheckedLength` already refused a Length past the bytes
    // that arrived, so both cuts are inside `datagram` and no later caller
    // has to hold that invariant in prose.
    const body_len: usize = switch (body) {
        .retry => 0,
        .initial => |b| @intCast(b.length),
        .zero_rtt, .handshake => |b| @intCast(b.length),
    };
    std.debug.assert(pn_offset + body_len <= datagram.len);

    return .{
        .first_byte = inv.first_byte,
        .version = inv.version,
        .dcid = inv.dcid,
        .scid = inv.scid,
        .body = body,
        .pn_offset = pn_offset,
        .protected = if (long_type == .retry) &.{} else datagram[pn_offset..][0..body_len],
        .whole_len = if (long_type == .retry) datagram.len else pn_offset + body_len,
    };
}

/// Reads the Length field and checks it against the bytes that arrived.
///
/// **This is the bound on the one number that says how far this packet
/// reaches.** A datagram can hold several packets, so the Length is what
/// tells a reader where the next one starts. A Length past the end of the
/// datagram would make the reader parse whatever memory followed.
fn takeCheckedLength(c: *Cursor) ParseError!u64 {
    const length = try c.takeVarint();
    // A packet number is at least one byte, so a Length of zero names no
    // packet at all.
    if (length == 0) return error.BadLength;
    if (length > c.remaining()) return error.BadLength;
    return length;
}

/// One short header, parsed up to the Packet Number field. RFC 9000
/// section 17.3.1.
pub const Short = struct {
    /// Still carrying its protected low five bits.
    first_byte: u8,
    dcid: ConnectionId,
    /// Where the Packet Number field starts in the datagram.
    pn_offset: usize,
};

/// Reads one short header, up to the Packet Number field.
///
/// **`dcid_len` is this endpoint's own choice and never the peer's.** A
/// short header carries no connection id length: the receiver knows how
/// long the ids it handed out are. So this takes the length as a
/// parameter, and a caller that passed a peer-supplied number would be
/// making a bug of its own. The assert says so.
pub fn parseShort(datagram: []const u8, dcid_len: usize) ParseError!Short {
    std.debug.assert(dcid_len <= max_connection_id_len);

    var c: Cursor = .init(datagram);
    const first_byte = try c.takeByte();
    if (form(first_byte) != .short) return error.WrongHeaderForm;
    if (first_byte & fixed_bit == 0) return error.FixedBitNotSet;

    const dcid = try ConnectionId.init(try c.take(dcid_len));
    // A packet number needs at least one byte after the connection id.
    if (c.isEmpty()) return error.Truncated;

    return .{ .first_byte = first_byte, .dcid = dcid, .pn_offset = c.at };
}

/// A Version Negotiation packet. RFC 9000 section 17.2.1.
///
/// It carries no version of its own and no packet number, so it is never
/// acknowledged and never protected.
pub const VersionNegotiation = struct {
    dcid: ConnectionId,
    scid: ConnectionId,
    /// The Supported Version list, still as bytes. Points into the
    /// datagram. Use `count` and `get` to read it.
    versions: []const u8,

    /// How many versions the server listed.
    pub fn count(self: VersionNegotiation) usize {
        return self.versions.len / 4;
    }

    /// The version at `index`, or `error.NoSuchVersion` when the list is
    /// shorter than that.
    ///
    /// **This is public and the bound is a returned error.** An assert is
    /// compiled out of a release build, and the list length came off the
    /// wire, so a caller that works its index out from a peer number must
    /// meet a bound that is still there.
    pub fn get(self: VersionNegotiation, index: usize) ParseError!Version {
        if (index >= self.count()) return error.NoSuchVersion;
        return @enumFromInt(std.mem.readInt(u32, self.versions[index * 4 ..][0..4], .big));
    }

    /// True when the server offered `wanted`.
    pub fn has(self: VersionNegotiation, wanted: Version) bool {
        var i: usize = 0;
        while (i < self.count()) : (i += 1) {
            const one = self.get(i) catch return false;
            if (one == wanted) return true;
        }
        return false;
    }
};

/// Reads a Version Negotiation packet.
///
/// **The list must be a whole number of versions and must not be
/// empty.** A trailing part of a version is a malformed packet, and an
/// empty list offers nothing, so both are refused rather than read as a
/// server that supports nothing.
pub fn parseVersionNegotiation(datagram: []const u8) ParseError!VersionNegotiation {
    const inv = try parseInvariant(datagram);
    if (inv.version != .negotiation) return error.UnsupportedVersion;
    if (inv.rest.len == 0 or inv.rest.len % 4 != 0) return error.BadVersionList;
    return .{ .dcid = inv.dcid, .scid = inv.scid, .versions = inv.rest };
}

/// Reads the Packet Number field, once header protection is removed.
///
/// The result is the truncated number. `decodePacketNumber` turns it into
/// the full one.
pub fn readPacketNumber(bytes: []const u8, len: u3) ParseError!u32 {
    std.debug.assert(len >= 1 and len <= max_packet_number_len);
    if (bytes.len < len) return error.Truncated;
    var value: u32 = 0;
    for (bytes[0..len]) |byte| value = (value << 8) | byte;
    return value;
}

/// How many bytes the Packet Number field needs. RFC 9000 appendix A.2.
///
/// `largest_acked` is the largest packet number the peer has
/// acknowledged in this packet number space, or null when it has
/// acknowledged none. RFC 9000 section 17.1 says the full number goes on
/// the wire until the first acknowledgment arrives, and the null case is
/// what makes that happen.
///
/// The appendix writes `num_bytes = ceil((log2(num_unacked) + 1) / 8)`.
/// The same answer with no floating point is the smallest `k` where
/// `2^(8k)` is at or above `2 * num_unacked`, which is the rule section
/// 17.1 states in words: represent more than twice the outstanding range.
pub fn encodedPacketNumberLen(full_pn: u64, largest_acked: ?u64) u3 {
    std.debug.assert(full_pn <= max_packet_number);

    const num_unacked: u128 = if (largest_acked) |acked| unacked: {
        std.debug.assert(acked <= full_pn);
        break :unacked @as(u128, full_pn) - @as(u128, acked);
    } else @as(u128, full_pn) + 1;

    const twice = num_unacked * 2;
    var len: u3 = 1;
    while (len < max_packet_number_len) : (len += 1) {
        if (@as(u128, 1) << (8 * @as(u7, len)) >= twice) return len;
    }
    return @intCast(max_packet_number_len);
}

/// Writes the low `len` bytes of `full_pn` into `out`, and returns them.
pub fn encodePacketNumber(out: *[max_packet_number_len]u8, full_pn: u64, len: u3) []u8 {
    std.debug.assert(len >= 1 and len <= max_packet_number_len);
    std.debug.assert(full_pn <= max_packet_number);
    var i: usize = 0;
    while (i < len) : (i += 1) {
        const shift: u6 = @intCast(8 * (@as(usize, len) - 1 - i));
        out[i] = @truncate(full_pn >> shift);
    }
    return out[0..len];
}

/// Rebuilds a full packet number from a truncated one. RFC 9000 appendix
/// A.3.
///
/// `largest_pn` is the largest packet number this endpoint has already
/// authenticated in this packet number space. `pn_nbits` is 8, 16, 24, or
/// 32.
///
/// **This is the algorithm of appendix A.3, written as it stands there.**
/// The two comparisons need a value that can go below zero, and the
/// packet number space is 62 bits, so the arithmetic runs at 128 bits
/// where nothing wraps. A version of this with `u64` subtraction reads
/// almost right and picks the wrong window at the edges.
///
/// This cannot fail. Every 32-bit truncated value belongs to some full
/// number, so there is no malformed input here. The bits reached this
/// function through `packetNumberLen`, which cannot report a bad width.
///
/// **The result is bounded by `max_packet_number`.** Appendix A.3 works
/// in a space that has no top, so with `largest_pn` near 2^62 - 1 the
/// candidate can climb past the largest number QUIC has. No packet
/// carries such a number, so the value is held at the bound rather than
/// passed on: a number that is not the peer's own fails the AEAD open,
/// and the packet is discarded before any acknowledgment records it.
/// Without the bound the number would reach `AckRanges`, where writing it
/// as a varint has no answer.
pub fn decodePacketNumber(largest_pn: u64, truncated_pn: u32, pn_nbits: u6) u64 {
    std.debug.assert(pn_nbits == 8 or pn_nbits == 16 or pn_nbits == 24 or pn_nbits == 32);
    std.debug.assert(largest_pn <= max_packet_number);

    const expected: i128 = @as(i128, largest_pn) + 1;
    const win: i128 = @as(i128, 1) << pn_nbits;
    const hwin: i128 = @divExact(win, 2);
    const mask: i128 = win - 1;

    const candidate: i128 = (expected & ~mask) | @as(i128, truncated_pn);
    const full: i128 = full: {
        if (candidate <= expected - hwin and candidate < (@as(i128, 1) << 62) - win) {
            break :full candidate + win;
        }
        if (candidate > expected + hwin and candidate >= win) {
            break :full candidate - win;
        }
        break :full candidate;
    };
    if (full > max_packet_number) return max_packet_number;
    return @intCast(full);
}

const testing = std.testing;

test "the two packet number encodings of RFC 9000 appendix A.2" {
    // **The appendix's own worked examples.** An endpoint acknowledged
    // 0xabe8b3 and sends 0xac5c02, so 29 519 numbers are outstanding and
    // 16 bits are needed for twice that range.
    try testing.expectEqual(@as(u3, 2), encodedPacketNumberLen(0xac5c02, 0xabe8b3));
    var out: [max_packet_number_len]u8 = undefined;
    try testing.expectEqualSlices(
        u8,
        &.{ 0x5c, 0x02 },
        encodePacketNumber(&out, 0xac5c02, 2),
    );

    // In the same state, 0xace8fe needs 24 bits, because twice the range
    // is 131 222 and 18 bits at least are needed.
    try testing.expectEqual(@as(u3, 3), encodedPacketNumberLen(0xace8fe, 0xabe8b3));
    try testing.expectEqualSlices(
        u8,
        &.{ 0xac, 0xe8, 0xfe },
        encodePacketNumber(&out, 0xace8fe, 3),
    );
}

test "the packet number decoding of RFC 9000 appendix A.3" {
    // **The appendix's own worked example.** The highest authenticated
    // number was 0xa82f30ea, and a 16-bit field holding 0x9b32 is
    // 0xa82f9b32 and not 0xa82e9b32.
    try testing.expectEqual(
        @as(u64, 0xa82f9b32),
        decodePacketNumber(0xa82f30ea, 0x9b32, 16),
    );
}

test "a truncated number picks the candidate nearest the next expected one" {
    // The window is what makes this hard. With 8 bits and a largest of
    // 0xff, the next expected is 0x100, so 0x00 is 0x100 and not 0x00.
    try testing.expectEqual(@as(u64, 0x100), decodePacketNumber(0xff, 0x00, 8));
    try testing.expectEqual(@as(u64, 0x101), decodePacketNumber(0xff, 0x01, 8));

    // **The branch that steps the candidate down a window.** The largest
    // seen is 0x100, so the next expected is 0x101. A field holding 0xff
    // is 0xff, a packet that arrived late, and not 0x1ff.
    try testing.expectEqual(@as(u64, 0xff), decodePacketNumber(0x100, 0xff, 8));

    // **The branch that steps it up a window.** The largest seen is
    // 0x17f, so the next expected is 0x180 and the window runs from
    // 0x100 to 0x1ff. A field holding 0x00 is 0x200 and not 0x100,
    // because 0x200 is the nearer of the two.
    try testing.expectEqual(@as(u64, 0x200), decodePacketNumber(0x17f, 0x00, 8));

    // The half window is inside the range, so a candidate exactly there
    // is taken as it stands.
    try testing.expectEqual(@as(u64, 0x180), decodePacketNumber(0xff, 0x80, 8));
    try testing.expectEqual(@as(u64, 0x17f), decodePacketNumber(0xff, 0x7f, 8));
}

test "decoding a packet number at the start of a space returns the number itself" {
    // Nothing has been received, so largest_pn is 0 and the next expected
    // is 1. A field holding 1 is 1.
    try testing.expectEqual(@as(u64, 1), decodePacketNumber(0, 1, 8));
    try testing.expectEqual(@as(u64, 0), decodePacketNumber(0, 0, 8));
    try testing.expectEqual(@as(u64, 2), decodePacketNumber(1, 2, 32));
}

test "a packet number near the top of the space never climbs past the bound" {
    // **Appendix A.3 works in a space with no top.** With `largest_pn`
    // at the last number QUIC has, the candidate can pass 2^62 - 1, and
    // that value would reach `AckRanges`, where a varint has no room for
    // it. The bound holds the result inside the space instead.
    var width: u6 = 8;
    while (width <= 32) : (width += 8) {
        var step: u32 = 0;
        while (step < 8) : (step += 1) {
            const near = decodePacketNumber(max_packet_number, step, width);
            try testing.expect(near <= max_packet_number);
            const one_below = decodePacketNumber(max_packet_number - 1, step, width);
            try testing.expect(one_below <= max_packet_number);
        }
    }
    // The largest truncated field at the largest width, which is the
    // worst case of all.
    try testing.expect(decodePacketNumber(max_packet_number, std.math.maxInt(u32), 32) <= max_packet_number);
}

test "every truncation width rebuilds the number that was encoded" {
    // A walk over the four widths, each side of the window. The full
    // number goes in, the low bytes come out, and the decode must find
    // the same number again.
    const widths = [_]u3{ 1, 2, 3, 4 };
    for (widths) |width| {
        const nbits: u6 = @as(u6, width) * 8;
        const half: u64 = @as(u64, 1) << (nbits - 1);
        var step: u64 = 0;
        while (step < 16) : (step += 1) {
            const full: u64 = 0x1234_5600 + step * (half / 8 + 1);
            var out: [max_packet_number_len]u8 = undefined;
            const written = encodePacketNumber(&out, full, width);
            const truncated = try readPacketNumber(written, width);
            // The receiver has seen everything up to the one before.
            try testing.expectEqual(full, decodePacketNumber(full - 1, truncated, nbits));
        }
    }
}

test "with nothing acknowledged the whole packet number goes on the wire" {
    // RFC 9000 section 17.1: before an acknowledgment arrives the full
    // number must be sent, and the null case is what makes that so.
    try testing.expectEqual(@as(u3, 1), encodedPacketNumberLen(0, null));
    try testing.expectEqual(@as(u3, 1), encodedPacketNumberLen(127, null));
    try testing.expectEqual(@as(u3, 2), encodedPacketNumberLen(128, null));
    try testing.expectEqual(@as(u3, 4), encodedPacketNumberLen(1 << 30, null));
    // The field is four bytes at most, whatever the number is.
    try testing.expectEqual(@as(u3, 4), encodedPacketNumberLen(max_packet_number, null));
}

test "the client Initial header of RFC 9001 appendix A.2 parses field for field" {
    // The unprotected header the appendix names, byte for byte:
    // c3 00000001 08 8394c8f03e515708 00 00 449e 00000002
    const header = [_]u8{
        0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0,
        0x3e, 0x51, 0x57, 0x08, 0x00, 0x00, 0x44, 0x9e, 0x00, 0x00,
        0x00, 0x02,
    };
    // The Length field says 1182, so the datagram must hold that much
    // after the header. The bytes are not the point here, the parse is.
    var datagram: [18 + 1182]u8 = @splat(0);
    @memcpy(datagram[0..header.len], &header);

    const p = try parseLong(&datagram);
    try testing.expectEqual(Version.v1, p.version);
    try testing.expectEqualSlices(
        u8,
        &.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 },
        p.dcid.slice(),
    );
    try testing.expectEqual(@as(u8, 0), p.scid.len);
    try testing.expectEqual(LongType.initial, @as(LongType, p.body));
    try testing.expectEqual(@as(usize, 0), p.body.initial.token.len);
    try testing.expectEqual(@as(u64, 1182), p.body.initial.length);
    // 7 fixed bytes, 8 of connection id, 1 token length, 2 of Length.
    try testing.expectEqual(@as(usize, 18), p.pn_offset);
    // The first byte says a 4-byte packet number, and the number is 2.
    try testing.expectEqual(@as(u3, 4), packetNumberLen(p.first_byte));
    try testing.expectEqual(@as(u32, 2), try readPacketNumber(datagram[18..], 4));
    try testing.expectEqual(@as(usize, 1200), p.packetLen(&datagram));

    // **The body is the slice `parseLong` cut**, so nothing re-slices a
    // caller's buffer with a number that came from somewhere else.
    try testing.expectEqual(@as(usize, 1182), p.protectedBody().len);
    try testing.expectEqualSlices(u8, datagram[18..1200], p.protectedBody());

    // A caller that hands `packetLen` a shorter buffer gets the bytes
    // that exist, which ends a coalescing walk rather than names a length
    // past the end.
    try testing.expectEqual(@as(usize, 20), p.packetLen(datagram[0..20]));
    try testing.expectEqual(@as(usize, 0), p.packetLen(&.{}));
}

test "the server Initial header of RFC 9001 appendix A.3 parses field for field" {
    // c1 00000001 00 08 f067a5502a4262b5 00 4075 0001
    const header = [_]u8{
        0xc1, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5,
        0x50, 0x2a, 0x42, 0x62, 0xb5, 0x00, 0x40, 0x75, 0x00, 0x01,
    };
    var datagram: [18 + 117]u8 = @splat(0);
    @memcpy(datagram[0..header.len], &header);

    const p = try parseLong(&datagram);
    try testing.expectEqual(Version.v1, p.version);
    try testing.expectEqual(@as(u8, 0), p.dcid.len);
    try testing.expectEqualSlices(
        u8,
        &.{ 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5 },
        p.scid.slice(),
    );
    try testing.expectEqual(@as(u64, 117), p.body.initial.length);
    try testing.expectEqual(@as(usize, 18), p.pn_offset);
    try testing.expectEqual(@as(u3, 2), packetNumberLen(p.first_byte));
    try testing.expectEqual(@as(u32, 1), try readPacketNumber(datagram[18..], 2));
}

test "the Retry packet of RFC 9001 appendix A.4 splits into a token and a tag" {
    const retry = [_]u8{
        0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5,
        0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e,
        0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58,
        0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba,
    };
    const p = try parseLong(&retry);
    try testing.expectEqual(LongType.retry, @as(LongType, p.body));
    try testing.expectEqualStrings("token", p.body.retry.token);
    try testing.expectEqualSlices(
        u8,
        &.{ 0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba },
        p.body.retry.integrity_tag,
    );
    // A Retry has no packet number, so nothing samples it.
    try testing.expectEqual(@as(usize, 0), p.pn_offset);
}

test "a Retry with no room for its tag is refused" {
    const short = [_]u8{ 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 1, 2, 3 };
    try testing.expectError(error.BadRetry, parseLong(&short));
}

test "a Length field past the end of the datagram is refused" {
    // **The bound that keeps a reader inside the datagram.** The Length
    // says 1182 and 4 bytes arrived, so nothing may be read.
    const header = [_]u8{
        0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0,
        0x3e, 0x51, 0x57, 0x08, 0x00, 0x00, 0x44, 0x9e, 0x00, 0x00,
        0x00, 0x02,
    };
    try testing.expectError(error.BadLength, parseLong(&header));

    // A Length of zero names no packet number at all.
    var zero = header;
    zero[16] = 0x00;
    zero[17] = 0x00;
    try testing.expectError(error.BadLength, parseLong(zero[0..18]));
}

test "a token length past the end of the datagram is refused" {
    // The Token Length is a varint the peer chose, so it is checked
    // against the bytes that arrived before the token is sliced.
    const header = [_]u8{
        0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0,
        0x3e, 0x51, 0x57, 0x08, 0x00, 0x7f, 0x00, 0x00,
    };
    try testing.expectError(error.Truncated, parseLong(&header));
}

test "a connection id longer than 20 bytes is refused, not held" {
    // RFC 8999 allows 255 and RFC 9000 section 17.2 caps this version at
    // 20. A longer one has nowhere to go in a `ConnectionId`.
    var datagram: [64]u8 = @splat(0);
    datagram[0] = 0xc3;
    datagram[4] = 0x01;
    datagram[5] = 21;
    try testing.expectError(error.ConnectionIdTooLong, parseLong(&datagram));
    try testing.expectError(error.ConnectionIdTooLong, ConnectionId.init(&([_]u8{0} ** 21)));
    try testing.expectEqual(@as(u8, 20), (try ConnectionId.init(&([_]u8{7} ** 20))).len);
}

test "a long header with the Fixed Bit clear is refused" {
    // RFC 9000 section 17.2: such a packet is not a version 1 packet.
    const header = [_]u8{ 0x83, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x02, 0x00, 0x00 };
    try testing.expectError(error.FixedBitNotSet, parseLong(&header));
}

test "a version this build does not speak still reads its invariant fields" {
    // RFC 8999 is the reason: a receiver must read the two connection ids
    // of any version at all, so it can answer with a version list.
    const header = [_]u8{
        0xc0, 0x0a, 0x0a, 0x0a, 0x0a, 0x02, 0xaa, 0xbb, 0x01, 0xcc, 0xde, 0xad,
    };
    try testing.expectError(error.UnsupportedVersion, parseLong(&header));

    const inv = try parseInvariant(&header);
    try testing.expect(!inv.version.isSupported());
    try testing.expect(inv.version.isReserved());
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, inv.dcid.slice());
    try testing.expectEqualSlices(u8, &.{0xcc}, inv.scid.slice());
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad }, inv.rest);
}

test "a Version Negotiation packet lists whole versions and never a part of one" {
    const packet_bytes = [_]u8{
        0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0xaa, 0x01, 0xbb,
        0x00, 0x00, 0x00, 0x01, 0x6b, 0x33, 0x43, 0xcf,
    };
    const vn = try parseVersionNegotiation(&packet_bytes);
    try testing.expectEqual(@as(usize, 2), vn.count());
    try testing.expectEqual(Version.v1, try vn.get(0));
    try testing.expectEqual(Version.v2, try vn.get(1));
    try testing.expect(vn.has(.v1));
    try testing.expect(!vn.has(@enumFromInt(0xdeadbeef)));

    // **The bound on the index is a returned error and not an assert.**
    // `get` is public and a release build strips asserts, so an index the
    // list does not reach must still be refused.
    try testing.expectError(error.NoSuchVersion, vn.get(2));
    try testing.expectError(error.NoSuchVersion, vn.get(std.math.maxInt(usize)));

    // A trailing part of a version is malformed, and so is an empty list.
    try testing.expectError(error.BadVersionList, parseVersionNegotiation(packet_bytes[0 .. packet_bytes.len - 1]));
    try testing.expectError(error.BadVersionList, parseVersionNegotiation(packet_bytes[0..9]));
}

test "a short header takes its connection id length from this endpoint" {
    // The wire carries no length here, so the caller supplies the one it
    // handed out. RFC 9000 section 17.3.1.
    const p = [_]u8{ 0x42, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0xbf, 0xf4, 0x01 };
    const short = try parseShort(&p, 4);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc, 0xdd }, short.dcid.slice());
    try testing.expectEqual(@as(usize, 5), short.pn_offset);
    try testing.expectEqual(@as(u3, 3), packetNumberLen(short.first_byte));
    try testing.expectEqual(Form.short, form(short.first_byte));

    // An empty connection id is legal and moves the packet number to 1.
    const bare = try parseShort(&p, 0);
    try testing.expectEqual(@as(usize, 1), bare.pn_offset);
    try testing.expectEqual(@as(u8, 0), bare.dcid.len);
}

test "a short header with no room for a packet number is refused" {
    const p = [_]u8{ 0x42, 0xaa, 0xbb };
    try testing.expectError(error.Truncated, parseShort(&p, 2));
    // And one with the Fixed Bit clear is not a version 1 packet.
    try testing.expectError(error.FixedBitNotSet, parseShort(&.{ 0x02, 0xaa, 0xbb, 0x01 }, 2));
}

test "the first byte splits into the fields RFC 9000 sections 17.2 and 17.3 name" {
    // A long header Initial with a 4-byte packet number.
    try testing.expectEqual(Form.long, form(0xc3));
    try testing.expectEqual(LongType.initial, longType(0xc3));
    try testing.expectEqual(@as(u3, 4), packetNumberLen(0xc3));
    // A Handshake with a 1-byte packet number.
    try testing.expectEqual(LongType.handshake, longType(0xe0));
    try testing.expectEqual(@as(u3, 1), packetNumberLen(0xe0));
    // Retry, and 0-RTT.
    try testing.expectEqual(LongType.retry, longType(0xf0));
    try testing.expectEqual(LongType.zero_rtt, longType(0xd0));
    // The names, so a diagnostic can say which one arrived.
    try testing.expectEqualStrings("Initial", LongType.initial.name());
    try testing.expectEqualStrings("Retry", LongType.retry.name());
}

test "the reserved version pattern is a value and never a fault" {
    // RFC 9000 section 15 sets aside `0x?a?a?a?a` so a peer can force
    // version negotiation on purpose.
    try testing.expect((@as(Version, @enumFromInt(0x0a0a0a0a))).isReserved());
    try testing.expect((@as(Version, @enumFromInt(0x1a2a3a4a))).isReserved());
    try testing.expect(!Version.v1.isReserved());
    try testing.expect(!Version.v2.isReserved());
    // Reserved and supported are different questions. Version 1 is the
    // one this package reads, and version 2 is a real version it does not.
    try testing.expect(Version.v1.isSupported());
    try testing.expect(!Version.v2.isSupported());
}

test "an empty connection id compares equal to another empty one" {
    const a: ConnectionId = .empty;
    const b = try ConnectionId.init(&.{});
    try testing.expect(a.eql(&b));
    const c = try ConnectionId.init(&.{ 1, 2, 3 });
    try testing.expect(!a.eql(&c));
    try testing.expect(c.eql(&c));
}
