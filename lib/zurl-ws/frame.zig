//! The WebSocket frame, RFC 6455 section 5. Pure bytes, and testable with
//! a table.
//!
//! **A frame header is attacker-controlled from its first byte.** The
//! opcode, the three reserved bits, the mask bit, and the length all come
//! off the wire. This module reads each one and refuses every shape RFC
//! 6455 forbids, so the reader above it never has to decide whether a
//! shape is legal:
//!
//! - **A reserved bit that is set is refused.** RSV1, RSV2, and RSV3 mean
//!   an extension, and this client offers none. A peer that sets one is
//!   describing a payload transform this build does not do, and a reader
//!   that ignored the bit would hand transformed bytes up as plain ones.
//! - **A reserved opcode is refused.** RFC 6455 section 5.2 keeps 3 to 7
//!   and 11 to 15 for later, so a peer that sends one is speaking a
//!   protocol this build does not know.
//! - **A masked frame from a server is refused.** Section 5.1 says a
//!   server must not mask, so a masked server frame is a protocol
//!   violation and never a payload. `decode` reports the mask bit, and
//!   `Session` is where the direction rule is applied.
//! - **The length must use its shortest form.** Section 5.2 names three
//!   forms and says the smallest that fits must be used. A peer that
//!   writes 200 as a 64-bit length has written the same number two ways,
//!   and two ways to write one number is how one reader counts a payload
//!   that another reader counts as a header.
//! - **The 64-bit length's top bit must be clear.** Section 5.2 says so.
//!   A set bit would make a length no counter of octets can hold.
//! - **A control frame must be final and must be short.** Section 5.5
//!   caps a control payload at 125 octets and forbids a fragmented
//!   control frame, because a peer must be able to answer a ping between
//!   the pieces of a long message.
//!
//! **What this module does not decide.** It puts no bound on a data
//! frame's payload past what the wire form allows. A payload of nearly
//! 2^63 octets is a legal frame and a hostile one, and the bound on it
//! belongs to the caller that has to find room for the bytes. See
//! `zurl_ws.Fetcher.Options.max_response_bytes`.
//!
//! **Masking is not a secret and not a defence.** RFC 6455 section 5.3
//! makes it a requirement: a client must mask every frame it sends, with a
//! key it cannot predict, because an unmasked client payload lets a
//! browser be used to write chosen bytes through a cache or a proxy that
//! reads them as a request. This module applies the key. Drawing it is
//! `zurl_ws.handshake.drawMask`, which reads `io.randomSecure`.

const std = @import("std");

/// What a frame carries, RFC 6455 section 5.2.
///
/// A non-exhaustive enum, because 3 to 7 and 11 to 15 are reserved and a
/// peer can put any of them on the wire. `isReserved` names them.
pub const Opcode = enum(u4) {
    /// This frame continues the message the last non-continuation frame
    /// started.
    continuation = 0x0,
    /// A message of UTF-8 text.
    text = 0x1,
    /// A message of octets.
    binary = 0x2,
    /// The close handshake, section 5.5.1.
    close = 0x8,
    /// A ping, section 5.5.2. Every one must be answered with a pong.
    ping = 0x9,
    /// A pong, section 5.5.3.
    pong = 0xa,
    _,

    /// Whether this opcode names a control frame.
    ///
    /// The high bit of the four is the whole rule, RFC 6455 section 5.2.
    /// A control frame may arrive between the pieces of a fragmented
    /// message, so a reader must be able to tell the two apart before it
    /// knows which opcodes it will ever see.
    pub fn isControl(o: Opcode) bool {
        return (@intFromEnum(o) & 0x8) != 0;
    }

    /// Whether RFC 6455 keeps this opcode for later.
    ///
    /// 3 to 7 are the reserved data opcodes and 11 to 15 are the reserved
    /// control opcodes. A peer that sends one is speaking an extension
    /// this build did not agree to.
    pub fn isReserved(o: Opcode) bool {
        return switch (@intFromEnum(o)) {
            0x0, 0x1, 0x2, 0x8, 0x9, 0xa => false,
            else => true,
        };
    }
};

/// How many octets a control frame's payload may hold, RFC 6455 section
/// 5.5.
pub const max_control_payload_bytes: usize = 125;

/// How many octets of a frame header this module reads before it knows how
/// many more there are.
pub const prefix_bytes: usize = 2;

/// The largest frame header RFC 6455 can write: the two octet prefix, an
/// eight octet length, and a four octet mask key.
pub const max_header_bytes: usize = prefix_bytes + 8 + 4;

/// The mask key of a client frame, RFC 6455 section 5.3.
pub const mask_key_bytes: usize = 4;

/// One frame header, read off the wire or built to write.
pub const Header = struct {
    /// Whether this frame ends the message it belongs to.
    fin: bool,
    /// The three extension bits. `decode` refuses any that is set, so a
    /// decoded header always reads false, false, false.
    rsv1: bool = false,
    rsv2: bool = false,
    rsv3: bool = false,
    opcode: Opcode,
    /// Whether `payload_len` octets on the wire are masked with
    /// `mask_key`.
    masked: bool,
    /// How many octets of payload follow the header.
    payload_len: u64,
    /// The key that masks the payload. Read it only when `masked`.
    mask_key: [mask_key_bytes]u8 = .{ 0, 0, 0, 0 },
};

/// Why a frame header could not be read.
pub const DecodeError = error{
    /// A reserved bit is set, so the peer named an extension this build
    /// did not agree to.
    ReservedBitSet,
    /// The opcode is one RFC 6455 keeps for later.
    ReservedOpcode,
    /// A control frame carries more than 125 octets, or it is not final.
    /// RFC 6455 section 5.5 forbids both.
    BadControlFrame,
    /// The length is written in a longer form than it needs. RFC 6455
    /// section 5.2 says the shortest form that fits must be used.
    NonMinimalLength,
    /// The 64-bit length has its top bit set, which RFC 6455 section 5.2
    /// forbids.
    LengthTooLarge,
    /// `extra` does not hold the number of octets `extraBytes` named for
    /// this prefix, so the fixed-size reads below it have no backing.
    HeaderLengthMismatch,
};

/// How many octets follow the two octet prefix in this frame's header.
///
/// Reads the length form and the mask bit and nothing else, so a caller
/// can size one read before it has a whole header. Never larger than
/// `max_header_bytes - prefix_bytes`.
pub fn extraBytes(prefix: [prefix_bytes]u8) usize {
    const masked = (prefix[1] & 0x80) != 0;
    const short = prefix[1] & 0x7f;
    const length_bytes: usize = switch (short) {
        126 => 2,
        127 => 8,
        else => 0,
    };
    return length_bytes + if (masked) mask_key_bytes else 0;
}

/// Reads one frame header.
///
/// `extra` must hold exactly `extraBytes(prefix)` octets, which is what
/// the caller read after the prefix.
///
/// **A shorter or a longer slice is a named fault and not an assertion.**
/// The length of `extra` is read from `prefix`, and `prefix` came off the
/// wire, so a caller that sized its read from anything else hands this
/// function a slice a peer chose the length of. Three fixed-size reads
/// below take their bound from that length, and an assertion is compiled
/// out of a ReleaseFast or a ReleaseSmall build, which is the build that
/// ships. The comparison costs one branch per frame.
///
/// Every refusal this makes is named in `DecodeError` and explained in the
/// module comment. The one shape it does **not** refuse is a payload
/// length larger than the caller can hold: that bound belongs to the
/// caller, because only the caller knows how much room it has.
pub fn decode(prefix: [prefix_bytes]u8, extra: []const u8) DecodeError!Header {
    if (extra.len != extraBytes(prefix)) return error.HeaderLengthMismatch;

    const fin = (prefix[0] & 0x80) != 0;
    // **Before the opcode and before the length.** A set reserved bit
    // says the payload was transformed by an extension, so nothing after
    // it can be read at face value.
    if ((prefix[0] & 0x70) != 0) return error.ReservedBitSet;

    const opcode: Opcode = @enumFromInt(@as(u4, @truncate(prefix[0] & 0x0f)));
    if (opcode.isReserved()) return error.ReservedOpcode;

    const masked = (prefix[1] & 0x80) != 0;
    const short = prefix[1] & 0x7f;

    var at: usize = 0;
    const payload_len: u64 = switch (short) {
        126 => blk: {
            const value = std.mem.readInt(u16, extra[0..2], .big);
            // The shortest form holds 0 to 125, so a 16-bit length that
            // fits there was written the long way.
            if (value < 126) return error.NonMinimalLength;
            at = 2;
            break :blk value;
        },
        127 => blk: {
            const value = std.mem.readInt(u64, extra[0..8], .big);
            if ((value & (@as(u64, 1) << 63)) != 0) return error.LengthTooLarge;
            // The 16-bit form holds up to 65535, so anything at or under
            // that was written the long way.
            if (value <= std.math.maxInt(u16)) return error.NonMinimalLength;
            at = 8;
            break :blk value;
        },
        else => short,
    };

    var header: Header = .{
        .fin = fin,
        .opcode = opcode,
        .masked = masked,
        .payload_len = payload_len,
    };
    if (masked) {
        @memcpy(&header.mask_key, extra[at..][0..mask_key_bytes]);
    }

    // **Last, because it reads both halves.** RFC 6455 section 5.5 says a
    // control frame must be final and must carry no more than 125 octets,
    // so that a peer can answer a ping between the pieces of a long
    // message.
    if (opcode.isControl()) {
        if (!fin) return error.BadControlFrame;
        if (payload_len > max_control_payload_bytes) return error.BadControlFrame;
    }

    return header;
}

/// Writes `header` into `out` and returns the part of `out` that holds it.
///
/// The length is written in its shortest form, which is the form RFC 6455
/// section 5.2 requires. A caller that could pick the form could write one
/// number two ways, which is the shape `decode` refuses on the way in.
pub fn encode(out: *[max_header_bytes]u8, header: Header) []u8 {
    out[0] = @as(u8, @intFromBool(header.fin)) << 7;
    if (header.rsv1) out[0] |= 0x40;
    if (header.rsv2) out[0] |= 0x20;
    if (header.rsv3) out[0] |= 0x10;
    out[0] |= @intFromEnum(header.opcode);

    const mask_bit: u8 = if (header.masked) 0x80 else 0;
    var at: usize = prefix_bytes;
    if (header.payload_len < 126) {
        out[1] = mask_bit | @as(u8, @intCast(header.payload_len));
    } else if (header.payload_len <= std.math.maxInt(u16)) {
        out[1] = mask_bit | 126;
        std.mem.writeInt(u16, out[2..4], @intCast(header.payload_len), .big);
        at = 4;
    } else {
        out[1] = mask_bit | 127;
        std.mem.writeInt(u64, out[2..10], header.payload_len, .big);
        at = 10;
    }

    if (header.masked) {
        @memcpy(out[at..][0..mask_key_bytes], &header.mask_key);
        at += mask_key_bytes;
    }
    return out[0..at];
}

/// Masks `payload` in place with `key`, RFC 6455 section 5.3.
///
/// `offset` is how many octets of this frame's payload were already
/// masked, so a caller that writes a payload in pieces gets the same
/// result as one that writes it whole. The transform is its own inverse,
/// so this both masks a frame that goes out and unmasks one that came in.
pub fn applyMask(payload: []u8, key: [mask_key_bytes]u8, offset: usize) void {
    for (payload, 0..) |*byte, i| {
        byte.* ^= key[(offset + i) % mask_key_bytes];
    }
}

const testing = std.testing;

test "the opcode table names the control frames and the reserved ones" {
    try testing.expect(!Opcode.continuation.isControl());
    try testing.expect(!Opcode.text.isControl());
    try testing.expect(!Opcode.binary.isControl());
    try testing.expect(Opcode.close.isControl());
    try testing.expect(Opcode.ping.isControl());
    try testing.expect(Opcode.pong.isControl());

    for ([_]u4{ 0x0, 0x1, 0x2, 0x8, 0x9, 0xa }) |raw| {
        try testing.expect(!@as(Opcode, @enumFromInt(raw)).isReserved());
    }
    for ([_]u4{ 0x3, 0x4, 0x5, 0x6, 0x7, 0xb, 0xc, 0xd, 0xe, 0xf }) |raw| {
        try testing.expect(@as(Opcode, @enumFromInt(raw)).isReserved());
    }
}

test "the three length forms each read back the number they hold" {
    // The shortest form, 0 to 125.
    {
        const prefix: [2]u8 = .{ 0x81, 5 };
        try testing.expectEqual(@as(usize, 0), extraBytes(prefix));
        const header = try decode(prefix, &.{});
        try testing.expect(header.fin);
        try testing.expectEqual(Opcode.text, header.opcode);
        try testing.expect(!header.masked);
        try testing.expectEqual(@as(u64, 5), header.payload_len);
    }
    // The 16-bit form, 126 to 65535.
    {
        const prefix: [2]u8 = .{ 0x82, 126 };
        try testing.expectEqual(@as(usize, 2), extraBytes(prefix));
        const header = try decode(prefix, &.{ 0x01, 0x00 });
        try testing.expectEqual(Opcode.binary, header.opcode);
        try testing.expectEqual(@as(u64, 256), header.payload_len);
    }
    // The 64-bit form, 65536 and up.
    {
        const prefix: [2]u8 = .{ 0x82, 127 };
        try testing.expectEqual(@as(usize, 8), extraBytes(prefix));
        const header = try decode(prefix, &.{ 0, 0, 0, 0, 0, 1, 0, 0 });
        try testing.expectEqual(@as(u64, 65536), header.payload_len);
    }
}

test "a length written in a longer form than it needs is refused" {
    // Two ways to write one number is how one reader counts a payload
    // that another reader counts as a header.
    try testing.expectError(
        error.NonMinimalLength,
        decode(.{ 0x81, 126 }, &.{ 0x00, 0x05 }),
    );
    try testing.expectError(
        error.NonMinimalLength,
        decode(.{ 0x81, 127 }, &.{ 0, 0, 0, 0, 0, 0, 0x01, 0x00 }),
    );
    // 65536 is the first number the 64-bit form is the shortest for.
    _ = try decode(.{ 0x81, 127 }, &.{ 0, 0, 0, 0, 0, 1, 0, 0 });
}

test "a 64-bit length with its top bit set is refused" {
    try testing.expectError(
        error.LengthTooLarge,
        decode(.{ 0x82, 127 }, &.{ 0x80, 0, 0, 0, 0, 0, 0, 0 }),
    );
}

test "a reserved bit and a reserved opcode are each refused" {
    try testing.expectError(error.ReservedBitSet, decode(.{ 0xc1, 0 }, &.{}));
    try testing.expectError(error.ReservedBitSet, decode(.{ 0xa1, 0 }, &.{}));
    try testing.expectError(error.ReservedBitSet, decode(.{ 0x91, 0 }, &.{}));
    try testing.expectError(error.ReservedOpcode, decode(.{ 0x83, 0 }, &.{}));
    try testing.expectError(error.ReservedOpcode, decode(.{ 0x8f, 0 }, &.{}));
}

test "a control frame that is long or split is refused" {
    // RFC 6455 section 5.5: a control frame carries at most 125 octets and
    // is never fragmented.
    try testing.expectError(
        error.BadControlFrame,
        decode(.{ 0x89, 126 }, &.{ 0x00, 0x7e }),
    );
    // Not final.
    try testing.expectError(error.BadControlFrame, decode(.{ 0x09, 4 }, &.{}));
    // 125 exactly is legal.
    const ok = try decode(.{ 0x89, 125 }, &.{});
    try testing.expectEqual(@as(u64, 125), ok.payload_len);
}

test "an extra slice of the wrong length is refused and never read past" {
    // **The check that used to be an assertion.** In a ReleaseFast build
    // the assertion was gone and each of these read octets that are not
    // there. Every one must now be a named error.
    //
    // The 16-bit length form needs two octets.
    try testing.expectError(error.HeaderLengthMismatch, decode(.{ 0x82, 126 }, &.{}));
    try testing.expectError(error.HeaderLengthMismatch, decode(.{ 0x82, 126 }, &.{0x01}));
    // The 64-bit form needs eight.
    try testing.expectError(error.HeaderLengthMismatch, decode(.{ 0x82, 127 }, &.{ 0, 0, 0, 0 }));
    // A masked frame needs four more for the key.
    try testing.expectError(error.HeaderLengthMismatch, decode(.{ 0x81, 0x80 | 3 }, &.{ 0xde, 0xad }));
    // A short form needs none, so a slice that carries some is refused
    // too: a caller that read too much has lost its place in the stream.
    try testing.expectError(error.HeaderLengthMismatch, decode(.{ 0x81, 5 }, &.{0x00}));

    // The exact length still reads.
    const header = try decode(.{ 0x82, 126 }, &.{ 0x01, 0x00 });
    try testing.expectEqual(@as(u64, 256), header.payload_len);
}

test "a masked frame reads its key back" {
    const prefix: [2]u8 = .{ 0x81, 0x80 | 3 };
    try testing.expectEqual(@as(usize, 4), extraBytes(prefix));
    const header = try decode(prefix, &.{ 0xde, 0xad, 0xbe, 0xef });
    try testing.expect(header.masked);
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, &header.mask_key);
    try testing.expectEqual(@as(u64, 3), header.payload_len);
}

test "encode writes the shortest form and decode reads it back" {
    const cases = [_]u64{ 0, 1, 125, 126, 200, 65535, 65536, 1 << 32 };
    for (cases) |length| {
        var storage: [max_header_bytes]u8 = undefined;
        const written = encode(&storage, .{
            .fin = true,
            .opcode = .binary,
            .masked = true,
            .payload_len = length,
            .mask_key = .{ 1, 2, 3, 4 },
        });

        var prefix: [prefix_bytes]u8 = undefined;
        @memcpy(&prefix, written[0..prefix_bytes]);
        try testing.expectEqual(written.len - prefix_bytes, extraBytes(prefix));

        const header = try decode(prefix, written[prefix_bytes..]);
        try testing.expectEqual(length, header.payload_len);
        try testing.expect(header.masked);
        try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, &header.mask_key);
        try testing.expectEqual(Opcode.binary, header.opcode);
    }
}

test "the mask is its own inverse, whole or in pieces" {
    const key: [mask_key_bytes]u8 = .{ 0x12, 0x34, 0x56, 0x78 };
    const plain = "the quick brown fox jumps over the lazy dog";

    var whole: [plain.len]u8 = undefined;
    @memcpy(&whole, plain);
    applyMask(&whole, key, 0);
    try testing.expect(!std.mem.eql(u8, plain, &whole));
    applyMask(&whole, key, 0);
    try testing.expectEqualStrings(plain, &whole);

    // The offset is what makes a payload written in pieces come out the
    // same as one written whole.
    var pieces: [plain.len]u8 = undefined;
    @memcpy(&pieces, plain);
    applyMask(pieces[0..7], key, 0);
    applyMask(pieces[7..30], key, 7);
    applyMask(pieces[30..], key, 30);

    var reference: [plain.len]u8 = undefined;
    @memcpy(&reference, plain);
    applyMask(&reference, key, 0);
    try testing.expectEqualSlices(u8, &reference, &pieces);
}

test "the RFC's own worked example masks to the octets it prints" {
    // RFC 6455 section 5.7, the masked single-frame text message "Hello":
    //   0x81 0x85 0x37 0xfa 0x21 0x3d 0x7f 0x9f 0x4d 0x51 0x58
    var payload: [5]u8 = "Hello".*;
    applyMask(&payload, .{ 0x37, 0xfa, 0x21, 0x3d }, 0);
    try testing.expectEqualSlices(u8, &.{ 0x7f, 0x9f, 0x4d, 0x51, 0x58 }, &payload);

    var storage: [max_header_bytes]u8 = undefined;
    const written = encode(&storage, .{
        .fin = true,
        .opcode = .text,
        .masked = true,
        .payload_len = 5,
        .mask_key = .{ 0x37, 0xfa, 0x21, 0x3d },
    });
    try testing.expectEqualSlices(
        u8,
        &.{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d },
        written,
    );
}

test "the RFC's unmasked example reads back as the RFC writes it" {
    // RFC 6455 section 5.7, the unmasked "Hello" a server sends:
    //   0x81 0x05 0x48 0x65 0x6c 0x6c 0x6f
    const header = try decode(.{ 0x81, 0x05 }, &.{});
    try testing.expect(header.fin);
    try testing.expect(!header.masked);
    try testing.expectEqual(Opcode.text, header.opcode);
    try testing.expectEqual(@as(u64, 5), header.payload_len);
}
