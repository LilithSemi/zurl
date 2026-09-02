//! The binary packet protocol, RFC 4253 section 6. Pure bytes, and
//! testable with a table.
//!
//! One packet on the wire is:
//!
//! ```
//! uint32  packet_length     how many bytes follow, the MAC not counted
//! byte    padding_length    at least 4
//! byte[]  payload           packet_length - padding_length - 1 bytes
//! byte[]  random padding    padding_length bytes
//! byte[]  mac               the cipher's tag, or nothing
//! ```
//!
//! **The padding rules are the whole safety of this layer, and this module
//! refuses every shape RFC 4253 section 6 forbids:**
//!
//! - **Padding shorter than 4 bytes is refused.** Section 6 sets that
//!   floor so that the front of a packet is never all length fields.
//! - **The length must line up with the block size.** Section 6 says the
//!   padded run must be a multiple of the cipher block size, or of 8,
//!   whichever is larger. A packet that does not line up is a packet a
//!   block cipher cannot have produced.
//! - **The payload must fit inside the length.** A `padding_length` of
//!   200 inside a `packet_length` of 16 names a payload of negative size.
//! - **A `packet_length` outside the bound is refused before one byte of
//!   the body is read.** See `max_packet_bytes`.
//!
//! **Where the length field sits differs by cipher, and that difference
//! is why `length_is_aad` exists.** With no cipher, and with a cipher that
//! encrypts the length with the rest, the four length bytes are part of
//! the padded run. With an AEAD that keeps the length outside the
//! ciphertext, which is both of the ciphers this build speaks, the length
//! is authenticated data and the padded run starts at `padding_length`.
//! OpenSSH's `packet.c` computes its padding the same way, and a client
//! that got this wrong would build packets that no server can parse.
//!
//! What this module does not own: it holds no key and it moves no byte on
//! or off a socket. `zurl_ssh.cipher` seals and opens, and
//! `zurl_ssh.Transport` reads and writes.

const std = @import("std");

/// The bound on `packet_length`.
///
/// OpenSSH's `PACKET_MAX_SIZE` is the same 256 KiB, and RFC 4253
/// section 6.1 asks every implementation to carry at least 35000 bytes.
/// The bound exists because `packet_length` is the first field a peer
/// writes and it can claim any value a `uint32` holds. A reader with no
/// bound would go looking for four gigabytes.
pub const max_packet_bytes: u32 = 256 * 1024;

/// The smallest padding RFC 4253 section 6 allows.
pub const min_padding_bytes: usize = 4;

/// The block size a packet lines up with when no cipher has a larger one.
/// RFC 4253 section 6 sets it.
pub const min_block_bytes: usize = 8;

/// Why a packet was refused.
pub const FrameError = error{
    /// `packet_length` is zero, or larger than `max_packet_bytes`.
    PacketLengthOutOfRange,
    /// `packet_length` does not line up with the block size. See the
    /// module comment.
    PacketNotBlockAligned,
    /// `padding_length` is under 4, which RFC 4253 section 6 forbids.
    PaddingTooShort,
    /// `padding_length` leaves no room for itself inside the packet, so
    /// the payload would have a negative size.
    PaddingLongerThanPacket,
    /// The payload does not fit the buffer the caller offered.
    PayloadTooLong,
};

/// How many bytes of padding a payload of `payload_bytes` needs.
///
/// `block` is the cipher block size, or `min_block_bytes` when it is
/// smaller. `length_is_aad` is true for a cipher that leaves the four
/// length bytes outside the padded run. See the module comment.
///
/// The answer is always at least `min_padding_bytes`, and it never passes
/// 255, because `padding_length` is one byte. A block size over 128 could
/// not keep both rules, and no cipher this build speaks has one.
pub fn paddingLen(payload_bytes: usize, block: usize, length_is_aad: bool) usize {
    std.debug.assert(block >= min_block_bytes);
    std.debug.assert(block <= 128);
    const head: usize = if (length_is_aad) 1 else 5;
    const unpadded = head + payload_bytes;
    var padding = block - (unpadded % block);
    if (padding < min_padding_bytes) padding += block;
    return padding;
}

/// How many bytes the whole body of a packet takes, the length field not
/// counted and the tag not counted.
///
/// This is what `packet_length` says.
pub fn bodyLen(payload_bytes: usize, block: usize, length_is_aad: bool) usize {
    return 1 + payload_bytes + paddingLen(payload_bytes, block, length_is_aad);
}

/// Checks a `packet_length` that came off the wire.
///
/// **This runs before the body is read.** The length decides how many
/// bytes this process then waits for, so a length that is refused costs
/// one comparison and no memory at all.
pub fn checkLength(
    packet_length: u32,
    block: usize,
    length_is_aad: bool,
    max_bytes: u32,
) FrameError!void {
    std.debug.assert(block >= min_block_bytes);
    if (packet_length == 0 or packet_length > max_bytes) return error.PacketLengthOutOfRange;
    // The smallest legal packet is one padding_length byte, one payload
    // byte, and four padding bytes. The alignment rule below normally
    // forces more, and this floor is the one that stands when it does
    // not.
    if (packet_length < 1 + min_padding_bytes) return error.PacketLengthOutOfRange;

    const padded: u64 = if (length_is_aad) packet_length else @as(u64, packet_length) + 4;
    if (padded % block != 0) return error.PacketNotBlockAligned;
}

/// Takes the payload out of a decrypted body.
///
/// `body` is `padding_length`, then the payload, then the padding. The
/// result points into `body`.
///
/// **Every rule about the padding is applied here**, because this is the
/// one place that sees the padding length. A caller that skipped this and
/// sliced the body itself could read a payload that runs off the end.
pub fn payloadOf(body: []const u8) FrameError![]const u8 {
    if (body.len == 0) return error.PacketLengthOutOfRange;
    const padding_length: usize = body[0];
    if (padding_length < min_padding_bytes) return error.PaddingTooShort;
    // `1 +` cannot overflow: padding_length is a byte and body.len is a
    // bounded packet.
    if (1 + padding_length > body.len) return error.PaddingLongerThanPacket;
    return body[1 .. body.len - padding_length];
}

/// Fills `out` with one packet body: `padding_length`, the payload, and
/// the padding.
///
/// `out.len` must be exactly `bodyLen(payload.len, block, length_is_aad)`,
/// which is a rule this build's own caller keeps, so it is an assert.
///
/// **The padding is random, and RFC 4253 section 6 says it must be.** The
/// caller draws it, because this module reads no clock and no entropy
/// source. `zurl_ssh.Transport` draws it from `io.randomSecure`.
pub fn writeBody(
    out: []u8,
    payload: []const u8,
    padding: []const u8,
) void {
    std.debug.assert(padding.len >= min_padding_bytes);
    std.debug.assert(padding.len <= 255);
    std.debug.assert(out.len == 1 + payload.len + padding.len);
    out[0] = @intCast(padding.len);
    @memcpy(out[1..][0..payload.len], payload);
    @memcpy(out[1 + payload.len ..][0..padding.len], padding);
}

const testing = std.testing;

test "padding fills the block and is never under four bytes" {
    // With no cipher the four length bytes are inside the padded run, so
    // the run starts at 5 bytes of overhead.
    const cases = [_]struct {
        payload: usize,
        block: usize,
        length_is_aad: bool,
        padding: usize,
    }{
        // 5 + 1 = 6, so 2 would fill the block and 2 is under the floor.
        .{ .payload = 1, .block = 8, .length_is_aad = false, .padding = 10 },
        // 5 + 3 = 8, already a whole block, so a whole block is added.
        .{ .payload = 3, .block = 8, .length_is_aad = false, .padding = 8 },
        // 5 + 11 = 16, and 8 is over the floor.
        .{ .payload = 11, .block = 8, .length_is_aad = false, .padding = 8 },
        // AEAD: the run starts at the padding_length byte.
        .{ .payload = 1, .block = 8, .length_is_aad = true, .padding = 6 },
        .{ .payload = 3, .block = 8, .length_is_aad = true, .padding = 4 },
        .{ .payload = 7, .block = 8, .length_is_aad = true, .padding = 8 },
        .{ .payload = 1, .block = 16, .length_is_aad = true, .padding = 14 },
        .{ .payload = 15, .block = 16, .length_is_aad = true, .padding = 16 },
    };
    for (cases) |case| {
        const padding = paddingLen(case.payload, case.block, case.length_is_aad);
        try testing.expectEqual(case.padding, padding);
        try testing.expect(padding >= min_padding_bytes);

        const body = bodyLen(case.payload, case.block, case.length_is_aad);
        const run = if (case.length_is_aad) body else body + 4;
        try testing.expectEqual(@as(usize, 0), run % case.block);
    }
}

test "every payload size up to a kilobyte builds a packet that checks out" {
    // **The round trip that proves the two halves agree.** What
    // `paddingLen` builds, `checkLength` must accept, for every size and
    // for every cipher shape this build has.
    for ([_]usize{ 8, 16 }) |block| {
        for ([_]bool{ false, true }) |length_is_aad| {
            for (0..1024) |payload| {
                const body = bodyLen(payload, block, length_is_aad);
                try checkLength(@intCast(body), block, length_is_aad, max_packet_bytes);
                const padding = paddingLen(payload, block, length_is_aad);
                try testing.expect(padding <= 255);
            }
        }
    }
}

test "a length outside the bound is refused before any body is read" {
    try testing.expectError(
        error.PacketLengthOutOfRange,
        checkLength(0, 8, false, max_packet_bytes),
    );
    try testing.expectError(
        error.PacketLengthOutOfRange,
        checkLength(max_packet_bytes + 8, 8, false, max_packet_bytes),
    );
    try testing.expectError(
        error.PacketLengthOutOfRange,
        checkLength(0xffff_ffff, 8, false, max_packet_bytes),
    );
    // Under the floor of one padding_length byte and four padding bytes.
    try testing.expectError(
        error.PacketLengthOutOfRange,
        checkLength(4, 8, true, max_packet_bytes),
    );
}

test "a length that does not line up with the block is refused" {
    // 12 + 4 is 16, so this one is legal with the length inside the run
    // and illegal with the length outside it.
    try checkLength(12, 8, false, max_packet_bytes);
    try testing.expectError(
        error.PacketNotBlockAligned,
        checkLength(12, 8, true, max_packet_bytes),
    );
    try checkLength(16, 16, true, max_packet_bytes);
    try testing.expectError(
        error.PacketNotBlockAligned,
        checkLength(24, 16, true, max_packet_bytes),
    );
    try testing.expectError(
        error.PacketNotBlockAligned,
        checkLength(13, 8, false, max_packet_bytes),
    );
}

test "padding under four bytes is a protocol violation and never tolerated" {
    // **A packet with three bytes of padding is well formed arithmetic
    // and a forbidden shape.** RFC 4253 section 6 sets the floor, so this
    // must fail rather than parse.
    var body: [16]u8 = undefined;
    @memset(&body, 0);
    for (0..min_padding_bytes) |short| {
        body[0] = @intCast(short);
        try testing.expectError(error.PaddingTooShort, payloadOf(&body));
    }
    body[0] = 4;
    try testing.expectEqual(@as(usize, 11), (try payloadOf(&body)).len);
}

test "padding longer than the packet is refused" {
    var body: [8]u8 = undefined;
    @memset(&body, 0);
    body[0] = 200;
    try testing.expectError(error.PaddingLongerThanPacket, payloadOf(&body));
    // Exactly filling the body leaves an empty payload, which is legal
    // arithmetic and which the message layer above refuses as no message.
    body[0] = 7;
    try testing.expectEqualSlices(u8, "", try payloadOf(&body));
    body[0] = 8;
    try testing.expectError(error.PaddingLongerThanPacket, payloadOf(&body));
    try testing.expectError(error.PacketLengthOutOfRange, payloadOf(""));
}

test "writeBody and payloadOf are the two halves of one packet" {
    const payload = "\x14hello";
    const block: usize = 8;
    const padding_len = paddingLen(payload.len, block, true);
    var padding: [255]u8 = undefined;
    @memset(padding[0..padding_len], 0xa5);

    var body: [64]u8 = undefined;
    const body_len = bodyLen(payload.len, block, true);
    writeBody(body[0..body_len], payload, padding[0..padding_len]);

    try testing.expectEqual(@as(u8, @intCast(padding_len)), body[0]);
    try testing.expectEqualSlices(u8, payload, try payloadOf(body[0..body_len]));
    try checkLength(@intCast(body_len), block, true, max_packet_bytes);
}

test "a packet at the bound is accepted and one block past it is refused" {
    const block: usize = 16;
    try checkLength(max_packet_bytes, block, true, max_packet_bytes);
    try testing.expectError(
        error.PacketLengthOutOfRange,
        checkLength(max_packet_bytes + @as(u32, block), block, true, max_packet_bytes),
    );
    // A caller may name a smaller bound than this module's own, and the
    // smaller one is what stands.
    try testing.expectError(
        error.PacketLengthOutOfRange,
        checkLength(1024, block, true, 512),
    );
}
