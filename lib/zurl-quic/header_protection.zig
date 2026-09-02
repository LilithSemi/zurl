//! Header protection, RFC 9001 section 5.4.
//!
//! **This is the step that hides the packet number from the path.** The
//! payload is protected first, then sixteen bytes of that ciphertext are
//! sampled, the sample goes through the header protection key, and the
//! five byte result is exclusive-ored over the low bits of the first byte
//! and over the Packet Number field.
//!
//! This file owns the sample, the two directions the mask is applied in,
//! and the bound that makes both safe. It owns no key: `protection.Keys`
//! makes the mask, and `initial.zig` makes the one key set that needs no
//! handshake.
//!
//! ## The order is the whole difficulty
//!
//! A sender knows how long its packet number is, so it protects the
//! payload, samples, masks the first byte, and masks that many bytes of
//! packet number. `apply` does that.
//!
//! A receiver knows none of it. The Packet Number Length lives in the two
//! bits header protection covers, so a receiver must unmask the first
//! byte **before** it can read how many packet number bytes to unmask.
//! `remove` does that, in that order, and returns the length it found.
//!
//! The sample is at a fixed place either way: four bytes past the start
//! of the Packet Number field, whatever the packet number length turns
//! out to be. RFC 9001 section 5.4.2 fixes it there for exactly this
//! reason.
//!
//! ## The bound
//!
//! Section 5.4.2 says an endpoint must discard a packet that is not long
//! enough to hold a whole sample. So `sample` checks `pn_offset + 4 + 16`
//! against the packet length, and every path here goes through it. A
//! packet shorter than that is `error.PacketTooShort` and nothing of it
//! is read.

const std = @import("std");

const packet = @import("packet.zig");
const protection = @import("protection.zig");

/// How many bytes of ciphertext one mask is made from. RFC 9001 section
/// 5.4.2.
pub const sample_len: usize = protection.header_sample_len;

/// How many bytes one mask holds. RFC 9001 section 5.4.1.
pub const mask_len: usize = protection.header_mask_len;

/// How far past the start of the Packet Number field the sample begins.
/// RFC 9001 section 5.4.2 fixes this at four, which is the longest a
/// packet number can be.
pub const sample_gap: usize = 4;

/// The bits of the first byte the mask covers. RFC 9001 section 5.4.1:
/// four for a long header and five for a short one, so the Key Phase bit
/// of a short header is covered as well.
pub const long_first_byte_mask: u8 = 0x0f;
pub const short_first_byte_mask: u8 = 0x1f;

/// Why header protection could not be applied or removed.
pub const Error = error{
    /// The packet is too short to hold a whole sample. RFC 9001 section
    /// 5.4.2 says an endpoint must discard such a packet.
    PacketTooShort,
};

/// The bits of the first byte the mask covers, for the form `first_byte`
/// names.
pub fn firstByteMask(first_byte: u8) u8 {
    return switch (packet.form(first_byte)) {
        .long => long_first_byte_mask,
        .short => short_first_byte_mask,
    };
}

/// The sixteen bytes one mask is made from. RFC 9001 section 5.4.2.
///
/// **This is the one bound in this file, and every path runs it.** A
/// packet that stops inside the sample is discarded whole.
pub fn sample(datagram: []const u8, pn_offset: usize) Error!*const [sample_len]u8 {
    const start = pn_offset + sample_gap;
    // The addition is on this build's own offsets and a length that
    // arrived, both far below `usize` overflow, and the comparison
    // refuses every packet that is short.
    if (start > datagram.len or datagram.len - start < sample_len) return error.PacketTooShort;
    return datagram[start..][0..sample_len];
}

/// Puts header protection on a packet this build wrote. RFC 9001 section
/// 5.4.1.
///
/// `datagram` must hold the whole packet, payload protection already
/// done. `pn_offset` is where the Packet Number field starts.
///
/// **The packet number length is read from the first byte and never
/// taken as a parameter.** A sender writes those two bits itself, before
/// header protection covers them, so the byte already carries the one
/// true answer. Taking the length a second way would let the two
/// disagree, and a packet masked over one width and unmasked over
/// another fails every tag check with nothing to say why.
pub fn apply(datagram: []u8, pn_offset: usize, keys: *const protection.Keys) Error!void {
    const mask = keys.headerMask(try sample(datagram, pn_offset));
    applyMask(datagram, pn_offset, packet.packetNumberLen(datagram[0]), mask);
}

/// Takes header protection off a packet that arrived, and returns how
/// long the Packet Number field is. RFC 9001 section 5.4.1.
///
/// **The first byte is unmasked before the length is read**, because the
/// length lives in the bits the mask covers. A reader that took the
/// length off the masked byte would unmask the wrong number of packet
/// number bytes and would then fail every tag check with no reason.
///
/// `datagram` is changed in place. On `error.PacketTooShort` nothing is
/// changed at all, because the sample is checked first.
pub fn remove(
    datagram: []u8,
    pn_offset: usize,
    keys: *const protection.Keys,
) Error!u3 {
    const mask = keys.headerMask(try sample(datagram, pn_offset));

    // The header form bit is not protected, so the width of the first
    // byte mask is readable before anything is unmasked.
    datagram[0] ^= mask[0] & firstByteMask(datagram[0]);
    const pn_len = packet.packetNumberLen(datagram[0]);

    // The Packet Number field is at most four bytes and the sample is
    // four bytes past it, so a packet that passed the sample check has
    // room for every one of them.
    for (datagram[pn_offset..][0..pn_len], mask[1..][0..pn_len]) |*byte, from| byte.* ^= from;
    return pn_len;
}

/// Exclusive-ors `mask` over the protected fields.
///
/// The same operation in both directions, which is why `remove` is
/// `apply` with the packet number length read in the middle.
fn applyMask(datagram: []u8, pn_offset: usize, pn_len: u3, mask: [mask_len]u8) void {
    datagram[0] ^= mask[0] & firstByteMask(datagram[0]);
    for (datagram[pn_offset..][0..pn_len], mask[1..][0..pn_len]) |*byte, from| byte.* ^= from;
}

const testing = std.testing;

test "the sample starts four bytes past the packet number, whatever its length" {
    // RFC 9001 section 5.4.2 fixes the gap at four so a receiver can
    // sample before it knows the packet number length.
    var datagram: [40]u8 = undefined;
    for (&datagram, 0..) |*byte, i| byte.* = @intCast(i);
    const s = try sample(&datagram, 10);
    try testing.expectEqual(@as(u8, 14), s[0]);
    try testing.expectEqual(@as(u8, 29), s[sample_len - 1]);
    try testing.expectEqual(@as(usize, 16), sample_len);
}

test "a packet with no room for a whole sample is refused" {
    // **The bound this file argues for.** Section 5.4.2 says such a
    // packet is discarded, and this is where that happens.
    var datagram: [19]u8 = @splat(0);
    // 0 + 4 + 16 is 20, and 19 bytes arrived.
    try testing.expectError(error.PacketTooShort, sample(&datagram, 0));
    var enough: [20]u8 = @splat(0);
    _ = try sample(&enough, 0);
    // An offset past the end of the datagram is refused and never wraps.
    try testing.expectError(error.PacketTooShort, sample(&enough, 100));
}

test "the mask covers four bits of a long header first byte and five of a short one" {
    // RFC 9001 section 5.4.1. The extra bit of a short header is the Key
    // Phase, which must not be readable on the path.
    try testing.expectEqual(@as(u8, 0x0f), firstByteMask(0xc3));
    try testing.expectEqual(@as(u8, 0x1f), firstByteMask(0x42));
    try testing.expectEqual(@as(u8, 0x0f), long_first_byte_mask);
    try testing.expectEqual(@as(u8, 0x1f), short_first_byte_mask);
}

test "apply and remove are each other's opposite on a long header" {
    const secret: [32]u8 = @splat(0x11);
    const keys: protection.Keys = .fromSecret(.aes_128_gcm, &secret);

    // A long header Initial with a 4-byte packet number at offset 18.
    var datagram: [64]u8 = undefined;
    for (&datagram, 0..) |*byte, i| byte.* = @intCast(i);
    // 0xc3 is an Initial packet with a 4-byte packet number.
    datagram[0] = 0xc3;
    const original = datagram;

    try apply(&datagram, 18, &keys);
    // The bits outside the mask are untouched, so the form and the type
    // still read the same on the path.
    try testing.expectEqual(original[0] & 0xf0, datagram[0] & 0xf0);
    try testing.expect(!std.mem.eql(u8, &original, &datagram));

    try testing.expectEqual(@as(u3, 4), try remove(&datagram, 18, &keys));
    try testing.expectEqualSlices(u8, &original, &datagram);
}

test "apply and remove are each other's opposite on a short header" {
    const secret: [32]u8 = @splat(0x22);
    const keys: protection.Keys = .fromSecret(.chacha20_poly1305, &secret);

    var datagram: [64]u8 = undefined;
    for (&datagram, 0..) |*byte, i| byte.* = @intCast(i);
    // A short header with the Key Phase set and a 3-byte packet number.
    datagram[0] = 0x46;
    const original = datagram;

    try apply(&datagram, 5, &keys);
    // The five low bits are covered, the three high ones are not.
    try testing.expectEqual(original[0] & 0xe0, datagram[0] & 0xe0);

    try testing.expectEqual(@as(u3, 3), try remove(&datagram, 5, &keys));
    try testing.expectEqualSlices(u8, &original, &datagram);
}

test "removing protection from a packet with no sample changes nothing" {
    // The sample is checked before anything is written, so a refused
    // packet is left exactly as it arrived.
    const secret: [32]u8 = @splat(0x33);
    const keys: protection.Keys = .fromSecret(.aes_128_gcm, &secret);
    var datagram: [10]u8 = .{ 0xc3, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    const original = datagram;
    try testing.expectError(error.PacketTooShort, remove(&datagram, 1, &keys));
    try testing.expectEqualSlices(u8, &original, &datagram);
}

test "each packet number length unmasks the bytes it names and no more" {
    // A receiver reads the length off the unmasked first byte, so each of
    // the four widths must come back with the bytes after it untouched.
    const secret: [32]u8 = @splat(0x44);
    const keys: protection.Keys = .fromSecret(.aes_128_gcm, &secret);
    var width: u3 = 1;
    while (width <= 4) : (width += 1) {
        var datagram: [64]u8 = undefined;
        for (&datagram, 0..) |*byte, i| byte.* = @intCast(i);
        datagram[0] = 0xc0 | @as(u8, width - 1);
        const original = datagram;

        try apply(&datagram, 18, &keys);
        // Only the first byte and `width` packet number bytes changed.
        const after: usize = 18 + @as(usize, width);
        try testing.expectEqualSlices(u8, original[1..18], datagram[1..18]);
        try testing.expectEqualSlices(u8, original[after..], datagram[after..]);

        try testing.expectEqual(width, try remove(&datagram, 18, &keys));
        try testing.expectEqualSlices(u8, &original, &datagram);
    }
}
