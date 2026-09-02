//! Packet protection, RFC 9001 section 5.
//!
//! **This file holds the shape a QUIC key set has, and the TLS task fills
//! it in.** QUIC protects each packet with an AEAD, and the AEAD's key,
//! IV, and header protection key all come from one TLS 1.3 secret through
//! HKDF-Expand-Label. This file owns that derivation and the three cipher
//! suites TLS 1.3 gives QUIC. It owns no handshake, so it produces no
//! secret of its own.
//!
//! ## What the TLS task adds, and what it does not have to write
//!
//! A caller with a TLS secret writes one line:
//!
//!     const keys: Keys = .fromSecret(.aes_128_gcm, secret);
//!
//! and gets `seal`, `open`, and `headerMask`. So the TLS task installs
//! **secrets** and never machinery. It needs to add:
//!
//! - the four `Level` values wired to the TLS handshake, so a secret
//!   arriving from TLS lands at the right one,
//! - the suite TLS negotiated, which is one of the three `Suite` names,
//! - `nextSecret` at a key update, which is already here.
//!
//! `initial.zig` already fills `Level.initial` in both directions, with
//! no handshake at all, because RFC 9001 section 5.2 derives those keys
//! from the client's first connection id.
//!
//! ## The two rules a reader should know
//!
//! **A nonce is the IV exclusive-ored with the packet number.** RFC 9001
//! section 5.3 writes the 62-bit packet number into the low bytes of a
//! 12-byte field and exclusive-ors that with the IV. So one key never
//! sees one nonce twice, as long as one packet number is never used
//! twice. That last part belongs to the sender above this file.
//!
//! **The associated data is the whole header.** Section 5.3 makes the
//! associated data every byte from the first one to the end of the
//! Packet Number field. So a middle box that changes a connection id
//! breaks the tag, and a receiver that authenticated the payload has
//! authenticated the header with it.

const std = @import("std");

const hkdf = std.crypto.kdf.hkdf;
const HkdfSha256 = hkdf.HkdfSha256;
const HkdfSha384 = hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384);

/// The hash under a cipher suite's key schedule.
pub const Hash = enum {
    sha256,
    sha384,

    /// How many bytes a secret of this hash takes.
    pub fn secretLen(self: Hash) usize {
        return switch (self) {
            .sha256 => 32,
            .sha384 => 48,
        };
    }
};

/// The longest secret any suite here uses. SHA-384 is the long one.
pub const max_secret_len: usize = 48;

/// The longest packet protection key any suite here uses.
pub const max_key_len: usize = 32;

/// How many bytes a packet protection IV takes. RFC 9001 section 5.1.
pub const iv_len: usize = 12;

/// How many bytes an AEAD tag takes. Every suite QUIC uses has a 16-byte
/// tag. RFC 9001 section 5.3.
pub const tag_len: usize = 16;

/// The longest label `expandLabel` accepts. Every QUIC label is far
/// shorter, and the bound keeps the info buffer on the stack.
pub const max_label_len: usize = 32;

/// HKDF-Expand-Label of TLS 1.3, RFC 8446 section 7.1, with the empty
/// context QUIC always uses.
///
/// The info is a two byte output length, a one byte label length, the six
/// bytes `tls13 ` with the label after them, and a one byte context
/// length of zero. RFC 9001 appendix A.1 prints the five QUIC labels in
/// exactly this form, and `initial.zig` checks against those bytes.
///
/// `secret` must be the length its hash names, and `label` must be at or
/// below `max_label_len`. Both are this build's own values, so both are
/// asserts and not returned errors.
pub fn expandLabel(hash: Hash, secret: []const u8, label: []const u8, out: []u8) void {
    std.debug.assert(secret.len == hash.secretLen());
    std.debug.assert(label.len <= max_label_len);
    std.debug.assert(out.len > 0);

    var info: [4 + "tls13 ".len + max_label_len]u8 = undefined;
    const written = buildHkdfLabel(&info, label, out.len);
    switch (hash) {
        .sha256 => HkdfSha256.expand(out, written, secret[0..32].*),
        .sha384 => HkdfSha384.expand(out, written, secret[0..48].*),
    }
}

/// Writes the `HkdfLabel` structure of RFC 8446 section 7.1 into `info`.
fn buildHkdfLabel(info: *[4 + "tls13 ".len + max_label_len]u8, label: []const u8, out_len: usize) []const u8 {
    // The length field is 16 bits, so an output above 65535 has no
    // structure at all. Nothing here asks for one.
    std.debug.assert(out_len <= std.math.maxInt(u16));
    std.mem.writeInt(u16, info[0..2], @intCast(out_len), .big);
    info[2] = @intCast("tls13 ".len + label.len);
    @memcpy(info[3..][0.."tls13 ".len], "tls13 ");
    @memcpy(info[3 + "tls13 ".len ..][0..label.len], label);
    // The context is empty for every QUIC label.
    const end = 3 + "tls13 ".len + label.len;
    info[end] = 0;
    return info[0 .. end + 1];
}

/// The AEAD algorithms TLS 1.3 gives QUIC. RFC 9001 sections 5.3 and
/// 5.4.3 and 5.4.4.
///
/// `TLS_AES_128_CCM_SHA256` is left out on purpose: RFC 9001 section
/// 5.4.1 defines no header protection for `TLS_AES_128_CCM_8_SHA256`,
/// and nothing this build talks to negotiates the CCM suites.
pub const Suite = enum {
    /// `TLS_AES_128_GCM_SHA256`. The suite an Initial packet always uses.
    aes_128_gcm,
    /// `TLS_AES_256_GCM_SHA384`.
    aes_256_gcm,
    /// `TLS_CHACHA20_POLY1305_SHA256`.
    chacha20_poly1305,

    /// The hash under this suite's key schedule.
    pub fn hash(self: Suite) Hash {
        return switch (self) {
            .aes_128_gcm, .chacha20_poly1305 => .sha256,
            .aes_256_gcm => .sha384,
        };
    }

    /// How many bytes the packet protection key takes.
    pub fn keyLen(self: Suite) usize {
        return switch (self) {
            .aes_128_gcm => 16,
            .aes_256_gcm, .chacha20_poly1305 => 32,
        };
    }

    /// How many bytes the header protection key takes. RFC 9001 sections
    /// 5.4.3 and 5.4.4 make it the same width as the packet key.
    pub fn headerKeyLen(self: Suite) usize {
        return self.keyLen();
    }
};

/// The four points in a connection where a different key set applies.
/// RFC 9001 section 4.1.
///
/// **The TLS task wires three of these.** `initial.zig` fills the first
/// with no handshake at all.
pub const Level = enum {
    initial,
    zero_rtt,
    handshake,
    application,

    /// The long header type that carries a packet at this level, or null
    /// for the application level, which uses the short header.
    pub fn longType(self: Level) ?@import("packet.zig").LongType {
        return switch (self) {
            .initial => .initial,
            .zero_rtt => .zero_rtt,
            .handshake => .handshake,
            .application => null,
        };
    }
};

/// Why a packet could not be opened.
pub const OpenError = error{
    /// The tag did not match. The packet was changed on the way, or it
    /// was not written with this key. RFC 9001 section 5.3 says a
    /// receiver discards such a packet and does not close the connection.
    AuthenticationFailed,
    /// The packet is shorter than an AEAD tag, so it cannot hold one.
    PacketTooShort,
    /// The output buffer has no room for the plaintext.
    NoRoom,
};

/// One key set: an AEAD suite, a packet protection key, an IV, and a
/// header protection key. RFC 9001 section 5.1.
///
/// Held by value and never by pointer, so a caller can keep one across a
/// key update without any lifetime question.
pub const Keys = struct {
    suite: Suite,
    /// The first `suite.keyLen()` bytes are the key. The rest are zero.
    key: [max_key_len]u8,
    iv: [iv_len]u8,
    /// The first `suite.headerKeyLen()` bytes are the key.
    hp: [max_key_len]u8,

    /// The five labels of RFC 9001 section 5.1.
    pub const key_label = "quic key";
    pub const iv_label = "quic iv";
    pub const header_label = "quic hp";
    pub const update_label = "quic ku";

    /// Derives a key set from one TLS secret. RFC 9001 section 5.1.
    ///
    /// **This is the one call the TLS task makes.** It hands over the
    /// secret TLS produced for a level and a direction, and gets back
    /// everything this package needs to protect and unprotect packets at
    /// that level.
    pub fn fromSecret(suite: Suite, secret: []const u8) Keys {
        std.debug.assert(secret.len == suite.hash().secretLen());
        var out: Keys = .{
            .suite = suite,
            .key = @splat(0),
            .iv = @splat(0),
            .hp = @splat(0),
        };
        expandLabel(suite.hash(), secret, key_label, out.key[0..suite.keyLen()]);
        expandLabel(suite.hash(), secret, iv_label, &out.iv);
        expandLabel(suite.hash(), secret, header_label, out.hp[0..suite.headerKeyLen()]);
        return out;
    }

    /// The secret that follows `secret` after a key update. RFC 9001
    /// section 6.
    ///
    /// Left here and unused, because a key update belongs to the
    /// connection engine above and the derivation belongs with the other
    /// four labels.
    pub fn nextSecret(suite: Suite, secret: []const u8, out: []u8) void {
        std.debug.assert(out.len == suite.hash().secretLen());
        expandLabel(suite.hash(), secret, update_label, out);
    }

    /// The packet protection key.
    pub fn keySlice(self: *const Keys) []const u8 {
        return self.key[0..self.suite.keyLen()];
    }

    /// The header protection key.
    pub fn headerKeySlice(self: *const Keys) []const u8 {
        return self.hp[0..self.suite.headerKeyLen()];
    }

    /// The nonce for one packet number. RFC 9001 section 5.3.
    ///
    /// The packet number is written into the low bytes of a 12-byte field
    /// and exclusive-ored with the IV. So the whole IV changes with every
    /// packet, and the low eight bytes change the most.
    pub fn nonce(self: *const Keys, packet_number: u64) [iv_len]u8 {
        var out = self.iv;
        var number: [8]u8 = undefined;
        std.mem.writeInt(u64, &number, packet_number, .big);
        for (out[iv_len - 8 ..], number) |*byte, from| byte.* ^= from;
        return out;
    }

    /// How many bytes `seal` writes for a payload of `plaintext_len`.
    pub fn sealedLen(plaintext_len: usize) usize {
        return plaintext_len + tag_len;
    }

    /// Protects one packet payload. RFC 9001 section 5.3.
    ///
    /// `out` takes the ciphertext and the tag, so it must be
    /// `plaintext.len + tag_len` bytes. `aad` is the packet header, from
    /// the first byte to the end of the Packet Number field.
    pub fn seal(
        self: *const Keys,
        out: []u8,
        plaintext: []const u8,
        aad: []const u8,
        packet_number: u64,
    ) void {
        std.debug.assert(out.len == sealedLen(plaintext.len));
        const npub = self.nonce(packet_number);
        const body = out[0..plaintext.len];
        const tag = out[plaintext.len..][0..tag_len];
        switch (self.suite) {
            .aes_128_gcm => std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(
                body,
                tag,
                plaintext,
                aad,
                npub,
                self.key[0..16].*,
            ),
            .aes_256_gcm => std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(
                body,
                tag,
                plaintext,
                aad,
                npub,
                self.key[0..32].*,
            ),
            .chacha20_poly1305 => std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
                body,
                tag,
                plaintext,
                aad,
                npub,
                self.key[0..32].*,
            ),
        }
    }

    /// Unprotects one packet payload, and returns how many bytes it
    /// wrote into `out`.
    ///
    /// **A packet shorter than a tag cannot hold one**, and a peer can
    /// send one. That is `error.PacketTooShort` and not a wrap on the
    /// subtraction below.
    pub fn open(
        self: *const Keys,
        out: []u8,
        sealed: []const u8,
        aad: []const u8,
        packet_number: u64,
    ) OpenError!usize {
        if (sealed.len < tag_len) return error.PacketTooShort;
        const body_len = sealed.len - tag_len;
        if (out.len < body_len) return error.NoRoom;

        const npub = self.nonce(packet_number);
        const body = sealed[0..body_len];
        const tag: [tag_len]u8 = sealed[body_len..][0..tag_len].*;
        const plain = out[0..body_len];

        switch (self.suite) {
            .aes_128_gcm => std.crypto.aead.aes_gcm.Aes128Gcm.decrypt(
                plain,
                body,
                tag,
                aad,
                npub,
                self.key[0..16].*,
            ) catch return error.AuthenticationFailed,
            .aes_256_gcm => std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(
                plain,
                body,
                tag,
                aad,
                npub,
                self.key[0..32].*,
            ) catch return error.AuthenticationFailed,
            .chacha20_poly1305 => std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
                plain,
                body,
                tag,
                aad,
                npub,
                self.key[0..32].*,
            ) catch return error.AuthenticationFailed,
        }
        return body_len;
    }

    /// The five byte header protection mask for one sample. RFC 9001
    /// sections 5.4.3 and 5.4.4.
    ///
    /// AES takes the sample as one block through the block cipher. ChaCha
    /// takes the first four bytes as a little-endian counter and the
    /// other twelve as a nonce, and encrypts five zero bytes.
    pub fn headerMask(self: *const Keys, sample: *const [header_sample_len]u8) [header_mask_len]u8 {
        var mask: [header_mask_len]u8 = undefined;
        switch (self.suite) {
            .aes_128_gcm => {
                var block: [16]u8 = undefined;
                std.crypto.core.aes.Aes128.initEnc(self.hp[0..16].*).encrypt(&block, sample);
                @memcpy(&mask, block[0..header_mask_len]);
            },
            .aes_256_gcm => {
                var block: [16]u8 = undefined;
                std.crypto.core.aes.Aes256.initEnc(self.hp[0..32].*).encrypt(&block, sample);
                @memcpy(&mask, block[0..header_mask_len]);
            },
            .chacha20_poly1305 => {
                const counter = std.mem.readInt(u32, sample[0..4], .little);
                const zeros: [header_mask_len]u8 = @splat(0);
                std.crypto.stream.chacha.ChaCha20IETF.xor(
                    &mask,
                    &zeros,
                    counter,
                    self.hp[0..32].*,
                    sample[4..16].*,
                );
            },
        }
        return mask;
    }
};

/// How many bytes of ciphertext a header protection mask is made from.
/// RFC 9001 section 5.4.2.
pub const header_sample_len: usize = 16;

/// How many bytes one header protection mask holds. RFC 9001 section
/// 5.4.1: one for the first byte and four for the packet number.
pub const header_mask_len: usize = 5;

const testing = std.testing;

test "the five HKDF labels of RFC 9001 appendix A.1 build byte for byte" {
    // **The appendix prints the info each label makes.** These are the
    // exact bytes HKDF-Expand is given, so a wrong one changes every key
    // under it.
    const cases = [_]struct { label: []const u8, out_len: usize, info: []const u8 }{
        .{
            .label = "client in",
            .out_len = 32,
            .info = &.{ 0x00, 0x20, 0x0f, 't', 'l', 's', '1', '3', ' ', 'c', 'l', 'i', 'e', 'n', 't', ' ', 'i', 'n', 0x00 },
        },
        .{
            .label = "server in",
            .out_len = 32,
            .info = &.{ 0x00, 0x20, 0x0f, 't', 'l', 's', '1', '3', ' ', 's', 'e', 'r', 'v', 'e', 'r', ' ', 'i', 'n', 0x00 },
        },
        .{
            .label = "quic key",
            .out_len = 16,
            .info = &.{ 0x00, 0x10, 0x0e, 't', 'l', 's', '1', '3', ' ', 'q', 'u', 'i', 'c', ' ', 'k', 'e', 'y', 0x00 },
        },
        .{
            .label = "quic iv",
            .out_len = 12,
            .info = &.{ 0x00, 0x0c, 0x0d, 't', 'l', 's', '1', '3', ' ', 'q', 'u', 'i', 'c', ' ', 'i', 'v', 0x00 },
        },
        .{
            .label = "quic hp",
            .out_len = 16,
            .info = &.{ 0x00, 0x10, 0x0d, 't', 'l', 's', '1', '3', ' ', 'q', 'u', 'i', 'c', ' ', 'h', 'p', 0x00 },
        },
    };
    for (cases) |case| {
        var info: [4 + "tls13 ".len + max_label_len]u8 = undefined;
        try testing.expectEqualSlices(u8, case.info, buildHkdfLabel(&info, case.label, case.out_len));
    }
}

test "the nonce is the IV with the packet number exclusive-ored into its low bytes" {
    // RFC 9001 section 5.3. A packet number of zero leaves the IV alone,
    // and a larger one changes only the low bytes.
    var keys: Keys = .{
        .suite = .aes_128_gcm,
        .key = @splat(0),
        .iv = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 },
        .hp = @splat(0),
    };
    try testing.expectEqualSlices(u8, &keys.iv, &keys.nonce(0));
    try testing.expectEqualSlices(
        u8,
        &.{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13 },
        &keys.nonce(1),
    );
    // The number is 62 bits wide, so the top four of the twelve bytes are
    // never touched.
    const big = keys.nonce((1 << 62) - 1);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, big[0..4]);
    try testing.expectEqual(@as(u8, 5 ^ 0x3f), big[4]);
}

test "the ChaCha20-Poly1305 short header packet of RFC 9001 appendix A.5" {
    // **The appendix's own vector, and the only one for a suite other
    // than AES-128-GCM.** The secret is given, and the four values under
    // it must match byte for byte.
    const secret = [_]u8{
        0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e, 0xbe, 0x69, 0x42, 0x27, 0x48, 0xad, 0x00, 0xa1,
        0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0, 0x7d, 0x60, 0x60, 0xf6, 0x88, 0xf3, 0x0f, 0x21, 0x63, 0x2b,
    };
    const keys: Keys = .fromSecret(.chacha20_poly1305, &secret);
    try expectHex(
        "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8",
        keys.keySlice(),
    );
    try expectHex("e0459b3474bdd0e44a41c144", &keys.iv);
    try expectHex(
        "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
        keys.headerKeySlice(),
    );

    var ku: [32]u8 = undefined;
    Keys.nextSecret(.chacha20_poly1305, &secret, &ku);
    try expectHex("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9", &ku);

    // The packet number is 654 360 564, and the nonce the appendix names
    // follows from the IV.
    const pn: u64 = 654_360_564;
    try expectHex("e0459b3474bdd0e46d417eb0", &keys.nonce(pn));

    // The unprotected header is `4200bff4` and the payload is one PING.
    const header = [_]u8{ 0x42, 0x00, 0xbf, 0xf4 };
    var sealed: [1 + tag_len]u8 = undefined;
    keys.seal(&sealed, &.{0x01}, &header, pn);
    try expectHex("655e5cd55c41f69080575d7999c25a5bfb", &sealed);

    // One byte is skipped to make the sample, because the packet number
    // is three bytes and the sample starts four bytes after the header.
    const sample = sealed[1..][0..header_sample_len];
    try expectHex("5e5cd55c41f69080575d7999c25a5bfb", sample);
    try expectHex("aefefe7d03", &keys.headerMask(sample));

    // And the packet opens again with the same key.
    var plain: [1]u8 = undefined;
    try testing.expectEqual(@as(usize, 1), try keys.open(&plain, &sealed, &header, pn));
    try testing.expectEqual(@as(u8, 0x01), plain[0]);
}

test "a packet whose tag was changed does not open" {
    // RFC 9001 section 5.3: a receiver discards such a packet. This is
    // the check that makes a changed packet unusable rather than a
    // packet this build reads and trusts.
    const secret: [32]u8 = @splat(0x42);
    const keys: Keys = .fromSecret(.aes_128_gcm, &secret);
    const header = [_]u8{ 0x42, 0x00, 0x00, 0x01 };

    var sealed: [4 + tag_len]u8 = undefined;
    keys.seal(&sealed, "abcd", &header, 1);

    var plain: [4]u8 = undefined;
    try testing.expectEqual(@as(usize, 4), try keys.open(&plain, &sealed, &header, 1));
    try testing.expectEqualStrings("abcd", &plain);

    // One bit of the tag.
    var broken = sealed;
    broken[broken.len - 1] ^= 0x01;
    try testing.expectError(error.AuthenticationFailed, keys.open(&plain, &broken, &header, 1));

    // One bit of the header, which is the associated data. This is why a
    // middle box cannot change a connection id.
    var other_header = header;
    other_header[1] ^= 0x01;
    try testing.expectError(error.AuthenticationFailed, keys.open(&plain, &sealed, &other_header, 1));

    // And the wrong packet number, which changes the nonce.
    try testing.expectError(error.AuthenticationFailed, keys.open(&plain, &sealed, &header, 2));
}

test "a packet shorter than a tag is refused rather than subtracted" {
    // **The bound on the one subtraction in `open`.** A peer sends a
    // packet with no room for a tag, and a reader with no check here
    // would wrap the length.
    const secret: [32]u8 = @splat(0x42);
    const keys: Keys = .fromSecret(.aes_128_gcm, &secret);
    var plain: [64]u8 = undefined;
    try testing.expectError(error.PacketTooShort, keys.open(&plain, &.{}, &.{}, 0));
    try testing.expectError(error.PacketTooShort, keys.open(&plain, &([_]u8{0} ** 15), &.{}, 0));
    // And an output with no room says so rather than writing past it.
    var small: [1]u8 = undefined;
    try testing.expectError(error.NoRoom, keys.open(&small, &([_]u8{0} ** 20), &.{}, 0));
}

test "each suite names its hash and the width of its two keys" {
    try testing.expectEqual(Hash.sha256, Suite.aes_128_gcm.hash());
    try testing.expectEqual(@as(usize, 16), Suite.aes_128_gcm.keyLen());
    try testing.expectEqual(@as(usize, 16), Suite.aes_128_gcm.headerKeyLen());

    try testing.expectEqual(Hash.sha384, Suite.aes_256_gcm.hash());
    try testing.expectEqual(@as(usize, 32), Suite.aes_256_gcm.keyLen());
    try testing.expectEqual(@as(usize, 48), Hash.sha384.secretLen());

    try testing.expectEqual(Hash.sha256, Suite.chacha20_poly1305.hash());
    try testing.expectEqual(@as(usize, 32), Suite.chacha20_poly1305.keyLen());
    try testing.expectEqual(@as(usize, 32), Hash.sha256.secretLen());
}

test "an AES-256-GCM key set seals and opens with a SHA-384 secret" {
    // The one suite whose secret is 48 bytes. A derivation that used the
    // wrong hash here would still produce keys and would not interoperate.
    const secret: [48]u8 = @splat(0x5a);
    const keys: Keys = .fromSecret(.aes_256_gcm, &secret);
    try testing.expectEqual(@as(usize, 32), keys.keySlice().len);

    const header = [_]u8{ 0xc3, 0x00, 0x00, 0x00, 0x01 };
    var sealed: [5 + tag_len]u8 = undefined;
    keys.seal(&sealed, "hello", &header, 7);
    var plain: [5]u8 = undefined;
    try testing.expectEqual(@as(usize, 5), try keys.open(&plain, &sealed, &header, 7));
    try testing.expectEqualStrings("hello", &plain);

    // And the mask comes off a 16 byte sample, whatever the suite.
    const sample: [header_sample_len]u8 = @splat(0x11);
    try testing.expectEqual(@as(usize, 5), keys.headerMask(&sample).len);
}

test "the four levels name the long header type that carries them" {
    const p = @import("packet.zig");
    try testing.expectEqual(p.LongType.initial, Level.initial.longType().?);
    try testing.expectEqual(p.LongType.zero_rtt, Level.zero_rtt.longType().?);
    try testing.expectEqual(p.LongType.handshake, Level.handshake.longType().?);
    // The application level uses the short header, which has no type.
    try testing.expectEqual(@as(?p.LongType, null), Level.application.longType());
}

/// Checks `bytes` against a lowercase hexadecimal string.
fn expectHex(expected: []const u8, bytes: []const u8) !void {
    var buffer: [256]u8 = undefined;
    std.debug.assert(bytes.len * 2 <= buffer.len);
    const got = std.fmt.bufPrint(&buffer, "{x}", .{bytes}) catch unreachable;
    try testing.expectEqualStrings(expected, got);
}
