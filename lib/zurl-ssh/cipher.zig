//! The two packet ciphers this build speaks, and the framing each one
//! puts around a packet.
//!
//! Both are AEAD, so **the MAC is implicit**. Neither negotiates a
//! separate MAC algorithm, and `zurl_ssh.algorithms` therefore offers no
//! MAC name at all. RFC 4253 section 6.4 describes a separate MAC, and an
//! AEAD replaces it.
//!
//! **`chacha20-poly1305@openssh.com`.** OpenSSH's `PROTOCOL.chacha20poly1305`
//! defines it. It takes 512 bits of key material and splits them into two
//! 256-bit keys:
//!
//! - `K_2` is the **first** 32 bytes. It keys the payload and the
//!   Poly1305 key.
//! - `K_1` is the **second** 32 bytes. It keys the packet length field,
//!   and nothing else.
//!
//! That order is the part that is easy to get wrong, and a client that
//! swapped the two would produce a length no server can read. See
//! `chachaLengthKey` and `chachaMainKey`, which are the one place the
//! split happens, and the test that pins each half against a keystream
//! computed on its own.
//!
//! The nonce of both ChaCha20 instances is the packet sequence number, as
//! a 64-bit big-endian value. The length field uses block counter 0. The
//! Poly1305 key is the first 32 bytes of the block at counter 0 under
//! `K_2`, and the payload starts at counter 1. The tag covers the
//! encrypted length and the encrypted payload, in that order.
//!
//! **`aes256-gcm@openssh.com`.** RFC 5647 section 7.1 describes the
//! framing and OpenSSH's `PROTOCOL` keeps it. The four length bytes go on
//! the wire in the clear and are authenticated as associated data. The
//! nonce is 12 bytes: 4 fixed bytes from the key exchange, then a 64-bit
//! invocation counter that starts at the value the key exchange gave and
//! goes up by one for each packet.
//!
//! **The tag is checked before the payload is decrypted**, in both. The
//! comparison is `std.crypto.timing_safe.eql`, inside the two standard
//! library primitives this module calls. A reader that decrypted first
//! would act on bytes a peer chose.
//!
//! What this module does not own: it derives no key and it frames no
//! packet. `zurl_ssh.kex` derives, and `zurl_ssh.packet` frames.

const std = @import("std");

const packet = @import("packet.zig");

const ChaCha20 = std.crypto.stream.chacha.ChaCha20With64BitNonce;
const Poly1305 = std.crypto.onetimeauth.Poly1305;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

/// The packet ciphers this build speaks.
pub const Algorithm = enum {
    chacha20_poly1305_openssh,
    aes256_gcm_openssh,
};

/// The tag both ciphers write, in bytes.
pub const tag_bytes: usize = 16;

/// The largest key any of these ciphers takes.
pub const max_key_bytes: usize = 64;

/// The largest initialisation vector any of these ciphers takes.
pub const max_iv_bytes: usize = 12;

/// The name of `a` on the wire.
pub fn name(a: Algorithm) []const u8 {
    return switch (a) {
        .chacha20_poly1305_openssh => "chacha20-poly1305@openssh.com",
        .aes256_gcm_openssh => "aes256-gcm@openssh.com",
    };
}

/// The algorithm `text` names, or null.
pub fn fromName(text: []const u8) ?Algorithm {
    inline for (@typeInfo(Algorithm).@"enum".fields) |field| {
        const candidate: Algorithm = @enumFromInt(field.value);
        if (std.mem.eql(u8, text, name(candidate))) return candidate;
    }
    return null;
}

/// How many bytes of key material `a` takes.
pub fn keyBytes(a: Algorithm) usize {
    return switch (a) {
        .chacha20_poly1305_openssh => 64,
        .aes256_gcm_openssh => 32,
    };
}

/// How many bytes of initialisation vector `a` takes.
pub fn ivBytes(a: Algorithm) usize {
    return switch (a) {
        .chacha20_poly1305_openssh => 0,
        .aes256_gcm_openssh => Aes256Gcm.nonce_length,
    };
}

/// The block size a packet of `a` lines up with, RFC 4253 section 6.
///
/// ChaCha20 is a stream cipher with no block to line up with, and
/// OpenSSH still lines its packets up on 8, which is the floor RFC 4253
/// sets. AES has a 16 byte block.
pub fn blockBytes(a: Algorithm) usize {
    return switch (a) {
        .chacha20_poly1305_openssh => 8,
        .aes256_gcm_openssh => 16,
    };
}

/// Whether the four length bytes stay outside the padded run.
///
/// True for both of these ciphers. See `zurl_ssh.packet` for what the
/// answer changes.
pub fn lengthIsAad(a: Algorithm) bool {
    return switch (a) {
        .chacha20_poly1305_openssh, .aes256_gcm_openssh => true,
    };
}

/// Whether the four length bytes go on the wire encrypted.
///
/// True for `chacha20-poly1305@openssh.com`, which encrypts them under a
/// key of their own. False for `aes256-gcm@openssh.com`, which leaves
/// them in the clear and authenticates them.
pub fn lengthIsEncrypted(a: Algorithm) bool {
    return switch (a) {
        .chacha20_poly1305_openssh => true,
        .aes256_gcm_openssh => false,
    };
}

/// Why a packet did not open.
pub const AuthError = error{
    /// The tag does not match. The packet was changed on the way, or it
    /// was never sealed with this key. Either one ends the session: a
    /// peer that cannot authenticate one packet cannot be trusted for the
    /// next.
    AuthenticationFailed,
};

/// One direction of one connection: a key, an initialisation vector, and
/// the framing rules of one algorithm.
///
/// Two of these run at once. `zurl_ssh.Transport` keeps one for what it
/// sends and one for what it reads, because the key exchange gives a
/// different key to each direction.
pub const State = struct {
    algorithm: Algorithm,
    key: [max_key_bytes]u8,
    /// The nonce of `aes256-gcm@openssh.com`, which goes up by one for
    /// each packet. Unused by the other algorithm.
    iv: [max_iv_bytes]u8,

    /// Takes the key material the key exchange produced.
    ///
    /// The lengths are what `keyBytes` and `ivBytes` say, and a caller
    /// that passes another length has a bug in its own key derivation, so
    /// both are asserts.
    pub fn init(algorithm: Algorithm, key: []const u8, iv: []const u8) State {
        std.debug.assert(key.len == keyBytes(algorithm));
        std.debug.assert(iv.len == ivBytes(algorithm));
        var s: State = .{
            .algorithm = algorithm,
            .key = @splat(0),
            .iv = @splat(0),
        };
        @memcpy(s.key[0..key.len], key);
        @memcpy(s.iv[0..iv.len], iv);
        return s;
    }

    /// Wipes the key material.
    ///
    /// A rekey replaces a `State`, and the one it replaces held the key
    /// of every packet before it. Leaving that in memory gives an attacker
    /// who reads this process later everything the old key protected.
    pub fn deinit(s: *State) void {
        std.crypto.secureZero(u8, &s.key);
        std.crypto.secureZero(u8, &s.iv);
    }

    /// The block size this direction lines packets up on.
    pub fn block(s: *const State) usize {
        return blockBytes(s.algorithm);
    }

    /// Seals one packet in place.
    ///
    /// `frame` is the four length bytes and then the body, which is
    /// `padding_length`, the payload, and the padding. On return `frame`
    /// holds what goes on the wire and `tag` holds the tag that follows
    /// it.
    ///
    /// `sequence` is the packet sequence number, which RFC 4253
    /// section 6.4 counts from zero and which never goes on the wire.
    pub fn seal(s: *State, sequence: u32, frame: []u8, tag: *[tag_bytes]u8) void {
        std.debug.assert(frame.len >= 4);
        switch (s.algorithm) {
            .chacha20_poly1305_openssh => {
                const nonce = chachaNonce(sequence);
                const length_key = chachaLengthKey(&s.key);
                const main_key = chachaMainKey(&s.key);

                ChaCha20.xor(frame[0..4], frame[0..4], 0, length_key, nonce);

                var poly_key: [Poly1305.key_length]u8 = undefined;
                defer std.crypto.secureZero(u8, &poly_key);
                ChaCha20.stream(&poly_key, 0, main_key, nonce);

                ChaCha20.xor(frame[4..], frame[4..], 1, main_key, nonce);
                Poly1305.create(tag, frame, &poly_key);
            },
            .aes256_gcm_openssh => {
                const nonce = s.iv[0..Aes256Gcm.nonce_length].*;
                Aes256Gcm.encrypt(
                    frame[4..],
                    tag,
                    frame[4..],
                    frame[0..4],
                    nonce,
                    s.key[0..Aes256Gcm.key_length].*,
                );
                s.advanceIv();
            },
        }
    }

    /// Turns the four length bytes off the wire into `packet_length`.
    ///
    /// **This runs before the tag is known**, and it must: the length
    /// says how many more bytes to read, and the tag comes after those
    /// bytes. So the value this returns is unauthenticated, and the
    /// caller must check it against `zurl_ssh.packet.checkLength` before
    /// it waits for one byte of the body. Nothing else may act on it.
    ///
    /// `on_wire` is left as it arrived, because the tag covers those four
    /// bytes in the form the peer wrote them.
    pub fn readLength(s: *const State, sequence: u32, on_wire: [4]u8) u32 {
        switch (s.algorithm) {
            .chacha20_poly1305_openssh => {
                var plain: [4]u8 = undefined;
                ChaCha20.xor(&plain, &on_wire, 0, chachaLengthKey(&s.key), chachaNonce(sequence));
                return std.mem.readInt(u32, &plain, .big);
            },
            .aes256_gcm_openssh => return std.mem.readInt(u32, &on_wire, .big),
        }
    }

    /// Opens one packet in place.
    ///
    /// `frame` is the four length bytes as they arrived and then the
    /// body, and `tag` is the tag that followed them. On success
    /// `frame[4..]` holds the plaintext body. On failure nothing in
    /// `frame` may be used.
    ///
    /// **The tag is checked first, in both algorithms.** The plaintext
    /// only appears after the check passes.
    pub fn open(s: *State, sequence: u32, frame: []u8, tag: [tag_bytes]u8) AuthError!void {
        std.debug.assert(frame.len >= 4);
        switch (s.algorithm) {
            .chacha20_poly1305_openssh => {
                const nonce = chachaNonce(sequence);
                const main_key = chachaMainKey(&s.key);

                var poly_key: [Poly1305.key_length]u8 = undefined;
                defer std.crypto.secureZero(u8, &poly_key);
                ChaCha20.stream(&poly_key, 0, main_key, nonce);

                var expected: [Poly1305.mac_length]u8 = undefined;
                Poly1305.create(&expected, frame, &poly_key);
                if (!std.crypto.timing_safe.eql([tag_bytes]u8, expected, tag)) {
                    return error.AuthenticationFailed;
                }

                ChaCha20.xor(frame[4..], frame[4..], 1, main_key, nonce);
            },
            .aes256_gcm_openssh => {
                const nonce = s.iv[0..Aes256Gcm.nonce_length].*;
                try Aes256Gcm.decrypt(
                    frame[4..],
                    frame[4..],
                    tag,
                    frame[0..4],
                    nonce,
                    s.key[0..Aes256Gcm.key_length].*,
                );
                s.advanceIv();
            },
        }
    }

    /// Counts one packet on the AES-GCM nonce.
    ///
    /// RFC 5647 section 7.1 makes the last 8 bytes an invocation counter
    /// and the first 4 a fixed field. The counter goes up by one for each
    /// packet, and it wraps, which is what OpenSSL's own GCM nonce
    /// generator does. A rekey lands long before a wrap can happen: see
    /// `zurl_ssh.Transport` and its byte bound.
    fn advanceIv(s: *State) void {
        const counter = std.mem.readInt(u64, s.iv[4..12], .big);
        std.mem.writeInt(u64, s.iv[4..12], counter +% 1, .big);
    }
};

/// The nonce both ChaCha20 instances use: the sequence number, as a
/// 64-bit big-endian value.
fn chachaNonce(sequence: u32) [8]u8 {
    var nonce: [8]u8 = undefined;
    std.mem.writeInt(u64, &nonce, sequence, .big);
    return nonce;
}

/// `K_1`, which keys the packet length field and nothing else.
///
/// **It is the second half of the key material.** See the module comment.
fn chachaLengthKey(key: *const [max_key_bytes]u8) [32]u8 {
    return key[32..64].*;
}

/// `K_2`, which keys the payload and the Poly1305 key.
///
/// **It is the first half of the key material.**
fn chachaMainKey(key: *const [max_key_bytes]u8) [32]u8 {
    return key[0..32].*;
}

const testing = std.testing;

/// Builds one sealed frame for a test, and hands back the pieces.
const Sealed = struct {
    frame: [256]u8,
    len: usize,
    tag: [tag_bytes]u8,
};

fn sealTestPacket(s: *State, sequence: u32, payload: []const u8) Sealed {
    const block = blockBytes(s.algorithm);
    const body = packet.bodyLen(payload.len, block, lengthIsAad(s.algorithm));
    var out: Sealed = .{ .frame = undefined, .len = 4 + body, .tag = undefined };
    std.mem.writeInt(u32, out.frame[0..4], @intCast(body), .big);
    var padding: [255]u8 = undefined;
    @memset(&padding, 0x5a);
    packet.writeBody(
        out.frame[4..][0..body],
        payload,
        padding[0..packet.paddingLen(payload.len, block, lengthIsAad(s.algorithm))],
    );
    s.seal(sequence, out.frame[0..out.len], &out.tag);
    return out;
}

test "the names and the sizes are the ones the two specifications give" {
    try testing.expectEqualStrings("chacha20-poly1305@openssh.com", name(.chacha20_poly1305_openssh));
    try testing.expectEqualStrings("aes256-gcm@openssh.com", name(.aes256_gcm_openssh));
    try testing.expectEqual(Algorithm.chacha20_poly1305_openssh, fromName("chacha20-poly1305@openssh.com").?);
    try testing.expectEqual(Algorithm.aes256_gcm_openssh, fromName("aes256-gcm@openssh.com").?);
    try testing.expectEqual(@as(?Algorithm, null), fromName("aes128-ctr"));
    try testing.expectEqual(@as(?Algorithm, null), fromName(""));

    try testing.expectEqual(@as(usize, 64), keyBytes(.chacha20_poly1305_openssh));
    try testing.expectEqual(@as(usize, 0), ivBytes(.chacha20_poly1305_openssh));
    try testing.expectEqual(@as(usize, 8), blockBytes(.chacha20_poly1305_openssh));
    try testing.expectEqual(@as(usize, 32), keyBytes(.aes256_gcm_openssh));
    try testing.expectEqual(@as(usize, 12), ivBytes(.aes256_gcm_openssh));
    try testing.expectEqual(@as(usize, 16), blockBytes(.aes256_gcm_openssh));
}

test "the length key is the second half of the key material, not the first" {
    // **This is the pin on the half that is easy to swap.** The expected
    // four bytes below are built here from `key[32..64]` with no help
    // from this module's own split, so a build that used the first half
    // would fail this test and would then fail against every server.
    var key: [64]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i);
    var s: State = .init(.chacha20_poly1305_openssh, &key, "");
    defer s.deinit();

    const sequence: u32 = 7;
    const sealed = sealTestPacket(&s, sequence, "\x14ok");

    var nonce: [8]u8 = undefined;
    std.mem.writeInt(u64, &nonce, sequence, .big);
    var plain_length: [4]u8 = undefined;
    std.mem.writeInt(u32, &plain_length, @intCast(sealed.len - 4), .big);
    var expected_length: [4]u8 = undefined;
    ChaCha20.xor(&expected_length, &plain_length, 0, key[32..64].*, nonce);

    try testing.expectEqualSlices(u8, &expected_length, sealed.frame[0..4]);
    // And the length reads back as the number that went in.
    try testing.expectEqual(
        @as(u32, @intCast(sealed.len - 4)),
        s.readLength(sequence, sealed.frame[0..4].*),
    );
}

test "the payload uses the first half of the key material at block counter one" {
    // The second pin: the payload keystream starts at counter 1, because
    // counter 0 produced the Poly1305 key. A build that started at 0
    // would hand the Poly1305 key to an attacker as a keystream.
    var key: [64]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(255 - i);
    var s: State = .init(.chacha20_poly1305_openssh, &key, "");
    defer s.deinit();

    const sequence: u32 = 0;
    const payload = "\x14a longer payload than one block would hold, so two blocks run";
    const sealed = sealTestPacket(&s, sequence, payload);

    var nonce: [8]u8 = undefined;
    std.mem.writeInt(u64, &nonce, sequence, .big);

    var plain_body: [256]u8 = undefined;
    @memcpy(plain_body[0 .. sealed.len - 4], sealed.frame[4..sealed.len]);
    ChaCha20.xor(plain_body[0 .. sealed.len - 4], plain_body[0 .. sealed.len - 4], 1, key[0..32].*, nonce);
    try testing.expectEqualSlices(u8, payload, try packet.payloadOf(plain_body[0 .. sealed.len - 4]));

    // And the Poly1305 key is block 0 under the same key.
    var poly_key: [32]u8 = undefined;
    ChaCha20.stream(&poly_key, 0, key[0..32].*, nonce);
    var expected_tag: [tag_bytes]u8 = undefined;
    Poly1305.create(&expected_tag, sealed.frame[0..sealed.len], &poly_key);
    try testing.expectEqualSlices(u8, &expected_tag, &sealed.tag);
}

test "both ciphers open what they sealed" {
    const payloads = [_][]const u8{ "\x14", "\x14one", "\x14a payload of some length here" };
    for ([_]Algorithm{ .chacha20_poly1305_openssh, .aes256_gcm_openssh }) |algorithm| {
        for (payloads) |payload| {
            var key: [max_key_bytes]u8 = undefined;
            @memset(&key, 0x33);
            var iv: [max_iv_bytes]u8 = undefined;
            @memset(&iv, 0x11);

            var sender: State = .init(algorithm, key[0..keyBytes(algorithm)], iv[0..ivBytes(algorithm)]);
            defer sender.deinit();
            var receiver: State = .init(algorithm, key[0..keyBytes(algorithm)], iv[0..ivBytes(algorithm)]);
            defer receiver.deinit();

            var sealed = sealTestPacket(&sender, 3, payload);
            try testing.expectEqual(
                @as(u32, @intCast(sealed.len - 4)),
                receiver.readLength(3, sealed.frame[0..4].*),
            );
            try receiver.open(3, sealed.frame[0..sealed.len], sealed.tag);
            try testing.expectEqualSlices(
                u8,
                payload,
                try packet.payloadOf(sealed.frame[4..sealed.len]),
            );
        }
    }
}

test "a changed byte anywhere in the packet fails the tag" {
    // **Every byte the peer wrote is covered**, the length field
    // included. A cipher that left the length out would let an attacker
    // move a packet boundary.
    for ([_]Algorithm{ .chacha20_poly1305_openssh, .aes256_gcm_openssh }) |algorithm| {
        var key: [max_key_bytes]u8 = undefined;
        @memset(&key, 0x77);
        var iv: [max_iv_bytes]u8 = undefined;
        @memset(&iv, 0x22);

        var sender: State = .init(algorithm, key[0..keyBytes(algorithm)], iv[0..ivBytes(algorithm)]);
        defer sender.deinit();
        const original = sealTestPacket(&sender, 0, "\x14tamper me");

        for (0..original.len) |i| {
            var receiver: State = .init(algorithm, key[0..keyBytes(algorithm)], iv[0..ivBytes(algorithm)]);
            defer receiver.deinit();
            var sealed = original;
            sealed.frame[i] ^= 0x01;
            try testing.expectError(
                error.AuthenticationFailed,
                receiver.open(0, sealed.frame[0..sealed.len], sealed.tag),
            );
        }

        // And a changed tag fails too.
        var receiver: State = .init(algorithm, key[0..keyBytes(algorithm)], iv[0..ivBytes(algorithm)]);
        defer receiver.deinit();
        var sealed = original;
        sealed.tag[0] ^= 0x80;
        try testing.expectError(
            error.AuthenticationFailed,
            receiver.open(0, sealed.frame[0..sealed.len], sealed.tag),
        );
    }
}

test "a packet replayed under another sequence number fails" {
    // **The sequence number is what stops a replay**, and it is never on
    // the wire. ChaCha20-Poly1305 puts it in the nonce, and AES-GCM puts
    // it in the invocation counter, so the two get there by different
    // routes and both must refuse.
    var key: [max_key_bytes]u8 = undefined;
    @memset(&key, 0x44);
    var chacha_sender: State = .init(.chacha20_poly1305_openssh, key[0..64], "");
    defer chacha_sender.deinit();
    const sealed = sealTestPacket(&chacha_sender, 1, "\x14replay");

    var chacha_receiver: State = .init(.chacha20_poly1305_openssh, key[0..64], "");
    defer chacha_receiver.deinit();
    var copy = sealed;
    try testing.expectError(
        error.AuthenticationFailed,
        chacha_receiver.open(2, copy.frame[0..copy.len], copy.tag),
    );
}

test "the AES-GCM nonce counts one packet at a time" {
    // A receiver that did not count would open packet 0 and then fail on
    // packet 1. This walks four packets through, in order.
    var key: [32]u8 = undefined;
    @memset(&key, 0x55);
    var iv: [12]u8 = .{ 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0xfe };

    var sender: State = .init(.aes256_gcm_openssh, &key, &iv);
    defer sender.deinit();
    var receiver: State = .init(.aes256_gcm_openssh, &key, &iv);
    defer receiver.deinit();

    for (0..4) |i| {
        var sealed = sealTestPacket(&sender, @intCast(i), "\x14tick");
        try receiver.open(@intCast(i), sealed.frame[0..sealed.len], sealed.tag);
        try testing.expectEqualSlices(u8, "\x14tick", try packet.payloadOf(sealed.frame[4..sealed.len]));
    }
    // The fixed field never moved, and the counter walked past a byte
    // boundary.
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, sender.iv[0..4]);
    try testing.expectEqual(@as(u64, 0x102), std.mem.readInt(u64, sender.iv[4..12], .big));
}

test "the AES-GCM length field goes on the wire in the clear" {
    // The two ciphers differ here, and a transport that read the length
    // the wrong way would wait for the wrong number of bytes.
    var key: [32]u8 = undefined;
    @memset(&key, 0x66);
    var iv: [12]u8 = undefined;
    @memset(&iv, 0);
    var s: State = .init(.aes256_gcm_openssh, &key, &iv);
    defer s.deinit();

    const sealed = sealTestPacket(&s, 0, "\x14clear");
    try testing.expectEqual(
        @as(u32, @intCast(sealed.len - 4)),
        std.mem.readInt(u32, sealed.frame[0..4], .big),
    );
    try testing.expect(lengthIsEncrypted(.chacha20_poly1305_openssh));
    try testing.expect(!lengthIsEncrypted(.aes256_gcm_openssh));
    try testing.expect(lengthIsAad(.chacha20_poly1305_openssh));
    try testing.expect(lengthIsAad(.aes256_gcm_openssh));
}

test "deinit leaves no key material behind" {
    var key: [64]u8 = undefined;
    @memset(&key, 0x99);
    var s: State = .init(.chacha20_poly1305_openssh, &key, "");
    const address = &s.key;
    s.deinit();
    // `s` is undefined after `deinit`, so the check reads the storage
    // through the pointer taken before it.
    for (address) |byte| try testing.expectEqual(@as(u8, 0), byte);
}
