//! The TLS 1.3 key schedule, RFC 8446 section 7.1, and the QUIC key sets
//! it feeds. RFC 9001 section 5.
//!
//! **This file makes secrets. It makes no key.** `protection.Keys` in
//! `zurl-quic` turns one secret into a packet protection key, an IV, and a
//! header protection key, and that derivation is already checked byte for
//! byte against RFC 9001 appendix A. So the work here is the ladder above
//! it: an extract, an expand, and a transcript hash at each rung.
//!
//! ## The ladder
//!
//! RFC 8446 section 7.1 prints it as a diagram. With no pre-shared key,
//! which is every handshake this build makes, it reads:
//!
//!     Early Secret     = HKDF-Extract(0, 0)
//!     Handshake Secret = HKDF-Extract(Derive(Early, "derived"), ECDHE)
//!     Master Secret    = HKDF-Extract(Derive(Handshake, "derived"), 0)
//!
//! and each rung gives two traffic secrets, one for each direction:
//!
//!     client_handshake   = Derive(Handshake, "c hs traffic", CH..SH)
//!     server_handshake   = Derive(Handshake, "s hs traffic", CH..SH)
//!     client_application = Derive(Master, "c ap traffic", CH..server Finished)
//!     server_application = Derive(Master, "s ap traffic", CH..server Finished)
//!
//! `Derive(secret, label, messages)` is HKDF-Expand-Label over the hash of
//! those messages. The transcript is therefore what binds a secret to the
//! exact bytes both sides saw, and a byte either side did not see gives a
//! different secret and a Finished message that does not check.
//!
//! ## What is not here
//!
//! There is no record layer, no early data, and no resumption. QUIC has no
//! TLS records at all: RFC 9001 section 4 carries the handshake messages
//! in CRYPTO frames, and `Handshake.zig` is the state machine over them.
//!
//! `HKDF-Expand-Label` itself is `std.crypto.tls.hkdfExpandLabel`, which
//! is the call the vendored TLS client makes for its own schedule. One
//! implementation, and no second one to drift.

const std = @import("std");

const tls = std.crypto.tls;
const quic = @import("zurl-quic");
const protection = quic.protection;

/// The longest secret any suite here uses. SHA-384 is the long one.
pub const max_secret_len = protection.max_secret_len;

/// One secret of the key schedule, held by value.
///
/// A secret is a fixed number of bytes, and the number comes from the
/// negotiated hash. The buffer is the longest of the two, and `len` says
/// how much of it is the secret. Nothing reads past `len`.
pub const Secret = struct {
    bytes: [max_secret_len]u8,
    len: u8,

    /// A secret of no bytes. This is what a level that has no secret yet
    /// holds.
    pub const none: Secret = .{ .bytes = @splat(0), .len = 0 };

    /// Builds a secret from the bytes of one derivation.
    pub fn from(bytes: []const u8) Secret {
        std.debug.assert(bytes.len <= max_secret_len);
        var out: Secret = .none;
        @memcpy(out.bytes[0..bytes.len], bytes);
        out.len = @intCast(bytes.len);
        return out;
    }

    /// The bytes of the secret.
    pub fn slice(self: *const Secret) []const u8 {
        return self.bytes[0..self.len];
    }

    /// Whether a derivation has filled this in.
    pub fn isSet(self: *const Secret) bool {
        return self.len != 0;
    }

    /// Writes zeroes over the secret.
    ///
    /// A secret stays in memory for as long as the connection needs it,
    /// and no longer. `std.crypto.secureZero` is what keeps the compiler
    /// from removing the write.
    pub fn clear(self: *Secret) void {
        std.crypto.secureZero(u8, &self.bytes);
        self.len = 0;
    }
};

/// A running hash of every handshake message, in the order they were sent
/// and received.
///
/// RFC 8446 section 4.4.1 calls this the transcript hash. It covers the
/// whole handshake message, the four byte header included, and it covers
/// nothing else: QUIC's CRYPTO frame headers and packet headers are not
/// in it.
pub const Transcript = union(protection.Hash) {
    sha256: std.crypto.hash.sha2.Sha256,
    sha384: std.crypto.hash.sha2.Sha384,

    /// A transcript with nothing in it.
    pub fn init(which: protection.Hash) Transcript {
        return switch (which) {
            .sha256 => .{ .sha256 = .init(.{}) },
            .sha384 => .{ .sha384 = .init(.{}) },
        };
    }

    /// Which hash this transcript runs.
    pub fn hash(self: *const Transcript) protection.Hash {
        return self.*;
    }

    /// Adds one run of bytes.
    pub fn update(self: *Transcript, bytes: []const u8) void {
        switch (self.*) {
            inline else => |*state| state.update(bytes),
        }
    }

    /// The hash of everything added so far, without ending the
    /// transcript. More messages follow every rung but the last.
    pub fn peek(self: *const Transcript) Secret {
        return switch (self.*) {
            inline else => |state| .from(&state.peek()),
        };
    }
};

/// The two traffic secrets of one rung, one for each direction.
pub const Pair = struct {
    /// Protects what the client sends.
    client: Secret,
    /// Protects what the server sends.
    server: Secret,

    /// Writes zeroes over both.
    pub fn clear(self: *Pair) void {
        self.client.clear();
        self.server.clear();
    }
};

/// The handshake rung: the two handshake traffic secrets, and the Master
/// Secret that the application rung comes from.
pub const HandshakeStage = struct {
    traffic: Pair,
    master: Secret,
};

/// The HKDF under one hash.
fn Hkdf(comptime hash: protection.Hash) type {
    return switch (hash) {
        .sha256 => std.crypto.kdf.hkdf.HkdfSha256,
        .sha384 => std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384),
    };
}

/// The hash type under one hash name.
fn Hash(comptime hash: protection.Hash) type {
    return switch (hash) {
        .sha256 => std.crypto.hash.sha2.Sha256,
        .sha384 => std.crypto.hash.sha2.Sha384,
    };
}

/// The HMAC under one hash.
fn Hmac(comptime hash: protection.Hash) type {
    return switch (hash) {
        .sha256 => std.crypto.auth.hmac.sha2.HmacSha256,
        .sha384 => std.crypto.auth.hmac.sha2.HmacSha384,
    };
}

/// `Derive-Secret(secret, label, messages)` of RFC 8446 section 7.1.
///
/// The context is the transcript hash, which is what makes the answer
/// depend on the exact bytes both sides exchanged.
fn deriveSecret(
    comptime hash: protection.Hash,
    secret: [Hkdf(hash).prk_length]u8,
    comptime label: []const u8,
    context: []const u8,
) Secret {
    const out = tls.hkdfExpandLabel(Hkdf(hash), secret, label, context, Hash(hash).digest_length);
    return .from(&out);
}

/// The Handshake Secret rung, and the Master Secret under it.
///
/// `shared` is the (EC)DHE shared secret. `hello_hash` is the transcript
/// through the ServerHello, which is the message that fixes both the
/// suite and the key share.
///
/// **The Master Secret comes out here and the application secrets do
/// not.** RFC 8446 section 7.1 derives the application secrets over the
/// transcript through the server's Finished, which has not been read at
/// this point. So the Master Secret is kept and `applicationSecrets`
/// finishes the job later.
pub fn handshakeSecrets(
    suite: protection.Suite,
    shared: []const u8,
    hello_hash: []const u8,
) HandshakeStage {
    switch (suite.hash()) {
        inline else => |hash| {
            const K = Hkdf(hash);
            const digest_len = Hash(hash).digest_length;
            const zeroes = [_]u8{0} ** digest_len;

            // Early Secret, with no pre-shared key. RFC 8446 section 7.1
            // makes the input a string of `Hash.length` zero bytes when
            // the client offers no PSK, and this client offers none.
            const early = K.extract(&zeroes, &zeroes);
            const early_derived = tls.hkdfExpandLabel(
                K,
                early,
                "derived",
                &tls.emptyHash(Hash(hash)),
                digest_len,
            );

            const handshake = K.extract(&early_derived, shared);
            const traffic: Pair = .{
                .client = deriveSecret(hash, handshake, "c hs traffic", hello_hash),
                .server = deriveSecret(hash, handshake, "s hs traffic", hello_hash),
            };

            const handshake_derived = tls.hkdfExpandLabel(
                K,
                handshake,
                "derived",
                &tls.emptyHash(Hash(hash)),
                digest_len,
            );
            const master = K.extract(&handshake_derived, &zeroes);

            return .{ .traffic = traffic, .master = .from(&master) };
        },
    }
}

/// The application rung. RFC 8446 section 7.1.
///
/// `finished_hash` is the transcript through the **server's** Finished
/// message, which is the last message of the server's flight. The
/// client's own Finished is not in it.
pub fn applicationSecrets(
    suite: protection.Suite,
    master: *const Secret,
    finished_hash: []const u8,
) Pair {
    switch (suite.hash()) {
        inline else => |hash| {
            const K = Hkdf(hash);
            std.debug.assert(master.len == K.prk_length);
            const key = master.bytes[0..K.prk_length].*;
            return .{
                .client = deriveSecret(hash, key, "c ap traffic", finished_hash),
                .server = deriveSecret(hash, key, "s ap traffic", finished_hash),
            };
        },
    }
}

/// The key that signs a Finished message. RFC 8446 section 4.4.4.
pub fn finishedKey(suite: protection.Suite, traffic: *const Secret) Secret {
    switch (suite.hash()) {
        inline else => |hash| {
            const K = Hkdf(hash);
            std.debug.assert(traffic.len == K.prk_length);
            const key = traffic.bytes[0..K.prk_length].*;
            const out = tls.hkdfExpandLabel(K, key, "finished", "", Hash(hash).digest_length);
            return .from(&out);
        },
    }
}

/// The `verify_data` of a Finished message. RFC 8446 section 4.4.4.
///
/// It is an HMAC under `finished_key` over the transcript hash of every
/// message before this one.
pub fn verifyData(
    suite: protection.Suite,
    key: *const Secret,
    transcript_hash: []const u8,
) Secret {
    switch (suite.hash()) {
        inline else => |hash| {
            const M = Hmac(hash);
            std.debug.assert(key.len == M.key_length);
            var out: [M.mac_length]u8 = undefined;
            M.create(&out, transcript_hash, key.slice());
            return .from(&out);
        },
    }
}

/// The secret that follows `secret` after a QUIC key update. RFC 9001
/// section 6.1.
///
/// The derivation is `protection.Keys.nextSecret`, which is checked
/// against the `ku` value of RFC 9001 appendix A.5.
pub fn nextSecret(suite: protection.Suite, secret: *const Secret) Secret {
    var out: Secret = .none;
    out.len = @intCast(suite.hash().secretLen());
    protection.Keys.nextSecret(suite, secret.slice(), out.bytes[0..out.len]);
    return out;
}

/// The QUIC key set for one traffic secret. RFC 9001 section 5.1.
///
/// **This is the one line that joins the two halves of RFC 9001.** The
/// secret above it comes from the TLS key schedule, and everything below
/// it is already checked against appendix A.
pub fn keys(suite: protection.Suite, secret: *const Secret) protection.Keys {
    return .fromSecret(suite, secret.slice());
}

/// The key set that follows a key update. RFC 9001 section 6.
///
/// **The header protection key does not change.** RFC 9001 section 5.4
/// says the same header protection key runs for the whole connection and
/// that a key update does not replace it. `protection.Keys.fromSecret`
/// derives all three from one secret, because that is what the Initial
/// keys and the first handshake keys need, so this call puts the header
/// protection key of `current` back over the new one.
///
/// A build that got this wrong would still talk to itself, and it would
/// fail against every other implementation on the first packet after an
/// update.
pub fn updatedKeys(
    suite: protection.Suite,
    current: *const protection.Keys,
    secret: *const Secret,
) protection.Keys {
    var out = keys(suite, secret);
    out.hp = current.hp;
    return out;
}

/// Which TLS 1.3 cipher suite a wire code point names, or null for one
/// QUIC cannot use.
///
/// RFC 9001 section 5.4.1 defines no header protection for
/// `TLS_AES_128_CCM_8_SHA256`, and nothing this build talks to
/// negotiates the CCM suites, so neither is here. A server that names a
/// suite the client hello never offered is a fault the caller reports.
pub fn suiteOf(code: tls.CipherSuite) ?protection.Suite {
    return switch (code) {
        .AES_128_GCM_SHA256 => .aes_128_gcm,
        .AES_256_GCM_SHA384 => .aes_256_gcm,
        .CHACHA20_POLY1305_SHA256 => .chacha20_poly1305,
        else => null,
    };
}

/// The wire code point of one suite.
pub fn codeOf(suite: protection.Suite) tls.CipherSuite {
    return switch (suite) {
        .aes_128_gcm => .AES_128_GCM_SHA256,
        .aes_256_gcm => .AES_256_GCM_SHA384,
        .chacha20_poly1305 => .CHACHA20_POLY1305_SHA256,
    };
}

const testing = std.testing;

test "a secret holds its bytes and clears to nothing" {
    var secret: Secret = .from(&[_]u8{0xab} ** 32);
    try testing.expectEqual(@as(u8, 32), secret.len);
    try testing.expect(secret.isSet());
    try testing.expectEqual(@as(usize, 32), secret.slice().len);
    secret.clear();
    try testing.expect(!secret.isSet());
    try testing.expectEqual(@as(usize, 0), secret.slice().len);
    try testing.expect(std.mem.allEqual(u8, &secret.bytes, 0));
}

test "the transcript reports the hash it runs and matches a direct digest" {
    var transcript: Transcript = .init(.sha256);
    try testing.expectEqual(protection.Hash.sha256, transcript.hash());
    transcript.update("hello ");
    transcript.update("world");

    var want: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("hello world", &want, .{});
    try testing.expectEqualSlices(u8, &want, transcript.peek().slice());

    // And more bytes may follow a peek, which is what every rung but the
    // last one needs.
    transcript.update("!");
    var want_more: [48]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("hello world!", want_more[0..32], .{});
    try testing.expectEqualSlices(u8, want_more[0..32], transcript.peek().slice());
}

test "the transcript runs SHA-384 for the one suite that names it" {
    var transcript: Transcript = .init(.sha384);
    try testing.expectEqual(protection.Hash.sha384, transcript.hash());
    transcript.update("abc");
    var want: [48]u8 = undefined;
    std.crypto.hash.sha2.Sha384.hash("abc", &want, .{});
    try testing.expectEqualSlices(u8, &want, transcript.peek().slice());
    try testing.expectEqual(@as(u8, 48), transcript.peek().len);
}

test "every suite gives a secret of the length its hash names" {
    for ([_]protection.Suite{ .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305 }) |suite| {
        var transcript: Transcript = .init(suite.hash());
        transcript.update("client hello and server hello");
        const shared = [_]u8{0x11} ** 32;
        const stage = handshakeSecrets(suite, &shared, transcript.peek().slice());

        const want_len = suite.hash().secretLen();
        try testing.expectEqual(want_len, stage.traffic.client.len);
        try testing.expectEqual(want_len, stage.traffic.server.len);
        try testing.expectEqual(want_len, stage.master.len);

        // The two directions never share a secret.
        try testing.expect(!std.mem.eql(u8, stage.traffic.client.slice(), stage.traffic.server.slice()));

        transcript.update("the rest of the server flight");
        const application = applicationSecrets(suite, &stage.master, transcript.peek().slice());
        try testing.expectEqual(want_len, application.client.len);
        try testing.expectEqual(want_len, application.server.len);

        // A handshake secret and an application secret of the same
        // direction are different secrets, so a key set of one level
        // cannot open a packet of another.
        try testing.expect(!std.mem.eql(
            u8,
            stage.traffic.client.slice(),
            application.client.slice(),
        ));
    }
}

test "one changed transcript byte changes every secret under it" {
    const suite: protection.Suite = .aes_128_gcm;
    const shared = [_]u8{0x22} ** 32;

    var first: Transcript = .init(suite.hash());
    first.update("client hello");
    const one = handshakeSecrets(suite, &shared, first.peek().slice());

    var second: Transcript = .init(suite.hash());
    second.update("client hellp");
    const two = handshakeSecrets(suite, &shared, second.peek().slice());

    try testing.expect(!std.mem.eql(u8, one.traffic.client.slice(), two.traffic.client.slice()));
    try testing.expect(!std.mem.eql(u8, one.traffic.server.slice(), two.traffic.server.slice()));

    // **The Master Secret is the one value the transcript does not
    // change.** RFC 8446 section 7.1 derives it from the Handshake Secret
    // with an empty context, so the transcript reaches the application
    // secrets through `applicationSecrets` and not through this rung.
    try testing.expectEqualSlices(u8, one.master.slice(), two.master.slice());

    // And it does reach the application secrets.
    const one_app = applicationSecrets(suite, &one.master, first.peek().slice());
    const two_app = applicationSecrets(suite, &two.master, second.peek().slice());
    try testing.expect(!std.mem.eql(u8, one_app.client.slice(), two_app.client.slice()));
    try testing.expect(!std.mem.eql(u8, one_app.server.slice(), two_app.server.slice()));
}

test "one changed shared secret byte changes every secret under it" {
    const suite: protection.Suite = .aes_128_gcm;
    var transcript: Transcript = .init(suite.hash());
    transcript.update("the same messages both times");

    const one = handshakeSecrets(suite, &[_]u8{0x33} ** 32, transcript.peek().slice());
    const two = handshakeSecrets(suite, &[_]u8{0x34} ** 32, transcript.peek().slice());

    try testing.expect(!std.mem.eql(u8, one.traffic.client.slice(), two.traffic.client.slice()));
    try testing.expect(!std.mem.eql(u8, one.master.slice(), two.master.slice()));
}

test "a Finished message checks under the key its own secret gives" {
    for ([_]protection.Suite{ .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305 }) |suite| {
        var transcript: Transcript = .init(suite.hash());
        transcript.update("hello");
        const stage = handshakeSecrets(suite, &[_]u8{0x44} ** 32, transcript.peek().slice());

        const key = finishedKey(suite, &stage.traffic.server);
        try testing.expectEqual(suite.hash().secretLen(), key.len);

        transcript.update("the server flight");
        const hash = transcript.peek();
        const data = verifyData(suite, &key, hash.slice());
        try testing.expectEqual(suite.hash().secretLen(), data.len);

        // The same inputs give the same answer, which is what the check
        // of a peer's Finished message rests on.
        const again = verifyData(suite, &key, hash.slice());
        try testing.expectEqualSlices(u8, data.slice(), again.slice());

        // The client's key gives another answer, so one direction's
        // Finished can never pass as the other's.
        const client_key = finishedKey(suite, &stage.traffic.client);
        const client_data = verifyData(suite, &client_key, hash.slice());
        try testing.expect(!std.mem.eql(u8, data.slice(), client_data.slice()));
    }
}

test "a key update gives a new secret and a new key set" {
    const suite: protection.Suite = .aes_128_gcm;
    const first: Secret = .from(&[_]u8{0x55} ** 32);
    const second = nextSecret(suite, &first);
    try testing.expectEqual(@as(u8, 32), second.len);
    try testing.expect(!std.mem.eql(u8, first.slice(), second.slice()));

    const first_keys = keys(suite, &first);
    const second_keys = updatedKeys(suite, &first_keys, &second);
    try testing.expect(!std.mem.eql(u8, first_keys.keySlice(), second_keys.keySlice()));
    try testing.expect(!std.mem.eql(u8, &first_keys.iv, &second_keys.iv));

    // **The header protection key does not change.** RFC 9001 section 5.4
    // says the same one runs for the whole connection.
    try testing.expectEqualSlices(u8, first_keys.headerKeySlice(), second_keys.headerKeySlice());

    // And a plain derivation from the new secret does change it, which is
    // the whole reason `updatedKeys` is a call of its own.
    const plain = keys(suite, &second);
    try testing.expect(!std.mem.eql(u8, first_keys.headerKeySlice(), plain.headerKeySlice()));
}

test "the suite names map both ways and QUIC refuses the CCM suites" {
    try testing.expectEqual(protection.Suite.aes_128_gcm, suiteOf(.AES_128_GCM_SHA256).?);
    try testing.expectEqual(protection.Suite.aes_256_gcm, suiteOf(.AES_256_GCM_SHA384).?);
    try testing.expectEqual(protection.Suite.chacha20_poly1305, suiteOf(.CHACHA20_POLY1305_SHA256).?);

    // RFC 9001 section 5.4.1 gives neither CCM suite a header protection
    // rule, so neither can be used.
    try testing.expect(suiteOf(.AES_128_CCM_SHA256) == null);
    try testing.expect(suiteOf(.AES_128_CCM_8_SHA256) == null);
    // And a TLS 1.2 suite is not a QUIC suite at all.
    try testing.expect(suiteOf(.ECDHE_RSA_WITH_AES_128_GCM_SHA256) == null);

    for ([_]protection.Suite{ .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305 }) |suite| {
        try testing.expectEqual(suite, suiteOf(codeOf(suite)).?);
    }
}

test "the key schedule agrees with the worked example of RFC 8448 section 3" {
    // RFC 8448 prints every value of one TLS 1.3 handshake. The transcript
    // hashes below are the ones it prints, so this checks the ladder
    // against numbers this build did not compute.
    //
    // The suite is `TLS_AES_128_GCM_SHA256`, so the hash is SHA-256.
    const suite: protection.Suite = .aes_128_gcm;

    // Section 3, "{server} extract secret 'handshake'": the shared secret
    // of the x25519 exchange.
    const shared = try hexBytes(32, "8bd4054fb55b9d63fdfbacf9f04b9f0d" ++
        "35e6d63f537563efd46272900f89492d");

    // The hash of ClientHello..ServerHello, which section 3 prints as
    // the digest before the handshake traffic secrets.
    const hello_hash = try hexBytes(32, "860c06edc07858ee8e78f0e7428c58ed" ++
        "d6b43f2ca3e6e95f02ed063cf0e1cad8");

    const stage = handshakeSecrets(suite, &shared, &hello_hash);

    // "client handshake traffic secret" and "server handshake traffic
    // secret" of section 3.
    const want_client = try hexBytes(32, "b3eddb126e067f35a780b3abf45e2d8f" ++
        "3b1a950738f52e9600746a0e27a55a21");
    const want_server = try hexBytes(32, "b67b7d690cc16c4e75e54213cb2d37b4" ++
        "e9c912bcded9105d42befd59d391ad38");
    try testing.expectEqualSlices(u8, &want_client, stage.traffic.client.slice());
    try testing.expectEqualSlices(u8, &want_server, stage.traffic.server.slice());

    // The Master Secret of the same section, which section 3 prints as
    // "derived secret for master".
    const want_master = try hexBytes(32, "18df06843d13a08bf2a449844c5f8a47" ++
        "8001bc4d4c627984d5a41da8d0402919");
    try testing.expectEqualSlices(u8, &want_master, stage.master.slice());

    // The hash of ClientHello..server Finished, which is where the
    // application secrets come from.
    const finished_hash = try hexBytes(32, "9608102a0f1ccc6db6250b7b7e417b1a" ++
        "000eaada3daae4777a7686c9ff83df13");
    const application = applicationSecrets(suite, &stage.master, &finished_hash);

    const want_client_app = try hexBytes(32, "9e40646ce79a7f9dc05af8889bce6552" ++
        "875afa0b06df0087f792ebb7c17504a5");
    const want_server_app = try hexBytes(32, "a11af9f05531f856ad47116b45a950328" ++
        "204b4f44bfb6b3a4b4f1f3fcb631643");
    try testing.expectEqualSlices(u8, &want_client_app, application.client.slice());
    try testing.expectEqualSlices(u8, &want_server_app, application.server.slice());
}

/// The five handshake messages of RFC 8448 section 3 that the server's
/// Finished message signs, in the order they went on the wire:
/// ClientHello, ServerHello, EncryptedExtensions, Certificate, and
/// CertificateVerify.
///
/// Held as the RFC prints them, so a reader can compare the text against
/// the RFC by eye. The four byte handshake header of each message is in
/// here, because RFC 8446 section 4.4.1 puts it in the transcript.
const rfc8448_flight =
    // ClientHello, 196 octets.
    "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef" ++
    "6283024dece7000006130113031302010000910000000b000900000673657276" ++
    "6572ff01000100000a00140012001d0017001800190100010101020103010400" ++
    "230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e" ++
    "51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603" ++
    "020308040805080604010501060102010402050206020202002d00020101001c" ++
    "00024001" ++
    // ServerHello, 90 octets.
    "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155" ++
    "772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdb" ++
    "f7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304" ++
    // EncryptedExtensions, 40 octets.
    "080000240022000a00140012001d00170018001901000101010201030104001c" ++
    "0002400100000000" ++
    // Certificate, 445 octets.
    "0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a" ++
    "864886f70d01010b0500300e310c300a06035504031303727361301e170d3136" ++
    "303733303031323335395a170d3236303733303031323335395a300e310c300a" ++
    "0603550403130372736130819f300d06092a864886f70d010101050003818d00" ++
    "30818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826" ++
    "d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced4312" ++
    "0998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda4308467480" ++
    "30530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a" ++
    "8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b060355" ++
    "1d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5" ++
    "b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a5" ++
    "8c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102" ++
    "702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0" ++
    "a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de10000" ++
    // CertificateVerify, 136 octets.
    "0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145a" ++
    "b3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248ee" ++
    "aaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c" ++
    "9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea2" ++
    "0d53dfacd42f74f3";

test "the Finished message of RFC 8448 section 3 checks under this transcript" {
    // The strongest offline evidence there is for the handshake half: the
    // messages are the RFC's own bytes, the transcript is built the way
    // `Handshake.zig` builds one, and the answer is the value the RFC
    // prints for `finished`.
    const suite: protection.Suite = .aes_128_gcm;

    var flight: [rfc8448_flight.len / 2]u8 = undefined;
    const bytes = try std.fmt.hexToBytes(&flight, rfc8448_flight);
    try testing.expectEqual(@as(usize, 196 + 90 + 40 + 445 + 136), bytes.len);

    // The server's handshake traffic secret, printed as the PRK of
    // "calculate finished".
    const server_handshake: Secret = .from(&try hexBytes(32, "b67b7d690cc16c4e75e54213cb2d37b4" ++
        "e9c912bcded9105d42befd59d391ad38"));

    // The finished key, printed as "expanded" under the same heading.
    const key = finishedKey(suite, &server_handshake);
    const want_key = try hexBytes(32, "008d3b66f816ea559f96b537e885c31f" ++
        "c068bf492c652f01f288a1d8cdc19fc8");
    try testing.expectEqualSlices(u8, &want_key, key.slice());

    // The transcript of every message before the Finished, added one
    // message at a time the way the state machine adds them.
    var transcript: Transcript = .init(suite.hash());
    transcript.update(bytes[0..196]); // ClientHello
    transcript.update(bytes[196..][0..90]); // ServerHello
    transcript.update(bytes[286..][0..40]); // EncryptedExtensions
    transcript.update(bytes[326..][0..445]); // Certificate
    transcript.update(bytes[771..][0..136]); // CertificateVerify

    // And the verify data, printed as "finished".
    const data = verifyData(suite, &key, transcript.peek().slice());
    const want_finished = try hexBytes(32, "9b9b141d906337fbd2cbdce71df4deda" ++
        "4ab42c309572cb7fffee5454b78f0718");
    try testing.expectEqualSlices(u8, &want_finished, data.slice());

    // One byte of one message changed gives another answer, which is what
    // makes the Finished message worth checking at all.
    flight[500] ^= 0x01;
    var tampered: Transcript = .init(suite.hash());
    tampered.update(&flight);
    const other = verifyData(suite, &key, tampered.peek().slice());
    try testing.expect(!std.mem.eql(u8, data.slice(), other.slice()));
}

/// Reads a hexadecimal string into a fixed array. Test helper.
fn hexBytes(comptime len: usize, text: []const u8) ![len]u8 {
    var out: [len]u8 = undefined;
    const written = try std.fmt.hexToBytes(&out, text);
    try testing.expectEqual(len, written.len);
    return out;
}
