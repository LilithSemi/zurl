//! The server's host key: what this build reads, what it refuses by name,
//! and where the trust decision is made.
//!
//! **Verifying the signature is not the same as trusting the key.** A
//! signature over the exchange hash proves that the peer holds the private
//! key for the public key it just presented. It proves nothing at all
//! about whether that key belongs to the host the user asked for. An
//! attacker in the middle presents a key it does hold, signs with it, and
//! passes every check in this file. The missing half is a record of which
//! key that host had before, which is what `known_hosts` is.
//!
//! So **this module makes the trust decision the caller's, and it gives no
//! way to skip it.** `Verifier` has no default and there is no "accept
//! anything" value in this package. `zurl_ssh.Transport.Options.verifier`
//! has no default value either, so a caller that forgets it does not
//! compile. A later task that adds `known_hosts` writes a `Verifier` and
//! changes nothing else.
//!
//! **What this build supports, and what it refuses by name.** Only
//! `ssh-ed25519`. `std.crypto` carries no RSA signer, so `ssh-rsa` and
//! `rsa-sha2-256` and `rsa-sha2-512` cannot be verified here at all, and a
//! client that accepted them without verifying would be worse than one
//! that refuses. `refusalFor` names each one and says why, so a user gets
//! a reason instead of a blank negotiation failure.
//!
//! What this module does not own: it reads no file and it asks no
//! question. `known_hosts` parsing is not here yet, and the `Verifier`
//! shape is what keeps a place for it.

const std = @import("std");

const wire = @import("wire.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// The host key algorithms this build can verify.
pub const Algorithm = enum {
    ssh_ed25519,
};

/// The name of `a` on the wire.
pub fn name(a: Algorithm) []const u8 {
    return switch (a) {
        .ssh_ed25519 => "ssh-ed25519",
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

/// Why this build cannot use a host key algorithm a server offered, in
/// words a user can act on.
///
/// **A negotiation that fails with no reason is a bug report nobody can
/// answer.** A server that offers `ssh-rsa` and nothing else gets a
/// message that says which algorithm and why, so the user knows to add an
/// Ed25519 host key rather than to guess.
///
/// Null for a name this build has never heard of, which needs no
/// explanation past "not offered".
pub fn refusalFor(text: []const u8) ?[]const u8 {
    const table = [_]struct { algorithm: []const u8, reason: []const u8 }{
        .{
            .algorithm = "ssh-rsa",
            .reason = "zurl carries no RSA verifier, and Zig's standard library has none outside TLS",
        },
        .{
            .algorithm = "rsa-sha2-256",
            .reason = "zurl carries no RSA verifier, and Zig's standard library has none outside TLS",
        },
        .{
            .algorithm = "rsa-sha2-512",
            .reason = "zurl carries no RSA verifier, and Zig's standard library has none outside TLS",
        },
        .{
            .algorithm = "ssh-dss",
            .reason = "DSA with a 1024 bit key is too weak, and OpenSSH removed it",
        },
        .{
            .algorithm = "ecdsa-sha2-nistp256",
            .reason = "zurl offers Ed25519 host keys only",
        },
        .{
            .algorithm = "ecdsa-sha2-nistp384",
            .reason = "zurl offers Ed25519 host keys only",
        },
        .{
            .algorithm = "ecdsa-sha2-nistp521",
            .reason = "zurl offers Ed25519 host keys only",
        },
        .{
            .algorithm = "ssh-ed25519-cert-v01@openssh.com",
            .reason = "zurl reads no certificate host key, so the plain ssh-ed25519 key is needed",
        },
    };
    for (table) |row| {
        if (std.mem.eql(u8, text, row.algorithm)) return row.reason;
    }
    return null;
}

/// Why a host key blob or a signature blob was refused.
pub const ParseError = wire.ReadError || error{
    /// The blob names an algorithm this build does not verify. The name
    /// is inside the blob, and it must match the one the negotiation
    /// chose.
    HostKeyAlgorithmUnsupported,
    /// The blob names one algorithm and the negotiation chose another. A
    /// server that does this is presenting a key for a question nobody
    /// asked.
    HostKeyAlgorithmMismatch,
    /// The key or the signature is not the size its algorithm gives.
    HostKeyMalformed,
    /// The 32 bytes are not a point on the curve, or they are not the
    /// canonical form of one.
    HostKeyNotCanonical,
};

/// A server's host key, read out of the blob it sent.
pub const PublicKey = union(Algorithm) {
    ssh_ed25519: Ed25519.PublicKey,

    /// Which algorithm this key is.
    pub fn algorithm(key: PublicKey) Algorithm {
        return std.meta.activeTag(key);
    }
};

/// Reads a host key blob, RFC 4253 section 6.6 and RFC 8709 section 4.
///
/// `expected` is the algorithm the negotiation chose. The blob names its
/// own algorithm, and the two must agree.
///
/// The blob is the byte string the server sent as `K_S`, and it goes into
/// the exchange hash exactly as it arrived. This function reads it and
/// never rewrites it.
pub fn parse(blob: []const u8, expected: Algorithm) ParseError!PublicKey {
    var r: wire.Reader = .init(blob);
    const declared = try r.string();
    const found = fromName(declared) orelse return error.HostKeyAlgorithmUnsupported;
    if (found != expected) return error.HostKeyAlgorithmMismatch;

    switch (found) {
        .ssh_ed25519 => {
            const bytes = try r.string();
            if (bytes.len != Ed25519.PublicKey.encoded_length) return error.HostKeyMalformed;
            if (!r.atEnd()) return error.HostKeyMalformed;
            const key = Ed25519.PublicKey.fromBytes(bytes[0..Ed25519.PublicKey.encoded_length].*) catch
                return error.HostKeyNotCanonical;
            return .{ .ssh_ed25519 = key };
        },
    }
}

/// Why a signature did not verify.
pub const VerifyError = ParseError || error{
    /// The signature does not match the message under this key. The peer
    /// does not hold the private key it claimed, or something changed the
    /// exchange hash between the two sides.
    HostKeySignatureInvalid,
};

/// Checks `signature_blob` against `message` under `key`.
///
/// `message` is the exchange hash `H`. RFC 4253 section 8 says the server
/// signs `H` and nothing else, so a caller that passed anything else here
/// would prove nothing.
///
/// **This proves the peer holds the private key. It does not prove the key
/// belongs to the host.** See the module comment, and see `Verifier`.
pub fn verify(key: PublicKey, signature_blob: []const u8, message: []const u8) VerifyError!void {
    var r: wire.Reader = .init(signature_blob);
    const declared = try r.string();
    const found = fromName(declared) orelse return error.HostKeyAlgorithmUnsupported;
    if (found != key.algorithm()) return error.HostKeyAlgorithmMismatch;

    switch (key) {
        .ssh_ed25519 => |public| {
            const bytes = try r.string();
            if (bytes.len != Ed25519.Signature.encoded_length) return error.HostKeyMalformed;
            if (!r.atEnd()) return error.HostKeyMalformed;
            const signature: Ed25519.Signature = .fromBytes(bytes[0..Ed25519.Signature.encoded_length].*);
            signature.verify(message, public) catch return error.HostKeySignatureInvalid;
        },
    }
}

/// How many bytes `fingerprintText` writes at most.
///
/// `SHA256:` and 43 base64 characters for 32 bytes with no padding.
pub const max_fingerprint_bytes = "SHA256:".len + 43;

/// The SHA-256 of a host key blob, which is what OpenSSH fingerprints.
pub fn fingerprint(blob: []const u8) [Sha256.digest_length]u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(blob, &digest, .{});
    return digest;
}

/// Writes the fingerprint of `blob` the way `ssh-keygen -l` prints it.
///
/// The form is `SHA256:` and the base64 of the digest with no padding.
/// `out` must hold `max_fingerprint_bytes`, which is a rule this build's
/// own callers keep, so it is an assert.
///
/// **This is what a caller shows a person who has to make the trust
/// decision.** A `Verifier` that asks a user anything asks it about this
/// string.
pub fn fingerprintText(out: []u8, blob: []const u8) []u8 {
    std.debug.assert(out.len >= max_fingerprint_bytes);
    const digest = fingerprint(blob);
    @memcpy(out[0..7], "SHA256:");
    const encoder = std.base64.standard_no_pad.Encoder;
    const text = encoder.encode(out[7..], &digest);
    return out[0 .. 7 + text.len];
}

/// Which host a key was presented for.
///
/// A `Verifier` needs both, because `known_hosts` keys a record on the
/// host name and on the port when the port is not 22.
pub const Peer = struct {
    host: []const u8,
    port: u16,
};

/// Why a host key was not trusted.
pub const TrustError = error{
    /// The verifier has no record of this host. This is the first
    /// connection, and nothing here can say whether the key is right.
    HostKeyUnknown,
    /// The verifier has a record, and this key is not it. **An attacker
    /// between the client and the host looks like this.**
    HostKeyChanged,
    /// The verifier has a record of this host, and every key in it is of a
    /// type this build cannot verify.
    ///
    /// **It is not `HostKeyUnknown`, and the difference is what a user
    /// does next.** A message that told the user to add the key would tell
    /// them to write the key that is in front of them beside a record they
    /// already hold, which is what an attacker in the middle needs.
    HostKeyAlgorithmUnknown,
    /// The verifier refused for a reason of its own. A user that said no
    /// lands here.
    HostKeyRejected,
    /// The verifier could not read what it needed. A `known_hosts` file
    /// that cannot be opened lands here.
    HostKeyCheckFailed,
};

/// The trust decision, which belongs to the caller.
///
/// **There is no default and no "accept anything" value in this package.**
/// A transport takes one of these and calls it with the key the server
/// presented, after the signature check has passed and before any secret
/// goes out. A verifier that returns without an error says the key belongs
/// to the host. Anything else ends the connection.
///
/// `blob` is the bytes the server sent, which is what a `known_hosts` line
/// holds in base64 and what `fingerprintText` reads.
pub const Verifier = struct {
    /// Passed back to `decide`.
    ctx: ?*anyopaque = null,
    decide: *const fn (
        ctx: ?*anyopaque,
        peer: Peer,
        key: PublicKey,
        blob: []const u8,
    ) TrustError!void,

    /// Asks the verifier about `key`.
    pub fn check(v: Verifier, peer: Peer, key: PublicKey, blob: []const u8) TrustError!void {
        return v.decide(v.ctx, peer, key, blob);
    }
};

const testing = std.testing;

/// A host key `ssh-keygen -t ed25519` produced, as the blob a server puts
/// on the wire. The fingerprint below is what `ssh-keygen -lf` printed for
/// the same key.
///
/// **Both values come from OpenSSH and not from this build**, so they
/// check the blob grammar and the fingerprint form against the program
/// every user compares zurl against.
const openssh_blob =
    "\x00\x00\x00\x0bssh-ed25519" ++
    "\x00\x00\x00\x20\x14\x97\x39\x67\xdd\xb9\x45\xf7\x9e\x21\xf5\x7c\xe5\x2c\xeb\x9a" ++
    "\xfc\x2d\x7c\xed\x69\xac\xbf\x13\x33\x6f\x68\x27\x18\x1c\x9f\xb4";
const openssh_fingerprint = "SHA256:BzhBXnUyS2UW9f+4rUVYltsPpuosxGA+oJO3dvUPSD0";

test "a host key blob OpenSSH wrote reads, and its fingerprint matches" {
    const key = try parse(openssh_blob, .ssh_ed25519);
    try testing.expectEqual(Algorithm.ssh_ed25519, key.algorithm());
    try testing.expectEqualSlices(
        u8,
        openssh_blob[19..51],
        &key.ssh_ed25519.toBytes(),
    );

    var text: [max_fingerprint_bytes]u8 = undefined;
    try testing.expectEqualStrings(openssh_fingerprint, fingerprintText(&text, openssh_blob));
}

test "a blob that names another algorithm is refused by name" {
    const rsa = "\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x01\x03";
    try testing.expectError(error.HostKeyAlgorithmUnsupported, parse(rsa, .ssh_ed25519));

    // A blob whose own name is one this build knows, but not the one the
    // negotiation chose, is a mismatch rather than an unknown name. There
    // is one supported name today, so this arm is reached by giving the
    // parser a name it knows against an expectation it cannot meet.
    try testing.expectEqual(@as(?Algorithm, null), fromName("ssh-rsa"));
    try testing.expectEqual(Algorithm.ssh_ed25519, fromName("ssh-ed25519").?);
}

test "a malformed host key blob is refused and never read past" {
    try testing.expectError(error.Truncated, parse("", .ssh_ed25519));
    try testing.expectError(error.LengthOutOfRange, parse("\x00\x00\xff\xff", .ssh_ed25519));
    // The right name, and a key of the wrong size.
    try testing.expectError(
        error.HostKeyMalformed,
        parse("\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x02ab", .ssh_ed25519),
    );
    // The right name and the right size, with bytes behind it.
    try testing.expectError(
        error.HostKeyMalformed,
        parse(openssh_blob ++ "extra", .ssh_ed25519),
    );
}

test "the signature check passes for the right key and fails for every other" {
    // A deterministic key pair, so the test is the same on every run.
    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    @memset(&seed, 0x2b);
    const pair = try Ed25519.KeyPair.generateDeterministic(seed);

    var blob_storage: [128]u8 = undefined;
    var blob_writer: wire.Writer = .init(&blob_storage);
    try blob_writer.string("ssh-ed25519");
    try blob_writer.string(&pair.public_key.toBytes());
    const blob = blob_writer.written();

    const exchange_hash = "a thirty two byte exchange hash!";
    const signature = try pair.sign(exchange_hash, null);

    var signature_storage: [128]u8 = undefined;
    var signature_writer: wire.Writer = .init(&signature_storage);
    try signature_writer.string("ssh-ed25519");
    try signature_writer.string(&signature.toBytes());
    const signature_blob = signature_writer.written();

    const key = try parse(blob, .ssh_ed25519);
    try verify(key, signature_blob, exchange_hash);

    // **A different message is a different hash, and the check must
    // fail.** This is what stops a signature captured from one session
    // from proving anything about another.
    try testing.expectError(
        error.HostKeySignatureInvalid,
        verify(key, signature_blob, "a thirty two byte exchange hash?"),
    );

    // A flipped bit anywhere in the signature fails too.
    for (0..Ed25519.Signature.encoded_length) |i| {
        var tampered: [128]u8 = undefined;
        @memcpy(tampered[0..signature_blob.len], signature_blob);
        tampered[19 + i] ^= 0x01;
        try testing.expectError(
            error.HostKeySignatureInvalid,
            verify(key, tampered[0..signature_blob.len], exchange_hash),
        );
    }

    // And a signature under another key fails, which is the whole point.
    var other_seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    @memset(&other_seed, 0x2c);
    const other = try Ed25519.KeyPair.generateDeterministic(other_seed);
    var other_blob_storage: [128]u8 = undefined;
    var other_blob_writer: wire.Writer = .init(&other_blob_storage);
    try other_blob_writer.string("ssh-ed25519");
    try other_blob_writer.string(&other.public_key.toBytes());
    const other_key = try parse(other_blob_writer.written(), .ssh_ed25519);
    try testing.expectError(
        error.HostKeySignatureInvalid,
        verify(other_key, signature_blob, exchange_hash),
    );
}

test "a signature blob of the wrong shape is refused before any curve work" {
    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    @memset(&seed, 0x31);
    const pair = try Ed25519.KeyPair.generateDeterministic(seed);
    var blob_storage: [128]u8 = undefined;
    var blob_writer: wire.Writer = .init(&blob_storage);
    try blob_writer.string("ssh-ed25519");
    try blob_writer.string(&pair.public_key.toBytes());
    const key = try parse(blob_writer.written(), .ssh_ed25519);

    try testing.expectError(error.Truncated, verify(key, "", "x"));
    try testing.expectError(
        error.HostKeyAlgorithmUnsupported,
        verify(key, "\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x00", "x"),
    );
    try testing.expectError(
        error.HostKeyMalformed,
        verify(key, "\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x03abc", "x"),
    );
}

test "every algorithm this build refuses gives a reason a user can act on" {
    // **A refusal with no reason is what this table exists to prevent.**
    const refused = [_][]const u8{
        "ssh-rsa",
        "rsa-sha2-256",
        "rsa-sha2-512",
        "ssh-dss",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "ssh-ed25519-cert-v01@openssh.com",
    };
    for (refused) |algorithm| {
        const reason = refusalFor(algorithm) orelse return error.TestExpectedReason;
        try testing.expect(reason.len != 0);
        try testing.expectEqual(@as(?Algorithm, null), fromName(algorithm));
    }
    // A name nobody has heard of needs no reason.
    try testing.expectEqual(@as(?[]const u8, null), refusalFor("made-up"));
    // And the one algorithm this build supports is never in the table.
    try testing.expectEqual(@as(?[]const u8, null), refusalFor("ssh-ed25519"));
}

test "a Verifier is called with the peer, the key, and the blob" {
    const Record = struct {
        host: []const u8 = "",
        port: u16 = 0,
        blob_len: usize = 0,
        answer: TrustError!void = {},

        fn decide(
            ctx: ?*anyopaque,
            peer: Peer,
            key: PublicKey,
            blob: []const u8,
        ) TrustError!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.host = peer.host;
            self.port = peer.port;
            self.blob_len = blob.len;
            std.debug.assert(key.algorithm() == .ssh_ed25519);
            return self.answer;
        }
    };

    var record: Record = .{};
    const verifier: Verifier = .{ .ctx = &record, .decide = Record.decide };
    const key = try parse(openssh_blob, .ssh_ed25519);

    try verifier.check(.{ .host = "example.test", .port = 2222 }, key, openssh_blob);
    try testing.expectEqualStrings("example.test", record.host);
    try testing.expectEqual(@as(u16, 2222), record.port);
    try testing.expectEqual(openssh_blob.len, record.blob_len);

    // **A verifier that says no ends the connection.** Every one of the
    // five answers is a refusal, and none of them is a value the
    // transport may carry on past.
    for ([_]TrustError{
        error.HostKeyUnknown,
        error.HostKeyChanged,
        error.HostKeyRejected,
        error.HostKeyCheckFailed,
        error.HostKeyAlgorithmUnknown,
    }) |answer| {
        record.answer = answer;
        try testing.expectError(
            answer,
            verifier.check(.{ .host = "example.test", .port = 22 }, key, openssh_blob),
        );
    }
}
