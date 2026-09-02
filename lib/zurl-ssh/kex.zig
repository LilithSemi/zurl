//! `curve25519-sha256`, RFC 8731, and the key derivation of RFC 4253
//! section 7.2.
//!
//! The exchange runs in two packets:
//!
//! ```
//! C -> S  SSH_MSG_KEX_ECDH_INIT    string Q_C
//! S -> C  SSH_MSG_KEX_ECDH_REPLY   string K_S, string Q_S, string signature
//! ```
//!
//! **The exchange hash `H` is the whole point of the exchange, and its
//! input is exactly eight fields in exactly one order.** RFC 4253
//! section 8 gives the list and RFC 8731 section 3 keeps it:
//!
//! ```
//! H = SHA256( string V_C || string V_S || string I_C || string I_S ||
//!             string K_S || string Q_C || string Q_S || mpint  K )
//! ```
//!
//! - `V_C` and `V_S` are the two identification strings **with no line
//!   ending on them**.
//! - `I_C` and `I_S` are the two `SSH_MSG_KEXINIT` payloads, **the message
//!   number included**, exactly as they went on the wire.
//! - `K_S` is the host key blob, exactly as the server sent it.
//! - `Q_C` and `Q_S` are the two 32 byte X25519 public values.
//! - `K` is the shared secret, as an **mpint** and not as a string. RFC
//!   8731 section 3 says so, and the difference is a leading zero byte
//!   whenever the top bit of the secret is set, which happens about half
//!   the time.
//!
//! A mistake anywhere in that list gives a hash that the server does not
//! agree with, so the server's signature over its own `H` fails against
//! ours. That failure is the proof this file is right: see the report and
//! `test_server.zig`.
//!
//! `H` of the first exchange is also the `session_id`, and it never
//! changes for the life of the connection. Every later exchange makes a
//! new `H` and keeps the first `session_id`.
//!
//! **The all-zero shared secret is refused.** RFC 8731 section 3 says a
//! client must check for it. `std.crypto.dh.X25519.scalarmult` reports it
//! as `error.IdentityElement`, and `sharedSecret` turns that into a named
//! refusal.
//!
//! What this module does not own: it draws no entropy and it moves no
//! byte. `zurl_ssh.Transport` draws the ephemeral key pair and sends the
//! packets.

const std = @import("std");

const messages = @import("messages.zig");
const wire = @import("wire.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const X25519 = std.crypto.dh.X25519;

/// How many bytes `curve25519-sha256` hashes to.
pub const hash_bytes = Sha256.digest_length;

/// How many bytes an X25519 public value takes.
pub const public_bytes = X25519.public_length;

/// The eight fields of the exchange hash, in the order RFC 4253 section 8
/// gives them.
///
/// The field order in this struct is the wire order on purpose. A reader
/// checking this file against the RFC reads one list.
pub const ExchangeHashInputs = struct {
    /// `V_C`, the client identification string with no line ending.
    client_version: []const u8,
    /// `V_S`, the server identification string with no line ending.
    server_version: []const u8,
    /// `I_C`, the client `SSH_MSG_KEXINIT` payload, the message number
    /// included.
    client_kexinit: []const u8,
    /// `I_S`, the server `SSH_MSG_KEXINIT` payload, the message number
    /// included.
    server_kexinit: []const u8,
    /// `K_S`, the host key blob as the server sent it.
    host_key_blob: []const u8,
    /// `Q_C`, the client X25519 public value.
    client_public: []const u8,
    /// `Q_S`, the server X25519 public value.
    server_public: []const u8,
    /// `K`, the shared secret as a big-endian magnitude. It goes in as an
    /// mpint.
    shared_secret: []const u8,
};

/// Builds the exchange hash.
///
/// The hash runs over the fields as they arrive, so no buffer holds the
/// whole input and a large `K_S` costs nothing extra.
pub fn exchangeHash(in: ExchangeHashInputs) [hash_bytes]u8 {
    var hasher: Sha256 = .init(.{});
    hashString(&hasher, in.client_version);
    hashString(&hasher, in.server_version);
    hashString(&hasher, in.client_kexinit);
    hashString(&hasher, in.server_kexinit);
    hashString(&hasher, in.host_key_blob);
    hashString(&hasher, in.client_public);
    hashString(&hasher, in.server_public);
    hashMpint(&hasher, in.shared_secret);

    var digest: [hash_bytes]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

/// Hashes one `string`: the 32-bit length, then the bytes.
fn hashString(hasher: *Sha256, data: []const u8) void {
    var length: [4]u8 = undefined;
    std.mem.writeInt(u32, &length, @intCast(data.len), .big);
    hasher.update(&length);
    hasher.update(data);
}

/// Hashes one `mpint`, from a big-endian magnitude.
///
/// The rule is `wire.Writer.mpint`'s rule, and the two must agree: the
/// same secret goes into the hash here and onto the wire there.
fn hashMpint(hasher: *Sha256, magnitude: []const u8) void {
    const trimmed = wire.trimLeadingZeros(magnitude);
    if (trimmed.len == 0) {
        hasher.update(&[_]u8{ 0, 0, 0, 0 });
        return;
    }
    const pad: u32 = if (trimmed[0] & 0x80 != 0) 1 else 0;
    var length: [4]u8 = undefined;
    std.mem.writeInt(u32, &length, @as(u32, @intCast(trimmed.len)) + pad, .big);
    hasher.update(&length);
    if (pad == 1) hasher.update(&[_]u8{0});
    hasher.update(trimmed);
}

/// Which key RFC 4253 section 7.2 derives, and the letter it uses.
pub const KeyPurpose = enum(u8) {
    initial_iv_client_to_server = 'A',
    initial_iv_server_to_client = 'B',
    encryption_key_client_to_server = 'C',
    encryption_key_server_to_client = 'D',
    integrity_key_client_to_server = 'E',
    integrity_key_server_to_client = 'F',
};

/// Fills `out` with one derived key, RFC 4253 section 7.2.
///
/// ```
/// K1 = HASH(K || H || purpose || session_id)
/// K2 = HASH(K || H || K1)
/// K3 = HASH(K || H || K1 || K2)   and so on
/// key = K1 || K2 || K3 || ...
/// ```
///
/// `K` goes in as an mpint, the same way it went into `H`.
///
/// `out` may be longer than one hash, and
/// `chacha20-poly1305@openssh.com` is why: it takes 64 bytes of key and
/// SHA-256 gives 32 at a time.
///
/// `session_id` is `H` of the **first** exchange and never of a later
/// one. A rekey derives new keys from the new `H` and the old
/// `session_id`.
pub fn deriveKey(
    out: []u8,
    shared_secret: []const u8,
    h: [hash_bytes]u8,
    purpose: KeyPurpose,
    session_id: []const u8,
) void {
    if (out.len == 0) return;

    var produced: usize = 0;
    var block: [hash_bytes]u8 = undefined;

    var first: Sha256 = .init(.{});
    hashMpint(&first, shared_secret);
    first.update(&h);
    first.update(&[_]u8{@intFromEnum(purpose)});
    first.update(session_id);
    first.final(&block);

    while (true) {
        const take = @min(out.len - produced, hash_bytes);
        @memcpy(out[produced..][0..take], block[0..take]);
        produced += take;
        if (produced == out.len) break;

        // Each later block hashes every byte produced so far, so the
        // whole run has to be hashed again. The runs this build asks for
        // are 64 bytes at most, which is two blocks.
        var next: Sha256 = .init(.{});
        hashMpint(&next, shared_secret);
        next.update(&h);
        next.update(out[0..produced]);
        next.final(&block);
    }
    std.crypto.secureZero(u8, &block);
}

/// Why the shared secret was refused.
pub const SharedSecretError = error{
    /// `Q_S` is not 32 bytes. RFC 8731 section 3 fixes the size.
    ServerPublicKeyMalformed,
    /// The shared secret came out all zero, which means `Q_S` is a point
    /// of small order. RFC 8731 section 3 says a client must check for
    /// this and end the connection.
    ServerPublicKeyWeak,
};

/// Computes `K` from this side's secret and the server's public value.
pub fn sharedSecret(
    secret: [X25519.secret_length]u8,
    server_public: []const u8,
) SharedSecretError![X25519.shared_length]u8 {
    if (server_public.len != public_bytes) return error.ServerPublicKeyMalformed;
    return X25519.scalarmult(secret, server_public[0..public_bytes].*) catch
        return error.ServerPublicKeyWeak;
}

/// Builds a `SSH_MSG_KEX_ECDH_INIT` into `out`.
pub fn writeEcdhInit(out: []u8, client_public: [public_bytes]u8) wire.WriteError![]u8 {
    var w: wire.Writer = .init(out);
    try w.byte(@intFromEnum(messages.Id.kex_ecdh_init));
    try w.string(&client_public);
    return w.written();
}

/// How many bytes a `SSH_MSG_KEX_ECDH_INIT` takes.
pub const ecdh_init_bytes = 1 + 4 + public_bytes;

/// Why a `SSH_MSG_KEX_ECDH_REPLY` was not read.
pub const ParseError = wire.ReadError || error{
    /// The payload is not a `SSH_MSG_KEX_ECDH_REPLY`.
    WrongMessage,
    /// There are bytes behind the three fields. A reply with a tail is a
    /// reply this build does not understand, and the tail would not be in
    /// the exchange hash.
    ReplyHasTrailingBytes,
};

/// The three fields of a `SSH_MSG_KEX_ECDH_REPLY`, RFC 5656 section 7.1.
///
/// Every slice points into the payload it was read from, and each one
/// goes into the exchange hash exactly as it arrived.
pub const EcdhReply = struct {
    host_key_blob: []const u8,
    server_public: []const u8,
    signature_blob: []const u8,
};

/// Reads a `SSH_MSG_KEX_ECDH_REPLY`.
pub fn parseEcdhReply(payload: []const u8) ParseError!EcdhReply {
    var r: wire.Reader = .init(payload);
    if (try r.byte() != @intFromEnum(messages.Id.kex_ecdh_reply)) return error.WrongMessage;
    const host_key_blob = try r.string();
    const server_public = try r.string();
    const signature_blob = try r.string();
    if (!r.atEnd()) return error.ReplyHasTrailingBytes;
    return .{
        .host_key_blob = host_key_blob,
        .server_public = server_public,
        .signature_blob = signature_blob,
    };
}

const testing = std.testing;

test "the exchange hash is the eight fields, in order, and nothing else" {
    // **This is the cross-check on the field order and on the mpint.**
    // The expected digest below is built here by writing the whole input
    // into one buffer by hand, straight off the list in RFC 4253
    // section 8, and hashing it once. `exchangeHash` hashes the same
    // fields one at a time. The two must agree.
    const inputs: ExchangeHashInputs = .{
        .client_version = "SSH-2.0-zurl_1.1",
        .server_version = "SSH-2.0-OpenSSH_9.6",
        .client_kexinit = "\x14client kexinit payload",
        .server_kexinit = "\x14server kexinit payload",
        .host_key_blob = "\x00\x00\x00\x0bssh-ed25519",
        .client_public = "Q_C thirty two bytes long here!!",
        .server_public = "Q_S thirty two bytes long here!!",
        // The top bit is set, so the mpint gains a leading zero byte.
        .shared_secret = &[_]u8{0x80} ** 32,
    };

    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(testing.allocator);
    const strings = [_][]const u8{
        inputs.client_version,
        inputs.server_version,
        inputs.client_kexinit,
        inputs.server_kexinit,
        inputs.host_key_blob,
        inputs.client_public,
        inputs.server_public,
    };
    for (strings) |field| {
        var length: [4]u8 = undefined;
        std.mem.writeInt(u32, &length, @intCast(field.len), .big);
        try buffer.appendSlice(testing.allocator, &length);
        try buffer.appendSlice(testing.allocator, field);
    }
    // The mpint, written by the other implementation of the same rule.
    var mpint_storage: [64]u8 = undefined;
    var mpint_writer: wire.Writer = .init(&mpint_storage);
    try mpint_writer.mpint(inputs.shared_secret);
    try buffer.appendSlice(testing.allocator, mpint_writer.written());
    // 33 bytes of value and a leading zero, so 4 + 33.
    try testing.expectEqual(@as(usize, 37), mpint_writer.written().len);

    var expected: [hash_bytes]u8 = undefined;
    Sha256.hash(buffer.items, &expected, .{});
    try testing.expectEqualSlices(u8, &expected, &exchangeHash(inputs));
}

test "every field changes the exchange hash" {
    // **A field that is hashed in the wrong place, or not at all, would
    // let this pass.** Each case below changes one field and nothing
    // else, and each must give a different hash.
    const base: ExchangeHashInputs = .{
        .client_version = "SSH-2.0-a",
        .server_version = "SSH-2.0-b",
        .client_kexinit = "\x14c",
        .server_kexinit = "\x14d",
        .host_key_blob = "e",
        .client_public = "f",
        .server_public = "g",
        .shared_secret = "h",
    };
    const original = exchangeHash(base);

    inline for (@typeInfo(ExchangeHashInputs).@"struct".fields) |field| {
        var changed = base;
        @field(changed, field.name) = "changed";
        try testing.expect(!std.mem.eql(u8, &original, &exchangeHash(changed)));
    }

    // And the length prefix is real: two fields whose bytes run together
    // the same way must still hash apart.
    var moved = base;
    moved.client_version = "SSH-2.0-aSSH-2.0-b";
    moved.server_version = "";
    try testing.expect(!std.mem.eql(u8, &original, &exchangeHash(moved)));
}

test "the shared secret goes in as an mpint and never as a string" {
    // A secret whose top bit is set gains a leading zero byte. A build
    // that wrote it as a plain string would hash 32 bytes where the
    // server hashed 33, and no handshake would ever complete.
    const high: ExchangeHashInputs = .{
        .client_version = "v",
        .server_version = "v",
        .client_kexinit = "i",
        .server_kexinit = "i",
        .host_key_blob = "k",
        .client_public = "q",
        .server_public = "q",
        .shared_secret = &[_]u8{0xff} ** 32,
    };
    var as_string: [4 + 32]u8 = undefined;
    std.mem.writeInt(u32, as_string[0..4], 32, .big);
    @memset(as_string[4..], 0xff);

    var hasher: Sha256 = .init(.{});
    inline for (.{ "v", "v", "i", "i", "k", "q", "q" }) |field| {
        var length: [4]u8 = undefined;
        std.mem.writeInt(u32, &length, field.len, .big);
        hasher.update(&length);
        hasher.update(field);
    }
    var string_style: Sha256 = hasher;
    string_style.update(&as_string);
    var wrong: [hash_bytes]u8 = undefined;
    string_style.final(&wrong);

    try testing.expect(!std.mem.eql(u8, &wrong, &exchangeHash(high)));

    // And a secret with a leading zero byte hashes the same as the same
    // number without it, because an mpint carries no leading zero.
    var trimmed = high;
    trimmed.shared_secret = &([_]u8{0} ** 3 ++ [_]u8{0x7f} ** 29);
    var untrimmed = high;
    untrimmed.shared_secret = &[_]u8{0x7f} ** 29;
    try testing.expectEqualSlices(u8, &exchangeHash(trimmed), &exchangeHash(untrimmed));
}

test "the derived keys differ by purpose and fill a run longer than one hash" {
    const secret = [_]u8{0x11} ** 32;
    const h = [_]u8{0x22} ** hash_bytes;
    const session_id = [_]u8{0x33} ** hash_bytes;

    var seen: [6][64]u8 = undefined;
    const purposes = [_]KeyPurpose{
        .initial_iv_client_to_server,
        .initial_iv_server_to_client,
        .encryption_key_client_to_server,
        .encryption_key_server_to_client,
        .integrity_key_client_to_server,
        .integrity_key_server_to_client,
    };
    for (purposes, 0..) |purpose, i| {
        deriveKey(&seen[i], &secret, h, purpose, &session_id);
    }
    for (0..purposes.len) |i| {
        for (i + 1..purposes.len) |j| {
            try testing.expect(!std.mem.eql(u8, &seen[i], &seen[j]));
        }
    }

    // The first 32 bytes of a 64 byte run are the 32 byte run, which is
    // what RFC 4253 section 7.2 describes.
    var short: [32]u8 = undefined;
    deriveKey(&short, &secret, h, .encryption_key_client_to_server, &session_id);
    try testing.expectEqualSlices(u8, &short, seen[2][0..32]);

    // The second block is `HASH(K || H || K1)`, built here on its own.
    var expected_second: [hash_bytes]u8 = undefined;
    var hasher: Sha256 = .init(.{});
    // The mpint of a secret whose top bit is clear is the length and the
    // 32 bytes, with no leading zero.
    hasher.update("\x00\x00\x00\x20");
    hasher.update(&secret);
    hasher.update(&h);
    hasher.update(&short);
    hasher.final(&expected_second);
    try testing.expectEqualSlices(u8, &expected_second, seen[2][32..64]);
}

test "a key run shorter than one hash takes the front of it" {
    const secret = [_]u8{0x44} ** 32;
    const h = [_]u8{0x55} ** hash_bytes;
    var twelve: [12]u8 = undefined;
    var full: [32]u8 = undefined;
    deriveKey(&twelve, &secret, h, .initial_iv_server_to_client, &h);
    deriveKey(&full, &secret, h, .initial_iv_server_to_client, &h);
    try testing.expectEqualSlices(u8, &twelve, full[0..12]);

    // A run of nothing asks for nothing, which is what
    // `chacha20-poly1305@openssh.com` needs for its initialisation
    // vector.
    var none: [0]u8 = undefined;
    deriveKey(&none, &secret, h, .initial_iv_client_to_server, &h);
}

test "a rekey keeps the first session id and takes the new exchange hash" {
    // The session id is the argument, so this proves the shape rather
    // than the transport's use of it. The transport test proves the use.
    const secret = [_]u8{0x66} ** 32;
    const session_id = [_]u8{0x77} ** hash_bytes;
    const first_h = session_id;
    const second_h = [_]u8{0x88} ** hash_bytes;

    var before: [32]u8 = undefined;
    var after: [32]u8 = undefined;
    deriveKey(&before, &secret, first_h, .encryption_key_client_to_server, &session_id);
    deriveKey(&after, &secret, second_h, .encryption_key_client_to_server, &session_id);
    try testing.expect(!std.mem.eql(u8, &before, &after));
}

test "the shared secret refuses a public value of the wrong size" {
    const secret = [_]u8{0x99} ** 32;
    try testing.expectError(error.ServerPublicKeyMalformed, sharedSecret(secret, ""));
    try testing.expectError(
        error.ServerPublicKeyMalformed,
        sharedSecret(secret, &[_]u8{0} ** 31),
    );
}

test "an all zero shared secret is refused, as RFC 8731 section 3 asks" {
    // **A point of small order gives every client the same secret.** The
    // all-zero public value is one, and a client that carried on would
    // agree a key with anybody who sent it.
    const secret = [_]u8{0x9a} ** 32;
    try testing.expectError(
        error.ServerPublicKeyWeak,
        sharedSecret(secret, &[_]u8{0} ** 32),
    );
    // The order two point is another.
    var order_two: [32]u8 = @splat(0);
    order_two[0] = 1;
    try testing.expectError(error.ServerPublicKeyWeak, sharedSecret(secret, &order_two));
}

test "two X25519 sides reach the same secret" {
    var client_seed: [32]u8 = undefined;
    @memset(&client_seed, 0xa1);
    var server_seed: [32]u8 = undefined;
    @memset(&server_seed, 0xb2);
    const client = try X25519.KeyPair.generateDeterministic(client_seed);
    const server = try X25519.KeyPair.generateDeterministic(server_seed);

    const from_client = try sharedSecret(client.secret_key, &server.public_key);
    const from_server = try sharedSecret(server.secret_key, &client.public_key);
    try testing.expectEqualSlices(u8, &from_client, &from_server);
}

test "the two key exchange packets are written and read back" {
    var storage: [ecdh_init_bytes]u8 = undefined;
    const public: [public_bytes]u8 = @splat(0xcd);
    const init_packet = try writeEcdhInit(&storage, public);
    try testing.expectEqual(ecdh_init_bytes, init_packet.len);
    try testing.expectEqual(@as(u8, 30), init_packet[0]);

    const reply =
        "\x1f" ++
        "\x00\x00\x00\x03key" ++
        "\x00\x00\x00\x03pub" ++
        "\x00\x00\x00\x03sig";
    const parsed = try parseEcdhReply(reply);
    try testing.expectEqualStrings("key", parsed.host_key_blob);
    try testing.expectEqualStrings("pub", parsed.server_public);
    try testing.expectEqualStrings("sig", parsed.signature_blob);
}

test "a reply that is short, wrong, or has a tail is refused" {
    try testing.expectError(error.Truncated, parseEcdhReply(""));
    try testing.expectError(error.WrongMessage, parseEcdhReply("\x1e\x00\x00\x00\x00"));
    try testing.expectError(error.Truncated, parseEcdhReply("\x1f\x00\x00\x00\x03key"));
    try testing.expectError(
        error.LengthOutOfRange,
        parseEcdhReply("\x1f\xff\xff\xff\xff"),
    );
    // **A tail is refused because nothing would hash it.** A reply the
    // signature does not cover is a reply an attacker can add to.
    try testing.expectError(
        error.ReplyHasTrailingBytes,
        parseEcdhReply(
            "\x1f\x00\x00\x00\x03key\x00\x00\x00\x03pub\x00\x00\x00\x03sigtail",
        ),
    );
}
