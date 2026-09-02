//! The keys QUIC version 1 writes into its own specification.
//!
//! **These are the two key sets that need no handshake at all**, so they
//! are the two this package can build while the TLS work is still to
//! come:
//!
//! - **The Initial keys, RFC 9001 section 5.2.** A client must protect
//!   its very first packet, and at that moment it has spoken to nobody.
//!   So QUIC derives those keys from the Destination Connection ID the
//!   client picked, with a salt printed in the RFC. That protects nothing
//!   from an attacker who read the packet, and it is not meant to: it
//!   keeps a middle box from reading and rewriting a handshake it does
//!   not understand. Section 5.2 says so in as many words.
//! - **The Retry integrity key, RFC 9001 section 5.8.** A Retry packet
//!   carries a 16-byte tag over a pseudo-packet that includes the
//!   client's original connection id. The key and the nonce are fixed
//!   numbers in the RFC, so anyone can check the tag and only somebody
//!   who saw the client's Initial packet can write one.
//!
//! Both use HKDF-SHA256 and AES-128-GCM alone, which `std.crypto` has. So
//! both are testable offline against RFC 9001 appendix A, and
//! `rfc9001_test.zig` checks them byte for byte.
//!
//! What this file does **not** have is the handshake keys and the 1-RTT
//! keys. Those come from TLS. `protection.Keys.fromSecret` is the call
//! that turns a TLS secret into a key set, and it is the same call this
//! file makes.

const std = @import("std");

const packet = @import("packet.zig");
const protection = @import("protection.zig");

/// The salt RFC 9001 section 5.2 prints for QUIC version 1.
///
/// This number changes with the QUIC version on purpose, so a packet of
/// one version cannot be read with another version's Initial keys.
pub const salt = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

/// The suite an Initial packet always uses. RFC 9001 section 5.2.
pub const suite: protection.Suite = .aes_128_gcm;

/// The label that derives the client's Initial secret.
pub const client_label = "client in";

/// The label that derives the server's Initial secret.
pub const server_label = "server in";

/// How many bytes an Initial secret takes. AES-128-GCM uses SHA-256.
pub const secret_len: usize = 32;

/// The two Initial secrets, one for each direction.
pub const Secrets = struct {
    /// Protects packets the client sends.
    client: [secret_len]u8,
    /// Protects packets the server sends.
    server: [secret_len]u8,
};

/// Derives the two Initial secrets from a Destination Connection ID. RFC
/// 9001 section 5.2.
///
/// `dcid` is the Destination Connection ID of the **client's first**
/// Initial packet, and it stays that value for the rest of the Initial
/// packets in both directions. A client that gets a Retry packet starts
/// again with the new one, which is what section 5.2 asks for.
pub fn secrets(dcid: []const u8) Secrets {
    std.debug.assert(dcid.len <= packet.max_connection_id_len);

    const initial_secret = std.crypto.kdf.hkdf.HkdfSha256.extract(&salt, dcid);
    var out: Secrets = .{ .client = undefined, .server = undefined };
    protection.expandLabel(.sha256, &initial_secret, client_label, &out.client);
    protection.expandLabel(.sha256, &initial_secret, server_label, &out.server);
    return out;
}

/// The secret before the two directions split. RFC 9001 section 5.2.
///
/// Exported because appendix A.1 prints it, so a test can check the
/// extract and the two expands one at a time.
pub fn extractSecret(dcid: []const u8) [secret_len]u8 {
    std.debug.assert(dcid.len <= packet.max_connection_id_len);
    return std.crypto.kdf.hkdf.HkdfSha256.extract(&salt, dcid);
}

/// The key set that protects packets the client sends.
pub fn clientKeys(dcid: []const u8) protection.Keys {
    return .fromSecret(suite, &secrets(dcid).client);
}

/// The key set that protects packets the server sends.
pub fn serverKeys(dcid: []const u8) protection.Keys {
    return .fromSecret(suite, &secrets(dcid).server);
}

/// The fixed key RFC 9001 section 5.8 uses for a Retry integrity tag.
pub const retry_key = [_]u8{
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
};

/// The fixed nonce RFC 9001 section 5.8 uses for a Retry integrity tag.
pub const retry_nonce = [_]u8{
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
};

/// The longest Retry packet this build will check.
///
/// **A tag needs its whole pseudo-packet in one run of bytes**, and
/// nothing in this package allocates, so the buffer is on the stack and
/// the stack needs a bound. A Retry packet carries an address validation
/// token the server chose, and no server sends one near this large: the
/// packet has to cross the path in one datagram. A longer one is refused
/// by name rather than truncated into a tag that would not match.
pub const max_retry_bytes: usize = 4096;

/// Why a Retry integrity tag could not be computed.
pub const RetryError = error{
    /// The Retry packet is longer than `max_retry_bytes`.
    RetryTooLong,
    /// The Retry packet is shorter than its own integrity tag.
    RetryTooShort,
    /// The original Destination Connection ID is longer than the 20 bytes
    /// RFC 9000 section 17.2 allows.
    OdcidTooLong,
};

/// The Retry integrity tag for one Retry packet. RFC 9001 section 5.8.
///
/// `odcid` is the Destination Connection ID of the client's Initial
/// packet, the one the Retry answers. `retry_without_tag` is the whole
/// Retry packet with its last 16 bytes left off.
///
/// The pseudo-packet is the length of `odcid` as one byte, `odcid`, and
/// then `retry_without_tag`. That is the associated data, the plaintext
/// is empty, and the tag is the whole output.
///
/// **Both bounds of the buffer are returned errors and neither is an
/// assert.** Every byte this function reads came off the wire, and an
/// assert is compiled out of a release build. A long `odcid` would write
/// past the stack buffer and would also lose its own length, because the
/// first byte of the pseudo-packet holds that length in one octet.
pub fn retryIntegrityTag(
    odcid: []const u8,
    retry_without_tag: []const u8,
) RetryError![packet.retry_integrity_tag_len]u8 {
    if (odcid.len > packet.max_connection_id_len) return error.OdcidTooLong;
    if (retry_without_tag.len > max_retry_bytes) return error.RetryTooLong;

    var pseudo: [1 + packet.max_connection_id_len + max_retry_bytes]u8 = undefined;
    pseudo[0] = @intCast(odcid.len);
    @memcpy(pseudo[1..][0..odcid.len], odcid);
    const at = 1 + odcid.len;
    @memcpy(pseudo[at..][0..retry_without_tag.len], retry_without_tag);
    const aad = pseudo[0 .. at + retry_without_tag.len];

    var tag: [packet.retry_integrity_tag_len]u8 = undefined;
    var empty: [0]u8 = undefined;
    std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(&empty, &tag, &.{}, aad, retry_nonce, retry_key);
    return tag;
}

/// True when a whole Retry packet carries the tag it should.
///
/// **A client must check this before it acts on a Retry.** RFC 9000
/// section 17.2.5.2 says a client discards a Retry with a tag that does
/// not match, because only somebody who saw the client's Initial packet
/// can write one. A client that skipped the check would let anyone on the
/// path restart its handshake with a connection id of their choosing.
///
/// The comparison runs in constant time, so a wrong tag tells a watcher
/// nothing about how wrong it was.
pub fn verifyRetry(odcid: []const u8, retry: []const u8) RetryError!bool {
    if (retry.len < packet.retry_integrity_tag_len) return error.RetryTooShort;
    const split = retry.len - packet.retry_integrity_tag_len;
    const want = try retryIntegrityTag(odcid, retry[0..split]);
    return std.crypto.timing_safe.eql(
        [packet.retry_integrity_tag_len]u8,
        want,
        retry[split..][0..packet.retry_integrity_tag_len].*,
    );
}

const testing = std.testing;

test "the Initial salt is the one RFC 9001 section 5.2 prints" {
    try testing.expectEqual(@as(usize, 20), salt.len);
    var buffer: [64]u8 = undefined;
    try testing.expectEqualStrings(
        "38762cf7f55934b34d179ae6a4c80cadccbb7f0a",
        try std.fmt.bufPrint(&buffer, "{x}", .{salt}),
    );
}

test "the Retry key and nonce are the ones RFC 9001 section 5.8 prints" {
    var buffer: [64]u8 = undefined;
    try testing.expectEqualStrings(
        "be0c690b9f66575a1d766b54e368c84e",
        try std.fmt.bufPrint(&buffer, "{x}", .{retry_key}),
    );
    try testing.expectEqualStrings(
        "461599d35d632bf2239825bb",
        try std.fmt.bufPrint(&buffer, "{x}", .{retry_nonce}),
    );
}

test "a Retry packet longer than the bound is refused rather than cut" {
    // The pseudo-packet lives on the stack, so the stack needs a bound.
    // A truncated tag would not match and the reason would be invisible.
    const long: [max_retry_bytes + 1]u8 = @splat(0);
    try testing.expectError(error.RetryTooLong, retryIntegrityTag(&.{1}, &long));
    // And a Retry with no room for its own tag says so.
    try testing.expectError(error.RetryTooShort, verifyRetry(&.{1}, &.{ 1, 2, 3 }));
}

test "a connection id longer than the bound is refused rather than written past the buffer" {
    // **Both bounds of the pseudo-packet are errors.** An assert is
    // compiled out of a release build, and a 100 byte connection id with
    // a full length Retry would write 4197 bytes into a 4117 byte stack
    // buffer. The first byte also holds the length in one octet, which
    // has no meaning above 255.
    const too_long: [packet.max_connection_id_len + 1]u8 = @splat(0);
    try testing.expectError(error.OdcidTooLong, retryIntegrityTag(&too_long, &.{1}));
    try testing.expectError(error.OdcidTooLong, verifyRetry(&too_long, &([_]u8{0} ** 20)));

    const huge: [300]u8 = @splat(7);
    try testing.expectError(error.OdcidTooLong, retryIntegrityTag(&huge, &.{1}));

    // Exactly the bound is still legal, and it gives a tag.
    const at_bound: [packet.max_connection_id_len]u8 = @splat(0);
    _ = try retryIntegrityTag(&at_bound, &.{1});
}

test "an Initial key set uses AES-128-GCM whatever the connection id is" {
    // RFC 9001 section 5.2 fixes the suite, because nothing has been
    // negotiated when these keys are made.
    const keys = clientKeys(&.{ 1, 2, 3, 4 });
    try testing.expectEqual(protection.Suite.aes_128_gcm, keys.suite);
    try testing.expectEqual(@as(usize, 16), keys.keySlice().len);
    try testing.expectEqual(@as(usize, 16), keys.headerKeySlice().len);
    try testing.expectEqual(@as(usize, 12), keys.iv.len);
}

test "a different connection id gives a different Initial key set" {
    // The connection id is the only input, so two connections that picked
    // different ids cannot read each other's Initial packets.
    const one = secrets(&.{ 1, 2, 3, 4 });
    const two = secrets(&.{ 1, 2, 3, 5 });
    try testing.expect(!std.mem.eql(u8, &one.client, &two.client));
    try testing.expect(!std.mem.eql(u8, &one.server, &two.server));
    // And the two directions never share a secret.
    try testing.expect(!std.mem.eql(u8, &one.client, &one.server));
}

test "an empty connection id still derives a key set" {
    // A client may pick a zero-length source id, and RFC 9000 section
    // 7.2 makes the destination id of a first Initial packet at least 8
    // bytes. Nothing here refuses the short case, because the derivation
    // is the same and the length rule belongs to the layer above.
    const keys = serverKeys(&.{});
    try testing.expectEqual(protection.Suite.aes_128_gcm, keys.suite);
}
