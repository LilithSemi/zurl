//! The `openssh-key-v1` private key format. Pure bytes, and testable
//! against files `ssh-keygen` wrote.
//!
//! What this module owns: the PEM wrapper, the base64 body, the container
//! of the format, the `bcrypt` key derivation, the `aes256-ctr` decryption
//! of an encrypted key, and the `ssh-ed25519` key pair inside it. It also
//! owns the signature a `publickey` attempt sends.
//!
//! What this module does not own: it opens no file and it reads no
//! directory. `zurl_ssh.keyfile` finds a key on disk and hands the text
//! here.
//!
//! **A private key file is a secret at rest, and every buffer that touches
//! it is wiped.** The decoded container, the private section, the derived
//! key and initialisation vector, and the key pair itself all pass through
//! `std.crypto.secureZero` before the memory goes back. `PrivateKey.deinit`
//! is the one a caller must not forget, and the rest happens inside
//! `parse` whichever way it leaves.
//!
//! **The passphrase belongs to the caller.** This module reads it, derives
//! from it, and keeps no copy. A caller that read a passphrase from a
//! terminal or a file wipes its own buffer.
//!
//! **What this build reads, and what it refuses by name.** `ssh-ed25519`
//! only, because `std.crypto` has no RSA signer and
//! `zurl_ssh.Transport` already refuses an RSA host key for the same
//! reason. `refusalFor` names every other key type and says why, so a user
//! with an `id_rsa` sees which key was found rather than a blank failure.
//! `cipherRefusalFor` and `kdfRefusalFor` do the same for an encrypted key
//! this build cannot open.
//!
//! The format, which OpenSSH's `PROTOCOL.key` describes:
//!
//!     "openssh-key-v1\0"
//!     string    cipher name
//!     string    kdf name
//!     string    kdf options
//!     uint32    number of keys, which is always 1
//!     string    public key blob
//!     string    the private section, encrypted and padded
//!
//! and the private section, once it is open:
//!
//!     uint32    check integer
//!     uint32    the same check integer
//!     string    key type
//!     ...       the key itself
//!     string    comment
//!     byte[n]   padding, 1, 2, 3, and so on
//!
//! **The two check integers are how the format catches a wrong
//! passphrase.** They are one random value written twice. A wrong key
//! decrypts them to two unrelated numbers, and the odds of a false match
//! are one in 2^32.

const std = @import("std");

const wire = @import("wire.zig");

const Aes256 = std.crypto.core.aes.Aes256;
const Allocator = std.mem.Allocator;
const Ed25519 = std.crypto.sign.Ed25519;
const bcrypt = std.crypto.pwhash.bcrypt;
const ctr = std.crypto.core.modes.ctr;

/// The first bytes of the container, with the zero byte at the end.
pub const magic = "openssh-key-v1\x00";

/// The first line of the PEM wrapper.
pub const pem_begin = "-----BEGIN OPENSSH PRIVATE KEY-----";

/// The last line of the PEM wrapper.
pub const pem_end = "-----END OPENSSH PRIVATE KEY-----";

/// The bound on a key file, in bytes of text.
///
/// An `ssh-ed25519` key file is under 500 bytes and an RSA 4096 key file
/// is under 4 kilobytes. The bound stops a file that is not a key at all
/// from costing this process anything.
pub const max_text_bytes = 16384;

/// The bound on the container, after the base64 comes off.
pub const max_container_bytes = 12288;

/// The bound on the public key blob inside a key file.
pub const max_public_blob_bytes = 1024;

/// How many bytes of the comment are kept.
pub const max_comment_bytes = 255;

/// How many bytes a signature blob needs, at most.
///
/// `string "ssh-ed25519"` and `string` of a 64 byte signature.
pub const max_signature_bytes = 4 + 11 + 4 + Ed25519.Signature.encoded_length;

/// The rounds a `bcrypt` key derivation may ask for.
///
/// `ssh-keygen -a` writes 16 by default and a user may ask for more. Each
/// round is real work, so a file that asks for a million is a file that
/// stops this process, and the bound is what refuses it.
pub const max_kdf_rounds = 1024;

/// The key types this build can sign with.
pub const Algorithm = enum {
    ssh_ed25519,

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
            if (std.mem.eql(u8, text, candidate.name())) return candidate;
        }
        return null;
    }
};

/// Why this build cannot sign with a key type it found, in words a user
/// can act on.
///
/// Null for a name this build has never heard of.
pub fn refusalFor(text: []const u8) ?[]const u8 {
    const table = [_]struct { key_type: []const u8, reason: []const u8 }{
        .{
            .key_type = "ssh-rsa",
            .reason = "zurl carries no RSA signer, and Zig's standard library has none outside TLS",
        },
        .{
            .key_type = "rsa-sha2-256",
            .reason = "zurl carries no RSA signer, and Zig's standard library has none outside TLS",
        },
        .{
            .key_type = "rsa-sha2-512",
            .reason = "zurl carries no RSA signer, and Zig's standard library has none outside TLS",
        },
        .{
            .key_type = "ssh-dss",
            .reason = "DSA with a 1024 bit key is too weak, and OpenSSH removed it",
        },
        .{
            .key_type = "ecdsa-sha2-nistp256",
            .reason = "zurl signs with Ed25519 keys only",
        },
        .{
            .key_type = "ecdsa-sha2-nistp384",
            .reason = "zurl signs with Ed25519 keys only",
        },
        .{
            .key_type = "ecdsa-sha2-nistp521",
            .reason = "zurl signs with Ed25519 keys only",
        },
        .{
            .key_type = "sk-ssh-ed25519@openssh.com",
            .reason = "a security key needs a USB token this build cannot talk to",
        },
        .{
            .key_type = "sk-ecdsa-sha2-nistp256@openssh.com",
            .reason = "a security key needs a USB token this build cannot talk to",
        },
        .{
            .key_type = "ssh-ed25519-cert-v01@openssh.com",
            .reason = "zurl sends no certificate, so the plain ssh-ed25519 key is needed",
        },
    };
    for (table) |row| {
        if (std.mem.eql(u8, text, row.key_type)) return row.reason;
    }
    return null;
}

/// Why this build cannot open a key encrypted with a cipher it found.
///
/// Null for a name this build has never heard of.
pub fn cipherRefusalFor(text: []const u8) ?[]const u8 {
    const table = [_]struct { cipher: []const u8, reason: []const u8 }{
        .{
            .cipher = "aes128-ctr",
            .reason = "ssh-keygen writes aes256-ctr, so a 128 bit key came from another tool",
        },
        .{
            .cipher = "aes192-ctr",
            .reason = "ssh-keygen writes aes256-ctr, so a 192 bit key came from another tool",
        },
        .{
            .cipher = "aes128-cbc",
            .reason = "zurl opens aes256-ctr only, which is what ssh-keygen writes",
        },
        .{
            .cipher = "aes192-cbc",
            .reason = "zurl opens aes256-ctr only, which is what ssh-keygen writes",
        },
        .{
            .cipher = "aes256-cbc",
            .reason = "zurl opens aes256-ctr only, which is what ssh-keygen writes",
        },
        .{
            .cipher = "3des-cbc",
            .reason = "triple DES is too weak, and OpenSSH stopped writing it",
        },
        .{
            .cipher = "aes128-gcm@openssh.com",
            .reason = "zurl opens aes256-ctr only, which is what ssh-keygen writes",
        },
        .{
            .cipher = "aes256-gcm@openssh.com",
            .reason = "zurl opens aes256-ctr only, which is what ssh-keygen writes",
        },
        .{
            .cipher = "chacha20-poly1305@openssh.com",
            .reason = "zurl opens aes256-ctr only, which is what ssh-keygen writes",
        },
    };
    for (table) |row| {
        if (std.mem.eql(u8, text, row.cipher)) return row.reason;
    }
    return null;
}

/// Why this build cannot run a key derivation it found.
///
/// Null for a name this build has never heard of.
pub fn kdfRefusalFor(text: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, text, "sha256")) {
        return "zurl runs the bcrypt derivation only, which is what ssh-keygen writes";
    }
    return null;
}

/// Why a key file was refused.
pub const ParseError = Allocator.Error || error{
    /// The text has no `-----BEGIN OPENSSH PRIVATE KEY-----` line, or no
    /// end line. A PEM key of another kind lands here, and so does a
    /// public key file given where a private key was wanted.
    PrivateKeyNotOpenSsh,
    /// The text is longer than `max_text_bytes`, or the container is
    /// longer than `max_container_bytes`.
    PrivateKeyTooLong,
    /// The base64 body holds a character that is not base64, or its
    /// length is not a whole number of groups.
    PrivateKeyBase64Invalid,
    /// The container does not start with `openssh-key-v1\0`.
    PrivateKeyMagicWrong,
    /// A length field runs past the container, or the container stops in
    /// the middle of a field.
    PrivateKeyMalformed,
    /// The file holds a number of keys that is not one. `ssh-keygen`
    /// writes one.
    PrivateKeyCountUnsupported,
    /// The key type is one this build cannot sign with. `refusalFor`
    /// names it.
    PrivateKeyAlgorithmUnsupported,
    /// The key is encrypted with a cipher this build cannot open.
    /// `cipherRefusalFor` names it.
    PrivateKeyCipherUnsupported,
    /// The key uses a derivation this build cannot run. `kdfRefusalFor`
    /// names it.
    PrivateKeyKdfUnsupported,
    /// The derivation asks for more rounds than `max_kdf_rounds`, or for
    /// none at all.
    PrivateKeyKdfRoundsOutOfRange,
    /// The derivation refused its own input for a reason the checks above
    /// do not cover. No file this build accepts reaches it, and the error
    /// is here because an error set is a promise the compiler checks and
    /// not a claim in a comment.
    PrivateKeyKdfFailed,
    /// The key is encrypted and no passphrase was given.
    PrivateKeyPassphraseRequired,
    /// **The two check integers do not match, and the key is
    /// encrypted.** That is what a wrong passphrase looks like. It is
    /// also what a file damaged in the encrypted part looks like, and the
    /// format cannot tell the two apart.
    PrivateKeyPassphraseWrong,
    /// The two check integers do not match and the key is not encrypted,
    /// or the padding is not the run the format writes, or the public key
    /// inside does not match the one outside.
    PrivateKeyCorrupt,
    /// The 32 bytes are not a point on the curve, or the private half and
    /// the public half do not belong together.
    PrivateKeyNotCanonical,
};

/// One private key, ready to sign with.
///
/// **This value holds a secret.** `deinit` wipes it, and a caller that
/// forgets leaves a key in memory for as long as the process runs. Keep
/// one where it will stay and pass a pointer: `publicBlob` and `comment`
/// point into this value.
pub const PrivateKey = struct {
    algorithm: Algorithm,
    pair: Ed25519.KeyPair,
    public_blob_storage: [max_public_blob_bytes]u8,
    public_blob_len: usize,
    comment_storage: [max_comment_bytes]u8,
    comment_len: usize,
    /// Whether the comment was longer than `max_comment_bytes` and was
    /// cut. **Recovery is never silent**, and a comment is only ever
    /// shown to a person.
    comment_truncated: bool,

    /// The public key blob, in the form RFC 4253 section 6.6 gives.
    ///
    /// This is what a `publickey` request sends and what the signature
    /// covers.
    pub fn publicBlob(k: *const PrivateKey) []const u8 {
        return k.public_blob_storage[0..k.public_blob_len];
    }

    /// The comment the key file carries, cut to `max_comment_bytes`.
    ///
    /// **Untrusted text**: the file may not be one this user wrote. A
    /// caller that shows it to a person makes it safe first, the way
    /// `zurl_ssh.userauth.sanitizeBanner` does.
    pub fn comment(k: *const PrivateKey) []const u8 {
        return k.comment_storage[0..k.comment_len];
    }

    /// The name of this key's algorithm on the wire.
    pub fn algorithmName(k: *const PrivateKey) []const u8 {
        return k.algorithm.name();
    }

    /// Signs `message` and writes the signature blob into `out`.
    ///
    /// The blob is the form RFC 4253 section 6.6 gives: the algorithm
    /// name and the signature, each as a string. `out` must hold
    /// `max_signature_bytes`.
    ///
    /// **`message` must be the blob of RFC 4252 section 7**, which starts
    /// with the session identifier. See
    /// `zurl_ssh.userauth.writeSignatureBlob` for why.
    pub fn sign(k: *const PrivateKey, message: []const u8, out: []u8) SignError![]u8 {
        switch (k.algorithm) {
            .ssh_ed25519 => {
                // No noise, so the signature is the deterministic one RFC
                // 8032 gives. OpenSSH signs the same way, and a
                // deterministic signature needs no entropy source at the
                // moment of signing.
                const signature = k.pair.sign(message, null) catch return error.SignatureFailed;
                var w: wire.Writer = .init(out);
                try w.string(Algorithm.ssh_ed25519.name());
                try w.string(&signature.toBytes());
                return w.written();
            },
        }
    }

    /// Wipes the key material.
    ///
    /// **Every byte, and not only the secret half.** The public blob and
    /// the comment say which key this was, and a key file that a user
    /// wanted kept private is one whose name is worth keeping private
    /// too.
    pub fn deinit(k: *PrivateKey) void {
        std.crypto.secureZero(u8, &k.pair.secret_key.bytes);
        // `PublicKey` keeps its own copy of the 32 bytes, beside the one
        // inside the secret key. Both go.
        std.crypto.secureZero(u8, &k.pair.public_key.bytes);
        std.crypto.secureZero(u8, &k.public_blob_storage);
        std.crypto.secureZero(u8, &k.comment_storage);
        k.public_blob_len = 0;
        k.comment_len = 0;
        k.comment_truncated = false;
    }
};

/// Why a signature could not be built.
pub const SignError = wire.WriteError || error{
    /// The curve refused the key. A key that parsed cannot reach this,
    /// and the error set carries it because the compiler checks an error
    /// set and not a comment.
    SignatureFailed,
};

/// Reads a key file.
///
/// `text` is the whole file, the PEM wrapper included. `passphrase` is
/// null for a key that is not encrypted. `gpa` holds the container while
/// the parse runs, and every byte of it is wiped before it goes back,
/// whichever way this function leaves.
///
/// `out` is written in place, and not returned, because it is most of a
/// kilobyte and because a caller must be able to `deinit` it from a known
/// address.
pub fn parse(
    out: *PrivateKey,
    gpa: Allocator,
    text: []const u8,
    passphrase: ?[]const u8,
) ParseError!void {
    if (text.len > max_text_bytes) return error.PrivateKeyTooLong;

    const body = try findBody(text);

    // The base64 body is wrapped across lines, and the whitespace is not
    // part of it. The characters are gathered first so that the decoder
    // sees one run.
    const packed_len = countBase64(body);
    if (packed_len > max_text_bytes) return error.PrivateKeyTooLong;
    const packed_text = try gpa.alloc(u8, packed_len);
    defer {
        std.crypto.secureZero(u8, packed_text);
        gpa.free(packed_text);
    }
    gatherBase64(packed_text, body);

    const decoder = std.base64.standard.Decoder;
    const container_len = decoder.calcSizeForSlice(packed_text) catch
        return error.PrivateKeyBase64Invalid;
    if (container_len > max_container_bytes) return error.PrivateKeyTooLong;
    const container = try gpa.alloc(u8, container_len);
    defer {
        std.crypto.secureZero(u8, container);
        gpa.free(container);
    }
    decoder.decode(container, packed_text) catch return error.PrivateKeyBase64Invalid;

    return parseContainer(out, container, passphrase);
}

/// Reads the container, once the PEM wrapper and the base64 are off.
///
/// `container` is written to in place when the key is encrypted, so the
/// caller's buffer holds the private section in the clear until it is
/// wiped. `parse` wipes it.
pub fn parseContainer(
    out: *PrivateKey,
    container: []u8,
    passphrase: ?[]const u8,
) ParseError!void {
    if (container.len < magic.len) return error.PrivateKeyMagicWrong;
    if (!std.mem.eql(u8, container[0..magic.len], magic)) return error.PrivateKeyMagicWrong;

    var r: wire.Reader = .init(container[magic.len..]);
    const cipher_name = r.string() catch return error.PrivateKeyMalformed;
    const kdf_name = r.string() catch return error.PrivateKeyMalformed;
    const kdf_options = r.string() catch return error.PrivateKeyMalformed;
    const key_count = r.uint32() catch return error.PrivateKeyMalformed;
    // `ssh-keygen` writes one key per file, and every reader in the wild
    // expects one. A file with another number is not something this build
    // guesses at.
    if (key_count != 1) return error.PrivateKeyCountUnsupported;

    const public_blob = r.string() catch return error.PrivateKeyMalformed;
    if (public_blob.len > max_public_blob_bytes) return error.PrivateKeyTooLong;

    // **The key type is read before any decryption work.** A user with an
    // `id_rsa` gets the name of the algorithm rather than a passphrase
    // prompt for a key this build could never use.
    var public_reader: wire.Reader = .init(public_blob);
    const declared = public_reader.string() catch return error.PrivateKeyMalformed;
    const algorithm = Algorithm.fromName(declared) orelse
        return error.PrivateKeyAlgorithmUnsupported;

    const private_section = r.string() catch return error.PrivateKeyMalformed;
    if (!r.atEnd()) return error.PrivateKeyMalformed;

    // The section sits inside `container`, so this is the same memory the
    // caller owns and the decryption happens in place. The offset comes
    // from the reader's own position and not from pointer arithmetic: `r`
    // walks `container[magic.len..]`, and `r.at` is the byte right behind
    // the string it just read.
    const start = magic.len + r.at - private_section.len;
    const section = container[start..][0..private_section.len];
    std.debug.assert(section.ptr == private_section.ptr);

    const encrypted = !std.mem.eql(u8, cipher_name, "none");
    if (encrypted) {
        try decryptSection(section, cipher_name, kdf_name, kdf_options, passphrase);
    } else {
        // A file that says `none` and then names a derivation is a file
        // nothing wrote. Refusing it is cheaper than guessing which field
        // to believe.
        if (!std.mem.eql(u8, kdf_name, "none")) return error.PrivateKeyMalformed;
        if (section.len % 8 != 0) return error.PrivateKeyCorrupt;
    }

    return readSection(out, section, algorithm, public_blob, encrypted);
}

/// Opens the private section in place.
fn decryptSection(
    section: []u8,
    cipher_name: []const u8,
    kdf_name: []const u8,
    kdf_options: []const u8,
    passphrase: ?[]const u8,
) ParseError!void {
    if (!std.mem.eql(u8, cipher_name, "aes256-ctr")) {
        return error.PrivateKeyCipherUnsupported;
    }
    if (!std.mem.eql(u8, kdf_name, "bcrypt")) {
        return error.PrivateKeyKdfUnsupported;
    }
    const pass = passphrase orelse return error.PrivateKeyPassphraseRequired;
    if (pass.len == 0) return error.PrivateKeyPassphraseRequired;

    // `aes256-ctr` runs a whole number of 16 byte blocks. A section of
    // another length was not written by this cipher.
    if (section.len % 16 != 0) return error.PrivateKeyCorrupt;
    if (section.len == 0) return error.PrivateKeyCorrupt;

    var options: wire.Reader = .init(kdf_options);
    const salt = options.string() catch return error.PrivateKeyMalformed;
    const rounds = options.uint32() catch return error.PrivateKeyMalformed;
    if (!options.atEnd()) return error.PrivateKeyMalformed;
    if (salt.len == 0) return error.PrivateKeyMalformed;
    // **Each round is real work, and the file chooses the number.** A file
    // that asks for four thousand million rounds would stop this process
    // for the rest of the day.
    if (rounds == 0 or rounds > max_kdf_rounds) return error.PrivateKeyKdfRoundsOutOfRange;

    // 32 bytes of key and 16 bytes of initialisation vector, in one run,
    // which is what OpenSSH's `sshkey.c` asks the derivation for.
    var material: [48]u8 = undefined;
    defer std.crypto.secureZero(u8, &material);
    // The rounds, the passphrase, and the salt are all checked above, so
    // nothing left here is about the round count. It gets its own name for
    // that reason.
    bcrypt.opensshKdf(pass, salt, &material, rounds) catch
        return error.PrivateKeyKdfFailed;

    var key: [32]u8 = material[0..32].*;
    defer std.crypto.secureZero(u8, &key);
    var iv: [16]u8 = material[32..48].*;
    defer std.crypto.secureZero(u8, &iv);

    // The counter is the whole 16 byte block, big-endian, which is what
    // RFC 4344 section 4 gives `aes256-ctr`.
    const context = Aes256.initEnc(key);
    ctr(@TypeOf(context), context, section, section, iv, .big);
}

/// Reads the private section, once it is in the clear.
fn readSection(
    out: *PrivateKey,
    section: []const u8,
    algorithm: Algorithm,
    public_blob: []const u8,
    encrypted: bool,
) ParseError!void {
    var r: wire.Reader = .init(section);
    const check1 = r.uint32() catch return error.PrivateKeyMalformed;
    const check2 = r.uint32() catch return error.PrivateKeyMalformed;
    // **This is the whole wrong-passphrase test the format has.** See the
    // module comment.
    if (check1 != check2) {
        return if (encrypted) error.PrivateKeyPassphraseWrong else error.PrivateKeyCorrupt;
    }

    const declared = r.string() catch return error.PrivateKeyMalformed;
    // The type inside must be the type outside. A file that names one
    // algorithm in the open and another under the passphrase is a file
    // that would have this build sign with a key nobody asked for.
    if (!std.mem.eql(u8, declared, algorithm.name())) return error.PrivateKeyCorrupt;

    switch (algorithm) {
        .ssh_ed25519 => {
            const public = r.string() catch return error.PrivateKeyMalformed;
            const secret = r.string() catch return error.PrivateKeyMalformed;
            if (public.len != Ed25519.PublicKey.encoded_length) return error.PrivateKeyCorrupt;
            if (secret.len != Ed25519.SecretKey.encoded_length) return error.PrivateKeyCorrupt;
            // OpenSSH writes the seed and the public key, in that order,
            // as one 64 byte string. The second half must be the public
            // key that came with it.
            if (!std.mem.eql(u8, secret[32..64], public)) return error.PrivateKeyCorrupt;

            const comment = r.string() catch return error.PrivateKeyMalformed;
            try checkPadding(r.rest());

            // The public blob outside the encryption must hold the same
            // key. It is what a `publickey` request sends, and a mismatch
            // would send one key and sign with another.
            var blob_reader: wire.Reader = .init(public_blob);
            _ = blob_reader.string() catch return error.PrivateKeyMalformed;
            const blob_public = blob_reader.string() catch return error.PrivateKeyMalformed;
            if (!blob_reader.atEnd()) return error.PrivateKeyCorrupt;
            if (!std.mem.eql(u8, blob_public, public)) return error.PrivateKeyCorrupt;

            // **The pair is rebuilt from the seed and checked here, and
            // not by `KeyPair.fromSecretKey`.** That function checks the
            // two halves only when runtime safety is on, so a
            // `ReleaseFast` build would take a file whose halves do not
            // belong together and sign with a key the server was never
            // shown.
            var pair = Ed25519.KeyPair.generateDeterministic(secret[0..32].*) catch
                return error.PrivateKeyNotCanonical;
            // **This frame holds a copy of the secret key.** `out` gets
            // one of its own below, and this one has to go whichever way
            // the function leaves.
            defer std.crypto.secureZero(u8, &pair.secret_key.bytes);
            if (!std.mem.eql(u8, &pair.public_key.toBytes(), public)) {
                return error.PrivateKeyCorrupt;
            }

            out.algorithm = .ssh_ed25519;
            out.pair = pair;
            @memcpy(out.public_blob_storage[0..public_blob.len], public_blob);
            out.public_blob_len = public_blob.len;
            const take = @min(comment.len, max_comment_bytes);
            @memcpy(out.comment_storage[0..take], comment[0..take]);
            out.comment_len = take;
            out.comment_truncated = comment.len > max_comment_bytes;
        },
    }
}

/// Checks the padding run the format writes at the end of the section.
///
/// The bytes are 1, 2, 3, and so on, up to the cipher's block size. A run
/// of anything else means the section did not decrypt to what was written.
fn checkPadding(tail: []const u8) ParseError!void {
    // The padding never reaches a whole block. A longer run means a length
    // field inside the section was read wrong.
    if (tail.len >= 16) return error.PrivateKeyCorrupt;
    for (tail, 1..) |byte, expected| {
        if (byte != @as(u8, @intCast(expected))) return error.PrivateKeyCorrupt;
    }
}

/// The base64 body between the two PEM lines.
fn findBody(text: []const u8) ParseError![]const u8 {
    const begin = std.mem.indexOf(u8, text, pem_begin) orelse
        return error.PrivateKeyNotOpenSsh;
    const body_at = begin + pem_begin.len;
    const end_offset = std.mem.indexOf(u8, text[body_at..], pem_end) orelse
        return error.PrivateKeyNotOpenSsh;
    return text[body_at..][0..end_offset];
}

/// How many base64 characters `body` holds.
fn countBase64(body: []const u8) usize {
    var total: usize = 0;
    for (body) |byte| {
        if (!isSpace(byte)) total += 1;
    }
    return total;
}

/// Copies the base64 characters of `body` into `out`, with the line
/// endings left behind.
fn gatherBase64(out: []u8, body: []const u8) void {
    var at: usize = 0;
    for (body) |byte| {
        if (isSpace(byte)) continue;
        out[at] = byte;
        at += 1;
    }
    std.debug.assert(at == out.len);
}

/// Whether `byte` is whitespace a PEM body may hold.
fn isSpace(byte: u8) bool {
    return byte == '\n' or byte == '\r' or byte == ' ' or byte == '\t';
}

const testing = std.testing;

/// An `ssh-ed25519` key `ssh-keygen -t ed25519 -N ""` wrote, with no
/// passphrase.
///
/// **This file came from OpenSSH and not from this build**, so it checks
/// the container grammar against the program that writes it.
pub const test_plain_key =
    \\-----BEGIN OPENSSH PRIVATE KEY-----
    \\b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
    \\QyNTUxOQAAACCN+pB+R1cVn1bKynhV2VfdUGCxwz82bw0J0CVKxJpBVgAAAJhmdLzLZnS8
    \\ywAAAAtzc2gtZWQyNTUxOQAAACCN+pB+R1cVn1bKynhV2VfdUGCxwz82bw0J0CVKxJpBVg
    \\AAAECohTFPaYx4Ld8w+qZQKWtFa16+fuGlu6cdOGHoNzeREo36kH5HVxWfVsrKeFXZV91Q
    \\YLHDPzZvDQnQJUrEmkFWAAAAD3BsYWluQHp1cmwudGVzdAECAwQFBg==
    \\-----END OPENSSH PRIVATE KEY-----
    \\
;

/// The `.pub` file `ssh-keygen` wrote beside `test_plain_key`, without the
/// `ssh-ed25519 ` prefix and without the comment.
pub const test_plain_public_base64 =
    "AAAAC3NzaC1lZDI1NTE5AAAAII36kH5HVxWfVsrKeFXZV91QYLHDPzZvDQnQJUrEmkFW";

/// An `ssh-ed25519` key with a passphrase, `aes256-ctr` and `bcrypt` with
/// the 16 rounds `ssh-keygen` writes by default.
pub const test_encrypted_key =
    \\-----BEGIN OPENSSH PRIVATE KEY-----
    \\b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCXNWcvV/
    \\Pu18s50BMo7pzHAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIL8W9MmdDo1EZb7R
    \\eHNwlfgbAWzHTVCzK7HSD2USOZO4AAAAkELpkg/yLzHz0zDNouE68WQYnSnR7ovx8RheL3
    \\ZKZWjl8XLvVUtVmZSxrO32dSYF2GgtI0xKGk2RdkRw/QHCI5ZIOhv+R5ij+192H5TrRgsd
    \\1b091wb6l+3F5L586wTZmCCa+TFHL3FZ3MtigUrHq4t+pzuCnM6FHx6YCW0Qs8+J+bTz8G
    \\wyltOU2rBxC1Vy6g==
    \\-----END OPENSSH PRIVATE KEY-----
    \\
;

/// The passphrase of `test_encrypted_key`.
pub const test_encrypted_passphrase = "correct horse battery staple";

/// The public half of `test_encrypted_key`, in base64.
pub const test_encrypted_public_base64 =
    "AAAAC3NzaC1lZDI1NTE5AAAAIL8W9MmdDo1EZb7ReHNwlfgbAWzHTVCzK7HSD2USOZO4";

/// The same key material as `test_encrypted_key`, with a different
/// passphrase and 8 rounds instead of 16, so the round count is read and
/// not assumed.
const test_encrypted_key_8 =
    \\-----BEGIN OPENSSH PRIVATE KEY-----
    \\b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBwFP6/R9
    \\cqloLEmOIPPeQiAAAACAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIHbuZNB5gAbZ90ws
    \\1/VdVjtePxEfB6kZ1pRByE31gRN8AAAAoMjxL6CCX2RPyJ1qqK65h4oQysmNstdMLEpuxx
    \\XQ1w5g0F4e24UZXeY8dBXOgE6ALyYVZ4md9OKXMKTeFcZwngRM8QN/RSGQHrEmvH9rbSsN
    \\b575J9ioTWEaekVF6sBlHOTxTeEkoW4Nq7aGUjpcHC1XKXZB+Fc2X26Jcu0eFeKHecOgY4
    \\4M7TxFiMJ+HXuGiBeftIb5Pi25g2rGino9YJY=
    \\-----END OPENSSH PRIVATE KEY-----
    \\
;

/// An RSA key `ssh-keygen -t rsa -b 2048` wrote, whole. This build
/// refuses it by name, and the whole file is here so that the refusal
/// happens on a real container and not on a truncated one.
pub const test_rsa_key =
    \\-----BEGIN OPENSSH PRIVATE KEY-----
    \\b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
    \\NhAAAAAwEAAQAAAQEAugaL1BvfmAlthww1Pf7BmjWTJKL6Lh5tdPsIcGSU7fE8Y1NNk27K
    \\6VRISptvY4TUyvGWTdeBpx7WlvHrvpFGstFVWsklZ0pKlrcd87qj1Qe809mA71YfbIO5nt
    \\eJq++LFjD6hXWxptFqc72vMXQZcsRjciqvVLsAuCTgY4H5XelUiQ6Ju3CRCOv96fXuXfEQ
    \\YhhH6H1PDj+v621FvhP7RhnR0Gcw5eGIhrYmw0g8JxjVspLlN/bLgXTyyY1MgHe/RAn0i5
    \\tmXo0hoVAPEwf4cDSz9h7fDJ9hSamNqY3SHlWZP2flRJtJKqWuyLGeY9NvCALSjqlpLvKb
    \\1Kbo3MxaSwAAA8iKh6QvioekLwAAAAdzc2gtcnNhAAABAQC6BovUG9+YCW2HDDU9/sGaNZ
    \\MkovouHm10+whwZJTt8TxjU02TbsrpVEhKm29jhNTK8ZZN14GnHtaW8eu+kUay0VVaySVn
    \\SkqWtx3zuqPVB7zT2YDvVh9sg7me14mr74sWMPqFdbGm0Wpzva8xdBlyxGNyKq9UuwC4JO
    \\Bjgfld6VSJDom7cJEI6/3p9e5d8RBiGEfofU8OP6/rbUW+E/tGGdHQZzDl4YiGtibDSDwn
    \\GNWykuU39suBdPLJjUyAd79ECfSLm2ZejSGhUA8TB/hwNLP2Ht8Mn2FJqY2pjdIeVZk/Z+
    \\VEm0kqpa7IsZ5j028IAtKOqWku8pvUpujczFpLAAAAAwEAAQAAAQAPmDjkoSmPX0r1RUq5
    \\Vb/5I4CgU6FReG+InPrKIURy5gQ/913LfEA6azxcNMeTujD0imglQmm2DtnCcalnolog53
    \\eWUsJ19D5ogBVct0rAsxNbVyJ97eRYfnpzHHKIHV61j4mQ4prv9yJLbZ1gMfFoM5p6maV1
    \\HvAif8Tn0p+LBb11O+jATBgPLFN9tL0ddggsYCVey4h4fRSfLWZAvjq/Em7R6ys4vcSAAj
    \\OsdUZTf9LJjADpDVpt89pvSVo+XMUKAbmhgaJFzJrRXfwHYcVqbTT1mvm86gwNN76zVF5U
    \\TJlZVd1Q4a3xCvZPMn2dAM05jpKy5EmoYd05Uxph2VDxAAAAgQCqyDKohJoNArOAZghJ2m
    \\Fzn4EB/BZA87tz7Mjjcnhzb9gsKh9EfdPnDn5OnWUhbcQ65AKSdP3J7tYESsB7WK7ZVdKk
    \\xJ5oFW+WmHU0FDhzt8VWNCl08Zs5lcSX5x7C9R+48gbeLdKYi1wR8VRDxSPpGrrV+PyC3G
    \\uMQJHxqRH2iwAAAIEA/bicoztUKocolJXOKWRW5Z6z18GnkyIBfd5QtrGIh2VwDbweU235
    \\PvZcEsADSWTRxRuzjcVGIMoZazsBwcO/vpQhn8Zp+FKrp4DHqwPx1ajvusJ3X+2kZjUdRs
    \\nsUW2FvCS1HX7KL1wnevpFlpDmAR7XjTILBpLCviUsbRb/6L0AAACBALuyR69SIKuwnwkP
    \\LqCe31U9dbDIkzqSDa8CrEnM3ynScWOzpPq8K+Mn2axx8BtC+DXlTcDkjyRFjmUFv5C2/J
    \\7Me2fpG0KlJERzEGMQNs8s6dwWfPArMtnwHn/zVn+iasQhuXW6fn5rworvGGYojVZQ/raF
    \\w4seHqTIWHtbA5OnAAAADXJzYUB6dXJsLnRlc3QBAgMEBQ==
    \\-----END OPENSSH PRIVATE KEY-----
    \\
;

/// An ECDSA key `ssh-keygen -t ecdsa` wrote, whole. This build refuses it
/// by name.
pub const test_ecdsa_key =
    \\-----BEGIN OPENSSH PRIVATE KEY-----
    \\b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
    \\1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSxhJiAePhEraNOsXvp2AP26frnqY7J
    \\zsCz4vqTg/mZDkH0csVJ9IFK2/pu0JPiZpwGUyGQDfJ63C+4sGnU2P8tAAAAqDZRAkg2UQ
    \\JIAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLGEmIB4+ESto06x
    \\e+nYA/bp+uepjsnOwLPi+pOD+ZkOQfRyxUn0gUrb+m7Qk+JmnAZTIZAN8nrcL7iwadTY/y
    \\0AAAAhAOzqMhKoPkZg/r+PhUvWH3pbdmd1kwVQASRe9QB+JfSiAAAAD2VjZHNhQHp1cmwu
    \\dGVzdA==
    \\-----END OPENSSH PRIVATE KEY-----
    \\
;

/// The public key blob `test_plain_public_base64` holds, as bytes.
fn decodePublicBlob(out: []u8, text: []const u8) ![]u8 {
    const decoder = std.base64.standard.Decoder;
    const len = try decoder.calcSizeForSlice(text);
    try decoder.decode(out[0..len], text);
    return out[0..len];
}

test "a key ssh-keygen wrote with no passphrase reads, and its public half matches" {
    var key: PrivateKey = undefined;
    try parse(&key, testing.allocator, test_plain_key, null);
    defer key.deinit();

    try testing.expectEqual(Algorithm.ssh_ed25519, key.algorithm);
    try testing.expectEqualStrings("plain@zurl.test", key.comment());
    try testing.expect(!key.comment_truncated);

    // **The blob must be the one the `.pub` file holds.** That file came
    // from `ssh-keygen`, so this checks the container against OpenSSH and
    // not against this build.
    var expected_storage: [128]u8 = undefined;
    const expected = try decodePublicBlob(&expected_storage, test_plain_public_base64);
    try testing.expectEqualSlices(u8, expected, key.publicBlob());

    // And the private half must produce the same public key.
    var blob_reader: wire.Reader = .init(key.publicBlob());
    try testing.expectEqualStrings("ssh-ed25519", try blob_reader.string());
    try testing.expectEqualSlices(u8, &key.pair.public_key.toBytes(), try blob_reader.string());
}

test "an encrypted key reads with the right passphrase and refuses every other" {
    var key: PrivateKey = undefined;
    try parse(&key, testing.allocator, test_encrypted_key, test_encrypted_passphrase);
    defer key.deinit();
    try testing.expectEqualStrings("enc@zurl.test", key.comment());

    var expected_storage: [128]u8 = undefined;
    const expected = try decodePublicBlob(&expected_storage, test_encrypted_public_base64);
    try testing.expectEqualSlices(u8, expected, key.publicBlob());

    // **The two check integers are what catch a wrong passphrase.** One
    // character off is a different key, and the section decrypts to
    // nothing that matches.
    var wrong: PrivateKey = undefined;
    try testing.expectError(
        error.PrivateKeyPassphraseWrong,
        parse(&wrong, testing.allocator, test_encrypted_key, "correct horse battery stapl"),
    );
    try testing.expectError(
        error.PrivateKeyPassphraseWrong,
        parse(&wrong, testing.allocator, test_encrypted_key, "x"),
    );
    try testing.expectError(
        error.PrivateKeyPassphraseRequired,
        parse(&wrong, testing.allocator, test_encrypted_key, null),
    );
    try testing.expectError(
        error.PrivateKeyPassphraseRequired,
        parse(&wrong, testing.allocator, test_encrypted_key, ""),
    );
}

test "the round count comes out of the file and is never assumed" {
    // A second key with 8 rounds instead of the 16 `ssh-keygen` writes by
    // default. A reader with the count hard-coded opens one of these two
    // and not the other.
    var key: PrivateKey = undefined;
    try parse(&key, testing.allocator, test_encrypted_key_8, "pw");
    defer key.deinit();
    try testing.expectEqualStrings("rounds8@zurl.test", key.comment());
}

test "an RSA key and an ECDSA key are refused by name before any other work" {
    var key: PrivateKey = undefined;
    try testing.expectError(
        error.PrivateKeyAlgorithmUnsupported,
        parse(&key, testing.allocator, test_rsa_key, null),
    );
    try testing.expectError(
        error.PrivateKeyAlgorithmUnsupported,
        parse(&key, testing.allocator, test_ecdsa_key, null),
    );

    // The refusal has a reason a user can act on.
    const rsa_reason = refusalFor("ssh-rsa") orelse return error.TestExpectedReason;
    try testing.expect(rsa_reason.len != 0);
    const ecdsa_reason = refusalFor("ecdsa-sha2-nistp256") orelse return error.TestExpectedReason;
    try testing.expect(ecdsa_reason.len != 0);
}

test "every key type, cipher, and derivation this build refuses names a reason" {
    const key_types = [_][]const u8{
        "ssh-rsa",
        "rsa-sha2-256",
        "rsa-sha2-512",
        "ssh-dss",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
        "ssh-ed25519-cert-v01@openssh.com",
    };
    for (key_types) |key_type| {
        const reason = refusalFor(key_type) orelse return error.TestExpectedReason;
        try testing.expect(reason.len != 0);
        try testing.expectEqual(@as(?Algorithm, null), Algorithm.fromName(key_type));
    }
    try testing.expectEqual(@as(?[]const u8, null), refusalFor("ssh-ed25519"));
    try testing.expectEqual(@as(?[]const u8, null), refusalFor("made-up"));

    const ciphers = [_][]const u8{
        "aes128-ctr",
        "aes192-ctr",
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "3des-cbc",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
        "chacha20-poly1305@openssh.com",
    };
    for (ciphers) |name| {
        const reason = cipherRefusalFor(name) orelse return error.TestExpectedReason;
        try testing.expect(reason.len != 0);
    }
    try testing.expectEqual(@as(?[]const u8, null), cipherRefusalFor("aes256-ctr"));
    try testing.expectEqual(@as(?[]const u8, null), cipherRefusalFor("none"));

    const derivation = kdfRefusalFor("sha256") orelse return error.TestExpectedReason;
    try testing.expect(derivation.len != 0);
    try testing.expectEqual(@as(?[]const u8, null), kdfRefusalFor("bcrypt"));
}

test "a file that is not an openssh key is refused and never guessed at" {
    var key: PrivateKey = undefined;
    const gpa = testing.allocator;
    try testing.expectError(
        error.PrivateKeyNotOpenSsh,
        parse(&key, gpa, "", null),
    );
    try testing.expectError(
        error.PrivateKeyNotOpenSsh,
        parse(&key, gpa, "ssh-ed25519 AAAAC3Nz user@host\n", null),
    );
    // A PEM key of another kind.
    try testing.expectError(
        error.PrivateKeyNotOpenSsh,
        parse(&key, gpa, "-----BEGIN RSA PRIVATE KEY-----\nMII=\n-----END RSA PRIVATE KEY-----\n", null),
    );
    // The right first line and no last line.
    try testing.expectError(
        error.PrivateKeyNotOpenSsh,
        parse(&key, gpa, pem_begin ++ "\nAAAA\n", null),
    );
    // A body that is not base64.
    try testing.expectError(
        error.PrivateKeyBase64Invalid,
        parse(&key, gpa, pem_begin ++ "\n!!!!\n" ++ pem_end ++ "\n", null),
    );
    // Base64 that decodes to something with the wrong magic.
    try testing.expectError(
        error.PrivateKeyMagicWrong,
        parse(&key, gpa, pem_begin ++ "\nAAAAAAAAAAAAAAAAAAAAAAAA\n" ++ pem_end ++ "\n", null),
    );

    const long: [max_text_bytes + 1]u8 = @splat('a');
    try testing.expectError(error.PrivateKeyTooLong, parse(&key, gpa, &long, null));
}

test "a container that lies about a length is refused and never read past" {
    var key: PrivateKey = undefined;

    // The magic, then a string that claims more bytes than the container
    // holds.
    var storage: [64]u8 = undefined;
    @memcpy(storage[0..magic.len], magic);
    var w: wire.Writer = .init(storage[magic.len..]);
    try w.uint32(0xffff);
    const container = storage[0 .. magic.len + w.at];
    try testing.expectError(
        error.PrivateKeyMalformed,
        parseContainer(&key, container, null),
    );

    // A well formed container that names two keys.
    var two_storage: [128]u8 = undefined;
    @memcpy(two_storage[0..magic.len], magic);
    var two: wire.Writer = .init(two_storage[magic.len..]);
    try two.string("none");
    try two.string("none");
    try two.string("");
    try two.uint32(2);
    try testing.expectError(
        error.PrivateKeyCountUnsupported,
        parseContainer(&key, two_storage[0 .. magic.len + two.at], null),
    );
}

test "a damaged plain key is corrupt and never a wrong passphrase" {
    // **The two answers must not be confused.** A user with a plain key
    // that got damaged is told the file is broken, and a user with the
    // wrong passphrase is told the passphrase is wrong. Only an encrypted
    // key can give the second answer.
    var container_storage: [512]u8 = undefined;
    const container = try buildPlainContainer(&container_storage, .{ .break_check = true });
    var key: PrivateKey = undefined;
    try testing.expectError(
        error.PrivateKeyCorrupt,
        parseContainer(&key, container, null),
    );
}

test "the padding run at the end of a section is checked" {
    var container_storage: [512]u8 = undefined;
    var key: PrivateKey = undefined;

    const good = try buildPlainContainer(&container_storage, .{});
    try parseContainer(&key, good, null);
    key.deinit();

    const bad = try buildPlainContainer(&container_storage, .{ .break_padding = true });
    try testing.expectError(
        error.PrivateKeyCorrupt,
        parseContainer(&key, bad, null),
    );
}

test "a public blob that does not match the private half is refused" {
    // **A file that sends one key and signs with another would prove
    // nothing to a server.** The two halves are compared, both inside the
    // section and against the blob outside it.
    var container_storage: [512]u8 = undefined;
    var key: PrivateKey = undefined;

    const outer = try buildPlainContainer(&container_storage, .{ .break_outer_public = true });
    try testing.expectError(
        error.PrivateKeyCorrupt,
        parseContainer(&key, outer, null),
    );

    const inner = try buildPlainContainer(&container_storage, .{ .break_inner_public = true });
    try testing.expectError(
        error.PrivateKeyCorrupt,
        parseContainer(&key, inner, null),
    );

    const mismatch = try buildPlainContainer(&container_storage, .{ .break_type = true });
    try testing.expectError(
        error.PrivateKeyCorrupt,
        parseContainer(&key, mismatch, null),
    );
}

/// What one hand-built container gets wrong, for the tests above.
const Damage = struct {
    break_check: bool = false,
    break_padding: bool = false,
    break_outer_public: bool = false,
    break_inner_public: bool = false,
    break_type: bool = false,
};

/// Builds a plain `openssh-key-v1` container, with one field wrong.
fn buildPlainContainer(storage: []u8, damage: Damage) ![]u8 {
    const seed: [Ed25519.KeyPair.seed_length]u8 = @splat(0x77);
    const pair = try Ed25519.KeyPair.generateDeterministic(seed);

    var blob_storage: [64]u8 = undefined;
    var blob: wire.Writer = .init(&blob_storage);
    try blob.string("ssh-ed25519");
    var public = pair.public_key.toBytes();
    if (damage.break_outer_public) public[0] ^= 0x01;
    try blob.string(&public);

    var section_storage: [256]u8 = undefined;
    var section: wire.Writer = .init(&section_storage);
    try section.uint32(0x11223344);
    try section.uint32(if (damage.break_check) 0x11223345 else 0x11223344);
    try section.string(if (damage.break_type) "ssh-rsa" else "ssh-ed25519");
    var inner_public = pair.public_key.toBytes();
    if (damage.break_inner_public) inner_public[0] ^= 0x02;
    try section.string(&inner_public);
    try section.string(&pair.secret_key.toBytes());
    try section.string("built@zurl.test");
    const pad_len = (8 - section.at % 8) % 8;
    for (0..pad_len) |i| {
        try section.byte(if (damage.break_padding) 0xee else @intCast(i + 1));
    }

    @memcpy(storage[0..magic.len], magic);
    var w: wire.Writer = .init(storage[magic.len..]);
    try w.string("none");
    try w.string("none");
    try w.string("");
    try w.uint32(1);
    try w.string(blob.written());
    try w.string(section.written());
    return storage[0 .. magic.len + w.at];
}

test "a signature blob names the algorithm and carries the signature" {
    var key: PrivateKey = undefined;
    try parse(&key, testing.allocator, test_plain_key, null);
    defer key.deinit();

    var storage: [max_signature_bytes]u8 = undefined;
    const blob = try key.sign("a message", &storage);

    var r: wire.Reader = .init(blob);
    try testing.expectEqualStrings("ssh-ed25519", try r.string());
    const signature_bytes = try r.string();
    try testing.expectEqual(Ed25519.Signature.encoded_length, signature_bytes.len);
    try testing.expect(r.atEnd());

    // The signature verifies under the public key the file carries, which
    // is the same check a server makes.
    const signature: Ed25519.Signature = .fromBytes(signature_bytes[0..64].*);
    try signature.verify("a message", key.pair.public_key);
    try testing.expectError(
        error.SignatureVerificationFailed,
        signature.verify("another message", key.pair.public_key),
    );

    // Ed25519 signatures are deterministic, so the same message signs to
    // the same bytes. A build that added noise would break a test that
    // compares two runs, and OpenSSH signs deterministically too.
    var second_storage: [max_signature_bytes]u8 = undefined;
    try testing.expectEqualSlices(u8, blob, try key.sign("a message", &second_storage));

    var tiny: [8]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, key.sign("a message", &tiny));
}

test "deinit leaves no key material behind" {
    // **A private key is a secret at rest and a secret in memory.** This
    // reads the bytes back after the wipe, which is the only way to show
    // the wipe happened.
    var key: PrivateKey = undefined;
    try parse(&key, testing.allocator, test_plain_key, null);
    const before = key.pair.secret_key.bytes;
    try testing.expect(!std.mem.allEqual(u8, &before, 0));

    key.deinit();
    try testing.expect(std.mem.allEqual(u8, &key.pair.secret_key.bytes, 0));
    try testing.expect(std.mem.allEqual(u8, &key.pair.public_key.bytes, 0));
    try testing.expect(std.mem.allEqual(u8, &key.public_blob_storage, 0));
    try testing.expect(std.mem.allEqual(u8, &key.comment_storage, 0));
    try testing.expectEqual(@as(usize, 0), key.public_blob_len);
    try testing.expectEqual(@as(usize, 0), key.comment_len);
}

test "a derivation that asks for too many rounds is refused before it runs" {
    // **The file chooses the number of rounds and each one is real
    // work.** The bound is checked before the derivation starts.
    var storage: [256]u8 = undefined;
    @memcpy(storage[0..magic.len], magic);
    var w: wire.Writer = .init(storage[magic.len..]);
    try w.string("aes256-ctr");
    try w.string("bcrypt");
    var options_storage: [64]u8 = undefined;
    var options: wire.Writer = .init(&options_storage);
    try options.string("0123456789abcdef");
    try options.uint32(1_000_000);
    try w.string(options.written());
    try w.uint32(1);
    var blob_storage: [64]u8 = undefined;
    var blob: wire.Writer = .init(&blob_storage);
    try blob.string("ssh-ed25519");
    try blob.string(&[_]u8{0} ** 32);
    try w.string(blob.written());
    try w.string(&[_]u8{0} ** 16);

    var key: PrivateKey = undefined;
    try testing.expectError(
        error.PrivateKeyKdfRoundsOutOfRange,
        parseContainer(&key, storage[0 .. magic.len + w.at], "pw"),
    );
}

test "an encrypted key with a cipher or a derivation this build refuses says which" {
    var storage: [256]u8 = undefined;
    var key: PrivateKey = undefined;

    @memcpy(storage[0..magic.len], magic);
    var w: wire.Writer = .init(storage[magic.len..]);
    try w.string("aes256-cbc");
    try w.string("bcrypt");
    try w.string("");
    try w.uint32(1);
    var blob_storage: [64]u8 = undefined;
    var blob: wire.Writer = .init(&blob_storage);
    try blob.string("ssh-ed25519");
    try blob.string(&[_]u8{0} ** 32);
    try w.string(blob.written());
    try w.string(&[_]u8{0} ** 16);
    try testing.expectError(
        error.PrivateKeyCipherUnsupported,
        parseContainer(&key, storage[0 .. magic.len + w.at], "pw"),
    );

    var second: wire.Writer = .init(storage[magic.len..]);
    try second.string("aes256-ctr");
    try second.string("sha256");
    try second.string("");
    try second.uint32(1);
    try second.string(blob.written());
    try second.string(&[_]u8{0} ** 16);
    try testing.expectError(
        error.PrivateKeyKdfUnsupported,
        parseContainer(&key, storage[0 .. magic.len + second.at], "pw"),
    );
}
