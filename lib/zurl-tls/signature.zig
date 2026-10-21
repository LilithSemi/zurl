//! Verifies a signature over bytes that are not a certificate, with the
//! public key of one.
//!
//! An OCSP response and a certificate revocation list are both signed with
//! the key of a certificate, and neither signature sits inside a
//! certificate. `Certificate.Parsed.verify` checks only the signature a
//! certificate carries over its own `tbsCertificate`, and the three
//! signature readers it reaches are private to `std`. This file carries
//! the same three readers with a `Certificate.Algorithm` in front of them,
//! so a caller hands it the message bytes, the signature bytes, and the
//! parsed key of the certificate that signed.
//!
//! **The key must have come through `certificate.parse`.** The RSA reader
//! of `std` walks its key with the same unbounded element reader
//! `certificate.zig` exists to close, and `certificate.parse` runs the
//! `rsaPublicKeyFits` check on every key it reads. Every caller of
//! `verify` reaches it with a `Certificate.Parsed` from that walk, so the
//! key below is one the reader has already proved fits.

const std = @import("std");

const Certificate = std.crypto.Certificate;
const crypto = std.crypto;
const mem = std.mem;

/// Every fault `verify` can report. The names are the ones
/// `Certificate.Parsed.VerifyError` carries, so a caller can fold this set
/// into an error it already reports for certificate signatures.
pub const VerifyError = error{
    CertificateSignatureAlgorithmMismatch,
    CertificateSignatureInvalid,
    CertificateSignatureInvalidLength,
    CertificateSignatureAlgorithmUnsupported,
    CertificateSignatureNamedCurveUnsupported,
    CertificateSignatureUnsupportedBitCount,
    CertificatePublicKeyInvalid,
    CertificateFieldHasInvalidLength,
    CertificateFieldHasWrongDataType,
};

/// Checks `signature` over `message` against the key of a certificate.
///
/// `algorithm` names the signature algorithm the signer declared, which
/// RFC 6960 carries as the `signatureAlgorithm` of a `BasicOCSPResponse`
/// and RFC 5280 as the `signatureAlgorithm` of a `CertificateList`. The
/// hash the algorithm names is the hash the signature covers, and the key
/// decides the mathematics: RSA, ECDSA, or Ed25519.
pub fn verify(
    algorithm: Certificate.Algorithm,
    message: []const u8,
    signature: []const u8,
    pub_key_algo: Certificate.Parsed.PubKeyAlgo,
    pub_key: []const u8,
) VerifyError!void {
    switch (algorithm) {
        inline .sha1WithRSAEncryption,
        .sha224WithRSAEncryption,
        .sha256WithRSAEncryption,
        .sha384WithRSAEncryption,
        .sha512WithRSAEncryption,
        => |algo| return verifyRsa(
            algo.Hash(),
            message,
            signature,
            pub_key_algo,
            pub_key,
        ),

        inline .ecdsa_with_SHA224,
        .ecdsa_with_SHA256,
        .ecdsa_with_SHA384,
        .ecdsa_with_SHA512,
        => |algo| return verifyEcdsa(
            algo.Hash(),
            message,
            signature,
            pub_key_algo,
            pub_key,
        ),

        .md2WithRSAEncryption, .md5WithRSAEncryption => {
            return error.CertificateSignatureAlgorithmUnsupported;
        },

        .curveEd25519 => return verifyEd25519(message, signature, pub_key_algo, pub_key),
    }
}

/// The RSA reader of `Certificate.Parsed.verifyRsa`, with `message` and
/// `signature` in place of the fields of a certificate.
fn verifyRsa(
    comptime Hash: type,
    msg: []const u8,
    sig: []const u8,
    pub_key_algo: Certificate.Parsed.PubKeyAlgo,
    pub_key: []const u8,
) !void {
    if (pub_key_algo != .rsaEncryption) return error.CertificateSignatureAlgorithmMismatch;
    const pk_components = try Certificate.rsa.PublicKey.parseDer(pub_key);
    const exponent = pk_components.exponent;
    const modulus = pk_components.modulus;
    if (exponent.len > modulus.len) return error.CertificatePublicKeyInvalid;
    if (sig.len != modulus.len) return error.CertificateSignatureInvalidLength;

    switch (modulus.len) {
        inline 128, 256, 384, 512 => |modulus_len| {
            const public_key = Certificate.rsa.PublicKey.fromBytes(exponent, modulus) catch
                return error.CertificateSignatureInvalid;
            Certificate.rsa.PKCS1v1_5Signature.verify(modulus_len, sig[0..modulus_len], msg, public_key, Hash) catch
                return error.CertificateSignatureInvalid;
        },
        else => return error.CertificateSignatureUnsupportedBitCount,
    }
}

/// The ECDSA reader of `Certificate.Parsed.verifyEcdsa`, with `message`
/// and `encoded_sig` in place of the fields of a certificate. The curve
/// comes from the key and the hash from the algorithm, which is the X.509
/// meaning and not the TLS 1.3 one.
fn verifyEcdsa(
    comptime Hash: type,
    message: []const u8,
    encoded_sig: []const u8,
    pub_key_algo: Certificate.Parsed.PubKeyAlgo,
    sec1_pub_key: []const u8,
) !void {
    const sig_named_curve = switch (pub_key_algo) {
        .X9_62_id_ecPublicKey => |named_curve| named_curve,
        else => return error.CertificateSignatureAlgorithmMismatch,
    };

    switch (sig_named_curve) {
        .secp521r1 => {
            return error.CertificateSignatureNamedCurveUnsupported;
        },
        inline .X9_62_prime256v1,
        .secp384r1,
        => |curve| {
            const Ecdsa = crypto.sign.ecdsa.Ecdsa(curve.Curve(), Hash);
            const sig = Ecdsa.Signature.fromDer(encoded_sig) catch |err| switch (err) {
                error.InvalidEncoding => return error.CertificateSignatureInvalid,
            };
            const pub_key = Ecdsa.PublicKey.fromSec1(sec1_pub_key) catch |err| switch (err) {
                error.InvalidEncoding => return error.CertificateSignatureInvalid,
                error.NonCanonical => return error.CertificateSignatureInvalid,
                error.NotSquare => return error.CertificateSignatureInvalid,
            };
            sig.verify(message, pub_key) catch |err| switch (err) {
                error.IdentityElement => return error.CertificateSignatureInvalid,
                error.NonCanonical => return error.CertificateSignatureInvalid,
                error.SignatureVerificationFailed => return error.CertificateSignatureInvalid,
            };
        },
    }
}

/// The Ed25519 reader of `Certificate.Parsed.verifyEd25519`, with
/// `message` and `encoded_sig` in place of the fields of a certificate.
fn verifyEd25519(
    message: []const u8,
    encoded_sig: []const u8,
    pub_key_algo: Certificate.Parsed.PubKeyAlgo,
    encoded_pub_key: []const u8,
) !void {
    if (pub_key_algo != .curveEd25519) return error.CertificateSignatureAlgorithmMismatch;
    const Ed25519 = crypto.sign.Ed25519;
    if (encoded_sig.len != Ed25519.Signature.encoded_length) return error.CertificateSignatureInvalid;
    const sig = Ed25519.Signature.fromBytes(encoded_sig[0..Ed25519.Signature.encoded_length].*);
    if (encoded_pub_key.len != Ed25519.PublicKey.encoded_length) return error.CertificateSignatureInvalid;
    const pub_key = Ed25519.PublicKey.fromBytes(encoded_pub_key[0..Ed25519.PublicKey.encoded_length].*) catch |err| switch (err) {
        error.NonCanonical => return error.CertificateSignatureInvalid,
    };
    sig.verify(message, pub_key) catch |err| switch (err) {
        error.InvalidEncoding, error.WeakPublicKey => return error.CertificateSignatureInvalid,
        error.IdentityElement => return error.CertificateSignatureInvalid,
        error.NonCanonical => return error.CertificateSignatureInvalid,
        error.SignatureVerificationFailed => return error.CertificateSignatureInvalid,
    };
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

const Client = @import("Client.zig");
const TestEcdsa = Client.TestEcdsa;

test "a signature over the message checks, and one over other bytes does not" {
    const key = try Client.testKey(0x71);
    var cert_buf: Client.DerBuf = .{};
    try Client.mint(&cert_buf, .{
        .serial = 1,
        .issuer_cn = "sign.test",
        .subject_cn = "sign.test",
        .san_dns = "sign.test",
    }, key.public_key, key);
    const cert: Certificate = .{ .buffer = cert_buf.slice(), .index = 0 };
    const parsed = try Certificate.parse(cert);

    const message = "the bytes an ocsp response signs";
    const signature = try key.sign(message, null);
    var sig_buf: [TestEcdsa.Signature.der_encoded_length_max]u8 = undefined;
    const der_sig = signature.toDer(&sig_buf);

    try verify(.ecdsa_with_SHA256, message, der_sig, parsed.pub_key_algo, parsed.pubKey());
    try std.testing.expectError(
        error.CertificateSignatureInvalid,
        verify(.ecdsa_with_SHA256, "other bytes", der_sig, parsed.pub_key_algo, parsed.pubKey()),
    );
}

test "the algorithm and the key have to agree" {
    const key = try Client.testKey(0x72);
    var cert_buf: Client.DerBuf = .{};
    try Client.mint(&cert_buf, .{
        .serial = 2,
        .issuer_cn = "agree.test",
        .subject_cn = "agree.test",
        .san_dns = "agree.test",
    }, key.public_key, key);
    const cert: Certificate = .{ .buffer = cert_buf.slice(), .index = 0 };
    const parsed = try Certificate.parse(cert);

    const message = "bytes";
    const signature = try key.sign(message, null);
    var sig_buf: [TestEcdsa.Signature.der_encoded_length_max]u8 = undefined;
    const der_sig = signature.toDer(&sig_buf);

    // An ECDSA key cannot check an RSA signature, whatever the bytes.
    try std.testing.expectError(
        error.CertificateSignatureAlgorithmMismatch,
        verify(.sha256WithRSAEncryption, message, der_sig, parsed.pub_key_algo, parsed.pubKey()),
    );
}
