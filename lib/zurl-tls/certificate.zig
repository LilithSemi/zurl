//! A bounded reader for an X.509 certificate that a peer sent.
//!
//! **Why this file is here.** `std.crypto.Certificate.der.Element.parse`
//! has no bound check of any kind. It reads the identifier octet and the
//! first length octet at the index it was given, it reads each long form
//! length octet, and it then adds the length the certificate wrote to the
//! index it reached. The sum can pass the end of the buffer and it can
//! wrap a `u32`. `std.crypto.Certificate.parse` calls that reader about
//! twenty times, each time at an offset it took from an element it read
//! before, so a peer picks every one of those numbers.
//!
//! Six octets are enough. `30 06 30 82 FF FF`, read as a certificate,
//! panics a ReleaseSafe build with "index out of bounds: index 6, len 6"
//! and gives a ReleaseFast build a segmentation fault. A TLS client reads
//! the host name of the leaf certificate after it parses the certificate,
//! so the fault comes before anything about the peer is authenticated.
//!
//! **What this file gives back.** `parse` produces
//! `std.crypto.Certificate.Parsed`, the same type the standard library
//! produces. `std.crypto.Certificate.Bundle.verify` takes that type, and
//! so does `Parsed.verify`, so the trust store and the signature check
//! stay exactly what they were. Only the walk changes.
//!
//! **What this file is not.** It is not a new certificate parser. `parse`
//! below is `std.crypto.Certificate.parse` of Zig 0.16.0, field for field
//! and error for error, with every call to the unbounded element reader
//! replaced by `parseElement`. Read the two side by side at each Zig
//! bump. The file `UPSTREAM` beside this one says the same about
//! `Client.zig`.

const std = @import("std");

const Certificate = std.crypto.Certificate;
const der = Certificate.der;
const mem = std.mem;
const testing = std.testing;

/// Every fault `parse` can report.
///
/// This is `std.crypto.Certificate.ParseError` with one name added. The
/// bounded walk refuses more inputs than the standard library does, and
/// every refusal but one carries a name that set already holds.
///
/// The one name of its own is `CertificateHasDuplicateExtension`. RFC 5280
/// section 4.2 says a certificate must not carry two instances of one
/// extension, and no name in the standard set says that.
///
/// `CertificateSignatureAlgorithmMismatch` is added because the walk below
/// compares the inner and the outer signature algorithm, which the
/// standard walk does not. The name is not new: it already has a row in
/// `zurl-net/errors.zig` and it already says what happened.
pub const ParseError = Certificate.ParseError || error{
    CertificateHasDuplicateExtension,
    CertificateSignatureAlgorithmMismatch,
};

/// The object identifier of `subjectAltName`, which is 2.5.29.17.
///
/// **The one identifier this walk reads for the host names.**
/// `std.crypto.Certificate.ExtensionId` maps 2.5.29.7 to the same value.
/// That is the retired X.509(1988) `subjectAltName`, it is not a name any
/// certificate authority profiles or validates, and the standard walk let
/// the last of the two win. So a certificate whose 2.5.29.17 named
/// `attacker.test`, which is what the authority signed, followed by a
/// 2.5.29.7 naming `victim.test`, sent the host check to the second one.
/// The names checked were then not the names anybody validated, which is
/// a hostname verification defect and therefore an authentication defect.
const oid_subject_alt_name = [_]u8{ 0x55, 0x1D, 0x11 };

/// Every fault `parseElement` can report.
pub const ElementError = der.Element.ParseError;

/// The most length octets a long form length may use.
///
/// `der.Element.Slice` addresses the buffer with a `u32`, so four octets
/// already name every offset a certificate can hold. The standard library
/// keeps the same rule.
const len_octets_max = @sizeOf(u32);

/// The largest buffer this file reads.
///
/// `der.Element.Slice` holds a `u32`, so an offset above this has no form
/// in the element type. A certificate is a few kilobytes, so no real input
/// comes near the bound.
const buffer_bytes_max = std.math.maxInt(u32);

/// Reads the DER element that starts at `index` in `bytes`, and proves that
/// the element stays inside `bytes`.
///
/// This is the shape of `std.crypto.Certificate.der.Element.parse` with a
/// check in front of every read and every computed extent:
///
/// * The identifier octet and the first length octet must both be there.
/// * A long form length uses at most four octets, and all of them must be
///   there.
/// * The end of the content must be at or below `bytes.len`.
///
/// The arithmetic runs in `u64`, so no sum can wrap, and `end` is proved to
/// be at or below `bytes.len` before either bound becomes a `u32`. Every
/// refusal is an error and never an assert: a peer wrote these numbers, so
/// a bad one is not a fault of this program.
///
/// `slice.start` is at least two octets past `index`, so a walk that steps
/// to `slice.start` or to `slice.end` always moves forward.
pub fn parseElement(bytes: []const u8, index: u32) ElementError!der.Element {
    const invalid = error.CertificateFieldHasInvalidLength;
    if (bytes.len > buffer_bytes_max) return invalid;

    // The identifier octet and the first length octet.
    var i: u64 = index;
    if (i + 2 > bytes.len) return invalid;
    const identifier: der.Identifier = @bitCast(bytes[i]);
    i += 1;
    const size_byte = bytes[i];
    i += 1;

    var size: u64 = size_byte;
    if ((size_byte >> 7) != 0) {
        // The long form. The high bit of the first length octet says how
        // many octets carry the length itself.
        const len_size: u7 = @truncate(size_byte);
        if (len_size > len_octets_max) return invalid;
        const len_end = i + len_size;
        if (len_end > bytes.len) return invalid;
        size = 0;
        while (i < len_end) : (i += 1) size = (size << 8) | bytes[i];
    }

    const value_end = i + size;
    if (value_end > bytes.len) return invalid;
    return .{
        .identifier = identifier,
        .slice = .{ .start = @intCast(i), .end = @intCast(value_end) },
    };
}

/// Reads the content of a BIT STRING, without its count of unused bits.
///
/// This is `std.crypto.Certificate.parseBitString` with one check added.
/// The standard library reads the first content octet with no bound, so a
/// BIT STRING of no content octets makes it read one octet past the end of
/// its own element, and an element that ends at the end of the buffer then
/// reads past the buffer.
///
/// `elem` must come from `parseElement` over `cert.buffer`. The bound is
/// checked again here all the same, because a fault of the caller must not
/// become a read out of bounds.
pub fn parseBitString(
    cert: Certificate,
    elem: der.Element,
) Certificate.ParseBitStringError!der.Element.Slice {
    if (elem.identifier.tag != .bitstring) return error.CertificateFieldHasWrongDataType;
    if (elem.slice.end > cert.buffer.len) return error.CertificateHasInvalidBitString;
    // The first content octet counts the unused bits at the end of the
    // string. A BIT STRING with no content octet carries no such count.
    if (elem.slice.start >= elem.slice.end) return error.CertificateHasInvalidBitString;
    if (cert.buffer[elem.slice.start] != 0) return error.CertificateHasInvalidBitString;
    return .{ .start = elem.slice.start + 1, .end = elem.slice.end };
}

/// Whether `std.crypto.Certificate.rsa.PublicKey.parseDer` can read
/// `pub_key` without a read out of bounds.
///
/// **A sibling of the fault this file closes.** `parseDer` walks the
/// `subjectPublicKey` of an RSA certificate with the same unbounded element
/// reader, and the peer writes those bytes too. A `subjectPublicKey` of one
/// octet makes it read a second octet that is not there. It is reached from
/// three places that all read a certificate the peer sent: `verifyRsa`
/// inside `Parsed.verify`, which the chain rule calls with the neighbour
/// certificate as the issuer, the same call with the leaf as its own issuer
/// for a self signed chain, and `CertificatePublicKey.verifySignature` for
/// the CertificateVerify message.
///
/// The check follows `parseDer` step by step and answers only about the
/// reads. A wrong tag is not a fault here, because `parseDer` reports that
/// itself and reads nothing more after it.
fn rsaPublicKeyFits(pub_key: []const u8) bool {
    const seq = parseElement(pub_key, 0) catch return false;
    if (seq.identifier.tag != .sequence) return true;
    const modulus = parseElement(pub_key, seq.slice.start) catch return false;
    if (modulus.identifier.tag != .integer) return true;
    _ = parseElement(pub_key, modulus.slice.end) catch return false;
    return true;
}

/// Reads the certificate in `cert` and gives back what the standard library
/// would give back for the same bytes, or an error.
///
/// **Use this and not `std.crypto.Certificate.parse` for any certificate a
/// peer sent.** The two agree on every certificate the standard library
/// accepts. They differ on the ones it cannot read: this one reports a
/// length fault and the standard library reads out of bounds.
///
/// The walk keeps the order of the standard library, so an element that
/// comes later in the certificate is read later here too, and a fault in an
/// earlier field keeps the name the standard library gives it.
///
/// The one rule that the standard library does not have is the public key
/// check at the end. See `rsaPublicKeyFits` for what it closes.
pub fn parse(cert: Certificate) ParseError!Certificate.Parsed {
    const cert_bytes = cert.buffer;
    const certificate = try parseElement(cert_bytes, cert.index);
    const tbs_certificate = try parseElement(cert_bytes, certificate.slice.start);
    const version_elem = try parseElement(cert_bytes, tbs_certificate.slice.start);
    const version = try Certificate.parseVersion(cert_bytes, version_elem);
    const serial_number = if (@as(u8, @bitCast(version_elem.identifier)) == 0xa0)
        try parseElement(cert_bytes, version_elem.slice.end)
    else
        version_elem;
    // RFC 5280 section 4.1.2.3: this field must hold the same algorithm
    // identifier as the `signatureAlgorithm` field of the Certificate.
    const tbs_signature = try parseElement(cert_bytes, serial_number.slice.end);
    const issuer = try parseElement(cert_bytes, tbs_signature.slice.end);
    const validity = try parseElement(cert_bytes, issuer.slice.end);
    const not_before = try parseElement(cert_bytes, validity.slice.start);
    const not_before_utc = try Certificate.parseTime(cert, not_before);
    const not_after = try parseElement(cert_bytes, not_before.slice.end);
    const not_after_utc = try Certificate.parseTime(cert, not_after);
    const subject = try parseElement(cert_bytes, validity.slice.end);

    const pub_key_info = try parseElement(cert_bytes, subject.slice.end);
    const pub_key_signature_algorithm = try parseElement(cert_bytes, pub_key_info.slice.start);
    const pub_key_algo_elem = try parseElement(cert_bytes, pub_key_signature_algorithm.slice.start);
    const pub_key_algo: Certificate.Parsed.PubKeyAlgo = switch (try Certificate.parseAlgorithmCategory(cert_bytes, pub_key_algo_elem)) {
        inline else => |tag| @unionInit(Certificate.Parsed.PubKeyAlgo, @tagName(tag), {}),
        .X9_62_id_ecPublicKey => pub_key_algo: {
            // RFC 5480 section 2.1.1.1: the parameters of an EC key name
            // the curve.
            const params_elem = try parseElement(cert_bytes, pub_key_algo_elem.slice.end);
            const named_curve = try Certificate.parseNamedCurve(cert_bytes, params_elem);
            break :pub_key_algo .{ .X9_62_id_ecPublicKey = named_curve };
        },
    };
    const pub_key_elem = try parseElement(cert_bytes, pub_key_signature_algorithm.slice.end);
    const pub_key = try parseBitString(cert, pub_key_elem);

    var common_name = der.Element.Slice.empty;
    var name_i = subject.slice.start;
    while (name_i < subject.slice.end) {
        const rdn = try parseElement(cert_bytes, name_i);
        var rdn_i = rdn.slice.start;
        while (rdn_i < rdn.slice.end) {
            const atav = try parseElement(cert_bytes, rdn_i);
            var atav_i = atav.slice.start;
            while (atav_i < atav.slice.end) {
                const ty_elem = try parseElement(cert_bytes, atav_i);
                const val = try parseElement(cert_bytes, ty_elem.slice.end);
                atav_i = val.slice.end;
                const ty = Certificate.parseAttribute(cert_bytes, ty_elem) catch |err| switch (err) {
                    error.CertificateHasUnrecognizedObjectId => continue,
                    else => |e| return e,
                };
                switch (ty) {
                    .commonName => common_name = val.slice,
                    else => {},
                }
            }
            rdn_i = atav.slice.end;
        }
        name_i = rdn.slice.end;
    }

    const sig_algo = try parseElement(cert_bytes, tbs_certificate.slice.end);
    const algo_elem = try parseElement(cert_bytes, sig_algo.slice.start);
    const signature_algorithm = try Certificate.parseAlgorithm(cert_bytes, algo_elem);
    const sig_elem = try parseElement(cert_bytes, sig_algo.slice.end);
    const signature = try parseBitString(cert, sig_elem);

    // RFC 5280 section 4.1.1.2 says the `signatureAlgorithm` of the
    // Certificate and the `signature` of the `tbsCertificate` must hold
    // the same value. The standard library reads the outer one and never
    // looks at the inner one, so the two could disagree.
    //
    // **Why the two must agree.** The signature covers the
    // `tbsCertificate`, so it covers the inner field and not the outer
    // one. The outer field is what picks the verifier. A peer that writes
    // two different algorithms therefore hands the verifier a name the
    // signer never signed, which is the shape every algorithm
    // substitution trick takes.
    //
    // The whole DER of each `AlgorithmIdentifier` is compared, parameters
    // and all, which is what RFC 5280 asks for and what OpenSSL's
    // `X509_ALGOR_cmp` does. The inner one runs from the octet after the
    // serial number to the end of its own content, and the outer one from
    // the octet after the `tbsCertificate`.
    const tbs_signature_der = cert_bytes[serial_number.slice.end..tbs_signature.slice.end];
    const outer_signature_der = cert_bytes[tbs_certificate.slice.end..sig_algo.slice.end];
    if (!mem.eql(u8, tbs_signature_der, outer_signature_der)) {
        return error.CertificateSignatureAlgorithmMismatch;
    }

    // Extensions.
    var subject_alt_name_slice = der.Element.Slice.empty;
    ext: {
        if (version == .v1)
            break :ext;

        if (pub_key_info.slice.end >= tbs_certificate.slice.end)
            break :ext;

        const outer_extensions = try parseElement(cert_bytes, pub_key_info.slice.end);
        if (outer_extensions.identifier.tag != .bitstring)
            break :ext;

        const extensions = try parseElement(cert_bytes, outer_extensions.slice.start);

        // True once 2.5.29.17 has been seen. A second instance of it is a
        // fault and not a value: the walk cannot know which of the two the
        // authority signed for, and taking either one is a guess about
        // what a host name means.
        var seen_subject_alt_name = false;

        var ext_i = extensions.slice.start;
        while (ext_i < extensions.slice.end) {
            const extension = try parseElement(cert_bytes, ext_i);
            ext_i = extension.slice.end;
            const oid_elem = try parseElement(cert_bytes, extension.slice.start);
            // The identifier is compared here and not through
            // `Certificate.parseExtensionId`, which folds 2.5.29.7 into
            // the same value. See `oid_subject_alt_name`.
            const oid_bytes = cert_bytes[oid_elem.slice.start..oid_elem.slice.end];
            if (!mem.eql(u8, oid_bytes, &oid_subject_alt_name)) continue;
            if (seen_subject_alt_name) return error.CertificateHasDuplicateExtension;
            seen_subject_alt_name = true;

            const critical_elem = try parseElement(cert_bytes, oid_elem.slice.end);
            const ext_bytes_elem = if (critical_elem.identifier.tag != .boolean)
                critical_elem
            else
                try parseElement(cert_bytes, critical_elem.slice.end);
            subject_alt_name_slice = ext_bytes_elem.slice;
        }
    }

    // The public key goes to an RSA reader that has the same unbounded
    // walk this file replaces, and this is the one place every certificate
    // the peer sent comes through. A key that reader cannot read is
    // refused here, before any code can hand it over.
    switch (pub_key_algo) {
        .rsaEncryption, .rsassa_pss => {
            if (!rsaPublicKeyFits(cert_bytes[pub_key.start..pub_key.end])) {
                return error.CertificateFieldHasInvalidLength;
            }
        },
        .X9_62_id_ecPublicKey, .curveEd25519 => {},
    }

    return .{
        .certificate = cert,
        .common_name_slice = common_name,
        .issuer_slice = issuer.slice,
        .subject_slice = subject.slice,
        .signature_slice = signature,
        .signature_algorithm = signature_algorithm,
        .message_slice = .{ .start = certificate.slice.start, .end = tbs_certificate.slice.end },
        .pub_key_algo = pub_key_algo,
        .pub_key_slice = pub_key,
        .validity = .{
            .not_before = not_before_utc,
            .not_after = not_after_utc,
        },
        .subject_alt_name_slice = subject_alt_name_slice,
        .version = version,
    };
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

/// The minter of `Client.zig`, which is the one place this package writes
/// a certificate. A second minter here would be a second reading of RFC
/// 5280, and the two would drift.
const Client = @import("Client.zig");

/// The six octets of the reproduction. `30 06` opens a six octet SEQUENCE,
/// and `30 82 FF FF` inside it opens a SEQUENCE of 65535 octets over a
/// buffer that holds six.
const evil_six = [_]u8{ 0x30, 0x06, 0x30, 0x82, 0xFF, 0xFF };

/// Mints one valid leaf certificate for the tests below.
fn mintLeaf(out: *Client.DerBuf, seed: u8) !void {
    const key = try Client.testKey(seed);
    try Client.mint(out, .{
        .serial = 7,
        .issuer_cn = "zurl test root",
        .subject_cn = "bounded.test",
        .san_dns = "bounded.test",
        .basic_constraints = .{ .ca = false },
        .key_usage = .digital_signature,
    }, key.public_key, key);
}

test "the six octets of the reproduction are refused and do not crash" {
    const cert: Certificate = .{ .buffer = &evil_six, .index = 0 };
    try testing.expectError(error.CertificateFieldHasInvalidLength, parse(cert));
}

test "a certificate whose lengths point far past the buffer is refused" {
    // Ten octets that send the standard library's reader two gigabytes
    // past the end of the buffer instead of one octet past it. `02 84 7F
    // FF FF FF` is an INTEGER of 2147483647 octets, and the walk then
    // reads the next field at the end of it. The six octet reproduction
    // reads one octet past the end and lands inside the client's own read
    // buffer, so a build with no bound check reads another connection's
    // bytes; this one leaves the mapping and a ReleaseFast zurl gives a
    // segmentation fault.
    const far = [_]u8{ 0x30, 0x08, 0x30, 0x06, 0x02, 0x84, 0x7F, 0xFF, 0xFF, 0xFF };
    const cert: Certificate = .{ .buffer = &far, .index = 0 };
    try testing.expectError(error.CertificateFieldHasInvalidLength, parse(cert));
}

test "every prefix of a real certificate is refused and none of them crash" {
    // The whole certificate parses, so every prefix shorter than it is a
    // truncated certificate. A peer can send any one of them.
    var buf: Client.DerBuf = .{};
    try mintLeaf(&buf, 0x51);
    const whole = buf.slice();

    _ = try parse(.{ .buffer = whole, .index = 0 });

    var len: usize = 0;
    while (len < whole.len) : (len += 1) {
        const cert: Certificate = .{ .buffer = whole[0..len], .index = 0 };
        try testing.expectError(error.CertificateFieldHasInvalidLength, parse(cert));
    }
}

test "a long form length of four FF octets is refused and does not wrap" {
    // Four length octets of `FF` are 4294967295. The standard library adds
    // that to the index it reached, in `u32`, so the sum wraps and the
    // element reads as a short one. The sum runs in `u64` here.
    const overflow = [_]u8{ 0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0x01, 0x00 };
    try testing.expectError(error.CertificateFieldHasInvalidLength, parseElement(&overflow, 0));

    // Five length octets name more octets than a `u32` holds.
    const too_many = [_]u8{ 0x30, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05 };
    try testing.expectError(error.CertificateFieldHasInvalidLength, parseElement(&too_many, 0));
}

test "an element that ends one octet past the buffer is refused" {
    // Three content octets over a buffer that holds two after the header.
    const past = [_]u8{ 0x04, 0x03, 0xAA, 0xBB };
    try testing.expectError(error.CertificateFieldHasInvalidLength, parseElement(&past, 0));

    // The same, in the long form.
    const past_long = [_]u8{ 0x04, 0x81, 0x03, 0xAA, 0xBB };
    try testing.expectError(error.CertificateFieldHasInvalidLength, parseElement(&past_long, 0));
}

test "an element that ends exactly at the buffer end is accepted" {
    // The legal case. An off-by-one here would refuse every certificate,
    // because the outermost SEQUENCE of a certificate ends at the end of
    // the bytes that carry it.
    const exact = [_]u8{ 0x04, 0x02, 0xAA, 0xBB };
    const elem = try parseElement(&exact, 0);
    try testing.expectEqual(der.Tag.octetstring, elem.identifier.tag);
    try testing.expectEqual(@as(u32, 2), elem.slice.start);
    try testing.expectEqual(@as(u32, 4), elem.slice.end);

    // The same, in the long form.
    const exact_long = [_]u8{ 0x04, 0x81, 0x02, 0xAA, 0xBB };
    const long = try parseElement(&exact_long, 0);
    try testing.expectEqual(@as(u32, 3), long.slice.start);
    try testing.expectEqual(@as(u32, 5), long.slice.end);

    // An element of no content at all still ends where it starts.
    const empty = [_]u8{ 0x05, 0x00 };
    const null_elem = try parseElement(&empty, 0);
    try testing.expectEqual(@as(u32, 2), null_elem.slice.start);
    try testing.expectEqual(@as(u32, 2), null_elem.slice.end);
}

test "an element with no length octet at all is refused" {
    const header_only = [_]u8{0x30};
    try testing.expectError(error.CertificateFieldHasInvalidLength, parseElement(&header_only, 0));
    try testing.expectError(error.CertificateFieldHasInvalidLength, parseElement("", 0));

    // The long form says four length octets and the buffer holds two.
    const short_length = [_]u8{ 0x30, 0x84, 0x00, 0x00 };
    try testing.expectError(error.CertificateFieldHasInvalidLength, parseElement(&short_length, 0));
}

test "a BIT STRING with no content octet is a fault and not a read past the end" {
    // `03 00` is a BIT STRING that carries no count of unused bits. The
    // standard library reads that count all the same.
    const empty_bits = [_]u8{ 0x03, 0x00 };
    const cert: Certificate = .{ .buffer = &empty_bits, .index = 0 };
    const elem = try parseElement(&empty_bits, 0);
    try testing.expectError(error.CertificateHasInvalidBitString, parseBitString(cert, elem));
}

test "an RSA public key the standard library cannot read is refused" {
    // `parseDer` reads two octets at offset zero, so one octet is not
    // enough. The check answers about the reads and not about the tags.
    try testing.expect(!rsaPublicKeyFits(""));
    try testing.expect(!rsaPublicKeyFits(&[_]u8{0xAB}));
    // A SEQUENCE that says two octets and carries none.
    try testing.expect(!rsaPublicKeyFits(&[_]u8{ 0x30, 0x02 }));
    // A SEQUENCE holding an INTEGER, and nothing where the exponent goes.
    try testing.expect(!rsaPublicKeyFits(&[_]u8{ 0x30, 0x03, 0x02, 0x01, 0x01 }));
    // A wrong tag is the business of `parseDer`, which reports it.
    try testing.expect(rsaPublicKeyFits(&[_]u8{ 0x04, 0x01, 0x00 }));
    // Two INTEGERs, which is what a real key holds.
    try testing.expect(rsaPublicKeyFits(&[_]u8{ 0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x03 }));
}

test "a real certificate parses to the same Parsed the standard library gives" {
    // The evidence that the walk is a transcription and not a rewrite. A
    // field that differs means the two parsers disagree about a
    // certificate that both of them accept.
    var buf: Client.DerBuf = .{};
    try mintLeaf(&buf, 0x52);
    const cert: Certificate = .{ .buffer = buf.slice(), .index = 0 };

    const ours = try parse(cert);
    const theirs = try cert.parse();

    try testing.expectEqual(theirs.certificate.index, ours.certificate.index);
    try testing.expectEqual(theirs.certificate.buffer.ptr, ours.certificate.buffer.ptr);
    try testing.expectEqual(theirs.certificate.buffer.len, ours.certificate.buffer.len);
    try testing.expectEqual(theirs.issuer_slice, ours.issuer_slice);
    try testing.expectEqual(theirs.subject_slice, ours.subject_slice);
    try testing.expectEqual(theirs.common_name_slice, ours.common_name_slice);
    try testing.expectEqual(theirs.signature_slice, ours.signature_slice);
    try testing.expectEqual(theirs.signature_algorithm, ours.signature_algorithm);
    try testing.expectEqual(theirs.pub_key_algo, ours.pub_key_algo);
    try testing.expectEqual(theirs.pub_key_slice, ours.pub_key_slice);
    try testing.expectEqual(theirs.message_slice, ours.message_slice);
    try testing.expectEqual(theirs.subject_alt_name_slice, ours.subject_alt_name_slice);
    try testing.expectEqual(theirs.validity.not_before, ours.validity.not_before);
    try testing.expectEqual(theirs.validity.not_after, ours.validity.not_after);
    try testing.expectEqual(theirs.version, ours.version);

    // And the accessors give the same bytes, which is what every caller
    // reads.
    try testing.expectEqualStrings(theirs.issuer(), ours.issuer());
    try testing.expectEqualStrings(theirs.subject(), ours.subject());
    try testing.expectEqualStrings(theirs.commonName(), ours.commonName());
    try testing.expectEqualStrings(theirs.signature(), ours.signature());
    try testing.expectEqualStrings(theirs.pubKey(), ours.pubKey());
    try testing.expectEqualStrings(theirs.message(), ours.message());
    try testing.expectEqualStrings(theirs.subjectAltName(), ours.subjectAltName());
}

test "the bounded walk still takes a certificate that carries every field" {
    // A certificate authority certificate, which carries the two
    // extensions the chain rule reads as well as the subject alternative
    // name. The walk must keep all of them.
    const key = try Client.testKey(0x53);
    var buf: Client.DerBuf = .{};
    try Client.mint(&buf, .{
        .serial = 8,
        .issuer_cn = "zurl test root",
        .subject_cn = "zurl test root",
        .san_dns = "root.test",
        .basic_constraints = .{ .ca = true, .path_len = 3 },
        .key_usage = .key_cert_sign,
    }, key.public_key, key);

    const cert: Certificate = .{ .buffer = buf.slice(), .index = 0 };
    const parsed = try parse(cert);
    try testing.expectEqual(Certificate.Version.v3, parsed.version);
    try testing.expectEqualStrings("zurl test root", parsed.commonName());
    try testing.expect(parsed.subject_alt_name_slice.end > parsed.subject_alt_name_slice.start);
}

test "every certificate of the trust store reads the same way in both walks" {
    // The minter writes ECDSA certificates alone, so this is what covers
    // an RSA key, a long form length, and a name of more than one
    // attribute. These are real certificate authority certificates, and
    // the two parsers must agree about every one of them.
    const pem = @import("bundle.zig").embedded_pem;
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";
    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");

    var buf: [8192]u8 = undefined;
    var checked: usize = 0;
    var rsa_checked: usize = 0;
    var start_index: usize = 0;
    while (mem.findPos(u8, pem, start_index, begin_marker)) |begin| {
        const cert_start = begin + begin_marker.len;
        const cert_end = mem.findPos(u8, pem, cert_start, end_marker) orelse break;
        start_index = cert_end + end_marker.len;

        const encoded = mem.trim(u8, pem[cert_start..cert_end], " \t\r\n");
        // Three octets in four, and the buffer must hold all of them.
        if (encoded.len / 4 * 3 + 3 > buf.len) continue;
        const len = try decoder.decode(&buf, encoded);

        const cert: Certificate = .{ .buffer = buf[0..len], .index = 0 };
        const theirs = cert.parse() catch continue;
        const ours = try parse(cert);

        try testing.expectEqual(theirs.issuer_slice, ours.issuer_slice);
        try testing.expectEqual(theirs.subject_slice, ours.subject_slice);
        try testing.expectEqual(theirs.common_name_slice, ours.common_name_slice);
        try testing.expectEqual(theirs.signature_slice, ours.signature_slice);
        try testing.expectEqual(theirs.signature_algorithm, ours.signature_algorithm);
        try testing.expectEqual(theirs.pub_key_algo, ours.pub_key_algo);
        try testing.expectEqual(theirs.pub_key_slice, ours.pub_key_slice);
        try testing.expectEqual(theirs.message_slice, ours.message_slice);
        try testing.expectEqual(theirs.subject_alt_name_slice, ours.subject_alt_name_slice);
        try testing.expectEqual(theirs.validity.not_before, ours.validity.not_before);
        try testing.expectEqual(theirs.validity.not_after, ours.validity.not_after);
        try testing.expectEqual(theirs.version, ours.version);

        checked += 1;
        if (ours.pub_key_algo == .rsaEncryption) rsa_checked += 1;
    }

    // The store holds about 150 roots, and most of them carry an RSA key.
    try testing.expect(checked > 50);
    try testing.expect(rsa_checked > 20);
}

test "an index past the end of the buffer is refused" {
    // `Certificate.index` names where the certificate starts, and a caller
    // that gets it wrong must get an error and not a read out of bounds.
    var buf: Client.DerBuf = .{};
    try mintLeaf(&buf, 0x54);
    const whole = buf.slice();
    const cert: Certificate = .{ .buffer = whole, .index = @intCast(whole.len) };
    try testing.expectError(error.CertificateFieldHasInvalidLength, parse(cert));
}

test "the subject alternative names come from 2.5.29.17 and never from 2.5.29.7" {
    // The defect. `std.crypto.Certificate` maps both identifiers to one
    // value and lets the last block in the certificate win, so a
    // certificate whose 2.5.29.17 names what the authority validated,
    // followed by a 2.5.29.7 naming something else, sent the host check
    // to the second block. The names checked were then not the names
    // anybody signed for, which is a hostname verification defect.
    const key = try Client.testKey(0x61);
    var buf: Client.DerBuf = .{};
    try Client.mint(&buf, .{
        .serial = 9,
        .issuer_cn = "zurl test root",
        .subject_cn = "signed.test",
        .san_dns = "signed.test",
        .legacy_san_dns = "forged.test",
        .key_usage = .digital_signature,
    }, key.public_key, key);

    const cert: Certificate = .{ .buffer = buf.slice(), .index = 0 };
    const ours = try parse(cert);
    const names = ours.subjectAltName();
    try testing.expect(mem.indexOf(u8, names, "signed.test") != null);
    try testing.expect(mem.indexOf(u8, names, "forged.test") == null);

    // And the standard library reads the other one, which is what this
    // walk is here to stop. If a Zig bump ever makes the two agree, this
    // line fails and the guard above can be read again.
    const theirs = try Certificate.parse(cert);
    const their_names = theirs.subjectAltName();
    try testing.expect(mem.indexOf(u8, their_names, "forged.test") != null);
}

test "a certificate that carries subjectAltName twice is refused" {
    // RFC 5280 section 4.2: a certificate must not hold two instances of
    // one extension. A walk that reads one of the two is guessing which
    // set of names the authority signed for.
    const key = try Client.testKey(0x62);
    var buf: Client.DerBuf = .{};
    try Client.mint(&buf, .{
        .serial = 10,
        .issuer_cn = "zurl test root",
        .subject_cn = "twice.test",
        .san_dns = "twice.test",
        .duplicate_san_dns = "other.test",
        .key_usage = .digital_signature,
    }, key.public_key, key);

    const cert: Certificate = .{ .buffer = buf.slice(), .index = 0 };
    try testing.expectError(error.CertificateHasDuplicateExtension, parse(cert));
}

test "a certificate whose two signature algorithm fields disagree is refused" {
    // RFC 5280 section 4.1.1.2 says the `signature` field of the
    // `tbsCertificate` and the outer `signatureAlgorithm` field must hold
    // the same value. The signature covers the inner field and the outer
    // field picks the verifier, so a peer that writes two different names
    // hands the verifier an algorithm the signer never signed.
    const key = try Client.testKey(0x63);
    var buf: Client.DerBuf = .{};
    try Client.mint(&buf, .{
        .serial = 11,
        .issuer_cn = "zurl test root",
        .subject_cn = "mismatch.test",
        .san_dns = "mismatch.test",
        .key_usage = .digital_signature,
        .inner_signature_oid = &Client.test_oid_sha384_with_rsa,
    }, key.public_key, key);

    const cert: Certificate = .{ .buffer = buf.slice(), .index = 0 };
    try testing.expectError(error.CertificateSignatureAlgorithmMismatch, parse(cert));

    // The standard library reads the outer field alone and accepts it.
    _ = try Certificate.parse(cert);
}

test "a certificate whose two signature algorithm fields agree still parses" {
    // The positive control of the rule above. Both fields name one
    // algorithm, which is every certificate a correct authority writes.
    const key = try Client.testKey(0x64);
    var buf: Client.DerBuf = .{};
    try Client.mint(&buf, .{
        .serial = 12,
        .issuer_cn = "zurl test root",
        .subject_cn = "agree.test",
        .san_dns = "agree.test",
        .key_usage = .digital_signature,
        .signature_oid = &Client.test_oid_sha1_with_rsa,
    }, key.public_key, key);

    const cert: Certificate = .{ .buffer = buf.slice(), .index = 0 };
    const ours = try parse(cert);
    try testing.expectEqual(Certificate.Algorithm.sha1WithRSAEncryption, ours.signature_algorithm);
}
