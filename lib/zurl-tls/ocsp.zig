//! One OCSP response, verified against the leaf certificate it speaks
//! about and the issuer that signed it.
//!
//! **What this covers.** RFC 6960 gives the `OCSPResponse`: a status, and
//! for the successful status one `BasicOCSPResponse` signed by the
//! certificate authority or by a responder it delegated. This file reads
//! the response, finds the `SingleResponse` for the leaf, checks the
//! signature under the key of the issuer, and reads the status and the
//! window. That is the whole of `--cert-status`, which curl defines as:
//! ask for a staple, refuse the connection when none arrives, and refuse
//! it when the staple that arrives does not vouch for the certificate.
//!
//! **The one simplification.** A delegated responder is accepted when the
//! issuer's own signature sits on its certificate and its
//! `extendedKeyUsage` names `id-kp-OCSPSigning`. The `id-pkix-ocsp-nocheck`
//! extension it usually carries is read past, because nothing here checks
//! the responder's own revocation: the response is pinned to one moment by
//! its `nextUpdate`, and the connection outlives no moment.
//!
//! Every walk here reads DER the peer sent, so every walk goes through
//! the bounded element reader of `certificate.zig`.

const std = @import("std");

const Certificate = std.crypto.Certificate;
const certificate = @import("certificate.zig");
const signature = @import("signature.zig");
const mem = std.mem;

const der = Certificate.der;

/// Every fault `verify` can report.
///
/// The two names of its own say what a user answers differently: a
/// response that says revoked is a fact about the certificate, and every
/// other fault is a fact about the response or the network. The rest are
/// the names `signature.verify` gives, which say the mathematics refused.
pub const VerifyError = signature.VerifyError || error{
    /// The staple says the certificate is revoked.
    TlsCertificateStatusRevoked,
    /// The staple is malformed, names another certificate, is unsigned or
    /// signed by nobody authorized, is stale, or says unknown.
    TlsCertificateStatusInvalid,
};

/// Every fault the DER walk can report. The walk reads a staple a peer
/// sent, so a length that does not fit is a refusal of the response and
/// not a fault of this program.
const ElemError = error{
    TlsCertificateStatusInvalid,
};

/// The object identifier of `id-pkix-ocsp-basic`, 1.3.6.1.5.5.7.48.1.1.
/// The only `responseType` RFC 6960 defines, and the only one this
/// verifier reads.
const oid_ocsp_basic = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01 };

/// The object identifier of `id-kp-OCSPSigning`, 1.3.6.1.5.5.7.3.9.
const oid_ocsp_signing = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09 };

/// The object identifier of `extendedKeyUsage`, 2.5.29.37.
const oid_ext_key_usage = [_]u8{ 0x55, 0x1D, 0x25 };

/// Reads the DER element that starts at `at` in `bytes`, and moves `at`
/// past it. The reader is the bounded one, so every refusal is the one
/// name the response carries.
fn next(bytes: []const u8, at: *usize) ElemError!der.Element {
    const e = certificate.parseElement(bytes, @intCast(at.*)) catch
        return error.TlsCertificateStatusInvalid;
    at.* = e.slice.end;
    return e;
}

/// The hash algorithms a `certID` may name. RFC 6960 puts SHA-1 there,
/// and practice puts the SHA-2 family beside it.
const CertIdHash = union(enum) {
    sha1: void,
    sha224: void,
    sha256: void,
    sha384: void,
    sha512: void,

    fn parse(bytes: []const u8) ?CertIdHash {
        const sha1: CertIdHash = .{ .sha1 = {} };
        const sha224: CertIdHash = .{ .sha224 = {} };
        const sha256: CertIdHash = .{ .sha256 = {} };
        const sha384: CertIdHash = .{ .sha384 = {} };
        const sha512: CertIdHash = .{ .sha512 = {} };
        const map = std.StaticStringMap(CertIdHash).initComptime(.{
            .{ &[5]u8{ 0x2B, 0x0E, 0x03, 0x02, 0x1A }, sha1 }, // 1.3.14.3.2.26
            .{ &[9]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04 }, sha224 },
            .{ &[9]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 }, sha256 },
            .{ &[9]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 }, sha384 },
            .{ &[9]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 }, sha512 },
        });
        return map.get(bytes);
    }

    fn digest(self: CertIdHash, bytes: []const u8, out: []u8) usize {
        switch (self) {
            .sha1 => {
                std.crypto.hash.Sha1.hash(bytes, out[0..std.crypto.hash.Sha1.digest_length], .{});
                return std.crypto.hash.Sha1.digest_length;
            },
            .sha224 => {
                std.crypto.hash.sha2.Sha224.hash(bytes, out[0..std.crypto.hash.sha2.Sha224.digest_length], .{});
                return std.crypto.hash.sha2.Sha224.digest_length;
            },
            .sha256 => {
                std.crypto.hash.sha2.Sha256.hash(bytes, out[0..std.crypto.hash.sha2.Sha256.digest_length], .{});
                return std.crypto.hash.sha2.Sha256.digest_length;
            },
            .sha384 => {
                std.crypto.hash.sha2.Sha384.hash(bytes, out[0..std.crypto.hash.sha2.Sha384.digest_length], .{});
                return std.crypto.hash.sha2.Sha384.digest_length;
            },
            .sha512 => {
                std.crypto.hash.sha2.Sha512.hash(bytes, out[0..std.crypto.hash.sha2.Sha512.digest_length], .{});
                return std.crypto.hash.sha2.Sha512.digest_length;
            },
        }
    }
};

/// Verifies one stapled `OCSPResponse` for `leaf`.
///
/// `issuer` is the certificate the peer chain named as the issuer of
/// `leaf`, the same certificate the chain signature check used. The
/// response is verified against that one certificate and no other: a
/// staple for a certificate this chain did not present is refused by the
/// `certID` match, and a staple signed by an authority this chain does
/// not present is refused by the signature check.
pub fn verify(
    response: []const u8,
    serial_der: []const u8,
    issuer: Certificate.Parsed,
    now_sec: i64,
) VerifyError!void {
    // OCSPResponse ::= SEQUENCE { responseStatus, responseBytes [0] }
    var at: usize = 0;
    const outer = try next(response, &at);
    if (outer.identifier.tag != .sequence) return error.TlsCertificateStatusInvalid;
    at = outer.slice.start;

    const status = try next(response, &at);
    // ENUMERATED, whose tag the standard library's `Tag` does not name.
    // A primitive universal tag of 10 is one.
    if (@as(u8, @bitCast(status.identifier)) != 0x0a) return error.TlsCertificateStatusInvalid;
    const status_bytes = response[status.slice.start..status.slice.end];
    if (status_bytes.len != 1 or status_bytes[0] != 0) {
        return error.TlsCertificateStatusInvalid;
    }

    const bytes_tag = try next(response, &at);
    // [0] EXPLICIT, which is a context tag the standard library's `Tag`
    // does not name. The byte is constructed, context class, tag zero.
    if (@as(u8, @bitCast(bytes_tag.identifier)) != 0xa0) {
        return error.TlsCertificateStatusInvalid;
    }
    at = bytes_tag.slice.start;

    const bytes_seq = try next(response, &at);
    if (bytes_seq.identifier.tag != .sequence) return error.TlsCertificateStatusInvalid;
    at = bytes_seq.slice.start;

    const response_type = try next(response, &at);
    if (response_type.identifier.tag != .object_identifier or
        !mem.eql(u8, &oid_ocsp_basic, response[response_type.slice.start..response_type.slice.end]))
    {
        return error.TlsCertificateStatusInvalid;
    }
    const response_octets = try next(response, &at);
    if (response_octets.identifier.tag != .octetstring) return error.TlsCertificateStatusInvalid;

    // The DER of the BasicOCSPResponse.
    const basic = response[response_octets.slice.start..response_octets.slice.end];
    return verifyBasic(basic, serial_der, issuer, now_sec);
}

/// Verifies the `BasicOCSPResponse` in `basic`.
fn verifyBasic(
    basic: []const u8,
    serial_der: []const u8,
    issuer: Certificate.Parsed,
    now_sec: i64,
) VerifyError!void {
    var at: usize = 0;
    const outer = try next(basic, &at);
    if (outer.identifier.tag != .sequence) return error.TlsCertificateStatusInvalid;
    at = outer.slice.start;

    // tbsResponseData, which the signature covers. It starts where the
    // outer SEQUENCE's content starts, header included, because that is
    // the DER the signer signed.
    const tbs = try next(basic, &at);
    if (tbs.identifier.tag != .sequence) return error.TlsCertificateStatusInvalid;
    const tbs_bytes = basic[outer.slice.start..tbs.slice.end];

    // signatureAlgorithm, then signature. The algorithm is read out of
    // the object identifier inside the SEQUENCE, which is the shape
    // `parseAlgorithm` takes.
    const sig_algo_elem = try next(basic, &at);
    if (sig_algo_elem.identifier.tag != .sequence) return error.TlsCertificateStatusInvalid;
    const sig_algo_oid = certificate.parseElement(basic, sig_algo_elem.slice.start) catch
        return error.TlsCertificateStatusInvalid;
    const sig_algorithm = Certificate.parseAlgorithm(basic, sig_algo_oid) catch
        return error.TlsCertificateStatusInvalid;
    const sig_elem = try next(basic, &at);
    if (sig_elem.identifier.tag != .bitstring) return error.TlsCertificateStatusInvalid;
    if (sig_elem.slice.start >= sig_elem.slice.end or basic[sig_elem.slice.start] != 0) {
        return error.TlsCertificateStatusInvalid;
    }
    const sig_bytes = basic[sig_elem.slice.start + 1 .. sig_elem.slice.end];

    // The optional [0] certificates: what a delegated responder rides in.
    // The tag wraps a SEQUENCE OF Certificate, and the walk below wants
    // the entries, so the wrapper comes off here.
    var certs: []const u8 = &.{};
    if (at < outer.slice.end) {
        const certs_tag = try next(basic, &at);
        if (@as(u8, @bitCast(certs_tag.identifier)) != 0xa0) {
            return error.TlsCertificateStatusInvalid;
        }
        const certs_seq = certificate.parseElement(basic, certs_tag.slice.start) catch
            return error.TlsCertificateStatusInvalid;
        if (certs_seq.identifier.tag != .sequence) return error.TlsCertificateStatusInvalid;
        certs = basic[certs_seq.slice.start..certs_seq.slice.end];
    }

    // The signer. The responderID inside the tbsResponseData names it,
    // and the candidates are the issuer first and the response's own
    // certificates after it.
    const id = try responderId(basic, tbs);
    const signer = try findSigner(certs, id, issuer, now_sec);

    try signature.verify(sig_algorithm, tbs_bytes, sig_bytes, signer.pub_key_algo, signer.pubKey());

    return checkResponses(basic, tbs, serial_der, issuer, now_sec);
}

/// What the `responderID` of the response names its signer by.
const ResponderId = union(enum) {
    /// A full DER `Name`, for `byName`.
    name: []const u8,
    /// A SHA-1 over the public key bytes, for `byKey`.
    key_hash: [std.crypto.hash.Sha1.digest_length]u8,
};

/// Reads the `responderID` out of the `tbsResponseData`.
///
/// RFC 6960 tags both forms explicitly: `byName` holds a whole `Name`
/// whose content is what a certificate's `subject()` carries, and
/// `byKey` holds an OCTET STRING whose content is the SHA-1 over the
/// public key bytes. The version field of the `tbsResponseData` is
/// optional and comes first when it is there, so the walk skips it by
/// tag.
fn responderId(basic: []const u8, tbs: der.Element) ElemError!ResponderId {
    var at: usize = tbs.slice.start;
    var id = try next(basic, &at);
    if (@as(u8, @bitCast(id.identifier)) == 0xa0) {
        id = try next(basic, &at);
    }
    switch (@as(u8, @bitCast(id.identifier))) {
        0xa1 => { // [1] byName, EXPLICIT
            const name_elem = certificate.parseElement(basic, id.slice.start) catch
                return error.TlsCertificateStatusInvalid;
            if (name_elem.identifier.tag != .sequence) return error.TlsCertificateStatusInvalid;
            return .{ .name = basic[name_elem.slice.start..name_elem.slice.end] };
        },
        0xa2 => { // [2] byKey, EXPLICIT
            const key_elem = certificate.parseElement(basic, id.slice.start) catch
                return error.TlsCertificateStatusInvalid;
            if (key_elem.identifier.tag != .octetstring) return error.TlsCertificateStatusInvalid;
            const key_bytes = basic[key_elem.slice.start..key_elem.slice.end];
            if (key_bytes.len != std.crypto.hash.Sha1.digest_length) {
                return error.TlsCertificateStatusInvalid;
            }
            var out: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
            @memcpy(&out, key_bytes);
            return .{ .key_hash = out };
        },
        else => return error.TlsCertificateStatusInvalid,
    }
}

/// Finds the certificate the `responderID` names, among the issuer and
/// the certificates the response carries.
///
/// A signer that is not the issuer must be a certificate the issuer
/// signed, for `id-kp-OCSPSigning`, and still within its validity dates.
/// Anything else is a stranger signing a statement about somebody else's
/// certificate.
fn findSigner(
    certs: []const u8,
    id: ResponderId,
    issuer: Certificate.Parsed,
    now_sec: i64,
) VerifyError!Certificate.Parsed {
    if (matches(id, issuer)) return issuer;

    var at: usize = 0;
    while (at < certs.len) {
        const cert_at = at;
        const cert_elem = try next(certs, &at);
        if (cert_elem.identifier.tag != .sequence) return error.TlsCertificateStatusInvalid;

        const candidate_cert: Certificate = .{ .buffer = certs, .index = @intCast(cert_at) };
        const candidate = certificate.parse(candidate_cert) catch
            return error.TlsCertificateStatusInvalid;
        if (!matches(id, candidate)) continue;

        // The responder certificate must be the issuer's to delegate, and
        // it must still be alive.
        if (!mem.eql(u8, candidate.issuer(), issuer.subject())) {
            return error.TlsCertificateStatusInvalid;
        }
        candidate.verify(issuer, now_sec) catch |err| switch (err) {
            error.CertificateExpired,
            error.CertificateNotYetValid,
            error.CertificateIssuerMismatch,
            => return error.TlsCertificateStatusInvalid,
            else => |e| return e,
        };
        if (!try maySignOcsp(candidate)) return error.TlsCertificateStatusInvalid;
        return candidate;
    }
    return error.TlsCertificateStatusInvalid;
}

/// Whether the `responderID` names this certificate.
fn matches(id: ResponderId, cert: Certificate.Parsed) bool {
    return switch (id) {
        .name => |name| mem.eql(u8, name, cert.subject()),
        .key_hash => |hash| blk: {
            var out: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
            std.crypto.hash.Sha1.hash(cert.pubKey(), &out, .{});
            break :blk mem.eql(u8, &hash, &out);
        },
    };
}

/// Whether the `extendedKeyUsage` of `cert` names `id-kp-OCSPSigning`.
///
/// An absent extension is a refusal, and not an acceptance: RFC 6960
/// section 4.2.2.2 gives a responder certificate this purpose exactly so
/// that a verifier can tell it from a certificate authority that only
/// looks like one.
fn maySignOcsp(cert: Certificate.Parsed) ElemError!bool {
    const cert_bytes = cert.certificate.buffer;
    var at: usize = cert.certificate.index;
    const outer = try next(cert_bytes, &at);
    at = outer.slice.start;
    const tbs = try next(cert_bytes, &at);
    at = tbs.slice.start;
    // version [0], then serial, signature, issuer, validity, subject,
    // subjectPublicKeyInfo, then the optional [3] extensions.
    var first = try next(cert_bytes, &at);
    if (@as(u8, @bitCast(first.identifier)) == 0xa0) {
        first = try next(cert_bytes, &at);
    }
    if (first.identifier.tag != .integer) return false; // serial
    _ = try next(cert_bytes, &at); // signature algorithm
    _ = try next(cert_bytes, &at); // issuer
    _ = try next(cert_bytes, &at); // validity
    _ = try next(cert_bytes, &at); // subject
    const spki = try next(cert_bytes, &at);
    if (spki.slice.end >= tbs.slice.end) return false;
    const exts_tag = try next(cert_bytes, &at);
    // [3] IMPLICIT, whose tag byte is constructed context tag three, the
    // low bits of which the standard library names .bitstring.
    if (@as(u8, @bitCast(exts_tag.identifier)) != 0xa3) return false;
    at = exts_tag.slice.start;
    const exts = try next(cert_bytes, &at);
    if (exts.identifier.tag != .sequence) return false;
    at = exts.slice.start;
    while (at < exts.slice.end) {
        const extension = try next(cert_bytes, &at);
        var inner: usize = extension.slice.start;
        const oid_elem = try next(cert_bytes, &inner);
        if (!mem.eql(u8, &oid_ext_key_usage, cert_bytes[oid_elem.slice.start..oid_elem.slice.end])) continue;
        const critical = try next(cert_bytes, &inner);
        const value_elem = if (critical.identifier.tag != .boolean)
            critical
        else
            try next(cert_bytes, &inner);
        const value = cert_bytes[value_elem.slice.start..value_elem.slice.end];
        var v_at: usize = 0;
        const purposes = try next(value, &v_at);
        if (purposes.identifier.tag != .sequence) return false;
        var p_at: usize = purposes.slice.start;
        while (p_at < purposes.slice.end) {
            const purpose = try next(value, &p_at);
            if (purpose.identifier.tag != .object_identifier) continue;
            if (mem.eql(u8, &oid_ocsp_signing, value[purpose.slice.start..purpose.slice.end])) {
                return true;
            }
        }
        return false;
    }
    return false;
}

/// Finds the `SingleResponse` for `leaf`, and checks its status and its
/// window.
///
/// The response may carry one entry for every certificate it speaks
/// about, so the walk reads entries until one names the leaf. A response
/// with no entry for the leaf says nothing about it, and that is refused.
fn checkResponses(
    basic: []const u8,
    tbs: der.Element,
    serial_der: []const u8,
    issuer: Certificate.Parsed,
    now_sec: i64,
) VerifyError!void {
    // responses is the third element of the tbsResponseData: responderID,
    // producedAt, responses. The version is optional and comes first when
    // it is there.
    var at: usize = tbs.slice.start;
    const first = try next(basic, &at);
    if (@as(u8, @bitCast(first.identifier)) == 0xa0) _ = try next(basic, &at);
    const produced_at = try next(basic, &at);
    if (produced_at.identifier.tag != .generalized_time) return error.TlsCertificateStatusInvalid;
    const produced = parseTime(basic, produced_at) catch return error.TlsCertificateStatusInvalid;
    const responses = try next(basic, &at);
    if (responses.identifier.tag != .sequence) return error.TlsCertificateStatusInvalid;

    if (now_sec < 0) return error.TlsCertificateStatusInvalid;
    const now: u64 = @intCast(now_sec);
    if (now < produced) return error.TlsCertificateStatusInvalid;

    var r_at: usize = responses.slice.start;
    while (r_at < responses.slice.end) {
        const single = try next(basic, &r_at);
        if (single.identifier.tag != .sequence) return error.TlsCertificateStatusInvalid;
        var s_at: usize = single.slice.start;

        const cert_id = try next(basic, &s_at);
        if (cert_id.identifier.tag != .sequence) return error.TlsCertificateStatusInvalid;
        if (!try certIdMatches(basic, cert_id, serial_der, issuer)) continue;

        const status = try next(basic, &s_at);
        const this_update = try next(basic, &s_at);
        var next_update: ?u64 = null;
        if (s_at < single.slice.end) {
            const next_tag = try next(basic, &s_at);
            // [0] EXPLICIT nextUpdate: the GeneralizedTime sits inside
            // the tag's own content. [1] singleExtensions is read past.
            if (@as(u8, @bitCast(next_tag.identifier)) == 0xa0) {
                const inner = certificate.parseElement(basic, next_tag.slice.start) catch
                    return error.TlsCertificateStatusInvalid;
                next_update = parseTime(basic, inner) catch return error.TlsCertificateStatusInvalid;
            }
        }

        switch (@as(u8, @bitCast(status.identifier))) {
            0x80 => {}, // [0] good
            0xa1 => return error.TlsCertificateStatusRevoked, // [1] revoked, which is constructed because it holds a RevokedInfo
            else => return error.TlsCertificateStatusInvalid, // [2] unknown, and everything malformed
        }

        const this = parseTime(basic, this_update) catch return error.TlsCertificateStatusInvalid;
        if (now < this) return error.TlsCertificateStatusInvalid;
        // A response with no nextUpdate has no window, and curl refuses
        // one the same way: the moment the staple vouches for must be
        // bounded, or it vouches for ever.
        const until = next_update orelse return error.TlsCertificateStatusInvalid;
        if (now > until) return error.TlsCertificateStatusInvalid;
        return;
    }
    return error.TlsCertificateStatusInvalid;
}

/// Whether the `certID` names `leaf` under `issuer`.
fn certIdMatches(
    basic: []const u8,
    cert_id: der.Element,
    serial_der: []const u8,
    issuer: Certificate.Parsed,
) ElemError!bool {
    var at: usize = cert_id.slice.start;
    const algo_elem = try next(basic, &at);
    // The hash algorithm is the object identifier inside the
    // AlgorithmIdentifier.
    const oid_elem = certificate.parseElement(basic, algo_elem.slice.start) catch {
        return false;
    };
    const hash = CertIdHash.parse(basic[oid_elem.slice.start..oid_elem.slice.end]) orelse {
        return false;
    };

    const name_hash = try next(basic, &at);
    const key_hash = try next(basic, &at);
    const serial = try next(basic, &at);

    var hashed: [std.crypto.hash.sha2.Sha512.digest_length]u8 = undefined;
    // The name hash covers the whole DER of the issuer's subject `Name`,
    // header included, which is the encoding RFC 6960 names and which is
    // one longer than `subject()` gives.
    const name_der = certificate.subjectName(issuer.certificate) catch {
        return false;
    };
    const name_len = hash.digest(issuer.certificate.buffer[name_der.start..name_der.end], &hashed);
    if (!mem.eql(u8, hashed[0..name_len], basic[name_hash.slice.start..name_hash.slice.end])) {
        return false;
    }
    const key_len = hash.digest(issuer.pubKey(), &hashed);
    if (!mem.eql(u8, hashed[0..key_len], basic[key_hash.slice.start..key_hash.slice.end])) {
        return false;
    }

    return mem.eql(u8, serial_der, basic[serial.slice.start..serial.slice.end]);
}

fn parseTime(basic: []const u8, e: der.Element) ElemError!u64 {
    const any_cert: Certificate = .{ .buffer = basic, .index = 0 };
    return Certificate.parseTime(any_cert, e) catch |err| switch (err) {
        else => error.TlsCertificateStatusInvalid,
    };
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

const Client = @import("Client.zig");
const TestEcdsa = Client.TestEcdsa;
const testing = std.testing;

const test_oid_ecdsa_with_sha256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
const test_oid_sha1 = [_]u8{ 0x2B, 0x0E, 0x03, 0x02, 0x1A };

/// The test clock. 2023-11-14, which the fixture window covers with a
/// year on each side.
const test_now_sec: i64 = 1_700_000_000;

/// A DER writer with the shape of the minter's `DerBuf`, carrying the
/// small subset an `OCSPResponse` needs. The wraps are explicit rather
/// than a stack of helpers, because the nesting of the response is the
/// thing under test.
const Der = struct {
    data: [4096]u8 = undefined,
    len: usize = 0,

    fn mark(self: *const Der) usize {
        return self.len;
    }

    fn slice(self: *const Der) []const u8 {
        return self.data[0..self.len];
    }

    fn push(self: *Der, bytes: []const u8) void {
        @memcpy(self.data[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    fn wrap(self: *Der, from: usize, tag: u8) void {
        const body = self.len - from;
        const header = 1 + lenLen(body);
        mem.copyBackwards(u8, self.data[from + header ..][0..body], self.data[from..][0..body]);
        self.data[from] = tag;
        writeLen(self.data[from + 1 ..], body);
        self.len += header;
    }

    fn integer(self: *Der, value: u8) void {
        self.push(&.{ 0x02, 0x01, value });
    }

    fn enumerated(self: *Der, value: u8) void {
        self.push(&.{ 0x0a, 0x01, value });
    }

    fn oid(self: *Der, bytes: []const u8) void {
        self.push(&.{ 0x06, @intCast(bytes.len) });
        self.push(bytes);
    }

    /// One `AlgorithmIdentifier` that names `oid` with no parameters.
    fn algorithm(self: *Der, oid_bytes: []const u8) void {
        const at = self.mark();
        self.oid(oid_bytes);
        self.wrap(at, 0x30);
    }

    fn octetString(self: *Der, bytes: []const u8) void {
        self.push(&.{0x04});
        writeLen(self.data[self.len..][0..3], bytes.len);
        // The tag byte is already past `len`, so only the length moves
        // the cursor.
        self.len += lenLen(bytes.len);
        self.push(bytes);
    }

    fn generalizedTime(self: *Der, utc: []const u8) void {
        self.push(&.{ 0x18, @intCast(utc.len) });
        self.push(utc);
    }
};

fn lenLen(body: usize) usize {
    if (body < 0x80) return 1;
    if (body <= 0xff) return 2;
    return 3;
}

fn writeLen(out: []u8, body: usize) void {
    if (body < 0x80) {
        out[0] = @intCast(body);
    } else if (body <= 0xff) {
        out[0] = 0x81;
        out[1] = @intCast(body);
    } else {
        out[0] = 0x82;
        out[1] = @intCast(body >> 8);
        out[2] = @truncate(body);
    }
}

/// One certificate authority, one leaf under it, and one response for
/// the leaf. `Fixture.response` is the staple as it would arrive, and
/// `verify` is what the client calls.
const Fixture = struct {
    root_key: TestEcdsa.KeyPair,
    responder_key: ?TestEcdsa.KeyPair = null,
    // The DER each parsed certificate points into, owned by the fixture,
    // for the reason `init` gives.
    root_der: []u8,
    leaf_der: []u8,
    responder_buf: Client.DerBuf = .{},
    root: Certificate.Parsed,
    leaf: Certificate.Parsed,
    // The DER of the leaf's serial, copied, so a verify never reads a
    // fixture buffer through a pointer into another one. The length rides
    // beside it, because a slice into `storage` would point at `init`'s
    // own copy of this struct, which is gone by the time a test reads it.
    leaf_serial_storage: [8]u8,
    leaf_serial_len: usize = 0,
    /// The `SingleResponse` bytes, held apart so a test can mint a
    /// response around a different one.
    single: Der,
    /// The full response, as it would arrive in a staple.
    response: []u8,

    const issuer_cn = "ocsp test root";

    /// Builds a good response signed by the root.
    fn init() !Fixture {
        const root_key = try Client.testKey(0x91);
        const leaf_key = try Client.testKey(0x92);

        var root_buf: Client.DerBuf = .{};
        try Client.mint(&root_buf, .{
            .serial = 1,
            .issuer_cn = issuer_cn,
            .subject_cn = issuer_cn,
            .san_dns = "root.test",
            .basic_constraints = .{ .ca = true },
            .key_usage = .key_cert_sign,
        }, root_key.public_key, root_key);

        var leaf_buf: Client.DerBuf = .{};
        try Client.mint(&leaf_buf, .{
            .serial = 1,
            .issuer_cn = issuer_cn,
            .subject_cn = "leaf.test",
            .san_dns = "leaf.test",
            .basic_constraints = .{ .ca = false },
            .key_usage = .digital_signature,
        }, leaf_key.public_key, root_key);

        // The copies outlive `init`, so the parsed certificates read bytes
        // that stay where they are. A `DerBuf` that moved with the fixture
        // would leave every pointer in `root` and `leaf` at the stack frame
        // `init` had when it built them.
        const root_der = try testing.allocator.dupe(u8, root_buf.slice());
        errdefer testing.allocator.free(root_der);
        const leaf_der = try testing.allocator.dupe(u8, leaf_buf.slice());
        errdefer testing.allocator.free(leaf_der);
        const root_cert: Certificate = .{ .buffer = root_der, .index = 0 };
        const leaf_cert: Certificate = .{ .buffer = leaf_der, .index = 0 };
        const root = try Certificate.parse(root_cert);
        const leaf = try Certificate.parse(leaf_cert);

        var single: Der = .{};
        try writeSingle(&single, root, leaf, .good);

        const response = try buildResponse(testing.allocator, root_key, single.slice(), &.{});
        errdefer testing.allocator.free(response);

        var fixture = Fixture{
            .root_key = root_key,
            .root_der = root_der,
            .leaf_der = leaf_der,
            .root = root,
            .leaf = leaf,
            .leaf_serial_storage = undefined,
            .leaf_serial_len = 0,
            .single = single,
            .response = response,
        };
        const serial_slice = try certificate.serial(leaf_cert);
        const serial_der = leaf_cert.buffer[serial_slice.start..serial_slice.end];
        @memcpy(fixture.leaf_serial_storage[0..serial_der.len], serial_der);
        fixture.leaf_serial_len = serial_der.len;
        return fixture;
    }

    fn leafSerial(fixture: *const Fixture) []const u8 {
        return fixture.leaf_serial_storage[0..fixture.leaf_serial_len];
    }

    fn deinit(fixture: *Fixture) void {
        testing.allocator.free(fixture.response);
        testing.allocator.free(fixture.root_der);
        testing.allocator.free(fixture.leaf_der);
    }
};

/// What the `certStatus` of the fixture's single response says.
const Status = enum {
    good,
    revoked,
    unknown,
};

/// Writes one `SingleResponse` for `leaf` under `root`, with a window
/// that covers the test clock.
fn writeSingle(out: *Der, root: Certificate.Parsed, leaf: Certificate.Parsed, status: Status) !void {
    const cert_id_at = out.mark();
    out.algorithm(&test_oid_sha1);
    var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    const name_der = certificate.subjectName(root.certificate) catch return error.TlsCertificateStatusInvalid;
    std.crypto.hash.Sha1.hash(root.certificate.buffer[name_der.start..name_der.end], &digest, .{});
    out.octetString(&digest); // issuerNameHash
    std.crypto.hash.Sha1.hash(root.pubKey(), &digest, .{});
    out.octetString(&digest); // issuerKeyHash
    const serial = try certificate.serial(leaf.certificate);
    const serial_content = leaf.certificate.buffer[serial.start..serial.end];
    // The serial rides as a whole INTEGER element, tag and length and
    // content, which is what the reader walks.
    out.push(&.{ 0x02, @intCast(serial_content.len) });
    out.push(serial_content);
    out.wrap(cert_id_at, 0x30);

    switch (status) {
        .good => out.push(&.{ 0x80, 0x00 }), // [0] good, NULL
        // [1] revoked is constructed, because it holds a RevokedInfo.
        .revoked => out.push(&.{ 0xa1, 0x02, 0x30, 0x00 }), // [1] revoked, an empty RevokedInfo
        .unknown => out.push(&.{ 0x82, 0x00 }), // [2] unknown
    }
    out.generalizedTime("20231101000000Z"); // thisUpdate
    const next_at = out.mark();
    out.generalizedTime("20241101000000Z"); // nextUpdate
    out.wrap(next_at, 0xa0);
}

/// Builds the whole `OCSPResponse` around `single`, signed by `signer`.
/// `certs` rides in the optional [0] of the `BasicOCSPResponse`, which is
/// where a delegated responder's certificate goes.
fn buildResponse(
    a: std.mem.Allocator,
    signer: TestEcdsa.KeyPair,
    single: []const u8,
    certs: []const u8,
) ![]u8 {
    var basic: Der = .{};

    // tbsResponseData
    const tbs_at = basic.mark();
    const responder_at = basic.mark();
    writeName(&basic, Fixture.issuer_cn);
    basic.wrap(responder_at, 0xa1); // [1] byName, EXPLICIT
    basic.generalizedTime("20231101000000Z"); // producedAt
    const responses_at = basic.mark();
    // One `SingleResponse` SEQUENCE around the entry, then the
    // `responses` SEQUENCE OF around it.
    const single_at = basic.mark();
    basic.push(single);
    basic.wrap(single_at, 0x30);
    basic.wrap(responses_at, 0x30);
    basic.wrap(tbs_at, 0x30);

    // The signature over the tbsResponseData, header included.
    const tbs_bytes = try a.dupe(u8, basic.slice()[tbs_at..]);
    defer a.free(tbs_bytes);
    const sig = try signer.sign(tbs_bytes, null);
    var sig_buf: [TestEcdsa.Signature.der_encoded_length_max]u8 = undefined;

    basic.algorithm(&test_oid_ecdsa_with_sha256);
    const bits_at = basic.mark();
    basic.push(&.{0x00});
    basic.push(sig.toDer(&sig_buf));
    basic.wrap(bits_at, 0x03);
    if (certs.len != 0) {
        const seq_at = basic.mark();
        basic.push(certs);
        basic.wrap(seq_at, 0x30);
        // The same position, wrapped again, puts the SEQUENCE OF behind
        // an explicit [0].
        basic.wrap(seq_at, 0xa0);
    }
    basic.wrap(0, 0x30);

    // OCSPResponse
    var out: Der = .{};
    out.enumerated(0); // successful
    const bytes_at = out.mark();
    const seq_at = out.mark();
    out.oid(&oid_ocsp_basic);
    out.octetString(basic.slice());
    out.wrap(seq_at, 0x30);
    out.wrap(bytes_at, 0xa0);
    out.wrap(0, 0x30);
    return a.dupe(u8, out.slice());
}

/// One `Name` of one common name, the same shape the minter writes.
fn writeName(out: *Der, common_name: []const u8) void {
    const at = out.mark();
    const set_at = out.mark();
    const atav = out.mark();
    out.push(&test_oid_common_name);
    out.push(&.{ 0x13, @intCast(common_name.len) });
    out.push(common_name);
    out.wrap(atav, 0x30);
    out.wrap(set_at, 0x31);
    out.wrap(at, 0x30);
}

const test_oid_common_name = [_]u8{ 0x06, 0x03, 0x55, 0x04, 0x03 };

fn wrapBody(out: *Der, from: usize, tag: u8) void {
    out.wrap(from, tag);
}

test "a good response signed by the issuer verifies" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try verify(fixture.response, fixture.leafSerial(), fixture.root, test_now_sec);
}

test "a response for another serial says nothing about the leaf" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    // One single response whose serial is 2, which is no certificate of
    // this chain.
    var other: Der = .{};
    try writeSingleForSerial(&other, fixture.root, 2, .good);
    const response = try buildResponse(testing.allocator, fixture.root_key, other.slice(), &.{});
    defer testing.allocator.free(response);
    try testing.expectError(
        error.TlsCertificateStatusInvalid,
        verify(response, fixture.leafSerial(), fixture.root, test_now_sec),
    );
}

test "a revoked response is revoked and not merely invalid" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var revoked: Der = .{};
    try writeSingle(&revoked, fixture.root, fixture.leaf, .revoked);
    const response = try buildResponse(testing.allocator, fixture.root_key, revoked.slice(), &.{});
    defer testing.allocator.free(response);
    try testing.expectError(
        error.TlsCertificateStatusRevoked,
        verify(response, fixture.leafSerial(), fixture.root, test_now_sec),
    );
}

test "an unknown status is invalid" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var unknown: Der = .{};
    try writeSingle(&unknown, fixture.root, fixture.leaf, .unknown);
    const response = try buildResponse(testing.allocator, fixture.root_key, unknown.slice(), &.{});
    defer testing.allocator.free(response);
    try testing.expectError(
        error.TlsCertificateStatusInvalid,
        verify(response, fixture.leafSerial(), fixture.root, test_now_sec),
    );
}

test "a response whose window has passed is invalid" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try testing.expectError(
        error.TlsCertificateStatusInvalid,
        verify(fixture.response, fixture.leafSerial(), fixture.root, test_now_sec + 2 * 366 * 86400),
    );
}

test "a response produced in the future is invalid" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try testing.expectError(
        error.TlsCertificateStatusInvalid,
        verify(fixture.response, fixture.leafSerial(), fixture.root, test_now_sec - 2 * 366 * 86400),
    );
}

test "a response signed by another key is refused" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const stranger_key = try Client.testKey(0x93);
    const response = try buildResponse(testing.allocator, stranger_key, fixture.single.slice(), &.{});
    defer testing.allocator.free(response);
    try testing.expectError(
        error.CertificateSignatureInvalid,
        verify(response, fixture.leafSerial(), fixture.root, test_now_sec),
    );
}

test "a response that names another issuer says nothing about the leaf" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const other_key = try Client.testKey(0x94);
    var other_root: Client.DerBuf = .{};
    try Client.mint(&other_root, .{
        .serial = 2,
        .issuer_cn = "other root",
        .subject_cn = "other root",
        .san_dns = "other.test",
        .basic_constraints = .{ .ca = true },
        .key_usage = .key_cert_sign,
    }, other_key.public_key, other_key);
    const other_cert: Certificate = .{ .buffer = other_root.slice(), .index = 0 };
    const other_parsed = try Certificate.parse(other_cert);

    try testing.expectError(
        error.TlsCertificateStatusInvalid,
        verify(fixture.response, fixture.leafSerial(), other_parsed, test_now_sec),
    );
}

test "a delegated responder the issuer signed and gave the purpose to signs" {
    var fixture = try Fixture.init();
    defer fixture.deinit();

    const responder_key = try Client.testKey(0x95);
    var responder_buf: Client.DerBuf = .{};
    try Client.mint(&responder_buf, .{
        .serial = 3,
        .issuer_cn = Fixture.issuer_cn,
        .subject_cn = "responder.test",
        .san_dns = "responder.test",
        .basic_constraints = .{ .ca = false },
        .key_usage = .digital_signature,
        .ext_key_usage = .ocsp_signing,
    }, responder_key.public_key, fixture.root_key);

    const responder_cert: Certificate = .{ .buffer = responder_buf.slice(), .index = 0 };
    const responder = try Certificate.parse(responder_cert);

    // byKey responderID, which is the SHA-1 over the responder's key.
    var single: Der = .{};
    try writeSingle(&single, fixture.root, fixture.leaf, .good);
    const response = try buildDelegated(testing.allocator, responder, responder_key, single.slice());
    defer testing.allocator.free(response);
    try verify(response, fixture.leafSerial(), fixture.root, test_now_sec);
}

test "a delegated responder without the purpose is refused" {
    var fixture = try Fixture.init();
    defer fixture.deinit();

    const responder_key = try Client.testKey(0x96);
    var responder_buf: Client.DerBuf = .{};
    try Client.mint(&responder_buf, .{
        .serial = 3,
        .issuer_cn = Fixture.issuer_cn,
        .subject_cn = "responder.test",
        .san_dns = "responder.test",
        .basic_constraints = .{ .ca = false },
        .key_usage = .digital_signature,
        .ext_key_usage = .email_protection,
    }, responder_key.public_key, fixture.root_key);

    const responder_cert: Certificate = .{ .buffer = responder_buf.slice(), .index = 0 };
    const responder = try Certificate.parse(responder_cert);

    var single: Der = .{};
    try writeSingle(&single, fixture.root, fixture.leaf, .good);
    const response = try buildDelegated(testing.allocator, responder, responder_key, single.slice());
    defer testing.allocator.free(response);
    try testing.expectError(
        error.TlsCertificateStatusInvalid,
        verify(response, fixture.leafSerial(), fixture.root, test_now_sec),
    );
}

/// Builds a response whose signer is a delegated responder, named by
/// key hash, whose certificate rides in the response.
fn buildDelegated(
    a: std.mem.Allocator,
    responder: Certificate.Parsed,
    responder_key: TestEcdsa.KeyPair,
    single: []const u8,
) ![]u8 {
    var basic: Der = .{};
    const tbs_at = basic.mark();
    // [2] byKey, EXPLICIT: an OCTET STRING that carries the SHA-1 over
    // the responder's public key bytes.
    const id_at = basic.mark();
    var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    std.crypto.hash.Sha1.hash(responder.pubKey(), &digest, .{});
    basic.octetString(&digest);
    basic.wrap(id_at, 0xa2);
    basic.generalizedTime("20231101000000Z"); // producedAt
    const responses_at = basic.mark();
    // One `SingleResponse` SEQUENCE around the entry, then the
    // `responses` SEQUENCE OF around it.
    const single_at = basic.mark();
    basic.push(single);
    basic.wrap(single_at, 0x30);
    basic.wrap(responses_at, 0x30);
    basic.wrap(tbs_at, 0x30);

    const tbs_bytes = try a.dupe(u8, basic.slice()[tbs_at..]);
    defer a.free(tbs_bytes);
    const sig = try responder_key.sign(tbs_bytes, null);
    var sig_buf: [TestEcdsa.Signature.der_encoded_length_max]u8 = undefined;

    basic.algorithm(&test_oid_ecdsa_with_sha256);
    const bits_at = basic.mark();
    basic.push(&.{0x00});
    basic.push(sig.toDer(&sig_buf));
    basic.wrap(bits_at, 0x03);
    // The responder certificate in the optional [0]: one SEQUENCE OF,
    // wrapped again at the same position to put it behind the tag.
    const seq_at = basic.mark();
    basic.push(responder.certificate.buffer);
    basic.wrap(seq_at, 0x30);
    basic.wrap(seq_at, 0xa0);
    basic.wrap(0, 0x30);

    var out: Der = .{};
    out.enumerated(0);
    const bytes_at = out.mark();
    const seq_out_at = out.mark();
    out.oid(&oid_ocsp_basic);
    out.octetString(basic.slice());
    out.wrap(seq_out_at, 0x30);
    out.wrap(bytes_at, 0xa0);
    out.wrap(0, 0x30);
    return a.dupe(u8, out.slice());
}

/// One single response for a serial that is not the leaf's.
fn writeSingleForSerial(out: *Der, root: Certificate.Parsed, serial: u8, status: Status) !void {
    const cert_id_at = out.mark();
    out.algorithm(&test_oid_sha1);
    var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    const name_der = certificate.subjectName(root.certificate) catch return error.TlsCertificateStatusInvalid;
    std.crypto.hash.Sha1.hash(root.certificate.buffer[name_der.start..name_der.end], &digest, .{});
    out.octetString(&digest);
    std.crypto.hash.Sha1.hash(root.pubKey(), &digest, .{});
    out.octetString(&digest);
    out.integer(serial);
    out.wrap(cert_id_at, 0x30);
    switch (status) {
        .good => out.push(&.{ 0x80, 0x00 }),
        .revoked => out.push(&.{ 0xa1, 0x02, 0x30, 0x00 }),
        .unknown => out.push(&.{ 0x82, 0x00 }),
    }
    out.generalizedTime("20231101000000Z");
    const next_at = out.mark();
    out.generalizedTime("20241101000000Z");
    out.wrap(next_at, 0xa0);
}
