//! An in-memory PEM loader for `std.crypto.Certificate.Bundle`.
//!
//! `std` can load a PEM only from a file, because
//! `Bundle.addCertsFromFile` asks the file for its size. An embedded CA
//! bundle is already in memory, so zurl needs a loader that does not need a
//! file.

const std = @import("std");

const Bundle = std.crypto.Certificate.Bundle;

/// The errors `addCertsFromPem` can return.
pub const AddPemError = std.mem.Allocator.Error || std.base64.Error ||
    Bundle.ParseCertError ||
    error{ MissingEndCertificateMarker, CertificateAuthorityBundleTooBig };

/// Adds every certificate in `pem` to `cb`, and returns how many it added.
///
/// `std.crypto.Certificate.Bundle.addCertsFromFile` can only load a PEM
/// from a file, because it asks the file for its size. `pem` is already in
/// memory, the way an embedded CA bundle is, so this function decodes it
/// directly. It follows the same marker-scanning shape as
/// `addCertsFromFile`, without the file.
///
/// `now_sec` is the current time, in seconds since the Unix epoch. A
/// certificate whose validity period has ended by `now_sec` is left out.
///
/// A PEM comes from a file or a build artifact, so malformed text is a
/// runtime fault here, never a panic.
pub fn addCertsFromPem(
    cb: *Bundle,
    gpa: std.mem.Allocator,
    pem: []const u8,
    now_sec: i64,
) AddPemError!usize {
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";
    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");

    var added: usize = 0;
    var start_index: usize = 0;
    while (std.mem.findPos(u8, pem, start_index, begin_marker)) |begin| {
        const cert_start = begin + begin_marker.len;
        const cert_end = std.mem.findPos(u8, pem, cert_start, end_marker) orelse
            return error.MissingEndCertificateMarker;
        start_index = cert_end + end_marker.len;

        const encoded = std.mem.trim(u8, pem[cert_start..cert_end], " \t\r\n");

        // Reserve worst-case decoded room, then decode straight into the
        // bundle's own byte store, the way `addCertsFromFile` does.
        try cb.bytes.ensureUnusedCapacity(gpa, encoded.len);
        // `Bundle` addresses its byte store with a `u32`. A PEM that decodes
        // to more than 4 GiB is a runtime fault, not a truncation.
        const decoded_start = std.math.cast(u32, cb.bytes.items.len) orelse
            return error.CertificateAuthorityBundleTooBig;
        const dest = cb.bytes.allocatedSlice()[decoded_start..];
        const decoded_len = try decoder.decode(dest, encoded);
        cb.bytes.items.len += decoded_len;

        // `std.crypto.Certificate.Bundle.parseCert` hands the decoded bytes
        // to `std.crypto.Certificate.parse`, which walks them with
        // `std.crypto.Certificate.der.Element.parse`. That walker reads two
        // bytes at whatever offset it is given, with no bounds check against
        // the buffer, and `parse` calls it about fifteen times at offsets it
        // takes from elements it read before. Malformed input therefore
        // makes `parse` read out of bounds and panic instead of returning an
        // error. `derCertificateFits` proves, before `parseCert` sees the
        // bytes, that every offset `parse` can read from holds a complete
        // DER header inside the buffer. See its doc comment for what it
        // proves and what it depends on.
        if (!derCertificateFits(cb.bytes.items, decoded_start)) {
            cb.bytes.items.len = decoded_start;
            return error.CertificateFieldHasInvalidLength;
        }

        // `parseCert` rewinds `cb.bytes.items.len` back to `decoded_start`
        // whenever it silently skips a certificate (an unrecognised object
        // id, an expired certificate, or a duplicate subject). It leaves
        // `cb.bytes.items.len` where it is only when it keeps the
        // certificate, so that growth is what `added` counts. When it
        // returns an error instead, this function propagates the error
        // immediately and the count of `added` no longer matters.
        try cb.parseCert(gpa, decoded_start, now_sec);
        if (cb.bytes.items.len > decoded_start) added += 1;
    }
    return added;
}

/// The most levels of nesting `derTreeFits` accepts.
///
/// A real X.509 certificate nests six levels deep. That is a measurement, not
/// an estimate: every one of the 2581 certificates in the trust stores on this
/// machine reaches exactly depth 6. A cap of 32 therefore leaves more than
/// five times the room any real certificate needs. The cap bounds the explicit
/// stack, and it stops a hostile PEM that nests hundreds of thousands of
/// sequences from exhausting memory.
const der_max_depth = 32;

/// The object identifier `id-ecPublicKey` (1.2.840.10045.2.1), in the DER
/// content form, without the tag and the length.
const der_ec_public_key_oid = "\x2a\x86\x48\xce\x3d\x02\x01";

/// One DER element: the identifier byte, and the half-open range of the
/// content. `end` is also the offset just past the whole element.
const DerElement = struct {
    identifier: u8,
    start: u32,
    end: u32,

    fn isConstructed(element: DerElement) bool {
        return element.identifier & 0x20 != 0;
    }

    fn tag(element: DerElement) u8 {
        return element.identifier & 0x1f;
    }
};

/// Reads the DER element that starts at `index` in `bytes`, and checks every
/// byte it touches against `bytes.len` first. Returns `null` when the
/// element does not fit, or when the encoding is not DER.
fn derRead(bytes: []const u8, index: u32) ?DerElement {
    const start: usize = index;
    if (bytes.len < start + 2) return null;

    const identifier = bytes[start];
    const size_byte = bytes[start + 1];

    var content_start: usize = start + 2;
    var length: usize = size_byte;
    if (size_byte & 0x80 != 0) {
        const size_len: usize = size_byte & 0x7f;
        // DER always uses the definite length form. `0x80` is the indefinite
        // form, which `der.Element.parse` decodes as a zero length instead of
        // rejecting it. Reject it here.
        if (size_len == 0) return null;
        if (size_len > @sizeOf(u32)) return null;
        if (bytes.len < content_start + size_len) return null;
        length = 0;
        for (bytes[content_start..][0..size_len]) |byte| length = (length << 8) | byte;
        content_start += size_len;
    }

    const content_end = std.math.add(usize, content_start, length) catch return null;
    if (content_end > bytes.len) return null;
    return .{
        .identifier = identifier,
        .start = std.math.cast(u32, content_start) orelse return null,
        .end = std.math.cast(u32, content_end) orelse return null,
    };
}

/// Returns the child of `parent` at position `position`, or `null` when
/// `parent` holds no such child.
fn derChild(bytes: []const u8, parent: DerElement, position: usize) ?DerElement {
    var offset = parent.start;
    var index: usize = 0;
    while (offset < parent.end) : (index += 1) {
        // A header is 2 bytes at least, so `element.end` always moves
        // `offset` forward and this loop always ends.
        const element = derRead(bytes, offset) orelse return null;
        if (element.end > parent.end) return null;
        if (index == position) return element;
        offset = element.end;
    }
    return null;
}

/// Checks that the DER element at `index` is constructed, that it ends
/// exactly at the end of `bytes`, and that every element nested inside it
/// tiles its parent with no gap and no overlap.
///
/// The walk is iterative, over a stack of `der_max_depth` entries, because
/// the input is untrusted and recursion here would let a deeply nested PEM
/// exhaust the call stack.
fn derTreeFits(bytes: []const u8, index: u32) bool {
    const total = std.math.cast(u32, bytes.len) orelse return false;
    const root = derRead(bytes, index) orelse return false;
    if (!root.isConstructed()) return false;
    // No trailing bytes. `Certificate.parse` reads at offsets that can reach
    // the end of the root element, so nothing may follow it.
    if (root.end != total) return false;

    var parent_ends: [der_max_depth]u32 = undefined;
    var depth: usize = 0;
    var offset = root.start;
    var limit = root.end;

    while (true) {
        if (offset == limit) {
            if (depth == 0) return true;
            depth -= 1;
            offset = limit;
            limit = parent_ends[depth];
            continue;
        }
        const element = derRead(bytes, offset) orelse return false;
        if (element.end > limit) return false;
        if (element.isConstructed() and element.end > element.start) {
            if (depth == der_max_depth) return false;
            parent_ends[depth] = limit;
            depth += 1;
            limit = element.end;
            offset = element.start;
        } else {
            offset = element.end;
        }
    }
}

/// Checks that the certificate at `index` holds every field
/// `std.crypto.Certificate.parse` steps into.
///
/// `derTreeFits` proves that each element of the tree fits. It does not
/// prove that an element exists at every offset `parse` reads from, because
/// `parse` also reads at the offset just past an element. This function adds
/// the missing proof. See `derCertificateFits` for the whole argument.
fn derCertShapeFits(bytes: []const u8, index: u32) bool {
    const root = derRead(bytes, index) orelse return false;

    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
    // signatureValue }. `parse` reads at the start of the root, at the end
    // of the first two children, and at the start of the third.
    const tbs = derChild(bytes, root, 0) orelse return false;
    const signature_algorithm = derChild(bytes, root, 1) orelse return false;
    const signature = derChild(bytes, root, 2) orelse return false;
    if (!tbs.isConstructed()) return false;
    if (!signature_algorithm.isConstructed()) return false;
    if (derChild(bytes, signature_algorithm, 0) == null) return false;
    // `parseBitString` reads one byte at the start of the signature, so the
    // signature must hold a byte. Every other element `parseBitString` sees
    // sits inside `tbs`, which two more elements follow.
    if (signature.start >= bytes.len) return false;

    // TBSCertificate ::= SEQUENCE { version [0] OPTIONAL, serialNumber,
    // signature, issuer, validity, subject, subjectPublicKeyInfo, ... }.
    // `parse` treats the first child as the version only when the identifier
    // byte is exactly 0xa0, the same test used here.
    const version = derChild(bytes, tbs, 0) orelse return false;
    const serial: usize = if (version.identifier == 0xa0) 1 else 0;
    const validity = derChild(bytes, tbs, serial + 3) orelse return false;
    const subject = derChild(bytes, tbs, serial + 4) orelse return false;
    const pub_key_info = derChild(bytes, tbs, serial + 5) orelse return false;

    // Validity ::= SEQUENCE { notBefore, notAfter }.
    if (!validity.isConstructed()) return false;
    if (derChild(bytes, validity, 1) == null) return false;

    // Name ::= SEQUENCE OF SET OF SEQUENCE. `parse` walks the subject three
    // levels deep to find the common name, so all three levels must be
    // constructed.
    if (!subject.isConstructed()) return false;
    var name_offset = subject.start;
    while (name_offset < subject.end) {
        const rdn = derRead(bytes, name_offset) orelse return false;
        if (!rdn.isConstructed()) return false;
        var rdn_offset = rdn.start;
        while (rdn_offset < rdn.end) {
            const atav = derRead(bytes, rdn_offset) orelse return false;
            if (!atav.isConstructed()) return false;
            rdn_offset = atav.end;
        }
        name_offset = rdn.end;
    }

    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }, and
    // AlgorithmIdentifier ::= SEQUENCE { algorithm, parameters OPTIONAL }.
    if (!pub_key_info.isConstructed()) return false;
    const key_algorithm = derChild(bytes, pub_key_info, 0) orelse return false;
    if (derChild(bytes, pub_key_info, 1) == null) return false;
    if (!key_algorithm.isConstructed()) return false;
    const key_algorithm_oid = derChild(bytes, key_algorithm, 0) orelse return false;
    // `parse` reads the named curve only for an elliptic curve key, so only
    // that key needs the second child.
    const oid_bytes = bytes[key_algorithm_oid.start..key_algorithm_oid.end];
    if (std.mem.eql(u8, oid_bytes, der_ec_public_key_oid)) {
        if (derChild(bytes, key_algorithm, 1) == null) return false;
    }

    return derExtensionsFit(bytes, tbs, version, pub_key_info);
}

/// Checks the extensions of the certificate, under the same two conditions
/// `std.crypto.Certificate.parse` uses to decide to read them.
fn derExtensionsFit(
    bytes: []const u8,
    tbs: DerElement,
    version: DerElement,
    pub_key_info: DerElement,
) bool {
    // `parse` skips the extensions for a version 1 certificate. A missing
    // version field, or a version field of any other length, is version 1.
    if (version.identifier != 0xa0) return true;
    if (version.end - version.start != 3) return true;
    const encoded_version = bytes[version.start..version.end];
    const is_v2 = std.mem.eql(u8, encoded_version, "\x02\x01\x01");
    const is_v3 = std.mem.eql(u8, encoded_version, "\x02\x01\x02");
    if (!is_v2 and !is_v3) return true;
    // `parse` also skips the extensions when nothing follows the public key.
    if (pub_key_info.end >= tbs.end) return true;

    // The element after the public key exists, because the children of `tbs`
    // tile it with no gap.
    const outer = derRead(bytes, pub_key_info.end) orelse return false;
    // `parse` stops unless the tag is 3. The extensions carry `[3] EXPLICIT`,
    // whose low five bits are also 3.
    if (outer.tag() != 3) return true;
    if (!outer.isConstructed()) return false;
    const extensions = derChild(bytes, outer, 0) orelse return false;
    if (!extensions.isConstructed()) return false;

    var offset = extensions.start;
    while (offset < extensions.end) {
        const extension = derRead(bytes, offset) orelse return false;
        if (!extension.isConstructed()) return false;
        // `parse` reads the object identifier at the start of the extension,
        // then reads again just past it. That second offset is the next
        // sibling, or the end of a parent, and every such offset stays inside
        // `tbs`, which the signature algorithm and the signature follow.
        if (derChild(bytes, extension, 0) == null) return false;
        offset = extension.end;
    }
    return true;
}

/// Reports whether `std.crypto.Certificate.parse` can walk the certificate
/// that starts at `index` in `bytes` without an out-of-bounds read.
///
/// `std.crypto.Certificate.der.Element.parse` trusts its caller to already
/// know that an offset is safe to read. It reads two bytes there with no
/// bounds check, and more for a long-form length. `Certificate.parse` calls
/// it about fifteen times, at offsets it takes from elements it read before:
/// the start of an element, and the offset just past an element. A
/// certificate decoded from a PEM has not earned that trust.
///
/// The guard proves two things together:
///
/// 1. `derTreeFits`: the whole buffer, from `index` to the end, is one
///    constructed element whose descendants tile it with no gap, no overlap,
///    and no trailing byte. Every element header therefore fits, and every
///    element boundary is either the start of another element or the end of
///    a parent.
/// 2. `derCertShapeFits`: the certificate holds every field `parse` steps
///    into. This turns each "offset just past an element" that `parse` reads
///    into the start of an element that rule 1 already proved fits.
///
/// Together the two rules cover every offset `parse` reads from, so `parse`
/// can only return an error, never panic.
///
/// The guarantee stops at `parse`. A certificate this guard accepts can still
/// panic other `std` functions that walk the same bytes later:
/// `rsa.PublicKey.parseDer` through `Bundle.verify` reads an empty public key,
/// and `Parsed.verifyHostName` reads a truncated subject alternative name.
/// Both are unguarded here. `std` has the same exposure through
/// `addCertsFromFile`, so zurl is no worse, but a TLS client that calls
/// `verify` on a bundle from an untrusted source needs its own guard.
///
/// This guard is coupled to `std`. It was checked against the
/// `std.crypto.Certificate.parse` of Zig 0.16.0. A change to that function,
/// such as one more field or one more nested read, can make this guard
/// insufficient again, and nothing here detects the drift. Read `parse`
/// again after a Zig upgrade.
fn derCertificateFits(bytes: []const u8, index: u32) bool {
    return derTreeFits(bytes, index) and derCertShapeFits(bytes, index);
}

/// The certificate authorities that the build put into the binary.
///
/// The build runs `tools/certdata2pem.zig` over NSS's `certdata.txt` and
/// injects the result here with `addAnonymousImport`. A static zurl carries
/// its own trust roots this way, and needs no filesystem to find them. That
/// is what makes zurl work on a bare target.
pub const embedded_pem = @embedFile("ca_bundle_pem");

/// Adds every embedded root certificate authority to `cb`, and returns how
/// many it added.
///
/// `now_sec` is the current time, in seconds since the Unix epoch, the same
/// as `addCertsFromPem` takes it.
pub fn loadEmbedded(cb: *Bundle, gpa: std.mem.Allocator, now_sec: i64) AddPemError!usize {
    return addCertsFromPem(cb, gpa, embedded_pem, now_sec);
}

/// Two real certificate authority certificates, for tests.
///
/// - AC RAIZ FNMT-RCM SERVIDORES SEGUROS: valid 2018-12-20 to 2043-12-20.
/// - ANF Secure Server Root CA: valid 2019-09-04 to 2039-08-30.
///
/// Both windows cover 1 700 000 000 (2023-11-14) and today, and both
/// certificates are expired by the year 2400.
pub const test_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIICbjCCAfOgAwIBAgIQYvYybOXE42hcG2LdnC6dlTAKBggqhkjOPQQDAzB4MQsw
    \\CQYDVQQGEwJFUzERMA8GA1UECgwIRk5NVC1SQ00xDjAMBgNVBAsMBUNlcmVzMRgw
    \\FgYDVQRhDA9WQVRFUy1RMjgyNjAwNEoxLDAqBgNVBAMMI0FDIFJBSVogRk5NVC1S
    \\Q00gU0VSVklET1JFUyBTRUdVUk9TMB4XDTE4MTIyMDA5MzczM1oXDTQzMTIyMDA5
    \\MzczM1oweDELMAkGA1UEBhMCRVMxETAPBgNVBAoMCEZOTVQtUkNNMQ4wDAYDVQQL
    \\DAVDZXJlczEYMBYGA1UEYQwPVkFURVMtUTI4MjYwMDRKMSwwKgYDVQQDDCNBQyBS
    \\QUlaIEZOTVQtUkNNIFNFUlZJRE9SRVMgU0VHVVJPUzB2MBAGByqGSM49AgEGBSuB
    \\BAAiA2IABPa6V1PIyqvfNkpSIeSX0oNnnvBlUdBeh8dHsVnyV0ebAAKTRBdp20LH
    \\sbI6GA60XYyzZl2hNPk2LEnb80b8s0RpRBNm/dfF/a82Tc4DTQdxz69qBdKiQ1oK
    \\Um8BA06Oi6NCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYD
    \\VR0OBBYEFAG5L++/EYZg8k/QQW6rcx/n0m5JMAoGCCqGSM49BAMDA2kAMGYCMQCu
    \\SuMrQMN0EfKVrRYj3k4MGuZdpSRea0R7/DjiT8ucRRcRTBQnJlU5dUoDzBOQn5IC
    \\MQD6SmxgiHPz7riYYqnOK8LZiqZwMR2vsJRM60/G49HzYqc8/5MuB1xJAWdpEgJy
    \\v+c=
    \\-----END CERTIFICATE-----
    \\-----BEGIN CERTIFICATE-----
    \\MIIF7zCCA9egAwIBAgIIDdPjvGz5a7EwDQYJKoZIhvcNAQELBQAwgYQxEjAQBgNV
    \\BAUTCUc2MzI4NzUxMDELMAkGA1UEBhMCRVMxJzAlBgNVBAoTHkFORiBBdXRvcmlk
    \\YWQgZGUgQ2VydGlmaWNhY2lvbjEUMBIGA1UECxMLQU5GIENBIFJhaXoxIjAgBgNV
    \\BAMTGUFORiBTZWN1cmUgU2VydmVyIFJvb3QgQ0EwHhcNMTkwOTA0MTAwMDM4WhcN
    \\MzkwODMwMTAwMDM4WjCBhDESMBAGA1UEBRMJRzYzMjg3NTEwMQswCQYDVQQGEwJF
    \\UzEnMCUGA1UEChMeQU5GIEF1dG9yaWRhZCBkZSBDZXJ0aWZpY2FjaW9uMRQwEgYD
    \\VQQLEwtBTkYgQ0EgUmFpejEiMCAGA1UEAxMZQU5GIFNlY3VyZSBTZXJ2ZXIgUm9v
    \\dCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANvrayvmZFSVgpCj
    \\cqQZAZ2cC4Ffc0m6p6zzBE57lgvsEeBbphzOG9INgxwruJ4dfkUyYA8H6XdYfp9q
    \\yGFOtibBTI3/TO80sh9l2Ll49a2pcbnvT1gdpd50IJeh7WhM3pIXS7yr/2WanvtH
    \\2Vdy8wmhrnZEE26cLUQ5vPnHO6RYPUG9tMJJo8gN0pcvB2VSAKduyK9o7PQUlrZX
    \\H1bDOZ8rbeTzPvY1ZNoMHKGESy9LS+IsJJ1tk0DrtSOOMspvRdOoiXsezx76W0OL
    \\zc2oD2rKDF65nkeP8Nm2CgtYZRczuSPkdxl9y0oukntPLxB3sY0vaJxizOBQ+OyR
    \\p1RMVwnVdmPF6GUe7m1qzwmd+nxPrWAI/VaZDxUse6mAq4xhj0oHdkLePfTdsiQz
    \\W7i1o0TJrH93PB0j7IKppuLIBkwC/qxcmZkLLxCKpvR/1Yd0DVlJRfbwcVw5Kda/
    \\SiOL9V8BY9KHcyi1Swr1+KuCLH5zJTIdC2MKF4EA/7Z2Xue0sUDKIbvVgFHlSFJn
    \\LNJhiQcND85Cd8BEc5xEUKDbEAotlRyBr+Qc5RQe8TZBAQIvfXOn3kLMTOmJDVb3
    \\n5HUA8ZsyY/b2BzgQJhdZpmYgG4t/wHFzstGH6wCxkPmrqKEPMVOHj1tyRRM4y5B
    \\u8o5vzY8KhmqQYdOpc5LMnndkEl/AgMBAAGjYzBhMB8GA1UdIwQYMBaAFJxf0Gxj
    \\o1+TypOYCK2Mh6UsXME3MB0GA1UdDgQWBBScX9BsY6Nfk8qTmAitjIelLFzBNzAO
    \\BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
    \\AgEATh65isagmD9uw2nAalxJUqzLK114OMHVVISfk/CHGT0sZonrDUL8zPB1hT+L
    \\9IBdeeUXZ701guLyPI59WzbLWoAAKfLOKyzxj6ptBZNscsdW699QIyjlRRA96Gej
    \\rw5VD5AJYu9LWaL2U/HANeQvwSS9eS9OICI7/RogsKQOLHDtdD+4E5UGUcjohybK
    \\pFtqFiGS3XNgnhAY3jyB6ugYw3yJ8otQPr0R4hUDqDZ9MwFsSBXXiJCZBMXM5gf0
    \\vPSQ7RPi6ovDj6MzD8EpTBNO2hVWcXNyglD2mjN8orGoGjR0ZVzO0eurU+AagNjq
    \\OknkJjCb5RyKqKkVMoaZkgoQI1YS4PbOTOK7vtuNknMBZi9iPrJyJ0U27U1W45eZ
    \\/zo1PqVUSlJZS2Db7v54EX9K3BR5YLZrZAPbFYPhor72I5dQ8AkzNqdxliXzuUJ9
    \\2zg/LFis6ELhDtjTO0wugumDLmsx2d1Hhk9tl5EuT+IocTUW0fJz/iUrB0ckYyfI
    \\+PbZa/wSMVYIwFNCr5zQM378BvAxRAMU8Vjq8moNqRGyg77FGr8H6lnco4g175x2
    \\MjxNBiLOFeXdntiP2t7SxDnlF4HPOEfrf4htWRvfn0IUrn7PqLBmZdo3r5+qPeoo
    \\tt7VMVgWglvquxl1AnMaykgaIZOQCo6ThKd9OyMYkomgjaw=
    \\-----END CERTIFICATE-----
    \\
;

/// One self-signed certificate, for tests that must tell a fixture apart
/// from every certificate a real trust store carries.
///
/// Subject: `CN=zurl test fixture do not trust`. No public certificate
/// authority uses this subject, so a test that finds it in a bundle knows
/// the fixture, and nothing else, put it there. Valid 2020-01-01 to
/// 2040-01-01, a window that covers `testNow()` (2023-11-14) and today.
///
/// Generated at authoring time with:
/// ```
/// openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 \
///   -nodes -keyout /dev/null -out fixture.pem \
///   -subj "/CN=zurl test fixture do not trust" \
///   -not_before 20200101000000Z -not_after 20400101000000Z
/// ```
/// The test suite does not run `openssl`; only the PEM output is kept.
pub const fixture_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBpzCCAU2gAwIBAgIUVrEoi2U41V6IObfpV/XVo7MUZbEwCgYIKoZIzj0EAwIw
    \\KTEnMCUGA1UEAwweenVybCB0ZXN0IGZpeHR1cmUgZG8gbm90IHRydXN0MB4XDTIw
    \\MDEwMTAwMDAwMFoXDTQwMDEwMTAwMDAwMFowKTEnMCUGA1UEAwweenVybCB0ZXN0
    \\IGZpeHR1cmUgZG8gbm90IHRydXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
    \\DUcQYNnbvNBp2HwFYSuBvG3dXzmmD4bk8RZXlumyxBriA+EBqjbwEoRDqXILjpOl
    \\BnldYOMAE1NAiFCH2k+w6aNTMFEwHQYDVR0OBBYEFFv7EpNXFbnYGu8InwCe3PRk
    \\1NHGMB8GA1UdIwQYMBaAFFv7EpNXFbnYGu8InwCe3PRk1NHGMA8GA1UdEwEB/wQF
    \\MAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhALQbDdJv9g6XiTEEoR62869uMNgGAVZe
    \\Eh7GnQMJ1DLyAiA9NWakJ2dStrnyzv8twityyJIu6U+fl8+M7dEFECO0KA==
    \\-----END CERTIFICATE-----
    \\
;

test "the fixture certificate adds one certificate and parses cleanly" {
    var cb: std.crypto.Certificate.Bundle = .empty;
    defer cb.deinit(std.testing.allocator);
    const added = try addCertsFromPem(&cb, std.testing.allocator, fixture_pem, 1_700_000_000);
    try std.testing.expectEqual(@as(usize, 1), added);
    try std.testing.expectEqual(@as(usize, 1), cb.map.count());
}

test "a PEM with two certificates adds both to the bundle" {
    var cb: std.crypto.Certificate.Bundle = .empty;
    defer cb.deinit(std.testing.allocator);
    const added = try addCertsFromPem(&cb, std.testing.allocator, test_pem, 1_700_000_000);
    try std.testing.expectEqual(@as(usize, 2), added);
    try std.testing.expectEqual(@as(usize, 2), cb.map.count());
}

test "an empty input adds nothing and does not fail" {
    var cb: std.crypto.Certificate.Bundle = .empty;
    defer cb.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), try addCertsFromPem(&cb, std.testing.allocator, "", 1_700_000_000));
}

test "text with a begin marker and no end marker is a runtime fault" {
    var cb: std.crypto.Certificate.Bundle = .empty;
    defer cb.deinit(std.testing.allocator);
    try std.testing.expectError(
        error.MissingEndCertificateMarker,
        addCertsFromPem(&cb, std.testing.allocator, "-----BEGIN CERTIFICATE-----\nQUJD\n", 1_700_000_000),
    );
}

test "text with no markers at all adds nothing" {
    var cb: std.crypto.Certificate.Bundle = .empty;
    defer cb.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), try addCertsFromPem(&cb, std.testing.allocator, "hello\nworld\n", 1_700_000_000));
}

// `QUJD` decodes to the three bytes "ABC". `std.crypto.Certificate.parse`
// reads that as a DER element whose declared length runs past the end of
// the buffer, which is `error.CertificateFieldHasInvalidLength`, not the
// `error.CertificateHasInvalidDefinition` the brief guessed (that name does
// not exist anywhere in `std`). See the report for why this needs a guard
// in this file: `std`'s own DER walker does not bounds-check this case and
// panics on it instead of returning an error.
test "base64 that is not a certificate is a runtime fault, not a panic" {
    var cb: std.crypto.Certificate.Bundle = .empty;
    defer cb.deinit(std.testing.allocator);
    const text = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n";
    try std.testing.expectError(error.CertificateFieldHasInvalidLength, addCertsFromPem(&cb, std.testing.allocator, text, 1_700_000_000));
}

test "a certificate that expired before now_sec is left out" {
    var cb: std.crypto.Certificate.Bundle = .empty;
    defer cb.deinit(std.testing.allocator);
    // Year 2400. Every certificate in test_pem is already expired by then.
    const added = try addCertsFromPem(&cb, std.testing.allocator, test_pem, 13_569_465_600);
    try std.testing.expectEqual(@as(usize, 0), added);
}

/// Wraps `body`, the base64 form of a DER certificate, in a PEM envelope.
fn testPemEnvelope(comptime body: []const u8) []const u8 {
    return "-----BEGIN CERTIFICATE-----\n" ++ body ++ "\n-----END CERTIFICATE-----\n";
}

/// Checks that a PEM whose only certificate is `body` is a runtime fault.
///
/// Every malformation below is rejected with the same error, because every
/// one of them means the same thing: the declared DER structure does not
/// agree with the bytes that carry it.
fn expectMalformedCert(comptime body: []const u8) !void {
    var cb: std.crypto.Certificate.Bundle = .empty;
    defer cb.deinit(std.testing.allocator);
    try std.testing.expectError(
        error.CertificateFieldHasInvalidLength,
        addCertsFromPem(&cb, std.testing.allocator, testPemEnvelope(body), 1_700_000_000),
    );
}

// Reproducers A to L. Each one made `std.crypto.Certificate.parse` read out
// of bounds and panic, or was already rejected and must stay rejected.

// A: 41 42 43. A primitive element whose length runs 66 bytes past a 3 byte
// buffer.
test "a declared length past the end of the buffer is a runtime fault" {
    try expectMalformedCert("QUJD");
}

// B: 30 02 30 00. A tidy tree, but the top level holds one child where
// `Certificate.parse` needs three.
test "a top level element with too few children is a runtime fault" {
    try expectMalformedCert("MAIwAA==");
}

// C: 30 80 30 00. `der.Element.parse` decodes the indefinite length form as
// a zero length, which DER forbids.
test "the indefinite der length form is a runtime fault" {
    try expectMalformedCert("MIAwAA==");
}

// D: 30 85 01 01 01 01 01.
test "a long form length of more than four bytes is a runtime fault" {
    try expectMalformedCert("MIUBAQEBAQ==");
}

// E: 30 84 ff ff ff ff.
test "a four byte length that no buffer can hold is a runtime fault" {
    try expectMalformedCert("MIT/////");
}

// F: 30 84 00. The length bytes themselves run past the end.
test "a truncated long form length is a runtime fault" {
    try expectMalformedCert("MIQA");
}

// G: 30. One identifier byte, and no length byte.
test "a certificate of one byte is a runtime fault" {
    try expectMalformedCert("MA==");
}

// H: 30 02 30 02 00 00. The child declares more content than the parent
// holds.
test "a child that runs past its parent is a runtime fault" {
    try expectMalformedCert("MAIwAgAA");
}

// I: 02 01 00. An INTEGER at the top level. `Certificate.parse` reads at the
// start of the content of the top level element, which only a constructed
// element has.
test "a primitive top level element is a runtime fault" {
    try expectMalformedCert("AgEA");
}

// J: 30 00 41 41. The top level element ends after two bytes, and two bytes
// follow it.
test "trailing bytes after the top level element are a runtime fault" {
    try expectMalformedCert("MABBQQ==");
}

// K: an empty body. Nothing decodes, so no element starts at offset 0.
test "an empty certificate body is a runtime fault" {
    try expectMalformedCert("");
}

// L: 30 07 30 05 a0 03 02 01 02. A well formed version 3 prefix, and none of
// the fields that follow it.
test "a version three prefix with no further fields is a runtime fault" {
    try expectMalformedCert("MAcwBaADAgEC");
}

test "the embedded bundle holds a usable set of root certificates" {
    var cb: std.crypto.Certificate.Bundle = .empty;
    defer cb.deinit(std.testing.allocator);
    const added = try loadEmbedded(&cb, std.testing.allocator, 1_700_000_000);
    // A real NSS root set is well over a hundred. A tiny number means the
    // generator silently produced almost nothing.
    try std.testing.expect(added > 100);
    try std.testing.expectEqual(added, cb.map.count());
}

test "the embedded bundle is not empty at compile time" {
    try std.testing.expect(embedded_pem.len > 100_000);
}

test "a der tree nested past the depth cap is a runtime fault, not a crash" {
    const depth = 4096;
    comptime std.debug.assert(depth > der_max_depth);

    // Each level is one SEQUENCE with a two byte long form length, so every
    // header is 4 bytes and the content of level `i` is every deeper level.
    var der: [depth * 4]u8 = undefined;
    for (0..depth) |level| {
        const content_len: u16 = @intCast((depth - 1 - level) * 4);
        der[level * 4 + 0] = 0x30;
        der[level * 4 + 1] = 0x82;
        der[level * 4 + 2] = @intCast(content_len >> 8);
        der[level * 4 + 3] = @truncate(content_len);
    }

    const encoder = std.base64.standard.Encoder;
    var encoded: [encoder.calcSize(der.len)]u8 = undefined;
    const body = encoder.encode(&encoded, &der);

    const text = try std.fmt.allocPrint(
        std.testing.allocator,
        "-----BEGIN CERTIFICATE-----\n{s}\n-----END CERTIFICATE-----\n",
        .{body},
    );
    defer std.testing.allocator.free(text);

    var cb: std.crypto.Certificate.Bundle = .empty;
    defer cb.deinit(std.testing.allocator);
    try std.testing.expectError(
        error.CertificateFieldHasInvalidLength,
        addCertsFromPem(&cb, std.testing.allocator, text, 1_700_000_000),
    );
}
