//! A certificate revocation list, read from a file and checked against a
//! peer certificate.
//!
//! **What this covers.** RFC 5280 section 5 gives the `CertificateList`:
//! a `tbsCertList` signed by the issuer of the certificates it revokes.
//! This file reads one, checks the signature against the issuer
//! certificate of the peer chain, checks the validity window, and answers
//! whether a serial number is on it. That is the whole of `--crlfile`, and
//! it is the check OpenSSL makes with `X509_V_FLAG_CRL_CHECK`: the leaf
//! certificate against the CRL its own issuer signed.
//!
//! **What this does not cover.** One CRL file, one issuer. A CRL signed by
//! a certificate that did not issue the leaf is refused by name, which is
//! also what OpenSSL does. Delta CRLs, CRL distribution points, and CRL
//! entry reasons are not read: `--crlfile` gives zurl one list, and the
//! list it gives is the authority.
//!
//! Every walk here reads DER the caller loaded from disk, so every walk
//! goes through the bounded element reader of `certificate.zig`.

const std = @import("std");

const Certificate = std.crypto.Certificate;
const certificate = @import("certificate.zig");
const signature = @import("signature.zig");
const mem = std.mem;

const der = Certificate.der;

/// Every fault `parsePem` can report.
pub const ParseError = error{
    /// The file holds no CRL at all: no PEM marker and not one byte of
    /// DER a `CertificateList` can be read out of.
    CrlBadFormat,
    /// A PEM block carries base64 that does not decode.
    CrlBadBase64,
    OutOfMemory,
};

/// Every fault `check` can report.
pub const CheckError = signature.VerifyError || error{
    /// The serial number of the peer certificate is on the list.
    TlsCertificateRevoked,
    /// The CRL names an issuer that did not issue the peer certificate.
    TlsCrlUntrusted,
    /// The validity window of the CRL does not cover the moment of the
    /// check.
    TlsCrlOutOfDate,
};

/// The largest CRL file this module reads into memory in one go.
///
/// A `--crlfile` path is untrusted input in the sense `loader.zig` spells
/// out for a `--cacert` path: it comes from a flag, not from zurl. 16 MiB
/// gives every real CRL room and turns a file larger than that into a
/// runtime error instead of an unbounded allocation.
pub const max_crl_file_bytes: usize = 16 * 1024 * 1024;

/// One parsed `CertificateList`, and everything `check` needs of it.
///
/// Every slice points into `der`, which this value owns. `deinit` frees
/// it, so a `List` must be deinit'd exactly once and nothing may outlive
/// it.
pub const List = struct {
    gpa: std.mem.Allocator,
    /// The DER this value owns, which every slice below points into.
    der: []u8,
    /// The `issuer` of the `tbsCertList`, as the bytes of the DER `Name`.
    /// This is what an issuer certificate's `subject()` must equal.
    issuer: []const u8,
    /// The whole `tbsCertList`, which the signature covers.
    tbs: []const u8,
    /// The signature algorithm the list declared beside its signature.
    signature_algorithm: Certificate.Algorithm,
    /// The signature, without its BIT STRING header.
    signature: []const u8,
    /// The `thisUpdate` of the list, in seconds.
    this_update: u64,
    /// The `nextUpdate` of the list, when it carries one, in seconds.
    next_update: ?u64,
    /// The `userCertificate` of every entry of `revokedCertificates`, each
    /// as the bytes of its DER INTEGER.
    serials: []const []const u8,

    pub fn deinit(list: *List) void {
        list.gpa.free(list.serials);
        list.gpa.free(list.der);
        list.* = undefined;
    }

    /// Whether `serial_der` is one of the serials on the list.
    ///
    /// The comparison is the bytes of the DER INTEGER, not the number it
    /// names. DER requires a minimal encoding, so two encodings of one
    /// serial are byte for byte the same.
    pub fn revoked(list: *const List, serial_der: []const u8) bool {
        for (list.serials) |one| {
            if (mem.eql(u8, one, serial_der)) return true;
        }
        return false;
    }

    /// Checks a peer certificate serial against the list.
    ///
    /// `serial_der` is the DER of the serial number of the certificate the
    /// peer presented, captured while its bytes were still current. The
    /// `issuer` is the certificate the peer chain named as the issuer of
    /// that certificate: the one its `issuer()` names and its signature
    /// checks under. The four checks are in the order OpenSSL makes them,
    /// and the first refusal says which one.
    ///
    /// The issuer certificate must have come through `certificate.parse`,
    /// which is what proves its RSA key fits the reader below. See
    /// `signature.zig`.
    pub fn check(
        list: *const List,
        serial_der: []const u8,
        issuer: Certificate.Parsed,
        now_sec: i64,
    ) CheckError!void {
        // The list is only about a certificate its own issuer signed. A
        // list from another authority says nothing about this leaf, and
        // accepting it would let any CRL the caller has on disk vouch for
        // any chain.
        if (!mem.eql(u8, list.issuer, issuer.subject())) {
            return error.TlsCrlUntrusted;
        }

        // The signature of the list, checked under the key of the issuer.
        // A list nobody signed is worth nothing.
        try signature.verify(
            list.signature_algorithm,
            list.tbs,
            list.signature,
            issuer.pub_key_algo,
            issuer.pubKey(),
        );

        // The window. A list from the future is as useless as one from
        // the past: either way the issuer has not said, at the moment of
        // this connection, that the serial is revoked.
        if (now_sec < 0) return error.TlsCrlOutOfDate;
        const now: u64 = @intCast(now_sec);
        if (now < list.this_update) return error.TlsCrlOutOfDate;
        const until = list.next_update orelse return error.TlsCrlOutOfDate;
        if (now > until) return error.TlsCrlOutOfDate;

        // And the check itself.
        if (list.revoked(serial_der)) {
            return error.TlsCertificateRevoked;
        }
    }
};

/// Reads one CRL out of `text`.
///
/// The text may be PEM, which is what curl's `--crlfile` mostly carries,
/// or the bare DER of one `CertificateList`. PEM wins when the file holds
/// a PEM marker; a file with no marker is DER. A file that holds several
/// PEM blocks gets the first, because one `--crlfile` is one list.
pub fn parsePem(gpa: std.mem.Allocator, text: []const u8) ParseError!List {
    const begin_marker = "-----BEGIN X509 CRL-----";
    const end_marker = "-----END X509 CRL-----";
    const second_begin = "-----BEGIN CRL-----";
    const second_end = "-----END CRL-----";

    if (mem.findPos(u8, text, 0, begin_marker)) |begin| {
        return parseBody(gpa, text, begin + begin_marker.len, end_marker);
    }
    if (mem.findPos(u8, text, 0, second_begin)) |begin| {
        return parseBody(gpa, text, begin + second_begin.len, second_end);
    }
    return parseDer(gpa, text);
}

fn parseBody(
    gpa: std.mem.Allocator,
    text: []const u8,
    body_at: usize,
    end_marker: []const u8,
) ParseError!List {
    const end = mem.findPos(u8, text, body_at, end_marker) orelse return error.CrlBadFormat;
    const encoded = mem.trim(u8, text[body_at..end], " \t\r\n");
    if (encoded.len == 0) return error.CrlBadFormat;
    // Three octets in four, and the padding never takes more.
    const decoded_max = encoded.len / 4 * 3 + 3;
    const decoded = gpa.alloc(u8, decoded_max) catch return error.OutOfMemory;
    errdefer gpa.free(decoded);
    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const len = decoder.decode(decoded, encoded) catch |err| switch (err) {
        error.NoSpaceLeft => unreachable, // the buffer holds every octet three octets in four
        else => return error.CrlBadBase64,
    };
    // `parseDer` copies what it reads, so the decode buffer can go now.
    defer gpa.free(decoded);
    return parseDer(gpa, decoded[0..len]);
}

/// Reads one `CertificateList` out of `der` bytes.
///
/// The `der` bytes are copied, because a PEM decode hands this a slice of
/// a buffer the caller is free to reuse. Everything else the `List`
/// carries points into the copy.
pub fn parseDer(gpa: std.mem.Allocator, input: []const u8) ParseError!List {
    const copy = gpa.dupe(u8, input) catch return error.OutOfMemory;
    errdefer gpa.free(copy);

    const list_elem = certificate.parseElement(copy, 0) catch return error.CrlBadFormat;
    if (list_elem.identifier.tag != .sequence) return error.CrlBadFormat;
    // The tbsCertList starts where the outer list's content starts, and
    // the signature covers it from there, SEQUENCE header included.
    const tbs_index = list_elem.slice.start;
    const tbs_elem = certificate.parseElement(copy, @intCast(tbs_index)) catch
        return error.CrlBadFormat;
    if (tbs_elem.identifier.tag != .sequence) return error.CrlBadFormat;

    const d = try tbs(gpa, copy, tbs_elem);
    errdefer gpa.free(d.serials);

    // signatureAlgorithm, then signatureValue. The algorithm is read out
    // of the object identifier inside the SEQUENCE, which is the shape
    // `parseAlgorithm` takes.
    const sig_algo_elem = certificate.parseElement(copy, tbs_elem.slice.end) catch
        return error.CrlBadFormat;
    if (sig_algo_elem.identifier.tag != .sequence) return error.CrlBadFormat;
    const sig_algo_oid = certificate.parseElement(copy, sig_algo_elem.slice.start) catch
        return error.CrlBadFormat;
    const signature_algorithm = Certificate.parseAlgorithm(copy, sig_algo_oid) catch
        return error.CrlBadFormat;
    const sig_elem = certificate.parseElement(copy, sig_algo_elem.slice.end) catch
        return error.CrlBadFormat;
    if (sig_elem.identifier.tag != .bitstring) return error.CrlBadFormat;
    // A signature BIT STRING has an unused bits count of zero, so the
    // content is the signature itself.
    if (sig_elem.slice.start >= sig_elem.slice.end) return error.CrlBadFormat;
    if (copy[sig_elem.slice.start] != 0) return error.CrlBadFormat;

    return .{
        .gpa = gpa,
        .der = copy,
        .issuer = d.issuer,
        .tbs = copy[tbs_index..tbs_elem.slice.end],
        .signature_algorithm = signature_algorithm,
        .signature = copy[sig_elem.slice.start + 1 .. sig_elem.slice.end],
        .this_update = d.this_update,
        .next_update = d.next_update,
        .serials = d.serials,
    };
}

/// The fields `parseDer` walks out of the `tbsCertList`.
const Tbs = struct {
    issuer: []const u8,
    this_update: u64,
    next_update: ?u64,
    serials: []const []const u8,
};

/// Walks the `tbsCertList`. The version field is optional, which is the
/// one reason the walk cannot be a plain list of positions.
fn tbs(gpa: std.mem.Allocator, copy: []u8, tbs_elem: der.Element) ParseError!Tbs {
    var at: usize = tbs_elem.slice.start;
    var first = certificate.parseElement(copy, @intCast(at)) catch return error.CrlBadFormat;

    // An INTEGER version comes first in a v2 list. A v1 list starts at the
    // signature algorithm, which is a SEQUENCE.
    var serials: []const []const u8 = &.{};
    if (first.identifier.tag == .integer) {
        at = first.slice.end;
        first = certificate.parseElement(copy, @intCast(at)) catch return error.CrlBadFormat;
    }

    // The signature algorithm of the tbsCertList. RFC 5280 section 5.1.2.2
    // says it must equal the outer one, and OpenSSL refuses a pair that
    // disagrees. The outer one is what picks the verifier, so the same
    // rule the certificate walk applies applies here.
    if (first.identifier.tag != .sequence) return error.CrlBadFormat;
    at = first.slice.end;

    // The issuer.
    first = certificate.parseElement(copy, @intCast(at)) catch return error.CrlBadFormat;
    if (first.identifier.tag != .sequence) return error.CrlBadFormat;
    const issuer = copy[first.slice.start..first.slice.end];
    at = first.slice.end;

    // thisUpdate, then the optional nextUpdate.
    const this_update = try time(copy, &at);
    const next_update: ?u64 = time(copy, &at) catch |err| switch (err) {
        error.CrlBadFormat => null,
        else => |e| return e,
    };

    // The optional revokedCertificates, then the optional [0]
    // crlExtensions. Both are recognized by the tag of what follows.
    if (at < tbs_elem.slice.end) {
        first = certificate.parseElement(copy, @intCast(at)) catch return error.CrlBadFormat;
        if (first.identifier.tag == .sequence) {
            serials = try entries(gpa, copy, first);
            at = first.slice.end;
        }
    }

    return .{
        .issuer = issuer,
        .this_update = this_update,
        .next_update = next_update,
        .serials = serials,
    };
}

/// Reads one UTCTime or GeneralizedTime at `at`, and moves `at` past it.
///
/// The clock of a CRL is the clock of a certificate, so the reader is the
/// same one the certificate walk uses, pointed at the bytes of this list.
/// A tag that is not a time is the absence of the field, which is how the
/// optional `nextUpdate` is told from the `revokedCertificates` that may
/// follow it.
fn time(copy: []const u8, at: *usize) ParseError!u64 {
    const elem = certificate.parseElement(copy, @intCast(at.*)) catch
        return error.CrlBadFormat;
    at.* = elem.slice.end;
    const any_cert: Certificate = .{ .buffer = copy, .index = 0 };
    return Certificate.parseTime(any_cert, elem) catch |err| switch (err) {
        error.CertificateFieldHasWrongDataType => error.CrlBadFormat,
        error.CertificateTimeInvalid => error.CrlBadFormat,
    };
}

/// Reads the serial of every entry of `revokedCertificates`.
///
/// The revocation date and the entry extensions of an entry are read past
/// and nothing else: a serial on the list is revoked, whatever reason the
/// entry names.
fn entries(
    gpa: std.mem.Allocator,
    copy: []u8,
    revoked_elem: der.Element,
) ParseError![]const []const u8 {
    var serials: std.ArrayList([]const u8) = .empty;
    errdefer serials.deinit(gpa);

    var at = revoked_elem.slice.start;
    while (at < revoked_elem.slice.end) {
        const entry = certificate.parseElement(copy, @intCast(at)) catch return error.CrlBadFormat;
        at = entry.slice.end;
        if (entry.identifier.tag != .sequence) return error.CrlBadFormat;

        const serial_elem = certificate.parseElement(copy, entry.slice.start) catch
            return error.CrlBadFormat;
        if (serial_elem.identifier.tag != .integer) return error.CrlBadFormat;
        const serial = copy[serial_elem.slice.start..serial_elem.slice.end];
        serials.append(gpa, serial) catch return error.OutOfMemory;
    }
    return serials.toOwnedSlice(gpa) catch return error.OutOfMemory;
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

const Client = @import("Client.zig");
const TestEcdsa = Client.TestEcdsa;
const testing = std.testing;

const test_oid_ecdsa_with_sha256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };

/// The test clock. 2023-11-14, which the fixture window covers with a
/// year on each side.
const test_now_sec: i64 = 1_700_000_000;

/// A DER writer with the shape of the minter's `DerBuf`, for the CRL the
/// tests build. The writer of a certificate is private to `Client.zig`,
/// and a CRL is not a certificate, so this one carries the small subset a
/// `CertificateList` needs: raw bytes, one wrap, one name, one time.
const Der = struct {
    data: [1024]u8 = undefined,
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

    /// Moves the bytes at `from` behind a header of `tag`, the way
    /// `DerBuf.wrapDer` does.
    fn wrap(self: *Der, from: usize, tag: u8) void {
        const body = self.len - from;
        const header = 1 + lenLen(body);
        mem.copyBackwards(u8, self.data[from + header ..][0..body], self.data[from..][0..body]);
        self.data[from] = tag;
        writeLen(self.data[from + 1 ..], body);
        self.len += header;
    }

    /// One `AlgorithmIdentifier` that names `oid` with no parameters.
    fn algorithm(self: *Der, oid: []const u8) void {
        const at = self.mark();
        self.push(&.{ 0x06, @intCast(oid.len) });
        self.push(oid);
        self.wrap(at, 0x30);
    }

    /// One `Name` that holds one common name and nothing else, which is
    /// the name the minter writes too.
    fn name(self: *Der, common_name: []const u8) void {
        const at = self.mark();
        const set_at = self.mark();
        const atav = self.mark();
        self.push(&test_oid_common_name);
        self.push(&.{ 0x13, @intCast(common_name.len) });
        self.push(common_name);
        self.wrap(atav, 0x30);
        self.wrap(set_at, 0x31);
        self.wrap(at, 0x30);
    }

    /// One UTCTime of 13 octets.
    fn time(self: *Der, utc: []const u8) void {
        self.push(&.{ 0x17, @intCast(utc.len) });
        self.push(utc);
    }

    /// One INTEGER that names a serial the minter could have written.
    fn integer(self: *Der, value: u8) void {
        self.push(&.{ 0x02, 0x01, value });
    }
};

const test_oid_common_name = [_]u8{ 0x06, 0x03, 0x55, 0x04, 0x03 };

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

/// One certificate authority, one leaf under it, and a signed
/// `CertificateList` that revokes `revoked`.
const Fixture = struct {
    root_key: TestEcdsa.KeyPair,
    root_buf: Client.DerBuf,
    leaf_buf: Client.DerBuf,
    root: Certificate.Parsed,
    leaf: Certificate.Parsed,
    // The DER of the leaf's serial, copied, so a check never reads a
    // fixture buffer through a pointer into another one.
    leaf_serial_storage: [8]u8,
    leaf_serial: []const u8,
    list_der: Der,
    list: List,

    const issuer_cn = "crl test root";

    fn init(revoked: []const u8) !Fixture {
        const root_key = try Client.testKey(0x81);
        const leaf_key = try Client.testKey(0x82);

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

        const root_cert: Certificate = .{ .buffer = root_buf.slice(), .index = 0 };
        const leaf_cert: Certificate = .{ .buffer = leaf_buf.slice(), .index = 0 };
        const root = try Certificate.parse(root_cert);
        const leaf = try Certificate.parse(leaf_cert);

        var list_der: Der = .{};
        try writeList(&list_der, root_key, revoked);
        var list = try parseDer(testing.allocator, list_der.slice());
        errdefer list.deinit();

        var fixture = Fixture{
            .root_key = root_key,
            .root_buf = root_buf,
            .leaf_buf = leaf_buf,
            .root = root,
            .leaf = leaf,
            .leaf_serial_storage = undefined,
            .leaf_serial = &.{},
            .list_der = list_der,
            .list = list,
        };
        const serial_slice = try certificate.serial(leaf_cert);
        const serial_der = leaf_cert.buffer[serial_slice.start..serial_slice.end];
        @memcpy(fixture.leaf_serial_storage[0..serial_der.len], serial_der);
        fixture.leaf_serial = fixture.leaf_serial_storage[0..serial_der.len];
        return fixture;
    }

    fn deinit(fixture: *Fixture) void {
        fixture.list.deinit();
    }

    fn checkLeaf(fixture: *Fixture) CheckError!void {
        return fixture.list.check(fixture.leaf_serial, fixture.root, test_now_sec);
    }
};

/// Writes a signed `CertificateList`. The window covers the test clock,
/// and the signature is the real signature of the root key over the
/// `tbsCertList`.
fn writeList(out: *Der, root_key: TestEcdsa.KeyPair, revoked: []const u8) !void {
    const tbs_at = out.mark();
    out.push(&.{ 0x02, 0x01, 0x01 }); // version v2
    out.algorithm(&test_oid_ecdsa_with_sha256);
    out.name(Fixture.issuer_cn);
    out.time("221114000000Z"); // thisUpdate
    out.time("241114000000Z"); // nextUpdate
    const revoked_at = out.mark();
    for (revoked) |serial| {
        const entry_at = out.mark();
        out.integer(serial);
        out.time("230101000000Z"); // revocationDate
        out.wrap(entry_at, 0x30);
    }
    out.wrap(revoked_at, 0x30);
    out.wrap(tbs_at, 0x30);

    const tbs_bytes = try testing.allocator.dupe(u8, out.slice()[tbs_at..]);
    defer testing.allocator.free(tbs_bytes);
    const sig = try root_key.sign(tbs_bytes, null);
    var sig_buf: [TestEcdsa.Signature.der_encoded_length_max]u8 = undefined;

    out.algorithm(&test_oid_ecdsa_with_sha256);
    const bits_at = out.mark();
    out.push(&.{0x00}); // unused bits of zero
    out.push(sig.toDer(&sig_buf));
    out.wrap(bits_at, 0x03);
    out.wrap(0, 0x30);
}

test "a list with one revoked serial carries it and no other" {
    var fixture = try Fixture.init(&.{7});
    defer fixture.deinit();

    try testing.expect(fixture.list.revoked(&.{0x07}));
    try testing.expect(!fixture.list.revoked(&.{0x08}));
}

test "check refuses a leaf the list revokes" {
    var fixture = try Fixture.init(&.{1});
    defer fixture.deinit();
    // The leaf carries serial 1.
    try testing.expectError(error.TlsCertificateRevoked, fixture.checkLeaf());
}

test "check passes a leaf the list does not revoke" {
    var fixture = try Fixture.init(&.{9});
    defer fixture.deinit();
    try fixture.checkLeaf();
}

test "a list signed by another authority is refused" {
    var fixture = try Fixture.init(&.{});
    defer fixture.deinit();

    const other_key = try Client.testKey(0x83);
    var other_root: Client.DerBuf = .{};
    try Client.mint(&other_root, .{
        .serial = 4,
        .issuer_cn = "other root",
        .subject_cn = "other root",
        .san_dns = "other.test",
        .basic_constraints = .{ .ca = true },
        .key_usage = .key_cert_sign,
    }, other_key.public_key, other_key);
    const other_cert: Certificate = .{ .buffer = other_root.slice(), .index = 0 };
    const other_parsed = try Certificate.parse(other_cert);

    try testing.expectError(
        error.TlsCrlUntrusted,
        fixture.list.check(fixture.leaf_serial, other_parsed, test_now_sec),
    );
}

test "a list whose window has passed is refused" {
    var fixture = try Fixture.init(&.{});
    defer fixture.deinit();
    var stale = fixture.list;
    stale.next_update = test_now_sec - 1;
    try testing.expectError(error.TlsCrlOutOfDate, stale.check(fixture.leaf_serial, fixture.root, test_now_sec));
}

test "a list whose window has not begun is refused" {
    var fixture = try Fixture.init(&.{});
    defer fixture.deinit();
    var early = fixture.list;
    early.this_update = test_now_sec + 1;
    try testing.expectError(error.TlsCrlOutOfDate, early.check(fixture.leaf_serial, fixture.root, test_now_sec));
}

test "a list with no nextUpdate is refused" {
    var fixture = try Fixture.init(&.{});
    defer fixture.deinit();
    var open_ended = fixture.list;
    open_ended.next_update = null;
    try testing.expectError(error.TlsCrlOutOfDate, open_ended.check(fixture.leaf_serial, fixture.root, test_now_sec));
}

test "a list that does not name its issuer's subject is refused" {
    var fixture = try Fixture.init(&.{});
    defer fixture.deinit();
    var renamed = fixture.list;
    renamed.issuer = renamed.issuer[1..];
    try testing.expectError(error.TlsCrlUntrusted, renamed.check(fixture.leaf_serial, fixture.root, test_now_sec));
}

test "a signature over other bytes than the list carries is refused" {
    var fixture = try Fixture.init(&.{});
    defer fixture.deinit();
    var forged = fixture.list;
    forged.tbs = forged.tbs[0 .. forged.tbs.len - 1];
    try testing.expectError(error.CertificateSignatureInvalid, forged.check(fixture.leaf_serial, fixture.root, test_now_sec));
}

test "a pem envelope decodes to the list the der form carries" {
    var fixture = try Fixture.init(&.{1});
    defer fixture.deinit();

    const encoder = std.base64.standard.Encoder;
    var encoded_buf: [2048]u8 = undefined;
    const encoded = encoder.encode(&encoded_buf, fixture.list.der);
    var pem_buf: [2048 + 64]u8 = undefined;
    const pem = try std.fmt.bufPrint(
        &pem_buf,
        "-----BEGIN X509 CRL-----\n{s}\n-----END X509 CRL-----\n",
        .{encoded},
    );

    var from_pem = try parsePem(testing.allocator, pem);
    defer from_pem.deinit();
    try testing.expect(from_pem.revoked(&.{0x01}));
    try testing.expectEqual(fixture.list.next_update, from_pem.next_update);
    try testing.expectEqualStrings(fixture.list.issuer, from_pem.issuer);
}

test "bare der bytes parse without a pem marker" {
    var fixture = try Fixture.init(&.{});
    defer fixture.deinit();
    var from_der = try parsePem(testing.allocator, fixture.list_der.slice());
    defer from_der.deinit();
    try testing.expectEqualStrings(fixture.list.issuer, from_der.issuer);
}

test "bytes that hold no list are refused" {
    const junk = "not a crl at all";
    try testing.expectError(error.CrlBadFormat, parsePem(testing.allocator, junk));
}

test "an empty pem block is refused" {
    const empty = "-----BEGIN X509 CRL-----\n-----END X509 CRL-----\n";
    try testing.expectError(error.CrlBadFormat, parsePem(testing.allocator, empty));
}

test "a list of no entries revokes nothing and still checks" {
    var fixture = try Fixture.init(&.{});
    defer fixture.deinit();
    try testing.expectEqual(@as(usize, 0), fixture.list.serials.len);
    try fixture.checkLeaf();
}
