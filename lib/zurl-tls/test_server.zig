//! A loopback TLS 1.3 server for tests.
//!
//! This is a test fixture, not a product. `zurl-http/test_server.zig` is
//! the same fixture with no TLS under it, and this one keeps its shape: a
//! script of raw responses, one accepted connection at a time, a capture
//! of every request head, and a `stop` that cancels the task.
//!
//! **It runs a real TLS 1.3 handshake.** It reads the client's hello, it
//! answers with a real x25519 key share, it signs a real CertificateVerify
//! with the private key of the leaf certificate it presents, it sends a
//! real Finished, and it checks the client's Finished before it answers a
//! single request. Nothing is stubbed out on either side, and the client
//! under test is the shipped one.
//!
//! **It presents a chain the test chooses.** `Chain` names nine of them:
//! two that a trusting client accepts, and seven that a correct client must
//! refuse. `Chain.forged_by_leaf` is the attack that `verifyIssued` closes,
//! which is a leaf certificate that is no certificate authority signing a
//! certificate for a name its owner does not hold. Before this fixture that
//! rule had unit tests and no transfer behind it.
//!
//! **It can also send a record that no correct client accepts.**
//! `Options.fault` names three of them, each one a length or an index that
//! made the client wrap a subtraction. See `Fault`.
//!
//! `rootPem` gives the certificate authority root of a chain, so a test can
//! write it to a file and name that file in `--cacert`. A test that does
//! not name it gets a client with no trust root for this server, which is
//! the ordinary "certificate from nobody" case.
//!
//! The leaf certificates carry `host_name` as a `dNSName` and the loopback
//! address of the listening socket as an `iPAddress`, so a url may name
//! either one and the host check passes for both. `Chain.wrong_host` is the
//! exception, and it names neither.
//!
//! Every certificate comes from `Client.mint`, the minter the chain tests
//! in `Client.zig` already use. A second minter here would be a second
//! reading of RFC 5280.
//!
//! **What this fixture leaves out, because no test needs it.** One cipher
//! suite, `TLS_AES_128_GCM_SHA256`, which the client offers in every build.
//! One key exchange group, x25519, which the client always offers a share
//! for. One signature scheme, `ecdsa_secp256r1_sha256`. No TLS 1.2 at all.
//! No session resumption and no session ticket. No client certificate and
//! no CertificateRequest. No HelloRetryRequest, no key update, and no
//! record fragmentation of its own: each flight goes out whole. No
//! renegotiation, which TLS 1.3 removed anyway.

const std = @import("std");
const crypto = std.crypto;
const tls = std.crypto.tls;
const testing = std.testing;
const Client = @import("Client.zig");

pub const TlsTestServer = @This();

/// The host name every leaf certificate carries, except the one of
/// `Chain.wrong_host`.
pub const host_name = "zurl.test";

/// The host name `Chain.wrong_host` carries instead.
pub const other_host_name = "other.test";

/// The common name of the certificate authority root this fixture mints.
pub const root_name = "zurl test root";

/// The common name of the leaf that signs the forged certificate of
/// `Chain.forged_by_leaf`.
pub const attacker_name = "attacker.test";

/// The common name of the sub-authority of `Chain.constrained_sub_ca` and
/// of `Chain.permitted_sub_ca`.
pub const sub_ca_name = "zurl test sub";

/// One scripted reply: the exact bytes written back to the client inside
/// the TLS session, status line through body.
pub const Response = []const u8;

/// How many request heads a server keeps.
pub const capture_max = 4;

/// How large one captured request, head and body together, may be.
pub const capture_bytes = 8192;

/// Which chain the server presents in its Certificate message.
pub const Chain = enum {
    /// One leaf for `host_name`, signed with its own key, sent alone.
    ///
    /// No trust store holds it, so a verifying client refuses it. This is
    /// the shape of the certificate a developer makes with one command.
    self_signed,
    /// A leaf for `host_name` under a certificate authority root, both
    /// sent, the leaf first.
    ///
    /// `rootPem` names the root. A test that gives that root to the client
    /// gets a transfer that completes; a test that does not gets a client
    /// that finds no trusted root and refuses.
    ca_issued,
    /// `ca_issued`, with a leaf whose `notAfter` has already passed.
    expired,
    /// `ca_issued`, with a leaf that names `other_host_name` and carries
    /// no address at all.
    wrong_host,
    /// The attack that `verifyIssued` closes.
    ///
    /// The chain is three certificates: a forged leaf for `host_name`, the
    /// real leaf of `attacker_name` that signed it, and the root that
    /// issued that real leaf. The middle certificate says `cA` FALSE, so
    /// RFC 5280 section 4.2.1.9 forbids the use of its key to check a
    /// certificate signature.
    ///
    /// **Every signature in it holds and the root is the one `rootPem`
    /// gives.** So a client that trusts that root and does not read
    /// `basicConstraints` completes this handshake and believes it reached
    /// `host_name`. Only the chain rule refuses it.
    forged_by_leaf,
    /// A leaf of six octets that no parser can read, sent alone.
    ///
    /// `30 06` opens a six octet SEQUENCE, and `30 82 FF FF` inside it
    /// opens a SEQUENCE of 65535 octets. `std.crypto.Certificate.parse`
    /// walked it with no bound check and read past the end of the buffer.
    /// The client reads this certificate before it checks the host name
    /// and before it asks the trust store, so every server could send it.
    /// See `certificate.zig`.
    malformed,
    /// A leaf for `host_name` under a sub-authority that may issue for
    /// `attacker_name` alone, under the root.
    ///
    /// The chain is three certificates, every signature in it holds, and
    /// the root is the one `rootPem` gives. The middle certificate carries
    /// `nameConstraints` with a `permittedSubtrees` of one `dNSName`, the
    /// name space of the attacker. RFC 5280 section 4.2.1.10 binds every
    /// certificate below it to that name space, and the CA/Browser Forum
    /// Baseline Requirements let such a sub-authority go without an audit
    /// **because clients hold it to the constraint**. A client that reads
    /// the extension and does nothing makes the holder of the key a
    /// certificate authority for the whole internet.
    constrained_sub_ca,
    /// `constrained_sub_ca`, with the constraint naming `host_name`.
    ///
    /// The positive control of the rule above: a constraint that permits
    /// the host must complete the transfer.
    permitted_sub_ca,
    /// `ca_issued`, with a leaf that carries an extension of a private
    /// object identifier marked critical.
    ///
    /// RFC 5280 section 4.2 says a client that cannot read a critical
    /// extension must refuse the certificate. This is the rule that keeps
    /// the client closed when an extension nobody has written yet
    /// arrives.
    unknown_critical_extension,
    /// `ca_issued`, with a leaf whose `extendedKeyUsage` names electronic
    /// mail protection alone.
    ///
    /// RFC 5280 section 4.2.1.12: such a certificate does not stand for a
    /// TLS server, and the authority above it may have checked an
    /// electronic mail address and never a host name.
    wrong_ext_key_usage,
};

/// A record the fixture sends that no correct client accepts.
///
/// Each one is a length or an index from the peer that reached arithmetic
/// with no lower bound. In a Debug build the client panicked. In the
/// ReleaseFast build a user runs there is no panic, so the read went on
/// with a length the server chose.
pub const Fault = enum {
    /// The fixture sends the records it was written to send.
    none,
    /// The five octets `17 03 03 00 00` after the handshake.
    ///
    /// The record claims no content at all, so the client subtracted the
    /// sixteen octet tag from zero and read 65520 octets that were never
    /// there. No key material and no valid tag are needed, because the
    /// subtraction happens before the cipher runs.
    short_record,
    /// An application record whose inner plaintext is four zero octets,
    /// with the tag that belongs to it.
    ///
    /// RFC 8446 section 5.4 makes such a record legal to send and illegal
    /// to accept: the padding is stripped and no inner content type is
    /// left. The client read the octet before the buffer as the content
    /// type and took the length of the message as the largest `usize`.
    zero_inner_plaintext,
    /// An encrypted handshake record of the tag alone, right after the
    /// ServerHello.
    ///
    /// It decrypts to no octets, so the fragment the client assembled
    /// grew by nothing and the step back to the inner content type
    /// wrapped to the largest `usize`.
    empty_handshake_fragment,
    /// An application record whose inner plaintext is `18 00 16`: an
    /// inner content type of `handshake` over two octets of message.
    ///
    /// A handshake sub-message carries a four octet header, and the read
    /// path read all four of them before it checked that four were
    /// there. Two octets are left here, so the three octet length was
    /// read out of the record and into the one before it, which the same
    /// peer wrote.
    short_handshake_header,
    /// An application record whose inner plaintext is `18 00 00 00 16`:
    /// a `key_update` sub-message whose body is empty.
    ///
    /// A `key_update` body is the one octet `request_update`. A length of
    /// zero passed the bound on the sub-message, and the read of that
    /// octet then took the first octet after the record. Its value picks
    /// whether the write keys are rotated, so a peer that steers it
    /// steers a key rotation.
    empty_key_update,
};

/// What `startWith` takes beyond the script.
pub const Options = struct {
    /// Which loopback address to listen on.
    host: []const u8 = "127.0.0.1",
    /// Which chain the server presents.
    chain: Chain = .ca_issued,
    /// Which record a correct client must refuse, if any.
    fault: Fault = .none,
    /// How many scripted responses one accepted connection serves before
    /// the server closes it. See `zurl-http/test_server.zig`, which holds
    /// the same option for the same reason.
    responses_per_connection: ?usize = 1,
    /// The protocol names this server may choose from the client's ALPN
    /// offer, in the order it prefers.
    ///
    /// The server answers with the first name of this list that the client
    /// also offered, and answers nothing when the two lists share no name
    /// or when the client offered none. RFC 7301 allows all three.
    alpn_protocols: []const []const u8 = &.{"http/1.1"},

    /// Whether the server closes the socket with no `close_notify` alert.
    ///
    /// **A TLS peer that closes must say so, and this is the fixture for a
    /// peer that does not.** RFC 8446 section 6.1 makes `close_notify` the
    /// end of a stream, and for an HTTP response whose body is delimited
    /// by the close it is the only thing that tells a whole body from a
    /// cut one. See `h1.tlsSetup`, which keeps `allow_truncation_attacks`
    /// off for exactly that framing.
    skip_close_notify: bool = false,
};

server: std.Io.net.Server,
task: std.Io.Future(void),
options: Options,
/// The certificates of the Certificate message, the leaf first.
certificates: [chain_max]Client.DerBuf,
certificate_count: usize,
/// The certificate authority root of the chain, or no bytes at all when
/// the chain has none. `rootPem` reads it.
root: Client.DerBuf,
has_root: bool,
/// The key pair of the leaf certificate. It signs CertificateVerify.
leaf_key: Client.TestEcdsa.KeyPair,
/// The request that asked for each scripted response, in order: the head,
/// then the body right behind it.
capture_storage: [capture_max][capture_bytes]u8,
/// How much of each slot the head fills, the blank line included.
capture_head_lens: [capture_max]usize,
/// How much of each slot the head and the body fill together.
capture_lens: [capture_max]usize,
/// How many request heads `capture_storage` holds.
capture_count: std.atomic.Value(usize),
/// How many connections the server has accepted.
accept_count: std.atomic.Value(usize),
/// How many handshakes reached the client's Finished and passed it.
///
/// A test of a chain a client must refuse reads this and expects zero: a
/// refusal that happened after the session came up would mean the client
/// checked the certificate too late.
handshake_count: std.atomic.Value(usize),

/// How many certificates one chain of this fixture holds.
const chain_max = 3;

// ---------------------------------------------------------------------
// The one cipher suite this fixture speaks.
// ---------------------------------------------------------------------

const Hash = crypto.hash.sha2.Sha256;
const Hkdf = crypto.kdf.hkdf.HkdfSha256;
const Hmac = crypto.auth.hmac.sha2.HmacSha256;
const Aead = crypto.aead.aes_gcm.Aes128Gcm;

/// The length of the transcript hash and of every traffic secret.
const digest_len = Hash.digest_length;

/// The largest plaintext this fixture puts in one record it writes. A
/// reply longer than this goes out in several records, which is legal
/// traffic and what a real server does as well.
const write_plaintext_max = 8192;

/// How many octets of one request this fixture reassembles before it gives
/// up on finding the end of the head.
const plaintext_max = 1 << 14;

/// The `notAfter` of the leaf of `Chain.expired`: the first day of 2021,
/// which every clock this suite runs under has passed.
const expired_not_after = "210101000000Z";

// ---------------------------------------------------------------------
// Starting and stopping.
// ---------------------------------------------------------------------

/// Starts listening on loopback and starts a task that serves `script` in
/// order over TLS, one entry per accepted connection.
///
/// Initializes `self` in place, for the reason
/// `zurl-http/test_server.zig`'s `start` does: the server task holds
/// `&self.server` for its whole life.
///
/// Returns `error.SkipZigTest` in a build with no concurrency at all. The
/// server and its client cannot both make progress on one task.
///
/// `self` and `script` must outlive the server.
pub fn start(self: *TlsTestServer, script: []const Response) !void {
    return self.startWith(script, .{});
}

/// The same as `start`, with the chain spelled out.
pub fn startWith(self: *TlsTestServer, script: []const Response, options: Options) !void {
    std.debug.assert(script.len <= capture_max);

    var address = try std.Io.net.IpAddress.parse(options.host, 0);
    self.server = try address.listen(testing.io, .{ .reuse_address = true });
    errdefer self.server.deinit(testing.io);

    self.options = options;
    self.capture_head_lens = @splat(0);
    self.capture_lens = @splat(0);
    self.capture_count = .init(0);
    self.accept_count = .init(0);
    self.handshake_count = .init(0);

    try self.mintChain();

    self.task = testing.io.concurrent(run, .{ self, script }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
}

/// Stops the server task and releases the listening socket. Every test
/// that calls `start` must call this, normally through `defer`.
pub fn stop(self: *TlsTestServer) void {
    self.task.cancel(testing.io);
    self.server.deinit(testing.io);
}

/// The OS-assigned port the server is listening on.
pub fn port(self: *const TlsTestServer) u16 {
    return self.server.socket.address.getPort();
}

/// How many connections the client opened on this server.
pub fn accepts(self: *const TlsTestServer) usize {
    return self.accept_count.load(.acquire);
}

/// How many TLS sessions came all the way up on this server.
pub fn handshakes(self: *const TlsTestServer) usize {
    return self.handshake_count.load(.acquire);
}

/// The request head the client sent on request `index`, status line
/// through the blank line, or null when the server has not answered that
/// many requests yet.
pub fn requestHead(self: *const TlsTestServer, index: usize) ?[]const u8 {
    if (index >= self.capture_count.load(.acquire)) return null;
    return self.capture_storage[index][0..self.capture_head_lens[index]];
}

/// The request body the client sent on request `index`, or null when the
/// server has not answered that many requests yet.
pub fn requestBody(self: *const TlsTestServer, index: usize) ?[]const u8 {
    if (index >= self.capture_count.load(.acquire)) return null;
    const slot = &self.capture_storage[index];
    return slot[self.capture_head_lens[index]..self.capture_lens[index]];
}

/// The largest PEM block `rootPem` writes.
pub const root_pem_max = 4096;

/// Writes the certificate authority root of this server's chain into `out`
/// as PEM, and returns the part of `out` it filled.
///
/// A test writes this to a file and names the file in `--cacert`, or in
/// `Transfer.Options.ca.cacert`. That is the only way a client can trust
/// this fixture, because no real trust store holds a certificate this
/// process minted a moment ago.
///
/// Reports `error.NoRootCertificate` for `Chain.self_signed` and
/// `Chain.malformed`, neither of which has a root to give.
pub fn rootPem(self: *const TlsTestServer, out: []u8) ![]const u8 {
    if (!self.has_root) return error.NoRootCertificate;
    return pemBlock(self.root.slice(), out);
}

// ---------------------------------------------------------------------
// The certificates.
// ---------------------------------------------------------------------

/// Mints the chain named by `self.options.chain`.
///
/// Runs before the server task starts, so the task borrows bytes that are
/// already written and never writes them itself.
fn mintChain(self: *TlsTestServer) !void {
    const leaf_key = try Client.testKey(0x41);
    const root_key = try Client.testKey(0x42);
    const attacker_key = try Client.testKey(0x43);
    const sub_ca_key = try Client.testKey(0x44);

    self.leaf_key = leaf_key;
    self.certificate_count = 0;
    self.has_root = false;
    self.root = .{};
    for (&self.certificates) |*certificate| certificate.* = .{};

    // The address of the listening socket, which every leaf but the one of
    // `Chain.wrong_host` carries as an `iPAddress` name. A url that names
    // `127.0.0.1` then passes the host check, and so does one that names
    // `host_name`.
    var address_buf: [16]u8 = undefined;
    const address: []const u8 = switch (self.server.socket.address) {
        .ip4 => |ip4| blk: {
            @memcpy(address_buf[0..4], &ip4.bytes);
            break :blk address_buf[0..4];
        },
        .ip6 => |ip6| blk: {
            @memcpy(address_buf[0..16], &ip6.bytes);
            break :blk address_buf[0..16];
        },
    };

    switch (self.options.chain) {
        .self_signed => {
            try Client.mint(&self.certificates[0], .{
                .serial = 1,
                .issuer_cn = host_name,
                .subject_cn = host_name,
                .san_dns = host_name,
                .san_ip = address,
                .key_usage = .digital_signature,
            }, leaf_key.public_key, leaf_key);
            self.certificate_count = 1;
        },
        .ca_issued,
        .expired,
        .wrong_host,
        .unknown_critical_extension,
        .wrong_ext_key_usage,
        => {
            try mintRoot(&self.root, root_key);
            const wrong = self.options.chain == .wrong_host;
            try Client.mint(&self.certificates[0], .{
                .serial = 2,
                .issuer_cn = root_name,
                .subject_cn = if (wrong) other_host_name else host_name,
                .san_dns = if (wrong) other_host_name else host_name,
                .san_ip = if (wrong) null else address,
                .key_usage = .digital_signature,
                .ext_key_usage = switch (self.options.chain) {
                    .wrong_ext_key_usage => .email_protection,
                    else => null,
                },
                .unknown_critical = self.options.chain == .unknown_critical_extension,
                .not_after = if (self.options.chain == .expired)
                    expired_not_after
                else
                    Client.mint_not_after,
            }, leaf_key.public_key, root_key);
            self.certificates[1] = self.root;
            self.certificate_count = 2;
            self.has_root = true;
        },
        .constrained_sub_ca, .permitted_sub_ca => {
            try mintRoot(&self.root, root_key);
            // The sub-authority. It is a real certificate authority, and
            // the name space it may issue for is the one the root wrote
            // into it.
            try Client.mint(&self.certificates[1], .{
                .serial = 5,
                .issuer_cn = root_name,
                .subject_cn = sub_ca_name,
                .basic_constraints = .{ .ca = true },
                .key_usage = .key_cert_sign,
                .name_constraints = .{
                    .permitted_dns = switch (self.options.chain) {
                        .permitted_sub_ca => host_name,
                        else => attacker_name,
                    },
                },
            }, sub_ca_key.public_key, root_key);
            // The leaf it issued, for a host outside that name space
            // unless the chain is the positive control.
            try Client.mint(&self.certificates[0], .{
                .serial = 6,
                .issuer_cn = sub_ca_name,
                .subject_cn = host_name,
                .san_dns = host_name,
                .san_ip = address,
                .key_usage = .digital_signature,
            }, leaf_key.public_key, sub_ca_key);
            self.certificates[2] = self.root;
            self.certificate_count = 3;
            self.has_root = true;
        },
        .forged_by_leaf => {
            try mintRoot(&self.root, root_key);
            // The certificate the attacker really holds. A domain
            // validated certificate for a name they own, and no
            // certificate authority: `cA` is FALSE and `keyUsage` asserts
            // `digitalSignature` alone.
            try Client.mint(&self.certificates[1], .{
                .serial = 3,
                .issuer_cn = root_name,
                .subject_cn = attacker_name,
                .san_dns = attacker_name,
                .basic_constraints = .{ .ca = false },
                .key_usage = .digital_signature,
            }, attacker_key.public_key, root_key);
            // The certificate they forged with it, for a name they do not
            // own. The key inside is the key this server signs
            // CertificateVerify with.
            try Client.mint(&self.certificates[0], .{
                .serial = 4,
                .issuer_cn = attacker_name,
                .subject_cn = host_name,
                .san_dns = host_name,
                .san_ip = address,
                .key_usage = .digital_signature,
            }, leaf_key.public_key, attacker_key);
            self.certificates[2] = self.root;
            self.certificate_count = 3;
            self.has_root = true;
        },
        .malformed => {
            // Written by hand, because the minter writes certificates a
            // parser can read and this chain is about one it cannot.
            const evil = [_]u8{ 0x30, 0x06, 0x30, 0x82, 0xFF, 0xFF };
            @memcpy(self.certificates[0].data[0..evil.len], &evil);
            self.certificates[0].len = evil.len;
            self.certificate_count = 1;
        },
    }
}

/// Mints the certificate authority root of every chain that has one.
///
/// It carries no `pathLenConstraint`, so the chain rule refuses
/// `Chain.forged_by_leaf` for the reason the test is about, which is the
/// middle certificate's `cA` FALSE, and never for a path length.
fn mintRoot(out: *Client.DerBuf, key: Client.TestEcdsa.KeyPair) !void {
    try Client.mint(out, .{
        .serial = 0x7f,
        .issuer_cn = root_name,
        .subject_cn = root_name,
        .basic_constraints = .{ .ca = true },
        .key_usage = .key_cert_sign,
    }, key.public_key, key);
}

/// Writes `der` into `out` as one PEM CERTIFICATE block.
fn pemBlock(der: []const u8, out: []u8) ![]const u8 {
    const begin = "-----BEGIN CERTIFICATE-----\n";
    const end = "-----END CERTIFICATE-----\n";
    const encoder = std.base64.standard.Encoder;

    var body_buf: [root_pem_max]u8 = undefined;
    const body = encoder.encode(body_buf[0..encoder.calcSize(der.len)], der);

    var at: usize = 0;
    at += try copyInto(out, at, begin);
    // PEM wraps the base64 at 64 columns. RFC 7468 section 2 asks for it,
    // and a reader that splits on lines needs it.
    var from: usize = 0;
    while (from < body.len) {
        const take = @min(64, body.len - from);
        at += try copyInto(out, at, body[from..][0..take]);
        at += try copyInto(out, at, "\n");
        from += take;
    }
    at += try copyInto(out, at, end);
    return out[0..at];
}

/// Copies `text` into `out` at `at`, and reports a buffer too small rather
/// than writing past it.
fn copyInto(out: []u8, at: usize, text: []const u8) !usize {
    if (at + text.len > out.len) return error.NoSpaceLeft;
    @memcpy(out[at..][0..text.len], text);
    return text.len;
}

// ---------------------------------------------------------------------
// A buffer that writes a length in front of a body whose size is known
// only after the body is written.
// ---------------------------------------------------------------------

fn Buf(comptime capacity: usize) type {
    return struct {
        data: [capacity]u8 = undefined,
        len: usize = 0,

        const Self = @This();

        fn push(self: *Self, bytes: []const u8) void {
            std.debug.assert(self.len + bytes.len <= capacity);
            @memcpy(self.data[self.len..][0..bytes.len], bytes);
            self.len += bytes.len;
        }

        fn byte(self: *Self, value: u8) void {
            self.push(&.{value});
        }

        fn int(self: *Self, comptime Int: type, value: Int) void {
            var out: [@divExact(@bitSizeOf(Int), 8)]u8 = undefined;
            std.mem.writeInt(Int, &out, value, .big);
            self.push(&out);
        }

        fn mark(self: *const Self) usize {
            return self.len;
        }

        fn slice(self: *const Self) []const u8 {
            return self.data[0..self.len];
        }

        /// Wraps everything written since `from` in a big endian length of
        /// `width` octets, which is what TLS puts in front of a vector.
        fn wrapLen(self: *Self, from: usize, width: usize) void {
            const body = self.len - from;
            std.debug.assert(self.len + width <= capacity);
            std.mem.copyBackwards(u8, self.data[from + width ..][0..body], self.data[from..][0..body]);
            var index: usize = 0;
            while (index < width) : (index += 1) {
                const shift: u5 = @intCast(8 * (width - 1 - index));
                self.data[from + index] = @truncate(body >> shift);
            }
            self.len += width;
        }
    };
}

// ---------------------------------------------------------------------
// The session.
// ---------------------------------------------------------------------

/// One direction of one encryption level.
const Keys = struct {
    key: [Aead.key_length]u8 = @splat(0),
    iv: [Aead.nonce_length]u8 = @splat(0),
    /// The record sequence number, which restarts at zero at each level.
    seq: u64 = 0,

    /// The nonce of the next record, which RFC 8446 section 5.3 builds by
    /// exclusive or of the sequence number with the write iv.
    fn nonce(self: *const Keys) [Aead.nonce_length]u8 {
        var out = self.iv;
        var counter: [8]u8 = undefined;
        std.mem.writeInt(u64, &counter, self.seq, .big);
        for (counter, 0..) |value, index| out[out.len - 8 + index] ^= value;
        return out;
    }
};

/// Everything one connection holds for as long as it lives.
const Conn = struct {
    server: *TlsTestServer,
    in: *std.Io.Reader,
    out: *std.Io.Writer,

    transcript: Hash = .init(.{}),
    handshake_secret: [digest_len]u8 = @splat(0),
    master_secret: [digest_len]u8 = @splat(0),
    client_finished_key: [Hmac.key_length]u8 = @splat(0),
    server_finished_key: [Hmac.key_length]u8 = @splat(0),

    read_keys: Keys = .{},
    write_keys: Keys = .{},

    /// The protocol name the server chose from the client's ALPN offer, or
    /// no bytes when it chose none.
    alpn: []const u8 = "",

    /// Where one decrypted record lands.
    scratch: [plaintext_max]u8 = undefined,
    /// The application data that has arrived and that no request has
    /// consumed yet.
    plain: [plaintext_max]u8 = undefined,
    plain_len: usize = 0,

    /// One record as it came off the socket.
    const Record = struct {
        /// The five octet header, which is also the additional data of an
        /// encrypted record.
        header: [tls.record_header_len]u8,
        /// The body, which points into the reader's own buffer and stays
        /// valid until the next read.
        body: []u8,

        fn contentType(self: *const Record) tls.ContentType {
            return @enumFromInt(self.header[0]);
        }
    };

    fn readRecord(c: *Conn) !Record {
        const peeked = try c.in.peek(tls.record_header_len);
        const header: [tls.record_header_len]u8 = peeked[0..tls.record_header_len].*;
        c.in.toss(tls.record_header_len);
        const len = std.mem.readInt(u16, header[3..5], .big);
        if (len > tls.max_ciphertext_len) return error.TlsRecordOverflow;
        return .{ .header = header, .body = try c.in.take(len) };
    }

    /// Reads one record and decrypts it with the current read keys.
    ///
    /// Returns the inner plaintext in `c.scratch` with its content type,
    /// which RFC 8446 section 5.2 puts at the end of the plaintext behind
    /// any padding.
    fn readSealed(c: *Conn) !struct { ct: tls.ContentType, body: []u8 } {
        const record = try c.readRecord();
        if (record.contentType() != .application_data) return error.TlsUnexpectedMessage;
        if (record.body.len < Aead.tag_length) return error.TlsRecordOverflow;
        const cut = record.body.len - Aead.tag_length;
        if (cut > c.scratch.len) return error.TlsRecordOverflow;

        const tag: [Aead.tag_length]u8 = record.body[cut..][0..Aead.tag_length].*;
        const plain = c.scratch[0..cut];
        Aead.decrypt(
            plain,
            record.body[0..cut],
            tag,
            &record.header,
            c.read_keys.nonce(),
            c.read_keys.key,
        ) catch return error.TlsBadRecordMac;
        c.read_keys.seq += 1;

        const end = std.mem.trimEnd(u8, plain, "\x00");
        if (end.len == 0) return error.TlsUnexpectedMessage;
        return .{
            .ct = @enumFromInt(end[end.len - 1]),
            .body = plain[0 .. end.len - 1],
        };
    }

    /// Writes one cleartext record.
    fn writePlain(c: *Conn, ct: tls.ContentType, payload: []const u8) !void {
        var header: [tls.record_header_len]u8 = .{ @intFromEnum(ct), 0x03, 0x03, 0, 0 };
        std.mem.writeInt(u16, header[3..5], @intCast(payload.len), .big);
        try c.out.writeAll(&header);
        try c.out.writeAll(payload);
        try c.out.flush();
    }

    /// Writes `payload` as one or more encrypted records under the current
    /// write keys.
    fn writeSealed(c: *Conn, ct: tls.ContentType, payload: []const u8) !void {
        var from: usize = 0;
        // A payload of no octets is still one record: a `close_notify`
        // carries two octets and an empty handshake flight never happens,
        // but a zero length reply must not send nothing at all.
        while (true) {
            const take = @min(write_plaintext_max, payload.len - from);
            var record: [write_plaintext_max + 1 + Aead.tag_length]u8 = undefined;
            const inner_len = take + 1;

            var header: [tls.record_header_len]u8 = .{
                @intFromEnum(tls.ContentType.application_data),
                0x03,
                0x03,
                0,
                0,
            };
            std.mem.writeInt(u16, header[3..5], @intCast(inner_len + Aead.tag_length), .big);

            var inner: [write_plaintext_max + 1]u8 = undefined;
            @memcpy(inner[0..take], payload[from..][0..take]);
            inner[take] = @intFromEnum(ct);

            Aead.encrypt(
                record[0..inner_len],
                record[inner_len..][0..Aead.tag_length],
                inner[0..inner_len],
                &header,
                c.write_keys.nonce(),
                c.write_keys.key,
            );
            c.write_keys.seq += 1;

            try c.out.writeAll(&header);
            try c.out.writeAll(record[0 .. inner_len + Aead.tag_length]);
            try c.out.flush();

            from += take;
            if (from >= payload.len) break;
        }
    }

    /// Writes one encrypted record whose inner plaintext is exactly
    /// `plain`.
    ///
    /// `writeSealed` puts the content type octet behind the payload, which
    /// RFC 8446 section 5.2 asks for. A fault needs a record that leaves
    /// it out, so this writes what the caller gives and nothing else. A
    /// plaintext of no octets gives a record of the tag alone.
    fn writeSealedExact(c: *Conn, plain: []const u8) !void {
        std.debug.assert(plain.len <= write_plaintext_max);
        var record: [write_plaintext_max + Aead.tag_length]u8 = undefined;

        var header: [tls.record_header_len]u8 = .{
            @intFromEnum(tls.ContentType.application_data),
            0x03,
            0x03,
            0,
            0,
        };
        std.mem.writeInt(u16, header[3..5], @intCast(plain.len + Aead.tag_length), .big);

        Aead.encrypt(
            record[0..plain.len],
            record[plain.len..][0..Aead.tag_length],
            plain,
            &header,
            c.write_keys.nonce(),
            c.write_keys.key,
        );
        c.write_keys.seq += 1;

        try c.out.writeAll(&header);
        try c.out.writeAll(record[0 .. plain.len + Aead.tag_length]);
        try c.out.flush();
    }

    /// Writes octets with no framing of any kind, which is how a fault
    /// puts a record header on the wire that no encoder here would write.
    fn writeRaw(c: *Conn, bytes: []const u8) !void {
        try c.out.writeAll(bytes);
        try c.out.flush();
    }
};

// ---------------------------------------------------------------------
// The handshake.
// ---------------------------------------------------------------------

/// Reads the ClientHello, answers the whole server flight, and checks the
/// client's Finished.
///
/// **A failure here is ordinary.** Four of the five chains this fixture
/// presents are chains a correct client refuses, and such a client stops
/// in the middle of this exchange. The caller counts only the handshakes
/// that finish.
fn handshake(c: *Conn) !void {
    const hello = try c.readRecord();
    if (hello.contentType() != .handshake) return error.TlsUnexpectedMessage;
    if (hello.body.len < 4) return error.TlsDecodeError;
    if (hello.body[0] != @intFromEnum(tls.HandshakeType.client_hello)) {
        return error.TlsUnexpectedMessage;
    }

    const session_id = sessionIdOf(hello.body) orelse return error.TlsDecodeError;
    const client_share = keyShareOf(hello.body) orelse return error.TlsIllegalParameter;
    if (client_share.len != crypto.dh.X25519.public_length) return error.TlsIllegalParameter;
    c.alpn = chooseAlpn(hello.body, c.server.options.alpn_protocols);

    // The transcript covers every octet of every handshake message, and
    // the ClientHello is the first of them.
    c.transcript = .init(.{});
    c.transcript.update(hello.body);

    // The key exchange. The secret key is derived from the session so that
    // a run leaves no shared state behind, and it never leaves this task.
    const x25519 = try crypto.dh.X25519.KeyPair.generateDeterministic([_]u8{0x5a} ** 32);

    var server_hello: Buf(512) = .{};
    writeServerHello(&server_hello, session_id, x25519.public_key);
    c.transcript.update(server_hello.slice());
    try c.writePlain(.handshake, server_hello.slice());

    // RFC 8446 appendix D.4. The client waits for this record before it
    // reads an encrypted one, and the vendored client is no exception.
    try c.writePlain(.change_cipher_spec, &[_]u8{
        @intFromEnum(tls.ChangeCipherSpecType.change_cipher_spec),
    });

    const shared = try crypto.dh.X25519.scalarmult(
        x25519.secret_key,
        client_share[0..crypto.dh.X25519.public_length].*,
    );
    deriveHandshakeKeys(c, &shared);

    // The fault that needs the handshake keys and nothing else. It goes
    // out in front of the server's flight, so the client meets it while
    // it is still assembling handshake messages. The session ends here:
    // a client that reads this record correctly refuses it.
    if (c.server.options.fault == .empty_handshake_fragment) {
        try c.writeSealedExact("");
        return error.FaultSent;
    }

    var flight: Buf(8192) = .{};
    try writeFlight(c, &flight);
    try c.writeSealed(.handshake, flight.slice());

    // The application secrets come from the transcript through the
    // server's Finished, and not through the client's. RFC 8446 section
    // 7.1.
    const handshake_hash = c.transcript.peek();
    try readClientFinished(c);
    deriveApplicationKeys(c, &handshake_hash);
}

/// Writes the ServerHello message, header and body.
fn writeServerHello(
    out: *Buf(512),
    session_id: []const u8,
    share: [crypto.dh.X25519.public_length]u8,
) void {
    out.byte(@intFromEnum(tls.HandshakeType.server_hello));
    const body = out.mark();
    out.int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2));
    // The server random. It must not be the HelloRetryRequest sentinel of
    // RFC 8446 section 4.1.3, and this is not it.
    out.push(&[_]u8{0x7e} ** 32);
    // The echo of the client's legacy session id. RFC 8446 section 4.1.3
    // asks for the exact octets back, and the client checks them.
    out.byte(@intCast(session_id.len));
    out.push(session_id);
    out.int(u16, @intFromEnum(tls.CipherSuite.AES_128_GCM_SHA256));
    out.byte(0); // legacy_compression_method

    const extensions = out.mark();
    out.int(u16, @intFromEnum(tls.ExtensionType.supported_versions));
    out.int(u16, 2);
    out.int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_3));
    out.int(u16, @intFromEnum(tls.ExtensionType.key_share));
    const entry = out.mark();
    out.int(u16, @intFromEnum(tls.NamedGroup.x25519));
    out.int(u16, share.len);
    out.push(&share);
    out.wrapLen(entry, 2);
    out.wrapLen(extensions, 2);
    out.wrapLen(body, 3);
}

/// Writes EncryptedExtensions, Certificate, CertificateVerify and
/// Finished, which is the whole of the server's flight.
fn writeFlight(c: *Conn, out: *Buf(8192)) !void {
    {
        out.byte(@intFromEnum(tls.HandshakeType.encrypted_extensions));
        const body = out.mark();
        const extensions = out.mark();
        if (c.alpn.len != 0) {
            out.int(u16, @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation));
            const ext = out.mark();
            const list = out.mark();
            out.byte(@intCast(c.alpn.len));
            out.push(c.alpn);
            out.wrapLen(list, 2);
            out.wrapLen(ext, 2);
        }
        out.wrapLen(extensions, 2);
        out.wrapLen(body, 3);
    }
    {
        out.byte(@intFromEnum(tls.HandshakeType.certificate));
        const body = out.mark();
        out.byte(0); // certificate_request_context
        const list = out.mark();
        for (c.server.certificates[0..c.server.certificate_count]) |*certificate| {
            const entry = out.mark();
            out.push(certificate.slice());
            out.wrapLen(entry, 3);
            out.int(u16, 0); // per certificate extensions
        }
        out.wrapLen(list, 3);
        out.wrapLen(body, 3);
    }
    c.transcript.update(out.slice());
    {
        // The signature covers the context string of RFC 8446 section
        // 4.4.3 and the transcript through the Certificate message.
        const hash = c.transcript.peek();
        var content: Buf(256) = .{};
        content.push(" " ** 64);
        content.push("TLS 1.3, server CertificateVerify");
        content.byte(0);
        content.push(&hash);

        const signature = try c.server.leaf_key.sign(content.slice(), null);
        var der_buf: [Client.TestEcdsa.Signature.der_encoded_length_max]u8 = undefined;
        const der = signature.toDer(&der_buf);

        const at = out.mark();
        out.byte(@intFromEnum(tls.HandshakeType.certificate_verify));
        const body = out.mark();
        out.int(u16, @intFromEnum(tls.SignatureScheme.ecdsa_secp256r1_sha256));
        const sig = out.mark();
        out.push(der);
        out.wrapLen(sig, 2);
        out.wrapLen(body, 3);
        c.transcript.update(out.data[at..out.len]);
    }
    {
        const digest = c.transcript.peek();
        const verify = tls.hmac(Hmac, &digest, c.server_finished_key);
        const at = out.mark();
        out.byte(@intFromEnum(tls.HandshakeType.finished));
        const body = out.mark();
        out.push(&verify);
        out.wrapLen(body, 3);
        c.transcript.update(out.data[at..out.len]);
    }
}

/// Reads the client's Finished and checks it.
///
/// **A fixture that skipped this check would answer a client that never
/// proved it held the handshake keys**, and a test of a completed transfer
/// would then prove less than it claims.
fn readClientFinished(c: *Conn) !void {
    const digest = c.transcript.peek();
    const expected = tls.hmac(Hmac, &digest, c.client_finished_key);
    while (true) {
        // The client sends its own change_cipher_spec first, in cleartext.
        const peeked = try c.in.peek(tls.record_header_len);
        if (peeked[0] == @intFromEnum(tls.ContentType.change_cipher_spec)) {
            _ = try c.readRecord();
            continue;
        }
        const message = try c.readSealed();
        if (message.ct != .handshake) return error.TlsUnexpectedMessage;
        if (message.body.len != 4 + Hmac.mac_length) return error.TlsDecodeError;
        if (message.body[0] != @intFromEnum(tls.HandshakeType.finished)) {
            return error.TlsUnexpectedMessage;
        }
        const got: [Hmac.mac_length]u8 = message.body[4..][0..Hmac.mac_length].*;
        if (!crypto.timing_safe.eql([Hmac.mac_length]u8, expected, got)) {
            return error.TlsDecryptError;
        }
        c.transcript.update(message.body);
        return;
    }
}

/// Derives the handshake traffic keys from the shared secret and the
/// transcript through the ServerHello. RFC 8446 section 7.1.
fn deriveHandshakeKeys(c: *Conn, shared: *const [crypto.dh.X25519.shared_length]u8) void {
    const zeroes: [digest_len]u8 = @splat(0);
    const empty = tls.emptyHash(Hash);
    const hello_hash = c.transcript.peek();

    const early = Hkdf.extract(&[1]u8{0}, &zeroes);
    const handshake_derived = tls.hkdfExpandLabel(Hkdf, early, "derived", &empty, digest_len);
    c.handshake_secret = Hkdf.extract(&handshake_derived, shared);
    const master_derived = tls.hkdfExpandLabel(Hkdf, c.handshake_secret, "derived", &empty, digest_len);
    c.master_secret = Hkdf.extract(&master_derived, &zeroes);

    const client = tls.hkdfExpandLabel(Hkdf, c.handshake_secret, "c hs traffic", &hello_hash, digest_len);
    const server = tls.hkdfExpandLabel(Hkdf, c.handshake_secret, "s hs traffic", &hello_hash, digest_len);

    c.client_finished_key = tls.hkdfExpandLabel(Hkdf, client, "finished", "", Hmac.key_length);
    c.server_finished_key = tls.hkdfExpandLabel(Hkdf, server, "finished", "", Hmac.key_length);
    c.read_keys = .{
        .key = tls.hkdfExpandLabel(Hkdf, client, "key", "", Aead.key_length),
        .iv = tls.hkdfExpandLabel(Hkdf, client, "iv", "", Aead.nonce_length),
    };
    c.write_keys = .{
        .key = tls.hkdfExpandLabel(Hkdf, server, "key", "", Aead.key_length),
        .iv = tls.hkdfExpandLabel(Hkdf, server, "iv", "", Aead.nonce_length),
    };
}

/// Derives the application traffic keys. Both sequence numbers restart at
/// zero, which RFC 8446 section 5.3 requires at every key change.
fn deriveApplicationKeys(c: *Conn, handshake_hash: *const [digest_len]u8) void {
    const client = tls.hkdfExpandLabel(Hkdf, c.master_secret, "c ap traffic", handshake_hash, digest_len);
    const server = tls.hkdfExpandLabel(Hkdf, c.master_secret, "s ap traffic", handshake_hash, digest_len);
    c.read_keys = .{
        .key = tls.hkdfExpandLabel(Hkdf, client, "key", "", Aead.key_length),
        .iv = tls.hkdfExpandLabel(Hkdf, client, "iv", "", Aead.nonce_length),
    };
    c.write_keys = .{
        .key = tls.hkdfExpandLabel(Hkdf, server, "key", "", Aead.key_length),
        .iv = tls.hkdfExpandLabel(Hkdf, server, "iv", "", Aead.nonce_length),
    };
}

// ---------------------------------------------------------------------
// Reading a ClientHello.
// ---------------------------------------------------------------------

/// The legacy session id of a ClientHello, or null when the message is not
/// shaped like one.
fn sessionIdOf(hello: []const u8) ?[]const u8 {
    if (hello.len < 4 + 2 + 32 + 1) return null;
    const at = 4 + 2 + 32;
    const len = hello[at];
    if (at + 1 + len > hello.len) return null;
    return hello[at + 1 ..][0..len];
}

/// The extensions block of a ClientHello, or null when the message is not
/// shaped like one.
fn extensionsOf(hello: []const u8) ?[]const u8 {
    if (hello.len < 4) return null;
    if (hello[0] != @intFromEnum(tls.HandshakeType.client_hello)) return null;
    const body_len = (@as(usize, hello[1]) << 16) | (@as(usize, hello[2]) << 8) | hello[3];
    if (4 + body_len != hello.len) return null;
    var at: usize = 4 + 2 + 32;
    if (at >= hello.len) return null;
    at += 1 + hello[at]; // legacy_session_id
    if (at + 2 > hello.len) return null;
    at += 2 + std.mem.readInt(u16, hello[at..][0..2], .big); // cipher_suites
    if (at >= hello.len) return null;
    at += 1 + hello[at]; // legacy_compression_methods
    if (at + 2 > hello.len) return null;
    const extensions_len = std.mem.readInt(u16, hello[at..][0..2], .big);
    at += 2;
    if (at + extensions_len != hello.len) return null;
    return hello[at..][0..extensions_len];
}

/// The body of extension `wanted` in a ClientHello, or null when the
/// message carries none.
fn extensionOf(hello: []const u8, wanted: tls.ExtensionType) ?[]const u8 {
    const extensions = extensionsOf(hello) orelse return null;
    var at: usize = 0;
    while (at + 4 <= extensions.len) {
        const kind = std.mem.readInt(u16, extensions[at..][0..2], .big);
        const len = std.mem.readInt(u16, extensions[at + 2 ..][0..2], .big);
        if (at + 4 + len > extensions.len) return null;
        const body = extensions[at + 4 ..][0..len];
        at += 4 + len;
        if (kind == @intFromEnum(wanted)) return body;
    }
    return null;
}

/// The client's x25519 key share, or null when the hello offers none.
fn keyShareOf(hello: []const u8) ?[]const u8 {
    const body = extensionOf(hello, .key_share) orelse return null;
    if (body.len < 2) return null;
    const list_len = std.mem.readInt(u16, body[0..2], .big);
    if (2 + list_len > body.len) return null;
    var at: usize = 2;
    while (at + 4 <= 2 + list_len) {
        const group = std.mem.readInt(u16, body[at..][0..2], .big);
        const key_len = std.mem.readInt(u16, body[at + 2 ..][0..2], .big);
        if (at + 4 + key_len > 2 + list_len) return null;
        const key = body[at + 4 ..][0..key_len];
        if (group == @intFromEnum(tls.NamedGroup.x25519)) return key;
        at += 4 + key_len;
    }
    return null;
}

/// The protocol name this server chooses from the client's ALPN offer.
///
/// Gives no octets when the client offered no extension, when the hello is
/// not shaped like one, or when the two lists share no name. RFC 7301
/// section 3.2 allows a server to answer nothing in the last case.
fn chooseAlpn(hello: []const u8, preferred: []const []const u8) []const u8 {
    const body = extensionOf(hello, .application_layer_protocol_negotiation) orelse return "";
    if (body.len < 2) return "";
    const list_len = std.mem.readInt(u16, body[0..2], .big);
    if (2 + list_len != body.len) return "";

    for (preferred) |want| {
        var at: usize = 2;
        while (at < body.len) {
            const len = body[at];
            if (at + 1 + len > body.len) return "";
            const name = body[at + 1 ..][0..len];
            if (std.mem.eql(u8, name, want)) return name;
            at += 1 + len;
        }
    }
    return "";
}

// ---------------------------------------------------------------------
// Serving.
// ---------------------------------------------------------------------

fn run(self: *TlsTestServer, script: []const Response) void {
    // Which scripted response goes out next. It also names the capture
    // slot, the way `zurl-http/test_server.zig` uses it.
    var next: usize = 0;
    while (next < script.len) {
        const stream = self.server.accept(testing.io) catch return;
        defer stream.close(testing.io);
        self.accept_count.store(self.accept_count.load(.monotonic) + 1, .release);

        var read_buffer: [tls.max_ciphertext_record_len]u8 = undefined;
        var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
        var write_buffer: [write_plaintext_max + 512]u8 = undefined;
        var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);

        serveConnection(self, &reader.interface, &writer.interface, script, &next);

        // Every failure above is swallowed, because a client that refuses
        // the certificate closes the connection and that is the point of
        // four of the five chains. A cancel arrives as one of those
        // failures and it is not ordinary: this task must end instead of
        // going back to `accept`. See `zurl-http/test_server.zig`'s
        // `taskCanceled` for why a task that ignores a cancel hangs the
        // suite.
        if (taskCanceled(&reader, &writer)) return;
    }
}

fn serveConnection(
    self: *TlsTestServer,
    in: *std.Io.Reader,
    out: *std.Io.Writer,
    script: []const Response,
    next: *usize,
) void {
    var c: Conn = .{ .server = self, .in = in, .out = out };
    handshake(&c) catch return;
    self.handshake_count.store(self.handshake_count.load(.monotonic) + 1, .release);

    switch (self.options.fault) {
        .none, .empty_handshake_fragment => {},
        .short_record,
        .zero_inner_plaintext,
        .short_handshake_header,
        .empty_key_update,
        => {
            // The client writes its request before it reads an answer, so
            // the request is taken first and the fault goes out in place
            // of the reply.
            _ = readRequest(&c, 0) catch false;
            sendFault(&c) catch {};
            return;
        },
    }

    var left: usize = self.options.responses_per_connection orelse script.len;
    while (next.* < script.len and left > 0) : (left -= 1) {
        const got = readRequest(&c, next.*) catch return;
        if (!got) break;
        self.capture_count.store(next.* + 1, .release);
        c.writeSealed(.application_data, script[next.*]) catch return;
        next.* += 1;
    }

    // A TLS peer that closes must say so. Without this the client reports
    // a truncated connection instead of the end of the body, and every
    // test that reads a reply to its end would fail for the wrong reason.
    //
    // A fixture that asks for the opposite is testing the client's answer
    // to a peer that vanishes. See `Options.skip_close_notify`.
    if (c.server.options.skip_close_notify) return;
    c.writeSealed(.alert, &tls.close_notify_alert) catch return;
}

/// Writes the record the options asked for, after the session is up.
///
/// The client is reading an answer when this arrives, so each record goes
/// through the read path of the shipped client with the application keys
/// in place.
fn sendFault(c: *Conn) !void {
    switch (c.server.options.fault) {
        .none, .empty_handshake_fragment => {},
        // A record header that claims no content at all. The client
        // subtracted the tag length from zero.
        .short_record => try c.writeRaw(&[_]u8{ 0x17, 0x03, 0x03, 0x00, 0x00 }),
        // A plaintext that is padding and nothing else. RFC 8446 section
        // 5.4 makes it legal to send and illegal to accept.
        .zero_inner_plaintext => try c.writeSealedExact(&[_]u8{0} ** 4),
        // A handshake sub-message header cut short. The trailing octet is
        // the inner content type, so the message is the two octets in
        // front of it and the four octet header is not all there.
        .short_handshake_header => try c.writeSealedExact(&[_]u8{ 0x18, 0x00, 0x16 }),
        // A `key_update` whose body is empty. The header is whole and the
        // one octet it announces is not there.
        .empty_key_update => try c.writeSealedExact(&[_]u8{ 0x18, 0x00, 0x00, 0x00, 0x16 }),
    }
}

/// Reads one whole request into the capture slot `slot`.
///
/// Gives false when the client closed the session before a whole request
/// arrived, which is ordinary at the end of a connection.
fn readRequest(c: *Conn, slot: usize) !bool {
    var searched: usize = 0;
    const head_end = while (true) {
        if (std.mem.indexOfPos(u8, c.plain[0..c.plain_len], searched, "\r\n\r\n")) |at| {
            break at + 4;
        }
        // The next search restarts three octets back, so a terminator cut
        // in half across two records is still found.
        searched = if (c.plain_len >= 3) c.plain_len - 3 else 0;
        if (!try fill(c)) return false;
    };

    const head = c.plain[0..head_end];
    c.server.capture_head_lens[slot] = capture(&c.server.capture_storage[slot], 0, head);

    // The body, right behind the head, framed by what the head announced.
    var body_end = head_end;
    if (contentLength(head)) |length| {
        while (c.plain_len < head_end + length) {
            if (!try fill(c)) return false;
        }
        body_end = head_end + length;
    } else if (isChunked(head)) {
        body_end = try chunkedEnd(c, head_end) orelse return false;
    }

    c.server.capture_lens[slot] = capture(
        &c.server.capture_storage[slot],
        c.server.capture_head_lens[slot],
        c.plain[head_end..body_end],
    );
    consume(c, body_end);
    return true;
}

/// Walks the chunked body that starts at `from` and gives the offset one
/// past its end, or null when the client closed first.
fn chunkedEnd(c: *Conn, from: usize) !?usize {
    var at = from;
    while (true) {
        const line_end = while (true) {
            if (std.mem.indexOfPos(u8, c.plain[0..c.plain_len], at, "\r\n")) |end| break end + 2;
            if (!try fill(c)) return null;
        };
        const text = std.mem.trim(u8, c.plain[at .. line_end - 2], " \t");
        const size = std.fmt.parseInt(usize, text, 16) catch return error.BadChunkSize;
        at = line_end;
        // The chunk data and the CRLF behind it. A zero size chunk carries
        // no data and ends on the CRLF of the empty trailer section.
        const need = if (size == 0) at + 2 else at + size + 2;
        if (need > c.plain.len) return error.ChunkTooLarge;
        while (c.plain_len < need) {
            if (!try fill(c)) return null;
        }
        at = need;
        if (size == 0) return at;
    }
}

/// Reads one more application record into `c.plain`.
///
/// Gives false at the end of the session, which is a `close_notify` alert
/// or a socket the peer closed.
fn fill(c: *Conn) !bool {
    const message = c.readSealed() catch return false;
    switch (message.ct) {
        .application_data => {},
        // RFC 8446 section 6.1. Any alert ends the session here: the
        // fixture answers none of them, so reading on would block.
        .alert => return false,
        // RFC 8446 section 5.1 allows a change_cipher_spec after the
        // handshake, and it carries nothing.
        .change_cipher_spec => return true,
        else => return error.TlsUnexpectedMessage,
    }
    if (c.plain_len + message.body.len > c.plain.len) return error.TlsRecordOverflow;
    @memcpy(c.plain[c.plain_len..][0..message.body.len], message.body);
    c.plain_len += message.body.len;
    return true;
}

/// Drops the first `n` octets of the reassembled application data.
fn consume(c: *Conn, n: usize) void {
    std.mem.copyForwards(u8, c.plain[0 .. c.plain_len - n], c.plain[n..c.plain_len]);
    c.plain_len -= n;
}

/// Appends as much of `text` as fits past `at` in `slot`, and gives the
/// new end. A request longer than the slot is truncated, not dropped: this
/// is a record for a test to read and not a value anything parses back.
fn capture(slot: *[capture_bytes]u8, at: usize, text: []const u8) usize {
    const n = @min(slot.len - at, text.len);
    @memcpy(slot[at..][0..n], text[0..n]);
    return at + n;
}

/// The `content-length` `head` announces, or null when it announces none.
fn contentLength(head: []const u8) ?usize {
    var lines = std.mem.splitScalar(u8, head, '\n');
    _ = lines.next();
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "content-length")) continue;
        return std.fmt.parseInt(usize, std.mem.trim(u8, line[colon + 1 ..], " \t"), 10) catch null;
    }
    return null;
}

/// Whether `head` frames its body with the chunked transfer coding.
fn isChunked(head: []const u8) bool {
    var lines = std.mem.splitScalar(u8, head, '\n');
    _ = lines.next();
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "transfer-encoding")) continue;
        return std.mem.indexOf(u8, line[colon + 1 ..], "chunked") != null;
    }
    return false;
}

/// Whether the task that owns `reader` and `writer` has been canceled.
///
/// A copy of `zurl-http/test_server.zig`'s function of the same name, for
/// the reason stated there: a task that catches `error.Canceled` and goes
/// back to `accept` blocks for ever, and `stop` blocks with it.
/// `zurl-tls` imports no other package of ours, so the copy stays here.
fn taskCanceled(
    reader: *const std.Io.net.Stream.Reader,
    writer: *const std.Io.net.Stream.Writer,
) bool {
    if (reader.err) |err| if (err == error.Canceled) return true;
    if (writer.err) |err| if (err == error.Canceled) return true;
    return false;
}

// ---------------------------------------------------------------------
// The fixture's own tests. They drive the shipped client, so a fixture
// that stopped speaking TLS reports here and not in the suites that use
// it.
// ---------------------------------------------------------------------

const Certificate = std.crypto.Certificate;

/// A time inside the validity of every certificate this fixture mints,
/// except the leaf of `Chain.expired`.
const test_now_sec: i64 = 1_700_000_000;

/// The host check and the trust check of `Client.Options`, which the file
/// declares as anonymous unions.
const HostCheck = @FieldType(Client.Options, "host");
const TrustCheck = @FieldType(Client.Options, "ca");

/// One client session against `server`, and the socket and the buffers it
/// borrows.
///
/// A struct because a `Client` holds the reader, the writer, and both
/// buffers by pointer for its whole life. A helper that built them on its
/// own frame and returned the session by value would leave every one of
/// those pointers dangling.
const Peer = struct {
    stream: std.Io.net.Stream,
    reader: std.Io.net.Stream.Reader,
    writer: std.Io.net.Stream.Writer,
    read_buffer: [Client.min_buffer_len]u8,
    // `Client.flush` asks the socket writer for `min_buffer_len` writable
    // octets, so a smaller buffer than that aborts the run.
    write_buffer: [Client.min_buffer_len]u8,
    session_read: [4096]u8,
    session_write: [4096]u8,
    entropy: [Client.Options.entropy_len]u8,
    session: Client,

    /// Dials `server` and runs the handshake in place.
    fn connect(
        self: *Peer,
        server: *TlsTestServer,
        host: HostCheck,
        ca: TrustCheck,
        alpn: []const []const u8,
        seed: u8,
    ) !void {
        var address: std.Io.net.IpAddress = .{ .ip4 = .loopback(server.port()) };
        self.stream = try address.connect(testing.io, .{ .mode = .stream });
        errdefer self.stream.close(testing.io);

        self.reader = .init(self.stream, testing.io, &self.read_buffer);
        self.writer = .init(self.stream, testing.io, &self.write_buffer);
        self.entropy = @splat(seed);

        self.session = try Client.init(&self.reader.interface, &self.writer.interface, .{
            .host = host,
            .ca = ca,
            .read_buffer = &self.session_read,
            .write_buffer = &self.session_write,
            .realtime_now = .{ .nanoseconds = @as(i96, test_now_sec) * std.time.ns_per_s },
            .alpn_protocols = alpn,
            .entropy = &self.entropy,
        });
    }

    fn close(self: *Peer) void {
        self.stream.close(testing.io);
    }

    /// Sends `request` and reads every octet the server sent back. The
    /// caller owns the result.
    ///
    /// **Two flushes, and both are needed.** `Client.flush` encrypts what
    /// the session buffered into the socket writer's buffer and stops
    /// there. Nothing reaches the socket until the socket writer is
    /// flushed as well, and a test that flushed only the session waits
    /// for a reply to a request that never left this process.
    fn exchange(self: *Peer, request: []const u8) ![]u8 {
        try self.session.writer.writeAll(request);
        try self.session.writer.flush();
        try self.writer.interface.flush();
        return self.session.reader.allocRemaining(testing.allocator, .unlimited);
    }
};

/// Runs one HTTPS-shaped exchange against `server` with the vendored
/// client, and gives what the client read back.
///
/// The caller owns the returned bytes.
fn fetch(server: *TlsTestServer, host: HostCheck, ca: TrustCheck) ![]u8 {
    var peer: Peer = undefined;
    try peer.connect(server, host, ca, &.{"http/1.1"}, 0x24);
    defer peer.close();
    return peer.exchange("GET / HTTP/1.1\r\nHost: " ++ host_name ++ "\r\n\r\n");
}

/// `fetch` against a bundle that holds `cb`, which is the shape every
/// chain test below takes.
fn fetchTrusting(
    server: *TlsTestServer,
    host: HostCheck,
    cb: *Certificate.Bundle,
    lock: *std.Io.RwLock,
) ![]u8 {
    return fetch(server, host, .{ .bundle = .{
        .gpa = testing.allocator,
        .io = testing.io,
        .lock = lock,
        .bundle = cb,
    } });
}

/// A bundle that holds the root of `server`, built from the PEM the
/// fixture writes. The caller deinitializes it.
fn trustRootOf(server: *const TlsTestServer) !Certificate.Bundle {
    var pem_buf: [root_pem_max]u8 = undefined;
    const pem = try server.rootPem(&pem_buf);

    var cb: Certificate.Bundle = .empty;
    errdefer cb.deinit(testing.allocator);
    _ = try @import("bundle.zig").addCertsFromPem(&cb, testing.allocator, pem, test_now_sec);
    return cb;
}

const ok_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

test "a trusted chain completes a real TLS 1.3 handshake and serves the reply" {
    var server: TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{ .chain = .ca_issued });
    defer server.stop();

    var cb = try trustRootOf(&server);
    defer cb.deinit(testing.allocator);
    var lock: std.Io.RwLock = .init;

    const body = try fetchTrusting(&server, .{ .explicit = host_name }, &cb, &lock);
    defer testing.allocator.free(body);

    try testing.expect(std.mem.endsWith(u8, body, "ok"));
    try testing.expectEqual(@as(usize, 1), server.handshakes());
    try testing.expectEqualStrings(
        "GET / HTTP/1.1\r\nHost: " ++ host_name ++ "\r\n\r\n",
        server.requestHead(0).?,
    );
}

test "the leaf answers for the loopback address as well as for the name" {
    // The fixture puts an `iPAddress` name in every leaf but one, so a
    // test may point a url at `127.0.0.1` and keep the host check on.
    var server: TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{ .chain = .ca_issued });
    defer server.stop();

    var cb = try trustRootOf(&server);
    defer cb.deinit(testing.allocator);
    var lock: std.Io.RwLock = .init;

    const body = try fetchTrusting(&server, .{ .explicit = "127.0.0.1" }, &cb, &lock);
    defer testing.allocator.free(body);
    try testing.expect(std.mem.endsWith(u8, body, "ok"));
}

test "a self-signed chain reaches no trusted root" {
    var server: TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{ .chain = .self_signed });
    defer server.stop();

    var cb: Certificate.Bundle = .empty;
    defer cb.deinit(testing.allocator);
    var lock: std.Io.RwLock = .init;

    try testing.expectError(
        error.TlsCertificateNotVerified,
        fetchTrusting(&server, .{ .explicit = host_name }, &cb, &lock),
    );
    // The session never came up, so the client refused before it could
    // send a request.
    try testing.expectEqual(@as(usize, 0), server.handshakes());
}

test "an expired leaf is refused" {
    var server: TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{ .chain = .expired });
    defer server.stop();

    var cb = try trustRootOf(&server);
    defer cb.deinit(testing.allocator);
    var lock: std.Io.RwLock = .init;

    try testing.expectError(
        error.CertificateExpired,
        fetchTrusting(&server, .{ .explicit = host_name }, &cb, &lock),
    );
}

test "a leaf for another name is refused" {
    var server: TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{ .chain = .wrong_host });
    defer server.stop();

    var cb = try trustRootOf(&server);
    defer cb.deinit(testing.allocator);
    var lock: std.Io.RwLock = .init;

    try testing.expectError(
        error.CertificateHostMismatch,
        fetchTrusting(&server, .{ .explicit = host_name }, &cb, &lock),
    );
}

test "a leaf that is no certificate authority cannot sign a leaf for another name" {
    // The attack of the fifth reason in `UPSTREAM`, run as a handshake and
    // not as a unit test. Every signature in the chain holds and the root
    // is one the client trusts, so only `verifyIssued` refuses it.
    var server: TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{ .chain = .forged_by_leaf });
    defer server.stop();

    var cb = try trustRootOf(&server);
    defer cb.deinit(testing.allocator);
    var lock: std.Io.RwLock = .init;

    try testing.expectError(
        error.CertificateIssuerNotCa,
        fetchTrusting(&server, .{ .explicit = host_name }, &cb, &lock),
    );
    try testing.expectEqual(@as(usize, 0), server.handshakes());
}

test "a leaf a parser cannot read is refused and does not crash the client" {
    // The reproduction as a handshake. Before the bounded reader, these
    // six octets panicked a ReleaseSafe build with "index out of bounds:
    // index 6, len 6" and gave a ReleaseFast build a segmentation fault,
    // and both happened before the client had authenticated anything.
    var server: TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{ .chain = .malformed });
    defer server.stop();

    // The chain has no root of its own, so the bundle stays empty. The
    // client never gets as far as the trust store all the same.
    var cb: Certificate.Bundle = .empty;
    defer cb.deinit(testing.allocator);
    var lock: std.Io.RwLock = .init;

    try testing.expectError(
        error.CertificateFieldHasInvalidLength,
        fetchTrusting(&server, .{ .explicit = host_name }, &cb, &lock),
    );
    // The session never came up, so nothing this server said was ever
    // taken for authenticated.
    try testing.expectEqual(@as(usize, 0), server.handshakes());
}

test "a client that verifies nothing still refuses a leaf it cannot read" {
    // `--insecure` turns the trust check off and it does not turn the
    // parser off. A certificate nobody can read is still a fault.
    var server: TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{ .chain = .malformed });
    defer server.stop();

    try testing.expectError(
        error.CertificateFieldHasInvalidLength,
        fetch(&server, .no_verification, .no_verification),
    );
}

test "a client that verifies nothing takes any chain" {
    // What `-k` asks for. The chain is the forged one, so this also says
    // that the refusal above came from the certificate rules and not from
    // anything else in the handshake.
    var server: TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{ .chain = .forged_by_leaf });
    defer server.stop();

    const body = try fetch(&server, .no_verification, .no_verification);
    defer testing.allocator.free(body);
    try testing.expect(std.mem.endsWith(u8, body, "ok"));
    try testing.expectEqual(@as(usize, 1), server.handshakes());
}

test "the server answers the ALPN name the client offered" {
    var server: TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{ .chain = .self_signed });
    defer server.stop();

    var peer: Peer = undefined;
    try peer.connect(&server, .no_verification, .no_verification, &.{ "h2", "http/1.1" }, 0x31);
    defer peer.close();

    // The fixture prefers `http/1.1`, and the client offered it second.
    // A server that echoed the client's first name instead would let an
    // HTTP/2 test pass against an HTTP/1.1 fixture.
    try testing.expectEqualStrings("http/1.1", peer.session.alpnProtocol().?);
}

test "one connection serves two requests when the options allow it" {
    const first_reply = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none";
    var server: TlsTestServer = undefined;
    try server.startWith(
        &.{ first_reply, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo" },
        .{ .chain = .self_signed, .responses_per_connection = 2 },
    );
    defer server.stop();

    var peer: Peer = undefined;
    try peer.connect(&server, .no_verification, .no_verification, &.{}, 0x52);
    defer peer.close();

    try peer.session.writer.writeAll("GET /a HTTP/1.1\r\nHost: x\r\n\r\n");
    try peer.session.writer.flush();
    try peer.writer.interface.flush();
    const first = try peer.session.reader.take(first_reply.len);
    try testing.expect(std.mem.endsWith(u8, first, "one"));

    const rest = try peer.exchange("GET /b HTTP/1.1\r\nHost: x\r\n\r\n");
    defer testing.allocator.free(rest);
    try testing.expect(std.mem.endsWith(u8, rest, "two"));

    try testing.expectEqual(@as(usize, 1), server.accepts());
    try testing.expectEqualStrings("GET /a HTTP/1.1\r\nHost: x\r\n\r\n", server.requestHead(0).?);
    try testing.expectEqualStrings("GET /b HTTP/1.1\r\nHost: x\r\n\r\n", server.requestHead(1).?);
}

test "the server reads a request body the client framed with a length" {
    var server: TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{ .chain = .self_signed });
    defer server.stop();

    var peer: Peer = undefined;
    try peer.connect(&server, .no_verification, .no_verification, &.{}, 0x63);
    defer peer.close();

    const body = try peer.exchange(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
    );
    defer testing.allocator.free(body);
    try testing.expect(std.mem.endsWith(u8, body, "ok"));
    try testing.expectEqualStrings("hello", server.requestBody(0).?);
}

test "the server reads a request body the client framed in chunks" {
    var server: TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{ .chain = .self_signed });
    defer server.stop();

    var peer: Peer = undefined;
    try peer.connect(&server, .no_verification, .no_verification, &.{}, 0x74);
    defer peer.close();

    const body = try peer.exchange(
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" ++
            "3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
    );
    defer testing.allocator.free(body);
    try testing.expect(std.mem.endsWith(u8, body, "ok"));
    // The fixture is a record of the wire and not a parser of it, so the
    // chunk framing is part of what a test reads back.
    try testing.expectEqualStrings(
        "3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
        server.requestBody(0).?,
    );
}

test "a sub-authority may not answer for a host outside its name constraints" {
    // The technically constrained sub-authority. Every signature holds,
    // the root is the one the client trusts, and the leaf names the host
    // that was asked for. Only the `nameConstraints` of the middle
    // certificate refuses it, and a client that reads the extension and
    // does nothing completes this transfer.
    var server: TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{ .chain = .constrained_sub_ca });
    defer server.stop();

    var cb = try trustRootOf(&server);
    defer cb.deinit(testing.allocator);
    var lock: std.Io.RwLock = .init;

    // The name is `CertificateNameNotPermitted` and not
    // `CertificateHostMismatch`. The leaf does name the host that was
    // asked for, so a host mismatch would say the wrong thing: what
    // refuses this chain is that the authority above the leaf was not
    // allowed to answer for that name.
    try testing.expectError(
        error.CertificateNameNotPermitted,
        fetchTrusting(&server, .{ .explicit = host_name }, &cb, &lock),
    );
    try testing.expectEqual(@as(usize, 0), server.handshakes());
}

test "a sub-authority answers for a host its name constraints permit" {
    // The positive control of the rule above. The constraint names the
    // host, so the same three certificate chain must complete.
    var server: TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{ .chain = .permitted_sub_ca });
    defer server.stop();

    var cb = try trustRootOf(&server);
    defer cb.deinit(testing.allocator);
    var lock: std.Io.RwLock = .init;

    const body = try fetchTrusting(&server, .{ .explicit = host_name }, &cb, &lock);
    defer testing.allocator.free(body);
    try testing.expect(std.mem.endsWith(u8, body, "ok"));
    try testing.expectEqual(@as(usize, 1), server.handshakes());
}

test "a leaf with a critical extension nobody reads is refused" {
    // RFC 5280 section 4.2. This is the rule that keeps the client closed
    // when an extension nobody has written yet arrives, so the extension
    // the fixture writes names a private arc and holds nothing.
    var server: TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{ .chain = .unknown_critical_extension });
    defer server.stop();

    var cb = try trustRootOf(&server);
    defer cb.deinit(testing.allocator);
    var lock: std.Io.RwLock = .init;

    try testing.expectError(
        error.CertificateHasUnrecognizedObjectId,
        fetchTrusting(&server, .{ .explicit = host_name }, &cb, &lock),
    );
    try testing.expectEqual(@as(usize, 0), server.handshakes());
}

test "a leaf for electronic mail does not stand for a TLS server" {
    // RFC 5280 section 4.2.1.12. The certificate authority above such a
    // leaf may have checked an electronic mail address and never a host
    // name.
    var server: TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{ .chain = .wrong_ext_key_usage });
    defer server.stop();

    var cb = try trustRootOf(&server);
    defer cb.deinit(testing.allocator);
    var lock: std.Io.RwLock = .init;

    // The name is `CertificateNotForServerAuth`. An earlier patch had to
    // report this leaf as `CertificateIssuerCannotSignCertificates`, and
    // a user then read that a certificate which is no authority at all is
    // "a certificate authority that cannot sign certificates".
    try testing.expectError(
        error.CertificateNotForServerAuth,
        fetchTrusting(&server, .{ .explicit = host_name }, &cb, &lock),
    );
    try testing.expectEqual(@as(usize, 0), server.handshakes());
}

test "a five octet record after the handshake is refused" {
    // `17 03 03 00 00`. The record claims no content, so the read path
    // subtracted the sixteen octet tag from zero and took 65520 octets
    // that were never there. A Debug build panicked with an integer
    // overflow and a ReleaseFast build took the signal SEGV.
    var server: TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{
        .chain = .self_signed,
        .fault = .short_record,
    });
    defer server.stop();

    var peer: Peer = undefined;
    try peer.connect(&server, .no_verification, .no_verification, &.{}, 0x85);
    defer peer.close();

    try testing.expectError(
        error.ReadFailed,
        peer.exchange("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
    );
    try testing.expectEqual(Client.ReadError.TlsRecordOverflow, peer.session.read_err.?);
}

test "a record whose inner plaintext is all zeroes is refused" {
    // RFC 8446 section 5.4 makes such a record legal to send and illegal
    // to accept. The padding is stripped and nothing is left, so the read
    // path took the octet before the buffer as the inner content type and
    // the length of the message as the largest `usize`.
    var server: TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{
        .chain = .self_signed,
        .fault = .zero_inner_plaintext,
    });
    defer server.stop();

    var peer: Peer = undefined;
    try peer.connect(&server, .no_verification, .no_verification, &.{}, 0x86);
    defer peer.close();

    try testing.expectError(
        error.ReadFailed,
        peer.exchange("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
    );
    try testing.expectEqual(Client.ReadError.TlsUnexpectedMessage, peer.session.read_err.?);
}

test "a handshake record that decrypts to no octets is refused" {
    // The same arithmetic one function away: the fragment the client
    // assembles grew by nothing, so the step back to the inner content
    // type wrapped. The record carries a real tag under the handshake
    // key, so only the server that holds those keys can send it.
    var server: TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{
        .chain = .self_signed,
        .fault = .empty_handshake_fragment,
    });
    defer server.stop();

    var peer: Peer = undefined;
    try testing.expectError(
        error.TlsUnexpectedMessage,
        peer.connect(&server, .no_verification, .no_verification, &.{}, 0x87),
    );
    try testing.expectEqual(@as(usize, 0), server.handshakes());
}

test "rootPem gives a block a bundle reads back" {
    var server: TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{ .chain = .ca_issued });
    defer server.stop();

    var cb = try trustRootOf(&server);
    defer cb.deinit(testing.allocator);
    // One root, and the bundle found it by its subject name.
    try testing.expectEqual(@as(usize, 1), cb.map.count());

    var other: TlsTestServer = undefined;
    try other.startWith(&.{ok_response}, .{ .chain = .self_signed });
    defer other.stop();
    var buf: [root_pem_max]u8 = undefined;
    try testing.expectError(error.NoRootCertificate, other.rootPem(&buf));
}

test "a handshake sub-message header cut short is refused" {
    // The four octet header of a sub-message was read before anything
    // checked that four octets were there. This record leaves two, so the
    // three octet length came out of the record before this one, and the
    // peer wrote that record too.
    var server: TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{
        .chain = .self_signed,
        .fault = .short_handshake_header,
    });
    defer server.stop();

    var peer: Peer = undefined;
    try peer.connect(&server, .no_verification, .no_verification, &.{}, 0x88);
    defer peer.close();

    try testing.expectError(
        error.ReadFailed,
        peer.exchange("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
    );
    try testing.expectEqual(Client.ReadError.TlsBadLength, peer.session.read_err.?);
}

test "a key update with an empty body is refused" {
    // The body of a `key_update` is one octet and it says whether the
    // write keys rotate too. A length of zero passed the bound on the
    // sub-message and the read of that octet took the first octet after
    // the record, which the peer also wrote. So the peer chose which
    // branch of a key rotation ran.
    var server: TlsTestServer = undefined;
    try server.startWith(&.{ok_response}, .{
        .chain = .self_signed,
        .fault = .empty_key_update,
    });
    defer server.stop();

    var peer: Peer = undefined;
    try peer.connect(&server, .no_verification, .no_verification, &.{}, 0x89);
    defer peer.close();

    try testing.expectError(
        error.ReadFailed,
        peer.exchange("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
    );
    try testing.expectEqual(Client.ReadError.TlsDecodeError, peer.session.read_err.?);
}
