const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

const std = @import("std"); // ZURL PATCH: upstream reads "../../std.zig".
const tls = std.crypto.tls;
const Client = @This();
const mem = std.mem;
const crypto = std.crypto;
const assert = std.debug.assert;
const Certificate = std.crypto.Certificate;
const certificate = @import("certificate.zig"); // ZURL PATCH: the bounded certificate reader. `Certificate.parse` has no bound check at all, so it reads past the end of a certificate a peer chose.
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

const max_ciphertext_len = tls.max_ciphertext_len;
const hmacExpandLabel = tls.hmacExpandLabel;
const hkdfExpandLabel = tls.hkdfExpandLabel;
const int = tls.int;
const array = tls.array;

/// The encrypted stream from the server to the client. Bytes are pulled from
/// here via `reader`.
///
/// The buffer is asserted to have capacity at least `min_buffer_len`.
input: *Reader,
/// Decrypted stream from the server to the client.
reader: Reader,

/// The encrypted stream from the client to the server. Bytes are pushed here
/// via `writer`.
///
/// The buffer is asserted to have capacity at least `min_buffer_len`.
output: *Writer,
/// The plaintext stream from the client to the server.
writer: Writer,

/// Populated when `error.TlsAlert` is returned.
alert: ?tls.Alert = null,
read_err: ?ReadError = null,
tls_version: tls.ProtocolVersion,
read_seq: u64,
write_seq: u64,
/// When this is true, the stream may still not be at the end because there
/// may be data in the input buffer.
received_close_notify: bool,
allow_truncation_attacks: bool,
application_cipher: tls.ApplicationCipher,

/// If non-null, ssl secrets are logged to a stream. Creating such a log file
/// allows other programs with access to that file to decrypt all traffic over
/// this connection.
ssl_key_log: ?*SslKeyLog,
/// ZURL PATCH: The ALPN protocol the peer chose, or a length of zero when
/// ZURL PATCH: it chose none. Read it with `alpnProtocol`. The name is held
/// ZURL PATCH: by value, because a `Client` is copied into whatever owns
/// ZURL PATCH: the session and the handshake record is gone by then.
alpn: AlpnSelection = .none, // ZURL PATCH
/// ZURL PATCH: The lock that guards the write state of this session, or
/// ZURL PATCH: null when one task drives the whole session.
/// ZURL PATCH:
/// ZURL PATCH: **A read and a write on one session are independent, with
/// ZURL PATCH: one exception.** The read path decrypts with `server_key`
/// ZURL PATCH: and `read_seq`, and the write path encrypts with
/// ZURL PATCH: `client_key` and `write_seq`. The two sets never overlap,
/// ZURL PATCH: and `input` and `output` are two buffers over one socket.
/// ZURL PATCH: The exception is a TLS 1.3 `key_update` of kind
/// ZURL PATCH: `update_requested`: RFC 8446 section 4.6.3 makes a peer
/// ZURL PATCH: that asks for one expect the other side to change its own
/// ZURL PATCH: write keys, so that arm of the read path writes
/// ZURL PATCH: `client_key`, `client_iv`, and `write_seq`.
/// ZURL PATCH:
/// ZURL PATCH: A caller that drives the read path and the write path from
/// ZURL PATCH: two tasks sets this. `readIndirect` then takes it around
/// ZURL PATCH: that one arm, and `prepareCiphertextRecord` takes it for
/// ZURL PATCH: as long as it encrypts, so a key that rotates never
/// ZURL PATCH: rotates under a record that is half encrypted and a nonce
/// ZURL PATCH: can never repeat under one key.
/// ZURL PATCH:
/// ZURL PATCH: Null costs one compare and no lock, so a session with one
/// ZURL PATCH: driver behaves exactly as upstream does. See `WriteLock`
/// ZURL PATCH: in the appended block.
write_lock: ?WriteLock = null, // ZURL PATCH

pub const ReadError = error{
    /// The alert description will be stored in `alert`.
    TlsAlert,
    TlsBadLength,
    TlsBadRecordMac,
    TlsConnectionTruncated,
    TlsDecodeError,
    TlsRecordOverflow,
    TlsUnexpectedMessage,
    TlsIllegalParameter,
    TlsSequenceOverflow,
};

pub const SslKeyLog = struct {
    client_key_seq: u64,
    server_key_seq: u64,
    client_random: [32]u8,
    writer: *Writer,

    fn clientCounter(key_log: *@This()) u64 {
        defer key_log.client_key_seq += 1;
        return key_log.client_key_seq;
    }

    fn serverCounter(key_log: *@This()) u64 {
        defer key_log.server_key_seq += 1;
        return key_log.server_key_seq;
    }
};

/// The `Reader` supplied to `init` requires a buffer capacity
/// at least this amount.
pub const min_buffer_len = tls.max_ciphertext_record_len;

pub const Options = struct {
    /// How to perform host verification of server certificates.
    host: union(enum) {
        /// No host verification is performed, which prevents a trusted connection from
        /// being established.
        no_verification,
        /// Verify that the server certificate was issued for a given host.
        explicit: []const u8,
    },
    /// How to verify the authenticity of server certificates.
    ca: union(enum) {
        /// No ca verification is performed, which prevents a trusted connection from
        /// being established.
        no_verification,
        /// Verify that the server certificate is a valid self-signed certificate.
        /// This provides no authorization guarantees, as anyone can create a
        /// self-signed certificate.
        self_signed,
        /// Verify that the server certificate is authorized by a given ca bundle.
        bundle: struct {
            gpa: std.mem.Allocator,
            io: std.Io,
            lock: *std.Io.RwLock,
            bundle: *Certificate.Bundle,
        },
    },
    write_buffer: []u8,
    read_buffer: []u8,
    /// Cryptographically secure random bytes. The pointer is not captured; data is only
    /// read during `init`.
    entropy: *const [entropy_len]u8,
    /// Current time according to the wall clock / calendar.
    realtime_now: std.Io.Timestamp,

    /// If non-null, ssl secrets are logged to this stream. Creating such a log file allows
    /// other programs with access to that file to decrypt all traffic over this connection.
    ///
    /// Only the `writer` field is observed during the handshake (`init`).
    /// After that, the other fields are populated.
    ssl_key_log: ?*SslKeyLog = null,
    /// By default, reaching the end-of-stream when reading from the server will
    /// cause `error.TlsConnectionTruncated` to be returned, unless a close_notify
    /// message has been received. By setting this flag to `true`, instead, the
    /// end-of-stream will be forwarded to the application layer above TLS.
    ///
    /// This makes the application vulnerable to truncation attacks unless the
    /// application layer itself verifies that the amount of data received equals
    /// the amount of data expected, such as HTTP with the Content-Length header.
    allow_truncation_attacks: bool = false,
    /// Populated when `error.TlsAlert` is returned from `init`.
    alert: ?*tls.Alert = null,
    // ZURL PATCH: The highest TLS version the client hello offers, which
    // ZURL PATCH: is curl's `--tls-max`. `.tls_1_2` offers TLS 1.2 alone.
    // ZURL PATCH: Every other value offers both versions, the way upstream
    // ZURL PATCH: always does. See the block after `cleartext_header_buf`.
    max_version: tls.ProtocolVersion = .tls_1_3, // ZURL PATCH
    // ZURL PATCH: The protocol names the ALPN extension offers, in the
    // ZURL PATCH: order of preference. RFC 7301. Upstream sends no ALPN
    // ZURL PATCH: extension at all, so a server that speaks HTTP/2 never
    // ZURL PATCH: gets the chance to say so.
    // ZURL PATCH:
    // ZURL PATCH: An empty list sends no extension, which is curl's
    // ZURL PATCH: `--no-alpn`. The peer's answer must name one of these
    // ZURL PATCH: entries, and a name outside the list stops the
    // ZURL PATCH: handshake. See `encodeAlpn` and `readAlpn` in the
    // ZURL PATCH: appended block.
    alpn_protocols: []const []const u8 = &.{}, // ZURL PATCH

    pub const entropy_len = 240;
};

// ZURL PATCH: One of the sixteen GREASE version values RFC 8701 reserves.
// ZURL PATCH: A server must ignore a version it does not recognise, so an
// ZURL PATCH: entry holding this offers nothing at all. It stands in the
// ZURL PATCH: `supported_versions` list where TLS 1.3 would be when
// ZURL PATCH: `Options.max_version` is TLS 1.2, which keeps the list the
// ZURL PATCH: same length as upstream builds it.
const grease_version: u16 = 0x0a0a; // ZURL PATCH

pub const InitError = error{
    InsufficientEntropy,
    DiskQuota,
    LockViolation,
    NotOpenForWriting,
    /// The alert description will be stored in `alert`.
    TlsAlert,
    TlsUnexpectedMessage,
    TlsIllegalParameter,
    TlsDecryptFailure,
    TlsRecordOverflow,
    TlsBadRecordMac,
    CertificateFieldHasInvalidLength,
    CertificateHostMismatch,
    CertificatePublicKeyInvalid,
    CertificateExpired,
    CertificateFieldHasWrongDataType,
    CertificateIssuerMismatch,
    CertificateNotYetValid,
    CertificateSignatureAlgorithmMismatch,
    CertificateSignatureAlgorithmUnsupported,
    CertificateSignatureInvalid,
    CertificateSignatureInvalidLength,
    CertificateSignatureNamedCurveUnsupported,
    CertificateSignatureUnsupportedBitCount,
    TlsCertificateNotVerified,
    TlsBadSignatureScheme,
    TlsBadRsaSignatureBitCount,
    InvalidEncoding,
    IdentityElement,
    SignatureVerificationFailed,
    TlsDecryptError,
    TlsConnectionTruncated,
    TlsDecodeError,
    UnsupportedCertificateVersion,
    CertificateTimeInvalid,
    CertificateHasUnrecognizedObjectId,
    CertificateHasInvalidBitString,
    MessageTooLong,
    NegativeIntoUnsigned,
    TargetTooSmall,
    BufferTooSmall,
    InvalidSignature,
    NotSquare,
    NonCanonical,
    WeakPublicKey,
    // ZURL PATCH: the caller's ALPN list has no wire form. A name of no
    // ZURL PATCH: bytes, a name over `alpn_max_protocol_len` bytes, or a
    // ZURL PATCH: list over `alpn_max_list_len` bytes reaches this. The
    // ZURL PATCH: hello is not written when it does.
    TlsAlpnOfferInvalid, // ZURL PATCH
    // ZURL PATCH: the peer chose an ALPN protocol the hello did not offer,
    // ZURL PATCH: which RFC 7301 section 3.2 forbids. The session would
    // ZURL PATCH: then carry a protocol this client cannot parse, so the
    // ZURL PATCH: handshake stops instead.
    TlsAlpnProtocolNotOffered, // ZURL PATCH
    // ZURL PATCH: the host of this session has no `server_name` extension,
    // ZURL PATCH: because the extension counts its host in a `u16` and this
    // ZURL PATCH: one is longer than that count holds. See `host_name_max`.
    TlsHostNameTooLong, // ZURL PATCH
    // ZURL PATCH: the chain rules of `verifyIssued`. A certificate that
    // signs another certificate must carry `basicConstraints` with `cA`
    // TRUE, it must assert `keyCertSign` where it carries `keyUsage`, and
    // it must leave room under any `pathLenConstraint` it names. Upstream
    // checks none of the three, so any certificate that chains to a
    // trusted root could sign a certificate for any other host.
    // ZURL PATCH: `StrengthError` holds the cryptographic floor, and
    // ZURL PATCH: `certificate.ParseError` holds the one name the bounded
    // ZURL PATCH: reader adds to the set the standard library gives.
} || IssuerError || StrengthError || certificate.ParseError || std.Io.Writer.Error || std.Io.Reader.ShortError || std.Io.Cancelable; // ZURL PATCH

/// Initiates a TLS handshake and establishes a TLSv1.2 or TLSv1.3 session.
///
/// `host` is only borrowed during this function call.
///
/// `input` is asserted to have buffer capacity at least `min_buffer_len`.
pub fn init(input: *Reader, output: *Writer, options: Options) InitError!Client {
    assert(input.buffer.len >= min_buffer_len);
    const host = switch (options.host) {
        .no_verification => "",
        .explicit => |host| host,
    };
    // ZURL PATCH: the cast below has no bound upstream. `host` reaches here
    // ZURL PATCH: from a url, and a url reaches zurl from a `Location`
    // ZURL PATCH: header, so the count is the peer's and not this build's.
    // ZURL PATCH: An `@intCast` that does not fit is undefined behaviour in
    // ZURL PATCH: ReleaseFast, which is the build a user runs, so the bound
    // ZURL PATCH: is a named refusal here. See `host_name_max`.
    if (host.len > host_name_max) return error.TlsHostNameTooLong; // ZURL PATCH
    const host_len: u16 = @intCast(host.len);

    const client_hello_rand = options.entropy[0..32].*;
    var key_seq: u64 = 0;
    var server_hello_rand: [32]u8 = undefined;
    const legacy_session_id = options.entropy[32..64].*;

    var key_share = KeyShare.init(options.entropy[64..240]) catch |err| switch (err) {
        // Only possible to happen if the seed is all zeroes.
        error.IdentityElement => return error.InsufficientEntropy,
    };

    // ZURL PATCH: the ALPN extension, RFC 7301. It is built here, before
    // ZURL PATCH: every length that must count it, and it is empty when
    // ZURL PATCH: the caller offers no protocol. The bytes go on the wire
    // ZURL PATCH: after the host, so the buffer below stays the size the
    // ZURL PATCH: compiler computed. See the `iovecs` block.
    var alpn_buf: [alpn_extension_max]u8 = undefined; // ZURL PATCH
    const alpn_extension = try encodeAlpn(options.alpn_protocols, &alpn_buf); // ZURL PATCH

    const extensions_payload = tls.extension(.supported_versions, array(u8, tls.ProtocolVersion, .{
        .tls_1_3,
        .tls_1_2,
    })) ++ tls.extension(.signature_algorithms, array(u16, tls.SignatureScheme, .{
        .ecdsa_secp256r1_sha256,
        .ecdsa_secp384r1_sha384,
        .rsa_pkcs1_sha256,
        .rsa_pkcs1_sha384,
        .rsa_pkcs1_sha512,
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
        .rsa_pss_rsae_sha512,
        .rsa_pss_pss_sha256,
        .rsa_pss_pss_sha384,
        .rsa_pss_pss_sha512,
        .rsa_pkcs1_sha1,
        .ed25519,
    })) ++ tls.extension(.supported_groups, array(u16, tls.NamedGroup, .{
        .x25519_ml_kem768,
        .secp256r1,
        .secp384r1,
        .x25519,
    })) ++ tls.extension(.psk_key_exchange_modes, array(u8, tls.PskKeyExchangeMode, .{
        .psk_dhe_ke,
    })) ++ tls.extension(.key_share, array(
        u16,
        u8,
        int(u16, @intFromEnum(tls.NamedGroup.x25519_ml_kem768)) ++
            array(u16, u8, key_share.ml_kem768_kp.public_key.toBytes() ++ key_share.x25519_kp.public_key) ++
            int(u16, @intFromEnum(tls.NamedGroup.secp256r1)) ++
            array(u16, u8, key_share.secp256r1_kp.public_key.toUncompressedSec1()) ++
            int(u16, @intFromEnum(tls.NamedGroup.secp384r1)) ++
            array(u16, u8, key_share.secp384r1_kp.public_key.toUncompressedSec1()) ++
            int(u16, @intFromEnum(tls.NamedGroup.x25519)) ++
            array(u16, u8, key_share.x25519_kp.public_key),
    ));
    const server_name_extension = int(u16, @intFromEnum(tls.ExtensionType.server_name)) ++
        int(u16, 2 + 1 + 2 + host_len) ++ // byte length of this extension payload
        int(u16, 1 + 2 + host_len) ++ // server_name_list byte count
        .{0x00} ++ // name_type
        int(u16, host_len);
    const server_name_extension_len = switch (options.host) {
        .no_verification => 0,
        .explicit => server_name_extension.len + host_len,
    };

    // ZURL PATCH: `alpn_extension.len` is the one term added to each of
    // ZURL PATCH: the three lengths that follow. The ALPN bytes trail the
    // ZURL PATCH: host on the wire, so every enclosing length counts them
    // ZURL PATCH: exactly the way it counts the host.
    const extensions_header =
        int(u16, @intCast(extensions_payload.len + server_name_extension_len + alpn_extension.len)) ++ // ZURL PATCH
        extensions_payload ++
        server_name_extension;

    const client_hello =
        int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
        client_hello_rand ++
        [1]u8{32} ++ legacy_session_id ++
        cipher_suites ++
        array(u8, tls.CompressionMethod, .{.null}) ++
        extensions_header;

    const out_handshake = .{@intFromEnum(tls.HandshakeType.client_hello)} ++
        int(u24, @intCast(client_hello.len - server_name_extension.len + server_name_extension_len + alpn_extension.len)) ++ // ZURL PATCH
        client_hello;

    var cleartext_header_buf = .{@intFromEnum(tls.ContentType.handshake)} ++ // ZURL PATCH: `var`, for the block below.
        int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_0)) ++
        int(u16, @intCast(out_handshake.len - server_name_extension.len + server_name_extension_len + alpn_extension.len)) ++ // ZURL PATCH
        out_handshake;

    // ZURL PATCH: `--tls-max 1.2` narrows the offer to TLS 1.2 alone.
    // ZURL PATCH:
    // ZURL PATCH: The `supported_versions` extension above is built at
    // ZURL PATCH: compile time, and every length after it is computed from
    // ZURL PATCH: its length, so an entry cannot be dropped without
    // ZURL PATCH: rewriting the whole hello. It can be **replaced**. This
    // ZURL PATCH: writes a GREASE version over the TLS 1.3 entry, which
    // ZURL PATCH: leaves the list two entries long and every length the
    // ZURL PATCH: same. RFC 8701 reserves the GREASE values and requires a
    // ZURL PATCH: server to ignore one it does not know, so the list then
    // ZURL PATCH: offers TLS 1.2 and nothing else. Chrome sends a GREASE
    // ZURL PATCH: version in this same extension on every connection.
    // ZURL PATCH:
    // ZURL PATCH: The offset is comptime. `extensions_payload` and
    // ZURL PATCH: `server_name_extension` are the tail of the buffer, and
    // ZURL PATCH: `supported_versions` is the first extension of the
    // ZURL PATCH: payload: two bytes of type, two of extension length, one
    // ZURL PATCH: of list length, then the entries. The assert reads the
    // ZURL PATCH: bytes back before it writes, so a later edit that moves
    // ZURL PATCH: the extension fails here instead of sending a hello with
    // ZURL PATCH: a corrupted field.
    if (options.max_version == .tls_1_2) { // ZURL PATCH
        const first_entry = cleartext_header_buf.len - server_name_extension.len - // ZURL PATCH
            extensions_payload.len + 2 + 2 + 1; // ZURL PATCH
        const offered = cleartext_header_buf[first_entry..][0..2]; // ZURL PATCH
        assert(std.mem.readInt(u16, offered, .big) == @intFromEnum(tls.ProtocolVersion.tls_1_3)); // ZURL PATCH
        @memcpy(offered, &int(u16, grease_version)); // ZURL PATCH
    } // ZURL PATCH

    const cleartext_header = switch (options.host) {
        .no_verification => cleartext_header_buf[0 .. cleartext_header_buf.len - server_name_extension.len],
        .explicit => &cleartext_header_buf,
    };

    {
        // ZURL PATCH: a third slice, which is the ALPN extension. It goes
        // ZURL PATCH: after the host for the reason the host goes outside
        // ZURL PATCH: the buffer: the buffer is built at compile time and
        // ZURL PATCH: neither length is known then. RFC 8446 section 4.2
        // ZURL PATCH: puts no order on the extensions of a hello, so an
        // ZURL PATCH: extension written last is a legal hello.
        var iovecs: [3][]const u8 = undefined; // ZURL PATCH
        var iovec_len: usize = 1; // ZURL PATCH
        iovecs[0] = cleartext_header; // ZURL PATCH
        if (host.len != 0) { // ZURL PATCH
            iovecs[iovec_len] = host; // ZURL PATCH
            iovec_len += 1; // ZURL PATCH
        } // ZURL PATCH
        if (alpn_extension.len != 0) { // ZURL PATCH
            iovecs[iovec_len] = alpn_extension; // ZURL PATCH
            iovec_len += 1; // ZURL PATCH
        } // ZURL PATCH
        try output.writeVecAll(iovecs[0..iovec_len]); // ZURL PATCH
        try output.flush();
    }

    var tls_version: tls.ProtocolVersion = undefined;
    // ZURL PATCH: the ALPN answer. `alpn_hello` holds what the cleartext
    // ZURL PATCH: Server Hello said, and `alpn_selected` holds what the
    // ZURL PATCH: session keeps. The two are apart because a TLS 1.3
    // ZURL PATCH: server answers ALPN in EncryptedExtensions, so a name in
    // ZURL PATCH: the Server Hello of a TLS 1.3 session is unauthenticated
    // ZURL PATCH: and must be dropped.
    var alpn_hello: AlpnSelection = .none; // ZURL PATCH
    var alpn_selected: AlpnSelection = .none; // ZURL PATCH
    var chain: Certificate.Chain = if (Certificate.Chain != void) .empty;
    defer if (Certificate.Chain != void) chain.deinit();
    // These are used for two purposes:
    // * Detect whether a certificate is the first one presented, in which case
    //   we need to verify the host name.
    var cert_index: usize = 0;
    // * Flip back and forth between the two cleartext buffers in order to keep
    //   the previous certificate in memory so that it can be verified by the
    //   next one.
    var cert_buf_index: usize = 0;
    var write_seq: u64 = 0;
    var read_seq: u64 = 0;
    var prev_cert: Certificate.Parsed = undefined;
    // ZURL PATCH: what the chain rules below need beyond one pair of
    // ZURL PATCH: certificates. `chain_host` is the host this session is
    // ZURL PATCH: for, which every `nameConstraints` of every issuer must
    // ZURL PATCH: allow, and it is null when the caller asked for no host
    // ZURL PATCH: check at all. `trust_checked` says whether the caller
    // ZURL PATCH: asked for a trust check, because the rules of RFC 5280
    // ZURL PATCH: are the trust check and `--insecure` turns it off. See
    // ZURL PATCH: `verifyIssued` and `verifyEndEntity`.
    const chain_host: ?[]const u8 = switch (options.host) { // ZURL PATCH
        .no_verification => null, // ZURL PATCH
        .explicit => |name| name, // ZURL PATCH
    }; // ZURL PATCH
    const trust_checked = options.ca != .no_verification; // ZURL PATCH
    const CipherState = enum {
        /// No cipher is in use
        cleartext,
        /// Handshake cipher is in use
        handshake,
        /// Application cipher is in use
        application,
    };
    var pending_cipher_state: CipherState = .cleartext;
    var cipher_state = pending_cipher_state;
    const HandshakeState = enum {
        /// In this state we expect only a server hello message.
        hello,
        /// In this state we expect only an encrypted_extensions message.
        encrypted_extensions,
        /// In this state we expect certificate handshake messages.
        certificate,
        /// In this state we expect certificate or certificate_verify messages.
        /// certificate messages are ignored since the trust chain is already
        /// established.
        trust_chain_established,
        /// In this state, we expect only the server_hello_done handshake message.
        server_hello_done,
        /// In this state, we expect only the finished handshake message.
        finished,
    };
    var handshake_state: HandshakeState = .hello;
    var handshake_cipher: tls.HandshakeCipher = undefined;
    var main_cert_pub_key: CertificatePublicKey = undefined;
    var tls12_negotiated_group: ?tls.NamedGroup = null;
    const now_sec = options.realtime_now.toSeconds();

    var cleartext_fragment_start: usize = 0;
    var cleartext_fragment_end: usize = 0;
    var cleartext_bufs: [2][tls.max_ciphertext_inner_record_len]u8 = undefined;
    fragment: while (true) {
        // Ensure the input buffer pointer is stable in this scope.
        input.rebase(tls.max_ciphertext_record_len) catch |err| switch (err) {
            error.EndOfStream => {}, // We have assurance the remainder of stream can be buffered.
            error.ReadFailed => |e| return e,
        };
        const record_header = input.peek(tls.record_header_len) catch |err| switch (err) {
            error.EndOfStream => return error.TlsConnectionTruncated,
            error.ReadFailed => |e| return e,
        };
        const record_ct = input.takeEnumNonexhaustive(tls.ContentType, .big) catch unreachable; // already peeked
        input.toss(2); // legacy_version
        const record_len = input.takeInt(u16, .big) catch unreachable; // already peeked
        if (record_len > tls.max_ciphertext_len) return error.TlsRecordOverflow;
        const record_buffer = input.take(record_len) catch |err| switch (err) {
            error.EndOfStream => return error.TlsConnectionTruncated,
            error.ReadFailed => return error.ReadFailed,
        };
        var record_decoder: tls.Decoder = .fromTheirSlice(record_buffer);
        var ctd, const ct = content: switch (cipher_state) {
            .cleartext => .{ record_decoder, record_ct },
            .handshake => {
                assert(tls_version == .tls_1_3);
                if (record_ct != .application_data) return error.TlsUnexpectedMessage;
                try record_decoder.ensure(record_len);
                const cleartext_buf = &cleartext_bufs[cert_buf_index % 2];
                switch (handshake_cipher) {
                    inline else => |*p| {
                        const pv = &p.version.tls_1_3;
                        const P = @TypeOf(p.*).A;
                        if (record_len < P.AEAD.tag_length) return error.TlsRecordOverflow;
                        const ciphertext = record_decoder.slice(record_len - P.AEAD.tag_length);
                        const cleartext_fragment_buf = cleartext_buf[cleartext_fragment_end..];
                        if (ciphertext.len > cleartext_fragment_buf.len) return error.TlsRecordOverflow;
                        const cleartext = cleartext_fragment_buf[0..ciphertext.len];
                        const auth_tag = record_decoder.array(P.AEAD.tag_length).*;
                        const nonce = nonce: {
                            const V = @Vector(P.AEAD.nonce_length, u8);
                            const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                            const operand: V = pad ++ @as([8]u8, @bitCast(big(read_seq)));
                            break :nonce @as(V, pv.server_handshake_iv) ^ operand;
                        };
                        P.AEAD.decrypt(cleartext, ciphertext, auth_tag, record_header, nonce, pv.server_handshake_key) catch
                            return error.TlsBadRecordMac;
                        // TODO use scalar, non-slice version
                        // ZURL PATCH: the fragment this record adds must
                        // ZURL PATCH: hold at least the inner content
                        // ZURL PATCH: type octet. RFC 8446 section 5.4
                        // ZURL PATCH: refuses a record with no non-zero
                        // ZURL PATCH: octet in it, and the guard above
                        // ZURL PATCH: bounds the ciphertext and not the
                        // ZURL PATCH: plaintext, so a record of the tag
                        // ZURL PATCH: alone and a record of zero octets
                        // ZURL PATCH: both reached the subtraction below
                        // ZURL PATCH: with nothing to subtract from.
                        const fragment = mem.trimEnd(u8, cleartext, "\x00"); // ZURL PATCH
                        if (fragment.len == 0) return error.TlsUnexpectedMessage; // ZURL PATCH
                        cleartext_fragment_end += fragment.len; // ZURL PATCH
                    },
                }
                read_seq += 1;
                cleartext_fragment_end -= 1;
                const ct: tls.ContentType = @enumFromInt(cleartext_buf[cleartext_fragment_end]);
                if (ct != .handshake) return error.TlsUnexpectedMessage;
                break :content .{ tls.Decoder.fromTheirSlice(@constCast(cleartext_buf[cleartext_fragment_start..cleartext_fragment_end])), ct };
            },
            .application => {
                assert(tls_version == .tls_1_2);
                if (record_ct != .handshake) return error.TlsUnexpectedMessage;
                try record_decoder.ensure(record_len);
                const cleartext_buf = &cleartext_bufs[cert_buf_index % 2];
                switch (handshake_cipher) {
                    inline else => |*p| {
                        const pv = &p.version.tls_1_2;
                        const P = @TypeOf(p.*).A;
                        if (record_len < P.record_iv_length + P.mac_length) return error.TlsRecordOverflow;
                        const message_len: u16 = record_len - P.record_iv_length - P.mac_length;
                        const cleartext_fragment_buf = cleartext_buf[cleartext_fragment_end..];
                        if (message_len > cleartext_fragment_buf.len) return error.TlsRecordOverflow;
                        const cleartext = cleartext_fragment_buf[0..message_len];
                        const ad = mem.toBytes(big(read_seq)) ++
                            record_header[0 .. 1 + 2] ++
                            mem.toBytes(big(message_len));
                        const record_iv = record_decoder.array(P.record_iv_length).*;
                        const masked_read_seq = read_seq &
                            comptime std.math.shl(u64, std.math.maxInt(u64), 8 * P.record_iv_length);
                        const nonce: [P.AEAD.nonce_length]u8 = nonce: {
                            const V = @Vector(P.AEAD.nonce_length, u8);
                            const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                            const operand: V = pad ++ @as([8]u8, @bitCast(big(masked_read_seq)));
                            break :nonce @as(V, pv.app_cipher.server_write_IV ++ record_iv) ^ operand;
                        };
                        const ciphertext = record_decoder.slice(message_len);
                        const auth_tag = record_decoder.array(P.mac_length);
                        P.AEAD.decrypt(cleartext, ciphertext, auth_tag.*, ad, nonce, pv.app_cipher.server_write_key) catch return error.TlsBadRecordMac;
                        cleartext_fragment_end += message_len;
                    },
                }
                read_seq += 1;
                break :content .{ tls.Decoder.fromTheirSlice(cleartext_buf[cleartext_fragment_start..cleartext_fragment_end]), record_ct };
            },
        };
        switch (ct) {
            .alert => {
                ctd.ensure(2) catch continue :fragment;
                if (options.alert) |a| a.* = .{
                    .level = ctd.decode(tls.Alert.Level),
                    .description = ctd.decode(tls.Alert.Description),
                };
                return error.TlsAlert;
            },
            .change_cipher_spec => {
                ctd.ensure(1) catch continue :fragment;
                if (ctd.decode(tls.ChangeCipherSpecType) != .change_cipher_spec) return error.TlsIllegalParameter;
                cipher_state = pending_cipher_state;
            },
            .handshake => while (true) {
                ctd.ensure(4) catch continue :fragment;
                const handshake_type = ctd.decode(tls.HandshakeType);
                const handshake_len = ctd.decode(u24);
                var hsd = ctd.sub(handshake_len) catch continue :fragment;
                const wrapped_handshake = ctd.buf[ctd.idx - handshake_len - 4 .. ctd.idx];
                switch (handshake_type) {
                    .server_hello => {
                        if (cipher_state != .cleartext) return error.TlsUnexpectedMessage;
                        if (handshake_state != .hello) return error.TlsUnexpectedMessage;
                        try hsd.ensure(2 + 32 + 1);
                        const legacy_version = hsd.decode(u16);
                        @memcpy(&server_hello_rand, hsd.array(32));
                        if (mem.eql(u8, &server_hello_rand, &tls.hello_retry_request_sequence)) {
                            // This is a HelloRetryRequest message. This client implementation
                            // does not expect to get one.
                            return error.TlsUnexpectedMessage;
                        }
                        const legacy_session_id_echo_len = hsd.decode(u8);
                        try hsd.ensure(legacy_session_id_echo_len + 2 + 1);
                        const legacy_session_id_echo = hsd.slice(legacy_session_id_echo_len);
                        const cipher_suite_tag = hsd.decode(tls.CipherSuite);
                        hsd.skip(1); // legacy_compression_method
                        var supported_version: ?u16 = null;
                        if (!hsd.eof()) {
                            try hsd.ensure(2);
                            const extensions_size = hsd.decode(u16);
                            var all_extd = try hsd.sub(extensions_size);
                            while (!all_extd.eof()) {
                                try all_extd.ensure(2 + 2);
                                const et = all_extd.decode(tls.ExtensionType);
                                const ext_size = all_extd.decode(u16);
                                var extd = try all_extd.sub(ext_size);
                                switch (et) {
                                    .supported_versions => {
                                        if (supported_version) |_| return error.TlsIllegalParameter;
                                        try extd.ensure(2);
                                        supported_version = extd.decode(u16);
                                    },
                                    .key_share => {
                                        if (key_share.getSharedSecret()) |_| return error.TlsIllegalParameter;
                                        try extd.ensure(4);
                                        const named_group = extd.decode(tls.NamedGroup);
                                        const key_size = extd.decode(u16);
                                        try extd.ensure(key_size);
                                        try key_share.exchange(named_group, extd.slice(key_size));
                                    },
                                    // ZURL PATCH: RFC 7301. A TLS 1.2 server
                                    // ZURL PATCH: answers ALPN here. A second
                                    // ZURL PATCH: copy of one extension is a
                                    // ZURL PATCH: fault, the way it is for
                                    // ZURL PATCH: `supported_versions` above.
                                    .application_layer_protocol_negotiation => { // ZURL PATCH
                                        if (alpn_hello.len != 0) return error.TlsIllegalParameter; // ZURL PATCH
                                        alpn_hello = try readAlpn(&extd, options.alpn_protocols); // ZURL PATCH
                                    }, // ZURL PATCH
                                    else => {},
                                }
                            }
                        }

                        tls_version = @enumFromInt(supported_version orelse legacy_version);
                        switch (tls_version) {
                            .tls_1_3 => if (!mem.eql(u8, legacy_session_id_echo, &legacy_session_id)) return error.TlsIllegalParameter,
                            // ZURL PATCH: `options.max_version` is the added guard.
                            // ZURL PATCH: RFC 8446 section 4.1.3 asks a client that
                            // ZURL PATCH: **offered** TLS 1.3 to abort on this sentinel,
                            // ZURL PATCH: because it means an attacker took TLS 1.3 out of
                            // ZURL PATCH: the hello. A client that offered TLS 1.2 alone,
                            // ZURL PATCH: which is `--tls-max 1.2`, asked for exactly what
                            // ZURL PATCH: it got, and a server that speaks TLS 1.3 sets the
                            // ZURL PATCH: sentinel anyway. Measured: `--tls-max 1.2` against
                            // ZURL PATCH: cloudflare.com aborted here, where curl runs.
                            .tls_1_2 => if (options.max_version != .tls_1_2 and mem.eql(u8, server_hello_rand[24..31], "DOWNGRD") and // ZURL PATCH
                                server_hello_rand[31] >> 1 == 0x00) return error.TlsIllegalParameter, // ZURL PATCH
                            else => return error.TlsIllegalParameter,
                        }

                        // ZURL PATCH: the cleartext ALPN answer counts only
                        // ZURL PATCH: for TLS 1.2. Over TLS 1.3 the choice
                        // ZURL PATCH: arrives in EncryptedExtensions, so a
                        // ZURL PATCH: name here came from nobody the client
                        // ZURL PATCH: has authenticated and it is dropped.
                        if (tls_version == .tls_1_2) alpn_selected = alpn_hello; // ZURL PATCH

                        switch (cipher_suite_tag) {
                            inline .AES_128_GCM_SHA256,
                            .AES_256_GCM_SHA384,
                            .CHACHA20_POLY1305_SHA256,
                            .AEGIS_256_SHA512,
                            .AEGIS_128L_SHA256,

                            .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                            .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                            .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,

                            // ZURL PATCH: the three suites below are the ECDSA
                            // form of the three above. `CipherSuite.with` maps
                            // both forms to the same record cipher, so this arm
                            // holds for either one.
                            .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // ZURL PATCH
                            .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, // ZURL PATCH
                            .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, // ZURL PATCH
                            => |tag| {
                                handshake_cipher = @unionInit(tls.HandshakeCipher, @tagName(tag.with()), .{
                                    .transcript_hash = .init(.{}),
                                    .version = undefined,
                                });
                                const p = &@field(handshake_cipher, @tagName(tag.with()));
                                p.transcript_hash.update(cleartext_header[tls.record_header_len..]); // Client Hello part 1
                                p.transcript_hash.update(host); // Client Hello part 2
                                p.transcript_hash.update(alpn_extension); // ZURL PATCH: Client Hello part 3.
                                p.transcript_hash.update(wrapped_handshake);
                            },

                            else => return error.TlsIllegalParameter,
                        }
                        switch (tls_version) {
                            .tls_1_3 => {
                                switch (cipher_suite_tag) {
                                    inline .AES_128_GCM_SHA256,
                                    .AES_256_GCM_SHA384,
                                    .CHACHA20_POLY1305_SHA256,
                                    .AEGIS_256_SHA512,
                                    .AEGIS_128L_SHA256,
                                    => |tag| {
                                        const sk = key_share.getSharedSecret() orelse return error.TlsIllegalParameter;
                                        const p = &@field(handshake_cipher, @tagName(tag.with()));
                                        const P = @TypeOf(p.*).A;
                                        const hello_hash = p.transcript_hash.peek();
                                        const zeroes = [1]u8{0} ** P.Hash.digest_length;
                                        const early_secret = P.Hkdf.extract(&[1]u8{0}, &zeroes);
                                        const empty_hash = tls.emptyHash(P.Hash);
                                        p.version = .{ .tls_1_3 = undefined };
                                        const pv = &p.version.tls_1_3;
                                        const hs_derived_secret = hkdfExpandLabel(P.Hkdf, early_secret, "derived", &empty_hash, P.Hash.digest_length);
                                        pv.handshake_secret = P.Hkdf.extract(&hs_derived_secret, sk);
                                        const ap_derived_secret = hkdfExpandLabel(P.Hkdf, pv.handshake_secret, "derived", &empty_hash, P.Hash.digest_length);
                                        pv.master_secret = P.Hkdf.extract(&ap_derived_secret, &zeroes);
                                        const client_secret = hkdfExpandLabel(P.Hkdf, pv.handshake_secret, "c hs traffic", &hello_hash, P.Hash.digest_length);
                                        const server_secret = hkdfExpandLabel(P.Hkdf, pv.handshake_secret, "s hs traffic", &hello_hash, P.Hash.digest_length);
                                        if (options.ssl_key_log) |key_log| logSecrets(key_log.writer, .{
                                            .client_random = &client_hello_rand,
                                        }, .{
                                            .SERVER_HANDSHAKE_TRAFFIC_SECRET = &server_secret,
                                            .CLIENT_HANDSHAKE_TRAFFIC_SECRET = &client_secret,
                                        });
                                        pv.client_finished_key = hkdfExpandLabel(P.Hkdf, client_secret, "finished", "", P.Hmac.key_length);
                                        pv.server_finished_key = hkdfExpandLabel(P.Hkdf, server_secret, "finished", "", P.Hmac.key_length);
                                        pv.client_handshake_key = hkdfExpandLabel(P.Hkdf, client_secret, "key", "", P.AEAD.key_length);
                                        pv.server_handshake_key = hkdfExpandLabel(P.Hkdf, server_secret, "key", "", P.AEAD.key_length);
                                        pv.client_handshake_iv = hkdfExpandLabel(P.Hkdf, client_secret, "iv", "", P.AEAD.nonce_length);
                                        pv.server_handshake_iv = hkdfExpandLabel(P.Hkdf, server_secret, "iv", "", P.AEAD.nonce_length);
                                    },
                                    else => return error.TlsIllegalParameter,
                                }
                                pending_cipher_state = .handshake;
                                handshake_state = .encrypted_extensions;
                            },
                            .tls_1_2 => switch (cipher_suite_tag) {
                                .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                                .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,

                                // ZURL PATCH: the ECDSA form of the three
                                // suites above. The key exchange is ECDHE for
                                // both forms, and `verifySignature` reads the
                                // signature algorithm from the message and the
                                // key type from the certificate, so the path
                                // after this point needs no change.
                                .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // ZURL PATCH
                                .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, // ZURL PATCH
                                .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, // ZURL PATCH
                                => handshake_state = .certificate,
                                else => return error.TlsIllegalParameter,
                            },
                            else => return error.TlsIllegalParameter,
                        }
                    },
                    .encrypted_extensions => {
                        if (tls_version != .tls_1_3) return error.TlsUnexpectedMessage;
                        if (cipher_state != .handshake) return error.TlsUnexpectedMessage;
                        if (handshake_state != .encrypted_extensions) return error.TlsUnexpectedMessage;
                        switch (handshake_cipher) {
                            inline else => |*p| p.transcript_hash.update(wrapped_handshake),
                        }
                        try hsd.ensure(2);
                        const total_ext_size = hsd.decode(u16);
                        var all_extd = try hsd.sub(total_ext_size);
                        while (!all_extd.eof()) {
                            try all_extd.ensure(4);
                            const et = all_extd.decode(tls.ExtensionType);
                            const ext_size = all_extd.decode(u16);
                            const extd = try all_extd.sub(ext_size);
                            var alpn_extd = extd; // ZURL PATCH: a copy the arm below consumes. It stands where upstream discards `extd`, so the line above is upstream's own.
                            switch (et) {
                                .server_name => {},
                                // ZURL PATCH: RFC 7301. A TLS 1.3 server
                                // ZURL PATCH: answers ALPN here, inside the
                                // ZURL PATCH: handshake encryption, so this
                                // ZURL PATCH: name is authenticated.
                                .application_layer_protocol_negotiation => { // ZURL PATCH
                                    if (alpn_selected.len != 0) return error.TlsIllegalParameter; // ZURL PATCH
                                    alpn_selected = try readAlpn(&alpn_extd, options.alpn_protocols); // ZURL PATCH
                                }, // ZURL PATCH
                                else => {},
                            }
                        }
                        handshake_state = .certificate;
                    },
                    .certificate => cert: {
                        if (cipher_state == .application) return error.TlsUnexpectedMessage;
                        switch (handshake_state) {
                            .certificate => {},
                            .trust_chain_established => break :cert,
                            else => return error.TlsUnexpectedMessage,
                        }
                        switch (handshake_cipher) {
                            inline else => |*p| p.transcript_hash.update(wrapped_handshake),
                        }

                        switch (tls_version) {
                            .tls_1_3 => {
                                try hsd.ensure(1 + 3);
                                const cert_req_ctx_len = hsd.decode(u8);
                                if (cert_req_ctx_len != 0) return error.TlsIllegalParameter;
                            },
                            .tls_1_2 => try hsd.ensure(3),
                            else => unreachable,
                        }
                        const certs_size = hsd.decode(u24);
                        const certs = try hsd.sub(certs_size);

                        var certs_decoder = certs;
                        while (!certs_decoder.eof()) {
                            try certs_decoder.ensure(3);
                            const cert_size = certs_decoder.decode(u24);
                            const certd = try certs_decoder.sub(cert_size);

                            if (tls_version == .tls_1_3) {
                                try certs_decoder.ensure(2);
                                const total_ext_size = certs_decoder.decode(u16);
                                const all_extd = try certs_decoder.sub(total_ext_size);
                                _ = all_extd;
                            }

                            const subject_cert: Certificate = .{
                                .buffer = certd.buf,
                                .index = @intCast(certd.idx),
                            };
                            const subject = try certificate.parse(subject_cert); // ZURL PATCH: the bounded reader. Upstream `parse` walks these bytes with no bound, and the host check below runs after it, so six octets from any server panicked this walk before anything was authenticated. See `certificate.zig`.
                            try verifyCertificateStrength(subject, trust_checked); // ZURL PATCH: the cryptographic floor of every certificate the peer sent, and not of the leaf alone. See `verifyCertificateStrength`.
                            if (cert_index == 0) {
                                try verifyEndEntity(subject, trust_checked); // ZURL PATCH: the rules a leaf must obey on its own: a critical extension nobody reads, and an extended key usage that is not server authentication. See `verifyEndEntity`.
                                // Verify the host on the first certificate.
                                switch (options.host) {
                                    .no_verification => {},
                                    .explicit => try verifyHost(subject, host), // ZURL PATCH: an address needs an iPAddress name. See the appended block.
                                }

                                // Keep track of the public key for the
                                // certificate_verify message later.
                                try main_cert_pub_key.init(subject.pub_key_algo, subject.pubKey());
                            } else {
                                try verifyIssued(prev_cert, subject, chain_host, cert_index - 1, now_sec); // ZURL PATCH: an issuer must be a certificate authority, and it must allow the host this session is for. See `verifyIssued`.
                            }

                            switch (options.ca) {
                                .no_verification => {
                                    handshake_state = .trust_chain_established;
                                    break :cert;
                                },
                                .self_signed => {
                                    try subject.verify(subject, now_sec);
                                    handshake_state = .trust_chain_established;
                                    break :cert;
                                },
                                .bundle => |ca| if (verify: {
                                    try ca.lock.lockShared(ca.io);
                                    defer ca.lock.unlockShared(ca.io);
                                    break :verify ca.bundle.verify(subject, now_sec);
                                }) {
                                    handshake_state = .trust_chain_established;
                                    break :cert;
                                } else |err| switch (err) {
                                    error.CertificateIssuerNotFound => {},
                                    else => |e| return e,
                                },
                            }

                            prev_cert = subject;
                            cert_index += 1;
                        }

                        if (Certificate.Chain != void) {
                            certs_decoder = certs;
                            while (!certs_decoder.eof()) {
                                try certs_decoder.ensure(3);
                                const cert_size = certs_decoder.decode(u24);
                                const certd = try certs_decoder.sub(cert_size);
                                chain.addCert(certd.rest()) catch |err| switch (err) {
                                    error.Unexpected => return error.TlsCertificateNotVerified,
                                };
                                if (tls_version == .tls_1_3) {
                                    try certs_decoder.ensure(2);
                                    const total_ext_size = certs_decoder.decode(u16);
                                    const all_extd = try certs_decoder.sub(total_ext_size);
                                    _ = all_extd;
                                }
                            }
                        }

                        cert_buf_index += 1;
                    },
                    .server_key_exchange => {
                        if (tls_version != .tls_1_2) return error.TlsUnexpectedMessage;
                        if (cipher_state != .cleartext) return error.TlsUnexpectedMessage;
                        switch (handshake_state) {
                            .trust_chain_established => {},
                            .certificate => try tryDownloadRootCert(&chain, &options),
                            else => return error.TlsUnexpectedMessage,
                        }

                        switch (handshake_cipher) {
                            inline else => |*p| p.transcript_hash.update(wrapped_handshake),
                        }
                        try hsd.ensure(1 + 2 + 1);
                        const curve_type = hsd.decode(u8);
                        if (curve_type != 0x03) return error.TlsIllegalParameter; // named_curve
                        const named_group = hsd.decode(tls.NamedGroup);
                        tls12_negotiated_group = named_group;
                        const key_size = hsd.decode(u8);
                        try hsd.ensure(key_size);
                        const server_pub_key = hsd.slice(key_size);
                        // ZURL PATCH: `verifySignature` now takes the version,
                        // because TLS 1.2 and TLS 1.3 read an ECDSA scheme
                        // name differently.
                        try main_cert_pub_key.verifySignature(&hsd, &.{ &client_hello_rand, &server_hello_rand, hsd.buf[0..hsd.idx] }, tls_version); // ZURL PATCH
                        try key_share.exchange(named_group, server_pub_key);
                        handshake_state = .server_hello_done;
                    },
                    .server_hello_done => {
                        if (tls_version != .tls_1_2) return error.TlsUnexpectedMessage;
                        if (cipher_state != .cleartext) return error.TlsUnexpectedMessage;
                        if (handshake_state != .server_hello_done) return error.TlsUnexpectedMessage;

                        const public_key_bytes: []const u8 = switch (tls12_negotiated_group orelse .secp256r1) {
                            .secp256r1 => &key_share.secp256r1_kp.public_key.toUncompressedSec1(),
                            .secp384r1 => &key_share.secp384r1_kp.public_key.toUncompressedSec1(),
                            .x25519 => &key_share.x25519_kp.public_key,
                            else => return error.TlsIllegalParameter,
                        };

                        const client_key_exchange_prefix = .{@intFromEnum(tls.ContentType.handshake)} ++
                            int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                            int(u16, @intCast(public_key_bytes.len + 5)) ++ // record length
                            .{@intFromEnum(tls.HandshakeType.client_key_exchange)} ++
                            int(u24, @intCast(public_key_bytes.len + 1)) ++ // handshake message length
                            .{@as(u8, @intCast(public_key_bytes.len))}; // public key length
                        const client_change_cipher_spec_msg = .{@intFromEnum(tls.ContentType.change_cipher_spec)} ++
                            int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                            array(u16, tls.ChangeCipherSpecType, .{.change_cipher_spec});
                        const pre_master_secret = key_share.getSharedSecret().?;
                        switch (handshake_cipher) {
                            inline else => |*p| {
                                const P = @TypeOf(p.*).A;
                                p.transcript_hash.update(wrapped_handshake);
                                p.transcript_hash.update(client_key_exchange_prefix[tls.record_header_len..]);
                                p.transcript_hash.update(public_key_bytes);
                                const master_secret = hmacExpandLabel(P.Hmac, pre_master_secret, &.{
                                    "master secret",
                                    &client_hello_rand,
                                    &server_hello_rand,
                                }, 48);
                                if (options.ssl_key_log) |key_log| logSecrets(key_log.writer, .{
                                    .client_random = &client_hello_rand,
                                }, .{
                                    .CLIENT_RANDOM = &master_secret,
                                });
                                const key_block = hmacExpandLabel(
                                    P.Hmac,
                                    &master_secret,
                                    &.{ "key expansion", &server_hello_rand, &client_hello_rand },
                                    @sizeOf(P.Tls_1_2),
                                );
                                const client_verify_cleartext = .{@intFromEnum(tls.HandshakeType.finished)} ++
                                    array(u24, u8, hmacExpandLabel(
                                        P.Hmac,
                                        &master_secret,
                                        &.{ "client finished", &p.transcript_hash.peek() },
                                        P.verify_data_length,
                                    ));
                                p.transcript_hash.update(&client_verify_cleartext);
                                p.version = .{ .tls_1_2 = .{
                                    .expected_server_verify_data = hmacExpandLabel(
                                        P.Hmac,
                                        &master_secret,
                                        &.{ "server finished", &p.transcript_hash.finalResult() },
                                        P.verify_data_length,
                                    ),
                                    .app_cipher = mem.bytesToValue(P.Tls_1_2, &key_block),
                                } };
                                const pv = &p.version.tls_1_2;
                                const nonce: [P.AEAD.nonce_length]u8 = nonce: {
                                    const V = @Vector(P.AEAD.nonce_length, u8);
                                    const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                                    const operand: V = pad ++ @as([8]u8, @bitCast(big(write_seq)));
                                    break :nonce @as(V, pv.app_cipher.client_write_IV ++ pv.app_cipher.client_salt) ^ operand;
                                };
                                var client_verify_msg = .{@intFromEnum(tls.ContentType.handshake)} ++
                                    int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                                    array(u16, u8, nonce[P.fixed_iv_length..].* ++
                                        @as([client_verify_cleartext.len + P.mac_length]u8, undefined));
                                P.AEAD.encrypt(
                                    client_verify_msg[client_verify_msg.len - P.mac_length -
                                        client_verify_cleartext.len ..][0..client_verify_cleartext.len],
                                    client_verify_msg[client_verify_msg.len - P.mac_length ..][0..P.mac_length],
                                    &client_verify_cleartext,
                                    mem.toBytes(big(write_seq)) ++ client_verify_msg[0 .. 1 + 2] ++ int(u16, client_verify_cleartext.len),
                                    nonce,
                                    pv.app_cipher.client_write_key,
                                );
                                var all_msgs_vec: [4][]const u8 = .{
                                    &client_key_exchange_prefix,
                                    public_key_bytes,
                                    &client_change_cipher_spec_msg,
                                    &client_verify_msg,
                                };
                                try output.writeVecAll(&all_msgs_vec);
                                try output.flush();
                            },
                        }
                        write_seq += 1;
                        pending_cipher_state = .application;
                        handshake_state = .finished;
                    },
                    .certificate_verify => {
                        if (tls_version != .tls_1_3) return error.TlsUnexpectedMessage;
                        if (cipher_state != .handshake) return error.TlsUnexpectedMessage;
                        switch (handshake_state) {
                            .trust_chain_established => {},
                            .certificate => try tryDownloadRootCert(&chain, &options),
                            else => return error.TlsUnexpectedMessage,
                        }
                        switch (handshake_cipher) {
                            inline else => |*p| {
                                try main_cert_pub_key.verifySignature(&hsd, &.{
                                    " " ** 64 ++ "TLS 1.3, server CertificateVerify\x00",
                                    &p.transcript_hash.peek(),
                                    // ZURL PATCH: the version is what keeps
                                    // this call strict about the curve.
                                }, tls_version); // ZURL PATCH
                                p.transcript_hash.update(wrapped_handshake);
                            },
                        }
                        handshake_state = .finished;
                    },
                    .finished => {
                        if (cipher_state == .cleartext) return error.TlsUnexpectedMessage;
                        if (handshake_state != .finished) return error.TlsUnexpectedMessage;
                        // This message is to trick buggy proxies into behaving correctly.
                        const client_change_cipher_spec_msg = .{@intFromEnum(tls.ContentType.change_cipher_spec)} ++
                            int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                            array(u16, tls.ChangeCipherSpecType, .{.change_cipher_spec});
                        const app_cipher = app_cipher: switch (handshake_cipher) {
                            inline else => |*p, tag| switch (tls_version) {
                                .tls_1_3 => {
                                    const pv = &p.version.tls_1_3;
                                    const P = @TypeOf(p.*).A;
                                    try hsd.ensure(P.Hmac.mac_length);
                                    const finished_digest = p.transcript_hash.peek();
                                    p.transcript_hash.update(wrapped_handshake);
                                    const expected_server_verify_data = tls.hmac(P.Hmac, &finished_digest, pv.server_finished_key);
                                    if (!std.crypto.timing_safe.eql([P.Hmac.mac_length]u8, expected_server_verify_data, hsd.array(P.Hmac.mac_length).*)) return error.TlsDecryptError;
                                    const handshake_hash = p.transcript_hash.finalResult();
                                    const verify_data = tls.hmac(P.Hmac, &handshake_hash, pv.client_finished_key);
                                    const out_cleartext = .{@intFromEnum(tls.HandshakeType.finished)} ++
                                        array(u24, u8, verify_data) ++
                                        .{@intFromEnum(tls.ContentType.handshake)};

                                    const wrapped_len = out_cleartext.len + P.AEAD.tag_length;

                                    var finished_msg = .{@intFromEnum(tls.ContentType.application_data)} ++
                                        int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                                        array(u16, u8, @as([wrapped_len]u8, undefined));

                                    const ad = finished_msg[0..tls.record_header_len];
                                    const ciphertext = finished_msg[tls.record_header_len..][0..out_cleartext.len];
                                    const auth_tag = finished_msg[finished_msg.len - P.AEAD.tag_length ..];
                                    const nonce = pv.client_handshake_iv;
                                    P.AEAD.encrypt(ciphertext, auth_tag, &out_cleartext, ad, nonce, pv.client_handshake_key);

                                    var all_msgs_vec: [2][]const u8 = .{
                                        &client_change_cipher_spec_msg,
                                        &finished_msg,
                                    };
                                    try output.writeVecAll(&all_msgs_vec);
                                    try output.flush();

                                    const client_secret = hkdfExpandLabel(P.Hkdf, pv.master_secret, "c ap traffic", &handshake_hash, P.Hash.digest_length);
                                    const server_secret = hkdfExpandLabel(P.Hkdf, pv.master_secret, "s ap traffic", &handshake_hash, P.Hash.digest_length);
                                    if (options.ssl_key_log) |key_log| logSecrets(key_log.writer, .{
                                        .counter = key_seq,
                                        .client_random = &client_hello_rand,
                                    }, .{
                                        .SERVER_TRAFFIC_SECRET = &server_secret,
                                        .CLIENT_TRAFFIC_SECRET = &client_secret,
                                    });
                                    key_seq += 1;
                                    break :app_cipher @unionInit(tls.ApplicationCipher, @tagName(tag), .{ .tls_1_3 = .{
                                        .client_secret = client_secret,
                                        .server_secret = server_secret,
                                        .client_key = hkdfExpandLabel(P.Hkdf, client_secret, "key", "", P.AEAD.key_length),
                                        .server_key = hkdfExpandLabel(P.Hkdf, server_secret, "key", "", P.AEAD.key_length),
                                        .client_iv = hkdfExpandLabel(P.Hkdf, client_secret, "iv", "", P.AEAD.nonce_length),
                                        .server_iv = hkdfExpandLabel(P.Hkdf, server_secret, "iv", "", P.AEAD.nonce_length),
                                    } });
                                },
                                .tls_1_2 => {
                                    const pv = &p.version.tls_1_2;
                                    const P = @TypeOf(p.*).A;
                                    try hsd.ensure(P.verify_data_length);
                                    if (!std.crypto.timing_safe.eql([P.verify_data_length]u8, pv.expected_server_verify_data, hsd.array(P.verify_data_length).*)) return error.TlsDecryptError;
                                    break :app_cipher @unionInit(tls.ApplicationCipher, @tagName(tag), .{ .tls_1_2 = pv.app_cipher });
                                },
                                else => unreachable,
                            },
                        };
                        if (options.ssl_key_log) |ssl_key_log| ssl_key_log.* = .{
                            .client_key_seq = key_seq,
                            .server_key_seq = key_seq,
                            .client_random = client_hello_rand,
                            .writer = ssl_key_log.writer,
                        };
                        return .{
                            .input = input,
                            .reader = .{
                                .buffer = options.read_buffer,
                                .vtable = &.{
                                    .stream = stream,
                                    .readVec = readVec,
                                },
                                .seek = 0,
                                .end = 0,
                            },
                            .output = output,
                            .writer = .{
                                .buffer = options.write_buffer,
                                .vtable = &.{
                                    .drain = drain,
                                    .flush = flush,
                                },
                            },
                            .tls_version = tls_version,
                            .read_seq = switch (tls_version) {
                                .tls_1_3 => 0,
                                .tls_1_2 => read_seq,
                                else => unreachable,
                            },
                            .write_seq = switch (tls_version) {
                                .tls_1_3 => 0,
                                .tls_1_2 => write_seq,
                                else => unreachable,
                            },
                            .received_close_notify = false,
                            .allow_truncation_attacks = options.allow_truncation_attacks,
                            .application_cipher = app_cipher,
                            .ssl_key_log = options.ssl_key_log,
                            .alpn = alpn_selected, // ZURL PATCH
                        };
                    },
                    else => return error.TlsUnexpectedMessage,
                }
                if (ctd.eof()) break;
                cleartext_fragment_start = ctd.idx;
            },
            else => return error.TlsUnexpectedMessage,
        }
        cleartext_fragment_start = 0;
        cleartext_fragment_end = 0;
    }
}

fn drain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
    const c: *Client = @alignCast(@fieldParentPtr("writer", w));
    const output = c.output;
    const ciphertext_buf = try output.writableSliceGreedy(min_buffer_len);
    var ciphertext_end: usize = 0;
    var total_clear: usize = 0;
    done: {
        {
            const buf = w.buffered();
            const prepared = prepareCiphertextRecord(c, ciphertext_buf[ciphertext_end..], buf, .application_data);
            total_clear += prepared.cleartext_len;
            ciphertext_end += prepared.ciphertext_end;
            if (prepared.cleartext_len < buf.len) break :done;
        }
        for (data[0 .. data.len - 1]) |buf| {
            const prepared = prepareCiphertextRecord(c, ciphertext_buf[ciphertext_end..], buf, .application_data);
            total_clear += prepared.cleartext_len;
            ciphertext_end += prepared.ciphertext_end;
            if (prepared.cleartext_len < buf.len) break :done;
        }
        const buf = data[data.len - 1];
        for (0..splat) |_| {
            const prepared = prepareCiphertextRecord(c, ciphertext_buf[ciphertext_end..], buf, .application_data);
            total_clear += prepared.cleartext_len;
            ciphertext_end += prepared.ciphertext_end;
            if (prepared.cleartext_len < buf.len) break :done;
        }
    }
    output.advance(ciphertext_end);
    return w.consume(total_clear);
}

fn flush(w: *Writer) Writer.Error!void {
    const c: *Client = @alignCast(@fieldParentPtr("writer", w));
    const output = c.output;
    const ciphertext_buf = try output.writableSliceGreedy(min_buffer_len);
    const prepared = prepareCiphertextRecord(c, ciphertext_buf, w.buffered(), .application_data);
    output.advance(prepared.ciphertext_end);
    w.end = 0;
}

/// Sends a `close_notify` alert, which is necessary for the server to
/// distinguish between a properly finished TLS session, or a truncation
/// attack.
pub fn end(c: *Client) Writer.Error!void {
    try flush(&c.writer);
    const output = c.output;
    const ciphertext_buf = try output.writableSliceGreedy(min_buffer_len);
    const prepared = prepareCiphertextRecord(c, ciphertext_buf, &tls.close_notify_alert, .alert);
    output.advance(prepared.ciphertext_end);
}

fn prepareCiphertextRecord(
    c: *Client,
    ciphertext_buf: []u8,
    bytes: []const u8,
    inner_content_type: tls.ContentType,
) struct {
    ciphertext_end: usize,
    cleartext_len: usize,
} {
    // ZURL PATCH: the write keys and `write_seq` are read and written
    // ZURL PATCH: below. A session that two tasks drive holds the lock for
    // ZURL PATCH: as long as this runs, so a `key_update` on the read path
    // ZURL PATCH: cannot rotate a key under a record that is half
    // ZURL PATCH: encrypted, and `write_seq` counts up once for each
    // ZURL PATCH: record whoever writes it.
    // ZURL PATCH:
    // ZURL PATCH: **No syscall runs under this lock.** The caller asks
    // ZURL PATCH: `output` for room before it calls this, so the flush
    // ZURL PATCH: that a full socket buffer needs has already happened.
    // ZURL PATCH: What is left is the AEAD, which is arithmetic.
    if (c.write_lock) |lock| lock.acquire(); // ZURL PATCH
    defer if (c.write_lock) |lock| lock.release(); // ZURL PATCH
    // Due to the trailing inner content type byte in the ciphertext, we need
    // an additional buffer for storing the cleartext into before encrypting.
    var cleartext_buf: [max_ciphertext_len]u8 = undefined;
    var ciphertext_end: usize = 0;
    var bytes_i: usize = 0;
    switch (c.application_cipher) {
        inline else => |*p| switch (c.tls_version) {
            .tls_1_3 => {
                const pv = &p.tls_1_3;
                const P = @TypeOf(p.*);
                const overhead_len = tls.record_header_len + P.AEAD.tag_length + 1;
                while (true) {
                    const encrypted_content_len: u16 = @min(
                        bytes.len - bytes_i,
                        tls.max_ciphertext_inner_record_len,
                        ciphertext_buf.len -| (overhead_len + ciphertext_end),
                    );
                    if (encrypted_content_len == 0) return .{
                        .ciphertext_end = ciphertext_end,
                        .cleartext_len = bytes_i,
                    };

                    @memcpy(cleartext_buf[0..encrypted_content_len], bytes[bytes_i..][0..encrypted_content_len]);
                    cleartext_buf[encrypted_content_len] = @intFromEnum(inner_content_type);
                    bytes_i += encrypted_content_len;
                    const ciphertext_len = encrypted_content_len + 1;
                    const cleartext = cleartext_buf[0..ciphertext_len];

                    const ad = ciphertext_buf[ciphertext_end..][0..tls.record_header_len];
                    ad.* = .{@intFromEnum(tls.ContentType.application_data)} ++
                        int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                        int(u16, ciphertext_len + P.AEAD.tag_length);
                    ciphertext_end += ad.len;
                    const ciphertext = ciphertext_buf[ciphertext_end..][0..ciphertext_len];
                    ciphertext_end += ciphertext_len;
                    const auth_tag = ciphertext_buf[ciphertext_end..][0..P.AEAD.tag_length];
                    ciphertext_end += auth_tag.len;
                    const nonce = nonce: {
                        const V = @Vector(P.AEAD.nonce_length, u8);
                        const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                        const operand: V = pad ++ mem.toBytes(big(c.write_seq));
                        break :nonce @as(V, pv.client_iv) ^ operand;
                    };
                    P.AEAD.encrypt(ciphertext, auth_tag, cleartext, ad, nonce, pv.client_key);
                    c.write_seq += 1; // TODO send key_update on overflow
                }
            },
            .tls_1_2 => {
                const pv = &p.tls_1_2;
                const P = @TypeOf(p.*);
                const overhead_len = tls.record_header_len + P.record_iv_length + P.mac_length;
                while (true) {
                    const message_len: u16 = @min(
                        bytes.len - bytes_i,
                        tls.max_ciphertext_inner_record_len,
                        ciphertext_buf.len -| (overhead_len + ciphertext_end),
                    );
                    if (message_len == 0) return .{
                        .ciphertext_end = ciphertext_end,
                        .cleartext_len = bytes_i,
                    };

                    @memcpy(cleartext_buf[0..message_len], bytes[bytes_i..][0..message_len]);
                    bytes_i += message_len;
                    const cleartext = cleartext_buf[0..message_len];

                    const record_header = ciphertext_buf[ciphertext_end..][0..tls.record_header_len];
                    ciphertext_end += tls.record_header_len;
                    record_header.* = .{@intFromEnum(inner_content_type)} ++
                        int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                        int(u16, P.record_iv_length + message_len + P.mac_length);
                    const ad = mem.toBytes(big(c.write_seq)) ++ record_header[0 .. 1 + 2] ++ int(u16, message_len);
                    const record_iv = ciphertext_buf[ciphertext_end..][0..P.record_iv_length];
                    ciphertext_end += P.record_iv_length;
                    const nonce: [P.AEAD.nonce_length]u8 = nonce: {
                        const V = @Vector(P.AEAD.nonce_length, u8);
                        const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                        const operand: V = pad ++ @as([8]u8, @bitCast(big(c.write_seq)));
                        break :nonce @as(V, pv.client_write_IV ++ pv.client_salt) ^ operand;
                    };
                    record_iv.* = nonce[P.fixed_iv_length..].*;
                    const ciphertext = ciphertext_buf[ciphertext_end..][0..message_len];
                    ciphertext_end += message_len;
                    const auth_tag = ciphertext_buf[ciphertext_end..][0..P.mac_length];
                    ciphertext_end += P.mac_length;
                    P.AEAD.encrypt(ciphertext, auth_tag, cleartext, ad, nonce, pv.client_write_key);
                    c.write_seq += 1; // TODO send key_update on overflow
                }
            },
            else => unreachable,
        },
    }
}

pub fn eof(c: Client) bool {
    return c.received_close_notify;
}

fn stream(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
    // This function writes exclusively to the buffer.
    _ = w;
    _ = limit;
    const c: *Client = @alignCast(@fieldParentPtr("reader", r));
    return readIndirect(c);
}

fn readVec(r: *Reader, data: [][]u8) Reader.Error!usize {
    // This function writes exclusively to the buffer.
    _ = data;
    const c: *Client = @alignCast(@fieldParentPtr("reader", r));
    return readIndirect(c);
}

fn readIndirect(c: *Client) Reader.Error!usize {
    const r = &c.reader;
    if (c.eof()) return error.EndOfStream;
    const input = c.input;
    // If at least one full encrypted record is not buffered, read once.
    const record_header = input.peek(tls.record_header_len) catch |err| switch (err) {
        error.EndOfStream => {
            // This is either a truncation attack, a bug in the server, or an
            // intentional omission of the close_notify message due to truncation
            // detection handled above the TLS layer.
            if (c.allow_truncation_attacks) {
                c.received_close_notify = true;
                return error.EndOfStream;
            } else {
                return failRead(c, error.TlsConnectionTruncated);
            }
        },
        error.ReadFailed => return error.ReadFailed,
    };
    const ct: tls.ContentType = @enumFromInt(record_header[0]);
    const legacy_version = mem.readInt(u16, record_header[1..][0..2], .big);
    _ = legacy_version;
    const record_len = mem.readInt(u16, record_header[3..][0..2], .big);
    if (record_len > max_ciphertext_len) return failRead(c, error.TlsRecordOverflow);
    const record_end = 5 + record_len;
    if (record_end > input.buffered().len) {
        input.fillMore() catch |err| switch (err) {
            error.EndOfStream => return failRead(c, error.TlsConnectionTruncated),
            error.ReadFailed => return error.ReadFailed,
        };
        if (record_end > input.buffered().len) return 0;
    }

    const cleartext_len, const inner_ct: tls.ContentType = cleartext: switch (c.application_cipher) {
        inline else => |*p| switch (c.tls_version) {
            .tls_1_3 => {
                const pv = &p.tls_1_3;
                const P = @TypeOf(p.*);
                const ad = input.take(tls.record_header_len) catch unreachable; // already peeked
                // ZURL PATCH: the record must be at least as long as the
                // ZURL PATCH: tag it ends with. The only length check
                // ZURL PATCH: above bounds `record_len` from above, so
                // ZURL PATCH: five octets from the server, `17 03 03 00
                // ZURL PATCH: 00`, made this subtraction wrap to 65520.
                // ZURL PATCH: The `take` below then failed into a `catch
                // ZURL PATCH: unreachable`, which is undefined behaviour
                // ZURL PATCH: in the build a user runs. The handshake
                // ZURL PATCH: loop in `init` carries the same bound.
                if (record_len < P.AEAD.tag_length) return failRead(c, error.TlsRecordOverflow); // ZURL PATCH
                const ciphertext_len = record_len - P.AEAD.tag_length;
                const ciphertext = input.take(ciphertext_len) catch unreachable; // already peeked
                const auth_tag = (input.takeArray(P.AEAD.tag_length) catch unreachable).*; // already peeked
                const nonce = nonce: {
                    const V = @Vector(P.AEAD.nonce_length, u8);
                    const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                    const operand: V = pad ++ mem.toBytes(big(c.read_seq));
                    break :nonce @as(V, pv.server_iv) ^ operand;
                };
                rebase(r, ciphertext.len);
                const cleartext = r.buffer[r.end..][0..ciphertext.len];
                P.AEAD.decrypt(cleartext, ciphertext, auth_tag, ad, nonce, pv.server_key) catch
                    return failRead(c, error.TlsBadRecordMac);
                // TODO use scalar, non-slice version
                const msg = mem.trimEnd(u8, cleartext, "\x00");
                // ZURL PATCH: RFC 8446 section 5.4 makes a plaintext of
                // ZURL PATCH: all zero octets a record to refuse: it
                // ZURL PATCH: carries no inner content type at all.
                // ZURL PATCH: Without this line both reads below use the
                // ZURL PATCH: largest `usize`, so the content type comes
                // ZURL PATCH: from the octet before the buffer and the
                // ZURL PATCH: length of the message is 16 exabytes.
                if (msg.len == 0) return failRead(c, error.TlsUnexpectedMessage); // ZURL PATCH
                break :cleartext .{ msg.len - 1, @enumFromInt(msg[msg.len - 1]) };
            },
            .tls_1_2 => {
                const pv = &p.tls_1_2;
                const P = @TypeOf(p.*);
                // ZURL PATCH: the record must hold the explicit IV and
                // ZURL PATCH: the tag before it holds any message. The
                // ZURL PATCH: same bound as the TLS 1.3 arm above, and
                // ZURL PATCH: the same one the handshake loop in `init`
                // ZURL PATCH: already carries. Without it a short record
                // ZURL PATCH: wraps `message_len` and the `take` below
                // ZURL PATCH: falls into a `catch unreachable`.
                if (record_len < P.record_iv_length + P.mac_length) return failRead(c, error.TlsRecordOverflow); // ZURL PATCH
                const message_len: u16 = record_len - P.record_iv_length - P.mac_length;
                const ad_header = input.take(tls.record_header_len) catch unreachable; // already peeked
                const ad = mem.toBytes(big(c.read_seq)) ++
                    ad_header[0 .. 1 + 2] ++
                    mem.toBytes(big(message_len));
                const record_iv = (input.takeArray(P.record_iv_length) catch unreachable).*; // already peeked
                const masked_read_seq = c.read_seq &
                    comptime std.math.shl(u64, std.math.maxInt(u64), 8 * P.record_iv_length);
                const nonce: [P.AEAD.nonce_length]u8 = nonce: {
                    const V = @Vector(P.AEAD.nonce_length, u8);
                    const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                    const operand: V = pad ++ @as([8]u8, @bitCast(big(masked_read_seq)));
                    break :nonce @as(V, pv.server_write_IV ++ record_iv) ^ operand;
                };
                const ciphertext = input.take(message_len) catch unreachable; // already peeked
                const auth_tag = (input.takeArray(P.mac_length) catch unreachable).*; // already peeked
                rebase(r, ciphertext.len);
                const cleartext = r.buffer[r.end..][0..ciphertext.len];
                P.AEAD.decrypt(cleartext, ciphertext, auth_tag, ad, nonce, pv.server_write_key) catch
                    return failRead(c, error.TlsBadRecordMac);
                break :cleartext .{ cleartext.len, ct };
            },
            else => unreachable,
        },
    };
    const cleartext = r.buffer[r.end..][0..cleartext_len];
    c.read_seq = std.math.add(u64, c.read_seq, 1) catch return failRead(c, error.TlsSequenceOverflow);
    switch (inner_ct) {
        .alert => {
            if (cleartext.len != 2) return failRead(c, error.TlsDecodeError);
            const alert: tls.Alert = .{
                .level = @enumFromInt(cleartext[0]),
                .description = @enumFromInt(cleartext[1]),
            };
            switch (alert.description) {
                .close_notify => {
                    c.received_close_notify = true;
                    return 0;
                },
                .user_canceled => {
                    // TODO: handle server-side closures
                    return failRead(c, error.TlsUnexpectedMessage);
                },
                else => {
                    c.alert = alert;
                    return failRead(c, error.TlsAlert);
                },
            }
        },
        .handshake => {
            var ct_i: usize = 0;
            while (true) {
                // ZURL PATCH: the four octets of the sub-message header are
                // ZURL PATCH: read below, and upstream checks that they are
                // ZURL PATCH: there only after it has read them. An inner
                // ZURL PATCH: plaintext of one to four octets therefore
                // ZURL PATCH: reads past the plaintext of this record and
                // ZURL PATCH: into the record before it, which the peer
                // ZURL PATCH: also wrote. The bound goes in front.
                if (cleartext.len - ct_i < 4) return failRead(c, error.TlsBadLength); // ZURL PATCH
                const handshake_type: tls.HandshakeType = @enumFromInt(cleartext[ct_i]);
                ct_i += 1;
                const handshake_len = mem.readInt(u24, cleartext[ct_i..][0..3], .big);
                ct_i += 3;
                const next_handshake_i = ct_i + handshake_len;
                if (next_handshake_i > cleartext.len) return failRead(c, error.TlsBadLength);
                const handshake = cleartext[ct_i..next_handshake_i];
                switch (handshake_type) {
                    .new_session_ticket => {
                        // This client implementation ignores new session tickets.
                    },
                    .key_update => {
                        // ZURL PATCH: RFC 8446 section 4.6.3 gives
                        // ZURL PATCH: `key_update` to TLS 1.3 alone. The
                        // ZURL PATCH: arm below reads `p.tls_1_3` out of an
                        // ZURL PATCH: untagged union, so on a TLS 1.2
                        // ZURL PATCH: session it read the live `tls_1_2`
                        // ZURL PATCH: bytes as a TLS 1.3 key schedule and
                        // ZURL PATCH: wrote the result back over the live
                        // ZURL PATCH: keys. No safety check stands in front
                        // ZURL PATCH: of an untagged union, in any build
                        // ZURL PATCH: mode, so the version is checked here.
                        if (c.tls_version != .tls_1_3) return failRead(c, error.TlsUnexpectedMessage); // ZURL PATCH
                        // ZURL PATCH: the body is one octet, the
                        // ZURL PATCH: `request_update`. Upstream reads
                        // ZURL PATCH: `handshake[0]` below, and a
                        // ZURL PATCH: `handshake_len` of zero passes the
                        // ZURL PATCH: bound above and leaves it empty.
                        if (handshake.len != 1) return failRead(c, error.TlsDecodeError); // ZURL PATCH
                        switch (c.application_cipher) {
                            inline else => |*p| {
                                const pv = &p.tls_1_3;
                                const P = @TypeOf(p.*);
                                const server_secret = hkdfExpandLabel(P.Hkdf, pv.server_secret, "traffic upd", "", P.Hash.digest_length);
                                if (c.ssl_key_log) |key_log| logSecrets(key_log.writer, .{
                                    .counter = key_log.serverCounter(),
                                    .client_random = &key_log.client_random,
                                }, .{
                                    .SERVER_TRAFFIC_SECRET = &server_secret,
                                });
                                pv.server_secret = server_secret;
                                pv.server_key = hkdfExpandLabel(P.Hkdf, server_secret, "key", "", P.AEAD.key_length);
                                pv.server_iv = hkdfExpandLabel(P.Hkdf, server_secret, "iv", "", P.AEAD.nonce_length);
                            },
                        }
                        c.read_seq = 0;

                        switch (@as(tls.KeyUpdateRequest, @enumFromInt(handshake[0]))) {
                            .update_requested => {
                                // ZURL PATCH: this arm is the one place the
                                // ZURL PATCH: read path writes the state the
                                // ZURL PATCH: write path uses. A session that
                                // ZURL PATCH: two tasks drive holds the lock
                                // ZURL PATCH: here, so the rotation below and
                                // ZURL PATCH: `prepareCiphertextRecord` never
                                // ZURL PATCH: run at once. See `write_lock`.
                                if (c.write_lock) |lock| lock.acquire(); // ZURL PATCH
                                defer if (c.write_lock) |lock| lock.release(); // ZURL PATCH
                                switch (c.application_cipher) {
                                    inline else => |*p| {
                                        const pv = &p.tls_1_3;
                                        const P = @TypeOf(p.*);
                                        const client_secret = hkdfExpandLabel(P.Hkdf, pv.client_secret, "traffic upd", "", P.Hash.digest_length);
                                        if (c.ssl_key_log) |key_log| logSecrets(key_log.writer, .{
                                            .counter = key_log.clientCounter(),
                                            .client_random = &key_log.client_random,
                                        }, .{
                                            .CLIENT_TRAFFIC_SECRET = &client_secret,
                                        });
                                        pv.client_secret = client_secret;
                                        pv.client_key = hkdfExpandLabel(P.Hkdf, client_secret, "key", "", P.AEAD.key_length);
                                        pv.client_iv = hkdfExpandLabel(P.Hkdf, client_secret, "iv", "", P.AEAD.nonce_length);
                                    },
                                }
                                c.write_seq = 0;
                            },
                            .update_not_requested => {},
                            _ => return failRead(c, error.TlsIllegalParameter),
                        }
                    },
                    else => return failRead(c, error.TlsUnexpectedMessage),
                }
                ct_i = next_handshake_i;
                if (ct_i >= cleartext.len) break;
            }
            return 0;
        },
        .application_data => {
            r.end += cleartext.len;
            return 0;
        },
        else => return failRead(c, error.TlsUnexpectedMessage),
    }
}

fn rebase(r: *Reader, capacity: usize) void {
    if (r.buffer.len - r.end >= capacity) return;
    const data = r.buffer[r.seek..r.end];
    @memmove(r.buffer[0..data.len], data);
    r.seek = 0;
    r.end = data.len;
    assert(r.buffer.len - r.end >= capacity);
}

fn failRead(c: *Client, err: ReadError) error{ReadFailed} {
    c.read_err = err;
    return error.ReadFailed;
}

fn logSecrets(w: *Writer, context: anytype, secrets: anytype) void {
    inline for (@typeInfo(@TypeOf(secrets)).@"struct".fields) |field| w.print("{s}" ++
        (if (@hasField(@TypeOf(context), "counter")) "_{d}" else "") ++ " {x} {x}\n", .{field.name} ++
        (if (@hasField(@TypeOf(context), "counter")) .{context.counter} else .{}) ++ .{
        context.client_random,
        @field(secrets, field.name),
    }) catch {};
}

fn big(x: anytype) @TypeOf(x) {
    return switch (native_endian) {
        .big => x,
        .little => @byteSwap(x),
    };
}

const KeyShare = struct {
    ml_kem768_kp: crypto.kem.ml_kem.MLKem768.KeyPair,
    secp256r1_kp: crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair,
    secp384r1_kp: crypto.sign.ecdsa.EcdsaP384Sha384.KeyPair,
    x25519_kp: crypto.dh.X25519.KeyPair,
    sk_buf: [sk_max_len]u8,
    sk_len: std.math.IntFittingRange(0, sk_max_len),

    const sk_max_len = @max(
        crypto.dh.X25519.shared_length + crypto.kem.ml_kem.MLKem768.shared_length,
        crypto.ecc.P256.scalar.encoded_length,
        crypto.ecc.P384.scalar.encoded_length,
        crypto.dh.X25519.shared_length,
    );

    fn init(seed: *const [176]u8) error{IdentityElement}!KeyShare {
        return .{
            .ml_kem768_kp = try .generateDeterministic(seed[0..64].*),
            .secp256r1_kp = try .generateDeterministic(seed[64..96].*),
            .secp384r1_kp = try .generateDeterministic(seed[96..144].*),
            .x25519_kp = try .generateDeterministic(seed[144..176].*),
            .sk_buf = undefined,
            .sk_len = 0,
        };
    }

    fn exchange(
        ks: *KeyShare,
        named_group: tls.NamedGroup,
        server_pub_key: []const u8,
    ) error{ TlsIllegalParameter, TlsDecryptFailure }!void {
        switch (named_group) {
            .x25519_ml_kem768 => {
                const hksl = crypto.kem.ml_kem.MLKem768.ciphertext_length;
                const xksl = hksl + crypto.dh.X25519.public_length;
                if (server_pub_key.len != xksl) return error.TlsIllegalParameter;

                const hsk = ks.ml_kem768_kp.secret_key.decaps(server_pub_key[0..hksl]) catch
                    return error.TlsDecryptFailure;
                const xsk = crypto.dh.X25519.scalarmult(ks.x25519_kp.secret_key, server_pub_key[hksl..xksl].*) catch
                    return error.TlsDecryptFailure;
                @memcpy(ks.sk_buf[0..hsk.len], &hsk);
                @memcpy(ks.sk_buf[hsk.len..][0..xsk.len], &xsk);
                ks.sk_len = hsk.len + xsk.len;
            },
            .secp256r1 => {
                const PublicKey = crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey;
                const pk = PublicKey.fromSec1(server_pub_key) catch return error.TlsDecryptFailure;
                const mul = pk.p.mulPublic(ks.secp256r1_kp.secret_key.bytes, .big) catch
                    return error.TlsDecryptFailure;
                const sk = mul.affineCoordinates().x.toBytes(.big);
                @memcpy(ks.sk_buf[0..sk.len], &sk);
                ks.sk_len = sk.len;
            },
            .secp384r1 => {
                const PublicKey = crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey;
                const pk = PublicKey.fromSec1(server_pub_key) catch return error.TlsDecryptFailure;
                const mul = pk.p.mulPublic(ks.secp384r1_kp.secret_key.bytes, .big) catch
                    return error.TlsDecryptFailure;
                const sk = mul.affineCoordinates().x.toBytes(.big);
                @memcpy(ks.sk_buf[0..sk.len], &sk);
                ks.sk_len = sk.len;
            },
            .x25519 => {
                const ksl = crypto.dh.X25519.public_length;
                if (server_pub_key.len != ksl) return error.TlsIllegalParameter;
                const sk = crypto.dh.X25519.scalarmult(ks.x25519_kp.secret_key, server_pub_key[0..ksl].*) catch
                    return error.TlsDecryptFailure;
                @memcpy(ks.sk_buf[0..sk.len], &sk);
                ks.sk_len = sk.len;
            },
            else => return error.TlsIllegalParameter,
        }
    }

    fn getSharedSecret(ks: *const KeyShare) ?[]const u8 {
        return if (ks.sk_len > 0) ks.sk_buf[0..ks.sk_len] else null;
    }
};

fn SchemeEcdsa(comptime scheme: tls.SignatureScheme) type {
    return switch (scheme) {
        .ecdsa_secp256r1_sha256 => crypto.sign.ecdsa.EcdsaP256Sha256,
        .ecdsa_secp384r1_sha384 => crypto.sign.ecdsa.EcdsaP384Sha384,
        else => @compileError("bad scheme"),
    };
}

fn SchemeRsa(comptime scheme: tls.SignatureScheme) type {
    return switch (scheme) {
        .rsa_pkcs1_sha256,
        .rsa_pkcs1_sha384,
        .rsa_pkcs1_sha512,
        .rsa_pkcs1_sha1,
        => Certificate.rsa.PKCS1v1_5Signature,
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
        .rsa_pss_rsae_sha512,
        .rsa_pss_pss_sha256,
        .rsa_pss_pss_sha384,
        .rsa_pss_pss_sha512,
        => Certificate.rsa.PSSSignature,
        else => @compileError("bad scheme"),
    };
}

fn SchemeEddsa(comptime scheme: tls.SignatureScheme) type {
    return switch (scheme) {
        .ed25519 => crypto.sign.Ed25519,
        else => @compileError("bad scheme"),
    };
}

fn SchemeHash(comptime scheme: tls.SignatureScheme) type {
    return switch (scheme) {
        .rsa_pkcs1_sha256,
        .ecdsa_secp256r1_sha256,
        .rsa_pss_rsae_sha256,
        .rsa_pss_pss_sha256,
        => crypto.hash.sha2.Sha256,
        .rsa_pkcs1_sha384,
        .ecdsa_secp384r1_sha384,
        .rsa_pss_rsae_sha384,
        .rsa_pss_pss_sha384,
        => crypto.hash.sha2.Sha384,
        .rsa_pkcs1_sha512,
        .ecdsa_secp521r1_sha512,
        .rsa_pss_rsae_sha512,
        .rsa_pss_pss_sha512,
        => crypto.hash.sha2.Sha512,
        .rsa_pkcs1_sha1,
        .ecdsa_sha1,
        => crypto.hash.Sha1,
        else => @compileError("bad scheme"),
    };
}

const CertificatePublicKey = struct {
    // ZURL PATCH: the field holds the tagged union and not the tag. For an EC
    // key the union also names the curve, and TLS 1.2 needs that curve. See
    // `verifySignature`. `init` reads `subject.pub_key_algo`, which is that
    // union already, so the call site does not change.
    algo: Certificate.Parsed.PubKeyAlgo, // ZURL PATCH
    buf: [600]u8,
    len: u16,

    fn init(
        cert_pub_key: *CertificatePublicKey,
        algo: Certificate.Parsed.PubKeyAlgo, // ZURL PATCH
        pub_key: []const u8,
    ) error{CertificatePublicKeyInvalid}!void {
        if (pub_key.len == 0 or pub_key.len > cert_pub_key.buf.len) return error.CertificatePublicKeyInvalid; // ZURL PATCH: an empty `subjectPublicKey` parses cleanly and must not reach a signature check.
        cert_pub_key.algo = algo;
        @memcpy(cert_pub_key.buf[0..pub_key.len], pub_key);
        cert_pub_key.len = @intCast(pub_key.len);
    }

    // ZURL PATCH: the four combinations of curve and hash that
    // `verifySignature` can build, and not only the two that a TLS 1.3 scheme
    // name allows.
    const VerifyError = error{ TlsDecodeError, TlsBadSignatureScheme, InvalidEncoding } ||
        // ecdsa
        crypto.errors.EncodingError ||
        crypto.errors.NotSquareError ||
        crypto.errors.NonCanonicalError ||
        SchemeEcdsa(.ecdsa_secp256r1_sha256).Signature.VerifyError ||
        SchemeEcdsa(.ecdsa_secp384r1_sha384).Signature.VerifyError ||
        CertificateEcdsa(.X9_62_prime256v1, .ecdsa_secp256r1_sha256).Signature.VerifyError || // ZURL PATCH
        CertificateEcdsa(.X9_62_prime256v1, .ecdsa_secp384r1_sha384).Signature.VerifyError || // ZURL PATCH
        CertificateEcdsa(.secp384r1, .ecdsa_secp256r1_sha256).Signature.VerifyError || // ZURL PATCH
        CertificateEcdsa(.secp384r1, .ecdsa_secp384r1_sha384).Signature.VerifyError || // ZURL PATCH
        // rsa
        error{TlsBadRsaSignatureBitCount} ||
        Certificate.rsa.PublicKey.ParseDerError ||
        Certificate.rsa.PublicKey.FromBytesError ||
        Certificate.rsa.PSSSignature.VerifyError ||
        Certificate.rsa.PKCS1v1_5Signature.VerifyError ||
        // eddsa
        SchemeEddsa(.ed25519).Signature.VerifyError;

    fn verifySignature(
        cert_pub_key: *const CertificatePublicKey,
        sigd: *tls.Decoder,
        msg: []const []const u8,
        tls_version: tls.ProtocolVersion, // ZURL PATCH: see the ECDSA arm below.
    ) VerifyError!void {
        const pub_key = cert_pub_key.buf[0..cert_pub_key.len];

        try sigd.ensure(2 + 2);
        const scheme = sigd.decode(tls.SignatureScheme);
        const sig_len = sigd.decode(u16);
        try sigd.ensure(sig_len);
        const encoded_sig = sigd.slice(sig_len);

        // ZURL PATCH: RFC 8446 section 4.4.3 forbids `rsa_pkcs1_sha1` in
        // ZURL PATCH: `CertificateVerify`, and RFC 9155 deprecates SHA-1 in
        // ZURL PATCH: every TLS signature. SHA-1 chosen prefix collisions
        // ZURL PATCH: have been public and affordable since 2020. The
        // ZURL PATCH: client hello no longer offers the scheme, and this
        // ZURL PATCH: refuses a server that chose it all the same. The two
        // ZURL PATCH: switches below keep their upstream prongs for it,
        // ZURL PATCH: which this line makes unreachable. `ecdsa_sha1`,
        // ZURL PATCH: 0x0203, has no prong in either switch and the first
        // ZURL PATCH: `else` already refuses it.
        if (scheme == .rsa_pkcs1_sha1) return error.TlsBadSignatureScheme; // ZURL PATCH

        // ZURL PATCH: `algo` is now the tagged union, so the comparison reads
        // the tag out of it.
        if (@as(Certificate.AlgorithmCategory, cert_pub_key.algo) != @as(Certificate.AlgorithmCategory, switch (scheme) { // ZURL PATCH
            .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            => .X9_62_id_ecPublicKey,
            .rsa_pkcs1_sha256,
            .rsa_pkcs1_sha384,
            .rsa_pkcs1_sha512,
            .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            .rsa_pkcs1_sha1,
            => .rsaEncryption,
            .rsa_pss_pss_sha256,
            .rsa_pss_pss_sha384,
            .rsa_pss_pss_sha512,
            => .rsassa_pss,
            else => return error.TlsBadSignatureScheme,
        })) return error.TlsBadSignatureScheme;

        switch (scheme) {
            inline .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            // ZURL PATCH: over TLS 1.2 the scheme names only the hash. The
            // code point 0x0503 means "SHA-384 with ECDSA" there, and the
            // curve comes from the certificate. TLS 1.3 gave the same code
            // point the name `ecdsa_secp384r1_sha384` and made it name the
            // curve as well. Upstream reads the TLS 1.3 meaning always, so a
            // TLS 1.2 server that holds a P-256 key and signs with SHA-384
            // makes it parse a P-256 point as a P-384 point and report
            // `InvalidEncoding`. `ecc256.badssl.com` does exactly that.
            // `verifyEcdsa` takes the curve from the certificate, and it
            // still holds TLS 1.3 to the strict meaning.
            => |comptime_scheme| try verifyEcdsa( // ZURL PATCH
                comptime_scheme, // ZURL PATCH
                cert_pub_key.algo.X9_62_id_ecPublicKey, // ZURL PATCH
                tls_version, // ZURL PATCH
                pub_key, // ZURL PATCH
                encoded_sig, // ZURL PATCH
                msg, // ZURL PATCH
            ), // ZURL PATCH
            inline .rsa_pkcs1_sha256,
            .rsa_pkcs1_sha384,
            .rsa_pkcs1_sha512,
            .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            .rsa_pss_pss_sha256,
            .rsa_pss_pss_sha384,
            .rsa_pss_pss_sha512,
            .rsa_pkcs1_sha1,
            => |comptime_scheme| {
                const RsaSignature = SchemeRsa(comptime_scheme);
                const Hash = SchemeHash(comptime_scheme);
                const PublicKey = Certificate.rsa.PublicKey;
                const components = try PublicKey.parseDer(pub_key);
                const exponent = components.exponent;
                const modulus = components.modulus;
                switch (modulus.len) {
                    // ZURL PATCH: 128 octets is a 1024 bit modulus, and it
                    // ZURL PATCH: was in this list. CA/Browser Forum
                    // ZURL PATCH: Baseline Requirements section 6.1.5 and
                    // ZURL PATCH: NIST SP 800-57 Part 1 Revision 5 both put
                    // ZURL PATCH: the floor at 2048 bits, which is 256
                    // ZURL PATCH: octets. A shorter modulus now reports
                    // ZURL PATCH: `TlsBadRsaSignatureBitCount`.
                    inline 256, 384, 512 => |modulus_len| { // ZURL PATCH
                        const key: PublicKey = try .fromBytes(exponent, modulus);
                        const sig = RsaSignature.fromBytes(modulus_len, encoded_sig);
                        try RsaSignature.concatVerify(modulus_len, sig, msg, key, Hash);
                    },
                    else => return error.TlsBadRsaSignatureBitCount,
                }
            },
            inline .ed25519 => |comptime_scheme| {
                const Eddsa = SchemeEddsa(comptime_scheme);
                if (encoded_sig.len != Eddsa.Signature.encoded_length) return error.InvalidEncoding;
                const sig = Eddsa.Signature.fromBytes(encoded_sig[0..Eddsa.Signature.encoded_length].*);
                if (pub_key.len != Eddsa.PublicKey.encoded_length) return error.InvalidEncoding;
                const key = try Eddsa.PublicKey.fromBytes(pub_key[0..Eddsa.PublicKey.encoded_length].*);
                var ver = try sig.verifier(key);
                for (msg) |part| ver.update(part);
                try ver.verify();
            },
            else => unreachable,
        }
    }
};

fn tryDownloadRootCert(chain: *Certificate.Chain, options: *const Options) !void {
    if (Certificate.Chain != void) switch (options.ca) {
        else => {},
        .bundle => |ca| {
            chain.verify(options.realtime_now) catch |err| switch (err) {
                error.Unexpected => return error.TlsCertificateNotVerified,
                else => |e| return e,
            };
            var bundle: Certificate.Bundle = .empty;
            defer bundle.deinit(ca.gpa);
            if (bundle.rescan(ca.gpa, ca.io, options.realtime_now)) {
                try ca.lock.lock(ca.io);
                defer ca.lock.unlock(ca.io);
                std.mem.swap(Certificate.Bundle, ca.bundle, &bundle);
            } else |err| switch (err) {
                error.Canceled => |e| return e,
                else => {},
            }
            return; // the os has verified the certificate for us
        },
    };
    return error.TlsCertificateNotVerified;
}

/// The priority order here is chosen based on what crypto algorithms Zig has
/// available in the standard library as well as what is faster. Following are
/// a few data points on the relative performance of these algorithms.
///
/// Measurement taken with 0.11.0-dev.810+c2f5848fe
/// on x86_64-linux Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz:
/// zig run .lib/std/crypto/benchmark.zig -OReleaseFast
///       aegis-128l:      15382 MiB/s
///        aegis-256:       9553 MiB/s
///       aes128-gcm:       3721 MiB/s
///       aes256-gcm:       3010 MiB/s
/// chacha20Poly1305:        597 MiB/s
///
/// Measurement taken with 0.11.0-dev.810+c2f5848fe
/// on x86_64-linux Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz:
/// zig run .lib/std/crypto/benchmark.zig -OReleaseFast -mcpu=baseline
///       aegis-128l:        629 MiB/s
/// chacha20Poly1305:        529 MiB/s
///        aegis-256:        461 MiB/s
///       aes128-gcm:        138 MiB/s
///       aes256-gcm:        120 MiB/s
///
/// ZURL PATCH: each TLS 1.2 suite below comes in two forms, one for a server
/// with an ECDSA certificate and one for a server with an RSA certificate.
/// Upstream lists only the `ECDHE_RSA` form, so a server that has an ECDSA
/// certificate and speaks only TLS 1.2 finds no suite that both sides hold
/// and sends an alert. The TLS 1.3 suites do not name a signature algorithm,
/// which is why the same server works over TLS 1.3.
///
/// The `ECDHE_ECDSA` form comes first in each pair. It agrees with the order
/// that curl and OpenSSL send, and a server that holds both certificates then
/// gets the faster one.
const cipher_suites = if (crypto.core.aes.has_hardware_support)
    array(u16, tls.CipherSuite, .{
        .AEGIS_128L_SHA256,
        .AEGIS_256_SHA512,
        .AES_128_GCM_SHA256,
        .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // ZURL PATCH
        .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .AES_256_GCM_SHA384,
        .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, // ZURL PATCH
        .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        .CHACHA20_POLY1305_SHA256,
        .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, // ZURL PATCH
        .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    })
else
    array(u16, tls.CipherSuite, .{
        .CHACHA20_POLY1305_SHA256,
        .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, // ZURL PATCH
        .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .AEGIS_128L_SHA256,
        .AEGIS_256_SHA512,
        .AES_128_GCM_SHA256,
        .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // ZURL PATCH
        .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .AES_256_GCM_SHA384,
        .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, // ZURL PATCH
        .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    });

// ZURL PATCH: everything below this line is not upstream. See the file
// `UPSTREAM` beside this one for what the patch is and how to re-sync it.
// The tests here hold the patch in place. They read the offered suite list,
// they drive `init` with a Server Hello that this file builds, and they run
// the host check over a subject alternative name block this file builds, so
// no test below opens a socket.

/// The lock a session uses when two tasks drive it.
///
/// ZURL PATCH: not upstream. See the `write_lock` field for what it guards
/// and why one lock is enough.
///
/// **A vtable and not a lock.** This file cannot name a lock of its own.
/// `std.Io.Mutex` needs the `std.Io` of the caller, and a `Client` holds
/// none; a `std.Thread.Mutex` would stop a whole thread of an event loop
/// that runs several tasks on one thread. So the owner of the session
/// gives the lock it already has, and this file calls it.
///
/// `acquire` must block until it holds the lock, and `release` must give
/// it back. The pair is never nested: no path of this file takes the lock
/// while it holds it.
pub const WriteLock = struct {
    ctx: *anyopaque,
    acquire_fn: *const fn (ctx: *anyopaque) void,
    release_fn: *const fn (ctx: *anyopaque) void,

    pub fn acquire(self: WriteLock) void {
        self.acquire_fn(self.ctx);
    }

    pub fn release(self: WriteLock) void {
        self.release_fn(self.ctx);
    }
};

/// The longest ALPN protocol name this client sends or accepts.
///
/// ZURL PATCH: not upstream. RFC 7301 gives a name one length byte, so the
/// wire form itself sets this bound.
pub const alpn_max_protocol_len = 255;

/// The longest `ProtocolNameList` this client sends, counted in bytes.
///
/// ZURL PATCH: not upstream. The list holds one length byte and the name for
/// each protocol. `zurl-net` offers `h2` and then `http/1.1`, which is twelve
/// bytes, so this is far above what it needs and it still bounds a caller
/// that asks for more.
pub const alpn_max_list_len = 512;

/// The room one whole ALPN extension needs: two bytes of extension type, two
/// of extension length, two of list length, then the list.
///
/// ZURL PATCH: not upstream.
pub const alpn_extension_max = 2 + 2 + 2 + alpn_max_list_len;

/// The ALPN protocol the peer chose.
///
/// ZURL PATCH: not upstream. The name is a buffer and not a slice, because a
/// `Client` is copied by value into whatever owns the session. A slice would
/// point into a handshake record that the session no longer holds.
pub const AlpnSelection = struct {
    buf: [alpn_max_protocol_len]u8,
    /// The bytes of `buf` the name uses. Zero means the peer chose nothing.
    len: u8,

    /// No protocol. This is what a peer that sends no ALPN extension leaves
    /// behind, and it is what `--no-alpn` always leaves behind.
    pub const none: AlpnSelection = .{ .buf = @splat(0), .len = 0 };

    /// The name the peer chose, or null when it chose none.
    pub fn slice(selection: *const AlpnSelection) ?[]const u8 {
        if (selection.len == 0) return null;
        return selection.buf[0..selection.len];
    }
};

/// The ALPN protocol the peer chose, or null when it chose none.
///
/// ZURL PATCH: not upstream. A null answer is not a fault. RFC 7301 lets a
/// server that shares no protocol with the client leave the extension out,
/// and the caller then keeps whatever it speaks by default.
///
/// The slice points into `c`, so it lives as long as the session does.
pub fn alpnProtocol(c: *const Client) ?[]const u8 {
    return c.alpn.slice();
}

/// Writes the ALPN extension for `protocols` into `out`, and gives back the
/// bytes it wrote.
///
/// ZURL PATCH: not upstream. An empty list gives an empty slice, and the
/// hello then carries no ALPN extension at all.
///
/// **Three lengths must agree.** RFC 7301 section 3.1 nests a
/// `ProtocolNameList` inside the extension, and each name inside the list:
///
///     0000: 00 10                  extension type, 16
///     0002: LL LL                  extension length, the list and its own length
///     0004: MM MM                  list length, the names and their length bytes
///     0006: NN <name>              one name, and NN more of them
///
/// The two outer lengths are written last, from the position the names
/// reached, so neither one can name a count that the bytes do not hold.
fn encodeAlpn(
    protocols: []const []const u8,
    out: *[alpn_extension_max]u8,
) error{TlsAlpnOfferInvalid}![]const u8 {
    if (protocols.len == 0) return out[0..0];

    const header_len = 2 + 2 + 2;
    var at: usize = header_len;
    for (protocols) |name| {
        // A name of no bytes has no wire form, and a name over 255 bytes
        // does not fit the length byte that carries it.
        if (name.len == 0 or name.len > alpn_max_protocol_len) return error.TlsAlpnOfferInvalid;
        if (at + 1 + name.len > header_len + alpn_max_list_len) return error.TlsAlpnOfferInvalid;
        out[at] = @intCast(name.len);
        at += 1;
        @memcpy(out[at..][0..name.len], name);
        at += name.len;
    }

    const list_len: u16 = @intCast(at - header_len);
    mem.writeInt(u16, out[0..2], @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation), .big);
    // The extension holds the list and the two bytes that count it.
    mem.writeInt(u16, out[2..4], list_len + 2, .big);
    mem.writeInt(u16, out[4..6], list_len, .big);
    return out[0..at];
}

/// Reads the peer's ALPN answer out of one extension, and checks it against
/// the list the hello offered.
///
/// ZURL PATCH: not upstream. `extd` covers the extension payload and nothing
/// else, so every length below is read inside a bound the caller set.
///
/// The name is untrusted input. RFC 7301 section 3.2 lets the server pick one
/// protocol out of the client's list and nothing else, so a name outside that
/// list is a protocol violation and it stops the handshake. Accepting it
/// would leave zurl reading a protocol it cannot parse.
fn readAlpn(
    extd: *tls.Decoder,
    offered: []const []const u8,
) error{ TlsDecodeError, TlsIllegalParameter, TlsAlpnProtocolNotOffered }!AlpnSelection {
    try extd.ensure(2);
    const list_len = extd.decode(u16);
    var listd = try extd.sub(list_len);
    // The extension carries the list and nothing after it.
    if (!extd.eof()) return error.TlsIllegalParameter;

    try listd.ensure(1);
    const name_len = listd.decode(u8);
    if (name_len == 0) return error.TlsIllegalParameter;
    try listd.ensure(name_len);
    const name = listd.slice(name_len);
    // The server answers with exactly one protocol.
    if (!listd.eof()) return error.TlsIllegalParameter;

    for (offered) |want| {
        if (!mem.eql(u8, want, name)) continue;
        var selection: AlpnSelection = .none;
        selection.len = @intCast(name.len);
        @memcpy(selection.buf[0..name.len], name);
        return selection;
    }
    return error.TlsAlpnProtocolNotOffered;
}

/// What the peer certificate must carry for this transfer.
///
/// ZURL PATCH: not upstream. One tag for each kind of host a url can name.
/// `walkSubjectAltNames` reads this and answers both kinds from one walk,
/// so a third kind added here gets the bounds of the walk for free.
const WantedName = union(enum) {
    /// A domain name. RFC 6125 section 6.4 gives it the wildcard rule and
    /// the common name fallback.
    dns: []const u8,
    /// The raw bytes of an address, four for IPv4 and sixteen for IPv6.
    address: []const u8,
};

/// Whether the peer certificate carries the host that was asked for, where
/// that host may be an address.
///
/// ZURL PATCH: not upstream. `Certificate.Parsed.verifyHostName` walks the
/// subject alternative names, reads a `dNSName`, and skips every other kind
/// with `else => {}`. A certificate for an address carries an `iPAddress`
/// name, tag 7, so that walk can never match one. `https://1.1.1.1/` and
/// `https://8.8.8.8/` failed with `error.CertificateHostMismatch`, and curl
/// 8.21.0 fetches both. The same gap closed every IPv6 literal over `https`.
///
/// **Both kinds of host take the same walk.** An earlier patch sent a name
/// to `Certificate.Parsed.verifyHostName` and an address to a walk of its
/// own. That walk had the bound checks and the upstream one had none, so a
/// six byte subject alternative name of `30 20 82 1E 61 62` panicked every
/// ordinary `https://name/` transfer before any trust check ran. There is
/// one walk now, in `walkSubjectAltNames`, and the bound lives in
/// `parseName`, which is the only way this file reads a DER element out of
/// that block. A third kind of host cannot get a walk with no bound,
/// because there is no second walk to write it in.
///
/// RFC 6125 section 6.4 says a client must not read an address as a domain
/// name, so a `dNSName` that reads `1.1.1.1` names no address and must not
/// match one. `WantedName` keeps the two apart.
fn verifyHost(
    subject: Certificate.Parsed,
    host: []const u8,
) Certificate.Parsed.VerifyHostNameError!void {
    var storage: [16]u8 = undefined;
    return walkSubjectAltNames(subject, wantedName(host, &storage));
}

/// What `host` asks a certificate for: a domain name, or the octets of an
/// address.
///
/// ZURL PATCH: not upstream. The host check and the name constraint check
/// of `verifyIssued` must read one host text the same way. Two readings
/// would let a chain answer for a host that one of the two refused.
///
/// `storage` holds the octets of an address, so it must live as long as
/// the value this gives back. An `iPAddress` name holds raw bytes and
/// never text: RFC 5280 section 4.2.1.6 gives it four bytes for IPv4, in
/// the order of RFC 791, and sixteen for IPv6, in the order of RFC 2460.
fn wantedName(host: []const u8, storage: *[16]u8) WantedName {
    // A fully qualified name may carry the root label, which is written as
    // a trailing dot. `https://example.com./` and `https://example.com/`
    // name the same host and reach the same server, and no certificate
    // holds a `dNSName` that ends in a dot, so the name with the dot
    // matched nothing and every such url exited 60. Measured: curl 8.21.0
    // fetches `https://example.com./` and prints `subjectAltName:
    // "example.com." matches cert's "example.com"`, so it strips the root
    // label before it compares. One dot is dropped and no more: a name
    // that ends in two dots is not a host name.
    const trimmed = if (host.len > 1 and host[host.len - 1] == '.') host[0 .. host.len - 1] else host;
    const address = std.Io.net.IpAddress.parse(trimmed, 0) catch return .{ .dns = trimmed };
    const wanted: WantedName = switch (address) {
        .ip4 => |ip4| bytes: {
            storage[0..4].* = ip4.bytes;
            break :bytes .{ .address = storage[0..4] };
        },
        .ip6 => |ip6| bytes: {
            storage.* = ip6.bytes;
            break :bytes .{ .address = storage[0..] };
        },
    };
    return wanted;
}

/// Reads one DER element out of `bytes` and proves that the element stays
/// inside `bytes`.
///
/// ZURL PATCH: not upstream. This is the guard the whole host check rests
/// on, and it is written once.
///
/// `Certificate.der.Element.parse` trusts the certificate three times. It
/// reads `bytes[index]` and `bytes[index + 1]` with no bound. It reads each
/// long form length octet with no bound. It then adds the length the
/// certificate wrote to the index it reached, which can pass the end of the
/// block and can overflow a `u32`. A peer picks every one of those numbers,
/// so each one is checked here before it is used.
///
/// The arithmetic is in `u64`, so no sum can wrap. `len_size` is at most
/// four, so `size` is at most `0xFFFFFFFF`, and `end` is proved to be at or
/// below `bytes.len` before either bound becomes a `u32`.
///
/// **The body moved to `certificate.zig`.** The same guard now bounds the
/// whole certificate walk and not the name block alone, and one reader is
/// what stops a second walk from being written without one. This name
/// stays because the host check and the extension reader below read like
/// the block they are about.
fn parseName(
    bytes: []const u8,
    index: u32,
) Certificate.der.Element.ParseError!Certificate.der.Element {
    return certificate.parseElement(bytes, index);
}

/// Whether the peer certificate carries `want` in its subject alternative
/// names.
///
/// ZURL PATCH: not upstream. This is the one walk over the block, and
/// `parseName` bounds every read it makes.
///
/// A certificate with no subject alternative name at all falls back to the
/// common name for a domain name, which is the upstream rule and RFC 2818.
/// An address takes no such fallback: the common name holds a name, an
/// address is not one, and RFC 6125 section 6.4.4 retired that fallback.
///
/// The walk always moves forward. `parseName` puts `slice.start` at least
/// two bytes past the index it read, so `name_i` grows on every turn and
/// the loop ends at `general_names.slice.end`.
fn walkSubjectAltNames(
    subject: Certificate.Parsed,
    want: WantedName,
) Certificate.Parsed.VerifyHostNameError!void {
    const subject_alt_name = subject.subjectAltName();
    if (subject_alt_name.len == 0) {
        switch (want) {
            .dns => |host| if (checkHostName(host, subject.commonName())) return,
            .address => {},
        }
        return error.CertificateHostMismatch;
    }

    const general_names = try parseName(subject_alt_name, 0);

    var name_i = general_names.slice.start;
    while (name_i < general_names.slice.end) {
        const general_name = try parseName(subject_alt_name, name_i);
        name_i = general_name.slice.end;

        const tag: Certificate.GeneralNameTag = @enumFromInt(@intFromEnum(general_name.identifier.tag));
        const name = subject_alt_name[general_name.slice.start..general_name.slice.end];
        switch (want) {
            .dns => |host| {
                if (tag != .dNSName) continue;
                if (checkHostName(host, name)) return;
            },
            .address => |wanted| {
                if (tag != .iPAddress) continue;
                // The two lengths must be equal. A name of four bytes
                // therefore cannot match an IPv6 address, and a name of
                // sixteen cannot match an IPv4 one.
                if (name.len != wanted.len) continue;
                if (std.mem.eql(u8, name, wanted)) return;
            },
        }
    }

    return error.CertificateHostMismatch;
}

/// Whether `dns_name` names `host_name`, per RFC 6125.
///
/// ZURL PATCH: not upstream by position, and upstream by rule. This is
/// `Certificate.Parsed.checkHostName` of the pinned Zig 0.16.0, byte for
/// byte in what it accepts. It is copied because it is private to that
/// file, and `walkSubjectAltNames` needs the name rule that the address
/// rule sits beside. Compare it with upstream at each Zig bump. See the
/// file `UPSTREAM` beside this one.
///
/// An exact match is case insensitive. A wildcard must be the leftmost
/// label and must read `*.rest.of.domain`, it matches exactly one label,
/// and a partial wildcard such as `f*.com` matches nothing.
fn checkHostName(host_name: []const u8, dns_name: []const u8) bool {
    if (host_name.len == 0 or dns_name.len == 0) return false;

    // RFC 6125 section 6.4.1: an exact match, without regard to case.
    if (std.ascii.eqlIgnoreCase(dns_name, host_name)) return true;

    // RFC 6125 section 6.4.3: a wildcard certificate.
    if (dns_name.len >= 3 and mem.startsWith(u8, dns_name, "*.")) {
        const wildcard_suffix = dns_name[2..];

        // The rest of the name carries no second wildcard.
        if (mem.indexOf(u8, wildcard_suffix, "*") != null) return false;

        // The wildcard covers the first label and nothing else.
        const dot_pos = mem.indexOf(u8, host_name, ".") orelse return false;
        const host_suffix = host_name[dot_pos + 1 ..];

        return std.ascii.eqlIgnoreCase(wildcard_suffix, host_suffix);
    }

    return false;
}

/// How many certificates one chain may hold.
///
/// ZURL PATCH: not upstream. RFC 5280 sets no ceiling, so this side sets
/// one. A public chain is three or four certificates long. Ten leaves room
/// for a private hierarchy and it stops a peer that sends a long list to
/// make this side do work.
pub const max_chain_certificates = 10;

/// What the extensions of one certificate say about what it may do.
///
/// ZURL PATCH: not upstream. `std.crypto.Certificate.Parsed` knows the
/// object identifier of each of these extensions and it keeps none of
/// them, so this file reads them.
const IssuerRights = struct {
    /// True when the certificate carries a `basicConstraints` extension.
    has_basic_constraints: bool = false,
    /// The `cA` boolean of `basicConstraints`. RFC 5280 section 4.2.1.9
    /// gives it the default value FALSE.
    is_ca: bool = false,
    /// The `pathLenConstraint` of `basicConstraints`, or null when the
    /// extension leaves it out. It counts the certificates that may sit
    /// between this one and the leaf.
    path_len: ?u32 = null,
    /// True when the certificate carries a `keyUsage` extension.
    has_key_usage: bool = false,
    /// The `keyCertSign` bit of `keyUsage`, which is bit 5. RFC 5280
    /// section 4.2.1.3.
    may_sign_certificates: bool = false,
    /// True when the certificate carries an `extendedKeyUsage` extension.
    /// RFC 5280 section 4.2.1.12 leaves the key good for every purpose
    /// when the extension is absent.
    has_ext_key_usage: bool = false,
    /// True when `extendedKeyUsage` names `id-kp-serverAuth` or
    /// `anyExtendedKeyUsage`. Only such a certificate may stand for a TLS
    /// server.
    may_authenticate_server: bool = false,
    /// The value of the `nameConstraints` extension, or null when the
    /// certificate carries none. The element indexes the buffer of the
    /// certificate it was read from. RFC 5280 section 4.2.1.10.
    name_constraints: ?Certificate.der.Element = null,
};

/// Every fault the issuer rules can report.
///
/// ZURL PATCH: not upstream. Each name says which rule refused, so a
/// failed fetch tells the user what the peer sent.
pub const IssuerError = error{
    /// The certificate has no `basicConstraints` extension, or the
    /// extension is there and `cA` is FALSE. RFC 5280 section 4.2.1.9
    /// forbids the use of such a key to check a certificate signature.
    CertificateIssuerNotCa,
    /// The certificate carries a `keyUsage` extension that does not assert
    /// `keyCertSign`. RFC 5280 section 4.2.1.3.
    CertificateIssuerCannotSignCertificates,
    /// The certificate carries an `extendedKeyUsage` extension that names
    /// neither `id-kp-serverAuth` nor `anyExtendedKeyUsage`. RFC 5280
    /// section 4.2.1.12. A certificate for electronic mail or for code
    /// signing does not stand for a TLS server.
    ///
    /// This name answers for a leaf as well as for a certificate
    /// authority, which is why it says neither. The earlier patch had to
    /// report a leaf with the wrong purpose as
    /// `CertificateIssuerCannotSignCertificates`, because a name of its
    /// own needs a row in `zurl-net/errors.zig` and that file was in
    /// another lane. The sentence a user read then called a certificate
    /// that is no authority "a certificate authority".
    CertificateNotForServerAuth,
    /// The host of this session sits outside the `permittedSubtrees` of a
    /// certificate authority in the chain, or inside its
    /// `excludedSubtrees`, or the extension holds a kind of subtree this
    /// client cannot check. RFC 5280 section 4.2.1.10.
    ///
    /// This is apart from `CertificateHostMismatch`, which the earlier
    /// patch had to reuse. The two send a user to two different places: a
    /// host mismatch says the certificate is for another name, and this
    /// says the certificate is for this name and the authority above it
    /// was not allowed to say so.
    CertificateNameNotPermitted,
    /// The certificate carries a `pathLenConstraint` that is smaller than
    /// the number of certificates below it in the chain. RFC 5280 section
    /// 4.2.1.9.
    CertificatePathLengthExceeded,
    /// The chain holds more certificates than `max_chain_certificates`.
    CertificateChainTooLong,
};

/// Every fault the extension reader can report.
///
/// ZURL PATCH: not upstream. Every name here is already a member of
/// `InitError` and of `quic.VerifyCertificateError`, so the extension
/// rules add no name to the set a caller already handles.
pub const ExtensionError = error{
    CertificateFieldHasInvalidLength,
    CertificateFieldHasWrongDataType,
    /// The certificate carries an extension that is marked critical and
    /// that this client does not read. RFC 5280 section 4.2 says such a
    /// certificate must be refused. See `issuerRights`.
    CertificateHasUnrecognizedObjectId,
};

/// Every fault the cryptographic floor can report.
///
/// ZURL PATCH: not upstream. See `verifyCertificateStrength`.
pub const StrengthError = error{
    /// The certificate is signed with a hash whose collision resistance is
    /// broken. See `weakSignatureAlgorithm`.
    CertificateSignatureAlgorithmWeak,
    /// The certificate carries a public key that is below the floor. See
    /// `rsa_modulus_octets_min`.
    CertificatePublicKeyTooWeak,
};

/// The smallest RSA modulus this client trusts, in octets.
///
/// ZURL PATCH: not upstream. 256 octets is 2048 bits. CA/Browser Forum
/// Baseline Requirements section 6.1.5 gives 2048 bits as the floor for a
/// certificate a public authority may issue, and NIST SP 800-57 Part 1
/// Revision 5 table 2 puts 1024 bit RSA below the 112 bit security
/// strength it asks for after 2013. No public authority has issued a
/// shorter key for many years, so the floor costs a user nothing and it
/// closes a private hierarchy that still holds one.
const rsa_modulus_octets_min = 256;

/// The longest host name this client sends in a `server_name` extension.
///
/// ZURL PATCH: not upstream. RFC 1035 section 2.3.4 bounds a domain name
/// at 255 octets, and RFC 6066 section 3 counts the name of a
/// `server_name` extension in a `u16`. The smaller of the two is the
/// bound, and a longer host answers `TlsHostNameTooLong` before the hello
/// is built. See `init`.
const host_name_max = 255;

/// The object identifier of `basicConstraints`, which is 2.5.29.19.
const oid_basic_constraints = [_]u8{ 0x55, 0x1D, 0x13 };

/// The object identifier of `keyUsage`, which is 2.5.29.15.
const oid_key_usage = [_]u8{ 0x55, 0x1D, 0x0F };

/// The object identifier of `subjectAltName`, which is 2.5.29.17.
///
/// The host check reads this extension, through `walkSubjectAltNames`, so
/// a certificate that marks it critical is one this client understands.
const oid_subject_alt_name = [_]u8{ 0x55, 0x1D, 0x11 };

/// The object identifier of `nameConstraints`, which is 2.5.29.30.
const oid_name_constraints = [_]u8{ 0x55, 0x1D, 0x1E };

/// The object identifier of `extendedKeyUsage`, which is 2.5.29.37.
const oid_ext_key_usage = [_]u8{ 0x55, 0x1D, 0x25 };

/// The object identifier of `anyExtendedKeyUsage`, which is 2.5.29.37.0.
/// RFC 5280 section 4.2.1.12 gives a key that names it every purpose.
const oid_any_ext_key_usage = [_]u8{ 0x55, 0x1D, 0x25, 0x00 };

/// The object identifier of `id-kp-serverAuth`, which is 1.3.6.1.5.5.7.3.1.
/// This is the purpose a TLS server certificate needs.
const oid_server_auth = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };

/// The rights `cert` holds over other certificates and over this session.
///
/// ZURL PATCH: not upstream. The walk goes down the `tbsCertificate` to the
/// `[3] EXPLICIT Extensions` field, and it reads the extensions that decide
/// whether a key may sign a certificate, whether it may stand for a TLS
/// server, and which names it may answer for. Every element it reads goes
/// through `parseName`, which is the one bounded reader in this file, so a
/// length the peer wrote cannot pass the end of the buffer and cannot wrap.
///
/// **An extension marked critical that this walk does not read refuses the
/// certificate.** RFC 5280 section 4.2 and section 6.1.4 (f) both say so,
/// and it is the rule that keeps this client closed when an extension that
/// nobody has written yet arrives. Without it `nameConstraints`,
/// `policyConstraints` and `inhibitAnyPolicy` were all read as if they
/// said nothing, so a certificate authority the issuer had bound to one
/// name space was a certificate authority for the whole internet.
///
/// A certificate below version 3 carries no extensions at all. The walk
/// then gives back the default value, which says the certificate is not a
/// certificate authority.
///
/// The walk always moves forward, because `parseName` puts `slice.end` at
/// least two bytes past the index it read.
fn issuerRights(cert: Certificate.Parsed) ExtensionError!IssuerRights {
    var rights: IssuerRights = .{};
    if (cert.version != .v3) return rights;

    const bytes = cert.certificate.buffer;
    const outer = try parseName(bytes, cert.certificate.index);
    const tbs = try parseName(bytes, outer.slice.start);

    // The fields of a `tbsCertificate` are a fixed list, and only the last
    // of them carries the extensions. The walk reads the list in order and
    // stops at the field tagged `[3]`, so no field before it can be read as
    // the extensions block.
    var field_index = tbs.slice.start;
    var extensions_block: ?Certificate.der.Element = null;
    while (field_index < tbs.slice.end) {
        const field = try parseName(bytes, field_index);
        field_index = field.slice.end;
        // `Tag` counts from the same value the class bits sit above, so
        // tag number 3 reads back as `.bitstring` here.
        if (field.identifier.class == .context_specific and field.identifier.tag == .bitstring) {
            extensions_block = field;
            break;
        }
    }
    const explicit = extensions_block orelse return rights;

    // `[3]` is an EXPLICIT tag, so the SEQUENCE OF Extension sits inside it.
    const extensions = try parseName(bytes, explicit.slice.start);
    var ext_index = extensions.slice.start;
    while (ext_index < extensions.slice.end) {
        const extension = try parseName(bytes, ext_index);
        ext_index = extension.slice.end;

        const oid = try parseName(bytes, extension.slice.start);
        // `critical` is a BOOLEAN with the default value FALSE, so the
        // octet string that holds the value comes after it when it is
        // there and directly after the identifier when it is not.
        const critical = try parseName(bytes, oid.slice.end);
        const value = if (critical.identifier.tag != .boolean)
            critical
        else
            try parseName(bytes, critical.slice.end);
        // A BOOLEAN carries exactly one octet, and DER writes TRUE as
        // 0xFF. Any octet that is not zero reads as TRUE, which is what
        // BER allows and what every other client does. A BOOLEAN of
        // another length is a fault and not a value: taking it as FALSE
        // would let a peer mark an extension critical in a way this walk
        // cannot see, which is the rule below turned off.
        const is_critical = if (critical.identifier.tag != .boolean) false else flag: {
            if (critical.slice.end - critical.slice.start != 1) {
                return error.CertificateFieldHasInvalidLength;
            }
            break :flag bytes[critical.slice.start] != 0;
        };

        const oid_bytes = bytes[oid.slice.start..oid.slice.end];
        if (mem.eql(u8, oid_bytes, &oid_basic_constraints)) {
            try readBasicConstraints(bytes, value, &rights);
        } else if (mem.eql(u8, oid_bytes, &oid_key_usage)) {
            try readKeyUsage(bytes, value, &rights);
        } else if (mem.eql(u8, oid_bytes, &oid_ext_key_usage)) {
            try readExtKeyUsage(bytes, value, &rights);
        } else if (mem.eql(u8, oid_bytes, &oid_name_constraints)) {
            rights.name_constraints = value;
        } else if (mem.eql(u8, oid_bytes, &oid_subject_alt_name)) {
            // The host check reads it. See `walkSubjectAltNames`.
        } else if (is_critical) {
            // RFC 5280 section 4.2: a client that does not read a
            // critical extension must refuse the certificate that
            // carries it.
            return error.CertificateHasUnrecognizedObjectId;
        }
    }
    return rights;
}

/// Reads `basicConstraints` out of the octet string that holds it.
///
/// ZURL PATCH: not upstream. RFC 5280 section 4.2.1.9 gives the value as
/// `SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER
/// OPTIONAL }`. DER leaves out a value that equals its default, and some
/// certificates write `cA FALSE` all the same, so the boolean is read and
/// not assumed.
///
/// A `pathLenConstraint` over four octets cannot name a chain this client
/// walks, so the walk keeps the ceiling instead of the number.
fn readBasicConstraints(
    bytes: []const u8,
    value: Certificate.der.Element,
    rights: *IssuerRights,
) ExtensionError!void {
    rights.has_basic_constraints = true;
    const seq = try parseName(bytes, value.slice.start);
    if (seq.identifier.tag != .sequence) return error.CertificateFieldHasWrongDataType;

    var index = seq.slice.start;
    if (index >= seq.slice.end) return;

    const first = try parseName(bytes, index);
    if (first.identifier.tag == .boolean) {
        index = first.slice.end;
        // A BOOLEAN carries exactly one octet, and DER makes TRUE the
        // value 0xFF. Any octet that is not zero reads as TRUE, which is
        // what BER allows and what every other client does.
        if (first.slice.end - first.slice.start != 1) return error.CertificateFieldHasInvalidLength;
        rights.is_ca = bytes[first.slice.start] != 0;
    }
    if (index >= seq.slice.end) return;

    const path = try parseName(bytes, index);
    if (path.identifier.tag != .integer) return;
    const digits = bytes[path.slice.start..path.slice.end];
    if (digits.len == 0) return error.CertificateFieldHasInvalidLength;
    // A negative constraint is not legal, and a value of more than four
    // octets is far above `max_chain_certificates`.
    if (digits[0] & 0x80 != 0) return error.CertificateFieldHasWrongDataType;
    if (digits.len > 4) {
        rights.path_len = max_chain_certificates;
        return;
    }
    var path_len: u32 = 0;
    for (digits) |digit| path_len = (path_len << 8) | digit;
    rights.path_len = path_len;
}

/// Reads `keyUsage` out of the octet string that holds it.
///
/// ZURL PATCH: not upstream. RFC 5280 section 4.2.1.3 gives the value as a
/// BIT STRING, and `keyCertSign` is bit 5. The first content octet of a
/// BIT STRING counts the unused bits at the end, so the bits start in the
/// second octet and bit 5 is the mask 0x04 there.
///
/// A BIT STRING with one content octet holds no bits at all, so the usage
/// stays unasserted.
fn readKeyUsage(
    bytes: []const u8,
    value: Certificate.der.Element,
    rights: *IssuerRights,
) ExtensionError!void {
    rights.has_key_usage = true;
    const bit_string = try parseName(bytes, value.slice.start);
    if (bit_string.identifier.tag != .bitstring) return error.CertificateFieldHasWrongDataType;

    const content = bytes[bit_string.slice.start..bit_string.slice.end];
    if (content.len == 0) return error.CertificateFieldHasInvalidLength;
    if (content[0] > 7) return error.CertificateFieldHasWrongDataType;
    if (content.len < 2) return;
    rights.may_sign_certificates = content[1] & 0x04 != 0;
}

/// Reads `extendedKeyUsage` out of the octet string that holds it.
///
/// ZURL PATCH: not upstream. RFC 5280 section 4.2.1.12 gives the value as
/// `SEQUENCE OF KeyPurposeId`, and it says a certificate that carries the
/// extension may be used for the purposes it names and for no other. A
/// certificate whose only purpose is electronic mail or code signing
/// therefore does not stand for a TLS server, and the certificate
/// authority above it may have checked an electronic mail address and
/// never a host name.
///
/// `anyExtendedKeyUsage` names every purpose, so it counts as well.
///
/// A purpose that is not an OBJECT IDENTIFIER is stepped over rather than
/// refused, because an unknown purpose says nothing about this one.
fn readExtKeyUsage(
    bytes: []const u8,
    value: Certificate.der.Element,
    rights: *IssuerRights,
) ExtensionError!void {
    rights.has_ext_key_usage = true;
    const seq = try parseName(bytes, value.slice.start);
    if (seq.identifier.tag != .sequence) return error.CertificateFieldHasWrongDataType;

    var index = seq.slice.start;
    while (index < seq.slice.end) {
        const purpose = try parseName(bytes, index);
        index = purpose.slice.end;
        if (purpose.identifier.tag != .object_identifier) continue;
        const oid_bytes = bytes[purpose.slice.start..purpose.slice.end];
        if (mem.eql(u8, oid_bytes, &oid_server_auth) or
            mem.eql(u8, oid_bytes, &oid_any_ext_key_usage))
        {
            rights.may_authenticate_server = true;
        }
    }
}

/// Checks the host of this session against the `nameConstraints` of one
/// certificate authority.
///
/// ZURL PATCH: not upstream. RFC 5280 section 4.2.1.10 lets a certificate
/// authority bind the certificate authorities below it to a name space.
/// The CA/Browser Forum Baseline Requirements let such a sub-authority go
/// without an audit **because the client holds it to that name space**. A
/// client that reads the extension and does nothing with it therefore
/// makes the holder of any constrained key a certificate authority for the
/// whole internet.
///
/// **The host is what this checks, and it is enough.** The one name this
/// session authenticates is the host the user asked for, which
/// `verifyHost` matched against the leaf. A name in the leaf that the
/// constraint forbids and that nobody asked for authenticates nothing. So
/// the check reads one host per issuer and needs no copy of the leaf,
/// which the record buffer would not hold anyway: `init` keeps two
/// certificates at a time.
///
/// **A constraint this side cannot check refuses the certificate.** A
/// `dNSName` subtree and an `iPAddress` subtree name a TLS server, and
/// every other kind of subtree names something else that this client does
/// not read, such as a directory name of the subject. Refusing is the
/// same rule as the one for a critical extension nobody reads, and this
/// extension is always critical.
///
/// `value` is the octet string of the extension and it indexes `bytes`,
/// which is the buffer of the certificate that carries it.
fn checkNameConstraints(
    bytes: []const u8,
    value: Certificate.der.Element,
    want: WantedName,
) (ExtensionError || error{CertificateNameNotPermitted})!void {
    const seq = try parseName(bytes, value.slice.start);
    if (seq.identifier.tag != .sequence) return error.CertificateFieldHasWrongDataType;

    // `NameConstraints ::= SEQUENCE { permittedSubtrees [0] OPTIONAL,
    // excludedSubtrees [1] OPTIONAL }`. Both are IMPLICIT, so each one
    // reads as a context specific element that holds the subtrees.
    var index = seq.slice.start;
    var permitted: ?Certificate.der.Element = null;
    var excluded: ?Certificate.der.Element = null;
    while (index < seq.slice.end) {
        const field = try parseName(bytes, index);
        index = field.slice.end;
        if (field.identifier.class != .context_specific) {
            return error.CertificateFieldHasWrongDataType;
        }
        switch (@intFromEnum(field.identifier.tag)) {
            0 => permitted = field,
            1 => excluded = field,
            // A field of this extension that RFC 5280 does not give.
            else => return error.CertificateNameNotPermitted,
        }
    }

    if (excluded) |block| {
        const match = try walkSubtrees(bytes, block, want);
        if (match.matched) return error.CertificateNameNotPermitted;
    }
    if (permitted) |block| {
        const match = try walkSubtrees(bytes, block, want);
        // A permitted subtree binds the kind of name it holds and no
        // other kind. RFC 5280 section 4.2.1.10: a certificate that
        // carries no name of that kind is acceptable.
        if (match.names_this_kind and !match.matched) return error.CertificateNameNotPermitted;
    }
}

/// What one walk of a subtree block found.
///
/// ZURL PATCH: not upstream. See `checkNameConstraints`.
const SubtreeMatch = struct {
    /// True when the block holds at least one subtree of the same kind as
    /// the wanted name.
    names_this_kind: bool = false,
    /// True when the wanted name is inside one of those subtrees.
    matched: bool = false,
};

/// Walks one `GeneralSubtrees` block and says what it holds about `want`.
///
/// ZURL PATCH: not upstream. Every element goes through `parseName`, and
/// the walk always moves forward, so a block a peer wrote cannot make it
/// read past the buffer and cannot make it run for ever.
fn walkSubtrees(
    bytes: []const u8,
    block: Certificate.der.Element,
    want: WantedName,
) (ExtensionError || error{CertificateNameNotPermitted})!SubtreeMatch {
    var found: SubtreeMatch = .{};
    var index = block.slice.start;
    while (index < block.slice.end) {
        const subtree = try parseName(bytes, index);
        index = subtree.slice.end;
        if (subtree.identifier.tag != .sequence) return error.CertificateFieldHasWrongDataType;

        const base = try parseName(bytes, subtree.slice.start);
        // `GeneralSubtree ::= SEQUENCE { base GeneralName, minimum [0]
        // DEFAULT 0, maximum [1] OPTIONAL }`. RFC 5280 section 4.2.1.10
        // says both numbers must be absent, so a subtree that carries one
        // is a constraint this side cannot obey.
        if (base.slice.end != subtree.slice.end) return error.CertificateNameNotPermitted;
        if (base.identifier.class != .context_specific) return error.CertificateNameNotPermitted;

        const tag: Certificate.GeneralNameTag = @enumFromInt(@intFromEnum(base.identifier.tag));
        const name = bytes[base.slice.start..base.slice.end];
        switch (tag) {
            .dNSName => switch (want) {
                .dns => |host| {
                    found.names_this_kind = true;
                    if (dnsInSubtree(name, host)) found.matched = true;
                },
                .address => {},
            },
            .iPAddress => switch (want) {
                .address => |address| {
                    found.names_this_kind = true;
                    if (addressInSubtree(name, address)) found.matched = true;
                },
                .dns => {},
            },
            // A subtree of a kind this client does not read. See the head
            // of `checkNameConstraints`.
            else => return error.CertificateNameNotPermitted,
        }
    }
    return found;
}

/// Whether `host` sits in the DNS subtree `base` names.
///
/// ZURL PATCH: not upstream. RFC 5280 section 4.2.1.10 says the subtree
/// holds the name itself and every name below it, so `example.com` holds
/// `example.com` and `host.example.com` and does not hold
/// `notexample.com`. The comparison is on labels for that reason, and it
/// ignores case the way a DNS name does.
///
/// A base of no octets holds every name, which is what RFC 5280 says.
///
/// A base that starts with a dot is the form some certificate authorities
/// write. It holds the names below the name and not the name itself.
fn dnsInSubtree(base: []const u8, host: []const u8) bool {
    const below_only = base.len != 0 and base[0] == '.';
    const want = if (below_only) base[1..] else base;
    if (want.len == 0) return true;
    if (host.len < want.len) return false;
    if (host.len == want.len) return !below_only and std.ascii.eqlIgnoreCase(want, host);
    const at = host.len - want.len;
    if (host[at - 1] != '.') return false;
    return std.ascii.eqlIgnoreCase(want, host[at..]);
}

/// Whether `address` sits in the address range `base` names.
///
/// ZURL PATCH: not upstream. RFC 5280 section 4.2.1.10 writes the base of
/// an `iPAddress` subtree as the address and the mask together, so eight
/// octets for IPv4 and thirty two for IPv6. An address of another width
/// than the base names is outside the range.
fn addressInSubtree(base: []const u8, address: []const u8) bool {
    if (base.len != address.len * 2) return false;
    const network = base[0..address.len];
    const mask = base[address.len..];
    for (address, network, mask) |octet, network_octet, mask_octet| {
        if (octet & mask_octet != network_octet & mask_octet) return false;
    }
    return true;
}

/// Checks the rules a leaf certificate must obey on its own.
///
/// ZURL PATCH: not upstream, and it is called from both certificate walks
/// beside `verifyHost`. `verifyIssued` cannot hold these rules: a server
/// whose leaf was signed by a root of the trust store sends one
/// certificate, and `verifyIssued` then never runs.
///
/// * RFC 5280 section 4.2: an extension marked critical that this client
///   does not read refuses the certificate. `issuerRights` holds that
///   rule, and this call is what runs it over the leaf.
/// * RFC 5280 section 4.2.1.12: a leaf that carries `extendedKeyUsage`
///   must name `id-kp-serverAuth` or `anyExtendedKeyUsage`. A certificate
///   for electronic mail or for code signing does not stand for a TLS
///   server.
///
/// `checking` is false when the caller asked for no trust check at all,
/// which is curl's `--insecure`. The rules above are the trust check, so
/// they answer the same flag as the chain rules do.
///
/// The extended key usage fault reports `CertificateNotForServerAuth`,
/// which is a name of its own. An earlier patch had to report it as
/// `CertificateIssuerCannotSignCertificates`, because a new name needs a
/// row in `zurl-net/errors.zig` and that file was in another lane. A user
/// then read that a certificate which is no authority at all was "a
/// certificate authority that cannot sign certificates".
fn verifyEndEntity(
    leaf: Certificate.Parsed,
    checking: bool,
) (IssuerError || ExtensionError)!void {
    if (!checking) return;
    const rights = try issuerRights(leaf);
    if (rights.has_ext_key_usage and !rights.may_authenticate_server) {
        return error.CertificateNotForServerAuth;
    }
}

/// Whether `algorithm` signs with a hash this client will not trust.
///
/// ZURL PATCH: not upstream. SHA-1 chosen prefix collisions have been
/// public since 2020 and cost about the price of a used car, and a
/// certificate signature is exactly the place where a collision buys an
/// attacker a certificate for a name they do not hold. RFC 9155 deprecates
/// SHA-1 in TLS signatures. MD2 and MD5 are worse again, and the standard
/// library already refuses those two.
///
/// **SHA-224 stays.** It has 112 bits of collision resistance, which is
/// the floor NIST SP 800-57 asks for and the floor OpenSSL security level
/// 2 asks for, and curl 8.21.0 still offers the three SHA-224 signature
/// schemes in its client hello. Nothing about it is broken.
fn weakSignatureAlgorithm(algorithm: Certificate.Algorithm) bool {
    return switch (algorithm) {
        .sha1WithRSAEncryption, .md2WithRSAEncryption, .md5WithRSAEncryption => true,
        .sha224WithRSAEncryption,
        .sha256WithRSAEncryption,
        .sha384WithRSAEncryption,
        .sha512WithRSAEncryption,
        .ecdsa_with_SHA224,
        .ecdsa_with_SHA256,
        .ecdsa_with_SHA384,
        .ecdsa_with_SHA512,
        .curveEd25519,
        => false,
    };
}

/// Checks the cryptographic floor of one certificate the peer sent.
///
/// ZURL PATCH: not upstream, and it is called once for **every**
/// certificate of both walks, which is what `verifyEndEntity` and
/// `verifyIssued` between them cannot do. `verifyEndEntity` reads the leaf
/// and `verifyIssued` reads a pair, so the certificate at the point where
/// the trust store answers never passes through either one as the subject,
/// and its signature is the one the root made.
///
/// Two floors:
///
/// * The signature algorithm. See `weakSignatureAlgorithm`. The algorithm
///   read here is the one `Certificate.Parsed.verify` dispatches on, so a
///   name refused here is a signature this client never checks.
/// * The public key. An RSA modulus below `rsa_modulus_octets_min` is
///   refused. An EC key needs no floor of its own: the reader of this file
///   knows secp256r1, secp384r1 and Ed25519 and no curve below any of
///   them, so a weaker curve is already an unknown one.
///
/// `checking` is false for curl's `--insecure`, which asks for no trust
/// check at all. A floor is part of the trust check, so it answers the
/// same flag that `verifyEndEntity` and `verifyIssued` answer. A user who
/// wrote `-k` gets what curl gives them.
///
/// The walk stops at the first certificate the trust store answers for, so
/// a certificate the chain never uses is never parsed and never reaches
/// this floor.
fn verifyCertificateStrength(
    cert: Certificate.Parsed,
    checking: bool,
) StrengthError!void {
    if (!checking) return;
    if (weakSignatureAlgorithm(cert.signature_algorithm)) {
        return error.CertificateSignatureAlgorithmWeak;
    }
    switch (cert.pub_key_algo) {
        .rsaEncryption, .rsassa_pss => {
            const key = cert.pubKey();
            const components = Certificate.rsa.PublicKey.parseDer(key) catch {
                // The key does not decode. `certificate.parse` already
                // refused a key the reader cannot read, so this arm is the
                // belt behind that brace and it refuses rather than
                // passing an unread key on.
                return error.CertificatePublicKeyTooWeak;
            };
            if (components.modulus.len < rsa_modulus_octets_min) {
                return error.CertificatePublicKeyTooWeak;
            }
        },
        .X9_62_id_ecPublicKey, .curveEd25519 => {},
    }
}

/// Checks that `issuer` issued `subject`, and that `issuer` was allowed to.
///
/// ZURL PATCH: not upstream, and **this is the one place the chain rules
/// live**. Both walks of a certificate list call it: the `certificate` arm
/// of `init` for TLS over TCP, and `quic.verifyCertificate` for the TLS 1.3
/// handshake that QUIC carries in CRYPTO frames. Neither one calls
/// `Certificate.Parsed.verify` on its own, so a rule added here reaches
/// both transports and a third caller cannot get a weaker set of rules by
/// copying the loop.
///
/// `std.crypto.Certificate.Parsed.verify` checks three things and no more:
/// that the subject's issuer name equals the issuer's subject name, that
/// the subject is inside its validity dates, and that the signature holds.
/// It reads neither `basicConstraints` nor `keyUsage`. Without the rules
/// below, **any certificate that chains to a trusted root can sign a
/// certificate for any other host**, so the holder of a domain validated
/// certificate for one name can mint one for a name they do not hold. The
/// rules RFC 5280 gives are:
///
/// * Section 4.2.1.9: a certificate that verifies a certificate signature
///   must carry `basicConstraints` with `cA` TRUE.
/// * Section 4.2.1.3: if the certificate carries `keyUsage`, that
///   extension must assert `keyCertSign`.
/// * Section 4.2.1.9: `pathLenConstraint` counts the certificates that may
///   sit between the issuer and the leaf.
/// * Section 4.2.1.12: if the certificate carries `extendedKeyUsage`, that
///   extension must name `id-kp-serverAuth` or `anyExtendedKeyUsage`. A
///   certificate authority the issuer above it bound to electronic mail
///   or to code signing does not stand behind a TLS server.
/// * Section 4.2.1.10: the host of this session must sit inside every
///   `nameConstraints` the certificate carries. This is the rule the
///   Baseline Requirements lean on when they let a technically
///   constrained sub-authority go without an audit.
/// * Section 4.2: an extension marked critical that this client does not
///   read refuses the certificate. `issuerRights` holds that rule.
///
/// `chain_host` is the host the user asked for, or null when the caller
/// asked for no host check. A session with no host check authenticates no
/// name, so there is no name for a constraint to bind.
///
/// `subject_index` is where `subject` sits in the chain, and the leaf is
/// zero. So `issuer` sits at `subject_index + 1`, and the number of
/// certificates between `issuer` and the leaf is `subject_index`.
///
/// A trust anchor does not come through here. The trust store answers for
/// a root, and a root the user named is trusted because the user named it.
fn verifyIssued(
    subject: Certificate.Parsed,
    issuer: Certificate.Parsed,
    chain_host: ?[]const u8,
    subject_index: usize,
    now_sec: i64,
) (IssuerError || ExtensionError || Certificate.Parsed.VerifyHostNameError ||
    Certificate.Parsed.VerifyError)!void {
    if (subject_index + 1 >= max_chain_certificates) return error.CertificateChainTooLong;

    const rights = try issuerRights(issuer);
    if (!rights.has_basic_constraints or !rights.is_ca) return error.CertificateIssuerNotCa;
    if (rights.has_key_usage and !rights.may_sign_certificates) {
        return error.CertificateIssuerCannotSignCertificates;
    }
    if (rights.has_ext_key_usage and !rights.may_authenticate_server) {
        return error.CertificateNotForServerAuth;
    }
    if (rights.path_len) |limit| {
        if (subject_index > limit) return error.CertificatePathLengthExceeded;
    }
    if (rights.name_constraints) |value| {
        if (chain_host) |host| {
            var storage: [16]u8 = undefined;
            try checkNameConstraints(
                issuer.certificate.buffer,
                value,
                wantedName(host, &storage),
            );
        }
    }

    try subject.verify(issuer, now_sec);
}

/// The one door from the QUIC handshake into this file.
///
/// ZURL PATCH: not upstream. RFC 9001 carries the TLS 1.3 handshake in QUIC
/// CRYPTO frames and not in TLS records, so `init` above cannot run it:
/// `init` reads records and it produces no per-level secret. The package
/// `zurl-quic-tls` runs the message state machine for QUIC, and it calls
/// the parts below rather than write them a second time.
///
/// **Everything that decides trust is here and not there.** The host name
/// walk, the address walk, the chain walk, the trust store, and the
/// signature check all run in this file for both transports. So a rule
/// added here reaches QUIC on the same day, and there is no second path
/// with weaker checks. The QUIC package holds no certificate code at all.
///
/// The key exchange is here for the same reason. `KeyShare` above already
/// holds the four groups, their deterministic generation, and the shared
/// secret each one produces.
pub const quic = struct {
    /// How many bytes of entropy `KeyExchange.init` reads. The same seed
    /// `init` above gives `KeyShare`.
    pub const key_exchange_seed_len = 176;

    /// The named groups a QUIC client hello may offer a key share for.
    ///
    /// `x25519_ml_kem768` is left out on purpose. Its share is 1216 bytes,
    /// which alone passes the 1200-byte bound RFC 9000 section 14.1 puts on
    /// a client's first datagram, so a hello carrying it must be split
    /// across datagrams before the client knows the peer exists. Every
    /// server that speaks HTTP/3 accepts `x25519`.
    pub const key_share_groups: []const tls.NamedGroup = &.{
        .x25519,
        .secp256r1,
        .secp384r1,
    };

    /// The ephemeral key pairs one handshake offers, and the shared secret
    /// the server's choice produces.
    ///
    /// This is `KeyShare` above with a public door on it. The generation,
    /// the four groups, and every scalar multiplication are that type's,
    /// so there is one Diffie-Hellman in this build.
    pub const KeyExchange = struct {
        inner: KeyShare,

        /// A seed of all zeroes gives an identity element, which is the one
        /// fault generation can report.
        pub fn init(seed: *const [key_exchange_seed_len]u8) error{InsufficientEntropy}!KeyExchange {
            return .{ .inner = KeyShare.init(seed) catch return error.InsufficientEntropy };
        }

        /// Writes one `KeyShareEntry` of RFC 8446 section 4.2.8: two bytes
        /// of group, two bytes of length, then the public key.
        ///
        /// `group` must be one of `key_share_groups`. Anything else is
        /// `error.TlsIllegalParameter`, so a group this file cannot answer
        /// never reaches the wire.
        pub fn writeShare(
            ke: *const KeyExchange,
            w: *Writer,
            group: tls.NamedGroup,
        ) (Writer.Error || error{TlsIllegalParameter})!void {
            switch (group) {
                .x25519 => try writeShareBytes(w, group, &ke.inner.x25519_kp.public_key),
                .secp256r1 => {
                    const point = ke.inner.secp256r1_kp.public_key.toUncompressedSec1();
                    try writeShareBytes(w, group, &point);
                },
                .secp384r1 => {
                    const point = ke.inner.secp384r1_kp.public_key.toUncompressedSec1();
                    try writeShareBytes(w, group, &point);
                },
                else => return error.TlsIllegalParameter,
            }
        }

        fn writeShareBytes(w: *Writer, group: tls.NamedGroup, key: []const u8) Writer.Error!void {
            try w.writeInt(u16, @intFromEnum(group), .big);
            try w.writeInt(u16, @intCast(key.len), .big);
            try w.writeAll(key);
        }

        /// Reads the server's share and keeps the shared secret.
        ///
        /// `server_pub_key` is bytes the peer chose, and every length in it
        /// is checked by `KeyShare.exchange` before any scalar
        /// multiplication runs.
        pub fn exchange(
            ke: *KeyExchange,
            group: tls.NamedGroup,
            server_pub_key: []const u8,
        ) error{ TlsIllegalParameter, TlsDecryptFailure }!void {
            return ke.inner.exchange(group, server_pub_key);
        }

        /// The shared secret, or null while no exchange has run.
        pub fn sharedSecret(ke: *const KeyExchange) ?[]const u8 {
            return ke.inner.getSharedSecret();
        }
    };

    /// The public key of the peer's leaf certificate, and the check of the
    /// CertificateVerify signature made with it.
    ///
    /// This is `CertificatePublicKey` above with a public door on it, so
    /// the ECDSA curve rule, the RSA modulus widths, and the Ed25519 arm
    /// are the ones `init` uses.
    pub const CertificateKey = struct {
        inner: CertificatePublicKey,

        /// Nothing is known until `verifyCertificate` fills it in. A
        /// signature check before that is a programming fault and not a
        /// peer's fault, so `verifySignature` asserts rather than reports.
        pub const empty: CertificateKey = .{ .inner = .{
            .algo = .{ .rsaEncryption = {} },
            .buf = @splat(0),
            .len = 0,
        } };

        /// Whether a leaf certificate has been read.
        pub fn isSet(key: *const CertificateKey) bool {
            return key.inner.len != 0;
        }

        /// Every fault the signature check can report. The set is
        /// `CertificatePublicKey.VerifyError`, so a scheme added there
        /// reaches the QUIC caller with no change here.
        pub const VerifyError = CertificatePublicKey.VerifyError;

        /// Checks the signature of a CertificateVerify message.
        ///
        /// `sigd` covers the message body and nothing else. `msg` is the
        /// content RFC 8446 section 4.4.3 signs. The version is always TLS
        /// 1.3 here, because RFC 9001 section 4.2 gives QUIC no other one,
        /// so the ECDSA curve rule stays the strict one.
        pub fn verifySignature(
            key: *const CertificateKey,
            sigd: *tls.Decoder,
            msg: []const []const u8,
        ) VerifyError!void {
            assert(key.isSet());
            return key.inner.verifySignature(sigd, msg, .tls_1_3);
        }
    };

    /// Every fault `verifyCertificate` can report.
    pub const VerifyCertificateError = error{
        TlsDecodeError,
        TlsIllegalParameter,
        TlsCertificateNotVerified,
        CertificatePublicKeyInvalid,
    } || IssuerError || StrengthError || certificate.ParseError ||
        Certificate.Parsed.VerifyHostNameError ||
        Certificate.Parsed.VerifyError || Certificate.Bundle.VerifyError ||
        std.Io.Cancelable;

    /// Runs the whole certificate check of a TLS 1.3 handshake over one
    /// Certificate message.
    ///
    /// `body` is the message body, which is the bytes after the four byte
    /// handshake header. `host` and `ca` are the two `Options` fields, by
    /// their own types, so a change to either shape reaches this call at
    /// compile time.
    ///
    /// **The order is the order `init` uses.** The host name of the leaf is
    /// checked first, on bytes nobody has authenticated yet, which is why
    /// `verifyHost` bounds every DER element it reads. Then each
    /// certificate is checked against the one before it, and each is
    /// offered to the trust store. A run that reaches the end of the list
    /// with nothing trusted is `error.TlsCertificateNotVerified`.
    ///
    /// `key_out` takes the public key of the leaf, for the
    /// CertificateVerify message that follows.
    pub fn verifyCertificate(
        body: []u8,
        host: @FieldType(Options, "host"),
        ca: @FieldType(Options, "ca"),
        realtime_now: std.Io.Timestamp,
        key_out: *CertificateKey,
    ) VerifyCertificateError!void {
        const now_sec = realtime_now.toSeconds();

        var d: tls.Decoder = .fromTheirSlice(body);
        // RFC 8446 section 4.4.2: the request context is empty in a
        // server's Certificate message.
        try d.ensure(1 + 3);
        if (d.decode(u8) != 0) return error.TlsIllegalParameter;
        const list_len = d.decode(u24);
        var certs = try d.sub(list_len);
        // The message carries the list and nothing after it.
        if (!d.eof()) return error.TlsIllegalParameter;

        var cert_index: usize = 0;
        var prev_cert: Certificate.Parsed = undefined;
        // The two values the chain rules need beyond one pair of
        // certificates. They are read here exactly as `init` reads them,
        // so both transports give `verifyIssued` the same answers.
        const chain_host: ?[]const u8 = switch (host) {
            .no_verification => null,
            .explicit => |name| name,
        };
        const trust_checked = ca != .no_verification;
        while (!certs.eof()) {
            try certs.ensure(3);
            const cert_size = certs.decode(u24);
            const certd = try certs.sub(cert_size);
            // Each entry carries its own extensions in TLS 1.3. Nothing
            // here reads one, and stepping over it is what keeps the
            // list walk in step with the bytes.
            try certs.ensure(2);
            const ext_size = certs.decode(u16);
            _ = try certs.sub(ext_size);

            const subject_cert: Certificate = .{
                .buffer = certd.buf,
                .index = @intCast(certd.idx),
            };
            // ZURL PATCH: the bounded reader, the same one the walk in
            // `init` uses. `Certificate.parse` has no bound check, and this
            // walk reads a certificate the peer sent before the host check
            // and before any trust check. See `certificate.zig`.
            const subject = try certificate.parse(subject_cert);
            try verifyCertificateStrength(subject, trust_checked);
            if (cert_index == 0) {
                try verifyEndEntity(subject, trust_checked);
                switch (host) {
                    .no_verification => {},
                    .explicit => |name| try verifyHost(subject, name),
                }
                try key_out.inner.init(subject.pub_key_algo, subject.pubKey());
            } else {
                try verifyIssued(prev_cert, subject, chain_host, cert_index - 1, now_sec);
            }

            switch (ca) {
                .no_verification => return,
                .self_signed => {
                    try subject.verify(subject, now_sec);
                    return;
                },
                .bundle => |trust| if (verify: {
                    try trust.lock.lockShared(trust.io);
                    defer trust.lock.unlockShared(trust.io);
                    break :verify trust.bundle.verify(subject, now_sec);
                }) {
                    return;
                } else |err| switch (err) {
                    error.CertificateIssuerNotFound => {},
                    else => |e| return e,
                },
            }

            prev_cert = subject;
            cert_index += 1;
        }

        // Every certificate was read and none of them reached a trust
        // root. `init` reports the same name through `tryDownloadRootCert`.
        return error.TlsCertificateNotVerified;
    }

    /// Writes the ALPN extension for `protocols`, and gives back the bytes
    /// it wrote.
    ///
    /// This is `encodeAlpn` above, which `init` uses for the same offer.
    /// One encoder, so a QUIC hello and a TLS hello carry the same bytes
    /// for the same list.
    pub fn encodeAlpnExtension(
        protocols: []const []const u8,
        out: *[alpn_extension_max]u8,
    ) error{TlsAlpnOfferInvalid}![]const u8 {
        return encodeAlpn(protocols, out);
    }

    /// Reads the peer's ALPN answer and checks it against the offer.
    ///
    /// This is `readAlpn` above. A name outside the offer stops the
    /// handshake in both transports.
    ///
    /// **QUIC has no answer of "none".** RFC 9001 section 8.1 requires ALPN
    /// on every QUIC connection, so the caller reports a missing extension
    /// as a fault. This call answers only for an extension that arrived.
    pub fn readAlpnAnswer(
        extd: *tls.Decoder,
        offered: []const []const u8,
    ) error{ TlsDecodeError, TlsIllegalParameter, TlsAlpnProtocolNotOffered }!AlpnSelection {
        return readAlpn(extd, offered);
    }
};

const testing = std.testing;

/// The ECDSA type for one certificate curve and one signature scheme.
///
/// ZURL PATCH: not upstream. `SchemeEcdsa` takes both the curve and the hash
/// from the scheme, which is the TLS 1.3 meaning. This takes the curve from
/// the certificate and only the hash from the scheme.
///
/// `curve` must not be `secp521r1`. `NamedCurve.Curve` refuses that one at
/// compile time, and `verifyEcdsa` reports it before it gets here.
fn CertificateEcdsa(
    comptime curve: Certificate.NamedCurve,
    comptime scheme: tls.SignatureScheme,
) type {
    return crypto.sign.ecdsa.Ecdsa(curve.Curve(), SchemeHash(scheme));
}

/// The curve that TLS 1.3 gives the name of an ECDSA signature scheme.
///
/// ZURL PATCH: not upstream.
fn schemeCurve(comptime scheme: tls.SignatureScheme) Certificate.NamedCurve {
    return switch (scheme) {
        .ecdsa_secp256r1_sha256 => .X9_62_prime256v1,
        .ecdsa_secp384r1_sha384 => .secp384r1,
        else => @compileError("bad scheme"),
    };
}

/// Verifies an ECDSA signature over `msg` with the public key of the server
/// certificate.
///
/// ZURL PATCH: not upstream. The hash comes from `scheme` and the curve comes
/// from `named_curve`, which the certificate gives.
///
/// TLS 1.2 codes an ECDSA signature as a hash and a signature algorithm, and
/// the two are free of each other. RFC 5246 section 7.4.1.4.1 and RFC 8422
/// section 5.1.3 say so. A server with a P-256 key may therefore sign with
/// SHA-384, and `ecc256.badssl.com` does.
///
/// TLS 1.3 gave each code point one name that fixes the curve as well. RFC
/// 8446 section 4.2.3 requires the curve of the key to be the curve in the
/// name. So the check below holds TLS 1.3 to that rule and lets TLS 1.2 use
/// the curve of the certificate.
fn verifyEcdsa(
    comptime scheme: tls.SignatureScheme,
    named_curve: Certificate.NamedCurve,
    tls_version: tls.ProtocolVersion,
    pub_key: []const u8,
    encoded_sig: []const u8,
    msg: []const []const u8,
) CertificatePublicKey.VerifyError!void {
    if (tls_version != .tls_1_2 and named_curve != comptime schemeCurve(scheme)) {
        return error.TlsBadSignatureScheme;
    }

    switch (named_curve) {
        inline .X9_62_prime256v1, .secp384r1 => |comptime_curve| {
            const Ecdsa = CertificateEcdsa(comptime_curve, scheme);
            const sig = try Ecdsa.Signature.fromDer(encoded_sig);
            const key = try Ecdsa.PublicKey.fromSec1(pub_key);
            var ver = try sig.verifier(key);
            for (msg) |part| ver.update(part);
            try ver.verify();
        },
        // This client has no P-521, so a certificate on that curve cannot be
        // verified whatever the scheme says.
        .secp521r1 => return error.TlsBadSignatureScheme,
    }
}

/// Signs `msg` with a fresh key on `curve` and the hash of `scheme`, then
/// runs `verifyEcdsa` over the result. The key is deterministic, so the test
/// is the same on every run.
///
/// ZURL PATCH: not upstream.
fn signAndVerifyEcdsa(
    comptime curve: Certificate.NamedCurve,
    comptime scheme: tls.SignatureScheme,
    tls_version: tls.ProtocolVersion,
    msg: []const u8,
) !void {
    const Ecdsa = CertificateEcdsa(curve, scheme);
    const seed = [_]u8{0x2a} ** Ecdsa.KeyPair.seed_length;
    const pair = try Ecdsa.KeyPair.generateDeterministic(seed);

    const signature = try pair.sign(msg, null);
    var der_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const der = signature.toDer(&der_buf);

    const sec1 = pair.public_key.toUncompressedSec1();
    return verifyEcdsa(scheme, curve, tls_version, &sec1, der, &.{msg});
}

test "TLS 1.2 takes the ECDSA curve from the certificate and the hash from the scheme" {
    // The second half of the defect. `ecc256.badssl.com` holds a P-256 key
    // and signs the Server Key Exchange with SHA-384. Over TLS 1.2 that is
    // legal, because the code point there names the hash alone. Upstream
    // reads the code point the TLS 1.3 way, parses the P-256 point as a P-384
    // point, and reports `InvalidEncoding`.
    try signAndVerifyEcdsa(.X9_62_prime256v1, .ecdsa_secp384r1_sha384, .tls_1_2, "server key exchange");
    try signAndVerifyEcdsa(.secp384r1, .ecdsa_secp256r1_sha256, .tls_1_2, "server key exchange");
}

test "a scheme whose curve matches the certificate works under either version" {
    for ([_]tls.ProtocolVersion{ .tls_1_2, .tls_1_3 }) |version| {
        try signAndVerifyEcdsa(.X9_62_prime256v1, .ecdsa_secp256r1_sha256, version, "hello");
        try signAndVerifyEcdsa(.secp384r1, .ecdsa_secp384r1_sha384, version, "hello");
    }
}

test "TLS 1.3 still holds the curve of the scheme against the certificate" {
    // RFC 8446 section 4.2.3 gives each code point one curve, so the leniency
    // above must not reach TLS 1.3.
    try testing.expectError(
        error.TlsBadSignatureScheme,
        signAndVerifyEcdsa(.X9_62_prime256v1, .ecdsa_secp384r1_sha384, .tls_1_3, "certificate verify"),
    );
    try testing.expectError(
        error.TlsBadSignatureScheme,
        signAndVerifyEcdsa(.secp384r1, .ecdsa_secp256r1_sha256, .tls_1_3, "certificate verify"),
    );
}

test "a signature over other bytes fails whatever the curve is" {
    // The leniency widens which key the client parses and not which signature
    // it accepts.
    const Ecdsa = CertificateEcdsa(.X9_62_prime256v1, .ecdsa_secp384r1_sha384);
    const seed = [_]u8{0x2a} ** Ecdsa.KeyPair.seed_length;
    const pair = try Ecdsa.KeyPair.generateDeterministic(seed);

    const signature = try pair.sign("the message that was signed", null);
    var der_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const der = signature.toDer(&der_buf);
    const sec1 = pair.public_key.toUncompressedSec1();

    try testing.expectError(error.SignatureVerificationFailed, verifyEcdsa(
        .ecdsa_secp384r1_sha384,
        .X9_62_prime256v1,
        .tls_1_2,
        &sec1,
        der,
        &.{"another message"},
    ));
}

test "a certificate on a curve this client has no code for reports" {
    var der: [8]u8 = undefined;
    var sec1: [97]u8 = undefined;
    try testing.expectError(error.TlsBadSignatureScheme, verifyEcdsa(
        .ecdsa_secp384r1_sha384,
        .secp521r1,
        .tls_1_2,
        &sec1,
        &der,
        &.{"anything"},
    ));
}

test "schemeCurve gives the curve that the TLS 1.3 name holds" {
    try testing.expectEqual(Certificate.NamedCurve.X9_62_prime256v1, comptime schemeCurve(.ecdsa_secp256r1_sha256));
    try testing.expectEqual(Certificate.NamedCurve.secp384r1, comptime schemeCurve(.ecdsa_secp384r1_sha384));
}

/// The suites this client offers, in the order that the Client Hello sends
/// them.
///
/// ZURL PATCH: not upstream. `cipher_suites` is the wire form, which is a
/// byte count and then two bytes for each suite. This reads it back.
fn offeredCipherSuites() [(cipher_suites.len - 2) / 2]tls.CipherSuite {
    var suites: [(cipher_suites.len - 2) / 2]tls.CipherSuite = undefined;
    for (&suites, 0..) |*suite, index| {
        const offset = 2 + index * 2;
        suite.* = @enumFromInt(mem.readInt(u16, cipher_suites[offset..][0..2], .big));
    }
    return suites;
}

/// The position of a suite in the offered list, or null when the list omits
/// it.
///
/// ZURL PATCH: not upstream.
fn offeredIndex(suites: []const tls.CipherSuite, want: tls.CipherSuite) ?usize {
    for (suites, 0..) |suite, index| {
        if (suite == want) return index;
    }
    return null;
}

test "the offered suites hold the ECDSA form of every TLS 1.2 suite" {
    // The defect this patch fixes. Upstream offers only the `ECDHE_RSA` form,
    // so a server with an ECDSA certificate that speaks only TLS 1.2 shares no
    // suite with this client and sends an alert.
    const suites = offeredCipherSuites();
    const pairs = [_]struct { ecdsa: tls.CipherSuite, rsa: tls.CipherSuite }{
        .{
            .ecdsa = .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            .rsa = .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        },
        .{
            .ecdsa = .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            .rsa = .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        },
        .{
            .ecdsa = .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            .rsa = .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        },
    };

    for (pairs) |pair| {
        const ecdsa_at = offeredIndex(&suites, pair.ecdsa) orelse {
            std.debug.print("the offered list omits {t}\n", .{pair.ecdsa});
            return error.TestExpectedEqual;
        };
        const rsa_at = offeredIndex(&suites, pair.rsa) orelse {
            std.debug.print("the offered list omits {t}\n", .{pair.rsa});
            return error.TestExpectedEqual;
        };
        // The ECDSA form comes first, which is the order curl sends. A server
        // that holds both certificates then gives the faster one.
        try testing.expect(ecdsa_at < rsa_at);
    }
}

test "the offered suites still hold every TLS 1.3 suite" {
    // The TLS 1.3 suites name no signature algorithm, so they already worked
    // with an ECDSA certificate. This test says the patch took none of them
    // away.
    const suites = offeredCipherSuites();
    for ([_]tls.CipherSuite{
        .AEGIS_128L_SHA256,
        .AEGIS_256_SHA512,
        .AES_128_GCM_SHA256,
        .AES_256_GCM_SHA384,
        .CHACHA20_POLY1305_SHA256,
    }) |want| {
        try testing.expect(offeredIndex(&suites, want) != null);
    }
}

test "the Client Hello sends the byte count of the suites that follow it" {
    // `array` writes the count, so a suite added by hand and not through it
    // would make a Client Hello that no server can read.
    const count = mem.readInt(u16, cipher_suites[0..2], .big);
    try testing.expectEqual(cipher_suites.len - 2, count);
    try testing.expectEqual(@as(usize, 0), count % 2);
}

/// Builds one cleartext Server Hello record that names `suite` and TLS 1.2.
///
/// ZURL PATCH: not upstream. The record carries no extension, so `init` reads
/// the version from the legacy field. The random bytes are zero, which is not
/// the "DOWNGRD" sentinel that `init` refuses.
fn serverHello12(suite: tls.CipherSuite, out: []u8) []u8 {
    const body = int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
        [1]u8{0} ** 32 ++ // random
        [1]u8{0} ++ // legacy_session_id_echo, empty
        int(u16, @intFromEnum(suite)) ++
        [1]u8{0}; // legacy_compression_method

    const handshake = [1]u8{@intFromEnum(tls.HandshakeType.server_hello)} ++
        int(u24, body.len) ++
        body;

    const record = [1]u8{@intFromEnum(tls.ContentType.handshake)} ++
        int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
        int(u16, handshake.len) ++
        handshake;

    @memcpy(out[0..record.len], &record);
    return out[0..record.len];
}

/// Runs `init` against one Server Hello and gives back the error it stops on.
///
/// ZURL PATCH: not upstream. The record is the only thing the fake server
/// says, so a handshake that gets past the suite reads end of stream and
/// reports `TlsConnectionTruncated`. That error is therefore the proof that
/// the suite was accepted, and `TlsIllegalParameter` is the proof that it was
/// not.
fn initAgainstServerHello(suite: tls.CipherSuite) anyerror {
    var read_buf: [min_buffer_len]u8 = undefined;
    var input: Reader = .fixed(&read_buf);
    input.end = serverHello12(suite, &read_buf).len;

    var write_buf: [4096]u8 = undefined;
    var discarding: Writer.Discarding = .init(&write_buf);

    var app_read_buf: [max_ciphertext_len]u8 = undefined;
    var app_write_buf: [max_ciphertext_len]u8 = undefined;
    var entropy: [Options.entropy_len]u8 = undefined;
    // A fixed seed keeps the test the same on every run. It must not be all
    // zeroes, because `KeyShare.init` refuses that seed.
    for (&entropy, 0..) |*byte, index| byte.* = @truncate(index + 1);

    const client = init(&input, &discarding.writer, .{
        .host = .no_verification,
        .ca = .no_verification,
        .write_buffer = &app_write_buf,
        .read_buffer = &app_read_buf,
        .entropy = &entropy,
        .realtime_now = .{ .nanoseconds = 0 },
    });
    _ = client catch |err| return err;
    return error.TestUnexpectedResult;
}

test "a TLS 1.2 Server Hello that names an ECDSA suite gets past suite selection" {
    // This is the arm the patch adds. Upstream stops here with
    // `TlsIllegalParameter`, because the suite is not one of the three it
    // knows. With the patch the handshake goes on to the certificate, and the
    // fake server says nothing more, so the truncation error is what comes
    // back.
    for ([_]tls.CipherSuite{
        .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    }) |suite| {
        try testing.expectEqual(error.TlsConnectionTruncated, initAgainstServerHello(suite));
    }
}

test "a TLS 1.2 Server Hello that names an RSA suite still gets past suite selection" {
    for ([_]tls.CipherSuite{
        .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    }) |suite| {
        try testing.expectEqual(error.TlsConnectionTruncated, initAgainstServerHello(suite));
    }
}

test "a TLS 1.2 Server Hello that names a suite this client does not offer stops" {
    // The patch widens the arm and does not open it. A suite that the Client
    // Hello never sent is still an illegal parameter.
    for ([_]tls.CipherSuite{
        .RSA_WITH_AES_128_CBC_SHA,
        .ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        .DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    }) |suite| {
        try testing.expectEqual(error.TlsIllegalParameter, initAgainstServerHello(suite));
    }
}

/// Builds one cleartext TLS 1.2 Server Hello whose random carries the RFC
/// 8446 downgrade sentinel.
///
/// ZURL PATCH: not upstream. A server that speaks TLS 1.3 and negotiates
/// TLS 1.2 has to set these last eight bytes. RFC 8446 section 4.1.3 asks a
/// client that **offered** TLS 1.3 to abort on them.
fn serverHello12Downgrade(suite: tls.CipherSuite, out: []u8) []u8 {
    const body = int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
        [1]u8{0} ** 24 ++ "DOWNGRD".* ++ [1]u8{0x01} ++ // random
        [1]u8{0} ++ // legacy_session_id_echo, empty
        int(u16, @intFromEnum(suite)) ++
        [1]u8{0}; // legacy_compression_method

    const handshake = [1]u8{@intFromEnum(tls.HandshakeType.server_hello)} ++
        int(u24, body.len) ++
        body;

    const record = [1]u8{@intFromEnum(tls.ContentType.handshake)} ++
        int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
        int(u16, handshake.len) ++
        handshake;

    @memcpy(out[0..record.len], &record);
    return out[0..record.len];
}

/// Runs `init` against the downgrade Server Hello and gives back the error
/// it stops on.
///
/// ZURL PATCH: not upstream. `TlsConnectionTruncated` means the sentinel was
/// accepted and the handshake went on; `TlsIllegalParameter` means it was
/// refused.
fn initAgainstDowngrade(max_version: tls.ProtocolVersion) anyerror {
    var read_buf: [min_buffer_len]u8 = undefined;
    var input: Reader = .fixed(&read_buf);
    input.end = serverHello12Downgrade(.ECDHE_RSA_WITH_AES_128_GCM_SHA256, &read_buf).len;

    var write_buf: [4096]u8 = undefined;
    var discarding: Writer.Discarding = .init(&write_buf);

    var app_read_buf: [max_ciphertext_len]u8 = undefined;
    var app_write_buf: [max_ciphertext_len]u8 = undefined;
    var entropy: [Options.entropy_len]u8 = undefined;
    for (&entropy, 0..) |*byte, index| byte.* = @truncate(index + 1);

    const client = init(&input, &discarding.writer, .{
        .host = .no_verification,
        .ca = .no_verification,
        .write_buffer = &app_write_buf,
        .read_buffer = &app_read_buf,
        .entropy = &entropy,
        .realtime_now = .{ .nanoseconds = 0 },
        .max_version = max_version,
    });
    _ = client catch |err| return err;
    return error.TestUnexpectedResult;
}

test "the downgrade sentinel stops a client that offered TLS 1.3, and not one that did not" {
    // ZURL PATCH: not upstream. The check belongs to a client that offered
    // TLS 1.3 and was answered with TLS 1.2, which is the attack RFC 8446
    // section 4.1.3 names. A client capped at TLS 1.2 asked for exactly
    // what it got, and a real server sets the sentinel anyway: measured,
    // `--tls-max 1.2` against cloudflare.com aborted here before this
    // guard, where curl runs the transfer.
    try testing.expectEqual(error.TlsIllegalParameter, initAgainstDowngrade(.tls_1_3));
    try testing.expectEqual(error.TlsConnectionTruncated, initAgainstDowngrade(.tls_1_2));
}

/// Runs `init` far enough to write one Client Hello, and gives back the
/// bytes it wrote.
///
/// ZURL PATCH: not upstream. The fake server says nothing, so `init` always
/// fails; the hello is already on the writer by then, which is what this
/// reads back. `out` must hold a whole hello.
fn clientHelloBytes(max_version: tls.ProtocolVersion, out: []u8) []const u8 {
    return clientHelloBytesAlpn(max_version, &.{}, out);
}

/// The same, for a run that offers a list of ALPN protocols.
///
/// ZURL PATCH: not upstream.
fn clientHelloBytesAlpn(
    max_version: tls.ProtocolVersion,
    alpn_protocols: []const []const u8,
    out: []u8,
) []const u8 {
    var read_buf: [min_buffer_len]u8 = undefined;
    var input: Reader = .fixed(&read_buf);
    // The buffer has to be `min_buffer_len`, which `init` asserts, and
    // the fake server has said nothing at all.
    input.end = 0;

    var written: Writer = .fixed(out);

    var app_read_buf: [max_ciphertext_len]u8 = undefined;
    var app_write_buf: [max_ciphertext_len]u8 = undefined;
    var entropy: [Options.entropy_len]u8 = undefined;
    for (&entropy, 0..) |*byte, index| byte.* = @truncate(index + 1);

    const client = init(&input, &written, .{
        .host = .no_verification,
        .ca = .no_verification,
        .write_buffer = &app_write_buf,
        .read_buffer = &app_read_buf,
        .entropy = &entropy,
        .realtime_now = .{ .nanoseconds = 0 },
        .max_version = max_version,
        .alpn_protocols = alpn_protocols,
    });
    _ = client catch {};
    return written.buffered();
}

/// The `supported_versions` extension payload inside one Client Hello.
///
/// ZURL PATCH: not upstream. The extension is `002b`, then a two-byte
/// length, then the one-byte list length, then the entries.
fn supportedVersionsOf(hello: []const u8) []const u8 {
    const at = mem.indexOf(u8, hello, &[_]u8{ 0x00, 0x2b, 0x00, 0x05, 0x04 }).?;
    return hello[at + 5 ..][0..4];
}

test "the Client Hello offers both versions unless --tls-max narrows it" {
    // ZURL PATCH: not upstream. This pins the whole `--tls-max` patch to
    // the bytes on the wire. Measured against a loopback listener that
    // dumped the real hello: a bare run and a `--tls-max 1.3` run both
    // send `0304 0303`, and `--tls-max 1.2` sends `0a0a 0303`.
    var both_buf: [4096]u8 = undefined;
    const both = supportedVersionsOf(clientHelloBytes(.tls_1_3, &both_buf));
    try testing.expectEqualSlices(u8, &[_]u8{ 0x03, 0x04, 0x03, 0x03 }, both);

    var capped_buf: [4096]u8 = undefined;
    const capped = supportedVersionsOf(clientHelloBytes(.tls_1_2, &capped_buf));
    // The TLS 1.3 entry is gone, and a GREASE value that every server must
    // ignore stands in its place, so the list is still two entries long
    // and every length after it is what upstream computed.
    try testing.expectEqualSlices(u8, &[_]u8{ 0x0a, 0x0a, 0x03, 0x03 }, capped);

    // The two hellos are the same length. That is the property the patch
    // rests on: nothing else in the record had to be recomputed.
    var a_buf: [4096]u8 = undefined;
    var b_buf: [4096]u8 = undefined;
    try testing.expectEqual(
        clientHelloBytes(.tls_1_3, &a_buf).len,
        clientHelloBytes(.tls_1_2, &b_buf).len,
    );
}

/// One subject alternative name, as a test writes it.
///
/// ZURL PATCH: not upstream.
const GeneralName = struct {
    tag: Certificate.GeneralNameTag,
    /// The value of the name. For an `iPAddress` these are the raw address
    /// bytes, four or sixteen of them, and never text.
    bytes: []const u8,
};

/// The longest subject alternative name block the tests below build.
///
/// ZURL PATCH: not upstream. A name of a single length byte holds at most
/// 127 bytes, and the block below stays far under both bounds.
const test_san_max = 256;

/// Writes `names` into `out` as a DER SEQUENCE of general names, and
/// returns the part of `out` that holds it.
///
/// ZURL PATCH: not upstream. This is the exact shape a certificate carries,
/// so a test reads the same bytes `verifyIpAddress` reads off the wire. A
/// general name is one identifier byte, one length byte, and its value.
/// The identifier is context specific and primitive, which is the top two
/// bits set and the fifth clear, plus the tag number of the name.
fn buildSan(out: []u8, names: []const GeneralName) []const u8 {
    var at: usize = 2;
    for (names) |name| {
        std.debug.assert(name.bytes.len < 128);
        std.debug.assert(at + 2 + name.bytes.len <= out.len);
        out[at] = 0x80 | @as(u8, @intFromEnum(name.tag));
        out[at + 1] = @intCast(name.bytes.len);
        @memcpy(out[at + 2 ..][0..name.bytes.len], name.bytes);
        at += 2 + name.bytes.len;
    }
    std.debug.assert(at - 2 < 128);
    out[0] = 0x30;
    out[1] = @intCast(at - 2);
    return out[0..at];
}

/// A `Certificate.Parsed` that carries `san` and a common name of `cn`.
///
/// ZURL PATCH: not upstream. `verifyHost` reads the subject alternative
/// names and the common name, and no other part of a certificate, so every
/// other field stays undefined and no test below touches one.
fn parsedWithSan(buffer: []const u8, san_len: usize, cn_len: usize) Certificate.Parsed {
    var parsed: Certificate.Parsed = undefined;
    parsed.certificate = .{ .buffer = buffer, .index = 0 };
    parsed.subject_alt_name_slice = .{ .start = 0, .end = @intCast(san_len) };
    parsed.common_name_slice = .{ .start = @intCast(san_len), .end = @intCast(san_len + cn_len) };
    return parsed;
}

test "an iPAddress name matches the address that was asked for" {
    // The whole defect. `https://1.1.1.1/` exited 60 where curl 8.21.0
    // exits 0, because the walk read a `dNSName` and skipped every other
    // kind, and those certificates carry an `iPAddress`.
    var storage: [test_san_max]u8 = undefined;

    const ip4 = buildSan(&storage, &.{
        .{ .tag = .dNSName, .bytes = "one.one.one.one" },
        .{ .tag = .iPAddress, .bytes = &.{ 1, 1, 1, 1 } },
    });
    try verifyHost(parsedWithSan(ip4, ip4.len, 0), "1.1.1.1");

    var storage6: [test_san_max]u8 = undefined;
    const ip6 = buildSan(&storage6, &.{
        .{ .tag = .iPAddress, .bytes = &.{
            0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0,    0,
            0,    0,    0,    0,    0,    0,    0x11, 0x11,
        } },
    });
    try verifyHost(parsedWithSan(ip6, ip6.len, 0), "2606:4700:4700::1111");
}

test "a certificate with no matching address name still fails" {
    // An address check that accepts too much is worse than one that
    // accepts nothing. Each case below names an address the certificate
    // does not carry.
    var storage: [test_san_max]u8 = undefined;

    // A different address of the same family.
    const other = buildSan(&storage, &.{.{ .tag = .iPAddress, .bytes = &.{ 1, 0, 0, 1 } }});
    try testing.expectError(
        error.CertificateHostMismatch,
        verifyHost(parsedWithSan(other, other.len, 0), "1.1.1.1"),
    );

    // The address as text, in a `dNSName`. RFC 6125 section 6.4 says a
    // client must not read an address as a domain name, so this must not
    // match however much it looks like the answer.
    const as_text = buildSan(&storage, &.{.{ .tag = .dNSName, .bytes = "1.1.1.1" }});
    try testing.expectError(
        error.CertificateHostMismatch,
        verifyHost(parsedWithSan(as_text, as_text.len, 0), "1.1.1.1"),
    );

    // A wildcard cannot cover an address either.
    const wildcard = buildSan(&storage, &.{.{ .tag = .dNSName, .bytes = "*.1.1.1" }});
    try testing.expectError(
        error.CertificateHostMismatch,
        verifyHost(parsedWithSan(wildcard, wildcard.len, 0), "1.1.1.1"),
    );

    // No subject alternative name at all. The common name holds a name,
    // and an address is not one, so there is no fallback to take.
    var empty: [16]u8 = undefined;
    @memcpy(empty[0..7], "1.1.1.1");
    try testing.expectError(
        error.CertificateHostMismatch,
        verifyHost(parsedWithSan(empty[0..7], 0, 7), "1.1.1.1"),
    );
}

test "an address name of the wrong length cannot match" {
    // An `iPAddress` name is four raw bytes for IPv4 and sixteen for IPv6.
    // A comparison that read the shorter one as a prefix of the longer
    // would let a certificate for 1.1.1.1 answer for `::ffff:101:101`, and
    // the other way round.
    var storage: [test_san_max]u8 = undefined;

    const four = buildSan(&storage, &.{.{ .tag = .iPAddress, .bytes = &.{ 1, 1, 1, 1 } }});
    try testing.expectError(
        error.CertificateHostMismatch,
        verifyHost(parsedWithSan(four, four.len, 0), "::ffff:1.1.1.1"),
    );

    var storage6: [test_san_max]u8 = undefined;
    const sixteen = buildSan(&storage6, &.{.{ .tag = .iPAddress, .bytes = &.{
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 1, 1, 1,
    } }});
    try testing.expectError(
        error.CertificateHostMismatch,
        verifyHost(parsedWithSan(sixteen, sixteen.len, 0), "1.1.1.1"),
    );
}

test "a host name keeps the upstream rule" {
    // The patch adds an address rule beside the name rule. It must change
    // nothing a name did before, because every `https` transfer to a name
    // reads this same call.
    var storage: [test_san_max]u8 = undefined;

    const names = buildSan(&storage, &.{
        .{ .tag = .dNSName, .bytes = "example.com" },
        .{ .tag = .dNSName, .bytes = "*.wild.example" },
    });
    const cert = parsedWithSan(names, names.len, 0);

    try verifyHost(cert, "example.com");
    try verifyHost(cert, "EXAMPLE.COM");
    try verifyHost(cert, "a.wild.example");
    try testing.expectError(error.CertificateHostMismatch, verifyHost(cert, "other.com"));
    try testing.expectError(error.CertificateHostMismatch, verifyHost(cert, "a.b.wild.example"));

    // A certificate that carries only an address answers for no name.
    const address_only = buildSan(&storage, &.{.{ .tag = .iPAddress, .bytes = &.{ 1, 1, 1, 1 } }});
    try testing.expectError(
        error.CertificateHostMismatch,
        verifyHost(parsedWithSan(address_only, address_only.len, 0), "example.com"),
    );
}

test "a general name that reads past the block is a length fault" {
    // Upstream trusts the length a certificate wrote. A name that claims
    // more bytes than the block holds would then index past the end of the
    // slice, so `parseName` checks it for every walk.
    var storage: [test_san_max]u8 = undefined;
    const san = buildSan(&storage, &.{.{ .tag = .iPAddress, .bytes = &.{ 1, 1, 1, 1 } }});

    // The same block, one byte short of the address it promises.
    try testing.expectError(
        error.CertificateFieldHasInvalidLength,
        verifyHost(parsedWithSan(san[0 .. san.len - 1], san.len - 1, 0), "1.1.1.1"),
    );
}

test "six bytes of subject alternative name are a length fault on the name path" {
    // The defect this walk was rewritten for. `30 20 82 1E 61 62` declares
    // a 32 byte sequence of general names holding a 30 byte `dNSName`, and
    // the block is six bytes long. `Certificate.Parsed.verifyHostName`
    // sliced `subject_alt_name[4..34]` of a six byte slice and panicked
    // with "index out of bounds: index 34, len 6". A server sends those
    // six bytes in its leaf certificate, and `init` runs this check on the
    // leaf before any trust check, so the crash came before authentication.
    //
    // Every ordinary `https://name/` transfer takes the name path, so the
    // name path is what this test drives. The address path answers the
    // same way, from the same walk and the same bound.
    const truncated = [_]u8{ 0x30, 0x20, 0x82, 0x1E, 0x61, 0x62 };

    try testing.expectError(
        error.CertificateFieldHasInvalidLength,
        verifyHost(parsedWithSan(&truncated, truncated.len, 0), "example.com"),
    );
    try testing.expectError(
        error.CertificateFieldHasInvalidLength,
        verifyHost(parsedWithSan(&truncated, truncated.len, 0), "1.1.1.1"),
    );
}

test "a general name with no length octet is a length fault" {
    // The sequence ends exactly at the end of the block, and the general
    // name inside it carries an identifier octet and no length octet.
    // `der.Element.parse` reads that missing octet as `bytes[i]`.
    const short = [_]u8{ 0x30, 0x01, 0x82 };

    try testing.expectError(
        error.CertificateFieldHasInvalidLength,
        verifyHost(parsedWithSan(&short, short.len, 0), "example.com"),
    );
    try testing.expectError(
        error.CertificateFieldHasInvalidLength,
        verifyHost(parsedWithSan(&short, short.len, 0), "1.1.1.1"),
    );
}

test "a long form length that would overflow is a length fault" {
    // Four length octets of `FF` are 4294967295. Upstream adds that to the
    // index it reached, in `u32`, so the sum wraps. `parseName` adds in
    // `u64` and compares with the length of the block.
    const overflow = [_]u8{ 0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x82, 0x01, 0x61 };

    try testing.expectError(
        error.CertificateFieldHasInvalidLength,
        verifyHost(parsedWithSan(&overflow, overflow.len, 0), "example.com"),
    );

    // Five length octets name more bytes than a `u32` holds, which is a
    // length no certificate may write.
    const too_many = [_]u8{ 0x30, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05 };
    try testing.expectError(
        error.CertificateFieldHasInvalidLength,
        verifyHost(parsedWithSan(&too_many, too_many.len, 0), "example.com"),
    );
}

test "the common name still answers for a name and never for an address" {
    // The one behaviour the walk takes from the kind of host it was given.
    // RFC 2818 lets a certificate with no subject alternative name answer
    // for its common name. RFC 6125 section 6.4.4 retired that for an
    // address.
    var storage: [16]u8 = undefined;
    @memcpy(storage[0..11], "example.com");

    try verifyHost(parsedWithSan(storage[0..11], 0, 11), "example.com");
    try testing.expectError(
        error.CertificateHostMismatch,
        verifyHost(parsedWithSan(storage[0..11], 0, 11), "other.com"),
    );
}

/// The ALPN extension for one list of protocols, as bytes a test can read.
///
/// ZURL PATCH: not upstream.
fn alpnBytes(protocols: []const []const u8, out: *[alpn_extension_max]u8) ![]const u8 {
    return encodeAlpn(protocols, out);
}

test "the ALPN extension nests three lengths that agree" {
    // The shape RFC 7301 section 3.1 gives: the extension type, the
    // extension length, the list length, then a length byte and a name.
    var buf: [alpn_extension_max]u8 = undefined;
    const one = try alpnBytes(&.{"http/1.1"}, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{
        0x00, 0x10, // application_layer_protocol_negotiation
        0x00, 0x0b, // extension length: the list and the two bytes that count it
        0x00, 0x09, // list length: one length byte and eight name bytes
        0x08, 'h',
        't',  't',
        'p',  '/',
        '1',  '.',
        '1',
    }, one);

    // The extension length is always the list length plus two, and the
    // list length is always the bytes after it.
    const ext_len = mem.readInt(u16, one[2..4], .big);
    const list_len = mem.readInt(u16, one[4..6], .big);
    try testing.expectEqual(one.len - 4, ext_len);
    try testing.expectEqual(one.len - 6, list_len);
    try testing.expectEqual(list_len + 2, ext_len);
}

test "the ALPN extension holds each name in the order it was offered" {
    // The order is the order of preference, so a list that reordered the
    // names would ask the server for the wrong protocol first. This is the
    // list zurl will offer when it grows HTTP/2.
    var buf: [alpn_extension_max]u8 = undefined;
    const two = try alpnBytes(&.{ "h2", "http/1.1" }, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{
        0x00, 0x10,
        0x00, 0x0e,
        0x00, 0x0c,
        0x02, 'h',
        '2',  0x08,
        'h',  't',
        't',  'p',
        '/',  '1',
        '.',  '1',
    }, two);
}

test "an empty ALPN list builds no extension at all" {
    // This is `--no-alpn`. Nothing is written, so the hello is the one
    // upstream always sent.
    var buf: [alpn_extension_max]u8 = undefined;
    const none = try alpnBytes(&.{}, &buf);
    try testing.expectEqual(@as(usize, 0), none.len);
}

test "an ALPN list that has no wire form is refused before the hello goes out" {
    var buf: [alpn_extension_max]u8 = undefined;

    // A name of no bytes cannot be told from the end of the list.
    try testing.expectError(error.TlsAlpnOfferInvalid, alpnBytes(&.{""}, &buf));

    // A name over 255 bytes does not fit the one length byte it gets.
    const long: [alpn_max_protocol_len + 1]u8 = @splat('x');
    try testing.expectError(error.TlsAlpnOfferInvalid, alpnBytes(&.{&long}, &buf));

    // And a list of names that together pass the bound of the buffer.
    const name: [alpn_max_protocol_len]u8 = @splat('x');
    const many = [_][]const u8{&name} ** 4;
    try testing.expectError(error.TlsAlpnOfferInvalid, alpnBytes(&many, &buf));

    // One under that bound still fits, so the refusal is the length and
    // never the count.
    const fits = [_][]const u8{&name} ** 2;
    const built = try alpnBytes(&fits, &buf);
    try testing.expectEqual(@as(usize, 6 + 2 * (1 + alpn_max_protocol_len)), built.len);
}

/// Walks the extensions of a Client Hello record and checks every length in
/// it against the bytes that follow.
///
/// ZURL PATCH: not upstream. The record header counts the handshake, the
/// handshake header counts the hello, and the hello counts its extensions.
/// This reads all three back, so a length that did not account for the ALPN
/// extension reports here.
fn checkHelloLengths(hello: []const u8) !void {
    try testing.expect(hello.len > tls.record_header_len);
    try testing.expectEqual(@intFromEnum(tls.ContentType.handshake), hello[0]);
    const record_len = mem.readInt(u16, hello[3..5], .big);
    try testing.expectEqual(hello.len - tls.record_header_len, record_len);

    const handshake = hello[tls.record_header_len..];
    try testing.expectEqual(@intFromEnum(tls.HandshakeType.client_hello), handshake[0]);
    const handshake_len = mem.readInt(u24, handshake[1..4], .big);
    try testing.expectEqual(handshake.len - 4, handshake_len);

    // The hello: version, random, session id, suites, compression, then
    // the extensions block.
    var at: usize = 4 + 2 + 32;
    const session_id_len = handshake[at];
    at += 1 + session_id_len;
    const suites_len = mem.readInt(u16, handshake[at..][0..2], .big);
    at += 2 + suites_len;
    const compression_len = handshake[at];
    at += 1 + compression_len;

    const extensions_len = mem.readInt(u16, handshake[at..][0..2], .big);
    at += 2;
    try testing.expectEqual(handshake.len - at, extensions_len);

    // And every extension inside the block, so a length that overran the
    // block cannot pass as one that fits it.
    const block_end = at + extensions_len;
    while (at < block_end) {
        try testing.expect(at + 4 <= block_end);
        const ext_len = mem.readInt(u16, handshake[at + 2 ..][0..2], .big);
        at += 4 + ext_len;
    }
    try testing.expectEqual(block_end, at);
}

/// The extensions block of one Client Hello, which is every extension and
/// none of the length that counts them.
///
/// ZURL PATCH: not upstream.
fn extensionsBlockOf(hello: []const u8) []const u8 {
    const handshake = hello[tls.record_header_len..];
    var at: usize = 4 + 2 + 32;
    at += 1 + handshake[at];
    at += 2 + mem.readInt(u16, handshake[at..][0..2], .big);
    at += 1 + handshake[at];

    const extensions_len = mem.readInt(u16, handshake[at..][0..2], .big);
    at += 2;
    return handshake[at..][0..extensions_len];
}

/// The ALPN extension inside one Client Hello, or null when it holds none.
///
/// ZURL PATCH: not upstream. It walks the extensions rather than searching
/// for the bytes, so a match cannot come from the middle of another field.
fn alpnExtensionOf(hello: []const u8) ?[]const u8 {
    const block = extensionsBlockOf(hello);
    var at: usize = 0;
    while (at < block.len) {
        const et = mem.readInt(u16, block[at..][0..2], .big);
        const ext_len = mem.readInt(u16, block[at + 2 ..][0..2], .big);
        if (et == @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation)) {
            return block[at..][0 .. 4 + ext_len];
        }
        at += 4 + ext_len;
    }
    return null;
}

test "the Client Hello carries the ALPN extension and every length still agrees" {
    // The defect this patch fixes. Upstream sends no ALPN extension, so a
    // server that offers HTTP/2 never gets the chance to say so.
    var buf: [4096]u8 = undefined;
    const hello = clientHelloBytesAlpn(.tls_1_3, &.{"http/1.1"}, &buf);
    try checkHelloLengths(hello);

    const ext = alpnExtensionOf(hello) orelse return error.TestExpectedEqual;
    var want_buf: [alpn_extension_max]u8 = undefined;
    try testing.expectEqualSlices(u8, try alpnBytes(&.{"http/1.1"}, &want_buf), ext);
}

test "a Client Hello that offers no ALPN carries no extension and still agrees" {
    // This is `--no-alpn`, and it is the hello upstream always built.
    var buf: [4096]u8 = undefined;
    const hello = clientHelloBytes(.tls_1_3, &buf);
    try checkHelloLengths(hello);
    try testing.expect(alpnExtensionOf(hello) == null);
}

test "the ALPN extension is the only difference between the two hellos" {
    // The lengths are the whole hazard of adding an extension to a hello
    // that upstream builds at compile time. Each of the three that
    // encloses the extension has to grow by exactly its size, and nothing
    // else in the hello may move.
    var with_buf: [4096]u8 = undefined;
    var without_buf: [4096]u8 = undefined;
    const with = clientHelloBytesAlpn(.tls_1_3, &.{"http/1.1"}, &with_buf);
    const without = clientHelloBytes(.tls_1_3, &without_buf);

    var want_buf: [alpn_extension_max]u8 = undefined;
    const ext = try alpnBytes(&.{"http/1.1"}, &want_buf);

    // The record.
    try testing.expectEqual(without.len + ext.len, with.len);
    try testing.expectEqual(
        mem.readInt(u16, without[3..5], .big) + ext.len,
        mem.readInt(u16, with[3..5], .big),
    );
    // The handshake message inside it.
    try testing.expectEqual(
        mem.readInt(u24, without[tls.record_header_len + 1 ..][0..3], .big) + ext.len,
        mem.readInt(u24, with[tls.record_header_len + 1 ..][0..3], .big),
    );

    // And the extensions block, which the extension is appended to. Every
    // extension upstream sends stands where it stood, and the ALPN one is
    // the tail.
    const with_block = extensionsBlockOf(with);
    const without_block = extensionsBlockOf(without);
    try testing.expectEqual(without_block.len + ext.len, with_block.len);
    try testing.expectEqualSlices(u8, without_block, with_block[0..without_block.len]);
    try testing.expectEqualSlices(u8, ext, with_block[without_block.len..]);
}

test "an ALPN offer beside --tls-max keeps both patches on the wire" {
    // The two patches write into the same hello: one replaces a version
    // entry inside the buffer, the other appends bytes after it. This
    // proves neither one moved the other.
    var buf: [4096]u8 = undefined;
    const hello = clientHelloBytesAlpn(.tls_1_2, &.{"http/1.1"}, &buf);
    try checkHelloLengths(hello);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x0a, 0x0a, 0x03, 0x03 }, supportedVersionsOf(hello));
    try testing.expect(alpnExtensionOf(hello) != null);
}

/// Reads one ALPN extension body the way `init` does.
///
/// ZURL PATCH: not upstream. `body` is the extension payload, which is the
/// list length and the list, and never the extension type or length.
fn readAlpnBody(body: []u8, offered: []const []const u8) !AlpnSelection {
    var decoder: tls.Decoder = .fromTheirSlice(body);
    return readAlpn(&decoder, offered);
}

test "the peer's ALPN answer is read back when the hello offered it" {
    var body = [_]u8{ 0x00, 0x09, 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1' };
    const selection = try readAlpnBody(&body, &.{"http/1.1"});
    try testing.expectEqualStrings("http/1.1", selection.slice().?);

    // And the answer is found wherever it stands in the offered list.
    var second = [_]u8{ 0x00, 0x03, 0x02, 'h', '2' };
    const h2 = try readAlpnBody(&second, &.{ "http/1.1", "h2" });
    try testing.expectEqualStrings("h2", h2.slice().?);
}

test "a peer that names a protocol the hello did not offer stops the handshake" {
    // The protocol violation this patch has to refuse. A client that
    // accepted it would go on to read a protocol it cannot parse.
    var body = [_]u8{ 0x00, 0x03, 0x02, 'h', '2' };
    try testing.expectError(error.TlsAlpnProtocolNotOffered, readAlpnBody(&body, &.{"http/1.1"}));

    // A hello that offered nothing at all, which is `--no-alpn`, offers no
    // name for the peer to match either.
    var same = [_]u8{ 0x00, 0x09, 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1' };
    try testing.expectError(error.TlsAlpnProtocolNotOffered, readAlpnBody(&same, &.{}));

    // A name that only starts the same is a different protocol.
    var prefix = [_]u8{ 0x00, 0x05, 0x04, 'h', 't', 't', 'p' };
    try testing.expectError(error.TlsAlpnProtocolNotOffered, readAlpnBody(&prefix, &.{"http/1.1"}));
}

test "an ALPN answer that does not decode stops the handshake" {
    // Every length in the answer comes from the peer, so each one is
    // checked against the bytes that follow it.
    const offered: []const []const u8 = &.{"http/1.1"};

    // A list length over the extension.
    var over = [_]u8{ 0x00, 0x20, 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1' };
    try testing.expectError(error.TlsDecodeError, readAlpnBody(&over, offered));

    // A name length over the list.
    var name_over = [_]u8{ 0x00, 0x09, 0x40, 'h', 't', 't', 'p', '/', '1', '.', '1' };
    try testing.expectError(error.TlsDecodeError, readAlpnBody(&name_over, offered));

    // A name of no bytes.
    var empty = [_]u8{ 0x00, 0x01, 0x00 };
    try testing.expectError(error.TlsIllegalParameter, readAlpnBody(&empty, offered));

    // Two names, where RFC 7301 section 3.2 allows exactly one.
    var two = [_]u8{ 0x00, 0x05, 0x02, 'h', '2', 0x01, 'x' };
    try testing.expectError(error.TlsIllegalParameter, readAlpnBody(&two, offered));

    // Bytes after the list, inside the same extension.
    var trailing = [_]u8{ 0x00, 0x03, 0x02, 'h', '2', 0xff };
    try testing.expectError(error.TlsIllegalParameter, readAlpnBody(&trailing, offered));
}

/// Builds one cleartext TLS 1.2 Server Hello that answers ALPN with
/// `selected`.
///
/// ZURL PATCH: not upstream. A TLS 1.2 server answers ALPN in the Server
/// Hello, so this drives the parse that `init` runs there.
fn serverHello12Alpn(selected: []const u8, out: []u8) ![]u8 {
    var ext_buf: [alpn_extension_max]u8 = undefined;
    const ext = try encodeAlpn(&.{selected}, &ext_buf);

    const fixed = int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
        [1]u8{0} ** 32 ++ // random
        [1]u8{0} ++ // legacy_session_id_echo, empty
        int(u16, @intFromEnum(tls.CipherSuite.ECDHE_RSA_WITH_AES_128_GCM_SHA256)) ++
        [1]u8{0}; // legacy_compression_method

    const body_len = fixed.len + 2 + ext.len;
    const handshake_len = 4 + body_len;
    const record_len = tls.record_header_len + handshake_len;
    try testing.expect(out.len >= record_len);

    var at: usize = 0;
    out[at] = @intFromEnum(tls.ContentType.handshake);
    at += 1;
    @memcpy(out[at..][0..2], &int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)));
    at += 2;
    @memcpy(out[at..][0..2], &int(u16, @intCast(handshake_len)));
    at += 2;
    out[at] = @intFromEnum(tls.HandshakeType.server_hello);
    at += 1;
    @memcpy(out[at..][0..3], &int(u24, @intCast(body_len)));
    at += 3;
    @memcpy(out[at..][0..fixed.len], &fixed);
    at += fixed.len;
    @memcpy(out[at..][0..2], &int(u16, @intCast(ext.len)));
    at += 2;
    @memcpy(out[at..][0..ext.len], ext);
    at += ext.len;

    try testing.expectEqual(record_len, at);
    return out[0..at];
}

/// Runs `init` against a TLS 1.2 Server Hello that answers ALPN, and gives
/// back the error it stops on.
///
/// ZURL PATCH: not upstream. `TlsConnectionTruncated` means the answer was
/// accepted and the handshake went on to ask for a certificate that the fake
/// server never sends.
fn initAgainstAlpn(offered: []const []const u8, selected: []const u8) anyerror {
    var read_buf: [min_buffer_len]u8 = undefined;
    var input: Reader = .fixed(&read_buf);
    const record = serverHello12Alpn(selected, &read_buf) catch |err| return err;
    input.end = record.len;

    var write_buf: [4096]u8 = undefined;
    var discarding: Writer.Discarding = .init(&write_buf);

    var app_read_buf: [max_ciphertext_len]u8 = undefined;
    var app_write_buf: [max_ciphertext_len]u8 = undefined;
    var entropy: [Options.entropy_len]u8 = undefined;
    for (&entropy, 0..) |*byte, index| byte.* = @truncate(index + 1);

    const client = init(&input, &discarding.writer, .{
        .host = .no_verification,
        .ca = .no_verification,
        .write_buffer = &app_write_buf,
        .read_buffer = &app_read_buf,
        .entropy = &entropy,
        .realtime_now = .{ .nanoseconds = 0 },
        .alpn_protocols = offered,
    });
    _ = client catch |err| return err;
    return error.TestUnexpectedResult;
}

test "init takes an offered ALPN answer and refuses one that was not offered" {
    // The whole path, from the offer in the hello to the answer in the
    // Server Hello. A protocol the hello named is accepted and the
    // handshake carries on, and one it did not name stops it.
    try testing.expectEqual(error.TlsConnectionTruncated, initAgainstAlpn(&.{"http/1.1"}, "http/1.1"));
    try testing.expectEqual(error.TlsAlpnProtocolNotOffered, initAgainstAlpn(&.{"http/1.1"}, "h2"));

    // And a run that offered nothing refuses every answer, so a peer
    // cannot force a protocol on `--no-alpn`.
    try testing.expectEqual(error.TlsAlpnProtocolNotOffered, initAgainstAlpn(&.{}, "http/1.1"));
}

test "a peer that answers no ALPN leaves the session with no protocol" {
    // RFC 7301 lets a server that shares no protocol with the client leave
    // the extension out. That is not a fault, and the caller keeps what it
    // speaks by default.
    const selection: AlpnSelection = .none;
    try testing.expect(selection.slice() == null);
    try testing.expectEqual(@as(u8, 0), selection.len);
}

// ---------------------------------------------------------------------
// The chain rules
//
// Every test below mints real X.509 version 3 certificates, signs them
// with real P-256 keys, and runs them through the code a fetch runs. No
// test reads a file and no test opens a socket.
// ---------------------------------------------------------------------

/// The signature type every minted certificate carries.
///
/// Public with `mint`, so a caller outside this file can name the key pair
/// it passes.
pub const TestEcdsa = crypto.sign.ecdsa.EcdsaP256Sha256;

/// Object identifiers the minter writes, without the tag and the length.
const test_oid_ecdsa_with_sha256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
const test_oid_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const test_oid_prime256v1 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const test_oid_common_name = [_]u8{ 0x55, 0x04, 0x03 };
const test_oid_subject_alt_name = [_]u8{ 0x55, 0x1D, 0x11 };
/// 2.5.29.7, the retired X.509(1988) spelling of `subjectAltName`. No
/// certificate authority profiles or validates it. `std.crypto.Certificate`
/// maps it to the same value as 2.5.29.17 and lets the last of the two
/// win, which sent the host check to names nobody signed for.
const test_oid_legacy_subject_alt_name = [_]u8{ 0x55, 0x1D, 0x07 };
/// `sha1WithRSAEncryption`, 1.2.840.113549.1.1.5. The minter writes it as
/// the name of an algorithm this client must refuse, over a signature it
/// really made with ECDSA and SHA-256. Every rule that reads it runs
/// before any signature check.
pub const test_oid_sha1_with_rsa = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05 };
/// `sha384WithRSAEncryption`, 1.2.840.113549.1.1.12. A strong algorithm
/// that the minter does not sign with, so a certificate that names it in
/// one field alone reads as two algorithms that disagree.
pub const test_oid_sha384_with_rsa = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C };
/// `id-kp-emailProtection`, 1.3.6.1.5.5.7.3.4. A purpose that is not
/// server authentication.
const test_oid_email_protection = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04 };
/// 1.3.6.1.4.1.99999.1, which sits in a private arc and names nothing.
/// The minter writes it as the identifier of a critical extension that no
/// client can read.
const test_oid_unknown = [_]u8{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8D, 0x1F, 0x01 };

/// A time inside the validity of every certificate the minter writes.
const test_now_sec: i64 = 1_700_000_000;

/// The same instant as a timestamp, for `quic.verifyCertificate`.
const test_now: std.Io.Timestamp = .{ .nanoseconds = @as(i96, test_now_sec) * std.time.ns_per_s };

/// A buffer that writes DER from the inside out.
///
/// `wrapDer` moves the body along and puts the tag and the length in
/// front of it, so a length is never written before the bytes it counts.
///
/// Public, with `mint` and `MintOptions`, because `zurl-tls/test_server.zig`
/// mints the chains it presents with this one minter. A second minter there
/// would be a second reading of RFC 5280, and the tests below and the
/// fixture would then disagree about what a certificate looks like.
pub const DerBuf = struct {
    data: [2048]u8 = undefined,
    len: usize = 0,

    fn push(self: *DerBuf, bytes: []const u8) void {
        @memcpy(self.data[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    fn byte(self: *DerBuf, value: u8) void {
        self.push(&.{value});
    }

    fn mark(self: *const DerBuf) usize {
        return self.len;
    }

    pub fn slice(self: *const DerBuf) []const u8 {
        return self.data[0..self.len];
    }

    fn wrapDer(self: *DerBuf, from: usize, tag: u8) void {
        const body = self.len - from;
        const header = 1 + testDerLengthLen(body);
        mem.copyBackwards(u8, self.data[from + header ..][0..body], self.data[from..][0..body]);
        self.data[from] = tag;
        testWriteDerLength(self.data[from + 1 ..], body);
        self.len += header;
    }

    fn oid(self: *DerBuf, bytes: []const u8) void {
        self.byte(0x06);
        self.byte(@intCast(bytes.len));
        self.push(bytes);
    }

    /// One `Name` that holds one common name and nothing else.
    fn name(self: *DerBuf, common_name: []const u8) void {
        const at = self.mark();
        const set_at = self.mark();
        const atav = self.mark();
        self.oid(&test_oid_common_name);
        self.byte(0x13);
        self.byte(@intCast(common_name.len));
        self.push(common_name);
        self.wrapDer(atav, 0x30);
        self.wrapDer(set_at, 0x31);
        self.wrapDer(at, 0x30);
    }

    /// One `AlgorithmIdentifier` that names `which`.
    fn algorithmIdentifier(self: *DerBuf, which: []const u8) void {
        const at = self.mark();
        self.oid(which);
        self.wrapDer(at, 0x30);
    }
};

fn testDerLengthLen(body: usize) usize {
    if (body < 0x80) return 1;
    if (body <= 0xff) return 2;
    return 3;
}

fn testWriteDerLength(out: []u8, body: usize) void {
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

/// What the `keyUsage` extension of a minted certificate says.
pub const MintKeyUsage = enum {
    /// No `keyUsage` extension at all.
    none,
    /// Bit 0 alone, which a leaf certificate carries.
    digital_signature,
    /// Bit 5 alone, which a certificate authority carries.
    key_cert_sign,
};

/// What the `basicConstraints` extension of a minted certificate says.
pub const MintBasicConstraints = struct {
    ca: bool,
    path_len: ?u8 = null,
};

/// What the `extendedKeyUsage` extension of a minted certificate names.
///
/// One purpose is enough for every test: a certificate that names
/// `server_auth` stands for a TLS server, and one that names
/// `email_protection` does not.
pub const MintExtKeyUsage = enum {
    /// `id-kp-serverAuth`, 1.3.6.1.5.5.7.3.1.
    server_auth,
    /// `id-kp-emailProtection`, 1.3.6.1.5.5.7.3.4.
    email_protection,
    /// `anyExtendedKeyUsage`, 2.5.29.37.0, which names every purpose.
    any,
};

/// What the `nameConstraints` extension of a minted certificate says.
///
/// RFC 5280 section 4.2.1.10 makes the extension critical and gives it to
/// a certificate authority alone. The minter writes one subtree of each
/// kind that is asked for, which is as much as a test needs.
pub const MintNameConstraints = struct {
    /// A `dNSName` subtree of `permittedSubtrees`.
    permitted_dns: ?[]const u8 = null,
    /// A `dNSName` subtree of `excludedSubtrees`.
    excluded_dns: ?[]const u8 = null,
    /// An `rfc822Name` subtree of `permittedSubtrees`, which is a kind of
    /// constraint this client does not read and must refuse.
    permitted_email: ?[]const u8 = null,
};

/// The default `notBefore` of a minted certificate, in UTCTime.
///
/// RFC 5280 section 4.1.2.5.1 reads a two digit year below 50 as 20YY, so
/// this is 2020 and the default `mint_not_after` is 2099.
pub const mint_not_before = "200101000000Z";

/// The default `notAfter` of a minted certificate, in UTCTime.
pub const mint_not_after = "991231235959Z";

pub const MintOptions = struct {
    serial: u8,
    issuer_cn: []const u8,
    subject_cn: []const u8,
    san_dns: ?[]const u8 = null,
    /// An `iPAddress` subject alternative name, four octets for IPv4 and
    /// sixteen for IPv6, or null for none.
    ///
    /// A certificate that answers for a loopback address needs this one.
    /// `verifyHost` reads the host as an address first, and a `dNSName`
    /// never matches an address. See `walkSubjectAltNames`.
    san_ip: ?[]const u8 = null,
    /// Null leaves the extension out, which is what an old certificate
    /// and a bare leaf both look like.
    basic_constraints: ?MintBasicConstraints = null,
    key_usage: MintKeyUsage = .none,
    /// The `extendedKeyUsage` extension, or null for none. RFC 5280
    /// section 4.2.1.12 leaves a key good for every purpose when the
    /// extension is absent.
    ext_key_usage: ?MintExtKeyUsage = null,
    /// The `nameConstraints` extension, or null for none. The minter
    /// marks it critical, which RFC 5280 section 4.2.1.10 requires.
    name_constraints: ?MintNameConstraints = null,
    /// Writes an extension of a private object identifier, marked
    /// critical, that no client can read.
    ///
    /// RFC 5280 section 4.2 says such a certificate must be refused, and
    /// that rule is what keeps this client closed when an extension
    /// nobody has written yet arrives.
    unknown_critical: bool = false,
    /// A second `subjectAltName` block written under the **retired**
    /// object identifier 2.5.29.7, which no certificate authority
    /// profiles or validates. It names one `dNSName`.
    ///
    /// `std.crypto.Certificate` maps 2.5.29.7 and 2.5.29.17 to one value
    /// and lets the last of the two win, so a certificate shaped like
    /// this sent the host check to a name nobody signed for.
    legacy_san_dns: ?[]const u8 = null,
    /// A second `subjectAltName` block under the real object identifier,
    /// 2.5.29.17. RFC 5280 section 4.2 forbids two instances of one
    /// extension, and a walk that reads one of the two is guessing.
    duplicate_san_dns: ?[]const u8 = null,
    /// The object identifier of the signature algorithm, written into
    /// **both** the `tbsCertificate.signature` field and the outer
    /// `signatureAlgorithm` field. Null writes `ecdsa-with-SHA256`, which
    /// is the algorithm the minter really signs with.
    ///
    /// A certificate minted with another identifier carries a signature
    /// that does not check out. Every test that uses this reads a rule
    /// that runs **before** any signature check.
    signature_oid: ?[]const u8 = null,
    /// The object identifier written into the `tbsCertificate.signature`
    /// field alone, so that the inner and the outer field disagree. RFC
    /// 5280 section 4.1.1.2 says they must hold the same value.
    inner_signature_oid: ?[]const u8 = null,
    /// The validity dates, both in UTCTime, both exactly 13 octets.
    ///
    /// A caller that wants a certificate outside its dates moves one of
    /// them. Every other caller leaves both alone.
    not_before: []const u8 = mint_not_before,
    not_after: []const u8 = mint_not_after,
};

/// Writes one X.509 version 3 certificate into `out` and signs it.
///
/// `subject_key` is the key the certificate carries. `signer` is the key
/// that signs it, so a self-signed certificate passes the same pair
/// twice.
///
/// Public for `zurl-tls/test_server.zig`, which presents the chains it
/// mints here to a real handshake. See `DerBuf`.
pub fn mint(
    out: *DerBuf,
    options: MintOptions,
    subject_key: TestEcdsa.PublicKey,
    signer: TestEcdsa.KeyPair,
) !void {
    var tbs: DerBuf = .{};
    tbs.push(&.{ 0xa0, 0x03, 0x02, 0x01, 0x02 });
    tbs.push(&.{ 0x02, 0x01, options.serial });
    tbs.algorithmIdentifier(options.inner_signature_oid orelse
        options.signature_oid orelse &test_oid_ecdsa_with_sha256);
    tbs.name(options.issuer_cn);
    {
        const at = tbs.mark();
        std.debug.assert(options.not_before.len == 13);
        std.debug.assert(options.not_after.len == 13);
        tbs.byte(0x17);
        tbs.byte(13);
        tbs.push(options.not_before);
        tbs.byte(0x17);
        tbs.byte(13);
        tbs.push(options.not_after);
        tbs.wrapDer(at, 0x30);
    }
    tbs.name(options.subject_cn);
    {
        const at = tbs.mark();
        const algo = tbs.mark();
        tbs.oid(&test_oid_ec_public_key);
        tbs.oid(&test_oid_prime256v1);
        tbs.wrapDer(algo, 0x30);
        const key = tbs.mark();
        tbs.byte(0x00);
        const point = subject_key.toUncompressedSec1();
        tbs.push(&point);
        tbs.wrapDer(key, 0x03);
        tbs.wrapDer(at, 0x30);
    }

    const has_extensions = options.san_dns != null or
        options.san_ip != null or
        options.basic_constraints != null or
        options.key_usage != .none or
        options.ext_key_usage != null or
        options.name_constraints != null or
        options.legacy_san_dns != null or
        options.duplicate_san_dns != null or
        options.unknown_critical;
    if (has_extensions) {
        const explicit = tbs.mark();
        if (options.san_dns != null or options.san_ip != null) {
            const ext = tbs.mark();
            tbs.oid(&test_oid_subject_alt_name);
            const value = tbs.mark();
            const seq = tbs.mark();
            // Tag 2 is `dNSName` and tag 7 is `iPAddress`. Both are
            // context specific and primitive, so the tag octet is
            // 0x80 + the number. RFC 5280 section 4.2.1.6.
            if (options.san_dns) |dns| {
                tbs.byte(0x82);
                tbs.byte(@intCast(dns.len));
                tbs.push(dns);
            }
            if (options.san_ip) |ip| {
                std.debug.assert(ip.len == 4 or ip.len == 16);
                tbs.byte(0x87);
                tbs.byte(@intCast(ip.len));
                tbs.push(ip);
            }
            tbs.wrapDer(seq, 0x30);
            tbs.wrapDer(value, 0x04);
            tbs.wrapDer(ext, 0x30);
        }
        // The two blocks below write a second set of subject alternative
        // names, and they come **after** the real one on purpose. A walk
        // that lets the last block win reads these and not the block the
        // authority signed for.
        if (options.legacy_san_dns) |dns| {
            const ext = tbs.mark();
            tbs.oid(&test_oid_legacy_subject_alt_name);
            const value = tbs.mark();
            const seq = tbs.mark();
            tbs.byte(0x82);
            tbs.byte(@intCast(dns.len));
            tbs.push(dns);
            tbs.wrapDer(seq, 0x30);
            tbs.wrapDer(value, 0x04);
            tbs.wrapDer(ext, 0x30);
        }
        if (options.duplicate_san_dns) |dns| {
            const ext = tbs.mark();
            tbs.oid(&test_oid_subject_alt_name);
            const value = tbs.mark();
            const seq = tbs.mark();
            tbs.byte(0x82);
            tbs.byte(@intCast(dns.len));
            tbs.push(dns);
            tbs.wrapDer(seq, 0x30);
            tbs.wrapDer(value, 0x04);
            tbs.wrapDer(ext, 0x30);
        }
        if (options.basic_constraints) |constraints| {
            const ext = tbs.mark();
            tbs.oid(&oid_basic_constraints);
            const value = tbs.mark();
            const seq = tbs.mark();
            tbs.push(if (constraints.ca)
                &[_]u8{ 0x01, 0x01, 0xff }
            else
                &[_]u8{ 0x01, 0x01, 0x00 });
            if (constraints.path_len) |limit| tbs.push(&.{ 0x02, 0x01, limit });
            tbs.wrapDer(seq, 0x30);
            tbs.wrapDer(value, 0x04);
            tbs.wrapDer(ext, 0x30);
        }
        switch (options.key_usage) {
            .none => {},
            // A BIT STRING counts its unused bits in the first octet.
            // Bit 0 alone leaves seven unused, and bit 5 alone leaves two.
            .digital_signature, .key_cert_sign => {
                const ext = tbs.mark();
                tbs.oid(&oid_key_usage);
                const value = tbs.mark();
                tbs.push(if (options.key_usage == .key_cert_sign)
                    &[_]u8{ 0x03, 0x02, 0x02, 0x04 }
                else
                    &[_]u8{ 0x03, 0x02, 0x07, 0x80 });
                tbs.wrapDer(value, 0x04);
                tbs.wrapDer(ext, 0x30);
            },
        }
        if (options.ext_key_usage) |usage| {
            const ext = tbs.mark();
            tbs.oid(&oid_ext_key_usage);
            const value = tbs.mark();
            const seq = tbs.mark();
            switch (usage) {
                .server_auth => tbs.oid(&oid_server_auth),
                .email_protection => tbs.oid(&test_oid_email_protection),
                .any => tbs.oid(&oid_any_ext_key_usage),
            }
            tbs.wrapDer(seq, 0x30);
            tbs.wrapDer(value, 0x04);
            tbs.wrapDer(ext, 0x30);
        }
        if (options.name_constraints) |constraints| {
            const ext = tbs.mark();
            tbs.oid(&oid_name_constraints);
            // RFC 5280 section 4.2.1.10: the extension is critical.
            tbs.push(&.{ 0x01, 0x01, 0xff });
            const value = tbs.mark();
            const seq = tbs.mark();
            if (constraints.permitted_dns != null or constraints.permitted_email != null) {
                const permitted = tbs.mark();
                // Tag 2 is `dNSName` and tag 1 is `rfc822Name`. Each base
                // sits alone in its `GeneralSubtree`, because RFC 5280
                // leaves `minimum` and `maximum` out.
                if (constraints.permitted_dns) |name| {
                    const subtree = tbs.mark();
                    tbs.byte(0x82);
                    tbs.byte(@intCast(name.len));
                    tbs.push(name);
                    tbs.wrapDer(subtree, 0x30);
                }
                if (constraints.permitted_email) |name| {
                    const subtree = tbs.mark();
                    tbs.byte(0x81);
                    tbs.byte(@intCast(name.len));
                    tbs.push(name);
                    tbs.wrapDer(subtree, 0x30);
                }
                // `[0] permittedSubtrees` is IMPLICIT and constructed.
                tbs.wrapDer(permitted, 0xa0);
            }
            if (constraints.excluded_dns) |name| {
                const excluded = tbs.mark();
                const subtree = tbs.mark();
                tbs.byte(0x82);
                tbs.byte(@intCast(name.len));
                tbs.push(name);
                tbs.wrapDer(subtree, 0x30);
                tbs.wrapDer(excluded, 0xa1);
            }
            tbs.wrapDer(seq, 0x30);
            tbs.wrapDer(value, 0x04);
            tbs.wrapDer(ext, 0x30);
        }
        if (options.unknown_critical) {
            const ext = tbs.mark();
            tbs.oid(&test_oid_unknown);
            tbs.push(&.{ 0x01, 0x01, 0xff });
            const value = tbs.mark();
            tbs.push(&.{ 0x05, 0x00 }); // NULL, a value that says nothing
            tbs.wrapDer(value, 0x04);
            tbs.wrapDer(ext, 0x30);
        }
        tbs.wrapDer(explicit, 0x30);
        tbs.wrapDer(explicit, 0xa3);
    }
    tbs.wrapDer(0, 0x30);

    const signature = try signer.sign(tbs.slice(), null);
    var sig_buf: [TestEcdsa.Signature.der_encoded_length_max]u8 = undefined;
    const der_sig = signature.toDer(&sig_buf);

    out.len = 0;
    out.push(tbs.slice());
    out.algorithmIdentifier(options.signature_oid orelse &test_oid_ecdsa_with_sha256);
    const at = out.mark();
    out.byte(0x00);
    out.push(der_sig);
    out.wrapDer(at, 0x03);
    out.wrapDer(0, 0x30);
}

fn mintedParsed(buf: *const DerBuf) !Certificate.Parsed {
    const cert: Certificate = .{ .buffer = buf.slice(), .index = 0 };
    return cert.parse();
}

/// One P-256 key pair, the same one for the same `seed` in every run.
///
/// Deterministic on purpose: a fixture that minted a fresh key on each run
/// would give a test that fails once in a while nothing to compare.
pub fn testKey(seed: u8) !TestEcdsa.KeyPair {
    return TestEcdsa.KeyPair.generateDeterministic(@splat(seed));
}

test "a minted certificate parses and carries the extensions it was given" {
    // The minter is the whole evidence of every test below it, so this
    // test reads its output back through the same parser a fetch uses.
    const key = try testKey(0x11);
    var buf: DerBuf = .{};
    try mint(&buf, .{
        .serial = 1,
        .issuer_cn = "mint.test",
        .subject_cn = "mint.test",
        .san_dns = "mint.test",
        .basic_constraints = .{ .ca = true, .path_len = 2 },
        .key_usage = .key_cert_sign,
    }, key.public_key, key);

    const parsed = try mintedParsed(&buf);
    try testing.expectEqual(Certificate.Version.v3, parsed.version);
    try testing.expectEqualStrings("mint.test", parsed.commonName());
    try verifyHost(parsed, "mint.test");
    // A self-signed certificate checks against itself, so the signature
    // the minter wrote is a real signature.
    try parsed.verify(parsed, test_now_sec);

    const rights = try issuerRights(parsed);
    try testing.expect(rights.has_basic_constraints);
    try testing.expect(rights.is_ca);
    try testing.expectEqual(@as(?u32, 2), rights.path_len);
    try testing.expect(rights.has_key_usage);
    try testing.expect(rights.may_sign_certificates);
}

test "a leaf certificate that is not a certificate authority cannot issue another one" {
    // This is the whole of finding F1. The attacker holds a real domain
    // validated certificate for a name they own, and they sign a
    // certificate for a name they do not own with its private key.
    const attacker_key = try testKey(0x21);
    const root_key = try testKey(0x22);

    var attacker_leaf: DerBuf = .{};
    try mint(&attacker_leaf, .{
        .serial = 2,
        .issuer_cn = "zurl test root",
        .subject_cn = "attacker.test",
        .san_dns = "attacker.test",
        .basic_constraints = .{ .ca = false },
        .key_usage = .digital_signature,
    }, attacker_key.public_key, root_key);

    var forged: DerBuf = .{};
    try mint(&forged, .{
        .serial = 3,
        .issuer_cn = "attacker.test",
        .subject_cn = "victim.test",
        .san_dns = "victim.test",
        .basic_constraints = .{ .ca = false },
        .key_usage = .digital_signature,
    }, attacker_key.public_key, attacker_key);

    const attacker_parsed = try mintedParsed(&attacker_leaf);
    const forged_parsed = try mintedParsed(&forged);

    // The forged certificate names the victim, so the host walk is happy
    // with it. Nothing there stops the attack.
    try verifyHost(forged_parsed, "victim.test");

    // What the code called before the fix. It says the pair is good,
    // because it checks the issuer name, the dates, and the signature,
    // and it reads neither `basicConstraints` nor `keyUsage`.
    try forged_parsed.verify(attacker_parsed, test_now_sec);

    // What the code calls now.
    try testing.expectError(
        error.CertificateIssuerNotCa,
        verifyIssued(forged_parsed, attacker_parsed, null, 0, test_now_sec),
    );
}

test "an issuer with no basicConstraints extension at all is refused" {
    // RFC 5280 section 4.2.1.9: an absent extension and a `cA` of FALSE
    // both forbid the use of the key to check a certificate signature.
    const issuer_key = try testKey(0x31);

    var issuer: DerBuf = .{};
    try mint(&issuer, .{
        .serial = 4,
        .issuer_cn = "bare.test",
        .subject_cn = "bare.test",
        .san_dns = "bare.test",
    }, issuer_key.public_key, issuer_key);

    var subject: DerBuf = .{};
    try mint(&subject, .{
        .serial = 5,
        .issuer_cn = "bare.test",
        .subject_cn = "victim.test",
        .san_dns = "victim.test",
    }, issuer_key.public_key, issuer_key);

    const issuer_parsed = try mintedParsed(&issuer);
    const subject_parsed = try mintedParsed(&subject);

    const rights = try issuerRights(issuer_parsed);
    try testing.expect(!rights.has_basic_constraints);
    try testing.expectError(
        error.CertificateIssuerNotCa,
        verifyIssued(subject_parsed, issuer_parsed, null, 0, test_now_sec),
    );
}

test "a certificate authority that does not assert keyCertSign is refused" {
    // RFC 5280 section 4.2.1.3. The extension is there and it names
    // another use, so this key must not check a certificate signature.
    const issuer_key = try testKey(0x41);

    var issuer: DerBuf = .{};
    try mint(&issuer, .{
        .serial = 6,
        .issuer_cn = "signer.test",
        .subject_cn = "signer.test",
        .san_dns = "signer.test",
        .basic_constraints = .{ .ca = true },
        .key_usage = .digital_signature,
    }, issuer_key.public_key, issuer_key);

    var subject: DerBuf = .{};
    try mint(&subject, .{
        .serial = 7,
        .issuer_cn = "signer.test",
        .subject_cn = "victim.test",
        .san_dns = "victim.test",
    }, issuer_key.public_key, issuer_key);

    const issuer_parsed = try mintedParsed(&issuer);
    const subject_parsed = try mintedParsed(&subject);

    try testing.expectError(
        error.CertificateIssuerCannotSignCertificates,
        verifyIssued(subject_parsed, issuer_parsed, null, 0, test_now_sec),
    );
}

test "a real certificate authority issues and the step passes" {
    const ca_key = try testKey(0x51);

    var ca: DerBuf = .{};
    try mint(&ca, .{
        .serial = 8,
        .issuer_cn = "good ca",
        .subject_cn = "good ca",
        .basic_constraints = .{ .ca = true },
        .key_usage = .key_cert_sign,
    }, ca_key.public_key, ca_key);

    var leaf: DerBuf = .{};
    try mint(&leaf, .{
        .serial = 9,
        .issuer_cn = "good ca",
        .subject_cn = "leaf.test",
        .san_dns = "leaf.test",
        .basic_constraints = .{ .ca = false },
        .key_usage = .digital_signature,
    }, ca_key.public_key, ca_key);

    const ca_parsed = try mintedParsed(&ca);
    const leaf_parsed = try mintedParsed(&leaf);
    try verifyIssued(leaf_parsed, ca_parsed, null, 0, test_now_sec);
}

test "a critical extension the reader does not know refuses the certificate" {
    // RFC 5280 section 4.2. The extension names a private arc and holds
    // nothing, so the only thing about it that can refuse a chain is that
    // it is critical and nobody reads it.
    const key = try testKey(0x61);

    var unknown: DerBuf = .{};
    try mint(&unknown, .{
        .serial = 0x20,
        .issuer_cn = "critical ca",
        .subject_cn = "critical ca",
        .basic_constraints = .{ .ca = true },
        .key_usage = .key_cert_sign,
        .unknown_critical = true,
    }, key.public_key, key);
    try testing.expectError(
        error.CertificateHasUnrecognizedObjectId,
        issuerRights(try mintedParsed(&unknown)),
    );

    // The control: the same certificate with the extension left out is
    // read to the end and says what it always said.
    var plain: DerBuf = .{};
    try mint(&plain, .{
        .serial = 0x21,
        .issuer_cn = "critical ca",
        .subject_cn = "critical ca",
        .basic_constraints = .{ .ca = true },
        .key_usage = .key_cert_sign,
    }, key.public_key, key);
    const rights = try issuerRights(try mintedParsed(&plain));
    try testing.expect(rights.is_ca);
}

test "extendedKeyUsage decides whether a key stands for a TLS server" {
    // RFC 5280 section 4.2.1.12. A certificate that names a purpose may
    // be used for that purpose and for no other.
    const key = try testKey(0x62);

    const Case = struct { usage: ?MintExtKeyUsage, serves: bool, carried: bool };
    for ([_]Case{
        .{ .usage = null, .serves = false, .carried = false },
        .{ .usage = .server_auth, .serves = true, .carried = true },
        .{ .usage = .any, .serves = true, .carried = true },
        .{ .usage = .email_protection, .serves = false, .carried = true },
    }) |case| {
        var cert: DerBuf = .{};
        try mint(&cert, .{
            .serial = 0x22,
            .issuer_cn = "purpose ca",
            .subject_cn = "purpose ca",
            .basic_constraints = .{ .ca = true },
            .key_usage = .key_cert_sign,
            .ext_key_usage = case.usage,
        }, key.public_key, key);

        const rights = try issuerRights(try mintedParsed(&cert));
        try testing.expectEqual(case.carried, rights.has_ext_key_usage);
        try testing.expectEqual(case.serves, rights.may_authenticate_server);
    }
}

test "a DNS name constraint holds the name and every name below it" {
    // RFC 5280 section 4.2.1.10.
    try testing.expect(dnsInSubtree("example.test", "example.test"));
    try testing.expect(dnsInSubtree("example.test", "host.example.test"));
    try testing.expect(dnsInSubtree("example.test", "a.b.example.test"));
    // The comparison is on labels. A name that ends with the same octets
    // and starts in the middle of a label belongs to somebody else.
    try testing.expect(!dnsInSubtree("example.test", "notexample.test"));
    try testing.expect(!dnsInSubtree("example.test", "example.test.evil.test"));
    try testing.expect(!dnsInSubtree("host.example.test", "example.test"));
    // A DNS name ignores case.
    try testing.expect(dnsInSubtree("Example.TEST", "HOST.example.test"));
    // A base of no octets holds every name.
    try testing.expect(dnsInSubtree("", "anything.test"));
    // A base that starts with a dot holds the names below it alone.
    try testing.expect(dnsInSubtree(".example.test", "host.example.test"));
    try testing.expect(!dnsInSubtree(".example.test", "example.test"));
}

test "an address name constraint holds the addresses its mask covers" {
    // RFC 5280 section 4.2.1.10 writes the base as the address and the
    // mask together.
    const class_c = [_]u8{ 192, 0, 2, 0, 255, 255, 255, 0 };
    try testing.expect(addressInSubtree(&class_c, &[_]u8{ 192, 0, 2, 7 }));
    try testing.expect(!addressInSubtree(&class_c, &[_]u8{ 192, 0, 3, 7 }));
    // A base that is not twice the width of the address names no range.
    try testing.expect(!addressInSubtree(&[_]u8{ 192, 0, 2, 0 }, &[_]u8{ 192, 0, 2, 7 }));
    // An IPv4 address is not inside an IPv6 subtree, whatever the mask
    // says, because the two are not the same kind of name.
    try testing.expect(!addressInSubtree(&[_]u8{0} ** 32, &[_]u8{ 192, 0, 2, 7 }));
}

test "a constrained certificate authority answers for its name space alone" {
    // The unit form of the chain the fixture presents. The authority may
    // issue for `inside.test` and for the names below it.
    const ca_key = try testKey(0x63);

    var ca: DerBuf = .{};
    try mint(&ca, .{
        .serial = 0x23,
        .issuer_cn = "constrained ca",
        .subject_cn = "constrained ca",
        .basic_constraints = .{ .ca = true },
        .key_usage = .key_cert_sign,
        .name_constraints = .{ .permitted_dns = "inside.test" },
    }, ca_key.public_key, ca_key);

    var leaf: DerBuf = .{};
    try mint(&leaf, .{
        .serial = 0x24,
        .issuer_cn = "constrained ca",
        .subject_cn = "host.inside.test",
        .san_dns = "host.inside.test",
        .key_usage = .digital_signature,
    }, ca_key.public_key, ca_key);

    const ca_parsed = try mintedParsed(&ca);
    const leaf_parsed = try mintedParsed(&leaf);

    try verifyIssued(leaf_parsed, ca_parsed, "host.inside.test", 0, test_now_sec);
    // The same certificates, and a session for a host the authority may
    // not answer for.
    try testing.expectError(
        error.CertificateNameNotPermitted,
        verifyIssued(leaf_parsed, ca_parsed, "outside.test", 0, test_now_sec),
    );
    // A session with no host check authenticates no name, so there is no
    // name for the constraint to bind.
    try verifyIssued(leaf_parsed, ca_parsed, null, 0, test_now_sec);
}

test "a name constraint of a kind this client cannot read refuses the chain" {
    // An `rfc822Name` subtree binds electronic mail addresses, which this
    // client never reads. Taking the chain would mean taking a constraint
    // this side cannot prove the certificate obeys.
    const ca_key = try testKey(0x64);

    var ca: DerBuf = .{};
    try mint(&ca, .{
        .serial = 0x25,
        .issuer_cn = "mail ca",
        .subject_cn = "mail ca",
        .basic_constraints = .{ .ca = true },
        .key_usage = .key_cert_sign,
        .name_constraints = .{ .permitted_email = "inside.test" },
    }, ca_key.public_key, ca_key);

    var leaf: DerBuf = .{};
    try mint(&leaf, .{
        .serial = 0x26,
        .issuer_cn = "mail ca",
        .subject_cn = "host.inside.test",
        .san_dns = "host.inside.test",
        .key_usage = .digital_signature,
    }, ca_key.public_key, ca_key);

    try testing.expectError(
        error.CertificateNameNotPermitted,
        verifyIssued(
            try mintedParsed(&leaf),
            try mintedParsed(&ca),
            "host.inside.test",
            0,
            test_now_sec,
        ),
    );
}

test "an excluded subtree refuses a host inside it" {
    // RFC 5280 section 4.2.1.10: `excludedSubtrees` names what the
    // authority may never issue for, whatever `permittedSubtrees` says.
    const ca_key = try testKey(0x65);

    var ca: DerBuf = .{};
    try mint(&ca, .{
        .serial = 0x27,
        .issuer_cn = "excluding ca",
        .subject_cn = "excluding ca",
        .basic_constraints = .{ .ca = true },
        .key_usage = .key_cert_sign,
        .name_constraints = .{ .excluded_dns = "secret.test" },
    }, ca_key.public_key, ca_key);

    var leaf: DerBuf = .{};
    try mint(&leaf, .{
        .serial = 0x28,
        .issuer_cn = "excluding ca",
        .subject_cn = "host.secret.test",
        .san_dns = "host.secret.test",
        .key_usage = .digital_signature,
    }, ca_key.public_key, ca_key);

    const ca_parsed = try mintedParsed(&ca);
    const leaf_parsed = try mintedParsed(&leaf);

    try testing.expectError(
        error.CertificateNameNotPermitted,
        verifyIssued(leaf_parsed, ca_parsed, "host.secret.test", 0, test_now_sec),
    );
    // A host outside the excluded subtree is still answered for.
    try verifyIssued(leaf_parsed, ca_parsed, "other.test", 0, test_now_sec);
}

test "pathLenConstraint counts the certificates below the issuer" {
    // RFC 5280 section 4.2.1.9. A constraint of zero lets the authority
    // issue a leaf and nothing that issues again.
    const ca_key = try testKey(0x61);

    var ca: DerBuf = .{};
    try mint(&ca, .{
        .serial = 10,
        .issuer_cn = "short ca",
        .subject_cn = "short ca",
        .basic_constraints = .{ .ca = true, .path_len = 0 },
        .key_usage = .key_cert_sign,
    }, ca_key.public_key, ca_key);

    var leaf: DerBuf = .{};
    try mint(&leaf, .{
        .serial = 11,
        .issuer_cn = "short ca",
        .subject_cn = "leaf.test",
        .san_dns = "leaf.test",
    }, ca_key.public_key, ca_key);

    const ca_parsed = try mintedParsed(&ca);
    const leaf_parsed = try mintedParsed(&leaf);

    // The leaf sits directly under the authority, so nothing is between
    // them and the constraint holds.
    try verifyIssued(leaf_parsed, ca_parsed, null, 0, test_now_sec);

    // One certificate between them breaks it.
    try testing.expectError(
        error.CertificatePathLengthExceeded,
        verifyIssued(leaf_parsed, ca_parsed, null, 1, test_now_sec),
    );
}

test "the chain walk stops at max_chain_certificates" {
    const ca_key = try testKey(0x71);

    var ca: DerBuf = .{};
    try mint(&ca, .{
        .serial = 12,
        .issuer_cn = "deep ca",
        .subject_cn = "deep ca",
        .basic_constraints = .{ .ca = true },
        .key_usage = .key_cert_sign,
    }, ca_key.public_key, ca_key);

    var leaf: DerBuf = .{};
    try mint(&leaf, .{
        .serial = 13,
        .issuer_cn = "deep ca",
        .subject_cn = "leaf.test",
    }, ca_key.public_key, ca_key);

    const ca_parsed = try mintedParsed(&ca);
    const leaf_parsed = try mintedParsed(&leaf);

    try testing.expectError(
        error.CertificateChainTooLong,
        verifyIssued(leaf_parsed, ca_parsed, null, max_chain_certificates - 1, test_now_sec),
    );
}

/// Writes one TLS 1.3 Certificate message body around `certs`.
///
/// The body is what `quic.verifyCertificate` reads: an empty request
/// context, then a list of entries, each one a certificate and an empty
/// extension block.
fn certificateMessage(out: []u8, certs: []const []const u8) []u8 {
    var len: usize = 0;
    out[len] = 0;
    len += 1;
    const list_at = len;
    len += 3;
    for (certs) |der_bytes| {
        std.mem.writeInt(u24, out[len..][0..3], @intCast(der_bytes.len), .big);
        len += 3;
        @memcpy(out[len..][0..der_bytes.len], der_bytes);
        len += der_bytes.len;
        std.mem.writeInt(u16, out[len..][0..2], 0, .big);
        len += 2;
    }
    std.mem.writeInt(u24, out[list_at..][0..3], @intCast(len - list_at - 3), .big);
    return out[0..len];
}

/// Runs `quic.verifyCertificate` over `certs` with `root` as the one
/// trusted certificate.
fn verifyAgainstRoot(
    certs: []const []const u8,
    root: []const u8,
    host: []const u8,
) !void {
    var bundle: Certificate.Bundle = .empty;
    defer bundle.deinit(testing.allocator);
    try bundle.bytes.appendSlice(testing.allocator, root);
    try bundle.parseCert(testing.allocator, 0, test_now_sec);

    var lock: std.Io.RwLock = .init;
    const ca: @FieldType(Options, "ca") = .{ .bundle = .{
        .gpa = testing.allocator,
        .io = testing.io,
        .lock = &lock,
        .bundle = &bundle,
    } };

    var body_buf: [8192]u8 = undefined;
    const body = certificateMessage(&body_buf, certs);

    var key: quic.CertificateKey = .empty;
    return quic.verifyCertificate(body, .{ .explicit = host }, ca, test_now, &key);
}

test "the whole certificate check refuses a forged leaf signed by a trusted leaf" {
    // The complete attack of finding F1, driven through the function the
    // QUIC handshake calls. The attacker owns `attacker.test` and holds a
    // certificate for it that a trusted root signed. They sign a
    // certificate for `victim.test` with that leaf's private key and send
    // the two together.
    const root_key = try testKey(0x81);
    const attacker_key = try testKey(0x82);

    var root: DerBuf = .{};
    try mint(&root, .{
        .serial = 20,
        .issuer_cn = "zurl test root",
        .subject_cn = "zurl test root",
        .basic_constraints = .{ .ca = true },
        .key_usage = .key_cert_sign,
    }, root_key.public_key, root_key);

    var attacker_leaf: DerBuf = .{};
    try mint(&attacker_leaf, .{
        .serial = 21,
        .issuer_cn = "zurl test root",
        .subject_cn = "attacker.test",
        .san_dns = "attacker.test",
        .basic_constraints = .{ .ca = false },
        .key_usage = .digital_signature,
    }, attacker_key.public_key, root_key);

    var forged: DerBuf = .{};
    try mint(&forged, .{
        .serial = 22,
        .issuer_cn = "attacker.test",
        .subject_cn = "victim.test",
        .san_dns = "victim.test",
        .basic_constraints = .{ .ca = false },
        .key_usage = .digital_signature,
    }, attacker_key.public_key, attacker_key);

    try testing.expectError(error.CertificateIssuerNotCa, verifyAgainstRoot(
        &.{ forged.slice(), attacker_leaf.slice() },
        root.slice(),
        "victim.test",
    ));
}

test "the whole certificate check still takes a chain a real server sends" {
    // The control for the test above. The same walk, the same root, and
    // an intermediate that is a real certificate authority. Nothing in
    // the new rules refuses a chain that follows RFC 5280.
    const root_key = try testKey(0x91);
    const intermediate_key = try testKey(0x92);
    const leaf_key = try testKey(0x93);

    var root: DerBuf = .{};
    try mint(&root, .{
        .serial = 30,
        .issuer_cn = "zurl test root",
        .subject_cn = "zurl test root",
        .basic_constraints = .{ .ca = true },
        .key_usage = .key_cert_sign,
    }, root_key.public_key, root_key);

    var intermediate: DerBuf = .{};
    try mint(&intermediate, .{
        .serial = 31,
        .issuer_cn = "zurl test root",
        .subject_cn = "zurl test issuing ca",
        .basic_constraints = .{ .ca = true, .path_len = 0 },
        .key_usage = .key_cert_sign,
    }, intermediate_key.public_key, root_key);

    var leaf: DerBuf = .{};
    try mint(&leaf, .{
        .serial = 32,
        .issuer_cn = "zurl test issuing ca",
        .subject_cn = "victim.test",
        .san_dns = "victim.test",
        .basic_constraints = .{ .ca = false },
        .key_usage = .digital_signature,
    }, leaf_key.public_key, intermediate_key);

    // Leaf and intermediate, which is what a server sends.
    try verifyAgainstRoot(
        &.{ leaf.slice(), intermediate.slice() },
        root.slice(),
        "victim.test",
    );

    // And a leaf the root signed itself.
    var direct: DerBuf = .{};
    try mint(&direct, .{
        .serial = 33,
        .issuer_cn = "zurl test root",
        .subject_cn = "victim.test",
        .san_dns = "victim.test",
        .basic_constraints = .{ .ca = false },
        .key_usage = .digital_signature,
    }, leaf_key.public_key, root_key);
    try verifyAgainstRoot(&.{direct.slice()}, root.slice(), "victim.test");
}

test "a malformed leaf certificate is refused by the whole certificate check" {
    // The reproduction, driven through the walk a QUIC handshake runs.
    // `30 06` opens a six octet SEQUENCE and `30 82 FF FF` inside it opens
    // one of 65535 octets, over a buffer that holds six. Upstream
    // `Certificate.parse` read past the end of it. The walk reads the leaf
    // before it checks the host and before it asks the trust store, so
    // this is what any server could send.
    const root_key = try testKey(0xA1);
    var root: DerBuf = .{};
    try mint(&root, .{
        .serial = 40,
        .issuer_cn = "zurl test root",
        .subject_cn = "zurl test root",
        .basic_constraints = .{ .ca = true },
        .key_usage = .key_cert_sign,
    }, root_key.public_key, root_key);

    const evil = [_]u8{ 0x30, 0x06, 0x30, 0x82, 0xFF, 0xFF };
    try testing.expectError(error.CertificateFieldHasInvalidLength, verifyAgainstRoot(
        &.{&evil},
        root.slice(),
        "victim.test",
    ));

    // The same fault, at a distance. These ten octets send the upstream
    // reader two gigabytes past the end of the buffer, and a ReleaseFast
    // zurl gave a segmentation fault on them.
    const far = [_]u8{ 0x30, 0x08, 0x30, 0x06, 0x02, 0x84, 0x7F, 0xFF, 0xFF, 0xFF };
    try testing.expectError(error.CertificateFieldHasInvalidLength, verifyAgainstRoot(
        &.{&far},
        root.slice(),
        "victim.test",
    ));

    // And every prefix of a certificate that does parse. A peer that cuts
    // a real certificate short gets an error at each length.
    var leaf: DerBuf = .{};
    try mint(&leaf, .{
        .serial = 41,
        .issuer_cn = "zurl test root",
        .subject_cn = "victim.test",
        .san_dns = "victim.test",
        .basic_constraints = .{ .ca = false },
        .key_usage = .digital_signature,
    }, root_key.public_key, root_key);

    const whole = leaf.slice();
    var len: usize = 0;
    while (len < whole.len) : (len += 1) {
        try testing.expectError(error.CertificateFieldHasInvalidLength, verifyAgainstRoot(
            &.{whole[0..len]},
            root.slice(),
            "victim.test",
        ));
    }
}

test "an empty subjectPublicKey is a fault and not an assert" {
    // A `subjectPublicKey` BIT STRING of `03 01 00` parses cleanly and
    // gives a key of no bytes. `CertificatePublicKey.init` took it before,
    // and the next message tripped an assert in Debug and reached
    // `verifySignature` with an empty key in ReleaseFast.
    var key: CertificatePublicKey = undefined;
    try testing.expectError(
        error.CertificatePublicKeyInvalid,
        key.init(.{ .rsaEncryption = {} }, ""),
    );
}

test "both certificate walks call the one chain rule" {
    // Finding F1 says the QUIC path wrote a second copy of the walk, so a
    // rule added to one loop would not reach the other. The rules now sit
    // in `verifyIssued`, and neither loop calls
    // `Certificate.Parsed.verify` for a neighbour any more.
    //
    // The needles are built at run time, so this test's own text is not
    // what it finds.
    const source = @embedFile("Client.zig");

    var needle_buf: [64]u8 = undefined;
    const call = std.fmt.bufPrint(&needle_buf, "{s}_cert.{s}(subject, now_sec)", .{
        "prev", "verify",
    }) catch unreachable;
    try testing.expect(std.mem.indexOf(u8, source, call) == null);

    // And both loops name the two functions that hold the rules: one for
    // a pair of certificates, one for the leaf on its own.
    for ([_][]const u8{
        "verifyIssued(prev_cert, subject, chain_host, cert_index - 1, now_sec)",
        "verifyEndEntity(subject, trust_checked)",
        // The cryptographic floor runs over every certificate of both
        // walks, and not over the leaf alone, so it is pinned here beside
        // the two rules that read one certificate and a pair.
        "verifyCertificateStrength(subject, trust_checked)",
    }) |shared| {
        var count: usize = 0;
        var index: usize = 0;
        while (std.mem.indexOfPos(u8, source, index, shared)) |at| {
            count += 1;
            index = at + shared.len;
        }
        // One call in `init`, one in `quic.verifyCertificate`, and one
        // here.
        try testing.expectEqual(@as(usize, 3), count);
    }
}

/// The `signature_algorithms` extension of `hello`, payload alone.
///
/// ZURL PATCH: not upstream. Written the way `alpnExtensionOf` above is,
/// and it gives back the list of schemes without the two lengths in front
/// of it.
fn signatureSchemesOf(hello: []const u8) ?[]const u8 {
    const block = extensionsBlockOf(hello);
    var at: usize = 0;
    while (at < block.len) {
        const et = mem.readInt(u16, block[at..][0..2], .big);
        const ext_len = mem.readInt(u16, block[at + 2 ..][0..2], .big);
        if (et == @intFromEnum(tls.ExtensionType.signature_algorithms)) {
            // The payload opens with its own two octet count, and the
            // schemes follow it.
            return block[at + 6 ..][0 .. ext_len - 2];
        }
        at += 4 + ext_len;
    }
    return null;
}

test "the Client Hello offers a SHA-1 scheme that this build will not accept" {
    // **The offer still carries `rsa_pkcs1_sha1`, and the refusal is on
    // receipt. That is a deliberate trade, not an oversight.**
    //
    // RFC 8446 section 4.4.3 forbids `rsa_pkcs1_sha1` in
    // `CertificateVerify`, and curl 8.21.0 with OpenSSL 3.6.3 offers 26
    // schemes with no SHA-1 among them, measured off the wire. Taking the
    // scheme out of this hello would match curl and would cost nothing.
    //
    // It cannot be done here. `lib/zurl-tls/Client.zig` is a vendored copy
    // under `tools/check_vendor.zig`, and that guard counts the upstream
    // lines a hunk drops against the lines of **code** the hunk puts back
    // with a marker. A comment pays for nothing, by design: an earlier
    // rule let nine marked comment lines pay for one removal, and that
    // slack would have paid for nine more deletions. So a net deletion of
    // one line can never be accounted, because every marker added to the
    // hunk pulls one more upstream line into it. A one for one
    // substitution would satisfy the guard, and there is no scheme to
    // substitute: `verifySignature` knows no curve above P-384, so every
    // scheme this build can check is offered already.
    //
    // **Nothing is lost that matters.** A server that chooses SHA-1
    // reaches `verifySignature` and is refused there, which is the test
    // below and which holds whatever the hello offered. The cost is that
    // such a server wastes a handshake instead of choosing another scheme,
    // which is availability and not security.
    //
    // `ecdsa_sha1` is a different case: upstream never offered it, so its
    // absence needs no patch and is asserted here.
    var buf: [4096]u8 = undefined;
    const hello = clientHelloBytes(.tls_1_3, &buf);
    try checkHelloLengths(hello);

    const schemes = signatureSchemesOf(hello) orelse return error.TestExpectedEqual;
    try testing.expect(schemes.len % 2 == 0);
    try testing.expect(schemes.len != 0);

    var saw_rsa_pkcs1_sha1 = false;
    var at: usize = 0;
    while (at < schemes.len) : (at += 2) {
        const scheme = mem.readInt(u16, schemes[at..][0..2], .big);
        if (scheme == @intFromEnum(tls.SignatureScheme.rsa_pkcs1_sha1)) saw_rsa_pkcs1_sha1 = true;
        try testing.expect(scheme != @intFromEnum(tls.SignatureScheme.ecdsa_sha1));
    }

    // Pinned as a fact, so that a later build which does take it out of
    // the hello fails here and reads the reasoning above before deciding.
    try testing.expect(saw_rsa_pkcs1_sha1);
}

test "a server that signs with SHA-1 is refused whatever the hello offered" {
    // The offer above is the first half of the rule and this is the
    // second. A server that chooses a scheme nobody offered still reaches
    // `verifySignature`, so the refusal is written there as well.
    const key = try testKey(0x71);
    var leaf: DerBuf = .{};
    try mint(&leaf, .{
        .serial = 20,
        .issuer_cn = "sha1.test",
        .subject_cn = "sha1.test",
        .san_dns = "sha1.test",
        .key_usage = .digital_signature,
    }, key.public_key, key);
    const parsed = try mintedParsed(&leaf);

    var cert_key: CertificatePublicKey = undefined;
    try cert_key.init(parsed.pub_key_algo, parsed.pubKey());

    // `04 01` is the length of the signature that follows, and the
    // signature itself is never read: the scheme is refused first.
    const wire = [_]u8{ 0x02, 0x01, 0x00, 0x04 } ++ [_]u8{0} ** 4;
    var sigd = tls.Decoder.fromTheirSlice(@constCast(&wire));
    try testing.expectError(
        error.TlsBadSignatureScheme,
        cert_key.verifySignature(&sigd, &.{"transcript"}, .tls_1_3),
    );
}

test "a certificate signed with SHA-1 is refused and one signed with SHA-256 is not" {
    // The chain half of the same rule. SHA-1 chosen prefix collisions
    // have been public and affordable since 2020, and a certificate
    // signature is where a collision buys a certificate for a name the
    // attacker does not hold.
    //
    // The minter signs with ECDSA and SHA-256 whatever the identifier
    // says, so the certificate below carries a signature that does not
    // check out. That is not what this test reads: the floor runs before
    // any signature check, which is the point of putting it there.
    const key = try testKey(0x72);
    var weak: DerBuf = .{};
    try mint(&weak, .{
        .serial = 21,
        .issuer_cn = "weak.test",
        .subject_cn = "weak.test",
        .san_dns = "weak.test",
        .key_usage = .digital_signature,
        .signature_oid = &test_oid_sha1_with_rsa,
    }, key.public_key, key);
    const weak_parsed = try mintedParsed(&weak);
    try testing.expectError(
        error.CertificateSignatureAlgorithmWeak,
        verifyCertificateStrength(weak_parsed, true),
    );

    // `--insecure` asks for no trust check at all, and the floor is part
    // of the trust check. curl gives a user who wrote `-k` the same.
    try verifyCertificateStrength(weak_parsed, false);

    var strong: DerBuf = .{};
    try mint(&strong, .{
        .serial = 22,
        .issuer_cn = "strong.test",
        .subject_cn = "strong.test",
        .san_dns = "strong.test",
        .key_usage = .digital_signature,
    }, key.public_key, key);
    try verifyCertificateStrength(try mintedParsed(&strong), true);
}

test "SHA-224 stays acceptable and MD5 does not" {
    // The floor is a line and not a preference. SHA-224 has 112 bits of
    // collision resistance, which is what NIST SP 800-57 asks for, and
    // curl still offers it. MD5 is broken outright.
    try testing.expect(!weakSignatureAlgorithm(.sha224WithRSAEncryption));
    try testing.expect(!weakSignatureAlgorithm(.ecdsa_with_SHA224));
    try testing.expect(!weakSignatureAlgorithm(.ecdsa_with_SHA256));
    try testing.expect(!weakSignatureAlgorithm(.curveEd25519));
    try testing.expect(weakSignatureAlgorithm(.sha1WithRSAEncryption));
    try testing.expect(weakSignatureAlgorithm(.md5WithRSAEncryption));
    try testing.expect(weakSignatureAlgorithm(.md2WithRSAEncryption));
}

/// One DER `RSAPublicKey` whose modulus holds `octets` octets.
///
/// ZURL PATCH: not upstream. The numbers inside mean nothing. Every rule
/// that reads this reads the width of the modulus and never its value.
fn rsaKeyOfWidth(out: []u8, octets: usize) []const u8 {
    var buf: DerBuf = .{};
    const seq = buf.mark();
    // The modulus, as a positive INTEGER. A leading zero octet keeps the
    // high bit of the first content octet clear, which DER asks for.
    buf.byte(0x02);
    buf.byte(0x82);
    buf.byte(@intCast((octets + 1) >> 8));
    buf.byte(@truncate(octets + 1));
    buf.byte(0x00);
    for (0..octets) |index| buf.byte(@truncate(index | 1));
    // The public exponent, 65537.
    buf.push(&.{ 0x02, 0x03, 0x01, 0x00, 0x01 });
    buf.wrapDer(seq, 0x30);

    @memcpy(out[0..buf.len], buf.slice());
    return out[0..buf.len];
}

test "an RSA key below 2048 bits is refused and one at the floor is not" {
    // CA/Browser Forum Baseline Requirements section 6.1.5 and NIST SP
    // 800-57 Part 1 Revision 5 both put the floor at 2048 bits. A 1024
    // bit modulus has been below every published floor since 2013.
    var storage: [1024]u8 = undefined;

    var weak: Certificate.Parsed = undefined;
    const small = rsaKeyOfWidth(&storage, 128);
    weak.certificate = .{ .buffer = small, .index = 0 };
    weak.pub_key_slice = .{ .start = 0, .end = @intCast(small.len) };
    weak.pub_key_algo = .{ .rsaEncryption = {} };
    weak.signature_algorithm = .sha256WithRSAEncryption;
    try testing.expectError(
        error.CertificatePublicKeyTooWeak,
        verifyCertificateStrength(weak, true),
    );
    // And `--insecure` still asks for nothing.
    try verifyCertificateStrength(weak, false);

    var storage_ok: [1024]u8 = undefined;
    var fine: Certificate.Parsed = undefined;
    const at_floor = rsaKeyOfWidth(&storage_ok, 256);
    fine.certificate = .{ .buffer = at_floor, .index = 0 };
    fine.pub_key_slice = .{ .start = 0, .end = @intCast(at_floor.len) };
    fine.pub_key_algo = .{ .rsaEncryption = {} };
    fine.signature_algorithm = .sha256WithRSAEncryption;
    try verifyCertificateStrength(fine, true);
}

test "a 1024 bit modulus cannot check a TLS signature either" {
    // The same floor on the handshake signature. `verifySignature` took
    // a 128 octet modulus, which is 1024 bits.
    var storage: [1024]u8 = undefined;
    const small = rsaKeyOfWidth(&storage, 128);

    var key: CertificatePublicKey = undefined;
    try key.init(.{ .rsaEncryption = {} }, small);

    // `rsa_pkcs1_sha256`, then a 128 octet signature of no meaning. The
    // width of the modulus is read before the signature is.
    const wire = [_]u8{ 0x04, 0x01, 0x00, 0x80 } ++ [_]u8{0} ** 128;
    var sigd = tls.Decoder.fromTheirSlice(@constCast(&wire));
    try testing.expectError(
        error.TlsBadRsaSignatureBitCount,
        key.verifySignature(&sigd, &.{"transcript"}, .tls_1_3),
    );
}

test "a host name with a trailing dot matches the certificate" {
    // `https://example.com./` names the same host as
    // `https://example.com/`, and no certificate carries a `dNSName` that
    // ends in a dot, so every such url exited 60. Measured: curl 8.21.0
    // fetches it and prints `subjectAltName: "example.com." matches
    // cert's "example.com"`.
    var storage: [test_san_max]u8 = undefined;
    const san = buildSan(&storage, &.{
        .{ .tag = .dNSName, .bytes = "example.com" },
    });
    const cert = parsedWithSan(san, san.len, 0);

    try verifyHost(cert, "example.com.");
    try verifyHost(cert, "example.com");
    // One root label is dropped and no more.
    try testing.expectError(
        error.CertificateHostMismatch,
        verifyHost(cert, "example.com.."),
    );
    try testing.expectError(
        error.CertificateHostMismatch,
        verifyHost(cert, "other.com."),
    );
}

test "a wildcard certificate answers a trailing dot too" {
    var storage: [test_san_max]u8 = undefined;
    const san = buildSan(&storage, &.{
        .{ .tag = .dNSName, .bytes = "*.wild.example" },
    });
    const cert = parsedWithSan(san, san.len, 0);
    try verifyHost(cert, "a.wild.example.");
    try testing.expectError(
        error.CertificateHostMismatch,
        verifyHost(cert, "a.b.wild.example."),
    );
}

test "a name constraint reads the host the same way the host check does" {
    // Both go through `wantedName`, so the root label is dropped once and
    // in one place. Two readings would let a chain answer for a host that
    // one of the two refused.
    const ca_key = try testKey(0x73);
    var ca: DerBuf = .{};
    try mint(&ca, .{
        .serial = 23,
        .issuer_cn = "dot root",
        .subject_cn = "dot root",
        .basic_constraints = .{ .ca = true },
        .key_usage = .key_cert_sign,
        .name_constraints = .{ .permitted_dns = "inside.test" },
    }, ca_key.public_key, ca_key);

    var leaf: DerBuf = .{};
    try mint(&leaf, .{
        .serial = 24,
        .issuer_cn = "dot root",
        .subject_cn = "host.inside.test",
        .san_dns = "host.inside.test",
        .key_usage = .digital_signature,
    }, ca_key.public_key, ca_key);

    const ca_parsed = try mintedParsed(&ca);
    const leaf_parsed = try mintedParsed(&leaf);
    try verifyIssued(leaf_parsed, ca_parsed, "host.inside.test.", 0, test_now_sec);
    try testing.expectError(
        error.CertificateNameNotPermitted,
        verifyIssued(leaf_parsed, ca_parsed, "outside.test.", 0, test_now_sec),
    );
}

test "a host name longer than the extension can carry is refused" {
    // `host` reaches `init` from a url, and a url can reach zurl from a
    // `Location` header, so the count is not always this build's. The
    // cast to `u16` had no bound, and an `@intCast` that does not fit is
    // undefined behaviour in ReleaseFast.
    var read_buf: [min_buffer_len]u8 = undefined;
    var input: Reader = .fixed(&read_buf);
    input.end = 0;

    var out_buf: [4096]u8 = undefined;
    var written: Writer = .fixed(&out_buf);

    var app_read_buf: [max_ciphertext_len]u8 = undefined;
    var app_write_buf: [max_ciphertext_len]u8 = undefined;
    var entropy: [Options.entropy_len]u8 = undefined;
    for (&entropy, 0..) |*byte, index| byte.* = @truncate(index + 1);

    const long: [host_name_max + 1]u8 = @splat('a');
    try testing.expectError(error.TlsHostNameTooLong, init(&input, &written, .{
        .host = .{ .explicit = &long },
        .ca = .no_verification,
        .write_buffer = &app_write_buf,
        .read_buffer = &app_read_buf,
        .entropy = &entropy,
        .realtime_now = test_now,
    }));
    // Nothing was written, so the refusal comes before the hello.
    try testing.expectEqual(@as(usize, 0), written.end);

    // And a host over 65535 octets, which is the count the cast itself
    // could not hold. Without the bound this is an `@intCast` that does
    // not fit, which panics a checked build and is undefined behaviour in
    // the ReleaseFast build a user runs.
    const huge = try testing.allocator.alloc(u8, 70_000);
    defer testing.allocator.free(huge);
    @memset(huge, 'b');

    var second_out: [4096]u8 = undefined;
    var second: Writer = .fixed(&second_out);
    input.end = 0;
    input.seek = 0;
    try testing.expectError(error.TlsHostNameTooLong, init(&input, &second, .{
        .host = .{ .explicit = huge },
        .ca = .no_verification,
        .write_buffer = &app_write_buf,
        .read_buffer = &app_read_buf,
        .entropy = &entropy,
        .realtime_now = test_now,
    }));
    try testing.expectEqual(@as(usize, 0), second.end);
}
