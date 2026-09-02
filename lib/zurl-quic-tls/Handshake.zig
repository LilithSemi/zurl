//! The TLS 1.3 handshake of a QUIC client, RFC 9001.
//!
//! **QUIC has no TLS records.** RFC 9001 section 4 carries the handshake
//! messages of RFC 8446 in QUIC CRYPTO frames, one stream of bytes for
//! each encryption level, and it asks TLS for a secret at each level
//! rather than for a record cipher. So the vendored TLS client cannot run
//! this handshake: that file reads records and produces a record cipher.
//! This file runs the message state machine instead, and it hands every
//! secret to `protection.Keys.fromSecret`, which RFC 9001 appendix A
//! already checks byte for byte.
//!
//! ## What this file does not decide
//!
//! **It decides no trust.** The host name walk, the address walk, the
//! chain walk, the trust store, and the CertificateVerify signature are
//! all `zurl_tls.Client.quic`, which is the vendored client's own code in
//! the vendored client's own file. There is no certificate parsing here
//! and no second set of rules. A rule added there reaches QUIC with no
//! change here.
//!
//! **It chooses no Diffie-Hellman.** `zurl_tls.Client.quic.KeyExchange` is
//! the vendored client's `KeyShare`, so both transports generate the same
//! key pairs from the same seed and run the same scalar multiplication.
//!
//! **It writes no packet.** It gives out the bytes that belong in CRYPTO
//! frames and it takes the bytes that arrived in them. `zurl-quic` builds
//! the packets, and the connection engine above owns the datagrams.
//!
//! ## The order of a handshake
//!
//! | Level | Client sends | Server sends |
//! | --- | --- | --- |
//! | Initial | ClientHello | ServerHello |
//! | Handshake | an empty Certificate when one was asked for, then Finished | EncryptedExtensions, CertificateRequest, Certificate, CertificateVerify, Finished |
//! | Application | nothing | NewSessionTicket, and nothing this build needs |
//!
//! **One fault ends it.** `State.failed` is terminal, and every call after
//! it is `error.TlsHandshakeFailed`. A refused message is left in its
//! stream, so without that state a caller that dropped the error would
//! read the same message again and move the transcript hash twice.
//!
//! The Initial keys need no handshake at all, so the ClientHello is
//! protected before the client has heard from anybody. The ServerHello
//! fixes the cipher suite and the key share, and every secret after it
//! comes from `schedule.zig`.
//!
//! ## What a peer chooses, and what bounds it
//!
//! Every byte the server sends is untrusted input.
//!
//! | Input | Bound |
//! | --- | --- |
//! | CRYPTO frame offset and length | The caller's buffer, in `CryptoStream` |
//! | A handshake message length | The bytes reassembled so far, and the buffer |
//! | The cipher suite | One of the three the hello offered |
//! | The negotiated version | TLS 1.3 and nothing else |
//! | The key share group | `offered_key_share_group`, the one group the hello sent a share for |
//! | An extension in a message | One the hello offered, and each identifier once |
//! | A handshake message length | The buffer of its own level, or `TlsMessageTooLong` |
//! | The ALPN answer | One of the names the hello offered |
//! | The transport parameters | `transport_parameters.decode`, then `checkPeerParameters` |
//! | The certificate chain | `zurl_tls.Client.quic.verifyCertificate` |
//! | The Finished verify data | A constant time comparison against the value the transcript gives |

const std = @import("std");

const tls = std.crypto.tls;
const quic = @import("zurl-quic");
const zurl_tls = @import("zurl-tls");

const packet = quic.packet;
const protection = quic.protection;
const transport_parameters = quic.transport_parameters;

const Client = zurl_tls.Client;
const CryptoStream = @import("CryptoStream.zig");
const Session = @import("Session.zig");
const schedule = @import("schedule.zig");

const Handshake = @This();

/// How many bytes of entropy `init` reads: a 32 byte client random and the
/// seed of the key exchange.
pub const entropy_len: usize = 32 + Client.quic.key_exchange_seed_len;

/// The longest ClientHello this build writes.
///
/// The host name takes at most 255 bytes, the ALPN offer at most
/// `alpn_max_list_len`, and the transport parameters far less than the
/// rest. A caller whose offer does not fit gets
/// `error.HandshakeBufferTooSmall` before a byte goes out.
pub const max_client_hello: usize = 2048;

/// The Certificate message this build sends when a server asks for a
/// client certificate: four bytes of header, a
/// `certificate_request_context` of no bytes, and a `certificate_list` of
/// no bytes. RFC 8446 section 4.4.2.
///
/// This build holds no client certificate, so the empty list is the only
/// honest answer, and RFC 8446 makes it the right one.
pub const empty_certificate = [_]u8{
    @intFromEnum(tls.HandshakeType.certificate),
    0, 0, 4, // body_len
    0, // certificate_request_context of no bytes
    0, 0, 0, // certificate_list of no bytes
};

/// The longest Handshake level flight this build writes: the empty
/// Certificate a server that asked for one gets, then a Finished of four
/// bytes of header and one SHA-384 digest.
pub const max_finished: usize = empty_certificate.len + 4 + protection.max_secret_len;

/// The least room the server's Handshake level flight needs.
///
/// EncryptedExtensions, Certificate, CertificateVerify and Finished all
/// arrive there, and the certificate chain is what makes it large. Eight
/// kilobytes holds an ordinary chain of three RSA-4096 certificates with
/// room to spare, and a server that sends more is refused by name.
pub const min_handshake_buffer: usize = 8192;

/// The least room the Initial level needs, which holds one ServerHello.
pub const min_initial_buffer: usize = 1024;

/// The least room the application level needs, which holds the session
/// tickets a server sends after the handshake.
///
/// **It bounds one message and not the whole stream.** `CryptoStream`
/// slides what it has read off the front, so a server may send tickets for
/// as long as the connection lives. Only a single ticket larger than this
/// is refused, and that is `error.TlsMessageTooLong`.
pub const min_application_buffer: usize = 4096;

/// The QUIC transport parameters extension. RFC 9001 section 8.2.
pub const transport_parameters_extension: tls.ExtensionType = .quic_transport_parameters;

/// The content a CertificateVerify signature covers. RFC 8446 section
/// 4.4.3.
const certificate_verify_context = " " ** 64 ++ "TLS 1.3, server CertificateVerify\x00";

/// The one key share group a QUIC client hello offers.
///
/// One x25519 share keeps the whole hello inside the 1200 byte bound RFC
/// 9000 section 14.1 puts on a client's first datagram, and every server
/// that speaks HTTP/3 takes it. It is a named constant because two places
/// must agree on it: `writeClientHello` sends it, and `readServerHello`
/// refuses any other answer.
pub const offered_key_share_group: tls.NamedGroup = .x25519;

/// The cipher suites a QUIC client hello offers, in the order of
/// preference.
///
/// The order follows the vendored TLS client: AES first where the machine
/// has instructions for it, and ChaCha20 first where it does not.
pub const offered_suites: []const protection.Suite = if (std.crypto.core.aes.has_hardware_support)
    &.{ .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305 }
else
    &.{ .chacha20_poly1305, .aes_128_gcm, .aes_256_gcm };

/// Where the handshake has reached.
pub const State = enum {
    /// The ClientHello is written and the ServerHello has not arrived.
    wait_server_hello,
    wait_encrypted_extensions,
    wait_certificate,
    wait_certificate_verify,
    wait_finished,
    /// The server's Finished checked, the client's Finished is queued, and
    /// the application keys are installed.
    complete,
    /// A message was refused, so this handshake is over.
    ///
    /// **It is terminal on purpose.** A refused message stays in its
    /// `CryptoStream`, and the transcript hash is a running state that a
    /// second read of the same bytes would move twice. QUIC callers
    /// habitually drop a per-frame error and carry on, so the state is
    /// what stops the next frame from running the same message again.
    failed,
};

/// Everything the handshake reports as a fault.
pub const Error = error{
    /// The ClientHello does not fit `max_client_hello`, or a buffer the
    /// caller gave is below its minimum.
    HandshakeBufferTooSmall,
    /// A handshake message arrived at an encryption level RFC 9001
    /// section 4.1.3 does not put it at.
    TlsWrongEncryptionLevel,
    /// The server chose a cipher suite the hello did not offer, or one
    /// RFC 9001 gives QUIC no header protection for.
    TlsBadCipherSuite,
    /// The server answered with a version other than TLS 1.3. RFC 9001
    /// section 4.2 gives QUIC no other one.
    TlsBadVersion,
    /// The server asked for a second ClientHello. This build offers an
    /// x25519 key share, which every server that speaks HTTP/3 accepts,
    /// so a retry means the server wants a group the offer did not carry.
    TlsHelloRetryRequest,
    /// A message this build does not expect at this point of the
    /// handshake, or one it never expects at all.
    TlsUnexpectedMessage,
    /// The server left out an extension RFC 9001 makes it send, or it
    /// sent one twice, or a field inside one is not the shape the RFC
    /// gives it.
    TlsIllegalParameter,
    /// The server sent no ALPN extension. RFC 9001 section 8.1 requires
    /// ALPN on every QUIC connection, so an answer of nothing is a fault
    /// here where it is not one over TLS.
    TlsAlpnMissing,
    /// The server sent no `quic_transport_parameters` extension. RFC 9001
    /// section 8.2 requires one.
    TlsTransportParametersMissing,
    /// A connection id in the transport parameters does not match the one
    /// the packets carried. RFC 9000 section 7.3.
    TlsConnectionIdMismatch,
    /// The Finished message does not check under the transcript.
    TlsDecryptError,
    /// The peer's certificate chain reached no trust root, or it named
    /// another host.
    TlsCertificateNotVerified,
    /// A message was refused earlier, so this handshake is over and no
    /// further byte is read. The first fault is the one that says why.
    TlsHandshakeFailed,
    /// The server sent an extension the client hello never offered. RFC
    /// 8446 section 4.2 makes that `unsupported_extension`.
    TlsUnsupportedExtension,
    /// A handshake message names a body no buffer at its level can hold,
    /// so no run of frames can ever complete it.
    TlsMessageTooLong,
    /// The host name is longer than the 255 bytes RFC 6066 section 3 gives
    /// a `HostName`, so the hello can carry no `server_name` for it.
    TlsServerNameTooLong,
} || CryptoStream.Error ||
    transport_parameters.DecodeError ||
    Client.quic.VerifyCertificateError ||
    error{ TlsDecodeError, TlsBadSignatureScheme, TlsAlpnOfferInvalid, TlsAlpnProtocolNotOffered } ||
    error{ InsufficientEntropy, TlsDecryptFailure } ||
    Client.quic.CertificateKey.VerifyError;

/// The Source Connection ID of a Retry packet whose integrity tag checked.
///
/// **The check is the constructor.** RFC 9000 section 17.2.5.2 has a
/// client discard a Retry whose tag does not match, because only somebody
/// who saw the client's first Initial packet can write one. A client that
/// skipped the check would let anyone on the path restart its handshake
/// with a connection id of their choosing. That requirement used to be a
/// sentence in a doc comment, which a caller can read and step past. It is
/// a type now: `verify` is the one function that makes one of these, and
/// `Options.retry_source_connection_id` takes nothing else.
pub const VerifiedRetry = struct {
    id: packet.ConnectionId,

    /// Every fault the check reports.
    pub const VerifyError = quic.initial.RetryError || error{
        /// The Retry carries a tag that is not the one its contents give,
        /// so it was written by somebody who never saw the client's first
        /// Initial packet. RFC 9000 section 17.2.5.2 discards it.
        RetryIntegrityFailed,
    };

    /// Checks a whole Retry packet and gives back its Source Connection
    /// ID.
    ///
    /// `odcid` is the Destination Connection ID of the client's first
    /// Initial packet, `retry` is every byte of the Retry packet with its
    /// integrity tag on the end, and `scid` is the Source Connection ID
    /// the Retry header carried.
    pub fn verify(
        odcid: []const u8,
        retry: []const u8,
        scid: packet.ConnectionId,
    ) VerifyError!VerifiedRetry {
        if (!try quic.initial.verifyRetry(odcid, retry)) return error.RetryIntegrityFailed;
        return .{ .id = scid };
    }
};

/// What the caller must supply to run a handshake.
pub const Options = struct {
    /// How to check the host name of the peer certificate. The type is
    /// the vendored client's own field, so the two transports cannot
    /// drift apart on what the choices are.
    host: @FieldType(Client.Options, "host"),
    /// How to check the authenticity of the peer certificate. Also the
    /// vendored client's own field.
    ca: @FieldType(Client.Options, "ca"),
    /// The ALPN protocols to offer, in the order of preference. RFC 9001
    /// section 8.1 makes ALPN mandatory for QUIC, so an empty list is
    /// refused rather than sent.
    ///
    /// `zurl_net.Connection.alpn_http_3` is the list an HTTP/3 transfer
    /// passes, and it is the same constant the TLS path reads its offers
    /// from.
    alpn_protocols: []const []const u8,
    /// The transport parameters this endpoint states. RFC 9000 section
    /// 18.
    parameters: transport_parameters.Parameters,
    /// Cryptographically secure random bytes. Read during `init` and not
    /// captured.
    entropy: *const [entropy_len]u8,
    /// The wall clock, for the validity dates of the certificates.
    realtime_now: std.Io.Timestamp,
    /// The Destination Connection ID of the client's **first** Initial
    /// packet. RFC 9000 section 7.3 has the server echo it in
    /// `original_destination_connection_id`.
    original_destination_connection_id: packet.ConnectionId,
    /// The Source Connection ID of a Retry packet, when one arrived. RFC
    /// 9000 section 7.3 has the server echo it in
    /// `retry_source_connection_id`, and requires that parameter to be
    /// absent when no Retry happened.
    ///
    /// **It also moves the Initial keys.** RFC 9001 section 5.2 has a
    /// client that gets a Retry derive the Initial keys again, from the
    /// Retry's Source Connection ID, because that is the Destination
    /// Connection ID of every Initial packet after it.
    ///
    /// **The integrity tag is checked by the type.** RFC 9000 section
    /// 17.2.5 makes a Retry with a tag that does not check a packet to
    /// discard. `VerifiedRetry.verify` is the only way to make one of
    /// these, so a Retry that fails the check cannot reach this field.
    retry_source_connection_id: ?VerifiedRetry = null,
    /// Where each packet number space carries on from, indexed the way
    /// `Session.space` indexes.
    ///
    /// A fresh connection leaves this at zero. **A Retry does not.** RFC
    /// 9000 section 17.2.5.3 says a client MUST NOT reset its packet
    /// numbers when it sends its Initial packets again, and the model for
    /// a Retry here is to build a second `Handshake`. So the caller reads
    /// `packetNumbers` off the first one and passes it here.
    next_packet_numbers: [3]u64 = @splat(0),
    /// Room for the ServerHello. At least `min_initial_buffer`.
    initial_buffer: []u8,
    /// Room for the server's Handshake level flight. At least
    /// `min_handshake_buffer`.
    handshake_buffer: []u8,
    /// Room for what the server sends after the handshake. At least
    /// `min_application_buffer`.
    application_buffer: []u8,
};

state: State,
host: @FieldType(Client.Options, "host"),
ca: @FieldType(Client.Options, "ca"),
alpn_protocols: []const []const u8,
realtime_now: std.Io.Timestamp,
original_destination_connection_id: packet.ConnectionId,
retry_source_connection_id: ?packet.ConnectionId,
/// The Source Connection ID the server chose, learned from its first
/// packet and checked against `initial_source_connection_id`.
server_connection_id: ?packet.ConnectionId,

client_random: [32]u8,
key_exchange: Client.quic.KeyExchange,
suite: ?protection.Suite,
transcript: ?schedule.Transcript,
handshake_traffic: schedule.Pair,
master: schedule.Secret,
certificate_key: Client.quic.CertificateKey,
alpn: Client.AlpnSelection,
peer_parameters: ?transport_parameters.Parameters,
/// Whether the server sent a CertificateRequest. RFC 8446 section 4.4.2
/// has a client with no certificate answer with an empty one, and that
/// answer goes into the transcript before the client's Finished.
certificate_requested: bool,

/// The ClientHello, kept because the transcript cannot hash it until the
/// ServerHello names the hash.
hello: [max_client_hello]u8,
hello_len: u16,
hello_sent: u16,
finished: [max_finished]u8,
finished_len: u8,
finished_sent: u8,

initial_in: CryptoStream,
handshake_in: CryptoStream,
application_in: CryptoStream,

/// The keys of every level, the packet number spaces, and the key update.
session: Session,

/// Starts a handshake and writes the ClientHello.
///
/// The hello is ready in the Initial level's send stream when this
/// returns, and `takeCrypto` gives it out.
pub fn init(options: Options) Error!Handshake {
    if (options.alpn_protocols.len == 0) return error.TlsAlpnOfferInvalid;
    if (options.initial_buffer.len < min_initial_buffer) return error.HandshakeBufferTooSmall;
    if (options.handshake_buffer.len < min_handshake_buffer) return error.HandshakeBufferTooSmall;
    if (options.application_buffer.len < min_application_buffer) return error.HandshakeBufferTooSmall;

    var self: Handshake = .{
        .state = .wait_server_hello,
        .host = options.host,
        .ca = options.ca,
        .alpn_protocols = options.alpn_protocols,
        .realtime_now = options.realtime_now,
        .original_destination_connection_id = options.original_destination_connection_id,
        .retry_source_connection_id = if (options.retry_source_connection_id) |retry|
            retry.id
        else
            null,
        .server_connection_id = null,
        .client_random = options.entropy[0..32].*,
        .key_exchange = try .init(options.entropy[32..entropy_len]),
        .suite = null,
        .transcript = null,
        .handshake_traffic = .{ .client = .none, .server = .none },
        .master = .none,
        .certificate_key = .empty,
        .alpn = .none,
        .peer_parameters = null,
        .certificate_requested = false,
        .hello = undefined,
        .hello_len = 0,
        .hello_sent = 0,
        .finished = undefined,
        .finished_len = 0,
        .finished_sent = 0,
        .initial_in = .init(options.initial_buffer),
        .handshake_in = .init(options.handshake_buffer),
        .application_in = .init(options.application_buffer),
        // The Initial keys come from the Destination Connection ID of the
        // Initial packets the client is sending now, with the salt RFC
        // 9001 section 5.2 prints. A Retry replaced that id, so the keys
        // come from the Retry's Source Connection ID once one arrived.
        // The packet numbers carry on, because RFC 9000 section 17.2.5.3
        // bars a client from resetting them across a Retry.
        .session = .initFrom(
            if (options.retry_source_connection_id) |retry|
                retry.id.slice()
            else
                options.original_destination_connection_id.slice(),
            options.next_packet_numbers,
        ),
    };

    const written = try self.writeClientHello(options.parameters);
    self.hello_len = @intCast(written);
    return self;
}

/// Writes zeroes over every secret the handshake holds.
///
/// `self.* = undefined` afterwards is a debugging aid and not a wipe: a
/// release build turns it into nothing at all. So every secret is written
/// over by name here, and `key_exchange` is one of them, because it holds
/// four private keys and the raw shared secret of the exchange.
pub fn deinit(self: *Handshake) void {
    self.handshake_traffic.clear();
    self.master.clear();
    self.session.clear();
    std.crypto.secureZero(u8, &self.finished);
    // `Client.quic.KeyExchange` has no `clear` of its own and holds only
    // fixed size fields, so the whole value is written over here.
    std.crypto.secureZero(u8, std.mem.asBytes(&self.key_exchange));
    self.* = undefined;
}

/// Where each packet number space has reached.
///
/// A Retry makes the caller build a second `Handshake`, and RFC 9000
/// section 17.2.5.3 bars it from resetting the packet numbers. This is
/// what it passes to `Options.next_packet_numbers`.
pub fn packetNumbers(self: *const Handshake) [3]u64 {
    var out: [3]u64 = undefined;
    for (&out, &self.session.spaces) |*slot, *from| slot.* = from.next;
    return out;
}

/// The connection id the server put in the Source Connection ID field of
/// its first packet.
///
/// **RFC 9000 section 7.3 has the client check this against the
/// `initial_source_connection_id` transport parameter.** The check runs
/// when EncryptedExtensions arrives, and a handshake that reaches that
/// message with no id set here is refused, because an unchecked
/// connection id is what a path attacker rewrites.
pub fn setServerConnectionId(self: *Handshake, id: packet.ConnectionId) void {
    self.server_connection_id = id;
}

/// The bytes this endpoint has to put into CRYPTO frames at `level`, or an
/// empty slice when there are none.
///
/// The offset of the first byte is `sentCrypto(level)`. The caller marks
/// what it really sent with `markCryptoSent`, so a frame that was built
/// and then dropped is offered again.
pub fn pendingCrypto(self: *const Handshake, level: protection.Level) []const u8 {
    return switch (level) {
        .initial => self.hello[self.hello_sent..self.hello_len],
        .handshake => self.finished[self.finished_sent..self.finished_len],
        .zero_rtt, .application => &.{},
    };
}

/// The stream offset the next CRYPTO frame at `level` carries.
pub fn sentCrypto(self: *const Handshake, level: protection.Level) u64 {
    return switch (level) {
        .initial => self.hello_sent,
        .handshake => self.finished_sent,
        .zero_rtt, .application => 0,
    };
}

/// Records that `count` bytes of `pendingCrypto(level)` went out.
pub fn markCryptoSent(self: *Handshake, level: protection.Level, count: usize) void {
    std.debug.assert(count <= self.pendingCrypto(level).len);
    switch (level) {
        .initial => self.hello_sent += @intCast(count),
        .handshake => self.finished_sent += @intCast(count),
        .zero_rtt, .application => std.debug.assert(count == 0),
    }
}

/// Takes the bytes of one CRYPTO frame and runs the handshake as far as
/// they allow.
///
/// `level` is the encryption level of the packet the frame arrived in,
/// `offset` is the frame's Offset field, and `bytes` is its payload.
///
/// **One fault ends the handshake.** A message this file refuses stays in
/// its `CryptoStream`, because consuming it would hide what went wrong. So
/// a caller that dropped the error and handed over the next frame would
/// read the same message again, hash it into the transcript a second time,
/// and run the certificate chain walk a second time. `State.failed` is
/// what stops that: every later call is `error.TlsHandshakeFailed` and
/// reads nothing.
pub fn provideCrypto(
    self: *Handshake,
    level: protection.Level,
    offset: u64,
    bytes: []const u8,
) Error!void {
    if (self.state == .failed) return error.TlsHandshakeFailed;

    // RFC 9001 section 4.1.3 gives 0-RTT no CRYPTO frames at all.
    const stream = switch (level) {
        .initial => &self.initial_in,
        .handshake => &self.handshake_in,
        .application => &self.application_in,
        .zero_rtt => return error.TlsWrongEncryptionLevel,
    };
    try stream.provide(offset, bytes);
    self.run() catch |err| {
        self.state = .failed;
        return err;
    };
}

/// Whether the handshake is finished and the application keys are in
/// place.
pub fn isComplete(self: *const Handshake) bool {
    return self.state == .complete;
}

/// The ALPN protocol the server chose. Null before EncryptedExtensions.
pub fn alpnProtocol(self: *const Handshake) ?[]const u8 {
    return self.alpn.slice();
}

/// The transport parameters the server stated. Null before
/// EncryptedExtensions.
pub fn peerParameters(self: *const Handshake) ?transport_parameters.Parameters {
    return self.peer_parameters;
}

/// The cipher suite TLS negotiated. Null before the ServerHello.
pub fn negotiatedSuite(self: *const Handshake) ?protection.Suite {
    return self.suite;
}

/// Reads whatever whole messages the streams hold.
fn run(self: *Handshake) Error!void {
    // The levels are read in the order a handshake uses them. A message
    // that arrived early at a higher level waits, because the state
    // machine refuses it until the state that expects it.
    try self.drain(.initial, &self.initial_in);
    try self.drain(.handshake, &self.handshake_in);
    try self.drain(.application, &self.application_in);
}

/// Reads every whole handshake message one stream holds.
fn drain(self: *Handshake, level: protection.Level, stream: *CryptoStream) Error!void {
    while (true) {
        const ready = stream.available();
        // A handshake message is one type byte and a 24-bit length.
        if (ready.len < 4) return;
        const kind: tls.HandshakeType = @enumFromInt(ready[0]);
        const body_len: u32 = (@as(u32, ready[1]) << 16) | (@as(u32, ready[2]) << 8) | ready[3];
        const whole_len = 4 + @as(usize, body_len);
        // **A length the buffer can never hold is a fault, not a wait.** A
        // server naming `body_len = 0xffffff` at a level with an eight
        // kilobyte buffer can never be satisfied, and a handshake that
        // kept waiting would hang until the idle timer.
        if (whole_len > stream.buffer.len) return error.TlsMessageTooLong;
        // The whole message has to be there before it is read.
        if (ready.len < whole_len) return;

        try self.handle(level, kind, ready[0..whole_len]);
        stream.consume(whole_len);
    }
}

/// Reads one handshake message.
///
/// **The transcript moves only after the message is accepted.** RFC 8446
/// section 4.4.1 hashes every handshake message in order, and the hash is
/// a running state with no way back. So a message that is refused must
/// leave it where it was, or a caller that recovers would carry a
/// transcript the server never had and die at Finished with a fault that
/// names the wrong thing.
fn handle(
    self: *Handshake,
    level: protection.Level,
    kind: tls.HandshakeType,
    whole: []u8,
) Error!void {
    const body = whole[4..];
    switch (kind) {
        .server_hello => {
            if (level != .initial) return error.TlsWrongEncryptionLevel;
            if (self.state != .wait_server_hello) return error.TlsUnexpectedMessage;
            try self.readServerHello(whole, body);
            self.state = .wait_encrypted_extensions;
        },
        .encrypted_extensions => {
            if (level != .handshake) return error.TlsWrongEncryptionLevel;
            if (self.state != .wait_encrypted_extensions) return error.TlsUnexpectedMessage;
            try self.readEncryptedExtensions(body);
            self.transcript.?.update(whole);
            self.state = .wait_certificate;
        },
        .certificate_request => {
            // RFC 8446 section 4.3.2. A server may ask for a client
            // certificate, and this build has none to give. RFC 8446
            // section 4.4.2 has the client answer with a Certificate
            // message that carries an empty list, which is what
            // `readFinished` queues after the server's Finished checks.
            if (level != .handshake) return error.TlsWrongEncryptionLevel;
            if (self.state != .wait_certificate) return error.TlsUnexpectedMessage;
            // One request and no more. The state does not move on this
            // message, because the server's Certificate still follows it,
            // so this flag is what keeps a second one out.
            if (self.certificate_requested) return error.TlsUnexpectedMessage;
            self.certificate_requested = true;
            self.transcript.?.update(whole);
        },
        .certificate => {
            if (level != .handshake) return error.TlsWrongEncryptionLevel;
            if (self.state != .wait_certificate) return error.TlsUnexpectedMessage;
            // **Every trust decision is in this one call**, and it is the
            // vendored TLS client's own code.
            try Client.quic.verifyCertificate(
                body,
                self.host,
                self.ca,
                self.realtime_now,
                &self.certificate_key,
            );
            self.transcript.?.update(whole);
            self.state = .wait_certificate_verify;
        },
        .certificate_verify => {
            if (level != .handshake) return error.TlsWrongEncryptionLevel;
            if (self.state != .wait_certificate_verify) return error.TlsUnexpectedMessage;
            // The signature covers the transcript **before** this
            // message, so the hash is taken first and the message goes in
            // after.
            const hash = self.transcript.?.peek();
            var sigd: tls.Decoder = .fromTheirSlice(body);
            try self.certificate_key.verifySignature(&sigd, &.{
                certificate_verify_context,
                hash.slice(),
            });
            self.transcript.?.update(whole);
            self.state = .wait_finished;
        },
        .finished => {
            if (level != .handshake) return error.TlsWrongEncryptionLevel;
            if (self.state != .wait_finished) return error.TlsUnexpectedMessage;
            try self.readFinished(whole, body);
            self.state = .complete;
        },
        .new_session_ticket => {
            // RFC 8446 section 4.6.1. A ticket arrives after the
            // handshake, at the application level. Nothing here resumes a
            // session, so the ticket is read to the end and dropped.
            if (level != .application) return error.TlsWrongEncryptionLevel;
            if (self.state != .complete) return error.TlsUnexpectedMessage;
        },
        .key_update => {
            // **RFC 9001 section 6 forbids this message in QUIC.** QUIC
            // updates keys with the Key Phase bit of the short header, so
            // a TLS KeyUpdate is a connection error of type
            // PROTOCOL_VIOLATION. `Session.update` is the QUIC way.
            return error.TlsUnexpectedMessage;
        },
        else => return error.TlsUnexpectedMessage,
    }
}

/// Reads the ServerHello and installs the Handshake keys. RFC 8446
/// section 4.1.3.
fn readServerHello(self: *Handshake, whole: []u8, body: []u8) Error!void {
    var d: tls.Decoder = .fromTheirSlice(body);
    try d.ensure(2 + 32 + 1);
    if (d.decode(u16) != @intFromEnum(tls.ProtocolVersion.tls_1_2)) return error.TlsIllegalParameter;
    const random = d.array(32);

    // **A HelloRetryRequest is a ServerHello with a fixed random.** RFC
    // 8446 section 4.1.3. This build offers an x25519 key share, which
    // every server that speaks HTTP/3 accepts, so a retry means the
    // server wants a group the offer did not carry. It is reported by
    // name rather than answered with a second hello this file cannot
    // build.
    if (std.mem.eql(u8, random, &tls.hello_retry_request_sequence)) {
        return error.TlsHelloRetryRequest;
    }

    // The hello sent an empty session id, because RFC 9001 section 8.4
    // bars the TLS 1.3 compatibility mode. The echo has to be empty too.
    const session_id_len = d.decode(u8);
    if (session_id_len != 0) return error.TlsIllegalParameter;

    try d.ensure(2 + 1);
    const suite_code = d.decode(tls.CipherSuite);
    const suite = schedule.suiteOf(suite_code) orelse return error.TlsBadCipherSuite;
    if (!offeredSuite(suite)) return error.TlsBadCipherSuite;
    if (d.decode(u8) != 0) return error.TlsIllegalParameter; // legacy_compression_method

    try d.ensure(2);
    const extensions_len = d.decode(u16);
    var extensions = try d.sub(extensions_len);
    if (!d.eof()) return error.TlsIllegalParameter;

    var seen_version = false;
    var seen_key_share = false;
    var group: tls.NamedGroup = undefined;
    var server_share: []const u8 = &.{};
    while (!extensions.eof()) {
        try extensions.ensure(2 + 2);
        const kind = extensions.decode(tls.ExtensionType);
        const len = extensions.decode(u16);
        var extd = try extensions.sub(len);
        switch (kind) {
            .supported_versions => {
                if (seen_version) return error.TlsIllegalParameter;
                seen_version = true;
                try extd.ensure(2);
                if (extd.decode(u16) != @intFromEnum(tls.ProtocolVersion.tls_1_3)) {
                    return error.TlsBadVersion;
                }
                if (!extd.eof()) return error.TlsIllegalParameter;
            },
            .key_share => {
                if (seen_key_share) return error.TlsIllegalParameter;
                seen_key_share = true;
                try extd.ensure(2 + 2);
                group = extd.decode(tls.NamedGroup);
                const share_len = extd.decode(u16);
                try extd.ensure(share_len);
                server_share = extd.slice(share_len);
                if (!extd.eof()) return error.TlsIllegalParameter;
            },
            // RFC 8446 section 4.1.3 gives a ServerHello no other
            // extension, and an unknown one is a fault rather than
            // something to step over.
            else => return error.TlsIllegalParameter,
        }
    }

    // **TLS 1.3 and nothing else.** RFC 9001 section 4.2 gives QUIC no
    // other version, and a server that leaves the extension out is
    // answering TLS 1.2 whatever the hello asked for.
    if (!seen_version) return error.TlsBadVersion;
    if (!seen_key_share) return error.TlsIllegalParameter;

    // **The group must be the one the hello sent a share for.** RFC 8446
    // section 4.1.4 makes any other group `illegal_parameter`. This hello
    // carries one x25519 share, so x25519 is the only legal answer.
    // `KeyExchange.exchange` takes four groups, because the TLS over TCP
    // client offers four, and without this check a server could name
    // `x25519_ml_kem768` and make the client decapsulate with a key pair
    // whose public key never left the machine.
    if (group != offered_key_share_group) return error.TlsIllegalParameter;
    try self.key_exchange.exchange(group, server_share);
    const shared = self.key_exchange.sharedSecret() orelse return error.TlsIllegalParameter;

    // The transcript starts here, because the hash comes from the suite
    // and the suite comes from this message.
    self.suite = suite;
    var transcript: schedule.Transcript = .init(suite.hash());
    transcript.update(self.hello[0..self.hello_len]);
    transcript.update(whole);

    const stage = schedule.handshakeSecrets(suite, shared, transcript.peek().slice());
    self.transcript = transcript;
    self.handshake_traffic = stage.traffic;
    self.master = stage.master;
    self.session.setHandshakeKeys(suite, &stage.traffic);
}

/// Whether a suite is one the hello offered.
fn offeredSuite(suite: protection.Suite) bool {
    for (offered_suites) |offer| {
        if (offer == suite) return true;
    }
    return false;
}

/// Reads EncryptedExtensions. RFC 8446 section 4.3.1 and RFC 9001 section
/// 8.
fn readEncryptedExtensions(self: *Handshake, body: []u8) Error!void {
    var d: tls.Decoder = .fromTheirSlice(body);
    try d.ensure(2);
    const extensions_len = d.decode(u16);
    var extensions = try d.sub(extensions_len);
    if (!d.eof()) return error.TlsIllegalParameter;

    var alpn: ?Client.AlpnSelection = null;
    var parameters: ?transport_parameters.Parameters = null;
    var seen: std.EnumSet(Known) = .initEmpty();

    while (!extensions.eof()) {
        try extensions.ensure(2 + 2);
        const kind = extensions.decode(tls.ExtensionType);
        const len = extensions.decode(u16);
        var extd = try extensions.sub(len);

        // **An extension the hello never offered is a fault.** RFC 8446
        // section 4.2: "Implementations MUST NOT send extension responses
        // if the remote endpoint did not send the corresponding extension
        // requests", and a client that gets one sends
        // `unsupported_extension`. ServerHello was strict here and this
        // message was not, which is one message of the same flight with
        // two rules.
        const known = knownExtension(kind) orelse {
            if (!offeredExtension(kind)) return error.TlsUnsupportedExtension;
            continue;
        };
        // **One identifier, one appearance.** RFC 8446 section 4.2 says
        // so, and a second copy is where a second value would hide.
        if (seen.contains(known)) return error.TlsIllegalParameter;
        seen.insert(known);

        switch (known) {
            .alpn => alpn = try Client.quic.readAlpnAnswer(&extd, self.alpn_protocols),
            .quic_transport_parameters => {
                parameters = try transport_parameters.decode(extd.rest());
            },
        }
    }

    // RFC 9001 section 8.1: ALPN is mandatory on a QUIC connection, and a
    // server that shares no protocol closes the connection instead of
    // leaving the extension out.
    self.alpn = alpn orelse return error.TlsAlpnMissing;
    // RFC 9001 section 8.2: a client that gets EncryptedExtensions with
    // no transport parameters closes with MISSING_EXTENSION.
    const stated = parameters orelse return error.TlsTransportParametersMissing;
    try self.checkPeerParameters(&stated);
    self.peer_parameters = stated;
}

/// The extensions this build reads out of EncryptedExtensions.
///
/// A second enum and not `tls.ExtensionType`, because that one is not
/// exhaustive and `std.EnumSet` needs a fixed set of names.
const Known = enum { alpn, quic_transport_parameters };

fn knownExtension(kind: tls.ExtensionType) ?Known {
    return switch (kind) {
        .application_layer_protocol_negotiation => .alpn,
        .quic_transport_parameters => .quic_transport_parameters,
        else => null,
    };
}

/// Whether `writeClientHello` sends this extension.
///
/// It is what bounds EncryptedExtensions. A server may answer only what it
/// was asked, so this list and the one `writeClientHello` writes are one
/// list, and a name added to the hello has to be added here too.
fn offeredExtension(kind: tls.ExtensionType) bool {
    return switch (kind) {
        .server_name,
        .supported_groups,
        .signature_algorithms,
        .application_layer_protocol_negotiation,
        .supported_versions,
        .key_share,
        .quic_transport_parameters,
        => true,
        else => false,
    };
}

/// Checks the parameters the server stated against what the packets
/// carried. RFC 9000 section 7.3.
///
/// **This is what authenticates the connection ids.** Every field of the
/// long header travels in the clear, so a path attacker can rewrite one.
/// The three checks below tie the ids the packets carried to ids the
/// server signed for, because the extension travels inside the handshake
/// encryption.
///
/// `transport_parameters.decode` has already bounded every value and
/// refused a repeated identifier. What is left is the part only the
/// connection knows.
fn checkPeerParameters(
    self: *const Handshake,
    stated: *const transport_parameters.Parameters,
) Error!void {
    // The Destination Connection ID of the client's first Initial packet.
    const original = stated.original_destination_connection_id orelse
        return error.TlsConnectionIdMismatch;
    if (!original.eql(&self.original_destination_connection_id)) {
        return error.TlsConnectionIdMismatch;
    }

    // The Source Connection ID the server used, which the client has been
    // sending back as a Destination Connection ID.
    const initial_source = stated.initial_source_connection_id orelse
        return error.TlsConnectionIdMismatch;
    const server_id = self.server_connection_id orelse return error.TlsConnectionIdMismatch;
    if (!initial_source.eql(&server_id)) return error.TlsConnectionIdMismatch;

    // A Retry gives one more id to check, and no Retry means the
    // parameter must not be there at all. RFC 9000 section 7.3.
    if (self.retry_source_connection_id) |wanted| {
        const stated_retry = stated.retry_source_connection_id orelse
            return error.TlsConnectionIdMismatch;
        if (!stated_retry.eql(&wanted)) return error.TlsConnectionIdMismatch;
    } else if (stated.retry_source_connection_id != null) {
        return error.TlsConnectionIdMismatch;
    }
}

/// Checks the server's Finished, installs the application keys, and
/// queues the client's Finished. RFC 8446 section 4.4.4.
fn readFinished(self: *Handshake, whole: []u8, body: []u8) Error!void {
    const suite = self.suite.?;
    const digest_len = suite.hash().secretLen();

    // The server signs the transcript that ends before its own Finished.
    const hash = self.transcript.?.peek();
    const server_key = schedule.finishedKey(suite, &self.handshake_traffic.server);
    const expected = schedule.verifyData(suite, &server_key, hash.slice());
    if (body.len != digest_len) return error.TlsDecryptError;
    // A constant time comparison, so the answer gives away nothing about
    // where the two differ.
    if (!std.crypto.timing_safe.eql([48]u8, padTo48(expected.slice()), padTo48(body))) {
        return error.TlsDecryptError;
    }

    self.transcript.?.update(whole);

    // The application secrets come from the transcript through the
    // server's Finished. RFC 8446 section 7.1.
    const application = schedule.applicationSecrets(suite, &self.master, self.transcript.?.peek().slice());
    self.session.setApplicationKeys(suite, &application);

    // **A server that asked for a client certificate gets an empty one.**
    // RFC 8446 section 4.4.2: a client with no certificate the server
    // would take sends a Certificate message carrying an empty list, and
    // it sends no CertificateVerify after it. The message goes into the
    // transcript before the client's Finished, because it is part of the
    // client's flight.
    var at: usize = 0;
    if (self.certificate_requested) {
        @memcpy(self.finished[0..empty_certificate.len], &empty_certificate);
        at = empty_certificate.len;
        self.transcript.?.update(self.finished[0..at]);
    }

    // The client's Finished covers the same transcript, so it is built
    // from the hash that was just taken.
    const client_key = schedule.finishedKey(suite, &self.handshake_traffic.client);
    const verify = schedule.verifyData(suite, &client_key, self.transcript.?.peek().slice());
    self.finished[at + 0] = @intFromEnum(tls.HandshakeType.finished);
    self.finished[at + 1] = 0;
    self.finished[at + 2] = 0;
    self.finished[at + 3] = @intCast(verify.len);
    @memcpy(self.finished[at + 4 ..][0..verify.len], verify.slice());
    self.finished_len = @intCast(at + 4 + verify.len);
    self.finished_sent = 0;

    self.transcript.?.update(self.finished[at..self.finished_len]);
}

/// Widens a digest to the longest one, so the comparison of two digests
/// of the same length runs over one fixed width.
///
/// The lengths are compared before this runs, so the padding cannot make
/// two different digests equal.
fn padTo48(bytes: []const u8) [48]u8 {
    std.debug.assert(bytes.len <= 48);
    var out: [48]u8 = @splat(0);
    @memcpy(out[0..bytes.len], bytes);
    return out;
}

/// Writes the ClientHello into `self.hello`, and reports how many bytes it
/// took. RFC 8446 section 4.1.2.
fn writeClientHello(self: *Handshake, parameters: transport_parameters.Parameters) Error!usize {
    var alpn_buf: [Client.alpn_extension_max]u8 = undefined;
    const alpn_extension = try Client.quic.encodeAlpnExtension(self.alpn_protocols, &alpn_buf);

    var w: std.Io.Writer = .fixed(&self.hello);
    write(&w, &.{@intFromEnum(tls.HandshakeType.client_hello)}) catch
        return error.HandshakeBufferTooSmall;
    const body_at = try open(&w, 3);

    // legacy_version is always TLS 1.2 in a TLS 1.3 hello.
    try writeInt(&w, u16, @intFromEnum(tls.ProtocolVersion.tls_1_2));
    try write(&w, &self.client_random);
    // **An empty legacy_session_id.** RFC 9001 section 8.4 bars the TLS
    // 1.3 compatibility mode, and the 32 byte fake session id is that
    // mode's only purpose.
    try writeInt(&w, u8, 0);

    const suites_at = try open(&w, 2);
    for (offered_suites) |suite| {
        try writeInt(&w, u16, @intFromEnum(schedule.codeOf(suite)));
    }
    try close(&w, suites_at, 2);

    // legacy_compression_methods: one method, "null".
    try writeInt(&w, u8, 1);
    try writeInt(&w, u8, 0);

    const extensions_at = try open(&w, 2);

    try self.writeServerName(&w);

    // supported_groups, RFC 8446 section 4.2.7.
    try writeInt(&w, u16, @intFromEnum(tls.ExtensionType.supported_groups));
    const groups_ext = try open(&w, 2);
    const groups_list = try open(&w, 2);
    for (Client.quic.key_share_groups) |group| {
        try writeInt(&w, u16, @intFromEnum(group));
    }
    try close(&w, groups_list, 2);
    try close(&w, groups_ext, 2);

    // signature_algorithms, RFC 8446 section 4.2.3. The same list the
    // vendored TLS client offers, so both transports accept the same
    // certificates.
    try writeInt(&w, u16, @intFromEnum(tls.ExtensionType.signature_algorithms));
    const sig_ext = try open(&w, 2);
    const sig_list = try open(&w, 2);
    for (signature_algorithms) |scheme| {
        try writeInt(&w, u16, @intFromEnum(scheme));
    }
    try close(&w, sig_list, 2);
    try close(&w, sig_ext, 2);

    // ALPN, RFC 7301. The bytes come from the vendored client's encoder,
    // so a QUIC hello and a TLS hello carry the same offer.
    try write(&w, alpn_extension);

    // supported_versions, RFC 8446 section 4.2.1. **TLS 1.3 alone**,
    // because RFC 9001 section 4.2 gives QUIC no other version.
    try writeInt(&w, u16, @intFromEnum(tls.ExtensionType.supported_versions));
    try writeInt(&w, u16, 3);
    try writeInt(&w, u8, 2);
    try writeInt(&w, u16, @intFromEnum(tls.ProtocolVersion.tls_1_3));

    // key_share, RFC 8446 section 4.2.8. One x25519 share, which keeps
    // the whole hello inside the 1200 byte bound RFC 9000 section 14.1
    // puts on a client's first datagram.
    try writeInt(&w, u16, @intFromEnum(tls.ExtensionType.key_share));
    const share_ext = try open(&w, 2);
    const share_list = try open(&w, 2);
    self.key_exchange.writeShare(&w, offered_key_share_group) catch |err| switch (err) {
        error.WriteFailed => return error.HandshakeBufferTooSmall,
        error.TlsIllegalParameter => |e| return e,
    };
    try close(&w, share_list, 2);
    try close(&w, share_ext, 2);

    // quic_transport_parameters, RFC 9001 section 8.2. The payload is the
    // parameters themselves, with no length of its own inside the
    // extension.
    try writeInt(&w, u16, @intFromEnum(transport_parameters_extension));
    const parameters_at = try open(&w, 2);
    transport_parameters.encode(parameters, &w) catch return error.HandshakeBufferTooSmall;
    try close(&w, parameters_at, 2);

    try close(&w, extensions_at, 2);
    try close(&w, body_at, 3);
    return w.end;
}

/// Writes the server_name extension, RFC 6066 section 3.
///
/// **An address gets no extension.** RFC 6066 says a literal address must
/// not appear in a server name, and `verifyHost` reads the same host as an
/// address to decide which name a certificate must carry. So the two
/// agree on what a name is.
fn writeServerName(self: *Handshake, w: *std.Io.Writer) Error!void {
    const host = switch (self.host) {
        .no_verification => return,
        .explicit => |name| name,
    };
    if (host.len == 0) return;
    // **A host this long is said and not swallowed.** RFC 6066 section 3
    // gives a `HostName` a 16 bit length, and this build bounds it at 255
    // so the hello stays inside `max_client_hello`. Leaving the extension
    // out is not a bypass, because `verifyCertificate` still runs on the
    // full host, but a recovery nobody can see is not a recovery.
    if (host.len > 255) return error.TlsServerNameTooLong;
    if (std.Io.net.IpAddress.parse(host, 0)) |_| {
        return;
    } else |_| {}

    try writeInt(w, u16, @intFromEnum(tls.ExtensionType.server_name));
    const ext = try open(w, 2);
    const list = try open(w, 2);
    try writeInt(w, u8, 0); // name_type: host_name
    const name = try open(w, 2);
    try write(w, host);
    try close(w, name, 2);
    try close(w, list, 2);
    try close(w, ext, 2);
}

/// The signature schemes the hello offers. The same list the vendored TLS
/// client sends.
const signature_algorithms = [_]tls.SignatureScheme{
    .ecdsa_secp256r1_sha256,
    .ecdsa_secp384r1_sha384,
    .rsa_pss_rsae_sha256,
    .rsa_pss_rsae_sha384,
    .rsa_pss_rsae_sha512,
    .rsa_pss_pss_sha256,
    .rsa_pss_pss_sha384,
    .rsa_pss_pss_sha512,
    .rsa_pkcs1_sha256,
    .rsa_pkcs1_sha384,
    .rsa_pkcs1_sha512,
    .ed25519,
};

/// Writes bytes, and turns a full buffer into a name the caller can act
/// on.
fn write(w: *std.Io.Writer, bytes: []const u8) error{HandshakeBufferTooSmall}!void {
    w.writeAll(bytes) catch return error.HandshakeBufferTooSmall;
}

/// Writes one big endian integer.
fn writeInt(
    w: *std.Io.Writer,
    comptime Int: type,
    value: Int,
) error{HandshakeBufferTooSmall}!void {
    w.writeInt(Int, value, .big) catch return error.HandshakeBufferTooSmall;
}

/// Leaves room for a length field of `width` bytes, and reports where it
/// went.
///
/// **Every length in this hello is written last**, from the position the
/// bytes really reached. So no field can name a count the buffer does not
/// hold, whatever is put between `open` and `close`.
fn open(w: *std.Io.Writer, width: usize) error{HandshakeBufferTooSmall}!usize {
    const at = w.end;
    var index: usize = 0;
    while (index < width) : (index += 1) try writeInt(w, u8, 0);
    return at;
}

/// Fills in a length field that `open` left room for.
fn close(w: *std.Io.Writer, at: usize, width: usize) error{HandshakeBufferTooSmall}!void {
    const length = w.end - at - width;
    // A `u16` field cannot name more, and nothing here writes a longer
    // run than the buffer holds.
    if (width == 2 and length > std.math.maxInt(u16)) return error.HandshakeBufferTooSmall;
    if (width == 3 and length > std.math.maxInt(u24)) return error.HandshakeBufferTooSmall;
    var index: usize = 0;
    while (index < width) : (index += 1) {
        const shift: u5 = @intCast(8 * (width - 1 - index));
        w.buffer[at + index] = @truncate(length >> shift);
    }
}
