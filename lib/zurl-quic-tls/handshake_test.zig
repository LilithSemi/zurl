//! The QUIC TLS handshake, run end to end against a server this file
//! builds.
//!
//! **No test here opens a socket.** The server below is a set of functions
//! that write the bytes RFC 8446 and RFC 9001 ask for. It holds a real
//! x25519 key pair, it makes a real self-signed certificate, and it signs
//! a real CertificateVerify, so the client runs every check it would run
//! against a real server: the key exchange, the key schedule, the
//! certificate chain, the signature, and the Finished message.
//!
//! The key schedule itself is checked against RFC 8448 in `schedule.zig`,
//! and the QUIC key derivation under it is checked against RFC 9001
//! appendix A in `zurl-quic`. What is checked here is the state machine
//! that joins them, and every way a peer can get it wrong.

const std = @import("std");

const tls = std.crypto.tls;
const crypto = std.crypto;
const quic = @import("zurl-quic");
const zurl_tls = @import("zurl-tls");

const packet = quic.packet;
const protection = quic.protection;
const transport_parameters = quic.transport_parameters;

const Client = zurl_tls.Client;
const Handshake = @import("Handshake.zig");
const Session = @import("Session.zig");
const schedule = @import("schedule.zig");

const testing = std.testing;

/// The ALPN offer of an HTTP/3 transfer. The same one byte list
/// `zurl_net.Connection.alpn_http_3` names.
const alpn_h3: []const []const u8 = &.{"h3"};

/// A wall clock inside the validity of the certificate the server builds.
/// The dates below run from 2020 to 2099.
const now: std.Io.Timestamp = .{ .nanoseconds = 1_700_000_000 * std.time.ns_per_s };

// ---------------------------------------------------------------------
// A buffer that writes DER and TLS structures, both of which put a length
// in front of a body whose size is known only after it is written.
// ---------------------------------------------------------------------

fn Buf(comptime capacity: usize) type {
    return struct {
        data: [capacity]u8 = undefined,
        len: usize = 0,

        const Self = @This();

        fn push(self: *Self, bytes: []const u8) void {
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

        /// Wraps everything written since `from` in a DER tag and its
        /// minimal length.
        fn wrapDer(self: *Self, from: usize, tag: u8) void {
            const body = self.len - from;
            const header = 1 + derLengthLen(body);
            std.mem.copyBackwards(
                u8,
                self.data[from + header ..][0..body],
                self.data[from..][0..body],
            );
            self.data[from] = tag;
            writeDerLength(self.data[from + 1 ..], body);
            self.len += header;
        }

        /// Wraps everything written since `from` in a big endian length
        /// of `width` bytes, which is what TLS puts in front of a vector.
        fn wrapLen(self: *Self, from: usize, width: usize) void {
            const body = self.len - from;
            std.mem.copyBackwards(
                u8,
                self.data[from + width ..][0..body],
                self.data[from..][0..body],
            );
            var index: usize = 0;
            while (index < width) : (index += 1) {
                const shift: u5 = @intCast(8 * (width - 1 - index));
                self.data[from + index] = @truncate(body >> shift);
            }
            self.len += width;
        }
    };
}

fn derLengthLen(body: usize) usize {
    if (body < 0x80) return 1;
    if (body <= 0xff) return 2;
    return 3;
}

fn writeDerLength(out: []u8, body: usize) void {
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

// ---------------------------------------------------------------------
// The server
// ---------------------------------------------------------------------

const Ecdsa = crypto.sign.ecdsa.EcdsaP256Sha256;

/// Object identifiers, without the tag and the length.
const oid_ecdsa_with_sha256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
const oid_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const oid_prime256v1 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const oid_common_name = [_]u8{ 0x55, 0x04, 0x03 };

/// What the server does differently from a server that follows the rules.
///
/// Each field is one way a peer can be wrong, and each one has a test.
const Fault = struct {
    /// Leave the ALPN extension out of EncryptedExtensions.
    no_alpn: bool = false,
    /// Answer an ALPN protocol the client never offered.
    alpn_not_offered: bool = false,
    /// Send the ALPN extension twice.
    duplicate_alpn: bool = false,
    /// Leave the transport parameters out.
    no_transport_parameters: bool = false,
    /// Echo the wrong `original_destination_connection_id`.
    wrong_original_connection_id: bool = false,
    /// Leave `initial_source_connection_id` out.
    no_initial_source_connection_id: bool = false,
    /// State a `retry_source_connection_id` when no Retry happened.
    unexpected_retry_connection_id: bool = false,
    /// Answer a cipher suite the hello never offered.
    unoffered_suite: bool = false,
    /// Answer TLS 1.2 in the `supported_versions` extension.
    wrong_version: bool = false,
    /// Send a HelloRetryRequest.
    hello_retry: bool = false,
    /// Echo a session id, which RFC 9001 section 8.4 bars.
    echo_session_id: bool = false,
    /// Change one byte of the Finished message.
    bad_finished: bool = false,
    /// Change one byte of the CertificateVerify signature.
    bad_signature: bool = false,
    /// Send an empty certificate list.
    empty_certificate_list: bool = false,
    /// Change one byte of the certificate, so its own signature fails.
    tampered_certificate: bool = false,
    /// Send a TLS KeyUpdate message, which RFC 9001 section 6 forbids.
    tls_key_update: bool = false,
    /// Name a key share group the hello never sent a share for.
    wrong_key_share_group: bool = false,
    /// Put an extension in EncryptedExtensions that the hello never
    /// offered.
    unoffered_extension: bool = false,
    /// Ask for a client certificate, RFC 8446 section 4.3.2.
    certificate_request: bool = false,
    /// Name a body length no buffer at the level can hold.
    message_too_long: bool = false,
};

const Server = struct {
    x25519: crypto.dh.X25519.KeyPair,
    signer: Ecdsa.KeyPair,
    certificate: Buf(1024) = .{},
    suite: protection.Suite = .aes_128_gcm,
    transcript: schedule.Transcript = undefined,
    traffic: schedule.Pair = undefined,
    master: schedule.Secret = undefined,
    connection_id: packet.ConnectionId,
    original_connection_id: packet.ConnectionId,
    fault: Fault = .{},

    fn init(connection_id: packet.ConnectionId, original: packet.ConnectionId) !Server {
        var self: Server = .{
            .x25519 = try .generateDeterministic([_]u8{0x5a} ** 32),
            .signer = try .generateDeterministic([_]u8{0x3c} ** 32),
            .connection_id = connection_id,
            .original_connection_id = original,
        };
        try self.buildCertificate();
        return self;
    }

    /// Builds a self-signed X.509 version 1 certificate around the
    /// server's ECDSA key, and signs it with that key.
    ///
    /// The signature is real, so a client that asks for `.self_signed`
    /// checks it and a tampered copy is refused.
    fn buildCertificate(self: *Server) !void {
        var tbs: Buf(1024) = .{};

        // serialNumber
        tbs.push(&.{ 0x02, 0x01, 0x01 });
        // signature: ecdsa-with-SHA256, no parameters.
        writeAlgorithmIdentifier(&tbs);
        // issuer and subject, the same name for a self-signed certificate.
        writeName(&tbs);
        // validity, from 2020 to 2099.
        {
            const at = tbs.mark();
            tbs.byte(0x17);
            tbs.byte(13);
            tbs.push("200101000000Z");
            tbs.byte(0x17);
            tbs.byte(13);
            tbs.push("991231235959Z");
            tbs.wrapDer(at, 0x30);
        }
        writeName(&tbs);
        // subjectPublicKeyInfo
        {
            const at = tbs.mark();
            {
                const algo = tbs.mark();
                writeOid(&tbs, &oid_ec_public_key);
                writeOid(&tbs, &oid_prime256v1);
                tbs.wrapDer(algo, 0x30);
            }
            {
                const key = tbs.mark();
                tbs.byte(0x00); // unused bits
                const point = self.signer.public_key.toUncompressedSec1();
                tbs.push(&point);
                tbs.wrapDer(key, 0x03);
            }
            tbs.wrapDer(at, 0x30);
        }
        tbs.wrapDer(0, 0x30);

        // The signature covers the whole TBSCertificate, header included.
        const signature = try self.signer.sign(tbs.slice(), null);
        var der_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
        const der_sig = signature.toDer(&der_buf);

        self.certificate.push(tbs.slice());
        writeAlgorithmIdentifier(&self.certificate);
        {
            const at = self.certificate.mark();
            self.certificate.byte(0x00);
            self.certificate.push(der_sig);
            self.certificate.wrapDer(at, 0x03);
        }
        self.certificate.wrapDer(0, 0x30);
    }

    fn writeAlgorithmIdentifier(buf: anytype) void {
        const at = buf.mark();
        writeOid(buf, &oid_ecdsa_with_sha256);
        buf.wrapDer(at, 0x30);
    }

    fn writeOid(buf: anytype, oid: []const u8) void {
        buf.byte(0x06);
        buf.byte(@intCast(oid.len));
        buf.push(oid);
    }

    /// One RDNSequence holding a single commonName.
    fn writeName(buf: anytype) void {
        const name = buf.mark();
        const rdn = buf.mark();
        const atav = buf.mark();
        writeOid(buf, &oid_common_name);
        const text = buf.mark();
        buf.push("zurl.test");
        buf.wrapDer(text, 0x13); // PrintableString
        buf.wrapDer(atav, 0x30);
        buf.wrapDer(rdn, 0x31); // SET
        buf.wrapDer(name, 0x30);
    }

    /// Reads the ClientHello, and writes the ServerHello.
    fn serverHello(self: *Server, hello: []const u8, out: *Buf(1024)) ![]const u8 {
        const client_share = findKeyShare(hello) orelse return error.NoKeyShare;

        const at = out.mark();
        out.byte(@intFromEnum(tls.HandshakeType.server_hello));
        const body = out.mark();
        out.int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2));
        if (self.fault.hello_retry) {
            out.push(&tls.hello_retry_request_sequence);
        } else {
            out.push(&[_]u8{0x7e} ** 32);
        }
        if (self.fault.echo_session_id) {
            out.byte(32);
            out.push(&[_]u8{0x11} ** 32);
        } else {
            out.byte(0);
        }
        const code: tls.CipherSuite = if (self.fault.unoffered_suite)
            .AES_128_CCM_SHA256
        else
            schedule.codeOf(self.suite);
        out.int(u16, @intFromEnum(code));
        out.byte(0); // legacy_compression_method

        const extensions = out.mark();
        out.int(u16, @intFromEnum(tls.ExtensionType.supported_versions));
        out.int(u16, 2);
        out.int(u16, @intFromEnum(
            if (self.fault.wrong_version) tls.ProtocolVersion.tls_1_2 else tls.ProtocolVersion.tls_1_3,
        ));
        out.int(u16, @intFromEnum(tls.ExtensionType.key_share));
        const share = out.mark();
        out.int(u16, @intFromEnum(
            if (self.fault.wrong_key_share_group)
                tls.NamedGroup.x25519_ml_kem768
            else
                tls.NamedGroup.x25519,
        ));
        out.int(u16, 32);
        out.push(&self.x25519.public_key);
        out.wrapLen(share, 2);
        out.wrapLen(extensions, 2);
        out.wrapLen(body, 3);

        const message = out.data[at..out.len];

        // The key schedule, from the same shared secret the client
        // computes.
        if (client_share.len != 32) return error.BadKeyShare;
        const shared = try crypto.dh.X25519.scalarmult(
            self.x25519.secret_key,
            client_share[0..32].*,
        );
        self.transcript = .init(self.suite.hash());
        self.transcript.update(hello);
        self.transcript.update(message);
        const stage = schedule.handshakeSecrets(self.suite, &shared, self.transcript.peek().slice());
        self.traffic = stage.traffic;
        self.master = stage.master;
        return message;
    }

    /// Writes EncryptedExtensions, Certificate, CertificateVerify and
    /// Finished, which is the whole of the server's Handshake level
    /// flight.
    fn flight(self: *Server, out: *Buf(4096)) ![]const u8 {
        const at = out.mark();
        try self.encryptedExtensions(out);
        if (self.fault.message_too_long) {
            // A Certificate message that names sixteen megabytes of body,
            // which no buffer at this level can ever hold.
            out.byte(@intFromEnum(tls.HandshakeType.certificate));
            out.push(&.{ 0xff, 0xff, 0xff });
            return out.data[at..out.len];
        }
        if (self.fault.certificate_request) try self.certificateRequest(out);
        try self.certificateMessage(out);
        try self.certificateVerify(out);
        if (self.fault.tls_key_update) {
            out.byte(@intFromEnum(tls.HandshakeType.key_update));
            out.push(&.{ 0, 0, 1, 0 });
            return out.data[at..out.len];
        }
        try self.finished(out);
        return out.data[at..out.len];
    }

    fn encryptedExtensions(self: *Server, out: *Buf(4096)) !void {
        const at = out.mark();
        out.byte(@intFromEnum(tls.HandshakeType.encrypted_extensions));
        const body = out.mark();
        const extensions = out.mark();

        if (!self.fault.no_alpn) {
            const name: []const u8 = if (self.fault.alpn_not_offered) "h2" else "h3";
            writeAlpn(out, name);
            if (self.fault.duplicate_alpn) writeAlpn(out, name);
        }

        if (!self.fault.no_transport_parameters) {
            out.int(u16, @intFromEnum(tls.ExtensionType.quic_transport_parameters));
            const parameters = out.mark();
            var w: std.Io.Writer = .fixed(out.data[out.len..]);
            var stated: transport_parameters.Parameters = .{
                .initial_max_data = 1 << 20,
                .initial_max_stream_data_uni = 1 << 16,
                .initial_max_streams_uni = 3,
                .original_destination_connection_id = if (self.fault.wrong_original_connection_id)
                    try .init(&[_]u8{0xff} ** 8)
                else
                    self.original_connection_id,
                .initial_source_connection_id = if (self.fault.no_initial_source_connection_id)
                    null
                else
                    self.connection_id,
            };
            if (self.fault.unexpected_retry_connection_id) {
                stated.retry_source_connection_id = try .init(&[_]u8{0xab} ** 4);
            }
            try transport_parameters.encode(stated, &w);
            out.len += w.end;
            out.wrapLen(parameters, 2);
        }

        if (self.fault.unoffered_extension) {
            // `early_data`, which this hello never asks for. RFC 8446
            // section 4.2 makes an answer to a question nobody asked
            // `unsupported_extension`.
            out.int(u16, 0x002a);
            out.int(u16, 0);
        }

        out.wrapLen(extensions, 2);
        out.wrapLen(body, 3);
        self.transcript.update(out.data[at..out.len]);
    }

    /// Asks for a client certificate. RFC 8446 section 4.3.2.
    fn certificateRequest(self: *Server, out: *Buf(4096)) !void {
        const at = out.mark();
        out.byte(@intFromEnum(tls.HandshakeType.certificate_request));
        const body = out.mark();
        out.byte(0); // certificate_request_context of no bytes
        const extensions = out.mark();
        out.int(u16, @intFromEnum(tls.ExtensionType.signature_algorithms));
        const ext = out.mark();
        const list = out.mark();
        out.int(u16, @intFromEnum(tls.SignatureScheme.ecdsa_secp256r1_sha256));
        out.wrapLen(list, 2);
        out.wrapLen(ext, 2);
        out.wrapLen(extensions, 2);
        out.wrapLen(body, 3);
        self.transcript.update(out.data[at..out.len]);
    }

    fn writeAlpn(out: *Buf(4096), name: []const u8) void {
        out.int(u16, @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation));
        const ext = out.mark();
        const list = out.mark();
        out.byte(@intCast(name.len));
        out.push(name);
        out.wrapLen(list, 2);
        out.wrapLen(ext, 2);
    }

    fn certificateMessage(self: *Server, out: *Buf(4096)) !void {
        const at = out.mark();
        out.byte(@intFromEnum(tls.HandshakeType.certificate));
        const body = out.mark();
        out.byte(0); // certificate_request_context
        const list = out.mark();
        if (!self.fault.empty_certificate_list) {
            const entry = out.mark();
            out.push(self.certificate.slice());
            out.wrapLen(entry, 3);
            out.int(u16, 0); // per certificate extensions
            if (self.fault.tampered_certificate) {
                // One byte of the public key inside the TBSCertificate,
                // so the certificate still parses and its own signature
                // no longer checks. The name and the dates are left
                // alone, so this is a signature fault and nothing else.
                const point = self.signer.public_key.toUncompressedSec1();
                const written = out.data[entry + 3 .. out.len];
                const found = std.mem.indexOf(u8, written, &point) orelse
                    return error.PublicKeyNotInCertificate;
                written[found + 10] ^= 0x01;
            }
        }
        out.wrapLen(list, 3);
        out.wrapLen(body, 3);
        self.transcript.update(out.data[at..out.len]);
    }

    fn certificateVerify(self: *Server, out: *Buf(4096)) !void {
        const hash = self.transcript.peek();
        var content: Buf(256) = .{};
        content.push(" " ** 64);
        content.push("TLS 1.3, server CertificateVerify");
        content.byte(0);
        content.push(hash.slice());

        const signature = try self.signer.sign(content.slice(), null);
        var der_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
        const der_sig = signature.toDer(&der_buf);

        const at = out.mark();
        out.byte(@intFromEnum(tls.HandshakeType.certificate_verify));
        const body = out.mark();
        out.int(u16, @intFromEnum(tls.SignatureScheme.ecdsa_secp256r1_sha256));
        const sig = out.mark();
        out.push(der_sig);
        if (self.fault.bad_signature) out.data[sig + 2 + 10] ^= 0x01;
        out.wrapLen(sig, 2);
        out.wrapLen(body, 3);
        self.transcript.update(out.data[at..out.len]);
    }

    fn finished(self: *Server, out: *Buf(4096)) !void {
        const key = schedule.finishedKey(self.suite, &self.traffic.server);
        const data = schedule.verifyData(self.suite, &key, self.transcript.peek().slice());

        const at = out.mark();
        out.byte(@intFromEnum(tls.HandshakeType.finished));
        const body = out.mark();
        out.push(data.slice());
        if (self.fault.bad_finished) out.data[body + 3] ^= 0x01;
        out.wrapLen(body, 3);
        self.transcript.update(out.data[at..out.len]);
    }

    /// What the server expects the client's Finished message to hold.
    ///
    /// A server that asked for a client certificate gets an empty
    /// Certificate message first, RFC 8446 section 4.4.2, and that message
    /// is part of the transcript the client's Finished covers.
    fn expectedClientFinished(self: *Server) schedule.Secret {
        if (self.fault.certificate_request) {
            self.transcript.update(&Handshake.empty_certificate);
        }
        const key = schedule.finishedKey(self.suite, &self.traffic.client);
        return schedule.verifyData(self.suite, &key, self.transcript.peek().slice());
    }
};

/// Finds the x25519 share inside a ClientHello.
fn findKeyShare(hello: []const u8) ?[]const u8 {
    const extensions = extensionsOf(hello) orelse return null;
    var at: usize = 0;
    while (at + 4 <= extensions.len) {
        const kind = std.mem.readInt(u16, extensions[at..][0..2], .big);
        const len = std.mem.readInt(u16, extensions[at + 2 ..][0..2], .big);
        const body = extensions[at + 4 ..][0..len];
        at += 4 + len;
        if (kind != @intFromEnum(tls.ExtensionType.key_share)) continue;
        const list_len = std.mem.readInt(u16, body[0..2], .big);
        var share_at: usize = 2;
        while (share_at + 4 <= 2 + list_len) {
            const group = std.mem.readInt(u16, body[share_at..][0..2], .big);
            const key_len = std.mem.readInt(u16, body[share_at + 2 ..][0..2], .big);
            const key = body[share_at + 4 ..][0..key_len];
            if (group == @intFromEnum(tls.NamedGroup.x25519)) return key;
            share_at += 4 + key_len;
        }
    }
    return null;
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

/// Whether a ClientHello carries one extension.
fn hasExtension(hello: []const u8, kind: tls.ExtensionType) bool {
    const extensions = extensionsOf(hello) orelse return false;
    var at: usize = 0;
    while (at + 4 <= extensions.len) {
        const found = std.mem.readInt(u16, extensions[at..][0..2], .big);
        const len = std.mem.readInt(u16, extensions[at + 2 ..][0..2], .big);
        if (found == @intFromEnum(kind)) return true;
        at += 4 + len;
    }
    return false;
}

/// The payload of one extension of a ClientHello.
fn extensionBody(hello: []const u8, kind: tls.ExtensionType) ?[]const u8 {
    const extensions = extensionsOf(hello) orelse return null;
    var at: usize = 0;
    while (at + 4 <= extensions.len) {
        const found = std.mem.readInt(u16, extensions[at..][0..2], .big);
        const len = std.mem.readInt(u16, extensions[at + 2 ..][0..2], .big);
        if (found == @intFromEnum(kind)) return extensions[at + 4 ..][0..len];
        at += 4 + len;
    }
    return null;
}

// ---------------------------------------------------------------------
// The client side of a run
// ---------------------------------------------------------------------

/// Everything one run needs to keep alive while the handshake reads it.
const Run = struct {
    initial_buffer: [Handshake.min_initial_buffer]u8 = undefined,
    handshake_buffer: [Handshake.min_handshake_buffer]u8 = undefined,
    application_buffer: [Handshake.min_application_buffer]u8 = undefined,
    entropy: [Handshake.entropy_len]u8 = undefined,
    original: packet.ConnectionId = undefined,
    server_id: packet.ConnectionId = undefined,

    fn options(self: *Run, host: @FieldType(Client.Options, "host"), ca: @FieldType(Client.Options, "ca")) Handshake.Options {
        for (&self.entropy, 0..) |*byte, index| byte.* = @truncate(index * 7 + 3);
        self.original = packet.ConnectionId.init(&[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 }) catch unreachable;
        self.server_id = packet.ConnectionId.init(&[_]u8{ 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5 }) catch unreachable;
        return .{
            .host = host,
            .ca = ca,
            .alpn_protocols = alpn_h3,
            .parameters = .{
                .initial_max_data = 1 << 20,
                .initial_max_streams_uni = 3,
                .initial_source_connection_id = self.original,
            },
            .entropy = &self.entropy,
            .realtime_now = now,
            .original_destination_connection_id = self.original,
            .initial_buffer = &self.initial_buffer,
            .handshake_buffer = &self.handshake_buffer,
            .application_buffer = &self.application_buffer,
        };
    }
};

/// Runs one whole handshake against a server with `fault` set, and gives
/// back whatever the client reported.
fn runHandshake(fault: Fault, run: *Run, out: *Handshake) !void {
    return runHandshakeAs(fault, .no_verification, .self_signed, run, out);
}

/// The same run, with the host check and the trust check the caller names.
fn runHandshakeAs(
    fault: Fault,
    host: @FieldType(Client.Options, "host"),
    ca: @FieldType(Client.Options, "ca"),
    run: *Run,
    out: *Handshake,
) !void {
    var hs: Handshake = try .init(run.options(host, ca));
    errdefer hs.deinit();

    var server: Server = try .init(run.server_id, run.original);
    server.fault = fault;

    const hello = hs.pendingCrypto(.initial);
    var hello_copy: Buf(2048) = .{};
    hello_copy.push(hello);
    hs.markCryptoSent(.initial, hello.len);

    var hello_out: Buf(1024) = .{};
    const server_hello = try server.serverHello(hello_copy.slice(), &hello_out);

    hs.setServerConnectionId(run.server_id);
    try hs.provideCrypto(.initial, 0, server_hello);

    var flight_out: Buf(4096) = .{};
    const flight = try server.flight(&flight_out);
    try hs.provideCrypto(.handshake, 0, flight);

    // The client's Finished must be the one the server expects. A server
    // that asked for a client certificate gets an empty one in front of
    // it.
    const finished = hs.pendingCrypto(.handshake);
    const want = server.expectedClientFinished();
    const at: usize = if (fault.certificate_request) Handshake.empty_certificate.len else 0;
    if (at != 0) try testing.expectEqualSlices(u8, &Handshake.empty_certificate, finished[0..at]);
    try testing.expectEqual(at + 4 + want.len, finished.len);
    try testing.expectEqualSlices(u8, want.slice(), finished[at + 4 ..]);

    out.* = hs;
}

// ---------------------------------------------------------------------
// The ClientHello
// ---------------------------------------------------------------------

test "the client hello carries every extension QUIC needs, and nothing that needs a record layer" {
    var run: Run = .{};
    var hs: Handshake = try .init(run.options(.{ .explicit = "example.test" }, .no_verification));
    defer hs.deinit();

    const hello = hs.pendingCrypto(.initial);
    try testing.expect(extensionsOf(hello) != null);
    try testing.expectEqual(@as(u64, 0), hs.sentCrypto(.initial));

    try testing.expect(hasExtension(hello, .server_name));
    try testing.expect(hasExtension(hello, .supported_groups));
    try testing.expect(hasExtension(hello, .signature_algorithms));
    try testing.expect(hasExtension(hello, .application_layer_protocol_negotiation));
    try testing.expect(hasExtension(hello, .supported_versions));
    try testing.expect(hasExtension(hello, .key_share));
    try testing.expect(hasExtension(hello, .quic_transport_parameters));

    // **No session ticket and no PSK.** RFC 9001 section 4.6 leaves 0-RTT
    // out of this build, and nothing here resumes a session.
    try testing.expect(!hasExtension(hello, .pre_shared_key));
    try testing.expect(!hasExtension(hello, .early_data));

    // **An empty legacy_session_id.** RFC 9001 section 8.4 bars the TLS
    // 1.3 compatibility mode, whose only purpose is that field.
    try testing.expectEqual(@as(u8, 0), hello[4 + 2 + 32]);

    // The whole hello fits the 1200 byte bound RFC 9000 section 14.1 puts
    // on the client's first datagram, with room for the packet header and
    // the CRYPTO frame header.
    try testing.expect(hello.len < 1000);
}

test "the client hello offers TLS 1.3 alone and the three QUIC suites" {
    var run: Run = .{};
    var hs: Handshake = try .init(run.options(.no_verification, .no_verification));
    defer hs.deinit();
    const hello = hs.pendingCrypto(.initial);

    const versions = extensionBody(hello, .supported_versions).?;
    // One length byte and one version.
    try testing.expectEqual(@as(usize, 3), versions.len);
    try testing.expectEqual(@as(u8, 2), versions[0]);
    try testing.expectEqual(
        @as(u16, @intFromEnum(tls.ProtocolVersion.tls_1_3)),
        std.mem.readInt(u16, versions[1..3], .big),
    );

    // The suite list holds the three suites RFC 9001 section 5.4 gives
    // header protection, and no other.
    const at = 4 + 2 + 32 + 1;
    const suites_len = std.mem.readInt(u16, hello[at..][0..2], .big);
    try testing.expectEqual(@as(usize, 3 * 2), suites_len);
    var index: usize = 0;
    while (index < 3) : (index += 1) {
        const code: tls.CipherSuite = @enumFromInt(
            std.mem.readInt(u16, hello[at + 2 + index * 2 ..][0..2], .big),
        );
        try testing.expect(schedule.suiteOf(code) != null);
    }
}

test "the client hello names the host, and never names an address" {
    var run: Run = .{};
    {
        var hs: Handshake = try .init(run.options(.{ .explicit = "cloudflare.com" }, .no_verification));
        defer hs.deinit();
        const body = extensionBody(hs.pendingCrypto(.initial), .server_name).?;
        try testing.expectEqualStrings("cloudflare.com", body[5..]);
    }
    {
        // RFC 6066 section 3 bars a literal address from a server name,
        // and `verifyHost` reads the same host as an address to pick the
        // kind of name the certificate must carry.
        var hs: Handshake = try .init(run.options(.{ .explicit = "1.1.1.1" }, .no_verification));
        defer hs.deinit();
        try testing.expect(!hasExtension(hs.pendingCrypto(.initial), .server_name));
    }
    {
        var hs: Handshake = try .init(run.options(.{ .explicit = "::1" }, .no_verification));
        defer hs.deinit();
        try testing.expect(!hasExtension(hs.pendingCrypto(.initial), .server_name));
    }
    {
        var hs: Handshake = try .init(run.options(.no_verification, .no_verification));
        defer hs.deinit();
        try testing.expect(!hasExtension(hs.pendingCrypto(.initial), .server_name));
    }
}

test "the transport parameters go out in the extension and read back the same" {
    var run: Run = .{};
    var hs: Handshake = try .init(run.options(.no_verification, .no_verification));
    defer hs.deinit();

    const body = extensionBody(hs.pendingCrypto(.initial), .quic_transport_parameters).?;
    const read = try transport_parameters.decode(body);
    try testing.expectEqual(@as(u64, 1 << 20), read.initial_max_data);
    try testing.expectEqual(@as(u64, 3), read.initial_max_streams_uni);
    try testing.expect(read.initial_source_connection_id != null);
    try testing.expectEqualSlices(
        u8,
        run.original.slice(),
        read.initial_source_connection_id.?.slice(),
    );
}

test "an empty ALPN offer is refused, because QUIC has no answer of none" {
    var run: Run = .{};
    var options = run.options(.no_verification, .no_verification);
    options.alpn_protocols = &.{};
    // RFC 9001 section 8.1 makes ALPN mandatory on a QUIC connection, so
    // an offer of nothing has no legal answer and the hello is not
    // written.
    try testing.expectError(error.TlsAlpnOfferInvalid, Handshake.init(options));
}

test "a buffer below its minimum is refused before a byte is written" {
    var run: Run = .{};
    var small: [16]u8 = undefined;
    {
        var options = run.options(.no_verification, .no_verification);
        options.initial_buffer = &small;
        try testing.expectError(error.HandshakeBufferTooSmall, Handshake.init(options));
    }
    {
        var options = run.options(.no_verification, .no_verification);
        options.handshake_buffer = &small;
        try testing.expectError(error.HandshakeBufferTooSmall, Handshake.init(options));
    }
    {
        var options = run.options(.no_verification, .no_verification);
        options.application_buffer = &small;
        try testing.expectError(error.HandshakeBufferTooSmall, Handshake.init(options));
    }
}

// ---------------------------------------------------------------------
// A whole handshake
// ---------------------------------------------------------------------

test "a whole handshake completes and installs a key set at every level" {
    var run: Run = .{};
    var hs: Handshake = undefined;
    try runHandshake(.{}, &run, &hs);
    defer hs.deinit();

    try testing.expect(hs.isComplete());
    try testing.expectEqualStrings("h3", hs.alpnProtocol().?);
    try testing.expectEqual(protection.Suite.aes_128_gcm, hs.negotiatedSuite().?);

    // The Initial keys were there from the start, and the two levels the
    // handshake produced are there now.
    try testing.expect(hs.session.writeKeys(.initial) != null);
    try testing.expect(hs.session.writeKeys(.handshake) != null);
    try testing.expect(hs.session.readKeys(.handshake) != null);
    try testing.expect(hs.session.writeKeys(.application) != null);
    try testing.expect(hs.session.readKeys(.application) != null);

    // No two of the six key sets share a packet protection key.
    const all = [_]protection.Keys{
        hs.session.writeKeys(.initial).?,
        hs.session.readKeys(.initial).?,
        hs.session.writeKeys(.handshake).?,
        hs.session.readKeys(.handshake).?,
        hs.session.writeKeys(.application).?,
        hs.session.readKeys(.application).?,
    };
    for (all, 0..) |one, index| {
        for (all[index + 1 ..]) |other| {
            try testing.expect(!std.mem.eql(u8, one.keySlice(), other.keySlice()));
        }
    }
}

test "the server transport parameters arrive, bounded and checked" {
    var run: Run = .{};
    var hs: Handshake = undefined;
    try runHandshake(.{}, &run, &hs);
    defer hs.deinit();

    const stated = hs.peerParameters().?;
    try testing.expectEqual(@as(u64, 1 << 20), stated.initial_max_data);
    try testing.expectEqual(@as(u64, 3), stated.initial_max_streams_uni);
    // The two connection ids the client checked. RFC 9000 section 7.3.
    try testing.expectEqualSlices(
        u8,
        run.original.slice(),
        stated.original_destination_connection_id.?.slice(),
    );
    try testing.expectEqualSlices(
        u8,
        run.server_id.slice(),
        stated.initial_source_connection_id.?.slice(),
    );
    // A parameter the server left out keeps the default RFC 9000 section
    // 18.2 gives it.
    try testing.expectEqual(
        transport_parameters.default_max_udp_payload_size,
        stated.max_udp_payload_size,
    );
    try testing.expectEqual(
        transport_parameters.default_active_connection_id_limit,
        stated.active_connection_id_limit,
    );
}

test "the keys of the two sides open each other's packets" {
    // The point of the whole handshake: the client's write keys and the
    // server's read keys are the same key set, at every level.
    var run: Run = .{};
    var hs: Handshake = undefined;
    try runHandshake(.{}, &run, &hs);
    defer hs.deinit();

    var server: Server = try .init(run.server_id, run.original);
    // Rebuild the server's own view by running the same messages again.
    var second: Handshake = try .init(run.options(.no_verification, .self_signed));
    defer second.deinit();
    var hello_copy: Buf(2048) = .{};
    hello_copy.push(second.pendingCrypto(.initial));
    var hello_out: Buf(1024) = .{};
    _ = try server.serverHello(hello_copy.slice(), &hello_out);

    // The server's handshake traffic secrets give the same key sets the
    // client installed, one for each direction.
    const client_write = second.session.writeKeys(.initial).?;
    _ = client_write;
    second.setServerConnectionId(run.server_id);
    try second.provideCrypto(.initial, 0, hello_out.slice());

    const server_write = schedule.keys(server.suite, &server.traffic.server);
    const server_read = schedule.keys(server.suite, &server.traffic.client);
    try testing.expectEqualSlices(
        u8,
        server_write.keySlice(),
        second.session.readKeys(.handshake).?.keySlice(),
    );
    try testing.expectEqualSlices(
        u8,
        server_read.keySlice(),
        second.session.writeKeys(.handshake).?.keySlice(),
    );

    // And a packet the server seals really opens under the client's key.
    const plaintext = "a QUIC payload";
    var sealed: [plaintext.len + protection.tag_len]u8 = undefined;
    const aad = [_]u8{ 0xe0, 0x00, 0x00, 0x00, 0x01 };
    server_write.seal(&sealed, plaintext, &aad, 7);
    var opened: [plaintext.len]u8 = undefined;
    const written = try second.session.readKeys(.handshake).?.open(&opened, &sealed, &aad, 7);
    try testing.expectEqualStrings(plaintext, opened[0..written]);
}

test "CRYPTO frames that arrive out of order still complete the handshake" {
    var run: Run = .{};
    var hs: Handshake = try .init(run.options(.no_verification, .self_signed));
    defer hs.deinit();

    var server: Server = try .init(run.server_id, run.original);
    var hello_copy: Buf(2048) = .{};
    hello_copy.push(hs.pendingCrypto(.initial));

    var hello_out: Buf(1024) = .{};
    const server_hello = try server.serverHello(hello_copy.slice(), &hello_out);
    hs.setServerConnectionId(run.server_id);

    // The ServerHello in three pieces, last one first.
    const third = server_hello.len / 3;
    try hs.provideCrypto(.initial, third * 2, server_hello[third * 2 ..]);
    try testing.expect(!hs.isComplete());
    try hs.provideCrypto(.initial, third, server_hello[third .. third * 2]);
    try hs.provideCrypto(.initial, 0, server_hello[0..third]);
    try testing.expect(hs.negotiatedSuite() != null);

    var flight_out: Buf(4096) = .{};
    const flight = try server.flight(&flight_out);

    // The flight in five pieces, in a shuffled order, with one piece
    // delivered twice.
    const step = flight.len / 5;
    const order = [_]usize{ 3, 0, 4, 1, 3, 2 };
    for (order) |piece| {
        const start = piece * step;
        const end = if (piece == 4) flight.len else start + step;
        try hs.provideCrypto(.handshake, start, flight[start..end]);
    }
    try testing.expect(hs.isComplete());
    try testing.expectEqualStrings("h3", hs.alpnProtocol().?);
}

test "a retransmitted CRYPTO frame that changed its bytes is refused" {
    var run: Run = .{};
    var hs: Handshake = try .init(run.options(.no_verification, .self_signed));
    defer hs.deinit();

    var server: Server = try .init(run.server_id, run.original);
    var hello_copy: Buf(2048) = .{};
    hello_copy.push(hs.pendingCrypto(.initial));
    var hello_out: Buf(1024) = .{};
    const server_hello = try server.serverHello(hello_copy.slice(), &hello_out);
    hs.setServerConnectionId(run.server_id);

    try hs.provideCrypto(.initial, 20, server_hello[20..]);
    // The same offset with other bytes. RFC 9000 section 19.6 makes that
    // a protocol violation, and it is what a rewrite of a message already
    // seen would look like.
    var changed: [8]u8 = undefined;
    @memcpy(&changed, server_hello[20..28]);
    changed[0] ^= 0xff;
    try testing.expectError(error.CryptoStreamMismatch, hs.provideCrypto(.initial, 20, &changed));
}

// ---------------------------------------------------------------------
// Every way the peer can be wrong
// ---------------------------------------------------------------------

/// Runs a handshake with `fault` set and gives back the error the client
/// reported. A run that completes is itself a failure.
fn faultReport(fault: Fault) anyerror {
    var run: Run = .{};
    var hs: Handshake = undefined;
    runHandshake(fault, &run, &hs) catch |err| return err;
    hs.deinit();
    return error.TestExpectedFailure;
}

test "a server that answers no ALPN is refused, because QUIC requires one" {
    // RFC 9001 section 8.1. A TLS server may leave the extension out and
    // the session runs on whatever the caller speaks. A QUIC server may
    // not.
    try testing.expectEqual(error.TlsAlpnMissing, faultReport(.{ .no_alpn = true }));
}

test "a server that answers a protocol the hello never offered is refused" {
    // RFC 7301 section 3.2. The check is the vendored TLS client's own
    // `readAlpn`, so both transports refuse the same answer.
    try testing.expectEqual(
        error.TlsAlpnProtocolNotOffered,
        faultReport(.{ .alpn_not_offered = true }),
    );
}

test "a repeated extension in EncryptedExtensions is refused" {
    // RFC 8446 section 4.2 gives each identifier one appearance, and a
    // second copy is where a second value would hide.
    try testing.expectEqual(error.TlsIllegalParameter, faultReport(.{ .duplicate_alpn = true }));
}

test "a server that sends no transport parameters is refused" {
    // RFC 9001 section 8.2 has the client close with MISSING_EXTENSION.
    try testing.expectEqual(
        error.TlsTransportParametersMissing,
        faultReport(.{ .no_transport_parameters = true }),
    );
}

test "every connection id rule of RFC 9000 section 7.3 is enforced" {
    // The long header travels in the clear, so a path attacker can
    // rewrite a connection id. These three checks tie the ids the packets
    // carried to ids the server signed for.
    try testing.expectEqual(
        error.TlsConnectionIdMismatch,
        faultReport(.{ .wrong_original_connection_id = true }),
    );
    try testing.expectEqual(
        error.TlsConnectionIdMismatch,
        faultReport(.{ .no_initial_source_connection_id = true }),
    );
    // A `retry_source_connection_id` with no Retry behind it is refused,
    // because the parameter must be absent when no Retry happened.
    try testing.expectEqual(
        error.TlsConnectionIdMismatch,
        faultReport(.{ .unexpected_retry_connection_id = true }),
    );
}

test "a handshake that never learned the server connection id refuses to finish" {
    var run: Run = .{};
    var hs: Handshake = try .init(run.options(.no_verification, .self_signed));
    defer hs.deinit();

    var server: Server = try .init(run.server_id, run.original);
    var hello_copy: Buf(2048) = .{};
    hello_copy.push(hs.pendingCrypto(.initial));
    var hello_out: Buf(1024) = .{};
    const server_hello = try server.serverHello(hello_copy.slice(), &hello_out);

    // `setServerConnectionId` is not called, so the client has nothing to
    // check `initial_source_connection_id` against. An unchecked id must
    // never pass.
    try hs.provideCrypto(.initial, 0, server_hello);
    var flight_out: Buf(4096) = .{};
    const flight = try server.flight(&flight_out);
    try testing.expectError(
        error.TlsConnectionIdMismatch,
        hs.provideCrypto(.handshake, 0, flight),
    );
}

test "a cipher suite the hello never offered is refused" {
    try testing.expectEqual(error.TlsBadCipherSuite, faultReport(.{ .unoffered_suite = true }));
}

test "a version other than TLS 1.3 is refused" {
    // RFC 9001 section 4.2 gives QUIC one version.
    try testing.expectEqual(error.TlsBadVersion, faultReport(.{ .wrong_version = true }));
}

test "a HelloRetryRequest is reported by name" {
    // This build offers one x25519 share, which every server that speaks
    // HTTP/3 accepts. A retry means the server wants a group the offer
    // did not carry, and it is said so rather than answered wrongly.
    try testing.expectEqual(error.TlsHelloRetryRequest, faultReport(.{ .hello_retry = true }));
}

test "a session id echo is refused, because the hello sent none" {
    // RFC 9001 section 8.4 bars the TLS 1.3 compatibility mode.
    try testing.expectEqual(error.TlsIllegalParameter, faultReport(.{ .echo_session_id = true }));
}

test "a Finished message that does not check stops the handshake" {
    // The one message that proves the server holds the handshake secret.
    try testing.expectEqual(error.TlsDecryptError, faultReport(.{ .bad_finished = true }));
}

test "a CertificateVerify signature that does not check stops the handshake" {
    try testing.expectEqual(
        error.SignatureVerificationFailed,
        faultReport(.{ .bad_signature = true }),
    );
}

test "an empty certificate list reaches no trust root" {
    try testing.expectEqual(
        error.TlsCertificateNotVerified,
        faultReport(.{ .empty_certificate_list = true }),
    );
}

test "a tampered certificate fails the trust check that the vendored client runs" {
    // `.self_signed` checks the certificate's own signature, and that
    // check is `Certificate.Parsed.verify` through
    // `zurl_tls.Client.quic.verifyCertificate`. Nothing in this package
    // decides it.
    try testing.expectEqual(
        error.CertificateSignatureInvalid,
        faultReport(.{ .tampered_certificate = true }),
    );
}

test "a TLS KeyUpdate message is refused, because QUIC has its own" {
    // RFC 9001 section 6: QUIC updates keys with the Key Phase bit, and a
    // TLS KeyUpdate is a connection error of type PROTOCOL_VIOLATION.
    try testing.expectEqual(error.TlsUnexpectedMessage, faultReport(.{ .tls_key_update = true }));
}

test "a message at the wrong encryption level is refused" {
    var run: Run = .{};
    var hs: Handshake = try .init(run.options(.no_verification, .self_signed));
    defer hs.deinit();

    var server: Server = try .init(run.server_id, run.original);
    var hello_copy: Buf(2048) = .{};
    hello_copy.push(hs.pendingCrypto(.initial));
    var hello_out: Buf(1024) = .{};
    const server_hello = try server.serverHello(hello_copy.slice(), &hello_out);
    hs.setServerConnectionId(run.server_id);

    // RFC 9001 section 4.1.3 puts the ServerHello at the Initial level
    // and nowhere else.
    try testing.expectError(
        error.TlsWrongEncryptionLevel,
        hs.provideCrypto(.handshake, 0, server_hello),
    );
}

test "a CRYPTO frame at the 0-RTT level is refused, because RFC 9001 has none there" {
    var run: Run = .{};
    var hs: Handshake = try .init(run.options(.no_verification, .no_verification));
    defer hs.deinit();
    try testing.expectError(
        error.TlsWrongEncryptionLevel,
        hs.provideCrypto(.zero_rtt, 0, "anything"),
    );
}

test "a server flight that arrives before the ServerHello is refused" {
    var run: Run = .{};
    var hs: Handshake = try .init(run.options(.no_verification, .self_signed));
    defer hs.deinit();

    var server: Server = try .init(run.server_id, run.original);
    var hello_copy: Buf(2048) = .{};
    hello_copy.push(hs.pendingCrypto(.initial));
    var hello_out: Buf(1024) = .{};
    _ = try server.serverHello(hello_copy.slice(), &hello_out);

    var flight_out: Buf(4096) = .{};
    const flight = try server.flight(&flight_out);
    // The state machine expects the ServerHello first, so
    // EncryptedExtensions here is out of order.
    try testing.expectError(
        error.TlsUnexpectedMessage,
        hs.provideCrypto(.handshake, 0, flight),
    );
}

// ---------------------------------------------------------------------
// After the handshake
// ---------------------------------------------------------------------

test "HANDSHAKE_DONE confirms the handshake and lets a key update run" {
    var run: Run = .{};
    var hs: Handshake = undefined;
    try runHandshake(.{}, &run, &hs);
    defer hs.deinit();

    // RFC 9001 section 6 bars a key update until the handshake is
    // confirmed, and for a client that is the HANDSHAKE_DONE frame.
    try testing.expectError(error.KeyUpdateNotAllowed, hs.session.update());

    // The frame the connection engine reads out of a 1-RTT packet. RFC
    // 9000 section 19.20 gives it type 0x1e and no payload at all.
    const one_byte = [_]u8{0x1e};
    var frames: quic.frame.Decoder = .init(&one_byte);
    try testing.expectEqual(quic.frame.Frame.handshake_done, (try frames.next()).?);
    try testing.expectEqual(@as(?quic.frame.Frame, null), try frames.next());
    hs.session.handshakeDone();

    try testing.expect(hs.session.handshake_confirmed);
    // Confirming the handshake drops the Handshake keys. RFC 9001 section
    // 4.9.2.
    try testing.expect(hs.session.writeKeys(.handshake) == null);

    const before = hs.session.writeKeys(.application).?;
    try hs.session.update();
    const after = hs.session.writeKeys(.application).?;
    try testing.expect(!std.mem.eql(u8, before.keySlice(), after.keySlice()));
    try testing.expectEqualSlices(u8, before.headerKeySlice(), after.headerKeySlice());
    try testing.expectEqual(@as(u1, 1), hs.session.keyPhase().?);
}

test "one packet number per level, and never the same one twice under one key" {
    var run: Run = .{};
    var hs: Handshake = undefined;
    try runHandshake(.{}, &run, &hs);
    defer hs.deinit();
    hs.session.handshakeDone();

    // Every number the application space issues is new, and each one goes
    // with a nonce nothing else uses.
    var seen: [64]u64 = undefined;
    const keys = hs.session.writeKeys(.application).?;
    var nonces: [64][12]u8 = undefined;
    for (&seen, 0..) |*slot, index| {
        slot.* = try hs.session.nextPacketNumber(.application);
        nonces[index] = keys.nonce(slot.*);
    }
    for (seen, 0..) |one, index| {
        for (seen[index + 1 ..]) |other| try testing.expect(one != other);
        for (nonces[index + 1 ..]) |other| {
            try testing.expect(!std.mem.eql(u8, &nonces[index], &other));
        }
    }
}

test "a session ticket after the handshake is read and dropped" {
    var run: Run = .{};
    var hs: Handshake = undefined;
    try runHandshake(.{}, &run, &hs);
    defer hs.deinit();

    // RFC 8446 section 4.6.1. Nothing here resumes a session, so the
    // ticket is stepped over rather than refused.
    var ticket: Buf(64) = .{};
    ticket.byte(@intFromEnum(tls.HandshakeType.new_session_ticket));
    const body = ticket.mark();
    ticket.int(u32, 7200); // ticket_lifetime
    ticket.int(u32, 0); // ticket_age_add
    ticket.byte(0); // ticket_nonce
    ticket.int(u16, 4); // ticket
    ticket.push("abcd");
    ticket.int(u16, 0); // extensions
    ticket.wrapLen(body, 3);

    try hs.provideCrypto(.application, 0, ticket.slice());
    try testing.expect(hs.isComplete());

    // And a ticket that arrives at the Handshake level is not a ticket.
    try testing.expectError(
        error.TlsWrongEncryptionLevel,
        hs.provideCrypto(.handshake, hs.handshake_in.base, ticket.slice()),
    );
}

test "the certificate check runs on the host the caller named" {
    // The certificate the server builds names `zurl.test` in its common
    // name and carries no subject alternative name, so RFC 6125 section
    // 6.4.4 falls back to the common name. That rule is the vendored TLS
    // client's `walkSubjectAltNames`, and this package has no host check
    // of its own to get it wrong.
    {
        var run: Run = .{};
        var hs: Handshake = undefined;
        try runHandshakeAs(.{}, .{ .explicit = "zurl.test" }, .self_signed, &run, &hs);
        defer hs.deinit();
        try testing.expect(hs.isComplete());
    }

    // Another host is refused, and the name of the refusal comes from
    // that same walk.
    {
        var run: Run = .{};
        var hs: Handshake = undefined;
        try testing.expectError(
            error.CertificateHostMismatch,
            runHandshakeAs(.{}, .{ .explicit = "other.test" }, .self_signed, &run, &hs),
        );
    }

    // An address needs an `iPAddress` name, and this certificate carries
    // none. RFC 6125 section 6.4 bars reading a common name as an
    // address, which is the gap the vendored client closed.
    {
        var run: Run = .{};
        var hs: Handshake = undefined;
        try testing.expectError(
            error.CertificateHostMismatch,
            runHandshakeAs(.{}, .{ .explicit = "10.0.0.1" }, .self_signed, &run, &hs),
        );
    }
}

// ---------------------------------------------------------------------
// Retry
// ---------------------------------------------------------------------

test "a Retry moves the Initial keys and adds one connection id to check" {
    // RFC 9001 section 5.2: a client that gets a Retry derives the
    // Initial keys again, from the Retry's Source Connection ID, because
    // that is the Destination Connection ID of every Initial packet after
    // it.
    var run: Run = .{};

    var before: Handshake = try .init(run.options(.no_verification, .no_verification));
    defer before.deinit();

    // Some packets went out under the first Initial keys, so the second
    // attempt must not start their numbers again.
    _ = try before.session.nextPacketNumber(.initial);
    _ = try before.session.nextPacketNumber(.initial);
    const carried = before.packetNumbers();
    try testing.expectEqual(@as(u64, 2), carried[0]);

    // The Retry of RFC 9001 appendix A.4, whose Source Connection ID is
    // the one the client sends to from here on. The tag is the packet's
    // own, so `VerifiedRetry.verify` accepts it.
    const retry = a4_retry;
    const retry_id = try packet.ConnectionId.init(retry[7..15]);
    const verified = try Handshake.VerifiedRetry.verify(run.original.slice(), &retry, retry_id);

    var options = run.options(.no_verification, .no_verification);
    options.retry_source_connection_id = verified;
    options.next_packet_numbers = carried;
    var after: Handshake = try .init(options);
    defer after.deinit();

    const first = before.session.writeKeys(.initial).?;
    const second = after.session.writeKeys(.initial).?;
    try testing.expect(!std.mem.eql(u8, first.keySlice(), second.keySlice()));
    // And the new keys are the ones the connection id alone gives, which
    // `zurl-quic` checks against RFC 9001 appendix A.
    try testing.expectEqualSlices(
        u8,
        quic.initial.clientKeys(retry_id.slice()).keySlice(),
        second.keySlice(),
    );
    // The original id still stands, because RFC 9000 section 7.3 has the
    // server echo the id of the **first** Initial packet.
    try testing.expectEqualSlices(
        u8,
        run.original.slice(),
        after.original_destination_connection_id.slice(),
    );
    // RFC 9000 section 17.2.5.3: a client MUST NOT reset its packet
    // numbers across a Retry. The next Initial packet takes number 2.
    try testing.expectEqual(@as(u64, 2), try after.session.nextPacketNumber(.initial));
}

/// The Retry packet of RFC 9001 appendix A.4, integrity tag included. Its
/// Destination Connection ID is the appendix's own, which is the one
/// `Run.options` gives the client.
const a4_retry = [_]u8{
    0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50,
    0x2a, 0x42, 0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2,
    0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f, 0x0f,
    0x24, 0x96, 0xba,
};

test "a Retry whose tag does not check cannot be made into a VerifiedRetry" {
    // The requirement used to be a sentence in a doc comment. It is the
    // constructor now, so a caller cannot reach `Options` without it.
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var retry = a4_retry;
    const scid = try packet.ConnectionId.init(retry[7..15]);

    const good = try Handshake.VerifiedRetry.verify(&odcid, &retry, scid);
    try testing.expectEqualSlices(u8, scid.slice(), good.id.slice());

    // One byte of the token changed, and the tag no longer matches.
    retry[19] ^= 0x01;
    try testing.expectError(
        error.RetryIntegrityFailed,
        Handshake.VerifiedRetry.verify(&odcid, &retry, scid),
    );
    // A packet too short to hold a tag is refused by name too.
    try testing.expectError(
        error.RetryTooShort,
        Handshake.VerifiedRetry.verify(&odcid, retry[0..8], scid),
    );
}

test "a Retry with a tag that does not check never reaches the handshake" {
    // The gate is `zurl_quic.initial.verifyRetry`, and this shows the two
    // answers it gives. A client that skipped it would let anyone on the
    // path restart the handshake with a connection id of their choosing.
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    // The Retry packet of RFC 9001 appendix A.4, tag included.
    var retry = [_]u8{
        0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50,
        0x2a, 0x42, 0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2,
        0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f, 0x0f,
        0x24, 0x96, 0xba,
    };
    try testing.expect(try quic.initial.verifyRetry(&odcid, &retry));

    // One byte of the token changed, and the tag no longer matches.
    retry[19] ^= 0x01;
    try testing.expect(!try quic.initial.verifyRetry(&odcid, &retry));
}

test "the offered suites are the ones the schedule can build a key for" {
    for (Handshake.offered_suites) |suite| {
        const code = schedule.codeOf(suite);
        try testing.expectEqual(suite, schedule.suiteOf(code).?);
    }
    try testing.expectEqual(@as(usize, 3), Handshake.offered_suites.len);
}

// ---------------------------------------------------------------------
// One fault ends the handshake
// ---------------------------------------------------------------------

test "a Certificate that fails to verify is checked once and never again" {
    // The chain walk is several signature checks. A refused message stays
    // in its `CryptoStream`, so a caller that dropped the error and handed
    // over the next frame would run the whole walk again, once per frame.
    // The state is terminal, so it does not.
    var run: Run = .{};
    var hs: Handshake = try .init(run.options(.no_verification, .self_signed));
    defer hs.deinit();

    var server: Server = try .init(run.server_id, run.original);
    server.fault = .{ .tampered_certificate = true };

    var hello_copy: Buf(2048) = .{};
    hello_copy.push(hs.pendingCrypto(.initial));
    hs.markCryptoSent(.initial, hs.pendingCrypto(.initial).len);
    var hello_out: Buf(1024) = .{};
    const server_hello = try server.serverHello(hello_copy.slice(), &hello_out);
    hs.setServerConnectionId(run.server_id);
    try hs.provideCrypto(.initial, 0, server_hello);

    var flight_out: Buf(4096) = .{};
    const flight = try server.flight(&flight_out);

    // The first read runs the walk and refuses the chain.
    try testing.expectError(
        error.CertificateSignatureInvalid,
        hs.provideCrypto(.handshake, 0, flight),
    );
    try testing.expectEqual(Handshake.State.failed, hs.state);

    // Every frame after it is answered from the state and reads nothing,
    // whatever the attacker sends and however small each frame is.
    var round: u64 = 0;
    while (round < 64) : (round += 1) {
        try testing.expectError(
            error.TlsHandshakeFailed,
            hs.provideCrypto(.handshake, 4096 + round, "x"),
        );
    }
    try testing.expect(!hs.isComplete());
}

test "a message that is refused leaves the transcript where it was" {
    // EncryptedExtensions used to go into the transcript before it was
    // read, so a caller that recovered and read it again hashed it twice
    // and died at Finished with a fault that named the wrong thing.
    var run: Run = .{};
    var hs: Handshake = try .init(run.options(.no_verification, .self_signed));
    defer hs.deinit();

    var server: Server = try .init(run.server_id, run.original);
    var hello_copy: Buf(2048) = .{};
    hello_copy.push(hs.pendingCrypto(.initial));
    var hello_out: Buf(1024) = .{};
    const server_hello = try server.serverHello(hello_copy.slice(), &hello_out);

    // No `setServerConnectionId`, so EncryptedExtensions is refused.
    try hs.provideCrypto(.initial, 0, server_hello);
    const before = hs.transcript.?.peek();

    var flight_out: Buf(4096) = .{};
    const flight = try server.flight(&flight_out);
    try testing.expectError(
        error.TlsConnectionIdMismatch,
        hs.provideCrypto(.handshake, 0, flight),
    );

    // The hash is the one it was before the message the client refused.
    const after = hs.transcript.?.peek();
    try testing.expectEqualSlices(u8, before.slice(), after.slice());

    // And the handshake is over, so a caller that "recovered" cannot feed
    // the same message in again and corrupt the transcript.
    try testing.expectEqual(Handshake.State.failed, hs.state);
    try testing.expectError(
        error.TlsHandshakeFailed,
        hs.provideCrypto(.handshake, 0, flight),
    );
    try testing.expectEqualSlices(u8, before.slice(), hs.transcript.?.peek().slice());
}

// ---------------------------------------------------------------------
// The smaller rules of the handshake
// ---------------------------------------------------------------------

test "a key share group the hello never sent a share for is refused" {
    // RFC 8446 section 4.1.4. `KeyExchange.exchange` takes four groups,
    // because the TLS over TCP client offers four. This hello sends one
    // x25519 share, so a server naming `x25519_ml_kem768` would make the
    // client decapsulate with a key pair whose public key never went out.
    try testing.expectEqual(
        error.TlsIllegalParameter,
        faultReport(.{ .wrong_key_share_group = true }),
    );
    try testing.expectEqual(tls.NamedGroup.x25519, Handshake.offered_key_share_group);
}

test "an extension in EncryptedExtensions the hello never offered is refused" {
    // RFC 8446 section 4.2: an answer to a question nobody asked is
    // `unsupported_extension`. ServerHello was strict here and this
    // message was not.
    try testing.expectEqual(
        error.TlsUnsupportedExtension,
        faultReport(.{ .unoffered_extension = true }),
    );
}

test "a message longer than its level's buffer is a fault and not a wait" {
    // A server naming sixteen megabytes of body can never be satisfied by
    // an eight kilobyte buffer, and a handshake that kept waiting would
    // hang until the idle timer.
    try testing.expectEqual(
        error.TlsMessageTooLong,
        faultReport(.{ .message_too_long = true }),
    );
}

test "a server that asks for a client certificate gets an empty one" {
    // RFC 8446 section 4.4.2. Refusing the message as unexpected would
    // end a handshake the RFC says can go on.
    var run: Run = .{};
    var hs: Handshake = undefined;
    try runHandshake(.{ .certificate_request = true }, &run, &hs);
    defer hs.deinit();

    try testing.expect(hs.isComplete());
    try testing.expect(hs.certificate_requested);

    // The flight starts with the empty Certificate and the Finished
    // follows it, and both go out on the one stream.
    const flight = hs.pendingCrypto(.handshake);
    try testing.expectEqualSlices(
        u8,
        &Handshake.empty_certificate,
        flight[0..Handshake.empty_certificate.len],
    );
    try testing.expectEqual(
        @as(u8, @intFromEnum(tls.HandshakeType.finished)),
        flight[Handshake.empty_certificate.len],
    );
}

test "a host name too long for the extension is said and not swallowed" {
    // The hello used to leave `server_name` out and carry on. The
    // certificate check still ran on the full host, so it was not a
    // bypass, but a recovery nobody can see is not a recovery.
    var run: Run = .{};
    const long = "a" ** 256;
    try testing.expectError(
        error.TlsServerNameTooLong,
        Handshake.init(run.options(.{ .explicit = long }, .no_verification)),
    );

    // One byte shorter still fits, and the name goes out.
    const fits = "b" ** 255;
    var hs: Handshake = try .init(run.options(.{ .explicit = fits }, .no_verification));
    defer hs.deinit();
    const body = extensionBody(hs.pendingCrypto(.initial), .server_name).?;
    try testing.expectEqualStrings(fits, body[5..]);
}

// ---------------------------------------------------------------------
// The key update
// ---------------------------------------------------------------------

test "the peer's update moves the keys once, whatever the peer sends after it" {
    // Two packets in the peer's new phase are one update. Rotating twice
    // would put the read keys a generation past the peer's write keys, and
    // every packet after that would fail to open and count toward the
    // integrity limit of RFC 9001 section 6.6.
    var run: Run = .{};
    var hs: Handshake = undefined;
    try runHandshake(.{}, &run, &hs);
    defer hs.deinit();
    hs.session.handshakeDone();

    const before = hs.session.readKeys(.application).?;
    const next = hs.session.readKeysForPhase(1).?;

    try hs.session.acceptPeerUpdate(1);
    try testing.expectEqual(@as(u1, 1), hs.session.keyPhase().?);
    try testing.expectEqualSlices(u8, next.keySlice(), hs.session.readKeys(.application).?.keySlice());

    // The second packet of the same phase changes nothing at all.
    try hs.session.acceptPeerUpdate(1);
    try hs.session.acceptPeerUpdate(1);
    try testing.expectEqual(@as(u1, 1), hs.session.keyPhase().?);
    try testing.expectEqualSlices(u8, next.keySlice(), hs.session.readKeys(.application).?.keySlice());

    // The generation before it is kept, because a packet the peer sent
    // before the update can still arrive. RFC 9001 section 6.3.
    try testing.expectEqualSlices(
        u8,
        before.keySlice(),
        hs.session.application.?.previous_read_keys.?.keySlice(),
    );
}

test "the peer's update bars this side from running one before it is acknowledged" {
    // RFC 9001 section 6.1: one update at a time. `rotate` moves the write
    // keys too, so accepting the peer's update starts the same wait an
    // update of this side's own starts.
    var run: Run = .{};
    var hs: Handshake = undefined;
    try runHandshake(.{}, &run, &hs);
    defer hs.deinit();
    hs.session.handshakeDone();

    try testing.expect(!hs.session.updatePending());
    try hs.session.acceptPeerUpdate(1);
    try testing.expect(hs.session.updatePending());
    try testing.expectError(error.KeyUpdateNotAllowed, hs.session.update());

    // A packet acknowledged in the new phase is what ends the wait.
    hs.session.confirmUpdate();
    try testing.expect(!hs.session.updatePending());
    try hs.session.update();
    try testing.expectEqual(@as(u1, 0), hs.session.keyPhase().?);
}

test "a packet reordered across an update opens under the generation it was sealed with" {
    // RFC 9001 section 6.3. Both a reordered packet of the old phase and
    // the start of a new update carry a Key Phase bit that is not the
    // current one, and only the packet number separates them.
    var run: Run = .{};
    var hs: Handshake = undefined;
    try runHandshake(.{}, &run, &hs);
    defer hs.deinit();
    hs.session.handshakeDone();

    const old = hs.session.readKeys(.application).?;
    try hs.session.acceptPeerUpdate(1);
    const current = hs.session.readKeys(.application).?;
    const next = hs.session.readKeysForPhase(0).?;

    // Packet 100 opened in the new phase, so it is the lowest number this
    // side has seen there.
    hs.session.recordOpened(1, 100);

    // A phase 0 packet numbered below it was sent before the update.
    try testing.expectEqual(Session.ReadGeneration.previous, hs.session.readGeneration(0, 90).?);
    try testing.expectEqualSlices(
        u8,
        old.keySlice(),
        hs.session.readKeysForPacket(0, 90).?.keySlice(),
    );
    // One at or above it is the peer starting the next update, and only
    // that one may be answered with `acceptPeerUpdate`.
    try testing.expectEqual(Session.ReadGeneration.next, hs.session.readGeneration(0, 100).?);
    try testing.expectEqualSlices(
        u8,
        next.keySlice(),
        hs.session.readKeysForPacket(0, 100).?.keySlice(),
    );
    try testing.expectEqual(Session.ReadGeneration.current, hs.session.readGeneration(1, 5).?);
    // And a packet of the current phase always opens under the current
    // keys.
    try testing.expectEqualSlices(
        u8,
        current.keySlice(),
        hs.session.readKeysForPacket(1, 5).?.keySlice(),
    );

    // Dropping the old generation writes over it, so the key does not sit
    // in memory once it has no use left.
    hs.session.discardPreviousReadKeys();
    try testing.expectEqual(
        @as(?protection.Keys, null),
        hs.session.application.?.previous_read_keys,
    );
    try testing.expectEqual(
        @as(?protection.Keys, null),
        hs.session.readKeysForPacket(0, 90),
    );
}

test "clearing a session writes over every key and not only the optional" {
    // Assigning null to an optional leaves the payload where it was. A doc
    // comment that says the keys are gone has to be true.
    var run: Run = .{};
    var hs: Handshake = undefined;
    try runHandshake(.{}, &run, &hs);

    var session = hs.session;
    // Pointers into the storage of each optional, taken while it is set.
    // Reading through `.?` after `clear` would be reading a null optional,
    // and the point of the test is the bytes underneath it.
    const initial_key = &session.initial.?.write.key;
    const handshake_iv = &session.handshake.?.read.iv;
    const application_key = &session.application.?.keys.write.key;
    const application_read = &session.application.?.keys.read.key;
    const next_read = &session.application.?.next_read_keys.key;
    try testing.expect(!std.mem.allEqual(u8, initial_key, 0));
    try testing.expect(!std.mem.allEqual(u8, application_key, 0));

    session.clear();
    try testing.expect(session.initial == null);
    try testing.expect(session.handshake == null);
    try testing.expect(session.application == null);
    try testing.expect(std.mem.allEqual(u8, initial_key, 0));
    try testing.expect(std.mem.allEqual(u8, handshake_iv, 0));
    try testing.expect(std.mem.allEqual(u8, application_key, 0));
    try testing.expect(std.mem.allEqual(u8, application_read, 0));
    try testing.expect(std.mem.allEqual(u8, next_read, 0));

    hs.deinit();
}

test "dropping a level's keys writes over them" {
    var run: Run = .{};
    var hs: Handshake = undefined;
    try runHandshake(.{}, &run, &hs);
    defer hs.deinit();

    const initial_key = &hs.session.initial.?.write.key;
    const initial_iv = &hs.session.initial.?.read.iv;
    const handshake_hp = &hs.session.handshake.?.write.hp;
    try testing.expect(!std.mem.allEqual(u8, initial_key, 0));
    try testing.expect(!std.mem.allEqual(u8, handshake_hp, 0));

    hs.session.dropInitialKeys();
    try testing.expect(hs.session.initial == null);
    try testing.expect(std.mem.allEqual(u8, initial_key, 0));
    try testing.expect(std.mem.allEqual(u8, initial_iv, 0));

    hs.session.dropHandshakeKeys();
    try testing.expect(hs.session.handshake == null);
    try testing.expect(std.mem.allEqual(u8, handshake_hp, 0));
}

test "session tickets keep arriving past the application buffer" {
    // `CryptoStream.consume` slides, so the room a level has does not run
    // out as the stream offsets climb. Without that, cumulative
    // post-handshake CRYPTO past `min_application_buffer` would kill a
    // connection to a server that did nothing wrong. RFC 8446 section
    // 4.6.1 lets a server send tickets for as long as the connection
    // lives.
    var run: Run = .{};
    var hs: Handshake = undefined;
    try runHandshake(.{}, &run, &hs);
    defer hs.deinit();

    var ticket: Buf(1024) = .{};
    ticket.byte(@intFromEnum(tls.HandshakeType.new_session_ticket));
    const body = ticket.mark();
    ticket.int(u32, 7200); // ticket_lifetime
    ticket.int(u32, 0); // ticket_age_add
    ticket.byte(0); // ticket_nonce
    ticket.int(u16, 512); // ticket
    ticket.push(&[_]u8{0x5a} ** 512);
    ticket.int(u16, 0); // extensions
    ticket.wrapLen(body, 3);

    // Twenty of these come to more than ten kilobytes, against a four
    // kilobyte buffer.
    var offset: u64 = 0;
    var round: usize = 0;
    while (round < 20) : (round += 1) {
        try hs.provideCrypto(.application, offset, ticket.slice());
        offset += ticket.slice().len;
    }

    try testing.expect(offset > Handshake.min_application_buffer * 2);
    try testing.expectEqual(offset, hs.application_in.base);
    try testing.expect(hs.isComplete());
}

test "a second CertificateRequest is refused" {
    // RFC 8446 section 4.3.2 gives a handshake one. The state does not
    // move on the message, so the flag is what keeps a second one out.
    var run: Run = .{};
    var hs: Handshake = undefined;
    try runHandshake(.{ .certificate_request = true }, &run, &hs);
    defer hs.deinit();

    var request: Buf(64) = .{};
    request.byte(@intFromEnum(tls.HandshakeType.certificate_request));
    request.push(&.{ 0, 0, 3, 0, 0, 0 });
    try testing.expectError(
        error.TlsUnexpectedMessage,
        hs.provideCrypto(.handshake, hs.handshake_in.base, request.slice()),
    );
}
