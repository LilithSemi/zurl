//! A loopback QUIC and HTTP/3 server for tests.
//!
//! This is a test fixture, not a product. `h2_test_server.zig` speaks
//! HTTP/2 frames over TCP with prior knowledge, and no HTTP/3 test can use
//! it: HTTP/3 rides on QUIC, and QUIC has no cleartext form at all. RFC
//! 9001 section 4 makes the TLS 1.3 handshake part of the transport, so a
//! fixture that speaks QUIC has to speak TLS too.
//!
//! **So this one does.** It holds an x25519 key pair, an ECDSA key pair,
//! and a self-signed certificate it signs itself, and it runs a real TLS
//! 1.3 handshake over CRYPTO frames: a real key exchange, a real
//! CertificateVerify signature, and a real Finished. The client verifies
//! every one of them through `zurl-quic-tls`, which reaches the vendored
//! TLS client's own certificate code. Nothing is stubbed out on either
//! side, and no test here touches the real network: the socket binds
//! 127.0.0.1 with a port the operating system picks.
//!
//! **What it leaves out, because a loopback path has none of it.** No loss
//! recovery and no retransmission: every datagram arrives, in order, so
//! nothing is ever sent twice. Acknowledgments name one range from zero to
//! the largest packet seen. There is no congestion control, no key update,
//! no Retry, no migration, and no server push. The client's own code for
//! all of that is exercised against real servers and by the vector tests
//! of `zurl-quic`; what this fixture proves is the part that only an
//! exchange can prove, which is that a request goes out and an answer
//! comes back.
//!
//! The certificate names `zurl.test`, so a test connects with that host
//! name and `Trust.self_signed`: the host name walk and the certificate's
//! own signature are both checked, and only the trust root is not.

const std = @import("std");
const Io = std.Io;
const tls = std.crypto.tls;
const crypto = std.crypto;
const quic = @import("zurl-quic");
const quic_tls = @import("zurl-quic-tls");
const zurl_h3 = @import("zurl-h3");
const zurl_qpack = @import("zurl-qpack");
const testing = std.testing;

const packet = quic.packet;
const protection = quic.protection;
const header_protection = quic.header_protection;
const frame = quic.frame;
const transport_parameters = quic.transport_parameters;
const schedule = quic_tls.schedule;
const h3_frame = zurl_h3.frame;
const varint_max_bytes = quic.varint.max_bytes;

pub const H3TestServer = @This();

/// The host name the certificate carries.
pub const host_name = "zurl.test";

/// How many requests one server keeps a record of.
pub const capture_max = 4;

/// How large one captured request head may be.
pub const capture_bytes = 8192;

/// The largest datagram this fixture sends.
const datagram_len = 1350;

/// How many octets of one stream the fixture reassembles.
const stream_buffer_len = 64 * 1024;

/// How many streams one connection may carry here.
const stream_slots = 8;

/// One scripted reply.
pub const Response = struct {
    /// The response fields, `:status` first, exactly as they go out. Every
    /// name must already be lower case, which is what RFC 9114 section 4.2
    /// puts on the wire.
    fields: []const zurl_qpack.Field,
    /// The response body.
    body: []const u8 = "",
    /// How many octets of the body go into one `DATA` frame. A small
    /// number is what makes a test of a body that arrives in pieces.
    data_chunk: usize = 16384,
    /// The fields of a trailer section, or none. RFC 9114 section 4.1.
    trailers: []const zurl_qpack.Field = &.{},
    /// Whether the reply carries no `FIN`, so the stream is cut short.
    cut_body: bool = false,
};

/// What `startWith` takes beyond the script.
pub const Options = struct {
    /// What the server puts in its own `SETTINGS` frame.
    settings: zurl_h3.Settings = .{ .qpack_max_table_capacity = 0, .qpack_blocked_streams = 0 },
    /// Whether the server opens a second control stream, which RFC 9114
    /// section 6.2.1 makes a connection error.
    duplicate_control_stream: bool = false,
    /// Whether the server's first control frame is a `GOAWAY` rather than
    /// a `SETTINGS`, which RFC 9114 section 6.2.1 makes
    /// H3_MISSING_SETTINGS.
    skip_settings: bool = false,
    /// A `GOAWAY` the server writes after its `SETTINGS`, or null.
    goaway: ?u64 = null,
    /// Whether the server opens a unidirectional stream of a type nobody
    /// defines, which the client must abandon rather than read. RFC 9114
    /// section 6.2.3.
    grease_stream: bool = false,
    /// Whether the server opens a unidirectional stream whose reserved
    /// type takes four varint bytes and sends those bytes one to a
    /// datagram.
    ///
    /// **RFC 9114 section 6.2.3 reserved types are `0x1f * N + 0x21`, and
    /// every one above `N = 0` needs two varint bytes or more**, so a
    /// conformant server greasing the connection splits one across
    /// packets whenever the path is busy. A client that dropped the part
    /// it already read would then read the remainder as a type of its
    /// own: the second byte here is `0x00`, which is the control stream
    /// type, and a second control stream closes the connection.
    split_grease_stream: bool = false,
    /// The payload length of a reserved control frame the server writes
    /// after its `SETTINGS`, or null for none.
    ///
    /// RFC 9114 section 7.2.8 has a peer send a reserved frame type on
    /// purpose, and section 9 says the client ignores an unknown type
    /// "regardless of length", so a length past anything the client
    /// buffers is legal traffic and not a reason to close.
    grease_control_frame: ?usize = null,
    /// A reserved frame the server writes on the request stream, before
    /// its answer, or null for none.
    ///
    /// `declared` is the length the frame header names and `sent` is how
    /// many octets of payload really follow it. The two are equal for the
    /// grease frame RFC 9114 section 7.2.8 describes. A `declared` far
    /// past `sent` is the peer that names a length it never finishes
    /// sending, which a client must bound rather than read for ever. See
    /// `h3.skip_octets_max`.
    grease_request_frame: ?GreaseFrame = null,
    /// Whether the server resets the request stream instead of answering.
    reset_request: ?u64 = null,
    /// Whether the server ends its own control stream right after its
    /// `SETTINGS`, and then answers the request as usual.
    ///
    /// **RFC 9114 section 6.2.1 makes the control stream live for the
    /// whole connection**, so a `FIN` on it is
    /// H3_CLOSED_CRITICAL_STREAM. A server that does this and then
    /// answers normally is the shape that tells whether the client reads
    /// the rule on the path a whole transfer takes, or only on the path a
    /// blocked send takes. See `h3.Session.serviceExcept`.
    close_control_stream: bool = false,
};

/// A reserved frame on the request stream. See `Options.grease_request_frame`.
pub const GreaseFrame = struct {
    declared: u64,
    sent: usize = 0,
};

socket: Io.net.Socket = undefined,
task: Io.Future(void) = undefined,
options: Options = .{},
capture_heads: [capture_max][capture_bytes]u8 = undefined,
capture_head_lens: [capture_max]usize = @splat(0),
capture_bodies: [capture_max][capture_bytes]u8 = undefined,
capture_body_lens: [capture_max]usize = @splat(0),
capture_count: std.atomic.Value(usize) = .init(0),
/// How many requests this fixture has answered, over every connection it
/// has accepted.
///
/// **The index into the script belongs to the server and not to one
/// connection.** A client under test opens one QUIC connection for one
/// transfer, so a redirect chain reaches this fixture as a second
/// connection and the second reply of the script belongs to it. A count
/// kept on the connection would start the script again at each hop and
/// answer the redirect for ever. Only the `run` task touches this.
answered: usize = 0,

/// Starts a server that answers `script` in order.
pub fn start(self: *H3TestServer, script: []const Response) !void {
    return self.startWith(script, .{});
}

/// The same as `start`, with every choice this fixture offers spelled out.
pub fn startWith(self: *H3TestServer, script: []const Response, options: Options) !void {
    std.debug.assert(script.len <= capture_max);

    var address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    self.socket = try address.bind(testing.io, .{ .mode = .dgram });
    errdefer self.socket.close(testing.io);

    self.options = options;
    self.capture_head_lens = @splat(0);
    self.capture_body_lens = @splat(0);
    self.capture_count = .init(0);
    self.answered = 0;

    self.task = testing.io.concurrent(run, .{ self, script }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
}

/// Stops the server task and releases the socket.
pub fn stop(self: *H3TestServer) void {
    self.task.cancel(testing.io);
    self.socket.close(testing.io);
}

pub fn port(self: *const H3TestServer) u16 {
    return self.socket.address.getPort();
}

pub fn requests(self: *const H3TestServer) usize {
    return self.capture_count.load(.acquire);
}

/// The request head of request `index`, rendered one field to a line as
/// `name: value\r\n`, the pseudo headers included and in the order they
/// arrived.
pub fn requestHead(self: *const H3TestServer, index: usize) ?[]const u8 {
    if (index >= self.capture_count.load(.acquire)) return null;
    return self.capture_heads[index][0..self.capture_head_lens[index]];
}

/// The request body of request `index`.
pub fn requestBody(self: *const H3TestServer, index: usize) ?[]const u8 {
    if (index >= self.capture_count.load(.acquire)) return null;
    return self.capture_bodies[index][0..self.capture_body_lens[index]];
}

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
            std.mem.copyBackwards(u8, self.data[from + header ..][0..body], self.data[from..][0..body]);
            self.data[from] = tag;
            writeDerLength(self.data[from + 1 ..], body);
            self.len += header;
        }

        /// Wraps everything written since `from` in a big endian length of
        /// `width` bytes, which is what TLS puts in front of a vector.
        fn wrapLen(self: *Self, from: usize, width: usize) void {
            const body = self.len - from;
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

const Ecdsa = crypto.sign.ecdsa.EcdsaP256Sha256;

/// Object identifiers, without the tag and the length.
const oid_ecdsa_with_sha256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
const oid_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const oid_prime256v1 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const oid_common_name = [_]u8{ 0x55, 0x04, 0x03 };

// ---------------------------------------------------------------------
// The TLS half
// ---------------------------------------------------------------------

const Tls = struct {
    x25519: crypto.dh.X25519.KeyPair,
    signer: Ecdsa.KeyPair,
    certificate: Buf(1024) = .{},
    suite: protection.Suite = .aes_128_gcm,
    transcript: schedule.Transcript = undefined,
    traffic: schedule.Pair = undefined,
    master: schedule.Secret = undefined,
    application: schedule.Pair = undefined,
    connection_id: packet.ConnectionId,
    original_connection_id: packet.ConnectionId,

    fn init(connection_id: packet.ConnectionId, original: packet.ConnectionId) !Tls {
        var self: Tls = .{
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
    fn buildCertificate(self: *Tls) !void {
        var tbs: Buf(1024) = .{};
        tbs.push(&.{ 0x02, 0x01, 0x01 }); // serialNumber
        writeAlgorithmIdentifier(&tbs);
        writeName(&tbs); // issuer
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
        writeName(&tbs); // subject
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
                tbs.byte(0x00);
                const point = self.signer.public_key.toUncompressedSec1();
                tbs.push(&point);
                tbs.wrapDer(key, 0x03);
            }
            tbs.wrapDer(at, 0x30);
        }
        tbs.wrapDer(0, 0x30);

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

    /// One RDNSequence holding a single commonName of `host_name`.
    fn writeName(buf: anytype) void {
        const name = buf.mark();
        const rdn = buf.mark();
        const atav = buf.mark();
        writeOid(buf, &oid_common_name);
        const text = buf.mark();
        buf.push(host_name);
        buf.wrapDer(text, 0x13);
        buf.wrapDer(atav, 0x30);
        buf.wrapDer(rdn, 0x31);
        buf.wrapDer(name, 0x30);
    }

    /// Reads the ClientHello and writes the ServerHello.
    fn serverHello(self: *Tls, hello: []const u8, out: *Buf(1024)) ![]const u8 {
        const client_share = findKeyShare(hello) orelse return error.NoKeyShare;

        const at = out.mark();
        out.byte(@intFromEnum(tls.HandshakeType.server_hello));
        const body = out.mark();
        out.int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2));
        out.push(&[_]u8{0x7e} ** 32);
        out.byte(0); // legacy_session_id_echo, empty. RFC 9001 section 8.4.
        out.int(u16, @intFromEnum(schedule.codeOf(self.suite)));
        out.byte(0); // legacy_compression_method

        const extensions = out.mark();
        out.int(u16, @intFromEnum(tls.ExtensionType.supported_versions));
        out.int(u16, 2);
        out.int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_3));
        out.int(u16, @intFromEnum(tls.ExtensionType.key_share));
        const share = out.mark();
        out.int(u16, @intFromEnum(tls.NamedGroup.x25519));
        out.int(u16, 32);
        out.push(&self.x25519.public_key);
        out.wrapLen(share, 2);
        out.wrapLen(extensions, 2);
        out.wrapLen(body, 3);

        const message = out.data[at..out.len];

        if (client_share.len != 32) return error.BadKeyShare;
        const shared = try crypto.dh.X25519.scalarmult(self.x25519.secret_key, client_share[0..32].*);
        self.transcript = .init(self.suite.hash());
        self.transcript.update(hello);
        self.transcript.update(message);
        const stage = schedule.handshakeSecrets(self.suite, &shared, self.transcript.peek().slice());
        self.traffic = stage.traffic;
        self.master = stage.master;
        return message;
    }

    /// Writes EncryptedExtensions, Certificate, CertificateVerify and
    /// Finished, which is the whole of the server's Handshake flight, and
    /// then derives the application secrets.
    fn flight(self: *Tls, out: *Buf(4096)) ![]const u8 {
        const at = out.mark();
        try self.encryptedExtensions(out);
        try self.certificateMessage(out);
        try self.certificateVerify(out);
        try self.finished(out);
        self.application = schedule.applicationSecrets(
            self.suite,
            &self.master,
            self.transcript.peek().slice(),
        );
        return out.data[at..out.len];
    }

    fn encryptedExtensions(self: *Tls, out: *Buf(4096)) !void {
        const at = out.mark();
        out.byte(@intFromEnum(tls.HandshakeType.encrypted_extensions));
        const body = out.mark();
        const extensions = out.mark();

        // ALPN, RFC 9001 section 8.1: mandatory on a QUIC connection.
        out.int(u16, @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation));
        const ext = out.mark();
        const list = out.mark();
        out.byte(@intCast(zurl_h3.alpn_name.len));
        out.push(zurl_h3.alpn_name);
        out.wrapLen(list, 2);
        out.wrapLen(ext, 2);

        out.int(u16, @intFromEnum(tls.ExtensionType.quic_transport_parameters));
        const parameters = out.mark();
        var w: std.Io.Writer = .fixed(out.data[out.len..]);
        // Enough for one request stream and the three unidirectional
        // streams RFC 9114 section 6.2 asks a client to open.
        try transport_parameters.encode(.{
            .initial_max_data = 1 << 20,
            .initial_max_stream_data_bidi_local = 1 << 18,
            .initial_max_stream_data_bidi_remote = 1 << 18,
            .initial_max_stream_data_uni = 1 << 18,
            .initial_max_streams_bidi = 8,
            .initial_max_streams_uni = 8,
            .original_destination_connection_id = self.original_connection_id,
            .initial_source_connection_id = self.connection_id,
        }, &w);
        out.len += w.end;
        out.wrapLen(parameters, 2);

        out.wrapLen(extensions, 2);
        out.wrapLen(body, 3);
        self.transcript.update(out.data[at..out.len]);
    }

    fn certificateMessage(self: *Tls, out: *Buf(4096)) !void {
        const at = out.mark();
        out.byte(@intFromEnum(tls.HandshakeType.certificate));
        const body = out.mark();
        out.byte(0); // certificate_request_context
        const list = out.mark();
        const entry = out.mark();
        out.push(self.certificate.slice());
        out.wrapLen(entry, 3);
        out.int(u16, 0); // per certificate extensions
        out.wrapLen(list, 3);
        out.wrapLen(body, 3);
        self.transcript.update(out.data[at..out.len]);
    }

    fn certificateVerify(self: *Tls, out: *Buf(4096)) !void {
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
        out.wrapLen(sig, 2);
        out.wrapLen(body, 3);
        self.transcript.update(out.data[at..out.len]);
    }

    fn finished(self: *Tls, out: *Buf(4096)) !void {
        const key = schedule.finishedKey(self.suite, &self.traffic.server);
        const data = schedule.verifyData(self.suite, &key, self.transcript.peek().slice());
        const at = out.mark();
        out.byte(@intFromEnum(tls.HandshakeType.finished));
        const body = out.mark();
        out.push(data.slice());
        out.wrapLen(body, 3);
        self.transcript.update(out.data[at..out.len]);
    }
};

/// Finds the x25519 share inside a ClientHello.
fn findKeyShare(hello: []const u8) ?[]const u8 {
    const extensions = extensionsOf(hello) orelse return null;
    var at: usize = 0;
    while (at + 4 <= extensions.len) {
        const kind = std.mem.readInt(u16, extensions[at..][0..2], .big);
        const len = std.mem.readInt(u16, extensions[at + 2 ..][0..2], .big);
        if (at + 4 + len > extensions.len) return null;
        const body = extensions[at + 4 ..][0..len];
        at += 4 + len;
        if (kind != @intFromEnum(tls.ExtensionType.key_share)) continue;
        if (body.len < 2) return null;
        const list_len = std.mem.readInt(u16, body[0..2], .big);
        var share_at: usize = 2;
        while (share_at + 4 <= 2 + list_len) {
            const group = std.mem.readInt(u16, body[share_at..][0..2], .big);
            const key_len = std.mem.readInt(u16, body[share_at + 2 ..][0..2], .big);
            if (share_at + 4 + key_len > body.len) return null;
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
    at += 1 + hello[at];
    if (at + 2 > hello.len) return null;
    at += 2 + std.mem.readInt(u16, hello[at..][0..2], .big);
    if (at >= hello.len) return null;
    at += 1 + hello[at];
    if (at + 2 > hello.len) return null;
    const extensions_len = std.mem.readInt(u16, hello[at..][0..2], .big);
    at += 2;
    if (at + extensions_len != hello.len) return null;
    return hello[at..][0..extensions_len];
}

// ---------------------------------------------------------------------
// The QUIC half
// ---------------------------------------------------------------------

/// One receiving half, reassembled by offset.
const Incoming = struct {
    id: u64 = 0,
    in_use: bool = false,
    data: [stream_buffer_len]u8 = undefined,
    end: usize = 0,
    read: usize = 0,
    fin: bool = false,
};

const Conn = struct {
    server: *H3TestServer,
    peer: Io.net.IpAddress,
    tls: Tls,
    /// The Destination Connection Id this side puts on every packet, which
    /// is the client's own Source Connection Id.
    dcid: packet.ConnectionId,
    /// This side's identifier.
    scid: packet.ConnectionId,
    initial_keys: protection.Keys,
    handshake_read: ?protection.Keys = null,
    handshake_write: ?protection.Keys = null,
    application_read: ?protection.Keys = null,
    application_write: ?protection.Keys = null,
    next_number: [3]u64 = .{ 0, 0, 0 },
    largest_recv: [3]?u64 = .{ null, null, null },
    ack_pending: [3]bool = .{ false, false, false },
    /// The client's CRYPTO stream at the Initial level.
    hello: [4096]u8 = undefined,
    hello_end: usize = 0,
    hello_sent: bool = false,
    handshake_done_sent: bool = false,
    control_opened: bool = false,
    /// The next stream number this side uses for a unidirectional stream.
    next_uni: u64 = 0,
    streams: [stream_slots]Incoming = @splat(.{}),
    /// Where the request stream's frame reader stopped.
    request_id: ?u64 = null,
};

fn run(self: *H3TestServer, script: []const Response) void {
    var datagram: [2048]u8 = undefined;
    var conn: ?Conn = null;

    while (true) {
        const message = self.socket.receiveTimeout(
            testing.io,
            &datagram,
            .{ .duration = .{ .raw = .fromSeconds(20), .clock = .awake } },
        ) catch return;
        if (message.data.len == 0) continue;

        if (conn == null) {
            conn = (accept(self, message) catch return) orelse continue;
        } else if (!sameAddress(conn.?.peer, message.from)) {
            // **A second connection, and the fixture takes it.** A client
            // under test opens one QUIC connection for one transfer, so a
            // redirect chain arrives here as a second connection from a
            // second source port. The fixture answers it with the next
            // reply of the script, because `answered` belongs to the
            // server.
            //
            // **A datagram that opens no connection is still dropped.**
            // `accept` reads an Initial packet and answers null for
            // anything else, so a stray datagram on a loopback port never
            // becomes the peer and never reaches the packet reader. The
            // client under test holds the same rule.
            const next = accept(self, message) catch return;
            if (next == null) continue;
            conn = next;
        }
        const c = &conn.?;
        processDatagram(c, message.data, script) catch return;
    }
}

fn accept(self: *H3TestServer, message: Io.net.IncomingMessage) !?Conn {
    const parsed = packet.parseLong(message.data) catch return null;
    if (parsed.body != .initial) return null;
    var scid_bytes: [8]u8 = .{ 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58 };
    const scid = try packet.ConnectionId.init(&scid_bytes);
    return .{
        .server = self,
        .peer = message.from,
        .tls = try .init(scid, parsed.dcid),
        .dcid = parsed.scid,
        .scid = scid,
        // RFC 9001 section 5.2: both key sets come from the Destination
        // Connection Id of the client's first Initial packet.
        .initial_keys = quic.initial.clientKeys(parsed.dcid.slice()),
    };
}

fn sameAddress(a: Io.net.IpAddress, b: Io.net.IpAddress) bool {
    return switch (a) {
        .ip4 => |left| switch (b) {
            .ip4 => |right| std.mem.eql(u8, &left.bytes, &right.bytes) and left.port == right.port,
            .ip6 => false,
        },
        .ip6 => |left| switch (b) {
            .ip4 => false,
            .ip6 => |right| std.mem.eql(u8, &left.bytes, &right.bytes) and left.port == right.port,
        },
    };
}

fn spaceOf(level: protection.Level) usize {
    return quic.loss.Space.fromLevel(level).index();
}

fn processDatagram(c: *Conn, datagram: []u8, script: []const Response) !void {
    var at: usize = 0;
    while (at < datagram.len) {
        if (datagram[at] == 0x00) break;
        const rest = datagram[at..];
        const consumed = try processPacket(c, rest, script);
        if (consumed == 0) break;
        at += consumed;
    }
    try flush(c, script);
}

fn processPacket(c: *Conn, bytes: []u8, script: []const Response) !usize {
    if (packet.form(bytes[0]) == .short) {
        const parsed = packet.parseShort(bytes, c.scid.len) catch return 0;
        const keys = c.application_read orelse return 0;
        try openAndRead(c, bytes, parsed.pn_offset, .application, bytes.len - parsed.pn_offset, keys, script);
        return bytes.len;
    }

    const parsed = packet.parseLong(bytes) catch return 0;
    const level: protection.Level, const length: usize = switch (parsed.body) {
        .initial => |i| .{ .initial, @intCast(i.length) },
        .handshake => |h| .{ .handshake, @intCast(h.length) },
        else => return 0,
    };
    const keys = switch (level) {
        .initial => c.initial_keys,
        .handshake => c.handshake_read orelse return parsed.pn_offset + length,
        else => unreachable,
    };
    const total = parsed.pn_offset + length;
    if (total > bytes.len) return 0;
    try openAndRead(c, bytes[0..total], parsed.pn_offset, level, length, keys, script);
    return total;
}

fn openAndRead(
    c: *Conn,
    bytes: []u8,
    pn_offset: usize,
    level: protection.Level,
    length: usize,
    keys: protection.Keys,
    script: []const Response,
) !void {
    const pn_len = header_protection.remove(bytes, pn_offset, &keys) catch return;
    const truncated = packet.readPacketNumber(bytes[pn_offset..], pn_len) catch return;
    const space = spaceOf(level);
    const number = packet.decodePacketNumber(c.largest_recv[space] orelse 0, truncated, @as(u6, pn_len) * 8);
    if (length < pn_len) return;

    const header = bytes[0 .. pn_offset + pn_len];
    const sealed = bytes[pn_offset + pn_len ..][0 .. length - pn_len];
    var payload: [2048]u8 = undefined;
    const opened = keys.open(&payload, sealed, header, number) catch return;

    if (c.largest_recv[space] == null or number > c.largest_recv[space].?) c.largest_recv[space] = number;

    var decoder: frame.Decoder = .init(payload[0..opened]);
    while (try decoder.next()) |f| {
        if (f.elicitsAck()) c.ack_pending[space] = true;
        switch (f) {
            .crypto => |cr| {
                if (level == .initial) {
                    const end = cr.offset + cr.data.len;
                    if (end > c.hello.len) return;
                    @memcpy(c.hello[@intCast(cr.offset)..][0..cr.data.len], cr.data);
                    if (end > c.hello_end) c.hello_end = @intCast(end);
                }
                // The client's Finished at the Handshake level needs no
                // answer here: the client is the side this fixture tests.
            },
            .stream => |s| try onStream(c, s, script),
            else => {},
        }
    }
}

fn onStream(c: *Conn, s: frame.Stream, script: []const Response) !void {
    const slot = findStream(c, s.stream_id) orelse return;
    const end: usize = @intCast(s.endOffset());
    if (end > slot.data.len) return;
    @memcpy(slot.data[@intCast(s.offset)..][0..s.data.len], s.data);
    if (end > slot.end) slot.end = end;
    if (s.fin) slot.fin = true;

    // A client-initiated bidirectional stream is a request. RFC 9114
    // section 4.1: the request head arrives whole before its `FIN`.
    if (s.stream_id % 4 == 0 and slot.fin) {
        try answer(c, slot, script);
    }
}

fn findStream(c: *Conn, id: u64) ?*Incoming {
    for (&c.streams) |*slot| {
        if (slot.in_use and slot.id == id) return slot;
    }
    for (&c.streams) |*slot| {
        if (!slot.in_use) {
            slot.* = .{ .id = id, .in_use = true };
            return slot;
        }
    }
    return null;
}

/// Reads one request and writes the scripted answer.
fn answer(c: *Conn, slot: *Incoming, script: []const Response) !void {
    if (slot.read != 0) return;
    slot.read = 1;
    const index = c.server.answered;
    if (index >= script.len) return;
    c.server.answered += 1;

    var decoder: zurl_qpack.Decoder = .init(.{});
    defer decoder.deinit(testing.allocator);

    // The request stream: a `HEADERS` frame, then any `DATA` frames.
    var at: usize = 0;
    var head_len: usize = 0;
    var body_len: usize = 0;
    while (at < slot.end) {
        const header = (h3_frame.readHeader(slot.data[at..slot.end]) catch return) orelse return;
        at += header.header_len;
        const length: usize = @intCast(header.length);
        if (at + length > slot.end) return;
        const payload = slot.data[at..][0..length];
        at += length;
        switch (header.kind) {
            .headers => {
                var section = decoder.decodeSection(testing.allocator, payload) catch return;
                defer section.deinit(testing.allocator);
                var w: std.Io.Writer = .fixed(&c.server.capture_heads[index]);
                for (section.list.fields.items) |field| {
                    w.writeAll(field.name) catch break;
                    w.writeAll(": ") catch break;
                    w.writeAll(field.value) catch break;
                    w.writeAll("\r\n") catch break;
                }
                head_len = w.end;
            },
            .data => {
                const room = c.server.capture_bodies[index].len - body_len;
                const take = @min(room, payload.len);
                @memcpy(c.server.capture_bodies[index][body_len..][0..take], payload[0..take]);
                body_len += take;
            },
            else => {},
        }
    }
    c.server.capture_head_lens[index] = head_len;
    c.server.capture_body_lens[index] = body_len;
    c.server.capture_count.store(index + 1, .release);
    c.request_id = slot.id;

    if (c.server.options.reset_request) |code| {
        try sendFrames(c, .application, &.{
            .{ .reset_stream = .{ .stream_id = slot.id, .application_error_code = code, .final_size = 0 } },
        });
        return;
    }

    const reply = script[index];
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);

    const block = try zurl_qpack.encoder.encodeAlloc(testing.allocator, reply.fields, .{});
    defer testing.allocator.free(block);
    var head: [h3_frame.max_header_bytes]u8 = undefined;
    if (c.server.options.grease_request_frame) |grease| {
        // Type `0x21` is one of the reserved types of RFC 9114 section
        // 7.2.3, so a client must ignore this frame and read the answer
        // behind it.
        const kind: h3_frame.Kind = @enumFromInt(0x21);
        try out.appendSlice(testing.allocator, h3_frame.writeHeader(kind, grease.declared, &head));
        try out.appendNTimes(testing.allocator, 0, grease.sent);
    }
    try out.appendSlice(testing.allocator, h3_frame.writeHeader(.headers, block.len, &head));
    try out.appendSlice(testing.allocator, block);

    var body_at: usize = 0;
    while (body_at < reply.body.len) {
        const take = @min(reply.data_chunk, reply.body.len - body_at);
        try out.appendSlice(testing.allocator, h3_frame.writeHeader(.data, take, &head));
        try out.appendSlice(testing.allocator, reply.body[body_at..][0..take]);
        body_at += take;
    }

    if (reply.trailers.len != 0) {
        const trailer_block = try zurl_qpack.encoder.encodeAlloc(testing.allocator, reply.trailers, .{});
        defer testing.allocator.free(trailer_block);
        try out.appendSlice(testing.allocator, h3_frame.writeHeader(.headers, trailer_block.len, &head));
        try out.appendSlice(testing.allocator, trailer_block);
    }

    try sendStream(c, slot.id, out.items, !reply.cut_body);
}

// ---------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------

fn flush(c: *Conn, script: []const Response) !void {
    _ = script;
    // The handshake, once the whole ClientHello has arrived.
    if (!c.hello_sent and c.hello_end > 4) {
        const body_len = (@as(usize, c.hello[1]) << 16) | (@as(usize, c.hello[2]) << 8) | c.hello[3];
        if (4 + body_len <= c.hello_end) {
            c.hello_sent = true;
            var hello_out: Buf(1024) = .{};
            const server_hello = try c.tls.serverHello(c.hello[0 .. 4 + body_len], &hello_out);
            try sendCrypto(c, .initial, server_hello);

            const keys: schedule.Pair = c.tls.traffic;
            c.handshake_read = schedule.keys(c.tls.suite, &keys.client);
            c.handshake_write = schedule.keys(c.tls.suite, &keys.server);

            var flight_out: Buf(4096) = .{};
            const flight = try c.tls.flight(&flight_out);
            try sendCrypto(c, .handshake, flight);

            c.application_read = schedule.keys(c.tls.suite, &c.tls.application.client);
            c.application_write = schedule.keys(c.tls.suite, &c.tls.application.server);
        }
    }

    if (c.application_write != null and !c.handshake_done_sent) {
        c.handshake_done_sent = true;
        try sendFrames(c, .application, &.{.{ .handshake_done = {} }});
        try openControlStreams(c);
    }

    // An acknowledgment for every space that has something to acknowledge.
    for ([_]protection.Level{ .initial, .handshake, .application }) |level| {
        const space = spaceOf(level);
        if (!c.ack_pending[space]) continue;
        if (writeKeys(c, level) == null) continue;
        const largest = c.largest_recv[space] orelse continue;
        c.ack_pending[space] = false;
        try sendFrames(c, level, &.{.{
            .ack = .{
                .largest_acknowledged = largest,
                .ack_delay = 0,
                .ack_range_count = 0,
                // One range, from zero to the largest. A loopback path drops
                // nothing, so there is no gap to report.
                .first_ack_range = largest,
                .ranges = &.{},
                .ecn = null,
            },
        }});
    }
}

/// Opens this side's control stream and writes the `SETTINGS` frame.
fn openControlStreams(c: *Conn) !void {
    if (c.control_opened) return;
    c.control_opened = true;
    const options = c.server.options;

    var payload: [128]u8 = undefined;
    var head: [h3_frame.max_header_bytes]u8 = undefined;

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);

    var prefix: [zurl_h3.stream_type.max_bytes]u8 = undefined;
    try out.appendSlice(testing.allocator, zurl_h3.stream_type.write(.control, &prefix));

    if (!options.skip_settings) {
        const body = zurl_h3.settings.encode(options.settings, &payload);
        try out.appendSlice(testing.allocator, h3_frame.writeHeader(.settings, body.len, &head));
        try out.appendSlice(testing.allocator, body);
    }
    if (options.grease_control_frame) |length| {
        // RFC 9114 section 7.2.8: `0x1f * N + 0x21` is a type a peer
        // sends on purpose. The payload is a run of one byte, because
        // nothing reads it.
        try out.appendSlice(testing.allocator, h3_frame.writeHeader(@enumFromInt(0x21), length, &head));
        try out.appendNTimes(testing.allocator, 0x5a, length);
    }
    if (options.goaway) |id| {
        var goaway: [h3_frame.max_header_bytes + varint_max_bytes]u8 = undefined;
        try out.appendSlice(testing.allocator, h3_frame.writeSingleVarint(.goaway, id, &goaway));
    }
    try sendStream(c, try nextUni(c), out.items, options.close_control_stream);

    if (options.duplicate_control_stream) {
        var second: [8]u8 = undefined;
        const again = zurl_h3.stream_type.write(.control, &second);
        try sendStream(c, try nextUni(c), again, false);
    }
    if (options.grease_stream) {
        var greased: [16]u8 = undefined;
        const written = zurl_h3.stream_type.write(@enumFromInt(0x21), &greased);
        try sendStream(c, try nextUni(c), written, false);
    }
    if (options.split_grease_stream) {
        // `0x1f * 529 + 0x21` is 16432, which needs the four byte varint
        // form, and its bytes are `80 00 40 30`. Each one goes in a
        // datagram of its own, so the client reads the type in four
        // steps.
        var greased: [16]u8 = undefined;
        const written = zurl_h3.stream_type.write(@enumFromInt(0x1f * 529 + 0x21), &greased);
        std.debug.assert(written.len == 4);
        try sendStreamByteByByte(c, try nextUni(c), written);
    }

    // The two QPACK streams. This fixture inserts nothing, so both carry
    // their type prefix and nothing else. RFC 9204 section 4.2.
    var qpack_prefix: [8]u8 = undefined;
    try sendStream(c, try nextUni(c), zurl_h3.stream_type.write(.qpack_encoder, &qpack_prefix), false);
    try sendStream(c, try nextUni(c), zurl_h3.stream_type.write(.qpack_decoder, &qpack_prefix), false);
}

fn nextUni(c: *Conn) !u64 {
    const id = try quic.stream.makeId(.server, .unidirectional, c.next_uni);
    c.next_uni += 1;
    return id;
}

fn writeKeys(c: *Conn, level: protection.Level) ?protection.Keys {
    return switch (level) {
        .initial => quic.initial.serverKeys(c.tls.original_connection_id.slice()),
        .handshake => c.handshake_write,
        .application => c.application_write,
        .zero_rtt => null,
    };
}

/// Splits `bytes` into CRYPTO frames that each fit one packet.
fn sendCrypto(c: *Conn, level: protection.Level, bytes: []const u8) !void {
    const chunk = 900;
    var at: usize = 0;
    while (at < bytes.len) {
        const take = @min(chunk, bytes.len - at);
        try sendFrames(c, level, &.{.{ .crypto = .{ .offset = at, .data = bytes[at..][0..take] } }});
        at += take;
    }
}

/// Splits `bytes` into `STREAM` frames that each fit one packet.
fn sendStream(c: *Conn, id: u64, bytes: []const u8, fin: bool) !void {
    const chunk = 900;
    var at: usize = 0;
    while (true) {
        const take = @min(chunk, bytes.len - at);
        const last = at + take == bytes.len;
        try sendFrames(c, .application, &.{.{ .stream = .{
            .stream_id = id,
            .offset = at,
            .data = bytes[at..][0..take],
            .fin = fin and last,
            .explicit_offset = true,
            .explicit_length = true,
        } }});
        at += take;
        if (last) break;
    }
}

/// Sends `bytes` as one `STREAM` frame for each octet, each in its own
/// datagram.
///
/// **This is what makes a split varint visible.** The client reads one
/// datagram at a time, so a type that arrives this way is offered to the
/// client's reader one byte at a time as well.
fn sendStreamByteByByte(c: *Conn, id: u64, bytes: []const u8) !void {
    for (bytes, 0..) |_, at| {
        try sendFrames(c, .application, &.{.{ .stream = .{
            .stream_id = id,
            .offset = at,
            .data = bytes[at..][0..1],
            .fin = false,
            .explicit_offset = true,
            .explicit_length = true,
        } }});
    }
}

/// Builds one packet holding `frames` and sends it.
fn sendFrames(c: *Conn, level: protection.Level, frames: []const frame.Frame) !void {
    const keys = writeKeys(c, level) orelse return;
    const space = spaceOf(level);
    const number = c.next_number[space];
    c.next_number[space] += 1;

    var payload: [datagram_len]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&payload);
    for (frames) |f| try frame.encode(f, &writer);
    var body = writer.buffered();

    // RFC 9001 section 5.4.2: the header protection sample runs from four
    // bytes past the start of the packet number and is sixteen bytes long,
    // so the packet number, the payload, and the AEAD tag together must
    // reach twenty bytes. A `HANDSHAKE_DONE` frame alone is one byte, so
    // the padding below is what makes such a packet protectable at all.
    const sample_floor = header_protection.sample_gap + header_protection.sample_len;
    if (1 + body.len + protection.tag_len < sample_floor) {
        const want = sample_floor - protection.tag_len - 1 - body.len;
        @memset(payload[body.len..][0..want], 0x00);
        body = payload[0 .. body.len + want];
    }

    var datagram: [datagram_len]u8 = undefined;
    const pn_len = packet.encodedPacketNumberLen(number, null);
    const header_len = writeHeader(c, level, &datagram, number, pn_len, body.len);
    if (header_len + body.len + protection.tag_len > datagram.len) return;
    keys.seal(datagram[header_len..][0 .. body.len + protection.tag_len], body, datagram[0..header_len], number);
    const total = header_len + body.len + protection.tag_len;
    try header_protection.apply(datagram[0..total], header_len - pn_len, &keys);
    body = &.{};

    c.server.socket.send(testing.io, &c.peer, datagram[0..total]) catch {};
}

fn writeHeader(
    c: *Conn,
    level: protection.Level,
    out: []u8,
    number: u64,
    pn_len: u3,
    body_len: usize,
) usize {
    const quic_engine = @import("quic.zig");
    return quic_engine.writeHeaderInto(.{
        .level = level,
        .out = out,
        .dcid = c.dcid,
        .scid = c.scid,
        .number = number,
        .pn_len = pn_len,
        .body_len = body_len,
    });
}

test "the fixture's certificate names the host a test connects to" {
    // The certificate carries one commonName and no subject alternative
    // name, so a client that verifies the host reaches the RFC 6125
    // section 6.4.4 fallback and finds this name.
    var server: Tls = try .init(
        try packet.ConnectionId.init(&.{ 1, 2, 3, 4 }),
        try packet.ConnectionId.init(&.{ 5, 6, 7, 8 }),
    );
    try testing.expect(server.certificate.len > 0);
    try testing.expect(std.mem.indexOf(u8, server.certificate.slice(), host_name) != null);
}
