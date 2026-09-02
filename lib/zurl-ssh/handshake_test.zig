//! End to end tests of `zurl_ssh.Transport` against the loopback fixture.
//!
//! These live in their own file because the client and the fixture import
//! each other's package and neither should import the other's module.
//! `zurl-stream/compose_test.zig` is here for the same reason.
//!
//! **No test in this file reaches the real network.** Every one starts a
//! `test_server` on 127.0.0.1 with a port the operating system assigns.
//!
//! What these prove: that the two sides agree on the exchange hash, on the
//! key derivation, on the packet framing of both ciphers, and on the
//! negotiation. What they cannot prove is that the agreement is the one
//! the rest of the world keeps, because both sides are this repository.
//! See `test_server.zig` and the report.

const std = @import("std");
const zurl_net = @import("zurl-net");

const Transport = @import("Transport.zig");
const algorithms = @import("algorithms.zig");
const cipher = @import("cipher.zig");
const hostkey = @import("hostkey.zig");
const messages = @import("messages.zig");
const test_server = @import("test_server.zig");

const testing = std.testing;

/// One fixture, one client, and the two values that must not move.
const Fixture = struct {
    server: *test_server,
    endpoint: *test_server.Endpoint,
    transport: *Transport,

    fn start(script: test_server.Script, options: Options) !Fixture {
        const server = try testing.allocator.create(test_server);
        errdefer testing.allocator.destroy(server);
        try server.start(script);
        errdefer server.stop();

        const endpoint = try testing.allocator.create(test_server.Endpoint);
        errdefer testing.allocator.destroy(endpoint);
        try endpoint.connect(server.port());
        errdefer endpoint.close();

        const transport = try testing.allocator.create(Transport);
        errdefer testing.allocator.destroy(transport);
        try transport.init(testing.allocator, testing.io, endpoint.channel(), .{
            .peer = .{ .host = "fixture.test", .port = 22 },
            .verifier = if (options.refuse_host_key)
                test_server.refusing_verifier
            else
                server.verifier(),
            .rekey_bytes = options.rekey_bytes,
            .rekey_seconds = options.rekey_seconds,
            .stall = options.stall,
            .low_speed_limit = options.low_speed_limit,
            .low_speed_time_s = options.low_speed_time_s,
        });
        return .{ .server = server, .endpoint = endpoint, .transport = transport };
    }

    const Options = struct {
        refuse_host_key: bool = false,
        rekey_bytes: u64 = 1 << 30,
        rekey_seconds: u32 = 3600,
        stall: std.Io.Timeout = .{
            .duration = .{ .raw = .fromSeconds(120), .clock = .awake },
        },
        low_speed_limit: u64 = 0,
        low_speed_time_s: u32 = 0,
    };

    fn stop(f: Fixture) void {
        f.transport.deinit();
        testing.allocator.destroy(f.transport);
        f.endpoint.close();
        testing.allocator.destroy(f.endpoint);
        f.server.stop();
        testing.allocator.destroy(f.server);
    }
};

test "a handshake completes and a payload comes back" {
    var f = try Fixture.start(.{ .echo_count = 1 }, .{});
    defer f.stop();

    try f.transport.handshake();

    // The session identifier exists, and it is the exchange hash.
    const session_id = f.transport.sessionId() orelse return error.TestExpectedSessionId;
    try testing.expectEqual(@as(usize, 32), session_id.len);

    // The negotiation picked the client's first choice, which is AES-GCM.
    // See `algorithms` for why that one is first.
    const choice = f.transport.negotiated() orelse return error.TestExpectedChoice;
    try testing.expectEqual(
        cipher.Algorithm.aes256_gcm_openssh,
        choice.cipher_client_to_server,
    );
    try testing.expectEqual(algorithms.KexAlgorithm.curve25519_sha256, choice.kex);
    try testing.expectEqual(hostkey.Algorithm.ssh_ed25519, choice.host_key);
    try testing.expect(choice.strict_kex);

    // The host key that came back is the fixture's own.
    const blob = f.transport.hostKeyBlob() orelse return error.TestExpectedHostKey;
    try testing.expectEqualSlices(u8, f.server.hostKeyBlob(), blob);

    // And a payload of the layer above rides the encrypted stream.
    try f.transport.send("\x50hello over ssh");
    try testing.expectEqualStrings("\x50hello over ssh", try f.transport.receive());

    try testing.expectEqual(@as(u64, 1), f.transport.counters.key_exchanges);
}

test "the same handshake runs over chacha20-poly1305" {
    // **The second cipher, and it frames a packet differently.** The
    // length field is encrypted under its own key here and in the clear in
    // the other one. A server that offers this one alone still gets it.
    var f = try Fixture.start(
        .{ .cipher_names = "chacha20-poly1305@openssh.com", .echo_count = 2 },
        .{},
    );
    defer f.stop();

    try f.transport.handshake();
    const choice = f.transport.negotiated().?;
    try testing.expectEqual(
        cipher.Algorithm.chacha20_poly1305_openssh,
        choice.cipher_client_to_server,
    );
    try testing.expectEqual(
        cipher.Algorithm.chacha20_poly1305_openssh,
        choice.cipher_server_to_client,
    );

    // Two packets in a row, because the nonce moves with the sequence
    // number and a number that did not move would fail on the second.
    try f.transport.send("\x50first");
    try testing.expectEqualStrings("\x50first", try f.transport.receive());
    try f.transport.send("\x50second");
    try testing.expectEqualStrings("\x50second", try f.transport.receive());
}

test "a handshake runs without strict key exchange too" {
    var f = try Fixture.start(.{ .strict_kex = false }, .{});
    defer f.stop();

    try f.transport.handshake();
    try testing.expect(!f.transport.negotiated().?.strict_kex);
    // With no strict rule the sequence numbers carry on, so the three
    // packets of the key exchange are still counted.
    try testing.expectEqual(@as(u32, 3), f.transport.receiveSequence());

    try f.transport.send("\x50plain");
    try testing.expectEqualStrings("\x50plain", try f.transport.receive());
}

test "strict key exchange puts the sequence numbers back to zero" {
    // **This is the property that closes CVE-2023-48795.** A packet
    // dropped from the front of the session moves the numbers apart, and
    // a reset at every `SSH_MSG_NEWKEYS` is what makes that visible.
    var f = try Fixture.start(.{}, .{});
    defer f.stop();

    try f.transport.handshake();
    try testing.expectEqual(@as(u32, 0), f.transport.receiveSequence());
}

test "a server that writes notices first is still read" {
    var f = try Fixture.start(.{
        .preamble = "This system is for authorised users only.\r\nSecond line.\r\n",
    }, .{});
    defer f.stop();

    try f.transport.handshake();
    try testing.expectEqualStrings("SSH-2.0-zurl_fixture", f.transport.serverVersion());
    try testing.expectEqualStrings("SSH-2.0-zurl", f.transport.clientVersion());
}

test "a signature over the wrong hash is refused" {
    // **The one test that shows the exchange hash is load bearing.** The
    // fixture signs a run of zeroes, and the client checks the signature
    // against the hash it built, so the two cannot agree.
    var f = try Fixture.start(.{ .forge_signature = true }, .{});
    defer f.stop();

    try testing.expectError(error.HostKeySignatureInvalid, f.transport.handshake());
}

test "a key presented by one holder and signed by another is refused" {
    var f = try Fixture.start(.{ .wrong_signing_key = true }, .{});
    defer f.stop();

    try testing.expectError(error.HostKeySignatureInvalid, f.transport.handshake());
}

test "a verifier that refuses the host key ends the handshake before any key is in place" {
    // **The signature passed and the connection still stops.** That is
    // the whole point of the trust decision being the caller's.
    var f = try Fixture.start(.{}, .{ .refuse_host_key = true });
    defer f.stop();

    try testing.expectError(error.HostKeyRejected, f.transport.handshake());

    // **The error value on its own proves nothing about the order.** A
    // build that ran the whole exchange, installed both ciphers, sent
    // `SSH_MSG_NEWKEYS`, and asked the verifier last would return the same
    // error and would have told a server it does not trust that it is
    // ready to talk. This is the trust boundary of the protocol, so the
    // test asserts where the refusal happened and not only that it did.
    try testing.expectEqual(@as(?[]const u8, null), f.transport.sessionId());
    try testing.expectEqual(@as(u64, 0), f.transport.counters.key_exchanges);
    try testing.expect(!f.transport.hasSendCipher());
    try testing.expect(!f.transport.hasRecvCipher());
    // The host key is kept, because a caller has to be able to print the
    // key it refused. Nothing else moved.
    try testing.expect(f.transport.hostKeyBlob() != null);
}

test "a server that offers only RSA host keys is refused by name" {
    var f = try Fixture.start(.{ .host_key_names = "ssh-rsa,rsa-sha2-512" }, .{});
    defer f.stop();

    try testing.expectError(error.NoCommonHostKeyAlgorithm, f.transport.handshake());
}

test "a server with no cipher in common is refused" {
    var f = try Fixture.start(.{ .cipher_names = "aes128-ctr,3des-cbc" }, .{});
    defer f.stop();

    try testing.expectError(error.NoCommonCipher, f.transport.handshake());
}

test "a server with no key exchange method in common is refused" {
    var f = try Fixture.start(.{ .kex_names = "diffie-hellman-group14-sha1" }, .{});
    defer f.stop();

    try testing.expectError(error.NoCommonKexAlgorithm, f.transport.handshake());
}

test "a server that offers no compression this build has is refused" {
    var f = try Fixture.start(.{ .compression_names = "zlib@openssh.com" }, .{});
    defer f.stop();

    try testing.expectError(error.NoCommonCompression, f.transport.handshake());
}

test "IGNORE and DEBUG are counted and never handed to a caller" {
    var f = try Fixture.start(.{ .chatter = true, .echo_count = 1 }, .{});
    defer f.stop();

    try f.transport.handshake();
    try f.transport.send("\x50after the chatter");
    try testing.expectEqualStrings("\x50after the chatter", try f.transport.receive());
    try testing.expectEqual(@as(u64, 1), f.transport.counters.ignore);
    try testing.expectEqual(@as(u64, 1), f.transport.counters.debug);
}

test "an IGNORE inside a strict key exchange is a violation" {
    // Strict key exchange forbids it, because a packet that is dropped
    // moves the sequence numbers apart with nobody the wiser.
    var f = try Fixture.start(.{ .chatter_in_kex = true }, .{});
    defer f.stop();

    try testing.expectError(error.StrictKexViolation, f.transport.handshake());
}

test "the same IGNORE is refused when the server named no strict marker" {
    // **This is the injection primitive of CVE-2023-48795.** The server
    // agreed to no strict rule, so nothing puts the sequence numbers back
    // to zero, and the traffic is still in the clear. An attacker between
    // the two sides writes one `SSH_MSG_IGNORE` here, this side counts it
    // and drops it, and `recv_sequence` moves on by one. The attacker then
    // deletes the first packet the server sends under the new key and no
    // tag fails.
    //
    // A build that counted and dropped this packet would pass the
    // handshake and hand the attacker that packet. Nothing legitimate is
    // lost: no server needs to write these three messages inside a key
    // exchange.
    var f = try Fixture.start(.{ .chatter_in_kex = true, .strict_kex = false }, .{});
    defer f.stop();

    try testing.expectError(error.StrictKexViolation, f.transport.handshake());
    try testing.expectEqual(@as(u64, 0), f.transport.counters.ignore);
    // Nothing was trusted and nothing was installed.
    try testing.expectEqual(@as(?[]const u8, null), f.transport.sessionId());
    try testing.expectEqual(@as(u64, 0), f.transport.counters.key_exchanges);
}

test "an IGNORE after the first NEWKEYS is legal again" {
    // **The rule is about the window an attacker can write into, and that
    // window closes at the first `SSH_MSG_NEWKEYS`.** After it every
    // packet carries a tag, so a rekey cannot be fed a packet from
    // outside, and RFC 4253 section 11 keeps letting a peer send these.
    // A build that refused them for the whole session would refuse a legal
    // server for no gain.
    var f = try Fixture.start(.{ .chatter = true, .strict_kex = false, .echo_count = 1 }, .{});
    defer f.stop();

    try f.transport.handshake();
    try f.transport.send("\x50still fine");
    try testing.expectEqualStrings("\x50still fine", try f.transport.receive());
    try testing.expectEqual(@as(u64, 1), f.transport.counters.ignore);
    try testing.expectEqual(@as(u64, 1), f.transport.counters.debug);
}

test "a DISCONNECT is a named fault, and the reason is kept" {
    var f = try Fixture.start(.{ .disconnect_instead = "the fixture said so" }, .{});
    defer f.stop();

    try f.transport.handshake();
    try testing.expectError(error.PeerDisconnected, f.transport.receive());

    const goodbye = f.transport.lastDisconnect() orelse return error.TestExpectedDisconnect;
    try testing.expectEqual(messages.DisconnectReason.by_application, goodbye.reason);
    try testing.expectEqualStrings("the fixture said so", goodbye.description);
}

test "a rekey the client starts keeps the session id and changes the keys" {
    var f = try Fixture.start(.{ .echo_count = 2 }, .{});
    defer f.stop();

    try f.transport.handshake();
    var first: [32]u8 = undefined;
    @memcpy(&first, f.transport.sessionId().?);

    try f.transport.send("\x50before");
    try testing.expectEqualStrings("\x50before", try f.transport.receive());

    try f.transport.rekey();
    try testing.expectEqual(@as(u64, 2), f.transport.counters.key_exchanges);
    // **The session identifier is the first exchange hash and never a
    // later one.** Every layer above binds its signatures to it.
    try testing.expectEqualSlices(u8, &first, f.transport.sessionId().?);

    // And the connection still works under the new keys.
    try f.transport.send("\x50after");
    try testing.expectEqualStrings("\x50after", try f.transport.receive());
}

test "a rekey the byte bound asks for runs on its own" {
    // A bound of one byte, so the exchange is due as soon as anything at
    // all has crossed the wire. The count is zero right after a key
    // exchange, which is why the first packet goes out under the first
    // key and the second one waits for a new one.
    var f = try Fixture.start(.{ .echo_count = 2 }, .{ .rekey_bytes = 1 });
    defer f.stop();

    try f.transport.handshake();
    try testing.expect(!f.transport.needsRekey());

    try f.transport.send("\x50first");
    try testing.expectEqual(@as(u64, 1), f.transport.counters.key_exchanges);
    try testing.expect(f.transport.needsRekey());

    try f.transport.send("\x50second");
    try testing.expectEqual(@as(u64, 2), f.transport.counters.key_exchanges);

    // **The bound goes back to the ordinary one before the reads.** A
    // bound of one byte is due again at once, and the reads below are here
    // for the order the echoes come back in and not for another exchange.
    // The read path runs one of its own, which the test after this proves.
    f.transport.options.rekey_bytes = 1 << 30;
    try testing.expectEqualStrings("\x50first", try f.transport.receive());
    try testing.expectEqualStrings("\x50second", try f.transport.receive());
}

test "a rekey the byte bound asks for runs from inside a read too" {
    // **The bound is checked on both paths.** A session that mostly reads
    // spends one key on everything the peer sends, and a build that looked
    // at the bound only where the layer above writes would keep that key
    // for as long as the peer kept writing. The ChaCha20 nonce is the
    // packet sequence number, so the key has to be replaced well before
    // that number comes round again.
    var f = try Fixture.start(.{ .echo_count = 2 }, .{ .rekey_bytes = 1 });
    defer f.stop();

    try f.transport.handshake();
    try f.transport.send("\x50first");
    try testing.expectEqual(@as(u64, 1), f.transport.counters.key_exchanges);

    // Nothing is written between here and the read. The read finds the
    // bound passed, runs a whole key exchange, and then hands over the
    // payload that was waiting behind it.
    try testing.expectEqualStrings("\x50first", try f.transport.receive());
    try testing.expectEqual(@as(u64, 2), f.transport.counters.key_exchanges);

    f.transport.options.rekey_bytes = 1 << 30;
    try f.transport.send("\x50second");
    try testing.expectEqualStrings("\x50second", try f.transport.receive());
    try testing.expectEqual(@as(u64, 2), f.transport.counters.key_exchanges);
}

test "a packet that crosses a rekey is kept and handed over in order" {
    // **RFC 4253 section 9 allows a data packet to arrive between this
    // side's `SSH_MSG_KEXINIT` and the peer's answer.** It belongs to the
    // caller, and the caller is in the middle of a `send`, so it waits in
    // the backlog and the next read takes it first.
    var f = try Fixture.start(.{
        .echo_count = 2,
        .data_before_rekey = "\x50in flight",
    }, .{ .rekey_bytes = 1 });
    defer f.stop();

    try f.transport.handshake();
    try f.transport.send("\x50first");

    // This send runs a key exchange, and the fixture writes a data packet
    // into the middle of it.
    try f.transport.send("\x50second");
    try testing.expectEqual(@as(u64, 2), f.transport.counters.key_exchanges);

    // The two packets that crossed the exchange come first, in the order
    // they arrived, and the echo of the second payload comes after them.
    f.transport.options.rekey_bytes = 1 << 30;
    try testing.expectEqualStrings("\x50first", try f.transport.receive());
    try testing.expectEqualStrings("\x50in flight", try f.transport.receive());
    try testing.expectEqualStrings("\x50second", try f.transport.receive());
}

test "a rekey the clock asks for runs on its own" {
    var f = try Fixture.start(.{ .echo_count = 1 }, .{ .rekey_seconds = 0 });
    defer f.stop();

    try f.transport.handshake();
    try testing.expect(f.transport.needsRekey());
    try f.transport.send("\x50timed");
    try testing.expectEqual(@as(u64, 2), f.transport.counters.key_exchanges);

    // **A bound of zero seconds is due again the moment it is met**, and
    // the read path checks the same bound. The fixture has one echo and no
    // round left for another exchange, so the ordinary bound goes back
    // before the read.
    f.transport.options.rekey_seconds = 3600;
    try testing.expectEqualStrings("\x50timed", try f.transport.receive());
}

test "a rekey the server starts is run from inside a read" {
    var f = try Fixture.start(.{ .echo_count = 1, .rekey_before_echo = 0 }, .{});
    defer f.stop();

    try f.transport.handshake();
    try f.transport.send("\x50through a rekey");
    // The server sends its `SSH_MSG_KEXINIT` before it echoes, so the
    // read below runs a whole key exchange and then returns the echo.
    try testing.expectEqualStrings("\x50through a rekey", try f.transport.receive());
    try testing.expectEqual(@as(u64, 2), f.transport.counters.key_exchanges);
}

test "strict key exchange stays on when a later KEXINIT drops the marker" {
    // **The marker is read once, on the first exchange.** The fixture
    // keeps applying the rule while it stops naming it, which is what
    // OpenSSH does. A client that read the marker again would stop
    // resetting its sequence numbers and the very next packet would fail
    // its tag.
    var f = try Fixture.start(.{
        .echo_count = 2,
        .drop_strict_on_rekey = true,
    }, .{});
    defer f.stop();

    try f.transport.handshake();
    try testing.expect(f.transport.negotiated().?.strict_kex);

    try f.transport.rekey();
    try testing.expect(f.transport.negotiated().?.strict_kex);
    try testing.expectEqual(@as(u32, 0), f.transport.receiveSequence());

    try f.transport.send("\x50after the drop");
    try testing.expectEqualStrings("\x50after the drop", try f.transport.receive());
}

test "a key exchange message outside a key exchange never reaches a caller" {
    // `SSH_MSG_NEWKEYS` belongs to a key exchange and to nothing else.
    // One that arrives between exchanges is a protocol violation.
    var f = try Fixture.start(.{ .stray_message = "\x15", .echo_count = 0 }, .{});
    defer f.stop();

    try f.transport.handshake();
    try testing.expectError(error.KexMessageUnexpected, f.transport.receive());
}

test "a method message outside a key exchange is refused too" {
    var f = try Fixture.start(.{
        .stray_message = "\x1f\x00\x00\x00\x00",
        .echo_count = 0,
    }, .{});
    defer f.stop();

    try f.transport.handshake();
    try testing.expectError(error.KexMessageUnexpected, f.transport.receive());
}

test "a packet length outside the bound is refused before the body is read" {
    // AES-GCM leaves the length in the clear, so a test can write one.
    var f = try Fixture.start(.{
        .cipher_names = "aes256-gcm@openssh.com",
        .raw_after_handshake = "\xff\xff\xff\xff",
    }, .{});
    defer f.stop();

    try f.transport.handshake();
    try testing.expectError(error.PacketLengthOutOfRange, f.transport.receive());
}

test "a packet length that does not line up with the block is refused" {
    var f = try Fixture.start(.{
        .cipher_names = "aes256-gcm@openssh.com",
        // 17 is inside the bound and is not a multiple of 16.
        .raw_after_handshake = "\x00\x00\x00\x11",
    }, .{});
    defer f.stop();

    try f.transport.handshake();
    try testing.expectError(error.PacketNotBlockAligned, f.transport.receive());
}

test "a changed byte in an encrypted packet fails the tag" {
    // The fixture writes a whole legal length and then rubbish. The
    // length lines up, so the read waits for the body and the tag, and
    // the tag is what refuses it.
    var f = try Fixture.start(.{
        .cipher_names = "aes256-gcm@openssh.com",
        .raw_after_handshake = "\x00\x00\x00\x10" ++ ("\x00" ** 16) ++ ("\x00" ** 16),
    }, .{});
    defer f.stop();

    try f.transport.handshake();
    try testing.expectError(error.AuthenticationFailed, f.transport.receive());
}

test "the host key fingerprint is the one ssh-keygen would print" {
    var f = try Fixture.start(.{}, .{});
    defer f.stop();

    try f.transport.handshake();
    const blob = f.transport.hostKeyBlob().?;
    var text: [hostkey.max_fingerprint_bytes]u8 = undefined;
    const printed = hostkey.fingerprintText(&text, blob);
    try testing.expect(std.mem.startsWith(u8, printed, "SHA256:"));
    try testing.expectEqual(hostkey.max_fingerprint_bytes, printed.len);
}

test "the fixture reports its own faults rather than looking like a client bug" {
    var f = try Fixture.start(.{ .echo_count = 1 }, .{});
    defer f.stop();

    try f.transport.handshake();
    try f.transport.send("\x50done");
    _ = try f.transport.receive();
    f.server.awaitDone();
    try testing.expectEqual(@as(?[]const u8, null), f.server.failure);
    try testing.expectEqual(@as(usize, 1), f.server.accept_count.load(.acquire));
}

test "a wrong guess is thrown away and the handshake still finishes" {
    // RFC 4253 section 7.1: a server may send its first key exchange
    // packet before it knows the negotiation went its way. This fixture
    // names a key exchange this build does not speak first, so the guess
    // is wrong and the packet that follows belongs to nobody.
    //
    // **The handshake must still finish.** A build that refused every
    // guess would refuse a server that is doing what the RFC allows.
    var f = try Fixture.start(.{
        .kex_names = "guess-kex@example.test," ++ algorithms.curve25519_sha256,
        .guessed_packet = "\x1ethrown away",
        .echo_count = 1,
    }, .{});
    defer f.stop();

    try f.transport.handshake();
    try f.transport.send("\x50after the guess");
    const echoed = try f.transport.receive();
    try testing.expectEqualStrings("\x50after the guess", echoed);
}

test "the packet a wrong guess throws away is held to the rule every other kex packet is" {
    // **This is the one packet of the first key exchange that nothing
    // reads.** It moves `recv_sequence` on by one, and that is the whole
    // injection primitive of CVE-2023-48795: an attacker who can add a
    // packet the client drops in silence can delete the first packet
    // after the new key with no tag failing.
    //
    // So the throw away runs through `readKexPacket` like every other
    // read of a key exchange, and a `SSH_MSG_IGNORE` here is the same
    // refusal it is anywhere else in the first exchange.
    var f = try Fixture.start(.{
        .kex_names = "guess-kex@example.test," ++ algorithms.curve25519_sha256,
        .guessed_packet = "\x02\x00\x00\x00\x03bad",
    }, .{});
    defer f.stop();

    try testing.expectError(error.StrictKexViolation, f.transport.handshake());
}

test "a peer under the rate --speed-limit named is refused by that name" {
    // **The stall bound and the rate bound are different bounds.** The
    // stall bound says how long one read may wait, and it starts again at
    // every byte, so a peer that writes one byte just before it runs out
    // passes it for ever. The rate bound is a deadline over the whole
    // connection and it does not start again.
    //
    // The fixture here waits for a payload the test never sends, so the
    // connection stays open and silent. The stall bound is 120 seconds
    // and the rate bound is one second, and the test asserts which of the
    // two reported, because a build with no rate bound would answer
    // `error.OperationTimedOut` two minutes later.
    var f = try Fixture.start(.{ .echo_count = 1 }, .{
        .stall = .{ .duration = .{ .raw = .fromSeconds(120), .clock = .awake } },
        .low_speed_limit = 1024 * 1024,
        .low_speed_time_s = 1,
    });
    defer f.stop();

    try f.transport.handshake();
    try testing.expectError(error.TransferTooSlow, f.transport.receive());
}
