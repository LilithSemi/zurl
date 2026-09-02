//! Appendix A of RFC 9001, checked byte for byte.
//!
//! **This file is the difference between code that looks right and code
//! that is right.** Every other file in this package tests its own rules
//! against its own reading of the RFC. This one takes the packets the RFC
//! printed and builds them again from nothing but a connection id, then
//! compares all 1200 bytes.
//!
//! It covers the five parts of the appendix:
//!
//! - **A.1**, the Initial secrets and the six keys under them.
//! - **A.2**, the client Initial packet: the CRYPTO frame, the padding
//!   to 1162 bytes, the AEAD seal, the header protection sample, the
//!   mask, and the 1200 protected bytes.
//! - **A.3**, the server Initial packet, the same way round, and then the
//!   receiving direction: header protection off, packet number decoded,
//!   payload opened, and the frames read back.
//! - **A.4**, the Retry integrity tag.
//! - **A.5**, the ChaCha20-Poly1305 short header packet, which lives in
//!   `protection.zig` beside the suite it tests.
//!
//! The vectors are held as hexadecimal text and read at run time, because
//! a wall of `0x` bytes cannot be compared against the RFC by eye and
//! this can.
//!
//! Nothing here touches the network. Every byte is in this file.

const std = @import("std");

const frame = @import("frame.zig");
const header_protection = @import("header_protection.zig");
const initial = @import("initial.zig");
const packet = @import("packet.zig");
const protection = @import("protection.zig");

const testing = std.testing;

/// The Destination Connection ID the whole appendix uses.
const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

test "RFC 9001 appendix A.1: the Initial secrets and the six keys under them" {
    // The extract comes first, because both directions share it.
    try expectHex(
        "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44",
        &initial.extractSecret(&dcid),
    );

    const s = initial.secrets(&dcid);
    try expectHex(
        "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
        &s.client,
    );
    try expectHex(
        "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
        &s.server,
    );

    const client = initial.clientKeys(&dcid);
    try expectHex("1f369613dd76d5467730efcbe3b1a22d", client.keySlice());
    try expectHex("fa044b2f42a3fd3b46fb255c", &client.iv);
    try expectHex("9f50449e04a0e810283a1e9933adedd2", client.headerKeySlice());

    const server = initial.serverKeys(&dcid);
    try expectHex("cf3a5331653c364c88f0f379b6067e37", server.keySlice());
    try expectHex("0ac1493ca1905853b0bba03e", &server.iv);
    try expectHex("c206b8d9b9f0f37644430b490eeaa314", server.headerKeySlice());
}

/// The CRYPTO frame of appendix A.2, which is the client's ClientHello.
const a2_crypto_frame =
    \\060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868
    \\04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578
    \\616d706c652e636f6dff01000100000a00080006001d00170018001000070005
    \\04616c706e000500050100000000003300260024001d00209370b2c9caa47fba
    \\baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400
    \\0d0010000e0403050306030203080408050806002d00020101001c0002400100
    \\3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000
    \\75300901100f088394c8f03e51570806048000ffff
;

/// The 1200 protected bytes of appendix A.2.
const a2_protected =
    \\c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11
    \\d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399
    \\1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c
    \\8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212
    \\30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5
    \\457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208
    \\4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec
    \\4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3
    \\485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db
    \\059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c
    \\7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8
    \\9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556
    \\be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74
    \\68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a
    \\c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00
    \\f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632
    \\291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964
    \\25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd
    \\14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff
    \\ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198
    \\e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd
    \\c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73
    \\203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f
    \\cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e
    \\fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade
    \\a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047
    \\90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2
    \\162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4
    \\40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0
    \\6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e
    \\8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0
    \\be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400
    \\54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab
    \\760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9
    \\f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4
    \\056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064
    \\7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241
    \\e221af44860018ab0856972e194cd934
;

/// The unprotected header of appendix A.2. The Length is 1182: four
/// bytes of packet number, 1162 of frames, and a 16-byte tag.
const a2_header = "c300000001088394c8f03e5157080000449e00000002";

/// How many bytes of frames the client Initial payload holds. The RFC
/// pads to this on purpose, so the datagram reaches 1200.
const a2_payload_len: usize = 1162;

test "RFC 9001 appendix A.2: the client Initial packet builds byte for byte" {
    // **The whole packet, from a connection id and a ClientHello.** The
    // header, the padding, the AEAD, the sample, the mask, and 1200
    // bytes that must match the RFC exactly.
    var crypto_buffer: [512]u8 = undefined;
    const crypto_frame = try fromHex(&crypto_buffer, a2_crypto_frame);
    try testing.expectEqual(@as(usize, 245), crypto_frame.len);

    // The payload is the CRYPTO frame with PADDING after it. A zero byte
    // is a PADDING frame, so the buffer starts zeroed.
    var payload: [a2_payload_len]u8 = @splat(0x00);
    @memcpy(payload[0..crypto_frame.len], crypto_frame);

    // The frames read back as the CRYPTO frame and one padding run.
    {
        var d: frame.Decoder = .init(&payload);
        const c = (try d.next()).?.crypto;
        try testing.expectEqual(@as(u64, 0), c.offset);
        try testing.expectEqual(@as(usize, 241), c.data.len);
        // The ClientHello starts with handshake type 1 and its length.
        try testing.expectEqual(@as(u8, 0x01), c.data[0]);
        try testing.expectEqual(
            @as(usize, a2_payload_len - crypto_frame.len),
            (try d.next()).?.padding,
        );
        try testing.expectEqual(@as(?frame.Frame, null), try d.next());
    }

    var header_buffer: [64]u8 = undefined;
    const header = try fromHex(&header_buffer, a2_header);
    try testing.expectEqual(@as(usize, 22), header.len);

    // The header parses into the fields the RFC names.
    var datagram: [1200]u8 = @splat(0);
    @memcpy(datagram[0..header.len], header);
    const parsed = try packet.parseLong(&datagram);
    try testing.expectEqual(@as(u64, 1182), parsed.body.initial.length);
    try testing.expectEqual(@as(usize, 18), parsed.pn_offset);
    try testing.expectEqualSlices(u8, &dcid, parsed.dcid.slice());
    const pn_len = packet.packetNumberLen(parsed.first_byte);
    try testing.expectEqual(@as(u3, 4), pn_len);
    try testing.expectEqual(@as(u32, 2), try packet.readPacketNumber(datagram[18..], pn_len));

    // The associated data is every byte to the end of the packet number.
    const keys = initial.clientKeys(&dcid);
    keys.seal(datagram[header.len..], &payload, header, 2);

    // The sample is the first 16 bytes of the protected payload, because
    // the packet number is four bytes long.
    const sample = try header_protection.sample(&datagram, parsed.pn_offset);
    try expectHex("d1b1c98dd7689fb8ec11d242b123dc9b", sample);
    try expectHex("437b9aec36", &keys.headerMask(sample));

    // The mask covers the low four bits of the first byte and the four
    // packet number bytes, so `c3...00000002` becomes `c0...7b9aec34`.
    try header_protection.apply(&datagram, parsed.pn_offset, &keys);
    try expectHex("c000000001088394c8f03e5157080000449e7b9aec34", datagram[0..22]);

    var want: [1200]u8 = undefined;
    try testing.expectEqualSlices(u8, try fromHex(&want, a2_protected), &datagram);
}

test "RFC 9001 appendix A.2: the client Initial packet reads back the way it was built" {
    // The receiving direction over the same 1200 bytes. A server takes
    // header protection off, decodes the packet number, opens the
    // payload, and reads the frames.
    var datagram: [1200]u8 = undefined;
    _ = try fromHex(&datagram, a2_protected);

    const parsed = try packet.parseLong(&datagram);
    try testing.expectEqualSlices(u8, &dcid, parsed.dcid.slice());
    try testing.expectEqual(@as(u64, 1182), parsed.body.initial.length);

    const keys = initial.clientKeys(parsed.dcid.slice());
    const pn_len = try header_protection.remove(&datagram, parsed.pn_offset, &keys);
    try testing.expectEqual(@as(u3, 4), pn_len);
    try expectHex("c300000001088394c8f03e5157080000449e00000002", datagram[0..22]);

    // Nothing has been received yet, so the largest is zero and the
    // truncated 2 decodes to 2.
    const truncated = try packet.readPacketNumber(datagram[parsed.pn_offset..], pn_len);
    const pn = packet.decodePacketNumber(0, truncated, @as(u6, pn_len) * 8);
    try testing.expectEqual(@as(u64, 2), pn);

    const aad = datagram[0 .. parsed.pn_offset + pn_len];
    const sealed = datagram[parsed.pn_offset + pn_len ..][0 .. @as(usize, @intCast(parsed.body.initial.length)) - pn_len];
    var payload: [a2_payload_len]u8 = undefined;
    try testing.expectEqual(a2_payload_len, try keys.open(&payload, sealed, aad, pn));

    var crypto_buffer: [512]u8 = undefined;
    const crypto_frame = try fromHex(&crypto_buffer, a2_crypto_frame);
    try testing.expectEqualSlices(u8, crypto_frame[4..], payload[4..crypto_frame.len]);

    var d: frame.Decoder = .init(&payload);
    const c = (try d.next()).?.crypto;
    try testing.expectEqual(@as(usize, 241), c.data.len);
    try testing.expect((try d.next()).?.padding > 900);
    try testing.expectEqual(@as(?frame.Frame, null), try d.next());
}

/// The server's unprotected payload of appendix A.3: an ACK frame and a
/// CRYPTO frame, and no padding.
const a3_payload =
    \\02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739
    \\88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94
    \\0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00
    \\020304
;

/// The 135 protected bytes of appendix A.3.
const a3_protected =
    \\cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a
    \\5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3
    \\dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84
    \\022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4
    \\2158407dd074ee
;

/// The unprotected header of appendix A.3. A new connection id and a
/// 2-byte packet number of 1.
const a3_header = "c1000000010008f067a5502a4262b50040750001";

test "RFC 9001 appendix A.3: the server Initial packet builds byte for byte" {
    var payload_buffer: [256]u8 = undefined;
    const payload = try fromHex(&payload_buffer, a3_payload);
    try testing.expectEqual(@as(usize, 99), payload.len);

    var header_buffer: [64]u8 = undefined;
    const header = try fromHex(&header_buffer, a3_header);
    try testing.expectEqual(@as(usize, 20), header.len);

    var datagram: [135]u8 = @splat(0);
    @memcpy(datagram[0..header.len], header);
    const parsed = try packet.parseLong(&datagram);
    // 2 bytes of packet number, 99 of frames, and a 16-byte tag.
    try testing.expectEqual(@as(u64, 117), parsed.body.initial.length);
    try testing.expectEqual(@as(usize, 18), parsed.pn_offset);
    try testing.expectEqual(@as(u8, 0), parsed.dcid.len);
    try expectHex("f067a5502a4262b5", parsed.scid.slice());

    const keys = initial.serverKeys(&dcid);
    keys.seal(datagram[header.len..], payload, header, 1);

    // The packet number is two bytes, so two bytes of ciphertext sit
    // between it and the sample.
    const sample = try header_protection.sample(&datagram, parsed.pn_offset);
    try expectHex("2cd0991cd25b0aac406a5816b6394100", sample);
    try expectHex("2ec0d8356a", &keys.headerMask(sample));

    // The appendix prints the protected header, so `c1...0001` becomes
    // `cf...c0d9`.
    try header_protection.apply(&datagram, parsed.pn_offset, &keys);
    try expectHex("cf000000010008f067a5502a4262b5004075c0d9", datagram[0..20]);

    var want: [135]u8 = undefined;
    try testing.expectEqualSlices(u8, try fromHex(&want, a3_protected), &datagram);
}

test "RFC 9001 appendix A.3: the server Initial packet opens and its frames read back" {
    var datagram: [135]u8 = undefined;
    _ = try fromHex(&datagram, a3_protected);

    const parsed = try packet.parseLong(&datagram);
    const keys = initial.serverKeys(&dcid);
    const pn_len = try header_protection.remove(&datagram, parsed.pn_offset, &keys);
    try testing.expectEqual(@as(u3, 2), pn_len);

    const truncated = try packet.readPacketNumber(datagram[parsed.pn_offset..], pn_len);
    const pn = packet.decodePacketNumber(0, truncated, @as(u6, pn_len) * 8);
    try testing.expectEqual(@as(u64, 1), pn);

    const aad = datagram[0 .. parsed.pn_offset + pn_len];
    const sealed = datagram[parsed.pn_offset + pn_len ..];
    var payload: [99]u8 = undefined;
    try testing.expectEqual(@as(usize, 99), try keys.open(&payload, sealed, aad, pn));

    var want: [256]u8 = undefined;
    try testing.expectEqualSlices(u8, try fromHex(&want, a3_payload), &payload);

    // **The frames the appendix names in words**: an ACK frame, a CRYPTO
    // frame, and no padding at all.
    var d: frame.Decoder = .init(&payload);
    const ack = (try d.next()).?.ack;
    try testing.expectEqual(@as(u64, 0), ack.largest_acknowledged);
    try testing.expectEqual(@as(u64, 0), ack.ack_range_count);
    var it = ack.iterator();
    try testing.expectEqualDeep(frame.Range{ .largest = 0, .smallest = 0 }, (try it.next()).?);
    try testing.expectEqual(@as(?frame.Range, null), try it.next());

    const c = (try d.next()).?.crypto;
    try testing.expectEqual(@as(u64, 0), c.offset);
    try testing.expectEqual(@as(usize, 90), c.data.len);
    // A ServerHello is handshake type 2.
    try testing.expectEqual(@as(u8, 0x02), c.data[0]);

    try testing.expectEqual(@as(?frame.Frame, null), try d.next());
}

/// The Retry packet of appendix A.4, tag included.
const a4_retry = "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba";

test "RFC 9001 appendix A.4: the Retry integrity tag matches the packet the RFC printed" {
    var buffer: [64]u8 = undefined;
    const retry = try fromHex(&buffer, a4_retry);

    const parsed = try packet.parseLong(retry);
    try testing.expectEqual(packet.LongType.retry, @as(packet.LongType, parsed.body));
    try testing.expectEqualStrings("token", parsed.body.retry.token);
    try expectHex("f067a5502a4262b5", parsed.scid.slice());

    // The original connection id is in the tag and not in the packet.
    const split = retry.len - packet.retry_integrity_tag_len;
    const tag = try initial.retryIntegrityTag(&dcid, retry[0..split]);
    try expectHex("04a265ba2eff4d829058fb3f0f2496ba", &tag);
    try testing.expect(try initial.verifyRetry(&dcid, retry));

    // **A Retry checked against another connection id must not pass.**
    // That check is what stops anyone on the path restarting a
    // handshake with a connection id of their own choosing.
    try testing.expect(!try initial.verifyRetry(&.{ 1, 2, 3, 4, 5, 6, 7, 8 }, retry));

    // And one byte changed anywhere in the packet breaks the tag.
    var broken: [36]u8 = undefined;
    @memcpy(&broken, retry);
    broken[16] ^= 0x01;
    try testing.expect(!try initial.verifyRetry(&dcid, &broken));
}

/// Reads a run of hexadecimal text into `out`, ignoring newlines.
///
/// The vectors are text so a reader can compare them against the RFC by
/// eye, which is the only way a 1200-byte vector gets checked at all.
fn fromHex(out: []u8, text: []const u8) ![]u8 {
    var at: usize = 0;
    var high: ?u8 = null;
    for (text) |char| {
        if (char == '\n' or char == ' ') continue;
        const nibble = try std.fmt.charToDigit(char, 16);
        if (high) |top| {
            if (at == out.len) return error.NoRoom;
            out[at] = (top << 4) | nibble;
            at += 1;
            high = null;
        } else {
            high = nibble;
        }
    }
    if (high != null) return error.OddLength;
    return out[0..at];
}

/// Checks `bytes` against a lowercase hexadecimal string.
fn expectHex(expected: []const u8, bytes: []const u8) !void {
    var buffer: [128]u8 = undefined;
    std.debug.assert(bytes.len * 2 <= buffer.len);
    try testing.expectEqualStrings(
        expected,
        try std.fmt.bufPrint(&buffer, "{x}", .{bytes}),
    );
}

test "the hexadecimal reader this file uses reads what it was given" {
    // The vectors depend on this, so it is checked rather than assumed.
    var out: [4]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, try fromHex(&out, "deadbeef"));
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad }, try fromHex(&out, "de\nad"));
    try testing.expectError(error.OddLength, fromHex(&out, "abc"));
    var small: [1]u8 = undefined;
    try testing.expectError(error.NoRoom, fromHex(&small, "aabb"));
    try testing.expectError(error.InvalidCharacter, fromHex(&out, "zz"));
}
