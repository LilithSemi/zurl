//! HPACK string literal coding, RFC 7541 section 5.2.
//!
//! A string literal is a length with an H flag in front of it and then the
//! octets, raw or Huffman coded. This file owns that shape. It owns
//! nothing above it: it does not know whether the string it reads is a
//! name or a value.
//!
//! **A decode reads untrusted bytes.** The length comes from the peer, so
//! it can name more octets than the block holds, and Huffman text expands
//! by up to eight fifths. Every decode therefore takes a bound and refuses
//! to write past it. The caller sets the bound because only the caller
//! knows what budget is left.

const std = @import("std");

const huffman = @import("huffman.zig");
const integer = @import("integer.zig");

const Allocator = std.mem.Allocator;

/// The prefix the length of a string literal uses. The bit above it is the
/// H flag.
const length_prefix_bits = 7;

/// The H flag, RFC 7541 section 5.2. Set means the octets are Huffman
/// coded.
const huffman_flag: u8 = 0x80;

pub const DecodeError = integer.Error || huffman.DecodeError || error{
    /// The string is longer than the bound the caller gave.
    StringTooLong,
};

/// One decoded string and the octets of the block it used.
pub const Decoded = struct {
    /// Allocated from the `gpa` the decode was given. The caller owns it.
    text: []u8,
    len: usize,
};

/// Reads the string literal at the front of `bytes`.
///
/// `out_len_max` bounds the decoded text. A raw string longer than it is
/// refused before anything is allocated, and a Huffman string that reaches
/// it stops there. Either way the answer is `error.StringTooLong`, and
/// either way this function allocates no more than `out_len_max` octets.
pub fn decode(gpa: Allocator, bytes: []const u8, out_len_max: usize) DecodeError!Decoded {
    if (bytes.len == 0) return error.Truncated;
    const huffman_coded = bytes[0] & huffman_flag != 0;

    const length = try integer.decode(length_prefix_bits, bytes);
    const end = std.math.add(usize, length.len, length.value) catch return error.Truncated;
    if (end > bytes.len) return error.Truncated;
    const octets = bytes[length.len..end];

    if (huffman_coded) {
        return .{ .text = try huffman.decode(gpa, octets, out_len_max), .len = end };
    }
    if (octets.len > out_len_max) return error.StringTooLong;
    return .{ .text = try gpa.dupe(u8, octets), .len = end };
}

/// Which of the two forms an encode writes.
pub const Coding = enum {
    /// Always raw, whatever it costs. This is what makes an encoded block
    /// readable in a packet capture.
    raw,
    /// Huffman coded when that is shorter, and raw when it is not. RFC
    /// 7541 lets an encoder pick per string, and a decoder reads either.
    huffman_when_shorter,

    fn huffmanFor(self: Coding, text: []const u8) bool {
        return switch (self) {
            .raw => false,
            .huffman_when_shorter => huffman.encodedLen(text) < text.len,
        };
    }
};

/// The number of octets `encode` writes for `text`.
///
/// `text` must be shorter than `integer.value_max`, because its length
/// goes on the wire as an HPACK integer. A header field of four gigabytes
/// is the caller's mistake, so this is an assert.
pub fn encodedLen(text: []const u8, coding: Coding) usize {
    std.debug.assert(text.len <= integer.value_max);
    const octets = if (coding.huffmanFor(text)) huffman.encodedLen(text) else text.len;
    return integer.encodedLen(length_prefix_bits, @intCast(octets)) + octets;
}

/// Writes `text` as a string literal into the front of `out`, and returns
/// the octets it used.
///
/// `out` must hold at least `encodedLen(text, coding)` octets, which is
/// the caller's to get right and so is an assert.
pub fn encode(text: []const u8, coding: Coding, out: []u8) []u8 {
    std.debug.assert(out.len >= encodedLen(text, coding));

    const use_huffman = coding.huffmanFor(text);
    const octets = if (use_huffman) huffman.encodedLen(text) else text.len;
    const flag: u8 = if (use_huffman) huffman_flag else 0;

    // The length goes into a scratch buffer first. `integer.encode` needs
    // room for the widest integer it can write, and `out` is allowed to be
    // exactly `encodedLen` long, which for a short string is less.
    var length_buffer: [integer.encoded_len_max]u8 = undefined;
    const header = integer.encode(length_prefix_bits, flag, @intCast(octets), &length_buffer);
    @memcpy(out[0..header.len], header);

    const body = out[header.len..][0..octets];
    if (use_huffman) {
        _ = huffman.encode(text, body);
    } else {
        @memcpy(body, text);
    }
    return out[0 .. header.len + octets];
}

const testing = std.testing;

test "RFC 7541 C.2.1, a raw literal name carries its length in front" {
    const bytes = [_]u8{ 0x0a, 'c', 'u', 's', 't', 'o', 'm', '-', 'k', 'e', 'y' };
    const got = try decode(testing.allocator, &bytes, 64);
    defer testing.allocator.free(got.text);

    try testing.expectEqualStrings("custom-key", got.text);
    try testing.expectEqual(@as(usize, bytes.len), got.len);

    var out: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, &bytes, encode("custom-key", .raw, &out));
}

test "RFC 7541 C.4.1, a Huffman literal sets the H flag and shortens the string" {
    const bytes = [_]u8{
        0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
    };
    const got = try decode(testing.allocator, &bytes, 64);
    defer testing.allocator.free(got.text);

    try testing.expectEqualStrings("www.example.com", got.text);
    try testing.expectEqual(@as(usize, bytes.len), got.len);

    var out: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, &bytes, encode("www.example.com", .huffman_when_shorter, &out));
}

test "an empty string is one octet in either coding" {
    var out: [8]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{0x00}, encode("", .raw, &out));
    try testing.expectEqualSlices(u8, &.{0x00}, encode("", .huffman_when_shorter, &out));

    const got = try decode(testing.allocator, &.{0x00}, 64);
    defer testing.allocator.free(got.text);
    try testing.expectEqualStrings("", got.text);
    try testing.expectEqual(@as(usize, 1), got.len);
}

test "a string Huffman coding cannot shorten goes out raw" {
    // Every octet above 127 is at least 19 bits, so this text is longer
    // Huffman coded than it is raw.
    const dense = [_]u8{ 0x80, 0x81, 0x82, 0x83 };
    var out: [64]u8 = undefined;
    const written = encode(&dense, .huffman_when_shorter, &out);

    try testing.expectEqual(@as(u8, 0x04), written[0]);
    try testing.expectEqualSlices(u8, &dense, written[1..]);
}

test "a string longer than 126 octets needs a continuation on its length" {
    const text = "a" ** 300;
    var out: [512]u8 = undefined;
    const written = encode(text, .raw, &out);
    try testing.expectEqualSlices(u8, &.{ 0x7f, 0xad, 0x01 }, written[0..3]);

    const got = try decode(testing.allocator, written, 1024);
    defer testing.allocator.free(got.text);
    try testing.expectEqualStrings(text, got.text);
}

test "a spread of strings round-trips through both codings" {
    const cases = [_][]const u8{
        "",
        "a",
        "/",
        ":method",
        "www.example.com",
        "Mon, 21 Oct 2013 20:13:21 GMT",
        "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
        "\x00\x01\x02\xfe\xff",
    };
    var out: [512]u8 = undefined;
    for (cases) |text| {
        inline for ([_]Coding{ .raw, .huffman_when_shorter }) |coding| {
            const written = encode(text, coding, &out);
            try testing.expectEqual(encodedLen(text, coding), written.len);

            const got = try decode(testing.allocator, written, 1024);
            defer testing.allocator.free(got.text);
            try testing.expectEqualStrings(text, got.text);
            try testing.expectEqual(written.len, got.len);
        }
    }
}

test "a length that runs past the block is truncated, not read past" {
    // Says twenty octets and gives three.
    try testing.expectError(error.Truncated, decode(testing.allocator, &.{ 0x14, 'a', 'b', 'c' }, 64));
    try testing.expectError(error.Truncated, decode(testing.allocator, &.{}, 64));
    try testing.expectError(error.Truncated, decode(testing.allocator, &.{0x7f}, 64));
}

test "a length larger than this build holds is refused before it is used" {
    // 0x7f then five continuation octets that add up past 2^32.
    try testing.expectError(
        error.IntegerOverflow,
        decode(testing.allocator, &.{ 0x7f, 0xff, 0xff, 0xff, 0xff, 0x7f }, 64),
    );
}

test "a raw string past the bound is refused before it is allocated" {
    const bytes = [_]u8{ 0x0a, 'c', 'u', 's', 't', 'o', 'm', '-', 'k', 'e', 'y' };
    try testing.expectError(error.StringTooLong, decode(testing.allocator, &bytes, 9));

    const got = try decode(testing.allocator, &bytes, 10);
    defer testing.allocator.free(got.text);
    try testing.expectEqualStrings("custom-key", got.text);
}

test "a Huffman string that expands past the bound is refused" {
    // 0x83 is three Huffman octets. Twenty of the bits are four codes for
    // "0", and the last four are the pad.
    const bytes = [_]u8{ 0x83, 0x00, 0x00, 0x0f };
    try testing.expectError(error.StringTooLong, decode(testing.allocator, &bytes, 2));

    const got = try decode(testing.allocator, &bytes, 4);
    defer testing.allocator.free(got.text);
    try testing.expectEqualStrings("0000", got.text);
}

test "a Huffman fault reaches the caller with the RFC's own name" {
    // 0x84 then four octets of ones is the EOS symbol inside a string.
    try testing.expectError(
        error.HuffmanEosSymbol,
        decode(testing.allocator, &.{ 0x84, 0xff, 0xff, 0xff, 0xff }, 64),
    );
    // 0x81 then five bits of "0" and three bits that are not all ones.
    try testing.expectError(
        error.HuffmanPadInvalid,
        decode(testing.allocator, &.{ 0x81, 0b00000_110 }, 64),
    );
}
