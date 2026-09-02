//! The string literal of RFC 9204 section 4.1.2.
//!
//! A string literal is an H flag, then a length, then the octets, raw or
//! Huffman coded. This file owns that shape. It owns nothing above it: it
//! does not know whether the string it reads is a name or a value.
//!
//! **The QPACK string literal can start part way through an octet.** RFC
//! 7541 puts the H flag at the top of a whole octet and the length in a
//! seven bit prefix under it. RFC 9204 keeps that shape but lets the
//! representation above it take the top bits first: an "N-bit prefix
//! string literal" gives the top `8 - N` bits to the representation, one
//! bit to the H flag, and an `N - 1` bit prefix to the length. N runs from
//! 2 to 8, and an 8-bit prefix string literal is HPACK's own. That is why
//! this file restates the coder rather than sharing
//! `zurl-hpack/string.zig`, which knows only the 8-bit form.
//!
//! **A decode reads untrusted bytes.** The length comes from the peer, so
//! it can name more octets than the section holds, and Huffman text
//! expands by up to eight fifths. Every decode therefore takes a bound and
//! refuses to write past it. The caller sets the bound because only the
//! caller knows what budget is left.

const std = @import("std");

const huffman = @import("huffman.zig");
const integer = @import("integer.zig");

const Allocator = std.mem.Allocator;

pub const DecodeError = integer.Error || huffman.DecodeError || error{
    /// The string is longer than the bound the caller gave.
    StringTooLong,
};

/// One decoded string and the octets of the section it used.
pub const Decoded = struct {
    /// Allocated from the `gpa` the decode was given. The caller owns it.
    text: []u8,
    len: usize,
};

/// The H flag of a `prefix_bits`-bit prefix string literal, RFC 9204
/// section 4.1.2.
pub fn huffmanFlag(comptime prefix_bits: u4) u8 {
    comptime checkPrefix(prefix_bits);
    return @as(u8, 1) << @as(u3, @intCast(prefix_bits - 1));
}

/// Reads the string literal at the front of `bytes`.
///
/// `prefix_bits` is N, the width the representation above left for this
/// string. The bits above the prefix in the first octet are ignored.
///
/// `out_len_max` bounds the decoded text. A raw string longer than it is
/// refused before anything is allocated, and a Huffman string that reaches
/// it stops there. Either way the answer is `error.StringTooLong`, and
/// either way this function allocates no more than `out_len_max` octets.
///
/// The bound is checked against the length the peer declared, before the
/// octets of the string have to arrive. So a length no bound can hold is
/// `error.StringTooLong` at the first octet and never `error.Truncated`.
pub fn decode(
    comptime prefix_bits: u4,
    gpa: Allocator,
    bytes: []const u8,
    out_len_max: usize,
) DecodeError!Decoded {
    comptime checkPrefix(prefix_bits);
    const flag = comptime huffmanFlag(prefix_bits);

    if (bytes.len == 0) return error.Truncated;
    const huffman_coded = bytes[0] & flag != 0;

    const length = try integer.decode(prefix_bits - 1, bytes);

    // The bound is checked before the truncation check on purpose. A
    // declared length that can never fit `out_len_max` is a fault at the
    // first octet, not a wait. The other order lets a peer name a length
    // no bound can hold and then send one octet at a time, and a caller
    // that re-reads a part instruction from its start pays the whole
    // decode again for each of those octets.
    const out_len_min = if (huffman_coded) huffman.minDecodedLen(length.value) else length.value;
    if (out_len_min > @as(u64, out_len_max)) return error.StringTooLong;

    // The length is a 62 bit number the peer chose, so it is widened to
    // `usize` only after it has been checked against the octets that
    // really arrived.
    if (length.value > bytes.len - length.len) return error.Truncated;
    const octets = bytes[length.len..][0..@intCast(length.value)];
    const end = length.len + octets.len;

    if (huffman_coded) {
        return .{ .text = try huffman.decode(gpa, octets, out_len_max), .len = end };
    }
    if (octets.len > out_len_max) return error.StringTooLong;
    return .{ .text = try gpa.dupe(u8, octets), .len = end };
}

/// Which of the two forms an encode writes.
pub const Coding = enum {
    /// Always raw, whatever it costs. This is what makes an encoded field
    /// section readable in a packet capture.
    raw,
    /// Huffman coded when that is shorter, and raw when it is not. RFC
    /// 9204 lets an encoder pick per string, and a decoder reads either.
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
/// goes on the wire as a prefixed integer. A field line of four exabytes
/// is the caller's mistake, so this is an assert.
pub fn encodedLen(comptime prefix_bits: u4, text: []const u8, coding: Coding) usize {
    comptime checkPrefix(prefix_bits);
    std.debug.assert(text.len <= integer.value_max);
    const octets = if (coding.huffmanFor(text)) huffman.encodedLen(text) else text.len;
    return integer.encodedLen(prefix_bits - 1, octets) + octets;
}

/// Writes `text` as a string literal into the front of `out`, and returns
/// the octets it used.
///
/// `high_bits` is what the representation above put in the top `8 -
/// prefix_bits` bits. It must carry no bit inside the H flag or the
/// length, and `out` must hold at least `encodedLen(prefix_bits, text,
/// coding)` octets. Both are the caller's to get right, so both are
/// asserts.
pub fn encode(
    comptime prefix_bits: u4,
    high_bits: u8,
    text: []const u8,
    coding: Coding,
    out: []u8,
) []u8 {
    comptime checkPrefix(prefix_bits);
    const flag = comptime huffmanFlag(prefix_bits);
    std.debug.assert(out.len >= encodedLen(prefix_bits, text, coding));
    std.debug.assert(high_bits & (flag | (flag - 1)) == 0);

    const use_huffman = coding.huffmanFor(text);
    const octets = if (use_huffman) huffman.encodedLen(text) else text.len;
    const pattern: u8 = if (use_huffman) high_bits | flag else high_bits;

    // The length goes into a scratch buffer first. `integer.encode` needs
    // room for the widest integer it can write, and `out` is allowed to be
    // exactly `encodedLen` long, which for a short string is less.
    var length_buffer: [integer.encoded_len_max]u8 = undefined;
    const header = integer.encode(prefix_bits - 1, pattern, octets, &length_buffer);
    @memcpy(out[0..header.len], header);

    const body = out[header.len..][0..octets];
    if (use_huffman) {
        _ = huffman.encode(text, body);
    } else {
        @memcpy(body, text);
    }
    return out[0 .. header.len + octets];
}

/// RFC 9204 section 4.1.2: "The prefix size, N, can have a value between 2
/// and 8, inclusive."
fn checkPrefix(comptime prefix_bits: u4) void {
    comptime {
        if (prefix_bits < 2 or prefix_bits > 8) {
            @compileError("a qpack string literal prefix is 2 to 8 bits, RFC 9204 section 4.1.2");
        }
    }
}

const testing = std.testing;

test "an 8-bit prefix string literal is the HPACK one, flag and all" {
    try testing.expectEqual(@as(u8, 0x80), huffmanFlag(8));

    const bytes = [_]u8{ 0x0a, 'c', 'u', 's', 't', 'o', 'm', '-', 'k', 'e', 'y' };
    const got = try decode(8, testing.allocator, &bytes, 64);
    defer testing.allocator.free(got.text);

    try testing.expectEqualStrings("custom-key", got.text);
    try testing.expectEqual(@as(usize, bytes.len), got.len);

    var out: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, &bytes, encode(8, 0, "custom-key", .raw, &out));
}

test "RFC 9204 B.3, a 6-bit prefix name in an insert with literal name" {
    // 0x4a is the '01' pattern of the instruction, H = 0, and a length of
    // ten in the five bits under the flag.
    try testing.expectEqual(@as(u8, 0x20), huffmanFlag(6));

    const bytes = [_]u8{ 0x4a, 'c', 'u', 's', 't', 'o', 'm', '-', 'k', 'e', 'y' };
    const got = try decode(6, testing.allocator, &bytes, 64);
    defer testing.allocator.free(got.text);

    try testing.expectEqualStrings("custom-key", got.text);
    try testing.expectEqual(@as(usize, bytes.len), got.len);

    var out: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, &bytes, encode(6, 0x40, "custom-key", .raw, &out));
}

test "a 4-bit prefix name in a literal field line with literal name" {
    // RFC 9204 section 4.5.6: '001', the N bit, then a 4-bit prefix string
    // literal. So H sits at bit 3 and the length has three bits under it.
    try testing.expectEqual(@as(u8, 0x08), huffmanFlag(4));

    var out: [64]u8 = undefined;
    const written = encode(4, 0x20, ":method", .raw, &out);
    // A length of seven fills the three bits, so it needs one more octet.
    try testing.expectEqualSlices(u8, &.{ 0x27, 0x00 }, written[0..2]);
    try testing.expectEqualStrings(":method", written[2..]);

    const got = try decode(4, testing.allocator, written, 64);
    defer testing.allocator.free(got.text);
    try testing.expectEqualStrings(":method", got.text);
    try testing.expectEqual(@as(usize, written.len), got.len);
}

test "a 3-bit length prefix that fills up carries the length on into more octets" {
    // A 4-bit prefix string literal holds a length of at most six in its
    // own bits, because all ones means "read on".
    var out: [512]u8 = undefined;
    try testing.expectEqualSlices(
        u8,
        &.{ 0x26, 'a', 'b', 'c', 'd', 'e', 'f' },
        encode(4, 0x20, "abcdef", .raw, &out),
    );
    try testing.expectEqualSlices(u8, &.{ 0x27, 0x00 }, encode(4, 0x20, "abcdefg", .raw, &out)[0..2]);
    try testing.expectEqualSlices(u8, &.{ 0x27, 0x01 }, encode(4, 0x20, "abcdefgh", .raw, &out)[0..2]);

    const longer = encode(4, 0x20, "a" ** 300, .raw, &out);
    try testing.expectEqualSlices(u8, &.{ 0x27, 0xa5, 0x02 }, longer[0..3]);

    const got = try decode(4, testing.allocator, longer, 512);
    defer testing.allocator.free(got.text);
    try testing.expectEqualStrings("a" ** 300, got.text);
}

test "a Huffman literal sets the H flag wherever the flag sits" {
    var out: [64]u8 = undefined;

    const wide = encode(8, 0, "www.example.com", .huffman_when_shorter, &out);
    try testing.expectEqual(@as(u8, 0x8c), wide[0]);

    var narrow_out: [64]u8 = undefined;
    const narrow = encode(6, 0x40, "www.example.com", .huffman_when_shorter, &narrow_out);
    try testing.expectEqual(@as(u8, 0x6c), narrow[0]);
    try testing.expectEqualSlices(u8, wide[1..], narrow[1..]);

    const got = try decode(6, testing.allocator, narrow, 64);
    defer testing.allocator.free(got.text);
    try testing.expectEqualStrings("www.example.com", got.text);
}

test "an empty string is one octet in either coding and at every prefix width" {
    var out: [8]u8 = undefined;
    inline for ([_]u4{ 2, 3, 4, 5, 6, 7, 8 }) |bits| {
        try testing.expectEqualSlices(u8, &.{0x00}, encode(bits, 0, "", .raw, &out));
        try testing.expectEqualSlices(u8, &.{0x00}, encode(bits, 0, "", .huffman_when_shorter, &out));

        const got = try decode(bits, testing.allocator, &.{0x00}, 64);
        defer testing.allocator.free(got.text);
        try testing.expectEqualStrings("", got.text);
        try testing.expectEqual(@as(usize, 1), got.len);
    }
}

test "a string Huffman coding cannot shorten goes out raw" {
    // Every octet above 127 is at least 19 bits, so this text is longer
    // Huffman coded than it is raw.
    const dense = [_]u8{ 0x80, 0x81, 0x82, 0x83 };
    var out: [64]u8 = undefined;
    const written = encode(8, 0, &dense, .huffman_when_shorter, &out);

    try testing.expectEqual(@as(u8, 0x04), written[0]);
    try testing.expectEqualSlices(u8, &dense, written[1..]);
}

test "a spread of strings round-trips at every prefix width and both codings" {
    const cases = [_][]const u8{
        "",
        "a",
        "/",
        ":method",
        "www.example.com",
        "Mon, 21 Oct 2013 20:13:21 GMT",
        "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
        "\x00\x01\x02\xfe\xff",
        "a" ** 300,
    };
    var out: [1024]u8 = undefined;
    for (cases) |text| {
        inline for ([_]u4{ 2, 3, 4, 5, 6, 7, 8 }) |bits| {
            inline for ([_]Coding{ .raw, .huffman_when_shorter }) |coding| {
                const written = encode(bits, 0, text, coding, &out);
                try testing.expectEqual(encodedLen(bits, text, coding), written.len);

                const got = try decode(bits, testing.allocator, written, 1024);
                defer testing.allocator.free(got.text);
                try testing.expectEqualStrings(text, got.text);
                try testing.expectEqual(written.len, got.len);
            }
        }
    }
}

test "a length that runs past the section is truncated, not read past" {
    // Says twenty octets and gives three.
    try testing.expectError(
        error.Truncated,
        decode(8, testing.allocator, &.{ 0x14, 'a', 'b', 'c' }, 64),
    );
    try testing.expectError(error.Truncated, decode(8, testing.allocator, &.{}, 64));
    try testing.expectError(error.Truncated, decode(8, testing.allocator, &.{0x7f}, 64));
    try testing.expectError(error.Truncated, decode(4, testing.allocator, &.{0x07}, 64));
}

test "a length larger than this build holds is refused before it is used" {
    // 0x7f then nine continuation octets that carry 63 bits of ones.
    const over = [_]u8{0x7f} ++ [_]u8{0xff} ** 8 ++ [_]u8{0x7f};
    try testing.expectError(error.IntegerOverflow, decode(8, testing.allocator, &over, 64));
}

test "a raw string past the bound is refused before it is allocated" {
    const bytes = [_]u8{ 0x0a, 'c', 'u', 's', 't', 'o', 'm', '-', 'k', 'e', 'y' };
    try testing.expectError(error.StringTooLong, decode(8, testing.allocator, &bytes, 9));

    const got = try decode(8, testing.allocator, &bytes, 10);
    defer testing.allocator.free(got.text);
    try testing.expectEqualStrings("custom-key", got.text);
}

test "a Huffman string that expands past the bound is refused" {
    // 0x83 is three Huffman octets. Twenty of the bits are four codes for
    // "0", and the last four are the pad.
    const bytes = [_]u8{ 0x83, 0x00, 0x00, 0x0f };
    try testing.expectError(error.StringTooLong, decode(8, testing.allocator, &bytes, 2));

    const got = try decode(8, testing.allocator, &bytes, 4);
    defer testing.allocator.free(got.text);
    try testing.expectEqualStrings("0000", got.text);
}

test "a declared length no bound can hold is a fault before the octets arrive" {
    // A raw string that says it carries 20 octets, into a bound of 8, with
    // nothing after the header. The answer is the fault and not a wait,
    // because no octet that arrives later can make 20 fit in 8.
    try testing.expectError(
        error.StringTooLong,
        decode(8, testing.allocator, &.{0x14}, 8),
    );
    // The Huffman form of the same thing. The longest code in the table is
    // 30 bits, so 60000 octets cannot decode to fewer than 16000.
    const huffman_60000 = [_]u8{ 0xff, 0xe1, 0xd3, 0x03 };
    try testing.expectError(
        error.StringTooLong,
        decode(8, testing.allocator, &huffman_60000, 64),
    );
    // A Huffman length that could still fit is a wait, not a fault. Three
    // octets carry at most seventeen bits, which is one symbol at least
    // and three at most.
    try testing.expectError(
        error.Truncated,
        decode(8, testing.allocator, &.{0x83}, 1),
    );
}

test "a Huffman fault reaches the caller with the RFC's own name" {
    // 0x84 then four octets of ones is the EOS symbol inside a string.
    try testing.expectError(
        error.HuffmanEosSymbol,
        decode(8, testing.allocator, &.{ 0x84, 0xff, 0xff, 0xff, 0xff }, 64),
    );
    // 0x81 then five bits of "0" and three bits that are not all ones.
    try testing.expectError(
        error.HuffmanPadInvalid,
        decode(8, testing.allocator, &.{ 0x81, 0b00000_110 }, 64),
    );
    // 0x82 then a symbol and a whole octet of pad.
    try testing.expectError(
        error.HuffmanPadTooLong,
        decode(8, testing.allocator, &.{ 0x82, 0x07, 0xff }, 64),
    );
}
