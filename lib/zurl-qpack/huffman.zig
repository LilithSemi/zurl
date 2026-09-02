//! The Huffman code of RFC 7541 Appendix B, and the two directions that
//! use it.
//!
//! RFC 9204 section 4.1.2 says QPACK uses this table "without
//! modification", so the table here is the same 257 rows `zurl-hpack`
//! carries. It is restated and not imported, because this package imports
//! nothing else of ours and the two comptime proofs below make a wrong
//! copy a build failure rather than a wire fault.
//!
//! This file owns the code table and the bit packing. It owns nothing
//! above that: it does not know that a string has a length in front of it,
//! and it never looks at a table of header fields.
//!
//! **The table is checked when this file compiles.** `codes` is 257 rows
//! copied from the RFC, and a copied table is exactly the kind of thing a
//! transcription error hides in. The `comptime` block below proves two
//! facts about it, and a build that breaks either one fails with a
//! sentence saying which:
//!
//! - The code is complete. The Kraft sum over all 257 lengths is exactly
//!   one, so every bit pattern of 30 bits decodes to a symbol and no
//!   pattern decodes to two.
//! - The code is canonical. Every listed code equals the code that the
//!   lengths alone give that symbol. `decode` reads the lengths and not
//!   the codes, so this is what ties the two halves of the table together.
//!
//! **A decode reads untrusted bytes.** RFC 7541 section 5.2 names three
//! faults a peer can send, and each one gets its own error below: a pad
//! longer than seven bits, a pad that is not the top of the EOS code, and
//! the EOS symbol itself inside a string. A decode also takes a bound on
//! how much it writes, because Huffman text expands, and a peer chooses
//! how much.

const std = @import("std");

const Allocator = std.mem.Allocator;

/// One row of RFC 7541 Appendix B.
///
/// `code` is the Huffman code aligned on its least significant bit, which
/// is the "code as hex" column of the RFC table. `bits` is its length.
pub const Code = struct {
    code: u32,
    bits: u5,
};

/// The symbol RFC 7541 reserves to mark the end of a string.
///
/// It never appears inside a string a peer may send. `decode` refuses a
/// string that carries it, and `encode` never writes it: the pad at the
/// end of an encode is only the top bits of this code, never the whole of
/// it.
pub const eos_symbol: u16 = 256;

/// The 256 octet symbols and `eos_symbol`.
pub const symbol_count: usize = 257;

/// The shortest and the longest code in the table.
///
/// `bits_min` is what bounds how far Huffman text expands: five bits in
/// give at most one octet out, so a decode writes at most eight fifths of
/// what it reads.
pub const bits_min: u6 = 5;
pub const bits_max: u6 = 30;

/// The fewest octets a Huffman string of `encoded_len` octets can decode
/// to.
///
/// `bits_max` is the longest code in the table, so `encoded_len` octets
/// carry at least this many symbols. A caller uses it to refuse a declared
/// length that can never fit its bound, before the octets arrive and
/// before anything is allocated. The answer is a floor and never an
/// estimate: a string this function passes may still decode past the
/// bound, and `decode` is what catches that.
///
/// The arithmetic runs at 128 bits because `encoded_len` is a 62 bit
/// number the peer chose, and the multiply by eight would wrap a `u64`.
pub fn minDecodedLen(encoded_len: u64) u64 {
    if (encoded_len == 0) return 0;
    // The last octet holds at most seven bits of pad, so the string uses
    // at least one bit of it.
    const bits: u128 = (@as(u128, encoded_len) - 1) * 8 + 1;
    return @intCast((bits + bits_max - 1) / bits_max);
}

pub const DecodeError = error{
    /// More than seven bits of pad follow the last symbol, so the encoder
    /// left out a symbol that would have fit.
    HuffmanPadTooLong,
    /// The pad is not the leading bits of the EOS code.
    HuffmanPadInvalid,
    /// The string carries the EOS symbol.
    HuffmanEosSymbol,
    /// The decoded text reaches the bound the caller gave.
    StringTooLong,
    OutOfMemory,
};

/// RFC 7541 Appendix B, in symbol order.
pub const codes: [symbol_count]Code = .{
    .{ .code = 0x1ff8, .bits = 13 }, // (0)
    .{ .code = 0x7fffd8, .bits = 23 }, // (1)
    .{ .code = 0xfffffe2, .bits = 28 }, // (2)
    .{ .code = 0xfffffe3, .bits = 28 }, // (3)
    .{ .code = 0xfffffe4, .bits = 28 }, // (4)
    .{ .code = 0xfffffe5, .bits = 28 }, // (5)
    .{ .code = 0xfffffe6, .bits = 28 }, // (6)
    .{ .code = 0xfffffe7, .bits = 28 }, // (7)
    .{ .code = 0xfffffe8, .bits = 28 }, // (8)
    .{ .code = 0xffffea, .bits = 24 }, // (9)
    .{ .code = 0x3ffffffc, .bits = 30 }, // (10)
    .{ .code = 0xfffffe9, .bits = 28 }, // (11)
    .{ .code = 0xfffffea, .bits = 28 }, // (12)
    .{ .code = 0x3ffffffd, .bits = 30 }, // (13)
    .{ .code = 0xfffffeb, .bits = 28 }, // (14)
    .{ .code = 0xfffffec, .bits = 28 }, // (15)
    .{ .code = 0xfffffed, .bits = 28 }, // (16)
    .{ .code = 0xfffffee, .bits = 28 }, // (17)
    .{ .code = 0xfffffef, .bits = 28 }, // (18)
    .{ .code = 0xffffff0, .bits = 28 }, // (19)
    .{ .code = 0xffffff1, .bits = 28 }, // (20)
    .{ .code = 0xffffff2, .bits = 28 }, // (21)
    .{ .code = 0x3ffffffe, .bits = 30 }, // (22)
    .{ .code = 0xffffff3, .bits = 28 }, // (23)
    .{ .code = 0xffffff4, .bits = 28 }, // (24)
    .{ .code = 0xffffff5, .bits = 28 }, // (25)
    .{ .code = 0xffffff6, .bits = 28 }, // (26)
    .{ .code = 0xffffff7, .bits = 28 }, // (27)
    .{ .code = 0xffffff8, .bits = 28 }, // (28)
    .{ .code = 0xffffff9, .bits = 28 }, // (29)
    .{ .code = 0xffffffa, .bits = 28 }, // (30)
    .{ .code = 0xffffffb, .bits = 28 }, // (31)
    .{ .code = 0x14, .bits = 6 }, // (32)
    .{ .code = 0x3f8, .bits = 10 }, // ! (33)
    .{ .code = 0x3f9, .bits = 10 }, // " (34)
    .{ .code = 0xffa, .bits = 12 }, // # (35)
    .{ .code = 0x1ff9, .bits = 13 }, // $ (36)
    .{ .code = 0x15, .bits = 6 }, // % (37)
    .{ .code = 0xf8, .bits = 8 }, // & (38)
    .{ .code = 0x7fa, .bits = 11 }, // ' (39)
    .{ .code = 0x3fa, .bits = 10 }, // ( (40)
    .{ .code = 0x3fb, .bits = 10 }, // ) (41)
    .{ .code = 0xf9, .bits = 8 }, // * (42)
    .{ .code = 0x7fb, .bits = 11 }, // + (43)
    .{ .code = 0xfa, .bits = 8 }, // , (44)
    .{ .code = 0x16, .bits = 6 }, // - (45)
    .{ .code = 0x17, .bits = 6 }, // . (46)
    .{ .code = 0x18, .bits = 6 }, // / (47)
    .{ .code = 0x0, .bits = 5 }, // 0 (48)
    .{ .code = 0x1, .bits = 5 }, // 1 (49)
    .{ .code = 0x2, .bits = 5 }, // 2 (50)
    .{ .code = 0x19, .bits = 6 }, // 3 (51)
    .{ .code = 0x1a, .bits = 6 }, // 4 (52)
    .{ .code = 0x1b, .bits = 6 }, // 5 (53)
    .{ .code = 0x1c, .bits = 6 }, // 6 (54)
    .{ .code = 0x1d, .bits = 6 }, // 7 (55)
    .{ .code = 0x1e, .bits = 6 }, // 8 (56)
    .{ .code = 0x1f, .bits = 6 }, // 9 (57)
    .{ .code = 0x5c, .bits = 7 }, // : (58)
    .{ .code = 0xfb, .bits = 8 }, // ; (59)
    .{ .code = 0x7ffc, .bits = 15 }, // < (60)
    .{ .code = 0x20, .bits = 6 }, // = (61)
    .{ .code = 0xffb, .bits = 12 }, // > (62)
    .{ .code = 0x3fc, .bits = 10 }, // ? (63)
    .{ .code = 0x1ffa, .bits = 13 }, // @ (64)
    .{ .code = 0x21, .bits = 6 }, // A (65)
    .{ .code = 0x5d, .bits = 7 }, // B (66)
    .{ .code = 0x5e, .bits = 7 }, // C (67)
    .{ .code = 0x5f, .bits = 7 }, // D (68)
    .{ .code = 0x60, .bits = 7 }, // E (69)
    .{ .code = 0x61, .bits = 7 }, // F (70)
    .{ .code = 0x62, .bits = 7 }, // G (71)
    .{ .code = 0x63, .bits = 7 }, // H (72)
    .{ .code = 0x64, .bits = 7 }, // I (73)
    .{ .code = 0x65, .bits = 7 }, // J (74)
    .{ .code = 0x66, .bits = 7 }, // K (75)
    .{ .code = 0x67, .bits = 7 }, // L (76)
    .{ .code = 0x68, .bits = 7 }, // M (77)
    .{ .code = 0x69, .bits = 7 }, // N (78)
    .{ .code = 0x6a, .bits = 7 }, // O (79)
    .{ .code = 0x6b, .bits = 7 }, // P (80)
    .{ .code = 0x6c, .bits = 7 }, // Q (81)
    .{ .code = 0x6d, .bits = 7 }, // R (82)
    .{ .code = 0x6e, .bits = 7 }, // S (83)
    .{ .code = 0x6f, .bits = 7 }, // T (84)
    .{ .code = 0x70, .bits = 7 }, // U (85)
    .{ .code = 0x71, .bits = 7 }, // V (86)
    .{ .code = 0x72, .bits = 7 }, // W (87)
    .{ .code = 0xfc, .bits = 8 }, // X (88)
    .{ .code = 0x73, .bits = 7 }, // Y (89)
    .{ .code = 0xfd, .bits = 8 }, // Z (90)
    .{ .code = 0x1ffb, .bits = 13 }, // [ (91)
    .{ .code = 0x7fff0, .bits = 19 }, // backslash (92)
    .{ .code = 0x1ffc, .bits = 13 }, // ] (93)
    .{ .code = 0x3ffc, .bits = 14 }, // ^ (94)
    .{ .code = 0x22, .bits = 6 }, // _ (95)
    .{ .code = 0x7ffd, .bits = 15 }, // ` (96)
    .{ .code = 0x3, .bits = 5 }, // a (97)
    .{ .code = 0x23, .bits = 6 }, // b (98)
    .{ .code = 0x4, .bits = 5 }, // c (99)
    .{ .code = 0x24, .bits = 6 }, // d (100)
    .{ .code = 0x5, .bits = 5 }, // e (101)
    .{ .code = 0x25, .bits = 6 }, // f (102)
    .{ .code = 0x26, .bits = 6 }, // g (103)
    .{ .code = 0x27, .bits = 6 }, // h (104)
    .{ .code = 0x6, .bits = 5 }, // i (105)
    .{ .code = 0x74, .bits = 7 }, // j (106)
    .{ .code = 0x75, .bits = 7 }, // k (107)
    .{ .code = 0x28, .bits = 6 }, // l (108)
    .{ .code = 0x29, .bits = 6 }, // m (109)
    .{ .code = 0x2a, .bits = 6 }, // n (110)
    .{ .code = 0x7, .bits = 5 }, // o (111)
    .{ .code = 0x2b, .bits = 6 }, // p (112)
    .{ .code = 0x76, .bits = 7 }, // q (113)
    .{ .code = 0x2c, .bits = 6 }, // r (114)
    .{ .code = 0x8, .bits = 5 }, // s (115)
    .{ .code = 0x9, .bits = 5 }, // t (116)
    .{ .code = 0x2d, .bits = 6 }, // u (117)
    .{ .code = 0x77, .bits = 7 }, // v (118)
    .{ .code = 0x78, .bits = 7 }, // w (119)
    .{ .code = 0x79, .bits = 7 }, // x (120)
    .{ .code = 0x7a, .bits = 7 }, // y (121)
    .{ .code = 0x7b, .bits = 7 }, // z (122)
    .{ .code = 0x7ffe, .bits = 15 }, // { (123)
    .{ .code = 0x7fc, .bits = 11 }, // | (124)
    .{ .code = 0x3ffd, .bits = 14 }, // } (125)
    .{ .code = 0x1ffd, .bits = 13 }, // ~ (126)
    .{ .code = 0xffffffc, .bits = 28 }, // (127)
    .{ .code = 0xfffe6, .bits = 20 }, // (128)
    .{ .code = 0x3fffd2, .bits = 22 }, // (129)
    .{ .code = 0xfffe7, .bits = 20 }, // (130)
    .{ .code = 0xfffe8, .bits = 20 }, // (131)
    .{ .code = 0x3fffd3, .bits = 22 }, // (132)
    .{ .code = 0x3fffd4, .bits = 22 }, // (133)
    .{ .code = 0x3fffd5, .bits = 22 }, // (134)
    .{ .code = 0x7fffd9, .bits = 23 }, // (135)
    .{ .code = 0x3fffd6, .bits = 22 }, // (136)
    .{ .code = 0x7fffda, .bits = 23 }, // (137)
    .{ .code = 0x7fffdb, .bits = 23 }, // (138)
    .{ .code = 0x7fffdc, .bits = 23 }, // (139)
    .{ .code = 0x7fffdd, .bits = 23 }, // (140)
    .{ .code = 0x7fffde, .bits = 23 }, // (141)
    .{ .code = 0xffffeb, .bits = 24 }, // (142)
    .{ .code = 0x7fffdf, .bits = 23 }, // (143)
    .{ .code = 0xffffec, .bits = 24 }, // (144)
    .{ .code = 0xffffed, .bits = 24 }, // (145)
    .{ .code = 0x3fffd7, .bits = 22 }, // (146)
    .{ .code = 0x7fffe0, .bits = 23 }, // (147)
    .{ .code = 0xffffee, .bits = 24 }, // (148)
    .{ .code = 0x7fffe1, .bits = 23 }, // (149)
    .{ .code = 0x7fffe2, .bits = 23 }, // (150)
    .{ .code = 0x7fffe3, .bits = 23 }, // (151)
    .{ .code = 0x7fffe4, .bits = 23 }, // (152)
    .{ .code = 0x1fffdc, .bits = 21 }, // (153)
    .{ .code = 0x3fffd8, .bits = 22 }, // (154)
    .{ .code = 0x7fffe5, .bits = 23 }, // (155)
    .{ .code = 0x3fffd9, .bits = 22 }, // (156)
    .{ .code = 0x7fffe6, .bits = 23 }, // (157)
    .{ .code = 0x7fffe7, .bits = 23 }, // (158)
    .{ .code = 0xffffef, .bits = 24 }, // (159)
    .{ .code = 0x3fffda, .bits = 22 }, // (160)
    .{ .code = 0x1fffdd, .bits = 21 }, // (161)
    .{ .code = 0xfffe9, .bits = 20 }, // (162)
    .{ .code = 0x3fffdb, .bits = 22 }, // (163)
    .{ .code = 0x3fffdc, .bits = 22 }, // (164)
    .{ .code = 0x7fffe8, .bits = 23 }, // (165)
    .{ .code = 0x7fffe9, .bits = 23 }, // (166)
    .{ .code = 0x1fffde, .bits = 21 }, // (167)
    .{ .code = 0x7fffea, .bits = 23 }, // (168)
    .{ .code = 0x3fffdd, .bits = 22 }, // (169)
    .{ .code = 0x3fffde, .bits = 22 }, // (170)
    .{ .code = 0xfffff0, .bits = 24 }, // (171)
    .{ .code = 0x1fffdf, .bits = 21 }, // (172)
    .{ .code = 0x3fffdf, .bits = 22 }, // (173)
    .{ .code = 0x7fffeb, .bits = 23 }, // (174)
    .{ .code = 0x7fffec, .bits = 23 }, // (175)
    .{ .code = 0x1fffe0, .bits = 21 }, // (176)
    .{ .code = 0x1fffe1, .bits = 21 }, // (177)
    .{ .code = 0x3fffe0, .bits = 22 }, // (178)
    .{ .code = 0x1fffe2, .bits = 21 }, // (179)
    .{ .code = 0x7fffed, .bits = 23 }, // (180)
    .{ .code = 0x3fffe1, .bits = 22 }, // (181)
    .{ .code = 0x7fffee, .bits = 23 }, // (182)
    .{ .code = 0x7fffef, .bits = 23 }, // (183)
    .{ .code = 0xfffea, .bits = 20 }, // (184)
    .{ .code = 0x3fffe2, .bits = 22 }, // (185)
    .{ .code = 0x3fffe3, .bits = 22 }, // (186)
    .{ .code = 0x3fffe4, .bits = 22 }, // (187)
    .{ .code = 0x7ffff0, .bits = 23 }, // (188)
    .{ .code = 0x3fffe5, .bits = 22 }, // (189)
    .{ .code = 0x3fffe6, .bits = 22 }, // (190)
    .{ .code = 0x7ffff1, .bits = 23 }, // (191)
    .{ .code = 0x3ffffe0, .bits = 26 }, // (192)
    .{ .code = 0x3ffffe1, .bits = 26 }, // (193)
    .{ .code = 0xfffeb, .bits = 20 }, // (194)
    .{ .code = 0x7fff1, .bits = 19 }, // (195)
    .{ .code = 0x3fffe7, .bits = 22 }, // (196)
    .{ .code = 0x7ffff2, .bits = 23 }, // (197)
    .{ .code = 0x3fffe8, .bits = 22 }, // (198)
    .{ .code = 0x1ffffec, .bits = 25 }, // (199)
    .{ .code = 0x3ffffe2, .bits = 26 }, // (200)
    .{ .code = 0x3ffffe3, .bits = 26 }, // (201)
    .{ .code = 0x3ffffe4, .bits = 26 }, // (202)
    .{ .code = 0x7ffffde, .bits = 27 }, // (203)
    .{ .code = 0x7ffffdf, .bits = 27 }, // (204)
    .{ .code = 0x3ffffe5, .bits = 26 }, // (205)
    .{ .code = 0xfffff1, .bits = 24 }, // (206)
    .{ .code = 0x1ffffed, .bits = 25 }, // (207)
    .{ .code = 0x7fff2, .bits = 19 }, // (208)
    .{ .code = 0x1fffe3, .bits = 21 }, // (209)
    .{ .code = 0x3ffffe6, .bits = 26 }, // (210)
    .{ .code = 0x7ffffe0, .bits = 27 }, // (211)
    .{ .code = 0x7ffffe1, .bits = 27 }, // (212)
    .{ .code = 0x3ffffe7, .bits = 26 }, // (213)
    .{ .code = 0x7ffffe2, .bits = 27 }, // (214)
    .{ .code = 0xfffff2, .bits = 24 }, // (215)
    .{ .code = 0x1fffe4, .bits = 21 }, // (216)
    .{ .code = 0x1fffe5, .bits = 21 }, // (217)
    .{ .code = 0x3ffffe8, .bits = 26 }, // (218)
    .{ .code = 0x3ffffe9, .bits = 26 }, // (219)
    .{ .code = 0xffffffd, .bits = 28 }, // (220)
    .{ .code = 0x7ffffe3, .bits = 27 }, // (221)
    .{ .code = 0x7ffffe4, .bits = 27 }, // (222)
    .{ .code = 0x7ffffe5, .bits = 27 }, // (223)
    .{ .code = 0xfffec, .bits = 20 }, // (224)
    .{ .code = 0xfffff3, .bits = 24 }, // (225)
    .{ .code = 0xfffed, .bits = 20 }, // (226)
    .{ .code = 0x1fffe6, .bits = 21 }, // (227)
    .{ .code = 0x3fffe9, .bits = 22 }, // (228)
    .{ .code = 0x1fffe7, .bits = 21 }, // (229)
    .{ .code = 0x1fffe8, .bits = 21 }, // (230)
    .{ .code = 0x7ffff3, .bits = 23 }, // (231)
    .{ .code = 0x3fffea, .bits = 22 }, // (232)
    .{ .code = 0x3fffeb, .bits = 22 }, // (233)
    .{ .code = 0x1ffffee, .bits = 25 }, // (234)
    .{ .code = 0x1ffffef, .bits = 25 }, // (235)
    .{ .code = 0xfffff4, .bits = 24 }, // (236)
    .{ .code = 0xfffff5, .bits = 24 }, // (237)
    .{ .code = 0x3ffffea, .bits = 26 }, // (238)
    .{ .code = 0x7ffff4, .bits = 23 }, // (239)
    .{ .code = 0x3ffffeb, .bits = 26 }, // (240)
    .{ .code = 0x7ffffe6, .bits = 27 }, // (241)
    .{ .code = 0x3ffffec, .bits = 26 }, // (242)
    .{ .code = 0x3ffffed, .bits = 26 }, // (243)
    .{ .code = 0x7ffffe7, .bits = 27 }, // (244)
    .{ .code = 0x7ffffe8, .bits = 27 }, // (245)
    .{ .code = 0x7ffffe9, .bits = 27 }, // (246)
    .{ .code = 0x7ffffea, .bits = 27 }, // (247)
    .{ .code = 0x7ffffeb, .bits = 27 }, // (248)
    .{ .code = 0xffffffe, .bits = 28 }, // (249)
    .{ .code = 0x7ffffec, .bits = 27 }, // (250)
    .{ .code = 0x7ffffed, .bits = 27 }, // (251)
    .{ .code = 0x7ffffee, .bits = 27 }, // (252)
    .{ .code = 0x7ffffef, .bits = 27 }, // (253)
    .{ .code = 0x7fffff0, .bits = 27 }, // (254)
    .{ .code = 0x3ffffee, .bits = 26 }, // (255)
    .{ .code = 0x3fffffff, .bits = 30 }, // EOS
};

/// What `decode` reads: the table sorted by code length, in the three
/// arrays a canonical decode walks.
///
/// `symbols` holds every symbol ordered first by code length and then by
/// symbol. For a code of `n` bits, `first_index[n]` is where that length's
/// run starts in `symbols`, `first_code[n]` is the smallest code of that
/// length, and `counts[n]` is how many there are. A code of `n` bits whose
/// value is `c` therefore names `symbols[first_index[n] + c -
/// first_code[n]]`, and no code of any other length can be confused with
/// it, because the code is complete.
const Layout = struct {
    counts: [bits_max + 1]u16,
    first_code: [bits_max + 1]u32,
    first_index: [bits_max + 1]u16,
    symbols: [symbol_count]u16,
};

const layout: Layout = buildLayout();

fn buildLayout() Layout {
    @setEvalBranchQuota(20_000);
    var result: Layout = .{
        .counts = @splat(0),
        .first_code = @splat(0),
        .first_index = @splat(0),
        .symbols = @splat(0),
    };
    for (codes) |entry| result.counts[entry.bits] += 1;

    // The canonical rule: the first code of length n + 1 is the first code
    // of length n, plus how many codes of length n there are, shifted up
    // one bit. It starts at length 1, where the first code is zero, and
    // the lengths this table does not use simply carry a count of zero.
    var next_code: u32 = 0;
    var next_index: u16 = 0;
    var bits: u6 = 1;
    while (bits <= bits_max) : (bits += 1) {
        result.first_code[bits] = next_code;
        result.first_index[bits] = next_index;
        next_index += result.counts[bits];
        next_code = (next_code + @as(u32, result.counts[bits])) << 1;
    }

    // `codes` is in symbol order, so filling each length's run in one pass
    // leaves every run sorted by symbol, which is what the canonical rule
    // needs.
    var filled: [bits_max + 1]u16 = @splat(0);
    for (codes, 0..) |entry, symbol| {
        result.symbols[result.first_index[entry.bits] + filled[entry.bits]] = @intCast(symbol);
        filled[entry.bits] += 1;
    }
    return result;
}

comptime {
    @setEvalBranchQuota(200_000);

    // The Kraft sum of a complete prefix code is exactly one. Written over
    // a common denominator of 2^bits_max it comes to 2^bits_max. A wrong
    // length in the table above breaks this, and so does a missing row.
    var kraft: u64 = 0;
    for (codes) |entry| kraft += @as(u64, 1) << (bits_max - @as(u6, entry.bits));
    if (kraft != @as(u64, 1) << bits_max) {
        @compileError("the huffman table of RFC 7541 Appendix B is not a complete prefix code");
    }

    // Every listed code equals the code the lengths give it. `decode`
    // reads only the lengths, so this is what proves the two columns of
    // the copied table agree.
    for (codes, 0..) |entry, symbol| {
        var offset: u16 = 0;
        while (layout.symbols[layout.first_index[entry.bits] + offset] != symbol) offset += 1;
        if (entry.code != layout.first_code[entry.bits] + @as(u32, offset)) {
            @compileError("the huffman table of RFC 7541 Appendix B is not canonical");
        }
    }
}

/// Decodes `encoded` into text this function allocates from `gpa`.
///
/// The caller owns the returned slice. `out_len_max` bounds it: a decode
/// that would write one octet more stops with `error.StringTooLong`
/// instead. The caller sets that bound, because Huffman text expands and
/// the peer picks by how much.
pub fn decode(gpa: Allocator, encoded: []const u8, out_len_max: usize) DecodeError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);

    // The shortest code is five bits, so `encoded` cannot make more than
    // eight fifths of its own length. The division comes first so the
    // multiply cannot wrap on a large slice.
    try out.ensureTotalCapacity(gpa, @min(out_len_max, encoded.len / 5 * 8 + 8));

    var pending: u32 = 0;
    var pending_bits: u6 = 0;
    for (encoded) |octet| {
        var mask: u8 = 0x80;
        while (mask != 0) : (mask >>= 1) {
            pending = (pending << 1) | @as(u32, @intFromBool(octet & mask != 0));
            pending_bits += 1;
            // The comptime check above proves the code is complete, so a
            // pattern of `bits_max` bits always matches a symbol and this
            // counter never reaches the end of `layout.counts`.
            std.debug.assert(pending_bits <= bits_max);

            const count: u32 = layout.counts[pending_bits];
            const first = layout.first_code[pending_bits];
            if (count == 0 or pending < first or pending - first >= count) continue;

            const offset: u16 = @intCast(pending - first);
            const symbol = layout.symbols[layout.first_index[pending_bits] + offset];
            if (symbol == eos_symbol) return error.HuffmanEosSymbol;
            if (out.items.len == out_len_max) return error.StringTooLong;
            try out.append(gpa, @intCast(symbol));
            pending = 0;
            pending_bits = 0;
        }
    }

    // RFC 7541 section 5.2: the pad is the leading bits of the EOS code,
    // which are all ones, and a pad of eight bits or more means the
    // encoder dropped a symbol that would have fit.
    if (pending_bits > 7) return error.HuffmanPadTooLong;
    if (pending_bits != 0 and pending != (@as(u32, 1) << @intCast(pending_bits)) - 1) {
        return error.HuffmanPadInvalid;
    }
    return out.toOwnedSlice(gpa);
}

/// The number of octets `encode` writes for `text`.
pub fn encodedLen(text: []const u8) usize {
    var bits: usize = 0;
    for (text) |octet| bits += codes[octet].bits;
    return (bits + 7) / 8;
}

/// Writes `text` Huffman coded into the front of `out`, and returns the
/// octets it used.
///
/// `out` must hold at least `encodedLen(text)` octets, which is the
/// caller's to get right and so is an assert.
pub fn encode(text: []const u8, out: []u8) []u8 {
    std.debug.assert(out.len >= encodedLen(text));

    // At most seven bits are held over from the last symbol, and the next
    // symbol is at most 30 bits, so 37 bits are in flight at the widest.
    var pending: u64 = 0;
    var pending_bits: u6 = 0;
    var len: usize = 0;
    for (text) |octet| {
        const entry = codes[octet];
        pending = (pending << @as(u6, entry.bits)) | entry.code;
        pending_bits += entry.bits;
        while (pending_bits >= 8) {
            pending_bits -= 8;
            out[len] = @truncate(pending >> pending_bits);
            len += 1;
        }
    }
    if (pending_bits != 0) {
        // Pad to the octet with the leading bits of the EOS code.
        const pad_bits: u6 = 8 - pending_bits;
        out[len] = @truncate((pending << pad_bits) | ((@as(u64, 1) << pad_bits) - 1));
        len += 1;
    }
    return out[0..len];
}

const testing = std.testing;

test "the table holds one row for every octet and one for EOS" {
    try testing.expectEqual(@as(usize, 257), codes.len);
    try testing.expectEqual(@as(u32, 0x3fffffff), codes[eos_symbol].code);
    try testing.expectEqual(@as(u5, 30), codes[eos_symbol].bits);
}

test "the RFC's own worked example, the code for a slash" {
    // RFC 7541 Appendix B names this one in prose: symbol 47 is six bits,
    // 011000, which is 0x18.
    try testing.expectEqual(@as(u32, 0x18), codes['/'].code);
    try testing.expectEqual(@as(u5, 6), codes['/'].bits);
}

test "no code is shorter than five bits or longer than thirty" {
    for (codes) |entry| {
        try testing.expect(entry.bits >= bits_min);
        try testing.expect(entry.bits <= bits_max);
    }
}

test "RFC 7541 C.4.1, www.example.com encodes to the RFC's twelve octets" {
    const want = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    var out: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, want.len), encodedLen("www.example.com"));
    try testing.expectEqualSlices(u8, &want, encode("www.example.com", &out));

    const back = try decode(testing.allocator, &want, 256);
    defer testing.allocator.free(back);
    try testing.expectEqualStrings("www.example.com", back);
}

test "RFC 7541 C.4.2, no-cache encodes to the RFC's six octets" {
    const want = [_]u8{ 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf };
    var out: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, &want, encode("no-cache", &out));

    const back = try decode(testing.allocator, &want, 256);
    defer testing.allocator.free(back);
    try testing.expectEqualStrings("no-cache", back);
}

test "RFC 7541 C.6.1, a date header value round-trips through the RFC's octets" {
    const want = [_]u8{
        0xd0, 0x7a, 0xbe, 0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20, 0x05,
        0x95, 0x04, 0x0b, 0x81, 0x66, 0xe0, 0x82, 0xa6, 0x2d, 0x1b, 0xff,
    };
    var out: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, &want, encode("Mon, 21 Oct 2013 20:13:21 GMT", &out));

    const back = try decode(testing.allocator, &want, 256);
    defer testing.allocator.free(back);
    try testing.expectEqualStrings("Mon, 21 Oct 2013 20:13:21 GMT", back);
}

test "an empty string encodes to nothing and decodes back to nothing" {
    var out: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), encodedLen(""));
    try testing.expectEqual(@as(usize, 0), encode("", &out).len);

    const back = try decode(testing.allocator, "", 256);
    defer testing.allocator.free(back);
    try testing.expectEqualStrings("", back);
}

test "every octet value round-trips, one at a time and all at once" {
    var all: [256]u8 = undefined;
    for (&all, 0..) |*slot, index| slot.* = @intCast(index);

    var out: [1024]u8 = undefined;
    for (all) |octet| {
        const one = [_]u8{octet};
        const written = encode(&one, &out);
        const back = try decode(testing.allocator, written, 8);
        defer testing.allocator.free(back);
        try testing.expectEqualSlices(u8, &one, back);
    }

    const written = encode(&all, &out);
    const back = try decode(testing.allocator, written, 512);
    defer testing.allocator.free(back);
    try testing.expectEqualSlices(u8, &all, back);
}

test "a pad longer than seven bits is refused" {
    // 0x07 is the five-bit code for "0" and three bits of ones. The whole
    // of the second octet is then pad, which comes to eleven bits, and no
    // pad may reach eight: a legal encoder would have fitted a symbol
    // there.
    try testing.expectError(error.HuffmanPadTooLong, decode(testing.allocator, &.{ 0x07, 0xff }, 64));
}

test "a pad that is not the top of the EOS code is refused" {
    // "0" is 00000. The remaining three bits must be 111 to be a pad.
    const good = [_]u8{0b00000_111};
    const bad = [_]u8{0b00000_110};

    const back = try decode(testing.allocator, &good, 64);
    defer testing.allocator.free(back);
    try testing.expectEqualStrings("0", back);

    try testing.expectError(error.HuffmanPadInvalid, decode(testing.allocator, &bad, 64));
}

test "the EOS symbol inside a string is refused" {
    // EOS is thirty ones followed by a legal pad of two ones, which is
    // four octets of 0xff.
    try testing.expectError(
        error.HuffmanEosSymbol,
        decode(testing.allocator, &.{ 0xff, 0xff, 0xff, 0xff }, 64),
    );
}

test "a decode stops at the bound the caller gave" {
    var out: [64]u8 = undefined;
    const written = encode("0000000000", &out);
    try testing.expectError(error.StringTooLong, decode(testing.allocator, written, 4));

    const back = try decode(testing.allocator, written, 10);
    defer testing.allocator.free(back);
    try testing.expectEqualStrings("0000000000", back);
}

test "a decode never writes more than eight fifths of what it reads" {
    // "0" is the shortest code in the table at five bits, and it is five
    // zero bits, so a run of zero octets is the widest expansion this code
    // allows. 100 octets carry 800 bits, which is 160 symbols exactly.
    const dense = [_]u8{0x00} ** 100;
    const back = try decode(testing.allocator, &dense, 1024);
    defer testing.allocator.free(back);

    try testing.expectEqual(@as(usize, 160), back.len);
    try testing.expectEqual(@as(usize, dense.len * 8 / 5), back.len);
    for (back) |octet| try testing.expectEqual(@as(u8, '0'), octet);
}

test "the fewest octets a declared Huffman length can decode to" {
    try testing.expectEqual(@as(u64, 0), minDecodedLen(0));
    try testing.expectEqual(@as(u64, 1), minDecodedLen(1));
    // Three octets carry 17 bits at least, which is one code of 30 bits.
    try testing.expectEqual(@as(u64, 1), minDecodedLen(3));
    // 30 octets carry 233 bits at least, which is eight such codes.
    try testing.expectEqual(@as(u64, 8), minDecodedLen(30));
    try testing.expectEqual(@as(u64, 16000), minDecodedLen(60000));

    // The widest length a peer can name is 2^62-1, and the multiply by
    // eight inside would wrap a `u64`.
    try testing.expectEqual(
        @as(u64, 1229782938247303441),
        minDecodedLen((@as(u64, 1) << 62) - 1),
    );
}

test "the floor never refuses a string that really does fit" {
    // A run of every octet value, so the mix of code widths is wide. What
    // `encode` writes must always pass the floor its own decoded length
    // sets, or a legal string would be refused before it was read.
    var text: [256]u8 = undefined;
    for (&text, 0..) |*octet, i| octet.* = @intCast(i);

    var out: [1024]u8 = undefined;
    var len: usize = 1;
    while (len <= text.len) : (len += 1) {
        const written = encode(text[0..len], &out);
        try testing.expect(minDecodedLen(written.len) <= len);
    }
}
