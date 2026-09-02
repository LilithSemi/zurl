//! The SSH data types of RFC 4251 section 5. Pure bytes, and testable with
//! a table.
//!
//! **Every byte a `Reader` walks came from the peer.** A length field can
//! claim any value a `uint32` can hold, so each read here checks the claim
//! against what is left in the buffer before it takes one byte. A caller
//! therefore never has to ask whether a slice it got back is inside the
//! packet it came from.
//!
//! What this module owns:
//!
//! - `byte`, `boolean`, `uint32`, `uint64`, `string`, and `mpint`, read and
//!   written the way RFC 4251 section 5 spells them.
//! - `NameList`, the comma-separated algorithm list, and `firstMatch`,
//!   which is the negotiation rule of RFC 4253 section 7.1.
//!
//! What this module does not own: no message numbers, no packet framing,
//! and no bound on how large a packet may be. `zurl_ssh.packet` keeps the
//! packet bound and `zurl_ssh.messages` names the message numbers.
//!
//! **A `boolean` is any non-zero byte.** RFC 4251 section 5 says a sender
//! must write 0 or 1 and a reader must take every non-zero value as true.
//! This module follows the reader's rule, because the peer is the sender.

const std = @import("std");

/// Why a read stopped.
pub const ReadError = error{
    /// The buffer ended in the middle of a value. A peer that writes a
    /// length and then fewer bytes lands here.
    Truncated,
    /// A length field claims more bytes than the whole buffer holds. This
    /// is separate from `Truncated` because it names a peer that lied
    /// about a size rather than one that stopped early.
    LengthOutOfRange,
};

/// Reads the SSH types out of one buffer, in order.
///
/// Every slice this returns points into `bytes`, so it is valid for as
/// long as the caller's buffer is.
pub const Reader = struct {
    bytes: []const u8,
    at: usize = 0,

    /// Reads over `bytes`, starting at the front.
    pub fn init(bytes: []const u8) Reader {
        return .{ .bytes = bytes };
    }

    /// How many bytes are left.
    pub fn left(r: *const Reader) usize {
        return r.bytes.len - r.at;
    }

    /// Whether every byte has been read.
    pub fn atEnd(r: *const Reader) bool {
        return r.at == r.bytes.len;
    }

    /// The bytes that are left, without reading them.
    pub fn rest(r: *const Reader) []const u8 {
        return r.bytes[r.at..];
    }

    /// Takes the next `n` bytes.
    pub fn take(r: *Reader, n: usize) ReadError![]const u8 {
        if (n > r.left()) return error.Truncated;
        const out = r.bytes[r.at..][0..n];
        r.at += n;
        return out;
    }

    /// Reads one byte.
    pub fn byte(r: *Reader) ReadError!u8 {
        const out = try r.take(1);
        return out[0];
    }

    /// Reads one boolean. Any non-zero byte is true, per RFC 4251
    /// section 5.
    pub fn boolean(r: *Reader) ReadError!bool {
        return try r.byte() != 0;
    }

    /// Reads one 32-bit unsigned integer, big-endian.
    pub fn uint32(r: *Reader) ReadError!u32 {
        const out = try r.take(4);
        return std.mem.readInt(u32, out[0..4], .big);
    }

    /// Reads one 64-bit unsigned integer, big-endian.
    pub fn uint64(r: *Reader) ReadError!u64 {
        const out = try r.take(8);
        return std.mem.readInt(u64, out[0..8], .big);
    }

    /// Reads one string: a 32-bit length, then that many bytes.
    ///
    /// **The length is checked against what is left before any byte is
    /// taken.** A peer that writes a length of 4294967295 costs this
    /// process one comparison.
    pub fn string(r: *Reader) ReadError![]const u8 {
        const len = try r.uint32();
        if (len > r.left()) return error.LengthOutOfRange;
        return r.take(@intCast(len));
    }

    /// Reads one name-list. The wire form is a string, and the text
    /// inside it is the list.
    pub fn nameList(r: *Reader) ReadError!NameList {
        return .{ .text = try r.string() };
    }
};

/// Why a write stopped.
pub const WriteError = error{
    /// The value does not fit the caller's buffer. The buffer is left
    /// with whatever the earlier writes put in it, so a caller must
    /// treat a failed build as a whole failed build.
    NoSpaceLeft,
};

/// Writes the SSH types into one buffer, in order.
pub const Writer = struct {
    buffer: []u8,
    at: usize = 0,

    /// Writes into `buffer`, starting at the front.
    pub fn init(buffer: []u8) Writer {
        return .{ .buffer = buffer };
    }

    /// What has been written so far.
    pub fn written(w: *const Writer) []u8 {
        return w.buffer[0..w.at];
    }

    /// How much room is left.
    pub fn room(w: *const Writer) usize {
        return w.buffer.len - w.at;
    }

    /// Writes `data`, with no length in front of it.
    pub fn bytes(w: *Writer, data: []const u8) WriteError!void {
        if (data.len > w.room()) return error.NoSpaceLeft;
        @memcpy(w.buffer[w.at..][0..data.len], data);
        w.at += data.len;
    }

    /// Writes one byte.
    pub fn byte(w: *Writer, value: u8) WriteError!void {
        return w.bytes(&.{value});
    }

    /// Writes one boolean, as 0 or 1.
    pub fn boolean(w: *Writer, value: bool) WriteError!void {
        return w.byte(@intFromBool(value));
    }

    /// Writes one 32-bit unsigned integer, big-endian.
    pub fn uint32(w: *Writer, value: u32) WriteError!void {
        var out: [4]u8 = undefined;
        std.mem.writeInt(u32, &out, value, .big);
        return w.bytes(&out);
    }

    /// Writes one 64-bit unsigned integer, big-endian.
    pub fn uint64(w: *Writer, value: u64) WriteError!void {
        var out: [8]u8 = undefined;
        std.mem.writeInt(u64, &out, value, .big);
        return w.bytes(&out);
    }

    /// Writes one string: the length, then the bytes.
    pub fn string(w: *Writer, data: []const u8) WriteError!void {
        if (data.len > std.math.maxInt(u32)) return error.NoSpaceLeft;
        try w.uint32(@intCast(data.len));
        return w.bytes(data);
    }

    /// Writes one name-list, from names this build holds.
    ///
    /// The names are joined with commas, and the join is the whole
    /// grammar of RFC 4251 section 5. An empty list writes a length of
    /// zero and no text, which is legal and which is what a client with
    /// no algorithm to offer in a category must write.
    pub fn nameList(w: *Writer, names: []const []const u8) WriteError!void {
        var total: usize = 0;
        for (names, 0..) |name, i| {
            if (i != 0) total += 1;
            total += name.len;
        }
        if (total > std.math.maxInt(u32)) return error.NoSpaceLeft;
        try w.uint32(@intCast(total));
        for (names, 0..) |name, i| {
            if (i != 0) try w.byte(',');
            try w.bytes(name);
        }
    }

    /// Writes one unsigned mpint, from a big-endian magnitude.
    ///
    /// RFC 4251 section 5 writes an mpint as a two's complement
    /// big-endian number in the shortest form that keeps its sign. So
    /// leading zero bytes come off, and a value whose top bit is set
    /// gains one zero byte in front of it, or it would read as negative.
    /// Zero writes a length of zero and no bytes at all.
    ///
    /// **The shared secret of a key exchange goes on the wire and into
    /// the exchange hash through this one function.** A single wrong byte
    /// here gives a hash that no server agrees with.
    pub fn mpint(w: *Writer, magnitude: []const u8) WriteError!void {
        const trimmed = trimLeadingZeros(magnitude);
        if (trimmed.len == 0) return w.uint32(0);
        const pad: u32 = if (trimmed[0] & 0x80 != 0) 1 else 0;
        if (trimmed.len > std.math.maxInt(u32) - pad) return error.NoSpaceLeft;
        try w.uint32(@as(u32, @intCast(trimmed.len)) + pad);
        if (pad == 1) try w.byte(0);
        return w.bytes(trimmed);
    }
};

/// Takes the leading zero bytes off a big-endian magnitude.
pub fn trimLeadingZeros(magnitude: []const u8) []const u8 {
    var start: usize = 0;
    while (start < magnitude.len and magnitude[start] == 0) start += 1;
    return magnitude[start..];
}

/// How many bytes `Writer.mpint` writes for `magnitude`, the length field
/// counted.
pub fn mpintLen(magnitude: []const u8) usize {
    const trimmed = trimLeadingZeros(magnitude);
    if (trimmed.len == 0) return 4;
    const pad: usize = if (trimmed[0] & 0x80 != 0) 1 else 0;
    return 4 + pad + trimmed.len;
}

/// A comma-separated list of algorithm names, RFC 4251 section 5.
///
/// The value holds the text and nothing else, so it costs no allocation
/// and it points into the packet it was read from.
pub const NameList = struct {
    text: []const u8,

    /// Walks the names, in the order the peer wrote them.
    pub const Iterator = struct {
        text: []const u8,
        at: usize = 0,
        done: bool = false,

        /// The next name, or null at the end of the list.
        pub fn next(it: *Iterator) ?[]const u8 {
            if (it.done) return null;
            if (it.text.len == 0) {
                it.done = true;
                return null;
            }
            const from = it.at;
            if (std.mem.indexOfScalarPos(u8, it.text, from, ',')) |comma| {
                it.at = comma + 1;
                return it.text[from..comma];
            }
            it.done = true;
            return it.text[from..];
        }
    };

    /// Walks the names.
    pub fn iterator(list: NameList) Iterator {
        return .{ .text = list.text };
    }

    /// Whether the list names `name`.
    pub fn contains(list: NameList, name: []const u8) bool {
        var it = list.iterator();
        while (it.next()) |candidate| {
            if (std.mem.eql(u8, candidate, name)) return true;
        }
        return false;
    }

    /// How many names the list holds.
    pub fn count(list: NameList) usize {
        var it = list.iterator();
        var total: usize = 0;
        while (it.next()) |_| total += 1;
        return total;
    }
};

/// The first of `ours` that `theirs` also names, or null.
///
/// **This is the negotiation rule of RFC 4253 section 7.1, and the order
/// is the whole rule.** The client's list is in preference order, and the
/// chosen algorithm is the first name on it that the server also holds. A
/// search that walked the server's list instead would let a server pick
/// the weakest algorithm the client can speak.
pub fn firstMatch(ours: []const []const u8, theirs: NameList) ?[]const u8 {
    for (ours) |name| {
        if (theirs.contains(name)) return name;
    }
    return null;
}

const testing = std.testing;

test "a string is a length and then that many bytes" {
    var r: Reader = .init("\x00\x00\x00\x03abc\x00\x00\x00\x00");
    try testing.expectEqualStrings("abc", try r.string());
    try testing.expectEqualStrings("", try r.string());
    try testing.expect(r.atEnd());
}

test "a length larger than the buffer is refused and nothing is read" {
    // **This is the bound that keeps a lying length field cheap.** The
    // peer claims four gigabytes and the reader answers with one
    // comparison.
    var r: Reader = .init("\xff\xff\xff\xff");
    try testing.expectError(error.LengthOutOfRange, r.string());

    var short: Reader = .init("\x00\x00\x00\x08abc");
    try testing.expectError(error.LengthOutOfRange, short.string());
}

test "a buffer that ends inside a value is truncated and never read past" {
    var r: Reader = .init("\x00\x00");
    try testing.expectError(error.Truncated, r.uint32());

    var empty: Reader = .init("");
    try testing.expectError(error.Truncated, empty.byte());
    try testing.expectError(error.Truncated, empty.boolean());
    try testing.expectError(error.Truncated, empty.uint64());
}

test "any non-zero byte is true, which is the rule RFC 4251 gives a reader" {
    var r: Reader = .init("\x00\x01\xff");
    try testing.expectEqual(false, try r.boolean());
    try testing.expectEqual(true, try r.boolean());
    try testing.expectEqual(true, try r.boolean());
}

test "the integers are big-endian" {
    var r: Reader = .init("\x01\x02\x03\x04\x00\x00\x00\x00\x00\x00\x00\x05");
    try testing.expectEqual(@as(u32, 0x01020304), try r.uint32());
    try testing.expectEqual(@as(u64, 5), try r.uint64());

    var storage: [12]u8 = undefined;
    var w: Writer = .init(&storage);
    try w.uint32(0x01020304);
    try w.uint64(5);
    try testing.expectEqualSlices(u8, r.bytes, w.written());
}

test "mpint writes the examples RFC 4251 section 5 gives" {
    // The four rows of the table in RFC 4251 section 5 that carry a
    // non-negative value. A negative mpint never appears in this
    // protocol, because the one mpint zurl writes is a shared secret.
    const cases = [_]struct { magnitude: []const u8, encoded: []const u8 }{
        .{ .magnitude = &.{}, .encoded = "\x00\x00\x00\x00" },
        .{ .magnitude = &.{ 0, 0, 0 }, .encoded = "\x00\x00\x00\x00" },
        .{
            .magnitude = &.{ 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7 },
            .encoded = "\x00\x00\x00\x08\x09\xa3\x78\xf9\xb2\xe3\x32\xa7",
        },
        .{ .magnitude = &.{0x80}, .encoded = "\x00\x00\x00\x02\x00\x80" },
        .{ .magnitude = &.{ 0x00, 0x80 }, .encoded = "\x00\x00\x00\x02\x00\x80" },
    };
    for (cases) |case| {
        var storage: [32]u8 = undefined;
        var w: Writer = .init(&storage);
        try w.mpint(case.magnitude);
        try testing.expectEqualSlices(u8, case.encoded, w.written());
        try testing.expectEqual(case.encoded.len, mpintLen(case.magnitude));
    }
}

test "a name-list splits on commas, and an empty list holds no name" {
    const list: NameList = .{ .text = "curve25519-sha256,ext-info-c" };
    try testing.expectEqual(@as(usize, 2), list.count());
    try testing.expect(list.contains("curve25519-sha256"));
    try testing.expect(list.contains("ext-info-c"));
    try testing.expect(!list.contains("curve25519"));
    try testing.expect(!list.contains(""));

    const empty: NameList = .{ .text = "" };
    try testing.expectEqual(@as(usize, 0), empty.count());
    try testing.expect(!empty.contains(""));

    const one: NameList = .{ .text = "only" };
    try testing.expectEqual(@as(usize, 1), one.count());
    try testing.expect(one.contains("only"));
}

test "the writer joins a name-list with commas and counts the text" {
    var storage: [64]u8 = undefined;
    var w: Writer = .init(&storage);
    try w.nameList(&.{ "a", "bb", "ccc" });
    try testing.expectEqualSlices(u8, "\x00\x00\x00\x08a,bb,ccc", w.written());

    var empty_storage: [8]u8 = undefined;
    var empty: Writer = .init(&empty_storage);
    try empty.nameList(&.{});
    try testing.expectEqualSlices(u8, "\x00\x00\x00\x00", empty.written());
}

test "firstMatch takes our order and never the peer's" {
    // **The proof that the client's preference decides.** The server lists
    // the weak name first, and the answer is still the strong one, because
    // the client's list is the one that is walked.
    const ours = [_][]const u8{ "strong", "weak" };
    const theirs: NameList = .{ .text = "weak,strong" };
    try testing.expectEqualStrings("strong", firstMatch(&ours, theirs).?);

    const none: NameList = .{ .text = "other" };
    try testing.expectEqual(@as(?[]const u8, null), firstMatch(&ours, none));
    try testing.expectEqual(@as(?[]const u8, null), firstMatch(&.{}, theirs));
}

test "a writer that runs out of room says so and never writes past the end" {
    var storage: [4]u8 = undefined;
    @memset(&storage, 0xaa);
    var w: Writer = .init(&storage);
    try testing.expectError(error.NoSpaceLeft, w.string("abc"));
    // The length went in before the room ran out. A caller must throw the
    // whole build away, which is what the doc comment on `WriteError`
    // says.
    try testing.expectEqual(@as(usize, 4), w.at);

    var small: [2]u8 = undefined;
    var tiny: Writer = .init(&small);
    try testing.expectError(error.NoSpaceLeft, tiny.uint32(1));
}
