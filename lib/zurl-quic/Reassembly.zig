//! `STREAM` frame reassembly: the bytes of one receiving half, put back in
//! order. RFC 9000 sections 2.2 and 4.5.
//!
//! **Every input here is a number the peer chose.** A `STREAM` frame names
//! an offset anywhere below 2^62, it may repeat bytes that already
//! arrived, it may leave a gap in front of itself, and it may arrive after
//! the frame that ends the stream. So this file is written as a set of
//! bounds first and a buffer second.
//!
//! | Input | Bound | Fault |
//! | --- | --- | --- |
//! | The end offset of a frame | 2^62 - 1, checked with a saturating add | `OffsetTooLarge` |
//! | The end offset against the window | The caller's buffer | `StreamBufferOverflow` |
//! | The final size a reset names | The caller's buffer | `StreamBufferOverflow` |
//! | Disjoint runs of received bytes | `max_ranges`, 16 | `TooManyStreamGaps` |
//! | Data past the final size | The final size | `FinalSizeError` |
//! | A second, different final size | The first one | `FinalSizeError` |
//! | A retransmission that changed its bytes | What is already stored | `StreamDataMismatch` |
//!
//! **The window is the caller's buffer and the flow control limit is the
//! same number.** `Streams.zig` gives a receiving half a buffer and then
//! advertises exactly that many bytes in `MAX_STREAM_DATA`, so a peer that
//! keeps to the limit never reaches `StreamBufferOverflow` and a peer that
//! passes the limit is refused before a byte is copied. The two bounds
//! cannot drift, because the second is built from the first.
//!
//! **The buffer is a ring.** Byte `n` of the stream sits at
//! `(head + n - read) % buffer.len`, so `consume` moves two numbers and
//! copies nothing. `CryptoStream` in `zurl-quic-tls` is the flat form of
//! the same idea, and it can be flat because a TLS flight is small and is
//! read once.
//!
//! Nothing here allocates.

const std = @import("std");
const varint = @import("varint.zig");

const Reassembly = @This();

/// How many disjoint runs of received bytes one half may hold.
///
/// A peer that sends every other 1 byte piece of a stream makes one run
/// for each piece. Sixteen is the same number `CryptoStream` allows, and
/// it is enough for reordering on a real path: a run joins its neighbour
/// as soon as the byte between them arrives.
pub const max_ranges: usize = 16;

/// One run of received bytes, as absolute stream offsets. `end` is one
/// past the last byte.
const Range = struct { start: u64, end: u64 };

/// Every fault this file can report. Each one is a connection error in
/// RFC 9000, and `Streams.zig` names the code.
pub const Error = error{
    /// A frame reaches past 2^62 - 1, which no stream offset may.
    /// RFC 9000 section 4.5, a FRAME_ENCODING_ERROR.
    OffsetTooLarge,
    /// A frame reaches past the window this side advertised.
    /// RFC 9000 section 4.1, a FLOW_CONTROL_ERROR.
    StreamBufferOverflow,
    /// More than `max_ranges` disjoint runs are open at once.
    ///
    /// **This is not a peer fault and it must not close a connection.**
    /// This side advertised `buffer.len` in `MAX_STREAM_DATA`, so RFC
    /// 9000 obliges it to take any arrangement of frames inside that
    /// window. `Streams.zig` drops such a frame and counts it, and the
    /// peer sends the bytes again.
    TooManyStreamGaps,
    /// Data arrived past a known final size, or a second `FIN` named a
    /// different one. RFC 9000 section 4.5, a FINAL_SIZE_ERROR.
    FinalSizeError,
    /// A retransmission carried different bytes at an offset that already
    /// holds some. RFC 9000 section 2.2, a PROTOCOL_VIOLATION.
    StreamDataMismatch,
};

/// The window. Byte `read` of the stream sits at `buffer[head]`.
buffer: []u8,
/// The ring index of stream offset `read`.
head: usize = 0,
/// The stream offset of the first byte the caller has not taken.
read: u64 = 0,
/// The received runs at or above `read`, in ascending order, disjoint,
/// and never touching: two runs that meet are one run.
ranges: [max_ranges]Range = undefined,
range_count: usize = 0,
/// The largest end offset any frame reached, whether it was stored or
/// repeated. **This is what the flow control counter reads**, because a
/// retransmission must not spend the window a second time.
highest: u64 = 0,
/// The size the `FIN` named, or null before one arrived.
final_size: ?u64 = null,

/// A half that reads into `buffer`. The window is `buffer.len` bytes wide.
///
/// Asserts the buffer is not empty: a zero width window can never take a
/// byte, so a caller that passed one made a programmer error rather than
/// met a runtime fault.
pub fn init(buffer: []u8) Reassembly {
    std.debug.assert(buffer.len > 0);
    return .{ .buffer = buffer };
}

/// How wide the window is, which is the number this side advertises.
pub fn windowLen(self: *const Reassembly) u64 {
    return self.buffer.len;
}

/// The largest offset a peer may reach without passing the window, given
/// what the caller has already taken.
///
/// **This is the value a `MAX_STREAM_DATA` frame carries.** It climbs as
/// the caller consumes, which is what gives the peer more room.
pub fn limit(self: *const Reassembly) u64 {
    return self.read +| self.buffer.len;
}

/// How many bytes are ready to read, counting from `read`.
pub fn contiguous(self: *const Reassembly) usize {
    if (self.range_count == 0) return 0;
    const first = self.ranges[0];
    if (first.start != self.read) return 0;
    return @intCast(first.end - first.start);
}

/// Whether every byte of the stream has arrived and the caller has taken
/// all of it.
pub fn isDrained(self: *const Reassembly) bool {
    const size = self.final_size orelse return false;
    return self.read == size;
}

/// Whether every byte of the stream has arrived, read or not.
pub fn isComplete(self: *const Reassembly) bool {
    const size = self.final_size orelse return false;
    return self.read + self.contiguous() == size;
}

/// The first run of readable bytes as one slice.
///
/// The ring can split a readable run in two, so this returns the part up
/// to the end of the buffer and the caller comes back for the rest. An
/// empty slice means nothing is ready.
pub fn peek(self: *const Reassembly) []const u8 {
    const ready = self.contiguous();
    if (ready == 0) return &.{};
    const to_wrap = self.buffer.len - self.head;
    return self.buffer[self.head..][0..@min(ready, to_wrap)];
}

/// Copies up to `out.len` readable bytes into `out`, gives the room back,
/// and returns how many bytes it moved.
pub fn take(self: *Reassembly, out: []u8) usize {
    var moved: usize = 0;
    while (moved < out.len) {
        const piece = self.peek();
        if (piece.len == 0) break;
        const n = @min(piece.len, out.len - moved);
        @memcpy(out[moved..][0..n], piece[0..n]);
        self.consume(n);
        moved += n;
    }
    return moved;
}

/// Gives back the room `count` readable bytes hold, which moves the
/// window forward.
///
/// Asserts `count` is at or below `contiguous()`. A caller that consumes
/// bytes that never arrived made a programmer error.
pub fn consume(self: *Reassembly, count: usize) void {
    std.debug.assert(count <= self.contiguous());
    if (count == 0) return;
    self.read += count;
    self.head = (self.head + count) % self.buffer.len;
    if (self.ranges[0].end == self.read) {
        self.dropFirstRange();
    } else {
        self.ranges[0].start = self.read;
    }
}

fn dropFirstRange(self: *Reassembly) void {
    std.mem.copyForwards(Range, self.ranges[0 .. self.range_count - 1], self.ranges[1..self.range_count]);
    self.range_count -= 1;
}

/// Takes one `STREAM` frame's data.
///
/// Every bound above runs before a byte is copied, so a refused frame
/// leaves this half exactly as it was.
pub fn push(self: *Reassembly, offset: u64, bytes: []const u8, fin: bool) Error!void {
    // **The end offset, with no unchecked add.** RFC 9000 section 4.5
    // stops a stream at 2^62 - 1, and the peer chose both numbers.
    const end = offset +| bytes.len;
    if (end > varint.max_value) return error.OffsetTooLarge;

    // RFC 9000 section 4.5: the final size is the offset of the byte one
    // past the end of the stream. A frame that reaches past it, and a
    // second `FIN` that names another number, are both FINAL_SIZE_ERROR.
    if (self.final_size) |known| {
        if (end > known) return error.FinalSizeError;
        if (fin and end != known) return error.FinalSizeError;
    } else if (fin and end < self.highest) {
        // The stream already carried a byte past the size this `FIN`
        // claims, so the two cannot both be true.
        return error.FinalSizeError;
    }

    // The window. `Streams.zig` advertises exactly `buffer.len` beyond
    // `read`, so a peer that keeps its promise never gets here.
    if (end > self.limit()) return error.StreamBufferOverflow;

    // Bytes below `read` were already taken by the caller and their room
    // is gone. A retransmission of them is legal and adds nothing.
    const start = @max(offset, self.read);
    if (end > start) {
        const skipped: usize = @intCast(start - offset);
        const data = bytes[skipped..];

        // RFC 9000 section 2.2: a peer must send the same bytes at the
        // same offset every time. A peer that does not is refused rather
        // than allowed to rewrite what this side already holds.
        if (!self.matchesStored(start, data)) return error.StreamDataMismatch;

        // The range set is grown before the copy, so a refusal for
        // `TooManyStreamGaps` copies nothing.
        try self.insert(start, end);
        self.store(start, data);
    }

    if (end > self.highest) self.highest = end;
    if (fin) self.final_size = end;
}

/// Records the final size a `RESET_STREAM` frame named. RFC 9000 section
/// 4.5 gives a reset the same final size rule a `FIN` has.
///
/// **Every bound sits next to the value it bounds.** A reset counts its
/// whole final size against the window, exactly as the bytes would have,
/// so the window bound is here and not only in the caller.
pub fn reset(self: *Reassembly, final_size: u64) Error!void {
    if (final_size > varint.max_value) return error.OffsetTooLarge;
    if (final_size < self.highest) return error.FinalSizeError;
    if (self.final_size) |known| {
        if (known != final_size) return error.FinalSizeError;
    }
    if (final_size > self.limit()) return error.StreamBufferOverflow;
    self.final_size = final_size;
    if (final_size > self.highest) self.highest = final_size;
}

/// Whether every byte of `data` that this half already holds is the same
/// byte. Bytes it does not hold are not compared.
fn matchesStored(self: *const Reassembly, start: u64, data: []const u8) bool {
    const end = start + data.len;
    for (self.ranges[0..self.range_count]) |r| {
        if (r.start >= end) break;
        if (r.end <= start) continue;
        const lo = @max(r.start, start);
        const hi = @min(r.end, end);
        const at: usize = @intCast(lo - start);
        const len: usize = @intCast(hi - lo);
        if (!self.equalsRing(lo, data[at..][0..len])) return false;
    }
    return true;
}

fn equalsRing(self: *const Reassembly, offset: u64, data: []const u8) bool {
    var index = self.indexOf(offset);
    var at: usize = 0;
    while (at < data.len) {
        const run = @min(data.len - at, self.buffer.len - index);
        if (!std.mem.eql(u8, self.buffer[index..][0..run], data[at..][0..run])) return false;
        at += run;
        index = 0;
    }
    return true;
}

fn store(self: *Reassembly, offset: u64, data: []const u8) void {
    var index = self.indexOf(offset);
    var at: usize = 0;
    while (at < data.len) {
        const run = @min(data.len - at, self.buffer.len - index);
        @memcpy(self.buffer[index..][0..run], data[at..][0..run]);
        at += run;
        index = 0;
    }
}

fn indexOf(self: *const Reassembly, offset: u64) usize {
    std.debug.assert(offset >= self.read);
    const delta: usize = @intCast(offset - self.read);
    std.debug.assert(delta < self.buffer.len);
    return (self.head + delta) % self.buffer.len;
}

/// Adds `[start, end)` to the range set, joining every run it touches.
///
/// Two runs that meet become one, so ten frames that arrived in order are
/// one range and a frame that fills a gap joins the runs either side of
/// it. That is what keeps `max_ranges` a bound on reordering and not a
/// bound on the number of frames.
fn insert(self: *Reassembly, start: u64, end: u64) Error!void {
    var first: usize = 0;
    while (first < self.range_count and self.ranges[first].end < start) : (first += 1) {}

    var lo = start;
    var hi = end;
    var past = first;
    while (past < self.range_count and self.ranges[past].start <= hi) : (past += 1) {
        lo = @min(lo, self.ranges[past].start);
        hi = @max(hi, self.ranges[past].end);
    }

    const tail = self.range_count - past;
    const wanted = first + 1 + tail;
    if (wanted > max_ranges) return error.TooManyStreamGaps;

    if (past > first + 1) {
        std.mem.copyForwards(Range, self.ranges[first + 1 ..][0..tail], self.ranges[past..][0..tail]);
    } else if (past == first) {
        std.mem.copyBackwards(Range, self.ranges[first + 1 ..][0..tail], self.ranges[first..][0..tail]);
    }
    self.ranges[first] = .{ .start = lo, .end = hi };
    self.range_count = wanted;
}

const testing = std.testing;

test "frames that arrive in order read back as one range" {
    var storage: [64]u8 = undefined;
    var r: Reassembly = .init(&storage);

    try r.push(0, "hello ", false);
    try r.push(6, "world", true);

    try testing.expectEqual(@as(usize, 1), r.range_count);
    try testing.expectEqual(@as(usize, 11), r.contiguous());
    try testing.expectEqual(@as(?u64, 11), r.final_size);
    try testing.expect(r.isComplete());

    var out: [16]u8 = undefined;
    try testing.expectEqual(@as(usize, 11), r.take(&out));
    try testing.expectEqualStrings("hello world", out[0..11]);
    try testing.expect(r.isDrained());
}

test "a gap holds back the bytes behind it until the byte in front arrives" {
    var storage: [64]u8 = undefined;
    var r: Reassembly = .init(&storage);

    try r.push(6, "world", false);
    // Nothing is readable: byte 0 has not arrived.
    try testing.expectEqual(@as(usize, 0), r.contiguous());
    try testing.expectEqual(@as(usize, 1), r.range_count);

    try r.push(0, "hello ", false);
    // The two runs joined into one.
    try testing.expectEqual(@as(usize, 1), r.range_count);
    try testing.expectEqual(@as(usize, 11), r.contiguous());

    var out: [16]u8 = undefined;
    try testing.expectEqual(@as(usize, 11), r.take(&out));
    try testing.expectEqualStrings("hello world", out[0..11]);
}

test "a frame that fills a gap joins the runs on both sides of it" {
    var storage: [64]u8 = undefined;
    var r: Reassembly = .init(&storage);

    try r.push(0, "aa", false);
    try r.push(4, "cc", false);
    try testing.expectEqual(@as(usize, 2), r.range_count);
    try testing.expectEqual(@as(usize, 2), r.contiguous());

    try r.push(2, "bb", false);
    try testing.expectEqual(@as(usize, 1), r.range_count);
    try testing.expectEqual(@as(usize, 6), r.contiguous());

    var out: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 6), r.take(&out));
    try testing.expectEqualStrings("aabbcc", out[0..6]);
}

test "the window slides, so a stream longer than the buffer still reads" {
    // The ring is what makes this work: eight bytes of buffer carry a
    // forty byte stream, because every read gives the room back.
    var storage: [8]u8 = undefined;
    var r: Reassembly = .init(&storage);

    var expected: [40]u8 = undefined;
    for (&expected, 0..) |*byte, index| byte.* = @truncate('a' + index % 26);

    var out: [40]u8 = undefined;
    var at: usize = 0;
    while (at < expected.len) : (at += 5) {
        try r.push(at, expected[at..][0..5], at + 5 == expected.len);
        try testing.expectEqual(@as(usize, 5), r.take(out[at..][0..5]));
    }
    try testing.expectEqualSlices(u8, &expected, &out);
    try testing.expect(r.isDrained());
}

test "the room a peer may use climbs as the caller reads" {
    var storage: [16]u8 = undefined;
    var r: Reassembly = .init(&storage);

    try testing.expectEqual(@as(u64, 16), r.limit());
    try r.push(0, "0123456789", false);
    // Reading nothing changes nothing.
    try testing.expectEqual(@as(u64, 16), r.limit());

    var out: [10]u8 = undefined;
    try testing.expectEqual(@as(usize, 10), r.take(&out));
    try testing.expectEqual(@as(u64, 26), r.limit());
}

test "a frame past the window is refused before a byte is copied" {
    var storage: [8]u8 = undefined;
    var r: Reassembly = .init(&storage);

    try testing.expectError(error.StreamBufferOverflow, r.push(0, "123456789", false));
    try testing.expectEqual(@as(usize, 0), r.contiguous());
    try testing.expectEqual(@as(usize, 0), r.range_count);
    try testing.expectEqual(@as(u64, 0), r.highest);

    // An offset far past the window is the same refusal and not an
    // allocation of anything.
    try testing.expectError(error.StreamBufferOverflow, r.push(1 << 40, "x", false));
    try testing.expectEqual(@as(usize, 0), r.range_count);
}

test "an offset near the top of the range is refused with no overflow" {
    var storage: [8]u8 = undefined;
    var r: Reassembly = .init(&storage);

    // The add saturates, so the comparison is what refuses this and not a
    // wrapped number that looks small.
    try testing.expectError(error.OffsetTooLarge, r.push(varint.max_value, "xx", false));
    try testing.expectError(error.OffsetTooLarge, r.push(std.math.maxInt(u64), "x", false));
    try testing.expectEqual(@as(usize, 0), r.range_count);

    // **Both bounds are broken at once here, and the 2^62 bound is the
    // one that names the fault.** RFC 9000 section 4.5 calls an offset
    // past the range a FRAME_ENCODING_ERROR, and the window gives a
    // FLOW_CONTROL_ERROR, so the order of the two checks is what decides
    // which code closes the connection. This test fails against a file
    // that checks the window first.
    try testing.expectError(error.OffsetTooLarge, r.push(varint.max_value - 1, "xxx", false));
    try testing.expectError(error.OffsetTooLarge, r.push(varint.max_value - 100, "x" ** 200, false));
    try testing.expectEqual(@as(usize, 0), r.range_count);
    try testing.expectEqual(@as(u64, 0), r.highest);
}

test "a reset naming a final size past the window is refused where the window is" {
    // The file's rule is that a bound sits next to the value it bounds.
    // A reset counts its whole final size against the window exactly as
    // the bytes would have, so the window bound belongs here and not only
    // in `Streams.zig`.
    var storage: [8]u8 = undefined;
    var r: Reassembly = .init(&storage);

    try testing.expectError(error.StreamBufferOverflow, r.reset(9));
    try testing.expectEqual(@as(?u64, null), r.final_size);
    try testing.expectEqual(@as(u64, 0), r.highest);

    // Exactly the window is legal.
    try r.reset(8);
    try testing.expectEqual(@as(?u64, 8), r.final_size);

    // The window climbs with what the caller took, so a reset that was
    // too large before is legal after a read.
    var second: [8]u8 = undefined;
    var s: Reassembly = .init(&second);
    try s.push(0, "abcd", false);
    var out: [4]u8 = undefined;
    try testing.expectEqual(@as(usize, 4), s.take(&out));
    try s.reset(12);
    try testing.expectEqual(@as(?u64, 12), s.final_size);
}

test "inserting a run before every other one moves the ranges that follow it" {
    // `insert` has two memmove branches and neither moves a byte while
    // every range set in a test ends with an empty tail. This is the
    // backwards branch: a run below every run already held, with two of
    // them to push up.
    var storage: [64]u8 = undefined;
    var r: Reassembly = .init(&storage);

    try r.push(4, "b", false);
    try r.push(8, "c", false);
    try testing.expectEqual(@as(usize, 2), r.range_count);

    try r.push(0, "a", false);
    try testing.expectEqual(@as(usize, 3), r.range_count);
    try testing.expectEqual(@as(u64, 0), r.ranges[0].start);
    try testing.expectEqual(@as(u64, 1), r.ranges[0].end);
    try testing.expectEqual(@as(u64, 4), r.ranges[1].start);
    try testing.expectEqual(@as(u64, 5), r.ranges[1].end);
    try testing.expectEqual(@as(u64, 8), r.ranges[2].start);
    try testing.expectEqual(@as(u64, 9), r.ranges[2].end);
    try testing.expectEqual(@as(usize, 1), r.contiguous());

    // The bytes the moved runs name are still the bytes that arrived.
    try r.push(1, "..", false);
    try r.push(3, ".", false);
    try r.push(5, "...", false);
    try testing.expectEqual(@as(usize, 1), r.range_count);
    var out: [9]u8 = undefined;
    try testing.expectEqual(@as(usize, 9), r.take(&out));
    try testing.expectEqualStrings("a...b...c", out[0..9]);
}

test "a run that joins three others moves the ranges left behind it" {
    // The forwards branch: one frame swallows three runs and one run
    // above them has to slide down to close the hole.
    var storage: [64]u8 = undefined;
    var r: Reassembly = .init(&storage);

    try r.push(0, "a", false);
    try r.push(4, "b", false);
    try r.push(8, "c", false);
    try r.push(12, "d", false);
    try testing.expectEqual(@as(usize, 4), r.range_count);

    // Offsets 1 to 7, which covers the run at 4 with the same byte it
    // already holds and meets the run at 8.
    try r.push(1, "...b...", false);
    try testing.expectEqual(@as(usize, 2), r.range_count);
    try testing.expectEqual(@as(u64, 0), r.ranges[0].start);
    try testing.expectEqual(@as(u64, 9), r.ranges[0].end);
    // The run above slid down into place and kept its own offsets.
    try testing.expectEqual(@as(u64, 12), r.ranges[1].start);
    try testing.expectEqual(@as(u64, 13), r.ranges[1].end);
    try testing.expectEqual(@as(usize, 9), r.contiguous());

    var out: [16]u8 = undefined;
    try testing.expectEqual(@as(usize, 9), r.take(&out));
    try testing.expectEqualStrings("a...b...c", out[0..9]);

    // The run that moved still reads back the byte it was given.
    try r.push(9, "...", false);
    try testing.expectEqual(@as(usize, 1), r.range_count);
    try testing.expectEqual(@as(usize, 4), r.take(&out));
    try testing.expectEqualStrings("...d", out[0..4]);
}

test "a peer that opens more runs than the bound allows is refused" {
    var storage: [128]u8 = undefined;
    var r: Reassembly = .init(&storage);

    // Every other byte, so each frame opens a run of its own.
    var index: usize = 0;
    while (index < max_ranges) : (index += 1) {
        try r.push(index * 2, "x", false);
        try testing.expectEqual(index + 1, r.range_count);
    }
    try testing.expectError(error.TooManyStreamGaps, r.push(max_ranges * 2, "x", false));
    try testing.expectEqual(max_ranges, r.range_count);

    // Filling one gap makes room again.
    try r.push(1, "y", false);
    try testing.expectEqual(max_ranges - 1, r.range_count);
    try r.push(max_ranges * 2, "x", false);
}

test "a retransmission that changed its bytes is refused" {
    var storage: [32]u8 = undefined;
    var r: Reassembly = .init(&storage);

    try r.push(0, "abcdef", false);
    // The same bytes again are legal and add nothing.
    try r.push(2, "cde", false);
    try testing.expectEqual(@as(usize, 6), r.contiguous());

    try testing.expectError(error.StreamDataMismatch, r.push(2, "cXe", false));
    // Nothing moved.
    try testing.expectEqual(@as(usize, 6), r.contiguous());
    var out: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 6), r.take(&out));
    try testing.expectEqualStrings("abcdef", out[0..6]);
}

test "an overlap that crosses the ring wrap is compared correctly" {
    var storage: [8]u8 = undefined;
    var r: Reassembly = .init(&storage);

    try r.push(0, "abcdef", false);
    var out: [4]u8 = undefined;
    _ = r.take(&out);
    // The window now starts at offset 4 and the ring head is at 4, so
    // bytes 8 onwards wrap round to index 0.
    try r.push(6, "ghij", false);
    try testing.expectEqual(@as(usize, 6), r.contiguous());

    try r.push(7, "hij", false);
    try testing.expectError(error.StreamDataMismatch, r.push(7, "hXj", false));

    var rest: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 6), r.take(&rest));
    try testing.expectEqualStrings("efghij", rest[0..6]);
}

test "a retransmission of bytes the caller already took is accepted and ignored" {
    var storage: [16]u8 = undefined;
    var r: Reassembly = .init(&storage);

    try r.push(0, "abcd", false);
    var out: [4]u8 = undefined;
    _ = r.take(&out);
    try testing.expectEqual(@as(u64, 4), r.read);

    // Those bytes are gone from the window, so there is nothing to
    // compare them against and nothing to store.
    try r.push(0, "abcd", false);
    try testing.expectEqual(@as(usize, 0), r.contiguous());
    try testing.expectEqual(@as(u64, 4), r.highest);

    // A frame that straddles the boundary stores only its new half.
    try r.push(2, "cdef", false);
    try testing.expectEqual(@as(usize, 2), r.contiguous());
    try testing.expectEqual(@as(usize, 2), r.take(&out));
    try testing.expectEqualStrings("ef", out[0..2]);
}

test "data past a final size is refused and so is a second, different one" {
    var storage: [32]u8 = undefined;
    var r: Reassembly = .init(&storage);

    try r.push(0, "abcde", true);
    try testing.expectEqual(@as(?u64, 5), r.final_size);

    // RFC 9000 section 4.5: nothing may reach past the final size.
    try testing.expectError(error.FinalSizeError, r.push(5, "f", false));
    try testing.expectError(error.FinalSizeError, r.push(3, "defg", false));
    // A second FIN naming another size is the same fault.
    try testing.expectError(error.FinalSizeError, r.push(0, "abc", true));
    // The same FIN again is legal.
    try r.push(0, "abcde", true);
    try testing.expectEqual(@as(?u64, 5), r.final_size);
}

test "a FIN below a byte that already arrived is refused" {
    var storage: [32]u8 = undefined;
    var r: Reassembly = .init(&storage);

    try r.push(8, "xy", false);
    try testing.expectEqual(@as(u64, 10), r.highest);
    // The stream already reached offset 10, so it cannot end at 4.
    try testing.expectError(error.FinalSizeError, r.push(0, "abcd", true));
    try testing.expectEqual(@as(?u64, null), r.final_size);
    // Ending at 10 is consistent, and it is accepted.
    try r.push(0, "abcdefgh", false);
    try r.push(8, "xy", true);
    try testing.expectEqual(@as(?u64, 10), r.final_size);
    try testing.expect(r.isComplete());
}

test "a reset carries the same final size rule a FIN does" {
    var storage: [32]u8 = undefined;
    var r: Reassembly = .init(&storage);

    try r.push(0, "abcd", false);
    try testing.expectError(error.FinalSizeError, r.reset(3));
    try r.reset(4);
    try testing.expectEqual(@as(?u64, 4), r.final_size);
    try testing.expectError(error.FinalSizeError, r.reset(9));
    try testing.expectError(error.OffsetTooLarge, r.reset(varint.max_value + 1));
}

test "the highest offset counts a retransmission once" {
    // This is the number the flow control counter reads. Counting the
    // length of every frame instead would spend the window twice for one
    // retransmission and stall a healthy connection.
    var storage: [32]u8 = undefined;
    var r: Reassembly = .init(&storage);

    try r.push(0, "abcdef", false);
    try testing.expectEqual(@as(u64, 6), r.highest);
    try r.push(0, "abcdef", false);
    try testing.expectEqual(@as(u64, 6), r.highest);
    try r.push(2, "cdefgh", false);
    try testing.expectEqual(@as(u64, 8), r.highest);
}

test "an empty frame at the end of a stream ends it" {
    var storage: [16]u8 = undefined;
    var r: Reassembly = .init(&storage);

    try r.push(0, "abc", false);
    try r.push(3, "", true);
    try testing.expectEqual(@as(?u64, 3), r.final_size);
    try testing.expect(r.isComplete());
    var out: [4]u8 = undefined;
    try testing.expectEqual(@as(usize, 3), r.take(&out));
    try testing.expect(r.isDrained());
}
