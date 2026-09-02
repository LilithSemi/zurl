//! One encryption level's CRYPTO stream, reassembled from frames that may
//! arrive out of order. RFC 9000 section 19.6 and RFC 9001 section 4.1.
//!
//! **QUIC delivers a datagram, not a stream.** A CRYPTO frame carries an
//! offset and a run of bytes, and the network may reorder two frames,
//! duplicate one, or drop one and deliver the next. So the handshake
//! cannot read the bytes in the order they arrive. This file puts them
//! back in order.
//!
//! ## What bounds this
//!
//! Every number in a CRYPTO frame belongs to the peer, and a
//! variable-length integer can name 2^62. Three bounds hold:
//!
//! - **The buffer.** The caller gives one, and an offset or a length that
//!   reaches past it is `error.CryptoStreamOverflow`. Nothing here
//!   allocates.
//! - **The gap count.** A peer that sends every other byte would ask for
//!   one range per byte. `max_ranges` is the bound, and a frame that would
//!   pass it is `error.TooManyCryptoGaps`.
//! - **The bytes already written.** A frame that covers bytes this stream
//!   already holds must carry the same bytes. RFC 9000 section 19.6 makes
//!   a different value a `PROTOCOL_VIOLATION`, so a peer cannot rewrite a
//!   ClientHello it already sent by resending one byte of it.
//!
//! **The buffer is a window and not the whole stream.** `consume` slides
//! what is left down to the front and moves `base`, so the room a level
//! has does not run out as the stream offsets climb. A frame that names
//! only bytes below `base` is a retransmission of what was already read:
//! it is counted in `retransmits_dropped` and dropped, because the bytes
//! it would be compared against are gone.
//!
//! ## What this does not do
//!
//! It does not read TLS messages. `Handshake.zig` does that, over the
//! contiguous run this file reports.

const std = @import("std");

const CryptoStream = @This();

/// How many disjoint runs of received bytes one stream holds.
///
/// A gap opens when a frame arrives before the one in front of it, so a
/// path that reorders a whole flight needs a few. Sixteen is far above
/// what an ordinary path produces, and it bounds a peer that fragments on
/// purpose.
pub const max_ranges: usize = 16;

/// Why a CRYPTO frame could not be taken.
pub const Error = error{
    /// The frame reaches past the buffer the caller gave. The bytes of a
    /// handshake are bounded by what this build accepts, and a peer that
    /// asks for more is refused rather than served.
    CryptoStreamOverflow,
    /// The frame would open more gaps than `max_ranges` holds.
    TooManyCryptoGaps,
    /// The frame covers bytes this stream already holds, and it carries
    /// other bytes there. RFC 9000 section 19.6.
    CryptoStreamMismatch,
};

/// One run of received bytes, as a half-open interval.
const Range = struct {
    start: u64,
    end: u64,
};

/// Where the bytes go. The caller owns it, and stream offset `base + n`
/// sits at `buffer[n]`.
buffer: []u8,
/// The runs received so far, sorted by `start` and never touching. The
/// numbers are offsets into `buffer`, not stream offsets.
ranges: [max_ranges]Range,
/// How many entries of `ranges` are in use.
range_count: usize,
/// The stream offset that sits at `buffer[0]`.
///
/// `consume` slides the buffer down, so this climbs while the buffer stays
/// the same size. Everything below it was read and is gone.
base: u64,
/// How many frames named only bytes that were read and slid away.
///
/// Those bytes cannot be compared any more, so the frame is dropped. It is
/// a retransmission and not a fault, and this is what keeps the count of
/// them in sight.
retransmits_dropped: u64,

/// An empty stream over `buffer`.
pub fn init(buffer: []u8) CryptoStream {
    return .{
        .buffer = buffer,
        .ranges = @splat(.{ .start = 0, .end = 0 }),
        .range_count = 0,
        .base = 0,
        .retransmits_dropped = 0,
    };
}

/// Takes the bytes of one CRYPTO frame.
///
/// `offset` is the frame's Offset field and `bytes` is its payload. A
/// frame of no bytes is legal and changes nothing.
pub fn provide(self: *CryptoStream, offset: u64, bytes: []const u8) Error!void {
    if (bytes.len == 0) return;

    // **The bound, and it runs before any byte is copied.** The sum is
    // checked rather than trusted: `offset` is a peer's varint, so it may
    // be any number a `u64` holds.
    const end = std.math.add(u64, offset, bytes.len) catch
        return error.CryptoStreamOverflow;

    // Bytes below `base` were read and slid off the front, so there is
    // nothing left to compare them against and no room to hold them.
    var payload = bytes;
    var start = offset;
    if (end <= self.base) {
        self.retransmits_dropped += 1;
        return;
    }
    if (start < self.base) {
        payload = bytes[@intCast(self.base - start)..];
        start = self.base;
        self.retransmits_dropped += 1;
    }

    const at = start - self.base;
    const stop = at + payload.len;
    if (stop > self.buffer.len) return error.CryptoStreamOverflow;

    // A retransmission must carry what it carried the first time. RFC
    // 9000 section 19.6 makes other bytes a protocol violation, so a peer
    // cannot rewrite a message it already sent.
    for (payload, 0..) |byte, index| {
        const position = at + index;
        if (self.holds(position) and self.buffer[@intCast(position)] != byte) {
            return error.CryptoStreamMismatch;
        }
    }

    // **The range goes in first.** `insert` can refuse the frame, and a
    // refused frame must leave no byte in the buffer that no range covers.
    try self.insert(.{ .start = at, .end = stop });
    @memcpy(self.buffer[@intCast(at)..@intCast(stop)], payload);
}

/// Whether the stream already received the byte at `position`.
fn holds(self: *const CryptoStream, position: u64) bool {
    for (self.ranges[0..self.range_count]) |range| {
        if (position >= range.start and position < range.end) return true;
    }
    return false;
}

/// Puts one range into the sorted list, joining it with any range it
/// touches or overlaps.
fn insert(self: *CryptoStream, incoming: Range) Error!void {
    var merged = incoming;

    // Take out every range the new one touches, widening it as we go. A
    // range that ends exactly where another starts is one run, so the
    // comparisons are inclusive at both ends.
    var out: usize = 0;
    var kept: [max_ranges]Range = undefined;
    for (self.ranges[0..self.range_count]) |range| {
        if (range.end < merged.start or range.start > merged.end) {
            kept[out] = range;
            out += 1;
            continue;
        }
        merged.start = @min(merged.start, range.start);
        merged.end = @max(merged.end, range.end);
    }

    if (out + 1 > max_ranges) return error.TooManyCryptoGaps;

    // Put the joined range back in sorted order.
    var index: usize = 0;
    while (index < out and kept[index].start < merged.start) index += 1;
    var at: usize = out;
    while (at > index) : (at -= 1) kept[at] = kept[at - 1];
    kept[index] = merged;

    self.range_count = out + 1;
    @memcpy(self.ranges[0..self.range_count], kept[0..self.range_count]);
}

/// How many bytes are in place from the front of the stream.
pub fn contiguous(self: *const CryptoStream) u64 {
    if (self.range_count == 0) return 0;
    if (self.ranges[0].start != 0) return 0;
    return self.ranges[0].end;
}

/// The bytes the reader has not taken yet, in order and with no gap.
///
/// The slice is writable because the TLS decoder above takes a `[]u8`. It
/// points into the caller's buffer and nothing here writes through it.
pub fn available(self: *const CryptoStream) []u8 {
    return self.buffer[0..@intCast(self.contiguous())];
}

/// Marks `count` bytes from the front as read, and slides the rest down.
///
/// `count` must be at or below `available().len`. It is this build's own
/// number and never a peer's, so it is an assert.
///
/// **The buffer slides on every read.** A stream that only ever moved its
/// read mark forward would reach the end of a fixed buffer for bytes it
/// handed over long ago. RFC 8446 section 4.6.1 lets a server send session
/// tickets for as long as the connection lives, so the application level
/// would die on a server that did nothing wrong. Sliding costs one copy of
/// what is still held, which is at most the buffer.
pub fn consume(self: *CryptoStream, count: usize) void {
    std.debug.assert(count <= self.available().len);
    if (count == 0) return;
    const shift: u64 = count;

    var highest: u64 = 0;
    for (self.ranges[0..self.range_count]) |range| highest = @max(highest, range.end);
    if (highest > shift) {
        std.mem.copyForwards(
            u8,
            self.buffer[0..@intCast(highest - shift)],
            self.buffer[@intCast(shift)..@intCast(highest)],
        );
    }

    var out: usize = 0;
    for (self.ranges[0..self.range_count]) |range| {
        if (range.end <= shift) continue;
        self.ranges[out] = .{
            .start = if (range.start > shift) range.start - shift else 0,
            .end = range.end - shift,
        };
        out += 1;
    }
    self.range_count = out;
    self.base += shift;
}

const testing = std.testing;

test "frames in order make one run and read back whole" {
    var storage: [64]u8 = undefined;
    var stream: CryptoStream = .init(&storage);

    try stream.provide(0, "hello ");
    try testing.expectEqual(@as(u64, 6), stream.contiguous());
    try testing.expectEqualStrings("hello ", stream.available());

    try stream.provide(6, "world");
    try testing.expectEqual(@as(u64, 11), stream.contiguous());
    try testing.expectEqualStrings("hello world", stream.available());
    try testing.expectEqual(@as(usize, 1), stream.range_count);

    stream.consume(6);
    try testing.expectEqualStrings("world", stream.available());
    stream.consume(5);
    try testing.expectEqual(@as(usize, 0), stream.available().len);
}

test "a frame that arrives early waits for the one in front of it" {
    var storage: [64]u8 = undefined;
    var stream: CryptoStream = .init(&storage);

    try stream.provide(6, "world");
    // Nothing is readable, because byte zero has not arrived.
    try testing.expectEqual(@as(u64, 0), stream.contiguous());
    try testing.expectEqual(@as(usize, 0), stream.available().len);
    try testing.expectEqual(@as(usize, 1), stream.range_count);

    try stream.provide(0, "hello ");
    try testing.expectEqualStrings("hello world", stream.available());
    // And the two runs joined into one.
    try testing.expectEqual(@as(usize, 1), stream.range_count);
}

test "three frames in the worst order still read back in the right one" {
    var storage: [64]u8 = undefined;
    var stream: CryptoStream = .init(&storage);

    try stream.provide(8, "three");
    try stream.provide(4, "two ");
    try testing.expectEqual(@as(u64, 0), stream.contiguous());
    try stream.provide(0, "one ");
    try testing.expectEqualStrings("one two three", stream.available());
    try testing.expectEqual(@as(usize, 1), stream.range_count);
}

test "a duplicate frame changes nothing and a changed one is refused" {
    var storage: [64]u8 = undefined;
    var stream: CryptoStream = .init(&storage);

    try stream.provide(0, "abcdef");
    // The same bytes again, which a path that duplicates a datagram
    // produces. This is not a fault.
    try stream.provide(0, "abcdef");
    try stream.provide(2, "cd");
    try testing.expectEqualStrings("abcdef", stream.available());

    // Other bytes at the same offset are a protocol violation. RFC 9000
    // section 19.6.
    try testing.expectError(error.CryptoStreamMismatch, stream.provide(0, "abXdef"));
    try testing.expectError(error.CryptoStreamMismatch, stream.provide(5, "F"));
    // And the stream is unchanged by the refusal.
    try testing.expectEqualStrings("abcdef", stream.available());
}

test "a frame that overlaps the end joins without losing the new bytes" {
    var storage: [64]u8 = undefined;
    var stream: CryptoStream = .init(&storage);

    try stream.provide(0, "abcd");
    try stream.provide(2, "cdef");
    try testing.expectEqualStrings("abcdef", stream.available());
    try testing.expectEqual(@as(usize, 1), stream.range_count);
}

test "an offset or a length past the buffer is refused before any copy" {
    var storage: [16]u8 = undefined;
    var stream: CryptoStream = .init(&storage);

    try testing.expectError(error.CryptoStreamOverflow, stream.provide(16, "a"));
    try testing.expectError(error.CryptoStreamOverflow, stream.provide(12, "abcdef"));
    // A peer may name a huge offset in a varint, and the sum must not
    // wrap into the buffer.
    try testing.expectError(error.CryptoStreamOverflow, stream.provide((1 << 62) - 1, "a"));
    try testing.expectEqual(@as(usize, 0), stream.range_count);

    // The last byte that does fit is taken.
    try stream.provide(15, "z");
    try testing.expectEqual(@as(usize, 1), stream.range_count);
}

test "a frame of no bytes is legal and changes nothing" {
    var storage: [16]u8 = undefined;
    var stream: CryptoStream = .init(&storage);
    try stream.provide(4, "");
    try testing.expectEqual(@as(usize, 0), stream.range_count);
    try testing.expectEqual(@as(u64, 0), stream.contiguous());
}

test "a peer that opens too many gaps is refused by name" {
    var storage: [256]u8 = undefined;
    var stream: CryptoStream = .init(&storage);

    // Every other byte, so each frame opens a gap of its own.
    var index: u64 = 0;
    while (index < max_ranges) : (index += 1) {
        try stream.provide(index * 2, "x");
    }
    try testing.expectEqual(max_ranges, stream.range_count);

    // One more run cannot be held, and the refusal names the reason.
    try testing.expectError(error.TooManyCryptoGaps, stream.provide(max_ranges * 2, "x"));

    // A frame that joins two runs instead of opening one is still taken,
    // because it lowers the count rather than raise it.
    try stream.provide(1, "y");
    try testing.expect(stream.range_count < max_ranges);
}

test "the ranges stay sorted whatever order the frames arrive in" {
    var storage: [64]u8 = undefined;
    var stream: CryptoStream = .init(&storage);

    try stream.provide(40, "d");
    try stream.provide(10, "b");
    try stream.provide(30, "c");
    try stream.provide(0, "a");
    try testing.expectEqual(@as(usize, 4), stream.range_count);

    var previous: u64 = 0;
    for (stream.ranges[0..stream.range_count], 0..) |range, position| {
        if (position != 0) try testing.expect(range.start > previous);
        previous = range.start;
    }
    // Only the run at zero is readable.
    try testing.expectEqualStrings("a", stream.available());
}

test "a refused frame leaves no byte in the buffer that no range covers" {
    var storage: [256]u8 = undefined;
    @memset(&storage, 0);
    var stream: CryptoStream = .init(&storage);

    // Every other byte, so each frame opens a gap of its own and the last
    // one this stream can hold fills `max_ranges`.
    var index: u64 = 0;
    while (index < max_ranges) : (index += 1) {
        try stream.provide(index * 2, "x");
    }
    try testing.expectEqual(max_ranges, stream.range_count);

    // One more run is refused, and the byte it carried must not be in the
    // buffer. Nothing reads a byte no range covers, so this is an
    // invariant and not an exploit, and an invariant that holds is what
    // keeps the next reader honest.
    const at = max_ranges * 2;
    try testing.expectError(error.TooManyCryptoGaps, stream.provide(at, "Z"));
    try testing.expectEqual(@as(u8, 0), storage[at]);
    try testing.expect(!stream.holds(at));
}

test "the buffer slides on every read, so a long stream fits a short buffer" {
    // The whole point of the slide: a level that runs for the life of the
    // connection must not run out of room for bytes it handed over long
    // ago.
    var storage: [16]u8 = undefined;
    var stream: CryptoStream = .init(&storage);

    var offset: u64 = 0;
    var round: usize = 0;
    while (round < 200) : (round += 1) {
        const text = [_]u8{@truncate(round)} ** 8;
        try stream.provide(offset, &text);
        try testing.expectEqualSlices(u8, &text, stream.available());
        stream.consume(text.len);
        offset += text.len;
    }

    // 1600 bytes went through a 16 byte buffer, and the stream offset kept
    // climbing.
    try testing.expectEqual(@as(u64, 1600), stream.base);
    try testing.expectEqual(@as(usize, 0), stream.range_count);
    try testing.expectEqual(@as(usize, 0), stream.available().len);
}

test "the slide keeps the bytes that were not read, and the gaps with them" {
    var storage: [32]u8 = undefined;
    var stream: CryptoStream = .init(&storage);

    try stream.provide(0, "abcdef");
    // A run that sits past a gap, so the slide has to move a range that
    // does not start at zero.
    try stream.provide(10, "xy");
    try testing.expectEqual(@as(usize, 2), stream.range_count);

    stream.consume(4);
    try testing.expectEqual(@as(u64, 4), stream.base);
    try testing.expectEqualStrings("ef", stream.available());
    try testing.expectEqual(@as(usize, 2), stream.range_count);

    // The gap is still where the peer left it, one stream offset at a
    // time: stream offset 10 is now buffer offset 6.
    try stream.provide(6, "ghij");
    try testing.expectEqualStrings("efghijxy", stream.available());
    try testing.expectEqual(@as(usize, 1), stream.range_count);
}

test "a frame of bytes that were already read is counted and dropped" {
    var storage: [32]u8 = undefined;
    var stream: CryptoStream = .init(&storage);

    try stream.provide(0, "abcdef");
    stream.consume(6);
    try testing.expectEqual(@as(u64, 6), stream.base);

    // The whole frame is behind the front, so there is nothing to do with
    // it and nothing to check it against.
    try stream.provide(0, "abcdef");
    try testing.expectEqual(@as(u64, 1), stream.retransmits_dropped);
    try testing.expectEqual(@as(usize, 0), stream.range_count);

    // A frame that straddles the front keeps the part that is still ahead
    // of it.
    try stream.provide(4, "efgh");
    try testing.expectEqual(@as(u64, 2), stream.retransmits_dropped);
    try testing.expectEqualStrings("gh", stream.available());
}
