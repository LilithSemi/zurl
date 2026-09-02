//! The sending half of one QUIC stream: the bytes that are written and not
//! yet acknowledged, what has gone out once, and what a loss put back in
//! the queue. RFC 9000 sections 2.2 and 13.3.
//!
//! **A QUIC sender cannot forget a byte until the peer acknowledges it.**
//! RFC 9000 section 13.3 makes the sender put lost stream data back on the
//! wire, so the bytes have to stay somewhere until an `ACK` frame covers
//! them. That somewhere is this ring, and its size is the whole of the
//! bound: a caller that has filled it writes no more until an
//! acknowledgment gives room back.
//!
//! So one buffer holds three things at once, and the three numbers say
//! which is which:
//!
//! ```text
//!   base            sent               written
//!    |               |                    |
//!    | acknowledged? | on the wire, not   | written by the caller,
//!    | no: waiting   | acknowledged       | never sent
//!    +---------------+--------------------+
//! ```
//!
//! Nothing here allocates, and nothing here reads a clock. `Streams.zig`
//! joins this to the flow control counters and to the frames.

const std = @import("std");
const varint = @import("varint.zig");

const SendBuffer = @This();

/// How many disjoint acknowledged runs one half may hold at once.
///
/// An `ACK` frame acknowledges packets, and one packet carries one run of
/// one stream, so a gap here is a lost packet whose neighbours arrived.
pub const max_acked_ranges: usize = 16;

/// How many disjoint runs may wait for retransmission at once.
pub const max_resend_ranges: usize = 16;

/// One run of stream offsets. `end` is one past the last byte.
const Range = struct { start: u64, end: u64 };

/// The next run of bytes to put in a `STREAM` frame.
pub const Chunk = struct {
    offset: u64,
    /// Borrowed from the ring. Valid until the next call that writes to
    /// this buffer.
    data: []const u8,
    /// Whether this frame carries the `FIN` bit.
    fin: bool,
    /// Whether these bytes have been on the wire before. A retransmission
    /// is not new data, so it does not move the connection flow control
    /// counter. RFC 9000 section 4.1.
    retransmit: bool,
};

/// The ring. Byte `base` of the stream sits at `buffer[head]`.
buffer: []u8,
head: usize = 0,
/// The first offset the peer has not acknowledged.
base: u64 = 0,
/// One past the last offset the caller has written.
written: u64 = 0,
/// One past the last offset that has been on the wire.
sent: u64 = 0,
/// Whether the caller closed the sending half.
fin_written: bool = false,
/// Whether the `FIN` bit has been on the wire and is not known lost.
fin_sent: bool = false,
/// Whether the peer acknowledged the `FIN`.
fin_acked: bool = false,
/// Acknowledged runs at or above `base`, ascending and disjoint. A run
/// that reaches `base` is not here: it moved `base` instead.
acked: [max_acked_ranges]Range = undefined,
acked_count: usize = 0,
/// Runs that a loss put back in the queue, ascending and disjoint.
resend: [max_resend_ranges]Range = undefined,
resend_count: usize = 0,
/// How many times a run was widened because the range set was full.
///
/// **A recovered fault is counted and never silent.** Widening a run
/// sends bytes the peer may already have, which costs bandwidth and never
/// correctness, because RFC 9000 section 2.2 makes those bytes the same
/// bytes.
coarsened: u64 = 0,
/// How many times flow control clipped a run that was waiting to go out
/// again. See `next`: a limit that let a byte out once still covers it,
/// so this counter stays at zero against a peer that keeps its promises.
resend_flow_blocked: u64 = 0,

/// A half that writes out of `buffer`. The caller may hold `buffer.len`
/// unacknowledged bytes and no more.
///
/// Asserts the buffer is not empty.
pub fn init(buffer: []u8) SendBuffer {
    std.debug.assert(buffer.len > 0);
    return .{ .buffer = buffer };
}

/// How many more bytes the caller may write before an acknowledgment
/// gives room back.
pub fn room(self: *const SendBuffer) usize {
    return self.buffer.len - @as(usize, @intCast(self.written - self.base));
}

/// How many bytes are written and never sent, plus everything waiting to
/// go out again.
pub fn pending(self: *const SendBuffer) u64 {
    var total = self.written - self.sent;
    for (self.resend[0..self.resend_count]) |r| total += r.end - r.start;
    return total;
}

/// Whether anything at all is waiting to go on the wire, the `FIN`
/// included.
pub fn hasWork(self: *const SendBuffer) bool {
    if (self.pending() > 0) return true;
    return self.fin_written and !self.fin_sent;
}

/// Whether the peer acknowledged every byte and the `FIN`.
pub fn isAcknowledged(self: *const SendBuffer) bool {
    return self.fin_written and self.fin_acked and self.base == self.written;
}

/// Copies up to `room()` bytes of `bytes` into the ring and returns how
/// many it took.
///
/// Asserts the caller has not already written the `FIN`. RFC 9000 section
/// 3.1 gives a stream nothing to send after the final byte, so writing
/// past it is a programmer error and not a peer's doing.
pub fn push(self: *SendBuffer, bytes: []const u8) usize {
    std.debug.assert(!self.fin_written);
    const n = @min(bytes.len, self.room());
    // A stream stops at 2^62 - 1. RFC 9000 section 4.5. The ring is far
    // smaller than that, so this is a ceiling and never a live bound, and
    // it is here so no arithmetic below can pass it.
    std.debug.assert(self.written +| n <= varint.max_value);

    var index = (self.head + @as(usize, @intCast(self.written - self.base))) % self.buffer.len;
    var at: usize = 0;
    while (at < n) {
        const run = @min(n - at, self.buffer.len - index);
        @memcpy(self.buffer[index..][0..run], bytes[at..][0..run]);
        at += run;
        index = 0;
    }
    self.written += n;
    return n;
}

/// Closes the sending half. Nothing more may be written after this.
pub fn finish(self: *SendBuffer) void {
    self.fin_written = true;
}

/// The next run to put in a `STREAM` frame, or null when nothing is due.
///
/// `allowed_end` is the largest offset flow control lets this frame
/// reach, which is the smaller of the stream limit and the connection
/// limit. `max_len` is what fits the packet. **A retransmission ignores
/// neither**: RFC 9000 section 4.1 counts a byte against the limit once,
/// and the limit that let it out the first time still covers it, so a
/// resend range should always be at or below `allowed_end`. That is an
/// invariant of the caller's limits and not of this buffer, so it is
/// checked here rather than trusted.
///
/// The run is one slice of the ring, so a run that crosses the wrap comes
/// back in two calls.
pub fn next(self: *SendBuffer, allowed_end: u64, max_len: usize) ?Chunk {
    if (self.resend_count > 0) {
        const r = self.resend[0];
        // **The limit binds a resend as well.** It should never bind,
        // because `Streams` only ever raises a flow control limit. A
        // limit that came back smaller is a fault of the peer or of the
        // layer above, and putting bytes past it on the wire is a
        // FLOW_CONTROL_ERROR the peer would close the connection for.
        // **Recovery is never silent**, so the clip is counted.
        if (allowed_end < r.end) self.resend_flow_blocked +|= 1;
        if (r.start >= allowed_end) return null;
        const end = @min(@min(r.end, allowed_end), r.start +| max_len);
        const piece = self.slice(r.start, @intCast(end - r.start));
        return .{
            .offset = r.start,
            .data = piece,
            // The `FIN` rides the run that reaches the last byte, and
            // only when it is not already out. A resend never invents
            // one.
            .fin = self.fin_written and !self.fin_sent and r.start + piece.len == self.written,
            .retransmit = true,
        };
    }

    if (self.sent < self.written) {
        const ceiling = @min(self.written, allowed_end);
        if (ceiling > self.sent) {
            const end = @min(ceiling, self.sent +| max_len);
            const piece = self.slice(self.sent, @intCast(end - self.sent));
            return .{
                .offset = self.sent,
                .data = piece,
                .fin = self.fin_written and !self.fin_sent and self.sent + piece.len == self.written,
                .retransmit = false,
            };
        }
    }

    // Nothing is left but the `FIN` itself, which RFC 9000 section 19.8
    // lets a frame carry with no data at all.
    if (self.fin_written and !self.fin_sent and self.sent == self.written) {
        return .{ .offset = self.sent, .data = &.{}, .fin = true, .retransmit = false };
    }
    return null;
}

/// Records that a chunk went on the wire.
///
/// Asserts the chunk names bytes this buffer holds, which is what `next`
/// returns and nothing else.
pub fn onSent(self: *SendBuffer, offset: u64, len: usize, fin: bool) void {
    std.debug.assert(offset >= self.base);
    std.debug.assert(offset +| len <= self.written);
    if (len > 0) {
        if (offset == self.sent) {
            self.sent += len;
        } else {
            // A retransmission. It leaves `sent` where it is and takes
            // the run out of the queue.
            remove(&self.resend, &self.resend_count, offset, offset + len);
        }
    }
    if (fin) self.fin_sent = true;
}

/// Records that the bytes of one lost packet must go out again.
///
/// RFC 9002 section 6.5: a sender puts the data of a lost packet back in
/// the queue. The bytes are still in the ring, because nothing leaves it
/// before an acknowledgment.
pub fn onLost(self: *SendBuffer, offset: u64, len: usize, fin: bool) void {
    if (fin) self.fin_sent = false;
    if (len == 0) return;
    const start = @max(offset, self.base);
    const end = offset +| len;
    if (end <= start) return;
    // Bytes the peer has already acknowledged need not go out again, and
    // the acknowledged set is what says which those are.
    var lo = start;
    for (self.acked[0..self.acked_count]) |r| {
        if (r.start <= lo and r.end > lo) lo = r.end;
    }
    if (end <= lo) return;
    self.coarsened += insert(&self.resend, &self.resend_count, lo, @min(end, self.written));
}

/// Records that the peer acknowledged a run, and moves `base` over
/// everything that is acknowledged from the front.
pub fn onAcked(self: *SendBuffer, offset: u64, len: usize, fin: bool) void {
    if (fin) self.fin_acked = true;
    if (len == 0) return;
    const start = @max(offset, self.base);
    const end = @min(offset +| len, self.written);
    if (end <= start) return;

    // An acknowledged run never needs sending again.
    remove(&self.resend, &self.resend_count, start, end);

    self.coarsened += insert(&self.acked, &self.acked_count, start, end);
    if (self.acked_count > 0 and self.acked[0].start == self.base) self.advance(self.acked[0].end);
}

/// Moves `base` to `to`, and then over every acknowledged run that the
/// move joined onto the front.
///
/// **The second half is what makes an out of order acknowledgment work.**
/// A peer that acknowledged the tail of a stream first leaves a run
/// sitting above `base`; the acknowledgment that fills the hole in front
/// of it must free that run's room as well, or the buffer never empties
/// and the caller can never write again.
fn advance(self: *SendBuffer, to: u64) void {
    if (to <= self.base) return;
    var target = to;
    var again = true;
    while (again) {
        again = false;
        for (self.acked[0..self.acked_count]) |r| {
            if (r.start <= target and r.end > target) {
                target = r.end;
                again = true;
            }
        }
    }
    const moved: usize = @intCast(target - self.base);
    self.base = target;
    self.head = (self.head + moved) % self.buffer.len;
    // A run that the move swallowed is dropped, and one that straddles
    // the new base is trimmed.
    var kept: usize = 0;
    for (self.acked[0..self.acked_count]) |r| {
        if (r.end <= self.base) continue;
        self.acked[kept] = .{ .start = @max(r.start, self.base), .end = r.end };
        kept += 1;
    }
    self.acked_count = kept;
    // The same for the retransmission queue, which cannot hold a byte
    // below `base` either.
    kept = 0;
    for (self.resend[0..self.resend_count]) |r| {
        if (r.end <= self.base) continue;
        self.resend[kept] = .{ .start = @max(r.start, self.base), .end = r.end };
        kept += 1;
    }
    self.resend_count = kept;
    if (self.sent < self.base) self.sent = self.base;
}

fn slice(self: *const SendBuffer, offset: u64, len: usize) []const u8 {
    std.debug.assert(offset >= self.base);
    std.debug.assert(offset + len <= self.written);
    const index = (self.head + @as(usize, @intCast(offset - self.base))) % self.buffer.len;
    return self.buffer[index..][0..@min(len, self.buffer.len - index)];
}

/// Adds `[start, end)` to a range set, joining every run it touches, and
/// returns 1 when the set was full and two runs had to be joined over the
/// gap between them.
///
/// **A full set widens a run rather than drop one.** Dropping an
/// acknowledged run makes this side send bytes again, which is wasteful
/// and safe. Dropping a run waiting for retransmission makes this side
/// **never** send bytes the peer is waiting for, which stalls the stream
/// for ever. Widening does neither: it sends more than it must, and RFC
/// 9000 section 2.2 makes the extra bytes the same bytes.
fn insert(set: []Range, count: *usize, start: u64, end: u64) u64 {
    var first: usize = 0;
    while (first < count.* and set[first].end < start) : (first += 1) {}

    var lo = start;
    var hi = end;
    var past = first;
    while (past < count.* and set[past].start <= hi) : (past += 1) {
        lo = @min(lo, set[past].start);
        hi = @max(hi, set[past].end);
    }

    const tail = count.* - past;
    const wanted = first + 1 + tail;
    if (wanted > set.len) {
        if (first > 0) {
            // Join this run with the one in front of it, over the gap.
            set[first - 1].end = hi;
            var kept = first;
            for (set[past..count.*]) |r| {
                set[kept] = r;
                kept += 1;
            }
            count.* = kept;
        } else {
            // Nothing is in front of it, so join it with the one behind.
            set[0] = .{ .start = lo, .end = @max(hi, set[0].end) };
        }
        return 1;
    }

    if (past > first + 1) {
        std.mem.copyForwards(Range, set[first + 1 ..][0..tail], set[past..][0..tail]);
    } else if (past == first) {
        std.mem.copyBackwards(Range, set[first + 1 ..][0..tail], set[first..][0..tail]);
    }
    set[first] = .{ .start = lo, .end = hi };
    count.* = wanted;
    return 0;
}

/// Takes `[start, end)` out of a range set. A run that straddles an end
/// is trimmed, and a run the removal splits in two becomes two runs.
///
/// **This is called on the retransmission queue and on no other set.** A
/// split that would pass the capacity widens the lower half instead, so
/// the removed bytes go out again. That costs bandwidth, where losing the
/// upper half would leave the peer waiting for ever.
fn remove(set: []Range, count: *usize, start: u64, end: u64) void {
    var kept: usize = 0;
    var index: usize = 0;
    while (index < count.*) : (index += 1) {
        const r = set[index];
        if (r.end <= start or r.start >= end) {
            set[kept] = r;
            kept += 1;
            continue;
        }
        const keeps_low = r.start < start;
        const keeps_high = r.end > end;
        if (keeps_low and keeps_high and kept + 2 > set.len) {
            set[kept] = r;
            kept += 1;
            continue;
        }
        if (keeps_low) {
            set[kept] = .{ .start = r.start, .end = start };
            kept += 1;
        }
        if (keeps_high) {
            set[kept] = .{ .start = end, .end = r.end };
            kept += 1;
        }
    }
    count.* = kept;
}

const testing = std.testing;

fn drain(self: *SendBuffer, out: []u8, allowed_end: u64, max_len: usize) usize {
    var at: usize = 0;
    while (self.next(allowed_end, max_len)) |chunk| {
        @memcpy(out[at..][0..chunk.data.len], chunk.data);
        at += chunk.data.len;
        self.onSent(chunk.offset, chunk.data.len, chunk.fin);
        if (chunk.data.len == 0) break;
    }
    return at;
}

test "written bytes come back in order and the FIN rides the last one" {
    var storage: [64]u8 = undefined;
    var s: SendBuffer = .init(&storage);

    try testing.expectEqual(@as(usize, 11), s.push("hello world"));
    s.finish();
    try testing.expect(s.hasWork());

    const chunk = s.next(1000, 100).?;
    try testing.expectEqual(@as(u64, 0), chunk.offset);
    try testing.expectEqualStrings("hello world", chunk.data);
    try testing.expect(chunk.fin);
    try testing.expect(!chunk.retransmit);

    s.onSent(chunk.offset, chunk.data.len, chunk.fin);
    try testing.expect(!s.hasWork());
    try testing.expect(s.next(1000, 100) == null);

    s.onAcked(0, 11, true);
    try testing.expect(s.isAcknowledged());
    try testing.expectEqual(@as(usize, 64), s.room());
}

test "a packet the caller cannot fill takes what fits and leaves the rest" {
    var storage: [64]u8 = undefined;
    var s: SendBuffer = .init(&storage);
    _ = s.push("abcdefghij");
    s.finish();

    var out: [16]u8 = undefined;
    // Four bytes to a packet.
    try testing.expectEqual(@as(usize, 10), s.drain(&out, 1000, 4));
    try testing.expectEqualStrings("abcdefghij", out[0..10]);
    try testing.expect(s.fin_sent);
}

test "flow control clips a chunk and the rest waits for the limit to move" {
    var storage: [64]u8 = undefined;
    var s: SendBuffer = .init(&storage);
    _ = s.push("abcdefghij");

    const first = s.next(4, 100).?;
    try testing.expectEqualStrings("abcd", first.data);
    s.onSent(first.offset, first.data.len, first.fin);

    // The limit is spent, so nothing more goes out whatever the packet
    // has room for.
    try testing.expect(s.next(4, 100) == null);

    const second = s.next(10, 100).?;
    try testing.expectEqualStrings("efghij", second.data);
}

test "the caller may not write past the ring until an acknowledgment gives room" {
    var storage: [8]u8 = undefined;
    var s: SendBuffer = .init(&storage);

    try testing.expectEqual(@as(usize, 8), s.push("0123456789"));
    try testing.expectEqual(@as(usize, 0), s.room());
    try testing.expectEqual(@as(usize, 0), s.push("more"));

    const chunk = s.next(1000, 100).?;
    s.onSent(chunk.offset, chunk.data.len, chunk.fin);
    // Sending is not acknowledging: the bytes must stay for a
    // retransmission.
    try testing.expectEqual(@as(usize, 0), s.room());

    s.onAcked(0, 4, false);
    try testing.expectEqual(@as(usize, 4), s.room());
    try testing.expectEqual(@as(usize, 4), s.push("89ab"));
}

test "a lost run goes out again and a fresh run waits behind it" {
    var storage: [64]u8 = undefined;
    var s: SendBuffer = .init(&storage);
    _ = s.push("abcdefgh");

    const first = s.next(1000, 4).?;
    s.onSent(first.offset, first.data.len, first.fin);
    const second = s.next(1000, 4).?;
    s.onSent(second.offset, second.data.len, second.fin);
    try testing.expect(!s.hasWork());

    // The first packet was lost.
    s.onLost(0, 4, false);
    try testing.expect(s.hasWork());
    const again = s.next(1000, 100).?;
    try testing.expectEqual(@as(u64, 0), again.offset);
    try testing.expectEqualStrings("abcd", again.data);
    try testing.expect(again.retransmit);
    s.onSent(again.offset, again.data.len, again.fin);
    try testing.expect(!s.hasWork());
    // `sent` did not move backwards.
    try testing.expectEqual(@as(u64, 8), s.sent);
}

test "a lost FIN goes out again on its own" {
    var storage: [64]u8 = undefined;
    var s: SendBuffer = .init(&storage);
    _ = s.push("abc");
    s.finish();

    const chunk = s.next(1000, 100).?;
    try testing.expect(chunk.fin);
    s.onSent(chunk.offset, chunk.data.len, chunk.fin);

    // Only the FIN was lost: the data was acknowledged.
    s.onAcked(0, 3, false);
    s.onLost(0, 0, true);
    try testing.expect(s.hasWork());
    const again = s.next(1000, 100).?;
    try testing.expectEqual(@as(usize, 0), again.data.len);
    try testing.expect(again.fin);
    s.onSent(again.offset, again.data.len, again.fin);
    s.onAcked(3, 0, true);
    try testing.expect(s.isAcknowledged());
}

test "a run the peer already acknowledged is not sent again" {
    var storage: [64]u8 = undefined;
    var s: SendBuffer = .init(&storage);
    _ = s.push("abcdefgh");
    const chunk = s.next(1000, 100).?;
    s.onSent(chunk.offset, chunk.data.len, chunk.fin);

    s.onAcked(0, 8, false);
    // A late loss report for bytes already acknowledged adds nothing.
    s.onLost(0, 8, false);
    try testing.expect(!s.hasWork());
    try testing.expectEqual(@as(usize, 0), s.resend_count);
}

test "an out of order acknowledgment moves the base only when the gap fills" {
    var storage: [64]u8 = undefined;
    var s: SendBuffer = .init(&storage);
    _ = s.push("abcdefghij");
    const chunk = s.next(1000, 100).?;
    s.onSent(chunk.offset, chunk.data.len, chunk.fin);

    s.onAcked(5, 5, false);
    // The front is still outstanding, so no room came back.
    try testing.expectEqual(@as(u64, 0), s.base);
    try testing.expectEqual(@as(usize, 1), s.acked_count);

    s.onAcked(0, 5, false);
    try testing.expectEqual(@as(u64, 10), s.base);
    try testing.expectEqual(@as(usize, 0), s.acked_count);
    try testing.expectEqual(@as(usize, 64), s.room());
}

test "a full retransmission queue widens a run rather than drop one" {
    // Dropping a run would leave bytes the peer is waiting for with
    // nothing to put them on the wire, and the stream would never end.
    var storage: [256]u8 = undefined;
    var s: SendBuffer = .init(&storage);
    var filler: [200]u8 = @splat('x');
    _ = s.push(&filler);
    const chunk = s.next(1000, 200).?;
    s.onSent(chunk.offset, chunk.data.len, chunk.fin);

    // Every other four bytes lost, which opens a run for each.
    var index: usize = 0;
    while (index < max_resend_ranges) : (index += 1) {
        s.onLost(index * 8, 4, false);
    }
    try testing.expectEqual(max_resend_ranges, s.resend_count);
    try testing.expectEqual(@as(u64, 0), s.coarsened);

    s.onLost(max_resend_ranges * 8, 4, false);
    try testing.expectEqual(max_resend_ranges, s.resend_count);
    try testing.expectEqual(@as(u64, 1), s.coarsened);
    // Every lost byte is still covered: the last run now spans the gap.
    const last = s.resend[max_resend_ranges - 1];
    try testing.expectEqual(@as(u64, max_resend_ranges * 8 + 4), last.end);
    try testing.expect(last.start <= (max_resend_ranges - 1) * 8);
}

test "flow control clips a retransmission and is not taken on trust" {
    var storage: [64]u8 = undefined;
    var s: SendBuffer = .init(&storage);
    _ = s.push("abcdefgh");
    const first = s.next(1000, 100).?;
    s.onSent(first.offset, first.data.len, first.fin);
    s.onLost(0, 8, false);

    // A limit that came back smaller than the one that let these bytes
    // out is a fault above this buffer. The run stops at it rather than
    // putting bytes past a limit the peer would close the connection for.
    try testing.expect(s.next(0, 100) == null);
    try testing.expectEqual(@as(u64, 1), s.resend_flow_blocked);
    try testing.expectEqual(@as(usize, 1), s.resend_count);

    const clipped = s.next(4, 100).?;
    try testing.expectEqual(@as(u64, 0), clipped.offset);
    try testing.expectEqualStrings("abcd", clipped.data);
    try testing.expect(clipped.retransmit);
    try testing.expectEqual(@as(u64, 2), s.resend_flow_blocked);

    // A limit that covers the whole run does not clip it and is not
    // counted.
    const whole = s.next(1000, 100).?;
    try testing.expectEqualStrings("abcdefgh", whole.data);
    try testing.expectEqual(@as(u64, 2), s.resend_flow_blocked);
}

test "a chunk that crosses the ring wrap comes back in two pieces" {
    var storage: [8]u8 = undefined;
    var s: SendBuffer = .init(&storage);

    _ = s.push("abcdefgh");
    const first = s.next(1000, 100).?;
    s.onSent(first.offset, first.data.len, first.fin);
    s.onAcked(0, 6, false);
    // The head is at index 6 now, so the next six bytes wrap.
    try testing.expectEqual(@as(usize, 6), s.room());
    _ = s.push("ijklmn");

    var out: [8]u8 = undefined;
    const moved = s.drain(&out, 1000, 100);
    try testing.expectEqual(@as(usize, 6), moved);
    try testing.expectEqualStrings("ijklmn", out[0..6]);
}
