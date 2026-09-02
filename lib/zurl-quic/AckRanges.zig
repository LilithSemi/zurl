//! The packet numbers this endpoint received in one packet number space,
//! and the `ACK` frame that reports them. RFC 9000 section 13.2.
//!
//! **There is one of these per space and they never share a number.** A
//! packet number 5 in the Initial space and a packet number 5 in the
//! application space are two different packets, so acknowledging one must
//! not acknowledge the other. `Recovery` keeps three of these and indexes
//! them by `loss.Space`.
//!
//! ## The set, and why it is a fixed size
//!
//! The received numbers are kept as ranges, largest first, with no
//! overlap and at least one number of gap between neighbours. That is the
//! shape RFC 9000 section 19.3 encodes, so building the frame is a walk
//! and not a sort.
//!
//! **The set holds `max_ranges` ranges and it never allocates.** A peer
//! that sends every other packet number makes one range per packet, so a
//! set that grew with the gaps would let a peer choose how much memory
//! this process uses. When the set is full the smallest range is dropped.
//! Section 13.2.3 allows that: a range that is no longer reported looks
//! lost to the peer, and the peer sends the data again. Losing an
//! acknowledgment is slow, and running out of memory is fatal, so this is
//! the safe direction. `dropped` counts it, because recovery is never
//! silent.
//!
//! ## When an ACK goes out
//!
//! RFC 9000 section 13.2.1 gives three reasons to acknowledge at once,
//! and `record` sets `immediate` for each of them:
//!
//! 1. The packet was an ack-eliciting Initial or Handshake packet. The
//!    handshake has no time to spare and section 13.2.1 requires it.
//! 2. Two ack-eliciting packets arrived since the last ACK went out.
//! 3. The packet arrived out of order, which is the signal section
//!    13.2.1 uses to tell the peer about a gap without waiting.
//!
//! Otherwise a deadline is armed at `max_ack_delay` after the packet
//! arrived. A packet that elicits no acknowledgment arms nothing, so this
//! endpoint never answers an ACK-only packet with an ACK-only packet.

const std = @import("std");

const frame = @import("frame.zig");
const loss = @import("loss.zig");
const varint = @import("varint.zig");

const AckRanges = @This();

/// How many ranges the set holds. A peer that makes more gaps than this
/// loses the report of its oldest ones.
pub const max_ranges: usize = 32;

/// The buffer `build` needs. One range past the first writes a Gap and an
/// ACK Range Length, and each is a variable-length integer of at most
/// eight bytes.
pub const max_range_bytes: usize = (max_ranges - 1) * 16;

/// The largest packet number this set keeps.
///
/// RFC 9000 section 17.1 makes a packet number at most 2^62 - 1, which is
/// also the largest value a variable-length integer can write. `record`
/// refuses a number above this, so every Gap and every ACK Range Length
/// `build` writes fits the wire form.
///
/// **The bound lives here and not in the caller.** `packet.decodePacketNumber`
/// caps its answer at the same number, so the wire path never offers a
/// larger one. That cap is in another file, and a bound in another file is
/// not a bound for this one: a second caller of `record`, or a relaxed cap,
/// would put an unwritable number into the set and `build` would then have
/// to fail on it.
pub const max_number: u64 = varint.max_value;

/// Why an `ACK` frame could not be built.
pub const BuildError = error{
    /// No packet has arrived in this space, so there is nothing to say.
    NothingToAcknowledge,
    /// The caller's buffer is shorter than `max_range_bytes`.
    NoSpace,
    /// A range holds a number larger than a variable-length integer can
    /// write. `record` refuses such a number, so this reports a set that
    /// was built some other way.
    RangeTooLarge,
    /// Two neighbouring ranges touch or overlap. The set keeps at least
    /// one number of gap between them, so this reports a set that was
    /// built some other way.
    RangesOutOfOrder,
};

/// The received ranges, largest first. Only the first `len` are live.
ranges: [max_ranges]frame.Range = undefined,
len: usize = 0,
/// When the largest received packet arrived. RFC 9000 section 19.3 makes
/// the ACK Delay field the time since then.
largest_time: loss.Instant = 0,
/// How many ack-eliciting packets arrived since the last ACK went out.
eliciting_pending: u32 = 0,
/// True when an ACK must go out without waiting for the deadline.
immediate: bool = false,
/// When a delayed ACK is due, or null when none is armed.
deadline: ?loss.Instant = null,
/// How many ranges were dropped because the set was full.
dropped: u64 = 0,
/// How many packets arrived that this set already held. A duplicate is
/// not an error, and counting it is how a caller sees a path that
/// duplicates.
duplicates: u64 = 0,
/// How many numbers were refused because they are above `max_number`.
/// Recovery is never silent, so a caller can see that a number arrived
/// that no `ACK` frame could name.
refused: u64 = 0,

/// What `record` did with one packet number.
pub const Recorded = enum {
    /// The number is new and the set holds it.
    added,
    /// The set already held the number.
    duplicate,
    /// The set was full and this number is older than everything in it,
    /// so it was not kept. The peer will send the data again.
    dropped,
    /// The number is above `max_number`, so no `ACK` frame could name it.
    /// It was not kept.
    refused,
};

/// Options for `record`.
pub const RecordOptions = struct {
    /// Whether the packet carried a frame that must be acknowledged. RFC
    /// 9000 section 13.2.1 only obliges an endpoint for these.
    ack_eliciting: bool,
    /// True for the Initial and Handshake spaces, where section 13.2.1
    /// requires an immediate acknowledgment.
    handshake_space: bool,
    /// How long this endpoint may hold an acknowledgment back. It is the
    /// `max_ack_delay` this endpoint advertised, not the peer's.
    max_ack_delay: loss.Duration,
};

/// Records one received packet number.
///
/// **A number above `max_number` is refused and not kept.** The type is
/// `u64` and the wire form holds 62 bits, so a caller can offer a number
/// no `ACK` frame can name. Keeping it would make `build` fail for the
/// life of the connection, so the check runs here, before the set changes.
pub fn record(
    self: *AckRanges,
    number: u64,
    now: loss.Instant,
    options: RecordOptions,
) Recorded {
    if (number > max_number) {
        self.refused +|= 1;
        return .refused;
    }

    const above_all = self.len == 0 or number > self.ranges[0].largest;
    const in_order = self.len == 0 or (above_all and number - self.ranges[0].largest == 1);

    const result = self.insert(number);
    switch (result) {
        .duplicate => {
            self.duplicates +|= 1;
            // A duplicate says nothing new, so it arms no timer and moves
            // no deadline.
            return result;
        },
        .dropped => {
            self.dropped +|= 1;
            return result;
        },
        // `insert` never refuses, because the bound above already ran.
        // The arm is here so that a later refusal in `insert` arms no
        // timer either.
        .refused => return result,
        .added => {},
    }

    if (above_all) self.largest_time = now;

    if (!options.ack_eliciting) return result;

    self.eliciting_pending +|= 1;
    if (options.handshake_space or !in_order or self.eliciting_pending >= 2) {
        self.immediate = true;
        self.deadline = null;
        return result;
    }
    if (self.deadline == null) self.deadline = now +| options.max_ack_delay;
    return result;
}

/// Puts `number` into the range set, merging with whatever it touches.
///
/// The comparison against `range.largest` runs before any add, so
/// `range.largest + 1` is only formed when `number` is already above it
/// and the add cannot overflow.
fn insert(self: *AckRanges, number: u64) Recorded {
    var index: usize = 0;
    while (index < self.len) : (index += 1) {
        const range = &self.ranges[index];
        if (number > range.largest) {
            if (number != range.largest + 1) break;
            range.largest = number;
            self.mergeUp(index);
            return .added;
        }
        if (number >= range.smallest) return .duplicate;
        if (range.smallest > 0 and number == range.smallest - 1) {
            range.smallest = number;
            self.mergeDown(index);
            return .added;
        }
    }
    return self.insertAt(index, number);
}

/// Joins range `index` with the one above it when they now touch.
fn mergeUp(self: *AckRanges, index: usize) void {
    if (index == 0) return;
    const above = &self.ranges[index - 1];
    if (above.smallest != self.ranges[index].largest + 1) return;
    above.smallest = self.ranges[index].smallest;
    self.removeAt(index);
}

/// Joins range `index` with the one below it when they now touch.
fn mergeDown(self: *AckRanges, index: usize) void {
    if (index + 1 >= self.len) return;
    const below = &self.ranges[index + 1];
    if (self.ranges[index].smallest != below.largest + 1) return;
    self.ranges[index].smallest = below.smallest;
    self.removeAt(index + 1);
}

fn removeAt(self: *AckRanges, index: usize) void {
    std.debug.assert(index < self.len);
    var i = index;
    while (i + 1 < self.len) : (i += 1) self.ranges[i] = self.ranges[i + 1];
    self.len -= 1;
}

/// Puts a one-number range at `index`, dropping the smallest range first
/// when the set is full.
fn insertAt(self: *AckRanges, index: usize, number: u64) Recorded {
    if (self.len == max_ranges) {
        // The set is full. The smallest range is the one the peer needs
        // least, because it is the oldest. A number older than all of
        // them is not worth evicting a newer one for.
        if (index == max_ranges) return .dropped;
        self.len -= 1;
        self.dropped +|= 1;
    }
    var i = self.len;
    while (i > index) : (i -= 1) self.ranges[i] = self.ranges[i - 1];
    self.ranges[index] = .{ .largest = number, .smallest = number };
    self.len += 1;
    return .added;
}

/// The largest packet number this space has received, or null when none
/// has arrived.
pub fn largest(self: AckRanges) ?u64 {
    if (self.len == 0) return null;
    return self.ranges[0].largest;
}

/// True when this space holds `number`.
pub fn contains(self: AckRanges, number: u64) bool {
    for (self.ranges[0..self.len]) |range| {
        if (number > range.largest) return false;
        if (number >= range.smallest) return true;
    }
    return false;
}

/// True when an `ACK` frame is due now.
pub fn due(self: AckRanges, now: loss.Instant) bool {
    if (self.len == 0) return false;
    if (self.immediate) return true;
    const deadline = self.deadline orelse return false;
    return now >= deadline;
}

/// When the next delayed `ACK` is due, or null when none is armed. The
/// caller folds this into its own timer.
pub fn nextDeadline(self: AckRanges) ?loss.Instant {
    if (self.immediate) return 0;
    return self.deadline;
}

/// The ACK Delay field for a frame built now. RFC 9000 section 19.3: the
/// time since the largest acknowledged packet arrived, in microseconds,
/// divided by two to the power of `exponent`.
pub fn ackDelayField(self: AckRanges, now: loss.Instant, exponent: u6) u64 {
    const elapsed_us = loss.since(now, self.largest_time) / loss.ns_per_us;
    const scaled = elapsed_us >> exponent;
    return @min(scaled, varint.max_value);
}

/// Builds the `ACK` frame for this space.
///
/// The returned frame's `ranges` field points into `out`, so `out` must
/// outlive the frame. `out.len` must be at least `max_range_bytes`.
///
/// **Every refusal is an error and none is an assertion.** The set is fed
/// from the wire through `record`, and an assertion is compiled out of a
/// ReleaseFast build, so a shape this function cannot write must be a
/// named fault the caller can act on. `record` already refuses each of
/// them, so these arms report a set that was built some other way.
pub fn build(self: AckRanges, ack_delay: u64, out: []u8) BuildError!frame.Ack {
    if (self.len == 0) return error.NothingToAcknowledge;
    if (out.len < max_range_bytes) return error.NoSpace;
    if (self.ranges[0].largest > max_number) return error.RangeTooLarge;

    var writer: std.Io.Writer = .fixed(out);
    var index: usize = 1;
    while (index < self.len) : (index += 1) {
        const previous = self.ranges[index - 1];
        const current = self.ranges[index];
        // The set keeps at least one number of gap between neighbours, so
        // `previous.smallest - current.largest` is at least 2. RFC 9000
        // section 19.3.1. The comparison is written as a subtraction from
        // `previous.smallest` so that neither side can wrap.
        if (previous.smallest < 2 or current.largest > previous.smallest - 2) {
            return error.RangesOutOfOrder;
        }
        const gap = previous.smallest - current.largest - 2;
        // The buffer is sized for `max_ranges - 1` pairs of eight-byte
        // integers, so neither write runs out of room, and `record`
        // bounds every number at `max_number`, so neither write is too
        // large. Both faults are still reported.
        try writeRangeValue(&writer, gap);
        try writeRangeValue(&writer, current.largest - current.smallest);
    }

    return .{
        .largest_acknowledged = self.ranges[0].largest,
        .ack_delay = ack_delay,
        .ack_range_count = self.len - 1,
        .first_ack_range = self.ranges[0].largest - self.ranges[0].smallest,
        .ranges = out[0..writer.end],
        .ecn = null,
    };
}

/// Writes one Gap or one ACK Range Length, and names each way it can
/// fail.
fn writeRangeValue(writer: *std.Io.Writer, value: u64) BuildError!void {
    varint.write(writer, value) catch |err| return switch (err) {
        error.ValueTooLarge => error.RangeTooLarge,
        else => error.NoSpace,
    };
}

/// Records that an `ACK` frame for this space went out. RFC 9000 section
/// 13.2.1 restarts the count and the deadline.
pub fn onAckSent(self: *AckRanges) void {
    self.eliciting_pending = 0;
    self.immediate = false;
    self.deadline = null;
}

/// Empties the set. RFC 9002 section 6.4 discards a packet number space
/// with its keys, and nothing in it may be acknowledged after that.
pub fn clear(self: *AckRanges) void {
    self.* = .{};
}

test "one packet gives one range and an ACK frame that names it" {
    const testing = std.testing;
    var set: AckRanges = .{};
    try testing.expectEqual(Recorded.added, set.record(7, 100, .{
        .ack_eliciting = true,
        .handshake_space = false,
        .max_ack_delay = 25,
    }));
    try testing.expectEqual(@as(?u64, 7), set.largest());
    try testing.expect(set.contains(7));
    try testing.expect(!set.contains(6));

    var out: [max_range_bytes]u8 = undefined;
    const ack = try set.build(3, &out);
    try testing.expectEqual(@as(u64, 7), ack.largest_acknowledged);
    try testing.expectEqual(@as(u64, 0), ack.first_ack_range);
    try testing.expectEqual(@as(u64, 0), ack.ack_range_count);
    try testing.expectEqual(@as(u64, 3), ack.ack_delay);
}

test "packets that arrive in order coalesce into one range" {
    const testing = std.testing;
    var set: AckRanges = .{};
    for (0..10) |n| {
        _ = set.record(n, 100, .{ .ack_eliciting = false, .handshake_space = false, .max_ack_delay = 25 });
    }
    try testing.expectEqual(@as(usize, 1), set.len);
    try testing.expectEqual(@as(u64, 9), set.ranges[0].largest);
    try testing.expectEqual(@as(u64, 0), set.ranges[0].smallest);
}

test "a packet that fills a gap joins the two ranges either side of it" {
    const testing = std.testing;
    var set: AckRanges = .{};
    const opts: RecordOptions = .{ .ack_eliciting = false, .handshake_space = false, .max_ack_delay = 25 };
    _ = set.record(1, 100, opts);
    _ = set.record(3, 100, opts);
    try testing.expectEqual(@as(usize, 2), set.len);

    _ = set.record(2, 100, opts);
    try testing.expectEqual(@as(usize, 1), set.len);
    try testing.expectEqual(@as(u64, 3), set.ranges[0].largest);
    try testing.expectEqual(@as(u64, 1), set.ranges[0].smallest);
}

test "a duplicate is counted and does not change the set" {
    const testing = std.testing;
    var set: AckRanges = .{};
    const opts: RecordOptions = .{ .ack_eliciting = true, .handshake_space = false, .max_ack_delay = 25 };
    _ = set.record(5, 100, opts);
    _ = set.record(6, 100, opts);
    const before = set.len;
    try testing.expectEqual(Recorded.duplicate, set.record(5, 200, opts));
    try testing.expectEqual(Recorded.duplicate, set.record(6, 200, opts));
    try testing.expectEqual(before, set.len);
    try testing.expectEqual(@as(u64, 2), set.duplicates);
}

test "the frame this set builds decodes back to the same ranges" {
    const testing = std.testing;
    var set: AckRanges = .{};
    const opts: RecordOptions = .{ .ack_eliciting = false, .handshake_space = false, .max_ack_delay = 25 };
    // Three runs with gaps: 20..22, 15..17, and 9.
    for ([_]u64{ 20, 21, 22, 15, 16, 17, 9 }) |n| _ = set.record(n, 100, opts);
    try testing.expectEqual(@as(usize, 3), set.len);

    var range_bytes: [max_range_bytes]u8 = undefined;
    const ack = try set.build(0, &range_bytes);

    var packet: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&packet);
    try frame.encode(.{ .ack = ack }, &writer);

    var decoder: frame.Decoder = .init(packet[0..writer.end]);
    const decoded = (try decoder.next()).?;
    var iterator = decoded.ack.iterator();

    const first = (try iterator.next()).?;
    try testing.expectEqual(@as(u64, 22), first.largest);
    try testing.expectEqual(@as(u64, 20), first.smallest);
    const second = (try iterator.next()).?;
    try testing.expectEqual(@as(u64, 17), second.largest);
    try testing.expectEqual(@as(u64, 15), second.smallest);
    const third = (try iterator.next()).?;
    try testing.expectEqual(@as(u64, 9), third.largest);
    try testing.expectEqual(@as(u64, 9), third.smallest);
    try testing.expectEqual(@as(?frame.Range, null), try iterator.next());
}

test "a full set drops its smallest range instead of growing" {
    const testing = std.testing;
    var set: AckRanges = .{};
    const opts: RecordOptions = .{ .ack_eliciting = false, .handshake_space = false, .max_ack_delay = 25 };
    // Every other number, so each one is its own range.
    var n: u64 = 0;
    while (n < max_ranges * 2) : (n += 2) _ = set.record(n, 100, opts);
    try testing.expectEqual(max_ranges, set.len);
    try testing.expectEqual(@as(u64, 0), set.ranges[max_ranges - 1].largest);

    // One more range past the top pushes the oldest one out.
    _ = set.record(max_ranges * 2, 100, opts);
    try testing.expectEqual(max_ranges, set.len);
    try testing.expectEqual(@as(u64, 1), set.dropped);
    try testing.expect(!set.contains(0));
    try testing.expect(set.contains(max_ranges * 2));

    // A number older than everything the full set holds is not kept.
    try testing.expectEqual(Recorded.dropped, set.record(0, 100, opts));
    try testing.expectEqual(max_ranges, set.len);
    try testing.expect(!set.contains(0));
}

test "an ack-eliciting handshake packet is acknowledged at once" {
    const testing = std.testing;
    var set: AckRanges = .{};
    _ = set.record(0, 100, .{ .ack_eliciting = true, .handshake_space = true, .max_ack_delay = 25 });
    try testing.expect(set.immediate);
    try testing.expect(set.due(100));
    try testing.expectEqual(@as(?loss.Instant, null), set.deadline);
}

test "one ack-eliciting packet in order waits for max_ack_delay" {
    const testing = std.testing;
    var set: AckRanges = .{};
    const opts: RecordOptions = .{ .ack_eliciting = true, .handshake_space = false, .max_ack_delay = 25 };
    _ = set.record(0, 100, opts);
    try testing.expect(!set.immediate);
    try testing.expectEqual(@as(?loss.Instant, 125), set.deadline);
    try testing.expect(!set.due(124));
    try testing.expect(set.due(125));
}

test "two ack-eliciting packets are acknowledged without waiting" {
    const testing = std.testing;
    var set: AckRanges = .{};
    const opts: RecordOptions = .{ .ack_eliciting = true, .handshake_space = false, .max_ack_delay = 25 };
    _ = set.record(0, 100, opts);
    try testing.expect(!set.due(100));
    _ = set.record(1, 101, opts);
    try testing.expect(set.due(101));
}

test "a packet out of order is acknowledged without waiting" {
    const testing = std.testing;
    var set: AckRanges = .{};
    const opts: RecordOptions = .{ .ack_eliciting = true, .handshake_space = false, .max_ack_delay = 25 };
    _ = set.record(5, 100, opts);
    set.onAckSent();
    try testing.expect(!set.due(100));
    // Number 7 leaves a gap at 6, so the peer must hear about it now.
    _ = set.record(7, 101, opts);
    try testing.expect(set.due(101));
}

test "a packet that elicits no acknowledgment arms no timer" {
    const testing = std.testing;
    var set: AckRanges = .{};
    _ = set.record(0, 100, .{ .ack_eliciting = false, .handshake_space = false, .max_ack_delay = 25 });
    _ = set.record(9, 100, .{ .ack_eliciting = false, .handshake_space = false, .max_ack_delay = 25 });
    try testing.expect(!set.immediate);
    try testing.expectEqual(@as(?loss.Instant, null), set.deadline);
    try testing.expect(!set.due(std.math.maxInt(loss.Instant)));
}

test "sending an ACK clears the deadline and the count" {
    const testing = std.testing;
    var set: AckRanges = .{};
    const opts: RecordOptions = .{ .ack_eliciting = true, .handshake_space = false, .max_ack_delay = 25 };
    _ = set.record(0, 100, opts);
    _ = set.record(1, 100, opts);
    try testing.expect(set.due(100));
    set.onAckSent();
    try testing.expect(!set.due(100));
    try testing.expectEqual(@as(u32, 0), set.eliciting_pending);
    // The ranges stay, because the peer may lose the ACK and the next one
    // must still name them.
    try testing.expectEqual(@as(usize, 1), set.len);
}

test "the ACK Delay field scales by the exponent and saturates at the varint limit" {
    const testing = std.testing;
    var set: AckRanges = .{};
    _ = set.record(0, 1_000_000, .{ .ack_eliciting = true, .handshake_space = false, .max_ack_delay = 25 });
    // 8 ms later, which is 8000 microseconds. With an exponent of 3 that
    // is 1000 units.
    try testing.expectEqual(@as(u64, 1000), set.ackDelayField(1_000_000 + 8 * loss.ns_per_ms, 3));
    try testing.expectEqual(@as(u64, 8000), set.ackDelayField(1_000_000 + 8 * loss.ns_per_ms, 0));
    // A clock that stepped backwards gives zero, not a huge field.
    try testing.expectEqual(@as(u64, 0), set.ackDelayField(0, 3));
}

test "a build with no received packet reports it and a short buffer is refused" {
    const testing = std.testing;
    var set: AckRanges = .{};
    var out: [max_range_bytes]u8 = undefined;
    try testing.expectError(error.NothingToAcknowledge, set.build(0, &out));

    _ = set.record(1, 100, .{ .ack_eliciting = true, .handshake_space = false, .max_ack_delay = 25 });
    var small: [max_range_bytes - 1]u8 = undefined;
    try testing.expectError(error.NoSpace, set.build(0, &small));
}

test "a number above the wire bound is refused and never reaches build" {
    const testing = std.testing;
    const opts: RecordOptions = .{ .ack_eliciting = true, .handshake_space = false, .max_ack_delay = 25 };
    var set: AckRanges = .{};

    // Every number a variable-length integer cannot write is refused, and
    // the set is left as it was.
    try testing.expectEqual(Recorded.refused, set.record(max_number + 1, 100, opts));
    try testing.expectEqual(Recorded.refused, set.record(std.math.maxInt(u64), 100, opts));
    try testing.expectEqual(@as(usize, 0), set.len);
    try testing.expectEqual(@as(u64, 2), set.refused);
    try testing.expectEqual(@as(?u64, null), set.largest());
    try testing.expect(!set.contains(std.math.maxInt(u64)));
    // A refused number arms no timer either.
    try testing.expectEqual(@as(?loss.Instant, null), set.deadline);
    try testing.expect(!set.immediate);

    // The largest number the wire form holds is still taken.
    try testing.expectEqual(Recorded.added, set.record(max_number, 100, opts));
    var out: [max_range_bytes]u8 = undefined;
    const ack = try set.build(0, &out);
    try testing.expectEqual(max_number, ack.largest_acknowledged);

    // A huge number beside a small one would make a Gap no frame can
    // write. The refusal above is what keeps that pair out of the set.
    _ = set.record(1, 100, opts);
    try testing.expectEqual(@as(usize, 2), set.len);
    _ = try set.build(0, &out);
}

test "a build refuses a range set it cannot write instead of reaching unreachable" {
    const testing = std.testing;
    var out: [max_range_bytes]u8 = undefined;

    // A set built past `record`, which is the only way these shapes
    // exist. In a ReleaseFast build the old code read these as undefined
    // behaviour, so each one must now be a named error.
    var too_large: AckRanges = .{ .len = 2 };
    too_large.ranges[0] = .{ .largest = std.math.maxInt(u64), .smallest = std.math.maxInt(u64) };
    too_large.ranges[1] = .{ .largest = 3, .smallest = 3 };
    try testing.expectError(error.RangeTooLarge, too_large.build(0, &out));

    var overlapping: AckRanges = .{ .len = 2 };
    overlapping.ranges[0] = .{ .largest = 9, .smallest = 5 };
    overlapping.ranges[1] = .{ .largest = 6, .smallest = 2 };
    try testing.expectError(error.RangesOutOfOrder, overlapping.build(0, &out));

    var touching: AckRanges = .{ .len = 2 };
    touching.ranges[0] = .{ .largest = 9, .smallest = 5 };
    touching.ranges[1] = .{ .largest = 4, .smallest = 0 };
    try testing.expectError(error.RangesOutOfOrder, touching.build(0, &out));

    var at_zero: AckRanges = .{ .len = 2 };
    at_zero.ranges[0] = .{ .largest = 1, .smallest = 1 };
    at_zero.ranges[1] = .{ .largest = 0, .smallest = 0 };
    try testing.expectError(error.RangesOutOfOrder, at_zero.build(0, &out));
}

test "clearing a discarded space leaves nothing to acknowledge" {
    const testing = std.testing;
    var set: AckRanges = .{};
    _ = set.record(4, 100, .{ .ack_eliciting = true, .handshake_space = true, .max_ack_delay = 25 });
    set.clear();
    try testing.expectEqual(@as(?u64, null), set.largest());
    try testing.expect(!set.due(std.math.maxInt(loss.Instant)));
    var out: [max_range_bytes]u8 = undefined;
    try testing.expectError(error.NothingToAcknowledge, set.build(0, &out));
}
