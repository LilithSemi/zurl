//! NewReno congestion control, RFC 9002 section 7 and appendix B.
//!
//! Three states, and the window tells you which one you are in:
//!
//! - **Slow start**, while the window is below `ssthresh`. Each
//!   acknowledged byte grows the window by a byte, so the window doubles
//!   every round trip.
//! - **Recovery**, while `recovery_start` is set and the packet being
//!   acknowledged was sent before it. The window does not grow. One loss
//!   halves the window once, however many packets that loss covered.
//! - **Congestion avoidance**, otherwise. One more datagram of window per
//!   window of bytes acknowledged, so the window grows by about one
//!   datagram per round trip.
//!
//! ## What is here and what is not
//!
//! **Persistent congestion is here.** RFC 9002 section 7.6 collapses the
//! window to the minimum when a whole probe timeout period times three
//! passed with nothing acknowledged. `Recovery` decides whether a run of
//! losses meets the rule, because that needs the sent-packet record, and
//! it calls `onPersistentCongestion`.
//!
//! **ECN is not here.** RFC 9002 section 7.1 treats an increase in the
//! peer's ECN-CE count as a congestion event. This build never marks a
//! datagram as ECN capable, so a well-behaved peer reports no CE count,
//! and a peer that reports one is describing traffic this endpoint did not
//! send. The `ACK` frame's ECN counts are decoded by `frame.zig` and are
//! not read here. Wiring ECN needs the socket option that sets the
//! codepoint, which belongs to the connection engine.
//!
//! **Pacing is not here.** Section 7.7 says an endpoint should pace, and
//! names it a should. Pacing needs a send timer in the engine above.
//! `available` gives that engine the window it has left.
//!
//! ## The unit
//!
//! Every number here is bytes. `max_datagram_size` is the unit the RFC
//! counts window growth in, and it is the largest datagram this endpoint
//! sends, not the largest the path allows.

const std = @import("std");

const loss = @import("loss.zig");

const Congestion = @This();

/// The largest datagram this endpoint sends. RFC 9002 section 7.2 uses it
/// for the initial window, the minimum window, and the growth step.
max_datagram_size: u64,
/// How many bytes the connection may have in flight. RFC 9002 section 7.
window: u64,
/// How many bytes of in-flight packets are outstanding.
bytes_in_flight: u64 = 0,
/// The slow start threshold. RFC 9002 appendix B.2 starts it at
/// "infinite", which is the largest value the type holds.
ssthresh: u64 = std.math.maxInt(u64),
/// When the current recovery period started, or null when there is none.
/// A packet sent at or before this instant does not grow the window and
/// does not start a second recovery period. RFC 9002 section 7.3.1.
recovery_start: ?loss.Instant = null,
/// Bytes acknowledged in congestion avoidance since the last time the
/// window grew. RFC 9002 appendix B.5 keeps this so integer arithmetic
/// gives the same growth as the RFC's division.
bytes_acked: u64 = 0,

/// How many congestion events halved the window. **Recovery is never
/// silent**: a caller that wants to say why a transfer is slow reads
/// this rather than guessing.
congestion_events: u64 = 0,
/// How many times persistent congestion collapsed the window to the
/// minimum. RFC 9002 section 7.6.
persistent_congestion_events: u64 = 0,

/// The window a connection starts with. RFC 9002 section 7.2:
/// `min(10 * max_datagram_size, max(14720, 2 * max_datagram_size))`.
pub fn initialWindow(max_datagram_size: u64) u64 {
    return @min(10 *| max_datagram_size, @max(14720, 2 *| max_datagram_size));
}

/// The floor under the window. RFC 9002 section 7.2:
/// `2 * max_datagram_size`.
pub fn minimumWindow(max_datagram_size: u64) u64 {
    return 2 *| max_datagram_size;
}

/// A controller at the start of a connection.
pub fn init(max_datagram_size: u64) Congestion {
    std.debug.assert(max_datagram_size > 0);
    return .{
        .max_datagram_size = max_datagram_size,
        .window = initialWindow(max_datagram_size),
    };
}

/// Records an in-flight packet leaving. RFC 9002 appendix B.4.
pub fn onPacketSent(self: *Congestion, bytes: u64) void {
    self.bytes_in_flight +|= bytes;
}

/// True when the packet was sent before the current recovery period
/// started, so it says nothing new about the path. RFC 9002 section 7.3.1.
pub fn inRecovery(self: Congestion, sent_time: loss.Instant) bool {
    const start = self.recovery_start orelse return false;
    return sent_time <= start;
}

/// Records one acknowledged in-flight packet. RFC 9002 appendix B.5.
pub fn onPacketAcked(self: *Congestion, sent_time: loss.Instant, bytes: u64) void {
    self.bytes_in_flight -|= bytes;

    // A packet from before the recovery period started grows nothing.
    if (self.inRecovery(sent_time)) return;

    if (self.window < self.ssthresh) {
        // Slow start.
        self.window +|= bytes;
        return;
    }

    // Congestion avoidance. The accumulator is appendix B.5's `bytes_acked`
    // and it is what makes the integer form match the RFC's division.
    self.bytes_acked +|= bytes;
    while (self.bytes_acked >= self.window) {
        self.bytes_acked -= self.window;
        self.window +|= self.max_datagram_size;
    }
}

/// Halves the window once for a loss. RFC 9002 appendix B.6.
///
/// `sent_time` is when the **largest** lost packet was sent. A second call
/// naming a packet from inside the period this call started changes
/// nothing, which is what stops one round trip of losses from halving the
/// window several times.
pub fn onCongestionEvent(self: *Congestion, sent_time: loss.Instant, now: loss.Instant) void {
    if (self.inRecovery(sent_time)) return;

    self.recovery_start = now;
    self.congestion_events +|= 1;

    // kLossReductionFactor is 0.5. RFC 9002 section 7.3.2.
    self.ssthresh = self.window / 2;
    self.window = @max(self.ssthresh, minimumWindow(self.max_datagram_size));
    self.bytes_acked = 0;
}

/// Removes lost bytes from the in-flight count. RFC 9002 appendix B.8.
pub fn onPacketsLost(self: *Congestion, bytes: u64) void {
    self.bytes_in_flight -|= bytes;
}

/// Collapses the window to the minimum. RFC 9002 section 7.6.
///
/// The recovery period is cleared with it, because the connection is
/// starting again from slow start and the next acknowledgment must be
/// allowed to grow the window.
pub fn onPersistentCongestion(self: *Congestion) void {
    self.window = minimumWindow(self.max_datagram_size);
    self.recovery_start = null;
    self.bytes_acked = 0;
    self.persistent_congestion_events +|= 1;
}

/// Drops the in-flight bytes of a packet number space that was discarded.
/// RFC 9002 section 6.4.
pub fn onSpaceDiscarded(self: *Congestion, bytes: u64) void {
    self.bytes_in_flight -|= bytes;
}

/// How many more bytes the window allows in flight. Zero when the window
/// is full.
pub fn available(self: Congestion) u64 {
    return self.window -| self.bytes_in_flight;
}

/// True when `bytes` more may go out under the window. A probe sent on a
/// probe timeout ignores this: RFC 9002 section 7 lets a probe pass the
/// window so a connection with everything lost is not deadlocked.
pub fn canSend(self: Congestion, bytes: u64) bool {
    return self.bytes_in_flight +| bytes <= self.window;
}

test "the initial window is ten datagrams at the QUIC minimum datagram size" {
    const testing = std.testing;
    // 1200 byte datagrams: min(12000, max(14720, 2400)) = 12000.
    try testing.expectEqual(@as(u64, 12000), initialWindow(1200));
    try testing.expectEqual(@as(u64, 2400), minimumWindow(1200));

    // Above 1472 bytes ten datagrams pass 14720, so the min takes the
    // constant arm. That constant is what section 7.2 puts the max there
    // for, and a reader should see both arms exercised.
    try testing.expectEqual(@as(u64, 14720), initialWindow(1500));
    try testing.expectEqual(@as(u64, 3000), minimumWindow(1500));

    // A one byte datagram size still gives a window two datagrams wide,
    // so the floor can never be zero.
    try testing.expectEqual(@as(u64, 2), minimumWindow(1));
}

test "slow start grows the window by every acknowledged byte" {
    const testing = std.testing;
    var cc: Congestion = .init(1200);
    try testing.expectEqual(@as(u64, 12000), cc.window);

    cc.onPacketSent(1200);
    try testing.expectEqual(@as(u64, 1200), cc.bytes_in_flight);
    cc.onPacketAcked(10, 1200);
    try testing.expectEqual(@as(u64, 0), cc.bytes_in_flight);
    try testing.expectEqual(@as(u64, 13200), cc.window);
}

test "a congestion event halves the window once and enters recovery" {
    const testing = std.testing;
    var cc: Congestion = .init(1200);
    cc.onPacketSent(6000);

    cc.onCongestionEvent(100, 200);
    try testing.expectEqual(@as(u64, 6000), cc.ssthresh);
    try testing.expectEqual(@as(u64, 6000), cc.window);
    try testing.expectEqual(@as(u64, 1), cc.congestion_events);
    try testing.expectEqual(@as(?loss.Instant, 200), cc.recovery_start);

    // A second loss from the same round trip changes nothing.
    cc.onCongestionEvent(150, 300);
    try testing.expectEqual(@as(u64, 6000), cc.window);
    try testing.expectEqual(@as(u64, 1), cc.congestion_events);

    // A loss of a packet sent after the period started halves it again.
    cc.onCongestionEvent(250, 400);
    try testing.expectEqual(@as(u64, 3000), cc.window);
    try testing.expectEqual(@as(u64, 2), cc.congestion_events);
}

test "the window never falls below two datagrams" {
    const testing = std.testing;
    var cc: Congestion = .init(1200);
    var round: usize = 0;
    var when: loss.Instant = 10;
    while (round < 20) : (round += 1) {
        cc.onCongestionEvent(when, when + 1);
        when += 10;
    }
    try testing.expectEqual(minimumWindow(1200), cc.window);
    try testing.expect(cc.window > 0);
}

test "an acknowledgment of a packet sent before recovery started does not grow the window" {
    const testing = std.testing;
    var cc: Congestion = .init(1200);
    cc.onPacketSent(12000);
    cc.onCongestionEvent(100, 200);
    const halved = cc.window;
    try testing.expectEqual(@as(u64, 6000), halved);

    // Sent at 100, which is at or before the recovery start of 200. The
    // bytes leave the flight but the window does not move and the
    // congestion avoidance accumulator does not move either.
    cc.onPacketAcked(100, 6000);
    try testing.expectEqual(halved, cc.window);
    try testing.expectEqual(@as(u64, 6000), cc.bytes_in_flight);
    try testing.expectEqual(@as(u64, 0), cc.bytes_acked);

    // Sent at 201, which is after it, so one window of bytes grows the
    // window by one datagram.
    cc.onPacketAcked(201, 6000);
    try testing.expectEqual(@as(u64, 7200), cc.window);
}

test "congestion avoidance adds one datagram per window of acknowledged bytes" {
    const testing = std.testing;
    var cc: Congestion = .init(1200);
    // Force congestion avoidance with a window at the threshold.
    cc.ssthresh = 6000;
    cc.window = 6000;
    cc.recovery_start = null;

    // 5999 bytes is not a window, so the window does not move.
    cc.onPacketAcked(10, 5999);
    try testing.expectEqual(@as(u64, 6000), cc.window);
    try testing.expectEqual(@as(u64, 5999), cc.bytes_acked);

    // One more byte completes the window.
    cc.onPacketAcked(10, 1);
    try testing.expectEqual(@as(u64, 7200), cc.window);
    try testing.expectEqual(@as(u64, 0), cc.bytes_acked);
}

test "persistent congestion collapses the window to the minimum and leaves recovery" {
    const testing = std.testing;
    var cc: Congestion = .init(1200);
    cc.onCongestionEvent(100, 200);
    cc.onPersistentCongestion();

    try testing.expectEqual(minimumWindow(1200), cc.window);
    try testing.expectEqual(@as(?loss.Instant, null), cc.recovery_start);
    try testing.expectEqual(@as(u64, 1), cc.persistent_congestion_events);

    // The next acknowledgment grows the window again, because slow start
    // is running and there is no recovery period to sit inside.
    cc.onPacketAcked(300, 1200);
    try testing.expect(cc.window > minimumWindow(1200));
}

test "the in-flight count never goes below zero however many bytes are removed" {
    const testing = std.testing;
    var cc: Congestion = .init(1200);
    cc.onPacketSent(1200);
    cc.onPacketsLost(9_999_999);
    try testing.expectEqual(@as(u64, 0), cc.bytes_in_flight);
    cc.onPacketAcked(10, 9_999_999);
    try testing.expectEqual(@as(u64, 0), cc.bytes_in_flight);
}

test "canSend and available agree about the room left under the window" {
    const testing = std.testing;
    var cc: Congestion = .init(1200);
    try testing.expectEqual(@as(u64, 12000), cc.available());
    try testing.expect(cc.canSend(12000));
    try testing.expect(!cc.canSend(12001));

    cc.onPacketSent(11_000);
    try testing.expectEqual(@as(u64, 1000), cc.available());
    try testing.expect(cc.canSend(1000));
    try testing.expect(!cc.canSend(1001));

    cc.onPacketSent(5000);
    try testing.expectEqual(@as(u64, 0), cc.available());
    try testing.expect(!cc.canSend(1));
}
