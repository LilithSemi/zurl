//! The round-trip time estimate of RFC 9002 section 5.
//!
//! Four numbers, and each one has a job:
//!
//! - `latest` is the most recent sample. Loss detection uses it, because
//!   a path that just got slower must not have its packets called lost.
//! - `smoothed` is the exponentially weighted average. The probe timeout
//!   is built from it.
//! - `rttvar` is the mean deviation. It is what stops a steady path from
//!   arming a probe too early.
//! - `min` is the smallest sample seen, and it is the floor that makes a
//!   hostile ACK Delay harmless. It never falls below `loss.granularity`,
//!   because a sample under the timer granularity is not a measurement
//!   and a floor of zero is no floor at all.
//!
//! ## Why a hostile ACK cannot stall the connection here
//!
//! The `ACK Delay` field is a variable-length integer the peer chose, so
//! it can name 2^62 in units of 2^20 microseconds. Two rules of section
//! 5.3 stop it, and both are in `update`:
//!
//! 1. **The delay is only subtracted when the result stays at or above
//!    `min`.** Section 5.3: "MUST NOT subtract the acknowledgment delay
//!    from the RTT sample if the resulting value is smaller than the
//!    min_rtt." So an enormous delay is not subtracted at all. There is
//!    no subtraction that can go below zero.
//! 2. **The delay is always capped at the peer's `max_ack_delay`**, which
//!    RFC 9000 section 18.2 already bounds below 2^14 milliseconds.
//!    Section 5.3 asks for the cap once the handshake is confirmed. This
//!    file applies it before confirmation as well, and drops the delay
//!    altogether until then, because a transport parameter the handshake
//!    has not confirmed is not a promise yet.
//!
//! The delay is also ignored for the Initial and Handshake spaces, which
//! section 5.3 permits, because a peer that could not decrypt a packet
//! reports a delay that means nothing.
//!
//! The estimate can only be moved by a sample, and a sample only exists
//! for a packet this endpoint really sent and the peer really named. See
//! `Recovery.onAckReceived`, which refuses an ACK naming a packet number
//! that was never sent before any of this runs.

const std = @import("std");

const loss = @import("loss.zig");
const Duration = loss.Duration;

const Rtt = @This();

/// The most recent sample. Zero before the first one.
latest: Duration = 0,
/// The weighted average. RFC 9002 section 5.3 starts it at `kInitialRtt`
/// so a probe timeout exists before any packet is acknowledged.
smoothed: Duration = loss.initial_rtt,
/// The mean deviation, started at half of `kInitialRtt`. Section 5.3.
rttvar: Duration = loss.initial_rtt / 2,
/// The smallest sample seen over the connection. RFC 9002 section 5.2.
/// Zero before the first sample.
min: Duration = 0,
/// Whether a sample has ever arrived. Before the first one `smoothed` and
/// `rttvar` hold the RFC's starting values and not measurements.
has_sample: bool = false,
/// The peer's `max_ack_delay` transport parameter, RFC 9000 section 18.2.
/// It bounds the delay a peer may claim once the handshake is confirmed,
/// and it is added to the probe timeout for the application space.
max_ack_delay: Duration = loss.default_max_ack_delay,

/// What one acknowledgment says about the path.
pub const Sample = struct {
    /// `now - sent_time` for the largest newly acknowledged packet.
    rtt: Duration,
    /// The peer's stated delay, already turned into nanoseconds by the
    /// caller. `Recovery` does that with saturating arithmetic, so a
    /// field naming 2^62 arrives here as the largest duration and not as
    /// a wrapped small one.
    ack_delay: Duration,
    /// Which packet number space the acknowledgment came from.
    space: loss.Space,
    /// Whether the handshake is confirmed. RFC 9001 section 4.1.2 makes
    /// the `HANDSHAKE_DONE` frame the point for a client.
    handshake_confirmed: bool,
};

/// Folds one sample into the estimate. RFC 9002 section 5.3.
///
/// The order of the last three lines is the RFC's own and not RFC 6298's.
/// Section 5.3 updates `smoothed_rtt` first and then measures the
/// deviation against the **new** average. TCP does it the other way. A
/// reader who knows RFC 6298 will look at this and think it is wrong, so
/// it is written out here: this is what QUIC specifies.
pub fn update(self: *Rtt, sample: Sample) void {
    self.latest = sample.rtt;

    if (!self.has_sample) {
        self.min = @max(sample.rtt, loss.granularity);
        self.smoothed = sample.rtt;
        self.rttvar = sample.rtt / 2;
        self.has_sample = true;
        return;
    }

    // **The floor under `min`.** RFC 9002 section 5.2 keeps the smallest
    // sample seen, and section 5.3 makes that value the guard on the one
    // subtraction below. A sample of zero, which a loopback path or a
    // clock that did not move gives, would set the guard to zero and let
    // any stated delay through. `loss.granularity` is the smallest
    // interval this endpoint can measure, so a sample under it is not a
    // measurement.
    self.min = @max(@min(self.min, sample.rtt), loss.granularity);

    var ack_delay = sample.ack_delay;
    // RFC 9002 section 5.3: an endpoint may ignore the delay outside the
    // application space. The peer states `max_ack_delay` for that space
    // alone, and a peer that could not decrypt a packet has no honest
    // delay to report for the other two.
    if (sample.space != .application) ack_delay = 0;
    // **The peer's stated delay is never applied above the value the peer
    // itself advertised.** Section 5.3 asks for the cap once the
    // handshake is confirmed. Before that the transport parameter is not
    // confirmed either, so the delay is not trusted at all and is
    // dropped. Dropping it can only make the sample larger, which
    // lengthens every timer built from it, and that is the safe
    // direction.
    if (!sample.handshake_confirmed) ack_delay = 0;
    ack_delay = @min(ack_delay, self.max_ack_delay);

    // **The one subtraction, and the guard that makes it safe.** The add
    // saturates, so a delay near 2^64 makes the comparison false and the
    // sample is used whole.
    var adjusted = sample.rtt;
    if (sample.rtt >= self.min +| ack_delay) adjusted = sample.rtt - ack_delay;

    // smoothed = 7/8 * smoothed + 1/8 * adjusted, written so no product
    // is formed. `smoothed * 7` overflows above 2^61 nanoseconds.
    self.smoothed = self.smoothed - (self.smoothed >> 3) +| (adjusted >> 3);

    const deviation = if (self.smoothed > adjusted)
        self.smoothed - adjusted
    else
        adjusted - self.smoothed;

    // rttvar = 3/4 * rttvar + 1/4 * deviation, written the same way.
    self.rttvar = self.rttvar - (self.rttvar >> 2) +| (deviation >> 2);
}

/// The probe timeout before any backoff. RFC 9002 section 6.2.1:
/// `smoothed_rtt + max(4 * rttvar, kGranularity)`.
///
/// `max_ack_delay` is **not** added here. Section 6.2.1 adds it only for
/// the application space, and `Recovery.ptoTimeAndSpace` is where that
/// happens, so this value stays usable for the two handshake spaces.
pub fn ptoBase(self: Rtt) Duration {
    return self.smoothed +| @max(self.rttvar *| 4, loss.granularity);
}

/// The time a packet must be older than before the time threshold calls
/// it lost. RFC 9002 section 6.1.2:
/// `max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity)`.
pub fn lossDelay(self: Rtt) Duration {
    return @max(loss.timeThreshold(@max(self.smoothed, self.latest)), loss.granularity);
}

/// How long a run of losses must last before it counts as persistent
/// congestion. RFC 9002 section 7.6.1: the probe timeout with no backoff,
/// including `max_ack_delay`, times `kPersistentCongestionThreshold`.
pub fn persistentCongestionDuration(self: Rtt) Duration {
    return (self.ptoBase() +| self.max_ack_delay) *| loss.persistent_congestion_threshold;
}

test "the first sample sets every field from itself, RFC 9002 section 5.3" {
    const testing = std.testing;
    var rtt: Rtt = .{};
    try testing.expectEqual(loss.initial_rtt, rtt.smoothed);
    try testing.expectEqual(loss.initial_rtt / 2, rtt.rttvar);
    try testing.expect(!rtt.has_sample);

    rtt.update(.{
        .rtt = 100 * loss.ns_per_ms,
        .ack_delay = 0,
        .space = .initial,
        .handshake_confirmed = false,
    });

    try testing.expect(rtt.has_sample);
    try testing.expectEqual(100 * loss.ns_per_ms, rtt.latest);
    try testing.expectEqual(100 * loss.ns_per_ms, rtt.min);
    try testing.expectEqual(100 * loss.ns_per_ms, rtt.smoothed);
    try testing.expectEqual(50 * loss.ns_per_ms, rtt.rttvar);
}

test "the second sample is 7/8 of the average plus 1/8 of it, worked by hand" {
    const testing = std.testing;
    const ms = loss.ns_per_ms;
    var rtt: Rtt = .{};
    rtt.update(.{ .rtt = 80 * ms, .ack_delay = 0, .space = .initial, .handshake_confirmed = false });
    // smoothed 80 ms, rttvar 40 ms, min 80 ms.
    rtt.update(.{ .rtt = 160 * ms, .ack_delay = 0, .space = .initial, .handshake_confirmed = false });

    // smoothed = 80 - 10 + 20 = 90 ms.
    try testing.expectEqual(@as(Duration, 90 * ms), rtt.smoothed);
    // deviation = |90 - 160| = 70 ms. rttvar = 40 - 10 + 17.5 = 47.5 ms.
    try testing.expectEqual(@as(Duration, 47_500_000), rtt.rttvar);
    try testing.expectEqual(@as(Duration, 80 * ms), rtt.min);
    try testing.expectEqual(@as(Duration, 160 * ms), rtt.latest);
}

test "a sample below the timer granularity does not take min_rtt under it" {
    const testing = std.testing;
    const ms = loss.ns_per_ms;
    // A loopback path, or a clock that did not move between the send and
    // the acknowledgment, gives a sample of zero.
    var first_zero: Rtt = .{ .max_ack_delay = 1000 * ms };
    first_zero.update(.{ .rtt = 0, .ack_delay = 0, .space = .application, .handshake_confirmed = true });
    try testing.expectEqual(loss.granularity, first_zero.min);
    try testing.expectEqual(@as(Duration, 0), first_zero.latest);

    // Without the floor the guard below reads `20 ms >= 0 + 20 ms`, which
    // is true, so the delay is subtracted whole and the sample becomes
    // zero. With the floor it reads `20 ms >= 1 ms + 20 ms`, which is
    // false, and section 5.3 leaves the sample alone.
    first_zero.update(.{ .rtt = 20 * ms, .ack_delay = 20 * ms, .space = .application, .handshake_confirmed = true });
    try testing.expectEqual(loss.granularity, first_zero.min);
    // adjusted = 20 ms. smoothed = 0 - 0 + 2.5 = 2.5 ms, and not zero.
    try testing.expectEqual(@as(Duration, 2_500_000), first_zero.smoothed);
    try testing.expectEqual(@as(Duration, 4_375_000), first_zero.rttvar);

    // A later sample under the granularity cannot pull the floor down
    // either.
    var later: Rtt = .{};
    later.update(.{ .rtt = 50 * ms, .ack_delay = 0, .space = .application, .handshake_confirmed = true });
    later.update(.{ .rtt = 1, .ack_delay = 0, .space = .application, .handshake_confirmed = true });
    try testing.expectEqual(loss.granularity, later.min);
}

test "the acknowledgment delay is subtracted in the application space" {
    const testing = std.testing;
    const ms = loss.ns_per_ms;
    // The cap is well above the stated delay, so the subtraction is the
    // only thing this test measures.
    var rtt: Rtt = .{ .max_ack_delay = 1000 * ms };
    rtt.update(.{ .rtt = 100 * ms, .ack_delay = 0, .space = .application, .handshake_confirmed = true });
    rtt.update(.{ .rtt = 200 * ms, .ack_delay = 40 * ms, .space = .application, .handshake_confirmed = true });

    // adjusted = 200 - 40 = 160 ms, since 200 >= min(100) + 40.
    // smoothed = 100 - 12.5 + 20 = 107.5 ms.
    try testing.expectEqual(@as(Duration, 107_500_000), rtt.smoothed);
}

test "the acknowledgment delay is ignored outside the application space" {
    const testing = std.testing;
    const ms = loss.ns_per_ms;
    var with_delay: Rtt = .{};
    var without: Rtt = .{};
    for ([_]loss.Space{ .initial, .handshake }) |space| {
        // The cap is well above the stated delay, so the space rule is
        // the only thing that can drop it.
        with_delay = .{ .max_ack_delay = 1000 * ms };
        without = .{ .max_ack_delay = 1000 * ms };
        with_delay.update(.{ .rtt = 100 * ms, .ack_delay = 0, .space = space, .handshake_confirmed = true });
        without.update(.{ .rtt = 100 * ms, .ack_delay = 0, .space = space, .handshake_confirmed = true });
        with_delay.update(.{ .rtt = 200 * ms, .ack_delay = 90 * ms, .space = space, .handshake_confirmed = true });
        without.update(.{ .rtt = 200 * ms, .ack_delay = 0, .space = space, .handshake_confirmed = true });
        try testing.expectEqual(without.smoothed, with_delay.smoothed);
        try testing.expectEqual(without.rttvar, with_delay.rttvar);
    }
}

test "after the handshake is confirmed the delay is capped at the peer's max_ack_delay" {
    const testing = std.testing;
    const ms = loss.ns_per_ms;
    var capped: Rtt = .{ .max_ack_delay = 25 * ms };
    var stated: Rtt = .{ .max_ack_delay = 25 * ms };
    capped.update(.{ .rtt = 100 * ms, .ack_delay = 0, .space = .application, .handshake_confirmed = true });
    stated.update(.{ .rtt = 100 * ms, .ack_delay = 0, .space = .application, .handshake_confirmed = true });

    // The peer claims 90 ms, which is above the 25 ms it advertised.
    capped.update(.{ .rtt = 200 * ms, .ack_delay = 90 * ms, .space = .application, .handshake_confirmed = true });
    // The same sample with the delay the cap allows.
    stated.update(.{ .rtt = 200 * ms, .ack_delay = 25 * ms, .space = .application, .handshake_confirmed = true });

    try testing.expectEqual(stated.smoothed, capped.smoothed);
    try testing.expectEqual(stated.rttvar, capped.rttvar);
    // adjusted = 200 - 25 = 175 ms. smoothed = 100 - 12.5 + 21.875.
    try testing.expectEqual(@as(Duration, 109_375_000), capped.smoothed);
}

test "before the handshake is confirmed the stated delay is dropped and not applied" {
    const testing = std.testing;
    const ms = loss.ns_per_ms;
    // The peer advertised 25 ms and states 90 ms. Section 5.3 asks for
    // the cap only after confirmation, which would leave 90 ms applied
    // whole before it. The delay is dropped instead.
    var early: Rtt = .{ .max_ack_delay = 25 * ms };
    var none: Rtt = .{ .max_ack_delay = 25 * ms };
    early.update(.{ .rtt = 100 * ms, .ack_delay = 0, .space = .application, .handshake_confirmed = false });
    none.update(.{ .rtt = 100 * ms, .ack_delay = 0, .space = .application, .handshake_confirmed = false });

    early.update(.{ .rtt = 200 * ms, .ack_delay = 90 * ms, .space = .application, .handshake_confirmed = false });
    none.update(.{ .rtt = 200 * ms, .ack_delay = 0, .space = .application, .handshake_confirmed = false });

    try testing.expectEqual(none.smoothed, early.smoothed);
    try testing.expectEqual(none.rttvar, early.rttvar);
    // adjusted = 200 ms whole. smoothed = 100 - 12.5 + 25 = 112.5 ms.
    try testing.expectEqual(@as(Duration, 112_500_000), early.smoothed);

    // After confirmation the same frame is worth 25 ms of delay and no
    // more, so the two rules differ and neither is the peer's 90 ms.
    var late: Rtt = .{ .max_ack_delay = 25 * ms };
    late.update(.{ .rtt = 100 * ms, .ack_delay = 0, .space = .application, .handshake_confirmed = true });
    late.update(.{ .rtt = 200 * ms, .ack_delay = 90 * ms, .space = .application, .handshake_confirmed = true });
    try testing.expectEqual(@as(Duration, 109_375_000), late.smoothed);
}

test "a delay that would take the sample below min_rtt is not subtracted" {
    const testing = std.testing;
    const ms = loss.ns_per_ms;
    var rtt: Rtt = .{ .max_ack_delay = 1000 * ms };
    rtt.update(.{ .rtt = 100 * ms, .ack_delay = 0, .space = .application, .handshake_confirmed = true });
    // min is 100 ms. A sample of 120 ms with a delay of 50 ms would give
    // 70 ms, which is below min, so section 5.3 leaves the sample alone.
    rtt.update(.{ .rtt = 120 * ms, .ack_delay = 50 * ms, .space = .application, .handshake_confirmed = true });

    // smoothed = 100 - 12.5 + 15 = 102.5 ms, the whole sample folded in.
    try testing.expectEqual(@as(Duration, 102_500_000), rtt.smoothed);
}

test "an ACK Delay of 2^62 units does not underflow and does not stall the estimate" {
    const testing = std.testing;
    var rtt: Rtt = .{ .max_ack_delay = 25 * loss.ns_per_ms };
    rtt.update(.{
        .rtt = 100 * loss.ns_per_ms,
        .ack_delay = 0,
        .space = .application,
        .handshake_confirmed = true,
    });
    const before = rtt.smoothed;

    // The largest duration a caller can hand over, which is what a
    // saturating conversion of a 2^62 varint gives. The cap takes it to
    // 25 ms, and the min guard then refuses to subtract even that.
    rtt.update(.{
        .rtt = 100 * loss.ns_per_ms,
        .ack_delay = std.math.maxInt(Duration),
        .space = .application,
        .handshake_confirmed = true,
    });

    // The delay was not subtracted, so the estimate did not move.
    try testing.expectEqual(before, rtt.smoothed);
    try testing.expectEqual(100 * loss.ns_per_ms, rtt.min);
    // And the probe timeout is still a real number the connection can use.
    try testing.expect(rtt.ptoBase() > 0);
    try testing.expect(rtt.ptoBase() < loss.max_pto);
}

test "a peer that repeats a huge delay cannot drive the average to zero" {
    const testing = std.testing;
    var rtt: Rtt = .{ .max_ack_delay = 25 * loss.ns_per_ms };
    rtt.update(.{
        .rtt = 100 * loss.ns_per_ms,
        .ack_delay = 0,
        .space = .application,
        .handshake_confirmed = true,
    });
    var round: usize = 0;
    while (round < 1000) : (round += 1) {
        rtt.update(.{
            .rtt = 100 * loss.ns_per_ms,
            .ack_delay = std.math.maxInt(Duration),
            .space = .application,
            .handshake_confirmed = true,
        });
    }
    // The cap took the delay to 25 ms and the min guard then refused to
    // subtract it, because 100 ms is below min(100 ms) plus 25 ms. Every
    // round folded the whole 100 ms sample back in, so the average never
    // moved at all.
    try testing.expectEqual(@as(Duration, 100 * loss.ns_per_ms), rtt.smoothed);
    try testing.expectEqual(@as(Duration, 100 * loss.ns_per_ms), rtt.min);
    // The deviation decayed by a quarter each round and stopped at 3
    // nanoseconds, where the shift truncates to zero. The granularity is
    // what holds the probe timeout above the average from there.
    try testing.expectEqual(@as(Duration, 3), rtt.rttvar);
    try testing.expectEqual(100 * loss.ns_per_ms + loss.granularity, rtt.ptoBase());
}

test "the probe timeout base is smoothed plus four deviations, with a granularity floor" {
    const testing = std.testing;
    var rtt: Rtt = .{};
    rtt.update(.{ .rtt = 100 * loss.ns_per_ms, .ack_delay = 0, .space = .initial, .handshake_confirmed = false });
    // smoothed 100 ms, rttvar 50 ms, so 100 + 200 = 300 ms.
    try testing.expectEqual(300 * loss.ns_per_ms, rtt.ptoBase());

    // A path with no measured jitter still waits at least one granularity
    // beyond the average.
    var steady: Rtt = .{ .smoothed = 10 * loss.ns_per_ms, .rttvar = 0, .has_sample = true };
    try testing.expectEqual(10 * loss.ns_per_ms + loss.granularity, steady.ptoBase());
}

test "the loss delay is 9/8 of the larger of the two estimates, floored at the granularity" {
    const testing = std.testing;
    var rtt: Rtt = .{ .smoothed = 80 * loss.ns_per_ms, .latest = 40 * loss.ns_per_ms, .has_sample = true };
    try testing.expectEqual(90 * loss.ns_per_ms, rtt.lossDelay());

    rtt.latest = 160 * loss.ns_per_ms;
    try testing.expectEqual(180 * loss.ns_per_ms, rtt.lossDelay());

    var tiny: Rtt = .{ .smoothed = 8, .latest = 8, .has_sample = true };
    try testing.expectEqual(loss.granularity, tiny.lossDelay());
}

test "the persistent congestion duration is three probe timeouts including max_ack_delay" {
    const testing = std.testing;
    const rtt: Rtt = .{
        .smoothed = 100 * loss.ns_per_ms,
        .rttvar = 10 * loss.ns_per_ms,
        .max_ack_delay = 25 * loss.ns_per_ms,
        .has_sample = true,
    };
    // (100 + 40 + 25) * 3 = 495 ms.
    try testing.expectEqual(495 * loss.ns_per_ms, rtt.persistentCongestionDuration());
}

test "every derived duration saturates rather than wraps at the top of the range" {
    const testing = std.testing;
    const huge: Rtt = .{
        .smoothed = std.math.maxInt(Duration),
        .rttvar = std.math.maxInt(Duration),
        .latest = std.math.maxInt(Duration),
        .max_ack_delay = std.math.maxInt(Duration),
        .has_sample = true,
    };
    try testing.expectEqual(std.math.maxInt(Duration), huge.ptoBase());
    try testing.expectEqual(std.math.maxInt(Duration), huge.lossDelay());
    try testing.expectEqual(std.math.maxInt(Duration), huge.persistentCongestionDuration());
}
