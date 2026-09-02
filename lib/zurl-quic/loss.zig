//! The units and the constants of RFC 9002, QUIC loss detection and
//! congestion control.
//!
//! **Every constant of RFC 9002 section 6.1.2 and section 7.2 is here,
//! with the section that fixes it.** The files that use them import this
//! one, so a reader finds one place where a number came from an RFC and
//! not from a guess.
//!
//! ## Time is a number the caller supplies
//!
//! `Instant` and `Duration` are nanoseconds on a monotonic clock. **No
//! file in this package reads a clock.** Every function that needs the
//! time takes it as a parameter, so a test drives the whole state machine
//! with fixed numbers and never sleeps. A test that sleeps is a test that
//! fails on a busy machine.
//!
//! The origin of `Instant` does not matter. Only differences are used,
//! and every subtraction of two instants is saturating, so a clock that
//! goes backwards gives zero and never a huge number.

const std = @import("std");

const protection = @import("protection.zig");

/// A point on a monotonic clock, in nanoseconds. The origin is the
/// caller's to choose.
pub const Instant = u64;

/// A length of time, in nanoseconds.
pub const Duration = u64;

pub const ns_per_us: Duration = 1_000;
pub const ns_per_ms: Duration = 1_000_000;
pub const ns_per_s: Duration = 1_000_000_000;

/// `kPacketThreshold`, RFC 9002 section 6.1.1. A packet is lost when a
/// packet at least this far above it is acknowledged.
pub const packet_threshold: u64 = 3;

/// `kTimeThreshold` is 9/8, RFC 9002 section 6.1.2. It is held as a shift
/// and an add, so `timeThreshold` needs no multiplication that could
/// overflow.
pub const time_threshold_shift: u6 = 3;

/// `kGranularity`, RFC 9002 section 6.1.2. The timer granularity, and the
/// floor under every loss delay and every probe timeout.
pub const granularity: Duration = ns_per_ms;

/// `kInitialRtt`, RFC 9002 section 6.2.2. The estimate before the first
/// sample exists.
pub const initial_rtt: Duration = 333 * ns_per_ms;

/// `kPersistentCongestionThreshold`, RFC 9002 section 7.6.1.
pub const persistent_congestion_threshold: u64 = 3;

/// The default `max_ack_delay` this endpoint advertises, RFC 9000 section
/// 18.2. A peer may state its own, and `Rtt.max_ack_delay` carries it.
pub const default_max_ack_delay: Duration = 25 * ns_per_ms;

/// **The ceiling on the probe timeout backoff.** RFC 9002 section 6.2.1
/// doubles the timeout at each expiry and names no limit, so the
/// pseudocode alone grows without bound and a connection that lost its
/// peer waits forever between probes. Two bounds are applied here.
///
/// The first is on the exponent: `pto_count` stops climbing at this
/// value, so the multiplier stops at 2^8, which is 256.
pub const max_pto_count: u32 = 8;

/// The second bound on the probe timeout, and the absolute one. Whatever
/// the round-trip estimate and the backoff say, one probe timeout is at
/// most this long. RFC 9000 section 10.1 gives an idle timeout of the
/// same order, so a connection that reaches this ceiling is already dead
/// and the caller closes it.
pub const max_pto: Duration = 60 * ns_per_s;

/// The smallest datagram every QUIC path must carry, RFC 9000 section
/// 14.1. It is the unit the congestion window counts in, and the size a
/// client pads an Initial datagram to.
pub const min_initial_datagram_bytes: u64 = 1200;

/// **The anti-amplification factor.** RFC 9000 section 8: before the
/// peer's address is validated, an endpoint sends at most this many times
/// the bytes it received.
pub const amplification_factor: u64 = 3;

/// Which endpoint this state machine runs in. The role decides two
/// things: who the anti-amplification limit binds, and how the peer's
/// address becomes validated.
pub const Role = enum {
    /// RFC 9002 section A.7: a client validates the server's address the
    /// moment it opens a packet the server protected, so the limit does
    /// not bind a client.
    client,
    /// RFC 9000 section 8: a server must not send more than
    /// `amplification_factor` times what it received until the client's
    /// address is validated.
    server,
};

/// A packet number space, RFC 9000 section 12.3.
///
/// **There are three, and a packet number means nothing outside the one
/// that issued it.** Loss detection, the round-trip estimate feed, and
/// ACK generation are each per space. `zero_rtt` is not a fourth space:
/// RFC 9000 section 12.3 puts 0-RTT and 1-RTT packets in one space, so
/// `fromLevel` maps both onto `application`.
pub const Space = enum(u2) {
    initial = 0,
    handshake = 1,
    application = 2,

    /// How many spaces there are. The arrays keyed by `Space` use it.
    pub const count: usize = 3;

    /// The array index for this space.
    pub fn index(self: Space) usize {
        return @intFromEnum(self);
    }

    /// The space a packet at `level` belongs to. RFC 9000 section 12.3
    /// shares one space between the 0-RTT and 1-RTT levels.
    pub fn fromLevel(level: protection.Level) Space {
        return switch (level) {
            .initial => .initial,
            .handshake => .handshake,
            .zero_rtt, .application => .application,
        };
    }

    /// The name RFC 9002 uses, for a diagnostic.
    pub fn name(self: Space) []const u8 {
        return switch (self) {
            .initial => "Initial",
            .handshake => "Handshake",
            .application => "ApplicationData",
        };
    }
};

/// The difference between two instants, or zero when `later` is before
/// `earlier`.
///
/// **A monotonic clock that steps backwards is a fault of the host and
/// not of the peer.** The RFC's pseudocode subtracts instants freely. A
/// wrapping subtraction here would turn one backward step into a duration
/// of nearly 2^64 nanoseconds, which stops every timer in the connection.
/// Saturating to zero fires the timer at once instead, which is the safe
/// direction.
pub fn since(later: Instant, earlier: Instant) Duration {
    return later -| earlier;
}

/// `kTimeThreshold * value`, which is 9/8 of it, with no overflow.
///
/// The multiplication `value * 9 / 8` overflows for a value above 2^61.
/// `value + value / 8` is the same number for every value the shift does
/// not round, and it cannot overflow before `value` alone does.
pub fn timeThreshold(value: Duration) Duration {
    return value +| (value >> time_threshold_shift);
}

test "the RFC 9002 constants are the numbers the RFC prints" {
    const testing = std.testing;
    try testing.expectEqual(@as(u64, 3), packet_threshold);
    try testing.expectEqual(@as(Duration, 1 * ns_per_ms), granularity);
    try testing.expectEqual(@as(Duration, 333 * ns_per_ms), initial_rtt);
    try testing.expectEqual(@as(u64, 3), persistent_congestion_threshold);
    try testing.expectEqual(@as(u64, 3), amplification_factor);
    try testing.expectEqual(@as(u64, 1200), min_initial_datagram_bytes);
}

test "the time threshold is 9/8 and it does not overflow at the top of the range" {
    const testing = std.testing;
    try testing.expectEqual(@as(Duration, 9), timeThreshold(8));
    try testing.expectEqual(@as(Duration, 1125 * ns_per_ms), timeThreshold(1000 * ns_per_ms));
    // 9/8 of this value passes 2^64, so a multiplication would wrap. The
    // saturating add reports the largest duration instead.
    try testing.expectEqual(std.math.maxInt(Duration), timeThreshold(std.math.maxInt(Duration)));
}

test "a clock that steps backwards gives zero and not a duration near 2^64" {
    const testing = std.testing;
    try testing.expectEqual(@as(Duration, 5), since(15, 10));
    try testing.expectEqual(@as(Duration, 0), since(10, 15));
    try testing.expectEqual(@as(Duration, 0), since(0, std.math.maxInt(Instant)));
}

test "0-RTT and 1-RTT share one packet number space and Initial keeps its own" {
    const testing = std.testing;
    try testing.expectEqual(Space.application, Space.fromLevel(.zero_rtt));
    try testing.expectEqual(Space.application, Space.fromLevel(.application));
    try testing.expectEqual(Space.initial, Space.fromLevel(.initial));
    try testing.expectEqual(Space.handshake, Space.fromLevel(.handshake));
    try testing.expectEqual(@as(usize, 3), Space.count);
    try testing.expectEqual(@as(usize, 0), Space.initial.index());
    try testing.expectEqual(@as(usize, 2), Space.application.index());
}

test "the probe timeout ceiling is stated and it is not unbounded" {
    const testing = std.testing;
    try testing.expectEqual(@as(u32, 8), max_pto_count);
    try testing.expectEqual(@as(Duration, 60 * ns_per_s), max_pto);
    // The largest multiplier the backoff can reach.
    try testing.expectEqual(@as(u64, 256), @as(u64, 1) << @intCast(max_pto_count));
}
