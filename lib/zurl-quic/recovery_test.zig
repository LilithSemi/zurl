//! RFC 9002 driven end to end, with fixed times and no clock.
//!
//! The RFC gives pseudocode and no test vectors, so every case here is a
//! worked example: the input times and packet numbers are chosen so the
//! answer can be computed by hand from the RFC's own formulas, and the
//! comment above each one shows the arithmetic. A reader can check the
//! test against the RFC without running it.
//!
//! **No test here sleeps and none opens a socket.** Time is a number the
//! caller passes, so the whole state machine runs at whatever speed the
//! machine has.

const std = @import("std");
const testing = std.testing;

const AckRanges = @import("AckRanges.zig");
const Congestion = @import("Congestion.zig");
const Recovery = @import("Recovery.zig");
const frame = @import("frame.zig");
const loss = @import("loss.zig");

const Instant = loss.Instant;
const ms = loss.ns_per_ms;
const s = loss.ns_per_s;

/// The buffer every call that can declare a loss needs.
const LostBuffer = [Recovery.max_sent_packets]u64;

/// Sends one ack-eliciting packet of one datagram.
fn send(recovery: *Recovery, space: loss.Space, number: u64, when: Instant) !void {
    try recovery.onPacketSent(space, .{
        .number = number,
        .sent_time = when,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
}

/// An `ACK` frame naming one range and nothing else.
fn ackOne(largest: u64, first_range: u64) frame.Ack {
    return .{
        .largest_acknowledged = largest,
        .ack_delay = 0,
        .ack_range_count = 0,
        .first_ack_range = first_range,
        .ranges = &[_]u8{},
        .ecn = null,
    };
}

test "the three packet number spaces resolve on their own and touch nothing else" {
    var lost: LostBuffer = undefined;
    var recovery: Recovery = .init(.{});

    try send(&recovery, .initial, 0, 0);
    try send(&recovery, .handshake, 0, 0);
    try send(&recovery, .application, 0, 0);
    try testing.expectEqual(@as(u64, 3600), recovery.bytesInFlight());

    // Packet number 0 exists in all three spaces. Acknowledging it in the
    // Initial space must resolve exactly one of them.
    const outcome = try recovery.onAckReceived(.initial, ackOne(0, 0), 10 * ms, 3, &lost);
    try testing.expectEqual(@as(u32, 1), outcome.newly_acked);

    try testing.expectEqual(@as(usize, 0), recovery.stateConst(.initial).sent_len);
    try testing.expectEqual(@as(usize, 1), recovery.stateConst(.handshake).sent_len);
    try testing.expectEqual(@as(usize, 1), recovery.stateConst(.application).sent_len);

    try testing.expectEqual(@as(?u64, 0), recovery.stateConst(.initial).largest_acked);
    try testing.expectEqual(@as(?u64, null), recovery.stateConst(.handshake).largest_acked);
    try testing.expectEqual(@as(?u64, null), recovery.stateConst(.application).largest_acked);

    try testing.expectEqual(@as(u64, 2400), recovery.bytesInFlight());
    try testing.expectEqual(@as(u32, 2), recovery.ackElicitingInFlight());
}

test "a received packet number is recorded in one space and in no other" {
    var recovery: Recovery = .init(.{});
    _ = recovery.onPacketReceived(.initial, 5, true, 100);
    try testing.expect(recovery.stateConst(.initial).ack.contains(5));
    try testing.expect(!recovery.stateConst(.handshake).ack.contains(5));
    try testing.expect(!recovery.stateConst(.application).ack.contains(5));
    try testing.expectEqual(@as(?u64, 5), recovery.stateConst(.initial).ack.largest());
    try testing.expectEqual(@as(?u64, null), recovery.stateConst(.application).ack.largest());
}

test "the packet threshold declares a packet lost three numbers below the largest" {
    var lost: LostBuffer = undefined;
    var recovery: Recovery = .init(.{});

    // Every packet leaves at the same instant, and the acknowledgment
    // arrives one nanosecond later. The round-trip sample is then 1 ns,
    // the loss delay falls to the one millisecond granularity, and the
    // time threshold reaches back to 99 ms, which is before any of them.
    // So the packet threshold is the only rule that can fire.
    for (0..5) |number| try send(&recovery, .application, number, 100 * ms);
    const outcome = try recovery.onAckReceived(
        .application,
        ackOne(4, 0),
        100 * ms + 1,
        3,
        &lost,
    );

    // 0 + 3 <= 4 and 1 + 3 <= 4, but 2 + 3 is above 4.
    try testing.expectEqual(@as(usize, 2), outcome.lost);
    try testing.expectEqual(@as(u64, 0), lost[0]);
    try testing.expectEqual(@as(u64, 1), lost[1]);
    try testing.expectEqual(@as(u32, 1), outcome.newly_acked);

    // Two are left in the record and the time threshold is armed for them.
    try testing.expectEqual(@as(usize, 2), recovery.stateConst(.application).sent_len);
    try testing.expectEqual(
        @as(?Instant, 100 * ms + loss.granularity),
        recovery.stateConst(.application).loss_time,
    );
}

test "the time threshold declares a packet lost 9/8 of a round trip after it left" {
    var lost: LostBuffer = undefined;
    var recovery: Recovery = .init(.{});

    // Packet 0 leaves at 0, packets 1 and 2 leave at 205 ms, and packet 2
    // is acknowledged at 210 ms. The sample is 5 ms, so the loss delay is
    // 9/8 of it, which is 5.625 ms, and the time threshold reaches back
    // to 204.375 ms. Packet 0 is older than that and packet 1 is not.
    // The packet threshold cannot fire, because 1 + 3 is above 2.
    try send(&recovery, .application, 0, 0);
    try send(&recovery, .application, 1, 205 * ms);
    try send(&recovery, .application, 2, 205 * ms);

    const outcome = try recovery.onAckReceived(.application, ackOne(2, 0), 210 * ms, 3, &lost);
    try testing.expect(outcome.rtt_sampled);
    try testing.expectEqual(@as(loss.Duration, 5 * ms), recovery.rtt.smoothed);
    try testing.expectEqual(@as(loss.Duration, 5_625_000), recovery.rtt.lossDelay());

    try testing.expectEqual(@as(usize, 1), outcome.lost);
    try testing.expectEqual(@as(u64, 0), lost[0]);

    // Packet 1 is not lost yet, and the timer says when it would be.
    try testing.expectEqual(@as(usize, 1), recovery.stateConst(.application).sent_len);
    try testing.expectEqual(@as(?Instant, 210_625_000), recovery.stateConst(.application).loss_time);
    try testing.expectEqual(@as(?Instant, 210_625_000), recovery.timer);

    // The timer firing declares it, and it names the space it came from.
    const timeout = try recovery.onLossDetectionTimeout(210_625_000, &lost);
    try testing.expect(timeout == .lost);
    try testing.expectEqual(@as(usize, 1), timeout.lost.count);
    try testing.expectEqual(loss.Space.application, timeout.lost.space);
    try testing.expectEqual(@as(u64, 1), lost[0]);
    try testing.expectEqual(@as(usize, 0), recovery.stateConst(.application).sent_len);
}

test "the probe timeout starts at the RFC's initial estimate and doubles at each expiry" {
    var lost: LostBuffer = undefined;
    var recovery: Recovery = .init(.{});

    // No sample yet, so smoothed is 333 ms and rttvar is 166.5 ms.
    // The base is 333 + max(4 * 166.5, 1) = 999 ms.
    try send(&recovery, .initial, 0, 0);
    try testing.expectEqual(@as(loss.Duration, 999 * ms), recovery.rtt.ptoBase());
    try testing.expectEqual(@as(?Instant, 999 * ms), recovery.timer);

    const first = try recovery.onLossDetectionTimeout(999 * ms, &lost);
    try testing.expect(first == .probe);
    try testing.expectEqual(loss.Space.initial, first.probe.space);
    try testing.expectEqual(@as(u8, 2), first.probe.packets);
    try testing.expect(first.probe.pad);
    try testing.expectEqual(@as(u32, 1), recovery.pto_count);
    // The next one is twice as far from the same send.
    try testing.expectEqual(@as(?Instant, 1998 * ms), recovery.timer);

    const second = try recovery.onLossDetectionTimeout(1998 * ms, &lost);
    try testing.expect(second == .probe);
    try testing.expectEqual(@as(u32, 2), recovery.pto_count);
    try testing.expectEqual(@as(?Instant, 3996 * ms), recovery.timer);
}

test "a timer that is not due changes nothing" {
    var lost: LostBuffer = undefined;
    var recovery: Recovery = .init(.{});
    try send(&recovery, .initial, 0, 0);

    const early = try recovery.onLossDetectionTimeout(998 * ms, &lost);
    try testing.expect(early == .idle);
    try testing.expectEqual(@as(u32, 0), recovery.pto_count);
    try testing.expectEqual(@as(u64, 0), recovery.pto_expirations);
}

test "the probe timeout stops at its ceiling and still moves the clock forward" {
    var lost: LostBuffer = undefined;
    var recovery: Recovery = .init(.{});
    try send(&recovery, .initial, 0, 0);

    // **Every gap here is real elapsed time and not the armed value.** A
    // timer that froze at the ceiling would give a gap of zero, which is
    // below any ceiling, so a test that only checks the upper bound
    // passes on an implementation that stopped moving. That is a probe
    // storm and not a backoff: the caller polls, the timeout is due
    // again at once, and the probes go out at the poll rate.
    //
    // The base is 999 ms with no sample yet. The armed instant is
    // measured from the one send at instant 0, so the first two gaps are
    // both 999 ms and each gap after that doubles, until what is left of
    // the 60 s ceiling ends the doubling.
    const opening = [_]Instant{
        999 * ms,
        999 * ms,
        1998 * ms,
        3996 * ms,
        7992 * ms,
        15984 * ms,
        28032 * ms,
    };

    var previous: Instant = 0;
    var round: usize = 0;
    while (round < 32) : (round += 1) {
        const now = recovery.timer.?;
        const gap = now - previous;
        try testing.expect(gap <= loss.max_pto);
        if (round < opening.len) {
            try testing.expectEqual(opening[round], gap);
        } else {
            // Past the ceiling the gap is the ceiling itself, every time.
            try testing.expectEqual(loss.max_pto, gap);
        }
        previous = now;
        const timeout = try recovery.onLossDetectionTimeout(now, &lost);
        try testing.expect(timeout == .probe);
    }

    // Both ceilings held: the exponent stopped, and so did the duration.
    try testing.expectEqual(loss.max_pto_count, recovery.pto_count);
    try testing.expectEqual(@as(u64, 32), recovery.pto_expirations);
    // 32 probes took 26 minutes of connection time. A frozen timer would
    // have served all 32 inside the first minute.
    try testing.expectEqual(@as(Instant, 1_560_000 * ms), previous);
    try testing.expectEqual(@as(?Instant, 1_620_000 * ms), recovery.timer);
}

test "an acknowledgment resets the backoff once the peer validated this address" {
    var lost: LostBuffer = undefined;
    var recovery: Recovery = .init(.{});
    try send(&recovery, .handshake, 0, 0);
    recovery.onHandshakeKeys();

    _ = try recovery.onLossDetectionTimeout(recovery.timer.?, &lost);
    _ = try recovery.onLossDetectionTimeout(recovery.timer.?, &lost);
    try testing.expectEqual(@as(u32, 2), recovery.pto_count);

    // An acknowledgment in the Handshake space proves the server answered
    // a packet only this endpoint could have sent. RFC 9002 section A.7.
    _ = try recovery.onAckReceived(.handshake, ackOne(0, 0), 5 * s, 3, &lost);
    try testing.expect(recovery.peerCompletedAddressValidation());
    try testing.expectEqual(@as(u32, 0), recovery.pto_count);
    // Nothing is outstanding and the address is validated, so no timer.
    try testing.expectEqual(@as(?Instant, null), recovery.timer);
}

test "with nothing in flight a client still probes, so the server is not deadlocked" {
    var lost: LostBuffer = undefined;
    var recovery: Recovery = .init(.{});
    // A client that has sent its Initial flight and had it all
    // acknowledged still has an unvalidated address at the server, so RFC
    // 9002 section 6.2.2.1 keeps the timer armed.
    try send(&recovery, .initial, 0, 0);
    _ = try recovery.onAckReceived(.initial, ackOne(0, 0), 10 * ms, 3, &lost);
    try testing.expectEqual(@as(u64, 0), recovery.bytesInFlight());
    try testing.expect(!recovery.peerCompletedAddressValidation());
    try testing.expect(recovery.timer != null);

    const timeout = try recovery.onLossDetectionTimeout(recovery.timer.?, &lost);
    try testing.expect(timeout == .probe);
    // One packet is enough to unblock, and it is padded so the server
    // earns three times 1200 bytes of budget.
    try testing.expectEqual(@as(u8, 1), timeout.probe.packets);
    try testing.expectEqual(loss.Space.initial, timeout.probe.space);
    try testing.expect(timeout.probe.pad);

    // Once the Handshake keys exist the anti-deadlock probe moves there,
    // because a Handshake packet proves address ownership.
    recovery.onHandshakeKeys();
    const next = try recovery.onLossDetectionTimeout(recovery.timer.?, &lost);
    try testing.expect(next == .probe);
    try testing.expectEqual(loss.Space.handshake, next.probe.space);
    try testing.expect(!next.probe.pad);
}

test "the application space is not probed before the handshake is confirmed" {
    var recovery: Recovery = .init(.{});
    try send(&recovery, .handshake, 0, 100 * ms);
    try send(&recovery, .application, 0, 0);

    // Both spaces have something outstanding. The application space is
    // skipped, so the Handshake send time decides the timeout even though
    // it is the later one.
    const before = recovery.ptoTimeAndSpace(200 * ms);
    try testing.expectEqual(loss.Space.handshake, before.space);
    try testing.expectEqual(@as(Instant, 100 * ms + 999 * ms), before.time);

    // After confirmation the application space is considered, and its
    // timeout carries the peer's stated acknowledgment delay.
    recovery.onHandshakeConfirmed(200 * ms);
    const after = recovery.ptoTimeAndSpace(200 * ms);
    try testing.expectEqual(loss.Space.application, after.space);
    try testing.expectEqual(@as(Instant, 0 + 999 * ms + 25 * ms), after.time);
}

test "an ACK naming a packet number this endpoint never sent is refused" {
    var lost: LostBuffer = undefined;
    var recovery: Recovery = .init(.{});

    // Nothing has been sent at all.
    try testing.expectError(
        error.AckedUnsentPacket,
        recovery.onAckReceived(.initial, ackOne(0, 0), 10 * ms, 3, &lost),
    );

    try send(&recovery, .application, 0, 0);
    try send(&recovery, .application, 1, 0);
    try send(&recovery, .application, 2, 0);

    // A number from the future. Without this gate every packet below it
    // is lost by the packet threshold and the connection empties itself.
    try testing.expectError(
        error.AckedUnsentPacket,
        recovery.onAckReceived(.application, ackOne(1_000_000, 0), 10 * ms, 3, &lost),
    );

    // Nothing moved: no packet left the record, no estimate was taken,
    // and the largest acknowledged is still unset.
    try testing.expectEqual(@as(usize, 3), recovery.stateConst(.application).sent_len);
    try testing.expectEqual(@as(?u64, null), recovery.stateConst(.application).largest_acked);
    try testing.expect(!recovery.rtt.has_sample);
    try testing.expectEqual(@as(u64, 3600), recovery.bytesInFlight());
    try testing.expectEqual(@as(u64, 0), recovery.packets_lost);
}

test "an ACK whose first range runs below zero is refused" {
    var lost: LostBuffer = undefined;
    var recovery: Recovery = .init(.{});
    try send(&recovery, .application, 0, 0);
    try send(&recovery, .application, 1, 0);
    try send(&recovery, .application, 2, 0);

    // largest 2 with a First ACK Range of 5 names packet number -3.
    const underflow: frame.Ack = .{
        .largest_acknowledged = 2,
        .ack_delay = 0,
        .ack_range_count = 0,
        .first_ack_range = 5,
        .ranges = &[_]u8{},
        .ecn = null,
    };
    try testing.expectError(
        error.RangeUnderflow,
        recovery.onAckReceived(.application, underflow, 10 * ms, 3, &lost),
    );
    try testing.expect(!recovery.rtt.has_sample);
}

test "an ACK whose gap runs below zero is refused" {
    var lost: LostBuffer = undefined;
    var recovery: Recovery = .init(.{});
    try send(&recovery, .application, 0, 0);
    try send(&recovery, .application, 1, 0);
    try send(&recovery, .application, 2, 0);

    // First range is packet 2 alone. The next range starts at
    // 2 - 10 - 2, which is below zero.
    const ranges = [_]u8{ 0x0a, 0x00 };
    const underflow: frame.Ack = .{
        .largest_acknowledged = 2,
        .ack_delay = 0,
        .ack_range_count = 1,
        .first_ack_range = 0,
        .ranges = &ranges,
        .ecn = null,
    };
    try testing.expectError(
        error.RangeUnderflow,
        recovery.onAckReceived(.application, underflow, 10 * ms, 3, &lost),
    );
}

test "an ACK that runs backwards takes back nothing" {
    var lost: LostBuffer = undefined;
    var recovery: Recovery = .init(.{});
    for (0..5) |number| try send(&recovery, .application, number, 0);

    const first = try recovery.onAckReceived(.application, ackOne(4, 4), 10 * ms, 3, &lost);
    try testing.expectEqual(@as(u32, 5), first.newly_acked);
    try testing.expectEqual(@as(?u64, 4), recovery.stateConst(.application).largest_acked);

    // The same frame again, and then an older one. Neither says anything
    // new, and neither moves the largest acknowledged back.
    const repeat = try recovery.onAckReceived(.application, ackOne(4, 4), 20 * ms, 3, &lost);
    try testing.expectEqual(@as(u32, 0), repeat.newly_acked);
    try testing.expect(!repeat.rtt_sampled);

    const older = try recovery.onAckReceived(.application, ackOne(2, 0), 30 * ms, 3, &lost);
    try testing.expectEqual(@as(u32, 0), older.newly_acked);
    try testing.expectEqual(@as(?u64, 4), recovery.stateConst(.application).largest_acked);
    try testing.expectEqual(@as(u64, 0), recovery.packets_lost);
}

test "an ACK Delay of 2^62 units leaves a usable estimate and a usable timer" {
    var lost: LostBuffer = undefined;
    var recovery: Recovery = .init(.{});
    try send(&recovery, .application, 0, 0);
    try send(&recovery, .application, 1, 0);
    recovery.onHandshakeConfirmed(0);

    _ = try recovery.onAckReceived(.application, ackOne(0, 0), 50 * ms, 3, &lost);
    try testing.expectEqual(@as(loss.Duration, 50 * ms), recovery.rtt.smoothed);

    // The largest field a variable-length integer can carry, with the
    // largest exponent RFC 9000 section 18.2 allows.
    const hostile: frame.Ack = .{
        .largest_acknowledged = 1,
        .ack_delay = (1 << 62) - 1,
        .ack_range_count = 0,
        .first_ack_range = 0,
        .ranges = &[_]u8{},
        .ecn = null,
    };
    _ = try recovery.onAckReceived(.application, hostile, 100 * ms, 20, &lost);

    // **Worked by hand from the RFC.** The field is (2^62 - 1) units of
    // 2^20 microseconds, so the conversion saturates at the largest
    // duration. The cap takes it to the peer's 25 ms. The sample is
    // 100 ms and min is 50 ms, so `100 >= 50 + 25` holds and the 25 ms
    // is subtracted: adjusted is 75 ms.
    //   smoothed = 50 - 50/8 + 75/8 = 53.125 ms
    //   deviation = |53.125 - 75| = 21.875 ms
    //   rttvar = 25 - 25/4 + 21.875/4 = 24.21875 ms
    //   ptoBase = 53.125 + 4 * 24.21875 = 150 ms
    try testing.expectEqual(@as(loss.Duration, 53_125_000), recovery.rtt.smoothed);
    try testing.expectEqual(@as(loss.Duration, 24_218_750), recovery.rtt.rttvar);
    try testing.expectEqual(@as(loss.Duration, 50 * ms), recovery.rtt.min);
    try testing.expectEqual(@as(loss.Duration, 150 * ms), recovery.rtt.ptoBase());
    // The probe timeout is still far inside its ceiling, so the
    // connection keeps sending.
    try testing.expect(recovery.rtt.ptoBase() <= loss.max_pto);
}

test "an ACK naming more ranges than the bound is used and the rest are counted" {
    var lost: LostBuffer = undefined;
    var recovery: Recovery = .init(.{});
    try send(&recovery, .initial, 1_000_000, 0);

    // Every pair is a zero Gap and a zero ACK Range Length, so each range
    // covers one packet number and steps down by two.
    const pairs = Recovery.max_ack_ranges + 44;
    const ranges = [_]u8{0} ** (pairs * 2);
    const many: frame.Ack = .{
        .largest_acknowledged = 1_000_000,
        .ack_delay = 0,
        .ack_range_count = pairs,
        .first_ack_range = 0,
        .ranges = &ranges,
        .ecn = null,
    };

    const outcome = try recovery.onAckReceived(.initial, many, 10 * ms, 3, &lost);
    // The packet really sent sits in the first range, so it resolves.
    try testing.expectEqual(@as(u32, 1), outcome.newly_acked);
    try testing.expectEqual(@as(u64, 1), recovery.ack_ranges_ignored);
}

test "one loss halves the window and NewReno leaves slow start" {
    var lost: LostBuffer = undefined;
    var recovery: Recovery = .init(.{});
    try testing.expectEqual(@as(u64, 12000), recovery.congestion.window);

    // Packets 0 to 4 leave at 200 ms and later, and packet 4 is
    // acknowledged at 600 ms.
    try send(&recovery, .application, 0, 200 * ms);
    try send(&recovery, .application, 1, 300 * ms);
    try send(&recovery, .application, 2, 400 * ms);
    try send(&recovery, .application, 3, 450 * ms);
    try send(&recovery, .application, 4, 500 * ms);

    const outcome = try recovery.onAckReceived(.application, ackOne(4, 0), 600 * ms, 3, &lost);
    try testing.expectEqual(@as(u32, 1), outcome.newly_acked);
    // The sample is 100 ms, the loss delay is 112.5 ms, and the time
    // threshold reaches back to 487.5 ms, so 0 to 3 are all lost.
    try testing.expectEqual(@as(usize, 4), outcome.lost);
    try testing.expect(!outcome.persistent_congestion);

    // Slow start added one datagram for the acknowledgment, and the loss
    // then halved the window once.
    try testing.expectEqual(@as(u64, 6600), recovery.congestion.window);
    try testing.expectEqual(@as(u64, 6600), recovery.congestion.ssthresh);
    try testing.expectEqual(@as(u64, 1), recovery.congestion.congestion_events);
    try testing.expectEqual(@as(u64, 0), recovery.bytesInFlight());
    try testing.expectEqual(@as(u64, 4), recovery.packets_lost);
}

test "a run of losses longer than three probe timeouts is persistent congestion" {
    var lost: LostBuffer = undefined;
    var recovery: Recovery = .init(.{ .peer_max_ack_delay = 25 * ms });

    // The first round trip gives the estimate a sample at 100 ms, which
    // is what section 7.6.2 needs before it will call anything persistent.
    try send(&recovery, .application, 0, 0);
    _ = try recovery.onAckReceived(.application, ackOne(0, 0), 100 * ms, 3, &lost);
    try testing.expectEqual(@as(?Instant, 100 * ms), recovery.first_rtt_sample);

    // Four packets over two and a half seconds, then one acknowledgment.
    // The estimate stays at 100 ms, so the duration is
    // (100 + max(4 * 37.5, 1) + 25) * 3 = 825 ms, and the run from
    // 200 ms to 1500 ms is 1300 ms, which is longer.
    try send(&recovery, .application, 1, 200 * ms);
    try send(&recovery, .application, 2, 700 * ms);
    try send(&recovery, .application, 3, 1500 * ms);
    try send(&recovery, .application, 4, 2500 * ms);

    const outcome = try recovery.onAckReceived(.application, ackOne(4, 0), 2600 * ms, 3, &lost);
    try testing.expectEqual(@as(usize, 3), outcome.lost);
    try testing.expect(outcome.persistent_congestion);
    try testing.expectEqual(@as(loss.Duration, 825 * ms), recovery.rtt.persistentCongestionDuration());

    // The window is back at two datagrams and the recovery period is gone,
    // so the next acknowledgment starts the climb again.
    try testing.expectEqual(Congestion.minimumWindow(1200), recovery.congestion.window);
    try testing.expectEqual(@as(?Instant, null), recovery.congestion.recovery_start);
    try testing.expectEqual(@as(u64, 1), recovery.congestion.persistent_congestion_events);
}

test "a loss run that started before the first round trip sample is not persistent" {
    var lost: LostBuffer = undefined;
    var recovery: Recovery = .init(.{ .peer_max_ack_delay = 25 * ms });

    // No sample has ever arrived when these go out, so section 7.6.2 bars
    // the rule however long the run is.
    try send(&recovery, .application, 0, 0);
    try send(&recovery, .application, 1, 1000 * ms);
    try send(&recovery, .application, 2, 2000 * ms);
    try send(&recovery, .application, 3, 3000 * ms);

    const outcome = try recovery.onAckReceived(.application, ackOne(3, 0), 3100 * ms, 3, &lost);
    try testing.expectEqual(@as(usize, 3), outcome.lost);
    try testing.expect(!outcome.persistent_congestion);
    try testing.expectEqual(@as(u64, 0), recovery.congestion.persistent_congestion_events);
    try testing.expect(recovery.congestion.window > Congestion.minimumWindow(1200));
}

test "the anti-amplification limit holds a server to three times what it received" {
    var recovery: Recovery = .init(.{ .role = .server });
    try testing.expect(!recovery.amplification.validated);
    try testing.expect(recovery.amplification.blocked());
    try testing.expect(!recovery.canSend(1));

    recovery.onDatagramReceived(1200);
    try testing.expectEqual(@as(u64, 3600), recovery.amplification.budget());
    try testing.expect(recovery.canSend(3600));
    try testing.expect(!recovery.canSend(3601));

    recovery.onDatagramSent(1200);
    try testing.expectEqual(@as(u64, 2400), recovery.amplification.budget());
    recovery.onDatagramSent(2400);
    try testing.expect(recovery.amplification.blocked());

    // Validation lifts it, and nothing can push it back on.
    recovery.validateAddress();
    try testing.expectEqual(std.math.maxInt(u64), recovery.amplification.budget());
    recovery.onDatagramSent(1_000_000);
    try testing.expect(!recovery.amplification.blocked());
}

test "a client starts validated, and the gate still works when a caller asks for it" {
    // A client has received nothing at all here, so a budget that bound
    // it would refuse every byte. It sends a full Initial datagram all
    // the same, and sending a megabyte does not take that away.
    var client: Recovery = .init(.{ .role = .client });
    try testing.expectEqual(@as(u64, 0), client.amplification.received);
    try testing.expect(client.canSend(loss.min_initial_datagram_bytes));
    client.onDatagramSent(1_000_000);
    try testing.expectEqual(std.math.maxInt(u64), client.amplification.budget());
    try testing.expect(client.canSend(loss.min_initial_datagram_bytes));

    // The same state machine with the gate turned on refuses the same
    // datagram, so what differs is the gate and not the role's
    // arithmetic.
    var limited: Recovery = .init(.{ .role = .client, .address_validated = false });
    try testing.expect(!limited.canSend(1));
    try testing.expect(limited.amplification.blocked());
    limited.onDatagramReceived(100);
    try testing.expectEqual(@as(u64, 300), limited.amplification.budget());
    try testing.expect(limited.canSend(300));
    try testing.expect(!limited.canSend(301));

    // And the timer follows the gate. RFC 9002 section A.6 arms nothing
    // for an endpoint that may not send.
    try send(&limited, .initial, 0, 0);
    try testing.expect(limited.timer != null);
    limited.onDatagramSent(300);
    limited.setLossDetectionTimer(10 * ms);
    try testing.expectEqual(@as(?Instant, null), limited.timer);
}

test "an endpoint blocked by the amplification limit arms no timer" {
    var recovery: Recovery = .init(.{ .role = .server });
    recovery.onDatagramReceived(1200);
    try send(&recovery, .initial, 0, 0);
    try testing.expect(recovery.timer != null);

    // Spending the whole budget cancels the timer, because there is
    // nothing the timer could send. RFC 9002 section A.6.
    recovery.onDatagramSent(3600);
    recovery.setLossDetectionTimer(10 * ms);
    try testing.expectEqual(@as(?Instant, null), recovery.timer);

    // More budget brings it back.
    recovery.onDatagramReceived(1200);
    recovery.setLossDetectionTimer(10 * ms);
    try testing.expect(recovery.timer != null);
}

test "a full sent record refuses another packet rather than losing one" {
    var recovery: Recovery = .init(.{});
    for (0..Recovery.max_sent_packets) |number| try send(&recovery, .initial, number, 0);
    try testing.expectEqual(Recovery.max_sent_packets, recovery.stateConst(.initial).sent_len);

    try testing.expectError(error.TooManyPacketsInFlight, recovery.onPacketSent(.initial, .{
        .number = Recovery.max_sent_packets,
        .sent_time = 0,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    }));

    // The record is unchanged, so the packet the caller could not send is
    // not counted as outstanding either.
    try testing.expectEqual(Recovery.max_sent_packets, recovery.stateConst(.initial).sent_len);
    try testing.expectEqual(
        @as(u64, Recovery.max_sent_packets * 1200),
        recovery.stateConst(.initial).bytes_in_flight,
    );
}

test "a caller buffer shorter than the record is refused rather than cut short" {
    var recovery: Recovery = .init(.{});
    try send(&recovery, .initial, 0, 0);
    var small: [8]u64 = undefined;
    try testing.expectError(
        error.LostBufferTooSmall,
        recovery.onAckReceived(.initial, ackOne(0, 0), 10 * ms, 3, &small),
    );
    try testing.expectError(
        error.LostBufferTooSmall,
        recovery.onLossDetectionTimeout(999 * ms, &small),
    );
}

test "discarding a space gives its bytes back and leaves the others alone" {
    var recovery: Recovery = .init(.{});
    try send(&recovery, .initial, 0, 0);
    try send(&recovery, .handshake, 0, 0);
    try testing.expectEqual(@as(u64, 2400), recovery.bytesInFlight());

    recovery.pto_count = 3;
    recovery.discardSpace(.initial, 100 * ms);

    try testing.expectEqual(@as(u64, 1200), recovery.bytesInFlight());
    try testing.expectEqual(@as(usize, 0), recovery.stateConst(.initial).sent_len);
    try testing.expectEqual(@as(?u64, null), recovery.stateConst(.initial).largest_sent);
    try testing.expectEqual(@as(usize, 1), recovery.stateConst(.handshake).sent_len);
    try testing.expectEqual(@as(u32, 0), recovery.pto_count);
}

test "a packet that elicits no acknowledgment gives no round trip sample" {
    var lost: LostBuffer = undefined;
    var recovery: Recovery = .init(.{});
    // An ACK-only packet is not in flight and not ack-eliciting.
    try recovery.onPacketSent(.application, .{
        .number = 0,
        .sent_time = 0,
        .size = 40,
        .ack_eliciting = false,
        .in_flight = false,
    });
    try testing.expectEqual(@as(u64, 0), recovery.bytesInFlight());

    const outcome = try recovery.onAckReceived(.application, ackOne(0, 0), 50 * ms, 3, &lost);
    try testing.expectEqual(@as(u32, 1), outcome.newly_acked);
    try testing.expect(!outcome.rtt_sampled);
    try testing.expect(!recovery.rtt.has_sample);
}

test "an ACK frame this endpoint builds names every space's own numbers" {
    var recovery: Recovery = .init(.{});
    _ = recovery.onPacketReceived(.initial, 0, true, 0);
    _ = recovery.onPacketReceived(.initial, 1, true, 0);
    _ = recovery.onPacketReceived(.application, 7, true, 0);

    try testing.expect(recovery.ackDue(.initial, 0));
    var out: [AckRanges.max_range_bytes]u8 = undefined;

    const initial_ack = try recovery.buildAck(.initial, 10 * ms, 3, &out);
    try testing.expectEqual(@as(u64, 1), initial_ack.largest_acknowledged);
    try testing.expectEqual(@as(u64, 1), initial_ack.first_ack_range);
    // RFC 9000 section 13.2.1 acknowledges a handshake packet at once, so
    // the delay it reports is zero.
    try testing.expectEqual(@as(u64, 0), initial_ack.ack_delay);

    const application_ack = try recovery.buildAck(.application, 8 * ms, 3, &out);
    try testing.expectEqual(@as(u64, 7), application_ack.largest_acknowledged);
    try testing.expectEqual(@as(u64, 0), application_ack.first_ack_range);
    // 8 ms is 8000 microseconds, and an exponent of 3 divides it by eight.
    try testing.expectEqual(@as(u64, 1000), application_ack.ack_delay);

    // The Handshake space heard nothing, so it has nothing to say.
    try testing.expectError(
        error.NothingToAcknowledge,
        recovery.buildAck(.handshake, 10 * ms, 3, &out),
    );
}

test "the next timeout is the earliest of the loss timer and an owed acknowledgment" {
    var recovery: Recovery = .init(.{ .local_max_ack_delay = 25 * ms });
    try send(&recovery, .initial, 0, 0);
    try testing.expectEqual(@as(?Instant, 999 * ms), recovery.timer);
    try testing.expectEqual(@as(?Instant, 999 * ms), recovery.nextTimeout());

    // An ack-eliciting application packet arrives, so an ACK is owed at
    // 25 ms and that is sooner than the probe.
    _ = recovery.onPacketReceived(.application, 0, true, 0);
    try testing.expectEqual(@as(?Instant, 25 * ms), recovery.nextTimeout());

    recovery.onAckSent(.application);
    try testing.expectEqual(@as(?Instant, 999 * ms), recovery.nextTimeout());
}

test "acknowledgment-only packets never fill the record and stop the connection" {
    var lost: LostBuffer = undefined;
    var recovery: Recovery = .init(.{});

    // **The attacker input, from the server side.** Send authenticated
    // ack-eliciting `PING` packets with gaps in the numbers, so each one
    // forces an immediate acknowledgment, and never send an `ACK` and
    // never send stream data. Every acknowledgment this endpoint builds
    // is recorded and none of them is in flight. RFC 9000 section 13.2.1
    // forbids the peer answering one with a non-ack-eliciting packet, so
    // nothing the peer sends ever takes them out of the record.
    var number: u64 = 0;
    while (number < 300) : (number += 1) {
        try recovery.onPacketSent(.application, .{
            .number = number,
            .sent_time = number * ms,
            .size = 40,
            .ack_eliciting = false,
            .in_flight = false,
        });
    }

    // 256 slots, 300 packets, so 44 of the oldest gave up their slot.
    try testing.expectEqual(@as(u64, 44), recovery.sent_records_evicted);
    try testing.expectEqual(Recovery.max_sent_packets, recovery.stateConst(.application).sent_len);
    // The number still climbs, so the gate on an ACK naming an unsent
    // packet still knows what this endpoint sent.
    try testing.expectEqual(@as(?u64, 299), recovery.stateConst(.application).largest_sent);
    try testing.expectEqual(@as(u64, 0), recovery.bytesInFlight());

    // **And the connection can still send.** This is what a full record
    // used to stop: no acknowledgments, no stream data, and no probes.
    try send(&recovery, .application, 300, 300 * ms);
    try testing.expectEqual(@as(u64, 1200), recovery.bytesInFlight());
    try testing.expectEqual(@as(u64, 45), recovery.sent_records_evicted);

    // A packet that is in flight is never the one that gives up a slot,
    // so the congestion window and the timer still account for it.
    const outcome = try recovery.onAckReceived(.application, ackOne(300, 0), 400 * ms, 3, &lost);
    try testing.expectEqual(@as(u32, 1), outcome.newly_acked);
    try testing.expectEqual(@as(u64, 0), recovery.bytesInFlight());
    // The sample is 100 ms, so the loss delay is 112.5 ms and the time
    // threshold reaches back to 287.5 ms. Numbers 45 to 297 fall to the
    // packet threshold, and 298 and 299 are too new for either rule.
    try testing.expectEqual(@as(usize, 253), outcome.lost);
    try testing.expectEqual(@as(usize, 2), recovery.stateConst(.application).sent_len);
}

test "a record full of packets in flight still refuses another rather than lose one" {
    var recovery: Recovery = .init(.{});
    for (0..Recovery.max_sent_packets) |number| try send(&recovery, .application, number, 0);

    // Nothing here may give up its slot: every entry counts against the
    // congestion window and holds bytes the peer must acknowledge.
    try testing.expectError(error.TooManyPacketsInFlight, recovery.onPacketSent(.application, .{
        .number = Recovery.max_sent_packets,
        .sent_time = 0,
        .size = 40,
        .ack_eliciting = false,
        .in_flight = false,
    }));
    try testing.expectEqual(@as(u64, 0), recovery.sent_records_evicted);
    try testing.expectEqual(Recovery.max_sent_packets, recovery.stateConst(.application).sent_len);
}

test "an ACK range past the bound names an older packet and does not acknowledge it" {
    var lost: LostBuffer = undefined;
    var recovery: Recovery = .init(.{});

    // Every pair is a zero Gap and a zero ACK Range Length, so range `k`
    // covers packet number `largest - 2 * (k - 1)` alone. Range 200
    // covers 602 and range 260 covers 482, and only the first 256 ranges
    // are used.
    try send(&recovery, .application, 482, 0);
    try send(&recovery, .application, 602, 0);
    try send(&recovery, .application, 1000, 0);

    const pairs = 300;
    const ranges = [_]u8{0} ** (pairs * 2);
    const many: frame.Ack = .{
        .largest_acknowledged = 1000,
        .ack_delay = 0,
        .ack_range_count = pairs,
        .first_ack_range = 0,
        .ranges = &ranges,
        .ecn = null,
    };

    const outcome = try recovery.onAckReceived(.application, many, 10 * ms, 3, &lost);
    // 1000 from the first range and 602 from range 200.
    try testing.expectEqual(@as(u32, 2), outcome.newly_acked);
    try testing.expectEqual(@as(?u64, 1000), outcome.largest_newly_acked);
    try testing.expectEqual(@as(u64, 1), recovery.ack_ranges_ignored);

    // 482 sits in range 260, past the bound, so it is not acknowledged
    // and the packet threshold then declares it lost.
    try testing.expectEqual(@as(usize, 1), outcome.lost);
    try testing.expectEqual(@as(u64, 482), lost[0]);
    try testing.expectEqual(@as(usize, 0), recovery.stateConst(.application).sent_len);
}

test "a Gap that runs below zero is refused even past the range bound" {
    var lost: LostBuffer = undefined;
    var recovery: Recovery = .init(.{});
    try send(&recovery, .application, 1000, 0);

    // 299 well formed pairs leave the running number at
    // 1000 - 2 * 299 = 402. The last pair names a Gap of 500, and
    // 402 - 500 - 2 is below zero. RFC 9000 section 19.3.1 makes the
    // frame a FRAME_ENCODING_ERROR. The bad pair sits past
    // `max_ack_ranges`, so a walk that stops at the bound never reads it.
    var ranges: [299 * 2 + 3]u8 = @splat(0);
    // 500 as a two byte variable-length integer, then a zero length.
    ranges[299 * 2] = 0x41;
    ranges[299 * 2 + 1] = 0xf4;

    const bad: frame.Ack = .{
        .largest_acknowledged = 1000,
        .ack_delay = 0,
        .ack_range_count = 300,
        .first_ack_range = 0,
        .ranges = &ranges,
        .ecn = null,
    };

    try testing.expectError(
        error.RangeUnderflow,
        recovery.onAckReceived(.application, bad, 10 * ms, 3, &lost),
    );

    // The frame changed nothing: the packet it named is still recorded,
    // no estimate was taken, and nothing was declared lost.
    try testing.expectEqual(@as(usize, 1), recovery.stateConst(.application).sent_len);
    try testing.expectEqual(@as(?u64, null), recovery.stateConst(.application).largest_acked);
    try testing.expect(!recovery.rtt.has_sample);
    try testing.expectEqual(@as(u64, 0), recovery.packets_lost);
}

test "a probe passes a full congestion window and never the amplification budget" {
    var recovery: Recovery = .init(.{ .role = .server });
    recovery.onDatagramReceived(1200);

    // The window is full of packets a probe is meant to recover.
    recovery.congestion.bytes_in_flight = recovery.congestion.window;
    try testing.expect(!recovery.canSend(1200));
    // RFC 9002 section 7 lets the probe through all the same. A caller
    // that gates a probe on `canSend` builds nothing here, and the
    // connection never recovers.
    try testing.expect(recovery.canSendProbe(1200));

    // RFC 9000 section 8 is absolute, and a probe does not pass it.
    recovery.onDatagramSent(3600);
    try testing.expect(!recovery.canSendProbe(1));
    try testing.expect(!recovery.canSend(1));
}

test "a probe with only application data outstanding names a space that still has keys" {
    var recovery: Recovery = .init(.{});
    try send(&recovery, .application, 0, 0);
    recovery.onHandshakeKeys();

    // RFC 9002 section 6.2.1 does not probe the application space before
    // the handshake is confirmed, so no space in the walk can be chosen.
    // The Initial space is discarded as soon as the Handshake keys
    // exist, so naming it would name a space with nothing to send in.
    const chosen = recovery.ptoTimeAndSpace(10 * ms);
    try testing.expectEqual(loss.Space.handshake, chosen.space);
    try testing.expectEqual(@as(Instant, 10 * ms + 999 * ms), chosen.time);

    // Without the Handshake keys the Initial space is the right answer.
    var early: Recovery = .init(.{});
    try send(&early, .application, 0, 0);
    try testing.expectEqual(loss.Space.initial, early.ptoTimeAndSpace(10 * ms).space);
}

test "a key update does not restart a packet number space" {
    var lost: LostBuffer = undefined;
    var recovery: Recovery = .init(.{});
    recovery.onHandshakeConfirmed(0);

    // Packet 10 goes out in one key phase and packet 11 in the next. The
    // packet number climbs across the update, RFC 9001 section 6, so both
    // sit in the same record and one ACK resolves both.
    try send(&recovery, .application, 10, 0);
    try send(&recovery, .application, 11, ms);

    const outcome = try recovery.onAckReceived(.application, ackOne(11, 1), 50 * ms, 3, &lost);
    try testing.expectEqual(@as(u32, 2), outcome.newly_acked);
    try testing.expectEqual(@as(usize, 0), recovery.stateConst(.application).sent_len);
    try testing.expectEqual(@as(?u64, 11), recovery.stateConst(.application).largest_acked);
}
