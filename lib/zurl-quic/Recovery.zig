//! Loss detection and the sending gate of RFC 9002.
//!
//! **This is the file that decides what was lost, when to probe, and how
//! much may go out.** It holds the three packet number spaces, the
//! round-trip estimate, the NewReno controller, and the
//! anti-amplification budget. It reads no clock, opens no socket, and
//! allocates nothing.
//!
//! ## The three packet number spaces, and how they stay apart
//!
//! RFC 9000 section 12.3 gives Initial, Handshake, and application data
//! one packet number space each. A packet number means nothing outside
//! the space that issued it, so **mixing two spaces acknowledges packets
//! that were never sent**.
//!
//! Everything that is per space lives inside `SpaceState`, and there are
//! three of them in an array indexed by `loss.Space`:
//!
//! | Per space | Why |
//! | --- | --- |
//! | The sent packet record | A number 5 in one space is not a number 5 in another |
//! | `largest_acked` | RFC 9002 section 6.1 measures the packet threshold inside one space |
//! | `loss_time` | Section 6.1.2, and `lossTimeAndSpace` picks the earliest of the three |
//! | `last_ack_eliciting_time` | Section 6.2.1 builds the probe timeout from the space it will probe |
//! | `ack_eliciting_in_flight` | Section 6.2.2.1 asks which space still has something outstanding |
//! | The received ranges, `AckRanges` | RFC 9000 section 13.2.1 acknowledges inside one space |
//!
//! **Every public function that touches any of that takes a
//! `loss.Space`.** There is no function here that works on "the current
//! space", because there is no current space.
//!
//! What is **not** per space is the round-trip estimate, the congestion
//! controller, and `pto_count`. RFC 9002 section 5 and section 7 make
//! all three properties of the path, and one path carries all three
//! spaces.
//!
//! 0-RTT and 1-RTT share the application space. `loss.Space.fromLevel`
//! is the one place that mapping is written.
//!
//! ## The state is per key phase as well as per space
//!
//! A key update does not restart a packet number space. RFC 9001 section
//! 6 keeps the number climbing across the update, so a packet sent in
//! phase 0 and acknowledged in phase 1 is the same packet and the same
//! entry in the record here. The phase belongs to the key set, which
//! `zurl-quic-tls` `Session` owns, and it is not repeated here. What this
//! file must not do is reset a space at an update, and it does not: only
//! `discardSpace` empties one, and RFC 9002 section 6.4 calls it when the
//! keys of that space are thrown away.
//!
//! ## No allocator, and the bounds that replace one
//!
//! | Bound | Value | What happens at it |
//! | --- | --- | --- |
//! | Sent packets recorded per space | `max_sent_packets` | The oldest entry that is not in flight gives up its slot, and `error.TooManyPacketsInFlight` when every entry is in flight |
//! | ACK ranges used from one frame | `max_ack_ranges` | The rest are read and checked, and then ignored |
//! | Received ranges held per space | `AckRanges.max_ranges` | The oldest range is dropped and counted |
//! | Probe timeout backoff exponent | `loss.max_pto_count` | The backoff stops doubling |
//! | Probe timeout | `loss.max_pto` | The timeout stops growing |
//!
//! ## Why a hostile ACK cannot stall the connection
//!
//! An `ACK` frame is bytes the peer wrote. Four gates run before any of
//! it reaches the estimate, in this order:
//!
//! 1. **`frame.zig` already refused a frame whose range count is larger
//!    than the bytes it arrived in**, so the walk is bounded by the
//!    datagram before it starts.
//! 2. **`onAckReceived` refuses a Largest Acknowledged above the largest
//!    packet number this endpoint really sent in that space**, with
//!    `error.AckedUnsentPacket`. RFC 9000 section 13.1 makes that a
//!    connection error. Without this gate a peer names a number from the
//!    future and every packet below it is declared lost by the packet
//!    threshold, which empties the connection in one frame.
//! 3. **`frame.RangeIterator` computes each range by checked
//!    subtraction**, so a Gap or an ACK Range Length that runs below zero
//!    is `error.RangeUnderflow` and not a wrap. The ranges it produces
//!    are strictly descending and never overlap, because each one is
//!    built from the one before it by subtracting at least two.
//! 4. **A round-trip sample only exists for a packet that is in the sent
//!    record**, which means this endpoint really sent it and it was not
//!    acknowledged before. `Rtt.update` then refuses to subtract an ACK
//!    Delay that would take the sample below the smallest one ever seen.
//!
//! `largest_acked` never decreases, so an ACK that runs backwards
//! acknowledges nothing new and un-acknowledges nothing.

const std = @import("std");

const AckRanges = @import("AckRanges.zig");
const Congestion = @import("Congestion.zig");
const Rtt = @import("Rtt.zig");
const frame = @import("frame.zig");
const loss = @import("loss.zig");

const Recovery = @This();

const Instant = loss.Instant;
const Duration = loss.Duration;
const Space = loss.Space;

/// How many sent packets one space records. A packet leaves the record
/// when it is acknowledged or declared lost, so this bounds the packets
/// outstanding and not the packets ever sent.
pub const max_sent_packets: usize = 256;

/// How many ranges of one `ACK` frame are used. A frame with more names
/// its highest ranges first, and those are the ones that matter, so the
/// rest are ignored rather than refused. Ignoring a range makes a packet
/// look unacknowledged, which costs a retransmission. Refusing the frame
/// would close a connection that a lossy path made legitimate.
///
/// **Every range is still read and checked, past this bound as well.** A
/// `Gap` or an `ACK Range Length` that subtracts below zero is a
/// FRAME_ENCODING_ERROR of RFC 9000 section 19.3.1 wherever it sits in
/// the frame, and a rule that only runs on the first 256 ranges is a rule
/// a peer moves its malformed pair past.
pub const max_ack_ranges: usize = 256;

/// One packet this endpoint sent. RFC 9002 section A.1.1.
pub const SentPacket = struct {
    /// The packet number, inside its own space.
    number: u64,
    /// When it went out.
    sent_time: Instant,
    /// The bytes it took in the datagram. Counted against the congestion
    /// window when `in_flight` is set.
    size: u16,
    /// Whether it carried a frame the peer must acknowledge. RFC 9000
    /// section 2 leaves `ACK`, `PADDING`, and `CONNECTION_CLOSE` out.
    ack_eliciting: bool,
    /// Whether it counts against the congestion window. RFC 9002 section
    /// 2: a packet is in flight when it is ack-eliciting or carries
    /// `PADDING`. An ack-eliciting packet is always in flight.
    in_flight: bool,
};

/// The anti-amplification budget of RFC 9000 section 8.
///
/// **Before the peer's address is validated, an endpoint sends at most
/// `loss.amplification_factor` times the bytes it received.** The RFC
/// puts the limit on the server, because the server is the one an
/// off-path attacker can aim at a victim by spoofing a source address. A
/// client validates the server's address the moment it opens a packet
/// the server protected, so `Recovery.init` starts a client validated.
///
/// The gate is still built for both roles, and `Options.address_validated`
/// turns it on for a client. That is what makes the rule testable, and it
/// is what a server built on this file would need.
///
/// The other half of the rule is the client's, and it is why a client
/// pads: RFC 9000 section 14.1 makes a client expand every datagram
/// carrying an Initial packet to `loss.min_initial_datagram_bytes`, so
/// the server earns three times that much budget and is not blocked.
/// `Probe.pad` is where this file says so.
pub const Amplification = struct {
    /// Bytes received from the peer.
    received: u64 = 0,
    /// Bytes sent to the peer.
    sent: u64 = 0,
    /// Whether the peer's address is validated. The limit does not apply
    /// after that.
    validated: bool,

    /// How many more bytes may go out.
    pub fn budget(self: Amplification) u64 {
        if (self.validated) return std.math.maxInt(u64);
        return (self.received *| loss.amplification_factor) -| self.sent;
    }

    /// True when a datagram of `bytes` fits inside the budget.
    pub fn canSend(self: Amplification, bytes: u64) bool {
        return bytes <= self.budget();
    }

    /// True when nothing at all may go out.
    pub fn blocked(self: Amplification) bool {
        return self.budget() == 0;
    }
};

/// Everything RFC 9002 keeps for one packet number space.
pub const SpaceState = struct {
    /// Packets sent and not yet resolved, ordered by packet number.
    sent: [max_sent_packets]SentPacket = undefined,
    sent_len: usize = 0,
    /// The largest packet number the peer acknowledged. **It never
    /// decreases**, so an ACK that runs backwards takes nothing back.
    largest_acked: ?u64 = null,
    /// The largest packet number this endpoint issued. An ACK naming
    /// anything above it is refused.
    largest_sent: ?u64 = null,
    /// When the time threshold next calls a packet lost. RFC 9002
    /// section 6.1.2.
    loss_time: ?Instant = null,
    /// When the last ack-eliciting packet went out. RFC 9002 section
    /// 6.2.1 measures the probe timeout from here.
    last_ack_eliciting_time: ?Instant = null,
    /// How many ack-eliciting packets are outstanding.
    ack_eliciting_in_flight: u32 = 0,
    /// How many bytes of in-flight packets are outstanding in this space.
    /// `discardSpace` gives them back to the controller.
    bytes_in_flight: u64 = 0,
    /// The packet numbers received in this space, and the ACK frame for
    /// them.
    ack: AckRanges = .{},
};

/// Why a packet could not be recorded as sent.
pub const SendError = error{
    /// The space already records `max_sent_packets` unresolved packets
    /// and **every one of them is in flight**, so no slot can be freed.
    /// The caller waits for an acknowledgment or a loss before sending
    /// more.
    TooManyPacketsInFlight,
};

/// Why an `ACK` frame could not be used.
pub const AckError = frame.RangeError || error{
    /// The peer acknowledged a packet number this endpoint never sent in
    /// that space. RFC 9000 section 13.1 makes it a connection error of
    /// type PROTOCOL_VIOLATION.
    AckedUnsentPacket,
    /// The caller's buffer for lost packet numbers is shorter than
    /// `max_sent_packets`.
    LostBufferTooSmall,
};

/// Why a loss detection timeout could not be served.
pub const TimeoutError = error{
    /// The caller's buffer for lost packet numbers is shorter than
    /// `max_sent_packets`.
    LostBufferTooSmall,
};

/// What one acknowledgment changed.
pub const AckOutcome = struct {
    /// How many packets left the record because the peer named them.
    newly_acked: u32 = 0,
    /// The largest of those numbers.
    largest_newly_acked: ?u64 = null,
    /// Whether the round-trip estimate took a sample from this frame.
    rtt_sampled: bool = false,
    /// How many packets the same call declared lost.
    lost: usize = 0,
    /// Whether that loss met the persistent congestion rule.
    persistent_congestion: bool = false,
};

/// What a loss detection timeout asks the caller to do.
pub const Timeout = union(enum) {
    /// The timer was not due, and nothing changed.
    idle,
    /// Packets were declared lost. Their numbers are in the caller's
    /// buffer and the caller sends their frames again.
    lost: Lost,
    /// A probe is due. RFC 9002 section 6.2.4: the caller sends new data
    /// if it has any, otherwise the oldest unacknowledged data, otherwise
    /// a `PING` frame.
    probe: Probe,
};

/// The result of a time threshold expiry.
pub const Lost = struct {
    space: Space,
    count: usize,
    persistent_congestion: bool,
};

/// The result of a probe timeout expiry.
pub const Probe = struct {
    /// Which space the probe goes in.
    space: Space,
    /// How many ack-eliciting packets to send. RFC 9002 section 6.2.4
    /// allows two, so one more loss does not need another timeout.
    packets: u8,
    /// True when the datagram must be padded to
    /// `loss.min_initial_datagram_bytes`. RFC 9002 section 6.2.2.1: a
    /// client pads its Initial probes so the server earns the
    /// anti-amplification budget it needs to answer.
    pad: bool,
};

/// An instant and the space it belongs to.
pub const Earliest = struct {
    time: Instant,
    space: Space,
};

/// How to start the state machine.
pub const Options = struct {
    role: loss.Role = .client,
    /// The largest datagram this endpoint sends. RFC 9002 section 7.2
    /// sizes the congestion window in these.
    max_datagram_size: u64 = loss.min_initial_datagram_bytes,
    /// The peer's `max_ack_delay` transport parameter. RFC 9000 section
    /// 18.2 bounds it below 2^14 milliseconds, and
    /// `transport_parameters.decode` already refuses a larger one.
    peer_max_ack_delay: Duration = loss.default_max_ack_delay,
    /// The `max_ack_delay` this endpoint advertised. It is how long an
    /// acknowledgment may be held back.
    local_max_ack_delay: Duration = loss.default_max_ack_delay,
    /// Whether the peer's address is validated at the start. Null takes
    /// the answer from the role: a client starts validated, a server does
    /// not. See `Amplification`.
    address_validated: ?bool = null,
};

role: loss.Role,
rtt: Rtt,
congestion: Congestion,
spaces: [Space.count]SpaceState,
amplification: Amplification,
/// How many probe timeouts expired with nothing acknowledged since. RFC
/// 9002 section 6.2.1 doubles the timeout for each one.
/// **`loss.max_pto_count` is the ceiling and this never passes it.**
pto_count: u32 = 0,
/// Whether the handshake is confirmed. RFC 9001 section 4.1.2 makes the
/// `HANDSHAKE_DONE` frame the point for a client.
handshake_confirmed: bool = false,
/// Whether the Handshake keys exist. RFC 9002 section 6.2.2.1 picks the
/// space of an anti-deadlock probe from this.
has_handshake_keys: bool = false,
/// Whether the peer ever acknowledged a Handshake packet. RFC 9002
/// section A.7 uses it to decide whether a client's own address is
/// validated at the peer.
handshake_ack_received: bool = false,
/// When the first round-trip sample arrived. RFC 9002 section 7.6.2 bars
/// persistent congestion for packets sent before it.
first_rtt_sample: ?Instant = null,
/// When the loss detection timer next fires, or null when it is off.
timer: ?Instant = null,
/// How long this endpoint may hold an acknowledgment back.
local_max_ack_delay: Duration,

/// How many packets were declared lost over the connection. Recovery is
/// never silent, and this is what a caller reports.
packets_lost: u64 = 0,
/// How many probe timeouts expired.
pto_expirations: u64 = 0,
/// How many `ACK` frames named more ranges than `max_ack_ranges`. The
/// ranges past the bound name the oldest packet numbers, and those are
/// the ones the walk does not use.
ack_ranges_ignored: u64 = 0,
/// How many recorded packets gave up their slot because the record was
/// full and they were not in flight. See `onPacketSent`.
sent_records_evicted: u64 = 0,

/// A state machine at the start of a connection.
pub fn init(options: Options) Recovery {
    return .{
        .role = options.role,
        .rtt = .{ .max_ack_delay = options.peer_max_ack_delay },
        .congestion = .init(options.max_datagram_size),
        .spaces = @splat(.{}),
        .amplification = .{
            .validated = options.address_validated orelse (options.role == .client),
        },
        .local_max_ack_delay = options.local_max_ack_delay,
    };
}

/// The state of one space, for a caller that wants to read it.
pub fn state(self: *Recovery, space: Space) *SpaceState {
    return &self.spaces[space.index()];
}

/// The state of one space, read only.
pub fn stateConst(self: *const Recovery, space: Space) *const SpaceState {
    return &self.spaces[space.index()];
}

// -- Sending -----------------------------------------------------------

/// Records a datagram this endpoint sent, for the anti-amplification
/// budget. RFC 9000 section 8.
pub fn onDatagramSent(self: *Recovery, bytes: u64) void {
    self.amplification.sent +|= bytes;
}

/// Records a datagram that arrived, for the same budget.
pub fn onDatagramReceived(self: *Recovery, bytes: u64) void {
    self.amplification.received +|= bytes;
}

/// Records that the peer's address is validated, so the budget no longer
/// binds. RFC 9000 section 8.1.
pub fn validateAddress(self: *Recovery) void {
    self.amplification.validated = true;
}

/// Records one packet leaving. RFC 9002 section A.5.
pub fn onPacketSent(self: *Recovery, space: Space, sent: SentPacket) SendError!void {
    // A packet number is issued once and it climbs. A number that went
    // backwards is a bug above this file and not a fault on the wire.
    const s = &self.spaces[space.index()];
    if (s.largest_sent) |last| std.debug.assert(sent.number > last);
    // RFC 9002 section 2: an ack-eliciting packet is in flight.
    std.debug.assert(!sent.ack_eliciting or sent.in_flight);

    // **A packet that is not in flight must never hold the record shut.**
    // It counts against no window and arms no timer, and the only thing
    // that takes it out of the record is an acknowledgment naming a
    // number at or above it. RFC 9000 section 13.2.1 forbids the peer
    // answering a non-ack-eliciting packet with a non-ack-eliciting one,
    // so a peer that sends nothing but `PING` never has a reason to send
    // that acknowledgment, and the record fills with this endpoint's own
    // acknowledgment-only packets. A full record refuses **both** kinds,
    // so the connection stops sending altogether: no acknowledgments, no
    // stream data, and no probes. The oldest entry that is not in flight
    // gives up its slot instead.
    if (s.sent_len == max_sent_packets and !self.evictOldestNotInFlight(s)) {
        return error.TooManyPacketsInFlight;
    }
    s.sent[s.sent_len] = sent;
    s.sent_len += 1;
    s.largest_sent = sent.number;

    if (!sent.in_flight) return;

    if (sent.ack_eliciting) {
        s.ack_eliciting_in_flight +|= 1;
        s.last_ack_eliciting_time = sent.sent_time;
    }
    s.bytes_in_flight +|= sent.size;
    self.congestion.onPacketSent(sent.size);
    self.setLossDetectionTimer(sent.sent_time);
}

/// Drops the oldest recorded packet that is not in flight and says
/// whether it found one.
///
/// The entry it drops holds no bytes in the congestion window, no
/// ack-eliciting count, and no round-trip sample, so the only thing lost
/// is one packet of the `newly_acked` count a later `ACK` could have
/// reported. **Recovery is never silent**, so every drop is counted in
/// `sent_records_evicted`.
fn evictOldestNotInFlight(self: *Recovery, s: *SpaceState) bool {
    for (s.sent[0..s.sent_len], 0..) |entry, index| {
        if (entry.in_flight) continue;
        std.mem.copyForwards(
            SentPacket,
            s.sent[index .. s.sent_len - 1],
            s.sent[index + 1 .. s.sent_len],
        );
        s.sent_len -= 1;
        self.sent_records_evicted +|= 1;
        return true;
    }
    return false;
}

/// True when `bytes` may go out now: the congestion window has room and
/// the anti-amplification budget allows it.
///
/// A probe ignores the congestion window. RFC 9002 section 7 lets one
/// through, because a connection whose window is full of lost packets
/// would otherwise never recover. It does **not** ignore the
/// anti-amplification budget, which section 8 makes absolute.
pub fn canSend(self: *const Recovery, bytes: u64) bool {
    return self.amplification.canSend(bytes) and self.congestion.canSend(bytes);
}

/// True when a probe of `bytes` may go out.
///
/// **A caller serving a `Timeout.probe` asks this and not `canSend`.**
/// RFC 9002 section 7 lets a probe pass a full congestion window, and a
/// caller that gates a probe on `canSend` builds nothing exactly when the
/// window is full of packets the probe is meant to recover, which is the
/// deadlock the probe exists to break. The anti-amplification budget of
/// section 8 still binds, and this is where it is checked.
pub fn canSendProbe(self: *const Recovery, bytes: u64) bool {
    return self.amplification.canSend(bytes);
}

/// How many bytes of in-flight packets are outstanding over all spaces.
pub fn bytesInFlight(self: *const Recovery) u64 {
    return self.congestion.bytes_in_flight;
}

/// How many ack-eliciting packets are outstanding over all spaces.
pub fn ackElicitingInFlight(self: *const Recovery) u32 {
    var total: u32 = 0;
    for (&self.spaces) |*s| total +|= s.ack_eliciting_in_flight;
    return total;
}

// -- Receiving ---------------------------------------------------------

/// Records one packet that arrived, so an `ACK` frame can name it.
pub fn onPacketReceived(
    self: *Recovery,
    space: Space,
    number: u64,
    ack_eliciting: bool,
    now: Instant,
) AckRanges.Recorded {
    return self.spaces[space.index()].ack.record(number, now, .{
        .ack_eliciting = ack_eliciting,
        // RFC 9000 section 13.2.1 requires an immediate acknowledgment of
        // every ack-eliciting Initial and Handshake packet.
        .handshake_space = space != .application,
        .max_ack_delay = self.local_max_ack_delay,
    });
}

/// True when an `ACK` frame for `space` is due now.
pub fn ackDue(self: *const Recovery, space: Space, now: Instant) bool {
    return self.spaces[space.index()].ack.due(now);
}

/// Builds the `ACK` frame for `space`. The frame's ranges point into
/// `out`, which must be at least `AckRanges.max_range_bytes` long.
pub fn buildAck(
    self: *const Recovery,
    space: Space,
    now: Instant,
    ack_delay_exponent: u6,
    out: []u8,
) AckRanges.BuildError!frame.Ack {
    const s = &self.spaces[space.index()];
    // RFC 9000 section 13.2.1: an endpoint reports no delay it did not
    // take. The Initial and Handshake spaces are acknowledged at once, so
    // the field is zero there.
    const delay = if (space == .application) s.ack.ackDelayField(now, ack_delay_exponent) else 0;
    return s.ack.build(delay, out);
}

/// Records that an `ACK` frame for `space` went out.
pub fn onAckSent(self: *Recovery, space: Space) void {
    self.spaces[space.index()].ack.onAckSent();
}

/// Reads one `ACK` frame the peer sent. RFC 9002 section A.7.
///
/// `lost_out` receives the packet numbers this call declared lost, and it
/// must be at least `max_sent_packets` long, which is the most one call
/// can produce.
pub fn onAckReceived(
    self: *Recovery,
    space: Space,
    ack: frame.Ack,
    now: Instant,
    ack_delay_exponent: u6,
    lost_out: []u64,
) AckError!AckOutcome {
    if (lost_out.len < max_sent_packets) return error.LostBufferTooSmall;

    const s = &self.spaces[space.index()];

    // **Gate one.** A number above the largest this space ever issued
    // names a packet that does not exist. RFC 9000 section 13.1.
    const largest_sent = s.largest_sent orelse return error.AckedUnsentPacket;
    if (ack.largest_acknowledged > largest_sent) return error.AckedUnsentPacket;

    // **Gate two.** The ranges are walked into a fixed array, and every
    // subtraction inside the walk is checked by `frame.RangeIterator`.
    // The result is strictly descending and never overlaps.
    //
    // **The walk runs to the end of the frame even after the array is
    // full.** Only the first `max_ack_ranges` are used, but a `Gap` or an
    // `ACK Range Length` that subtracts below zero is a
    // FRAME_ENCODING_ERROR of RFC 9000 section 19.3.1 wherever it sits,
    // and a walk that stops at the bound is a walk a peer puts its
    // malformed pair past. Reading the rest costs one loop over bytes
    // `frame.zig` already bounded by the datagram.
    var ranges: [max_ack_ranges]frame.Range = undefined;
    var range_count: usize = 0;
    var over_bound = false;
    var iterator = ack.iterator();
    while (try iterator.next()) |range| {
        if (range_count == max_ack_ranges) {
            over_bound = true;
            continue;
        }
        ranges[range_count] = range;
        range_count += 1;
    }
    if (over_bound) self.ack_ranges_ignored +|= 1;

    // **`largest_acked` never decreases.** A frame that names an older
    // number acknowledges nothing new.
    if (s.largest_acked == null or ack.largest_acknowledged > s.largest_acked.?) {
        s.largest_acked = ack.largest_acknowledged;
    }

    var outcome: AckOutcome = .{};
    var newly_acked_eliciting = false;
    var largest_acked_packet: ?SentPacket = null;

    // Both lists are sorted, so one walk resolves them. `range_index - 1`
    // names the range under consideration and it only moves toward the
    // larger ranges as the packet numbers climb.
    var range_index: usize = range_count;
    var write: usize = 0;
    for (s.sent[0..s.sent_len]) |sent| {
        while (range_index > 0 and sent.number > ranges[range_index - 1].largest) {
            range_index -= 1;
        }
        const acked = range_index > 0 and sent.number >= ranges[range_index - 1].smallest;
        if (!acked) {
            s.sent[write] = sent;
            write += 1;
            continue;
        }

        outcome.newly_acked +|= 1;
        if (outcome.largest_newly_acked == null or sent.number > outcome.largest_newly_acked.?) {
            outcome.largest_newly_acked = sent.number;
        }
        if (sent.number == ack.largest_acknowledged) largest_acked_packet = sent;
        if (sent.in_flight) {
            s.bytes_in_flight -|= sent.size;
            self.congestion.onPacketAcked(sent.sent_time, sent.size);
        }
        if (sent.ack_eliciting) {
            s.ack_eliciting_in_flight -|= 1;
            newly_acked_eliciting = true;
        }
    }
    s.sent_len = write;

    // **The round-trip sample.** RFC 9002 section 5.1 takes one only when
    // the largest acknowledged number is newly acknowledged and something
    // in this frame was ack-eliciting. A packet that was already
    // acknowledged gives no sample, so a peer cannot repeat one frame to
    // drag the estimate.
    if (largest_acked_packet) |packet| {
        if (newly_acked_eliciting and now >= packet.sent_time) {
            self.rtt.update(.{
                .rtt = loss.since(now, packet.sent_time),
                .ack_delay = ackDelayToNanoseconds(ack.ack_delay, ack_delay_exponent),
                .space = space,
                .handshake_confirmed = self.handshake_confirmed,
            });
            if (self.first_rtt_sample == null) self.first_rtt_sample = now;
            outcome.rtt_sampled = true;
        }
    }

    if (space == .handshake and outcome.newly_acked > 0) self.handshake_ack_received = true;

    outcome.lost = self.detectAndRemoveLostPackets(
        space,
        now,
        lost_out,
        &outcome.persistent_congestion,
    );

    // RFC 9002 section A.7: the backoff resets only when the client is
    // sure the server has validated its address. Otherwise the server may
    // still be blocked and the probes must keep coming.
    if (self.peerCompletedAddressValidation()) self.pto_count = 0;

    self.setLossDetectionTimer(now);
    return outcome;
}

/// The `ACK Delay` field turned into nanoseconds, with no wrap.
///
/// The field is a variable-length integer, so it can name 2^62, and the
/// exponent multiplies it again. Both steps saturate, so a hostile frame
/// arrives at `Rtt.update` as the largest duration and not as a small
/// wrapped one. `Rtt.update` then refuses to subtract it.
fn ackDelayToNanoseconds(field: u64, exponent: u6) Duration {
    const scale = @as(u64, 1) << exponent;
    return field *| scale *| loss.ns_per_us;
}

// -- Loss detection ----------------------------------------------------

/// Declares packets lost in one space and takes them out of the record.
/// RFC 9002 section A.10.
///
/// `persistent_out` is set when the run of losses meets the persistent
/// congestion rule of section 7.6.2.
fn detectAndRemoveLostPackets(
    self: *Recovery,
    space: Space,
    now: Instant,
    lost_out: []u64,
    persistent_out: *bool,
) usize {
    const s = &self.spaces[space.index()];
    s.loss_time = null;
    persistent_out.* = false;

    const largest_acked = s.largest_acked orelse return 0;

    const loss_delay = self.rtt.lossDelay();
    const lost_send_time = now -| loss_delay;

    var lost_count: usize = 0;
    var lost_bytes: u64 = 0;
    var largest_lost_time: ?Instant = null;
    var run: PersistentRun = .{ .first_rtt_sample = self.first_rtt_sample };
    var previous_number: ?u64 = null;

    var write: usize = 0;
    for (s.sent[0..s.sent_len]) |sent| {
        if (sent.number > largest_acked) {
            // The record climbs, so nothing after this can be resolved.
            s.sent[write] = sent;
            write += 1;
            run.close();
            previous_number = null;
            continue;
        }

        // RFC 9002 section 6.1.1, the packet threshold. The add
        // saturates, so a number near 2^64 cannot wrap into a small one.
        const by_packet = sent.number +| loss.packet_threshold <= largest_acked;
        // RFC 9002 section 6.1.2, the time threshold.
        const by_time = sent.sent_time <= lost_send_time;

        if (!by_packet and !by_time) {
            // Not lost yet. The timer is armed for the moment it would be.
            const when = sent.sent_time +| loss_delay;
            s.loss_time = if (s.loss_time) |current| @min(current, when) else when;
            s.sent[write] = sent;
            write += 1;
            run.close();
            previous_number = null;
            continue;
        }

        if (lost_count < lost_out.len) lost_out[lost_count] = sent.number;
        lost_count += 1;
        if (sent.in_flight) {
            lost_bytes +|= sent.size;
            s.bytes_in_flight -|= sent.size;
            if (largest_lost_time == null or sent.sent_time > largest_lost_time.?) {
                largest_lost_time = sent.sent_time;
            }
        }
        if (sent.ack_eliciting) s.ack_eliciting_in_flight -|= 1;

        // RFC 9002 section 7.6.2 needs the losses to be consecutive. A
        // packet number that is not one above the last one means a packet
        // between them was acknowledged, which ends the run.
        const contiguous = previous_number != null and sent.number == previous_number.? + 1;
        if (!contiguous) run.close();
        run.add(sent);
        previous_number = sent.number;
    }
    s.sent_len = write;
    run.close();

    if (lost_count == 0) return 0;

    self.packets_lost +|= lost_count;
    self.congestion.onPacketsLost(lost_bytes);
    if (largest_lost_time) |when| self.congestion.onCongestionEvent(when, now);

    if (run.longest > self.rtt.persistentCongestionDuration()) {
        self.congestion.onPersistentCongestion();
        persistent_out.* = true;
    }

    return lost_count;
}

/// The longest run of consecutive lost ack-eliciting packets seen in one
/// pass. RFC 9002 section 7.6.2.
const PersistentRun = struct {
    /// When the first round-trip sample arrived. Section 7.6.2 only
    /// counts packets sent after it, because before it the probe timeout
    /// is a guess and not a measurement.
    first_rtt_sample: ?Instant,
    start: ?Instant = null,
    end: Instant = 0,
    /// How many ack-eliciting packets the current run holds. Section
    /// 7.6.2 needs two, because a receiver only has to acknowledge these.
    eliciting: u32 = 0,
    /// The longest qualifying span found so far.
    longest: Duration = 0,

    fn add(self: *PersistentRun, sent: SentPacket) void {
        if (!sent.ack_eliciting) return;
        if (self.start == null) self.start = sent.sent_time;
        self.end = sent.sent_time;
        self.eliciting +|= 1;
    }

    fn close(self: *PersistentRun) void {
        defer {
            self.start = null;
            self.end = 0;
            self.eliciting = 0;
        }
        if (self.eliciting < 2) return;
        const start = self.start orelse return;
        const first = self.first_rtt_sample orelse return;
        if (start <= first) return;
        self.longest = @max(self.longest, loss.since(self.end, start));
    }
};

/// The earliest armed time threshold over the three spaces, and which
/// space it belongs to. RFC 9002 section A.8.
pub fn lossTimeAndSpace(self: *const Recovery) ?Earliest {
    var best: ?Earliest = null;
    for ([_]Space{ .initial, .handshake, .application }) |space| {
        const when = self.spaces[space.index()].loss_time orelse continue;
        if (best == null or when < best.?.time) best = .{ .time = when, .space = space };
    }
    return best;
}

/// True when the peer has validated this endpoint's address, so the probe
/// backoff may reset. RFC 9002 section A.7.
pub fn peerCompletedAddressValidation(self: *const Recovery) bool {
    // A server's address is validated by the client as soon as the client
    // opens a packet, so the question only has a real answer for a client.
    if (self.role == .server) return true;
    return self.handshake_ack_received or self.handshake_confirmed;
}

/// The probe timeout multiplier. **This is where the backoff stops.**
/// RFC 9002 section 6.2.1 doubles the timeout at each expiry and names no
/// limit. `loss.max_pto_count` caps the exponent at 8, so the multiplier
/// stops at 256 and a connection that lost its peer keeps probing at a
/// fixed rate rather than at a rate that halves forever.
fn ptoBackoff(self: *const Recovery) u64 {
    const count = @min(self.pto_count, loss.max_pto_count);
    return @as(u64, 1) << @intCast(count);
}

/// When the next probe timeout fires and which space it probes. RFC 9002
/// section A.8.
///
/// **Every duration here is capped at `loss.max_pto`.** That is the second
/// ceiling, and it is the absolute one: whatever the estimate and the
/// backoff say, one probe timeout is at most one minute.
///
/// **And the instant returned is always in the future.** A ceiling that
/// arms a timer in the past makes the timeout due on every call, which
/// turns the backoff into a probe storm at a peer that stopped answering.
pub fn ptoTimeAndSpace(self: *const Recovery, now: Instant) Earliest {
    const backoff = self.ptoBackoff();
    const duration = @min(self.rtt.ptoBase() *| backoff, loss.max_pto);

    if (self.ackElicitingInFlight() == 0) {
        // The anti-deadlock probe of RFC 9002 section 6.2.2.1. Nothing is
        // outstanding, so the peer may be the one that is blocked, and a
        // packet from here is what unblocks it. The RFC asserts the
        // address is not validated at this point. That is not asserted
        // here: `setLossDetectionTimer` already returns without arming a
        // timer in that case, so reaching this line means a caller asked
        // directly, and answering is more useful than stopping.
        const space: Space = if (self.has_handshake_keys) .handshake else .initial;
        return .{ .time = now +| duration, .space = space };
    }

    var best: ?Earliest = null;
    for ([_]Space{ .initial, .handshake, .application }) |space| {
        const s = &self.spaces[space.index()];
        if (s.ack_eliciting_in_flight == 0) continue;
        var space_duration = duration;
        if (space == .application) {
            // RFC 9002 section 6.2.1: the application space is not probed
            // before the handshake is confirmed, and its timeout carries
            // the peer's stated acknowledgment delay.
            if (!self.handshake_confirmed) continue;
            space_duration = @min(
                duration +| (self.rtt.max_ack_delay *| backoff),
                loss.max_pto,
            );
        }
        const last = s.last_ack_eliciting_time orelse continue;
        // **The armed instant is never in the past.** RFC 9002 section
        // 6.2.1 measures the timeout from the last ack-eliciting packet,
        // and the pseudocode holds only because serving the timeout sends
        // a probe that moves that instant. When both ceilings bind and
        // the caller sends nothing, the instant stops moving and
        // `last +| space_duration` becomes a constant already behind
        // `now`. The timeout is then due on every call, and the backoff
        // the ceiling was built to produce turns into one probe per poll
        // at a peer that has gone silent. A spent timeout starts a fresh
        // one from here instead, so the gap between two probes is the
        // ceiling and not the poll interval.
        const armed = last +| space_duration;
        const when = if (armed > now) armed else now +| space_duration;
        if (best == null or when < best.?.time) best = .{ .time = when, .space = space };
    }

    // Reaching this line means the only space with something outstanding
    // is the application space and the handshake is not confirmed, so no
    // probe may go there yet. RFC 9002 section 6.2.2.1 picks the space
    // the same way the anti-deadlock probe above does: naming `.initial`
    // once the Handshake keys exist names a space the caller has usually
    // already discarded.
    const fallback: Space = if (self.has_handshake_keys) .handshake else .initial;
    return best orelse .{ .time = now +| duration, .space = fallback };
}

/// Arms the loss detection timer. RFC 9002 section A.6.
pub fn setLossDetectionTimer(self: *Recovery, now: Instant) void {
    if (self.lossTimeAndSpace()) |earliest| {
        self.timer = earliest.time;
        return;
    }

    // RFC 9002 section A.6: an endpoint blocked by the anti-amplification
    // limit cannot send, so a timer would only fire and do nothing.
    if (self.amplification.blocked()) {
        self.timer = null;
        return;
    }

    if (self.ackElicitingInFlight() == 0 and self.peerCompletedAddressValidation()) {
        self.timer = null;
        return;
    }

    self.timer = self.ptoTimeAndSpace(now).time;
}

/// Serves a loss detection timeout. RFC 9002 section A.9.
///
/// `lost_out` receives the packet numbers this call declared lost and must
/// be at least `max_sent_packets` long.
pub fn onLossDetectionTimeout(
    self: *Recovery,
    now: Instant,
    lost_out: []u64,
) TimeoutError!Timeout {
    if (lost_out.len < max_sent_packets) return error.LostBufferTooSmall;

    const armed = self.timer orelse return .idle;
    if (now < armed) return .idle;

    if (self.lossTimeAndSpace()) |earliest| {
        var persistent = false;
        const count = self.detectAndRemoveLostPackets(earliest.space, now, lost_out, &persistent);
        self.setLossDetectionTimer(now);
        return .{ .lost = .{
            .space = earliest.space,
            .count = count,
            .persistent_congestion = persistent,
        } };
    }

    const outstanding = self.congestion.bytes_in_flight > 0;
    const space: Space = if (outstanding)
        self.ptoTimeAndSpace(now).space
    else if (self.has_handshake_keys)
        .handshake
    else
        .initial;

    // RFC 9002 section 6.2.2.1: a client's Initial probe is padded so the
    // server earns three times that many bytes of budget to answer with.
    const pad = space == .initial and self.role == .client;

    // **The ceiling.** The count stops climbing, so the backoff stops
    // doubling and the connection keeps probing at a fixed rate.
    self.pto_count = @min(self.pto_count + 1, loss.max_pto_count);
    self.pto_expirations +|= 1;
    self.setLossDetectionTimer(now);

    return .{ .probe = .{
        .space = space,
        .packets = if (outstanding) 2 else 1,
        .pad = pad,
    } };
}

/// The next instant anything is due: the loss detection timer, or an ACK
/// this endpoint owes. Null when nothing is armed.
pub fn nextTimeout(self: *const Recovery) ?Instant {
    var best: ?Instant = self.timer;
    for (&self.spaces) |*s| {
        const when = s.ack.nextDeadline() orelse continue;
        if (best == null or when < best.?) best = when;
    }
    return best;
}

// -- Connection events -------------------------------------------------

/// Records that the Handshake keys exist. RFC 9002 section 6.2.2.1 picks
/// the space of an anti-deadlock probe from this.
pub fn onHandshakeKeys(self: *Recovery) void {
    self.has_handshake_keys = true;
}

/// Records that the handshake is confirmed. RFC 9001 section 4.1.2: the
/// `HANDSHAKE_DONE` frame is the point for a client.
pub fn onHandshakeConfirmed(self: *Recovery, now: Instant) void {
    self.handshake_confirmed = true;
    self.setLossDetectionTimer(now);
}

/// Throws away one packet number space with its keys. RFC 9002 section
/// 6.4 and section A.11.
///
/// The application space is never discarded, because the connection ends
/// with it.
pub fn discardSpace(self: *Recovery, space: Space, now: Instant) void {
    std.debug.assert(space != .application);
    const s = &self.spaces[space.index()];
    self.congestion.onSpaceDiscarded(s.bytes_in_flight);
    s.* = .{};
    self.pto_count = 0;
    self.setLossDetectionTimer(now);
}

test {
    _ = @import("recovery_test.zig");
}
