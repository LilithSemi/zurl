//! The stream table of one QUIC connection: the two state machines, both
//! levels of flow control, the stream limits, and the frames that carry
//! them. RFC 9000 sections 2, 3, 4, and 19.
//!
//! **This is the layer between the frames and HTTP/3.** `frame.zig` reads
//! and writes one `STREAM` frame and knows nothing about the stream it
//! names. `zurl-h3` reads a stream of octets and knows nothing about how
//! they arrived. This file joins the two: it puts the octets of one stream
//! back in order, it keeps the sender inside the window the peer gave, and
//! it says when a window must be widened.
//!
//! ## Flow control is two-level, and the levels cannot deadlock
//!
//! RFC 9000 section 4 puts a limit on each stream and a limit on the
//! connection, in each direction. Four counters, and every one of them is
//! a `stream.Flow`.
//!
//! **Receiving.** A stream's window is exactly the length of the buffer
//! the caller gave it, so a peer that keeps to the limit can always be
//! stored and a peer that passes it is refused before a byte is copied.
//! The connection's window is `Options.recv_window`, and `init` refuses a
//! window smaller than the sum of every stream window in the table.
//!
//! **That comparison alone is not enough.** Connection room is spent on
//! the highest offset a stream reached, which RFC 9000 section 4 asks for
//! so that a retransmission cannot spend the window twice. A peer can
//! therefore hold a stream's whole window with one byte at the top of it
//! and leave the gap in front unfilled. No caller can read such a stream,
//! so room that came back only with the bytes a caller read would never
//! come back at all. The connection would narrow with each such stream
//! and stop with no fault to report.
//!
//! **So connection room comes back when a slot ends, and not when its
//! bytes are read.** Four places give it back:
//!
//! - `read`, for the bytes the caller took.
//! - `onResetStream`, for what the reset will never deliver. RFC 9000
//!   section 4.5 counts the final size whether the bytes arrived or not.
//! - `stopSending`, for the whole half at once. The caller has said it
//!   wants no more of it, and a peer that answers with no `RESET_STREAM`
//!   must not hold room for the rest of the connection.
//! - `release`, for whatever is left when the slot goes back to the table.
//!
//! `takeMaxData` then sends its frame early, before its own threshold,
//! whenever the room left cannot cover one stream window. With that, the
//! room left is never below the sum of the windows of the free slots, so
//! a free slot can always fill its own window whatever every other stream
//! is doing, and a caller that stops reading one stream cannot stop the
//! rest.
//!
//! **Sending.** The peer's `MAX_DATA` is one window shared by every
//! stream, so a stream that writes as fast as it can would take all of it
//! and the rest would send nothing. `sendRoom` gives a stream an even
//! share of what is left, with one datagram as the floor. That is the rule
//! `zurl-http/h2.zig` reached with `roomToSend` and `shareOfConnection`,
//! and it is here for the same reason.
//!
//! ## What this file does not do
//!
//! No socket, no packet, no timer, and no allocator. `Streams.init` takes
//! the caller's slots and each slot already holds the caller's two
//! buffers, so the whole table is memory the caller chose and sized.
//! Nothing here reads a clock: retransmission and loss are the caller's,
//! through `onLost` and `onAcked`.

const std = @import("std");
const varint = @import("varint.zig");
const frame = @import("frame.zig");
const stream = @import("stream.zig");
const transport_error = @import("transport_error.zig");
const Reassembly = @import("Reassembly.zig");
const SendBuffer = @import("SendBuffer.zig");

const Streams = @This();

/// The smallest share of the connection send window one stream may take,
/// whatever the even share works out to.
///
/// One datagram of the size RFC 9000 section 14.1 makes every path carry.
/// An even share that rounded to nothing would stop every stream instead
/// of slowing each one.
pub const min_send_share: u64 = 1200;

/// How many stream numbers of one kind this table remembers for each
/// direction of the peer's stream space.
///
/// **The table must tell "opened and released" from "never opened".** RFC
/// 9000 section 3.2 opens every lower stream number with the one the peer
/// names, and QUIC delivers streams in whatever order the packets arrive,
/// so a number below the highest the peer has used is as likely to be a
/// stream that never opened as one that finished. A high water mark
/// carries only one of those two meanings, so this table keeps one bit
/// for each number instead.
///
/// The set is a fixed array and nothing here allocates. `init` refuses a
/// stream limit above this number, and a limit that large would need one
/// slot for each stream anyway.
pub const max_tracked_streams: u64 = 512;

/// One bit for each peer stream number of one kind, set when the stream
/// finished and its slot went back to the table.
const ReleasedSet = [max_tracked_streams / 64]u64;

/// Every fault the stream layer can report. Each one is a connection
/// error in RFC 9000, and `errorCode` names the number it closes with.
pub const Error = Reassembly.Error || stream.FlowError || stream.IdError || error{
    /// A frame arrived for a stream in a state that has no answer for it:
    /// data on the sending half of a unidirectional stream this side
    /// opened, or a `MAX_STREAM_DATA` for a receive-only stream. RFC 9000
    /// section 19, a STREAM_STATE_ERROR.
    StreamStateError,
    /// The peer opened a stream past the limit this side gave it, or this
    /// side was asked to open one past the limit the peer gave. RFC 9000
    /// section 4.6, a STREAM_LIMIT_ERROR.
    StreamLimitError,
    /// A `MAX_STREAMS` frame named a count above 2^60. RFC 9000 section
    /// 19.11 makes that a FRAME_ENCODING_ERROR and not a
    /// STREAM_LIMIT_ERROR, because the frame itself cannot be read and
    /// no limit was passed.
    StreamCountTooLarge,
    /// Every slot in the caller's table is busy.
    ///
    /// **This is a local resource fault and not a protocol error.** The
    /// peer kept to every limit this side advertised, so nothing about the
    /// connection is wrong; this build simply has no room. A caller waits
    /// for a stream to end rather than close the connection.
    NoStreamSlot,
};

/// The RFC 9000 section 20.1 code that closes a connection on `err`.
pub fn errorCode(err: Error) transport_error.Code {
    return switch (err) {
        error.FlowControlError, error.StreamBufferOverflow => .flow_control_error,
        error.StreamLimitError, error.StreamNumberTooLarge => .stream_limit_error,
        error.StreamStateError => .stream_state_error,
        error.FinalSizeError => .final_size_error,
        error.OffsetTooLarge, error.StreamCountTooLarge => .frame_encoding_error,
        error.StreamDataMismatch => .protocol_violation,
        // The peer is not breaking a rule here: this side ran out of a
        // slot. RFC 9000 section 20.1 gives that INTERNAL_ERROR, and
        // `init` is what keeps a peer inside the limits this side gave
        // from ever reaching it.
        error.NoStreamSlot => .internal_error,
        // **No frame from the wire reaches this.** `onStream` drops a
        // frame that opens one gap too many and counts it, because this
        // side promised the whole window in `MAX_STREAM_DATA` and a
        // `STREAM` frame is sent again. The code is here for a caller
        // that drives `Reassembly` itself.
        error.TooManyStreamGaps => .internal_error,
    };
}

/// One stream, both halves.
///
/// A slot is reused: `open` takes an idle one and `release` gives it
/// back. The two buffers belong to the caller for the life of the table
/// and are never handed out.
pub const Stream = struct {
    /// The stream identifier. Meaningless while `in_use` is false.
    id: u64 = 0,
    in_use: bool = false,
    send: SendBuffer,
    recv: Reassembly,
    send_state: stream.SendState = .ready,
    recv_state: stream.RecvState = .recv,
    /// The largest offset this side may send on this stream. RFC 9000
    /// section 4.1, raised by a `MAX_STREAM_DATA` frame.
    send_limit: u64 = 0,
    /// The largest offset this side has told the peer it may reach, which
    /// is what the last `MAX_STREAM_DATA` carried.
    recv_limit: u64 = 0,
    /// How many bytes of this stream have already been counted into
    /// `Streams.recv_consumed`.
    ///
    /// **One byte gives its connection room back once.** A byte the
    /// caller read is counted in `read`, and a byte a reset will never
    /// deliver is counted in `finishRecv`. Without this number the two
    /// would count the same byte twice on a stream that was read and then
    /// reset, and the connection window would grow past what this side
    /// has buffers for.
    recv_released: u64 = 0,
    /// Whether the caller has given up on the receiving half.
    ///
    /// `stopSending` sets this. The connection room the half held came
    /// back at that moment, so every byte that arrives after it is
    /// dropped and counted rather than stored: storing it would spend
    /// room that has already been given away.
    recv_abandoned: bool = false,
    /// The application error code a `RESET_STREAM` from the peer carried,
    /// or null.
    peer_reset_code: ?u64 = null,
    /// The application error code a `STOP_SENDING` from the peer carried,
    /// or null.
    peer_stop_code: ?u64 = null,
    /// A `RESET_STREAM` this side owes the peer, and the code it carries.
    pending_reset: ?u64 = null,
    /// A `STOP_SENDING` this side owes the peer, and the code it carries.
    pending_stop: ?u64 = null,
    /// Whether this side owes a `STREAM_DATA_BLOCKED` frame. RFC 9000
    /// section 4.1 asks a sender that cannot send to say so, which is how
    /// a peer learns its own window is the reason nothing is moving.
    pending_blocked: bool = false,

    /// A slot with `send_buffer` for the sending half and `recv_buffer`
    /// for the receiving half.
    ///
    /// Neither buffer may be empty. The receiving buffer's length is the
    /// window this side advertises for the stream, so it is also the
    /// number `init` adds up when it checks the connection window.
    pub fn init(send_buffer: []u8, recv_buffer: []u8) Stream {
        return .{ .send = .init(send_buffer), .recv = .init(recv_buffer) };
    }

    /// Whether both halves are finished, so the slot may be reused.
    pub fn isDone(self: *const Stream) bool {
        if (!self.in_use) return true;
        if (self.pending_reset != null or self.pending_stop != null) return false;
        return self.send_state.finished() and self.recv_state.finished();
    }

    fn reset(self: *Stream) void {
        self.* = .{ .send = .init(self.send.buffer), .recv = .init(self.recv.buffer) };
    }
};

/// The limits this side announces and the table it works out of.
pub const Options = struct {
    /// Which endpoint this is. RFC 9000 section 2.1 reads the low bit of
    /// every stream identifier against it.
    role: stream.Initiator,
    /// The caller's slots, each already holding its two buffers.
    slots: []Stream,
    /// The connection window this side advertises, which is its own
    /// `initial_max_data`.
    ///
    /// **At or above the sum of every receiving buffer in `slots`.** See
    /// the file comment: that is the whole of the anti-deadlock argument,
    /// and `init` refuses a smaller number rather than let a stalled
    /// reader stop the connection.
    recv_window: u64,
    /// The peer's `initial_max_data`, which is the connection window this
    /// side may send inside.
    peer_max_data: u64 = 0,
    /// The peer's `initial_max_stream_data_bidi_remote`: the window on a
    /// bidirectional stream **this** side opened.
    peer_max_stream_data_bidi_remote: u64 = 0,
    /// The peer's `initial_max_stream_data_bidi_local`: the window on a
    /// bidirectional stream the **peer** opened.
    peer_max_stream_data_bidi_local: u64 = 0,
    /// The peer's `initial_max_stream_data_uni`.
    peer_max_stream_data_uni: u64 = 0,
    /// The peer's `initial_max_streams_bidi`: how many bidirectional
    /// streams this side may open.
    peer_max_streams_bidi: u64 = 0,
    /// The peer's `initial_max_streams_uni`.
    peer_max_streams_uni: u64 = 0,
    /// How many bidirectional streams this side lets the peer open.
    local_max_streams_bidi: u64 = 0,
    /// How many unidirectional streams this side lets the peer open.
    local_max_streams_uni: u64 = 0,
    /// How many slots this side keeps for the streams it opens itself.
    ///
    /// **Peer streams and local streams share one pool.** A peer that
    /// fills the pool inside the limits this side gave it would stop this
    /// side opening anything, and an HTTP/3 client needs one slot for its
    /// request and three for the streams RFC 9114 section 6.2 names. So
    /// `init` adds this to the two peer limits and refuses a table that
    /// cannot hold the sum.
    ///
    /// The reservation needs no check at run time. A peer can hold at
    /// most `local_max_streams_bidi + local_max_streams_uni` slots,
    /// because `accept` refuses a number at or above the limit and never
    /// opens one number twice, so this many slots always remain.
    local_slot_reserve: u64 = 0,
};

/// The faults `init` can report before a connection exists.
pub const InitError = error{
    /// The connection window is smaller than the sum of the stream
    /// windows in the table, so a set of stalled readers could hold every
    /// byte of connection room and the rest of the connection would stop
    /// with nothing to report. See the file comment.
    ConnectionWindowTooSmall,
    /// A stream limit names more streams than a varint can identify, or
    /// more peer streams of one kind than `max_tracked_streams`. RFC 9000
    /// section 4.6.
    StreamLimitTooLarge,
    /// The table holds fewer slots than the limits this side would
    /// advertise.
    ///
    /// **`local_max_streams_bidi + local_max_streams_uni +
    /// local_slot_reserve` must be at or below `slots.len`.** RFC 9000
    /// section 4.6 makes a stream limit a promise: a peer that keeps to
    /// it may open that many streams at once, and each one needs a slot.
    /// A table that cannot hold them all would report `NoStreamSlot` and
    /// close the connection with INTERNAL_ERROR, for a peer that did
    /// nothing wrong. The fault belongs to the numbers the caller chose,
    /// so it is reported here, before a connection exists.
    StreamSlotsTooFew,
};

role: stream.Initiator,
slots: []Stream,

/// What this side may still send on the connection. `limit` is the peer's
/// `MAX_DATA`, `used` is every new stream byte that has gone out.
send_flow: stream.Flow,
/// What the peer may still send on the connection. `limit` is the last
/// `MAX_DATA` this side sent, `used` is the sum of the highest offset
/// every stream reached.
recv_flow: stream.Flow,
/// How wide the connection window is.
recv_window: u64,
/// How many bytes the caller has taken off every stream, plus the bytes a
/// reset stream will never deliver. **This is what the connection window
/// slides over**: RFC 9000 section 4.5 makes a reset stream's final size
/// count, so a reset must give its room back or the window shrinks for
/// good.
recv_consumed: u64 = 0,
/// Whether this side owes a `DATA_BLOCKED` frame.
pending_blocked: bool = false,

/// How many streams of each kind this side may open, indexed by
/// `kindIndex`.
peer_stream_limit: [2]u64,
/// How many streams of each kind this side lets the peer open.
local_stream_limit: [2]u64,
/// The last `MAX_STREAMS` this side sent for each kind.
sent_stream_limit: [2]u64,
/// The next stream number this side will use for each kind.
next_number: [2]u64 = .{ 0, 0 },
/// One past the highest stream number the peer has opened, for each kind.
///
/// **This says how far the peer has counted and nothing else.** It is not
/// what decides whether a number names a live stream: RFC 9000 section
/// 3.2 opens every lower number with the one the peer names, and packets
/// arrive in any order, so a number below this mark is as likely to be
/// new as to be finished. `peer_released` answers that question.
peer_opened: [2]u64 = .{ 0, 0 },
/// The peer stream numbers of each kind that finished and gave their slot
/// back. See `max_tracked_streams`.
peer_released: [2]ReleasedSet = .{ @splat(0), @splat(0) },
/// The widest receiving buffer in the table.
///
/// `takeMaxData` reads this: connection room below one stream window
/// means a free slot could not fill its own window, which is the
/// property the file comment rests on.
max_stream_window: u64,
/// The per-stream windows the peer announced, for each of the three
/// cases RFC 9000 section 18.2 names.
peer_max_stream_data_bidi_remote: u64,
peer_max_stream_data_bidi_local: u64,
peer_max_stream_data_uni: u64,
/// Where `nextSend` starts looking, so no stream is served first every
/// time.
send_cursor: usize = 0,

/// How many frames from the peer named a stream this table had already
/// finished and released.
///
/// **A recovered fault is counted and never silent.** RFC 9000 section 3
/// lets a peer send on a stream after this side has forgotten it, because
/// a retransmission crosses the acknowledgment that closed it. Such a
/// frame is dropped, and this says how often.
dropped_frames: u64 = 0,

/// A table over `options.slots`.
pub fn init(options: Options) InitError!Streams {
    var window_sum: u64 = 0;
    var widest: u64 = 0;
    for (options.slots) |*slot| {
        std.debug.assert(slot.send.buffer.len > 0);
        std.debug.assert(slot.recv.buffer.len > 0);
        window_sum +|= slot.recv.buffer.len;
        widest = @max(widest, slot.recv.buffer.len);
    }
    // The first comparison the anti-deadlock argument rests on.
    if (options.recv_window < window_sum) return error.ConnectionWindowTooSmall;

    for ([_]u64{
        options.peer_max_streams_bidi,
        options.peer_max_streams_uni,
        options.local_max_streams_bidi,
        options.local_max_streams_uni,
    }) |limit| {
        if (limit > frame.max_stream_count) return error.StreamLimitTooLarge;
    }

    // The released set holds one bit for each number the peer may use, so
    // a limit past the set has nowhere to record a finished stream.
    if (options.local_max_streams_bidi > max_tracked_streams) return error.StreamLimitTooLarge;
    if (options.local_max_streams_uni > max_tracked_streams) return error.StreamLimitTooLarge;

    // **The limits this side advertises must fit the table.** See
    // `InitError.StreamSlotsTooFew`. Peer and local streams share one
    // pool, so the peer's two limits and the caller's own reservation are
    // added together.
    const promised = options.local_max_streams_bidi +|
        options.local_max_streams_uni +|
        options.local_slot_reserve;
    if (promised > options.slots.len) return error.StreamSlotsTooFew;

    const self: Streams = .{
        .max_stream_window = widest,
        .role = options.role,
        .slots = options.slots,
        .send_flow = .init(options.peer_max_data),
        .recv_flow = .init(options.recv_window),
        .recv_window = options.recv_window,
        .peer_stream_limit = .{ options.peer_max_streams_bidi, options.peer_max_streams_uni },
        .local_stream_limit = .{ options.local_max_streams_bidi, options.local_max_streams_uni },
        .sent_stream_limit = .{ options.local_max_streams_bidi, options.local_max_streams_uni },
        .peer_max_stream_data_bidi_remote = options.peer_max_stream_data_bidi_remote,
        .peer_max_stream_data_bidi_local = options.peer_max_stream_data_bidi_local,
        .peer_max_stream_data_uni = options.peer_max_stream_data_uni,
    };
    for (self.slots) |*slot| slot.reset();
    return self;
}

fn kindIndex(kind: stream.Kind) usize {
    return switch (kind) {
        .bidirectional => 0,
        .unidirectional => 1,
    };
}

/// The stream `id` names, or null when this table holds none.
pub fn get(self: *Streams, id: u64) ?*Stream {
    for (self.slots) |*slot| {
        if (slot.in_use and slot.id == id) return slot;
    }
    return null;
}

/// How many slots are busy.
pub fn openCount(self: *const Streams) usize {
    var count: usize = 0;
    for (self.slots) |*slot| {
        if (slot.in_use) count += 1;
    }
    return count;
}

/// Opens the next stream of `kind` that this side may open.
///
/// RFC 9000 section 4.6: the peer's `initial_max_streams` and every
/// `MAX_STREAMS` after it say how many. A caller past that limit gets
/// `error.StreamLimitError` and should send a `STREAMS_BLOCKED` frame,
/// which `takeStreamsBlocked` builds.
pub fn open(self: *Streams, kind: stream.Kind) Error!*Stream {
    const index = kindIndex(kind);
    const number = self.next_number[index];
    if (number >= self.peer_stream_limit[index]) return error.StreamLimitError;
    const id = try stream.makeId(self.role, kind, number);

    const slot = self.freeSlot() orelse return error.NoStreamSlot;
    self.next_number[index] = number + 1;
    self.fill(slot, id);
    return slot;
}

fn freeSlot(self: *Streams) ?*Stream {
    for (self.slots) |*slot| {
        if (!slot.in_use) return slot;
    }
    return null;
}

fn fill(self: *Streams, slot: *Stream, id: u64) void {
    slot.reset();
    slot.in_use = true;
    slot.id = id;
    slot.send_limit = self.initialSendLimit(id);
    slot.recv_limit = slot.recv.buffer.len;
    // A half the protocol gives no direction starts finished, so
    // `isDone` never waits for a half that can never move.
    if (!stream.localCanSend(id, self.role)) slot.send_state = .data_recvd;
    if (!stream.localCanReceive(id, self.role)) slot.recv_state = .data_read;
}

/// The window the peer announced for a stream with this identifier. RFC
/// 9000 section 18.2 gives three numbers and this is where the choice
/// between them lives.
fn initialSendLimit(self: *const Streams, id: u64) u64 {
    return switch (stream.kindOf(id)) {
        .unidirectional => self.peer_max_stream_data_uni,
        .bidirectional => if (stream.isLocal(id, self.role))
            self.peer_max_stream_data_bidi_remote
        else
            self.peer_max_stream_data_bidi_local,
    };
}

/// Whether the peer stream `number` of `index` finished and gave its slot
/// back.
fn isReleased(self: *const Streams, index: usize, number: u64) bool {
    // `init` keeps every peer stream limit at or below the set, and
    // `accept` refuses a number at or above the limit, so this never
    // fires from the wire. It is the bound next to the value it bounds.
    if (number >= max_tracked_streams) return false;
    const word: usize = @intCast(number / 64);
    const bit: u6 = @intCast(number % 64);
    return self.peer_released[index][word] & (@as(u64, 1) << bit) != 0;
}

/// Records that the peer stream `number` of `index` finished.
fn markReleased(self: *Streams, index: usize, number: u64) void {
    if (number >= max_tracked_streams) return;
    const word: usize = @intCast(number / 64);
    const bit: u6 = @intCast(number % 64);
    self.peer_released[index][word] |= @as(u64, 1) << bit;
}

/// Gives a finished slot back to the table.
///
/// Asserts the stream is finished. RFC 9000 section 3 keeps a stream
/// alive until both halves are done, so releasing an open one would drop
/// data the peer is still sending.
///
/// **Two things leave with the slot.** The connection room the receiving
/// half still holds comes back, because room that came back only with the
/// bytes a caller read would never come back for a half with a gap in it.
/// And a peer stream is written into `peer_released`, so a frame that
/// crosses the acknowledgment which closed the stream is told apart from
/// a frame for a number the peer has not opened yet.
pub fn release(self: *Streams, slot: *Stream) void {
    std.debug.assert(slot.isDone());
    if (!slot.in_use) {
        slot.reset();
        return;
    }
    self.releaseRecv(slot);
    if (!stream.isLocal(slot.id, self.role)) {
        self.markReleased(kindIndex(stream.kindOf(slot.id)), stream.numberOf(slot.id));
    }
    slot.reset();
}

/// The stream a frame from the peer names, opening it when the peer just
/// opened it, or null when it is a stream this table has already finished.
///
/// RFC 9000 section 3: a frame may arrive for a stream this side closed
/// and forgot, because a retransmission crosses the acknowledgment that
/// closed it. Such a frame is dropped and counted, not refused.
fn accept(self: *Streams, id: u64) Error!?*Stream {
    if (self.get(id)) |found| return found;

    const kind = stream.kindOf(id);
    const index = kindIndex(kind);
    const number = stream.numberOf(id);

    if (stream.isLocal(id, self.role)) {
        // This side opens its own streams in order, so an identifier at
        // or above the next number is one this side never opened. RFC
        // 9000 section 19.8 makes that a STREAM_STATE_ERROR.
        if (number >= self.next_number[index]) return error.StreamStateError;
        // Below the next number, so it is a stream this side opened and
        // has already released.
        self.dropped_frames += 1;
        return null;
    }

    // RFC 9000 section 4.6: a peer may not open past the limit this side
    // gave it. Opening stream number N opens every number below it too.
    if (number >= self.local_stream_limit[index]) return error.StreamLimitError;

    // **"Opened and released" is a bit, and never a comparison against a
    // high water mark.** A number below the mark is a stream the peer
    // opened implicitly and whose first frame has not arrived yet, quite
    // as often as it is a stream that finished. Reading the mark as
    // "finished" drops a stream for the life of the connection: a server
    // that opens its three HTTP/3 streams in descending order loses the
    // two lower ones, and one frame naming the last number the limit
    // allows would lose every peer stream after it.
    if (self.isReleased(index, number)) {
        self.dropped_frames += 1;
        return null;
    }

    // `init` bounds the peer's two limits by the table, so a peer inside
    // the limits this side gave it always finds a slot here.
    const slot = self.freeSlot() orelse return error.NoStreamSlot;
    self.fill(slot, id);
    if (number >= self.peer_opened[index]) self.peer_opened[index] = number + 1;
    return slot;
}

/// Takes one `STREAM` frame. RFC 9000 section 19.8.
pub fn onStream(self: *Streams, f: frame.Stream) Error!void {
    // A unidirectional stream this side opened carries nothing back, so a
    // `STREAM` frame naming one is the peer writing where it may not.
    if (!stream.localCanReceive(f.stream_id, self.role)) return error.StreamStateError;

    // **The 2^62 bound runs before either flow control check, and before
    // a slot is taken.** RFC 9000 section 4.5 calls an offset past the
    // range a FRAME_ENCODING_ERROR, while the window gives a
    // FLOW_CONTROL_ERROR, so the order of the checks is what decides the
    // code the connection closes with. `endOffset` saturates, so the
    // comparison reads a number above the bound and never a wrapped one.
    const end = f.endOffset();
    if (end > varint.max_value) return error.OffsetTooLarge;

    const slot = try self.accept(f.stream_id) orelse return;
    if (slot.recv_abandoned or !slot.recv_state.readable()) {
        // The half is reset, drained, or given up on. RFC 9000 section
        // 3.2 lets this side drop the data, and the final size rules were
        // already met when the reset arrived.
        self.dropped_frames += 1;
        return;
    }

    const before = slot.recv.highest;

    // **Both levels, and the stream level first.** A frame that passes
    // the stream limit must not spend connection room on its way to
    // being refused. Neither check moves a counter, so a refusal leaves
    // the connection exactly as it was.
    if (end > slot.recv_limit) return error.FlowControlError;
    const wanted = if (end > before) end - before else 0;
    if (self.recv_flow.used +| wanted > self.recv_flow.limit) return error.FlowControlError;

    slot.recv.push(f.offset, f.data, f.fin) catch |err| switch (err) {
        // **One gap too many is not a peer fault.** This side advertised
        // the whole buffer in `MAX_STREAM_DATA`, so RFC 9000 obliges it
        // to take any arrangement of frames inside that window, and
        // seventeen one byte frames at every other offset are such an
        // arrangement. Ordinary reordering on a lossy path reaches it as
        // well. A `STREAM` frame is sent again, so the frame is dropped
        // and counted and the bytes come back when a gap has closed.
        error.TooManyStreamGaps => {
            self.dropped_frames += 1;
            return;
        },
        else => |rest| return rest,
    };
    self.recv_flow.used += slot.recv.highest - before;

    if (f.fin and slot.recv_state == .recv) slot.recv_state = .size_known;
    if (slot.recv.isComplete() and slot.recv_state == .size_known) slot.recv_state = .data_recvd;
    if (slot.recv.isDrained() and slot.recv_state == .data_recvd) slot.recv_state = .data_read;
}

/// Takes one `RESET_STREAM` frame. RFC 9000 section 19.4.
pub fn onResetStream(self: *Streams, f: frame.ResetStream) Error!void {
    if (!stream.localCanReceive(f.stream_id, self.role)) return error.StreamStateError;
    // The same order `onStream` uses, and for the same reason: a final
    // size past the range is a FRAME_ENCODING_ERROR and not a
    // FLOW_CONTROL_ERROR.
    if (f.final_size > varint.max_value) return error.OffsetTooLarge;

    const slot = try self.accept(f.stream_id) orelse return;
    if (slot.recv_state.finished()) {
        // **The final size rules hold whatever the state of the half.**
        // RFC 9000 section 4.5 gives one stream one final size, so a
        // reset naming another one is a FINAL_SIZE_ERROR even when this
        // side has read every byte and has nothing left to drop. Skipping
        // the rule here would take a `final_size` of 2^62 - 1 as a no-op.
        try slot.recv.reset(f.final_size);
        self.dropped_frames += 1;
        return;
    }

    const before = slot.recv.highest;
    if (f.final_size > slot.recv_limit) return error.FlowControlError;
    const wanted = if (f.final_size > before) f.final_size - before else 0;
    if (self.recv_flow.used +| wanted > self.recv_flow.limit) return error.FlowControlError;

    try slot.recv.reset(f.final_size);
    self.recv_flow.used += slot.recv.highest - before;

    slot.peer_reset_code = f.application_error_code;
    slot.recv_state = .reset_read;
    // **The room a reset stream will never deliver comes back at once.**
    // RFC 9000 section 4.5 counts the final size against the connection
    // window whether the bytes arrived or not, so a reset that gave
    // nothing back would shrink the window for the rest of the
    // connection.
    self.releaseRecv(slot);
}

/// Gives back the connection room a stream will never deliver.
///
/// `Stream.recv_released` is what stops a byte being counted twice: the
/// bytes the caller already read were counted in `read`, and this counts
/// only the rest.
fn releaseRecv(self: *Streams, slot: *Stream) void {
    std.debug.assert(slot.recv.highest >= slot.recv_released);
    self.recv_consumed += slot.recv.highest - slot.recv_released;
    slot.recv_released = slot.recv.highest;
}

/// Takes one `STOP_SENDING` frame. RFC 9000 section 19.5.
///
/// The peer is asking this side to stop writing. RFC 9000 section 3.5
/// requires a `RESET_STREAM` in answer, and this queues one with the code
/// the peer named, which is what the RFC recommends.
pub fn onStopSending(self: *Streams, f: frame.StopSending) Error!void {
    if (!stream.localCanSend(f.stream_id, self.role)) return error.StreamStateError;
    const slot = try self.accept(f.stream_id) orelse return;
    slot.peer_stop_code = f.application_error_code;
    if (slot.send_state.finished() or slot.send_state == .reset_sent) return;
    slot.pending_reset = f.application_error_code;
    slot.send_state = .reset_sent;
}

/// Takes one `MAX_DATA` frame. RFC 9000 section 19.9.
pub fn onMaxData(self: *Streams, value: u64) void {
    if (self.send_flow.raise(value)) self.pending_blocked = false;
}

/// Takes one `MAX_STREAM_DATA` frame. RFC 9000 section 19.10.
pub fn onMaxStreamData(self: *Streams, f: frame.MaxStreamData) Error!void {
    // RFC 9000 section 19.10: a receive-only stream has no sending half
    // for this frame to widen.
    if (!stream.localCanSend(f.stream_id, self.role)) return error.StreamStateError;
    const slot = try self.accept(f.stream_id) orelse return;
    if (f.maximum_stream_data > slot.send_limit) {
        slot.send_limit = f.maximum_stream_data;
        slot.pending_blocked = false;
    }
}

/// Takes one `MAX_STREAMS` frame. RFC 9000 section 19.11.
pub fn onMaxStreams(self: *Streams, f: frame.MaxStreams) Error!void {
    // RFC 9000 section 19.11: a count above 2^60 makes the frame itself
    // unreadable, which is a FRAME_ENCODING_ERROR. No limit was passed,
    // so STREAM_LIMIT_ERROR would name the wrong fault.
    if (f.maximum_streams > frame.max_stream_count) return error.StreamCountTooLarge;
    const index = kindIndex(f.kind);
    if (f.maximum_streams > self.peer_stream_limit[index]) {
        self.peer_stream_limit[index] = f.maximum_streams;
    }
}

/// How much room a stream has to send now, in bytes.
///
/// **An even share of the connection window, with one datagram as the
/// floor.** See the file comment: one stream must not take the whole
/// connection window and leave the others nothing. `zurl-http/h2.zig`
/// divides its own connection window the same way.
pub fn sendRoom(self: *Streams, slot: *const Stream) u64 {
    if (!slot.send_state.writable()) return 0;
    const stream_room = if (slot.send_limit > slot.send.sent) slot.send_limit - slot.send.sent else 0;
    if (stream_room == 0) return 0;

    const connection_room = self.send_flow.room();
    if (connection_room == 0) return 0;

    var sharers: u64 = 0;
    for (self.slots) |*other| {
        if (other.in_use and other.send.hasWork()) sharers += 1;
    }
    if (sharers <= 1) return @min(stream_room, connection_room);
    const even = connection_room / sharers;
    return @min(stream_room, @min(connection_room, @max(even, min_send_share)));
}

/// Writes application bytes onto a stream, and returns how many it took.
///
/// The bound is the send buffer, not the window: bytes wait in the buffer
/// until the window lets them out. Asserts the sending half is open.
pub fn write(self: *Streams, slot: *Stream, bytes: []const u8) usize {
    _ = self;
    std.debug.assert(slot.send_state.writable());
    const taken = slot.send.push(bytes);
    if (taken > 0 and slot.send_state == .ready) slot.send_state = .send;
    return taken;
}

/// Closes the sending half, so the next frame carries the `FIN` bit.
pub fn finish(self: *Streams, slot: *Stream) void {
    _ = self;
    if (!slot.send_state.writable()) return;
    slot.send.finish();
    if (slot.send_state == .ready) slot.send_state = .send;
}

/// Takes up to `out.len` readable bytes off a stream and gives the room
/// back at both levels.
pub fn read(self: *Streams, slot: *Stream, out: []u8) usize {
    // An abandoned half gave its room back already, so counting a byte
    // out of it here would give the same room back twice.
    if (slot.recv_abandoned or slot.recv_state.reset()) return 0;
    const moved = slot.recv.take(out);
    self.recv_consumed += moved;
    slot.recv_released += moved;
    if (slot.recv.isDrained() and !slot.recv_state.finished()) slot.recv_state = .data_read;
    return moved;
}

/// The next run of stream bytes to put in a packet, or null when nothing
/// is due.
pub const Outgoing = struct {
    slot: *Stream,
    chunk: SendBuffer.Chunk,
};

/// Picks a stream with work and returns its next chunk, at most `max_len`
/// bytes.
///
/// The search starts one past the stream it served last, so a stream that
/// always has data cannot hold the packet against the others.
pub fn nextSend(self: *Streams, max_len: usize) ?Outgoing {
    if (self.slots.len == 0) return null;
    var tried: usize = 0;
    while (tried < self.slots.len) : (tried += 1) {
        const index = (self.send_cursor + tried) % self.slots.len;
        const slot = &self.slots[index];
        if (!slot.in_use or !slot.send.hasWork()) continue;
        const room = self.sendRoom(slot);
        // A `FIN` with no data behind it needs no window at all. RFC 9000
        // section 4.1 counts bytes, and there are none.
        const allowed_end = slot.send.sent +| room;
        const chunk = slot.send.next(allowed_end, max_len) orelse {
            // The window is spent. RFC 9000 section 4.1 asks a blocked
            // sender to say so, which is how the peer learns its own
            // limit is the reason.
            if (slot.send.pending() > 0) {
                if (slot.send_limit <= slot.send.sent) slot.pending_blocked = true;
                if (self.send_flow.blocked()) self.pending_blocked = true;
            }
            continue;
        };
        self.send_cursor = (index + 1) % self.slots.len;
        return .{ .slot = slot, .chunk = chunk };
    }
    return null;
}

/// Records that a chunk went on the wire, and spends the windows it used.
pub fn onSent(self: *Streams, slot: *Stream, chunk: SendBuffer.Chunk) void {
    const fresh = !chunk.retransmit;
    slot.send.onSent(chunk.offset, chunk.data.len, chunk.fin);
    if (fresh and chunk.data.len > 0) {
        // A retransmission spends nothing: RFC 9000 section 4.1 counts a
        // byte against the connection limit once.
        self.send_flow.used += chunk.data.len;
    }
    if (chunk.fin and slot.send_state == .send) slot.send_state = .data_sent;
}

/// Records that the frames of one lost packet must go out again.
pub fn onLost(self: *Streams, slot: *Stream, offset: u64, len: usize, fin: bool) void {
    _ = self;
    if (slot.send_state == .reset_sent or slot.send_state.finished()) return;
    slot.send.onLost(offset, len, fin);
    if (slot.send_state == .data_sent and slot.send.hasWork()) slot.send_state = .send;
}

/// Records that the peer acknowledged a run of one stream.
pub fn onAcked(self: *Streams, slot: *Stream, offset: u64, len: usize, fin: bool) void {
    _ = self;
    slot.send.onAcked(offset, len, fin);
    if (slot.send.isAcknowledged()) slot.send_state = .data_recvd;
}

/// Records that the peer acknowledged the `RESET_STREAM` this side sent.
pub fn onResetAcked(self: *Streams, slot: *Stream) void {
    _ = self;
    if (slot.send_state == .reset_sent) slot.send_state = .reset_recvd;
}

/// Queues a `RESET_STREAM` for this side's sending half. RFC 9000 section
/// 19.4.
pub fn reset(self: *Streams, slot: *Stream, code: u64) void {
    _ = self;
    if (!slot.send_state.writable()) return;
    slot.pending_reset = code;
    slot.send_state = .reset_sent;
}

/// Queues a `STOP_SENDING` for this side's receiving half, and gives up
/// on that half. RFC 9000 section 19.5.
///
/// **The connection room the half holds comes back now.** The caller has
/// said it wants no more of these octets. RFC 9000 section 3.5 asks the
/// peer for a `RESET_STREAM` in answer, and `onResetStream` is where the
/// room would come back, but a peer that sends none would hold the room
/// for the rest of the connection. Every byte that arrives after this is
/// dropped and counted, so nothing spends the window a second time.
pub fn stopSending(self: *Streams, slot: *Stream, code: u64) void {
    if (slot.recv_abandoned or !slot.recv_state.readable()) return;
    slot.pending_stop = code;
    slot.recv_abandoned = true;
    self.releaseRecv(slot);
}

/// How far past the last `MAX_DATA` the connection window has moved
/// before this side sends another.
///
/// Half the window, which is the same threshold `zurl-http/h2.zig` uses. A
/// smaller number spends frames on updates, and a larger one lets the peer
/// run out of room before the update reaches it.
fn updateThreshold(window: u64) u64 {
    return @max(window / 2, 1);
}

/// The `MAX_DATA` frame this side owes, or null when the peer has room.
/// RFC 9000 section 19.9.
pub fn takeMaxData(self: *Streams) ?u64 {
    const wanted = self.recv_consumed +| self.recv_window;
    if (wanted <= self.recv_flow.limit) return null;
    // **The threshold saves frames, and it must not hold the connection
    // shut.** Half the window is the ordinary trigger. Below one stream
    // window of room the property the file comment rests on is gone: a
    // free slot could not fill its own window, so a peer that opened a
    // stream there would stop with nothing to report. That case sends the
    // frame whatever the delta is.
    if (wanted - self.recv_flow.limit < updateThreshold(self.recv_window) and
        self.recv_flow.room() >= self.max_stream_window) return null;
    self.recv_flow.limit = wanted;
    return wanted;
}

/// The `MAX_STREAM_DATA` frame one stream owes, or null when it has room.
/// RFC 9000 section 19.10.
pub fn takeMaxStreamData(self: *Streams, slot: *Stream) ?frame.MaxStreamData {
    _ = self;
    // A half nobody reads and a half nobody wants both stay where they
    // are. Widening either would ask for octets that go straight in the
    // bin.
    if (slot.recv_abandoned or !slot.recv_state.readable()) return null;
    const window = slot.recv.buffer.len;
    const wanted = slot.recv.limit();
    if (wanted <= slot.recv_limit) return null;
    if (wanted - slot.recv_limit < updateThreshold(window)) return null;
    slot.recv_limit = wanted;
    return .{ .stream_id = slot.id, .maximum_stream_data = wanted };
}

/// The `MAX_STREAMS` frame this side owes for `kind`, or null.
/// RFC 9000 section 19.11.
///
/// This build lets the peer open a fixed number of streams and never
/// raises it, so the frame goes out once at most. A client that opens
/// every request stream itself needs the peer to open only the three
/// HTTP/3 unidirectional streams, and RFC 9114 section 6.2 names them all.
pub fn takeMaxStreams(self: *Streams, kind: stream.Kind) ?frame.MaxStreams {
    const index = kindIndex(kind);
    if (self.local_stream_limit[index] <= self.sent_stream_limit[index]) return null;
    self.sent_stream_limit[index] = self.local_stream_limit[index];
    return .{ .kind = kind, .maximum_streams = self.local_stream_limit[index] };
}

/// The `DATA_BLOCKED` frame this side owes, or null. RFC 9000 section
/// 19.12.
pub fn takeDataBlocked(self: *Streams) ?u64 {
    if (!self.pending_blocked) return null;
    self.pending_blocked = false;
    return self.send_flow.limit;
}

/// The `STREAM_DATA_BLOCKED` frame one stream owes, or null. RFC 9000
/// section 19.13.
pub fn takeStreamDataBlocked(self: *Streams, slot: *Stream) ?frame.StreamDataBlocked {
    _ = self;
    if (!slot.pending_blocked) return null;
    slot.pending_blocked = false;
    return .{ .stream_id = slot.id, .maximum_stream_data = slot.send_limit };
}

/// The `STREAMS_BLOCKED` frame this side owes for `kind`, or null. RFC
/// 9000 section 19.14.
pub fn takeStreamsBlocked(self: *Streams, kind: stream.Kind) ?frame.StreamsBlocked {
    const index = kindIndex(kind);
    if (self.next_number[index] < self.peer_stream_limit[index]) return null;
    return .{ .kind = kind, .maximum_streams = self.peer_stream_limit[index] };
}

/// The `RESET_STREAM` frame one stream owes, or null. RFC 9000 section
/// 19.4.
pub fn takeReset(self: *Streams, slot: *Stream) ?frame.ResetStream {
    _ = self;
    const code = slot.pending_reset orelse return null;
    slot.pending_reset = null;
    return .{
        .stream_id = slot.id,
        .application_error_code = code,
        // RFC 9000 section 4.5: the final size of a reset stream is how
        // much of it really went out.
        .final_size = slot.send.written,
    };
}

/// The `STOP_SENDING` frame one stream owes, or null. RFC 9000 section
/// 19.5.
pub fn takeStopSending(self: *Streams, slot: *Stream) ?frame.StopSending {
    _ = self;
    const code = slot.pending_stop orelse return null;
    slot.pending_stop = null;
    return .{ .stream_id = slot.id, .application_error_code = code };
}

const testing = std.testing;

const Fixture = struct {
    send_storage: [4][256]u8 = undefined,
    recv_storage: [4][256]u8 = undefined,
    slots: [4]Stream = undefined,

    fn table(
        self: *Fixture,
        role: stream.Initiator,
        extra: struct {
            recv_window: u64 = 4 * 256,
            peer_max_data: u64 = 1 << 20,
            peer_stream_data: u64 = 1 << 16,
            peer_streams: u64 = 8,
            // Two of each kind fills the four slots exactly. `init` refuses
            // more, because a peer inside the limit this side gave it must
            // always find a slot.
            local_streams: u64 = 2,
            /// Overrides `local_streams` for one kind, so a test can give the
            /// four slots to one kind alone.
            local_bidi: ?u64 = null,
            local_uni: ?u64 = null,
            local_slot_reserve: u64 = 0,
        },
    ) !Streams {
        for (&self.slots, 0..) |*slot, index| {
            slot.* = .init(&self.send_storage[index], &self.recv_storage[index]);
        }
        return Streams.init(.{
            .role = role,
            .slots = &self.slots,
            .recv_window = extra.recv_window,
            .peer_max_data = extra.peer_max_data,
            .peer_max_stream_data_bidi_remote = extra.peer_stream_data,
            .peer_max_stream_data_bidi_local = extra.peer_stream_data,
            .peer_max_stream_data_uni = extra.peer_stream_data,
            .peer_max_streams_bidi = extra.peer_streams,
            .peer_max_streams_uni = extra.peer_streams,
            .local_max_streams_bidi = extra.local_bidi orelse extra.local_streams,
            .local_max_streams_uni = extra.local_uni orelse extra.local_streams,
            .local_slot_reserve = extra.local_slot_reserve,
        });
    }
};

test "a connection window smaller than the stream windows it holds is refused" {
    // **This is the anti-deadlock check.** Without it, four stalled
    // readers each holding 256 bytes would hold every byte of a 512 byte
    // connection window, and every other stream would stop with no fault
    // to report.
    var fixture: Fixture = .{};
    try testing.expectError(error.ConnectionWindowTooSmall, fixture.table(.client, .{ .recv_window = 512 }));
    // The sum of the four stream windows is exactly enough.
    const ok = try fixture.table(.client, .{ .recv_window = 4 * 256 });
    try testing.expectEqual(@as(u64, 1024), ok.recv_window);
}

test "a stalled reader cannot stop another stream from filling its own window" {
    var fixture: Fixture = .{};
    var table = try fixture.table(.server, .{});

    // The client opens two streams and fills the first one to its window.
    const first = try stream.makeId(.client, .bidirectional, 0);
    const second = try stream.makeId(.client, .bidirectional, 1);
    var filler: [256]u8 = @splat('x');
    try table.onStream(.{ .stream_id = first, .offset = 0, .data = &filler });

    // Nobody read the first stream. The second one still takes its whole
    // window, because the connection window covers both.
    try table.onStream(.{ .stream_id = second, .offset = 0, .data = &filler });
    try testing.expectEqual(@as(u64, 512), table.recv_flow.used);

    // Each stream is at its own limit and refuses one more byte, which is
    // the stream level doing the work rather than the connection level.
    try testing.expectError(error.FlowControlError, table.onStream(.{
        .stream_id = first,
        .offset = 256,
        .data = "y",
    }));
    try testing.expect(table.recv_flow.room() > 0);
}

test "the connection window slides as the caller reads and MAX_DATA says so" {
    var fixture: Fixture = .{};
    var table = try fixture.table(.server, .{});
    const id = try stream.makeId(.client, .bidirectional, 0);

    var filler: [200]u8 = @splat('x');
    try table.onStream(.{ .stream_id = id, .offset = 0, .data = &filler });
    // Nothing was read, so no window moved.
    try testing.expect(table.takeMaxData() == null);

    var out: [200]u8 = undefined;
    const slot = table.get(id).?;
    try testing.expectEqual(@as(usize, 200), table.read(slot, &out));
    try testing.expectEqualSlices(u8, &filler, &out);

    // Half the window is the threshold, and 200 is below half of 1024.
    try testing.expect(table.takeMaxData() == null);

    // The stream window moved too, and the peer needs that frame before
    // it may write past offset 256.
    const widened = table.takeMaxStreamData(slot).?;
    try testing.expectEqual(@as(u64, 456), widened.maximum_stream_data);

    try table.onStream(.{ .stream_id = id, .offset = 200, .data = &filler });
    _ = table.read(slot, &out);
    try testing.expectEqual(@as(u64, 400), table.recv_consumed);
    _ = table.takeMaxStreamData(slot);
    try table.onStream(.{ .stream_id = id, .offset = 400, .data = filler[0..112] });
    _ = table.read(slot, out[0..112]);
    try testing.expectEqual(@as(u64, 512), table.recv_consumed);

    const raised = table.takeMaxData().?;
    try testing.expectEqual(@as(u64, 512 + 1024), raised);
    try testing.expectEqual(raised, table.recv_flow.limit);
    // The frame goes out once for one move.
    try testing.expect(table.takeMaxData() == null);
}

test "a peer that passes the stream limit is refused before it spends connection room" {
    var fixture: Fixture = .{};
    var table = try fixture.table(.server, .{});
    const id = try stream.makeId(.client, .bidirectional, 0);

    var filler: [257]u8 = @splat('x');
    try testing.expectError(error.FlowControlError, table.onStream(.{
        .stream_id = id,
        .offset = 0,
        .data = &filler,
    }));
    try testing.expectEqual(@as(u64, 0), table.recv_flow.used);
    try testing.expectEqual(transport_error.Code.flow_control_error, errorCode(error.FlowControlError));
}

test "an offset near the top of the range is refused and nothing is allocated for it" {
    // **The 2^62 bound is what refuses this, and not the window.** RFC
    // 9000 section 4.5 asks for FRAME_ENCODING_ERROR here, so the order
    // of the two checks is what the test is about: a file that runs the
    // flow control check first reports FLOW_CONTROL_ERROR and passes with
    // no 2^62 check at all.
    var fixture: Fixture = .{};
    var table = try fixture.table(.server, .{});
    const id = try stream.makeId(.client, .bidirectional, 0);

    try testing.expectError(error.OffsetTooLarge, table.onStream(.{
        .stream_id = id,
        .offset = (1 << 62) - 2,
        .data = "xx",
    }));
    try testing.expectEqual(@as(u64, 0), table.recv_flow.used);
    // Nothing was allocated for it, which is what the name says: no slot
    // was taken and no stream was opened.
    try testing.expectEqual(@as(usize, 0), table.openCount());
    try testing.expect(table.get(id) == null);
    try testing.expectEqual(transport_error.Code.frame_encoding_error, errorCode(error.OffsetTooLarge));

    // An offset at the very top of the range saturates the add rather
    // than wrapping it round to a small number.
    try testing.expectError(error.OffsetTooLarge, table.onStream(.{
        .stream_id = id,
        .offset = std.math.maxInt(u64),
        .data = "xx",
    }));
    try testing.expectEqual(@as(usize, 0), table.openCount());

    // A `RESET_STREAM` naming a final size past the range takes the same
    // route to the same code.
    try testing.expectError(error.OffsetTooLarge, table.onResetStream(.{
        .stream_id = id,
        .application_error_code = 1,
        .final_size = (1 << 62),
    }));
    try testing.expectEqual(@as(usize, 0), table.openCount());
}

test "a retransmission spends the window once" {
    var fixture: Fixture = .{};
    var table = try fixture.table(.server, .{});
    const id = try stream.makeId(.client, .bidirectional, 0);

    try table.onStream(.{ .stream_id = id, .offset = 0, .data = "abcdef" });
    try testing.expectEqual(@as(u64, 6), table.recv_flow.used);
    try table.onStream(.{ .stream_id = id, .offset = 0, .data = "abcdef" });
    try testing.expectEqual(@as(u64, 6), table.recv_flow.used);
    try table.onStream(.{ .stream_id = id, .offset = 4, .data = "efgh" });
    try testing.expectEqual(@as(u64, 8), table.recv_flow.used);
}

test "one stream cannot take the whole connection send window" {
    var fixture: Fixture = .{};
    var table = try fixture.table(.client, .{ .peer_max_data = 8000 });

    const one = try table.open(.bidirectional);
    var filler: [256]u8 = @splat('x');
    _ = table.write(one, &filler);

    // One stream with work takes the whole connection window, which is
    // what a single request always saw.
    try testing.expectEqual(@as(u64, 8000), table.sendRoom(one));

    // A second stream with work halves it, so neither can starve the
    // other.
    const two = try table.open(.bidirectional);
    _ = table.write(two, &filler);
    try testing.expectEqual(@as(u64, 4000), table.sendRoom(one));
    try testing.expectEqual(@as(u64, 4000), table.sendRoom(two));

    // With a small window the floor is what each one gets, so neither is
    // stopped by an even share that rounds to nothing.
    table.send_flow = .init(100);
    try testing.expectEqual(@as(u64, 100), table.sendRoom(one));
    try testing.expectEqual(@as(u64, 100), table.sendRoom(two));
}

test "a stream sends inside both windows and the smaller one wins" {
    var fixture: Fixture = .{};
    var table = try fixture.table(.client, .{ .peer_max_data = 10, .peer_stream_data = 4 });

    const slot = try table.open(.bidirectional);
    _ = table.write(slot, "abcdefghij");
    const first = table.nextSend(100).?;
    try testing.expectEqualStrings("abcd", first.chunk.data);
    table.onSent(first.slot, first.chunk);
    // The stream window is spent, so nothing more goes out and the peer
    // is told which limit is in the way.
    try testing.expect(table.nextSend(100) == null);
    const blocked = table.takeStreamDataBlocked(slot).?;
    try testing.expectEqual(@as(u64, 4), blocked.maximum_stream_data);

    try table.onMaxStreamData(.{ .stream_id = slot.id, .maximum_stream_data = 100 });
    const second = table.nextSend(100).?;
    // The connection window allows six more.
    try testing.expectEqualStrings("efghij", second.chunk.data);
    table.onSent(second.slot, second.chunk);
    try testing.expectEqual(@as(u64, 10), table.send_flow.used);
}

test "a MAX_DATA that names a smaller number is ignored" {
    var fixture: Fixture = .{};
    var table = try fixture.table(.client, .{ .peer_max_data = 100 });
    table.onMaxData(500);
    try testing.expectEqual(@as(u64, 500), table.send_flow.limit);
    table.onMaxData(200);
    try testing.expectEqual(@as(u64, 500), table.send_flow.limit);
}

test "a peer that opens past the limit this side gave is refused" {
    var fixture: Fixture = .{};
    var table = try fixture.table(.server, .{ .local_streams = 2 });

    try table.onStream(.{ .stream_id = try stream.makeId(.client, .bidirectional, 0), .data = "a" });
    try table.onStream(.{ .stream_id = try stream.makeId(.client, .bidirectional, 1), .data = "b" });
    try testing.expectError(error.StreamLimitError, table.onStream(.{
        .stream_id = try stream.makeId(.client, .bidirectional, 2),
        .data = "c",
    }));
    try testing.expectEqual(transport_error.Code.stream_limit_error, errorCode(error.StreamLimitError));
}

test "this side refuses to open past the limit the peer gave" {
    var fixture: Fixture = .{};
    var table = try fixture.table(.client, .{ .peer_streams = 2 });
    _ = try table.open(.unidirectional);
    _ = try table.open(.unidirectional);
    try testing.expectError(error.StreamLimitError, table.open(.unidirectional));
    // The peer is told, which is what RFC 9000 section 19.14 is for.
    const blocked = table.takeStreamsBlocked(.unidirectional).?;
    try testing.expectEqual(@as(u64, 2), blocked.maximum_streams);

    try table.onMaxStreams(.{ .kind = .unidirectional, .maximum_streams = 3 });
    _ = try table.open(.unidirectional);
}

test "a peer that writes on a unidirectional stream it does not own is refused" {
    var fixture: Fixture = .{};
    var table = try fixture.table(.client, .{});
    // A client-initiated unidirectional stream carries data away from the
    // client, so a server that writes on one is writing where it may not.
    const id = try stream.makeId(.client, .unidirectional, 0);
    try testing.expectError(error.StreamStateError, table.onStream(.{ .stream_id = id, .data = "x" }));
    try testing.expectEqual(transport_error.Code.stream_state_error, errorCode(error.StreamStateError));
}

test "a frame for a stream this side never opened is refused" {
    var fixture: Fixture = .{};
    var table = try fixture.table(.client, .{});
    const id = try stream.makeId(.client, .bidirectional, 7);
    try testing.expectError(error.StreamStateError, table.onStream(.{ .stream_id = id, .data = "x" }));
}

test "a frame for a stream this side already released is dropped and counted" {
    var fixture: Fixture = .{};
    var table = try fixture.table(.client, .{});
    const slot = try table.open(.bidirectional);
    const id = slot.id;
    _ = table.write(slot, "hi");
    table.finish(slot);
    const chunk = table.nextSend(100).?;
    table.onSent(chunk.slot, chunk.chunk);
    table.onAcked(slot, 0, 2, true);
    try table.onStream(.{ .stream_id = id, .offset = 0, .data = "ok", .fin = true });
    _ = table.read(slot, &.{});
    var out: [4]u8 = undefined;
    _ = table.read(slot, &out);
    try testing.expect(slot.isDone());
    table.release(slot);

    // A retransmission that crossed the acknowledgment.
    try testing.expectEqual(@as(u64, 0), table.dropped_frames);
    try table.onStream(.{ .stream_id = id, .offset = 0, .data = "ok" });
    try testing.expectEqual(@as(u64, 1), table.dropped_frames);
}

test "a reset gives back the connection room its stream will never deliver" {
    var fixture: Fixture = .{};
    var table = try fixture.table(.server, .{});
    const id = try stream.makeId(.client, .bidirectional, 0);

    try table.onStream(.{ .stream_id = id, .offset = 0, .data = "abcd" });
    try testing.expectEqual(@as(u64, 4), table.recv_flow.used);
    try testing.expectEqual(@as(u64, 0), table.recv_consumed);

    try table.onResetStream(.{ .stream_id = id, .application_error_code = 7, .final_size = 20 });
    const slot = table.get(id).?;
    try testing.expectEqual(@as(?u64, 7), slot.peer_reset_code);
    try testing.expect(slot.recv_state.reset());
    // Without this the window would be twenty bytes narrower for the rest
    // of the connection.
    try testing.expectEqual(@as(u64, 20), table.recv_consumed);
    try testing.expectEqual(@as(u64, 20), table.recv_flow.used);
    // Nothing reads out of a reset stream.
    var out: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), table.read(slot, &out));
}

test "a reset naming a final size below what already arrived is refused" {
    var fixture: Fixture = .{};
    var table = try fixture.table(.server, .{});
    const id = try stream.makeId(.client, .bidirectional, 0);
    try table.onStream(.{ .stream_id = id, .offset = 0, .data = "abcd" });
    try testing.expectError(error.FinalSizeError, table.onResetStream(.{
        .stream_id = id,
        .application_error_code = 1,
        .final_size = 2,
    }));
    try testing.expectEqual(transport_error.Code.final_size_error, errorCode(error.FinalSizeError));
}

test "STOP_SENDING makes this side reset the stream with the code the peer named" {
    var fixture: Fixture = .{};
    var table = try fixture.table(.client, .{});
    const slot = try table.open(.bidirectional);
    _ = table.write(slot, "abcdef");

    try table.onStopSending(.{ .stream_id = slot.id, .application_error_code = 0x10c });
    try testing.expectEqual(stream.SendState.reset_sent, slot.send_state);
    const reset_frame = table.takeReset(slot).?;
    try testing.expectEqual(@as(u64, 0x10c), reset_frame.application_error_code);
    try testing.expectEqual(@as(u64, 6), reset_frame.final_size);
    // The frame goes out once.
    try testing.expect(table.takeReset(slot) == null);
    // Nothing more is written on a reset stream.
    try testing.expect(table.nextSend(100) == null);
}

test "a slot is reused once both halves are finished" {
    var fixture: Fixture = .{};
    var table = try fixture.table(.client, .{});
    try testing.expectEqual(@as(usize, 0), table.openCount());

    var index: usize = 0;
    while (index < fixture.slots.len) : (index += 1) _ = try table.open(.unidirectional);
    try testing.expectEqual(@as(usize, 4), table.openCount());
    try testing.expectError(error.NoStreamSlot, table.open(.unidirectional));

    const first = &fixture.slots[0];
    table.finish(first);
    const chunk = table.nextSend(100).?;
    table.onSent(chunk.slot, chunk.chunk);
    table.onAcked(first, 0, 0, true);
    try testing.expect(first.isDone());
    table.release(first);
    try testing.expectEqual(@as(usize, 3), table.openCount());
    _ = try table.open(.unidirectional);
}

test "lost stream bytes go out again and are not counted twice" {
    var fixture: Fixture = .{};
    var table = try fixture.table(.client, .{});
    const slot = try table.open(.bidirectional);
    _ = table.write(slot, "abcdefgh");

    const first = table.nextSend(4).?;
    table.onSent(first.slot, first.chunk);
    const second = table.nextSend(4).?;
    table.onSent(second.slot, second.chunk);
    try testing.expectEqual(@as(u64, 8), table.send_flow.used);

    table.onLost(slot, 0, 4, false);
    const again = table.nextSend(100).?;
    try testing.expect(again.chunk.retransmit);
    try testing.expectEqualStrings("abcd", again.chunk.data);
    table.onSent(again.slot, again.chunk);
    // A retransmission spends no connection window.
    try testing.expectEqual(@as(u64, 8), table.send_flow.used);
}

test "the send cursor moves, so no stream is served first every time" {
    var fixture: Fixture = .{};
    var table = try fixture.table(.client, .{});
    const one = try table.open(.unidirectional);
    const two = try table.open(.unidirectional);
    _ = table.write(one, "1111");
    _ = table.write(two, "2222");

    const first = table.nextSend(2).?;
    try testing.expectEqual(one.id, first.slot.id);
    table.onSent(first.slot, first.chunk);
    const second = table.nextSend(2).?;
    try testing.expectEqual(two.id, second.slot.id);
    table.onSent(second.slot, second.chunk);
    const third = table.nextSend(2).?;
    try testing.expectEqual(one.id, third.slot.id);
}

test "a peer that opens its streams in descending order keeps every one of them" {
    // **RFC 9000 section 3.2 opens every lower stream number with the one
    // the peer names**, and QUIC delivers streams in whatever order the
    // packets arrive. An HTTP/3 server opens unidirectional ids 11, 7 and
    // 3, which are numbers 2, 1 and 0, and a server may open them in that
    // order. A table that reads "below the high water mark" as "finished
    // and released" drops ids 3 and 7 for the life of the connection: the
    // client waits for a SETTINGS frame that never arrives.
    var fixture: Fixture = .{};
    var table = try fixture.table(.client, .{ .local_bidi = 0, .local_uni = 4 });

    const third = try stream.makeId(.server, .unidirectional, 2);
    const second = try stream.makeId(.server, .unidirectional, 1);
    const first = try stream.makeId(.server, .unidirectional, 0);
    try testing.expectEqual(@as(u64, 11), third);
    try testing.expectEqual(@as(u64, 7), second);
    try testing.expectEqual(@as(u64, 3), first);

    try table.onStream(.{ .stream_id = third, .offset = 0, .data = "c" });
    try table.onStream(.{ .stream_id = second, .offset = 0, .data = "b" });
    try table.onStream(.{ .stream_id = first, .offset = 0, .data = "a" });

    try testing.expectEqual(@as(usize, 3), table.openCount());
    try testing.expectEqual(@as(u64, 0), table.dropped_frames);
    try testing.expectEqual(@as(u64, 3), table.recv_flow.used);

    var out: [1]u8 = undefined;
    const ids = [_]u64{ first, second, third };
    const wanted = [_]u8{ 'a', 'b', 'c' };
    for (ids, wanted) |id, want| {
        const slot = table.get(id) orelse return error.StreamWasBlackholed;
        try testing.expectEqual(@as(usize, 1), table.read(slot, &out));
        try testing.expectEqual(want, out[0]);
    }

    // **The amplified form.** One frame naming the last number the limit
    // allows must not blackhole every number below it.
    var second_fixture: Fixture = .{};
    var wide = try second_fixture.table(.client, .{ .local_bidi = 0, .local_uni = 4 });
    const last = try stream.makeId(.server, .unidirectional, 3);
    try wide.onStream(.{ .stream_id = last, .offset = 0, .data = "z" });
    try wide.onStream(.{ .stream_id = first, .offset = 0, .data = "a" });
    try testing.expect(wide.get(first) != null);
    try testing.expectEqual(@as(u64, 0), wide.dropped_frames);
}

test "a peer stream that finished is told apart from one that never opened" {
    // The other half of the same rule. A frame that crosses the
    // acknowledgment which closed a stream is still dropped, and the bit
    // `release` set is what says so.
    var fixture: Fixture = .{};
    var table = try fixture.table(.client, .{ .local_bidi = 0, .local_uni = 4 });
    const id = try stream.makeId(.server, .unidirectional, 1);

    try table.onStream(.{ .stream_id = id, .offset = 0, .data = "hi", .fin = true });
    const slot = table.get(id).?;
    var out: [4]u8 = undefined;
    try testing.expectEqual(@as(usize, 2), table.read(slot, &out));
    try testing.expect(slot.isDone());
    table.release(slot);
    try testing.expectEqual(@as(usize, 0), table.openCount());

    // A retransmission of the same stream takes no slot.
    try table.onStream(.{ .stream_id = id, .offset = 0, .data = "hi" });
    try testing.expectEqual(@as(u64, 1), table.dropped_frames);
    try testing.expectEqual(@as(usize, 0), table.openCount());

    // The number below it was never opened, so it still gets a slot.
    const lower = try stream.makeId(.server, .unidirectional, 0);
    try table.onStream(.{ .stream_id = lower, .offset = 0, .data = "a" });
    try testing.expectEqual(@as(usize, 1), table.openCount());
    try testing.expectEqual(@as(u64, 1), table.dropped_frames);

    // And a `RESET_STREAM` for the released stream is dropped rather than
    // taking a slot of its own.
    try table.onResetStream(.{ .stream_id = id, .application_error_code = 1, .final_size = 2 });
    try testing.expectEqual(@as(usize, 1), table.openCount());
    try testing.expectEqual(@as(u64, 2), table.dropped_frames);
}

test "connection room comes back when a slot ends and not when its bytes are read" {
    // **Connection room is spent on the highest offset a stream
    // reached**, which RFC 9000 section 4 asks for so a retransmission
    // cannot spend the window twice. A peer that sends one byte at the
    // top of a stream window and never fills the gap in front of it holds
    // that whole window, and no caller can read the stream. Three of them
    // hold 768 of a 1024 byte connection window. Every frame below is
    // legal QUIC.
    var fixture: Fixture = .{};
    var table = try fixture.table(.server, .{ .local_bidi = 4, .local_uni = 0 });

    var index: u64 = 0;
    while (index < 3) : (index += 1) {
        const stalled = try stream.makeId(.client, .bidirectional, index);
        try table.onStream(.{ .stream_id = stalled, .offset = 255, .data = "x", .fin = true });
    }
    try testing.expectEqual(@as(u64, 768), table.recv_flow.used);
    try testing.expectEqual(@as(u64, 0), table.recv_consumed);
    try testing.expectEqual(@as(u64, 256), table.recv_flow.room());

    // The fourth stream fills its own window, which is exactly the
    // property the file comment promises, and the caller reads all of it.
    const id = try stream.makeId(.client, .bidirectional, 3);
    var filler: [256]u8 = @splat('y');
    try table.onStream(.{ .stream_id = id, .offset = 0, .data = &filler });
    const slot = table.get(id).?;
    var out: [256]u8 = undefined;
    try testing.expectEqual(@as(usize, 256), table.read(slot, &out));
    try testing.expectEqual(@as(u64, 1024), table.recv_flow.used);
    try testing.expectEqual(@as(u64, 256), table.recv_consumed);
    try testing.expectEqual(@as(u64, 0), table.recv_flow.room());

    // The stream window moved, so the peer may write to offset 512.
    const widened = table.takeMaxStreamData(slot).?;
    try testing.expectEqual(@as(u64, 512), widened.maximum_stream_data);

    // **The frame a threshold on its own never sends.** A delta of 256 is
    // below half of 1024, so an implementation that only counts the delta
    // says nothing here and the connection can never receive another
    // byte. Room has fallen below one stream window, so the frame goes
    // out whatever the delta.
    const raised = table.takeMaxData() orelse return error.ConnectionStopped;
    try testing.expectEqual(@as(u64, 256 + 1024), raised);
    try testing.expectEqual(@as(u64, 256), table.recv_flow.room());

    // And the peer really can send those octets.
    try table.onStream(.{ .stream_id = id, .offset = 256, .data = &filler });
    try testing.expectEqual(@as(u64, 1280), table.recv_flow.used);
}

test "giving up on a receiving half gives its connection room back" {
    var fixture: Fixture = .{};
    var table = try fixture.table(.server, .{});
    const id = try stream.makeId(.client, .bidirectional, 0);
    var filler: [200]u8 = @splat('x');
    try table.onStream(.{ .stream_id = id, .offset = 0, .data = &filler });
    try testing.expectEqual(@as(u64, 200), table.recv_flow.used);
    try testing.expectEqual(@as(u64, 0), table.recv_consumed);

    const slot = table.get(id).?;
    table.stopSending(slot, 0x10c);
    // RFC 9000 section 3.5 asks the peer for a `RESET_STREAM`, and
    // `onResetStream` is where the room would come back. A peer that
    // sends none must not hold the room for the rest of the connection.
    try testing.expectEqual(@as(u64, 200), table.recv_consumed);
    const asked = table.takeStopSending(slot).?;
    try testing.expectEqual(@as(u64, 0x10c), asked.application_error_code);

    // Octets that arrive after it are dropped and spend nothing, so the
    // room that was given back is not spent a second time.
    try table.onStream(.{ .stream_id = id, .offset = 200, .data = &filler });
    try testing.expectEqual(@as(u64, 200), table.recv_flow.used);
    try testing.expectEqual(@as(u64, 1), table.dropped_frames);

    // Nothing reads out of it and no window is widened for it.
    var out: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), table.read(slot, &out));
    try testing.expect(table.takeMaxStreamData(slot) == null);
    try testing.expectEqual(@as(u64, 200), table.recv_consumed);
}

test "a frame that opens one gap too many is dropped and not a connection error" {
    // This side advertised the whole 256 byte window in
    // `MAX_STREAM_DATA`, so RFC 9000 obliges it to take any arrangement
    // of frames inside that window. Seventeen one byte frames at offsets
    // 0, 2, 4 and so on are such an arrangement, and ordinary reordering
    // on a lossy path reaches it too. Closing the connection for 17 bytes
    // of payload is not an answer.
    var fixture: Fixture = .{};
    var table = try fixture.table(.server, .{});
    const id = try stream.makeId(.client, .bidirectional, 0);

    var index: usize = 0;
    while (index <= Reassembly.max_ranges) : (index += 1) {
        try table.onStream(.{ .stream_id = id, .offset = @as(u64, index) * 2, .data = "x" });
    }
    const slot = table.get(id).?;
    try testing.expectEqual(Reassembly.max_ranges, slot.recv.range_count);
    try testing.expectEqual(@as(u64, 1), table.dropped_frames);
    // The dropped frame spent no room and left no byte behind.
    const held: u64 = (Reassembly.max_ranges - 1) * 2 + 1;
    try testing.expectEqual(held, table.recv_flow.used);
    try testing.expectEqual(held, slot.recv.highest);

    // A `STREAM` frame is sent again, and once a gap has closed it lands.
    try table.onStream(.{ .stream_id = id, .offset = 1, .data = "y" });
    try testing.expectEqual(Reassembly.max_ranges - 1, slot.recv.range_count);
    try table.onStream(.{ .stream_id = id, .offset = Reassembly.max_ranges * 2, .data = "x" });
    try testing.expectEqual(@as(u64, Reassembly.max_ranges * 2 + 1), table.recv_flow.used);
    try testing.expectEqual(@as(u64, 1), table.dropped_frames);
}

test "a stream limit larger than the table it works out of is refused" {
    // **RFC 9000 section 4.6 makes a stream limit a promise.** A peer
    // inside the limit may open that many streams at once and each one
    // needs a slot, so a table of four slots that advertises eight of
    // each kind runs dry on a peer that did nothing wrong. `NoStreamSlot`
    // would close the connection with INTERNAL_ERROR for this side's own
    // arithmetic.
    var fixture: Fixture = .{};
    try testing.expectError(error.StreamSlotsTooFew, fixture.table(.client, .{ .local_streams = 8 }));
    try testing.expectError(error.StreamSlotsTooFew, fixture.table(.client, .{ .local_bidi = 3, .local_uni = 2 }));
    // The reservation counts as well: a caller that needs a slot for a
    // request of its own has to say so, because peer streams and local
    // streams share one pool.
    try testing.expectError(error.StreamSlotsTooFew, fixture.table(.client, .{
        .local_bidi = 0,
        .local_uni = 4,
        .local_slot_reserve = 1,
    }));

    // Exactly the table is allowed, and the peer filling its whole share
    // still leaves the slot this side kept.
    var table = try fixture.table(.client, .{
        .local_bidi = 0,
        .local_uni = 3,
        .local_slot_reserve = 1,
    });
    var index: u64 = 0;
    while (index < 3) : (index += 1) {
        const id = try stream.makeId(.server, .unidirectional, index);
        // A `MAX_STREAM_DATA` or a `STOP_SENDING` opens a stream too, so
        // a peer can fill its share with frames that carry no data.
        try table.onStream(.{ .stream_id = id, .data = "x" });
    }
    try testing.expectEqual(@as(usize, 3), table.openCount());
    _ = try table.open(.bidirectional);
    try testing.expectEqual(@as(usize, 4), table.openCount());

    // One more of the peer's own kind is past the limit it was given, and
    // that is a protocol error and not a table fault.
    const past = try stream.makeId(.server, .unidirectional, 3);
    try testing.expectError(error.StreamLimitError, table.onStream(.{ .stream_id = past, .data = "x" }));

    // **A frame that carries no stream data opens a stream too.**
    // `MAX_STREAM_DATA` and `STOP_SENDING` both go through `accept`, and
    // such a stream never finishes on its own, so a peer could fill the
    // table with them. The same bound holds them inside its share.
    var quiet_fixture: Fixture = .{};
    var quiet = try quiet_fixture.table(.client, .{
        .local_bidi = 3,
        .local_uni = 0,
        .local_slot_reserve = 1,
    });
    var number: u64 = 0;
    while (number < 3) : (number += 1) {
        const id = try stream.makeId(.server, .bidirectional, number);
        try quiet.onStopSending(.{ .stream_id = id, .application_error_code = 1 });
        try quiet.onMaxStreamData(.{ .stream_id = id, .maximum_stream_data = 10 });
    }
    try testing.expectEqual(@as(usize, 3), quiet.openCount());
    const fourth = try stream.makeId(.server, .bidirectional, 3);
    try testing.expectError(error.StreamLimitError, quiet.onStopSending(.{
        .stream_id = fourth,
        .application_error_code = 1,
    }));
    // The slot this side kept is still there.
    _ = try quiet.open(.unidirectional);
    try testing.expectEqual(@as(usize, 4), quiet.openCount());
}

test "a RESET_STREAM for a finished stream still meets the final size rule" {
    var fixture: Fixture = .{};
    var table = try fixture.table(.server, .{});
    const id = try stream.makeId(.client, .bidirectional, 0);
    try table.onStream(.{ .stream_id = id, .offset = 0, .data = "abcd", .fin = true });
    const slot = table.get(id).?;
    var out: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 4), table.read(slot, &out));
    try testing.expect(slot.recv_state.finished());

    // The same size again is a retransmission that crossed the
    // acknowledgment, and it is dropped.
    try table.onResetStream(.{ .stream_id = id, .application_error_code = 1, .final_size = 4 });
    try testing.expectEqual(@as(u64, 1), table.dropped_frames);

    // **Another size is a FINAL_SIZE_ERROR whatever the state of the
    // half.** RFC 9000 section 4.5 gives one stream one final size.
    // Skipping the rule here would take 2^62 - 1 as a no-op.
    try testing.expectError(error.FinalSizeError, table.onResetStream(.{
        .stream_id = id,
        .application_error_code = 1,
        .final_size = 5,
    }));
    try testing.expectError(error.FinalSizeError, table.onResetStream(.{
        .stream_id = id,
        .application_error_code = 1,
        .final_size = (1 << 62) - 1,
    }));
    try testing.expectError(error.OffsetTooLarge, table.onResetStream(.{
        .stream_id = id,
        .application_error_code = 1,
        .final_size = 1 << 62,
    }));
}

test "a MAX_STREAMS naming more streams than the space holds is a frame encoding error" {
    var fixture: Fixture = .{};
    var table = try fixture.table(.client, .{});
    try testing.expectError(error.StreamCountTooLarge, table.onMaxStreams(.{
        .kind = .bidirectional,
        .maximum_streams = frame.max_stream_count + 1,
    }));
    // RFC 9000 section 19.11 names FRAME_ENCODING_ERROR here. No limit
    // was passed, so STREAM_LIMIT_ERROR would name the wrong fault.
    try testing.expectEqual(
        transport_error.Code.frame_encoding_error,
        errorCode(error.StreamCountTooLarge),
    );
    // The bound itself is legal.
    try table.onMaxStreams(.{ .kind = .bidirectional, .maximum_streams = frame.max_stream_count });
    try testing.expectEqual(frame.max_stream_count, table.peer_stream_limit[0]);
}

test "MAX_STREAM_DATA goes out when a reader has taken half a window" {
    var fixture: Fixture = .{};
    var table = try fixture.table(.server, .{});
    const id = try stream.makeId(.client, .bidirectional, 0);
    var filler: [200]u8 = @splat('x');
    try table.onStream(.{ .stream_id = id, .offset = 0, .data = &filler });
    const slot = table.get(id).?;
    try testing.expect(table.takeMaxStreamData(slot) == null);

    var out: [200]u8 = undefined;
    _ = table.read(slot, &out);
    const raised = table.takeMaxStreamData(slot).?;
    try testing.expectEqual(id, raised.stream_id);
    try testing.expectEqual(@as(u64, 200 + 256), raised.maximum_stream_data);
    try testing.expect(table.takeMaxStreamData(slot) == null);
}
