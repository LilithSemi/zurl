//! QUIC streams: the identifier, the two state machines, and the flow
//! control counter. RFC 9000 sections 2, 3, and 4.
//!
//! **This file holds no buffer and no table.** It holds the rules that a
//! stream identifier carries in its low two bits, the states of RFC 9000
//! figures 2 and 3, and the one counter that both levels of flow control
//! are made of. `Reassembly.zig` puts received bytes back in order,
//! `SendBuffer.zig` holds the bytes that are not acknowledged yet, and
//! `Streams.zig` joins all four into the table a connection keeps.
//!
//! Nothing here allocates. Every value is a number.

const std = @import("std");
const varint = @import("varint.zig");
const frame = @import("frame.zig");

/// Which endpoint opened a stream. RFC 9000 section 2.1, bit 0x1 of the
/// identifier.
pub const Initiator = enum(u1) {
    client = 0,
    server = 1,

    /// The other endpoint.
    pub fn peer(self: Initiator) Initiator {
        return switch (self) {
            .client => .server,
            .server => .client,
        };
    }
};

/// Whether a stream carries data in one direction or in both. RFC 9000
/// section 2.1, bit 0x2 of the identifier.
///
/// This is `frame.StreamKind`, and it is the same type rather than a
/// second one, because `MAX_STREAMS` and `STREAMS_BLOCKED` name the same
/// two halves of the stream space that an identifier does.
pub const Kind = frame.StreamKind;

/// The largest stream identifier a varint can name. RFC 9000 section 2.1.
pub const max_id: u64 = varint.max_value;

/// The largest stream number, which is the identifier without its two low
/// bits. RFC 9000 section 2.1: a stream number above this names an
/// identifier past `max_id`, which has no encoding.
///
/// **This number is itself legal.** `max_number << 2` is `max_id - 3`, so
/// all four identifiers it names fit in a varint. A bound that refused it
/// would lose the last stream of every space.
pub const max_number: u64 = max_id >> 2;

/// Every fault a stream identifier can carry.
pub const IdError = error{
    /// The stream number is above `max_number`, so the identifier it
    /// names cannot be written as a varint. RFC 9000 section 4.6 makes
    /// this a connection error of type STREAM_LIMIT_ERROR.
    StreamNumberTooLarge,
};

/// The identifier of the `number`th stream of `kind` that `initiator`
/// opened. RFC 9000 section 2.1.
///
/// The number counts from zero inside each of the four spaces, so the
/// first bidirectional stream a client opens is 0 and the first
/// unidirectional stream a client opens is 2.
pub fn makeId(initiator: Initiator, kind: Kind, number: u64) IdError!u64 {
    if (number > max_number) return error.StreamNumberTooLarge;
    const low: u64 = @as(u64, @intFromEnum(initiator)) | switch (kind) {
        .bidirectional => @as(u64, 0),
        .unidirectional => @as(u64, 2),
    };
    return (number << 2) | low;
}

/// Which endpoint opened the stream `id` names.
pub fn initiatorOf(id: u64) Initiator {
    return if (id & 0x1 == 0) .client else .server;
}

/// Whether the stream `id` names carries data in one direction or in both.
pub fn kindOf(id: u64) Kind {
    return if (id & 0x2 == 0) .bidirectional else .unidirectional;
}

/// The stream number inside its own space, which is `id` without its two
/// low bits.
pub fn numberOf(id: u64) u64 {
    return id >> 2;
}

/// Whether an endpoint in the role `role` opened the stream `id` names.
pub fn isLocal(id: u64, role: Initiator) bool {
    return initiatorOf(id) == role;
}

/// Whether an endpoint in the role `role` may send on the stream `id`
/// names. RFC 9000 section 2.1.
///
/// A bidirectional stream carries data both ways whoever opened it. A
/// unidirectional stream carries data only from the endpoint that opened
/// it, so the other endpoint that writes on one has broken the protocol.
pub fn localCanSend(id: u64, role: Initiator) bool {
    return switch (kindOf(id)) {
        .bidirectional => true,
        .unidirectional => isLocal(id, role),
    };
}

/// Whether an endpoint in the role `role` may receive on the stream `id`
/// names. The mirror of `localCanSend`.
pub fn localCanReceive(id: u64, role: Initiator) bool {
    return switch (kindOf(id)) {
        .bidirectional => true,
        .unidirectional => !isLocal(id, role),
    };
}

/// The states of the sending half of a stream. RFC 9000 section 3.1.
///
/// `ready` is a stream that exists and has sent nothing. `data_recvd` and
/// `reset_recvd` are terminal: the peer acknowledged every byte, or it
/// acknowledged the reset.
pub const SendState = enum {
    ready,
    send,
    data_sent,
    data_recvd,
    reset_sent,
    reset_recvd,

    /// Whether more application data may go out in this state.
    ///
    /// RFC 9000 section 3.1: once the `FIN` bit has gone out the stream is
    /// closed for sending, and a reset ends it whatever was outstanding.
    pub fn writable(self: SendState) bool {
        return switch (self) {
            .ready, .send => true,
            .data_sent, .data_recvd, .reset_sent, .reset_recvd => false,
        };
    }

    /// Whether this half has nothing left to do.
    pub fn finished(self: SendState) bool {
        return switch (self) {
            .data_recvd, .reset_recvd => true,
            .ready, .send, .data_sent, .reset_sent => false,
        };
    }
};

/// The states of the receiving half of a stream. RFC 9000 section 3.2.
///
/// `size_known` is a stream whose `FIN` arrived with a gap still open
/// behind it. `data_read` and `reset_read` are terminal.
pub const RecvState = enum {
    recv,
    size_known,
    data_recvd,
    data_read,
    reset_recvd,
    reset_read,

    /// Whether more application data may arrive in this state.
    ///
    /// RFC 9000 section 3.2: a `STREAM` frame that arrives after the final
    /// size is known may repeat bytes already received and may not add
    /// any, which `Reassembly` enforces on the offsets. A frame after a
    /// reset is dropped.
    pub fn readable(self: RecvState) bool {
        return switch (self) {
            .recv, .size_known, .data_recvd => true,
            .data_read, .reset_recvd, .reset_read => false,
        };
    }

    /// Whether the peer reset this half.
    pub fn reset(self: RecvState) bool {
        return switch (self) {
            .reset_recvd, .reset_read => true,
            .recv, .size_known, .data_recvd, .data_read => false,
        };
    }

    /// Whether this half has nothing left to do.
    pub fn finished(self: RecvState) bool {
        return switch (self) {
            .data_read, .reset_read => true,
            .recv, .size_known, .data_recvd, .reset_recvd => false,
        };
    }
};

/// Every fault a flow control counter can report.
pub const FlowError = error{
    /// The peer sent more data than the limit this side gave it. RFC 9000
    /// section 4.1 makes this a connection error of type
    /// FLOW_CONTROL_ERROR.
    FlowControlError,
};

/// One direction of one level of flow control: how many bytes have been
/// counted, and how many are allowed. RFC 9000 section 4.
///
/// **One type serves all four counters**: what this side may send on a
/// stream, what this side may send on the connection, what the peer may
/// send on a stream, and what the peer may send on the connection. The
/// arithmetic is the same in every one, and a second copy of it is a
/// second place for an overflow to hide.
///
/// A limit only ever goes up. RFC 9000 section 4.1 says a `MAX_DATA` or a
/// `MAX_STREAM_DATA` that names a smaller number than one already received
/// must be ignored, so `raise` ignores it and reports that it did.
pub const Flow = struct {
    /// The largest offset this counter allows, counted from zero.
    limit: u64,
    /// How much of the limit is spent.
    used: u64 = 0,

    /// A counter with `limit` and nothing spent.
    pub fn init(limit: u64) Flow {
        return .{ .limit = limit, .used = 0 };
    }

    /// How many more bytes the limit allows.
    pub fn room(self: Flow) u64 {
        if (self.used >= self.limit) return 0;
        return self.limit - self.used;
    }

    /// Whether the limit is spent.
    pub fn blocked(self: Flow) bool {
        return self.used >= self.limit;
    }

    /// Spends `n` bytes, or reports that the limit does not reach.
    ///
    /// The add saturates rather than wraps, so a peer that names an offset
    /// near 2^62 meets the comparison and never the overflow.
    pub fn consume(self: *Flow, n: u64) FlowError!void {
        const wanted = self.used +| n;
        if (wanted > self.limit) return error.FlowControlError;
        self.used = wanted;
    }

    /// Records that the counter has reached `end`, which is an absolute
    /// offset and not a count.
    ///
    /// **This is the form the receiving side needs.** A `STREAM` frame
    /// names an offset, and a retransmission names one already counted, so
    /// counting the length of every frame would count the same byte twice
    /// and stop a healthy connection.
    pub fn reach(self: *Flow, end: u64) FlowError!void {
        if (end > self.limit) return error.FlowControlError;
        if (end > self.used) self.used = end;
    }

    /// Raises the limit to `new_limit`, and reports whether it moved.
    ///
    /// A smaller number is ignored, which RFC 9000 section 4.1 requires:
    /// a `MAX_DATA` frame may arrive after a later one that overtook it.
    pub fn raise(self: *Flow, new_limit: u64) bool {
        if (new_limit <= self.limit) return false;
        self.limit = new_limit;
        return true;
    }
};

const testing = std.testing;

test "the low two bits of an identifier name the initiator and the kind" {
    // RFC 9000 table 1, all four rows.
    try testing.expectEqual(@as(u64, 0), try makeId(.client, .bidirectional, 0));
    try testing.expectEqual(@as(u64, 1), try makeId(.server, .bidirectional, 0));
    try testing.expectEqual(@as(u64, 2), try makeId(.client, .unidirectional, 0));
    try testing.expectEqual(@as(u64, 3), try makeId(.server, .unidirectional, 0));

    // The first four streams a client opens of each kind.
    try testing.expectEqual(@as(u64, 4), try makeId(.client, .bidirectional, 1));
    try testing.expectEqual(@as(u64, 6), try makeId(.client, .unidirectional, 1));
    try testing.expectEqual(@as(u64, 10), try makeId(.client, .unidirectional, 2));

    // The last identifier of each space, which is the largest number the
    // bound allows shifted back into place.
    for ([_]u64{ 0, 1, 2, 3, 4, 6, 10, max_number << 2 }) |id| {
        try testing.expectEqual(id, try makeId(initiatorOf(id), kindOf(id), numberOf(id)));
    }
}

test "a stream number that names no encodable identifier is refused" {
    try testing.expectEqual(@as(u64, (1 << 62) - 1) >> 2, max_number);
    try testing.expectError(error.StreamNumberTooLarge, makeId(.client, .bidirectional, max_number + 1));
    try testing.expectError(error.StreamNumberTooLarge, makeId(.server, .unidirectional, std.math.maxInt(u64)));

    // One below the bound still has an encoding, and it is the largest
    // identifier a varint can hold for that space.
    const largest = try makeId(.server, .unidirectional, max_number - 1);
    try testing.expect(largest <= varint.max_value);

    // **The bound itself is legal.** All four identifiers of the last
    // stream number fit in a varint, and the largest of them is exactly
    // `max_id`. A bound that refused this number would make the last
    // stream of every space unreachable.
    for ([_]Initiator{ .client, .server }) |who| {
        for ([_]Kind{ .bidirectional, .unidirectional }) |what| {
            const id = try makeId(who, what, max_number);
            try testing.expect(id <= max_id);
            try testing.expectEqual(max_number, numberOf(id));
        }
    }
    try testing.expectEqual(max_id, try makeId(.server, .unidirectional, max_number));
}

test "a unidirectional stream carries data only away from the endpoint that opened it" {
    const client_uni = try makeId(.client, .unidirectional, 0);
    try testing.expect(localCanSend(client_uni, .client));
    try testing.expect(!localCanReceive(client_uni, .client));
    try testing.expect(!localCanSend(client_uni, .server));
    try testing.expect(localCanReceive(client_uni, .server));

    const server_uni = try makeId(.server, .unidirectional, 0);
    try testing.expect(!localCanSend(server_uni, .client));
    try testing.expect(localCanReceive(server_uni, .client));

    // A bidirectional stream carries data both ways whoever opened it.
    for ([_]u64{ try makeId(.client, .bidirectional, 0), try makeId(.server, .bidirectional, 0) }) |id| {
        for ([_]Initiator{ .client, .server }) |role| {
            try testing.expect(localCanSend(id, role));
            try testing.expect(localCanReceive(id, role));
        }
    }
}

test "a flow control limit stops the byte that would pass it" {
    var f: Flow = .init(10);
    try testing.expectEqual(@as(u64, 10), f.room());
    try f.consume(4);
    try testing.expectEqual(@as(u64, 6), f.room());
    try f.consume(6);
    try testing.expect(f.blocked());
    try testing.expectError(error.FlowControlError, f.consume(1));
    // The refused byte was not counted.
    try testing.expectEqual(@as(u64, 10), f.used);
}

test "a count near the top of the range meets the limit and never an overflow" {
    var f: Flow = .init(varint.max_value);
    try f.consume(varint.max_value);
    // A second consume of the whole range would wrap an unchecked add.
    try testing.expectError(error.FlowControlError, f.consume(varint.max_value));
    try testing.expectError(error.FlowControlError, f.consume(std.math.maxInt(u64)));
    try testing.expectEqual(@as(u64, varint.max_value), f.used);
}

test "an offset already counted is not counted a second time" {
    // A retransmitted STREAM frame names an offset the connection already
    // counted. `reach` is what stops it spending the window twice.
    var f: Flow = .init(100);
    try f.reach(40);
    try f.reach(40);
    try f.reach(20);
    try testing.expectEqual(@as(u64, 40), f.used);
    try f.reach(100);
    try testing.expectEqual(@as(u64, 0), f.room());
    try testing.expectError(error.FlowControlError, f.reach(101));
    try testing.expectEqual(@as(u64, 100), f.used);
}

test "a limit only ever goes up" {
    // RFC 9000 section 4.1: a MAX_DATA frame that names a smaller number
    // than one already received is ignored, because frames may be
    // reordered.
    var f: Flow = .init(100);
    try testing.expect(f.raise(200));
    try testing.expectEqual(@as(u64, 200), f.limit);
    try testing.expect(!f.raise(150));
    try testing.expectEqual(@as(u64, 200), f.limit);
    try testing.expect(!f.raise(200));
    try testing.expectEqual(@as(u64, 200), f.limit);
}

test "the sending half stops writing at the FIN and the receiving half stops reading at a reset" {
    try testing.expect(SendState.ready.writable());
    try testing.expect(SendState.send.writable());
    try testing.expect(!SendState.data_sent.writable());
    try testing.expect(!SendState.reset_sent.writable());
    try testing.expect(SendState.data_recvd.finished());
    try testing.expect(SendState.reset_recvd.finished());
    try testing.expect(!SendState.data_sent.finished());

    try testing.expect(RecvState.recv.readable());
    try testing.expect(RecvState.size_known.readable());
    try testing.expect(!RecvState.reset_recvd.readable());
    try testing.expect(RecvState.reset_recvd.reset());
    try testing.expect(!RecvState.data_recvd.reset());
    try testing.expect(RecvState.data_read.finished());
    try testing.expect(RecvState.reset_read.finished());
}
