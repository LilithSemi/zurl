//! The `CONTINUATION` order rule of RFC 9113 section 6.10.
//!
//! A `HEADERS` or a `PUSH_PROMISE` that does not carry `END_HEADERS`
//! leaves a header block open. Section 6.10 then allows exactly one next
//! frame: a `CONTINUATION` on the same stream. Any other frame, a
//! `CONTINUATION` on a different stream, and a `CONTINUATION` with no
//! open block are each a connection error of type `PROTOCOL_ERROR`.
//!
//! The rule is written down here as one small state machine, and not
//! spread through the frame reader, because it is the one rule in the
//! frame layer that needs memory from one frame to the next. A reader
//! that checks it inline gets it wrong the first time a new frame type is
//! added.
//!
//! This file owns the order rule and the two bounds that stop a peer from
//! holding a block open forever. It owns no HPACK state, no stream table,
//! and no buffer. It never sees a header block fragment, only its length.
//!
//! **A header block with no end is an attack, not a mistake.** A peer can
//! send `CONTINUATION` frames until the receiver runs out of memory, and
//! several HTTP/2 builds have fallen to exactly that. `limits` bounds both
//! the number of frames and the octets they carry, so a block always
//! ends, and always ends with a name.

const std = @import("std");
const errors = @import("errors.zig");
const frame = @import("frame.zig");

const Error = errors.Error;

/// The bounds on one header block.
pub const limits = struct {
    /// How many `CONTINUATION` frames one header block may take.
    ///
    /// The bound matters on its own, apart from `block_octets_max`: a
    /// `CONTINUATION` with an empty payload adds no octets, so a peer
    /// could send them forever and never reach the octet bound. This is
    /// what stops that.
    ///
    /// 64 frames at the smallest legal `SETTINGS_MAX_FRAME_SIZE` carry
    /// 1 MiB, which is far above any real header list.
    pub const continuation_frames_max: u32 = 64;

    /// How many octets one header block may carry, over every frame it
    /// takes.
    ///
    /// This is a frame-layer bound and not `SETTINGS_MAX_HEADER_LIST_SIZE`.
    /// That setting counts the header list after the decompression, which
    /// only HPACK can measure. This counts the octets on the wire, which
    /// is what a receiver must hold before it can decompress anything.
    pub const block_octets_max: usize = 128 * 1024;
};

/// Which frame type opened the block.
pub const Kind = enum { headers, push_promise };

/// What one frame did to the header block state.
pub const Outcome = enum {
    /// The frame carries no header block fragment, and no block was
    /// open.
    unrelated,
    /// A `HEADERS` or a `PUSH_PROMISE` opened a block that needs at
    /// least one `CONTINUATION`.
    opened,
    /// A `CONTINUATION` added to an open block, and more are still
    /// needed.
    continued,
    /// The block ended on this frame. A `HEADERS` with `END_HEADERS`
    /// gives this without ever opening anything.
    completed,
};

/// The open header block, while there is one.
pub const Open = struct {
    /// The stream every `CONTINUATION` of this block must carry.
    stream_id: u31,
    kind: Kind,
    /// How many `CONTINUATION` frames have arrived so far.
    continuations: u32,
    /// The payload octets counted so far, over every frame of the block.
    octets: usize,
};

/// The state machine of section 6.10.
///
/// One `Sequencer` belongs to one connection. `accept` takes every frame
/// header the connection reads, in the order they arrive, and reports
/// what each one did.
pub const Sequencer = struct {
    open: ?Open = null,

    /// True while a header block is waiting for a `CONTINUATION`.
    pub fn isOpen(self: *const Sequencer) bool {
        return self.open != null;
    }

    /// The stream of the open block, or null when none is open.
    pub fn openStream(self: *const Sequencer) ?u31 {
        const open = self.open orelse return null;
        return open.stream_id;
    }

    /// Takes one frame header and reports what it did.
    ///
    /// `payload_len` is the frame's own length field. It is at or above
    /// the header block fragment inside it, because padding and the
    /// priority fields only add. Counting the frame length rather than
    /// the fragment keeps this file free of the payload rules, and it
    /// bounds in the safe direction: the bound never lets through more
    /// octets than it names.
    ///
    /// Call this before the payload is parsed. An out-of-order frame is
    /// then refused on its header alone.
    pub fn accept(self: *Sequencer, header: frame.Header, payload_len: usize) Error!Outcome {
        if (self.open) |*open| return self.acceptWhileOpen(open.*, header, payload_len);

        switch (header.type) {
            // Section 6.10: a CONTINUATION must follow a HEADERS, a
            // PUSH_PROMISE, or another CONTINUATION. Nothing is open, so
            // it follows none of them.
            .continuation => return error.ContinuationUnexpected,

            .headers, .push_promise => {
                if (payload_len > limits.block_octets_max) return error.HeaderBlockTooLarge;
                if (header.has(frame.flag.end_headers)) return .completed;
                self.open = .{
                    .stream_id = header.stream_id,
                    .kind = if (header.type == .headers) .headers else .push_promise,
                    .continuations = 0,
                    .octets = payload_len,
                };
                return .opened;
            },

            else => return .unrelated,
        }
    }

    /// Clears the open block.
    ///
    /// The engine calls this after it takes the connection down, so a
    /// `Sequencer` can be reused. It never clears a block that is still
    /// running, because that would let the next frame through the rule.
    pub fn reset(self: *Sequencer) void {
        self.open = null;
    }

    fn acceptWhileOpen(
        self: *Sequencer,
        open: Open,
        header: frame.Header,
        payload_len: usize,
    ) Error!Outcome {
        // Section 6.10: "A receiver MUST treat the receipt of any other
        // type of frame or a frame on a different stream as a connection
        // error of type PROTOCOL_ERROR."
        if (header.type != .continuation) return error.ContinuationExpected;
        if (header.stream_id != open.stream_id) return error.ContinuationStreamMismatch;

        var next = open;
        next.continuations += 1;
        if (next.continuations > limits.continuation_frames_max) return error.ContinuationFlood;

        next.octets = std.math.add(usize, next.octets, payload_len) catch
            return error.HeaderBlockTooLarge;
        if (next.octets > limits.block_octets_max) return error.HeaderBlockTooLarge;

        if (header.has(frame.flag.end_headers)) {
            self.open = null;
            return .completed;
        }
        self.open = next;
        return .continued;
    }
};

const testing = std.testing;

/// A frame header with only the fields the sequencer reads.
fn head(t: frame.Type, flags: u8, stream_id: u31) frame.Header {
    return .{ .length = 0, .type = t, .flags = flags, .stream_id = stream_id };
}

const end_headers = frame.flag.end_headers;

test "a HEADERS with END_HEADERS completes on its own and opens nothing" {
    var seq: Sequencer = .{};
    try testing.expectEqual(Outcome.completed, try seq.accept(head(.headers, end_headers, 1), 4));
    try testing.expect(!seq.isOpen());
    try testing.expectEqual(@as(?u31, null), seq.openStream());
}

test "a HEADERS without END_HEADERS opens a block that a CONTINUATION closes" {
    var seq: Sequencer = .{};
    try testing.expectEqual(Outcome.opened, try seq.accept(head(.headers, 0, 1), 4));
    try testing.expect(seq.isOpen());
    try testing.expectEqual(@as(?u31, 1), seq.openStream());
    try testing.expectEqual(Kind.headers, seq.open.?.kind);

    try testing.expectEqual(Outcome.continued, try seq.accept(head(.continuation, 0, 1), 4));
    try testing.expect(seq.isOpen());

    try testing.expectEqual(
        Outcome.completed,
        try seq.accept(head(.continuation, end_headers, 1), 4),
    );
    try testing.expect(!seq.isOpen());
}

test "a PUSH_PROMISE opens a block the same way and remembers which type did" {
    var seq: Sequencer = .{};
    try testing.expectEqual(Outcome.opened, try seq.accept(head(.push_promise, 0, 3), 8));
    try testing.expectEqual(Kind.push_promise, seq.open.?.kind);
    try testing.expectEqual(
        Outcome.completed,
        try seq.accept(head(.continuation, end_headers, 3), 0),
    );
}

test "a frame of any other type may not interleave with an open block" {
    // Section 6.10 names no exception, so every type is refused, and the
    // list below walks all of them.
    const others = [_]frame.Type{
        .data,          .headers,      .priority, .rst_stream,
        .settings,      .push_promise, .ping,     .goaway,
        .window_update,
    };
    for (others) |t| {
        var seq: Sequencer = .{};
        _ = try seq.accept(head(.headers, 0, 1), 4);
        try testing.expectError(error.ContinuationExpected, seq.accept(head(t, 0, 1), 4));
    }

    // An unknown type is refused too. RFC 9113 section 4.1 says to ignore
    // one, but section 6.10 is the stricter rule and it wins: a receiver
    // cannot know an unknown frame is harmless here.
    var seq: Sequencer = .{};
    _ = try seq.accept(head(.headers, 0, 1), 4);
    try testing.expectError(
        error.ContinuationExpected,
        seq.accept(head(@enumFromInt(0xff), 0, 1), 4),
    );
}

test "a CONTINUATION on the wrong stream is refused" {
    var seq: Sequencer = .{};
    _ = try seq.accept(head(.headers, 0, 1), 4);
    try testing.expectError(
        error.ContinuationStreamMismatch,
        seq.accept(head(.continuation, 0, 3), 4),
    );

    // Stream 0 is the same fault, not a different one.
    var other: Sequencer = .{};
    _ = try other.accept(head(.headers, 0, 1), 4);
    try testing.expectError(
        error.ContinuationStreamMismatch,
        other.accept(head(.continuation, end_headers, 0), 4),
    );
}

test "a CONTINUATION with no open block is refused" {
    var seq: Sequencer = .{};
    try testing.expectError(
        error.ContinuationUnexpected,
        seq.accept(head(.continuation, end_headers, 1), 4),
    );

    // The same after a block already closed.
    var closed: Sequencer = .{};
    _ = try closed.accept(head(.headers, end_headers, 1), 4);
    try testing.expectError(
        error.ContinuationUnexpected,
        closed.accept(head(.continuation, 0, 1), 4),
    );
}

test "a second header block opens after the first one closes" {
    var seq: Sequencer = .{};
    _ = try seq.accept(head(.headers, 0, 1), 4);
    _ = try seq.accept(head(.continuation, end_headers, 1), 4);
    try testing.expectEqual(Outcome.unrelated, try seq.accept(head(.data, 0, 1), 10));
    try testing.expectEqual(Outcome.opened, try seq.accept(head(.headers, 0, 3), 4));
    try testing.expectEqual(@as(?u31, 3), seq.openStream());
}

test "a CONTINUATION flood is bounded by the frame count, even with empty payloads" {
    var seq: Sequencer = .{};
    _ = try seq.accept(head(.headers, 0, 1), 0);

    // Every frame carries nothing, so the octet bound never fires. Only
    // the frame count stops this.
    var sent: u32 = 0;
    while (sent < limits.continuation_frames_max) : (sent += 1) {
        try testing.expectEqual(Outcome.continued, try seq.accept(head(.continuation, 0, 1), 0));
    }
    try testing.expectEqual(@as(usize, 0), seq.open.?.octets);
    try testing.expectError(error.ContinuationFlood, seq.accept(head(.continuation, 0, 1), 0));

    try testing.expectEqual(
        errors.Fault{ .code = .enhance_your_calm, .scope = .connection },
        errors.classify(error.ContinuationFlood, 1),
    );
}

test "a CONTINUATION flood is bounded by the octet count, even with few frames" {
    var seq: Sequencer = .{};
    _ = try seq.accept(head(.headers, 0, 1), 0);

    // Four frames of 64 KiB each are well inside the frame bound, and
    // the third one runs past the octet bound.
    const chunk: usize = 64 * 1024;
    try testing.expectEqual(Outcome.continued, try seq.accept(head(.continuation, 0, 1), chunk));
    try testing.expectEqual(Outcome.continued, try seq.accept(head(.continuation, 0, 1), chunk));
    try testing.expectEqual(limits.block_octets_max, seq.open.?.octets);
    try testing.expectError(
        error.HeaderBlockTooLarge,
        seq.accept(head(.continuation, 0, 1), 1),
    );
}

test "a single HEADERS above the octet bound is refused before it opens anything" {
    var seq: Sequencer = .{};
    try testing.expectError(
        error.HeaderBlockTooLarge,
        seq.accept(head(.headers, end_headers, 1), limits.block_octets_max + 1),
    );
    try testing.expect(!seq.isOpen());
}

test "the frame count starts again for each new block" {
    var seq: Sequencer = .{};
    var block: u32 = 0;
    while (block < 3) : (block += 1) {
        _ = try seq.accept(head(.headers, 0, 1), 0);
        // The last frame of the block is the one that carries
        // END_HEADERS, so the run below is one short of the bound.
        var sent: u32 = 0;
        while (sent < limits.continuation_frames_max - 1) : (sent += 1) {
            _ = try seq.accept(head(.continuation, 0, 1), 0);
        }
        _ = try seq.accept(head(.continuation, end_headers, 1), 0);
        try testing.expect(!seq.isOpen());
    }
}

test "the bound counts the CONTINUATION that ends the block" {
    var seq: Sequencer = .{};
    _ = try seq.accept(head(.headers, 0, 1), 0);
    var sent: u32 = 0;
    while (sent < limits.continuation_frames_max) : (sent += 1) {
        _ = try seq.accept(head(.continuation, 0, 1), 0);
    }
    // Frame 65 is refused even when it would have ended the block.
    try testing.expectError(
        error.ContinuationFlood,
        seq.accept(head(.continuation, end_headers, 1), 0),
    );
}

test "reset clears an open block" {
    var seq: Sequencer = .{};
    _ = try seq.accept(head(.headers, 0, 1), 4);
    try testing.expect(seq.isOpen());
    seq.reset();
    try testing.expect(!seq.isOpen());
    try testing.expectEqual(Outcome.unrelated, try seq.accept(head(.ping, 0, 0), 8));
}

test "a frame that is not a header block type passes through untouched" {
    var seq: Sequencer = .{};
    const types = [_]frame.Type{ .data, .priority, .rst_stream, .settings, .ping, .goaway, .window_update };
    for (types) |t| {
        try testing.expectEqual(Outcome.unrelated, try seq.accept(head(t, 0, 0), 8));
        try testing.expect(!seq.isOpen());
    }
    try testing.expectEqual(
        Outcome.unrelated,
        try seq.accept(head(@enumFromInt(0x2a), 0, 0), 8),
    );
}
