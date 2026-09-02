//! The frames of QUIC, RFC 9000 section 19.
//!
//! This file reads and writes the twenty frame types RFC 9000 defines. It
//! owns the bytes of a frame and the checks section 19 states about those
//! bytes. It owns no connection state: it does not know which streams are
//! open, which packet numbers are outstanding, or which frame types the
//! packet it came from allows.
//!
//! ## Nothing here allocates, and that is the whole memory answer
//!
//! A decoded frame **borrows** the packet payload it came from. A
//! `CRYPTO` frame's data, a `STREAM` frame's data, a `NEW_TOKEN` frame's
//! token, an `ACK` frame's ranges, and a `CONNECTION_CLOSE` frame's
//! reason are all slices into the caller's own buffer. So a length the
//! peer chose can never ask this process for memory, and a peer that
//! writes 2^62 as a length gets `error.Truncated` from `Cursor`.
//!
//! `Decoder` is an iterator over one packet payload for the same reason.
//! A packet can hold thousands of frames, and a decoder that collected
//! them into a list would turn one datagram into an allocation the peer
//! sized.
//!
//! ## The ACK frame is the one that needs a second look
//!
//! `ACK Range Count` is a varint, so a peer can claim 2^62 ranges in a
//! frame that carries none. Two things stop that. Each range is two
//! varints and so at least two bytes, which makes the count refusable in
//! one comparison against the bytes that arrived. And the ranges are kept
//! **as bytes**, walked by `Ack.iterator`, so nothing is built from the
//! count at all.
//!
//! Section 19.3.1 subtracts each Gap and each ACK Range Length from a
//! running largest, and says a computed packet number below zero is a
//! connection error of type FRAME_ENCODING_ERROR. Every one of those
//! subtractions is checked in `RangeIterator.next`, and a frame that
//! would go below zero is `error.RangeUnderflow`.
//!
//! ## The reason phrase comes from the peer
//!
//! A `CONNECTION_CLOSE` frame carries text the peer wrote, and something
//! above may print it. `sanitizeReason` is what makes that safe: it
//! copies into a caller-sized buffer and turns every byte that is not
//! printable ASCII into a question mark. A control byte in a reason
//! phrase is what moves a terminal cursor and hides the rest of a
//! diagnostic.

const std = @import("std");

const Cursor = @import("Cursor.zig");
const packet = @import("packet.zig");
const varint = @import("varint.zig");

/// The frame type numbers of RFC 9000 table 3.
///
/// Five of the types use the low bits of the number to carry a flag, so
/// several of these name a range and not one value. `Type.of` maps a
/// number onto the name.
pub const type_number = struct {
    pub const padding: u64 = 0x00;
    pub const ping: u64 = 0x01;
    /// 0x02 with no ECN counts, 0x03 with them.
    pub const ack: u64 = 0x02;
    pub const ack_ecn: u64 = 0x03;
    pub const reset_stream: u64 = 0x04;
    pub const stop_sending: u64 = 0x05;
    pub const crypto: u64 = 0x06;
    pub const new_token: u64 = 0x07;
    /// 0x08 to 0x0f. The low three bits are the OFF, LEN, and FIN flags.
    pub const stream_first: u64 = 0x08;
    pub const stream_last: u64 = 0x0f;
    pub const max_data: u64 = 0x10;
    pub const max_stream_data: u64 = 0x11;
    /// 0x12 for bidirectional streams, 0x13 for unidirectional.
    pub const max_streams_bidi: u64 = 0x12;
    pub const max_streams_uni: u64 = 0x13;
    pub const data_blocked: u64 = 0x14;
    pub const stream_data_blocked: u64 = 0x15;
    pub const streams_blocked_bidi: u64 = 0x16;
    pub const streams_blocked_uni: u64 = 0x17;
    pub const new_connection_id: u64 = 0x18;
    pub const retire_connection_id: u64 = 0x19;
    pub const path_challenge: u64 = 0x1a;
    pub const path_response: u64 = 0x1b;
    /// 0x1c for a transport close, 0x1d for an application close.
    pub const connection_close: u64 = 0x1c;
    pub const connection_close_app: u64 = 0x1d;
    pub const handshake_done: u64 = 0x1e;
};

/// The flag bits inside a `STREAM` frame type. RFC 9000 section 19.8.
pub const stream_flag = struct {
    /// The Offset field is present.
    pub const off: u64 = 0x04;
    /// The Length field is present.
    pub const len: u64 = 0x02;
    /// This frame ends the stream.
    pub const fin: u64 = 0x01;
};

/// The largest stream count `MAX_STREAMS` and `STREAMS_BLOCKED` may name.
/// RFC 9000 sections 19.11 and 19.14: a larger one names a stream id
/// past 2^62 - 1, which has no encoding.
pub const max_stream_count: u64 = 1 << 60;

/// The three ECN counters of an `ACK` frame of type 0x03. RFC 9000
/// section 19.3.2.
pub const EcnCounts = struct {
    ect0: u64,
    ect1: u64,
    ce: u64,
};

/// One range of acknowledged packet numbers, both ends included.
pub const Range = struct {
    largest: u64,
    smallest: u64,

    /// How many packet numbers the range covers.
    pub fn count(self: Range) u64 {
        return self.largest - self.smallest + 1;
    }
};

/// An `ACK` frame. RFC 9000 section 19.3.
///
/// **The ranges stay as bytes.** See the module comment: the range count
/// is a varint the peer chose, so nothing is sized from it.
pub const Ack = struct {
    largest_acknowledged: u64,
    /// In units of 2^`ack_delay_exponent` microseconds. The exponent is a
    /// transport parameter, so this file cannot turn the field into a
    /// duration and does not try.
    ack_delay: u64,
    /// How many Gap and ACK Range Length pairs `ranges` holds.
    ack_range_count: u64,
    /// How many packets below `largest_acknowledged` the first range
    /// covers. Zero means only the largest is acknowledged.
    first_ack_range: u64,
    /// The Gap and ACK Range Length pairs, still encoded. Points into the
    /// packet payload. Exactly `ack_range_count` pairs are here.
    ranges: []const u8,
    /// Present when the frame type was 0x03.
    ecn: ?EcnCounts,

    /// Walks the ranges, largest first.
    pub fn iterator(self: Ack) RangeIterator {
        return .{ .ack = self, .cursor = .init(self.ranges), .state = .first };
    }
};

/// Why an `ACK` frame's ranges cannot be walked.
pub const RangeError = error{
    /// A Gap or an ACK Range Length subtracted below zero. RFC 9000
    /// section 19.3.1 makes this a connection error of type
    /// FRAME_ENCODING_ERROR.
    RangeUnderflow,
    /// A range ran past the bytes the frame carried.
    Truncated,
};

/// Walks an `ACK` frame's ranges, largest packet number first.
///
/// **Every subtraction here is checked.** Section 19.3.1 computes each
/// range from the one before it by subtracting, and a peer can write
/// numbers that take the running value below zero. That is a malformed
/// frame and not a wrap.
pub const RangeIterator = struct {
    ack: Ack,
    cursor: Cursor,
    state: State,
    /// The smallest packet number the previous range covered.
    previous_smallest: u64 = 0,
    /// How many pairs have been read.
    done: u64 = 0,

    const State = enum { first, more, ended };

    /// The next range, or null at the end.
    pub fn next(self: *RangeIterator) RangeError!?Range {
        switch (self.state) {
            .ended => return null,
            .first => {
                // smallest = largest - first_ack_range. Section 19.3.
                if (self.ack.first_ack_range > self.ack.largest_acknowledged) {
                    self.state = .ended;
                    return error.RangeUnderflow;
                }
                const smallest = self.ack.largest_acknowledged - self.ack.first_ack_range;
                self.previous_smallest = smallest;
                self.state = if (self.ack.ack_range_count == 0) .ended else .more;
                return .{ .largest = self.ack.largest_acknowledged, .smallest = smallest };
            },
            .more => {},
        }

        if (self.done == self.ack.ack_range_count) {
            self.state = .ended;
            return null;
        }

        const gap = self.cursor.takeVarint() catch {
            self.state = .ended;
            return error.Truncated;
        };
        const length = self.cursor.takeVarint() catch {
            self.state = .ended;
            return error.Truncated;
        };
        self.done += 1;

        // largest = previous_smallest - gap - 2. Section 19.3.1.
        // The two subtractions are checked one at a time, so neither can
        // wrap on the way to a number that looks legal.
        if (self.previous_smallest < 2 or gap > self.previous_smallest - 2) {
            self.state = .ended;
            return error.RangeUnderflow;
        }
        const largest = self.previous_smallest - gap - 2;

        // smallest = largest - ack_range_length. Section 19.3.1.
        if (length > largest) {
            self.state = .ended;
            return error.RangeUnderflow;
        }
        const smallest = largest - length;

        self.previous_smallest = smallest;
        if (self.done == self.ack.ack_range_count) self.state = .ended;
        return .{ .largest = largest, .smallest = smallest };
    }
};

/// A `RESET_STREAM` frame. RFC 9000 section 19.4.
pub const ResetStream = struct {
    stream_id: u64,
    application_error_code: u64,
    final_size: u64,
};

/// A `STOP_SENDING` frame. RFC 9000 section 19.5.
pub const StopSending = struct {
    stream_id: u64,
    application_error_code: u64,
};

/// A `CRYPTO` frame. RFC 9000 section 19.6.
///
/// **This is the frame that carries the TLS handshake.** The TLS task
/// reassembles a run of these into one byte stream per encryption level.
pub const Crypto = struct {
    offset: u64,
    /// Points into the packet payload.
    data: []const u8,
};

/// A `NEW_TOKEN` frame. RFC 9000 section 19.7.
pub const NewToken = struct {
    /// Points into the packet payload. Never empty: section 19.7 makes an
    /// empty token a connection error of type FRAME_ENCODING_ERROR.
    token: []const u8,
};

/// A `STREAM` frame. RFC 9000 section 19.8.
pub const Stream = struct {
    stream_id: u64,
    offset: u64 = 0,
    fin: bool = false,
    /// Points into the packet payload.
    data: []const u8,
    /// True when the OFF bit was set. An offset of zero has two legal
    /// spellings, and the round trip keeps whichever one arrived.
    explicit_offset: bool = false,
    /// True when the LEN bit was set. When it was not, the data ran to
    /// the end of the packet, so the frame was the last one there.
    explicit_length: bool = true,

    /// The last byte offset this frame reaches.
    ///
    /// RFC 9000 section 19.8 caps this at 2^62 - 1 and `decode` refuses a
    /// frame that passes it. **The add still saturates**, because a
    /// caller may build a `Stream` by hand and this value is compared
    /// against a bound rather than trusted. A saturated result is above
    /// 2^62 - 1, so the comparison that reads it refuses the frame.
    pub fn endOffset(self: Stream) u64 {
        return self.offset +| self.data.len;
    }
};

/// A `MAX_STREAM_DATA` frame. RFC 9000 section 19.10.
pub const MaxStreamData = struct {
    stream_id: u64,
    maximum_stream_data: u64,
};

/// Which half of the stream space a count applies to. RFC 9000 sections
/// 19.11 and 19.14.
pub const StreamKind = enum { bidirectional, unidirectional };

/// A `MAX_STREAMS` frame. RFC 9000 section 19.11.
pub const MaxStreams = struct {
    kind: StreamKind,
    /// At or below `max_stream_count`.
    maximum_streams: u64,
};

/// A `STREAM_DATA_BLOCKED` frame. RFC 9000 section 19.13.
pub const StreamDataBlocked = struct {
    stream_id: u64,
    maximum_stream_data: u64,
};

/// A `STREAMS_BLOCKED` frame. RFC 9000 section 19.14.
pub const StreamsBlocked = struct {
    kind: StreamKind,
    /// At or below `max_stream_count`.
    maximum_streams: u64,
};

/// How many bytes a Stateless Reset Token takes. RFC 9000 section 10.3.
pub const stateless_reset_token_len: usize = 16;

/// A `NEW_CONNECTION_ID` frame. RFC 9000 section 19.15.
pub const NewConnectionId = struct {
    sequence_number: u64,
    /// Never above `sequence_number`: section 19.15 makes a larger value
    /// a connection error of type FRAME_ENCODING_ERROR.
    retire_prior_to: u64,
    /// Held by value, because it outlives the datagram. Never empty:
    /// section 19.15 requires 1 to 20 bytes.
    connection_id: packet.ConnectionId,
    stateless_reset_token: [stateless_reset_token_len]u8,
};

/// How many bytes a `PATH_CHALLENGE` or `PATH_RESPONSE` frame carries.
/// RFC 9000 sections 19.17 and 19.18.
pub const path_data_len: usize = 8;

/// A `CONNECTION_CLOSE` frame. RFC 9000 section 19.19.
pub const ConnectionClose = struct {
    /// True for type 0x1d, which carries an application error code.
    application: bool,
    error_code: u64,
    /// The frame type that caused the close. Null for an application
    /// close, which section 19.19 gives no such field.
    frame_type: ?u64,
    /// Text the **peer** wrote. Points into the packet payload. Put it
    /// through `sanitizeReason` before anything prints it.
    reason: []const u8,
};

/// A room a caller should give `sanitizeReason`.
///
/// **This is a display bound and never a decode bound.** A peer may
/// legally write a longer reason, and refusing the frame over it would
/// throw away the error code as well. So the decode takes whatever the
/// packet holds and this is what a diagnostic keeps.
pub const max_reason_bytes: usize = 1024;

/// Copies `reason` into `out` with every byte that is not printable
/// ASCII turned into a question mark, and returns the part it wrote.
///
/// **This is the gate on the one run of bytes in QUIC that a peer writes
/// for a human to read.** A control byte in a reason phrase moves a
/// terminal cursor, so a peer could hide the rest of a diagnostic, or
/// print an error this build never reported. Every byte below 0x20, the
/// delete byte, and every byte above 0x7e become a question mark.
///
/// Copies at most `out.len` bytes. A longer reason is cut and not
/// refused, because the reason is the least important field of the frame.
pub fn sanitizeReason(reason: []const u8, out: []u8) []u8 {
    const take = @min(reason.len, out.len);
    for (reason[0..take], out[0..take]) |from, *to| {
        to.* = if (from >= 0x20 and from <= 0x7e) from else '?';
    }
    return out[0..take];
}

/// One frame of RFC 9000 section 19.
///
/// A run of `PADDING` frames arrives as one value with a count, because a
/// packet padded to 1200 bytes holds a thousand of them and a reader that
/// reported each one separately would turn one datagram into a thousand
/// steps for nothing.
pub const Frame = union(enum) {
    /// How many padding bytes ran together. Never zero.
    padding: usize,
    ping,
    ack: Ack,
    reset_stream: ResetStream,
    stop_sending: StopSending,
    crypto: Crypto,
    new_token: NewToken,
    stream: Stream,
    max_data: u64,
    max_stream_data: MaxStreamData,
    max_streams: MaxStreams,
    data_blocked: u64,
    stream_data_blocked: StreamDataBlocked,
    streams_blocked: StreamsBlocked,
    new_connection_id: NewConnectionId,
    retire_connection_id: u64,
    path_challenge: [path_data_len]u8,
    path_response: [path_data_len]u8,
    connection_close: ConnectionClose,
    handshake_done,

    /// The name RFC 9000 table 3 gives the type.
    pub fn name(self: Frame) []const u8 {
        return switch (self) {
            .padding => "PADDING",
            .ping => "PING",
            .ack => "ACK",
            .reset_stream => "RESET_STREAM",
            .stop_sending => "STOP_SENDING",
            .crypto => "CRYPTO",
            .new_token => "NEW_TOKEN",
            .stream => "STREAM",
            .max_data => "MAX_DATA",
            .max_stream_data => "MAX_STREAM_DATA",
            .max_streams => "MAX_STREAMS",
            .data_blocked => "DATA_BLOCKED",
            .stream_data_blocked => "STREAM_DATA_BLOCKED",
            .streams_blocked => "STREAMS_BLOCKED",
            .new_connection_id => "NEW_CONNECTION_ID",
            .retire_connection_id => "RETIRE_CONNECTION_ID",
            .path_challenge => "PATH_CHALLENGE",
            .path_response => "PATH_RESPONSE",
            .connection_close => "CONNECTION_CLOSE",
            .handshake_done => "HANDSHAKE_DONE",
        };
    }

    /// True when the frame counts toward the packet being
    /// acknowledgment-eliciting. RFC 9000 section 2 of the "Spec" column
    /// in table 3: `ACK`, `PADDING`, and `CONNECTION_CLOSE` do not.
    pub fn elicitsAck(self: Frame) bool {
        return switch (self) {
            .padding, .ack, .connection_close => false,
            else => true,
        };
    }

    /// True when losing the frame means it must be sent again. Table 3
    /// marks `ACK`, `PADDING`, and `CONNECTION_CLOSE` as not carrying
    /// this obligation.
    pub fn isRetransmittable(self: Frame) bool {
        return self.elicitsAck();
    }

    /// The frame type number this frame writes. RFC 9000 table 3.
    pub fn typeNumber(self: Frame) u64 {
        return switch (self) {
            .padding => type_number.padding,
            .ping => type_number.ping,
            .ack => |a| if (a.ecn == null) type_number.ack else type_number.ack_ecn,
            .reset_stream => type_number.reset_stream,
            .stop_sending => type_number.stop_sending,
            .crypto => type_number.crypto,
            .new_token => type_number.new_token,
            .stream => |s| type_number.stream_first |
                (if (s.explicit_offset) stream_flag.off else 0) |
                (if (s.explicit_length) stream_flag.len else 0) |
                (if (s.fin) stream_flag.fin else 0),
            .max_data => type_number.max_data,
            .max_stream_data => type_number.max_stream_data,
            .max_streams => |m| switch (m.kind) {
                .bidirectional => type_number.max_streams_bidi,
                .unidirectional => type_number.max_streams_uni,
            },
            .data_blocked => type_number.data_blocked,
            .stream_data_blocked => type_number.stream_data_blocked,
            .streams_blocked => |s| switch (s.kind) {
                .bidirectional => type_number.streams_blocked_bidi,
                .unidirectional => type_number.streams_blocked_uni,
            },
            .new_connection_id => type_number.new_connection_id,
            .retire_connection_id => type_number.retire_connection_id,
            .path_challenge => type_number.path_challenge,
            .path_response => type_number.path_response,
            .connection_close => |c| if (c.application)
                type_number.connection_close_app
            else
                type_number.connection_close,
            .handshake_done => type_number.handshake_done,
        };
    }
};

/// Why a run of bytes is not a frame.
pub const DecodeError = error{
    /// A field ran past the end of the packet payload. This covers every
    /// varint-declared length that named more bytes than arrived.
    Truncated,
    /// A frame type this version does not define. RFC 9000 section 12.4
    /// makes this a connection error of type FRAME_ENCODING_ERROR.
    UnknownFrameType,
    /// The frame type used more bytes than it needed. RFC 9000 section
    /// 12.4 makes the Frame Type field the one varint that must be
    /// minimal, so one type has one spelling.
    FrameTypeNotMinimal,
    /// A `NEW_TOKEN` frame with no token. RFC 9000 section 19.7.
    EmptyToken,
    /// A `NEW_CONNECTION_ID` frame whose length was zero or above 20, or
    /// whose Retire Prior To was above its Sequence Number. RFC 9000
    /// section 19.15.
    BadConnectionId,
    /// A `MAX_STREAMS` or `STREAMS_BLOCKED` frame above 2^60. RFC 9000
    /// sections 19.11 and 19.14.
    StreamCountTooLarge,
    /// A `STREAM` or `CRYPTO` frame whose offset and length together pass
    /// 2^62 - 1. RFC 9000 sections 19.6 and 19.8.
    OffsetTooLarge,
    /// An `ACK` frame claiming more ranges than its bytes can hold.
    BadAckRanges,
};

/// Reads the frames of one packet payload, one at a time.
///
/// **An iterator and not a list**, for the reason the module comment
/// gives: a packet can hold as many frames as it has bytes, and building
/// a list of them would size an allocation from the peer.
pub const Decoder = struct {
    cursor: Cursor,

    /// Starts at the front of one decrypted packet payload.
    pub fn init(payload: []const u8) Decoder {
        return .{ .cursor = .init(payload) };
    }

    /// True when every frame has been read.
    pub fn isEmpty(self: Decoder) bool {
        return self.cursor.isEmpty();
    }

    /// The next frame, or null at the end of the payload.
    ///
    /// A frame this returns points into the payload the decoder was
    /// given, so it lives exactly as long as that buffer.
    pub fn next(self: *Decoder) DecodeError!?Frame {
        if (self.cursor.isEmpty()) return null;

        const spelled = try self.cursor.takeVarintDecoded();
        // **One frame type, one spelling.** RFC 9000 section 12.4 makes
        // this the one varint that must be minimal, because two
        // spellings of one type is where this build and a middle box
        // read one packet as two.
        if (!spelled.isMinimal()) return error.FrameTypeNotMinimal;
        const t = spelled.value;

        if (t >= type_number.stream_first and t <= type_number.stream_last) {
            return .{ .stream = try self.decodeStream(t) };
        }

        return switch (t) {
            type_number.padding => .{ .padding = self.takePaddingRun() },
            type_number.ping => .ping,
            type_number.ack, type_number.ack_ecn => .{ .ack = try self.decodeAck(t == type_number.ack_ecn) },
            type_number.reset_stream => .{ .reset_stream = .{
                .stream_id = try self.cursor.takeVarint(),
                .application_error_code = try self.cursor.takeVarint(),
                .final_size = try self.cursor.takeVarint(),
            } },
            type_number.stop_sending => .{ .stop_sending = .{
                .stream_id = try self.cursor.takeVarint(),
                .application_error_code = try self.cursor.takeVarint(),
            } },
            type_number.crypto => .{ .crypto = try self.decodeCrypto() },
            type_number.new_token => .{ .new_token = try self.decodeNewToken() },
            type_number.max_data => .{ .max_data = try self.cursor.takeVarint() },
            type_number.max_stream_data => .{ .max_stream_data = .{
                .stream_id = try self.cursor.takeVarint(),
                .maximum_stream_data = try self.cursor.takeVarint(),
            } },
            type_number.max_streams_bidi, type_number.max_streams_uni => .{ .max_streams = .{
                .kind = if (t == type_number.max_streams_bidi) .bidirectional else .unidirectional,
                .maximum_streams = try self.takeStreamCount(),
            } },
            type_number.data_blocked => .{ .data_blocked = try self.cursor.takeVarint() },
            type_number.stream_data_blocked => .{ .stream_data_blocked = .{
                .stream_id = try self.cursor.takeVarint(),
                .maximum_stream_data = try self.cursor.takeVarint(),
            } },
            type_number.streams_blocked_bidi, type_number.streams_blocked_uni => .{ .streams_blocked = .{
                .kind = if (t == type_number.streams_blocked_bidi) .bidirectional else .unidirectional,
                .maximum_streams = try self.takeStreamCount(),
            } },
            type_number.new_connection_id => .{ .new_connection_id = try self.decodeNewConnectionId() },
            type_number.retire_connection_id => .{ .retire_connection_id = try self.cursor.takeVarint() },
            type_number.path_challenge => .{ .path_challenge = (try self.cursor.takeArray(path_data_len)).* },
            type_number.path_response => .{ .path_response = (try self.cursor.takeArray(path_data_len)).* },
            type_number.connection_close, type_number.connection_close_app => .{
                .connection_close = try self.decodeConnectionClose(t == type_number.connection_close_app),
            },
            type_number.handshake_done => .handshake_done,
            // RFC 9000 section 12.4: an unknown type is a connection
            // error of type FRAME_ENCODING_ERROR, not a frame to skip.
            // A frame of unknown type has an unknown length, so a reader
            // could not skip it even if the RFC allowed that.
            else => error.UnknownFrameType,
        };
    }

    /// Counts the padding bytes that follow the one already read.
    ///
    /// A packet padded to the 1200 bytes RFC 9000 section 14.1 asks for
    /// holds a thousand of these, so they are counted and not reported
    /// one by one.
    fn takePaddingRun(self: *Decoder) usize {
        var run: usize = 1;
        while (!self.cursor.isEmpty() and self.cursor.rest()[0] == 0x00) {
            self.cursor.at += 1;
            run += 1;
        }
        return run;
    }

    fn decodeAck(self: *Decoder, with_ecn: bool) DecodeError!Ack {
        const largest_acknowledged = try self.cursor.takeVarint();
        const ack_delay = try self.cursor.takeVarint();
        const ack_range_count = try self.cursor.takeVarint();
        const first_ack_range = try self.cursor.takeVarint();

        // **The bound on the range count, and it runs before the walk.**
        // Each range is a Gap and an ACK Range Length, so two varints and
        // two bytes at least. A count above half the bytes left cannot be
        // true, whatever the ranges say, and refusing it here turns a
        // claim of 2^62 ranges into one comparison.
        if (ack_range_count > self.cursor.remaining() / 2) return error.BadAckRanges;

        // Walk the pairs to find where they end. The walk is bounded by
        // the check above, so it runs at most `remaining / 2` times.
        const start = self.cursor.at;
        var seen: u64 = 0;
        while (seen < ack_range_count) : (seen += 1) {
            _ = try self.cursor.takeVarint();
            _ = try self.cursor.takeVarint();
        }
        const ranges = self.cursor.bytes[start..self.cursor.at];

        const ecn: ?EcnCounts = if (with_ecn) .{
            .ect0 = try self.cursor.takeVarint(),
            .ect1 = try self.cursor.takeVarint(),
            .ce = try self.cursor.takeVarint(),
        } else null;

        return .{
            .largest_acknowledged = largest_acknowledged,
            .ack_delay = ack_delay,
            .ack_range_count = ack_range_count,
            .first_ack_range = first_ack_range,
            .ranges = ranges,
            .ecn = ecn,
        };
    }

    fn decodeCrypto(self: *Decoder) DecodeError!Crypto {
        const offset = try self.cursor.takeVarint();
        const length = try self.cursor.takeVarint();
        const data = try self.cursor.takeVarintLength(length);
        // RFC 9000 section 19.6: the end of a CRYPTO frame cannot pass
        // 2^62 - 1. The subtraction cannot wrap, because `offset` came
        // from a varint and so is at or below `varint.max_value`.
        if (data.len > varint.max_value - offset) return error.OffsetTooLarge;
        return .{ .offset = offset, .data = data };
    }

    fn decodeNewToken(self: *Decoder) DecodeError!NewToken {
        const length = try self.cursor.takeVarint();
        const token = try self.cursor.takeVarintLength(length);
        // RFC 9000 section 19.7: a client must treat an empty token as a
        // connection error of type FRAME_ENCODING_ERROR.
        if (token.len == 0) return error.EmptyToken;
        return .{ .token = token };
    }

    fn decodeStream(self: *Decoder, t: u64) DecodeError!Stream {
        const explicit_offset = t & stream_flag.off != 0;
        const explicit_length = t & stream_flag.len != 0;

        const stream_id = try self.cursor.takeVarint();
        const offset: u64 = if (explicit_offset) try self.cursor.takeVarint() else 0;
        const data = if (explicit_length) data: {
            const length = try self.cursor.takeVarint();
            break :data try self.cursor.takeVarintLength(length);
        } else
            // No Length field, so the data runs to the end of the packet
            // and this frame is the last one in it.
            try self.cursor.take(self.cursor.remaining());

        // RFC 9000 section 19.8: the largest offset a stream reaches
        // cannot pass 2^62 - 1.
        if (data.len > varint.max_value - offset) return error.OffsetTooLarge;

        return .{
            .stream_id = stream_id,
            .offset = offset,
            .fin = t & stream_flag.fin != 0,
            .data = data,
            .explicit_offset = explicit_offset,
            .explicit_length = explicit_length,
        };
    }

    fn takeStreamCount(self: *Decoder) DecodeError!u64 {
        const value = try self.cursor.takeVarint();
        // RFC 9000 sections 19.11 and 19.14: a count above 2^60 names a
        // stream id with no encoding.
        if (value > max_stream_count) return error.StreamCountTooLarge;
        return value;
    }

    fn decodeNewConnectionId(self: *Decoder) DecodeError!NewConnectionId {
        const sequence_number = try self.cursor.takeVarint();
        const retire_prior_to = try self.cursor.takeVarint();
        // RFC 9000 section 19.15: Retire Prior To is never above the
        // Sequence Number of the id the same frame delivers.
        if (retire_prior_to > sequence_number) return error.BadConnectionId;

        // The length is one byte and not a varint, so a peer can claim
        // 255. Section 19.15 allows 1 to 20.
        const length = try self.cursor.takeByte();
        if (length == 0 or length > packet.max_connection_id_len) return error.BadConnectionId;
        const connection_id = packet.ConnectionId.init(try self.cursor.take(length)) catch
            return error.BadConnectionId;

        return .{
            .sequence_number = sequence_number,
            .retire_prior_to = retire_prior_to,
            .connection_id = connection_id,
            .stateless_reset_token = (try self.cursor.takeArray(stateless_reset_token_len)).*,
        };
    }

    fn decodeConnectionClose(self: *Decoder, application: bool) DecodeError!ConnectionClose {
        const error_code = try self.cursor.takeVarint();
        // Section 19.19: only the transport close carries a frame type.
        const frame_type: ?u64 = if (application) null else try self.cursor.takeVarint();
        const length = try self.cursor.takeVarint();
        return .{
            .application = application,
            .error_code = error_code,
            .frame_type = frame_type,
            .reason = try self.cursor.takeVarintLength(length),
        };
    }
};

/// Why a frame could not be written.
pub const EncodeError = varint.EncodeError || std.Io.Writer.Error;

/// Writes `f` onto a stream.
///
/// **A value that has no encoding is a bug above and not a fault on the
/// wire.** A frame reaching here came from this build, so an offset past
/// 2^62 - 1 or a stream count past 2^60 means a caller built something
/// QUIC cannot say. Those are asserts. `error.ValueTooLarge` stays a
/// returned error, because a release build strips the asserts and a
/// wrong packet must not go out either way.
pub fn encode(f: Frame, w: *std.Io.Writer) EncodeError!void {
    switch (f) {
        .padding => |count| {
            std.debug.assert(count > 0);
            try w.splatByteAll(0x00, count);
            return;
        },
        else => {},
    }

    try varint.write(w, f.typeNumber());
    switch (f) {
        .padding => unreachable,
        .ping, .handshake_done => {},
        .ack => |a| {
            try varint.write(w, a.largest_acknowledged);
            try varint.write(w, a.ack_delay);
            try varint.write(w, a.ack_range_count);
            try varint.write(w, a.first_ack_range);
            try w.writeAll(a.ranges);
            if (a.ecn) |ecn| {
                try varint.write(w, ecn.ect0);
                try varint.write(w, ecn.ect1);
                try varint.write(w, ecn.ce);
            }
        },
        .reset_stream => |r| {
            try varint.write(w, r.stream_id);
            try varint.write(w, r.application_error_code);
            try varint.write(w, r.final_size);
        },
        .stop_sending => |s| {
            try varint.write(w, s.stream_id);
            try varint.write(w, s.application_error_code);
        },
        .crypto => |c| {
            std.debug.assert(c.data.len <= varint.max_value - c.offset);
            try varint.write(w, c.offset);
            try varint.write(w, c.data.len);
            try w.writeAll(c.data);
        },
        .new_token => |n| {
            std.debug.assert(n.token.len > 0);
            try varint.write(w, n.token.len);
            try w.writeAll(n.token);
        },
        .stream => |s| {
            std.debug.assert(s.explicit_offset or s.offset == 0);
            std.debug.assert(s.data.len <= varint.max_value - s.offset);
            try varint.write(w, s.stream_id);
            if (s.explicit_offset) try varint.write(w, s.offset);
            if (s.explicit_length) try varint.write(w, s.data.len);
            try w.writeAll(s.data);
        },
        .max_data => |v| try varint.write(w, v),
        .max_stream_data => |m| {
            try varint.write(w, m.stream_id);
            try varint.write(w, m.maximum_stream_data);
        },
        .max_streams => |m| {
            std.debug.assert(m.maximum_streams <= max_stream_count);
            try varint.write(w, m.maximum_streams);
        },
        .data_blocked => |v| try varint.write(w, v),
        .stream_data_blocked => |s| {
            try varint.write(w, s.stream_id);
            try varint.write(w, s.maximum_stream_data);
        },
        .streams_blocked => |s| {
            std.debug.assert(s.maximum_streams <= max_stream_count);
            try varint.write(w, s.maximum_streams);
        },
        .new_connection_id => |n| {
            std.debug.assert(n.retire_prior_to <= n.sequence_number);
            std.debug.assert(n.connection_id.len > 0);
            try varint.write(w, n.sequence_number);
            try varint.write(w, n.retire_prior_to);
            try w.writeByte(n.connection_id.len);
            try w.writeAll(n.connection_id.slice());
            try w.writeAll(&n.stateless_reset_token);
        },
        .retire_connection_id => |v| try varint.write(w, v),
        .path_challenge => |data| try w.writeAll(&data),
        .path_response => |data| try w.writeAll(&data),
        .connection_close => |c| {
            try varint.write(w, c.error_code);
            if (c.frame_type) |t| {
                std.debug.assert(!c.application);
                try varint.write(w, t);
            } else {
                std.debug.assert(c.application);
            }
            try varint.write(w, c.reason.len);
            try w.writeAll(c.reason);
        },
    }
}

const testing = std.testing;

/// Reads exactly one frame out of `bytes` and checks nothing is left.
fn decodeOne(bytes: []const u8) !Frame {
    var d: Decoder = .init(bytes);
    const f = (try d.next()) orelse return error.Truncated;
    try testing.expect(d.isEmpty());
    return f;
}

/// Writes `f` and gives back the bytes.
fn encodeOne(f: Frame, out: []u8) ![]u8 {
    var w: std.Io.Writer = .fixed(out);
    try encode(f, &w);
    return out[0..w.end];
}

test "every frame type of RFC 9000 table 3 round trips through its own bytes" {
    // **One row for each of the twenty types**, with the bytes written
    // out by hand from section 19 and the value they must decode to. The
    // encode must give the same bytes back.
    const token = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const reset_token = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const path_data = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const new_cid = try packet.ConnectionId.init(&.{ 0xaa, 0xbb, 0xcc, 0xdd });

    const cases = [_]struct { bytes: []const u8, frame: Frame }{
        .{ .bytes = &.{0x00}, .frame = .{ .padding = 1 } },
        .{ .bytes = &.{0x01}, .frame = .ping },
        .{
            // ACK, largest 10, delay 3, 0 ranges, first range 2.
            .bytes = &.{ 0x02, 0x0a, 0x03, 0x00, 0x02 },
            .frame = .{ .ack = .{
                .largest_acknowledged = 10,
                .ack_delay = 3,
                .ack_range_count = 0,
                .first_ack_range = 2,
                .ranges = &.{},
                .ecn = null,
            } },
        },
        .{
            // ACK with the three ECN counts of section 19.3.2.
            .bytes = &.{ 0x03, 0x0a, 0x03, 0x00, 0x02, 0x04, 0x05, 0x06 },
            .frame = .{ .ack = .{
                .largest_acknowledged = 10,
                .ack_delay = 3,
                .ack_range_count = 0,
                .first_ack_range = 2,
                .ranges = &.{},
                .ecn = .{ .ect0 = 4, .ect1 = 5, .ce = 6 },
            } },
        },
        .{
            .bytes = &.{ 0x04, 0x04, 0x0b, 0x40, 0xc8 },
            .frame = .{ .reset_stream = .{
                .stream_id = 4,
                .application_error_code = 11,
                .final_size = 200,
            } },
        },
        .{
            .bytes = &.{ 0x05, 0x08, 0x0b },
            .frame = .{ .stop_sending = .{ .stream_id = 8, .application_error_code = 11 } },
        },
        .{
            .bytes = &.{ 0x06, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef },
            .frame = .{ .crypto = .{ .offset = 0, .data = &token } },
        },
        .{
            .bytes = &.{ 0x07, 0x04, 0xde, 0xad, 0xbe, 0xef },
            .frame = .{ .new_token = .{ .token = &token } },
        },
        .{
            // STREAM 0x08: no offset, no length, no fin.
            .bytes = &.{ 0x08, 0x04, 0xde, 0xad, 0xbe, 0xef },
            .frame = .{ .stream = .{
                .stream_id = 4,
                .data = &token,
                .explicit_offset = false,
                .explicit_length = false,
            } },
        },
        .{
            // STREAM 0x0f: offset, length, and fin all present.
            .bytes = &.{ 0x0f, 0x04, 0x40, 0xc8, 0x04, 0xde, 0xad, 0xbe, 0xef },
            .frame = .{ .stream = .{
                .stream_id = 4,
                .offset = 200,
                .fin = true,
                .data = &token,
                .explicit_offset = true,
                .explicit_length = true,
            } },
        },
        .{ .bytes = &.{ 0x10, 0x44, 0x00 }, .frame = .{ .max_data = 1024 } },
        .{
            .bytes = &.{ 0x11, 0x04, 0x44, 0x00 },
            .frame = .{ .max_stream_data = .{ .stream_id = 4, .maximum_stream_data = 1024 } },
        },
        .{
            .bytes = &.{ 0x12, 0x40, 0x64 },
            .frame = .{ .max_streams = .{ .kind = .bidirectional, .maximum_streams = 100 } },
        },
        .{
            .bytes = &.{ 0x13, 0x40, 0x64 },
            .frame = .{ .max_streams = .{ .kind = .unidirectional, .maximum_streams = 100 } },
        },
        .{ .bytes = &.{ 0x14, 0x44, 0x00 }, .frame = .{ .data_blocked = 1024 } },
        .{
            .bytes = &.{ 0x15, 0x04, 0x44, 0x00 },
            .frame = .{ .stream_data_blocked = .{ .stream_id = 4, .maximum_stream_data = 1024 } },
        },
        .{
            .bytes = &.{ 0x16, 0x40, 0x64 },
            .frame = .{ .streams_blocked = .{ .kind = .bidirectional, .maximum_streams = 100 } },
        },
        .{
            .bytes = &.{ 0x17, 0x40, 0x64 },
            .frame = .{ .streams_blocked = .{ .kind = .unidirectional, .maximum_streams = 100 } },
        },
        .{
            .bytes = &.{
                0x18, 0x02, 0x01, 0x04, 0xaa, 0xbb, 0xcc, 0xdd,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            },
            .frame = .{ .new_connection_id = .{
                .sequence_number = 2,
                .retire_prior_to = 1,
                .connection_id = new_cid,
                .stateless_reset_token = reset_token,
            } },
        },
        .{ .bytes = &.{ 0x19, 0x02 }, .frame = .{ .retire_connection_id = 2 } },
        .{
            .bytes = &.{ 0x1a, 1, 2, 3, 4, 5, 6, 7, 8 },
            .frame = .{ .path_challenge = path_data },
        },
        .{
            .bytes = &.{ 0x1b, 1, 2, 3, 4, 5, 6, 7, 8 },
            .frame = .{ .path_response = path_data },
        },
        .{
            // A transport close, which carries the frame type that caused it.
            .bytes = &.{ 0x1c, 0x0a, 0x06, 0x02, 'n', 'o' },
            .frame = .{ .connection_close = .{
                .application = false,
                .error_code = 10,
                .frame_type = type_number.crypto,
                .reason = "no",
            } },
        },
        .{
            // An application close, which carries none.
            .bytes = &.{ 0x1d, 0x0a, 0x02, 'n', 'o' },
            .frame = .{ .connection_close = .{
                .application = true,
                .error_code = 10,
                .frame_type = null,
                .reason = "no",
            } },
        },
        .{ .bytes = &.{0x1e}, .frame = .handshake_done },
    };

    var seen_types = std.AutoHashMap(u64, void).init(testing.allocator);
    defer seen_types.deinit();

    for (cases) |case| {
        const read = try decodeOne(case.bytes);
        try testing.expectEqualDeep(case.frame, read);
        try testing.expectEqual(case.bytes[0], @as(u8, @intCast(read.typeNumber())));

        var out: [64]u8 = undefined;
        try testing.expectEqualSlices(u8, case.bytes, try encodeOne(read, &out));
        try seen_types.put(read.typeNumber(), {});
    }

    // Every number in table 3 is in the table above: the twenty names,
    // with a second row for each of the five types whose low bits carry a
    // flag, and both ends of the STREAM range.
    try testing.expectEqual(@as(usize, 25), seen_types.count());
}

test "an unknown frame type ends the packet rather than being skipped" {
    // RFC 9000 section 12.4 makes this a connection error of type
    // FRAME_ENCODING_ERROR. A reader could not skip it in any case: an
    // unknown type has an unknown length.
    try testing.expectError(error.UnknownFrameType, decodeOne(&.{0x1f}));
    try testing.expectError(error.UnknownFrameType, decodeOne(&.{ 0x40, 0x40 }));
}

test "one frame type has one spelling" {
    // RFC 9000 section 12.4 makes the Frame Type field the one varint
    // that must be minimal. `0x4001` is PING written in two bytes.
    try testing.expectError(error.FrameTypeNotMinimal, decodeOne(&.{ 0x40, 0x01 }));
    try testing.expectError(error.FrameTypeNotMinimal, decodeOne(&.{ 0x80, 0x00, 0x00, 0x01 }));
    // The one byte spelling is read.
    try testing.expectEqual(Frame.ping, try decodeOne(&.{0x01}));
}

test "a run of PADDING arrives as one count and writes back the same run" {
    // A packet padded to 1200 bytes holds a thousand of these.
    var payload: [1200]u8 = @splat(0x00);
    payload[0] = 0x01;
    var d: Decoder = .init(&payload);
    try testing.expectEqual(Frame.ping, (try d.next()).?);
    try testing.expectEqual(@as(usize, 1199), (try d.next()).?.padding);
    try testing.expectEqual(@as(?Frame, null), try d.next());

    var out: [16]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0 }, try encodeOne(.{ .padding = 3 }, &out));
}

test "a decoder walks every frame in one payload and then reports the end" {
    // PING, PADDING run, CRYPTO, HANDSHAKE_DONE.
    const payload = [_]u8{
        0x01, 0x00, 0x00, 0x06, 0x00, 0x02, 0xaa, 0xbb, 0x1e,
    };
    var d: Decoder = .init(&payload);
    try testing.expectEqual(Frame.ping, (try d.next()).?);
    try testing.expectEqual(@as(usize, 2), (try d.next()).?.padding);
    const crypto = (try d.next()).?.crypto;
    try testing.expectEqual(@as(u64, 0), crypto.offset);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, crypto.data);
    try testing.expectEqual(Frame.handshake_done, (try d.next()).?);
    try testing.expectEqual(@as(?Frame, null), try d.next());
    try testing.expect(d.isEmpty());
}

test "an ACK frame walks its ranges largest first" {
    // Largest 100, first range 2, so 98..100. Then a gap of 1 and a
    // length of 3: largest = 98 - 1 - 2 = 95, smallest = 95 - 3 = 92.
    // Then a gap of 0 and a length of 0: largest = 92 - 0 - 2 = 90.
    const bytes = [_]u8{ 0x02, 0x40, 0x64, 0x00, 0x02, 0x02, 0x01, 0x03, 0x00, 0x00 };
    const a = (try decodeOne(&bytes)).ack;
    try testing.expectEqual(@as(u64, 100), a.largest_acknowledged);
    try testing.expectEqual(@as(u64, 2), a.ack_range_count);
    try testing.expectEqual(@as(u64, 2), a.first_ack_range);

    var it = a.iterator();
    try testing.expectEqualDeep(Range{ .largest = 100, .smallest = 98 }, (try it.next()).?);
    try testing.expectEqualDeep(Range{ .largest = 95, .smallest = 92 }, (try it.next()).?);
    try testing.expectEqualDeep(Range{ .largest = 90, .smallest = 90 }, (try it.next()).?);
    try testing.expectEqual(@as(?Range, null), try it.next());

    try testing.expectEqual(@as(u64, 3), Range.count(.{ .largest = 100, .smallest = 98 }));

    var out: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, &bytes, try encodeOne(.{ .ack = a }, &out));
}

test "an ACK frame claiming more ranges than its bytes hold is refused at once" {
    // **The bound this file argues for.** The peer says 2^62 ranges and
    // sends none. The check is one comparison and no walk.
    const huge = [_]u8{
        // Largest Acknowledged of 100, and an ACK Delay of 0.
        0x02, 0x40, 0x64, 0x00,
        // ACK Range Count of 2^62 - 1.
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        // First ACK Range, and then nothing at all.
        0x00,
    };
    try testing.expectError(error.BadAckRanges, decodeOne(&huge));

    // A count of 4 with room for two pairs is refused the same way.
    const short = [_]u8{ 0x02, 0x40, 0x64, 0x00, 0x04, 0x00, 1, 1, 1, 1, 1 };
    try testing.expectError(error.BadAckRanges, decodeOne(&short));
}

test "an ACK range that subtracts below zero is a fault and not a wrap" {
    // RFC 9000 section 19.3.1: a computed packet number below zero is a
    // connection error of type FRAME_ENCODING_ERROR.
    //
    // First ACK Range past the largest.
    {
        const bytes = [_]u8{ 0x02, 0x05, 0x00, 0x00, 0x06 };
        var it = (try decodeOne(&bytes)).ack.iterator();
        try testing.expectError(error.RangeUnderflow, it.next());
    }
    // A gap that takes the running largest below zero.
    {
        // Largest 5, first range 0, so smallest 5. Gap 10 gives
        // 5 - 10 - 2, which is below zero.
        const bytes = [_]u8{ 0x02, 0x05, 0x00, 0x01, 0x00, 0x0a, 0x00 };
        var it = (try decodeOne(&bytes)).ack.iterator();
        try testing.expectEqualDeep(Range{ .largest = 5, .smallest = 5 }, (try it.next()).?);
        try testing.expectError(error.RangeUnderflow, it.next());
    }
    // A range length past the largest of its own range.
    {
        // Largest 10, first range 0. Gap 0 gives largest 8, and a length
        // of 20 takes the smallest below zero.
        const bytes = [_]u8{ 0x02, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x14 };
        var it = (try decodeOne(&bytes)).ack.iterator();
        try testing.expectEqualDeep(Range{ .largest = 10, .smallest = 10 }, (try it.next()).?);
        try testing.expectError(error.RangeUnderflow, it.next());
    }
    // The smallest of the previous range being 0 or 1 leaves no room for
    // `- gap - 2` at all.
    {
        const bytes = [_]u8{ 0x02, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };
        var it = (try decodeOne(&bytes)).ack.iterator();
        try testing.expectEqualDeep(Range{ .largest = 1, .smallest = 1 }, (try it.next()).?);
        try testing.expectError(error.RangeUnderflow, it.next());
    }
}

test "an ACK iterator that reported a fault reports the end afterwards" {
    // A caller that kept asking must not get the same fault forever, and
    // must never get a range after one.
    const bytes = [_]u8{ 0x02, 0x05, 0x00, 0x00, 0x06 };
    var it = (try decodeOne(&bytes)).ack.iterator();
    try testing.expectError(error.RangeUnderflow, it.next());
    try testing.expectEqual(@as(?Range, null), try it.next());
}

test "a varint length past the end of the packet is refused in every frame that has one" {
    // Each of these declares more bytes than the packet holds.
    // CRYPTO with a length of 2^62 - 1.
    try testing.expectError(error.Truncated, decodeOne(&.{
        0x06, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xaa,
    }));
    // NEW_TOKEN with a length of 100 and one byte after it.
    try testing.expectError(error.Truncated, decodeOne(&.{ 0x07, 0x64, 0xaa }));
    // STREAM with the LEN bit and a length of 100.
    try testing.expectError(error.Truncated, decodeOne(&.{ 0x0a, 0x04, 0x64, 0xaa }));
    // CONNECTION_CLOSE with a reason length of 100.
    try testing.expectError(error.Truncated, decodeOne(&.{ 0x1c, 0x0a, 0x06, 0x64, 'n' }));
    // NEW_CONNECTION_ID with no room for the reset token.
    try testing.expectError(error.Truncated, decodeOne(&.{ 0x18, 0x02, 0x01, 0x04, 0xaa, 0xbb, 0xcc, 0xdd }));
    // PATH_CHALLENGE with seven bytes.
    try testing.expectError(error.Truncated, decodeOne(&.{ 0x1a, 1, 2, 3, 4, 5, 6, 7 }));
}

test "a NEW_TOKEN frame with an empty token is refused" {
    // RFC 9000 section 19.7 makes this a connection error of type
    // FRAME_ENCODING_ERROR.
    try testing.expectError(error.EmptyToken, decodeOne(&.{ 0x07, 0x00 }));
}

test "a NEW_CONNECTION_ID frame outside the rules of section 19.15 is refused" {
    const token = [_]u8{0} ** 16;
    // Retire Prior To above the Sequence Number.
    var bytes = [_]u8{ 0x18, 0x01, 0x02, 0x04, 0xaa, 0xbb, 0xcc, 0xdd } ++ token;
    try testing.expectError(error.BadConnectionId, decodeOne(&bytes));

    // A length of zero. Section 19.15 asks for 1 to 20.
    bytes = [_]u8{ 0x18, 0x02, 0x01, 0x00, 0xaa, 0xbb, 0xcc, 0xdd } ++ token;
    try testing.expectError(error.BadConnectionId, decodeOne(&bytes));

    // A length of 21, which is past the cap of RFC 9000 section 17.2.
    var long = [_]u8{ 0x18, 0x02, 0x01, 21 } ++ ([_]u8{0xaa} ** 21) ++ token;
    try testing.expectError(error.BadConnectionId, decodeOne(&long));

    // A length of 255, which is what a peer writes to make a reader run
    // past the datagram.
    long[3] = 255;
    try testing.expectError(error.BadConnectionId, decodeOne(&long));
}

test "a stream count above 2^60 is refused" {
    // RFC 9000 sections 19.11 and 19.14: a larger count names a stream id
    // that has no encoding.
    const at_limit = [_]u8{ 0x12, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try testing.expectEqual(max_stream_count, (try decodeOne(&at_limit)).max_streams.maximum_streams);

    const past_limit = [_]u8{ 0x12, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    try testing.expectError(error.StreamCountTooLarge, decodeOne(&past_limit));
    const past_limit_blocked = [_]u8{ 0x17, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    try testing.expectError(error.StreamCountTooLarge, decodeOne(&past_limit_blocked));
}

test "a STREAM or CRYPTO frame that reaches past 2^62 - 1 is refused" {
    // RFC 9000 sections 19.6 and 19.8 cap the largest offset a stream
    // reaches. The offset here is the largest varint, so any data at all
    // passes the cap.
    const stream = [_]u8{
        0x0e, 0x04,
        0xff, 0xff,
        0xff, 0xff,
        0xff, 0xff,
        0xff, 0xff,
        0x02, 0xaa,
        0xbb,
    };
    try testing.expectError(error.OffsetTooLarge, decodeOne(&stream));

    const crypto = [_]u8{
        0x06,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0x02,
        0xaa,
        0xbb,
    };
    try testing.expectError(error.OffsetTooLarge, decodeOne(&crypto));

    // An offset that reaches exactly the cap is legal.
    const at_cap = [_]u8{
        0x06,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xfd,
        0x02,
        0xaa,
        0xbb,
    };
    const c = (try decodeOne(&at_cap)).crypto;
    try testing.expectEqual(varint.max_value, c.offset + c.data.len);
}

test "a STREAM frame with no Length field takes the rest of the packet" {
    // RFC 9000 section 19.8: with the LEN bit clear the data runs to the
    // end, so such a frame is always the last one in its packet.
    const payload = [_]u8{ 0x08, 0x04, 'h', 'e', 'l', 'l', 'o' };
    var d: Decoder = .init(&payload);
    const s = (try d.next()).?.stream;
    try testing.expectEqualStrings("hello", s.data);
    try testing.expect(!s.explicit_length);
    try testing.expectEqual(@as(?Frame, null), try d.next());

    // With an offset of 200 and the FIN bit, the end offset is 205.
    const with_offset = [_]u8{ 0x0d, 0x04, 0x40, 0xc8, 'h', 'e', 'l', 'l', 'o' };
    const t = (try decodeOne(&with_offset)).stream;
    try testing.expectEqual(@as(u64, 205), t.endOffset());
    // The add saturates, so a hand built frame near the top of the range
    // gives a number above the bound and never a wrapped small one.
    const at_top: Stream = .{ .stream_id = 0, .offset = std.math.maxInt(u64), .data = "xx" };
    try testing.expectEqual(std.math.maxInt(u64), at_top.endOffset());
    try testing.expect(at_top.endOffset() > varint.max_value);
    try testing.expect(t.fin);
    try testing.expect(t.explicit_offset);
}

test "an offset of zero keeps whichever spelling arrived" {
    // Both spellings are legal, so the round trip must not change one
    // into the other.
    const implicit = (try decodeOne(&.{ 0x0a, 0x04, 0x02, 0xaa, 0xbb })).stream;
    try testing.expect(!implicit.explicit_offset);
    try testing.expectEqual(@as(u64, 0), implicit.offset);

    const explicit = (try decodeOne(&.{ 0x0e, 0x04, 0x00, 0x02, 0xaa, 0xbb })).stream;
    try testing.expect(explicit.explicit_offset);
    try testing.expectEqual(@as(u64, 0), explicit.offset);

    var out: [16]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 0x0a, 0x04, 0x02, 0xaa, 0xbb }, try encodeOne(.{ .stream = implicit }, &out));
    try testing.expectEqualSlices(u8, &.{ 0x0e, 0x04, 0x00, 0x02, 0xaa, 0xbb }, try encodeOne(.{ .stream = explicit }, &out));
}

test "a reason phrase from the peer is cut to the caller's room and stripped of control bytes" {
    // **The gate on the one run of bytes in QUIC a peer writes for a
    // human.** A control byte moves a terminal cursor, so a peer could
    // hide the rest of a diagnostic behind its own text.
    var out: [32]u8 = undefined;
    try testing.expectEqualStrings("ok", sanitizeReason("ok", &out));
    try testing.expectEqualStrings("a?b?c", sanitizeReason("a\rb\nc", &out));
    try testing.expectEqualStrings("?[2J", sanitizeReason("\x1b[2J", &out));
    try testing.expectEqualStrings("??", sanitizeReason(&.{ 0x00, 0x7f }, &out));
    // A byte above ASCII is replaced too, one for one.
    try testing.expectEqualStrings("??", sanitizeReason("\xc3\xa9", &out));

    // A longer reason is cut and never overruns the room it was given.
    var small: [4]u8 = undefined;
    try testing.expectEqualStrings("abcd", sanitizeReason("abcdefgh", &small));
    var none: [0]u8 = undefined;
    try testing.expectEqualStrings("", sanitizeReason("abcd", &none));
}

test "a CONNECTION_CLOSE reason as long as the packet allows is read and not refused" {
    // The reason is the least important field of the frame, so a long one
    // must not cost the caller the error code.
    var payload: [4 + 300]u8 = undefined;
    payload[0] = 0x1d;
    payload[1] = 0x0a;
    payload[2] = 0x41;
    payload[3] = 0x2c;
    @memset(payload[4..], 'x');
    const c = (try decodeOne(&payload)).connection_close;
    try testing.expectEqual(@as(u64, 10), c.error_code);
    try testing.expectEqual(@as(usize, 300), c.reason.len);
    try testing.expect(c.application);
    try testing.expectEqual(@as(?u64, null), c.frame_type);
    try testing.expectEqual(@as(usize, 1024), max_reason_bytes);
}

test "an empty payload holds no frames" {
    var d: Decoder = .init(&.{});
    try testing.expect(d.isEmpty());
    try testing.expectEqual(@as(?Frame, null), try d.next());
}

test "the frames that do not elicit an acknowledgment are the three table 3 names" {
    try testing.expect(!(Frame{ .padding = 1 }).elicitsAck());
    const ack: Frame = .{ .ack = .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .ack_range_count = 0,
        .first_ack_range = 0,
        .ranges = &.{},
        .ecn = null,
    } };
    try testing.expect(!ack.elicitsAck());
    const close: Frame = .{ .connection_close = .{
        .application = true,
        .error_code = 0,
        .frame_type = null,
        .reason = "",
    } };
    try testing.expect(!close.elicitsAck());
    try testing.expect(!close.isRetransmittable());

    try testing.expect((@as(Frame, .ping)).elicitsAck());
    try testing.expect((@as(Frame, .handshake_done)).elicitsAck());
    try testing.expect((Frame{ .max_data = 1 }).elicitsAck());
}

test "every frame reports the name RFC 9000 table 3 gives it" {
    try testing.expectEqualStrings("PING", (@as(Frame, .ping)).name());
    try testing.expectEqualStrings("PADDING", (Frame{ .padding = 1 }).name());
    try testing.expectEqualStrings("HANDSHAKE_DONE", (@as(Frame, .handshake_done)).name());
    try testing.expectEqualStrings("RETIRE_CONNECTION_ID", (Frame{ .retire_connection_id = 0 }).name());
    try testing.expectEqualStrings("MAX_DATA", (Frame{ .max_data = 0 }).name());
}

test "a frame that stops inside itself is Truncated and reads nothing after" {
    try testing.expectError(error.Truncated, decodeOne(&.{0x04}));
    try testing.expectError(error.Truncated, decodeOne(&.{ 0x04, 0x01 }));
    try testing.expectError(error.Truncated, decodeOne(&.{ 0x04, 0x01, 0x02 }));
    try testing.expectError(error.Truncated, decodeOne(&.{ 0x02, 0x0a }));
    try testing.expectError(error.Truncated, decodeOne(&.{ 0x03, 0x0a, 0x00, 0x00, 0x00, 0x01 }));
}
