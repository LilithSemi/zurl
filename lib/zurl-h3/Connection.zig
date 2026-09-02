//! The connection rules of HTTP/3: which stream carries what, which frame
//! may appear where, and the order the first frames must arrive in. RFC
//! 9114 sections 4, 5, 6, and 7.
//!
//! **This file holds no bytes and no socket.** It is the state that says
//! whether the frame the caller just read is allowed, and it is separate
//! from the framing so a test can drive every refusal in two lines.
//!
//! ## The three rules a peer can break at once
//!
//! **Each critical stream arrives once.** RFC 9114 section 6.2.1 gives
//! each endpoint one control stream, and RFC 9204 section 4.2 gives it one
//! QPACK encoder stream and one QPACK decoder stream. A peer that opens a
//! second of any of them is a connection error of type
//! H3_STREAM_CREATION_ERROR, not something to tolerate: two control
//! streams have two `SETTINGS` frames, and this side would have to decide
//! which one describes the peer.
//!
//! **`SETTINGS` is first on the control stream, and it is there once.**
//! RFC 9114 section 6.2.1 makes any other first frame a connection error
//! of type H3_MISSING_SETTINGS, and that holds for a frame type this build
//! does not know as well: an unknown frame is stepped over everywhere
//! else, and here it is not, because the rule is about the **first** frame
//! and not about which frames are understood. A second `SETTINGS` is
//! H3_FRAME_UNEXPECTED.
//!
//! **A message is `HEADERS`, then `DATA`, then `HEADERS`.** RFC 9114
//! section 4.1. `Message` is that order, and `DATA` before any `HEADERS`
//! is H3_FRAME_UNEXPECTED rather than a body with no head.
//!
//! ## Push is refused, and said so
//!
//! This build sends no `MAX_PUSH_ID`, which RFC 9114 section 7.2.7 makes
//! the same as a push limit of nothing. So a `PUSH_PROMISE` frame, a push
//! stream, and a `CANCEL_PUSH` frame are each H3_ID_ERROR here, which is
//! what the RFC asks of a client that allowed no push. curl does the same:
//! it sends no `MAX_PUSH_ID` on an HTTP/3 connection either.

const std = @import("std");
const frame = @import("frame.zig");
const settings = @import("settings.zig");
const stream_type = @import("stream_type.zig");
const error_code = @import("error_code.zig");

const Connection = @This();

/// Which endpoint this is.
pub const Role = enum { client, server };

/// Every fault this file can report. Each name is the RFC 9114 section
/// 8.1 code without its `H3_` prefix, and `errorCode` gives the number.
pub const Error = error{
    /// A frame arrived on a stream that may not carry it, or a second
    /// `SETTINGS` arrived. H3_FRAME_UNEXPECTED.
    FrameUnexpected,
    /// The first frame of the control stream was not `SETTINGS`.
    /// H3_MISSING_SETTINGS.
    MissingSettings,
    /// A `SETTINGS` payload named a reserved identifier or repeated one.
    /// H3_SETTINGS_ERROR.
    SettingsError,
    /// A frame payload is not the shape its type requires. H3_FRAME_ERROR.
    FrameError,
    /// The peer opened a second control, QPACK encoder, or QPACK decoder
    /// stream. H3_STREAM_CREATION_ERROR.
    StreamCreationError,
    /// The peer closed a stream that must stay open for the life of the
    /// connection. H3_CLOSED_CRITICAL_STREAM.
    ClosedCriticalStream,
    /// A push or a `GOAWAY` named an identifier the connection does not
    /// allow. H3_ID_ERROR.
    IdError,
    /// The peer stayed inside the RFC and passed a limit this build keeps
    /// for itself. H3_EXCESSIVE_LOAD.
    ///
    /// **This is the code for a refusal that is this side's choice.** RFC
    /// 9114 section 8.1 gives it for "the endpoint detected that its peer
    /// is exhibiting a behavior that might be generating excessive load",
    /// which is what a local ceiling on legal traffic is. A code that
    /// says the peer was malformed would name a fault the peer did not
    /// commit.
    ExcessiveLoad,
};

/// The RFC 9114 section 8.1 code that closes a connection on `err`.
pub fn errorCode(err: Error) error_code.Code {
    return switch (err) {
        error.FrameUnexpected => .frame_unexpected,
        error.MissingSettings => .missing_settings,
        error.SettingsError => .settings_error,
        error.FrameError => .frame_error,
        error.StreamCreationError => .stream_creation_error,
        error.ClosedCriticalStream => .closed_critical_stream,
        error.IdError => .id_error,
        error.ExcessiveLoad => .excessive_load,
    };
}

/// What the caller should do with a stream a peer just opened.
pub const StreamRole = enum {
    control,
    qpack_encoder,
    qpack_decoder,
    /// The type is one this build does not read. RFC 9114 section 6.2
    /// asks the caller to abandon the stream: send `STOP_SENDING` with
    /// H3_STREAM_CREATION_ERROR and read no more of it.
    abandon,
};

/// What the caller should do with a frame.
pub const Disposition = enum {
    /// Read the payload and act on it. Only a frame of this disposition
    /// meets the caller's bound on what it buffers.
    act,
    /// Step over the payload and buffer none of it. RFC 9114 section 9
    /// requires this of any frame type an endpoint does not know.
    ///
    /// **The length of such a frame is not bounded by anything this side
    /// promised.** Section 7.2.8 has a conformant peer send a reserved
    /// type on purpose, and section 9 says to ignore it "regardless of
    /// length", so a caller that buffered the payload before it read the
    /// disposition would close the connection on legal traffic. The
    /// caller drains these octets through a fixed sink instead.
    skip,
};

role: Role,
/// What this side named in its own `SETTINGS` frame.
local_settings: settings.Settings,
/// What the peer named in its `SETTINGS` frame, or null before one
/// arrived.
peer_settings: ?settings.Settings = null,
/// The identifier of the peer's control stream, or null before it opened
/// one.
peer_control_stream: ?u64 = null,
peer_qpack_encoder_stream: ?u64 = null,
peer_qpack_decoder_stream: ?u64 = null,
/// Whether a `SETTINGS` frame has arrived on the control stream.
settings_seen: bool = false,
/// The identifier the last `GOAWAY` from the peer named, or null.
goaway_received: ?u64 = null,
/// How many streams the caller abandoned because the type was one this
/// build does not read.
///
/// **A recovered fault is counted and never silent.** RFC 9114 section
/// 6.2.3 has a peer open such a stream on purpose, so this is expected
/// traffic and not a reason to close anything, but a reader must be able
/// to see it happened.
abandoned_streams: u64 = 0,
/// How many frames the caller stepped over because the type was one this
/// build does not act on.
ignored_frames: u64 = 0,

/// A connection in role `role` that announced `local_settings`.
pub fn init(role: Role, local_settings: settings.Settings) Connection {
    return .{ .role = role, .local_settings = local_settings };
}

/// Records the type of a unidirectional stream the peer opened.
///
/// The stream identifier is carried so a later
/// `onPeerUniStreamClosed` can name the same stream.
pub fn onPeerUniStream(self: *Connection, id: u64, t: stream_type.Type) Error!StreamRole {
    switch (t) {
        .control => {
            // RFC 9114 section 6.2.1: one control stream for each
            // endpoint. A second one is not something to tolerate.
            if (self.peer_control_stream != null) return error.StreamCreationError;
            self.peer_control_stream = id;
            return .control;
        },
        .qpack_encoder => {
            if (self.peer_qpack_encoder_stream != null) return error.StreamCreationError;
            self.peer_qpack_encoder_stream = id;
            return .qpack_encoder;
        },
        .qpack_decoder => {
            if (self.peer_qpack_decoder_stream != null) return error.StreamCreationError;
            self.peer_qpack_decoder_stream = id;
            return .qpack_decoder;
        },
        // RFC 9114 section 4.6: a server may open a push stream only
        // inside the limit a `MAX_PUSH_ID` frame set, and this build sets
        // none.
        .push => return error.IdError,
        _ => {
            self.abandoned_streams += 1;
            return .abandon;
        },
    }
}

/// Reports that the peer closed or reset one of its unidirectional
/// streams.
///
/// RFC 9114 section 6.2.1 and RFC 9204 section 4.2 make the control
/// stream and the two QPACK streams live for the whole connection, so an
/// end on any of them is a connection error of type
/// H3_CLOSED_CRITICAL_STREAM.
pub fn onPeerUniStreamClosed(self: *Connection, id: u64) Error!void {
    if (self.peer_control_stream == id) return error.ClosedCriticalStream;
    if (self.peer_qpack_encoder_stream == id) return error.ClosedCriticalStream;
    if (self.peer_qpack_decoder_stream == id) return error.ClosedCriticalStream;
}

/// Checks a frame that arrived on the peer's control stream.
///
/// **The first frame must be `SETTINGS`.** An unknown type does not pass
/// this gate, which is the one place in HTTP/3 where an unknown frame is
/// not stepped over. RFC 9114 section 6.2.1.
pub fn onControlFrame(self: *Connection, kind: frame.Kind) Error!Disposition {
    if (!self.settings_seen) {
        if (kind != .settings) return error.MissingSettings;
        self.settings_seen = true;
        return .act;
    }
    return switch (kind) {
        // RFC 9114 section 7.2.4: exactly one.
        .settings => error.FrameUnexpected,
        .goaway, .max_push_id => .act,
        // RFC 9114 section 7.2.3: this build allowed no push, so there is
        // nothing to cancel and a peer that cancels one is naming an
        // identifier that cannot exist.
        .cancel_push => error.IdError,
        // RFC 9114 section 7.2: these belong to a request stream.
        .data, .headers, .push_promise => error.FrameUnexpected,
        _ => {
            self.ignored_frames += 1;
            return .skip;
        },
    };
}

/// Reads the payload of the peer's `SETTINGS` frame.
///
/// **A second `SETTINGS` is a fault and not a panic.** `onControlFrame`
/// refuses one before the payload is read, but this function is public and
/// that guard lives in another function, so a second caller here is a
/// protocol error the peer can reach and never an invariant this file may
/// assume. RFC 9114 section 7.2.4 makes it H3_FRAME_UNEXPECTED.
pub fn onSettings(self: *Connection, payload: []const u8) Error!void {
    if (self.peer_settings != null) return error.FrameUnexpected;
    self.peer_settings = try settings.decode(payload);
}

/// Reads the payload of a `GOAWAY` frame from the peer.
///
/// RFC 9114 section 5.2: a server names the largest client-initiated
/// bidirectional stream it might act on, and every later `GOAWAY` names
/// the same identifier or a smaller one. A larger one is H3_ID_ERROR,
/// because it would take back a refusal the client already acted on.
pub fn onGoaway(self: *Connection, id: u64) Error!void {
    switch (self.role) {
        .client => {
            // The identifier names a client-initiated bidirectional
            // stream, which is 0 modulo 4. RFC 9114 section 5.2.
            if (id % 4 != 0) return error.IdError;
        },
        // A client's `GOAWAY` names a push identifier, which has no such
        // shape.
        .server => {},
    }
    if (self.goaway_received) |previous| {
        if (id > previous) return error.IdError;
    }
    self.goaway_received = id;
}

/// Reads the payload of a `MAX_PUSH_ID` frame from the peer.
///
/// RFC 9114 section 7.2.7 lets only a client send one, so a client that
/// receives one has a server sending a frame it may not.
pub fn onMaxPushId(self: *Connection, id: u64) Error!void {
    _ = id;
    if (self.role == .client) return error.FrameUnexpected;
}

/// The per-message frame order of RFC 9114 section 4.1, for one request
/// stream.
///
/// A response is one or more informational `HEADERS`, then the final
/// `HEADERS`, then `DATA`, then an optional trailer `HEADERS`. Anything
/// else is H3_FRAME_UNEXPECTED.
pub const Message = struct {
    /// How far through the order this stream has read.
    state: State = .head,
    /// How many informational responses arrived. RFC 9114 puts no bound
    /// on them, so this build does, and the caller reads it against
    /// `informational_max`.
    informational: u32 = 0,

    pub const State = enum {
        /// Nothing has arrived. Only `HEADERS` may.
        head,
        /// The final `HEADERS` arrived. `DATA` and a trailer may follow.
        body,
        /// The trailer arrived. Nothing may follow.
        trailers,
    };

    /// How many informational responses one message may carry.
    ///
    /// **RFC 9114 puts no bound on this, so a peer could send them for
    /// ever and never answer.** Eight is the number `zurl-http/h2.zig`
    /// already uses for the same reason on HTTP/2.
    pub const informational_max: u32 = 8;

    /// Checks a frame on a request stream, given whether the `HEADERS`
    /// frame it names carries an informational status.
    ///
    /// The caller passes `informational` only for a `HEADERS` frame; it
    /// is read nowhere else. The status is inside a QPACK field section,
    /// so only the caller can know it.
    pub fn onFrame(self: *Message, kind: frame.Kind, informational: bool) Error!Disposition {
        switch (kind) {
            .headers => switch (self.state) {
                .head => {
                    if (informational) {
                        // **The sequence is legal, and the ceiling is
                        // this side's own.** RFC 9114 puts no bound on
                        // informational responses, so the code is
                        // H3_EXCESSIVE_LOAD and not a code that says the
                        // peer sent a frame it may not. The comparison is
                        // `>=` so it still holds if the increment below
                        // ever moves by more than one.
                        if (self.informational >= informational_max) return error.ExcessiveLoad;
                        self.informational += 1;
                    } else {
                        self.state = .body;
                    }
                    return .act;
                },
                .body => {
                    // A second final `HEADERS` is the trailer section.
                    // RFC 9114 section 4.1: an informational status may
                    // not appear there.
                    if (informational) return error.FrameUnexpected;
                    self.state = .trailers;
                    return .act;
                },
                .trailers => return error.FrameUnexpected,
            },
            .data => switch (self.state) {
                // RFC 9114 section 4.1: a body with no head.
                .head => return error.FrameUnexpected,
                .body => return .act,
                .trailers => return error.FrameUnexpected,
            },
            // RFC 9114 section 7.2: these belong to the control stream.
            .settings, .goaway, .max_push_id, .cancel_push => return error.FrameUnexpected,
            // This build allowed no push. RFC 9114 section 7.2.5.
            .push_promise => return error.IdError,
            _ => return .skip,
        }
    }
};

const testing = std.testing;

test "the peer gets one control stream and a second one closes the connection" {
    var c: Connection = .init(.client, .{});
    try testing.expectEqual(StreamRole.control, try c.onPeerUniStream(3, .control));
    try testing.expectEqual(@as(?u64, 3), c.peer_control_stream);
    try testing.expectError(error.StreamCreationError, c.onPeerUniStream(7, .control));
    try testing.expectEqual(error_code.Code.stream_creation_error, errorCode(error.StreamCreationError));
}

test "each QPACK stream arrives once as well" {
    var c: Connection = .init(.client, .{});
    try testing.expectEqual(StreamRole.qpack_encoder, try c.onPeerUniStream(7, .qpack_encoder));
    try testing.expectEqual(StreamRole.qpack_decoder, try c.onPeerUniStream(11, .qpack_decoder));
    try testing.expectError(error.StreamCreationError, c.onPeerUniStream(15, .qpack_encoder));
    try testing.expectError(error.StreamCreationError, c.onPeerUniStream(19, .qpack_decoder));
}

test "a stream of a type this build does not read is abandoned and counted" {
    var c: Connection = .init(.client, .{});
    try testing.expectEqual(StreamRole.abandon, try c.onPeerUniStream(3, @enumFromInt(0x21)));
    try testing.expectEqual(StreamRole.abandon, try c.onPeerUniStream(7, @enumFromInt(0x22)));
    try testing.expectEqual(@as(u64, 2), c.abandoned_streams);
    // Two of them is not a fault: the type is not a critical stream, so
    // there is nothing to be a second copy of.
}

test "a push stream is refused because this build allowed no push" {
    var c: Connection = .init(.client, .{});
    try testing.expectError(error.IdError, c.onPeerUniStream(3, .push));
    try testing.expectEqual(error_code.Code.id_error, errorCode(error.IdError));
}

test "closing a critical stream closes the connection" {
    var c: Connection = .init(.client, .{});
    _ = try c.onPeerUniStream(3, .control);
    _ = try c.onPeerUniStream(7, .qpack_encoder);
    try testing.expectError(error.ClosedCriticalStream, c.onPeerUniStreamClosed(3));
    try testing.expectError(error.ClosedCriticalStream, c.onPeerUniStreamClosed(7));
    // A stream that is not critical may end whenever it likes.
    try c.onPeerUniStreamClosed(99);
}

test "SETTINGS must be the first frame on the control stream" {
    // RFC 9114 section 6.2.1. Every other type, known or not, is
    // H3_MISSING_SETTINGS before SETTINGS has arrived.
    for ([_]frame.Kind{ .goaway, .max_push_id, .data, .headers, @enumFromInt(0x21) }) |kind| {
        var c: Connection = .init(.client, .{});
        try testing.expectError(error.MissingSettings, c.onControlFrame(kind));
        try testing.expect(!c.settings_seen);
    }
    try testing.expectEqual(error_code.Code.missing_settings, errorCode(error.MissingSettings));

    var good: Connection = .init(.client, .{});
    try testing.expectEqual(Disposition.act, try good.onControlFrame(.settings));
    try testing.expect(good.settings_seen);
}

test "SETTINGS arrives once and a second one closes the connection" {
    var c: Connection = .init(.client, .{});
    _ = try c.onControlFrame(.settings);
    try c.onSettings(&.{ 0x06, 0x44, 0x00 });
    try testing.expectEqual(@as(?u64, 0x400), c.peer_settings.?.max_field_section_size);
    try testing.expectError(error.FrameUnexpected, c.onControlFrame(.settings));
    try testing.expectEqual(error_code.Code.frame_unexpected, errorCode(error.FrameUnexpected));
}

test "a frame that belongs on a request stream is refused on the control stream" {
    var c: Connection = .init(.client, .{});
    _ = try c.onControlFrame(.settings);
    for ([_]frame.Kind{ .data, .headers, .push_promise }) |kind| {
        try testing.expectError(error.FrameUnexpected, c.onControlFrame(kind));
    }
}

test "an unknown frame on the control stream is stepped over once SETTINGS has arrived" {
    var c: Connection = .init(.client, .{});
    _ = try c.onControlFrame(.settings);
    // **`skip` and not `act`**, so the caller never has to hold the
    // payload of a frame it does not read. RFC 9114 section 9 asks for the
    // frame to be ignored whatever its length.
    try testing.expectEqual(Disposition.skip, try c.onControlFrame(@enumFromInt(0x21)));
    try testing.expectEqual(Disposition.skip, try c.onControlFrame(@enumFromInt(0x22)));
    try testing.expectEqual(@as(u64, 2), c.ignored_frames);
}

test "a GOAWAY names a client stream and never a larger one than before" {
    var c: Connection = .init(.client, .{});
    _ = try c.onControlFrame(.settings);
    try testing.expectEqual(Disposition.act, try c.onControlFrame(.goaway));
    try c.onGoaway(8);
    try testing.expectEqual(@as(?u64, 8), c.goaway_received);
    // The same identifier again, and a smaller one, are both legal.
    try c.onGoaway(8);
    try c.onGoaway(4);
    // A larger one would take back a refusal the client already acted on.
    try testing.expectError(error.IdError, c.onGoaway(8));

    // The identifier names a client-initiated bidirectional stream, so it
    // is 0 modulo 4.
    var other: Connection = .init(.client, .{});
    try testing.expectError(error.IdError, other.onGoaway(3));
    try testing.expectError(error.IdError, other.onGoaway(6));
}

test "a server that sends MAX_PUSH_ID or CANCEL_PUSH to a client is refused" {
    var c: Connection = .init(.client, .{});
    _ = try c.onControlFrame(.settings);
    // The frame type is allowed on a control stream, and the payload rule
    // is what refuses it.
    try testing.expectEqual(Disposition.act, try c.onControlFrame(.max_push_id));
    try testing.expectError(error.FrameUnexpected, c.onMaxPushId(4));
    // Nothing was pushed, so nothing can be cancelled.
    try testing.expectError(error.IdError, c.onControlFrame(.cancel_push));
}

test "a message is HEADERS then DATA then HEADERS" {
    var m: Message = .{};
    // A body with no head.
    try testing.expectError(error.FrameUnexpected, m.onFrame(.data, false));

    try testing.expectEqual(Disposition.act, try m.onFrame(.headers, false));
    try testing.expectEqual(Message.State.body, m.state);
    try testing.expectEqual(Disposition.act, try m.onFrame(.data, false));
    try testing.expectEqual(Disposition.act, try m.onFrame(.data, false));

    // The trailer section.
    try testing.expectEqual(Disposition.act, try m.onFrame(.headers, false));
    try testing.expectEqual(Message.State.trailers, m.state);
    // Nothing follows it.
    try testing.expectError(error.FrameUnexpected, m.onFrame(.data, false));
    try testing.expectError(error.FrameUnexpected, m.onFrame(.headers, false));
}

test "informational responses come before the head and are bounded" {
    var m: Message = .{};
    var index: u32 = 0;
    while (index < Message.informational_max) : (index += 1) {
        try testing.expectEqual(Disposition.act, try m.onFrame(.headers, true));
        try testing.expectEqual(Message.State.head, m.state);
    }
    // RFC 9114 puts no bound on them, so this build does: a peer could
    // otherwise send a 1xx for ever and never answer. The sequence is
    // legal, so the code names this side's ceiling and not a frame the
    // peer may not send.
    try testing.expectError(error.ExcessiveLoad, m.onFrame(.headers, true));
    try testing.expectEqual(error_code.Code.excessive_load, errorCode(error.ExcessiveLoad));

    // The final head still lands.
    var fresh: Message = .{};
    try testing.expectEqual(Disposition.act, try fresh.onFrame(.headers, true));
    try testing.expectEqual(Disposition.act, try fresh.onFrame(.headers, false));
    try testing.expectEqual(Message.State.body, fresh.state);
    // A trailer section may not carry an informational status.
    try testing.expectError(error.FrameUnexpected, fresh.onFrame(.headers, true));
}

test "a control stream frame is refused on a request stream" {
    var m: Message = .{};
    _ = try m.onFrame(.headers, false);
    for ([_]frame.Kind{ .settings, .goaway, .max_push_id, .cancel_push }) |kind| {
        var fresh: Message = m;
        try testing.expectError(error.FrameUnexpected, fresh.onFrame(kind, false));
    }
    // A PUSH_PROMISE is refused for the identifier and not for the place.
    var promised: Message = m;
    try testing.expectError(error.IdError, promised.onFrame(.push_promise, false));
}

test "an unknown frame on a request stream is stepped over wherever it appears" {
    var m: Message = .{};
    // RFC 9114 section 9: before the head, after it, and after the
    // trailers.
    try testing.expectEqual(Disposition.skip, try m.onFrame(@enumFromInt(0x21), false));
    _ = try m.onFrame(.headers, false);
    try testing.expectEqual(Disposition.skip, try m.onFrame(@enumFromInt(0x22), false));
    _ = try m.onFrame(.headers, false);
    try testing.expectEqual(Disposition.skip, try m.onFrame(@enumFromInt(0x40), false));
}

test "a second onSettings is a protocol error and not a panic" {
    // `onControlFrame` refuses a second `SETTINGS` before the payload is
    // read, and this function is public, so the rule has to hold here as
    // well. A build with asserts stripped would otherwise take the second
    // payload and describe the peer by it.
    var c: Connection = .init(.client, .{});
    _ = try c.onControlFrame(.settings);
    try c.onSettings(&.{ 0x06, 0x44, 0x00 });
    try testing.expectEqual(@as(?u64, 0x400), c.peer_settings.?.max_field_section_size);

    try testing.expectError(error.FrameUnexpected, c.onSettings(&.{ 0x06, 0x44, 0x01 }));
    // The first payload is what still describes the peer.
    try testing.expectEqual(@as(?u64, 0x400), c.peer_settings.?.max_field_section_size);
}

test "a settings payload naming more pairs than the bound allows is excessive load and not malformed" {
    // RFC 9114 section 7.2.4.1 encourages reserved identifiers, so a long
    // pair list is legal traffic. The code must say this side stopped
    // reading and not that the peer wrote a bad frame.
    var payload: [3 * (settings.max_pairs + 1)]u8 = undefined;
    var index: usize = 0;
    while (index <= settings.max_pairs) : (index += 1) {
        const id: u64 = 0x100 + index;
        payload[index * 3] = @intCast(0x40 | (id >> 8));
        payload[index * 3 + 1] = @intCast(id & 0xff);
        payload[index * 3 + 2] = 0x00;
    }
    var c: Connection = .init(.client, .{});
    _ = try c.onControlFrame(.settings);
    try testing.expectError(error.ExcessiveLoad, c.onSettings(&payload));
}
