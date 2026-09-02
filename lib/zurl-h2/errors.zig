//! The HTTP/2 error codes, and what this build does with each fault it
//! finds in a frame. RFC 9113 section 7.
//!
//! This file owns two things. The first is `ErrorCode`, the 32-bit number
//! that goes on the wire in a `RST_STREAM` or a `GOAWAY`. The second is
//! `Error`, the Zig error set that every parse in this package returns,
//! and `classify`, which turns one of those errors into the code and the
//! scope a peer must be told.
//!
//! This file owns no I/O and no state. It knows nothing about a
//! connection, a stream table, or a window. It never decides to close
//! anything. It says what a fault is called and how bad it is, and the
//! engine above decides what to do.
//!
//! **Every fault here comes from the peer.** Not one of them is an
//! assertion. A malformed frame is a runtime fault, so each is a named
//! error with a code and a scope.

const std = @import("std");

/// The error codes of RFC 9113 section 7.
///
/// The enum is non-exhaustive because the registry can grow, and a
/// `GOAWAY` must keep the number the peer sent so a report can show it.
/// `normalise` maps an unknown code onto `.internal_error`, which is what
/// section 7 tells a receiver to do.
pub const ErrorCode = enum(u32) {
    no_error = 0x00,
    protocol_error = 0x01,
    internal_error = 0x02,
    flow_control_error = 0x03,
    settings_timeout = 0x04,
    stream_closed = 0x05,
    frame_size_error = 0x06,
    refused_stream = 0x07,
    cancel = 0x08,
    compression_error = 0x09,
    connect_error = 0x0a,
    enhance_your_calm = 0x0b,
    inadequate_security = 0x0c,
    http_1_1_required = 0x0d,
    _,

    /// The code as it goes on the wire.
    pub fn int(code: ErrorCode) u32 {
        return @intFromEnum(code);
    }

    /// Reads a code off the wire. Every 32-bit value is accepted, because
    /// section 7 says an unknown code must not change behaviour.
    pub fn fromInt(value: u32) ErrorCode {
        return @enumFromInt(value);
    }

    /// True when this build knows the code.
    pub fn isKnown(code: ErrorCode) bool {
        return name(code) != null;
    }

    /// The code the engine acts on. RFC 9113 section 7 says an unknown
    /// code may be handled as `INTERNAL_ERROR`, so this build does that.
    pub fn normalise(code: ErrorCode) ErrorCode {
        return if (name(code) == null) .internal_error else code;
    }

    /// The name from the registry, or null when this build does not know
    /// the code.
    pub fn name(code: ErrorCode) ?[]const u8 {
        return switch (code) {
            .no_error => "NO_ERROR",
            .protocol_error => "PROTOCOL_ERROR",
            .internal_error => "INTERNAL_ERROR",
            .flow_control_error => "FLOW_CONTROL_ERROR",
            .settings_timeout => "SETTINGS_TIMEOUT",
            .stream_closed => "STREAM_CLOSED",
            .frame_size_error => "FRAME_SIZE_ERROR",
            .refused_stream => "REFUSED_STREAM",
            .cancel => "CANCEL",
            .compression_error => "COMPRESSION_ERROR",
            .connect_error => "CONNECT_ERROR",
            .enhance_your_calm => "ENHANCE_YOUR_CALM",
            .inadequate_security => "INADEQUATE_SECURITY",
            .http_1_1_required => "HTTP_1_1_REQUIRED",
            _ => null,
        };
    }
};

/// How much of the connection a fault takes down. RFC 9113 section 5.4.
///
/// A stream error kills one stream with a `RST_STREAM` and leaves the
/// connection up. A connection error kills the whole connection with a
/// `GOAWAY`. The two are not interchangeable: a connection error handled
/// as a stream error leaves a peer that already broke the framing free to
/// keep sending.
pub const Scope = enum { stream, connection };

/// What a peer must be told about one fault.
pub const Fault = struct {
    code: ErrorCode,
    scope: Scope,
};

/// Every fault this package reports.
///
/// Each one names a rule of RFC 9113 that the peer broke. None of them is
/// a bug in this build, so none of them is an assertion.
pub const Error = error{
    /// A send asked for more octets than the flow control window holds.
    ///
    /// **This was an assert, and an assert is not a check in the build
    /// that ships.** `Window.consume` took the caller's word that the
    /// window held the octets, so in `ReleaseFast` and `ReleaseSmall`,
    /// where `std.debug.assert` is compiled out, a wrong count ran
    /// `available -= octets` past zero with nothing to stop it. The count
    /// is this build's own, so reaching this is a fault of zurl and not of
    /// a peer, which is why it reads as an error and never as a stream
    /// error sent to the other side.
    FlowControlExceeded,
    /// The length field is above the `SETTINGS_MAX_FRAME_SIZE` this build
    /// told the peer about. RFC 9113 section 4.2.
    FrameTooLarge,
    /// The payload is shorter than the fields the frame type must carry.
    PayloadTruncated,
    /// A frame that belongs to a stream arrived on stream 0.
    StreamIdZero,
    /// A frame that belongs to the connection arrived on a stream.
    StreamIdNonZero,
    /// The `Pad Length` field is the length of the payload or more, so
    /// the padding leaves no room for itself. RFC 9113 section 6.1.
    PadLengthTooLong,
    /// A `SETTINGS` payload is not a whole number of 6-octet entries.
    /// RFC 9113 section 6.5.
    SettingsLengthInvalid,
    /// A `SETTINGS` frame carries `ACK` and a payload. RFC 9113 section
    /// 6.5.
    SettingsAckNotEmpty,
    /// `SETTINGS_ENABLE_PUSH` is neither 0 nor 1. RFC 9113 section 6.5.2.
    SettingsEnablePushInvalid,
    /// `SETTINGS_INITIAL_WINDOW_SIZE` is above 2^31-1. RFC 9113 section
    /// 6.5.2.
    SettingsInitialWindowSizeInvalid,
    /// `SETTINGS_MAX_FRAME_SIZE` is outside 16384 to 16777215. RFC 9113
    /// section 6.5.2.
    SettingsMaxFrameSizeInvalid,
    /// A `PING` payload is not 8 octets. RFC 9113 section 6.7.
    PingLengthInvalid,
    /// A `RST_STREAM` payload is not 4 octets. RFC 9113 section 6.4.
    RstStreamLengthInvalid,
    /// A `PRIORITY` payload is not 5 octets. RFC 9113 section 6.3.
    PriorityLengthInvalid,
    /// A `GOAWAY` payload is shorter than 8 octets. RFC 9113 section 6.8.
    GoawayLengthInvalid,
    /// A `WINDOW_UPDATE` payload is not 4 octets. RFC 9113 section 6.9.
    WindowUpdateLengthInvalid,
    /// A `WINDOW_UPDATE` carries an increment of 0. RFC 9113 section 6.9.
    WindowUpdateZero,
    /// An increment takes a flow-control window above 2^31-1. RFC 9113
    /// section 6.9.1.
    WindowOverflow,
    /// A frame arrived while a header block was open, and it was not a
    /// `CONTINUATION`. RFC 9113 section 6.10.
    ContinuationExpected,
    /// A `CONTINUATION` arrived on a stream other than the one that has
    /// the open header block. RFC 9113 section 6.10.
    ContinuationStreamMismatch,
    /// A `CONTINUATION` arrived with no header block open. RFC 9113
    /// section 6.10.
    ContinuationUnexpected,
    /// The peer sent more `CONTINUATION` frames for one header block than
    /// this build accepts. See `continuation.limits`.
    ContinuationFlood,
    /// One header block grew past the octet bound this build accepts. See
    /// `continuation.limits`.
    HeaderBlockTooLarge,
    /// The client connection preface is not the 24 octets of RFC 9113
    /// section 3.4.
    BadPreface,
};

/// The code and the scope for one fault.
///
/// `stream_id` is the identifier the frame carried. Two faults change
/// scope with it: a flow-control fault on stream 0 is a connection error
/// and the same fault on a stream is a stream error, per RFC 9113 section
/// 6.9. Everything else has one scope whatever the stream.
pub fn classify(err: Error, stream_id: u31) Fault {
    return switch (err) {
        // RFC 9113 section 6.9. An increment of 0 or a window that runs
        // over is a stream error on a stream, and a connection error on
        // the connection window.
        error.WindowUpdateZero => .{
            .code = .protocol_error,
            .scope = if (stream_id == 0) .connection else .stream,
        },
        error.WindowOverflow => .{
            .code = .flow_control_error,
            .scope = if (stream_id == 0) .connection else .stream,
        },
        // **This one is this build's own fault and not the peer's.** A
        // send asked for more octets than the window held, and the count
        // came from this side. It is classified all the same, because a
        // caller that reaches `classify` has a fault to report and the
        // connection cannot go on either way. `internal_error` says whose
        // fault it is, which `flow_control_error` would not: that code
        // tells the peer it broke the rules.
        error.FlowControlExceeded => .{
            .code = .internal_error,
            .scope = if (stream_id == 0) .connection else .stream,
        },

        // RFC 9113 section 6.3. A PRIORITY of the wrong length takes down
        // one stream only, because the frame carries no connection state.
        error.PriorityLengthInvalid => .{ .code = .frame_size_error, .scope = .stream },

        error.FrameTooLarge,
        error.PayloadTruncated,
        error.SettingsLengthInvalid,
        error.SettingsAckNotEmpty,
        error.PingLengthInvalid,
        error.RstStreamLengthInvalid,
        error.GoawayLengthInvalid,
        error.WindowUpdateLengthInvalid,
        => .{ .code = .frame_size_error, .scope = .connection },

        error.StreamIdZero,
        error.StreamIdNonZero,
        error.PadLengthTooLong,
        error.SettingsEnablePushInvalid,
        error.SettingsMaxFrameSizeInvalid,
        error.ContinuationExpected,
        error.ContinuationStreamMismatch,
        error.ContinuationUnexpected,
        error.BadPreface,
        => .{ .code = .protocol_error, .scope = .connection },

        error.SettingsInitialWindowSizeInvalid => .{
            .code = .flow_control_error,
            .scope = .connection,
        },

        // RFC 9113 section 11.8 names ENHANCE_YOUR_CALM for a peer that
        // is using the protocol to make work. A header block with no end
        // is exactly that.
        error.ContinuationFlood,
        error.HeaderBlockTooLarge,
        => .{ .code = .enhance_your_calm, .scope = .connection },
    };
}

const testing = std.testing;

test "the error codes carry the numbers of RFC 9113 section 7" {
    try testing.expectEqual(@as(u32, 0x00), ErrorCode.no_error.int());
    try testing.expectEqual(@as(u32, 0x01), ErrorCode.protocol_error.int());
    try testing.expectEqual(@as(u32, 0x02), ErrorCode.internal_error.int());
    try testing.expectEqual(@as(u32, 0x03), ErrorCode.flow_control_error.int());
    try testing.expectEqual(@as(u32, 0x04), ErrorCode.settings_timeout.int());
    try testing.expectEqual(@as(u32, 0x05), ErrorCode.stream_closed.int());
    try testing.expectEqual(@as(u32, 0x06), ErrorCode.frame_size_error.int());
    try testing.expectEqual(@as(u32, 0x07), ErrorCode.refused_stream.int());
    try testing.expectEqual(@as(u32, 0x08), ErrorCode.cancel.int());
    try testing.expectEqual(@as(u32, 0x09), ErrorCode.compression_error.int());
    try testing.expectEqual(@as(u32, 0x0a), ErrorCode.connect_error.int());
    try testing.expectEqual(@as(u32, 0x0b), ErrorCode.enhance_your_calm.int());
    try testing.expectEqual(@as(u32, 0x0c), ErrorCode.inadequate_security.int());
    try testing.expectEqual(@as(u32, 0x0d), ErrorCode.http_1_1_required.int());
}

test "an unknown error code is kept, reported as unknown, and read as INTERNAL_ERROR" {
    const unknown = ErrorCode.fromInt(0xdead_beef);
    try testing.expectEqual(@as(u32, 0xdead_beef), unknown.int());
    try testing.expect(!unknown.isKnown());
    try testing.expectEqual(@as(?[]const u8, null), unknown.name());
    try testing.expectEqual(ErrorCode.internal_error, unknown.normalise());
}

test "a known error code keeps its own value through normalise" {
    try testing.expect(ErrorCode.refused_stream.isKnown());
    try testing.expectEqualStrings("REFUSED_STREAM", ErrorCode.refused_stream.name().?);
    try testing.expectEqual(ErrorCode.refused_stream, ErrorCode.refused_stream.normalise());
}

test "0x0e is the first code past the registry, so it is unknown" {
    try testing.expect(!ErrorCode.fromInt(0x0e).isKnown());
    try testing.expectEqual(ErrorCode.internal_error, ErrorCode.fromInt(0x0e).normalise());
}

test "a flow-control fault changes scope with the stream it arrived on" {
    try testing.expectEqual(Scope.connection, classify(error.WindowUpdateZero, 0).scope);
    try testing.expectEqual(Scope.stream, classify(error.WindowUpdateZero, 1).scope);
    try testing.expectEqual(Scope.connection, classify(error.WindowOverflow, 0).scope);
    try testing.expectEqual(Scope.stream, classify(error.WindowOverflow, 7).scope);

    try testing.expectEqual(ErrorCode.protocol_error, classify(error.WindowUpdateZero, 1).code);
    try testing.expectEqual(ErrorCode.flow_control_error, classify(error.WindowOverflow, 1).code);
}

test "a size fault is a connection error, and a bad PRIORITY length is not" {
    try testing.expectEqual(
        Fault{ .code = .frame_size_error, .scope = .connection },
        classify(error.FrameTooLarge, 3),
    );
    try testing.expectEqual(
        Fault{ .code = .frame_size_error, .scope = .stream },
        classify(error.PriorityLengthInvalid, 3),
    );
}

test "a header block with no end is ENHANCE_YOUR_CALM on the connection" {
    try testing.expectEqual(
        Fault{ .code = .enhance_your_calm, .scope = .connection },
        classify(error.ContinuationFlood, 1),
    );
    try testing.expectEqual(
        Fault{ .code = .enhance_your_calm, .scope = .connection },
        classify(error.HeaderBlockTooLarge, 1),
    );
}

test "every error in the set has a classification on stream 0 and on a stream" {
    // `classify` switches over `Error` with no `else`, so a new error
    // fails the build rather than falling into a default. This walks the
    // set anyway, to prove no arm returns a code this build does not
    // know.
    inline for (@typeInfo(Error).error_set.?) |e| {
        const err = @field(anyerror, e.name);
        for ([_]u31{ 0, 1 }) |stream_id| {
            const fault = classify(@errorCast(err), stream_id);
            try testing.expect(fault.code.isKnown());
        }
    }
}
