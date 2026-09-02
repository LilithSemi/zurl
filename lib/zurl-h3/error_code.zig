//! The HTTP/3 error codes of RFC 9114 section 8.1 and RFC 9204 section
//! 6, and the name each one carries.
//!
//! **These travel where RFC 9000 puts an application error code**: in a
//! `RESET_STREAM`, a `STOP_SENDING`, or an application `CONNECTION_CLOSE`
//! of type 0x1d. They are a different space from the transport codes of
//! `zurl_quic.transport_error`, and putting one in the other's frame tells
//! the peer something this side did not mean.

const std = @import("std");

/// The application error codes of HTTP/3.
pub const Code = enum(u64) {
    /// No error. This is used when the connection or stream needs to be
    /// closed but there is no error to signal. RFC 9114 section 8.1.
    no_error = 0x0100,
    general_protocol_error = 0x0101,
    internal_error = 0x0102,
    stream_creation_error = 0x0103,
    closed_critical_stream = 0x0104,
    frame_unexpected = 0x0105,
    frame_error = 0x0106,
    excessive_load = 0x0107,
    id_error = 0x0108,
    settings_error = 0x0109,
    missing_settings = 0x010a,
    request_rejected = 0x010b,
    request_cancelled = 0x010c,
    request_incomplete = 0x010d,
    message_error = 0x010e,
    connect_error = 0x010f,
    version_fallback = 0x0110,
    /// RFC 9204 section 6. The three QPACK codes share the HTTP/3 space.
    qpack_decompression_failed = 0x0200,
    qpack_encoder_stream_error = 0x0201,
    qpack_decoder_stream_error = 0x0202,
    _,

    /// The name RFC 9114 table 5 and RFC 9204 section 6 give the code, or
    /// `"UNKNOWN"` for a number outside both.
    ///
    /// A number outside them is legal: RFC 9114 section 8.1 reserves
    /// `0x1f * N + 0x21` for a peer to send on purpose, so a client that
    /// refused one would refuse a conformant peer.
    pub fn name(self: Code) []const u8 {
        return switch (self) {
            .no_error => "H3_NO_ERROR",
            .general_protocol_error => "H3_GENERAL_PROTOCOL_ERROR",
            .internal_error => "H3_INTERNAL_ERROR",
            .stream_creation_error => "H3_STREAM_CREATION_ERROR",
            .closed_critical_stream => "H3_CLOSED_CRITICAL_STREAM",
            .frame_unexpected => "H3_FRAME_UNEXPECTED",
            .frame_error => "H3_FRAME_ERROR",
            .excessive_load => "H3_EXCESSIVE_LOAD",
            .id_error => "H3_ID_ERROR",
            .settings_error => "H3_SETTINGS_ERROR",
            .missing_settings => "H3_MISSING_SETTINGS",
            .request_rejected => "H3_REQUEST_REJECTED",
            .request_cancelled => "H3_REQUEST_CANCELLED",
            .request_incomplete => "H3_REQUEST_INCOMPLETE",
            .message_error => "H3_MESSAGE_ERROR",
            .connect_error => "H3_CONNECT_ERROR",
            .version_fallback => "H3_VERSION_FALLBACK",
            .qpack_decompression_failed => "QPACK_DECOMPRESSION_FAILED",
            .qpack_encoder_stream_error => "QPACK_ENCODER_STREAM_ERROR",
            .qpack_decoder_stream_error => "QPACK_DECODER_STREAM_ERROR",
            _ => if (isReserved(@intFromEnum(self))) "RESERVED" else "UNKNOWN",
        };
    }
};

/// Whether `value` is one of the codes RFC 9114 section 8.1 reserves for
/// a peer to send on purpose, to check that this side ignores them.
///
/// The pattern is `0x1f * N + 0x21`, which is the same one RFC 9114 uses
/// for a reserved frame type and a reserved setting identifier.
pub fn isReserved(value: u64) bool {
    if (value < 0x21) return false;
    return (value - 0x21) % 0x1f == 0;
}

const testing = std.testing;

test "every code RFC 9114 table 5 lists has the number the table gives it" {
    try testing.expectEqual(@as(u64, 0x0100), @intFromEnum(Code.no_error));
    try testing.expectEqual(@as(u64, 0x0105), @intFromEnum(Code.frame_unexpected));
    try testing.expectEqual(@as(u64, 0x0109), @intFromEnum(Code.settings_error));
    try testing.expectEqual(@as(u64, 0x010a), @intFromEnum(Code.missing_settings));
    try testing.expectEqual(@as(u64, 0x010e), @intFromEnum(Code.message_error));
    try testing.expectEqual(@as(u64, 0x0110), @intFromEnum(Code.version_fallback));
    try testing.expectEqualStrings("H3_MISSING_SETTINGS", Code.missing_settings.name());
}

test "the three QPACK codes share the HTTP/3 space" {
    // RFC 9204 section 6 puts them at 0x0200, which is outside the
    // 0x0100 block RFC 9114 uses and inside the same application code
    // space.
    try testing.expectEqual(@as(u64, 0x0200), @intFromEnum(Code.qpack_decompression_failed));
    try testing.expectEqual(@as(u64, 0x0202), @intFromEnum(Code.qpack_decoder_stream_error));
    try testing.expectEqualStrings("QPACK_ENCODER_STREAM_ERROR", Code.qpack_encoder_stream_error.name());
}

test "the reserved pattern names the numbers RFC 9114 says it does" {
    // 0x1f * N + 0x21 for N of 0, 1, 2.
    try testing.expect(isReserved(0x21));
    try testing.expect(isReserved(0x40));
    try testing.expect(isReserved(0x5f));
    try testing.expect(!isReserved(0x22));
    try testing.expect(!isReserved(0x00));
    try testing.expect(!isReserved(0x20));
    try testing.expectEqualStrings("RESERVED", @as(Code, @enumFromInt(0x21)).name());
    try testing.expectEqualStrings("UNKNOWN", @as(Code, @enumFromInt(0x22)).name());
}
