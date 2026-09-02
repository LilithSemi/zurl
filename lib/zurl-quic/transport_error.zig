//! The transport error codes of RFC 9000 section 20.1, and the name each
//! one carries.
//!
//! **A `CONNECTION_CLOSE` frame carries one of these numbers, and the
//! number is what the peer acts on.** Sending 0x0a where 0x03 belongs
//! tells a peer that this side found a protocol violation when what it
//! really found was a window it had already given away, and a peer that
//! logs the two differently then logs the wrong one.
//!
//! The set is closed: RFC 9000 gives 0x00 to 0x10 and reserves 0x0100 to
//! 0x01ff for the TLS alerts, which `Code.fromAlert` builds.

const std = @import("std");

/// The transport error codes RFC 9000 section 20.1 defines.
pub const Code = enum(u64) {
    no_error = 0x00,
    internal_error = 0x01,
    connection_refused = 0x02,
    flow_control_error = 0x03,
    stream_limit_error = 0x04,
    stream_state_error = 0x05,
    final_size_error = 0x06,
    frame_encoding_error = 0x07,
    transport_parameter_error = 0x08,
    connection_id_limit_error = 0x09,
    protocol_violation = 0x0a,
    invalid_token = 0x0b,
    application_error = 0x0c,
    crypto_buffer_exceeded = 0x0d,
    key_update_error = 0x0e,
    aead_limit_reached = 0x0f,
    no_viable_path = 0x10,
    _,

    /// The first code of the range RFC 9000 section 20.1 reserves for a
    /// TLS alert.
    pub const crypto_error_first: u64 = 0x0100;

    /// The code that carries TLS alert `alert`. RFC 9000 section 20.1
    /// puts the alert description in the low byte.
    pub fn fromAlert(description: u8) Code {
        return @enumFromInt(crypto_error_first + description);
    }

    /// The TLS alert this code carries, or null for a code that carries
    /// none.
    pub fn alert(self: Code) ?u8 {
        const value = @intFromEnum(self);
        if (value < crypto_error_first or value > crypto_error_first + 0xff) return null;
        return @truncate(value - crypto_error_first);
    }

    /// The name RFC 9000 table 7 gives the code, or `"UNKNOWN"` for a
    /// number outside the table.
    ///
    /// A number outside the table is legal: section 20.1 leaves the rest
    /// of the space for later versions, and a peer may send one.
    pub fn name(self: Code) []const u8 {
        return switch (self) {
            .no_error => "NO_ERROR",
            .internal_error => "INTERNAL_ERROR",
            .connection_refused => "CONNECTION_REFUSED",
            .flow_control_error => "FLOW_CONTROL_ERROR",
            .stream_limit_error => "STREAM_LIMIT_ERROR",
            .stream_state_error => "STREAM_STATE_ERROR",
            .final_size_error => "FINAL_SIZE_ERROR",
            .frame_encoding_error => "FRAME_ENCODING_ERROR",
            .transport_parameter_error => "TRANSPORT_PARAMETER_ERROR",
            .connection_id_limit_error => "CONNECTION_ID_LIMIT_ERROR",
            .protocol_violation => "PROTOCOL_VIOLATION",
            .invalid_token => "INVALID_TOKEN",
            .application_error => "APPLICATION_ERROR",
            .crypto_buffer_exceeded => "CRYPTO_BUFFER_EXCEEDED",
            .key_update_error => "KEY_UPDATE_ERROR",
            .aead_limit_reached => "AEAD_LIMIT_REACHED",
            .no_viable_path => "NO_VIABLE_PATH",
            _ => if (self.alert() != null) "CRYPTO_ERROR" else "UNKNOWN",
        };
    }
};

const testing = std.testing;

test "every code RFC 9000 table 7 lists has the number the table gives it" {
    try testing.expectEqual(@as(u64, 0x00), @intFromEnum(Code.no_error));
    try testing.expectEqual(@as(u64, 0x03), @intFromEnum(Code.flow_control_error));
    try testing.expectEqual(@as(u64, 0x04), @intFromEnum(Code.stream_limit_error));
    try testing.expectEqual(@as(u64, 0x05), @intFromEnum(Code.stream_state_error));
    try testing.expectEqual(@as(u64, 0x06), @intFromEnum(Code.final_size_error));
    try testing.expectEqual(@as(u64, 0x0a), @intFromEnum(Code.protocol_violation));
    try testing.expectEqual(@as(u64, 0x10), @intFromEnum(Code.no_viable_path));
    try testing.expectEqualStrings("FLOW_CONTROL_ERROR", Code.flow_control_error.name());
}

test "a TLS alert travels in the reserved range and comes back out of it" {
    // RFC 9000 section 20.1: CRYPTO_ERROR is 0x0100 to 0x01ff, and the
    // low byte is the alert description.
    const bad_certificate: u8 = 42;
    const code: Code = .fromAlert(bad_certificate);
    try testing.expectEqual(@as(u64, 0x012a), @intFromEnum(code));
    try testing.expectEqual(@as(?u8, bad_certificate), code.alert());
    try testing.expectEqualStrings("CRYPTO_ERROR", code.name());

    try testing.expectEqual(@as(?u8, null), Code.protocol_violation.alert());
    try testing.expectEqual(@as(?u8, null), @as(Code, @enumFromInt(0x0200)).alert());
    try testing.expectEqualStrings("UNKNOWN", @as(Code, @enumFromInt(0x0200)).name());
}
