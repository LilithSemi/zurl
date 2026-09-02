//! The transport layer message numbers of RFC 4253, and the four messages
//! a transport must answer on its own.
//!
//! **A message number off the wire is an untrusted integer.** `Id` is a
//! non-exhaustive enum for that reason, and `idOf` uses
//! `std.enums.fromInt`. A `@enumFromInt` on a byte the peer chose is
//! undefined behaviour for every value this build does not name, and a
//! peer can write all 256 of them.
//!
//! What this module owns: the numbers, and the parsers for `DISCONNECT`,
//! `IGNORE`, `DEBUG`, and `UNIMPLEMENTED`. Those four are the messages
//! that may arrive at any moment and that no layer above the transport
//! asked for. RFC 4253 section 11 says a receiver must accept them at any
//! time.
//!
//! What this module does not own: no framing, and no key exchange. The
//! `KEXINIT` body lives in `zurl_ssh.kex`.

const std = @import("std");

const wire = @import("wire.zig");

/// The message numbers this transport knows, RFC 4250 section 4.1.2.
///
/// Non-exhaustive, because the peer writes this byte. A number this build
/// does not name is not a fault by itself: RFC 4253 section 11.4 says an
/// unknown message must be answered with `UNIMPLEMENTED` and the
/// connection must carry on.
pub const Id = enum(u8) {
    disconnect = 1,
    ignore = 2,
    unimplemented = 3,
    debug = 4,
    service_request = 5,
    service_accept = 6,
    /// RFC 8308 section 2. This transport never sends one and answers one
    /// by ignoring it.
    ext_info = 7,
    kexinit = 20,
    newkeys = 21,
    /// RFC 5656 section 7.1, used by `curve25519-sha256` as RFC 8731
    /// section 3 describes. The number is shared with every other key
    /// exchange method, so it only means this while that method is the
    /// one in progress.
    kex_ecdh_init = 30,
    /// RFC 5656 section 7.1.
    kex_ecdh_reply = 31,
    _,
};

/// The message number at the front of `payload`, or null for an empty
/// payload.
///
/// An empty payload is not a message. RFC 4253 section 6 puts the number
/// in the first byte, so a payload of zero bytes carries no message at
/// all.
pub fn idOf(payload: []const u8) ?Id {
    if (payload.len == 0) return null;
    return @enumFromInt(payload[0]);
}

/// Whether the transport answers this message itself.
///
/// The four here arrive at any time and belong to no request. A layer
/// above the transport never sees one.
pub fn isTransportHousekeeping(id: Id) bool {
    return switch (id) {
        .ignore, .debug, .unimplemented, .ext_info => true,
        else => false,
    };
}

/// Why a peer ended the connection, RFC 4250 section 4.2.2.
///
/// Non-exhaustive, because the peer writes this number and RFC 4250
/// section 4.2.4 lets a private range carry values this build does not
/// name.
pub const DisconnectReason = enum(u32) {
    host_not_allowed_to_connect = 1,
    protocol_error = 2,
    key_exchange_failed = 3,
    reserved = 4,
    mac_error = 5,
    compression_error = 6,
    service_not_available = 7,
    protocol_version_not_supported = 8,
    host_key_not_verifiable = 9,
    connection_lost = 10,
    by_application = 11,
    too_many_connections = 12,
    auth_cancelled_by_user = 13,
    no_more_auth_methods_available = 14,
    illegal_user_name = 15,
    _,
};

/// Why a parse of one of these messages stopped.
pub const ParseError = wire.ReadError || error{
    /// The message number at the front is not the one asked for.
    WrongMessage,
};

/// What a `SSH_MSG_DISCONNECT` carries, RFC 4253 section 11.1.
///
/// The two slices point into the payload they were read from.
///
/// **The description is untrusted text.** It comes from the peer, it can
/// hold any byte, and a caller that shows it to a person must make it
/// safe first.
pub const Disconnect = struct {
    reason: DisconnectReason,
    description: []const u8,
    language: []const u8,
};

/// Reads a `SSH_MSG_DISCONNECT`.
pub fn parseDisconnect(payload: []const u8) ParseError!Disconnect {
    var r: wire.Reader = .init(payload);
    if (try r.byte() != @intFromEnum(Id.disconnect)) return error.WrongMessage;
    return .{
        .reason = @enumFromInt(try r.uint32()),
        .description = try r.string(),
        // RFC 4253 section 11.1 puts a language tag last. Some servers
        // leave it off, so a payload that ends here reads as an empty tag
        // rather than as a fault. A tag that starts and then stops short
        // is still `error.Truncated`.
        .language = if (r.atEnd()) "" else try r.string(),
    };
}

/// What a `SSH_MSG_DEBUG` carries, RFC 4253 section 11.3.
///
/// **The message is untrusted text**, for the reason `Disconnect` gives.
pub const Debug = struct {
    always_display: bool,
    message: []const u8,
    language: []const u8,
};

/// Reads a `SSH_MSG_DEBUG`.
pub fn parseDebug(payload: []const u8) ParseError!Debug {
    var r: wire.Reader = .init(payload);
    if (try r.byte() != @intFromEnum(Id.debug)) return error.WrongMessage;
    return .{
        .always_display = try r.boolean(),
        .message = try r.string(),
        .language = if (r.atEnd()) "" else try r.string(),
    };
}

/// Reads a `SSH_MSG_UNIMPLEMENTED`, and returns the sequence number of the
/// packet the peer did not understand, RFC 4253 section 11.4.
pub fn parseUnimplemented(payload: []const u8) ParseError!u32 {
    var r: wire.Reader = .init(payload);
    if (try r.byte() != @intFromEnum(Id.unimplemented)) return error.WrongMessage;
    return r.uint32();
}

/// Builds a `SSH_MSG_DISCONNECT` into `out`.
///
/// The language tag is empty, which RFC 4253 section 11.1 allows.
pub fn writeDisconnect(
    out: []u8,
    reason: DisconnectReason,
    description: []const u8,
) wire.WriteError![]u8 {
    var w: wire.Writer = .init(out);
    try w.byte(@intFromEnum(Id.disconnect));
    try w.uint32(@intFromEnum(reason));
    try w.string(description);
    try w.string("");
    return w.written();
}

/// Builds a `SSH_MSG_UNIMPLEMENTED` for the packet numbered `sequence`.
pub fn writeUnimplemented(out: []u8, sequence: u32) wire.WriteError![]u8 {
    var w: wire.Writer = .init(out);
    try w.byte(@intFromEnum(Id.unimplemented));
    try w.uint32(sequence);
    return w.written();
}

const testing = std.testing;

test "a message number the peer invented is read and never used as a tag" {
    // **`@enumFromInt` on a non-exhaustive enum is defined for every
    // value.** The switch below must therefore have an else arm, and the
    // peer can reach it with any of the numbers this build does not name.
    const id = idOf(&.{0xfe}).?;
    try testing.expectEqual(@as(u8, 0xfe), @intFromEnum(id));
    try testing.expect(!isTransportHousekeeping(id));
    try testing.expectEqual(@as(?Id, null), idOf(""));
    try testing.expectEqual(Id.kexinit, idOf(&.{ 20, 1, 2 }).?);
}

test "a DISCONNECT reads its reason and its description" {
    const payload =
        "\x01" ++
        "\x00\x00\x00\x0b" ++
        "\x00\x00\x00\x07goodbye" ++
        "\x00\x00\x00\x02en";
    const message = try parseDisconnect(payload);
    try testing.expectEqual(DisconnectReason.by_application, message.reason);
    try testing.expectEqualStrings("goodbye", message.description);
    try testing.expectEqualStrings("en", message.language);
}

test "a DISCONNECT with a reason nobody named still reads" {
    const payload = "\x01\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00";
    const message = try parseDisconnect(payload);
    try testing.expectEqual(@as(u32, 0xffff), @intFromEnum(message.reason));
    try testing.expectEqualStrings("", message.description);
}

test "a DISCONNECT with no language tag reads, because some servers send none" {
    const payload = "\x01\x00\x00\x00\x02\x00\x00\x00\x03bye";
    const message = try parseDisconnect(payload);
    try testing.expectEqual(DisconnectReason.protocol_error, message.reason);
    try testing.expectEqualStrings("bye", message.description);
    try testing.expectEqualStrings("", message.language);
}

test "a truncated DISCONNECT is a fault and never a short read" {
    try testing.expectError(error.Truncated, parseDisconnect("\x01\x00\x00"));
    try testing.expectError(error.LengthOutOfRange, parseDisconnect("\x01\x00\x00\x00\x02\x00\x00\x00\x09ab"));
    try testing.expectError(error.WrongMessage, parseDisconnect("\x02\x00\x00\x00\x02"));
    try testing.expectError(error.Truncated, parseDisconnect(""));
}

test "a DEBUG reads its flag and its message" {
    const payload = "\x04\x01\x00\x00\x00\x04text\x00\x00\x00\x00";
    const message = try parseDebug(payload);
    try testing.expectEqual(true, message.always_display);
    try testing.expectEqualStrings("text", message.message);
    try testing.expectError(error.WrongMessage, parseDebug("\x03\x01"));
}

test "an UNIMPLEMENTED names the packet it answers" {
    try testing.expectEqual(@as(u32, 7), try parseUnimplemented("\x03\x00\x00\x00\x07"));
    try testing.expectError(error.Truncated, parseUnimplemented("\x03\x00"));
    try testing.expectError(error.WrongMessage, parseUnimplemented("\x04\x00\x00\x00\x07"));
}

test "the two builders write what their parsers read" {
    var storage: [64]u8 = undefined;
    const built = try writeDisconnect(&storage, .by_application, "done");
    const parsed = try parseDisconnect(built);
    try testing.expectEqual(DisconnectReason.by_application, parsed.reason);
    try testing.expectEqualStrings("done", parsed.description);
    try testing.expectEqualStrings("", parsed.language);

    const answer = try writeUnimplemented(&storage, 42);
    try testing.expectEqual(@as(u32, 42), try parseUnimplemented(answer));
}

test "IGNORE, DEBUG, UNIMPLEMENTED, and EXT_INFO are the transport's own" {
    try testing.expect(isTransportHousekeeping(.ignore));
    try testing.expect(isTransportHousekeeping(.debug));
    try testing.expect(isTransportHousekeeping(.unimplemented));
    try testing.expect(isTransportHousekeeping(.ext_info));
    // A `DISCONNECT` ends the session, so it is not housekeeping. A
    // `KEXINIT` starts a rekey, which the transport runs but which a
    // caller must not be told is nothing.
    try testing.expect(!isTransportHousekeeping(.disconnect));
    try testing.expect(!isTransportHousekeeping(.kexinit));
}
