//! The close frame's payload, RFC 6455 section 5.5.1 and section 7.4.
//!
//! **A close frame is the one place a peer writes text that zurl may show
//! a person.** The payload holds a two octet status code and then a reason
//! in UTF-8, and both come from the peer. So both are bounded and both are
//! cleaned here, before either can reach a message, a terminal, or a log:
//!
//! - **The code is checked against RFC 6455 section 7.4.** A code under
//!   1000, and the codes the RFC says must never travel, are refused. A
//!   peer that writes 1006 is claiming a closure that by definition never
//!   arrives on the wire, so reading it back would let a peer forge the
//!   reason a transfer ended.
//! - **A payload of exactly one octet is refused.** A status code is two
//!   octets, so one octet is neither a code nor an absent one.
//! - **The reason is cut to `max_reason_bytes` and every byte outside
//!   printable ASCII becomes `?`.** A raw escape moves a terminal's
//!   cursor and paints colour, a raw newline draws a second line that
//!   reads like one of zurl's own, and an unbounded reason turns one line
//!   into megabytes. `src/cli/safe.zig` keeps the same rule for the
//!   command line, and this is that rule at the point the bytes come off
//!   the wire, so no path from this payload to an output can miss it.
//!
//! This module reads bytes and writes bytes. It opens nothing.

const std = @import("std");

const frame = @import("frame.zig");

/// How many octets of a peer's reason this keeps.
///
/// A close payload is at most 125 octets, of which two are the code, so
/// 123 is the whole reason a peer can send. The bound is written down all
/// the same, because it is the bound a reader of `Parsed.reason` may rely
/// on and not a number that follows from somewhere else.
pub const max_reason_bytes: usize = frame.max_control_payload_bytes - 2;

/// The status code a client sends for an ordinary close, RFC 6455 section
/// 7.4.1.
pub const normal: u16 = 1000;

/// What a close frame said.
pub const Parsed = struct {
    /// The code the peer wrote, or null when the payload was empty.
    ///
    /// An empty payload is legal and means the peer named no reason. RFC
    /// 6455 section 7.1.5 says an endpoint then treats the code as 1005,
    /// which is a value that never travels, so this reports null rather
    /// than invent a number the peer did not write.
    code: ?u16,
    /// The reason, cut to `max_reason_bytes` and with every byte outside
    /// printable ASCII replaced by `?`. Points into the caller's storage.
    reason: []const u8,
    /// Whether the reason lost a tail to the bound.
    truncated: bool,
};

/// Why a close payload could not be read.
pub const ParseError = error{
    /// The payload holds exactly one octet, which is neither a status code
    /// nor an absent one.
    ShortPayload,
    /// The code is one RFC 6455 section 7.4.1 does not allow on the wire.
    ReservedCode,
};

/// Whether `code` is one an endpoint may put in a close frame.
///
/// RFC 6455 section 7.4.1 and the IANA registry it opens:
///
/// - under 1000: not assigned at all.
/// - 1000 to 1003 and 1007 to 1011: the protocol's own codes.
/// - 1004, 1012 to 1014: not assigned.
/// - 1005, 1006, and 1015: **reserved and never sent**. Each names a
///   condition an endpoint works out for itself, so a peer that writes one
///   is telling a lie about how the connection ended.
/// - 3000 to 3999: registered with IANA by a library or a framework.
/// - 4000 to 4999: private, for one application's own use.
pub fn codeAllowed(code: u16) bool {
    return switch (code) {
        1000...1003, 1007...1011 => true,
        3000...4999 => true,
        else => false,
    };
}

/// Reads a close frame's payload.
///
/// `storage` receives the cleaned reason, and the `Parsed.reason` result
/// points into it. `payload` may be any length a control frame allows,
/// which is 125 octets or fewer, so `storage` never needs more than
/// `max_reason_bytes`.
pub fn parse(
    payload: []const u8,
    storage: *[max_reason_bytes]u8,
) ParseError!Parsed {
    if (payload.len == 0) {
        return .{ .code = null, .reason = storage[0..0], .truncated = false };
    }
    if (payload.len == 1) return error.ShortPayload;

    const code = std.mem.readInt(u16, payload[0..2], .big);
    if (!codeAllowed(code)) return error.ReservedCode;

    const raw = payload[2..];
    const kept = @min(raw.len, storage.len);
    for (raw[0..kept], 0..) |byte, i| {
        storage[i] = if (std.ascii.isPrint(byte)) byte else '?';
    }
    return .{
        .code = code,
        .reason = storage[0..kept],
        .truncated = kept < raw.len,
    };
}

/// Writes a close payload holding `code` and no reason into `out`.
///
/// zurl sends no reason of its own. A reason is text a peer would have to
/// read and show, and this client has nothing to say that the code does
/// not already say.
pub fn write(out: *[2]u8, code: u16) []const u8 {
    std.mem.writeInt(u16, out, code, .big);
    return out;
}

const testing = std.testing;

test "an empty payload names no code and no reason" {
    var storage: [max_reason_bytes]u8 = undefined;
    const parsed = try parse(&.{}, &storage);
    try testing.expectEqual(@as(?u16, null), parsed.code);
    try testing.expectEqualStrings("", parsed.reason);
}

test "a one octet payload is refused" {
    var storage: [max_reason_bytes]u8 = undefined;
    try testing.expectError(error.ShortPayload, parse(&.{0x03}, &storage));
}

test "the codes RFC 6455 allows read back and the rest are refused" {
    var storage: [max_reason_bytes]u8 = undefined;
    for ([_]u16{ 1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 3000, 3999, 4000, 4999 }) |code| {
        var payload: [2]u8 = undefined;
        std.mem.writeInt(u16, &payload, code, .big);
        const parsed = try parse(&payload, &storage);
        try testing.expectEqual(@as(?u16, code), parsed.code);
    }
    // 1005, 1006, and 1015 name conditions that never travel. A peer that
    // writes one is claiming a closure it cannot have observed.
    for ([_]u16{ 0, 999, 1004, 1005, 1006, 1012, 1013, 1014, 1015, 2999, 5000, 65535 }) |code| {
        var payload: [2]u8 = undefined;
        std.mem.writeInt(u16, &payload, code, .big);
        try testing.expectError(error.ReservedCode, parse(&payload, &storage));
    }
}

test "a reason reaches the caller with its control bytes gone" {
    var storage: [max_reason_bytes]u8 = undefined;
    const payload = "\x03\xe8" ++ "bye\x1b[31m\nzurl: forged\x07";
    const parsed = try parse(payload, &storage);
    try testing.expectEqual(@as(?u16, 1000), parsed.code);
    try testing.expectEqualStrings("bye?[31m?zurl: forged?", parsed.reason);
    try testing.expect(!parsed.truncated);
}

test "a reason at the bound is whole and one past it is marked" {
    var storage: [max_reason_bytes]u8 = undefined;

    var at_bound: [2 + max_reason_bytes]u8 = undefined;
    std.mem.writeInt(u16, at_bound[0..2], normal, .big);
    @memset(at_bound[2..], 'Q');
    const whole = try parse(&at_bound, &storage);
    try testing.expectEqual(max_reason_bytes, whole.reason.len);
    try testing.expect(!whole.truncated);

    // A control frame cannot carry more than 125 octets, so this shape
    // never arrives from a conforming peer. The bound is kept all the
    // same: a reader of `reason` relies on it, and a caller that passed a
    // longer slice must not be able to write past the storage.
    var past: [2 + max_reason_bytes + 10]u8 = undefined;
    std.mem.writeInt(u16, past[0..2], normal, .big);
    @memset(past[2..], 'Q');
    const cut = try parse(&past, &storage);
    try testing.expectEqual(max_reason_bytes, cut.reason.len);
    try testing.expect(cut.truncated);
}

test "the written payload reads back as the code it holds" {
    var out: [2]u8 = undefined;
    const payload = write(&out, normal);
    var storage: [max_reason_bytes]u8 = undefined;
    const parsed = try parse(payload, &storage);
    try testing.expectEqual(@as(?u16, normal), parsed.code);
    try testing.expectEqualStrings("", parsed.reason);
}
