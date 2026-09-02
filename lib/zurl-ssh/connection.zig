//! The connection protocol messages of RFC 4254. Pure bytes, and testable
//! with a table.
//!
//! What this module owns: the message numbers of the connection layer, the
//! builders for every message this build sends, and the parsers for every
//! message it reads. Nothing here holds a socket, a window, or a channel.
//! `zurl_ssh.Channel` is the state machine that does.
//!
//! **Every number a parser returns came from the peer.** A window
//! increment, a maximum packet size, a data length, and an exit status are
//! all fields the far side chose. This module reads them and bounds none
//! of them, because a bound belongs where the value is used: `Channel`
//! checks a window against `max_window_bytes` and a packet size against
//! `max_peer_packet_bytes`, and a caller of `parseData` gets a slice that
//! `wire.Reader` already held inside the payload it came from.
//!
//! **A channel number is untrusted too.** RFC 4254 section 5 gives each
//! side its own numbering, so the "recipient channel" in a message the
//! peer sends is a number this side chose and the peer echoed. A message
//! naming any other number belongs to no channel this build opened, and
//! `Channel` refuses it rather than acting on it.

const std = @import("std");

const wire = @import("wire.zig");

/// The connection protocol message numbers, RFC 4250 section 4.1.2.
///
/// Non-exhaustive, because the peer writes this byte and RFC 4253 section
/// 11.4 says a number this build does not name must be answered with
/// `SSH_MSG_UNIMPLEMENTED` rather than ending the connection.
pub const Id = enum(u8) {
    global_request = 80,
    request_success = 81,
    request_failure = 82,
    channel_open = 90,
    channel_open_confirmation = 91,
    channel_open_failure = 92,
    channel_window_adjust = 93,
    channel_data = 94,
    channel_extended_data = 95,
    channel_eof = 96,
    channel_close = 97,
    channel_request = 98,
    channel_success = 99,
    channel_failure = 100,
    _,
};

/// The message number at the front of `payload`, or null for an empty
/// payload.
///
/// The same rule `zurl_ssh.messages.idOf` keeps, read as a connection
/// layer number. An empty payload is not a message.
pub fn idOf(payload: []const u8) ?Id {
    if (payload.len == 0) return null;
    return @enumFromInt(payload[0]);
}

/// Whether `id` belongs to the connection protocol.
///
/// RFC 4250 section 4.1.2 keeps 80 to 127 for it. A number in that range
/// that this build does not name is still the connection layer's, so the
/// answer is the range and not the enum's own member list.
pub fn isConnectionMessage(id: u8) bool {
    return id >= 80 and id <= 127;
}

/// Which stream an `SSH_MSG_CHANNEL_EXTENDED_DATA` carries, RFC 4254
/// section 5.2.
///
/// Non-exhaustive: the field is a `uint32` the peer writes, and only one
/// value has ever been assigned.
pub const ExtendedDataType = enum(u32) {
    /// The remote command's standard error.
    ///
    /// **This is not the body.** A transfer that mixed it into the body
    /// would write a warning from the far side into the file the user
    /// asked for.
    stderr = 1,
    _,
};

/// Why a peer would not open a channel, RFC 4254 section 5.1.
///
/// Non-exhaustive, because the field is a `uint32` and section 5.1 keeps a
/// private range above 0xFE000000.
pub const OpenFailureReason = enum(u32) {
    administratively_prohibited = 1,
    connect_failed = 2,
    unknown_channel_type = 3,
    resource_shortage = 4,
    _,

    /// A sentence for a reason this build knows, or null for one it does
    /// not.
    ///
    /// The peer also sends its own description, and that text is
    /// untrusted. This is zurl's own words for the number beside it.
    pub fn text(reason: OpenFailureReason) ?[]const u8 {
        return switch (reason) {
            .administratively_prohibited => "the server does not allow this channel type",
            .connect_failed => "the server could not make the connection the channel asked for",
            .unknown_channel_type => "the server does not know this channel type",
            .resource_shortage => "the server has no resources for another channel",
            _ => null,
        };
    }
};

/// The channel type this build opens. RFC 4254 section 6.1.
pub const session_channel_type = "session";

/// The request name that runs a command, RFC 4254 section 6.5.
pub const exec_request = "exec";

/// The request name that starts a subsystem, RFC 4254 section 6.5.
pub const subsystem_request = "subsystem";

/// The request name a server sends with a command's exit status, RFC 4254
/// section 6.10.
pub const exit_status_request = "exit-status";

/// The request name a server sends when a command died on a signal, RFC
/// 4254 section 6.10.
pub const exit_signal_request = "exit-signal";

/// Why a message could not be read.
pub const ParseError = wire.ReadError || error{
    /// The message number at the front is not the one asked for.
    WrongMessage,
    /// The message carried bytes after its last field. A peer that writes
    /// a longer message than the grammar has is not speaking this
    /// protocol, and a reader that ignored the tail would take whatever a
    /// later revision put there as nothing at all.
    TrailingBytes,
};

/// Why a message could not be built.
pub const BuildError = wire.WriteError;

/// The largest message a channel builder writes before its payload.
///
/// A `SSH_MSG_CHANNEL_REQUEST` for `subsystem` is the longest: one message
/// number, one channel number, the request name, the want-reply boolean,
/// and the subsystem name. 64 bytes covers every name this build sends,
/// and `Channel` keeps a buffer of exactly this size for the ones that
/// carry no caller data.
pub const max_control_bytes = 64;

/// Writes `SSH_MSG_CHANNEL_OPEN` for a session, RFC 4254 sections 5.1 and
/// 6.1.
pub fn writeOpenSession(
    out: []u8,
    sender_channel: u32,
    initial_window: u32,
    max_packet: u32,
) BuildError![]u8 {
    var w: wire.Writer = .init(out);
    try w.byte(@intFromEnum(Id.channel_open));
    try w.string(session_channel_type);
    try w.uint32(sender_channel);
    try w.uint32(initial_window);
    try w.uint32(max_packet);
    return w.written();
}

/// What a `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` carries, RFC 4254 section
/// 5.1.
pub const OpenConfirmation = struct {
    /// The number this side put in its `SSH_MSG_CHANNEL_OPEN`.
    recipient_channel: u32,
    /// The number the peer wants in every message this side sends about
    /// this channel.
    sender_channel: u32,
    /// How many bytes this side may send before the peer adjusts the
    /// window. **Untrusted.**
    initial_window: u32,
    /// The largest data payload the peer will take in one message.
    /// **Untrusted, and it can be zero**, which would let no byte through
    /// at all. `Channel` refuses that rather than looping forever.
    max_packet: u32,
};

/// Reads a `SSH_MSG_CHANNEL_OPEN_CONFIRMATION`.
pub fn parseOpenConfirmation(payload: []const u8) ParseError!OpenConfirmation {
    var r: wire.Reader = .init(payload);
    if (try r.byte() != @intFromEnum(Id.channel_open_confirmation)) return error.WrongMessage;
    const out: OpenConfirmation = .{
        .recipient_channel = try r.uint32(),
        .sender_channel = try r.uint32(),
        .initial_window = try r.uint32(),
        .max_packet = try r.uint32(),
    };
    // RFC 4254 section 5.1 lets a channel type add its own fields here.
    // `session` adds none, so anything left belongs to no grammar this
    // build asked for.
    if (!r.atEnd()) return error.TrailingBytes;
    return out;
}

/// What a `SSH_MSG_CHANNEL_OPEN_FAILURE` carries, RFC 4254 section 5.1.
pub const OpenFailure = struct {
    recipient_channel: u32,
    reason: OpenFailureReason,
    /// **Untrusted text.** It comes from the peer, it can hold any byte,
    /// and a caller that shows it to a person must make it safe first.
    description: []const u8,
    language: []const u8,
};

/// Reads a `SSH_MSG_CHANNEL_OPEN_FAILURE`.
pub fn parseOpenFailure(payload: []const u8) ParseError!OpenFailure {
    var r: wire.Reader = .init(payload);
    if (try r.byte() != @intFromEnum(Id.channel_open_failure)) return error.WrongMessage;
    const out: OpenFailure = .{
        .recipient_channel = try r.uint32(),
        .reason = @enumFromInt(try r.uint32()),
        .description = try r.string(),
        .language = try r.string(),
    };
    if (!r.atEnd()) return error.TrailingBytes;
    return out;
}

/// Writes `SSH_MSG_CHANNEL_DATA`, RFC 4254 section 5.2.
///
/// `out` must hold `9 + data.len`. The caller checked the peer's window
/// and the peer's maximum packet size before it got here; this writer
/// checks neither, because it has no channel to read them from.
pub fn writeData(out: []u8, recipient_channel: u32, data: []const u8) BuildError![]u8 {
    var w: wire.Writer = .init(out);
    try w.byte(@intFromEnum(Id.channel_data));
    try w.uint32(recipient_channel);
    try w.string(data);
    return w.written();
}

/// What a `SSH_MSG_CHANNEL_DATA` carries.
pub const Data = struct {
    recipient_channel: u32,
    /// Points into the payload it was read from.
    bytes: []const u8,
};

/// Reads a `SSH_MSG_CHANNEL_DATA`.
pub fn parseData(payload: []const u8) ParseError!Data {
    var r: wire.Reader = .init(payload);
    if (try r.byte() != @intFromEnum(Id.channel_data)) return error.WrongMessage;
    const out: Data = .{
        .recipient_channel = try r.uint32(),
        .bytes = try r.string(),
    };
    if (!r.atEnd()) return error.TrailingBytes;
    return out;
}

/// What a `SSH_MSG_CHANNEL_EXTENDED_DATA` carries, RFC 4254 section 5.2.
pub const ExtendedData = struct {
    recipient_channel: u32,
    /// Which stream. **This build takes `stderr` and nothing else into a
    /// diagnostic**, and every other value is counted and dropped.
    kind: ExtendedDataType,
    /// Points into the payload it was read from.
    bytes: []const u8,
};

/// Reads a `SSH_MSG_CHANNEL_EXTENDED_DATA`.
pub fn parseExtendedData(payload: []const u8) ParseError!ExtendedData {
    var r: wire.Reader = .init(payload);
    if (try r.byte() != @intFromEnum(Id.channel_extended_data)) return error.WrongMessage;
    const out: ExtendedData = .{
        .recipient_channel = try r.uint32(),
        .kind = @enumFromInt(try r.uint32()),
        .bytes = try r.string(),
    };
    if (!r.atEnd()) return error.TrailingBytes;
    return out;
}

/// Writes `SSH_MSG_CHANNEL_WINDOW_ADJUST`, RFC 4254 section 5.2.
pub fn writeWindowAdjust(out: []u8, recipient_channel: u32, add: u32) BuildError![]u8 {
    var w: wire.Writer = .init(out);
    try w.byte(@intFromEnum(Id.channel_window_adjust));
    try w.uint32(recipient_channel);
    try w.uint32(add);
    return w.written();
}

/// What a `SSH_MSG_CHANNEL_WINDOW_ADJUST` carries.
pub const WindowAdjust = struct {
    recipient_channel: u32,
    /// How many more bytes this side may send. **Untrusted**, and a sum
    /// that would pass 2^32-1 is a fault RFC 4254 section 5.2 leaves
    /// undefined. `Channel` treats it as one.
    add: u32,
};

/// Reads a `SSH_MSG_CHANNEL_WINDOW_ADJUST`.
pub fn parseWindowAdjust(payload: []const u8) ParseError!WindowAdjust {
    var r: wire.Reader = .init(payload);
    if (try r.byte() != @intFromEnum(Id.channel_window_adjust)) return error.WrongMessage;
    const out: WindowAdjust = .{
        .recipient_channel = try r.uint32(),
        .add = try r.uint32(),
    };
    if (!r.atEnd()) return error.TrailingBytes;
    return out;
}

/// Writes `SSH_MSG_CHANNEL_EOF`, RFC 4254 section 5.3.
///
/// It says this side will send no more data. It does not close the
/// channel, and the peer keeps sending after it.
pub fn writeEof(out: []u8, recipient_channel: u32) BuildError![]u8 {
    return writeChannelOnly(out, .channel_eof, recipient_channel);
}

/// Writes `SSH_MSG_CHANNEL_CLOSE`, RFC 4254 section 5.3.
pub fn writeClose(out: []u8, recipient_channel: u32) BuildError![]u8 {
    return writeChannelOnly(out, .channel_close, recipient_channel);
}

/// Writes `SSH_MSG_CHANNEL_FAILURE`, RFC 4254 section 5.4.
///
/// This build answers a server's `SSH_MSG_CHANNEL_REQUEST` that wants a
/// reply with this and never with a success: it runs no request the far
/// side can ask for.
pub fn writeChannelFailure(out: []u8, recipient_channel: u32) BuildError![]u8 {
    return writeChannelOnly(out, .channel_failure, recipient_channel);
}

/// Writes `SSH_MSG_REQUEST_FAILURE`, RFC 4254 section 4.
///
/// The answer to a `SSH_MSG_GLOBAL_REQUEST` that wants one. This build
/// grants no global request, and a server that asks for one and never
/// hears back waits for as long as it likes.
pub fn writeGlobalFailure(out: []u8) BuildError![]u8 {
    var w: wire.Writer = .init(out);
    try w.byte(@intFromEnum(Id.request_failure));
    return w.written();
}

fn writeChannelOnly(out: []u8, id: Id, recipient_channel: u32) BuildError![]u8 {
    var w: wire.Writer = .init(out);
    try w.byte(@intFromEnum(id));
    try w.uint32(recipient_channel);
    return w.written();
}

/// Reads the recipient channel out of any channel message.
///
/// RFC 4254 section 5.2 puts it in the same place in every one, straight
/// after the message number, so one reader answers for all of them. A
/// caller uses this to decide whether a message belongs to the channel it
/// holds **before** it parses the rest.
pub fn recipientChannelOf(payload: []const u8) ParseError!u32 {
    var r: wire.Reader = .init(payload);
    _ = try r.byte();
    return r.uint32();
}

/// Writes `SSH_MSG_CHANNEL_REQUEST` for `exec`, RFC 4254 section 6.5.
///
/// **`command` reaches a shell on the far side.** RFC 4254 section 6.5
/// says the server runs it "as if" typed at a shell, so every quoting rule
/// of that shell applies. This writer puts the bytes on the wire and
/// judges none of them: the escaping belongs to whoever builds the
/// command, and `zurl_scp` is the one caller in this repository that does.
pub fn writeExec(
    out: []u8,
    recipient_channel: u32,
    command: []const u8,
    want_reply: bool,
) BuildError![]u8 {
    return writeRequest(out, recipient_channel, exec_request, want_reply, command);
}

/// Writes `SSH_MSG_CHANNEL_REQUEST` for `subsystem`, RFC 4254 section 6.5.
///
/// A subsystem name is not a command line. The server looks it up in its
/// own `Subsystem` table and runs what that names, so nothing here reaches
/// a shell.
pub fn writeSubsystem(
    out: []u8,
    recipient_channel: u32,
    name: []const u8,
    want_reply: bool,
) BuildError![]u8 {
    return writeRequest(out, recipient_channel, subsystem_request, want_reply, name);
}

fn writeRequest(
    out: []u8,
    recipient_channel: u32,
    request: []const u8,
    want_reply: bool,
    argument: []const u8,
) BuildError![]u8 {
    var w: wire.Writer = .init(out);
    try w.byte(@intFromEnum(Id.channel_request));
    try w.uint32(recipient_channel);
    try w.string(request);
    try w.boolean(want_reply);
    try w.string(argument);
    return w.written();
}

/// The head of a `SSH_MSG_CHANNEL_REQUEST`, RFC 4254 section 5.4.
///
/// The fields after `want_reply` differ for every request name, so this
/// reads as far as the name and hands the rest back.
pub const RequestHead = struct {
    recipient_channel: u32,
    /// **Untrusted text**, and this build compares it against the two
    /// names it acts on and drops every other.
    request: []const u8,
    want_reply: bool,
    /// Whatever the request name puts after the boolean. Points into the
    /// payload it was read from.
    rest: []const u8,
};

/// Reads the head of a `SSH_MSG_CHANNEL_REQUEST`.
pub fn parseRequestHead(payload: []const u8) ParseError!RequestHead {
    var r: wire.Reader = .init(payload);
    if (try r.byte() != @intFromEnum(Id.channel_request)) return error.WrongMessage;
    return .{
        .recipient_channel = try r.uint32(),
        .request = try r.string(),
        .want_reply = try r.boolean(),
        .rest = r.rest(),
    };
}

/// Reads the `uint32` an `exit-status` request carries, RFC 4254 section
/// 6.10.
///
/// `rest` is `RequestHead.rest` for a request named `exit-status`.
pub fn parseExitStatus(rest: []const u8) ParseError!u32 {
    var r: wire.Reader = .init(rest);
    const status = try r.uint32();
    if (!r.atEnd()) return error.TrailingBytes;
    return status;
}

/// What an `exit-signal` request carries, RFC 4254 section 6.10.
pub const ExitSignal = struct {
    /// The signal name with no `SIG` in front of it, such as `TERM`.
    /// **Untrusted text.**
    name: []const u8,
    core_dumped: bool,
    /// **Untrusted text.**
    message: []const u8,
    language: []const u8,
};

/// Reads an `exit-signal` request body.
pub fn parseExitSignal(rest: []const u8) ParseError!ExitSignal {
    var r: wire.Reader = .init(rest);
    const out: ExitSignal = .{
        .name = try r.string(),
        .core_dumped = try r.boolean(),
        .message = try r.string(),
        .language = try r.string(),
    };
    if (!r.atEnd()) return error.TrailingBytes;
    return out;
}

/// The head of a `SSH_MSG_GLOBAL_REQUEST`, RFC 4254 section 4.
pub const GlobalRequestHead = struct {
    /// **Untrusted text.**
    request: []const u8,
    want_reply: bool,
};

/// Reads the head of a `SSH_MSG_GLOBAL_REQUEST`.
pub fn parseGlobalRequestHead(payload: []const u8) ParseError!GlobalRequestHead {
    var r: wire.Reader = .init(payload);
    if (try r.byte() != @intFromEnum(Id.global_request)) return error.WrongMessage;
    return .{
        .request = try r.string(),
        .want_reply = try r.boolean(),
    };
}

/// The head of a `SSH_MSG_CHANNEL_OPEN` the peer sent, RFC 4254 section
/// 5.1.
///
/// A server opens a channel for `forwarded-tcpip` and for `x11`, and this
/// build asked for neither. `Channel` reads this only so that it can
/// refuse the open by its sender channel number, which is the one field
/// the refusal needs.
pub const PeerOpenHead = struct {
    /// **Untrusted text.**
    channel_type: []const u8,
    /// The number to put in the `SSH_MSG_CHANNEL_OPEN_FAILURE`.
    sender_channel: u32,
};

/// Reads the head of a peer's `SSH_MSG_CHANNEL_OPEN`.
pub fn parsePeerOpenHead(payload: []const u8) ParseError!PeerOpenHead {
    var r: wire.Reader = .init(payload);
    if (try r.byte() != @intFromEnum(Id.channel_open)) return error.WrongMessage;
    return .{
        .channel_type = try r.string(),
        .sender_channel = try r.uint32(),
    };
}

/// Writes `SSH_MSG_CHANNEL_OPEN_FAILURE`, RFC 4254 section 5.1.
///
/// This build opens the channels it wants and takes none. A server that
/// offers one hears this, with `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`,
/// which is what OpenSSH's own client answers when no forwarding was
/// asked for.
pub fn writeOpenFailure(
    out: []u8,
    recipient_channel: u32,
    reason: OpenFailureReason,
    description: []const u8,
) BuildError![]u8 {
    var w: wire.Writer = .init(out);
    try w.byte(@intFromEnum(Id.channel_open_failure));
    try w.uint32(recipient_channel);
    try w.uint32(@intFromEnum(reason));
    try w.string(description);
    try w.string("");
    return w.written();
}

const testing = std.testing;

test "an open for a session carries the type, the number, the window, and the packet size" {
    var storage: [64]u8 = undefined;
    const built = try writeOpenSession(&storage, 0, 1 << 20, 32768);
    try testing.expectEqualSlices(u8, &.{
        90,
        0,
        0,
        0,
        7,
        's',
        'e',
        's',
        's',
        'i',
        'o',
        'n',
        0,
        0,
        0,
        0,
        0,
        0x10,
        0,
        0,
        0,
        0,
        128,
        0,
    }, built);
}

test "an open confirmation reads its four numbers and refuses a tail" {
    const good = [_]u8{
        91,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        7,
        0,
        0,
        0x80,
        0,
        0,
        0,
        0x40,
        0,
    };
    const parsed = try parseOpenConfirmation(&good);
    try testing.expectEqual(@as(u32, 0), parsed.recipient_channel);
    try testing.expectEqual(@as(u32, 7), parsed.sender_channel);
    try testing.expectEqual(@as(u32, 32768), parsed.initial_window);
    try testing.expectEqual(@as(u32, 16384), parsed.max_packet);

    // **A tail is a refusal and never a tolerance.** `session` adds no
    // field of its own, so a byte after the last one belongs to a grammar
    // this build did not agree to.
    const trailing = good ++ [_]u8{0};
    try testing.expectError(error.TrailingBytes, parseOpenConfirmation(&trailing));

    // And a message cut short is `Truncated` and not a zero.
    try testing.expectError(error.Truncated, parseOpenConfirmation(good[0 .. good.len - 1]));
}

test "an open failure keeps its reason and its untrusted description" {
    const payload = [_]u8{
        92,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        3,
        0,
        0,
        0,
        2,
        'n',
        'o',
        0,
        0,
        0,
        0,
    };
    const parsed = try parseOpenFailure(&payload);
    try testing.expectEqual(OpenFailureReason.unknown_channel_type, parsed.reason);
    try testing.expectEqualStrings("no", parsed.description);
    try testing.expectEqualStrings("", parsed.language);
    try testing.expectEqualStrings(
        "the server does not know this channel type",
        OpenFailureReason.text(parsed.reason).?,
    );

    // A number RFC 4254 does not assign parses and has no sentence of
    // zurl's own. It is not a fault: section 5.1 keeps a private range.
    const private: OpenFailureReason = @enumFromInt(0xFE000001);
    try testing.expectEqual(@as(?[]const u8, null), private.text());
}

test "data and extended data are two different messages and only one is the body" {
    var storage: [32]u8 = undefined;
    const built = try writeData(&storage, 3, "hi");
    try testing.expectEqualSlices(u8, &.{ 94, 0, 0, 0, 3, 0, 0, 0, 2, 'h', 'i' }, built);

    const parsed = try parseData(built);
    try testing.expectEqual(@as(u32, 3), parsed.recipient_channel);
    try testing.expectEqualStrings("hi", parsed.bytes);

    // The same bytes under message 95 are stderr and carry a type in
    // front of the string. A reader that took one for the other would
    // write a remote warning into the file the user asked for.
    const extended = [_]u8{ 95, 0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 2, 'h', 'i' };
    try testing.expectError(error.WrongMessage, parseData(&extended));
    const stderr = try parseExtendedData(&extended);
    try testing.expectEqual(ExtendedDataType.stderr, stderr.kind);
    try testing.expectEqualStrings("hi", stderr.bytes);
    try testing.expectError(error.WrongMessage, parseExtendedData(built));
}

test "a string length that the payload cannot back is a refusal and never a read" {
    // The length says 4096 and the payload holds two bytes. `wire.Reader`
    // checks the claim before it takes a byte, so this costs one
    // comparison.
    const payload = [_]u8{ 94, 0, 0, 0, 0, 0, 0, 0x10, 0, 'h', 'i' };
    try testing.expectError(error.LengthOutOfRange, parseData(&payload));
}

test "every channel message names its channel in the same place" {
    var storage: [16]u8 = undefined;
    try testing.expectEqual(@as(u32, 9), try recipientChannelOf(try writeEof(&storage, 9)));
    try testing.expectEqual(@as(u32, 9), try recipientChannelOf(try writeClose(&storage, 9)));
    try testing.expectEqual(
        @as(u32, 9),
        try recipientChannelOf(try writeWindowAdjust(&storage, 9, 1)),
    );
    try testing.expectEqual(
        @as(u32, 9),
        try recipientChannelOf(try writeChannelFailure(&storage, 9)),
    );
}

test "eof and close are two different messages" {
    var storage: [16]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 96, 0, 0, 0, 1 }, try writeEof(&storage, 1));
    var second: [16]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 97, 0, 0, 0, 1 }, try writeClose(&second, 1));
}

test "exec and subsystem differ only in the request name" {
    var exec_storage: [64]u8 = undefined;
    const exec = try writeExec(&exec_storage, 0, "scp -pf 'a'", true);
    var subsystem_storage: [64]u8 = undefined;
    const subsystem = try writeSubsystem(&subsystem_storage, 0, "sftp", true);

    const exec_head = try parseRequestHead(exec);
    try testing.expectEqualStrings("exec", exec_head.request);
    try testing.expect(exec_head.want_reply);

    const subsystem_head = try parseRequestHead(subsystem);
    try testing.expectEqualStrings("subsystem", subsystem_head.request);

    // The argument of each is a string, so the shell metacharacters in
    // the exec command are carried whole and are not the wire format's
    // problem.
    var r: wire.Reader = .init(exec_head.rest);
    try testing.expectEqualStrings("scp -pf 'a'", try r.string());
}

test "an exit status is one number and a tail after it is a refusal" {
    try testing.expectEqual(@as(u32, 0), try parseExitStatus(&.{ 0, 0, 0, 0 }));
    try testing.expectEqual(@as(u32, 127), try parseExitStatus(&.{ 0, 0, 0, 127 }));
    try testing.expectError(error.TrailingBytes, parseExitStatus(&.{ 0, 0, 0, 1, 0 }));
    try testing.expectError(error.Truncated, parseExitStatus(&.{ 0, 0, 0 }));
}

test "an exit signal names the signal and never a status" {
    const rest = [_]u8{
        0,   0,   0,   4,
        'T', 'E', 'R', 'M',
        0,   0,   0,   0,
        3,   'b', 'y', 'e',
        0,   0,   0,   0,
    };
    const parsed = try parseExitSignal(&rest);
    try testing.expectEqualStrings("TERM", parsed.name);
    try testing.expect(!parsed.core_dumped);
    try testing.expectEqualStrings("bye", parsed.message);
}

test "the connection message range is the range and not this build's member list" {
    // 80 to 127, RFC 4250 section 4.1.2. A number in it that this build
    // does not name still belongs to the connection layer, so a `Channel`
    // answers it with `SSH_MSG_UNIMPLEMENTED` rather than taking it for a
    // transport message.
    try testing.expect(!isConnectionMessage(79));
    try testing.expect(isConnectionMessage(80));
    try testing.expect(isConnectionMessage(101));
    try testing.expect(isConnectionMessage(127));
    try testing.expect(!isConnectionMessage(128));
}

test "a global request head reads the name and the boolean" {
    const payload = [_]u8{
        80,
        0,
        0,
        0,
        12,
        'h',
        'o',
        's',
        't',
        'k',
        'e',
        'y',
        's',
        '-',
        '0',
        '0',
        '@',
        1,
        0,
        0,
        0,
        0,
    };
    const head = try parseGlobalRequestHead(&payload);
    try testing.expectEqualStrings("hostkeys-00@", head.request);
    try testing.expect(head.want_reply);

    var storage: [8]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{82}, try writeGlobalFailure(&storage));
}

test "a peer's channel open is read only far enough to refuse it" {
    const payload = [_]u8{
        90,
        0,
        0,
        0,
        4,
        'x',
        '1',
        '1',
        ' ',
        0,
        0,
        0,
        5,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    };
    const head = try parsePeerOpenHead(&payload);
    try testing.expectEqualStrings("x11 ", head.channel_type);
    try testing.expectEqual(@as(u32, 5), head.sender_channel);

    var storage: [64]u8 = undefined;
    const refusal = try writeOpenFailure(
        &storage,
        head.sender_channel,
        .administratively_prohibited,
        "no",
    );
    const parsed = try parseOpenFailure(refusal);
    try testing.expectEqual(@as(u32, 5), parsed.recipient_channel);
    try testing.expectEqual(OpenFailureReason.administratively_prohibited, parsed.reason);
}

test "a builder that runs out of room says so and never writes past the buffer" {
    var storage: [4]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, writeOpenSession(&storage, 0, 1, 1));
    try testing.expectError(error.NoSpaceLeft, writeData(&storage, 0, "abcdefgh"));
    try testing.expectError(error.NoSpaceLeft, writeSubsystem(&storage, 0, "sftp", true));
}

test "max_control_bytes holds every control message this build sends" {
    var storage: [max_control_bytes]u8 = undefined;
    _ = try writeOpenSession(&storage, 0, 1 << 21, 1 << 15);
    _ = try writeEof(&storage, std.math.maxInt(u32));
    _ = try writeClose(&storage, std.math.maxInt(u32));
    _ = try writeWindowAdjust(&storage, std.math.maxInt(u32), std.math.maxInt(u32));
    _ = try writeChannelFailure(&storage, std.math.maxInt(u32));
    _ = try writeGlobalFailure(&storage);
    _ = try writeSubsystem(&storage, 0, "sftp", true);
    _ = try writeOpenFailure(&storage, 0, .administratively_prohibited, "not asked for");
}
