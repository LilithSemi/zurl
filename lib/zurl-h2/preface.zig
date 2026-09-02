//! The connection preface and the first `SETTINGS` exchange. RFC 9113
//! section 3.4.
//!
//! A client starts an HTTP/2 connection with 24 fixed octets, and then a
//! `SETTINGS` frame that may be empty. A server answers with its own
//! `SETTINGS` frame. Each side acknowledges what it got with a `SETTINGS`
//! frame that carries the `ACK` flag and nothing else.
//!
//! This file owns those octets and nothing more. It writes the preface,
//! it reads one back for a test, and it builds the three `SETTINGS`
//! frames the exchange needs. It does not wait for the peer, it does not
//! time an acknowledgement out, and it holds no connection. Section 3.4
//! lets a client send its first request before the server answers, and
//! whether to do that is the engine's decision, not this file's.

const std = @import("std");
const errors = @import("errors.zig");
const frame = @import("frame.zig");
const payload = @import("payload.zig");
const settings = @import("settings.zig");

const Error = errors.Error;

/// The 24 octets a client sends first. RFC 9113 section 3.4.
///
/// The string is the ASCII of a request line that no HTTP/1.1 server
/// answers, so a server that does not speak HTTP/2 fails the connection
/// rather than acting on it.
pub const client: []const u8 = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The octets of `client`.
pub const client_len: usize = 24;

/// The largest first flight this build writes: the preface, then a
/// `SETTINGS` frame carrying every parameter it knows.
pub const client_flight_len_max: usize = client_len + frame.header_len + settings.payload_len_max;

/// Writes the client preface.
pub fn writeClient(w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.writeAll(client);
}

/// Writes the client preface and the first `SETTINGS` frame.
///
/// The frame carries only the parameters of `wanted` that differ from the
/// RFC defaults, because a peer keeps its default for every parameter it
/// is not told about.
pub fn writeClientFlight(
    w: *std.Io.Writer,
    wanted: settings.Settings,
) std.Io.Writer.Error!void {
    try writeClient(w);

    var entries: [settings.payload_len_max]u8 = undefined;
    const changes = wanted.changesFrom(.initial);
    const frame_payload: payload.Settings = .{ .ack = false, .entries = changes.encode(&entries) };

    var out: [frame.header_len + settings.payload_len_max]u8 = undefined;
    try w.writeAll(frame_payload.encode(&out));
}

/// Writes a `SETTINGS` frame with the `ACK` flag. RFC 9113 section 6.5.
pub fn writeSettingsAck(w: *std.Io.Writer) std.Io.Writer.Error!void {
    var out: [frame.header_len]u8 = undefined;
    const frame_payload: payload.Settings = .{ .ack = true, .entries = &.{} };
    try w.writeAll(frame_payload.encode(&out));
}

/// Reads a client preface and checks it.
///
/// A client does not need this. It is here so a test, and later a server
/// side, can prove the octets this build writes are the octets the RFC
/// names, with no socket in the way.
pub fn readClient(r: *std.Io.Reader) (Error || std.Io.Reader.Error)!void {
    var got: [client_len]u8 = undefined;
    try r.readSliceAll(&got);
    if (!std.mem.eql(u8, &got, client)) return error.BadPreface;
}

const testing = std.testing;

test "the preface is the 24 octets of RFC 9113 section 3.4" {
    try testing.expectEqual(@as(usize, 24), client.len);
    try testing.expectEqual(client_len, client.len);
    try testing.expectEqualSlices(u8, &.{
        'P',  'R',  'I', ' ', '*',  ' ',  'H',  'T',
        'T',  'P',  '/', '2', '.',  '0',  0x0d, 0x0a,
        0x0d, 0x0a, 'S', 'M', 0x0d, 0x0a, 0x0d, 0x0a,
    }, client);
}

test "the preface writes and reads back" {
    var buf: [client_len]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeClient(&w);
    try testing.expectEqualSlices(u8, client, w.buffered());

    var r: std.Io.Reader = .fixed(w.buffered());
    try readClient(&r);
}

test "a preface with one octet changed is a fault" {
    var wrong = (client[0..client_len].*);
    wrong[0] = 'p';
    var r: std.Io.Reader = .fixed(&wrong);
    try testing.expectError(error.BadPreface, readClient(&r));

    try testing.expectEqual(
        errors.Fault{ .code = .protocol_error, .scope = .connection },
        errors.classify(error.BadPreface, 0),
    );
}

test "a stream shorter than the preface reports the end, and does not read past" {
    var r: std.Io.Reader = .fixed("PRI * HTTP/2.0");
    try testing.expectError(error.EndOfStream, readClient(&r));
}

test "the first flight is the preface then a SETTINGS frame" {
    var wanted: settings.Settings = .initial;
    wanted.enable_push = false;
    wanted.initial_window_size = 1 << 20;

    var buf: [client_flight_len_max]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeClientFlight(&w, wanted);

    const flight = w.buffered();
    try testing.expectEqualSlices(u8, client, flight[0..client_len]);

    const rest = flight[client_len..];
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x00, 0x0c, // length 12, so two entries
        0x04, // SETTINGS
        0x00, // no ACK
        0x00, 0x00, 0x00, 0x00, // stream 0
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // ENABLE_PUSH 0
        0x00, 0x04, 0x00, 0x10, 0x00, 0x00, // INITIAL_WINDOW_SIZE 1 MiB
    }, rest);

    // The frame reads back into the settings that went in.
    const header = frame.Header.parse(rest[0..frame.header_len]);
    const parsed = try payload.Frame.parse(header, rest[frame.header_len..]);
    var applied: settings.Settings = .initial;
    _ = try parsed.payload.settings.applyTo(&applied);
    try testing.expectEqual(wanted, applied);
}

test "a client with no changes still sends an empty SETTINGS frame" {
    var buf: [client_flight_len_max]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeClientFlight(&w, .initial);

    const rest = w.buffered()[client_len..];
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x00, 0x00, // length 0
        0x04, // SETTINGS
        0x00, // no ACK
        0x00, 0x00, 0x00, 0x00, // stream 0
    }, rest);
}

test "a SETTINGS ACK is nine octets and carries nothing" {
    var buf: [frame.header_len]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeSettingsAck(&w);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x00, 0x00, // length 0
        0x04, // SETTINGS
        0x01, // ACK
        0x00, 0x00, 0x00, 0x00, // stream 0
    }, w.buffered());

    const header = frame.Header.parse(w.buffered()[0..frame.header_len]);
    const parsed = try payload.Frame.parse(header, &.{});
    try testing.expect(parsed.payload.settings.ack);
    try testing.expectEqual(@as(usize, 0), parsed.payload.settings.count());
}
