//! A loopback MQTT 3.1.1 broker for the tests of this package.
//!
//! This is a test fixture, not a product. It speaks enough of the protocol
//! to run a connect, a publish, and a subscribe, and it lets a test bend
//! every answer. It validates almost nothing: a test that pins the bytes a
//! packet carries has to see those bytes as they arrived.
//!
//! **No test in this package reaches the real network.** Every one that
//! needs a peer starts one of these on 127.0.0.1, with a port the
//! operating system assigns.
//!
//! **This fixture speaks no TLS.** A TLS session needs a certificate and a
//! key, and this repository has no fixture for either. So an `mqtts` test
//! here proves what a session opens with, at the one function that
//! decides, and it cannot prove a live handshake. This file says so rather
//! than let a reader think it does.
//!
//! **The fixture can frame a packet the way a hostile broker would.**
//! `Script.remaining_length_bytes` writes a length of the caller's own
//! choosing, so a test can send a fifth continuation byte or announce 256
//! MiB and watch the client refuse. Those two are the reason
//! `zurl_mqtt.varint` and `zurl_mqtt.Session` exist, and a fixture that
//! could not produce them would leave both untested against a socket.

const std = @import("std");
const testing = std.testing;

const packet = @import("packet.zig");
const varint = @import("varint.zig");

pub const Server = @This();

/// How many bytes of the packet log this keeps.
pub const log_bytes = 8192;

/// One message the fixture delivers to a subscriber.
pub const Message = struct {
    topic: []const u8,
    payload: []const u8,
    /// The QoS bits of the fixed header. Above zero puts a packet
    /// identifier between the topic and the payload.
    qos: u2 = 0,
};

/// What the fixture answers.
///
/// Every field has the answer a working broker gives, so a test names only
/// the one it wants to bend.
pub const Script = struct {
    /// The return code of the CONNACK. Zero is accepted.
    connack_code: u8 = 0,
    /// The return code of the SUBACK. `0x80` is a refusal.
    suback_code: u8 = 0,
    /// The identifier the SUBACK echoes. Null echoes the one the
    /// SUBSCRIBE carried, which is what a broker does.
    suback_id: ?u16 = null,
    /// The type nibble of the answer to a CONNECT. Null answers with a
    /// CONNACK.
    connack_type: ?u4 = null,
    /// The messages the fixture delivers after a SUBACK, in order.
    messages: []const Message = &.{},
    /// How many PINGRESP packets go out before the messages do.
    ///
    /// **This is how a test makes a broker that says much and delivers
    /// nothing.** A PINGRESP carries no message, so a client that counts
    /// only messages reads every one of these and never finishes. See
    /// `Fetcher.max_empty_packets`.
    pingresps_before_messages: u32 = 0,
    /// Bytes the fixture writes in place of the first message.
    ///
    /// **This is how a test makes a hostile length.** The bytes go out as
    /// they are written here, so a test can put `30 ff ff ff ff 7f` on the
    /// wire and watch `Session.receive` refuse the fifth byte.
    raw_after_suback: ?[]const u8 = null,
    /// Whether to close the socket as soon as the CONNACK is written.
    close_after_connack: bool = false,
};

server: std.Io.net.Server,
task: std.Io.Future(void),
script: Script,
/// Every byte the client wrote, in order. Read through `log` after `wait`.
log_storage: [log_bytes]u8,
log_len: usize,
/// Set when the task has finished writing `log_storage`.
done: std.atomic.Value(bool),
/// How many connections the fixture accepted. A test that proves a url was
/// refused before any dial asserts this is zero.
accept_count: std.atomic.Value(usize),

/// Starts listening on loopback and starts a task that runs one session.
///
/// Initializes `s` in place, so the task can hold `&s.server` for its
/// whole life.
///
/// Returns `error.SkipZigTest` in a build with no concurrency at all. The
/// broker and its client cannot both make progress on one task.
///
/// `s` and every slice inside `script` must outlive the server.
pub fn start(s: *Server, script: Script) !void {
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    s.server = try address.listen(testing.io, .{ .reuse_address = true });
    errdefer s.server.deinit(testing.io);

    s.script = script;
    s.log_len = 0;
    s.done = .init(false);
    s.accept_count = .init(0);

    s.task = testing.io.concurrent(run, .{s}) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
}

/// Starts a broker that accepts one connection, writes nothing at all, and
/// holds the socket open.
///
/// **This is the peer the read bound exists for.** The connect succeeds,
/// so the dial is over, and then the CONNACK never arrives. Without a
/// bound the transfer waits for it forever.
pub fn startSilent(s: *Server) !void {
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    s.server = try address.listen(testing.io, .{ .reuse_address = true });
    errdefer s.server.deinit(testing.io);

    s.script = .{};
    s.log_len = 0;
    s.done = .init(false);
    s.accept_count = .init(0);

    s.task = testing.io.concurrent(runSilent, .{s}) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
}

/// The port the operating system assigned to the listener.
pub fn port(s: *const Server) u16 {
    return s.server.socket.address.getPort();
}

/// How many connections the client opened.
pub fn connections(s: *const Server) usize {
    return s.accept_count.load(.acquire);
}

/// Every byte the client sent.
///
/// Call `wait` first for a complete log. Without it this can read a log
/// the task has not finished writing, which is a race that passes on an
/// idle machine and fails on a loaded one.
pub fn log(s: *const Server) []const u8 {
    if (!s.done.load(.acquire)) return "";
    return s.log_storage[0..s.log_len];
}

/// Waits for the session to finish.
pub fn wait(s: *Server) void {
    s.task.await(testing.io);
}

/// Stops the server task and releases the listening socket. Every test
/// that calls `start` must call this, normally through `defer`.
///
/// The task is canceled and not joined. A test that opens no connection
/// leaves `run` inside `accept`, where a plain join waits forever.
pub fn stop(s: *Server) void {
    s.task.cancel(testing.io);
    s.server.deinit(testing.io);
}

fn runSilent(s: *Server) void {
    const stream = s.server.accept(testing.io) catch return;
    defer stream.close(testing.io);
    _ = s.accept_count.fetchAdd(1, .release);
    s.done.store(true, .release);

    const hold: std.Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(60), .clock = .awake } };
    hold.sleep(testing.io) catch {};
}

fn run(s: *Server) void {
    const stream = s.server.accept(testing.io) catch return;
    defer stream.close(testing.io);
    _ = s.accept_count.fetchAdd(1, .release);

    var read_buffer: [4096]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    var write_buffer: [4096]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);

    var session: Wire = .{
        .s = s,
        .reader = &reader.interface,
        .writer = &writer.interface,
    };
    serve(&session) catch {};
    s.done.store(true, .release);
}

/// One dialogue, over one reader and one writer.
const Wire = struct {
    s: *Server,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    /// Holds the body of the packet in play.
    body_storage: [4096]u8 = undefined,

    /// One packet the client sent.
    const Incoming = struct {
        kind: u4,
        flags: u4,
        body: []const u8,
    };

    /// Reads one whole packet, and records every byte of it.
    fn read(w: *Wire) !Incoming {
        const header = try w.reader.takeByte();
        w.record(&.{header});

        var length_bytes: [varint.max_bytes]u8 = undefined;
        var length_len: usize = 0;
        const remaining: u32 = while (true) {
            if (length_len == varint.max_bytes) return error.BadLength;
            length_bytes[length_len] = try w.reader.takeByte();
            length_len += 1;
            w.record(length_bytes[length_len - 1 ..][0..1]);
            const read_length = varint.decode(length_bytes[0..length_len]) catch |err| switch (err) {
                error.Incomplete => continue,
                else => return error.BadLength,
            };
            break read_length.value;
        };
        if (remaining > w.body_storage.len) return error.TooLarge;

        const body = w.body_storage[0..remaining];
        try w.reader.readSliceAll(body);
        w.record(body);
        return .{
            .kind = @intCast(header >> 4),
            .flags = @intCast(header & 0x0f),
            .body = body,
        };
    }

    fn record(w: *Wire, bytes: []const u8) void {
        const room = w.s.log_storage.len - w.s.log_len;
        const n = @min(room, bytes.len);
        @memcpy(w.s.log_storage[w.s.log_len..][0..n], bytes[0..n]);
        w.s.log_len += n;
    }

    fn send(w: *Wire, bytes: []const u8) !void {
        try w.writer.writeAll(bytes);
        try w.writer.flush();
    }

    /// Writes a packet with a fixed header, a minimal length, and a body.
    fn sendPacket(w: *Wire, kind: u4, flags: u4, body: []const u8) !void {
        var head: [1 + varint.max_bytes]u8 = undefined;
        head[0] = (@as(u8, kind) << 4) | flags;
        const length = try varint.encode(head[1..], @intCast(body.len));
        try w.writer.writeAll(head[0 .. 1 + length.len]);
        try w.writer.writeAll(body);
        try w.writer.flush();
    }

    /// Writes one PUBLISH the way a broker delivers it.
    fn sendMessage(w: *Wire, message: Message) !void {
        var body: [2048]u8 = undefined;
        var at: usize = 0;
        std.mem.writeInt(u16, body[0..2], @intCast(message.topic.len), .big);
        at += 2;
        @memcpy(body[at..][0..message.topic.len], message.topic);
        at += message.topic.len;
        if (message.qos != 0) {
            std.mem.writeInt(u16, body[at..][0..2], 1, .big);
            at += 2;
        }
        @memcpy(body[at..][0..message.payload.len], message.payload);
        at += message.payload.len;

        try w.sendPacket(
            @intFromEnum(packet.Type.publish),
            @as(u4, message.qos) << 1,
            body[0..at],
        );
    }
};

fn serve(w: *Wire) !void {
    const script = w.s.script;

    const connect = try w.read();
    if (connect.kind != @intFromEnum(packet.Type.connect)) return;
    try w.sendPacket(
        script.connack_type orelse @intFromEnum(packet.Type.connack),
        0,
        &.{ 0x00, script.connack_code },
    );
    if (script.close_after_connack or script.connack_code != 0) return;

    while (true) {
        const next = w.read() catch return;
        switch (@as(packet.Type, @enumFromInt(next.kind))) {
            .publish => {
                // A QoS 0 publish is acknowledged by nothing at all,
                // which is what this build sends.
            },
            .subscribe => {
                const id = script.suback_id orelse
                    std.mem.readInt(u16, next.body[0..2], .big);
                var answer: [3]u8 = undefined;
                std.mem.writeInt(u16, answer[0..2], id, .big);
                answer[2] = script.suback_code;
                try w.sendPacket(@intFromEnum(packet.Type.suback), 0, &answer);
                if (script.suback_code == 0x80) return;

                if (script.raw_after_suback) |bytes| {
                    try w.send(bytes);
                    // The raw bytes stand in for the whole delivery, so
                    // nothing else goes out and the client is left to
                    // refuse them.
                    const hold: std.Io.Timeout = .{
                        .duration = .{ .raw = .fromSeconds(60), .clock = .awake },
                    };
                    hold.sleep(testing.io) catch {};
                    return;
                }

                var pings: u32 = 0;
                while (pings < script.pingresps_before_messages) : (pings += 1) {
                    try w.sendPacket(@intFromEnum(packet.Type.pingresp), 0, &.{});
                }

                for (script.messages) |message| try w.sendMessage(message);
            },
            .disconnect => return,
            else => return,
        }
    }
}

test "the fixture runs a whole publish and records every byte" {
    var server: Server = undefined;
    try server.start(.{});
    defer server.stop();

    var address = try std.Io.net.IpAddress.parse("127.0.0.1", server.port());
    const stream = try address.connect(testing.io, .{ .mode = .stream });
    defer stream.close(testing.io);

    var read_buffer: [1024]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    var write_buffer: [1024]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);

    // The CONNECT curl sends, measured, with `zurl` in the identifier.
    const connect = [_]u8{
        0x10, 0x18, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3c,
        0x00, 0x0c, 'z',  'u',  'r', 'l', 'I', 'A', 'g',  'O',  'j',  '0',
        '5',  'A',
    };
    try writer.interface.writeAll(&connect);
    try writer.interface.flush();

    var connack: [4]u8 = undefined;
    try reader.interface.readSliceAll(&connack);
    try testing.expectEqualSlices(u8, &.{ 0x20, 0x02, 0x00, 0x00 }, &connack);

    const publish = [_]u8{ 0x30, 0x05, 0x00, 0x03, 't', '/', 'a' };
    try writer.interface.writeAll(&publish);
    try writer.interface.writeAll(&.{ 0xe0, 0x00 });
    try writer.interface.flush();

    server.wait();
    try testing.expectEqualSlices(
        u8,
        &(connect ++ publish ++ [_]u8{ 0xe0, 0x00 }),
        server.log(),
    );
    try testing.expectEqual(@as(usize, 1), server.connections());
}

test "the fixture delivers the messages a script names, in order" {
    var server: Server = undefined;
    try server.start(.{ .messages = &.{
        .{ .topic = "zurl/sub", .payload = "payload-one" },
        .{ .topic = "zurl/sub", .payload = "payload-two" },
    } });
    defer server.stop();

    var address = try std.Io.net.IpAddress.parse("127.0.0.1", server.port());
    const stream = try address.connect(testing.io, .{ .mode = .stream });
    defer stream.close(testing.io);

    var read_buffer: [1024]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    var write_buffer: [1024]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);

    try writer.interface.writeAll(&.{
        0x10, 0x0e, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x02, 'i', 'd',
    });
    try writer.interface.flush();
    var connack: [4]u8 = undefined;
    try reader.interface.readSliceAll(&connack);

    // The SUBSCRIBE curl sends, measured.
    try writer.interface.writeAll(&.{
        0x82, 0x0d, 0x00, 0x01, 0x00, 0x08, 'z', 'u', 'r', 'l', '/', 's', 'u', 'b', 0x00,
    });
    try writer.interface.flush();

    var suback: [5]u8 = undefined;
    try reader.interface.readSliceAll(&suback);
    try testing.expectEqualSlices(u8, &.{ 0x90, 0x03, 0x00, 0x01, 0x00 }, &suback);

    // And then the two messages, in the shape mosquitto sent curl.
    var first: [23]u8 = undefined;
    try reader.interface.readSliceAll(&first);
    try testing.expectEqualSlices(u8, &.{
        0x30, 0x15, 0x00, 0x08, 'z', 'u', 'r', 'l', '/', 's', 'u', 'b',
        'p',  'a',  'y',  'l',  'o', 'a', 'd', '-', 'o', 'n', 'e',
    }, &first);

    var second: [23]u8 = undefined;
    try reader.interface.readSliceAll(&second);
    try testing.expectEqualStrings("payload-two", second[12..]);
}

test "the fixture can put a hostile remaining length on the wire" {
    // **The fixture the length bound needs.** Without this, the fifth
    // continuation byte and the 256 MiB claim are tested against a buffer
    // and never against a socket.
    var server: Server = undefined;
    try server.start(.{
        .raw_after_suback = &.{ 0x30, 0xff, 0xff, 0xff, 0xff, 0x7f },
    });
    defer server.stop();

    var address = try std.Io.net.IpAddress.parse("127.0.0.1", server.port());
    const stream = try address.connect(testing.io, .{ .mode = .stream });
    defer stream.close(testing.io);

    var read_buffer: [1024]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    var write_buffer: [1024]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);

    try writer.interface.writeAll(&.{
        0x10, 0x0e, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x02, 'i', 'd',
    });
    try writer.interface.writeAll(&.{
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 't', 0x00,
    });
    try writer.interface.flush();

    var head: [9]u8 = undefined;
    try reader.interface.readSliceAll(&head);
    var hostile: [6]u8 = undefined;
    try reader.interface.readSliceAll(&hostile);
    try testing.expectEqualSlices(u8, &.{ 0x30, 0xff, 0xff, 0xff, 0xff, 0x7f }, &hostile);
}
