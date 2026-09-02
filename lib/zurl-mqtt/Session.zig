//! One MQTT dialogue: the packet framing off a socket, and the packet
//! identifiers a session hands out.
//!
//! **This is where the remaining length a peer chose meets this package's
//! ceiling.** `varint.zig` refuses a length that is not a legal encoding.
//! It cannot refuse a length that is legal and enormous, because 268 435
//! 455 is a legal encoding, so this file checks the decoded number against
//! `max_packet_bytes` **before** it grows a buffer or reads a byte of the
//! body. A five byte header must never be able to ask this process for a
//! quarter of a gigabyte.
//!
//! The read is bounded twice more. `stall` says how long the peer may
//! write nothing, through `zurl_net.bounded`, and the length bytes
//! themselves are read one at a time so a peer that sends continuation
//! bytes forever is refused at the fifth and not at the last.
//!
//! **This file holds no socket.** It reads and writes through a
//! `zurl_net.line.Channel`, which is a reader, a writer, and a flush. A
//! test drives a whole dialogue over two buffers, and the STARTTLS shape
//! that `retarget` serves elsewhere works here too, though MQTT has no
//! such upgrade: `mqtts` is TLS from the first byte.
//!
//! This file speaks no MQTT grammar above the fixed header. Which packet
//! a body is, and what it holds, belongs to `packet.zig`.

const Session = @This();

const std = @import("std");

const zurl_net = @import("zurl-net");

const packet = @import("packet.zig");
const varint = @import("varint.zig");

const Io = std.Io;

/// How many bytes of one packet this package reads.
///
/// **The ceiling on a number the peer chose.** A remaining length of one
/// mebibyte is far past any message an MQTT deployment sends over a
/// broker's default 256 KiB limit, and it is a fraction of the 256 MiB the
/// four byte encoding can name. A packet past it is
/// `error.PacketTooLarge`, and no byte of its body is read: a reader that
/// took the length and skipped the bytes would be doing the peer's work
/// for it.
pub const max_packet_bytes: usize = 1024 * 1024;

/// Every fault a read of one packet can report.
pub const ReceiveError = zurl_net.bounded.ExactError || error{
    /// The remaining length is not a legal variable byte integer. See
    /// `varint.DecodeError` for the three shapes.
    BadRemainingLength,
    /// The remaining length is legal and past `max_packet_bytes`.
    PacketTooLarge,
    /// The peer sent a fixed header whose type is not one MQTT 3.1.1
    /// names. Type 0 and type 15 are both reserved.
    ReservedPacketType,
};

/// Every fault a write can report.
pub const SendError = Io.Writer.Error;

/// One packet, read whole.
///
/// `body` points into this session's own buffer, so it is valid until the
/// next `receive` on this `Session`.
pub const Incoming = struct {
    kind: packet.Type,
    /// The low nibble of the fixed header. A PUBLISH carries its QoS, its
    /// retain bit, and its duplicate bit here.
    flags: u4,
    body: []const u8,
};

allocator: std.mem.Allocator,
io: Io,
/// Where this dialogue reads and writes. Undefined until `begin`.
channel: zurl_net.line.Channel,
/// How long one read may wait with no byte arriving.
stall: Io.Timeout,
/// Holds the body of the packet in play. Grows to what a packet needs and
/// never past `max_packet_bytes`.
buffer: std.ArrayList(u8),
/// The identifier the next SUBSCRIBE carries.
///
/// MQTT 3.1.1 section 2.3.1 makes zero the one value a packet identifier
/// may not take, so this starts at one, which is what curl sends.
next_id: u16,

/// A `Session` that has no channel yet.
pub fn init(allocator: std.mem.Allocator, io: Io) Session {
    return .{
        .allocator = allocator,
        .io = io,
        .channel = undefined,
        .stall = .none,
        .buffer = .empty,
        .next_id = 1,
    };
}

/// Frees what this `Session` holds.
pub fn deinit(s: *Session) void {
    s.wipe();
    s.buffer.deinit(s.allocator);
}

/// Zeroes the packet buffer.
///
/// **A packet body is a message in the clear**, and the CONNECT this
/// package builds carries a password, so the buffer is zeroed rather than
/// left for the next transfer to read. That is the rule `zurl-scp`
/// records.
pub fn wipe(s: *Session) void {
    std.crypto.secureZero(u8, s.buffer.items);
    s.buffer.clearRetainingCapacity();
}

/// Starts a dialogue over `channel`.
///
/// The identifiers start over, because a new connection is a new session
/// to the broker.
pub fn begin(s: *Session, channel: zurl_net.line.Channel, stall: Io.Timeout) void {
    s.channel = channel;
    s.stall = stall;
    s.next_id = 1;
    s.wipe();
}

/// The identifier the next SUBSCRIBE carries.
///
/// Wraps past 65 535 back to one and never to zero. A session that sent
/// that many subscribes does not exist here, because this package sends
/// exactly one, but the rule costs a line and a zero identifier is a
/// packet a broker must refuse.
pub fn takeId(s: *Session) u16 {
    const id = s.next_id;
    s.next_id = if (s.next_id == std.math.maxInt(u16)) 1 else s.next_id + 1;
    return id;
}

/// Writes one packet and flushes it.
pub fn send(s: *Session, bytes: []const u8) SendError!void {
    try s.channel.writer.writeAll(bytes);
    try s.channel.flush(s.channel.ctx);
}

/// Reads one whole packet.
///
/// The order is the whole point of this function:
///
/// 1. one fixed header byte,
/// 2. the remaining length, one byte at a time, at most four,
/// 3. the length checked against `max_packet_bytes`,
/// 4. and only then a buffer of that size and a read of that many bytes.
///
/// A caller that read the length and allocated before step 3 would let a
/// five byte header ask this process for 256 MiB.
pub fn receive(s: *Session) ReceiveError!Incoming {
    var header: [1]u8 = undefined;
    try zurl_net.bounded.readExact(s.channel.reader, s.io, &header, s.stall);

    const raw_type: u4 = @intCast(header[0] >> 4);
    // Type 0 and type 15 are reserved by section 2.2.1, and the enum names
    // neither, so a peer that sends one is refused rather than read as
    // something it is not.
    if (raw_type == 0 or raw_type == 15) return error.ReservedPacketType;
    const kind: packet.Type = @enumFromInt(raw_type);
    const flags: u4 = @intCast(header[0] & 0x0f);

    // **The length bytes are read one at a time.** A peer that never
    // clears the top bit is refused at the fifth byte. A read of four
    // bytes at once would block a peer that meant to send one.
    var length_bytes: [varint.max_bytes]u8 = undefined;
    var length_len: usize = 0;
    const remaining: u32 = while (true) {
        if (length_len == varint.max_bytes) return error.BadRemainingLength;
        try zurl_net.bounded.readExact(
            s.channel.reader,
            s.io,
            length_bytes[length_len..][0..1],
            s.stall,
        );
        length_len += 1;
        const read = varint.decode(length_bytes[0..length_len]) catch |err| switch (err) {
            // More bytes belong to this length, so read another one. The
            // loop's own bound above is what stops this going on forever.
            error.Incomplete => continue,
            error.TooManyBytes, error.NotMinimal => return error.BadRemainingLength,
        };
        break read.value;
    };

    // **The ceiling, and it runs before anything is allocated.**
    if (remaining > max_packet_bytes) return error.PacketTooLarge;

    s.wipe();
    s.buffer.resize(s.allocator, remaining) catch return error.OutOfMemory;
    if (remaining != 0) {
        try zurl_net.bounded.readExact(s.channel.reader, s.io, s.buffer.items, s.stall);
    }
    return .{ .kind = kind, .flags = flags, .body = s.buffer.items };
}

/// Names the fault a read reported, for a message to a user.
pub fn describe(err: ReceiveError) []const u8 {
    return switch (err) {
        error.BadRemainingLength => "the broker sent a packet whose remaining length is not a variable byte integer MQTT 3.1.1 section 2.2.3 allows",
        error.PacketTooLarge => "the broker announced a packet larger than zurl reads",
        error.ReservedPacketType => "the broker sent a packet whose type MQTT 3.1.1 section 2.2.1 reserves",
        error.EndOfStream => "the broker closed the connection in the middle of a packet",
        error.OutOfMemory => "zurl ran out of memory reading a packet",
        error.StreamTooLong => "the broker sent more than zurl reads",
        error.ReadFailed => "zurl did not read from the broker",
        error.OperationTimedOut => "the broker sent no byte for as long as zurl waits",
        error.ReadTimeoutUnsupported => "this build has no concurrency, so an mqtt read cannot be bounded, and an unbounded one would wait for a broker that may never answer",
        error.Canceled => "the mqtt read was stopped from outside",
    };
}

const testing = std.testing;

/// A channel over two fixed buffers, for a test that drives a dialogue
/// with no socket at all.
const Loop = struct {
    reader: Io.Reader,
    writer: Io.Writer,
    sent: [4096]u8,

    fn init(l: *Loop, incoming: []const u8) void {
        l.reader = .fixed(incoming);
        l.writer = .fixed(&l.sent);
    }

    fn channel(l: *Loop) zurl_net.line.Channel {
        return .{ .reader = &l.reader, .writer = &l.writer, .ctx = null, .flush = noFlush };
    }

    fn written(l: *Loop) []const u8 {
        return l.writer.buffered();
    }

    fn noFlush(ctx: ?*anyopaque) Io.Writer.Error!void {
        _ = ctx;
    }
};

/// A `Session` and a `Loop`, both on the heap, so neither moves.
const Fixture = struct {
    session: Session,
    loop: Loop,

    fn start(incoming: []const u8) !*Fixture {
        const f = try testing.allocator.create(Fixture);
        f.session = .init(testing.allocator, testing.io);
        f.loop.init(incoming);
        f.session.begin(f.loop.channel(), .none);
        return f;
    }

    fn stop(f: *Fixture) void {
        f.session.deinit();
        testing.allocator.destroy(f);
    }
};

test "a whole packet reads back as its type, its flags, and its body" {
    // The CONNACK mosquitto sent curl, measured, and then the SUBACK.
    const f = try Fixture.start(&.{ 0x20, 0x02, 0x00, 0x00, 0x90, 0x03, 0x00, 0x01, 0x00 });
    defer f.stop();

    const connack = try f.session.receive();
    try testing.expectEqual(packet.Type.connack, connack.kind);
    try testing.expectEqual(@as(u4, 0), connack.flags);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00 }, connack.body);

    const suback = try f.session.receive();
    try testing.expectEqual(packet.Type.suback, suback.kind);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x01, 0x00 }, suback.body);
}

test "a packet with an empty body reads, and reads nothing after itself" {
    const f = try Fixture.start(&.{ 0xd0, 0x00, 0xe0, 0x00 });
    defer f.stop();

    const ping = try f.session.receive();
    try testing.expectEqual(packet.Type.pingresp, ping.kind);
    try testing.expectEqual(@as(usize, 0), ping.body.len);

    const bye = try f.session.receive();
    try testing.expectEqual(packet.Type.disconnect, bye.kind);
}

test "the flags nibble reaches the caller, because a PUBLISH carries its QoS there" {
    const f = try Fixture.start(&.{ 0x3b, 0x02, 'h', 'i' });
    defer f.stop();

    const message = try f.session.receive();
    try testing.expectEqual(packet.Type.publish, message.kind);
    try testing.expectEqual(@as(u4, 0b1011), message.flags);
}

test "a fifth continuation byte ends the session rather than reads on" {
    // **The hazard this file exists for, on a live reader.** A peer that
    // never clears the top bit would hold an unbounded reader forever.
    const f = try Fixture.start(&([_]u8{0x30} ++ [_]u8{0xff} ** 32));
    defer f.stop();

    try testing.expectError(error.BadRemainingLength, f.session.receive());
    try testing.expect(describe(error.BadRemainingLength).len != 0);
}

test "a length with two spellings ends the session" {
    // `80 00` names zero and `00` names it in one byte. See `varint.zig`.
    const f = try Fixture.start(&.{ 0x30, 0x80, 0x00 });
    defer f.stop();
    try testing.expectError(error.BadRemainingLength, f.session.receive());
}

test "a length past the ceiling is refused before a byte of body is read" {
    // **The check the whole file is for.** `ff ff ff 7f` is a legal
    // encoding of 268 435 455, and a reader that allocated on it would ask
    // this process for 256 MiB on five bytes of input. The four length
    // bytes are all this reads.
    const f = try Fixture.start(&.{ 0x30, 0xff, 0xff, 0xff, 0x7f });
    defer f.stop();

    try testing.expectError(error.PacketTooLarge, f.session.receive());
    try testing.expectEqual(@as(usize, 0), f.session.buffer.items.len);

    // A length one byte past the ceiling is refused too, so the bound is
    // the number and not an order of magnitude near it.
    var over: [8]u8 = undefined;
    var digits: [varint.max_bytes]u8 = undefined;
    const encoded = try varint.encode(&digits, @intCast(max_packet_bytes + 1));
    over[0] = 0x30;
    @memcpy(over[1..][0..encoded.len], encoded);
    const g = try Fixture.start(over[0 .. 1 + encoded.len]);
    defer g.stop();
    try testing.expectError(error.PacketTooLarge, g.session.receive());
}

test "a packet of exactly the ceiling is read, so the bound is not off by one" {
    // The body is not actually sent here: the read gets as far as the
    // length check, passes it, and then finds the stream ended. What this
    // proves is that the ceiling itself does not refuse.
    var digits: [varint.max_bytes]u8 = undefined;
    const encoded = try varint.encode(&digits, @intCast(max_packet_bytes));
    var header: [8]u8 = undefined;
    header[0] = 0x30;
    @memcpy(header[1..][0..encoded.len], encoded);

    const f = try Fixture.start(header[0 .. 1 + encoded.len]);
    defer f.stop();
    try testing.expectError(error.EndOfStream, f.session.receive());
}

test "a reserved packet type is refused rather than read as its neighbour" {
    // Type 0 and type 15 are reserved by section 2.2.1. Reading one as
    // whatever enum value happened to sit there is how a peer picks the
    // branch this build takes.
    const zero = try Fixture.start(&.{ 0x00, 0x00 });
    defer zero.stop();
    try testing.expectError(error.ReservedPacketType, zero.session.receive());

    const fifteen = try Fixture.start(&.{ 0xf0, 0x00 });
    defer fifteen.stop();
    try testing.expectError(error.ReservedPacketType, fifteen.session.receive());
}

test "a peer that closes in the middle of a packet is a fault and not an end" {
    const f = try Fixture.start(&.{ 0x30, 0x08, 'a', 'b' });
    defer f.stop();
    try testing.expectError(error.EndOfStream, f.session.receive());
}

test "send writes the packet whole and identifiers start at one" {
    const f = try Fixture.start(&.{});
    defer f.stop();

    try testing.expectEqual(@as(u16, 1), f.session.takeId());
    try testing.expectEqual(@as(u16, 2), f.session.takeId());

    try f.session.send(&.{ 0xe0, 0x00 });
    try testing.expectEqualSlices(u8, &.{ 0xe0, 0x00 }, f.loop.written());

    // A new dialogue starts the identifiers over, because a new
    // connection is a new session to the broker.
    f.session.begin(f.loop.channel(), .none);
    try testing.expectEqual(@as(u16, 1), f.session.takeId());
}

test "an identifier never wraps to zero" {
    // Section 2.3.1 makes zero the one value a packet identifier may not
    // take.
    const f = try Fixture.start(&.{});
    defer f.stop();

    f.session.next_id = std.math.maxInt(u16);
    try testing.expectEqual(std.math.maxInt(u16), f.session.takeId());
    try testing.expectEqual(@as(u16, 1), f.session.takeId());
}

test "wipe leaves no byte of the last packet in the buffer" {
    // A packet body is a message in the clear, and a CONNECT carries a
    // password.
    const f = try Fixture.start(&.{ 0x30, 0x06, 's', 'e', 'c', 'r', 'e', 't' });
    defer f.stop();

    const message = try f.session.receive();
    try testing.expectEqualStrings("secret", message.body);

    const held = f.session.buffer.items.ptr[0..6];
    f.session.wipe();
    // **The check is that the message is gone, and not that a chosen byte
    // took its place.** `secureZero` writes zeroes and then
    // `clearRetainingCapacity` writes `undefined` over the same bytes,
    // which a Debug build fills with `0xaa` and a release build leaves
    // alone. Neither is any letter of the message, and that is the
    // property this test is for.
    for (held, "secret") |byte, original| try testing.expect(byte != original);
}

test "every fault a read reports has a sentence of its own" {
    const every = [_]ReceiveError{
        error.BadRemainingLength,
        error.PacketTooLarge,
        error.ReservedPacketType,
        error.EndOfStream,
        error.OutOfMemory,
        error.StreamTooLong,
        error.ReadFailed,
        error.OperationTimedOut,
        error.ReadTimeoutUnsupported,
        error.Canceled,
    };
    for (every) |err| {
        try testing.expect(describe(err).len != 0);
        for (every) |other| {
            if (err == other) continue;
            try testing.expect(!std.mem.eql(u8, describe(err), describe(other)));
        }
    }
}
