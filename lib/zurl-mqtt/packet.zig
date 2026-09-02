//! The MQTT 3.1.1 control packets this package sends and reads.
//!
//! Every packet is a one byte fixed header, then the remaining length that
//! `varint.zig` holds, then that many bytes. This file builds the four
//! packets a transfer sends and reads the three it receives. It knows no
//! socket: a builder fills a caller's buffer and a reader is handed the
//! bytes a `Session` already read.
//!
//! ## What a transfer sends, and where each field came from
//!
//! The order and the bytes are curl 8.21.0's own, read off a byte logging
//! relay in front of a real mosquitto 2.1.2:
//!
//! ```
//! publish:    CONNECT, [CONNACK], PUBLISH, DISCONNECT
//! subscribe:  CONNECT, [CONNACK], SUBSCRIBE, [SUBACK], [PUBLISH]...
//! ```
//!
//! curl's CONNECT with no credential was
//! `10 18 00 04 4d 51 54 54 04 02 00 3c 00 0c "curlIAgOj05A"`: protocol
//! name `MQTT`, level 4 which is 3.1.1, flags `02` which is clean session,
//! keep alive 60, and a twelve byte client id. With `-u alice:s3cret` the
//! flags became `c2`, which adds the user name bit and the password bit,
//! and the two strings went on the end. This file writes the same shape,
//! with `zurl` where curl writes `curl`.
//!
//! **Everything this build sends is QoS 0.** curl sends `30` for a PUBLISH
//! and `00` for the requested QoS of a SUBSCRIBE, measured, so no packet
//! identifier appears in a PUBLISH and no PUBACK is ever expected. A QoS 1
//! or 2 dialogue is a different state machine with its own retransmission,
//! and this package does not have one. See `zurl_mqtt.Fetcher`.
//!
//! ## The bounds this file keeps
//!
//! **A string is two bytes of count and then that many octets**, MQTT
//! 3.1.1 section 1.5.3, so a count is 65 535 at most and a builder refuses
//! anything longer with `error.StringTooLong` before it writes a byte. A
//! reader takes a count off the front of a buffer it was given and refuses
//! a count that runs past the end of that buffer, so no read here can
//! reach past the packet the `Session` bounded.
//!
//! This file allocates nothing.

const std = @import("std");

const varint = @import("varint.zig");

/// The control packet types MQTT 3.1.1 section 2.2.1 names, in its own
/// numbering.
///
/// Every type is here and not only the ones this package uses, because a
/// reader has to name what a peer sent even when the answer is that this
/// build does not read it.
pub const Type = enum(u4) {
    connect = 1,
    connack = 2,
    publish = 3,
    puback = 4,
    pubrec = 5,
    pubrel = 6,
    pubcomp = 7,
    subscribe = 8,
    suback = 9,
    unsubscribe = 10,
    unsuback = 11,
    pingreq = 12,
    pingresp = 13,
    disconnect = 14,

    /// The name a message to a user prints for this type.
    pub fn describe(t: Type) []const u8 {
        return switch (t) {
            .connect => "CONNECT",
            .connack => "CONNACK",
            .publish => "PUBLISH",
            .puback => "PUBACK",
            .pubrec => "PUBREC",
            .pubrel => "PUBREL",
            .pubcomp => "PUBCOMP",
            .subscribe => "SUBSCRIBE",
            .suback => "SUBACK",
            .unsubscribe => "UNSUBSCRIBE",
            .unsuback => "UNSUBACK",
            .pingreq => "PINGREQ",
            .pingresp => "PINGRESP",
            .disconnect => "DISCONNECT",
        };
    }
};

/// The protocol name every CONNECT of MQTT 3.1.1 carries. Section 3.1.2.1.
pub const protocol_name = "MQTT";

/// The protocol level of MQTT 3.1.1. Section 3.1.2.2, and the byte curl
/// sends, measured.
pub const protocol_level: u8 = 4;

/// The keep alive a CONNECT names, in seconds.
///
/// 60, which is the `00 3c` curl sends, measured. **Nothing in this
/// package sends a PINGREQ**, so this is the interval a broker may drop an
/// idle session after. A subscribe that waits longer than this for a
/// message may find the connection closed, and `Fetcher` reports that
/// close rather than reconnect behind the user's back.
pub const keep_alive_s: u16 = 60;

/// The connect flag bits of MQTT 3.1.1 section 3.1.2.3 that this package
/// sets.
pub const connect_flag_clean_session: u8 = 0x02;
pub const connect_flag_password: u8 = 0x40;
pub const connect_flag_user_name: u8 = 0x80;

/// How many octets one MQTT string may carry. Section 1.5.3.
pub const max_string_bytes: usize = 65_535;

/// Why a packet could not be built.
pub const BuildError = error{
    /// A string is longer than the two byte count in front of it holds.
    StringTooLong,
    /// The packet is longer than the caller's buffer.
    PacketTooLong,
    /// A CONNECT was asked for with a password and no user name. MQTT
    /// 3.1.1 section 3.1.2.9 has no such packet, and a broker answers one
    /// by closing.
    PasswordWithoutUser,
};

/// Builds one packet at a time into storage the caller owns.
///
/// A value and not a bare slice, so the bound on a packet this build sends
/// is one named number in one place. `reset` starts the next packet, and
/// `written` is the bytes to put on the socket.
pub const Writer = struct {
    /// How many bytes one packet this package sends may take.
    ///
    /// The largest is a PUBLISH: five bytes of header, the topic with its
    /// count, and the payload. `zurl_mqtt.Fetcher.max_publish_bytes`
    /// bounds the payload at 256 KiB, and this is that plus the room a
    /// topic and a header need.
    ///
    /// **This is the bound on what this package writes, and
    /// `zurl_mqtt.Session.max_packet_bytes` is the bound on what it
    /// reads.** They are separate numbers because they answer to different
    /// people: this one to the user's own `-d`, and that one to a peer.
    /// They are also different sizes because they cost differently. This
    /// buffer is a fixed field of every `Fetcher`, and `-Z` gives one
    /// `Fetcher` to each worker, so the number is paid for whether a run
    /// publishes anything or not. The read buffer grows to the packet in
    /// hand and costs nothing until one arrives.
    pub const max_bytes: usize = 256 * 1024 + 8192;

    bytes: [max_bytes]u8,
    len: usize,

    /// Starts `w` holding no packet.
    ///
    /// In place, and not a value returned, because `bytes` is a quarter of
    /// a megabyte: a `Writer` lives as a field of a heap value and never on
    /// a stack. See `zurl_mqtt.Fetcher`.
    pub fn init(w: *Writer) void {
        w.len = 0;
    }

    /// Throws away whatever packet is in the buffer.
    pub fn reset(w: *Writer) void {
        w.len = 0;
    }

    /// The packet built so far.
    pub fn written(w: *const Writer) []const u8 {
        return w.bytes[0..w.len];
    }
};

/// What one packet's variable header and payload need before the fixed
/// header can be written.
///
/// A builder fills this out first, because the remaining length has to be
/// known before the byte in front of it goes down. Every builder here
/// writes the body into the tail of the caller's buffer and then moves it
/// back, which costs one copy and keeps every length exact.
const header_room: usize = 1 + varint.max_bytes;

/// Writes the fixed header in front of a body already at
/// `w.bytes[header_room..]`, and leaves `w` holding the whole packet.
fn frame(w: *Writer, kind: Type, flags: u4, body_len: usize) BuildError!void {
    if (body_len > varint.max_value) return error.PacketTooLong;

    var length_bytes: [varint.max_bytes]u8 = undefined;
    // The check above is the whole of what `encode` refuses.
    const length = varint.encode(&length_bytes, @intCast(body_len)) catch unreachable;

    // The body was built at `header_room`, which leaves room for the
    // longest header. This one is a byte plus the length, so it starts
    // that far in front of the body and the packet then moves to the front
    // of the buffer. One copy, and every length exact.
    const start = header_room - 1 - length.len;
    w.bytes[start] = (@as(u8, @intFromEnum(kind)) << 4) | flags;
    @memcpy(w.bytes[start + 1 ..][0..length.len], length);
    const total = 1 + length.len + body_len;
    std.mem.copyForwards(u8, w.bytes[0..total], w.bytes[start..][0..total]);
    w.len = total;
}

/// Writes a string with the two byte count MQTT 3.1.1 section 1.5.3 puts
/// in front of it.
///
/// **This is the framing half of this package's injection rule.** The
/// count is computed from `text` and never from a byte inside it, so no
/// byte `text` holds can end the string early or start a packet. See
/// `zurl_mqtt.topic`.
fn putString(out: []u8, at: *usize, text: []const u8) BuildError!void {
    if (text.len > max_string_bytes) return error.StringTooLong;
    if (at.* + 2 + text.len > out.len) return error.PacketTooLong;
    std.mem.writeInt(u16, out[at.*..][0..2], @intCast(text.len), .big);
    @memcpy(out[at.* + 2 ..][0..text.len], text);
    at.* += 2 + text.len;
}

/// Writes a CONNECT.
///
/// An empty `user` and an empty `password` set neither flag, which is the
/// anonymous connect curl sends for a url with no credential, measured.
/// A password with no user name is refused: MQTT 3.1.1 section 3.1.2.9
/// says the password flag may be set only where the user name flag is, and
/// a packet that broke that rule would be thrown away by the broker while
/// this build reported it sent.
pub fn writeConnect(
    w: *Writer,
    client_id: []const u8,
    user: []const u8,
    password: []const u8,
) BuildError!void {
    if (user.len == 0 and password.len != 0) return error.PasswordWithoutUser;

    const body = w.bytes[header_room..];
    var at: usize = 0;
    try putString(body, &at, protocol_name);

    if (at + 4 > body.len) return error.PacketTooLong;
    body[at] = protocol_level;
    var flags: u8 = connect_flag_clean_session;
    if (user.len != 0) flags |= connect_flag_user_name;
    if (password.len != 0) flags |= connect_flag_password;
    body[at + 1] = flags;
    std.mem.writeInt(u16, body[at + 2 ..][0..2], keep_alive_s, .big);
    at += 4;

    try putString(body, &at, client_id);
    if (user.len != 0) try putString(body, &at, user);
    if (password.len != 0) try putString(body, &at, password);

    try frame(w, .connect, 0, at);
}

/// Writes a PUBLISH, QoS 0, no retain and no duplicate flag.
///
/// **No packet identifier goes out.** Section 3.3.2.2 puts one in a
/// PUBLISH only at QoS 1 or 2, and this build sends QoS 0, which is the
/// `30` curl writes.
pub fn writePublish(w: *Writer, topic: []const u8, payload: []const u8) BuildError!void {
    const body = w.bytes[header_room..];
    var at: usize = 0;
    try putString(body, &at, topic);
    if (at + payload.len > body.len) return error.PacketTooLong;
    @memcpy(body[at..][0..payload.len], payload);
    at += payload.len;

    try frame(w, .publish, 0, at);
}

/// Writes a SUBSCRIBE for one topic filter, at QoS 0.
///
/// The `0b0010` in the flag nibble is not optional: section 3.8.1 makes it
/// the only value a SUBSCRIBE may carry, and curl writes `82`, measured.
pub fn writeSubscribe(w: *Writer, packet_id: u16, filter: []const u8) BuildError!void {
    const body = w.bytes[header_room..];
    var at: usize = 0;
    if (at + 2 > body.len) return error.PacketTooLong;
    std.mem.writeInt(u16, body[0..2], packet_id, .big);
    at += 2;
    try putString(body, &at, filter);
    if (at + 1 > body.len) return error.PacketTooLong;
    body[at] = 0;
    at += 1;

    try frame(w, .subscribe, 0b0010, at);
}

/// Writes a DISCONNECT, which carries nothing at all. Section 3.14.
pub fn writeDisconnect(w: *Writer) BuildError!void {
    try frame(w, .disconnect, 0, 0);
}

/// Why a packet a peer sent could not be read.
pub const ReadError = error{
    /// The packet is shorter than the fields its type must carry.
    PacketTruncated,
    /// A string's count runs past the end of the packet.
    StringRunsPast,
};

/// The CONNACK return codes of MQTT 3.1.1 section 3.2.2.3.
pub const ReturnCode = enum(u8) {
    accepted = 0,
    unacceptable_protocol_version = 1,
    identifier_rejected = 2,
    server_unavailable = 3,
    bad_user_name_or_password = 4,
    not_authorized = 5,
    _,

    /// The words a message to a user prints for this code.
    pub fn describe(c: ReturnCode) []const u8 {
        return switch (c) {
            .accepted => "the connection was accepted",
            .unacceptable_protocol_version => "the broker does not speak MQTT 3.1.1",
            .identifier_rejected => "the broker refused the client identifier",
            .server_unavailable => "the broker is not available",
            .bad_user_name_or_password => "the broker refused the user name or the password",
            .not_authorized => "the broker did not authorize this client",
            _ => "the broker answered with a return code MQTT 3.1.1 does not name",
        };
    }
};

/// Reads the return code out of a CONNACK's body. Section 3.2.
pub fn connackReturnCode(body: []const u8) ReadError!ReturnCode {
    if (body.len < 2) return error.PacketTruncated;
    return @enumFromInt(body[1]);
}

/// The return code a SUBACK carries for the one filter this package sends.
///
/// Section 3.9.3 names three granted QoS values and one failure. This
/// build asks for QoS 0 and a broker may grant no more than it was asked
/// for, so any granted value is a success and `0x80` is the refusal.
pub const suback_failure: u8 = 0x80;

/// What one SUBACK said.
pub const Suback = struct {
    packet_id: u16,
    /// The one byte the broker returned for the one filter that was sent.
    code: u8,

    /// Whether the broker took the subscription.
    pub fn granted(s: Suback) bool {
        return s.code != suback_failure;
    }
};

/// Reads a SUBACK's body. Section 3.9.
pub fn suback(body: []const u8) ReadError!Suback {
    if (body.len < 3) return error.PacketTruncated;
    return .{
        .packet_id = std.mem.readInt(u16, body[0..2], .big),
        .code = body[2],
    };
}

/// What one PUBLISH carried.
pub const Publish = struct {
    /// The topic the broker sent this message on. Points into the body it
    /// was read from.
    topic: []const u8,
    /// The message itself. Points into the body it was read from.
    message: []const u8,
    /// The bytes of the body from the topic count through the end.
    ///
    /// **This is what curl writes to standard output**, measured: a
    /// subscribe printed `00 08 "zurl/sub" "payload-one"` for one message,
    /// which is the two byte count and the topic in front of the payload.
    /// See `zurl_mqtt.Fetcher` for why this build writes the same bytes.
    raw: []const u8,
};

/// Reads a PUBLISH's body. Section 3.3.
///
/// `flags` is the low nibble of the fixed header, which carries the QoS in
/// bits 1 and 2. **A QoS above zero is read far enough to skip its packet
/// identifier and no further**: this build sends no acknowledgement, so a
/// broker that delivers at QoS 1 gets no PUBACK and will send the message
/// again on the next session. `Fetcher` says so in a diagnostic rather
/// than let a user think the message was acknowledged.
pub fn publish(body: []const u8, flags: u4) ReadError!Publish {
    if (body.len < 2) return error.PacketTruncated;
    const topic_len = std.mem.readInt(u16, body[0..2], .big);
    if (@as(usize, topic_len) + 2 > body.len) return error.StringRunsPast;
    const topic = body[2..][0..topic_len];

    var at: usize = 2 + @as(usize, topic_len);
    const qos = (flags >> 1) & 0b11;
    if (qos != 0) {
        if (at + 2 > body.len) return error.PacketTruncated;
        at += 2;
    }

    return .{ .topic = topic, .message = body[at..], .raw = body };
}

const testing = std.testing;

/// A `Writer` on the heap, because it holds a megabyte.
fn testWriter() !*Writer {
    const w = try testing.allocator.create(Writer);
    w.init();
    return w;
}

test "the CONNECT is the one curl sends, byte for byte" {
    // Measured off curl 8.21.0 through a relay to mosquitto 2.1.2. The
    // client id is the only part that differs, because curl writes `curl`
    // and eight random bytes and this writes `zurl` and eight.
    const w = try testWriter();
    defer testing.allocator.destroy(w);

    try writeConnect(w, "zurlIAgOj05A", "", "");
    try testing.expectEqualSlices(u8, &.{
        0x10, 0x18,
        0x00, 0x04,
        'M',  'Q',
        'T',  'T',
        0x04, 0x02,
        0x00, 0x3c,
        0x00, 0x0c,
        'z',  'u',
        'r',  'l',
        'I',  'A',
        'g',  'O',
        'j',  '0',
        '5',  'A',
    }, w.written());
}

test "a credential sets both flag bits and adds two strings, as curl does" {
    // Measured: `-u alice:s3cret` turned the flag byte from `02` into `c2`
    // and put `00 05 "alice" 00 06 "s3cret"` on the end.
    const w = try testWriter();
    defer testing.allocator.destroy(w);

    try writeConnect(w, "zurljAM5vLqk", "alice", "s3cret");
    const bytes = w.written();
    try testing.expectEqual(@as(u8, 0x10), bytes[0]);
    try testing.expectEqual(@as(u8, 0x27), bytes[1]);
    try testing.expectEqual(@as(u8, 0xc2), bytes[9]);
    try testing.expectEqualStrings("alice", bytes[28..33]);
    try testing.expectEqualStrings("s3cret", bytes[35..41]);

    // A user name with no password sets one bit and not the other, which
    // is what curl sent for `mqtt://bob@host/t`.
    try writeConnect(w, "zurljAM5vLqk", "bob", "");
    try testing.expectEqual(
        @as(u8, connect_flag_clean_session | connect_flag_user_name),
        w.written()[9],
    );

    // A password with no user name is refused. MQTT 3.1.1 section 3.1.2.9
    // does not allow it and a broker throws the packet away.
    try testing.expectError(error.PasswordWithoutUser, writeConnect(w, "id", "", "pw"));
}

test "the PUBLISH is the one curl sends, byte for byte" {
    // Measured: `curl -d 'hello world' mqtt://127.0.0.1/zurl/test` put
    // `30 16 00 09 "zurl/test" "hello world"` on the wire.
    const w = try testWriter();
    defer testing.allocator.destroy(w);

    try writePublish(w, "zurl/test", "hello world");
    try testing.expectEqualSlices(u8, &.{
        0x30, 0x16,
        0x00, 0x09,
        'z',  'u',
        'r',  'l',
        '/',  't',
        'e',  's',
        't',  'h',
        'e',  'l',
        'l',  'o',
        ' ',  'w',
        'o',  'r',
        'l',  'd',
    }, w.written());
}

test "the SUBSCRIBE is the one curl sends, byte for byte" {
    // Measured: `curl mqtt://127.0.0.1/zurl/sub` put
    // `82 0d 00 01 00 08 "zurl/sub" 00` on the wire.
    const w = try testWriter();
    defer testing.allocator.destroy(w);

    try writeSubscribe(w, 1, "zurl/sub");
    try testing.expectEqualSlices(u8, &.{
        0x82, 0x0d,
        0x00, 0x01,
        0x00, 0x08,
        'z',  'u',
        'r',  'l',
        '/',  's',
        'u',  'b',
        0x00,
    }, w.written());
}

test "the DISCONNECT is the two bytes curl sends" {
    const w = try testWriter();
    defer testing.allocator.destroy(w);
    try writeDisconnect(w);
    try testing.expectEqualSlices(u8, &.{ 0xe0, 0x00 }, w.written());
}

test "a payload past 127 bytes puts a two byte length on the wire" {
    // Measured: a 300 byte `--data-binary` on the topic `t/k` went out as
    // `30 b1 02 00 03 74 2f 6b` and then 300 bytes.
    const w = try testWriter();
    defer testing.allocator.destroy(w);

    const payload = [_]u8{'K'} ** 300;
    try writePublish(w, "t/k", &payload);
    const bytes = w.written();
    try testing.expectEqualSlices(u8, &.{ 0x30, 0xb1, 0x02, 0x00, 0x03, 't', '/', 'k' }, bytes[0..8]);
    try testing.expectEqual(@as(usize, 3 + 2 + 3 + 300), bytes.len);
    try testing.expectEqualSlices(u8, &payload, bytes[8..]);
}

test "a topic of any byte at all reaches the wire whole, inside its count" {
    // **The framing proof of this package's injection rule.** A CR, an LF,
    // and a NUL each end a command line in every other protocol here. In
    // MQTT they are data: the count in front of the string is computed
    // from the bytes, so the packet ends where the count says and nowhere
    // else. `zurl_mqtt.topic` still refuses a NUL, for the reason it
    // gives, and this proves the framing does not need it to.
    const w = try testWriter();
    defer testing.allocator.destroy(w);

    const nasty = "a\r\n\x00\x1b\xffb";
    try writePublish(w, nasty, "\x00\r\n\xff");
    const bytes = w.written();
    try testing.expectEqual(@as(u8, 0x30), bytes[0]);
    // Two count bytes, seven topic bytes, four payload bytes.
    try testing.expectEqual(@as(u8, 13), bytes[1]);
    try testing.expectEqual(@as(usize, 15), bytes.len);

    // And it reads back as the same two fields.
    const read = try publish(bytes[2..], 0);
    try testing.expectEqualStrings(nasty, read.topic);
    try testing.expectEqualSlices(u8, "\x00\r\n\xff", read.message);
}

test "a string longer than its count holds is refused before a byte is written" {
    const w = try testWriter();
    defer testing.allocator.destroy(w);

    const huge = try testing.allocator.alloc(u8, max_string_bytes + 1);
    defer testing.allocator.free(huge);
    @memset(huge, 't');

    try testing.expectError(error.StringTooLong, writePublish(w, huge, ""));
    try testing.expectError(error.StringTooLong, writeSubscribe(w, 1, huge));
    try testing.expectError(error.StringTooLong, writeConnect(w, huge, "", ""));
}

test "a CONNACK says whether the broker took the connection" {
    // Measured: mosquitto answered `20 02 00 00` for an accepted connect.
    try testing.expectEqual(ReturnCode.accepted, try connackReturnCode(&.{ 0x00, 0x00 }));
    try testing.expectEqual(
        ReturnCode.not_authorized,
        try connackReturnCode(&.{ 0x00, 0x05 }),
    );
    // A code nobody named still reads, and it still says nothing was
    // accepted.
    const unknown = try connackReturnCode(&.{ 0x00, 0x77 });
    try testing.expect(unknown != .accepted);
    try testing.expect(unknown.describe().len != 0);

    // A body too short for the two bytes is refused rather than read past.
    try testing.expectError(error.PacketTruncated, connackReturnCode(&.{}));
    try testing.expectError(error.PacketTruncated, connackReturnCode(&.{0x00}));
}

test "a SUBACK says whether the filter was granted" {
    // Measured: mosquitto answered `90 03 00 01 00`.
    const taken = try suback(&.{ 0x00, 0x01, 0x00 });
    try testing.expectEqual(@as(u16, 1), taken.packet_id);
    try testing.expect(taken.granted());

    const refused = try suback(&.{ 0x00, 0x01, suback_failure });
    try testing.expect(!refused.granted());

    try testing.expectError(error.PacketTruncated, suback(&.{ 0x00, 0x01 }));
}

test "a PUBLISH whose topic count runs past the packet is refused" {
    // **The bound on a count a peer chose.** The count says the topic is
    // 40 bytes and the packet holds four, so a reader with no check here
    // would hand a caller a slice of memory the packet never carried.
    try testing.expectError(error.StringRunsPast, publish(&.{ 0x00, 0x28, 'a', 'b' }, 0));
    try testing.expectError(error.StringRunsPast, publish(&.{ 0xff, 0xff }, 0));
    try testing.expectError(error.PacketTruncated, publish(&.{0x00}, 0));

    // A count of exactly what is left reads, with an empty message.
    const exact = try publish(&.{ 0x00, 0x02, 'a', 'b' }, 0);
    try testing.expectEqualStrings("ab", exact.topic);
    try testing.expectEqualStrings("", exact.message);
}

test "a PUBLISH at QoS 1 skips its packet identifier and no further" {
    // The identifier sits between the topic and the message at QoS 1 and
    // 2. A reader that did not skip it would put two bytes of framing at
    // the front of every message.
    const body = [_]u8{ 0x00, 0x02, 'a', 'b', 0x00, 0x07, 'm', 's', 'g' };
    const read = try publish(&body, 0b0010);
    try testing.expectEqualStrings("ab", read.topic);
    try testing.expectEqualStrings("msg", read.message);

    // And a packet too short to hold the identifier is refused.
    try testing.expectError(
        error.PacketTruncated,
        publish(&.{ 0x00, 0x02, 'a', 'b', 0x00 }, 0b0010),
    );
}

test "the raw field is the bytes curl prints for one message" {
    // Measured: a subscribe to `zurl/sub` printed
    // `00 08 "zurl/sub" "payload-one"` on standard output, which is the
    // whole body of the PUBLISH.
    const body = [_]u8{ 0x00, 0x08 } ++ "zurl/sub".* ++ "payload-one".*;
    const read = try publish(&body, 0);
    try testing.expectEqualSlices(u8, &body, read.raw);
    try testing.expectEqualStrings("zurl/sub", read.topic);
    try testing.expectEqualStrings("payload-one", read.message);
}

test "every packet type has a name of its own" {
    const every = [_]Type{
        .connect,  .connack, .publish,   .puback,     .pubrec,
        .pubrel,   .pubcomp, .subscribe, .suback,     .unsubscribe,
        .unsuback, .pingreq, .pingresp,  .disconnect,
    };
    for (every) |kind| {
        try testing.expect(kind.describe().len != 0);
        for (every) |other| {
            if (kind == other) continue;
            try testing.expect(!std.mem.eql(u8, kind.describe(), other.describe()));
        }
    }
}
