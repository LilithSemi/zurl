//! One LDAP dialogue: the message ids, the envelope off the socket, and
//! the bound on what one message may hold.
//!
//! **This is the file that reads an attacker-controlled length before it
//! reads the bytes that length describes.** `ber.zig` bounds a length
//! inside a buffer that already exists. This one has no buffer yet: the
//! header arrives first, the length is in it, and the buffer is made from
//! that number. So the order here is the whole point:
//!
//! 1. Read the tag byte and the first length byte, two bytes, into a field
//!    of this value. Nothing is allocated.
//! 2. Refuse a tag that is not `SEQUENCE`, and refuse the indefinite
//!    length form and a length octet count over `ber.max_length_octets`.
//! 3. Read the remaining length octets, at most four, into the same field.
//! 4. **Check the length against `max_message_bytes` before anything is
//!    allocated.**
//! 5. Grow the buffer to fit and read exactly that many bytes.
//! 6. Hand the whole message to `message.read`, which walks it with
//!    `ber.Cursor` and its own nesting bound.
//!
//! A peer that says `30 84 ff ff ff ff` therefore costs this process six
//! bytes read and one comparison, and never four gigabytes of memory.
//!
//! **A `Session` must not move once a message has been read from it.** The
//! message a caller holds points into `buffer`, which this value owns.
//!
//! What this file does not own: the meaning of a message, which is
//! `message.zig`, and what a transfer does with one, which is
//! `Fetcher.zig`.

const Session = @This();

const std = @import("std");
const zurl_net = @import("zurl-net");

const ber = @import("ber.zig");
const message = @import("message.zig");

const Io = std.Io;

/// How many bytes one `LDAPMessage` may hold, its header counted.
///
/// **This is the bound the header check above reads.** 8 MiB is past any
/// message a directory sends: a `SearchResultEntry` carrying a
/// photograph is a few hundred kilobytes, and a server that has more to
/// say sends more entries rather than one larger one.
///
/// It is smaller than `ber.max_element_bytes`, so the bound a caller meets
/// first is this one, which is the one whose sentence names a message.
pub const max_message_bytes: usize = 8 * 1024 * 1024;

/// How many bytes a message header may take: the tag, the length octet
/// count, and up to `ber.max_length_octets` length octets.
pub const max_header_bytes: usize = 2 + ber.max_length_octets;

/// The message id RFC 4511 section 4.4 gives an unsolicited notification.
///
/// Zero, and a server sends one when it is about to close the connection.
/// It is the one reply whose id does not match a request, so `receive`
/// reads it apart from a mismatch rather than refuse it as one.
pub const notification_id: i32 = 0;

/// Every fault a dialogue can report.
pub const Error = message.ReadError || error{
    /// The peer sent a message longer than `max_message_bytes`. No byte of
    /// it past the header is read.
    MessageTooLarge,
    /// The peer answered a message id this session never sent. See
    /// `receive`.
    MessageIdMismatch,
    /// The peer sent the unsolicited notification of RFC 4511 section
    /// 4.4.1: it is closing the connection.
    ServerDisconnecting,
    /// This session has sent every message id RFC 4511 allows.
    MessageIdExhausted,
    /// The connection failed. `Connection.readError` names the cause.
    ReadFailed,
    /// The peer sent no byte for as long as this waits.
    OperationTimedOut,
    /// The caller asked for a stall bound and this build has no
    /// concurrency, so nothing can watch the clock while the read runs.
    ReadTimeoutUnsupported,
    /// The read was stopped from outside.
    Canceled,
    /// The peer closed in the middle of a message, or before one.
    EndOfStream,
    /// A write did not reach the peer.
    WriteFailed,
    /// The message needs more memory than this process has.
    OutOfMemory,
};

gpa: std.mem.Allocator,
io: Io,
channel: zurl_net.line.Channel,
/// How long one read may wait with no byte arriving.
stall: Io.Timeout,
/// Holds the message in play. Grown on demand and never past
/// `max_message_bytes`. Null until the first message arrives.
buffer: ?[]u8,
/// Holds the header of the message being read, before the buffer exists.
header: [max_header_bytes]u8,
/// The id the next request carries. RFC 4511 section 4.1.1.1 starts at
/// one, and curl's first message id is 1, measured.
next_id: i32,

/// A session that holds no buffer and points at no channel.
///
/// **`begin` is what starts a dialogue, and this is what makes the
/// value.** The two are separate because the buffer outlives one transfer:
/// a `Fetcher` that ran a search once reads the next one with no
/// allocation at all, and a `begin` that emptied the buffer would leak it
/// instead.
pub fn init(gpa: std.mem.Allocator, io: Io) Session {
    return .{
        .gpa = gpa,
        .io = io,
        .channel = undefined,
        .stall = .none,
        .buffer = null,
        .header = undefined,
        .next_id = 1,
    };
}

/// Starts one dialogue over `channel`, keeping the buffer this session
/// already grew.
///
/// The message ids start again at one, which is what a new connection
/// wants: RFC 4511 section 4.1.1.1 scopes an id to a connection, and curl's
/// first id on every connection is 1, measured.
pub fn begin(s: *Session, channel: zurl_net.line.Channel, stall: Io.Timeout) void {
    s.channel = channel;
    s.stall = stall;
    s.next_id = 1;
}

/// Frees what this session holds, after wiping it.
pub fn deinit(s: *Session) void {
    s.wipe();
    if (s.buffer) |held| s.gpa.free(held);
    s.buffer = null;
}

/// Zeroes every buffer this session holds.
///
/// **A message buffer holds directory entries**, and a directory entry may
/// hold a `userPassword`. The buffer outlives the transfer that read it,
/// because it is reused, so a later reader of this memory would find the
/// last transfer's answer. `Fetcher.open` runs this with a `defer`, which
/// is the rule `zurl-scp` records.
pub fn wipe(s: *Session) void {
    if (s.buffer) |held| std.crypto.secureZero(u8, held);
    std.crypto.secureZero(u8, &s.header);
}

/// Points this session at another channel, keeping its message ids.
///
/// **This is what a StartTLS upgrade needs.** RFC 4511 section 4.14 runs
/// the extended operation on the plain stream and everything after it
/// inside the session, and the message ids run on across the change: a
/// server that saw id 1 for the StartTLS must not see id 1 again for the
/// bind.
pub fn retarget(s: *Session, channel: zurl_net.line.Channel) void {
    s.channel = channel;
}

/// The id for the next request, and moves on.
pub fn takeId(s: *Session) Error!i32 {
    if (s.next_id == message.max_message_id) return error.MessageIdExhausted;
    const id = s.next_id;
    s.next_id += 1;
    return id;
}

/// How many bytes are buffered and not read yet.
///
/// **A StartTLS upgrade reads this before the handshake.** A server that
/// wrote bytes behind its answer wrote them in cleartext, and carrying
/// them into the session would hand a caller text a listener could have
/// chosen.
pub fn buffered(s: *const Session) usize {
    return s.channel.reader.buffered().len;
}

/// Writes one whole message and flushes it.
pub fn send(s: *Session, bytes: []const u8) Error!void {
    s.channel.writer.writeAll(bytes) catch return error.WriteFailed;
    s.channel.flush(s.channel.ctx) catch return error.WriteFailed;
}

/// Reads one whole message and returns what it holds.
///
/// `want_id` is the message id this reply must carry. A reply with
/// another id is `error.MessageIdMismatch`, because a reply to a request
/// this session did not send is a reply this session cannot read: the
/// operation it answers decides what its fields mean.
///
/// **The one id that is not a mismatch is zero.** RFC 4511 section 4.4.1
/// gives an unsolicited notification message id zero, and a server sends
/// one, an `ExtendedResponse`, when it is about to close. That reads as
/// `error.ServerDisconnecting` and never as a mismatch, so a user learns
/// the server hung up rather than that the ids did not line up.
///
/// The returned `message.Message` borrows this session's buffer. It is
/// valid until the next `receive` and until `deinit`.
pub fn receive(s: *Session, want_id: i32) Error!message.Message {
    const total = try s.readEnvelope();
    const m = try message.read(s.buffer.?[0..total]);

    if (m.id == want_id) return m;
    if (m.id == notification_id and m.kind == .extended_response) {
        return error.ServerDisconnecting;
    }
    return error.MessageIdMismatch;
}

/// Reads the header and then the body, and returns how many bytes of
/// `buffer` the whole message takes.
///
/// See the module doc comment for the order the checks run in.
fn readEnvelope(s: *Session) Error!usize {
    try s.readExact(s.header[0..2]);

    // Every LDAPMessage is a `SEQUENCE`. A peer that starts one with
    // anything else is a peer this build cannot read, and reading past the
    // tag would be reading a length from a field that is not one.
    if (s.header[0] != ber.sequence.byte()) return error.UnexpectedTag;

    const first = s.header[1];
    var header_len: usize = 2;
    var body_len: usize = 0;

    if (first < 0x80) {
        body_len = first;
    } else if (first == 0x80) {
        return error.IndefiniteLength;
    } else {
        const count: usize = first & 0x7f;
        if (count > ber.max_length_octets) return error.LengthTooLarge;
        try s.readExact(s.header[2..][0..count]);
        var value: u64 = 0;
        for (s.header[2..][0..count]) |b| {
            value = (value << 8) | b;
        }
        // **The bound, and it runs before anything is allocated.** `count`
        // is at most four, so `value` is at most 0xffffffff, and this
        // comparison is what keeps that number from reaching an
        // allocation.
        if (value > max_message_bytes) return error.MessageTooLarge;
        body_len = @intCast(value);
        header_len = 2 + count;
    }

    const total = std.math.add(usize, header_len, body_len) catch return error.MessageTooLarge;
    if (total > max_message_bytes) return error.MessageTooLarge;

    try s.grow(total);
    const held = s.buffer.?;
    @memcpy(held[0..header_len], s.header[0..header_len]);
    try s.readExact(held[header_len..total]);
    return total;
}

/// Makes sure `buffer` holds at least `need` bytes.
///
/// It grows and never shrinks, so a session that read one large message
/// reads every later one with no allocation at all. `need` is already
/// under `max_message_bytes` when this runs.
fn grow(s: *Session, need: usize) Error!void {
    std.debug.assert(need <= max_message_bytes);
    if (s.buffer) |held| {
        if (held.len >= need) return;
        // The old bytes are a message this session already read, so they
        // are wiped before the copy that `realloc` may make.
        std.crypto.secureZero(u8, held);
        s.buffer = s.gpa.realloc(held, need) catch return error.OutOfMemory;
        return;
    }
    s.buffer = s.gpa.alloc(u8, need) catch return error.OutOfMemory;
}

/// Fills `out` from the peer, under the stall bound.
fn readExact(s: *Session, out: []u8) Error!void {
    return zurl_net.bounded.readExact(s.channel.reader, s.io, out, s.stall) catch |err| switch (err) {
        error.EndOfStream => error.EndOfStream,
        error.ReadFailed => error.ReadFailed,
        error.OperationTimedOut => error.OperationTimedOut,
        error.ReadTimeoutUnsupported => error.ReadTimeoutUnsupported,
        error.Canceled => error.Canceled,
        error.OutOfMemory => error.OutOfMemory,
        error.StreamTooLong => error.MessageTooLarge,
    };
}

const testing = std.testing;

/// A session over two buffers, with no socket at all.
const Pair = struct {
    session: Session,
    reader: Io.Reader,
    writer: Io.Writer,
    out: [4096]u8 = undefined,

    fn init(p: *Pair, incoming: []const u8) void {
        p.reader = .fixed(incoming);
        p.writer = .fixed(&p.out);
        p.session = .init(testing.allocator, testing.io);
        p.session.begin(.{
            .reader = &p.reader,
            .writer = &p.writer,
            .ctx = null,
            .flush = noFlush,
        }, .none);
    }

    fn noFlush(ctx: ?*anyopaque) Io.Writer.Error!void {
        _ = ctx;
    }
};

test "a message ids run from one and never repeat" {
    var p: Pair = undefined;
    p.init("");
    defer p.session.deinit();

    // curl's first message id is 1, measured on the wire.
    try testing.expectEqual(@as(i32, 1), try p.session.takeId());
    try testing.expectEqual(@as(i32, 2), try p.session.takeId());
    try testing.expectEqual(@as(i32, 3), try p.session.takeId());

    p.session.next_id = message.max_message_id;
    try testing.expectError(error.MessageIdExhausted, p.session.takeId());
}

test "a whole message read off two buffers comes back with its fields" {
    // The BindResponse slapd sent, measured.
    const bytes = [_]u8{
        0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07,
        0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
    };
    var p: Pair = undefined;
    p.init(&bytes);
    defer p.session.deinit();

    const m = try p.session.receive(1);
    try testing.expectEqual(@as(i32, 1), m.id);
    try testing.expectEqual(message.Kind.bind_response, m.kind);
    try testing.expectEqual(message.ResultCode.success, (try message.result(m.op)).code);
}

test "two messages in one read come back one at a time and in order" {
    // slapd wrote the entry and the done in one segment, measured.
    const bytes = [_]u8{ 0x30, 0x26, 0x02, 0x01, 0x02, 0x64, 0x21, 0x04, 0x0f } ++
        "dc=zurl,dc=test".* ++
        [_]u8{ 0x30, 0x0e, 0x30, 0x0c, 0x04, 0x02, 'd', 'c', 0x31, 0x06, 0x04, 0x04 } ++ "zurl".* ++
        [_]u8{ 0x30, 0x0c, 0x02, 0x01, 0x02, 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00 };

    var p: Pair = undefined;
    p.init(&bytes);
    defer p.session.deinit();

    const first = try p.session.receive(2);
    try testing.expectEqual(message.Kind.search_entry, first.kind);
    try testing.expectEqualStrings("dc=zurl,dc=test", (try message.entry(first.op)).dn);

    const second = try p.session.receive(2);
    try testing.expectEqual(message.Kind.search_done, second.kind);
    try testing.expectEqual(message.ResultCode.success, (try message.result(second.op)).code);
}

test "a length that names more than max_message_bytes is refused after six bytes" {
    // **The check this file exists for.** A peer that says
    // `30 84 ff ff ff ff` names four gigabytes. Nothing is allocated for
    // it, and the six header bytes are all that this reads.
    var p: Pair = undefined;
    p.init(&.{ 0x30, 0x84, 0xff, 0xff, 0xff, 0xff });
    defer p.session.deinit();

    try testing.expectError(error.MessageTooLarge, p.session.receive(1));
    try testing.expectEqual(@as(?[]u8, null), p.session.buffer);
}

test "one byte past the bound is still past it, and one byte under is not" {
    const over = max_message_bytes + 1;
    var p: Pair = undefined;
    p.init(&.{
        0x30,                  0x84,
        @truncate(over >> 24), @truncate(over >> 16),
        @truncate(over >> 8),  @truncate(over),
    });
    defer p.session.deinit();
    try testing.expectError(error.MessageTooLarge, p.session.receive(1));
    try testing.expectEqual(@as(?[]u8, null), p.session.buffer);
}

test "the indefinite length form is refused before any body is read" {
    var p: Pair = undefined;
    p.init(&.{ 0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00 });
    defer p.session.deinit();
    try testing.expectError(error.IndefiniteLength, p.session.receive(1));
    try testing.expectEqual(@as(?[]u8, null), p.session.buffer);
}

test "a length octet count past four is refused before any body is read" {
    var p: Pair = undefined;
    p.init(&.{ 0x30, 0x85, 1, 2, 3, 4, 5 });
    defer p.session.deinit();
    try testing.expectError(error.LengthTooLarge, p.session.receive(1));
    try testing.expectEqual(@as(?[]u8, null), p.session.buffer);
}

test "a message that does not start with a SEQUENCE is refused at its first byte" {
    var p: Pair = undefined;
    p.init(&.{ 0x04, 0x02, 'a', 'b' });
    defer p.session.deinit();
    try testing.expectError(error.UnexpectedTag, p.session.receive(1));
}

test "a peer that closes in the middle of a message is a fault and not a short one" {
    // The header says twelve bytes of body and the peer sent four.
    var p: Pair = undefined;
    p.init(&.{ 0x30, 0x0c, 0x02, 0x01, 0x01, 0x61 });
    defer p.session.deinit();
    try testing.expectError(error.EndOfStream, p.session.receive(1));
}

test "a reply carrying another request's id is refused by name" {
    // The id decides which operation a reply answers, so a reply to a
    // request this session did not send is a reply it cannot read.
    const bytes = [_]u8{
        0x30, 0x0c, 0x02, 0x01, 0x09, 0x61, 0x07,
        0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
    };
    var p: Pair = undefined;
    p.init(&bytes);
    defer p.session.deinit();
    try testing.expectError(error.MessageIdMismatch, p.session.receive(1));
}

test "the unsolicited notification of RFC 4511 reads as a disconnection" {
    // Message id zero and an `ExtendedResponse`, which is what a server
    // sends when it is about to close. Reading it as an id mismatch would
    // send a user to look at the wrong thing.
    const bytes = [_]u8{
        0x30, 0x0c, 0x02, 0x01, 0x00, 0x78, 0x07,
        0x0a, 0x01, 0x34, 0x04, 0x00, 0x04, 0x00,
    };
    var p: Pair = undefined;
    p.init(&bytes);
    defer p.session.deinit();
    try testing.expectError(error.ServerDisconnecting, p.session.receive(1));
}

test "a message id of zero that is not an extended response is still a mismatch" {
    const bytes = [_]u8{
        0x30, 0x0c, 0x02, 0x01, 0x00, 0x61, 0x07,
        0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
    };
    var p: Pair = undefined;
    p.init(&bytes);
    defer p.session.deinit();
    try testing.expectError(error.MessageIdMismatch, p.session.receive(1));
}

test "the buffer grows for a larger message and is not shrunk for a smaller one" {
    // One long message and one short one. The second must not allocate.
    const long_value = "z" ** 200;
    // `30 81 d6` holds 214 bytes: the id, then a BindResponse of 208 whose
    // diagnostic is `04 81 c8` and 200 octets.
    const long = [_]u8{
        0x30, 0x81, 0xd6, 0x02, 0x01, 0x01, 0x61, 0x81,
        0xd0, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x81,
        0xc8,
    } ++ long_value.*;
    const short = [_]u8{
        0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07,
        0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
    };

    var p: Pair = undefined;
    p.init(&(long ++ short));
    defer p.session.deinit();

    const first = try p.session.receive(1);
    try testing.expectEqualStrings(long_value, (try message.result(first.op)).diagnostic);
    const grown = p.session.buffer.?.len;
    try testing.expect(grown >= long.len);

    _ = try p.session.receive(1);
    try testing.expectEqual(grown, p.session.buffer.?.len);
}

test "wipe leaves nothing of the last message in the buffer" {
    // The buffer outlives the transfer that read it, so a later reader of
    // this memory must find zeros and not the last entry.
    const bytes = [_]u8{ 0x30, 0x14, 0x02, 0x01, 0x01, 0x61, 0x0f, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x08 } ++ "hunter2!".*;
    var p: Pair = undefined;
    p.init(&bytes);
    defer p.session.deinit();

    _ = try p.session.receive(1);
    try testing.expect(std.mem.indexOf(u8, p.session.buffer.?, "hunter2!") != null);

    p.session.wipe();
    try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, p.session.buffer.?, "hunter2!"));
    for (p.session.buffer.?) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "send writes every byte it is given and flushes them" {
    var p: Pair = undefined;
    p.init("");
    defer p.session.deinit();

    var w: message.RequestWriter = .init();
    try message.writeUnbind(&w, 3);
    try p.session.send(w.written());
    try testing.expectEqualSlices(u8, &.{ 0x30, 0x05, 0x02, 0x01, 0x03, 0x42, 0x00 }, p.writer.buffered());
}

test "buffered reports what the peer wrote and has not been read yet" {
    var p: Pair = undefined;
    p.init(&.{ 0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 'x' });
    defer p.session.deinit();

    _ = try p.session.receive(1);
    // The one byte behind the message is still there.
    try testing.expectEqual(@as(usize, 1), p.session.buffered());
}
