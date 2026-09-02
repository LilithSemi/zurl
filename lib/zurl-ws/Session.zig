//! One WebSocket dialogue, over one reader and one writer.
//!
//! `frame.zig` says what shapes RFC 6455 allows. This file adds the two
//! rules that depend on **which end** of the connection is speaking:
//!
//! - **A frame that arrives masked is refused.** RFC 6455 section 5.1
//!   says a server must not mask. A masked frame from a server is a
//!   protocol violation, and reading it as a payload would let a peer
//!   choose whether four octets of its own text are read as a mask key or
//!   as data.
//! - **Every frame that goes out is masked, with a key drawn afresh for
//!   that one frame.** Section 5.1 and section 5.3 say a client must mask
//!   every frame, and section 5.3 says the key must be unpredictable.
//!   `writeControl` is the only writer, and it draws through
//!   `handshake.drawMask`, which reads `io.randomSecure`. There is no path
//!   through this file that writes an unmasked frame and none that reuses
//!   a key.
//!
//! **And the one rule that needs memory of the last frame.** RFC 6455
//! section 5.4 makes a message a `text` or a `binary` frame and then the
//! `continuation` frames that finish it. `frame.zig` reads one header and
//! nothing else, so it cannot see the order. This file holds one bit,
//! `message_open`, and refuses the two orders section 5.4 forbids: a
//! `continuation` frame with no message open, and a `text` or `binary`
//! frame that starts while the last message is unfinished. A reader with
//! no such bit hands the octets of a stray continuation frame up as a
//! message of its own, which is a stream RFC 6455 says to reject.
//!
//! **The client writes control frames and nothing else.** zurl reads a
//! WebSocket, the way curl's own tool does: it answers a ping with a pong
//! and it answers a close with a close. So `writeControl` takes the
//! payload by value into a 125 octet scratch, which is the whole size RFC
//! 6455 section 5.5 allows a control frame, and a data frame needs no
//! streaming writer here.
//!
//! **A `Session` must not move while a payload read from it is in use.**
//! The scratch is a field of this value.
//!
//! This file opens nothing. It reads and writes through the caller's own
//! `zurl_net.line.Channel`, so a test drives a whole dialogue over two
//! buffers with no socket at all.

const Session = @This();

const std = @import("std");
const zurl_net = @import("zurl-net");

const frame = @import("frame.zig");
const handshake = @import("handshake.zig");

const Io = std.Io;

io: Io,
/// Where this dialogue reads and writes. `flush` is a function pointer
/// because a `zurl_net.Connection` needs its own: an encrypted connection
/// has a plaintext buffer and a ciphertext buffer in a row, and flushing
/// only the first leaves the frame inside the process.
channel: zurl_net.line.Channel,
/// Backs the masked copy of an outgoing control payload. A field and not a
/// stack buffer, so the bound is one named number.
scratch: [frame.max_control_payload_bytes]u8 = undefined,
/// Whether a fragmented message is open, which is true from the first
/// frame of a message that is not final until the `continuation` frame
/// that finishes it. RFC 6455 section 5.4. A control frame does not touch
/// it, because section 5.4 lets one arrive between the pieces.
message_open: bool = false,

/// Why a frame could not be read.
pub const ReadError = zurl_net.bounded.ExactError || frame.DecodeError || error{
    /// The peer masked a frame. RFC 6455 section 5.1 says a server must
    /// not, so this is a protocol violation and never a payload.
    ServerFrameMasked,
    /// A `continuation` frame arrived with no message open, or a `text`
    /// or `binary` frame arrived while the last message was unfinished.
    /// RFC 6455 section 5.4 says a reader must fail the connection for
    /// either.
    MessageOutOfOrder,
};

/// Why a frame could not be written.
pub const WriteError = Io.Writer.Error || Io.RandomSecureError;

/// Reads one frame header.
///
/// Reads the two octet prefix, then exactly the octets that prefix says
/// follow, so nothing of the payload is consumed. Every shape RFC 6455
/// forbids is refused here or in `frame.decode`.
///
/// `stall` bounds one wait and never the whole read. A peer that writes
/// nothing at all for that long is `error.OperationTimedOut`.
pub fn readHeader(s: *Session, stall: Io.Timeout) ReadError!frame.Header {
    var prefix: [frame.prefix_bytes]u8 = undefined;
    try zurl_net.bounded.readExact(s.channel.reader, s.io, &prefix, stall);

    var extra: [frame.max_header_bytes - frame.prefix_bytes]u8 = undefined;
    const extra_len = frame.extraBytes(prefix);
    try zurl_net.bounded.readExact(s.channel.reader, s.io, extra[0..extra_len], stall);

    const header = try frame.decode(prefix, extra[0..extra_len]);
    // **The direction rule, and it is the reason this file exists.** RFC
    // 6455 section 5.1: a server must not mask.
    if (header.masked) return error.ServerFrameMasked;

    // **The order rule, RFC 6455 section 5.4.** A control frame may
    // arrive between the pieces of a message, so it changes nothing.
    // Every other frame either opens a message or continues one, and the
    // bit says which of the two this one is allowed to be.
    if (!header.opcode.isControl()) {
        const continues = header.opcode == .continuation;
        if (continues != s.message_open) return error.MessageOutOfOrder;
        s.message_open = !header.fin;
    }
    return header;
}

/// Fills `out` with a frame's payload.
///
/// The caller sizes `out` from the header it already read, after it has
/// checked that length against its own bound. A peer that closes before
/// `out` is full is `error.EndOfStream`: a frame that stopped in the
/// middle leaves no way to find the next header, so the only safe answer
/// is to end the session.
pub fn readPayload(
    s: *Session,
    out: []u8,
    stall: Io.Timeout,
) zurl_net.bounded.ExactError!void {
    try zurl_net.bounded.readExact(s.channel.reader, s.io, out, stall);
}

/// Writes one control frame, masked with a key drawn for this frame
/// alone.
///
/// `payload` must fit `frame.max_control_payload_bytes`, which RFC 6455
/// section 5.5 is the whole allowance for a control frame. A longer one is
/// a programmer error and not a fault on the wire, so it is an assertion.
///
/// `opcode` must name a control frame, for the same reason: this is the
/// only writer, and a data frame written through it would be sent whole
/// with no way to fragment it.
///
/// The frame goes out flushed. A control frame that sat in a buffer would
/// be a pong the peer never sees, and a peer that sees no pong closes the
/// connection.
pub fn writeControl(
    s: *Session,
    opcode: frame.Opcode,
    payload: []const u8,
) WriteError!void {
    std.debug.assert(opcode.isControl());
    std.debug.assert(payload.len <= frame.max_control_payload_bytes);

    // **A fresh draw for this frame and no other.** See the file comment.
    var key: [frame.mask_key_bytes]u8 = undefined;
    try handshake.drawMask(s.io, &key);

    var header_storage: [frame.max_header_bytes]u8 = undefined;
    const header = frame.encode(&header_storage, .{
        .fin = true,
        .opcode = opcode,
        .masked = true,
        .payload_len = payload.len,
        .mask_key = key,
    });

    @memcpy(s.scratch[0..payload.len], payload);
    const masked = s.scratch[0..payload.len];
    frame.applyMask(masked, key, 0);

    try s.channel.writer.writeAll(header);
    try s.channel.writer.writeAll(masked);
    try s.channel.flush(s.channel.ctx);
}

const testing = std.testing;

/// A `Channel` over two buffers, so a test drives a dialogue with no
/// socket.
const Pair = struct {
    reader: Io.Reader,
    writer: Io.Writer,

    fn flush(ctx: ?*anyopaque) Io.Writer.Error!void {
        const self: *Pair = @ptrCast(@alignCast(ctx.?));
        try self.writer.flush();
    }

    fn channel(self: *Pair) zurl_net.line.Channel {
        return .{
            .reader = &self.reader,
            .writer = &self.writer,
            .ctx = self,
            .flush = flush,
        };
    }
};

test "an unmasked server frame reads back with its header" {
    // RFC 6455 section 5.7's unmasked "Hello".
    var out_storage: [64]u8 = undefined;
    var pair: Pair = .{
        .reader = .fixed("\x81\x05Hello"),
        .writer = .fixed(&out_storage),
    };
    var session: Session = .{ .io = testing.io, .channel = pair.channel() };

    const header = try session.readHeader(.none);
    try testing.expect(header.fin);
    try testing.expectEqual(frame.Opcode.text, header.opcode);
    try testing.expectEqual(@as(u64, 5), header.payload_len);

    var payload: [5]u8 = undefined;
    try session.readPayload(&payload, .none);
    try testing.expectEqualStrings("Hello", &payload);
}

test "a masked frame from the peer is refused" {
    // **The direction rule.** RFC 6455 section 5.1: a server must not
    // mask. These are the exact octets of the RFC's masked client frame,
    // arriving from the wrong end.
    var out_storage: [64]u8 = undefined;
    var pair: Pair = .{
        .reader = .fixed("\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58"),
        .writer = .fixed(&out_storage),
    };
    var session: Session = .{ .io = testing.io, .channel = pair.channel() };
    try testing.expectError(error.ServerFrameMasked, session.readHeader(.none));
}

test "a continuation frame with no message open is refused" {
    // RFC 6455 section 5.4: a `continuation` frame continues the message
    // the last non-final frame started. With nothing open there is
    // nothing to continue, and a reader that kept no state handed these
    // five octets up as a message of its own.
    var out_storage: [64]u8 = undefined;
    var pair: Pair = .{
        .reader = .fixed("\x80\x05Hello"),
        .writer = .fixed(&out_storage),
    };
    var session: Session = .{ .io = testing.io, .channel = pair.channel() };
    try testing.expectError(error.MessageOutOfOrder, session.readHeader(.none));
}

test "a new message that starts before the last one finished is refused" {
    // The first frame is text and not final, so a message is open. RFC
    // 6455 section 5.4 says only a `continuation` frame may follow.
    var out_storage: [64]u8 = undefined;
    var pair: Pair = .{
        .reader = .fixed("\x01\x02ab\x81\x02cd"),
        .writer = .fixed(&out_storage),
    };
    var session: Session = .{ .io = testing.io, .channel = pair.channel() };

    const first = try session.readHeader(.none);
    try testing.expect(!first.fin);
    try testing.expectEqual(frame.Opcode.text, first.opcode);
    var payload: [2]u8 = undefined;
    try session.readPayload(&payload, .none);
    try testing.expect(session.message_open);

    try testing.expectError(error.MessageOutOfOrder, session.readHeader(.none));
}

test "a message split over a first frame and its continuations reads whole" {
    // Text "ab", continuation "cd", final continuation "ef", with a ping
    // in the middle. RFC 6455 section 5.4 lets a control frame arrive
    // between the pieces, so the ping must not close the message.
    var out_storage: [128]u8 = undefined;
    var pair: Pair = .{
        .reader = .fixed("\x01\x02ab\x89\x00\x00\x02cd\x80\x02ef\x81\x01z"),
        .writer = .fixed(&out_storage),
    };
    var session: Session = .{ .io = testing.io, .channel = pair.channel() };
    var payload: [2]u8 = undefined;

    const first = try session.readHeader(.none);
    try testing.expectEqual(frame.Opcode.text, first.opcode);
    try session.readPayload(&payload, .none);
    try testing.expectEqualStrings("ab", &payload);

    const ping = try session.readHeader(.none);
    try testing.expectEqual(frame.Opcode.ping, ping.opcode);
    try testing.expect(session.message_open);

    const second = try session.readHeader(.none);
    try testing.expectEqual(frame.Opcode.continuation, second.opcode);
    try testing.expect(!second.fin);
    try session.readPayload(&payload, .none);
    try testing.expectEqualStrings("cd", &payload);

    const last = try session.readHeader(.none);
    try testing.expectEqual(frame.Opcode.continuation, last.opcode);
    try testing.expect(last.fin);
    try session.readPayload(&payload, .none);
    try testing.expectEqualStrings("ef", &payload);
    try testing.expect(!session.message_open);

    // The message closed, so a new one may start.
    const next = try session.readHeader(.none);
    try testing.expectEqual(frame.Opcode.text, next.opcode);
}

test "a frame that stops in the middle of its payload is not half read" {
    var out_storage: [64]u8 = undefined;
    var pair: Pair = .{
        .reader = .fixed("\x81\x05He"),
        .writer = .fixed(&out_storage),
    };
    var session: Session = .{ .io = testing.io, .channel = pair.channel() };
    _ = try session.readHeader(.none);
    var payload: [5]u8 = undefined;
    try testing.expectError(error.EndOfStream, session.readPayload(&payload, .none));
}

test "every frame this writes is masked" {
    var out_storage: [64]u8 = undefined;
    var pair: Pair = .{ .reader = .fixed(""), .writer = .fixed(&out_storage) };
    var session: Session = .{ .io = testing.io, .channel = pair.channel() };

    try session.writeControl(.pong, "ping-body");

    const written = pair.writer.buffered();
    var prefix: [frame.prefix_bytes]u8 = undefined;
    @memcpy(&prefix, written[0..frame.prefix_bytes]);
    // `decode` alone would refuse nothing about the mask, so the bit is
    // read straight off the wire here.
    try testing.expect((written[1] & 0x80) != 0);

    const extra_len = frame.extraBytes(prefix);
    const header = try frame.decode(prefix, written[frame.prefix_bytes..][0..extra_len]);
    try testing.expect(header.masked);
    try testing.expectEqual(frame.Opcode.pong, header.opcode);
    try testing.expect(header.fin);

    // The payload on the wire is the masked text, and unmasking it gives
    // back what the caller asked to send.
    var payload: [9]u8 = undefined;
    @memcpy(&payload, written[frame.prefix_bytes + extra_len ..][0..9]);
    // Masked, so the bytes on the wire are not the plain text.
    try testing.expect(!std.mem.eql(u8, "ping-body", &payload));
    frame.applyMask(&payload, header.mask_key, 0);
    try testing.expectEqualStrings("ping-body", &payload);
}

test "two frames in a row carry two different mask keys" {
    // **A key is drawn for one frame and never reused.** Two frames under
    // one key hand an attacker the exclusive-or of the two payloads. The
    // keys here come straight off the wire, so this reads what a peer
    // would read.
    var out_storage: [256]u8 = undefined;
    var pair: Pair = .{ .reader = .fixed(""), .writer = .fixed(&out_storage) };
    var session: Session = .{ .io = testing.io, .channel = pair.channel() };

    var keys: [8][frame.mask_key_bytes]u8 = undefined;
    for (&keys) |*key| {
        pair.writer = .fixed(&out_storage);
        try session.writeControl(.ping, "x");
        const written = pair.writer.buffered();
        // The prefix is two octets, then the four octet key, because a one
        // octet payload uses the shortest length form.
        try testing.expectEqual(@as(usize, 2 + 4 + 1), written.len);
        @memcpy(key, written[2..6]);
    }

    for (keys, 0..) |first, i| {
        for (keys[i + 1 ..]) |second| {
            try testing.expect(!std.mem.eql(u8, &first, &second));
        }
    }
}

test "a close frame goes out with the code it carries" {
    const close = @import("close.zig");
    var out_storage: [64]u8 = undefined;
    var pair: Pair = .{ .reader = .fixed(""), .writer = .fixed(&out_storage) };
    var session: Session = .{ .io = testing.io, .channel = pair.channel() };

    var code_storage: [2]u8 = undefined;
    try session.writeControl(.close, close.write(&code_storage, close.normal));

    const written = pair.writer.buffered();
    var prefix: [frame.prefix_bytes]u8 = undefined;
    @memcpy(&prefix, written[0..frame.prefix_bytes]);
    const extra_len = frame.extraBytes(prefix);
    const header = try frame.decode(prefix, written[frame.prefix_bytes..][0..extra_len]);
    try testing.expectEqual(frame.Opcode.close, header.opcode);
    try testing.expect(header.masked);

    var payload: [2]u8 = undefined;
    @memcpy(&payload, written[frame.prefix_bytes + extra_len ..][0..2]);
    frame.applyMask(&payload, header.mask_key, 0);
    try testing.expectEqual(@as(u16, 1000), std.mem.readInt(u16, &payload, .big));
}
