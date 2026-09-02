//! The RFC 959 command and reply dialogue, over one reader and one
//! writer.
//!
//! **This is the whole of the control connection, and it holds no
//! socket.** It reads through a `std.Io.Reader` and writes through a
//! `std.Io.Writer`, so the same code runs over a plain stream, over a TLS
//! session, and over two buffers in a test. That is what lets a test pin
//! the exact bytes of a whole login and transfer, `AUTH TLS` and `PROT P`
//! included, with no network at all.
//!
//! **Every command goes out through `command.write`**, which refuses a
//! NUL, a CR, or an LF in the argument. Nothing here writes to the
//! `std.Io.Writer` any other way, so no command can carry a forged line
//! ending whatever the argument came from.
//!
//! **Every reply is read whole.** `readReply` follows the RFC 959 rule for
//! a multi-line reply, which `reply.zig` holds: a reply that opens with a
//! hyphen ends only at a line carrying the same code and a space. A reader
//! that stopped at the first line would read the rest of a multi-line
//! greeting as the answer to the next command, and every answer after that
//! would belong to the command before it.
//!
//! **Every read is bounded twice**: `zurl_net.bounded.readLine` stops a
//! line that never ends, and `stall` stops a peer that writes nothing.
//! `reply.max_lines` and `reply.max_reply_bytes` stop a reply that never
//! ends.
//!
//! What this does not do: it dials nothing, it opens no data connection,
//! and it knows no url. `Fetcher.zig` owns all three.

const Control = @This();

const std = @import("std");
const zurl_net = @import("zurl-net");

const command = @import("command.zig");
const reply = @import("reply.zig");

const Io = std.Io;

/// Where the dialogue reads and writes.
///
/// `zurl_net.line.Channel`, which every line-oriented protocol package
/// shares. `flush` is a function pointer and not a call on `writer`,
/// because a `zurl_net.Connection` needs its own `flush`: an encrypted
/// connection has a plaintext buffer and a ciphertext buffer in a row, and
/// flushing only the first leaves the whole command inside the process. A
/// raw stream writer needs its own flush instead. One pointer serves both.
pub const Channel = zurl_net.line.Channel;

/// Every fault reading a reply can report.
pub const ReadError = zurl_net.bounded.LineError || reply.ParseError;

/// Every fault this can report.
pub const Error = ReadError || Io.Writer.Error || command.WriteError;

io: Io,
channel: Channel,
/// How long one read of a reply line may wait with no byte arriving.
stall: Io.Timeout,
/// Holds one reply line as it arrives.
line_storage: [reply.max_line_bytes]u8,
/// Holds the text of the reply in play.
reply_storage: [reply.max_reply_bytes]u8,
/// Holds one command line as it is built.
command_storage: [command.max_command_bytes]u8,

/// Initializes `c` in place.
///
/// In place, and not a value returned, because the storage above is over
/// eleven kilobytes and the `Reply` a caller holds points into
/// `reply_storage`. A `Control` must not move once a reply has been read
/// from it.
pub fn init(c: *Control, io: Io, channel: Channel, stall: Io.Timeout) void {
    c.io = io;
    c.channel = channel;
    c.stall = stall;
}

/// Points the dialogue at another reader and writer, keeping the storage.
///
/// **This is what an `AUTH TLS` upgrade needs.** The dialogue before the
/// handshake runs over the raw stream, and the dialogue after it runs over
/// the TLS session. The state either side of that is the server's, not
/// this value's, so the same `Control` carries on.
pub fn retarget(c: *Control, channel: Channel) void {
    c.channel = channel;
}

/// How many bytes the reader holds and nobody has read.
///
/// **A TLS upgrade must find this zero.** A server that wrote bytes behind
/// its `234` answer wrote them in cleartext, and a reader that carried
/// them across the handshake would hand a caller cleartext the peer chose
/// as though the session had protected it. See `Fetcher.upgradeToTls`.
pub fn buffered(c: *Control) usize {
    return c.channel.reader.buffered().len;
}

/// Reads one whole reply.
///
/// The returned `Reply` borrows `reply_storage`, so it is valid until the
/// next call on this `Control`.
pub fn readReply(c: *Control) ReadError!reply.Reply {
    var collector: reply.Collector = .init(&c.reply_storage);
    while (true) {
        const line = try zurl_net.bounded.readLine(
            c.channel.reader,
            c.io,
            &c.line_storage,
            c.stall,
        );
        if (try collector.push(line)) return collector.finish();
    }
}

/// Writes one command and sends it.
///
/// **The argument is refused before any byte reaches the writer** when it
/// holds a NUL, a CR, or an LF. See `command.write`.
pub fn send(c: *Control, verb: []const u8, argument: ?[]const u8) Error!void {
    const line = try command.write(&c.command_storage, verb, argument);
    try c.channel.writer.writeAll(line);
    try c.channel.flush(c.channel.ctx);
}

/// `send`, for a command whose argument is a number this package computed.
pub fn sendNumber(c: *Control, verb: []const u8, value: u64) Error!void {
    const line = try command.writeNumber(&c.command_storage, verb, value);
    try c.channel.writer.writeAll(line);
    try c.channel.flush(c.channel.ctx);
}

/// Sends one command and reads its whole reply.
pub fn ask(c: *Control, verb: []const u8, argument: ?[]const u8) Error!reply.Reply {
    try c.send(verb, argument);
    return c.readReply();
}

/// `ask`, for a command whose argument is a number this package computed.
pub fn askNumber(c: *Control, verb: []const u8, value: u64) Error!reply.Reply {
    try c.sendNumber(verb, value);
    return c.readReply();
}

const testing = std.testing;

/// A `Control` over two buffers, so a test can drive the whole dialogue
/// with no socket.
const Wire = struct {
    control: Control,
    reader: Io.Reader,
    sent: std.Io.Writer.Allocating,

    fn init(w: *Wire, server_says: []const u8) void {
        w.reader = .fixed(server_says);
        w.sent = .init(testing.allocator);
        w.control.init(testing.io, .{
            .reader = &w.reader,
            .writer = &w.sent.writer,
            .ctx = w,
            .flush = flush,
        }, .none);
    }

    fn deinit(w: *Wire) void {
        w.sent.deinit();
    }

    fn flush(ctx: ?*anyopaque) Io.Writer.Error!void {
        _ = ctx;
    }

    fn wire(w: *Wire) []const u8 {
        return w.sent.written();
    }
};

test "a one line reply is read whole" {
    var w: Wire = undefined;
    w.init("220 Ready\r\n");
    defer w.deinit();

    const r = try w.control.readReply();
    try testing.expectEqual(@as(u16, 220), r.code);
    try testing.expectEqualStrings("Ready", r.text);
}

test "a multi-line greeting does not desynchronise the session" {
    // **The defect this test exists for.** A reader that stopped at the
    // first line would read `220-Welcome` as the greeting, then read
    // `  more` as the answer to `USER`, and every answer after it would
    // belong to the command before it. The `RETR` would then read the
    // answer to `PASS`.
    var w: Wire = undefined;
    w.init(
        "220-Welcome\r\n" ++
            "  more\r\n" ++
            "230 Not the end, wrong code\r\n" ++
            "220-still open\r\n" ++
            "220 Ready\r\n" ++
            "331 Password required\r\n" ++
            "230 Logged in\r\n",
    );
    defer w.deinit();

    const greeting = try w.control.readReply();
    try testing.expectEqual(@as(u16, 220), greeting.code);

    const user = try w.control.ask(command.user, "anonymous");
    try testing.expectEqual(@as(u16, 331), user.code);

    const pass = try w.control.ask(command.pass, "ftp@example.com");
    try testing.expectEqual(@as(u16, 230), pass.code);

    try testing.expectEqualStrings(
        "USER anonymous\r\nPASS ftp@example.com\r\n",
        w.wire(),
    );
}

test "the whole login and download reaches the wire as curl writes it" {
    // Every line below was measured from curl 8.21.0 against a loopback
    // RFC 959 server, in this order. The one difference is `PWD`, which
    // curl sends and zurl does not: see `Fetcher.open`.
    var w: Wire = undefined;
    w.init(
        "220 Ready\r\n" ++
            "331 Password required\r\n" ++
            "230 Logged in\r\n" ++
            "229 Entering Extended Passive Mode (|||37809|)\r\n" ++
            "200 Type set to I\r\n" ++
            "213 45\r\n" ++
            "150 Opening data connection\r\n" ++
            "226 Transfer complete\r\n" ++
            "221 Goodbye\r\n",
    );
    defer w.deinit();

    _ = try w.control.readReply();
    _ = try w.control.ask(command.user, "anonymous");
    _ = try w.control.ask(command.pass, "ftp@example.com");

    // **A `Reply` borrows the one storage this `Control` reuses**, so each
    // answer is read before the next command goes out. A test that held
    // two of them at once would read the second reply through the first
    // one's slice, and so would a session.
    const epsv = try w.control.ask(command.epsv, null);
    const data_port = (try reply.parseEpsv(epsv.text)).port;

    _ = try w.control.ask(command.type_, "I");
    const size = try w.control.ask(command.size, "f.txt");
    const size_bytes = reply.parseSize(size.text);

    _ = try w.control.ask(command.retr, "f.txt");
    _ = try w.control.readReply();
    _ = try w.control.ask(command.quit, null);

    try testing.expectEqual(@as(u16, 37809), data_port);
    try testing.expectEqual(@as(?u64, 45), size_bytes);

    try testing.expectEqualStrings(
        "USER anonymous\r\n" ++
            "PASS ftp@example.com\r\n" ++
            "EPSV\r\n" ++
            "TYPE I\r\n" ++
            "SIZE f.txt\r\n" ++
            "RETR f.txt\r\n" ++
            "QUIT\r\n",
        w.wire(),
    );
}

test "the RFC 4217 commands go out in the order the standard sets" {
    // `AUTH TLS` first, and the handshake between it and `USER`, so no
    // credential goes out in cleartext. Then `PBSZ 0` and `PROT P` after
    // the login, which is what protects the data connection.
    var w: Wire = undefined;
    w.init(
        "220 Ready\r\n" ++
            "234 Proceed with negotiation\r\n" ++
            "331 Password required\r\n" ++
            "230 Logged in\r\n" ++
            "200 PBSZ=0\r\n" ++
            "200 PROT set\r\n",
    );
    defer w.deinit();

    _ = try w.control.readReply();
    const auth = try w.control.ask(command.auth, "TLS");
    try testing.expectEqual(@as(u16, 234), auth.code);
    // Here the handshake runs, and `Fetcher.upgradeStep` asserts that
    // `buffered` is zero before it starts. That check cannot be made here:
    // this reader is a fixed slice, so every byte of the script is
    // buffered from the start, where a socket holds only what arrived.

    _ = try w.control.ask(command.user, "alice");
    _ = try w.control.ask(command.pass, "s3cret");
    _ = try w.control.ask(command.pbsz, "0");
    _ = try w.control.ask(command.prot, "P");

    try testing.expectEqualStrings(
        "AUTH TLS\r\n" ++
            "USER alice\r\n" ++
            "PASS s3cret\r\n" ++
            "PBSZ 0\r\n" ++
            "PROT P\r\n",
        w.wire(),
    );
}

test "a command with a forged line ending never reaches the writer" {
    // **The injection proof at the dialogue.** `command.write` refuses
    // before `writeAll` runs, so not one byte of the forged command goes
    // out, and the command before it is the last thing on the wire.
    var w: Wire = undefined;
    w.init("220 Ready\r\n");
    defer w.deinit();

    _ = try w.control.readReply();
    try testing.expectError(
        error.ArgumentHasFramingByte,
        w.control.send(command.user, "alice\r\nPASS hunter2"),
    );
    try testing.expectError(
        error.ArgumentHasFramingByte,
        w.control.send(command.retr, "f\r\nDELE important"),
    );
    try testing.expectError(
        error.ArgumentHasFramingByte,
        w.control.send(command.pass, "p\x00q"),
    );
    try testing.expectEqualStrings("", w.wire());
}

test "a reply line longer than the bound ends the session" {
    var storage: [reply.max_line_bytes + 64]u8 = undefined;
    @memset(&storage, 'x');
    storage[0] = '2';
    storage[1] = '2';
    storage[2] = '0';
    storage[3] = ' ';

    var w: Wire = undefined;
    w.init(&storage);
    defer w.deinit();

    try testing.expectError(error.LineTooLong, w.control.readReply());
}

test "a reply that never ends is refused at the line count" {
    var storage: std.ArrayList(u8) = .empty;
    defer storage.deinit(testing.allocator);
    try storage.appendSlice(testing.allocator, "220-open\r\n");
    var i: usize = 0;
    while (i < reply.max_lines + 4) : (i += 1) {
        try storage.appendSlice(testing.allocator, "220-still\r\n");
    }

    var w: Wire = undefined;
    w.init(storage.items);
    defer w.deinit();

    try testing.expectError(error.ReplyTooManyLines, w.control.readReply());
}

test "a peer that closes in the middle of a reply is a fault, not an end" {
    var w: Wire = undefined;
    w.init("220-open\r\n  more\r\n");
    defer w.deinit();

    try testing.expectError(error.EndOfStream, w.control.readReply());
}

test "a peer that says nothing at all is a fault, not an empty reply" {
    var w: Wire = undefined;
    w.init("");
    defer w.deinit();

    try testing.expectError(error.EndOfStream, w.control.readReply());
}

test "a reply whose first line carries no code ends the session" {
    var w: Wire = undefined;
    w.init("hello there\r\n");
    defer w.deinit();

    try testing.expectError(error.ReplyMalformed, w.control.readReply());
}

test "retarget keeps the storage and changes only where the bytes go" {
    // The `AUTH TLS` upgrade needs this: the dialogue before the
    // handshake runs over the raw stream and the dialogue after it runs
    // over the session, and the server's state carries across.
    var w: Wire = undefined;
    w.init("220 Ready\r\n");
    defer w.deinit();

    _ = try w.control.readReply();

    var second: Io.Reader = .fixed("230 Logged in\r\n");
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    w.control.retarget(.{
        .reader = &second,
        .writer = &out.writer,
        .ctx = &w,
        .flush = Wire.flush,
    });

    const r = try w.control.ask(command.user, "alice");
    try testing.expectEqual(@as(u16, 230), r.code);
    try testing.expectEqualStrings("USER alice\r\n", out.written());
    // Nothing went to the first writer.
    try testing.expectEqualStrings("", w.wire());
}
