//! The RFC 5321 command and reply dialogue, over one reader and one
//! writer.
//!
//! **This is the whole of the SMTP conversation, and it holds no socket.**
//! It reads and writes through a `zurl_net.line.Session`, so the same code
//! runs over a plain stream, over a TLS session, and over two buffers in a
//! test.
//!
//! **A reply is one line or many, and getting that wrong desynchronises
//! the whole session.** An `EHLO` answer is a multi-line reply by
//! definition: one line for each thing the server can do. A reader that
//! stopped at the first line would read the rest of the capability list as
//! the answer to `MAIL FROM`, and would then hand a message to a server
//! that was not waiting for one. The rule lives in `zurl_net.reply`,
//! shared with `zurl-ftp`, because RFC 5321 section 4.2 and RFC 959
//! section 4.2 spell a reply the same way.
//!
//! **Every command goes out through `send`**, which is the one place this
//! package turns text into a command, and which refuses a NUL, a CR, or an
//! LF in any part of the line before a byte reaches the writer.
//!
//! **The message is not a command, and `sendMessage` is the one thing that
//! writes past that gate.** A message body carries its own line endings,
//! and `message.write` is what makes each of those lines safe. See that
//! module: the rule it keeps is the one that decides whether a message
//! arrives whole or turns into a run of commands.
//!
//! **Every read is bounded three ways**: `max_line_bytes` stops a line
//! that never ends, `reply_limits` stops a reply that never ends, and the
//! stall timeout stops a peer that writes nothing.
//!
//! What this does not do: it dials nothing and it knows no url.
//! `Fetcher.zig` owns both.

const Control = @This();

const std = @import("std");
const zurl_net = @import("zurl-net");

const command = @import("command.zig");
const message = @import("message.zig");

const Io = std.Io;

/// How many bytes of one reply line this reads, the line ending counted.
///
/// RFC 5321 section 4.5.3.1.5 sets a reply line at 512 octets. This is
/// twice that, because a server that writes a longer banner is common and
/// a client that ended the session over one would refuse mail it could
/// have sent. Passing it is `error.LineTooLong`.
pub const max_line_bytes = 1024;

/// How large one reply may grow.
///
/// An `EHLO` answer is one line for each extension, and a busy server has
/// a few dozen. 128 lines is past every one of them, and the byte bound is
/// what stops a server that writes a thousand-byte line a hundred times
/// from taking 128 KiB out of one command.
pub const reply_limits: zurl_net.reply.Limits = .{
    .max_lines = 128,
    .max_reply_bytes = 8192,
};

/// The reply grammar, under this package's own bounds. See
/// `zurl_net.reply`.
pub const Collector = zurl_net.reply.Collector(reply_limits);

/// One reply, already read whole. See `zurl_net.reply.Reply`.
pub const Reply = zurl_net.reply.Reply;

/// The dialogue this holds. See `zurl_net.line.Session`.
pub const Session = zurl_net.line.Session(max_line_bytes, command.max_command_bytes);

/// Where the dialogue reads and writes. See `zurl_net.line.Channel`.
pub const Channel = zurl_net.line.Channel;

/// Every fault reading a reply can report.
pub const ReadError = Session.ReadError || zurl_net.reply.ParseError;

/// Every fault this can report.
pub const Error = ReadError || Io.Writer.Error || command.WriteError;

session: Session,
/// Holds the text of the reply in play.
reply_storage: [reply_limits.max_reply_bytes]u8,

/// Initializes `c` in place.
///
/// In place, and not a value returned, because the storage is kilobytes
/// and a `Reply` a caller holds points into `reply_storage`. A `Control`
/// must not move once a reply has been read from it.
pub fn init(c: *Control, io: Io, channel: Channel, stall: Io.Timeout) void {
    c.session.init(io, channel, stall);
}

/// Points the dialogue at another reader and writer, keeping the storage.
///
/// **This is what a `STARTTLS` upgrade needs.** See
/// `zurl_net.line.Session.retarget`.
pub fn retarget(c: *Control, channel: Channel) void {
    c.session.retarget(channel);
}

/// How many bytes the reader holds and nobody has read.
///
/// **A TLS upgrade must find this zero.** See
/// `zurl_net.line.Session.buffered`.
pub fn buffered(c: *Control) usize {
    return c.session.buffered();
}

/// Reads one whole reply.
///
/// The returned `Reply` borrows `reply_storage`, so it is valid until the
/// next call on this `Control`.
pub fn readReply(c: *Control) ReadError!Reply {
    var collector: Collector = .init(&c.reply_storage);
    while (true) {
        const line = try c.session.readLine();
        if (try collector.push(line)) return collector.finish();
    }
}

/// Sends one command.
///
/// `parts` is the whole line, in order, so a `MAIL FROM` is
/// `.{ "MAIL FROM:<", address, ">" }`.
///
/// **This is the one place this package turns text into an SMTP command.**
/// A NUL, a CR, or an LF in any part is `error.ArgumentHasFramingByte`,
/// and not one byte of the command reaches the writer. See
/// `zurl_net.line.write`.
pub fn send(c: *Control, parts: []const []const u8) Error!void {
    return c.session.send(parts);
}

/// Sends one command and reads its whole reply.
pub fn ask(c: *Control, parts: []const []const u8) Error!Reply {
    try c.send(parts);
    return c.readReply();
}

/// Writes the octets of a `DATA` phase and reads the reply that ends it.
///
/// `payload` must already be what `message.write` produced: every line
/// stuffed, every ending a `CRLF`, and the `.<CRLF>` terminator on the
/// end. **This function checks nothing**, because checking a body byte by
/// byte at the socket would be a second copy of a rule that already has
/// one home. `Fetcher.send` is the only caller and `message.write` is the
/// only thing it passes.
pub fn sendMessage(c: *Control, payload: []const u8) Error!Reply {
    try c.session.sendRaw(payload);
    return c.readReply();
}

const testing = std.testing;

/// A `Control` over two buffers, so a test drives the whole dialogue with
/// no socket.
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

test "the whole send reaches the wire as curl writes it" {
    // Measured from curl 8.21.0 against a loopback SMTP fixture, in this
    // order.
    var w: Wire = undefined;
    w.init(
        "220 fixture ESMTP ready\r\n" ++
            "250-fixture\r\n" ++
            "250-SIZE 1000000\r\n" ++
            "250 STARTTLS\r\n" ++
            "250 sender ok\r\n" ++
            "250 recipient ok\r\n" ++
            "354 go ahead\r\n" ++
            "250 message accepted\r\n" ++
            "221 bye\r\n",
    );
    defer w.deinit();

    const greeting = try w.control.readReply();
    try testing.expectEqual(@as(u16, 220), greeting.code);

    const hello = try w.control.ask(&.{ command.ehlo, " ", "mail.example.com" });
    try testing.expectEqual(@as(u16, 250), hello.code);
    // **The whole capability list is one reply.** A reader that stopped at
    // the first line would read `250-SIZE 1000000` as the answer to
    // `MAIL FROM`.
    try testing.expectEqualStrings("fixture\n250-SIZE 1000000\nSTARTTLS", hello.text);
    try testing.expect(command.announces(hello.text, command.size_keyword));
    try testing.expect(command.announces(hello.text, command.starttls_keyword));

    _ = try w.control.ask(&.{ command.mail, "a@b.example", command.path_close });
    _ = try w.control.ask(&.{ command.rcpt, "c@d.example", command.path_close });
    const go = try w.control.ask(&.{command.data});
    try testing.expectEqual(@as(u16, 354), go.code);
    try testing.expect(go.isIntermediate());

    var payload: [64]u8 = undefined;
    const written = try message.write(&payload, "hello\r\n");
    const accepted = try w.control.sendMessage(written);
    try testing.expectEqual(@as(u16, 250), accepted.code);

    _ = try w.control.ask(&.{command.quit});

    try testing.expectEqualStrings(
        "EHLO mail.example.com\r\n" ++
            "MAIL FROM:<a@b.example>\r\n" ++
            "RCPT TO:<c@d.example>\r\n" ++
            "DATA\r\n" ++
            "hello\r\n.\r\n" ++
            "QUIT\r\n",
        w.wire(),
    );
}

test "a multi-line EHLO answer does not put the session one reply out of step" {
    // **The defect this test exists for.** An `EHLO` answer is a
    // multi-line reply by definition. A reader that stopped at the first
    // line would read the rest of the capability list as the answers to
    // `MAIL FROM` and `RCPT TO`, and would then hand a message to a server
    // that was not waiting for one.
    var w: Wire = undefined;
    w.init(
        "220 ready\r\n" ++
            "250-fixture\r\n" ++
            "250-PIPELINING\r\n" ++
            "220 not the end, wrong code\r\n" ++
            "250-8BITMIME\r\n" ++
            "250 SIZE 100\r\n" ++
            "550 sender refused\r\n",
    );
    defer w.deinit();

    _ = try w.control.readReply();
    const hello = try w.control.ask(&.{ command.ehlo, " ", "h" });
    try testing.expectEqual(@as(u16, 250), hello.code);

    // The very next reply is the answer to `MAIL FROM`, and it says the
    // sender was refused. A session one reply out of step would have read
    // this as a success.
    const sender = try w.control.ask(&.{ command.mail, "a@b", command.path_close });
    try testing.expectEqual(@as(u16, 550), sender.code);
    try testing.expect(sender.isNegative());
}

test "a command with a forged line ending never reaches the writer" {
    // **The injection proof at the dialogue.** The gate refuses before
    // `writeAll` runs, so not one byte of the forged command goes out.
    // curl 8.21.0 does not refuse the same text: measured, it puts a
    // second `RCPT TO` on the wire.
    var w: Wire = undefined;
    w.init("220 ready\r\n");
    defer w.deinit();

    _ = try w.control.readReply();

    const forged = [_][]const u8{
        "c@d>\r\nRCPT TO:<evil@x",
        "c@d>\nRCPT TO:<evil@x",
        "c@d>\rRCPT TO:<evil@x",
        "c@d\x00",
        "\r\n",
        "\n",
        "\r",
        "\x00",
        "a@b>\r\nDATA",
        "h\r\nMAIL FROM:<evil@x>",
        "h\r\nQUIT",
    };
    for (forged) |part| {
        try testing.expectError(
            error.ArgumentHasFramingByte,
            w.control.send(&.{ command.mail, part, command.path_close }),
        );
        try testing.expectError(
            error.ArgumentHasFramingByte,
            w.control.send(&.{ command.rcpt, part, command.path_close }),
        );
        try testing.expectError(
            error.ArgumentHasFramingByte,
            w.control.send(&.{ command.ehlo, " ", part }),
        );
        try testing.expectError(
            error.ArgumentHasFramingByte,
            w.control.send(&.{ command.helo, " ", part }),
        );
        try testing.expectError(
            error.ArgumentHasFramingByte,
            w.control.send(&.{ command.mail, "a@b", command.path_close, command.size_parameter, part }),
        );
    }

    try testing.expectEqualStrings("", w.wire());
}

test "a message that holds a period line reaches the wire stuffed" {
    // **The end to end shape of the dot-stuffing rule.** Without it the
    // server would end the `DATA` phase at the second line and read
    // `line two` as an SMTP command.
    var w: Wire = undefined;
    w.init("250 accepted\r\n");
    defer w.deinit();

    var payload: [128]u8 = undefined;
    const written = try message.write(&payload, "line one\r\n.\r\nline two\r\n");
    _ = try w.control.sendMessage(written);

    try testing.expectEqualStrings("line one\r\n..\r\nline two\r\n.\r\n", w.wire());
    // The one run that ends the phase is at the end and nowhere else.
    try testing.expectEqual(
        @as(?usize, w.wire().len - 5),
        std.mem.indexOf(u8, w.wire(), "\r\n.\r\n"),
    );
}

test "a reply line longer than the bound ends the session" {
    var storage: [max_line_bytes + 64]u8 = undefined;
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
    try storage.appendSlice(testing.allocator, "250-open\r\n");
    var i: usize = 0;
    while (i < reply_limits.max_lines + 4) : (i += 1) {
        try storage.appendSlice(testing.allocator, "250-still\r\n");
    }

    var w: Wire = undefined;
    w.init(storage.items);
    defer w.deinit();

    try testing.expectError(error.ReplyTooManyLines, w.control.readReply());
}

test "a reply whose first line carries no code ends the session" {
    var w: Wire = undefined;
    w.init("hello there\r\n");
    defer w.deinit();

    try testing.expectError(error.ReplyMalformed, w.control.readReply());
}

test "a peer that says nothing at all is a fault, not an empty reply" {
    var w: Wire = undefined;
    w.init("");
    defer w.deinit();

    try testing.expectError(error.EndOfStream, w.control.readReply());
}

test "retarget keeps the storage and changes only where the bytes go" {
    var w: Wire = undefined;
    w.init("220 ready\r\n");
    defer w.deinit();

    _ = try w.control.readReply();

    var second: Io.Reader = .fixed("250 fixture\r\n");
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    w.control.retarget(.{
        .reader = &second,
        .writer = &out.writer,
        .ctx = &w,
        .flush = Wire.flush,
    });

    const hello = try w.control.ask(&.{ command.ehlo, " ", "mail.example.com" });
    try testing.expectEqual(@as(u16, 250), hello.code);
    try testing.expectEqualStrings("EHLO mail.example.com\r\n", out.written());
    try testing.expectEqualStrings("", w.wire());
}
