//! The RFC 1939 command and response dialogue, over one reader and one
//! writer.
//!
//! **This is the whole of the POP3 conversation, and it holds no socket.**
//! It reads and writes through a `zurl_net.line.Session`, so the same code
//! runs over a plain stream, over a TLS session, and over two buffers in a
//! test. That is what lets a test pin the exact bytes of a whole login and
//! retrieval, `STLS` included, with no network at all.
//!
//! **Every command goes out through `send`**, which is the one place this
//! package turns text into a command. `send` calls
//! `zurl_net.line.Session.send`, which refuses a NUL, a CR, or an LF in
//! any part of the line before a byte reaches the writer. Nothing here
//! writes a command any other way, so no command can carry a forged line
//! ending whatever the argument came from.
//!
//! **A multi-line body ends at one period on a line of its own**, and
//! `readBody` is what keeps that rule. See `response.terminates` and
//! `response.unstuff` for what a looser reader would do to a message.
//!
//! **Every read is bounded three ways**: `max_line_bytes` stops a line
//! that never ends, the stall timeout stops a peer that writes nothing,
//! and the `max_bytes` of `readBody` stops a body that never ends.
//!
//! What this does not do: it dials nothing and it knows no url.
//! `Fetcher.zig` owns both.

const Control = @This();

const std = @import("std");
const zurl_net = @import("zurl-net");

const command = @import("command.zig");
const response = @import("response.zig");

const Io = std.Io;

/// How many bytes of one line this reads, the line ending counted.
///
/// **A POP3 line carries a message, not just an answer.** A `RETR` body is
/// the message itself, and RFC 5322 section 2.1.1 asks a sender to keep a
/// line under 1000 octets but does not make a receiver refuse a longer
/// one. This is eight times that, so an ordinary message always fits, and
/// it is a bound because a peer that writes one line forever would
/// otherwise fill memory. Passing it is `error.LineTooLong`.
pub const max_line_bytes = 8192;

/// The dialogue this holds. See `zurl_net.line.Session`.
pub const Session = zurl_net.line.Session(max_line_bytes, command.max_command_bytes);

/// Where the dialogue reads and writes. See `zurl_net.line.Channel`.
pub const Channel = zurl_net.line.Channel;

/// Every fault reading one line can report.
pub const ReadError = Session.ReadError || response.ParseError;

/// Every fault reading a multi-line body can report.
pub const BodyError = Session.ReadError || error{
    /// The body passed the byte bound the caller gave.
    StreamTooLong,
    /// The body needs more memory than this process has.
    OutOfMemory,
};

/// Every fault this can report.
pub const Error = ReadError || BodyError || Io.Writer.Error || command.WriteError;

session: Session,

/// Initializes `c` in place.
///
/// In place, and not a value returned, because the line storage is
/// kilobytes and a `Response` a caller holds points into it. A `Control`
/// must not move once a line has been read from it.
pub fn init(c: *Control, io: Io, channel: Channel, stall: Io.Timeout) void {
    c.session.init(io, channel, stall);
}

/// Points the dialogue at another reader and writer, keeping the storage.
///
/// **This is what an `STLS` upgrade needs.** See
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

/// Reads one single-line response.
///
/// The returned `Response` borrows the session's line storage, so it is
/// valid until the next read on this `Control`.
pub fn readResponse(c: *Control) ReadError!response.Response {
    const line = try c.session.readLine();
    return response.parse(line);
}

/// Sends one command.
///
/// **This is the one place this package turns text into a POP3 command.**
/// A NUL, a CR, or an LF in the verb or in the argument is
/// `error.ArgumentHasFramingByte`, and not one byte of the command reaches
/// the writer. See `zurl_net.line.write`.
pub fn send(c: *Control, verb: []const u8, argument: ?[]const u8) Error!void {
    if (argument) |text| return c.session.send(&.{ verb, " ", text });
    return c.session.send(&.{verb});
}

/// Sends one command and reads its single-line response.
pub fn ask(c: *Control, verb: []const u8, argument: ?[]const u8) Error!response.Response {
    try c.send(verb, argument);
    return c.readResponse();
}

/// One line of a SASL exchange.
///
/// **A `+` on its own is not a `+OK`.** RFC 5034 section 4 writes a
/// challenge as `+ <base64>`, and `readResponse` would read that as a
/// success and send the next command where the server is waiting for a
/// response. See `response.challenge`.
pub const AuthLine = union(enum) {
    /// The server wrote a challenge. The text is still base64, and it
    /// **borrows the session's line storage**.
    challenge: []const u8,
    /// The server ended the exchange.
    done: response.Response,
};

/// Reads the next line of a SASL exchange.
pub fn readAuthLine(c: *Control) Error!AuthLine {
    const line = try c.session.readLine();
    if (response.challenge(line)) |text| return .{ .challenge = text };
    return .{ .done = try response.parse(line) };
}

/// Sends one line of a SASL exchange, with no verb in front of it.
///
/// **This is the one command shape in this package that carries no verb**,
/// because the line answers a challenge and not a command. It still goes
/// through `zurl_net.line.Session.send`, so a NUL, a CR, or an LF in it is
/// refused before a byte reaches the writer.
pub fn sendAuthResponse(c: *Control, text: []const u8) Error!void {
    return c.session.send(&.{text});
}

/// Reads a multi-line body, up to and including the line that ends it.
///
/// The body belongs to the caller, which must free it with `gpa`.
///
/// **The body ends at one period on a line of its own, and at nothing
/// else.** A line of two periods is a body line whose text is one period,
/// and `response.unstuff` takes the added one off. A reader that stopped
/// at the first `.` would cut a message in half and read the rest of it as
/// answers to later commands.
///
/// Every line arrives with a `CRLF` ending, which is what the server sent
/// and what curl writes out: measured against curl 8.21.0 on a loopback
/// POP3 fixture, the body of a `RETR` reaches standard output with its
/// `CRLF` endings kept and the terminating period line dropped.
///
/// **Three bounds hold it.** One line cannot pass `max_line_bytes`, the
/// whole body cannot pass `max_bytes`, and no single read may wait longer
/// than the session's stall timeout. A server that never writes the
/// period therefore ends the transfer instead of holding it forever.
pub fn readBody(c: *Control, gpa: std.mem.Allocator, max_bytes: u64) BodyError![]u8 {
    var collected: std.ArrayList(u8) = .empty;
    errdefer collected.deinit(gpa);

    while (true) {
        const line = try c.session.readLine();
        if (response.terminates(line)) {
            return collected.toOwnedSlice(gpa) catch error.OutOfMemory;
        }
        const text = response.unstuff(line);
        const room = max_bytes -| collected.items.len;
        if (@as(u64, text.len) + 2 > room) return error.StreamTooLong;
        collected.appendSlice(gpa, text) catch return error.OutOfMemory;
        collected.appendSlice(gpa, "\r\n") catch return error.OutOfMemory;
    }
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

test "the whole login and retrieval reaches the wire as curl writes it" {
    // Measured from curl 8.21.0 against a loopback POP3 fixture, in this
    // order. The one difference is `CAPA`, which curl sends and zurl does
    // not: see `Fetcher.open`.
    var w: Wire = undefined;
    w.init(
        "+OK POP3 fixture ready\r\n" ++
            "+OK user ok\r\n" ++
            "+OK logged in\r\n" ++
            "+OK 26 octets\r\n" ++
            "Subject: hi\r\n" ++
            "\r\n" ++
            "body line\r\n" ++
            "..hidden\r\n" ++
            ".\r\n" ++
            "+OK bye\r\n",
    );
    defer w.deinit();

    const greeting = try w.control.readResponse();
    try testing.expect(greeting.ok);
    try testing.expectEqualStrings("POP3 fixture ready", greeting.text);

    _ = try w.control.ask(command.user, "alice");
    _ = try w.control.ask(command.pass, "s3cret");
    const start = try w.control.ask(command.retr, "1");
    try testing.expect(start.ok);

    const body = try w.control.readBody(testing.allocator, 1024);
    defer testing.allocator.free(body);
    // The doubled period is one period again, and the period line is
    // gone. This is byte for byte what curl writes out.
    try testing.expectEqualStrings(
        "Subject: hi\r\n\r\nbody line\r\n.hidden\r\n",
        body,
    );

    _ = try w.control.ask(command.quit, null);
    try testing.expectEqualStrings(
        "USER alice\r\nPASS s3cret\r\nRETR 1\r\nQUIT\r\n",
        w.wire(),
    );
}

test "a command with a forged line ending never reaches the writer" {
    // **The injection proof at the dialogue.** The gate refuses before
    // `writeAll` runs, so not one byte of the forged command goes out.
    // The `DELE` below is the one that matters: `QUIT` makes a `DELE`
    // permanent, so a url that could write one would delete mail.
    var w: Wire = undefined;
    w.init("+OK ready\r\n");
    defer w.deinit();

    _ = try w.control.readResponse();

    const forged = [_][]const u8{
        "1\r\nDELE 2",
        "1\nDELE 2",
        "1\rDELE 2",
        "1\x00 2",
        "\r\n",
        "\n",
        "\r",
        "\x00",
        "bob\r\nPASS hunter2",
        "\r\nQUIT",
        "hunter2\r\nDELE 1",
    };
    const verbs = [_][]const u8{
        command.user, command.pass, command.apop, command.retr, command.list,
        command.dele, command.stat, command.top,  command.uidl, command.capa,
        command.stls, command.quit,
    };
    for (forged) |argument| {
        for (verbs) |verb| {
            try testing.expectError(
                error.ArgumentHasFramingByte,
                w.control.send(verb, argument),
            );
        }
        // A forged verb is refused too, because `--request` gives a user a
        // way to name one.
        try testing.expectError(
            error.ArgumentHasFramingByte,
            w.control.send(argument, null),
        );
        try testing.expectError(
            error.ArgumentHasFramingByte,
            w.control.send(argument, "1"),
        );
    }

    try testing.expectEqualStrings("", w.wire());
}

test "a body ends only at one period on a line of its own" {
    // **The defect this test exists for.** Every line below would end the
    // body for a reader that took the first period it saw, and the rest of
    // the message would then be read as answers to later commands.
    var w: Wire = undefined;
    w.init(
        "+OK message\r\n" ++
            "..\r\n" ++
            ". \r\n" ++
            " .\r\n" ++
            "...\r\n" ++
            ".not the end\r\n" ++
            ".\r\n" ++
            "+OK bye\r\n",
    );
    defer w.deinit();

    _ = try w.control.readResponse();
    const body = try w.control.readBody(testing.allocator, 1024);
    defer testing.allocator.free(body);
    // `. ` is a stuffed line whose text is one space, so the period comes
    // off it too. Only the bare period line ends the body.
    try testing.expectEqualStrings(
        ".\r\n \r\n .\r\n..\r\nnot the end\r\n",
        body,
    );

    // The session is still in step: the next line is the answer to the
    // next command and not part of the message.
    const after = try w.control.readResponse();
    try testing.expect(after.ok);
    try testing.expectEqualStrings("bye", after.text);
}

test "an empty body is a body and not a fault" {
    var w: Wire = undefined;
    w.init("+OK empty\r\n.\r\n");
    defer w.deinit();

    _ = try w.control.readResponse();
    const body = try w.control.readBody(testing.allocator, 1024);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("", body);
}

test "a body larger than the bound is refused and no byte of it comes back" {
    var w: Wire = undefined;
    w.init("+OK big\r\nabcdefghij\r\nabcdefghij\r\n.\r\n");
    defer w.deinit();

    _ = try w.control.readResponse();
    // Twelve bytes of room holds the first line and its ending and no
    // more.
    try testing.expectError(error.StreamTooLong, w.control.readBody(testing.allocator, 12));
}

test "a body of exactly the bound is read" {
    var w: Wire = undefined;
    w.init("+OK exact\r\nabcdefghij\r\n.\r\n");
    defer w.deinit();

    _ = try w.control.readResponse();
    const body = try w.control.readBody(testing.allocator, 12);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("abcdefghij\r\n", body);
}

test "a peer that never writes the period ends the transfer" {
    // The peer closes with the body still open. That is a fault and never
    // an end: a message read short is a message a user would trust.
    var w: Wire = undefined;
    w.init("+OK message\r\nline one\r\nline two\r\n");
    defer w.deinit();

    _ = try w.control.readResponse();
    try testing.expectError(error.EndOfStream, w.control.readBody(testing.allocator, 4096));
}

test "a line longer than the bound ends the session" {
    var storage: [max_line_bytes + 64]u8 = undefined;
    @memset(&storage, 'x');
    storage[0] = '+';
    storage[1] = 'O';
    storage[2] = 'K';
    storage[3] = ' ';

    var w: Wire = undefined;
    w.init(&storage);
    defer w.deinit();

    try testing.expectError(error.LineTooLong, w.control.readResponse());
}

test "an answer that is neither +OK nor -ERR ends the session" {
    var w: Wire = undefined;
    w.init("220 Ready\r\n");
    defer w.deinit();

    try testing.expectError(error.ResponseMalformed, w.control.readResponse());
}

test "a peer that says nothing at all is a fault, not an empty answer" {
    var w: Wire = undefined;
    w.init("");
    defer w.deinit();

    try testing.expectError(error.EndOfStream, w.control.readResponse());
}

test "retarget keeps the storage and changes only where the bytes go" {
    // The `STLS` upgrade needs this: the dialogue before the handshake
    // runs over the raw stream and the dialogue after it runs over the
    // session.
    var w: Wire = undefined;
    w.init("+OK ready\r\n");
    defer w.deinit();

    _ = try w.control.readResponse();

    var second: Io.Reader = .fixed("+OK logged in\r\n");
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    w.control.retarget(.{
        .reader = &second,
        .writer = &out.writer,
        .ctx = &w,
        .flush = Wire.flush,
    });

    const r = try w.control.ask(command.user, "alice");
    try testing.expect(r.ok);
    try testing.expectEqualStrings("USER alice\r\n", out.written());
    try testing.expectEqualStrings("", w.wire());
}

test "an APOP login puts the digest on the wire and never the password" {
    var w: Wire = undefined;
    w.init("+OK ready <1896.697170952@dbc.mtview.ca.us>\r\n+OK logged in\r\n");
    defer w.deinit();

    const greeting = try w.control.readResponse();
    const timestamp = response.apopTimestamp(greeting.text).?;
    const digest = command.apopDigest(timestamp, "tanstaaf");

    var argument: [128]u8 = undefined;
    const text = try std.fmt.bufPrint(&argument, "{s} {s}", .{ "mrose", &digest });
    _ = try w.control.ask(command.apop, text);

    try testing.expectEqualStrings(
        "APOP mrose c4c9334bac560ecc979e58001b3e22fb\r\n",
        w.wire(),
    );
    // The password itself is nowhere on the wire.
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, w.wire(), "tanstaaf"),
    );
}
