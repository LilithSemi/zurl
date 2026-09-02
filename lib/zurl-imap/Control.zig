//! The RFC 3501 tagged command dialogue, over one reader and one writer.
//!
//! **This is the part of IMAP that is unlike the other three mail
//! protocols.** POP3, SMTP, and FTP each answer one command with one
//! answer, in order. IMAP tags every command and matches every answer to a
//! tag, and it may write any number of untagged lines in between, some of
//! which answer the command and some of which report a change nobody asked
//! about. So `run` reads until it sees the tag it sent, and it takes no
//! untagged line as an end.
//!
//! **A literal is the second half of the grammar.** RFC 3501 section 4.3
//! writes a string as `{n}` at the end of a line, followed by exactly `n`
//! octets, and those octets may hold a `CRLF`. `run` reads them with
//! `zurl_net.bounded.readExact` and then reads the rest of the line. A
//! reader that took them as lines would read a message body as a run of
//! answers, and would then match one of them against its own tag.
//!
//! **This holds no socket.** It reads and writes through a
//! `zurl_net.line.Session`, so the same code runs over a plain stream,
//! over a TLS session, and over two buffers in a test.
//!
//! **Every command goes out through `send`**, which is the one place this
//! package turns text into a command, and which refuses a NUL, a CR, or an
//! LF in any part of the line before a byte reaches the writer.
//!
//! **Every read is bounded four ways**: `max_line_bytes` stops a line that
//! never ends, the stall timeout stops a peer that writes nothing,
//! `max_untagged_lines` stops a server that writes lines for ever, and the
//! `max_bytes` of `run` stops an answer that grows without end.
//!
//! **Each of the four counts in every mode.** `Mode` decides what an
//! answer keeps and never how much of it is read. A count that ran in one
//! mode alone was the defect that let a server holding a `FETCH` open with
//! `{0}` lines run this process for as long as it liked: the line count
//! sat in the outer loop and the byte count charged only what was kept.
//! See `collect` and `readLiteral`.
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
/// **An IMAP line carries message headers.** A `FETCH` of a header set
/// arrives inside a literal, which this does not read as a line, but an
/// untagged `LIST` line names a mailbox and an `OK` line carries a
/// response code that some servers fill generously. This is far past
/// either. Passing it is `error.LineTooLong`.
pub const max_line_bytes = 8192;

/// How many untagged lines one command may draw.
///
/// **A tagged answer is the only end, so a server that never writes one
/// must still not hold this process.** The byte bound below covers an
/// answer that grows, and this covers one that does not: a server writing
/// `* 1 EXISTS` for ever writes nine bytes each time and would pass no
/// byte bound at all, because `run` keeps only what the caller asked for.
/// Passing it is `error.TooManyUntaggedLines`.
pub const max_untagged_lines = 4096;

/// The dialogue this holds. See `zurl_net.line.Session`.
pub const Session = zurl_net.line.Session(max_line_bytes, command.max_command_bytes);

/// Where the dialogue reads and writes. See `zurl_net.line.Channel`.
pub const Channel = zurl_net.line.Channel;

/// Every fault this can report.
pub const Error = Session.ReadError || response.ParseError || Io.Writer.Error ||
    command.WriteError || error{
    /// The server wrote more untagged lines than `max_untagged_lines`
    /// before it answered the tag.
    TooManyUntaggedLines,
    /// The server asked for the rest of a command. This package sends no
    /// command that has a rest, so a continuation request means the two
    /// ends do not agree about what was sent, and the session cannot go
    /// on.
    UnexpectedContinuation,
    /// The answer passed the byte bound the caller gave.
    StreamTooLong,
    /// The answer needs more memory than this process has.
    OutOfMemory,
};

/// What `run` keeps out of an answer.
pub const Mode = enum {
    /// Nothing. The tagged status is the whole answer.
    discard,
    /// Every untagged line, exactly as it arrived, each with a `CRLF`
    /// after it, and the octets of any literal in the middle of one.
    ///
    /// This is what curl writes out for a `LIST`, measured against curl
    /// 8.21.0 on a loopback IMAP fixture.
    untagged,
    /// The octets of every literal, and nothing else.
    ///
    /// This is what curl writes out for a `FETCH`, measured: the body of
    /// `* 1 FETCH (BODY[] {21}` is the 21 octets and never the line around
    /// them.
    literal,
};

/// What one command drew.
pub const Outcome = struct {
    /// The word the tagged line carried.
    status: response.Status,
    /// The text after that word. **Borrows the session's line storage**,
    /// so it is valid until the next read on this `Control`.
    text: []const u8,
    /// What `Mode` asked to keep. Owned by the caller, which must free it
    /// with the same allocator it passed `run`.
    body: []u8,
};

session: Session,
/// How many commands have gone out. The tag of the next one.
sent: u16,
/// Holds the tag of the command in play.
tag_storage: [command.tag_bytes]u8,

/// Initializes `c` in place.
///
/// In place, and not a value returned, because the line storage is
/// kilobytes and an `Outcome` a caller holds points into it. A `Control`
/// must not move once a line has been read from it.
pub fn init(c: *Control, io: Io, channel: Channel, stall: Io.Timeout) void {
    c.session.init(io, channel, stall);
    c.sent = 0;
}

/// Points the dialogue at another reader and writer, keeping the storage
/// **and the tag counter**.
///
/// **This is what a `STARTTLS` upgrade needs, and the counter is the part
/// that matters.** RFC 3501 gives each command of one connection its own
/// tag, and the handshake does not start a new connection. A dialogue that
/// reset the counter would send `A001` twice, and the answer to the first
/// would end the second.
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

/// Reads the greeting, which carries no tag.
///
/// RFC 3501 section 7.1: a server greets with an untagged `OK`, an
/// untagged `PREAUTH`, or an untagged `BYE`. Anything else is a server
/// this package cannot speak to.
pub fn readGreeting(c: *Control) Error!response.Status {
    const greeting = try c.readGreetingLine();
    return greeting.status orelse error.ResponseMalformed;
}

/// Reads the greeting and hands back the whole line.
///
/// **The text of a greeting is not decoration.** RFC 3501 section 7.1 lets
/// a server write a `[CAPABILITY ...]` response code in it, and a client
/// that reads that one needs no `CAPABILITY` command at all. That is one
/// round trip saved on every session, and it is the list a SASL login
/// picks its mechanism from. See `zurl_imap.Fetcher.login`.
///
/// The text **borrows the session's line storage**, so a caller that needs
/// it after the next read must copy it.
pub fn readGreetingLine(c: *Control) Error!response.Line {
    const line = try c.session.readLine();
    // The greeting answers no command, so no tag can match it. A tag that
    // no command used is what says so.
    const read = try response.readLine(line, "");
    if (read.kind != .untagged) return error.ResponseMalformed;
    if (read.status == null) return error.ResponseMalformed;
    return read;
}

/// The tag the next command will carry.
fn nextTag(c: *Control) []const u8 {
    c.sent += 1;
    return command.writeTag(&c.tag_storage, c.sent);
}

/// Sends one command, and returns the tag it carried.
///
/// `parts` is everything after the tag and the space, in order. So a
/// `SELECT` is `.{ "SELECT", " ", quoted_mailbox }`.
///
/// **This is the one place this package turns text into an IMAP command.**
/// A NUL, a CR, or an LF in any part is `error.ArgumentHasFramingByte`,
/// and not one byte of the command reaches the writer. See
/// `zurl_net.line.write`.
///
/// The returned tag points into this value's own storage and is valid
/// until the next `send`.
pub fn send(c: *Control, parts: []const []const u8) Error![]const u8 {
    const tag = c.nextTag();

    // Sixteen, which holds the longest command this package builds:
    // `UID FETCH n BODY[]` is seven parts, and the tag and its space are
    // two more. A caller that passed more than fourteen is refused by
    // name rather than overrun the array.
    var line: [16][]const u8 = undefined;
    if (parts.len + 2 > line.len) return error.CommandTooLong;
    line[0] = tag;
    line[1] = " ";
    for (parts, 0..) |part, i| line[i + 2] = part;

    try c.session.send(line[0 .. parts.len + 2]);
    return tag;
}

/// Reads every line of an answer, up to and including the tagged one.
///
/// `tag` is what `send` returned. The answer ends at that tag and at
/// nothing else: see the module comment.
///
/// The body belongs to the caller, which must free it with `gpa`. It is
/// empty for `Mode.discard`.
pub fn collect(
    c: *Control,
    gpa: std.mem.Allocator,
    tag: []const u8,
    mode: Mode,
    max_bytes: u64,
) Error!Outcome {
    var kept: std.ArrayList(u8) = .empty;
    errdefer kept.deinit(gpa);

    // **Every line this reads is counted, in every mode.** The count used
    // to live in the outer loop alone, so the literal continuation loop
    // below read lines that no counter saw. A server answering
    // `{0}<CRLF>` again and again then held this process for ever, at five
    // octets a line, with flat memory and before any credential was sent.
    var lines: usize = 0;
    // **And every literal octet is charged, whether or not it is kept.**
    // `.discard` and `.literal` mode keep no line at all, so `max_bytes`
    // against `kept.items.len` charged nothing for them. This counter is
    // what a mode cannot step around.
    var read_bytes: u64 = 0;

    while (true) {
        const line = try c.nextLine(&lines);
        const read = try response.readLine(line, tag);
        switch (read.kind) {
            .tagged => {
                const body = kept.toOwnedSlice(gpa) catch return error.OutOfMemory;
                return .{
                    .status = read.status orelse return error.ResponseMalformedTagged,
                    .text = read.text,
                    .body = body,
                };
            },
            // This package sends no command with a rest, so a request for
            // one says the two ends do not agree about what was sent.
            .continuation => return error.UnexpectedContinuation,
            .untagged => {},
        }

        if (mode == .untagged) try append(gpa, &kept, max_bytes, line, true);

        // **A literal is read as a count of octets and never as lines.**
        // One untagged response may hold several, each followed by more of
        // the same logical line.
        var length = response.literalLength(line);
        while (length) |n| {
            try c.readLiteral(gpa, &kept, &read_bytes, n, mode, max_bytes);
            const rest = try c.nextLine(&lines);
            if (mode == .untagged) try append(gpa, &kept, max_bytes, rest, true);
            length = response.literalLength(rest);
        }
    }
}

/// Reads one line and charges it against `max_untagged_lines`.
///
/// **Every `readLine` inside `collect` goes through this**, the ones in the
/// literal continuation loop included. A line that no counter sees is a
/// line a peer can write for ever. See `collect`.
fn nextLine(c: *Control, lines: *usize) Error![]const u8 {
    lines.* += 1;
    if (lines.* > max_untagged_lines) return error.TooManyUntaggedLines;
    return c.session.readLine();
}

/// Reads `n` octets and keeps them when `mode` asks for them.
///
/// **The octets are read whatever the mode is.** They are on the wire, and
/// a reader that skipped them would read them as answers to later
/// commands. The mode decides only whether they are kept.
///
/// **And they are charged whatever the mode is.** `read` counts every
/// octet of every literal of this answer, so a mode that keeps nothing
/// still reaches `max_bytes`. Charging `kept.items.len` alone let a
/// `.discard` answer read `max_bytes` octets on every line of it.
///
/// Both counts are checked against `max_bytes` **before** the buffer is
/// made, so a server that writes `{4294967295}` costs this process nothing.
fn readLiteral(
    c: *Control,
    gpa: std.mem.Allocator,
    kept: *std.ArrayList(u8),
    read: *u64,
    n: u32,
    mode: Mode,
    max_bytes: u64,
) Error!void {
    if (@as(u64, n) > max_bytes -| read.*) return error.StreamTooLong;
    read.* += n;
    if (n == 0) return;
    const start = kept.items.len;
    if (@as(u64, n) > max_bytes -| start) return error.StreamTooLong;

    kept.resize(gpa, start + n) catch return error.OutOfMemory;
    try zurl_net.bounded.readExact(
        c.session.channel.reader,
        c.session.io,
        kept.items[start..],
        c.session.stall,
    );
    if (mode == .discard) kept.shrinkRetainingCapacity(start);
}

/// Adds `text` to `kept`, with a `CRLF` after it when `ending` is true.
fn append(
    gpa: std.mem.Allocator,
    kept: *std.ArrayList(u8),
    max_bytes: u64,
    text: []const u8,
    ending: bool,
) Error!void {
    const extra: u64 = @as(u64, text.len) + @as(u64, if (ending) 2 else 0);
    if (extra > max_bytes -| kept.items.len) return error.StreamTooLong;
    kept.appendSlice(gpa, text) catch return error.OutOfMemory;
    if (ending) kept.appendSlice(gpa, "\r\n") catch return error.OutOfMemory;
}

/// One line of a SASL exchange.
///
/// **A SASL exchange is the one place a continuation request is not a
/// fault.** Every other command this package sends has no rest, so a `+`
/// line says the two ends do not agree about what was sent. An
/// `AUTHENTICATE` is different: RFC 3501 section 6.2.2 makes the whole
/// exchange a run of `+` lines, each carrying a challenge, each answered
/// with one line of base64.
pub const AuthLine = union(enum) {
    /// The server wrote a challenge. The text is still base64, and it
    /// **borrows the session's line storage**.
    challenge: []const u8,
    /// The server ended the exchange with the tag that opened it.
    done: struct {
        status: response.Status,
        /// Borrows the session's line storage.
        text: []const u8,
    },
};

/// Reads the next line of a SASL exchange.
///
/// Untagged lines are skipped, and every one of them is charged against
/// `max_untagged_lines`, so a server that writes them for ever ends the
/// exchange instead of holding this process. That is the same bound
/// `collect` keeps, for the same reason.
///
/// `lines` is the caller's own counter, so one exchange is bounded across
/// every call.
pub fn readAuthLine(c: *Control, tag: []const u8, lines: *usize) Error!AuthLine {
    while (true) {
        const line = try c.nextLine(lines);
        const read = try response.readLine(line, tag);
        switch (read.kind) {
            .continuation => return .{ .challenge = read.text },
            .tagged => return .{ .done = .{
                .status = read.status orelse return error.ResponseMalformedTagged,
                .text = read.text,
            } },
            // A change in the mailbox, reported in the middle of a login.
            // It is data and never an end.
            .untagged => {},
        }
    }
}

/// Sends one line of a SASL exchange, with no tag in front of it.
///
/// **This is the one command shape in this package that carries no tag**,
/// and RFC 3501 section 6.2.2 is why: the line answers a challenge and not
/// a command, so a tag on it would reach the server as part of the base64.
/// It still goes through `zurl_net.line.Session.send`, so a NUL, a CR, or
/// an LF in it is refused before a byte reaches the writer.
pub fn sendAuthResponse(c: *Control, text: []const u8) Error!void {
    return c.session.send(&.{text});
}

/// Sends one command and reads its whole answer.
pub fn run(
    c: *Control,
    gpa: std.mem.Allocator,
    parts: []const []const u8,
    mode: Mode,
    max_bytes: u64,
) Error!Outcome {
    const tag = try c.send(parts);
    return c.collect(gpa, tag, mode, max_bytes);
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

test "the whole login and fetch reaches the wire as curl writes it" {
    // Measured from curl 8.21.0 against a loopback IMAP fixture. curl also
    // sends `CAPABILITY` first, which moves every tag on by one, and zurl
    // does not: see `Fetcher.open`.
    var w: Wire = undefined;
    w.init(
        "* OK [CAPABILITY IMAP4rev1] fixture ready\r\n" ++
            "A001 OK logged in\r\n" ++
            "* 2 EXISTS\r\n" ++
            "* OK [UIDVALIDITY 1]\r\n" ++
            "A002 OK [READ-WRITE] selected\r\n" ++
            "* 1 FETCH (BODY[] {21}\r\n" ++
            "Subject: hi\r\n\r\nbody\r\n" ++
            ")\r\n" ++
            "A003 OK done\r\n" ++
            "* BYE\r\n" ++
            "A004 OK logout\r\n",
    );
    defer w.deinit();

    try testing.expectEqual(response.Status.ok, try w.control.readGreeting());

    const login = try w.control.run(testing.allocator, &.{
        command.login, " ", "alice", " ", "s3cret",
    }, .discard, 4096);
    defer testing.allocator.free(login.body);
    try testing.expectEqual(response.Status.ok, login.status);

    const select = try w.control.run(testing.allocator, &.{
        command.select, " ", "INBOX",
    }, .discard, 4096);
    defer testing.allocator.free(select.body);
    try testing.expectEqual(response.Status.ok, select.status);
    try testing.expectEqualStrings("[READ-WRITE] selected", select.text);

    const fetch = try w.control.run(testing.allocator, &.{
        command.uid, " ", command.fetch, " ", "1", " ", command.whole_message,
    }, .literal, 4096);
    defer testing.allocator.free(fetch.body);
    // **Only the octets of the literal reach the caller.** The line around
    // them, and the `)` that closes the response, do not. This is byte for
    // byte what curl writes out.
    try testing.expectEqualStrings("Subject: hi\r\n\r\nbody\r\n", fetch.body);

    const logout = try w.control.run(testing.allocator, &.{command.logout}, .discard, 4096);
    defer testing.allocator.free(logout.body);

    try testing.expectEqualStrings(
        "A001 LOGIN alice s3cret\r\n" ++
            "A002 SELECT INBOX\r\n" ++
            "A003 UID FETCH 1 BODY[]\r\n" ++
            "A004 LOGOUT\r\n",
        w.wire(),
    );
}

test "an untagged line never ends a command, and a foreign tag ends the session" {
    // **The defect this test exists for.** A reader that stopped at the
    // first line would take `* 2 EXISTS` as the answer to `LOGIN`, and
    // every answer after it would belong to the command before it.
    var w: Wire = undefined;
    w.init(
        "* 5 EXISTS\r\n" ++
            "* 1 RECENT\r\n" ++
            "* OK [UNSEEN 3]\r\n" ++
            "A001 OK logged in\r\n",
    );
    defer w.deinit();

    const tag = try w.control.send(&.{ command.login, " ", "a", " ", "b" });
    try testing.expectEqualStrings("A001", tag);
    const out = try w.control.collect(testing.allocator, tag, .discard, 4096);
    defer testing.allocator.free(out.body);
    try testing.expectEqual(response.Status.ok, out.status);
}

test "a tagged line carrying another tag ends the session rather than the command" {
    var w: Wire = undefined;
    w.init("A002 OK done\r\n");
    defer w.deinit();

    const tag = try w.control.send(&.{command.logout});
    try testing.expectEqualStrings("A001", tag);
    try testing.expectError(
        error.ResponseMalformed,
        w.control.collect(testing.allocator, tag, .discard, 4096),
    );
}

test "untagged mode keeps the lines exactly as they arrived" {
    // This is what curl writes out for a `LIST`, measured byte for byte.
    var w: Wire = undefined;
    w.init(
        "* LIST (\\HasNoChildren) \"/\" INBOX\r\n" ++
            "* LIST (\\HasNoChildren) \"/\" Sent\r\n" ++
            "A001 OK done\r\n",
    );
    defer w.deinit();

    const out = try w.control.run(testing.allocator, &.{
        command.list, " ", "\"\"", " ", command.list_all_pattern,
    }, .untagged, 4096);
    defer testing.allocator.free(out.body);
    try testing.expectEqualStrings(
        "* LIST (\\HasNoChildren) \"/\" INBOX\r\n* LIST (\\HasNoChildren) \"/\" Sent\r\n",
        out.body,
    );
    try testing.expectEqualStrings("A001 LIST \"\" *\r\n", w.wire());
}

test "a literal is read by its count, even when the octets hold a line ending" {
    // **The defect this test exists for.** The literal below holds a line
    // that looks like a tagged answer. A reader that read the octets as
    // lines would match it against the tag and end the command in the
    // middle of a message.
    const body = "A001 OK not really the end\r\nmore body\r\n";
    var script: std.Io.Writer.Allocating = .init(testing.allocator);
    defer script.deinit();
    try script.writer.print(
        "* 1 FETCH (BODY[] {{{d}}}\r\n{s})\r\nA001 OK done\r\n",
        .{ body.len, body },
    );

    var w: Wire = undefined;
    w.init(script.written());
    defer w.deinit();

    const out = try w.control.run(testing.allocator, &.{
        command.fetch, " ", "1", " ", command.whole_message,
    }, .literal, 4096);
    defer testing.allocator.free(out.body);
    try testing.expectEqualStrings(body, out.body);
    try testing.expectEqual(response.Status.ok, out.status);
}

test "a response with two literals keeps both, in order" {
    var w: Wire = undefined;
    w.init(
        "* 1 FETCH (BODY[HEADER] {5}\r\n" ++
            "one\r\n" ++
            " BODY[TEXT] {5}\r\n" ++
            "two\r\n" ++
            ")\r\n" ++
            "A001 OK done\r\n",
    );
    defer w.deinit();

    const out = try w.control.run(testing.allocator, &.{
        command.fetch, " ", "1", " ", command.whole_message,
    }, .literal, 4096);
    defer testing.allocator.free(out.body);
    try testing.expectEqualStrings("one\r\ntwo\r\n", out.body);
}

test "a literal of nothing is a literal and not a fault" {
    var w: Wire = undefined;
    w.init("* 1 FETCH (BODY[] {0}\r\n)\r\nA001 OK done\r\n");
    defer w.deinit();

    const out = try w.control.run(testing.allocator, &.{
        command.fetch, " ", "1", " ", command.whole_message,
    }, .literal, 4096);
    defer testing.allocator.free(out.body);
    try testing.expectEqualStrings("", out.body);
}

test "discard mode still reads the octets of a literal off the wire" {
    // **A reader that skipped them would read them as answers.** The
    // second command below only gets its own answer because the first one
    // consumed the whole literal.
    var w: Wire = undefined;
    w.init(
        "* 1 FETCH (BODY[] {13}\r\nA001 OK bad\r\n)\r\n" ++
            "A001 OK first\r\n" ++
            "A002 OK second\r\n",
    );
    defer w.deinit();

    const first = try w.control.run(testing.allocator, &.{command.capability}, .discard, 4096);
    defer testing.allocator.free(first.body);
    try testing.expectEqualStrings("", first.body);
    try testing.expectEqualStrings("first", first.text);

    const second = try w.control.run(testing.allocator, &.{command.capability}, .discard, 4096);
    defer testing.allocator.free(second.body);
    try testing.expectEqualStrings("second", second.text);
}

test "a literal larger than the bound is refused before the buffer is made" {
    // The count says four gigabytes and the peer wrote nothing. A reader
    // that made the buffer first would ask for four gigabytes.
    var w: Wire = undefined;
    w.init("* 1 FETCH (BODY[] {4294967295}\r\n");
    defer w.deinit();

    try testing.expectError(error.StreamTooLong, w.control.run(testing.allocator, &.{
        command.fetch, " ", "1", " ", command.whole_message,
    }, .literal, 4096));
}

test "an answer larger than the bound is refused" {
    var w: Wire = undefined;
    w.init(
        "* LIST () \"/\" 0123456789\r\n" ++
            "* LIST () \"/\" 0123456789\r\n" ++
            "A001 OK done\r\n",
    );
    defer w.deinit();

    try testing.expectError(error.StreamTooLong, w.control.run(testing.allocator, &.{
        command.list, " ", "\"\"", " ", command.list_all_pattern,
    }, .untagged, 30));
}

test "a server that writes untagged lines for ever is refused at the line count" {
    // **The bound a byte count cannot keep.** In `discard` mode nothing is
    // kept, so no byte bound would ever fire, and a server writing
    // `* 1 EXISTS` for ever would hold this process until it was killed.
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    var i: usize = 0;
    while (i < max_untagged_lines + 4) : (i += 1) {
        try script.appendSlice(testing.allocator, "* 1 EXISTS\r\n");
    }

    var w: Wire = undefined;
    w.init(script.items);
    defer w.deinit();

    try testing.expectError(error.TooManyUntaggedLines, w.control.run(
        testing.allocator,
        &.{command.capability},
        .discard,
        1 << 20,
    ));
}

test "a literal continuation loop is bounded in every mode" {
    // **The pre-authentication loop this bound exists for.** A `FETCH`
    // whose literal is `{0}` costs nothing: `readLiteral` returns at once,
    // and in `.discard` and `.literal` mode nothing is kept, so no byte
    // count moved either. The line count lived in the outer loop, so the
    // continuation loop below it advanced no counter of any kind. Five
    // octets on the wire bought one more turn, for ever, on a url that
    // needs no credential at all.
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try script.appendSlice(testing.allocator, "* 1 FETCH (BODY[] {0}\r\n");
    var i: usize = 0;
    while (i < max_untagged_lines + 4) : (i += 1) {
        try script.appendSlice(testing.allocator, "{0}\r\n");
    }

    for ([_]Mode{ .discard, .literal, .untagged }) |mode| {
        var w: Wire = undefined;
        w.init(script.items);
        defer w.deinit();

        try testing.expectError(error.TooManyUntaggedLines, w.control.run(
            testing.allocator,
            &.{ command.fetch, " ", "1", " ", command.whole_message },
            mode,
            1 << 20,
        ));
    }
}

test "the literal octets of one answer are charged in every mode" {
    // The sibling bound. Every literal of an answer is charged against
    // `max_bytes`, whether or not the mode keeps it, so a `.discard`
    // answer cannot read `max_bytes` octets on each of its lines.
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try script.appendSlice(testing.allocator, "* 1 FETCH (BODY[] {8}\r\n");
    try script.appendSlice(testing.allocator, "12345678");
    try script.appendSlice(testing.allocator, " {8}\r\n");
    try script.appendSlice(testing.allocator, "abcdefgh");
    try script.appendSlice(testing.allocator, ")\r\nA001 OK done\r\n");

    for ([_]Mode{ .discard, .literal }) |mode| {
        var w: Wire = undefined;
        w.init(script.items);
        defer w.deinit();

        // Twelve octets of room, and the two literals come to sixteen.
        try testing.expectError(error.StreamTooLong, w.control.run(
            testing.allocator,
            &.{ command.fetch, " ", "1", " ", command.whole_message },
            mode,
            12,
        ));
    }
}

test "a continuation request ends the session, because this package sends no rest" {
    var w: Wire = undefined;
    w.init("+ go ahead\r\n");
    defer w.deinit();

    try testing.expectError(error.UnexpectedContinuation, w.control.run(
        testing.allocator,
        &.{ command.login, " ", "a", " ", "b" },
        .discard,
        4096,
    ));
}

test "a command with a forged line ending never reaches the writer" {
    // **The injection proof at the dialogue.** The gate refuses before
    // `writeAll` runs, so not one byte of the forged command goes out. A
    // forged line here would write a second command under a tag this
    // client never used, and the answer to it would then be read against
    // the wrong command for the rest of the session.
    var w: Wire = undefined;
    w.init("* OK ready\r\n");
    defer w.deinit();

    _ = try w.control.readGreeting();

    const forged = [_][]const u8{
        "INBOX\r\nA002 LOGOUT",
        "INBOX\nA002 LOGOUT",
        "INBOX\rA002 LOGOUT",
        "IN\x00BOX",
        "\r\n",
        "\n",
        "\r",
        "\x00",
        "alice\r\nA002 LOGIN bob pw",
        "s3cret\r\nA002 DELETE INBOX",
    };
    const verbs = [_][]const u8{
        command.login,    command.select, command.examine, command.list,
        command.fetch,    command.uid,    command.logout,  command.capability,
        command.starttls,
    };
    for (forged) |part| {
        for (verbs) |verb| {
            try testing.expectError(
                error.ArgumentHasFramingByte,
                w.control.send(&.{ verb, " ", part }),
            );
            try testing.expectError(
                error.ArgumentHasFramingByte,
                w.control.send(&.{ verb, " ", part, " ", "x" }),
            );
        }
        // A forged verb is refused too, because `--request` gives a user a
        // way to name one.
        try testing.expectError(error.ArgumentHasFramingByte, w.control.send(&.{part}));
    }

    try testing.expectEqualStrings("", w.wire());
}

test "a greeting that is not an untagged status ends the session" {
    for ([_][]const u8{
        "A001 OK ready\r\n",
        "+ ready\r\n",
        "220 ready\r\n",
        "* 2 EXISTS\r\n",
        "\r\n",
    }) |script| {
        var w: Wire = undefined;
        w.init(script);
        defer w.deinit();
        try testing.expectError(error.ResponseMalformed, w.control.readGreeting());
    }
}

test "a greeting of BYE is read, so a caller can say what happened" {
    var w: Wire = undefined;
    w.init("* BYE this server is full\r\n");
    defer w.deinit();
    try testing.expectEqual(response.Status.bye, try w.control.readGreeting());
}

test "retarget keeps the tag counter, so no tag is used twice" {
    // **The rule a `STARTTLS` upgrade needs.** RFC 3501 gives each command
    // of one connection its own tag, and the handshake does not start a
    // new connection. A dialogue that reset the counter would send `A001`
    // twice, and the answer to the first would end the second.
    var w: Wire = undefined;
    w.init("* OK ready\r\nA001 OK go ahead\r\n");
    defer w.deinit();

    _ = try w.control.readGreeting();
    const first = try w.control.send(&.{command.starttls});
    try testing.expectEqualStrings("A001", first);

    var second_reader: Io.Reader = .fixed("A002 OK logged in\r\n");
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    w.control.retarget(.{
        .reader = &second_reader,
        .writer = &out.writer,
        .ctx = &w,
        .flush = Wire.flush,
    });

    const answer = try w.control.run(testing.allocator, &.{
        command.login, " ", "alice", " ", "s3cret",
    }, .discard, 4096);
    defer testing.allocator.free(answer.body);
    try testing.expectEqual(response.Status.ok, answer.status);
    try testing.expectEqualStrings("A002 LOGIN alice s3cret\r\n", out.written());
}

test "a line longer than the bound ends the session" {
    var storage: [max_line_bytes + 64]u8 = undefined;
    @memset(&storage, 'x');
    storage[0] = '*';
    storage[1] = ' ';

    var w: Wire = undefined;
    w.init(&storage);
    defer w.deinit();

    try testing.expectError(error.LineTooLong, w.control.readGreeting());
}

test "a peer that closes before the tagged answer is a fault, not an end" {
    var w: Wire = undefined;
    w.init("* 1 EXISTS\r\n");
    defer w.deinit();

    try testing.expectError(error.EndOfStream, w.control.run(
        testing.allocator,
        &.{command.capability},
        .discard,
        4096,
    ));
}

test "a peer that closes in the middle of a literal is a fault, not a short body" {
    var w: Wire = undefined;
    w.init("* 1 FETCH (BODY[] {100}\r\nonly a few octets");
    defer w.deinit();

    try testing.expectError(error.EndOfStream, w.control.run(
        testing.allocator,
        &.{ command.fetch, " ", "1", " ", command.whole_message },
        .literal,
        4096,
    ));
}
