//! The command and reply machinery a line-oriented protocol needs.
//!
//! **This is the shared half of FTP, SMTP, IMAP, and POP3.** All four
//! write a command as one line and read an answer as one line or several.
//! The grammar over the line belongs to the package that owns the
//! protocol. The three things below belong here, because all four need
//! each of them and a second copy of any one is a second place to get it
//! wrong:
//!
//! - `write`, which turns text into a command line and **refuses a NUL, a
//!   CR, or an LF in any part of it**. That refusal is the injection gate
//!   of every one of the four protocols.
//! - `Channel`, which is where a dialogue reads and writes. It holds no
//!   socket, so a test drives a whole session over two buffers.
//! - `Session`, which puts `bounded.readLine` under `Channel` and sends a
//!   command through `write`. It is the only writer, so no command can
//!   reach a peer any other way.
//!
//! **The rule `write` keeps.** A command is `text<CRLF>`, so a CR or an LF
//! inside the text ends the line early and starts a command of the text's
//! own choosing. `USER a<CRLF>PASS x<CRLF>` from a url is two commands
//! where the url named one, and `RCPT TO:<a><CRLF>DATA<CRLF>` from a
//! recipient address is a message the sender never wrote. A NUL goes with
//! them: none of the four protocols puts a NUL in a command, an operating
//! system reads a path up to the first one, and one rule over the three
//! bytes is the rule this project already keeps everywhere else.
//!
//! **The refusal comes before any byte reaches the socket.** `write`
//! checks every part first and only then fills the caller's buffer, so a
//! refused command leaves nothing half written on the wire and nothing
//! half written in the buffer.
//!
//! This module opens nothing. `Session` reads and writes through the
//! caller's own reader and writer.

const std = @import("std");

const bounded = @import("bounded.zig");

const Io = std.Io;

/// How many bytes of one command line a protocol package normally holds,
/// the `CRLF` counted.
///
/// None of the four protocols sets a limit that fits every server. A url
/// path can be long, a password longer, and an IMAP mailbox name longer
/// still, so this is generous. It is a bound because an unbounded command
/// needs an unbounded buffer, and a package that wants another number
/// simply sizes its own storage. Passing the buffer is
/// `error.CommandTooLong`.
pub const max_command_bytes = 2048;

/// Why a command was not written.
pub const WriteError = error{
    /// A part holds a NUL, a CR, or an LF. See the module comment: any of
    /// the three would end the command line and let the part write a
    /// command of its own.
    ArgumentHasFramingByte,
    /// The parts together do not fit the caller's buffer.
    CommandTooLong,
};

/// Whether `text` holds a byte that could end a command line.
///
/// The three bytes are NUL, CR, and LF. `zurl_core.url.hasFramingByte`
/// answers the same question for a url, and this module keeps its own copy
/// so that `zurl-net` needs no url rule to write a command line.
pub fn hasFramingByte(text: []const u8) bool {
    for (text) |byte| {
        if (byte == 0 or byte == '\r' or byte == '\n') return true;
    }
    return false;
}

/// Writes `parts`, one after another, followed by a `CRLF`, into `out`.
///
/// **Every part is checked before anything is written.** A NUL, a CR, or
/// an LF anywhere in any part is `error.ArgumentHasFramingByte` and `out`
/// is not touched at all.
///
/// The literal parts of a command are checked with the rest. A string
/// constant can never fail the check, so the cost is nothing and the rule
/// stays one rule: every byte that reaches a command line passed through
/// here.
///
/// The result points into `out`.
pub fn write(out: []u8, parts: []const []const u8) WriteError![]u8 {
    // **The refusal, and it runs first.** See the module comment for what
    // each of the three bytes would do to the line.
    var total: usize = 2;
    for (parts) |part| {
        if (hasFramingByte(part)) return error.ArgumentHasFramingByte;
        total += part.len;
    }
    if (total > out.len) return error.CommandTooLong;

    var at: usize = 0;
    for (parts) |part| {
        @memcpy(out[at..][0..part.len], part);
        at += part.len;
    }
    out[at] = '\r';
    out[at + 1] = '\n';
    return out[0 .. at + 2];
}

/// Where a dialogue reads and writes.
///
/// `flush` is a function pointer and not a call on `writer`, because a
/// `zurl_net.Connection` needs its own `flush`: an encrypted connection
/// has a plaintext buffer and a ciphertext buffer in a row, and flushing
/// only the first leaves the whole command inside the process. A raw
/// stream writer needs its own flush instead. One pointer serves both.
pub const Channel = struct {
    reader: *Io.Reader,
    writer: *Io.Writer,
    /// Passed back to `flush`.
    ctx: ?*anyopaque = null,
    flush: *const fn (ctx: ?*anyopaque) Io.Writer.Error!void,
};

/// One line-oriented dialogue, over one reader and one writer.
///
/// `line_bytes` is the bound on one answer line and `command_bytes` is the
/// bound on one command line. They are comptime parameters because the
/// four protocols do not agree on either: an FTP reply line is short and
/// an IMAP `FETCH` line carries a whole message header.
///
/// **A `Session` must not move once a line has been read from it.** The
/// line a caller holds points into `line_storage`, which is a field of
/// this value.
pub fn Session(comptime line_bytes: usize, comptime command_bytes: usize) type {
    return struct {
        const Self = @This();

        /// The bound on one answer line, the line ending counted.
        pub const max_line_bytes = line_bytes;

        /// The bound on one command line, the `CRLF` counted.
        pub const max_command_line_bytes = command_bytes;

        /// Every fault a read can report.
        pub const ReadError = bounded.LineError;

        /// Every fault this can report.
        pub const Error = ReadError || Io.Writer.Error || WriteError;

        io: Io,
        channel: Channel,
        /// How long one read may wait with no byte arriving.
        stall: Io.Timeout,
        /// Holds one answer line as it arrives.
        line_storage: [line_bytes]u8,
        /// Holds one command line as it is built.
        command_storage: [command_bytes]u8,

        /// Initializes `s` in place.
        ///
        /// In place, and not a value returned, because the storage above
        /// is kilobytes and the line a caller holds points into it.
        pub fn init(s: *Self, io: Io, channel: Channel, stall: Io.Timeout) void {
            s.io = io;
            s.channel = channel;
            s.stall = stall;
        }

        /// Points the dialogue at another reader and writer, keeping the
        /// storage.
        ///
        /// **This is what a STARTTLS upgrade needs.** The dialogue before
        /// the handshake runs over the raw stream and the dialogue after
        /// it runs over the TLS session. The state either side of that is
        /// the server's, not this value's, so the same `Session` carries
        /// on.
        pub fn retarget(s: *Self, channel: Channel) void {
            s.channel = channel;
        }

        /// How many bytes the reader holds and nobody has read.
        ///
        /// **A TLS upgrade must find this zero.** A server that wrote
        /// bytes behind its answer to `STARTTLS` or `STLS` wrote them in
        /// cleartext, and a reader that carried them across the handshake
        /// would hand a caller text the peer chose as though TLS had
        /// protected it.
        pub fn buffered(s: *Self) usize {
            return s.channel.reader.buffered().len;
        }

        /// Reads one line, with its ending taken off.
        ///
        /// The result points into `line_storage`, so it is valid until the
        /// next read on this `Session`.
        ///
        /// Bounded twice: `line_bytes` stops a line that never ends, and
        /// `stall` stops a peer that writes nothing.
        pub fn readLine(s: *Self) ReadError![]u8 {
            return bounded.readLine(s.channel.reader, s.io, &s.line_storage, s.stall);
        }

        /// Writes one command and sends it.
        ///
        /// **Every part is refused before any byte reaches the writer**
        /// when it holds a NUL, a CR, or an LF. See `write`.
        pub fn send(s: *Self, parts: []const []const u8) Error!void {
            const command = try write(&s.command_storage, parts);
            try s.channel.writer.writeAll(command);
            try s.channel.flush(s.channel.ctx);
        }

        /// Writes `payload` and sends it, with no line ending added.
        ///
        /// **This is the one way past `write`, and it is not a way past
        /// the injection rule.** A message body is not a command: it is
        /// data whose line endings are its own, and a caller that has
        /// already made every line of it safe writes it here. SMTP's
        /// `DATA` phase is the only caller, and `zurl_smtp.message` is
        /// what makes the body safe before this runs. See that module for
        /// the dot-stuffing rule that does it.
        pub fn sendRaw(s: *Self, payload: []const u8) Io.Writer.Error!void {
            try s.channel.writer.writeAll(payload);
            try s.channel.flush(s.channel.ctx);
        }
    };
}

const testing = std.testing;

test "a command line is the parts, in order, and a CRLF" {
    var out: [64]u8 = undefined;
    try testing.expectEqualStrings("QUIT\r\n", try write(&out, &.{"QUIT"}));
    try testing.expectEqualStrings("USER bob\r\n", try write(&out, &.{ "USER", " ", "bob" }));
    try testing.expectEqualStrings(
        "MAIL FROM:<a@b>\r\n",
        try write(&out, &.{ "MAIL FROM:<", "a@b", ">" }),
    );
    try testing.expectEqualStrings(
        "a001 LOGIN bob pw\r\n",
        try write(&out, &.{ "a001", " ", "LOGIN", " ", "bob", " ", "pw" }),
    );
}

test "an empty part writes nothing and is not an error" {
    var out: [64]u8 = undefined;
    try testing.expectEqualStrings("RETR \r\n", try write(&out, &.{ "RETR", " ", "" }));
    try testing.expectEqualStrings("\r\n", try write(&out, &.{}));
}

test "a CR, an LF, or a NUL in any part is refused and nothing is written" {
    // **The injection proof of the shared gate.** Each part below would
    // end the command line early and put a command of its own behind it.
    var out: [128]u8 = undefined;
    @memset(&out, 0xaa);

    const forged = [_][]const u8{
        "a\r\nQUIT",
        "a\nQUIT",
        "a\rQUIT",
        "a\x00b",
        "\r\n",
        "\n",
        "\r",
        "\x00",
        "bob\r\nPASS hunter2",
        "INBOX\r\na002 LOGOUT",
        "a@b\r\nDATA",
    };
    for (forged) |part| {
        // The forged text refuses wherever it sits in the list.
        try testing.expectError(error.ArgumentHasFramingByte, write(&out, &.{part}));
        try testing.expectError(error.ArgumentHasFramingByte, write(&out, &.{ "USER", " ", part }));
        try testing.expectError(error.ArgumentHasFramingByte, write(&out, &.{ part, " ", "LOGOUT" }));
        try testing.expectError(
            error.ArgumentHasFramingByte,
            write(&out, &.{ "a001", " ", "SELECT", " ", part }),
        );
    }

    // Not one byte of the buffer moved.
    for (out) |byte| try testing.expectEqual(@as(u8, 0xaa), byte);
}

test "a byte that is not framing still reaches the command line" {
    // The rule refuses three bytes and never a fourth. A space, a tab, a
    // DEL, and a high byte are all ordinary in a name a server holds.
    var out: [64]u8 = undefined;
    try testing.expectEqualStrings("RETR a b\r\n", try write(&out, &.{ "RETR", " ", "a b" }));
    try testing.expectEqualStrings("RETR a\tb\r\n", try write(&out, &.{ "RETR", " ", "a\tb" }));
    try testing.expectEqualStrings("RETR a\x7fb\r\n", try write(&out, &.{ "RETR", " ", "a\x7fb" }));
    try testing.expectEqualStrings("RETR \xc3\xa9\r\n", try write(&out, &.{ "RETR", " ", "\xc3\xa9" }));
    try testing.expectEqualStrings("RETR a%0db\r\n", try write(&out, &.{ "RETR", " ", "a%0db" }));
}

test "a command longer than the buffer is refused rather than overrun" {
    var out: [16]u8 = undefined;
    @memset(&out, 0xaa);
    try testing.expectError(error.CommandTooLong, write(&out, &.{ "RETR", " ", "a-long-name.txt" }));
    for (out) |byte| try testing.expectEqual(@as(u8, 0xaa), byte);

    // A command of exactly the buffer is written.
    try testing.expectEqualStrings("RETR abcdefghi\r\n", try write(&out, &.{ "RETR", " ", "abcdefghi" }));
}

test "hasFramingByte names the three bytes and no others" {
    try testing.expect(hasFramingByte("a\r"));
    try testing.expect(hasFramingByte("a\n"));
    try testing.expect(hasFramingByte("a\x00"));
    try testing.expect(!hasFramingByte("a\tb c\x7f\xff"));
    try testing.expect(!hasFramingByte(""));
}

/// A `Session` over two buffers, so a test drives a dialogue with no
/// socket.
const Wire = struct {
    session: Session(1024, 2048),
    reader: Io.Reader,
    sent: std.Io.Writer.Allocating,

    fn init(w: *Wire, server_says: []const u8) void {
        w.reader = .fixed(server_says);
        w.sent = .init(testing.allocator);
        w.session.init(testing.io, .{
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
};

test "a session reads lines and writes commands over two buffers" {
    var w: Wire = undefined;
    w.init("+OK ready\r\n+OK 1 20\r\n");
    defer w.deinit();

    try testing.expectEqualStrings("+OK ready", try w.session.readLine());
    try w.session.send(&.{ "USER", " ", "bob" });
    try testing.expectEqualStrings("+OK 1 20", try w.session.readLine());
    try testing.expectEqualStrings("USER bob\r\n", w.sent.written());
    try testing.expectError(error.EndOfStream, w.session.readLine());
}

test "a session refuses a forged command and writes not one byte of it" {
    // **The injection proof at the dialogue.** `write` refuses before
    // `writeAll` runs, so the command before it is the last thing on the
    // wire.
    var w: Wire = undefined;
    w.init("+OK ready\r\n");
    defer w.deinit();

    _ = try w.session.readLine();
    try testing.expectError(
        error.ArgumentHasFramingByte,
        w.session.send(&.{ "USER", " ", "bob\r\nPASS hunter2" }),
    );
    try testing.expectError(
        error.ArgumentHasFramingByte,
        w.session.send(&.{ "RETR", " ", "1\r\nDELE 2" }),
    );
    try testing.expectEqualStrings("", w.sent.written());
}

test "a session retargets and keeps its storage" {
    // A STARTTLS upgrade needs this: the dialogue before the handshake
    // runs over the raw stream and the dialogue after it runs over the
    // session.
    var w: Wire = undefined;
    w.init("+OK ready\r\n");
    defer w.deinit();

    _ = try w.session.readLine();

    var second: Io.Reader = .fixed("+OK logged in\r\n");
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    w.session.retarget(.{
        .reader = &second,
        .writer = &out.writer,
        .ctx = &w,
        .flush = Wire.flush,
    });

    try w.session.send(&.{ "USER", " ", "bob" });
    try testing.expectEqualStrings("+OK logged in", try w.session.readLine());
    try testing.expectEqualStrings("USER bob\r\n", out.written());
    // Nothing went to the first writer.
    try testing.expectEqualStrings("", w.sent.written());
}

test "buffered reports what the reader holds and nobody has read" {
    var w: Wire = undefined;
    w.init("+OK ready\r\nextra\r\n");
    defer w.deinit();

    _ = try w.session.readLine();
    // A fixed reader holds the whole script from the start, which a
    // socket does not. The number is what a TLS upgrade checks, and this
    // proves the accessor reads the reader and not a copy.
    try testing.expectEqual(@as(usize, "extra\r\n".len), w.session.buffered());
}

test "a line longer than the session bound ends the dialogue" {
    const Small = Session(16, 64);
    var storage: [64]u8 = undefined;
    @memset(&storage, 'x');
    var reader: Io.Reader = .fixed(&storage);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    var s: Small = undefined;
    s.init(testing.io, .{
        .reader = &reader,
        .writer = &out.writer,
        .flush = Wire.flush,
    }, .none);
    try testing.expectError(error.LineTooLong, s.readLine());
}

test "sendRaw writes the payload and adds no line ending" {
    var w: Wire = undefined;
    w.init("");
    defer w.deinit();

    try w.session.sendRaw("line one\r\n.\r\n");
    try testing.expectEqualStrings("line one\r\n.\r\n", w.sent.written());
}
