//! A loopback RFC 5321 server for the tests of this package.
//!
//! This is a test fixture, not a product. It speaks enough of the dialogue
//! to run a whole send, and it lets a test bend every answer. It validates
//! nothing: a test that pins the bytes a command carries has to see those
//! bytes as they arrived.
//!
//! **No test in this package reaches the real network.** Every one that
//! needs a peer starts one of these on 127.0.0.1, with a port the
//! operating system assigns.
//!
//! **The fixture takes the dot-stuffing off, the way a real server does.**
//! `body` gives back the message as its author wrote it, so a test that
//! compares it against what it sent has proved the round trip of RFC 5321
//! section 4.5.2. It also ends the `DATA` phase at the first line holding
//! one period and nothing else, exactly as the standard says, which is
//! what makes the injection test real: a client that did not stuff would
//! see this fixture read the rest of the message as commands, and the
//! command log would show them.
//!
//! **This fixture speaks no TLS**, for the reason `zurl_pop3.test_server`
//! gives.

const std = @import("std");
const testing = std.testing;

pub const Server = @This();

/// How many bytes of the command log this keeps.
pub const log_bytes = 8192;

/// How many bytes of message body this keeps.
pub const body_bytes = 8192;

/// What the fixture answers.
pub const Script = struct {
    /// The greeting line.
    greeting: []const u8 = "220 fixture ESMTP ready",
    /// The answer to `EHLO`, one line for each entry.
    ehlo: []const []const u8 = &.{ "250-fixture", "250-SIZE 1000000", "250 STARTTLS" },
    /// The answer to `HELO`.
    helo: []const u8 = "250 fixture",
    /// The answer to `MAIL FROM`.
    mail: []const u8 = "250 sender ok",
    /// The answer to `RCPT TO`.
    rcpt: []const u8 = "250 recipient ok",
    /// The answer to `DATA`.
    data: []const u8 = "354 go ahead",
    /// The answer after the message.
    body_reply: []const u8 = "250 message accepted",
    /// The answer to `STARTTLS`. The default refuses, because this fixture
    /// speaks no TLS.
    starttls: []const u8 = "454 TLS is not available on this fixture",
    /// Bytes the fixture writes straight after its `STARTTLS` answer.
    starttls_trailer: ?[]const u8 = null,
    /// The answer to `QUIT`.
    quit: []const u8 = "221 bye",
    /// The answer to anything else.
    unknown: []const u8 = "500 unknown command",
    /// The challenges the fixture writes, in order, one for each `334` it
    /// answers before it ends the exchange.
    ///
    /// **Each entry is already base64**, because a challenge reaches the
    /// wire encoded and a test that pins the bytes has to name them as
    /// they travel. The default is one empty challenge, which is what a
    /// `PLAIN` exchange with no initial response draws: RFC 4954 section 4
    /// writes it `334 `.
    auth_challenges: []const []const u8 = &.{""},
    /// The answer that ends a SASL exchange.
    auth_reply: []const u8 = "235 authentication succeeded",
};

server: std.Io.net.Server,
task: std.Io.Future(void),
script: Script,
/// Every command line the client wrote, one for each line, joined with
/// `\n`. Read through `commands` after `wait`.
log_storage: [log_bytes]u8,
log_len: usize,
/// The message the client sent, with the dot-stuffing taken off. Read
/// through `body` after `wait`.
body_storage: [body_bytes]u8,
body_len: usize,
/// Set when the task has finished writing both.
done: std.atomic.Value(bool),
/// How many connections the fixture accepted.
accept_count: std.atomic.Value(usize),

/// Starts listening on loopback and starts a task that runs one session.
///
/// Returns `error.SkipZigTest` in a build with no concurrency at all.
///
/// `s` and every slice inside `script` must outlive the server.
pub fn start(s: *Server, script: Script) !void {
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    s.server = try address.listen(testing.io, .{ .reuse_address = true });
    errdefer s.server.deinit(testing.io);

    s.script = script;
    s.log_len = 0;
    s.body_len = 0;
    s.done = .init(false);
    s.accept_count = .init(0);

    s.task = testing.io.concurrent(run, .{s}) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
}

/// Starts a server that accepts one connection, writes nothing at all, and
/// holds the socket open.
pub fn startSilent(s: *Server) !void {
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    s.server = try address.listen(testing.io, .{ .reuse_address = true });
    errdefer s.server.deinit(testing.io);

    s.script = .{};
    s.log_len = 0;
    s.body_len = 0;
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

/// Every command the client sent, one for each line.
///
/// Call `wait` first for a complete list.
pub fn commands(s: *const Server) []const u8 {
    if (!s.done.load(.acquire)) return "";
    return s.log_storage[0..s.log_len];
}

/// The message the client sent, with the dot-stuffing taken off.
///
/// Call `wait` first.
pub fn body(s: *const Server) []const u8 {
    if (!s.done.load(.acquire)) return "";
    return s.body_storage[0..s.body_len];
}

/// Waits for the session to finish.
pub fn wait(s: *Server) void {
    s.task.await(testing.io);
}

/// Stops the server task and releases the listening socket.
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

const Session = struct {
    s: *Server,
    writer: *std.Io.Writer,
    reader: *std.Io.Reader,
    /// True while the client is writing the message.
    in_data: bool = false,
    /// Holds one `334` line as it is built.
    challenge_storage: [1024]u8 = undefined,

    fn line(session: *Session, text: []const u8) !void {
        try session.writer.writeAll(text);
        try session.writer.writeAll("\r\n");
        try session.writer.flush();
    }
};

fn run(s: *Server) void {
    const stream = s.server.accept(testing.io) catch return;
    defer stream.close(testing.io);
    _ = s.accept_count.fetchAdd(1, .release);

    var read_buffer: [4096]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    var write_buffer: [4096]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);

    var session: Session = .{ .s = s, .writer = &writer.interface, .reader = &reader.interface };
    serve(&session) catch {};
    s.done.store(true, .release);
}

fn serve(session: *Session) !void {
    try session.line(session.s.script.greeting);

    while (true) {
        const raw = session.reader.takeDelimiterInclusive('\n') catch return;
        const text = std.mem.trimEnd(u8, raw, "\r\n");

        // **The `DATA` phase ends at one period on a line of its own**,
        // and at no other line. RFC 5321 section 4.1.1.4. A client that
        // did not stuff a period line would end the phase here, and every
        // line after it would reach the command log below.
        if (session.in_data) {
            if (text.len == 1 and text[0] == '.') {
                session.in_data = false;
                try session.line(session.s.script.body_reply);
                continue;
            }
            // The receiving half of section 4.5.2: one period comes off.
            const unstuffed = if (text.len != 0 and text[0] == '.') text[1..] else text;
            try appendBody(session.s, unstuffed);
            continue;
        }

        try log(session.s, text);

        var it = std.mem.splitScalar(u8, text, ' ');
        const verb = it.first();

        if (eq(verb, "EHLO")) {
            for (session.s.script.ehlo) |answer| try session.line(answer);
        } else if (eq(verb, "HELO")) {
            try session.line(session.s.script.helo);
        } else if (std.mem.startsWith(u8, verb, "MAIL")) {
            try session.line(session.s.script.mail);
        } else if (std.mem.startsWith(u8, verb, "RCPT")) {
            try session.line(session.s.script.rcpt);
        } else if (eq(verb, "AUTH")) {
            // **Every response of the exchange reaches the command log**,
            // so a test can pin the base64 the client wrote and decode it
            // to prove which fields went out. RFC 4954 section 4: the
            // server writes `334 <challenge>` and the client answers with
            // one line of base64.
            //
            // A client that put its first message on the `AUTH` line
            // itself, which is `--sasl-ir`, has already sent one response,
            // so the fixture writes one challenge fewer. That is what a
            // real server does: it is answering a message it already has.
            var words: usize = 1;
            while (it.next()) |_| words += 1;
            // `AUTH PLAIN` is two words and `AUTH PLAIN <base64>` is
            // three.
            const skip: usize = if (words >= 3) 1 else 0;
            const challenges = session.s.script.auth_challenges;
            var i: usize = @min(skip, challenges.len);
            while (i < challenges.len) : (i += 1) {
                try session.line(if (challenges[i].len == 0)
                    "334 "
                else
                    try std.fmt.bufPrint(&session.challenge_storage, "334 {s}", .{challenges[i]}));
                const answer_raw = session.reader.takeDelimiterInclusive('\n') catch return;
                try log(session.s, std.mem.trimEnd(u8, answer_raw, "\r\n"));
            }
            try session.line(session.s.script.auth_reply);
        } else if (eq(verb, "DATA")) {
            try session.line(session.s.script.data);
            if (std.mem.startsWith(u8, session.s.script.data, "3")) session.in_data = true;
        } else if (eq(verb, "STARTTLS")) {
            // **The answer and any trailer go out in one write**, for the
            // reason `zurl_pop3.test_server` gives.
            try session.writer.writeAll(session.s.script.starttls);
            try session.writer.writeAll("\r\n");
            if (session.s.script.starttls_trailer) |trailer| try session.writer.writeAll(trailer);
            try session.writer.flush();

            if (std.mem.startsWith(u8, session.s.script.starttls, "2")) {
                const hold: std.Io.Timeout = .{
                    .duration = .{ .raw = .fromSeconds(60), .clock = .awake },
                };
                hold.sleep(testing.io) catch {};
                return;
            }
        } else if (eq(verb, "QUIT")) {
            try session.line(session.s.script.quit);
            return;
        } else {
            try session.line(session.s.script.unknown);
        }
    }
}

fn eq(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn log(s: *Server, command: []const u8) !void {
    if (s.log_len != 0) {
        if (s.log_len == s.log_storage.len) return;
        s.log_storage[s.log_len] = '\n';
        s.log_len += 1;
    }
    const n = @min(s.log_storage.len - s.log_len, command.len);
    @memcpy(s.log_storage[s.log_len..][0..n], command[0..n]);
    s.log_len += n;
}

/// Adds one line of the message, with a `CRLF` after it, so `body` gives
/// back what the author wrote.
fn appendBody(s: *Server, text: []const u8) !void {
    const room = s.body_storage.len - s.body_len;
    const n = @min(room, text.len);
    @memcpy(s.body_storage[s.body_len..][0..n], text[0..n]);
    s.body_len += n;
    if (s.body_storage.len - s.body_len >= 2) {
        s.body_storage[s.body_len] = '\r';
        s.body_storage[s.body_len + 1] = '\n';
        s.body_len += 2;
    }
}

test "the fixture runs a whole send and gives the message back unstuffed" {
    var server: Server = undefined;
    try server.start(.{});
    defer server.stop();

    var address = try std.Io.net.IpAddress.parse("127.0.0.1", server.port());
    const stream = try address.connect(testing.io, .{ .mode = .stream });
    defer stream.close(testing.io);

    var read_buffer: [4096]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    var write_buffer: [1024]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);

    const wire = struct {
        fn read(r: *std.Io.Reader) ![]const u8 {
            return std.mem.trimEnd(u8, try r.takeDelimiterInclusive('\n'), "\r\n");
        }
        fn send(w: *std.Io.Writer, text: []const u8) !void {
            try w.writeAll(text);
            try w.flush();
        }
    };

    try testing.expectEqualStrings("220 fixture ESMTP ready", try wire.read(&reader.interface));
    try wire.send(&writer.interface, "EHLO mail.example.com\r\n");
    try testing.expectEqualStrings("250-fixture", try wire.read(&reader.interface));
    try testing.expectEqualStrings("250-SIZE 1000000", try wire.read(&reader.interface));
    try testing.expectEqualStrings("250 STARTTLS", try wire.read(&reader.interface));

    try wire.send(&writer.interface, "MAIL FROM:<a@b.example>\r\n");
    try testing.expectEqualStrings("250 sender ok", try wire.read(&reader.interface));
    try wire.send(&writer.interface, "RCPT TO:<c@d.example>\r\n");
    try testing.expectEqualStrings("250 recipient ok", try wire.read(&reader.interface));
    try wire.send(&writer.interface, "DATA\r\n");
    try testing.expectEqualStrings("354 go ahead", try wire.read(&reader.interface));

    // The stuffed form goes out, and the fixture gives back the author's
    // own text.
    try wire.send(&writer.interface, "line one\r\n..\r\nline two\r\n.\r\n");
    try testing.expectEqualStrings("250 message accepted", try wire.read(&reader.interface));

    try wire.send(&writer.interface, "QUIT\r\n");
    try testing.expectEqualStrings("221 bye", try wire.read(&reader.interface));

    server.wait();
    try testing.expectEqualStrings(
        "EHLO mail.example.com\nMAIL FROM:<a@b.example>\nRCPT TO:<c@d.example>\nDATA\nQUIT",
        server.commands(),
    );
    try testing.expectEqualStrings("line one\r\n.\r\nline two\r\n", server.body());
    try testing.expectEqual(@as(usize, 1), server.connections());
}

test "an unstuffed period line ends the phase, and the rest becomes commands" {
    // **This is what makes the dot-stuffing test real.** The fixture obeys
    // RFC 5321 section 4.1.1.4, so a client that did not stuff would see
    // exactly this: the message cut short, and the rest of it in the
    // command log.
    var server: Server = undefined;
    try server.start(.{});
    defer server.stop();

    var address = try std.Io.net.IpAddress.parse("127.0.0.1", server.port());
    const stream = try address.connect(testing.io, .{ .mode = .stream });
    defer stream.close(testing.io);

    var read_buffer: [4096]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    var write_buffer: [1024]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);

    const send = struct {
        fn all(w: *std.Io.Writer, text: []const u8) !void {
            try w.writeAll(text);
            try w.flush();
        }
    };
    const read = struct {
        fn line(r: *std.Io.Reader) ![]const u8 {
            return std.mem.trimEnd(u8, try r.takeDelimiterInclusive('\n'), "\r\n");
        }
    };

    _ = try read.line(&reader.interface);
    try send.all(&writer.interface, "DATA\r\n");
    _ = try read.line(&reader.interface);

    // The body carries a lone period, unstuffed. Everything after it is a
    // command as far as this server is concerned.
    try send.all(&writer.interface, "line one\r\n.\r\nRCPT TO:<evil@x>\r\nQUIT\r\n");
    _ = try read.line(&reader.interface); // 250 for the short message
    _ = try read.line(&reader.interface); // 250 for the forged RCPT
    _ = try read.line(&reader.interface); // 221 for the QUIT

    server.wait();
    try testing.expectEqualStrings("DATA\nRCPT TO:<evil@x>\nQUIT", server.commands());
    try testing.expectEqualStrings("line one\r\n", server.body());
}
