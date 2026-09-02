//! A loopback RFC 1939 server for the tests of this package.
//!
//! This is a test fixture, not a product. It speaks enough of the dialogue
//! to run a login, a listing, and a retrieval, and it lets a test bend
//! every answer. It validates nothing: a test that pins the bytes a
//! command carries has to see those bytes as they arrived.
//!
//! **No test in this package reaches the real network.** Every one that
//! needs a peer starts one of these on 127.0.0.1, with a port the
//! operating system assigns.
//!
//! **This fixture speaks no TLS.** A TLS session needs a certificate and a
//! key, and this repository has no fixture for either. So a `pop3s` test
//! here proves what a session opens with, at the one function that
//! decides, and proves that a refused `STLS` sends no credential. It
//! cannot prove a live handshake, and this file says so rather than let a
//! reader think it does.
//!
//! **The fixture adds the dot-stuffing and the client takes it off.**
//! `Script.body` is the message as a user should receive it, and `send`
//! doubles a leading period on the way out. A test that reads the same
//! bytes back has proved the round trip, which is what RFC 1939 section 3
//! asks of both ends.

const std = @import("std");
const testing = std.testing;

pub const Server = @This();

/// How many bytes of the command log this keeps.
pub const log_bytes = 8192;

/// What the fixture answers.
///
/// Every field has the answer a working server gives, so a test names only
/// the one it wants to bend.
pub const Script = struct {
    /// The greeting line. A `<...>` at the end of it offers APOP.
    greeting: []const u8 = "+OK POP3 fixture ready",
    /// The answer to `USER`.
    user: []const u8 = "+OK user accepted",
    /// The answer to `PASS`.
    pass: []const u8 = "+OK logged in",
    /// The answer to `APOP`.
    apop: []const u8 = "+OK logged in",
    /// The answer to `STAT`.
    stat: []const u8 = "+OK 2 320",
    /// The answer to `DELE`.
    dele: []const u8 = "+OK marked for deletion",
    /// The answer to `NOOP` and to any other single-line command.
    unknown: []const u8 = "-ERR unknown command",
    /// The answer to `STLS`. The default refuses, because this fixture
    /// speaks no TLS.
    stls: []const u8 = "-ERR STLS not supported by this fixture",
    /// Bytes the fixture writes straight after its `STLS` answer.
    ///
    /// **A test uses this to prove one rule**: a server that writes in the
    /// clear behind its `STLS` answer has written bytes that no session
    /// protects, and the client must not carry them across the handshake.
    stls_trailer: ?[]const u8 = null,
    /// The answer to `QUIT`.
    quit: []const u8 = "+OK bye",
    /// The status line of a `RETR`.
    retr: []const u8 = "+OK 34 octets",
    /// A negative answer to `RETR`. Null runs the retrieval.
    retr_refused: ?[]const u8 = null,
    /// The message a `RETR` sends, **as a user should receive it**. The
    /// fixture adds the dot-stuffing itself.
    body: []const u8 = "Subject: hi\r\n\r\nbody line\r\n.hidden\r\n",
    /// The status line of a `LIST` with no argument.
    list: []const u8 = "+OK 2 messages",
    /// The body a `LIST` with no argument sends.
    list_body: []const u8 = "1 200\r\n2 120\r\n",
    /// The answer to a `LIST` with an argument.
    list_one: []const u8 = "+OK 1 200",
    /// The body of a `CAPA` answer, or null for a server that does not
    /// know the command.
    ///
    /// **Null is the default, and it is what a server from before RFC
    /// 2449 answers.** Every test written before SASL runs against that
    /// server and logs in with `USER` and `PASS`, which is why none of
    /// them changed beyond the `CAPA` line in the command log.
    capa: ?[]const u8 = null,
    /// The challenges a SASL exchange writes, in order, one for each `+`
    /// line before the answer that ends it.
    ///
    /// **Each entry is already base64.** The default is one empty
    /// challenge, which is what a `PLAIN` exchange with no initial
    /// response draws: RFC 5034 writes it `+ `.
    auth_challenges: []const []const u8 = &.{""},
    /// The answer that ends a SASL exchange.
    auth_reply: []const u8 = "+OK authenticated",
};

server: std.Io.net.Server,
task: std.Io.Future(void),
script: Script,
/// Every command line the client wrote, one for each line, joined with
/// `\n`. Read through `commands` after `wait`.
log_storage: [log_bytes]u8,
log_len: usize,
/// Set when the task has finished writing `log_storage`.
done: std.atomic.Value(bool),
/// How many connections the fixture accepted. A test that proves a url was
/// refused before any dial asserts this is zero.
accept_count: std.atomic.Value(usize),

/// Starts listening on loopback and starts a task that runs one session.
///
/// Initializes `s` in place, so the task can hold `&s.server` for its
/// whole life.
///
/// Returns `error.SkipZigTest` in a build with no concurrency at all. The
/// server and its client cannot both make progress on one task.
///
/// `s` and every slice inside `script` must outlive the server.
pub fn start(s: *Server, script: Script) !void {
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    s.server = try address.listen(testing.io, .{ .reuse_address = true });
    errdefer s.server.deinit(testing.io);

    s.script = script;
    s.log_len = 0;
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
///
/// **This is the peer the read bound exists for.** The connect succeeds,
/// so the dial is over, and then the greeting never arrives. Without a
/// bound the transfer waits for it forever.
pub fn startSilent(s: *Server) !void {
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    s.server = try address.listen(testing.io, .{ .reuse_address = true });
    errdefer s.server.deinit(testing.io);

    s.script = .{};
    s.log_len = 0;
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
/// Call `wait` first for a complete list. Without it this can read a log
/// the task has not finished writing, which is a race that passes on an
/// idle machine and fails on a loaded one.
pub fn commands(s: *const Server) []const u8 {
    if (!s.done.load(.acquire)) return "";
    return s.log_storage[0..s.log_len];
}

/// Waits for the session to finish.
pub fn wait(s: *Server) void {
    s.task.await(testing.io);
}

/// Stops the server task and releases the listening socket. Every test
/// that calls `start` must call this, normally through `defer`.
///
/// The task is canceled and not joined. A test that opens no connection
/// leaves `run` inside `accept`, where a plain join waits forever.
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

/// The state one session holds.
const Session = struct {
    s: *Server,
    writer: *std.Io.Writer,
    reader: *std.Io.Reader,
    /// Holds one `+` line as it is built.
    challenge_storage: [1024]u8 = undefined,

    fn line(session: *Session, text: []const u8) !void {
        try session.writer.writeAll(text);
        try session.writer.writeAll("\r\n");
        try session.writer.flush();
    }

    /// Writes a multi-line body, with the dot-stuffing RFC 1939 asks for,
    /// and the period line that ends it.
    fn body(session: *Session, text: []const u8) !void {
        var it = std.mem.splitSequence(u8, text, "\r\n");
        while (it.next()) |one| {
            // The split leaves an empty piece after the last `CRLF`, and
            // that piece is not a line.
            if (it.index == null and one.len == 0) break;
            if (one.len != 0 and one[0] == '.') try session.writer.writeAll(".");
            try session.writer.writeAll(one);
            try session.writer.writeAll("\r\n");
        }
        try session.writer.writeAll(".\r\n");
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
        const command = std.mem.trimEnd(u8, raw, "\r\n");
        try log(session.s, command);

        var it = std.mem.splitScalar(u8, command, ' ');
        const verb = it.first();
        const argument = it.rest();

        if (eq(verb, "USER")) {
            try session.line(session.s.script.user);
        } else if (eq(verb, "PASS")) {
            try session.line(session.s.script.pass);
        } else if (eq(verb, "APOP")) {
            try session.line(session.s.script.apop);
        } else if (eq(verb, "STAT")) {
            try session.line(session.s.script.stat);
        } else if (eq(verb, "DELE")) {
            try session.line(session.s.script.dele);
        } else if (eq(verb, "STLS")) {
            // **The answer and any trailer go out in one write.** A test
            // that proves the client refuses cleartext written behind the
            // answer needs both to reach the client together, and two
            // flushes are two segments.
            try session.writer.writeAll(session.s.script.stls);
            try session.writer.writeAll("\r\n");
            if (session.s.script.stls_trailer) |text| try session.writer.writeAll(text);
            try session.writer.flush();

            // **This fixture speaks no TLS**, so after a positive answer
            // it says nothing more. Reading a ClientHello as command lines
            // would answer with bytes no TLS client can read, and which
            // fault the client then reported would depend on whether the
            // hello happened to hold a line ending. Silence is the one
            // answer that is the same every run, and the bound the client
            // keeps on the handshake is what the test measures.
            if (std.mem.startsWith(u8, session.s.script.stls, "+OK")) {
                const hold: std.Io.Timeout = .{
                    .duration = .{ .raw = .fromSeconds(60), .clock = .awake },
                };
                hold.sleep(testing.io) catch {};
                return;
            }
        } else if (eq(verb, "CAPA")) {
            if (session.s.script.capa) |body| {
                try session.line("+OK capability list follows");
                try session.body(body);
            } else {
                // What a server from before RFC 2449 answers, and the
                // default: the login then falls back to `USER` and
                // `PASS`.
                try session.line(session.s.script.unknown);
            }
        } else if (eq(verb, "AUTH")) {
            // **Every response of the exchange reaches the command log**,
            // so a test can pin the base64 the client wrote and decode it
            // to prove which fields went out. RFC 5034 section 4: the
            // server writes `+ <challenge>` and the client answers with
            // one line of base64.
            //
            // A client that put its first message on the `AUTH` line
            // itself, which is `--sasl-ir`, has already sent one
            // response, so the fixture writes one challenge fewer.
            var words: usize = 1;
            while (it.next()) |_| words += 1;
            const skip: usize = if (words >= 3) 1 else 0;
            const challenges = session.s.script.auth_challenges;
            var i: usize = @min(skip, challenges.len);
            while (i < challenges.len) : (i += 1) {
                try session.line(if (challenges[i].len == 0)
                    "+ "
                else
                    try std.fmt.bufPrint(&session.challenge_storage, "+ {s}", .{challenges[i]}));
                const answer_raw = session.reader.takeDelimiterInclusive('\n') catch return;
                try log(session.s, std.mem.trimEnd(u8, answer_raw, "\r\n"));
            }
            try session.line(session.s.script.auth_reply);
        } else if (eq(verb, "RETR")) {
            if (session.s.script.retr_refused) |text| {
                try session.line(text);
            } else {
                try session.line(session.s.script.retr);
                try session.body(session.s.script.body);
            }
        } else if (eq(verb, "LIST")) {
            if (argument.len == 0) {
                try session.line(session.s.script.list);
                try session.body(session.s.script.list_body);
            } else {
                try session.line(session.s.script.list_one);
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

test "the fixture runs a whole retrieval and records every command" {
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
            try w.writeAll("\r\n");
            try w.flush();
        }
    };

    try testing.expectEqualStrings("+OK POP3 fixture ready", try wire.read(&reader.interface));
    try wire.send(&writer.interface, "USER alice");
    try testing.expectEqualStrings("+OK user accepted", try wire.read(&reader.interface));
    try wire.send(&writer.interface, "PASS s3cret");
    try testing.expectEqualStrings("+OK logged in", try wire.read(&reader.interface));

    try wire.send(&writer.interface, "RETR 1");
    try testing.expectEqualStrings("+OK 34 octets", try wire.read(&reader.interface));

    // **The fixture stuffs the leading period and the client takes it
    // off.** The line `.hidden` arrives as `..hidden`, and the body ends
    // at the one line that holds a single period.
    try testing.expectEqualStrings("Subject: hi", try wire.read(&reader.interface));
    try testing.expectEqualStrings("", try wire.read(&reader.interface));
    try testing.expectEqualStrings("body line", try wire.read(&reader.interface));
    try testing.expectEqualStrings("..hidden", try wire.read(&reader.interface));
    try testing.expectEqualStrings(".", try wire.read(&reader.interface));

    try wire.send(&writer.interface, "QUIT");
    try testing.expectEqualStrings("+OK bye", try wire.read(&reader.interface));

    server.wait();
    try testing.expectEqualStrings(
        "USER alice\nPASS s3cret\nRETR 1\nQUIT",
        server.commands(),
    );
    try testing.expectEqual(@as(usize, 1), server.connections());
}
