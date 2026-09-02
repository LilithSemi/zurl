//! A loopback RFC 3501 server for the tests of this package.
//!
//! This is a test fixture, not a product. It speaks enough of the dialogue
//! to run a login, a `SELECT`, a `FETCH`, and a `LIST`, and it lets a test
//! bend every answer. It validates nothing: a test that pins the bytes a
//! command carries has to see those bytes as they arrived.
//!
//! **No test in this package reaches the real network.** Every one that
//! needs a peer starts one of these on 127.0.0.1, with a port the
//! operating system assigns.
//!
//! **This fixture speaks no TLS**, for the reason `zurl_pop3.test_server`
//! gives. A `STARTTLS` test here proves that a refusal sends no
//! credential, and that a peer that accepts and then speaks no TLS is
//! bounded. It cannot prove a live handshake.
//!
//! **The fixture answers with the tag it was given.** A test that wanted a
//! server answering the wrong tag would be testing the client's own
//! `response.readLine`, which has its own table tests. What this fixture
//! adds is the literal: `Script.body` goes out as `{n}` and then exactly
//! `n` octets, so a client that read the octets as lines fails here.

const std = @import("std");
const testing = std.testing;

pub const Server = @This();

/// How many bytes of the command log this keeps.
pub const log_bytes = 8192;

/// What the fixture answers.
pub const Script = struct {
    /// The greeting line, with no tag.
    greeting: []const u8 = "* OK [CAPABILITY IMAP4rev1] fixture ready",
    /// The status word of the answer to `LOGIN`.
    login: []const u8 = "OK logged in",
    /// The status word of the answer to `SELECT`.
    select: []const u8 = "OK [READ-WRITE] selected",
    /// The untagged lines a `SELECT` writes before its tagged answer.
    select_untagged: []const []const u8 = &.{ "* 2 EXISTS", "* OK [UIDVALIDITY 1]" },
    /// The status word of the answer to `FETCH` and to `UID FETCH`.
    fetch: []const u8 = "OK fetch done",
    /// The message a `FETCH` sends, inside a literal.
    body: []const u8 = "Subject: hi\r\n\r\nbody\r\n",
    /// The status word of the answer to `LIST`.
    list: []const u8 = "OK list done",
    /// The untagged lines a `LIST` writes.
    list_untagged: []const []const u8 = &.{
        "* LIST (\\HasNoChildren) \"/\" INBOX",
        "* LIST (\\HasNoChildren) \"/\" Sent",
    },
    /// The status word of the answer to `STARTTLS`. The default refuses,
    /// because this fixture speaks no TLS.
    starttls: []const u8 = "NO STARTTLS is not available on this fixture",
    /// Bytes the fixture writes straight after its `STARTTLS` answer.
    ///
    /// **A test uses this to prove one rule**: a server that writes in the
    /// clear behind its `STARTTLS` answer has written bytes that no
    /// session protects, and the client must not carry them across the
    /// handshake.
    starttls_trailer: ?[]const u8 = null,
    /// The status word of the answer to `LOGOUT`.
    logout: []const u8 = "OK logout done",
    /// The status word of the answer to anything else.
    unknown: []const u8 = "BAD unknown command",
    /// The untagged lines a `CAPABILITY` writes.
    capability_untagged: []const []const u8 = &.{"* CAPABILITY IMAP4rev1"},
    /// The status word of the answer to `CAPABILITY`.
    capability: []const u8 = "OK capability done",
    /// The challenges a SASL exchange writes, in order, one for each `+`
    /// line before the tagged answer.
    ///
    /// **Each entry is already base64**, because a challenge reaches the
    /// wire encoded and a test that pins the bytes has to name them as
    /// they travel. The default is one empty challenge, which is what a
    /// `PLAIN` exchange with no initial response draws: RFC 3501 section
    /// 6.2.2 writes it `+ `.
    auth_challenges: []const []const u8 = &.{""},
    /// The status word of the answer that ends a SASL exchange.
    authenticate: []const u8 = "OK authenticated",
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
/// **This is the peer the read bound exists for.**
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
/// Call `wait` first for a complete list.
pub fn commands(s: *const Server) []const u8 {
    if (!s.done.load(.acquire)) return "";
    return s.log_storage[0..s.log_len];
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
    /// Holds one `+` line as it is built.
    challenge_storage: [1024]u8 = undefined,

    fn line(session: *Session, text: []const u8) !void {
        try session.writer.writeAll(text);
        try session.writer.writeAll("\r\n");
        try session.writer.flush();
    }

    /// Writes the tagged end of a command.
    fn tagged(session: *Session, tag: []const u8, text: []const u8) !void {
        try session.writer.writeAll(tag);
        try session.writer.writeAll(" ");
        try session.writer.writeAll(text);
        try session.writer.writeAll("\r\n");
        try session.writer.flush();
    }

    /// Writes a `FETCH` answer, with the message inside a literal.
    fn literal(session: *Session, body: []const u8) !void {
        try session.writer.print("* 1 FETCH (BODY[] {{{d}}}\r\n", .{body.len});
        try session.writer.writeAll(body);
        try session.writer.writeAll(")\r\n");
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
        const tag = it.first();
        const verb = it.next() orelse "";

        if (eq(verb, "LOGIN")) {
            try session.tagged(tag, session.s.script.login);
        } else if (eq(verb, "CAPABILITY")) {
            for (session.s.script.capability_untagged) |untagged| try session.line(untagged);
            try session.tagged(tag, session.s.script.capability);
        } else if (eq(verb, "AUTHENTICATE")) {
            // **Every response of the exchange reaches the command log**,
            // so a test can pin the base64 the client wrote and decode it
            // to prove which fields went out. RFC 3501 section 6.2.2: the
            // server writes `+ <challenge>` and the client answers with
            // one line of base64.
            //
            // A client that put its first message on the `AUTHENTICATE`
            // line itself, which is `--sasl-ir`, has already sent one
            // response, so the fixture writes one challenge fewer.
            var words: usize = 2;
            while (it.next()) |_| words += 1;
            const skip: usize = if (words >= 4) 1 else 0;

            // **The tag is copied before the first response is read.**
            // `tag` points into the reader's own buffer, and the next
            // read overwrites it, so a fixture that kept the slice ended
            // the exchange with the first four bytes of the client's
            // base64 in place of the tag.
            var tag_storage: [64]u8 = undefined;
            const kept_tag = tag_storage[0..@min(tag.len, tag_storage.len)];
            @memcpy(kept_tag, tag[0..kept_tag.len]);

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
            try session.tagged(kept_tag, session.s.script.authenticate);
        } else if (eq(verb, "SELECT") or eq(verb, "EXAMINE")) {
            for (session.s.script.select_untagged) |untagged| try session.line(untagged);
            try session.tagged(tag, session.s.script.select);
        } else if (eq(verb, "LIST")) {
            for (session.s.script.list_untagged) |untagged| try session.line(untagged);
            try session.tagged(tag, session.s.script.list);
        } else if (eq(verb, "FETCH") or eq(verb, "UID")) {
            if (std.mem.startsWith(u8, session.s.script.fetch, "OK")) {
                try session.literal(session.s.script.body);
            }
            try session.tagged(tag, session.s.script.fetch);
        } else if (eq(verb, "STARTTLS")) {
            // **The answer and any trailer go out in one write**, for the
            // reason `zurl_pop3.test_server` gives.
            try session.writer.writeAll(tag);
            try session.writer.writeAll(" ");
            try session.writer.writeAll(session.s.script.starttls);
            try session.writer.writeAll("\r\n");
            if (session.s.script.starttls_trailer) |text| try session.writer.writeAll(text);
            try session.writer.flush();

            // This fixture speaks no TLS, so after a positive answer it
            // says nothing more. See `zurl_pop3.test_server` for why
            // silence is the one answer that is the same every run.
            if (std.mem.startsWith(u8, session.s.script.starttls, "OK")) {
                const hold: std.Io.Timeout = .{
                    .duration = .{ .raw = .fromSeconds(60), .clock = .awake },
                };
                hold.sleep(testing.io) catch {};
                return;
            }
        } else if (eq(verb, "LOGOUT")) {
            try session.line("* BYE fixture closing");
            try session.tagged(tag, session.s.script.logout);
            return;
        } else {
            try session.tagged(tag, session.s.script.unknown);
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

test "the fixture runs a whole fetch and records every command" {
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

    try testing.expectEqualStrings(
        "* OK [CAPABILITY IMAP4rev1] fixture ready",
        try wire.read(&reader.interface),
    );
    try wire.send(&writer.interface, "A001 LOGIN alice s3cret");
    try testing.expectEqualStrings("A001 OK logged in", try wire.read(&reader.interface));

    try wire.send(&writer.interface, "A002 SELECT INBOX");
    try testing.expectEqualStrings("* 2 EXISTS", try wire.read(&reader.interface));
    try testing.expectEqualStrings("* OK [UIDVALIDITY 1]", try wire.read(&reader.interface));
    try testing.expectEqualStrings("A002 OK [READ-WRITE] selected", try wire.read(&reader.interface));

    // **The message goes out as a counted literal**, so a client that read
    // the octets as lines would fail against this fixture.
    try wire.send(&writer.interface, "A003 UID FETCH 1 BODY[]");
    try testing.expectEqualStrings("* 1 FETCH (BODY[] {21}", try wire.read(&reader.interface));
    var octets: [21]u8 = undefined;
    try reader.interface.readSliceAll(&octets);
    try testing.expectEqualStrings("Subject: hi\r\n\r\nbody\r\n", &octets);
    try testing.expectEqualStrings(")", try wire.read(&reader.interface));
    try testing.expectEqualStrings("A003 OK fetch done", try wire.read(&reader.interface));

    try wire.send(&writer.interface, "A004 LOGOUT");
    try testing.expectEqualStrings("* BYE fixture closing", try wire.read(&reader.interface));
    try testing.expectEqualStrings("A004 OK logout done", try wire.read(&reader.interface));

    server.wait();
    try testing.expectEqualStrings(
        "A001 LOGIN alice s3cret\nA002 SELECT INBOX\nA003 UID FETCH 1 BODY[]\nA004 LOGOUT",
        server.commands(),
    );
    try testing.expectEqual(@as(usize, 1), server.connections());
}
