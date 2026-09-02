//! A loopback RFC 959 server for the tests of this package.
//!
//! This is a test fixture, not a product. It speaks enough of the control
//! dialogue to run a login, a passive data connection, and a download or a
//! listing, and it lets a test bend every answer. It validates nothing: a
//! test that pins the bytes a command carries has to see those bytes as
//! they arrived.
//!
//! **No test in this package reaches the real network.** Every one that
//! needs a peer starts one of these on 127.0.0.1 with a port the operating
//! system assigns, and the data listener it opens is on 127.0.0.1 too.
//!
//! **This fixture speaks no TLS.** A TLS session needs a certificate and a
//! key, and this repository has no fixture for either. So an `ftps` test
//! here proves what a session opens with, at the one function that
//! decides, and proves that a refused `AUTH TLS` sends no credential. It
//! cannot prove a live handshake, and this file says so rather than let a
//! reader think it does.
//!
//! `Script.pasv_address` is the field the interesting test uses: the
//! fixture listens on 127.0.0.1 and names another address in its `227`
//! answer, and the client must reach the transfer anyway. See
//! `Fetcher.dataPort`.

const std = @import("std");
const testing = std.testing;

pub const Server = @This();

/// How many bytes of the command log this keeps.
pub const log_bytes = 8192;

/// What the fixture answers, and what it sends down the data connection.
///
/// Every field has the answer a working server gives, so a test names only
/// the one it wants to bend.
pub const Script = struct {
    /// The greeting lines, in order. More than one line makes a
    /// multi-line greeting, and the fixture writes them exactly as given.
    greeting: []const []const u8 = &.{"220 Ready"},
    /// The answer to `USER`.
    user: []const u8 = "331 Password required",
    /// The answer to `PASS`.
    pass: []const u8 = "230 Logged in",
    /// The answer to `CWD`.
    cwd: []const u8 = "250 Directory changed",
    /// The answer to `TYPE`.
    type: []const u8 = "200 Type set",
    /// The answer to `SIZE`. Null answers `213` with the length of `body`.
    size: ?[]const u8 = null,
    /// The answer to `REST`.
    rest: []const u8 = "350 Restarting",
    /// The answer to `AUTH`.
    auth: []const u8 = "504 AUTH not supported by this fixture",
    /// The answer to `PBSZ`.
    pbsz: []const u8 = "200 PBSZ=0",
    /// The answer to `PROT`.
    prot: []const u8 = "200 PROT set",
    /// The answer to `QUIT`.
    quit: []const u8 = "221 Goodbye",
    /// The preliminary answer to `RETR`, `LIST`, and `NLST`.
    transfer_start: []const u8 = "150 Opening data connection",
    /// The answer after the data connection closes.
    transfer_end: []const u8 = "226 Transfer complete",
    /// A negative answer to `RETR`, `LIST`, and `NLST`. Null runs the
    /// transfer.
    transfer_refused: ?[]const u8 = null,
    /// What `RETR` sends. `REST` takes bytes off the front of it.
    body: []const u8 = "hello ftp body\n",
    /// What `LIST` sends.
    list: []const u8 = "-rw-r--r-- 1 u g 15 Jan  1 00:00 f.txt\r\ndrwxr-xr-x 2 u g 4096 Jan  1 00:00 sub\r\n",
    /// What `NLST` sends.
    nlst: []const u8 = "f.txt\r\nsub\r\n",
    /// Whether `EPSV` opens a listener. False answers `500` so the client
    /// falls back to `PASV`, which is the shape RFC 2428 asks a client to
    /// handle.
    epsv: bool = true,
    /// An answer to `PASV` written out in full, with no listener opened.
    /// A test that pins how a malformed `227` is read uses this.
    pasv_reply: ?[]const u8 = null,
    /// The four address bytes the `227` answer names. Null names
    /// 127.0.0.1, which is where the listener really is.
    ///
    /// **A test sets this to prove the address is ignored.** The listener
    /// stays on 127.0.0.1 whatever this says, so a client that dialed the
    /// address in the answer would reach nothing.
    pasv_address: ?[4]u8 = null,
    /// Whether the fixture writes the data at all, or opens the
    /// connection and closes it with nothing in it.
    send_data: bool = true,
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
/// How many control connections the fixture accepted. A test that proves
/// a url was refused before any dial asserts this is zero.
accept_count: std.atomic.Value(usize),
/// How many data connections the fixture accepted.
data_count: std.atomic.Value(usize),

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
    s.data_count = .init(0);

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
/// **This is the peer the reply bound exists for.** The connect succeeds,
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
    s.data_count = .init(0);

    s.task = testing.io.concurrent(runSilent, .{s}) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
}

/// The port the operating system assigned to the control listener.
pub fn port(s: *const Server) u16 {
    return s.server.socket.address.getPort();
}

/// How many control connections the client opened.
pub fn connections(s: *const Server) usize {
    return s.accept_count.load(.acquire);
}

/// How many data connections the client opened.
pub fn dataConnections(s: *const Server) usize {
    return s.data_count.load(.acquire);
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
///
/// The task ends when the client closes the control connection or sends
/// `QUIT`, so a test that ran a transfer to its end may call this. A test
/// whose client gave up early calls `stop` instead.
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
    /// The passive listener a `PASV` or an `EPSV` opened, or null when
    /// none is open.
    data: ?std.Io.net.Server = null,
    /// How many bytes `REST` took off the front of the next transfer.
    rest: u64 = 0,

    fn reply(session: *Session, text: []const u8) !void {
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
    defer if (session.data) |*d| d.deinit(testing.io);

    serve(&session) catch {};
    s.done.store(true, .release);
}

fn serve(session: *Session) !void {
    for (session.s.script.greeting) |line| try session.reply(line);

    while (true) {
        const line = session.reader.takeDelimiterInclusive('\n') catch return;
        const command = std.mem.trimEnd(u8, line, "\r\n");
        try log(session.s, command);

        var it = std.mem.splitScalar(u8, command, ' ');
        const verb = it.first();
        const argument = it.rest();

        if (eq(verb, "USER")) {
            try session.reply(session.s.script.user);
        } else if (eq(verb, "PASS")) {
            try session.reply(session.s.script.pass);
        } else if (eq(verb, "CWD")) {
            try session.reply(session.s.script.cwd);
        } else if (eq(verb, "TYPE")) {
            try session.reply(session.s.script.type);
        } else if (eq(verb, "AUTH")) {
            try session.reply(session.s.script.auth);
        } else if (eq(verb, "PBSZ")) {
            try session.reply(session.s.script.pbsz);
        } else if (eq(verb, "PROT")) {
            try session.reply(session.s.script.prot);
        } else if (eq(verb, "SIZE")) {
            try sizeReply(session);
        } else if (eq(verb, "REST")) {
            session.rest = std.fmt.parseInt(u64, argument, 10) catch 0;
            try session.reply(session.s.script.rest);
        } else if (eq(verb, "EPSV")) {
            try epsvReply(session);
        } else if (eq(verb, "PASV")) {
            try pasvReply(session);
        } else if (eq(verb, "RETR") or eq(verb, "LIST") or eq(verb, "NLST")) {
            try transfer(session, verb);
        } else if (eq(verb, "QUIT")) {
            try session.reply(session.s.script.quit);
            return;
        } else {
            try session.reply("500 Unknown command");
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

fn sizeReply(session: *Session) !void {
    if (session.s.script.size) |text| return session.reply(text);
    var line: [32]u8 = undefined;
    const text = try std.fmt.bufPrint(&line, "213 {d}", .{session.s.script.body.len});
    try session.reply(text);
}

fn openData(session: *Session) !u16 {
    if (session.data) |*old| old.deinit(testing.io);
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    session.data = try address.listen(testing.io, .{ .reuse_address = true });
    return session.data.?.socket.address.getPort();
}

fn epsvReply(session: *Session) !void {
    if (!session.s.script.epsv) return session.reply("500 EPSV not understood");
    const p = try openData(session);
    var line: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&line, "229 Entering Extended Passive Mode (|||{d}|)", .{p});
    try session.reply(text);
}

fn pasvReply(session: *Session) !void {
    if (session.s.script.pasv_reply) |text| return session.reply(text);
    const p = try openData(session);
    // **The listener is on 127.0.0.1 whatever this answer says.** A test
    // that names another address here proves the client ignored it,
    // because the transfer still runs.
    const address = session.s.script.pasv_address orelse [4]u8{ 127, 0, 0, 1 };
    var line: [80]u8 = undefined;
    const text = try std.fmt.bufPrint(&line, "227 Entering Passive Mode ({d},{d},{d},{d},{d},{d})", .{
        address[0], address[1], address[2], address[3], p >> 8, p & 0xff,
    });
    try session.reply(text);
}

fn transfer(session: *Session, verb: []const u8) !void {
    if (session.s.script.transfer_refused) |text| {
        session.rest = 0;
        return session.reply(text);
    }

    const whole = if (eq(verb, "RETR"))
        session.s.script.body
    else if (eq(verb, "LIST"))
        session.s.script.list
    else
        session.s.script.nlst;
    const from = @min(session.rest, whole.len);
    const payload = whole[from..];
    session.rest = 0;

    try session.reply(session.s.script.transfer_start);

    var listener = session.data orelse return session.reply("425 No data connection");
    session.data = null;
    defer listener.deinit(testing.io);

    const data = try listener.accept(testing.io);
    _ = session.s.data_count.fetchAdd(1, .release);
    if (session.s.script.send_data) {
        var buffer: [4096]u8 = undefined;
        var data_writer = std.Io.net.Stream.Writer.init(data, testing.io, &buffer);
        data_writer.interface.writeAll(payload) catch {};
        data_writer.interface.flush() catch {};
    }
    data.close(testing.io);

    try session.reply(session.s.script.transfer_end);
}

test "the fixture runs a whole download and records every command" {
    var server: Server = undefined;
    try server.start(.{ .body = "hello ftp body\n" });
    defer server.stop();

    var address = try std.Io.net.IpAddress.parse("127.0.0.1", server.port());
    const stream = try address.connect(testing.io, .{ .mode = .stream });
    defer stream.close(testing.io);

    var read_buffer: [1024]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    var write_buffer: [1024]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);

    const line = struct {
        fn read(r: *std.Io.Reader) ![]const u8 {
            return std.mem.trimEnd(u8, try r.takeDelimiterInclusive('\n'), "\r\n");
        }
        fn send(w: *std.Io.Writer, text: []const u8) !void {
            try w.writeAll(text);
            try w.writeAll("\r\n");
            try w.flush();
        }
    };

    try testing.expectEqualStrings("220 Ready", try line.read(&reader.interface));
    try line.send(&writer.interface, "USER anonymous");
    try testing.expectEqualStrings("331 Password required", try line.read(&reader.interface));
    try line.send(&writer.interface, "PASS ftp@example.com");
    try testing.expectEqualStrings("230 Logged in", try line.read(&reader.interface));

    try line.send(&writer.interface, "EPSV");
    const epsv = try line.read(&reader.interface);
    try testing.expect(std.mem.startsWith(u8, epsv, "229 "));
    const open = std.mem.lastIndexOfScalar(u8, epsv, '(').?;
    const inside = epsv[open + 4 .. std.mem.indexOfScalar(u8, epsv[open..], ')').? + open - 1];
    const data_port = try std.fmt.parseInt(u16, inside, 10);

    try line.send(&writer.interface, "RETR f.txt");
    try testing.expectEqualStrings("150 Opening data connection", try line.read(&reader.interface));

    var data_address = try std.Io.net.IpAddress.parse("127.0.0.1", data_port);
    const data = try data_address.connect(testing.io, .{ .mode = .stream });
    defer data.close(testing.io);
    var data_buffer: [1024]u8 = undefined;
    var data_reader = std.Io.net.Stream.Reader.init(data, testing.io, &data_buffer);
    const body = try data_reader.interface.allocRemaining(testing.allocator, .limited(1024));
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("hello ftp body\n", body);

    try testing.expectEqualStrings("226 Transfer complete", try line.read(&reader.interface));
    try line.send(&writer.interface, "QUIT");
    try testing.expectEqualStrings("221 Goodbye", try line.read(&reader.interface));

    server.wait();
    try testing.expectEqualStrings(
        "USER anonymous\nPASS ftp@example.com\nEPSV\nRETR f.txt\nQUIT",
        server.commands(),
    );
    try testing.expectEqual(@as(usize, 1), server.connections());
    try testing.expectEqual(@as(usize, 1), server.dataConnections());
}
