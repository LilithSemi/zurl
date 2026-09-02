//! Running one blocking call against a deadline.
//!
//! **A bound belongs where the wait is, and there is one of each here.**
//! `zurl_net.Connection` keeps no clock, and `tcp.zig` bounds the connect
//! and nothing after it. So every caller that opens a connection and then
//! reads from it has two waits that can run forever, and every caller was
//! writing its own answer to both. `h1` wrote one for the setup and none
//! for the read. `dict` and `gopher` wrote neither. This file holds the two
//! answers once, so a protocol package added later gets both by calling
//! them, and not by remembering to write them again.
//!
//! Each function races the work against `std.Io.Timeout` through
//! `std.Io.Select`, the same shape `tcp.dial` already uses. A build with no
//! concurrency cannot watch a clock while the work runs, so it refuses the
//! call by name. A dropped bound is worse than a named refusal.
//!
//! `readLine` is the third answer, and it is the line framing the
//! architecture puts in this package. A command and reply protocol reads
//! its answers as lines, and each one needs the same two bounds: how long
//! one line may be, and how long the peer may write nothing. The grammar
//! over the line stays in the protocol package that owns it.

const std = @import("std");

const Connection = @import("Connection.zig");
const errors = @import("errors.zig");
const tcp = @import("tcp.zig");

/// What one connection needs to come up.
pub const Setup = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    host: tcp.Host,
    port: u16,
    /// How much room the connection keeps for bytes read and not taken.
    read_buffer_len: usize,
    /// Null for a plain hop.
    tls: ?Connection.Tls = null,
    /// Where the dial records a `TCP_NODELAY` that did not take. Null
    /// throws the fault away.
    ///
    /// A pointer, and not a returned value, because the setup runs as a
    /// raced task and a task that loses the race returns nothing.
    no_delay_error: ?*?tcp.NoDelayError = null,
    /// Whether to turn Nagle's algorithm off. False is `--no-tcp-nodelay`.
    no_delay: bool = true,
    /// A step the protocol runs on the open stream, before the handshake.
    /// Null for a connection that needs none, which is every connection
    /// but an explicit TLS upgrade.
    upgrade: ?Upgrade = null,
};

/// A step a protocol runs on the open stream, between the dial and the
/// TLS handshake.
///
/// **This exists so an explicit TLS upgrade shares the connect
/// deadline.** RFC 4217 puts a command and a reply between the dial and
/// the handshake: FTP sends `AUTH TLS` and reads a `234` on the plain
/// stream, and only then starts TLS. A caller that ran that dialogue
/// itself, and called `setup` after it, would leave the dialogue and the
/// handshake with no bound at all, and a peer that answered nothing would
/// hold the transfer forever. Running it inside the raced task puts all
/// three under one `--connect-timeout`, which is the property this file's
/// `setup` already argues for.
///
/// `run` returns false for a step that did not finish. It records its own
/// reason where the caller can read it, because a task that loses the race
/// returns nothing at all, which is the same rule `no_delay_error`
/// follows.
pub const Upgrade = struct {
    /// Passed back to `run`.
    ctx: *anyopaque,
    /// Runs on the open stream. False stops the setup with
    /// `error.UpgradeFailed`, and no handshake starts.
    ///
    /// **The stream is plaintext while this runs.** A step must send no
    /// credential and read nothing it will trust, because nothing protects
    /// either yet.
    run: *const fn (ctx: *anyopaque, io: std.Io, stream: std.Io.net.Stream) bool,
};

/// Brings `c` up against the peer, and stops waiting after `timeout`.
///
/// `c` is initialized only when this returns without an error. On a fault
/// this closes the socket itself, because `Connection.init` takes the
/// socket only when it succeeds.
///
/// **The dial and the handshake share one deadline.** curl's
/// `--connect-timeout` covers both, so the race must run one task that does
/// both. A dial raced on its own, with the handshake after it, leaves a
/// stalled handshake with no bound at all, and no test sees the difference
/// because a handshake against a peer that answers nothing looks the same
/// either way until it never ends. `gophers` had exactly that shape.
pub fn setup(
    c: *Connection,
    io: std.Io,
    timeout: std.Io.Timeout,
    s: Setup,
) errors.SetupError!void {
    switch (timeout) {
        // No bound was asked for, so no second task is needed. This is
        // also the path a build with no concurrency always takes, which is
        // why such a build still opens connections.
        .none => return setupTask(c, s),
        else => {},
    }

    var results: [2]SetupRace = undefined;
    var race: std.Io.Select(SetupRace) = .init(io, &results);

    race.concurrent(.setup, setupTask, .{ c, s }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => return error.ConnectTimeoutUnsupported,
    };
    race.concurrent(.deadline, deadlineTask, .{ io, timeout }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            endSetup(c, &race);
            return error.ConnectTimeoutUnsupported;
        },
    };

    const first = race.await() catch |err| switch (err) {
        error.Canceled => {
            endSetup(c, &race);
            return error.Canceled;
        },
    };

    switch (first) {
        .setup => |result| {
            endSetup(c, &race);
            return result;
        },
        .deadline => |slept| {
            endSetup(c, &race);
            slept catch |err| switch (err) {
                error.Canceled => return error.Canceled,
            };
            return error.OperationTimedOut;
        },
    }
}

/// Dials the peer, runs the protocol's own step when it has one, and, for
/// a hop with TLS, completes the handshake.
///
/// The dial takes no bound of its own. The race outside is the bound, and a
/// second one inside would refuse the request in a build with no
/// concurrency even where the caller asked for no bound at all.
///
/// **All three steps run in this one task, so all three share the one
/// deadline.** See `Setup.upgrade` for why the middle one is here and not
/// at the caller.
fn setupTask(c: *Connection, s: Setup) errors.SetupError!void {
    const stream = try tcp.dial(s.io, s.host, s.port, .{
        .no_delay_error = s.no_delay_error,
        .no_delay = s.no_delay,
    });
    errdefer stream.close(s.io);
    if (s.upgrade) |step| {
        if (!step.run(step.ctx, s.io, stream)) return error.UpgradeFailed;
    }
    try c.init(s.allocator, s.io, stream, .{
        .read_buffer_len = s.read_buffer_len,
        .tls = s.tls,
    });
}

const SetupRace = union(enum) {
    setup: errors.SetupError!void,
    deadline: std.Io.Cancelable!void,
};

/// Ends `race` and closes a connection that came up after the caller
/// stopped waiting for one.
///
/// `std.Io.Select.cancel` waits for every task, so a setup that finished at
/// the deadline is still reported here, and it owns a socket. Closing it is
/// the only way that descriptor goes back.
fn endSetup(c: *Connection, race: *std.Io.Select(SetupRace)) void {
    while (race.cancel()) |result| switch (result) {
        .setup => |done| if (done) |_| c.deinit() else |_| {},
        .deadline => {},
    };
}

/// The wait one read may take, from curl's `--speed-limit` and
/// `--speed-time` and the calling package's own ceiling.
///
/// **A flag narrows a package bound and never widens it.** `--speed-time`
/// says how long a transfer may make no progress, and `ceiling_s` says how
/// long this package waits when nobody asked. The answer is the lower of
/// the two.
///
/// A `--speed-limit` of zero, or a `--speed-time` of zero, turns curl's own
/// watchdog off. It does not turn this bound off: a read with no bound is a
/// process a peer can hold forever, and IronStyle asks for a bound on every
/// wait. The package ceiling stands instead.
///
/// One function, so a protocol package added later reads the two flags the
/// same way this one does.
pub fn stallTimeout(low_speed_limit: u64, low_speed_time_s: u32, ceiling_s: u32) std.Io.Timeout {
    const seconds: u32 = if (low_speed_limit == 0 or low_speed_time_s == 0)
        ceiling_s
    else
        @min(low_speed_time_s, ceiling_s);
    return .{ .duration = .{ .raw = .fromSeconds(seconds), .clock = .awake } };
}

/// Every fault `readLine` can report.
///
/// `LineTooLong` is the one name that is not in `ReadError`. It says the
/// peer wrote a line longer than the caller's buffer and never a line
/// ending, which is a bound the caller keeps and not a fault on the wire.
/// `EndOfStream` is here too: a line-framed protocol reads a reply that the
/// peer must finish, so a close in the middle of one is a fault, where the
/// same close ends a `readToEnd` answer.
pub const LineError = ReadError || error{ EndOfStream, LineTooLong };

/// Reads one line from `r` into `out`, and stops waiting after `stall` with
/// no byte arriving.
///
/// **This is the line framing that a command and reply protocol needs.**
/// FTP, SMTP, IMAP, and POP3 all read a reply as lines, and each one bounds
/// the same two things: how long one line may be, and how long the peer may
/// say nothing. The grammar above the line belongs to the protocol package.
/// The two bounds belong here, so a package added later gets both by
/// calling this and not by writing them again.
///
/// Returns the line with its ending taken off, so a `CRLF` ending and a
/// bare `LF` ending both give the same text. The result points into `out`.
///
/// `out.len` is the bound on one line. A peer that writes `out.len` bytes
/// with no ending in them is `error.LineTooLong`, and the bytes it already
/// wrote are consumed: the caller cannot resynchronise on a line it never
/// saw the end of, so the only safe answer is to end the session.
///
/// A line of exactly `out.len` bytes with its ending inside them is read.
/// The ending counts against the bound, because the bound is on the bytes
/// this reads and not on the text it returns.
pub fn readLine(
    r: *std.Io.Reader,
    io: std.Io,
    out: []u8,
    stall: std.Io.Timeout,
) LineError![]u8 {
    var at: usize = 0;
    while (true) {
        const held = r.buffered();
        if (held.len == 0) {
            try fill(r, io, stall);
            continue;
        }

        const room = out.len - at;
        if (std.mem.indexOfScalar(u8, held, '\n')) |i| {
            const take = i + 1;
            if (take > room) return error.LineTooLong;
            @memcpy(out[at..][0..take], held[0..take]);
            at += take;
            r.toss(take);
            return stripLineEnding(out[0..at]);
        }

        // No ending in what is held, so every byte of it belongs to this
        // line. A held run longer than the room left cannot fit whatever
        // is still to come either.
        if (held.len >= room) return error.LineTooLong;
        @memcpy(out[at..][0..held.len], held);
        at += held.len;
        r.toss(held.len);
    }
}

/// Every fault `readExact` can report.
pub const ExactError = ReadError || error{EndOfStream};

/// Fills `out` from `r`, and stops waiting after `stall` with no byte
/// arriving.
///
/// **This is what a counted answer needs, and IMAP is the protocol that
/// has one.** RFC 3501 section 4.3 writes a string as `{n}<CRLF>` followed
/// by exactly `n` octets, and those octets may hold any byte at all,
/// including a `CRLF`. A reader that read them as lines would read a
/// message body as a run of answers.
///
/// `out.len` is the whole bound this keeps. The caller decides how large
/// that is, and a caller reading a counted answer must check the count
/// against its own bound **before** it makes the buffer. A peer that
/// closes before `out` is full is `error.EndOfStream`, and no partial
/// count is reported: a caller cannot tell where the rest of the answer
/// would have ended, so the only safe answer is to end the session.
pub fn readExact(
    r: *std.Io.Reader,
    io: std.Io,
    out: []u8,
    stall: std.Io.Timeout,
) ExactError!void {
    var at: usize = 0;
    while (at < out.len) {
        const held = r.buffered();
        if (held.len == 0) {
            try fill(r, io, stall);
            continue;
        }
        const take = @min(held.len, out.len - at);
        @memcpy(out[at..][0..take], held[0..take]);
        at += take;
        r.toss(take);
    }
}

/// Takes the line ending off `line`.
///
/// A `CRLF` and a bare `LF` both go, and a bare `CR` in the middle stays.
/// RFC 959 and its neighbours write `CRLF`, and a server that writes `LF`
/// alone is common enough that curl reads both.
fn stripLineEnding(line: []u8) []u8 {
    var end = line.len;
    if (end > 0 and line[end - 1] == '\n') end -= 1;
    if (end > 0 and line[end - 1] == '\r') end -= 1;
    return line[0..end];
}

/// Every fault `readToEnd` can report.
pub const ReadError = error{
    /// The answer needs more memory than this process has.
    OutOfMemory,
    /// The answer passed `max_bytes`. No byte of it is returned.
    StreamTooLong,
    /// The connection failed. `Connection.readError` names the cause.
    ReadFailed,
    /// The peer sent no byte for `stall`. A half open socket and a peer
    /// that stopped writing both land here.
    OperationTimedOut,
    /// The caller asked for a stall bound, and this build has no
    /// concurrency, so nothing can watch the clock while the read runs.
    ///
    /// The read refuses instead of dropping the bound, for the reason
    /// `tcp.DialError.ConnectTimeoutUnsupported` gives.
    ReadTimeoutUnsupported,
    /// Something outside the read stopped it.
    Canceled,
};

/// Reads `c` until the peer closes, and stops waiting after `stall` with no
/// byte arriving.
///
/// The answer belongs to the caller, which must free it with `gpa`.
///
/// **`stall` bounds one wait and never the whole transfer.** A transfer
/// that keeps making progress runs for as long as it needs, which is what a
/// download of a large file does. A transfer that stops making progress
/// ends after `stall`. That is the rule curl's `--speed-time` describes, and
/// it is the one bound a protocol whose answer ends only when the peer
/// closes can keep.
///
/// **`max_bytes` counts the answer and never one byte more.** An answer of
/// exactly `max_bytes` is returned. An answer of `max_bytes + 1` is
/// `error.StreamTooLong`, and no byte of it reaches the caller.
pub fn readToEnd(
    c: *Connection,
    io: std.Io,
    gpa: std.mem.Allocator,
    max_bytes: u64,
    stall: std.Io.Timeout,
) ReadError![]u8 {
    var collected: std.ArrayList(u8) = .empty;
    errdefer collected.deinit(gpa);

    const r = c.reader();
    while (true) {
        // Whatever is buffered already needs no wait at all, so it is
        // taken before the clock starts on the next read.
        const held = r.buffered();
        if (held.len != 0) {
            if (@as(u64, held.len) > max_bytes - collected.items.len) return error.StreamTooLong;
            collected.appendSlice(gpa, held) catch return error.OutOfMemory;
            r.toss(held.len);
            continue;
        }

        fill(r, io, stall) catch |err| switch (err) {
            // The peer closed, which is how an answer of this shape ends.
            error.EndOfStream => break,
            else => |rest| return rest,
        };
    }

    return collected.toOwnedSlice(gpa) catch error.OutOfMemory;
}

/// Every fault `waitForBytes` can report.
pub const WaitError = ReadError || error{EndOfStream};

/// Waits until at least one octet is buffered in `r`, and stops waiting
/// after `stall` with none arriving.
///
/// **This is what a protocol that must answer while it reads needs.**
/// `readToEnd` reads a whole answer and hands it back at the end, which
/// suits a protocol whose answer is one lump. A protocol that has to write
/// back part way through cannot use it: a telnet peer waits for the answer
/// to its option negotiation before it writes a login prompt, so a reader
/// that collected everything first would wait for text the peer is waiting
/// to be allowed to send.
///
/// The caller reads what arrived through `r.buffered()` and consumes it
/// with `r.toss`. **The caller keeps the size bound**, because only the
/// caller knows how much of the answer it has already taken. The two
/// bounds this keeps are the stall and nothing else.
///
/// `error.EndOfStream` says the peer closed. Whether that ends the answer
/// or breaks it is the caller's question.
pub fn waitForBytes(
    r: *std.Io.Reader,
    io: std.Io,
    stall: std.Io.Timeout,
) WaitError!void {
    if (r.buffered().len != 0) return;
    return fill(r, io, stall);
}

/// Waits for one byte to arrive, and stops waiting after `stall`.
fn fill(
    r: *std.Io.Reader,
    io: std.Io,
    stall: std.Io.Timeout,
) (ReadError || error{EndOfStream})!void {
    switch (stall) {
        .none => return fillTask(r),
        else => {},
    }

    var results: [2]FillRace = undefined;
    var race: std.Io.Select(FillRace) = .init(io, &results);

    race.concurrent(.fill, fillTask, .{r}) catch |err| switch (err) {
        error.ConcurrencyUnavailable => return error.ReadTimeoutUnsupported,
    };
    race.concurrent(.deadline, deadlineTask, .{ io, stall }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            endFill(&race);
            return error.ReadTimeoutUnsupported;
        },
    };

    const first = race.await() catch |err| switch (err) {
        error.Canceled => {
            endFill(&race);
            return error.Canceled;
        },
    };

    switch (first) {
        .fill => |result| {
            endFill(&race);
            return result;
        },
        .deadline => |slept| {
            endFill(&race);
            slept catch |err| switch (err) {
                error.Canceled => return error.Canceled,
            };
            return error.OperationTimedOut;
        },
    }
}

/// One read of at least one byte, as its own task.
fn fillTask(r: *std.Io.Reader) std.Io.Reader.Error!void {
    return r.fill(1);
}

const FillRace = union(enum) {
    fill: std.Io.Reader.Error!void,
    deadline: std.Io.Cancelable!void,
};

/// Ends `race`. A read that finished at the deadline leaves its bytes in
/// the reader's own buffer, which the next call takes, so there is nothing
/// to release here.
fn endFill(race: *std.Io.Select(FillRace)) void {
    while (race.cancel()) |result| switch (result) {
        .fill => {},
        .deadline => {},
    };
}

/// The deadline, as its own task.
fn deadlineTask(io: std.Io, timeout: std.Io.Timeout) std.Io.Cancelable!void {
    return timeout.sleep(io);
}

const testing = std.testing;

test "a stall bound of none reads to the end of the stream" {
    // The `.none` arm takes no second task, so it is the arm a build with
    // no concurrency runs. It must still read the whole answer.
    var buffer: [8]u8 = undefined;
    var source: std.Io.Reader = .fixed("hello, gopher");
    _ = &buffer;

    var collected: std.ArrayList(u8) = .empty;
    defer collected.deinit(testing.allocator);
    while (true) {
        fill(&source, testing.io, .none) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        const held = source.buffered();
        try collected.appendSlice(testing.allocator, held);
        source.toss(held.len);
    }
    try testing.expectEqualStrings("hello, gopher", collected.items);
}

test "readLine takes a CRLF ending and a bare LF ending off the same way" {
    var source: std.Io.Reader = .fixed("220 Ready\r\n331 Password\nlast\r\n");
    var line: [64]u8 = undefined;

    try testing.expectEqualStrings("220 Ready", try readLine(&source, testing.io, &line, .none));
    try testing.expectEqualStrings("331 Password", try readLine(&source, testing.io, &line, .none));
    try testing.expectEqualStrings("last", try readLine(&source, testing.io, &line, .none));
    try testing.expectError(error.EndOfStream, readLine(&source, testing.io, &line, .none));
}

test "readLine keeps an empty line and a CR inside the text" {
    var source: std.Io.Reader = .fixed("\r\na\rb\r\n");
    var line: [64]u8 = undefined;

    try testing.expectEqualStrings("", try readLine(&source, testing.io, &line, .none));
    // A CR that is not before the LF is data, not framing.
    try testing.expectEqualStrings("a\rb", try readLine(&source, testing.io, &line, .none));
}

test "a line of exactly the bound is read, and one byte past it is refused" {
    // The bound counts the bytes read, the line ending included, because
    // that is what the buffer has to hold.
    {
        var source: std.Io.Reader = .fixed("abcd\r\n");
        var line: [6]u8 = undefined;
        try testing.expectEqualStrings("abcd", try readLine(&source, testing.io, &line, .none));
    }
    {
        var source: std.Io.Reader = .fixed("abcde\r\n");
        var line: [6]u8 = undefined;
        try testing.expectError(error.LineTooLong, readLine(&source, testing.io, &line, .none));
    }
}

test "a peer that writes no line ending at all is refused and never read forever" {
    // **This is the bound that keeps a hostile server from filling memory.**
    // The peer writes and writes and never ends the line, so a reader with
    // no bound would grow until the process died.
    var storage: [4096]u8 = undefined;
    @memset(&storage, 'x');
    var source: std.Io.Reader = .fixed(&storage);
    var line: [64]u8 = undefined;
    try testing.expectError(error.LineTooLong, readLine(&source, testing.io, &line, .none));
}

test "readExact fills the buffer and never reads past it" {
    var source: std.Io.Reader = .fixed("0123456789rest of the stream\r\n");
    var out: [10]u8 = undefined;
    try readExact(&source, testing.io, &out, .none);
    try testing.expectEqualStrings("0123456789", &out);

    // The bytes after the count are still there, and they are read as
    // lines again, which is what an IMAP literal needs.
    var line: [64]u8 = undefined;
    try testing.expectEqualStrings(
        "rest of the stream",
        try readLine(&source, testing.io, &line, .none),
    );
}

test "readExact reads a count that holds a line ending, because a literal may" {
    // **This is why a counted answer cannot be read as lines.** The three
    // octets below hold a `CRLF`, and a reader that stopped at it would
    // read the rest of the message as answers to later commands.
    var source: std.Io.Reader = .fixed("a\r\nb\r\n");
    var out: [3]u8 = undefined;
    try readExact(&source, testing.io, &out, .none);
    try testing.expectEqualStrings("a\r\n", &out);

    var line: [64]u8 = undefined;
    try testing.expectEqualStrings("b", try readLine(&source, testing.io, &line, .none));
}

test "readExact reports a peer that closes before the count is filled" {
    var source: std.Io.Reader = .fixed("012");
    var out: [10]u8 = undefined;
    try testing.expectError(error.EndOfStream, readExact(&source, testing.io, &out, .none));
}

test "readExact of nothing reads nothing and asks the peer for nothing" {
    var source: std.Io.Reader = .fixed("");
    var out: [0]u8 = undefined;
    try readExact(&source, testing.io, &out, .none);
}

test "readLine joins a line the peer wrote in pieces" {
    // A socket hands a reader whatever arrived, so one line can need
    // several fills. The bound counts the whole line and not one piece.
    const Pieces = struct {
        parts: []const []const u8,
        at: usize,
        reader: std.Io.Reader,

        fn stream(io_r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
            _ = limit;
            const self: *@This() = @alignCast(@fieldParentPtr("reader", io_r));
            if (self.at == self.parts.len) return error.EndOfStream;
            const part = self.parts[self.at];
            self.at += 1;
            try w.writeAll(part);
            return part.len;
        }
    };

    var buffer: [64]u8 = undefined;
    var pieces: Pieces = .{
        .parts = &.{ "227 Entering ", "Passive Mode ", "(127,0,0,1,4,1)\r\nnext\r\n" },
        .at = 0,
        .reader = .{ .vtable = &.{ .stream = Pieces.stream }, .buffer = &buffer, .seek = 0, .end = 0 },
    };

    var line: [128]u8 = undefined;
    try testing.expectEqualStrings(
        "227 Entering Passive Mode (127,0,0,1,4,1)",
        try readLine(&pieces.reader, testing.io, &line, .none),
    );
    try testing.expectEqualStrings("next", try readLine(&pieces.reader, testing.io, &line, .none));
}
