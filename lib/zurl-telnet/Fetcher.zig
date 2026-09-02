//! Runs one `telnet://` transfer: the dial, whatever the caller sends, and
//! the answer.
//!
//! **This is a relay and not a request and reply.** RFC 854 has no
//! request, no status, and no length: the two ends write to each other
//! until one closes. So a transfer here writes the body the caller named,
//! then reads until the peer closes, and the octets that come back are the
//! answer.
//!
//! **The escaping is what makes it safe.** Every 255 in outgoing data is
//! doubled, or the peer reads the octet after it as a command. See
//! `iac.escape`, which is the one writer of outgoing data. Incoming
//! commands are answered where RFC 854 asks for an answer and reach the
//! output nowhere at all.
//!
//! **A `Fetcher` must not move once `open` has run.** The body reader it
//! hands back points into this value.
//!
//! **The answer is bounded.** RFC 854 puts no length on the wire, so a
//! hostile server can write forever. `Options.max_response_bytes` is the
//! bound on the data octets, and a peer past it gets
//! `error.FileSizeExceeded`, exit 63.
//!
//! **The commands are bounded separately.** A command octet becomes no
//! data octet, so `Options.max_response_bytes` never counts one. A peer
//! that writes negotiation forever is stopped by `iac.max_answers`, and a
//! peer that writes commands drawing no answer at all, such as a
//! subnegotiation that never ends, is stopped by `iac.max_discarded`. Both
//! are `error.WeirdServerReply`, exit 8.
//!
//! What this does not do: no TLS, because curl carries no `telnets` scheme
//! and RFC 854 names none. No `-t`/`--telnet-option`, so `TERMINAL-TYPE`,
//! `XDISPLOC`, and `NEW-ENVIRON` are refused where curl with a `-t` would
//! accept one. No terminal: the answer goes to the output as octets, and
//! zurl runs no line discipline over it.
//!
//! **Standard input is not read on its own.** curl relays standard input
//! to a telnet peer with no flag at all, measured. zurl sends what
//! `Options.body` names, which the command line fills from `-d` and from
//! `-T`, so `-T -` is the flag that relays standard input.
//!
//! This file imports `zurl-core` and `zurl-net`. It does not import
//! `zurl`, and it never will. See `protocol`.

const Fetcher = @This();

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_net = @import("zurl-net");

const iac = @import("iac.zig");

const Io = std.Io;
const Error = zurl_core.Error;
const Diagnostics = zurl_core.Diagnostics;

/// The scheme this package handles.
pub const scheme = "telnet";

/// The port a url of this scheme uses when it names none.
///
/// 23, which RFC 854 assigns and which curl 8.21.0 dials for
/// `telnet://127.0.0.1`, measured: with no port in the url, curl reported
/// `Failed to connect to 127.0.0.1:23`.
pub const default_port: ?u16 = 23;

/// The status a telnet transfer reports.
///
/// Zero, because RFC 854 has no status at all. curl prints `000` for
/// `%{http_code}` on a protocol with no status of its own.
pub const status: u16 = 0;

/// How many octets of answer this package reads by default.
///
/// A telnet session has no length on the wire: the two ends write until
/// one closes. Without a bound a server that never closes holds this
/// process for as long as it likes and fills memory while it does.
///
/// 16 MiB, the same number `zurl-gopher` uses for an answer of the same
/// shape. `Options.max_response_bytes` narrows it, and `--max-filesize`
/// narrows that.
pub const default_max_response_bytes: u64 = 16 * 1024 * 1024;

/// How many octets this package sends in one transfer.
///
/// The body is read into memory and escaped whole, so the bound is on the
/// text before escaping. A body larger than this is
/// `error.FileSizeExceeded` before a socket opens.
pub const default_max_send_bytes: u64 = 16 * 1024 * 1024;

/// How much room the connection keeps for octets read and not taken yet.
pub const read_buffer_len: usize = 8192;

/// How many octets of one read this decodes at a time.
pub const chunk_bytes: usize = 4096;

/// How long one read may wait with no octet arriving.
///
/// **A telnet session ends when the peer closes, so a peer that never
/// writes and never closes holds this process forever.**
/// `--connect-timeout` covers the dial alone.
///
/// 300 seconds is curl's own `--speed-time` default, and this is the same
/// question: how long a transfer may make no progress. `--speed-time`
/// narrows it and never widens it.
pub const default_read_timeout_s: u32 = 300;

/// `default_read_timeout_s`, as a `std.Io.Timeout`.
pub const default_read_timeout: Io.Timeout = .{
    .duration = .{ .raw = .fromSeconds(default_read_timeout_s), .clock = .awake },
};

/// Where the octets this transfer sends come from.
///
/// The shape matches `zurl_http.engine.Body` field for field, because
/// `src/cli/body.zig` fills one of those from `-T` and from the `-d`
/// family alike. It is written out here because this package must build
/// with no `zurl` and no `zurl-http` in its import table.
pub const Source = struct {
    /// How many octets `read` produces in total, or null when the count is
    /// not known before the body goes out, which is what a pipe gives.
    len: ?u64,
    /// The state `read` acts on.
    ctx: *anyopaque,
    /// Fills up to `len` octets of `buffer` and returns how many it wrote.
    /// Zero says the body has ended, and a negative value says the source
    /// could not be read.
    read: *const fn (ctx: *anyopaque, buffer: [*]u8, len: usize) callconv(.c) isize,
};

/// What one transfer may ask for.
pub const Options = struct {
    /// A cap on the dial. `.none` waits for as long as the operating
    /// system does.
    connect_timeout: Io.Timeout = .none,
    /// The bound on the answer. See `default_max_response_bytes`.
    max_response_bytes: u64 = default_max_response_bytes,
    /// The bound on what this transfer sends. See
    /// `default_max_send_bytes`.
    max_send_bytes: u64 = default_max_send_bytes,
    /// How long one read may wait with no octet arriving. See
    /// `default_read_timeout_s`.
    read_timeout: Io.Timeout = default_read_timeout,
    /// Whether to turn Nagle's algorithm off on the connection. False is
    /// `--no-tcp-nodelay`.
    tcp_no_delay: bool = true,
    /// What to send, or null for a transfer that sends nothing. This is
    /// `-d` and `-T`.
    body: ?Source = null,
    /// Where a url naming one host and port dials instead. This is
    /// `--resolve` and `--connect-to`.
    ///
    /// **An entry moves the dial and nothing else.** A telnet session
    /// writes no host name to the peer and opens no TLS, so the dial is
    /// all there is to move. See `zurl_net.override`.
    connect_to: []const zurl_net.override.HostOverride = &.{},
};

allocator: std.mem.Allocator,
io: Io,
/// The answer of the transfer in play, or null when none is held.
answer: ?[]u8,
/// Reads `answer`. Valid only while `answer` holds something.
body: Io.Reader,
/// Backs the data octets of one decoded chunk.
data_storage: [chunk_bytes]u8,
/// Backs the negotiation answers of one decoded chunk.
answer_storage: [iac.answersBound(chunk_bytes)]u8,

/// A `Fetcher` that holds no answer yet.
pub fn init(allocator: std.mem.Allocator, io: Io) Fetcher {
    return .{
        .allocator = allocator,
        .io = io,
        .answer = null,
        .body = undefined,
        .data_storage = undefined,
        .answer_storage = undefined,
    };
}

/// Frees the answer this `Fetcher` holds. Safe to call more than once.
pub fn deinit(f: *Fetcher) void {
    f.release();
}

fn release(f: *Fetcher) void {
    const held = f.answer orelse return;
    f.allocator.free(held);
    f.answer = null;
}

/// The answer of one telnet transfer.
pub const Body = struct {
    /// Streams the data octets the peer wrote, with every doubled 255
    /// halved and every command taken out. Valid until the next `open` on
    /// this `Fetcher`, or until `deinit`.
    reader: *Io.Reader,
    /// How many octets the answer holds.
    length: u64,
};

/// Runs one transfer and returns its answer.
///
/// Frees whatever the previous call held first, so a `Fetcher` never holds
/// two answers at once.
///
/// The faults, and the exit code each carries:
///
/// - a url that names no port is `error.InvalidUrl`, exit 3.
/// - a peer that does not accept a connection is `error.CouldNotConnect`,
///   exit 7. Measured: `curl telnet://127.0.0.1:1` exits 7.
/// - a body past `options.max_send_bytes` is `error.FileSizeExceeded`,
///   exit 63, and no socket opens.
/// - an answer past `options.max_response_bytes` is
///   `error.FileSizeExceeded`, exit 63.
/// - a peer that negotiates past `iac.max_answers` is
///   `error.WeirdServerReply`, exit 8.
pub fn open(f: *Fetcher, url: zurl_core.Url, options: Options, d: ?*Diagnostics) Error!Body {
    f.release();

    const port = url.port orelse return fail(d, error.InvalidUrl, &.{
        "a telnet url names a port, and this one names none",
    });
    // **`--resolve` and `--connect-to` move this dial and nothing else.**
    // A telnet session writes no host name to the peer and opens no TLS,
    // so the dial is all there is to move here. See `zurl_net.override`.
    const target = zurl_net.override.dialTarget(options.connect_to, url.host, port);
    // A host that does not read and a host name no resolver can look up
    // are two faults, exit 3 and exit 6. See `zurl_net.errors.hostInit`.
    const host = zurl_net.tcp.Host.init(target.host) catch |err| return fail(d, zurl_net.errors.hostInit(err).err, &.{
        target.faultPrefix(err),
        target.host,
    });

    // **The body is read and escaped before the dial.** A body that does
    // not fit the bound costs no connection at all, and the escaping
    // happens once rather than one piece at a time.
    const escaped: ?[]u8 = if (options.body) |source|
        try f.readAndEscape(source, options, d)
    else
        null;
    defer if (escaped) |held| f.allocator.free(held);

    var connection: zurl_net.Connection = undefined;
    zurl_net.bounded.setup(&connection, f.io, options.connect_timeout, .{
        .allocator = f.allocator,
        .io = f.io,
        .host = host,
        .port = target.port,
        .read_buffer_len = read_buffer_len,
        .tls = null,
        .no_delay = options.tcp_no_delay,
    }) catch |err| return reportSetup(err, url.host, d);
    defer connection.deinit();

    if (escaped) |text| {
        connection.writer().writeAll(text) catch return reportWrite(&connection, d);
        connection.flush() catch return reportWrite(&connection, d);
    }

    const answer = try f.relay(&connection, options, d);
    f.answer = answer;
    f.body = .fixed(answer);
    return .{ .reader = &f.body, .length = answer.len };
}

/// Reads the whole body and returns it with every 255 doubled. The caller
/// frees it.
///
/// **This is the one path from a caller's octets to a socket**, so it is
/// the one place the escaping can be forgotten, and it is not forgotten
/// here. See `iac.escape`.
fn readAndEscape(
    f: *Fetcher,
    source: Source,
    options: Options,
    d: ?*Diagnostics,
) Error![]u8 {
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(f.allocator);

    var buffer: [chunk_bytes]u8 = undefined;
    while (true) {
        const n = source.read(source.ctx, &buffer, buffer.len);
        if (n < 0) return fail(d, error.ReadError, &.{
            "zurl did not read what it was told to send to the telnet peer",
        });
        if (n == 0) break;
        const taken: usize = @intCast(n);
        if (@as(u64, raw.items.len) + taken > options.max_send_bytes) return failNumber(
            d,
            error.FileSizeExceeded,
            "the body of this telnet transfer is longer than the ",
            options.max_send_bytes,
            " octets zurl sends",
        );
        raw.appendSlice(f.allocator, buffer[0..taken]) catch
            return Diagnostics.record(d, error.OutOfMemory, .{});
    }

    const needed = iac.escapedLen(raw.items);
    const out = f.allocator.alloc(u8, needed) catch
        return Diagnostics.record(d, error.OutOfMemory, .{});
    errdefer f.allocator.free(out);
    // `needed` is exactly what `escape` writes, so the refusal arm below
    // is unreachable. It is written all the same, because a bound that is
    // only asserted is a bound that a later change can move.
    return iac.escape(out, raw.items) catch return fail(d, error.WriteError, &.{
        "zurl could not escape the telnet body it was told to send",
    });
}

/// Reads until the peer closes, answering the negotiation as it goes, and
/// returns the data octets. The caller frees them.
///
/// **The answers have to go out while the read runs.** A telnet server
/// waits for the answer to its option negotiation before it writes a login
/// prompt, so a reader that collected the whole answer first would wait
/// for text the peer is waiting to be allowed to send. That is why this
/// reads through `zurl_net.bounded.waitForBytes` and not through
/// `readToEnd`.
fn relay(
    f: *Fetcher,
    connection: *zurl_net.Connection,
    options: Options,
    d: ?*Diagnostics,
) Error![]u8 {
    var decoder: iac.Decoder = .{};
    var collected: std.ArrayList(u8) = .empty;
    errdefer collected.deinit(f.allocator);

    const reader = connection.reader();
    while (true) {
        zurl_net.bounded.waitForBytes(reader, f.io, options.read_timeout) catch |err| switch (err) {
            // The peer closed, which is how a telnet session ends.
            error.EndOfStream => break,
            else => |rest| return reportRead(rest, connection, d),
        };

        const held = reader.buffered();
        const take = @min(held.len, chunk_bytes);
        const fed = decoder.feed(
            held[0..take],
            &f.data_storage,
            &f.answer_storage,
        ) catch |err| switch (err) {
            error.TooManyNegotiations => return fail(d, error.WeirdServerReply, &.{
                "the telnet peer negotiated more times than zurl answers in one session",
            }),
            error.TooManyCommandOctets => return fail(d, error.WeirdServerReply, &.{
                "the telnet peer wrote more command octets than zurl reads in one session, and those octets carry no data",
            }),
            // `answer_storage` is sized with `iac.answersBound` and `take`
            // is never larger than `chunk_bytes`, so this arm is
            // unreachable. `iac.Decoder` checks the room for every answer
            // it writes all the same, because a bound that only the caller
            // keeps is a bound that a later change can make wrong. That is
            // the defect this arm now reports instead of an overrun.
            error.AnswerBufferTooSmall => return fail(d, error.ReadError, &.{
                "zurl had no room for the telnet negotiation it had to answer",
            }),
            // `data_storage` is `chunk_bytes` and `take` is never larger
            // than `chunk_bytes`, so this arm is unreachable too. It is a
            // read fault and not a weird reply for the same reason the arm
            // above is: the peer chose the octets, this end chose the
            // buffer, and only this end can size it wrong.
            error.DataBufferTooSmall => return fail(d, error.ReadError, &.{
                "zurl had no room for the telnet data it had already read",
            }),
        };
        reader.toss(take);

        // **Saturating, so the room left is never a wrapped number.** Every
        // append below is bounded by this comparison, so the collected
        // length cannot pass the ceiling today. An unsigned subtraction
        // that rests on that alone stops bounding anything for the rest of
        // the transfer the first time it wraps, and `-|` costs nothing.
        if (@as(u64, fed.data.len) > options.max_response_bytes -| collected.items.len) {
            return failNumber(
                d,
                error.FileSizeExceeded,
                "the telnet peer wrote more than the ",
                options.max_response_bytes,
                " octets zurl reads from one session, which ends only when the peer closes",
            );
        }
        collected.appendSlice(f.allocator, fed.data) catch
            return Diagnostics.record(d, error.OutOfMemory, .{});

        if (fed.answers.len != 0) {
            connection.writer().writeAll(fed.answers) catch return reportWrite(connection, d);
            connection.flush() catch return reportWrite(connection, d);
        }
    }

    return collected.toOwnedSlice(f.allocator) catch
        Diagnostics.record(d, error.OutOfMemory, .{});
}

/// Reports a dial fault with the sentence `zurl-net` holds for it.
fn reportSetup(
    err: zurl_net.errors.SetupError,
    host: []const u8,
    d: ?*Diagnostics,
) Error {
    const mapping = zurl_net.errors.map(err);
    if (mapping.message) |text| return fail(d, mapping.err, &.{ host, ": ", text });
    return fail(d, mapping.err, &.{ host, ": ", @errorName(err) });
}

/// Reports a write that did not reach the peer.
fn reportWrite(connection: *zurl_net.Connection, d: ?*Diagnostics) Error {
    const cause = connection.writeError() orelse return fail(d, error.WriteError, &.{
        "zurl did not write to the telnet peer",
    });
    return fail(d, error.WriteError, &.{
        "zurl did not write to the telnet peer: ",
        @errorName(cause),
    });
}

/// Reports a read that did not finish.
fn reportRead(
    err: zurl_net.bounded.ReadError,
    connection: *zurl_net.Connection,
    d: ?*Diagnostics,
) Error {
    return switch (err) {
        error.OutOfMemory => Diagnostics.record(d, error.OutOfMemory, .{}),
        error.StreamTooLong => fail(d, error.FileSizeExceeded, &.{
            "the telnet peer wrote more than zurl reads from one session",
        }),
        error.OperationTimedOut => fail(d, error.OperationTimedOut, &.{
            "the telnet peer sent no octet for as long as zurl waits, and a telnet session ends only when the peer closes",
        }),
        error.ReadTimeoutUnsupported => fail(d, error.ReadError, &.{
            "this build has no concurrency, so a telnet read cannot be bounded, and an unbounded one would wait for a peer that may never answer",
        }),
        error.Canceled => fail(d, error.AbortedByCallback, &.{
            "the telnet read was stopped from outside",
        }),
        error.ReadFailed => {
            const cause = connection.readError() orelse return fail(d, error.ReadError, &.{
                "zurl did not read the telnet answer",
            });
            return fail(d, error.ReadError, &.{
                "zurl did not read the telnet answer: ",
                @errorName(cause),
            });
        },
    };
}

/// Writes `parts`, one after another, into `d`'s own message storage,
/// records `err` with that message, and returns `err`.
fn fail(d: ?*Diagnostics, err: Error, parts: []const []const u8) Error {
    const target = d orelse return err;
    const out: []u8 = &target.message_storage;
    var at: usize = 0;
    for (parts) |part| {
        const n = @min(out.len - at, part.len);
        @memcpy(out[at..][0..n], part[0..n]);
        at += n;
    }
    return Diagnostics.record(d, err, .{ .message = out[0..at] });
}

/// `fail` for a sentence with a number in the middle of it.
fn failNumber(
    d: ?*Diagnostics,
    err: Error,
    before: []const u8,
    value: u64,
    after: []const u8,
) Error {
    var digits: [20]u8 = undefined;
    const text = std.fmt.bufPrint(&digits, "{d}", .{value}) catch digits[0..0];
    return fail(d, err, &.{ before, text, after });
}

/// Returns the dispatch entry for the `telnet` scheme.
///
/// `Front` is the front package's own namespace, taken as a comptime
/// parameter. Passing the namespace rather than importing it is what keeps
/// this package free of a `zurl` import.
///
/// **`f` must outlive every transfer the client runs on this scheme**, and
/// must not move: the entry carries `f` as its opaque pointer, and the
/// body reader points inside it.
pub fn protocol(f: *Fetcher, comptime Front: type) Front.protocol.Protocol {
    return .{
        .scheme = scheme,
        .default_port = default_port,
        .ptr = f,
        .vtable = &Dispatch(Front).vtable,
        // This package dials the origin itself and reads no proxy field,
        // so a transfer that named a proxy is refused by name rather than
        // run direct. curl carries telnet through a proxy and this build
        // does not. See `Front.protocol.Unread`.
        .unread = .{ .proxy = true },
    };
}

/// The vtable for one front package.
fn Dispatch(comptime Front: type) type {
    return struct {
        const vtable: Front.protocol.Protocol.VTable = .{ .perform = performTelnet };

        fn performTelnet(
            ptr: ?*anyopaque,
            c: *Front.Client,
            url: zurl_core.Url,
            options: Front.Transfer.Options,
            d: ?*Diagnostics,
        ) Error!Front.Response {
            _ = c;
            const f: *Fetcher = @ptrCast(@alignCast(ptr.?));
            const body = try f.open(url, translate(options), d);
            return .{
                .status = status,
                .content_length = body.length,
                .transfer_encoding = .none,
                .body = body.reader,
            };
        }

        /// Reads the front package's own options into this package's.
        ///
        /// **`--max-filesize` narrows the bound and never widens it.** A
        /// zero there means the user named none, so the package bound
        /// stands.
        fn translate(options: Front.Transfer.Options) Options {
            return .{
                .connect_timeout = options.connect_timeout,
                .max_response_bytes = if (options.max_size == 0)
                    default_max_response_bytes
                else
                    @min(options.max_size, default_max_response_bytes),
                .read_timeout = zurl_net.bounded.stallTimeout(
                    options.low_speed_limit,
                    options.low_speed_time_s,
                    default_read_timeout_s,
                ),
                .tcp_no_delay = options.tcp_no_delay,
                .body = if (options.body) |source|
                    .{ .len = source.len, .ctx = source.ctx, .read = source.read }
                else
                    null,
                .connect_to = options.connect_to,
            };
        }
    };
}

const testing = std.testing;
const test_server = @import("test_server.zig");

/// The smallest front package that `protocol` can build against.
///
/// This is a stub of the shape `zurl` exports, and it is here to prove one
/// thing: `protocol` needs the shape and never the package. This file must
/// build with no `zurl` in its import table at all.
const StubFront = struct {
    const Client = struct {};

    const Transfer = struct {
        const Options = struct {
            connect_timeout: Io.Timeout = .none,
            low_speed_limit: u64 = 1,
            low_speed_time_s: u32 = 300,
            max_size: u64 = 0,
            tcp_no_delay: bool = true,
            body: ?Source = null,
            connect_to: []const zurl_net.override.HostOverride = &.{},
        };
    };

    const Response = struct {
        status: u16,
        content_length: ?u64,
        transfer_encoding: std.http.TransferEncoding,
        body: *Io.Reader,
        effective_url: []const u8 = "",
    };

    const protocol = struct {
        // The stub keeps the shape of `zurl.protocol.Unread`. A stub that
        // dropped a field would let this package compile against a front
        // it no longer fits.
        const Unread = struct {
            proxy: bool = false,
            credentials: bool = false,
        };

        const Protocol = struct {
            scheme: []const u8,
            default_port: ?u16,
            ptr: ?*anyopaque,
            vtable: *const VTable,
            unread: Unread = .{},

            const VTable = struct {
                perform: *const fn (
                    ptr: ?*anyopaque,
                    c: *Client,
                    url: zurl_core.Url,
                    options: Transfer.Options,
                    d: ?*Diagnostics,
                ) Error!Response,
            };
        };
    };
};

/// A `Source` over a slice, for the tests below.
const SliceSource = struct {
    text: []const u8,
    at: usize = 0,

    fn source(s: *SliceSource) Source {
        return .{ .len = s.text.len, .ctx = s, .read = readSlice };
    }

    fn readSlice(ctx: *anyopaque, buffer: [*]u8, len: usize) callconv(.c) isize {
        const s: *SliceSource = @ptrCast(@alignCast(ctx));
        const take = @min(len, s.text.len - s.at);
        @memcpy(buffer[0..take], s.text[s.at..][0..take]);
        s.at += take;
        return @intCast(take);
    }
};

fn parseTelnetUrl(text: []const u8) !zurl_core.Url {
    var schemes: zurl_core.url.Schemes = .empty;
    try schemes.add(.{ .name = scheme, .default_port = default_port });
    return zurl_core.url.parseWith(text, &schemes);
}

/// Runs one transfer against `server` and returns its answer.
fn fetch(
    f: *Fetcher,
    server: *const test_server.Server,
    options: Options,
    d: ?*Diagnostics,
) Error!Body {
    var url_buffer: [64]u8 = undefined;
    const text = std.fmt.bufPrint(
        &url_buffer,
        "telnet://127.0.0.1:{d}",
        .{server.port()},
    ) catch return error.InvalidUrl;
    return f.open(parseTelnetUrl(text) catch return error.InvalidUrl, options, d);
}

test {
    _ = iac;
    _ = test_server;
}

test "the package names the scheme and the port RFC 854 assigns" {
    try testing.expectEqualStrings("telnet", scheme);
    try testing.expectEqual(@as(?u16, 23), default_port);
}

test "an IAC octet in the body is escaped before it reaches the socket" {
    // **The whole point of this package's escaping.** These three octets
    // are `IAC DO TERMINAL-TYPE`, so a writer that passed them through
    // would send a negotiation the user never asked for. Measured against
    // curl 8.21.0: standard input of `he<FF>llo<CRLF>bye<CRLF>` reached a
    // loopback server as `he<FF><FF>llo<CRLF>bye<CRLF>`.
    var server: test_server.Server = undefined;
    // The body is 13 octets and one of them is escaped, so 14 arrive.
    try server.start(.{ .greeting = "", .answer = "ok\r\n", .expect_bytes = 14 });
    defer server.stop();

    var source: SliceSource = .{ .text = "he\xffllo\r\nbye\r\n" };
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    _ = try fetch(&f, &server, .{ .body = source.source() }, null);

    server.awaitDone();
    try testing.expectEqualSlices(u8, "he\xff\xffllo\r\nbye\r\n", server.received());
}

test "a whole exchange: the greeting is answered and the data reaches the caller" {
    // The fixture opens with `IAC DO TERMINAL-TYPE`, which is what a real
    // telnet server does and what curl was measured against.
    var server: test_server.Server = undefined;
    try server.start(.{
        .greeting = "\xff\xfd\x18login: ",
        .answer = "welcome\r\n",
        // The refusal and the four offers, five lines of three octets.
        .expect_bytes = 15,
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    const body = try fetch(&f, &server, .{}, null);

    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    // The command never reaches the output, and the data does.
    try testing.expectEqualStrings("login: welcome\r\n", contents);

    // The six lines curl writes for the same greeting, measured.
    server.awaitDone();
    try testing.expectEqualSlices(
        u8,
        "\xff\xfc\x18" ++ "\xff\xfb\x00" ++ "\xff\xfd\x00" ++
            "\xff\xfb\x03" ++ "\xff\xfd\x03",
        server.received(),
    );
}

test "a doubled IAC in the answer comes back as one octet" {
    // Measured against curl 8.21.0: a server that wrote
    // `data<FF><FF>with-iac<CRLF>`, then `IAC WILL ECHO`, then
    // `tail<CRLF>` gave curl's standard output
    // `data<FF>with-iac<CRLF>tail<CRLF>`.
    var server: test_server.Server = undefined;
    try server.start(.{
        .greeting = "data\xff\xffwith-iac\r\n",
        .answer = "\xff\xfb\x01tail\r\n",
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    const body = try fetch(&f, &server, .{}, null);
    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualSlices(u8, "data\xffwith-iac\r\ntail\r\n", contents);
}

test "a peer that only writes data gets nothing back" {
    // Measured: with a server that opened with plain data, curl 8.21.0
    // wrote only the standard input it was given and no negotiation at
    // all.
    var server: test_server.Server = undefined;
    try server.start(.{ .greeting = "hi\r\n", .answer = "" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    const body = try fetch(&f, &server, .{}, null);
    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("hi\r\n", contents);

    server.awaitDone();
    try testing.expectEqualStrings("", server.received());
}

test "an answer past the bound is refused" {
    var server: test_server.Server = undefined;
    try server.start(.{ .greeting = "0123456789", .answer = "0123456789" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    try testing.expectError(
        error.FileSizeExceeded,
        fetch(&f, &server, .{ .max_response_bytes = 15 }, &d),
    );
    try testing.expectEqual(@as(?u32, 63), d.curl_code);
}

test "a body past the send bound never opens a socket" {
    var server: test_server.Server = undefined;
    try server.start(.{ .greeting = "", .answer = "" });
    defer server.stop();

    var source: SliceSource = .{ .text = "0123456789" };
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    try testing.expectError(error.FileSizeExceeded, fetch(&f, &server, .{
        .body = source.source(),
        .max_send_bytes = 4,
    }, &d));
    try testing.expectEqual(@as(usize, 0), server.connections());
}

test "a url that names no port never dials" {
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    const url: zurl_core.Url = .{
        .scheme = "telnet",
        .user = null,
        .password = null,
        .host = "example.com",
        .port = null,
        .path = "/",
        .query = null,
        .fragment = null,
    };
    try testing.expectError(error.InvalidUrl, f.open(url, .{}, &d));
}

test "a peer that refuses a connection carries curl's own exit 7" {
    // Measured: `curl telnet://127.0.0.1:1` exits 7.
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    try testing.expectError(
        error.CouldNotConnect,
        f.open(try parseTelnetUrl("telnet://127.0.0.1:1"), .{}, &d),
    );
    try testing.expectEqual(@as(?u32, 7), d.curl_code);
}

test "the dispatch entry names the scheme and its port" {
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    const entry = f.protocol(StubFront);
    try testing.expectEqualStrings("telnet", entry.scheme);
    try testing.expectEqual(@as(?u16, 23), entry.default_port);
    try testing.expectEqual(@as(?*anyopaque, &f), entry.ptr);
}

test "--connect-to moves a telnet dial and --resolve reaches this package too" {
    // The defect this closes: this package read no `connect_to`, so a
    // user who named either flag got a dial to the url's own host and no
    // diagnostic. curl 8.21.0 applies both to `telnet`, measured.
    //
    // **No test here touches a resolver.** The url names `127.0.0.2:1`,
    // which refuses at once, so the flag is the only thing that can reach
    // the fixture.
    var server: test_server.Server = undefined;
    try server.start(.{ .greeting = "moved\n" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    const url = try parseTelnetUrl("telnet://127.0.0.2:1");

    var bare: Diagnostics = .{};
    try testing.expectError(error.CouldNotConnect, f.open(url, .{}, &bare));
    try testing.expectEqual(@as(usize, 0), server.connections());

    const body = try f.open(url, .{ .connect_to = &.{.{
        .from_host = "127.0.0.2",
        .from_port = 1,
        .to_host = "127.0.0.1",
        .to_port = server.port(),
    }} }, null);
    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("moved\n", contents);
    try testing.expectEqual(@as(usize, 1), server.connections());
}

test "the telnet translation carries --connect-to into this package" {
    const D = Dispatch(StubFront);
    try testing.expectEqual(@as(usize, 0), D.translate(.{}).connect_to.len);

    const overrides: []const zurl_net.override.HostOverride = &.{.{
        .from_host = "a.test",
        .to_host = "127.0.0.1",
        .to_port = 9,
    }};
    const carried = D.translate(.{ .connect_to = overrides });
    try testing.expectEqual(@as(usize, 1), carried.connect_to.len);
    try testing.expectEqualStrings("a.test", carried.connect_to[0].from_host);
}
