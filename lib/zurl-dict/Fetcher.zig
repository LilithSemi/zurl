//! Runs one `dict://` transfer: the dial, the RFC 2229 session, and the
//! answer.
//!
//! A `Fetcher` owns the answer of the transfer in play. `open` frees
//! whatever the last call left and holds the new answer, so one `Fetcher`
//! serves one transfer at a time, the same rule `zurl.Client` keeps for
//! its own HTTP exchange.
//!
//! **A `Fetcher` must not move once `open` has run.** The body reader it
//! hands back points into this value. Keep one where it will stay, and
//! pass a pointer.
//!
//! **The connection does not outlive `open`.** RFC 2229 lets a client send
//! the whole session in one write and read until the server closes, which
//! is what curl does, so the answer is complete when `open` returns and
//! there is nothing left to read from a socket. The socket closes inside
//! `open` and the body is a reader over memory.
//!
//! **The answer is bounded and buffered.** A dict answer ends when the
//! peer closes, so it carries no length and a hostile server can write
//! forever. `Options.max_response_bytes` is the bound, and a peer past it
//! gets `error.FileSizeExceeded`, exit 63, with no byte of the answer
//! reaching the output. See that field.
//!
//! What this does not do: no `AUTH`, because curl sends none for `dict`
//! either, measured with `curl -u bob:secret dict://...`. No connection
//! reuse: the session ends with `QUIT` and the server closes.
//!
//! This file imports `zurl-core` and `zurl-net`. It does not import
//! `zurl`, and it never will. See `protocol`.

const Fetcher = @This();

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_net = @import("zurl-net");

const request = @import("request.zig");

const Io = std.Io;
const Error = zurl_core.Error;
const Diagnostics = zurl_core.Diagnostics;

/// The scheme this package handles.
pub const scheme = "dict";

/// The port a `dict` url uses when it names none. RFC 2229 assigns 2628.
pub const default_port: ?u16 = 2628;

/// The status a `dict://` transfer reports.
///
/// Zero, because RFC 2229 has no status a transfer as a whole carries.
/// curl 8.21.0 prints `000` for `%{http_code}` on a `dict://` url that
/// worked, measured with
/// `curl -w '%{http_code}' -o /dev/null dict://127.0.0.1:PORT/d:hello`.
pub const status: u16 = 0;

/// How many bytes of answer this package reads by default.
///
/// A dict answer has no length on the wire: the server writes its lines
/// and closes, so the end of the answer and the end of the socket are one
/// event. Without a bound a server that never closes holds this process
/// for as long as it likes and fills memory while it does.
///
/// 16 MiB is far past any dictionary answer. The largest `DEFINE` in the
/// WordNet database is a few kilobytes, and a `MATCH` over every database
/// is a list of words.
///
/// curl keeps no such bound. It streams the answer and stops only when the
/// user's own `--max-filesize` says so.
pub const default_max_response_bytes: u64 = 16 * 1024 * 1024;

/// How much room the connection keeps for bytes read and not taken yet.
/// One RFC 2229 line fits in far less. This is the size a block of the
/// answer moves in.
pub const read_buffer_len: usize = 8192;

/// How long one read of the answer may wait with no byte arriving.
///
/// **A dict answer ends when the peer closes, so a peer that never writes
/// and never closes holds this process forever.** `--connect-timeout`
/// covers the dial and nothing after it, and `zurl_net.Connection` keeps no
/// clock of its own. Without this a `socat TCP-LISTEN:2628` that accepts
/// and writes nothing hung zurl until a signal.
///
/// 300 seconds is curl's own `--speed-time` default, and this is the same
/// question: how long a transfer may make no progress. `--speed-time`
/// narrows it and never widens it, the way `--max-filesize` narrows
/// `default_max_response_bytes`.
///
/// This bounds one wait and never the whole transfer. A peer that keeps
/// sending runs for as long as the size bound allows.
pub const default_read_timeout_s: u32 = 300;

/// `default_read_timeout_s`, as a `std.Io.Timeout`.
pub const default_read_timeout: Io.Timeout = .{
    .duration = .{ .raw = .fromSeconds(default_read_timeout_s), .clock = .awake },
};

allocator: std.mem.Allocator,
io: Io,
/// The answer of the transfer in play, or null when none is held. `open`
/// frees this before it reads another, and `deinit` frees it.
answer: ?[]u8,
/// Reads `answer`. Valid only while `answer` holds something.
body: Io.Reader,
/// Backs the session this transfer writes. A field and not a stack buffer,
/// so the bound is one named number and not a frame size.
request_storage: [request.max_request_bytes]u8,
/// Holds the percent-decoded path. A field for the same reason
/// `request_storage` is.
path_storage: [request.max_path_bytes]u8,

/// What one transfer may ask for.
///
/// A struct of this package's own, and not `zurl.Transfer.Options`,
/// because this package must build with no `zurl` in its import table.
/// `Dispatch` fills it from the front package's own options.
pub const Options = struct {
    /// A cap on the dial. `.none` waits for as long as the operating
    /// system does.
    connect_timeout: Io.Timeout = .none,
    /// The bound on the answer. See `default_max_response_bytes`.
    ///
    /// A caller that reads `--max-filesize` narrows this. The lower of the
    /// two wins, because both are bounds and neither may widen the other.
    max_response_bytes: u64 = default_max_response_bytes,
    /// How long one read may wait with no byte arriving. See
    /// `default_read_timeout_s`. `.none` waits forever, which no caller in
    /// this repository asks for.
    read_timeout: Io.Timeout = default_read_timeout,
    /// Whether to turn Nagle's algorithm off on the connection. False is
    /// `--no-tcp-nodelay`.
    tcp_no_delay: bool = true,
    /// Where a url naming one host and port dials instead. This is
    /// `--resolve` and `--connect-to`.
    ///
    /// **An entry moves the dial and nothing else.** See
    /// `zurl_net.override`. A dict session carries no name to a peer and
    /// opens no TLS, so the dial is all there is to move here.
    connect_to: []const zurl_net.override.HostOverride = &.{},
};

/// A `Fetcher` that holds no answer yet.
pub fn init(allocator: std.mem.Allocator, io: Io) Fetcher {
    return .{
        .allocator = allocator,
        .io = io,
        .answer = null,
        .body = undefined,
        .request_storage = undefined,
        .path_storage = undefined,
    };
}

/// Frees the answer this `Fetcher` holds. Safe to call more than once, and
/// safe on a `Fetcher` that never opened anything.
pub fn deinit(f: *Fetcher) void {
    f.release();
}

fn release(f: *Fetcher) void {
    const held = f.answer orelse return;
    f.allocator.free(held);
    f.answer = null;
}

/// The answer of one `dict://` transfer.
pub const Body = struct {
    /// Streams the answer. Valid until the next `open` on this `Fetcher`,
    /// or until `deinit`, whichever comes first.
    reader: *Io.Reader,
    /// How many bytes the answer holds. Always known, because the whole
    /// answer is read before this returns.
    length: u64,
};

/// Runs one transfer and returns its answer.
///
/// Frees whatever the previous call held first, so a `Fetcher` never holds
/// two answers at once.
///
/// **Every byte the server sent reaches the caller, headers and all.**
/// curl 8.21.0 does no parsing of a dict answer: measured against a
/// loopback RFC 2229 server, `curl dict://h/d:hello` wrote the `220`
/// banner, the `250` answer to `CLIENT`, the `150` and `151` lines, the
/// definition, the `.` line, the closing `250`, and the `221` of `QUIT`,
/// byte for byte. So a caller that wants the definition alone parses this
/// text itself, exactly as it would parse curl's output.
///
/// The three faults, and the exit code each carries:
///
/// - a url whose decoded path holds a byte below 0x20 is
///   `error.InvalidUrl`, exit 3. curl refuses the same url with the same
///   code, measured on `dict://h/d:a%09b` and `dict://h/d:a%0d%0aQUIT`.
/// - a peer that does not accept a connection is `error.CouldNotConnect`,
///   exit 7. Measured: `curl dict://127.0.0.1:1/d:hello` exits 7.
/// - an answer past `options.max_response_bytes` is
///   `error.FileSizeExceeded`, exit 63, and no byte of it is returned.
pub fn open(f: *Fetcher, url: zurl_core.Url, options: Options, d: ?*Diagnostics) Error!Body {
    f.release();

    const session = try f.buildSession(url, d);
    const port = url.port orelse return fail(d, error.InvalidUrl, &.{
        "a dict url names a port, and this one names none",
    });
    // **`--resolve` and `--connect-to` move this dial and nothing else.**
    // A dict session writes no host name to the peer, so there is nothing
    // else for an entry to reach. See `zurl_net.override`.
    const target = zurl_net.override.dialTarget(options.connect_to, url.host, port);
    // A host that does not read and a host name no resolver can look up
    // are two faults, exit 3 and exit 6. See `zurl_net.errors.hostInit`.
    const host = zurl_net.tcp.Host.init(target.host) catch |err| return fail(d, zurl_net.errors.hostInit(err).err, &.{
        target.faultPrefix(err),
        target.host,
    });

    const stream = zurl_net.tcp.dial(f.io, host, target.port, .{
        .timeout = options.connect_timeout,
        .no_delay = options.tcp_no_delay,
    }) catch |err| return f.reportSetup(err, url.host, d);
    var connection: zurl_net.Connection = undefined;
    connection.init(f.allocator, f.io, stream, .{
        .read_buffer_len = read_buffer_len,
    }) catch |err| {
        stream.close(f.io);
        return f.reportSetup(err, url.host, d);
    };
    // The connection ends with this call whatever happens next. The
    // session carries `QUIT`, the server closes, and there is no second
    // request to keep a socket for.
    defer connection.deinit();

    const w = connection.writer();
    w.writeAll(session) catch return f.reportWrite(&connection, d);
    connection.flush() catch return f.reportWrite(&connection, d);

    // **Two bounds on one read: the size and the wait.**
    // `zurl_net.bounded.readToEnd` keeps both. The size bound stops a peer
    // that writes forever, and the wait bound stops a peer that writes
    // nothing. A dict answer ends only when the peer closes, so the
    // protocol itself ends neither one.
    const answer = zurl_net.bounded.readToEnd(
        &connection,
        f.io,
        f.allocator,
        options.max_response_bytes,
        options.read_timeout,
    ) catch |err| switch (err) {
        error.OutOfMemory => return Diagnostics.record(d, error.OutOfMemory, .{}),
        error.StreamTooLong => return failNumber(
            d,
            error.FileSizeExceeded,
            "the server wrote more than the ",
            options.max_response_bytes,
            " bytes zurl reads from a dict answer, which ends only when the peer closes",
        ),
        error.ReadFailed => return f.reportRead(&connection, d),
        // Exit 28, which is the code curl gives a transfer that stopped
        // moving.
        error.OperationTimedOut => return fail(d, error.OperationTimedOut, &.{
            "the dict server sent no byte for as long as zurl waits, and a dict answer ends only when the peer closes",
        }),
        error.ReadTimeoutUnsupported => return fail(d, error.ReadError, &.{
            "this build has no concurrency, so a dict read cannot be bounded, and an unbounded one would wait for a peer that may never answer",
        }),
        error.Canceled => return fail(d, error.AbortedByCallback, &.{
            "the dict read was stopped from outside",
        }),
    };

    f.answer = answer;
    f.body = .fixed(answer);
    return .{ .reader = &f.body, .length = answer.len };
}

/// Builds the session bytes for `url` into this `Fetcher`'s own storage.
///
/// Two steps, and the order of the two is the whole of the injection rule:
/// the path is decoded first, and the decoded bytes are then held to
/// `zurl_core.url.hasControlByte` **before** any of them is written into a
/// command line. `zurl_core.url.parse` already refused a raw control byte
/// in the path, so the only way one can arrive is a percent escape, and
/// this is where such an escape becomes a byte.
///
/// Without that order `dict://h/d:a%0d%0aQUIT` would write a `DEFINE` line
/// and then a second line of the url's own choosing. curl refuses the same
/// url with exit 3, measured.
fn buildSession(f: *Fetcher, url: zurl_core.Url, d: ?*Diagnostics) Error![]const u8 {
    const path = try f.decodePath(url.path, d);

    if (zurl_core.url.hasControlByte(path)) return fail(d, error.InvalidUrl, &.{
        "the path holds a control byte, which would end the dict command line early",
    });

    var w: Io.Writer = .fixed(&f.request_storage);
    request.writeSession(&w, path) catch return fail(d, error.InvalidUrl, &.{
        "the dict command this url builds is longer than the ",
        std.fmt.comptimePrint("{d}", .{request.max_request_bytes}),
        " bytes zurl writes",
    });
    return w.buffered();
}

/// Percent-decodes `escaped` into this `Fetcher`'s own path storage.
///
/// An escape that does not decode leaves the text alone. curl 8.21.0 does
/// the same: `dict://h/d:a%zzb` reaches the wire as `DEFINE ! a%zzb`,
/// measured, so the raw text is the word and the server decides.
fn decodePath(f: *Fetcher, escaped: []const u8, d: ?*Diagnostics) Error![]const u8 {
    const out: []u8 = &f.path_storage;
    if (escaped.len > out.len) return fail(d, error.InvalidUrl, &.{
        "the path is longer than the ",
        std.fmt.comptimePrint("{d}", .{request.max_path_bytes}),
        " bytes zurl reads",
    });

    return zurl_core.url.percentDecode(out, escaped) catch |err| switch (err) {
        error.InvalidEscape => escape: {
            @memcpy(out[0..escaped.len], escaped);
            break :escape out[0..escaped.len];
        },
        // The decoded form is never longer than the escaped form, and the
        // check above already refused a text that does not fit. This arm
        // is a named fault and not an `unreachable`, which a ReleaseFast
        // build turns into undefined behaviour.
        error.NoSpaceLeft => fail(d, error.InvalidUrl, &.{
            "the path is longer than zurl reads",
        }),
    };
}

/// Reports a dial or handshake fault with the sentence `zurl-net` holds
/// for it.
fn reportSetup(
    f: *Fetcher,
    err: zurl_net.errors.SetupError,
    host: []const u8,
    d: ?*Diagnostics,
) Error {
    _ = f;
    const mapping = zurl_net.errors.map(err);
    if (mapping.message) |text| return fail(d, mapping.err, &.{ host, ": ", text });
    return fail(d, mapping.err, &.{ host, ": ", @errorName(err) });
}

/// Reports a write that did not reach the peer.
///
/// The connection knows the socket fault under the writer, so the message
/// names it. A write that fails with no fault recorded is the writer
/// having run out of its own buffer, which cannot happen here: the session
/// is written whole and then flushed.
fn reportWrite(f: *Fetcher, connection: *zurl_net.Connection, d: ?*Diagnostics) Error {
    _ = f;
    const cause = connection.writeError() orelse return fail(d, error.WriteError, &.{
        "zurl did not write the dict request",
    });
    return fail(d, error.WriteError, &.{
        "zurl did not write the dict request: ",
        @errorName(cause),
    });
}

/// Reports a read that did not finish.
///
/// A dict answer ends when the peer closes, so the end of the socket is
/// not a fault here and never reaches this function. Only a real read
/// fault does.
fn reportRead(f: *Fetcher, connection: *zurl_net.Connection, d: ?*Diagnostics) Error {
    _ = f;
    const cause = connection.readError() orelse return fail(d, error.ReadError, &.{
        "zurl did not read the dict answer",
    });
    return fail(d, error.ReadError, &.{
        "zurl did not read the dict answer: ",
        @errorName(cause),
    });
}

/// Writes `parts`, one after another, into `d`'s own message storage,
/// records `err` with that message, and returns `err`.
///
/// The text goes into `Diagnostics.message_storage` for the reason
/// `zurl.Client.caFailureMessage` puts its own text there: the sentence
/// names a host and a path this package holds in buffers it reuses, so a
/// borrowed message would read the next transfer's url. A message longer
/// than the storage loses its tail, because a diagnostic that says less is
/// a cost and one that is not written at all is a fault.
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
///
/// A separate function because the number has to be formatted into storage
/// that outlives this call, and `Diagnostics.message_storage` is the only
/// such storage this package may write.
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

/// Returns the dispatch entry that registers this fetcher with a client.
///
/// `Front` is the front package's own namespace, taken as a comptime
/// parameter. Passing the namespace rather than importing it is what keeps
/// this package free of a `zurl` import: the front package imports no
/// protocol package, and no protocol package imports the front package, so
/// a build can leave any protocol out and a program outside this
/// repository can bring its own in.
///
/// The caller registers the result:
///
///     var fetcher: zurl_dict.Fetcher = .init(gpa, io);
///     defer fetcher.deinit();
///     try client.registerProtocol(fetcher.protocol(zurl));
///
/// `registerProtocol` teaches the url parser the scheme at the same time,
/// so `dict://h/d:hello` parses after that one call and not before.
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
        // run direct. curl carries dict through a proxy and this build
        // does not. See `Front.protocol.Unread`.
        .unread = .{ .proxy = true },
    };
}

/// The vtable for one front package. One instantiation for each `Front`,
/// and each one holds a single comptime constant, so the table lives in
/// the binary's own read-only data and never on a stack.
fn Dispatch(comptime Front: type) type {
    return struct {
        const vtable: Front.protocol.Protocol.VTable = .{ .perform = performDict };

        /// Runs one `dict://` transfer.
        ///
        /// `c` goes unread. The client holds a connection pool and a trust
        /// store, and this reads neither: RFC 2229 has no TLS in this
        /// package and the session opens and closes one socket.
        fn performDict(
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
        /// stands. Any other value is the lower of the two, because both
        /// are bounds.
        ///
        /// **`--speed-time` narrows the wait the same way.** The front
        /// package's stall guard cannot reach this transfer: `Client.perform`
        /// clears `body_stack_live` before it dispatches, and this package
        /// returns a reader over memory whose bytes are all read before
        /// `open` returns. So the guard would watch a reader that never
        /// waits. The wait that matters happens inside `open`, and the flag
        /// reaches it here instead.
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
/// build with no `zurl` in its import table at all, because a protocol
/// package that imports the front package cannot be left out of a build
/// that does not want it.
///
/// A change to `zurl.protocol.Protocol` that this stub does not follow is
/// a compile error at the call in `src/cli/run.zig`, which is where the
/// real types meet.
const StubFront = struct {
    const Client = struct {};

    const Transfer = struct {
        const Options = struct {
            connect_timeout: Io.Timeout = .none,
            low_speed_limit: u64 = 1,
            low_speed_time_s: u32 = 300,
            max_size: u64 = 0,
            tcp_no_delay: bool = true,
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

/// Parses `text` the way `zurl.Client` does, with `dict` registered.
fn parseDictUrl(text: []const u8) !zurl_core.Url {
    var schemes: zurl_core.url.Schemes = .empty;
    try schemes.add(.{ .name = scheme, .default_port = default_port });
    return zurl_core.url.parseWith(text, &schemes);
}

test {
    _ = request;
    _ = test_server;
}

test "the package names the scheme and the port RFC 2229 assigns" {
    try testing.expectEqualStrings("dict", scheme);
    try testing.expectEqual(@as(?u16, 2628), default_port);
}

test "a whole session reaches the server and the whole answer comes back" {
    var server: test_server.Server = undefined;
    try server.start(&.{
        "220 test.example dictd 1.0 <1.2.3@test>\r\n",
        "250 ok\r\n",
        "150 1 definitions retrieved\r\n151 \"hello\" wn \"WordNet\"\r\nhello\r\n.\r\n250 ok\r\n",
        "221 bye\r\n",
    });
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "dict://127.0.0.1:{d}/d:hello", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    const body = try fetcher.open(try parseDictUrl(text), .{}, null);

    // The bytes the server saw are curl's own three lines.
    try testing.expectEqualStrings(
        "CLIENT " ++ request.client_id ++ "\r\nDEFINE ! hello\r\nQUIT\r\n",
        server.received(),
    );

    // And every byte the server wrote is the body, banner and all. curl
    // does no parsing here either.
    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings(
        "220 test.example dictd 1.0 <1.2.3@test>\r\n" ++
            "250 ok\r\n" ++
            "150 1 definitions retrieved\r\n151 \"hello\" wn \"WordNet\"\r\nhello\r\n.\r\n250 ok\r\n" ++
            "221 bye\r\n",
        contents,
    );
    try testing.expectEqual(contents.len, body.length);
}

test "a url with a percent escaped control byte never forges a second line" {
    // **The injection proof.** `zurl_core.url.parse` refuses a raw CR in
    // a path, so the only way one reaches a command line is an escape.
    // The decode runs before the write, and the check runs between them.
    //
    // curl 8.21.0 refuses the same url with exit 3, `URL using
    // bad/illegal format`, measured on `dict://h/d:a%0d%0aQUIT`.
    var server: test_server.Server = undefined;
    try server.start(&.{"220 ready\r\n"});
    defer server.stop();

    var url_buffer: [96]u8 = undefined;
    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    const paths = [_][]const u8{
        "d:a%0d%0aQUIT",
        "d:a%0aSHOW%20DB",
        "d:a%0db",
        "d:a%09b",
        "d:a%00b",
        // The database field and the strategy field are the same rule.
        "d:hello:wn%0d%0aQUIT",
        "m:hello:wn:exact%0d%0aQUIT",
        // And the raw form, which writes the path straight out.
        "SHOW%0d%0aQUIT",
    };
    for (paths) |path| {
        const text = try std.fmt.bufPrint(
            &url_buffer,
            "dict://127.0.0.1:{d}/{s}",
            .{ server.port(), path },
        );
        var d: Diagnostics = .{};
        try testing.expectError(error.InvalidUrl, fetcher.open(try parseDictUrl(text), .{}, &d));
        // curl exits 3 for the same url.
        try testing.expectEqual(@as(u32, 3), d.curl_code.?);
        try testing.expect(std.mem.indexOf(u8, d.message.?, "control byte") != null);
    }

    // No url above opened a connection, so the server saw nothing at all.
    try testing.expectEqual(@as(usize, 0), server.connections());
}

test "a space and a DEL still reach the wire, escaped the way curl escapes them" {
    // The other half of the rule. A byte the escape can carry must not be
    // refused: curl sends `dict://h/d:a%20b` as `DEFINE ! a\ b`, so a
    // word with a space in it still works.
    var server: test_server.Server = undefined;
    try server.start(&.{"220 ready\r\n"});
    defer server.stop();

    var url_buffer: [96]u8 = undefined;
    const text = try std.fmt.bufPrint(
        &url_buffer,
        "dict://127.0.0.1:{d}/d:a%20b%7f",
        .{server.port()},
    );

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();
    _ = try fetcher.open(try parseDictUrl(text), .{}, null);

    try testing.expectEqualStrings(
        "CLIENT " ++ request.client_id ++ "\r\nDEFINE ! a\\ b\\\x7f\r\nQUIT\r\n",
        server.received(),
    );
}

test "an answer past the bound is refused and none of it is returned" {
    var server: test_server.Server = undefined;
    try server.start(&.{ "0123456789", "0123456789" });
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "dict://127.0.0.1:{d}/d:x", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(
        error.FileSizeExceeded,
        fetcher.open(try parseDictUrl(text), .{ .max_response_bytes = 8 }, &d),
    );
    // curl's own code for a transfer past `--max-filesize`.
    try testing.expectEqual(@as(u32, 63), d.curl_code.?);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "8 bytes") != null);
    // Nothing is held, so no part of the answer can be read afterwards.
    try testing.expectEqual(@as(?[]u8, null), fetcher.answer);
}

test "an answer of exactly the bound is read and not refused" {
    // The bound is a bound and not a fence one byte inside it.
    var server: test_server.Server = undefined;
    try server.start(&.{"01234567"});
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "dict://127.0.0.1:{d}/d:x", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    const body = try fetcher.open(try parseDictUrl(text), .{ .max_response_bytes = 8 }, null);
    try testing.expectEqual(@as(u64, 8), body.length);
}

test "a peer that does not accept a connection is curl's own exit 7" {
    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    var d: Diagnostics = .{};
    // Port 1 on the loopback address accepts nothing. Measured:
    // `curl dict://127.0.0.1:1/d:hello` exits 7.
    try testing.expectError(
        error.CouldNotConnect,
        fetcher.open(try parseDictUrl("dict://127.0.0.1:1/d:hello"), .{}, &d),
    );
    try testing.expectEqual(@as(u32, 7), d.curl_code.?);
}

test "a second open frees the answer the first one held" {
    var server: test_server.Server = undefined;
    try server.start(&.{"first answer"});
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "dict://127.0.0.1:{d}/d:x", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    _ = try fetcher.open(try parseDictUrl(text), .{}, null);
    try testing.expect(fetcher.answer != null);

    // A transfer that fails leaves nothing held either.
    try testing.expectError(
        error.CouldNotConnect,
        fetcher.open(try parseDictUrl("dict://127.0.0.1:1/d:x"), .{}, null),
    );
    try testing.expectEqual(@as(?[]u8, null), fetcher.answer);
}

test "a failure with no diagnostics still reports the error" {
    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    try testing.expectError(
        error.InvalidUrl,
        fetcher.open(try parseDictUrl("dict://127.0.0.1:1/d:a%0db"), .{}, null),
    );
    try testing.expectError(
        error.CouldNotConnect,
        fetcher.open(try parseDictUrl("dict://127.0.0.1:1/d:x"), .{}, null),
    );
}

test "a path longer than the bound is refused before any dial" {
    var long: [request.max_path_bytes + 32]u8 = undefined;
    @memset(&long, 'a');
    long[0] = '/';

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    const url: zurl_core.Url = .{
        .scheme = scheme,
        .user = null,
        .password = null,
        .host = "127.0.0.1",
        .port = 1,
        .path = &long,
        .query = null,
        .fragment = null,
    };
    var d: Diagnostics = .{};
    try testing.expectError(error.InvalidUrl, fetcher.open(url, .{}, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "longer than") != null);
}

test "protocol builds a dispatch entry that runs the whole transfer" {
    var server: test_server.Server = undefined;
    try server.start(&.{"220 ready\r\n250 ok\r\n"});
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "dict://127.0.0.1:{d}/d:hello", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    const entry = fetcher.protocol(StubFront);
    try testing.expectEqualStrings("dict", entry.scheme);
    try testing.expectEqual(@as(?u16, 2628), entry.default_port);

    var client: StubFront.Client = .{};
    const response = try entry.vtable.perform(
        entry.ptr,
        &client,
        try parseDictUrl(text),
        .{},
        null,
    );
    // Zero, the way curl reports `%{http_code}` for a `dict://` transfer.
    try testing.expectEqual(@as(u16, 0), response.status);
    try testing.expectEqual(@as(?u64, 19), response.content_length);

    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("220 ready\r\n250 ok\r\n", contents);
}

test "a peer that accepts and writes nothing ends the transfer" {
    // The hang. `socat TCP-LISTEN:2628` accepts and writes nothing, and a
    // dict answer ends only when the peer closes, so nothing in the
    // protocol ends the read. `--connect-timeout` covers the dial and
    // stops there. Without a read bound only a signal ended the process.
    var server: test_server.Server = undefined;
    try server.startSilent();
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "dict://127.0.0.1:{d}/d:x", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    var d: Diagnostics = .{};
    const options: Options = .{
        .read_timeout = .{ .duration = .{ .raw = .fromMilliseconds(200), .clock = .awake } },
    };
    try testing.expectError(
        error.OperationTimedOut,
        fetcher.open(try parseDictUrl(text), options, &d),
    );
    // Exit 28, the code curl gives a transfer that stopped moving.
    try testing.expectEqual(@as(u32, 28), d.curl_code.?);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "sent no byte") != null);
}

test "--speed-time narrows the read bound and never widens it" {
    const D = Dispatch(StubFront);
    const seconds = struct {
        fn of(t: Io.Timeout) i64 {
            return @divTrunc(t.duration.raw.toMilliseconds(), 1000);
        }
    }.of;

    // No flag: the package bound stands.
    try testing.expectEqual(
        @as(i64, default_read_timeout_s),
        seconds(D.translate(.{}).read_timeout),
    );
    // A shorter wait wins.
    try testing.expectEqual(
        @as(i64, 5),
        seconds(D.translate(.{ .low_speed_time_s = 5 }).read_timeout),
    );
    // A longer one does not. Both numbers are bounds.
    try testing.expectEqual(
        @as(i64, default_read_timeout_s),
        seconds(D.translate(.{ .low_speed_time_s = default_read_timeout_s * 4 }).read_timeout),
    );
    // `--speed-limit 0` turns curl's watchdog off. It does not leave this
    // read with no bound at all.
    try testing.expectEqual(
        @as(i64, default_read_timeout_s),
        seconds(D.translate(.{ .low_speed_limit = 0, .low_speed_time_s = 5 }).read_timeout),
    );
}

test "--max-filesize narrows the package bound and never widens it" {
    const D = Dispatch(StubFront);
    // No flag: the package bound stands.
    try testing.expectEqual(
        default_max_response_bytes,
        D.translate(.{ .max_size = 0 }).max_response_bytes,
    );
    // A lower flag wins.
    try testing.expectEqual(@as(u64, 100), D.translate(.{ .max_size = 100 }).max_response_bytes);
    // A higher flag does not. Both numbers are bounds, and a bound may
    // not widen another.
    try testing.expectEqual(
        default_max_response_bytes,
        D.translate(.{ .max_size = default_max_response_bytes * 4 }).max_response_bytes,
    );
}

test "--connect-to moves a dict dial and --resolve reaches this package too" {
    // The defect this closes: this package read no `connect_to` at all,
    // so a user who named either flag got a dial to the url's own host
    // and no diagnostic. curl 8.21.0 applies both to `dict`, measured:
    // `curl --connect-to h:2628:127.0.0.1:2628 dict://h/d:x` exits 7, the
    // refused connect, where the bare url exits 6, the name that does not
    // resolve.
    var server: test_server.Server = undefined;
    try server.start(&.{ "220 ready\r\n", "250 ok\r\n", "151 def\r\ntext\r\n.\r\n250 ok\r\n" });
    defer server.stop();

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();
    // **The url names a peer that is not the server, and no test here
    // touches a resolver.** `127.0.0.2:1` refuses at once, so the flag is
    // the only thing that can reach the server below.
    const url = try parseDictUrl("dict://127.0.0.2:1/d:hello");

    // Without an entry the dial goes where the url says and is refused.
    var bare: Diagnostics = .{};
    try testing.expectError(error.CouldNotConnect, fetcher.open(url, .{}, &bare));
    try testing.expectEqual(@as(usize, 0), server.connections());

    // With one the dial lands on the loopback server.
    const overrides: []const zurl_net.override.HostOverride = &.{.{
        .from_host = "127.0.0.2",
        .from_port = 1,
        .to_host = "127.0.0.1",
        .to_port = server.port(),
    }};
    const body = try fetcher.open(url, .{ .connect_to = overrides }, null);
    try testing.expect(body.length > 0);
    try testing.expectEqual(@as(usize, 1), server.connections());
}

test "the dict translation carries --connect-to into this package" {
    // The field is on `Options` and the dispatch must fill it. A
    // translation that dropped it would leave the flag working in a unit
    // test and doing nothing on the command line.
    const D = Dispatch(StubFront);
    const overrides: []const zurl_net.override.HostOverride = &.{.{
        .from_host = "a.test",
        .to_host = "127.0.0.1",
        .to_port = 9,
    }};
    const translated = D.translate(.{ .connect_to = overrides });
    try testing.expectEqual(@as(usize, 1), translated.connect_to.len);
    try testing.expectEqualStrings("a.test", translated.connect_to[0].from_host);

    // And a command line that named neither flag still dials the url.
    try testing.expectEqual(@as(usize, 0), D.translate(.{}).connect_to.len);
}
