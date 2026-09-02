//! Runs one `gopher://` or `gophers://` transfer: the dial, the one
//! request line, and the answer.
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
//! **One package owns both schemes.** RFC 1436 names the request and the
//! answer, and `gophers` changes neither: it puts the same two on a TLS
//! session. That is the same reason `zurl.protocol.builtins` gives `http`
//! and `https` one vtable. `protocol` and `secureProtocol` build the two
//! dispatch entries, and both point at one table that reads `url.scheme`.
//!
//! **The connection does not outlive `open`.** A gopher answer ends when
//! the peer closes, so the answer is complete when `open` returns and
//! there is nothing left to read from a socket.
//!
//! **The answer is bounded and buffered.** It carries no length, so a
//! hostile server can write forever. `Options.max_response_bytes` is the
//! bound, and a peer past it gets `error.FileSizeExceeded`, exit 63, with
//! no byte of the answer reaching the output. See that field.
//!
//! What this does not do: no menu parsing. curl writes the answer through
//! byte for byte, measured, so a caller that wants the menu rows reads
//! them out of the body itself. No `-I`, because a gopher answer has no
//! head. No connection reuse: RFC 1436 gives one connection one request.
//!
//! This file imports `zurl-core` and `zurl-net`. It does not import
//! `zurl`, and it never will. See `protocol`.

const Fetcher = @This();

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_net = @import("zurl-net");

const selector = @import("selector.zig");

const Io = std.Io;
const Error = zurl_core.Error;
const Diagnostics = zurl_core.Diagnostics;

/// The plain scheme this package handles.
pub const scheme = "gopher";

/// The encrypted scheme this package handles. Same protocol, same port, a
/// TLS session under it.
pub const secure_scheme = "gophers";

/// The port a url of either scheme uses when it names none.
///
/// 70 for both. RFC 1436 assigns it to gopher, and curl 8.21.0 dials 70
/// for `gophers://127.0.0.1/1/` as well, measured with `curl -v`.
pub const default_port: ?u16 = 70;

/// The status a gopher transfer reports.
///
/// Zero, because RFC 1436 has no status at all: a server that has nothing
/// answers with a menu row that says so, in the body. curl 8.21.0 prints
/// `000` for `%{http_code}` on a `gopher://` url that worked, measured.
pub const status: u16 = 0;

/// How many bytes of answer this package reads by default.
///
/// A gopher answer has no length on the wire: the server writes and
/// closes, so the end of the answer and the end of the socket are one
/// event. Without a bound a server that never closes holds this process
/// for as long as it likes and fills memory while it does.
///
/// 16 MiB is far past a menu and past the text files gopher was built for.
/// A server offering something larger needs this number raised, which is
/// `Options.max_response_bytes`.
///
/// curl keeps no such bound. It streams the answer and stops only when the
/// user's own `--max-filesize` says so.
pub const default_max_response_bytes: u64 = 16 * 1024 * 1024;

/// How much room the connection keeps for bytes read and not taken yet.
pub const read_buffer_len: usize = 8192;

/// How long one read of the answer may wait with no byte arriving.
///
/// **A gopher answer ends when the peer closes, so a peer that never writes
/// and never closes holds this process forever.** `--connect-timeout`
/// covers the dial and the handshake and nothing after them, and
/// `zurl_net.Connection` keeps no clock of its own.
///
/// 300 seconds is curl's own `--speed-time` default, and this is the same
/// question: how long a transfer may make no progress. `--speed-time`
/// narrows it and never widens it.
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
/// Backs the request line. A field and not a stack buffer, so the bound is
/// one named number and not a frame size.
request_storage: [selector.max_request_bytes]u8,
/// Holds the path and the query joined, still escaped.
join_storage: [selector.max_selector_bytes]u8,

/// The trust store a `gophers` session verifies against, and the way to
/// fill it.
///
/// **A `gophers` session verifies exactly as an `https` session does.**
/// The bundle here is the one the front package loads for HTTP, so a
/// `--cacert` moves both or neither. A build that leaves this null cannot
/// open a `gophers` session at all: `open` reports
/// `error.SslConnectError` and says the build gave it no trust store,
/// rather than fall back to a session that verifies nothing.
///
/// The shape matches `zurl.Client.TlsMaterials` field for field, which is
/// what `Dispatch` copies from. It is written out here because this
/// package must build with no `zurl` in its import table.
pub const Trust = struct {
    lock: *Io.RwLock,
    bundle: *std.crypto.Certificate.Bundle,
    /// Passed back to `load`.
    ptr: *anyopaque,
    /// Fills `bundle` from the sources the transfer named. Called once,
    /// before the handshake, and only for a `gophers` url.
    load: *const fn (ptr: *anyopaque) Error!void,
};

/// What one transfer may ask for.
///
/// A struct of this package's own, and not `zurl.Transfer.Options`,
/// because this package must build with no `zurl` in its import table.
/// `Dispatch` fills it from the front package's own options.
pub const Options = struct {
    /// A cap on the dial and the handshake together. `.none` waits for as
    /// long as the operating system does.
    connect_timeout: Io.Timeout = .none,
    /// The bound on the answer. See `default_max_response_bytes`.
    max_response_bytes: u64 = default_max_response_bytes,
    /// How long one read may wait with no byte arriving. See
    /// `default_read_timeout_s`.
    read_timeout: Io.Timeout = default_read_timeout,
    /// Whether to turn Nagle's algorithm off on the connection. False is
    /// `--no-tcp-nodelay`.
    tcp_no_delay: bool = true,
    /// Whether to accept a peer certificate that does not verify. This is
    /// `-k`/`--insecure`, and it reaches nothing but `tlsOptions`.
    insecure: bool = false,
    /// The lowest TLS version to keep. This is `--tlsv1.2` and
    /// `--tlsv1.3`.
    tls_min_version: zurl_core.tls.MinVersion = .floor,
    /// The highest TLS version to keep. This is `--tls-max`.
    tls_max_version: zurl_core.tls.Version = .highest,
    /// The trust store for a `gophers` session. See `Trust`.
    trust: ?Trust = null,
    /// Where a url naming one host and port dials instead. This is
    /// `--resolve` and `--connect-to`.
    ///
    /// **An entry moves the dial and nothing else.** `tlsOptions` reads
    /// `url.host` and never this, so a `gophers` peer at the dialed
    /// address must still hold a certificate for the name the url wrote.
    /// Any other reading would make this flag a way to turn verification
    /// off with no `-k`. See `zurl_net.override`.
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
        .join_storage = undefined,
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

/// The answer of one gopher transfer.
pub const Body = struct {
    /// Streams the answer. Valid until the next `open` on this `Fetcher`,
    /// or until `deinit`, whichever comes first.
    reader: *Io.Reader,
    /// How many bytes the answer holds. Always known, because the whole
    /// answer is read before this returns.
    length: u64,
    /// The item type the url named, or null when it named none. Nothing
    /// on the wire carries it, and nothing here reads it. See
    /// `selector.itemType`.
    item_type: ?u8,
};

/// Whether `url` asks for a TLS session.
///
/// The scheme and nothing else. Compared without regard to case, per RFC
/// 3986, so `GOPHERS://` is as encrypted as `gophers://`.
pub fn isSecure(url: zurl_core.Url) bool {
    return std.ascii.eqlIgnoreCase(url.scheme, secure_scheme);
}

/// Runs one transfer and returns its answer.
///
/// Frees whatever the previous call held first, so a `Fetcher` never holds
/// two answers at once.
///
/// **Every byte the server sent reaches the caller.** curl 8.21.0 writes a
/// gopher answer through with no transformation, measured against a
/// loopback server: the menu rows, their tabs, their CRLF line endings,
/// and the `.` line that ends a menu all reach standard output. So a
/// caller that wants the rows parses this text itself.
///
/// The faults, and the exit code each carries:
///
/// - a url whose decoded selector holds a NUL, a CR, or an LF is
///   `error.InvalidUrl`, exit 3. curl sends such a selector. See
///   `selector.writeRequest`.
/// - a peer that does not accept a connection is `error.CouldNotConnect`,
///   exit 7. Measured: `curl gopher://127.0.0.1:1/1/` exits 7, and
///   `gophers://127.0.0.1:1/1/` exits 7 as well.
/// - a peer certificate that does not verify is
///   `error.PeerFailedVerification`, exit 60, the same answer an `https`
///   url gets.
/// - an answer past `options.max_response_bytes` is
///   `error.FileSizeExceeded`, exit 63, and no byte of it is returned.
pub fn open(f: *Fetcher, url: zurl_core.Url, options: Options, d: ?*Diagnostics) Error!Body {
    f.release();

    const joined = selector.join(&f.join_storage, url) catch return fail(d, error.InvalidUrl, &.{
        "the selector this url names is longer than the ",
        std.fmt.comptimePrint("{d}", .{selector.max_selector_bytes}),
        " bytes zurl reads",
    });
    const item_type = selector.itemType(joined);
    const request = selector.writeRequest(
        &f.request_storage,
        selector.strip(joined),
    ) catch |err| switch (err) {
        error.SelectorTooLong => return fail(d, error.InvalidUrl, &.{
            "the selector this url names is longer than zurl writes",
        }),
        // **The injection refusal.** A CR or an LF would end the request
        // line, and a NUL is not a byte a selector may carry. See
        // `selector.writeRequest` for what curl does with the same url.
        error.SelectorHasFramingByte => return fail(d, error.InvalidUrl, &.{
            "the selector holds a NUL, a CR, or an LF, and any of the three would end the gopher request line early",
        }),
    };

    const port = url.port orelse return fail(d, error.InvalidUrl, &.{
        "a gopher url names a port, and this one names none",
    });
    // **`--resolve` and `--connect-to` move this dial and nothing else.**
    // `tlsOptions` below reads `url.host`, so a `gophers` peer at the
    // dialed address still has to hold a certificate for the name the url
    // wrote. See `zurl_net.override`.
    const target = zurl_net.override.dialTarget(options.connect_to, url.host, port);
    // A host that does not read and a host name no resolver can look up
    // are two faults, exit 3 and exit 6. See `zurl_net.errors.hostInit`.
    const host = zurl_net.tcp.Host.init(target.host) catch |err| return fail(d, zurl_net.errors.hostInit(err).err, &.{
        target.faultPrefix(err),
        target.host,
    });

    const tls = try f.tlsOptions(url, options, d);

    // **The dial and the handshake share one deadline.** A `gophers` peer
    // that completes the TCP handshake and never sends a ServerHello held
    // this transfer forever, because the bound went to the dial and the
    // handshake ran with none. `zurl_net.bounded.setup` races both halves
    // together, which is what the HTTPS path does.
    var connection: zurl_net.Connection = undefined;
    zurl_net.bounded.setup(&connection, f.io, options.connect_timeout, .{
        .allocator = f.allocator,
        .io = f.io,
        .host = host,
        .port = target.port,
        .read_buffer_len = read_buffer_len,
        .tls = tls,
        .no_delay = options.tcp_no_delay,
    }) catch |err| return reportSetup(err, url.host, d);
    // RFC 1436 gives one connection one request, so nothing keeps this
    // socket past the answer.
    defer connection.deinit();

    connection.writer().writeAll(request) catch return reportWrite(&connection, d);
    connection.flush() catch return reportWrite(&connection, d);

    // **Two bounds on one read: the size and the wait.**
    // `zurl_net.bounded.readToEnd` keeps both. The size bound stops a peer
    // that writes forever, and the wait bound stops a peer that writes
    // nothing. A gopher answer ends only when the peer closes, so the
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
            " bytes zurl reads from a gopher answer, which ends only when the peer closes",
        ),
        error.ReadFailed => return reportRead(&connection, d),
        // Exit 28, which is the code curl gives a transfer that stopped
        // moving.
        error.OperationTimedOut => return fail(d, error.OperationTimedOut, &.{
            "the gopher server sent no byte for as long as zurl waits, and a gopher answer ends only when the peer closes",
        }),
        error.ReadTimeoutUnsupported => return fail(d, error.ReadError, &.{
            "this build has no concurrency, so a gopher read cannot be bounded, and an unbounded one would wait for a peer that may never answer",
        }),
        error.Canceled => return fail(d, error.AbortedByCallback, &.{
            "the gopher read was stopped from outside",
        }),
    };

    f.answer = answer;
    f.body = .fixed(answer);
    return .{ .reader = &f.body, .length = answer.len, .item_type = item_type };
}

/// The TLS options one `gophers` hop opens with, or null for a plain
/// `gopher` hop.
///
/// **This is the one place in this package that turns peer verification
/// off, and it reads `options.insecure` and nothing else.** A function and
/// not four lines inside `open`, so a test can name both answers and prove
/// that no input other than the flag can reach the second one. This is the
/// same shape `zurl_http.h1.tlsSetup` keeps for `https`, and for the same
/// reason.
///
/// Both halves of the check go together, the way curl does it. A host name
/// check is worthless against a peer whose chain nobody trusts, and a
/// trusted chain for the wrong host is worthless too.
///
/// **A build with no trust store cannot open a `gophers` session.** The
/// `null` arm below reports `error.SslConnectError` rather than fall back
/// to `.none`, because a fallback there is exactly the hole this package
/// must not open: `gophers` would then be a way to reach a TLS session
/// with no verification at all.
///
/// The trust roots load here, before the handshake, and only for a
/// `gophers` url. A `gopher` url therefore never reads a certificate file,
/// which is what the HTTP engine does for a hop that speaks no TLS.
fn tlsOptions(
    f: *Fetcher,
    url: zurl_core.Url,
    options: Options,
    d: ?*Diagnostics,
) Error!?zurl_net.Connection.Tls {
    _ = f;
    if (!isSecure(url)) return null;

    if (options.insecure) {
        return .{
            .host = .none,
            .trust = .none,
            .min_version = options.tls_min_version,
            .max_version = options.tls_max_version,
            .alpn_protocols = &.{},
        };
    }

    const trust = options.trust orelse return fail(d, error.SslConnectError, &.{
        "this build gave the gopher package no trust store, so it cannot verify a gophers peer",
    });
    try trust.load(trust.ptr);

    return .{
        .host = .{ .explicit = url.host },
        .trust = .{ .bundle = .{ .lock = trust.lock, .bundle = trust.bundle } },
        .min_version = options.tls_min_version,
        .max_version = options.tls_max_version,
        // **No ALPN extension at all.** RFC 7301 needs a registered
        // protocol name, and gopher has none. An offer of `http/1.1` here
        // would name a protocol this hop does not speak, and a peer that
        // answered it would be answering about the wrong thing.
        .alpn_protocols = &.{},
        // `allow_truncation_attacks` keeps its default, which is false.
        // **That default is load-bearing here.** A gopher answer ends when
        // the peer closes, so a middle box that cuts the connection early
        // would otherwise hand a short answer up as a whole one, and
        // nothing in the protocol could tell the two apart. With the
        // default, a session that ends with no `close_notify` fails the
        // transfer and says so. HTTP can afford the other answer because
        // it carries its own length. This cannot.
    };
}

/// Reports a dial or handshake fault with the sentence `zurl-net` holds
/// for it.
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
        "zurl did not write the gopher request",
    });
    return fail(d, error.WriteError, &.{
        "zurl did not write the gopher request: ",
        @errorName(cause),
    });
}

/// Reports a read that did not finish.
///
/// A gopher answer ends when the peer closes, so the end of the socket is
/// not a fault here. A TLS session that ends with no `close_notify` is
/// one, and it arrives through this function: see `tlsOptions`.
fn reportRead(connection: *zurl_net.Connection, d: ?*Diagnostics) Error {
    const cause = connection.readError() orelse return fail(d, error.ReadError, &.{
        "zurl did not read the gopher answer",
    });
    return fail(d, error.ReadError, &.{
        "zurl did not read the gopher answer: ",
        @errorName(cause),
    });
}

/// Writes `parts`, one after another, into `d`'s own message storage,
/// records `err` with that message, and returns `err`.
///
/// The text goes into `Diagnostics.message_storage` because the sentence
/// names a host this package holds in a buffer it reuses, so a borrowed
/// message would read the next transfer's url. A message longer than the
/// storage loses its tail, because a diagnostic that says less is a cost
/// and one that is not written at all is a fault.
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

/// Returns the dispatch entry for the plain `gopher` scheme.
///
/// `Front` is the front package's own namespace, taken as a comptime
/// parameter. Passing the namespace rather than importing it is what keeps
/// this package free of a `zurl` import: the front package imports no
/// protocol package, and no protocol package imports the front package, so
/// a build can leave any protocol out and a program outside this
/// repository can bring its own in.
///
/// A caller that wants `gophers` too registers `secureProtocol` beside
/// this one. The two are separate entries because a dispatch table names
/// one scheme for each row, and they share one vtable because they share
/// one protocol.
///
/// **`f` must outlive every transfer the client runs on either scheme**,
/// and must not move: the entry carries `f` as its opaque pointer, and the
/// body reader points inside it.
pub fn protocol(f: *Fetcher, comptime Front: type) Front.protocol.Protocol {
    return .{
        .scheme = scheme,
        .default_port = default_port,
        .ptr = f,
        .vtable = &Dispatch(Front).vtable,
        // This package dials the origin itself and reads no proxy field,
        // so a transfer that named a proxy is refused by name rather than
        // run direct. curl carries gopher through a proxy and this build
        // does not. See `Front.protocol.Unread`.
        .unread = .{ .proxy = true },
    };
}

/// Returns the dispatch entry for the `gophers` scheme. See `protocol`.
pub fn secureProtocol(f: *Fetcher, comptime Front: type) Front.protocol.Protocol {
    return .{
        .scheme = secure_scheme,
        .default_port = default_port,
        .ptr = f,
        .vtable = &Dispatch(Front).vtable,
        // This package dials the origin itself and reads no proxy field,
        // so a transfer that named a proxy is refused by name rather than
        // run direct. curl carries gopher through a proxy and this build
        // does not. See `Front.protocol.Unread`.
        .unread = .{ .proxy = true },
    };
}

/// The vtable for one front package. One instantiation for each `Front`,
/// and each one holds a single comptime constant, so the table lives in
/// the binary's own read-only data and never on a stack.
fn Dispatch(comptime Front: type) type {
    return struct {
        const vtable: Front.protocol.Protocol.VTable = .{ .perform = performGopher };

        /// Runs one gopher transfer, plain or encrypted.
        ///
        /// `c` is read for one thing: the trust store a `gophers` session
        /// verifies against. That store is the one the front package
        /// loads for HTTP, so a program holds one set of roots and not
        /// two.
        fn performGopher(
            ptr: ?*anyopaque,
            c: *Front.Client,
            url: zurl_core.Url,
            options: Front.Transfer.Options,
            d: ?*Diagnostics,
        ) Error!Front.Response {
            const f: *Fetcher = @ptrCast(@alignCast(ptr.?));
            const body = try f.open(url, translate(c, options), d);
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
        /// package's stall guard cannot reach this transfer:
        /// `Client.perform` clears `body_stack_live` before it dispatches,
        /// and this package returns a reader over memory whose bytes are
        /// all read before `open` returns. So the guard would watch a
        /// reader that never waits. The wait that matters happens inside
        /// `open`, and the flag reaches it here instead.
        fn translate(c: *Front.Client, options: Front.Transfer.Options) Options {
            const materials = c.tlsMaterials();
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
                .insecure = options.insecure,
                .tls_min_version = options.tls_min_version,
                .tls_max_version = options.tls_max_version,
                .trust = .{
                    .lock = materials.lock,
                    .bundle = materials.bundle,
                    .ptr = materials.ptr,
                    .load = materials.load,
                },
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
/// A change to `zurl.protocol.Protocol` or to `zurl.Client.TlsMaterials`
/// that this stub does not follow is a compile error at the call in
/// `src/cli/run.zig`, which is where the real types meet.
const StubFront = struct {
    const Client = struct {
        lock: Io.RwLock = .init,
        bundle: std.crypto.Certificate.Bundle = .empty,
        loads: usize = 0,

        fn tlsMaterials(self: *Client) Trust {
            return .{
                .lock = &self.lock,
                .bundle = &self.bundle,
                .ptr = self,
                .load = countLoad,
            };
        }

        fn countLoad(ptr: *anyopaque) Error!void {
            const self: *Client = @ptrCast(@alignCast(ptr));
            self.loads += 1;
        }
    };

    const Transfer = struct {
        const Options = struct {
            connect_timeout: Io.Timeout = .none,
            low_speed_limit: u64 = 1,
            low_speed_time_s: u32 = 300,
            max_size: u64 = 0,
            tcp_no_delay: bool = true,
            connect_to: []const zurl_net.override.HostOverride = &.{},
            insecure: bool = false,
            tls_min_version: zurl_core.tls.MinVersion = .floor,
            tls_max_version: zurl_core.tls.Version = .highest,
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

/// Parses `text` the way `zurl.Client` does, with both schemes registered.
fn parseGopherUrl(text: []const u8) !zurl_core.Url {
    var schemes: zurl_core.url.Schemes = .empty;
    try schemes.add(.{ .name = scheme, .default_port = default_port });
    try schemes.add(.{ .name = secure_scheme, .default_port = default_port });
    return zurl_core.url.parseWith(text, &schemes);
}

test {
    _ = selector;
    _ = test_server;
}

test "both schemes name the same port RFC 1436 assigns" {
    try testing.expectEqualStrings("gopher", scheme);
    try testing.expectEqualStrings("gophers", secure_scheme);
    try testing.expectEqual(@as(?u16, 70), default_port);
}

test "the request line reaches the server and the whole answer comes back" {
    var server: test_server.Server = undefined;
    try server.start("0About\t/about.txt\t127.0.0.1\t70\r\n1Sub\t/sub\t127.0.0.1\t70\r\n.\r\n");
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "gopher://127.0.0.1:{d}/1/", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    const body = try fetcher.open(try parseGopherUrl(text), .{}, null);

    // The bytes the server saw are curl's own request line.
    try testing.expectEqualStrings("/\r\n", server.received());
    try testing.expectEqual(@as(?u8, '1'), body.item_type);

    // And every byte the server wrote is the body, the `.` line included.
    // curl writes a gopher answer through with no transformation.
    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings(
        "0About\t/about.txt\t127.0.0.1\t70\r\n1Sub\t/sub\t127.0.0.1\t70\r\n.\r\n",
        contents,
    );
    try testing.expectEqual(contents.len, body.length);
}

test "a url with a percent escaped line ending never forges a second request" {
    // **The injection proof.** curl 8.21.0 sends `gopher://h/1a%0d%0ab`
    // as two request lines, measured. This refuses the url and opens no
    // connection at all.
    var server: test_server.Server = undefined;
    try server.start("never written\r\n");
    defer server.stop();

    var url_buffer: [96]u8 = undefined;
    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    const paths = [_][]const u8{
        "/1a%0d%0ab",
        "/1a%0db",
        "/1a%0ab",
        "/1a%00b",
        "/1/dir%0d%0aGET%20/%20HTTP/1.0",
    };
    for (paths) |path| {
        const text = try std.fmt.bufPrint(
            &url_buffer,
            "gopher://127.0.0.1:{d}{s}",
            .{ server.port(), path },
        );
        var d: Diagnostics = .{};
        try testing.expectError(error.InvalidUrl, fetcher.open(try parseGopherUrl(text), .{}, &d));
        try testing.expectEqual(@as(u32, 3), d.curl_code.?);
        try testing.expect(std.mem.indexOf(u8, d.message.?, "CR") != null);
    }

    try testing.expectEqual(@as(usize, 0), server.connections());
}

test "a tab still reaches the wire, because a search request needs one" {
    var server: test_server.Server = undefined;
    try server.start("found\r\n");
    defer server.stop();

    var url_buffer: [96]u8 = undefined;
    const text = try std.fmt.bufPrint(
        &url_buffer,
        "gopher://127.0.0.1:{d}/7/search%09zurl",
        .{server.port()},
    );

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();
    _ = try fetcher.open(try parseGopherUrl(text), .{}, null);

    try testing.expectEqualStrings("/search\tzurl\r\n", server.received());
}

test "an empty selector is what a url with no path sends" {
    // Measured: `gopher://h/` and `gopher://h/x` both send the empty
    // line, because curl drops the leading slash and the item type.
    var server: test_server.Server = undefined;
    try server.start("root\r\n");
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "gopher://127.0.0.1:{d}/", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();
    const body = try fetcher.open(try parseGopherUrl(text), .{}, null);

    try testing.expectEqualStrings("\r\n", server.received());
    try testing.expectEqual(@as(?u8, null), body.item_type);
}

test "an answer past the bound is refused and none of it is returned" {
    var server: test_server.Server = undefined;
    try server.start("0123456789");
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "gopher://127.0.0.1:{d}/1/", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(
        error.FileSizeExceeded,
        fetcher.open(try parseGopherUrl(text), .{ .max_response_bytes = 4 }, &d),
    );
    // curl's own code for a transfer past `--max-filesize`.
    try testing.expectEqual(@as(u32, 63), d.curl_code.?);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "4 bytes") != null);
    try testing.expectEqual(@as(?[]u8, null), fetcher.answer);
}

test "an answer of exactly the bound is read and not refused" {
    var server: test_server.Server = undefined;
    try server.start("0123");
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "gopher://127.0.0.1:{d}/1/", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    const body = try fetcher.open(try parseGopherUrl(text), .{ .max_response_bytes = 4 }, null);
    try testing.expectEqual(@as(u64, 4), body.length);
}

test "a peer that does not accept a connection is curl's own exit 7" {
    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    var d: Diagnostics = .{};
    // Measured: `curl gopher://127.0.0.1:1/1/` exits 7.
    try testing.expectError(
        error.CouldNotConnect,
        fetcher.open(try parseGopherUrl("gopher://127.0.0.1:1/1/"), .{}, &d),
    );
    try testing.expectEqual(@as(u32, 7), d.curl_code.?);
}

test "gophers verifies the peer the way https does, and -k is the only way out" {
    // **The safety property of this package, checked at the one function
    // that decides it.** No real handshake runs here: this asks what
    // options a session would open with, which is the whole of the
    // decision. A live handshake would need a TLS server, and this
    // package's tests reach no network.
    var lock: Io.RwLock = .init;
    var bundle: std.crypto.Certificate.Bundle = .empty;
    var loads: usize = 0;

    const Counter = struct {
        fn load(ptr: *anyopaque) Error!void {
            const n: *usize = @ptrCast(@alignCast(ptr));
            n.* += 1;
        }
    };
    const trust: Trust = .{
        .lock = &lock,
        .bundle = &bundle,
        .ptr = &loads,
        .load = Counter.load,
    };

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    const secure = try parseGopherUrl("gophers://example.com/1/");
    const verified = (try fetcher.tlsOptions(secure, .{ .trust = trust }, null)).?;
    // The host name is checked against the url's own host, and the chain
    // against the trust store the front package loaded.
    try testing.expectEqualStrings("example.com", verified.host.explicit);
    try testing.expectEqual(&bundle, verified.trust.bundle.bundle);
    try testing.expectEqual(&lock, verified.trust.bundle.lock);
    // The roots load before the handshake, and only for a `gophers` url.
    try testing.expectEqual(@as(usize, 1), loads);

    // A plain `gopher` url opens no session and loads no roots.
    const plain = try parseGopherUrl("gopher://example.com/1/");
    try testing.expectEqual(
        @as(?zurl_net.Connection.Tls, null),
        try fetcher.tlsOptions(plain, .{ .trust = trust }, null),
    );
    try testing.expectEqual(@as(usize, 1), loads);

    // `-k` is the one input that turns the two checks off, and it turns
    // both off together.
    const insecure = (try fetcher.tlsOptions(secure, .{
        .trust = trust,
        .insecure = true,
    }, null)).?;
    try testing.expectEqual(zurl_net.Connection.HostCheck.none, insecure.host);
    try testing.expectEqual(zurl_net.Connection.TrustCheck.none, insecure.trust);
}

test "no input other than --insecure reaches a session that verifies nothing" {
    // Every other option is moved one at a time, and the verification
    // stays on for each. A build that grew a second way to reach `.none`
    // would fail here.
    var lock: Io.RwLock = .init;
    var bundle: std.crypto.Certificate.Bundle = .empty;
    const Nothing = struct {
        fn load(ptr: *anyopaque) Error!void {
            _ = ptr;
        }
    };
    var anchor: usize = 0;
    const trust: Trust = .{
        .lock = &lock,
        .bundle = &bundle,
        .ptr = &anchor,
        .load = Nothing.load,
    };

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();
    const secure = try parseGopherUrl("gophers://example.com/1/");

    const rows = [_]Options{
        .{ .trust = trust },
        .{ .trust = trust, .tcp_no_delay = false },
        .{ .trust = trust, .max_response_bytes = 1 },
        .{ .trust = trust, .tls_min_version = .tls_1_3 },
        .{ .trust = trust, .tls_max_version = .tls_1_2 },
        // A moved dial is one more input that must not reach the check.
        .{ .trust = trust, .connect_to = &.{.{ .to_host = "127.0.0.1", .to_port = 9 }} },
    };
    for (rows) |row| {
        const tls = (try fetcher.tlsOptions(secure, row, null)).?;
        try testing.expect(tls.host == .explicit);
        try testing.expect(tls.trust == .bundle);
    }
}

test "a build with no trust store refuses a gophers url instead of skipping the check" {
    // The fallback that must not exist. Without a trust store there is
    // nothing to verify against, and the answer is a refusal and never a
    // session that trusts everything.
    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    const secure = try parseGopherUrl("gophers://example.com/1/");
    var d: Diagnostics = .{};
    try testing.expectError(
        error.SslConnectError,
        fetcher.tlsOptions(secure, .{ .trust = null }, &d),
    );
    try testing.expect(std.mem.indexOf(u8, d.message.?, "no trust store") != null);

    // And `-k` with no trust store is still the user's own choice, so it
    // opens the session the flag asked for.
    const insecure = (try fetcher.tlsOptions(secure, .{ .trust = null, .insecure = true }, null)).?;
    try testing.expectEqual(zurl_net.Connection.TrustCheck.none, insecure.trust);
}

test "a gophers session offers no ALPN protocol" {
    // RFC 7301 needs a registered name and gopher has none, so the
    // extension is left out rather than filled with a name this hop does
    // not speak.
    var lock: Io.RwLock = .init;
    var bundle: std.crypto.Certificate.Bundle = .empty;
    const Nothing = struct {
        fn load(ptr: *anyopaque) Error!void {
            _ = ptr;
        }
    };
    var anchor: usize = 0;
    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    const tls = (try fetcher.tlsOptions(try parseGopherUrl("gophers://example.com/1/"), .{
        .trust = .{ .lock = &lock, .bundle = &bundle, .ptr = &anchor, .load = Nothing.load },
    }, null)).?;
    try testing.expectEqual(@as(usize, 0), tls.alpn_protocols.len);

    // And a cut session is a fault and not an end of stream. A gopher
    // answer has no length, so this default is what tells a finished
    // answer from a truncated one.
    try testing.expect(!tls.allow_truncation_attacks);
}

test "the scheme decides the transport and nothing else does" {
    try testing.expect(isSecure(try parseGopherUrl("gophers://example.com/1/")));
    try testing.expect(!isSecure(try parseGopherUrl("gopher://example.com/1/")));
    // RFC 3986 makes a scheme case-insensitive.
    try testing.expect(isSecure(try parseGopherUrl("GOPHERS://example.com/1/")));
    try testing.expect(!isSecure(try parseGopherUrl("GOPHER://example.com/1/")));
}

test "a second open frees the answer the first one held" {
    var server: test_server.Server = undefined;
    try server.start("first answer");
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "gopher://127.0.0.1:{d}/1/", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    _ = try fetcher.open(try parseGopherUrl(text), .{}, null);
    try testing.expect(fetcher.answer != null);

    try testing.expectError(
        error.CouldNotConnect,
        fetcher.open(try parseGopherUrl("gopher://127.0.0.1:1/1/"), .{}, null),
    );
    try testing.expectEqual(@as(?[]u8, null), fetcher.answer);
}

test "a failure with no diagnostics still reports the error" {
    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    try testing.expectError(
        error.InvalidUrl,
        fetcher.open(try parseGopherUrl("gopher://127.0.0.1:1/1a%0db"), .{}, null),
    );
    try testing.expectError(
        error.CouldNotConnect,
        fetcher.open(try parseGopherUrl("gopher://127.0.0.1:1/1/"), .{}, null),
    );
}

test "protocol builds two dispatch entries that share one table" {
    var server: test_server.Server = undefined;
    try server.start("menu row\r\n.\r\n");
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "gopher://127.0.0.1:{d}/1/", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    const plain = fetcher.protocol(StubFront);
    const secure = fetcher.secureProtocol(StubFront);
    try testing.expectEqualStrings("gopher", plain.scheme);
    try testing.expectEqualStrings("gophers", secure.scheme);
    try testing.expectEqual(@as(?u16, 70), plain.default_port);
    try testing.expectEqual(@as(?u16, 70), secure.default_port);
    // One protocol, one table. The scheme in the url is what tells the
    // two transports apart.
    try testing.expectEqual(plain.vtable, secure.vtable);

    var client: StubFront.Client = .{};
    const response = try plain.vtable.perform(
        plain.ptr,
        &client,
        try parseGopherUrl(text),
        .{},
        null,
    );
    try testing.expectEqual(@as(u16, 0), response.status);
    try testing.expectEqual(@as(?u64, 13), response.content_length);

    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("menu row\r\n.\r\n", contents);

    // A plain hop reads no certificate at all.
    try testing.expectEqual(@as(usize, 0), client.loads);
}

test "a peer that accepts and writes nothing ends the transfer" {
    // The hang. A gopher answer ends only when the peer closes, so nothing
    // in the protocol ends the read. `--connect-timeout` covers the dial
    // and stops there. Without a read bound only a signal ended the
    // process.
    var server: test_server.Server = undefined;
    try server.startSilent();
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "gopher://127.0.0.1:{d}/1/x", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    var d: Diagnostics = .{};
    const options: Options = .{
        .read_timeout = .{ .duration = .{ .raw = .fromMilliseconds(200), .clock = .awake } },
    };
    try testing.expectError(
        error.OperationTimedOut,
        fetcher.open(try parseGopherUrl(text), options, &d),
    );
    // Exit 28, the code curl gives a transfer that stopped moving.
    try testing.expectEqual(@as(u32, 28), d.curl_code.?);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "sent no byte") != null);
}

test "a gophers peer that never answers the hello ends the transfer" {
    // The second hang, one layer up. The peer completes the TCP handshake
    // and never sends a ServerHello. `--connect-timeout` used to reach the
    // dial alone, and the handshake after it ran with no bound at all, so
    // this transfer waited forever.
    //
    // `-k` is what lets this test run with no certificate: it turns the
    // checks off, and it does not turn the handshake off, so the wait
    // under test is the same wait.
    var server: test_server.Server = undefined;
    try server.startSilent();
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "gophers://127.0.0.1:{d}/1/x", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    var d: Diagnostics = .{};
    const options: Options = .{
        .insecure = true,
        .connect_timeout = .{ .duration = .{ .raw = .fromMilliseconds(200), .clock = .awake } },
    };
    try testing.expectError(
        error.OperationTimedOut,
        fetcher.open(try parseGopherUrl(text), options, &d),
    );
    try testing.expectEqual(@as(u32, 28), d.curl_code.?);
    // The peer accepted, so the dial itself was never the wait.
    try testing.expectEqual(@as(usize, 1), server.connections());
}

test "--speed-time narrows the read bound and never widens it" {
    var client: StubFront.Client = .{};
    const D = Dispatch(StubFront);
    const seconds = struct {
        fn of(t: Io.Timeout) i64 {
            return @divTrunc(t.duration.raw.toMilliseconds(), 1000);
        }
    }.of;

    // No flag: the package bound stands.
    try testing.expectEqual(
        @as(i64, default_read_timeout_s),
        seconds(D.translate(&client, .{}).read_timeout),
    );
    // A shorter wait wins.
    try testing.expectEqual(
        @as(i64, 5),
        seconds(D.translate(&client, .{ .low_speed_time_s = 5 }).read_timeout),
    );
    // A longer one does not. Both numbers are bounds.
    try testing.expectEqual(
        @as(i64, default_read_timeout_s),
        seconds(D.translate(&client, .{ .low_speed_time_s = default_read_timeout_s * 4 }).read_timeout),
    );
    // `--speed-limit 0` turns curl's watchdog off. It does not leave this
    // read with no bound at all.
    try testing.expectEqual(
        @as(i64, default_read_timeout_s),
        seconds(D.translate(&client, .{ .low_speed_limit = 0, .low_speed_time_s = 5 }).read_timeout),
    );
}

test "--max-filesize narrows the package bound and never widens it" {
    var client: StubFront.Client = .{};
    const D = Dispatch(StubFront);
    try testing.expectEqual(
        default_max_response_bytes,
        D.translate(&client, .{ .max_size = 0 }).max_response_bytes,
    );
    try testing.expectEqual(
        @as(u64, 100),
        D.translate(&client, .{ .max_size = 100 }).max_response_bytes,
    );
    try testing.expectEqual(
        default_max_response_bytes,
        D.translate(&client, .{ .max_size = default_max_response_bytes * 4 }).max_response_bytes,
    );

    // And `-k` travels from the front package's options and nowhere else.
    try testing.expect(!D.translate(&client, .{}).insecure);
    try testing.expect(D.translate(&client, .{ .insecure = true }).insecure);

    // `--connect-to` travels the same way. A translation that dropped it
    // would leave the flag working in a unit test and doing nothing on
    // the command line.
    const overrides: []const zurl_net.override.HostOverride = &.{.{
        .from_host = "a.test",
        .to_host = "127.0.0.1",
        .to_port = 9,
    }};
    try testing.expectEqual(@as(usize, 0), D.translate(&client, .{}).connect_to.len);
    const carried = D.translate(&client, .{ .connect_to = overrides });
    try testing.expectEqual(@as(usize, 1), carried.connect_to.len);
    try testing.expectEqualStrings("a.test", carried.connect_to[0].from_host);
}

test "--connect-to moves a gopher dial and --resolve reaches this package too" {
    // The defect this closes: this package read no `connect_to`, so a
    // user who named either flag got a dial to the url's own host and no
    // diagnostic. curl 8.21.0 applies both to `gopher`, measured.
    //
    // **No test here touches a resolver.** The url names `127.0.0.2:1`,
    // which refuses at once, so the flag is the only thing that can reach
    // the server below.
    var server: test_server.Server = undefined;
    try server.start("iline\tfake\t(NULL)\t0\r\n.\r\n");
    defer server.stop();

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();
    const url = try parseGopherUrl("gopher://127.0.0.2:1/1/");

    var bare: Diagnostics = .{};
    try testing.expectError(error.CouldNotConnect, fetcher.open(url, .{}, &bare));
    try testing.expectEqual(@as(usize, 0), server.connections());

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

test "a moved dial leaves a gophers certificate checked against the url's own name" {
    // **The rule that keeps this flag from becoming a second `-k`.** The
    // dial goes to the address the entry names, and the certificate is
    // still checked against the name the url wrote. A peer at the dialed
    // address that holds a certificate for itself and not for the url's
    // host therefore fails the check, exactly as it would with no flag.
    var lock: Io.RwLock = .init;
    var bundle: std.crypto.Certificate.Bundle = .empty;
    const Nothing = struct {
        fn load(ptr: *anyopaque) Error!void {
            _ = ptr;
        }
    };
    var anchor: usize = 0;
    const trust: Trust = .{
        .lock = &lock,
        .bundle = &bundle,
        .ptr = &anchor,
        .load = Nothing.load,
    };

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();
    const secure = try parseGopherUrl("gophers://example.com/1/");

    const overrides: []const zurl_net.override.HostOverride = &.{.{
        .from_host = "example.com",
        .from_port = default_port.?,
        .to_host = "127.0.0.1",
        .to_port = 9999,
    }};

    // The entry does move the dial.
    const target = zurl_net.override.dialTarget(overrides, secure.host, secure.port.?);
    try testing.expectEqualStrings("127.0.0.1", target.host);
    try testing.expectEqual(@as(u16, 9999), target.port);

    // And it reaches neither the name nor the trust decision.
    const tls = (try fetcher.tlsOptions(secure, .{
        .trust = trust,
        .connect_to = overrides,
    }, null)).?;
    try testing.expect(tls.host == .explicit);
    try testing.expectEqualStrings("example.com", tls.host.explicit);
    try testing.expect(tls.trust == .bundle);
}
