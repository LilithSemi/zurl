//! Runs one `rtsp://` transfer: the dial, one request, and its reply.
//!
//! A `Fetcher` owns the answer of the transfer in play. `open` frees
//! whatever the last call left and holds the new answer, so one `Fetcher`
//! serves one transfer at a time, the same rule `zurl.Client` keeps for
//! its own HTTP exchange.
//!
//! **A `Fetcher` must not move once `open` has run.** The body reader it
//! hands back points into this value, and so do the head block and the
//! request buffer.
//!
//! **One scheme, and no TLS twin.** RFC 2326 registers `rtsp` and
//! `rtspu`, which is RTSP over UDP, and neither is a TLS scheme. RFC 7826
//! adds `rtsps` for RTSP 2.0, which this build does not speak, and curl
//! 8.21.0 carries no `rtsps` at all: its `--version` line lists `rtsp` and
//! nothing else, measured. So this package registers one scheme.
//!
//! ## What curl does, measured, and what this build does instead
//!
//! Every measurement below came off curl 8.21.0 through a `socat -x -v`
//! relay in front of a real mediamtx 1.18.2 on loopback.
//!
//! **curl's command line cannot change the RTSP method.** It sent
//! `OPTIONS * RTSP/1.0` for every url and every flag: for
//! `rtsp://host/stream`, for `rtsp://host/nosuch`, for `-X DESCRIBE`, and
//! for `-X OPTIONS`. `-X` reaches `CURLOPT_CUSTOMREQUEST`, which the RTSP
//! code does not read, and `curl --help all` names no `--rtsp-request`,
//! `--rtsp-session-id`, `--rtsp-stream-uri`, or `--rtsp-transport`: those
//! four are `CURLOPT_RTSP_*` options a program sets through libcurl and
//! not flags a person types.
//!
//! **This build makes those four flags.** `-X` and `--rtsp-request` both
//! name the method, and the other three fill the headers they name. That
//! is a larger surface than curl's command line and the same surface
//! libcurl already has, so a script written against libcurl's options maps
//! across. The default with no flag at all is `OPTIONS *`, which is curl's
//! whole behaviour, so `zurl rtsp://host/stream` puts the same bytes on
//! the wire that `curl rtsp://host/stream` does.
//!
//! **What curl does carry through, this carries too.** `-H` reached the
//! wire: `Accept: application/sdp` and `Require: x` both went out.
//! `-u u:p` became `Authorization: Basic dTpw`. `-i` printed the reply
//! head. `-x` was tried as a proxy, and curl exited 7 when it could not
//! reach one.
//!
//! **`-d` reaches nothing in curl and reaches a body here.** Measured,
//! `curl -d 'param: v' rtsp://host/stream` still sent `OPTIONS *` with no
//! body at all. RFC 2326 sections 10.8 and 10.9 give `GET_PARAMETER` and
//! `SET_PARAMETER` a body, so `-d` fills it for those two and is refused
//! by name beside any other method: a server that read a body after a
//! `PLAY` would be reading the next request.
//!
//! ## What this build does not do
//!
//! - **No interleaved binary data.** RFC 2326 section 10.12 lets a server
//!   put RTP on the control connection behind a `$` marker. This build
//!   asks for no interleaved transport, and a `$` that arrives anyway is
//!   `error.WeirdServerReply` by name rather than read as a status line.
//!   See `zurl_rtsp.Session.interleave_marker`.
//! - **No RTP or RTCP at all.** A `PLAY` starts a stream that arrives on
//!   another socket this build does not open. The reply to the `PLAY` is
//!   the whole of what a transfer returns, and `--rtsp-transport` names a
//!   transport the caller has arranged elsewhere.
//! - **No session state across transfers.** One transfer is one request,
//!   so a `SETUP` and the `PLAY` after it are two runs of zurl. The
//!   `Session` header the `SETUP` reply carried is on `Body.session`, and
//!   the next run passes it back with `--rtsp-session-id`. curl's own
//!   command line cannot do this at all, because it cannot send a `SETUP`.
//! - **No `ANNOUNCE` and no `RECORD`.** See `zurl_rtsp.method.refusal`.
//! - **No `401` challenge answered.** `-u` sends a preemptive `Basic`, the
//!   way curl does, and a `401` comes back to the caller unanswered.
//! - **No redirect followed.** RFC 2326 section 11.3.2 gives RTSP a `302`,
//!   and following one would send the credential to a host the **server**
//!   chose.
//! - **No proxy.** curl tries one and this build does not, so a transfer
//!   that named a proxy is refused by name with exit 4 rather than
//!   connected direct. See `protocol`.
//!
//! This file imports `zurl-core` and `zurl-net`. It does not import
//! `zurl`, and it never will. See `protocol`.

const Fetcher = @This();

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_net = @import("zurl-net");

const method = @import("method.zig");
const reply = @import("reply.zig");
const request = @import("request.zig");
const target = @import("target.zig");
const Session = @import("Session.zig");

const Io = std.Io;
const Error = zurl_core.Error;
const Diagnostics = zurl_core.Diagnostics;

/// The scheme this package handles.
pub const scheme = "rtsp";

/// The port an `rtsp://` url uses when it names none.
///
/// 554, RFC 2326 section 3.2, which is what curl dials, measured with
/// `curl -v`.
pub const default_port: ?u16 = target.default_port;

/// The method a transfer sends when nobody names one.
///
/// `OPTIONS`, which is curl's own default and the only thing curl's
/// command line can send. See the module comment.
pub const default_method: method.Method = .options;

/// How many bytes of reply body this package reads by default.
///
/// A `DESCRIBE` answers with an SDP description, which is a few kilobytes
/// at most. 16 MiB is the number every other non-HTTP package here keeps,
/// and `--max-filesize` narrows it.
pub const default_max_body_bytes: u64 = 16 * 1024 * 1024;

/// How many bytes of request body this package sends.
///
/// A `SET_PARAMETER` body is a short list of assignments. 1 MiB is far
/// past that, and a `-d` longer than it is `error.FileSizeExceeded`.
pub const max_request_body_bytes: u64 = 1024 * 1024;

/// How much room the connection keeps for bytes read and not taken yet.
pub const read_buffer_len: usize = 16384;

/// How long one read may wait with no byte arriving.
///
/// **Every wait an RTSP transfer makes needs this.** A reply ends at an
/// empty line the server chooses to send, and `--connect-timeout` covers
/// the dial and nothing after it.
///
/// 300 seconds is curl's own `--speed-time` default, and this is the same
/// question. `--speed-time` narrows it and never widens it.
pub const default_read_timeout_s: u32 = 300;

/// `default_read_timeout_s`, as a `std.Io.Timeout`.
pub const default_read_timeout: Io.Timeout = .{
    .duration = .{ .raw = .fromSeconds(default_read_timeout_s), .clock = .awake },
};

/// The user agent this build names when the caller names none.
pub const default_user_agent = "zurl/0.1";

/// The target an `OPTIONS` names when nobody names a stream uri.
///
/// `*`, RFC 2326 section 10.1, which says the request is about the server
/// and not about one stream. curl writes it for every rtsp url it is
/// given, measured, whatever the path of that url is.
pub const server_target = "*";

/// The media type a `DESCRIBE` asks for.
///
/// RFC 2326 section 10.2 makes SDP the description format every RTSP
/// server writes, and libcurl's own `rtsp.c` sends this header for a
/// `DESCRIBE`. A caller that wants another one names it with `-H`, and
/// then this build sends the caller's and not its own.
pub const describe_accept = "application/sdp";

/// The header names this build writes itself.
///
/// **A caller's own `-H` of any of these wins, and this build then writes
/// none of its own.** Two headers of one name let a server read whichever
/// it likes, and for `Session` or `Authorization` that is a server picking
/// which credential to believe.
const owned_headers = [_][]const u8{
    "CSeq",
    "User-Agent",
    "Session",
    "Transport",
    "Authorization",
    "Accept",
    "Content-Type",
    "Content-Length",
};

/// Where a credential came from.
pub const CredentialSource = enum {
    /// The user name and password in the url itself.
    userinfo,
    /// `Transfer.Options.credentials`, which `-u` fills.
    options,
    /// A `machine` or a `default` entry of the netrc text.
    netrc,
    /// A caller's own `-H Authorization`.
    header,
    /// Nobody named one, so no `Authorization` went out.
    none,

    /// Names this source for a message to a user. Names the source and
    /// never the credential, which is a secret.
    pub fn describe(s: CredentialSource) []const u8 {
        return switch (s) {
            .userinfo => "the user name and password in the url",
            .options => "the -u option",
            .netrc => "the netrc file",
            .header => "an Authorization header the caller wrote",
            .none => "no credential at all",
        };
    }
};

/// One header a caller asked to be sent.
///
/// `std.http.Header` itself, and not a copy of its shape. RTSP borrows
/// RFC 2616's header grammar whole, so the type that names an HTTP header
/// names an RTSP one, and a copy here would be a second type the front
/// package would have to convert into.
pub const Header = std.http.Header;

/// Where the body of a request comes from.
///
/// The shape of `zurl.Transfer.Body`, written out here because this
/// package must build with no `zurl` in its import table.
pub const Source = struct {
    /// How many bytes `read` produces in total, or null when the count is
    /// not known before the body goes out.
    len: ?u64,
    /// The state `read` acts on.
    ctx: *anyopaque,
    /// Fills up to `len` bytes of `buffer` and returns how many bytes it
    /// wrote. Zero says the body has ended, and a negative value says the
    /// source could not be read.
    read: *const fn (ctx: *anyopaque, buffer: [*]u8, len: usize) callconv(.c) isize,
    /// The media type the caller named for this body, or null.
    content_type: ?[]const u8 = null,
};

/// What one transfer may ask for.
pub const Options = struct {
    /// A cap on the dial.
    connect_timeout: Io.Timeout = .none,
    /// The bound on the reply body. See `default_max_body_bytes`.
    max_body_bytes: u64 = default_max_body_bytes,
    /// How long one read may wait with no byte arriving.
    read_timeout: Io.Timeout = default_read_timeout,
    /// Whether to turn Nagle's algorithm off. False is `--no-tcp-nodelay`.
    tcp_no_delay: bool = true,
    /// The method to send, as the text a user typed. Null sends
    /// `default_method`.
    ///
    /// **Text and not a `method.Method`**, because the front package hands
    /// this field over and the front package must not import this one. A
    /// name this build does not send is refused by `resolveMethod`, before
    /// any dial.
    method_name: ?[]const u8 = null,
    /// The uri the request line names, from `--rtsp-stream-uri`. Null
    /// builds one out of the url. See `resolveTarget`.
    stream_uri: ?[]const u8 = null,
    /// The `Session` header value, from `--rtsp-session-id`.
    session_id: ?[]const u8 = null,
    /// The `Transport` header value, from `--rtsp-transport`.
    transport: ?[]const u8 = null,
    /// The headers `-H` named.
    headers: []const Header = &.{},
    /// The credential `-u` named, or null.
    credentials: ?zurl_core.auth.Credentials = null,
    /// The text of a netrc file the caller already read, or null.
    netrc_text: ?[]const u8 = null,
    /// The body of the request, or null.
    body: ?Source = null,
    /// The `User-Agent` value. Empty sends none at all.
    user_agent: []const u8 = default_user_agent,
    /// Whether a reply outside the 200 range fails the transfer. This is
    /// `-f`/`--fail`, and the front package reads it for HTTP.
    fail_on_error: bool = false,
    /// Where a url naming one host and port dials instead. This is
    /// `--resolve` and `--connect-to`.
    ///
    /// **An entry moves the dial and nothing else.** The request line and
    /// every header are built from the url, so an entry reaches none of
    /// them. This package speaks no TLS at all, so there is no certificate
    /// name to keep either. See `zurl_net.override`.
    connect_to: []const zurl_net.override.HostOverride = &.{},
};

allocator: std.mem.Allocator,
io: Io,
/// The body of the reply in play, or null when none is held.
answer: ?[]u8,
/// Reads `answer`. Valid only while a transfer's answer is held.
body: Io.Reader,
/// The request dialogue.
session: Session,
/// Builds the one request head this transfer sends.
request_writer: request.Writer,
/// Holds the target the request line names.
target_storage: target.Storage,
/// Holds the `Authorization` value `-u` builds.
authorization_storage: [max_authorization_bytes]u8,
/// Holds the `Session` value a reply carried, for `Body.session`.
session_storage: [max_session_id_bytes]u8,
session_len: usize,

/// How many bytes of `Authorization` value this package writes.
///
/// A `Basic` value is the base64 of "user:password", so a credential of
/// 1024 bytes each way needs a little over 2732 for the value and the
/// scratch the encoder wants. 4096 covers both with room to spare.
pub const max_authorization_bytes: usize = 4096;

/// How many bytes of `Session` identifier this package keeps.
///
/// RFC 2326 section 3.4 makes a session identifier at least eight
/// characters and sets no ceiling. 256 is far past any server's.
pub const max_session_id_bytes: usize = 256;

/// How many bytes of credential this package sends.
pub const max_credential_bytes: usize = 1024;

/// Starts `f` in place.
///
/// In place, and not a value returned, because the buffers above come to
/// tens of kilobytes and the head a caller holds points into them.
pub fn init(f: *Fetcher, allocator: std.mem.Allocator, io: Io) void {
    f.allocator = allocator;
    f.io = io;
    f.answer = null;
    f.body = .fixed("");
    f.request_writer = .{};
    f.session_len = 0;
    // The session gets its channel at the dial. Its numbers and its clock
    // are set here so a caller that reads them before a transfer reads the
    // values a transfer would start with.
    f.session.io = io;
    f.session.stall = default_read_timeout;
    f.session.next_cseq = Session.first_cseq;
    f.session.head_len = 0;
}

/// A `Fetcher` on the heap, ready to use. The caller frees it with
/// `destroy`.
pub fn create(allocator: std.mem.Allocator, io: Io) std.mem.Allocator.Error!*Fetcher {
    const f = try allocator.create(Fetcher);
    f.init(allocator, io);
    return f;
}

/// Frees a `Fetcher` that `create` made.
pub fn destroy(f: *Fetcher) void {
    const allocator = f.allocator;
    f.deinit();
    allocator.destroy(f);
}

/// Frees what this `Fetcher` holds. Safe to call more than once, and safe
/// on a `Fetcher` that never opened anything.
pub fn deinit(f: *Fetcher) void {
    f.release();
    f.wipe();
}

/// Frees the reply body.
fn release(f: *Fetcher) void {
    const held = f.answer orelse return;
    f.allocator.free(held);
    f.answer = null;
    f.body = .fixed("");
}

/// Zeroes every buffer that held a credential.
fn wipe(f: *Fetcher) void {
    std.crypto.secureZero(u8, &f.authorization_storage);
    // The request head carried the `Authorization` line.
    std.crypto.secureZero(u8, f.request_writer.bytes[0..f.request_writer.len]);
    std.crypto.secureZero(u8, &f.request_writer.line_storage);
    f.request_writer.reset();
}

/// The answer of one RTSP transfer.
pub const Body = struct {
    /// Streams the reply body. Valid until the next `open` on this
    /// `Fetcher`, or until `deinit`, whichever comes first.
    reader: *Io.Reader,
    /// How many bytes the reply body holds.
    length: u64,
    /// The status code of the reply. curl reports this as
    /// `%{http_code}`, measured: an `OPTIONS` that worked printed `200`.
    status: u16,
    /// The whole reply head, the status line through the empty line, with
    /// its `CRLF` line endings. This is what `-i` prints.
    ///
    /// Points into the session's own storage, so it is valid for as long
    /// as `reader` is.
    head: []const u8,
    /// The `Session` identifier the reply carried, or null. A `SETUP`
    /// reply carries one, and the next run passes it back with
    /// `--rtsp-session-id`.
    session: ?[]const u8,
    /// The `CSeq` the request carried.
    cseq: u64,
};

/// Runs one transfer and returns its answer.
///
/// Frees whatever the previous call held first, so a `Fetcher` never holds
/// two answers at once.
///
/// The faults, and the exit code each carries:
///
/// - a url or a flag this build will not send is `error.InvalidUrl`, exit
///   3, and no socket opens at all.
/// - a method this build does not send is `error.NotBuiltIn`, exit 4. See
///   `zurl_rtsp.method.refusal`.
/// - a part of the request holding a NUL, a CR, or an LF is
///   `error.InvalidUrl`, exit 3, and no socket opens. See
///   `zurl_rtsp.request`.
/// - a peer that does not accept a connection is `error.CouldNotConnect`,
///   exit 7.
/// - a reply this build cannot read, a reply carrying another request's
///   `CSeq`, and an interleaved frame are each
///   `error.WeirdServerReply`, exit 8.
/// - a reply body past `options.max_body_bytes` is
///   `error.FileSizeExceeded`, exit 63.
/// - a reply outside the 200 range under `-f` is
///   `error.HttpReturnedError`, exit 22, which is what curl gives an HTTP
///   url under the same flag.
pub fn open(f: *Fetcher, url: zurl_core.Url, options: Options, d: ?*Diagnostics) Error!Body {
    f.release();
    f.session_len = 0;
    // **Every transfer starts its numbers over at one**, because every
    // transfer opens its own connection. curl does the same: measured, the
    // first request of each run carried `CSeq: 1`.
    f.session.next_cseq = Session.first_cseq;
    // The request head held the `Authorization` line, so it is zeroed on
    // every path out.
    defer f.wipe();

    const verb = try resolveMethod(options, d);

    // **Everything the request needs is built before anything is dialed.**
    // A flag that could forge a header and a body that cannot be read each
    // cost no connection and send no credential.
    const line_target = try f.resolveTarget(url, verb, options, d);

    var payload: []u8 = &.{};
    defer if (payload.len != 0) f.allocator.free(payload);
    if (options.body) |source| {
        if (!verb.takesBody()) return fail(d, error.InvalidUrl, &.{
            "a body was given for an rtsp ",
            verb.text(),
            ", and RFC 2326 gives a body to GET_PARAMETER and SET_PARAMETER alone, so a server would read it as the request after this one",
        });
        payload = try f.readPayload(source, d);
    }

    var credential_source: CredentialSource = .none;
    const authorization = try f.resolveAuthorization(url, options, &credential_source, d);

    const cseq = f.session.takeCseq() catch return fail(d, error.WeirdServerReply, &.{
        "this rtsp session has sent every sequence number zurl writes",
    });
    try f.buildRequest(verb, line_target, cseq, authorization, payload, options, d);

    const port = url.port orelse return fail(d, error.InvalidUrl, &.{
        "an rtsp url names a port, and this one names none",
    });
    // **`--resolve` and `--connect-to` move this dial and nothing else.**
    // The request line and the `Session` header are built above, from the
    // url, so an entry reaches neither. See `zurl_net.override`.
    const target_peer = zurl_net.override.dialTarget(options.connect_to, url.host, port);
    // A host that does not read and a host name no resolver can look up
    // are two faults, exit 3 and exit 6. See `zurl_net.errors.hostInit`.
    const host = zurl_net.tcp.Host.init(target_peer.host) catch |err| return fail(d, zurl_net.errors.hostInit(err).err, &.{
        target_peer.faultPrefix(err),
        target_peer.host,
    });

    var connection: zurl_net.Connection = undefined;
    zurl_net.bounded.setup(&connection, f.io, options.connect_timeout, .{
        .allocator = f.allocator,
        .io = f.io,
        .host = host,
        .port = target_peer.port,
        .read_buffer_len = read_buffer_len,
        // **No TLS.** See the module comment: there is no `rtsps` here and
        // curl carries none either.
        .tls = null,
        .no_delay = options.tcp_no_delay,
    }) catch |err| return reportSetup(err, url.host, d);
    // RFC 2326 keeps a connection across requests and this build sends
    // one, so nothing holds this socket past the reply.
    defer connection.deinit();

    // The session keeps its own numbers across the dial, so the `CSeq`
    // above is the one this request carries.
    f.session.channel = .{
        .reader = connection.reader(),
        .writer = connection.writer(),
        .ctx = &connection,
        .flush = flushConnection,
    };
    f.session.io = f.io;
    f.session.stall = options.read_timeout;

    f.session.send(f.request_writer.written(), payload) catch
        return reportWrite(&connection, d);

    const answer = f.session.receive(cseq, options.max_body_bytes) catch |err|
        return fail(d, receiveErrorOf(err), &.{Session.describe(err)});

    if (answer.head.session) |named| {
        const n = @min(f.session_storage.len, named.len);
        @memcpy(f.session_storage[0..n], named[0..n]);
        f.session_len = n;
    }

    // **The body is read before the status is judged**, so `-f` still
    // leaves the connection in a state this build understands, and so a
    // failing reply's own explanation is available to a caller that wants
    // it.
    if (answer.head.content_length != 0) {
        const held = f.allocator.alloc(u8, @intCast(answer.head.content_length)) catch
            return Diagnostics.record(d, error.OutOfMemory, .{});
        errdefer f.allocator.free(held);
        f.session.readBody(held) catch |err| return fail(d, readErrorOf(err), &.{
            bodyFaultOf(err),
        });
        f.answer = held;
        f.body = .fixed(held);
    }

    if (options.fail_on_error and !answer.status.ok()) {
        return failStatus(d, answer.status);
    }

    return .{
        .reader = &f.body,
        .length = answer.head.content_length,
        .status = answer.status.code,
        .head = answer.head_block,
        .session = if (f.session_len == 0) null else f.session_storage[0..f.session_len],
        .cseq = cseq,
    };
}

/// The method this transfer sends.
///
/// **A name this build does not send is `error.NotBuiltIn`, exit 4**,
/// which is curl's code for a feature a build does not carry, and the
/// sentence names what the method does and why it is refused.
/// `zurl_rtsp.method.refusal` holds the sentences.
fn resolveMethod(options: Options, d: ?*Diagnostics) Error!method.Method {
    const name = options.method_name orelse return default_method;
    if (method.parse(name)) |verb| return verb;
    return fail(d, error.NotBuiltIn, &.{
        "zurl does not send the rtsp request this url asked for: ",
        method.refusal(name) orelse "it is not a method RFC 2326 section 10 names",
    });
}

/// The uri the request line names.
///
/// `--rtsp-stream-uri` first, because a `SETUP` names a track inside a
/// stream and no url can say which one. Then `*` for an `OPTIONS`, which
/// is what curl writes for every rtsp url, measured. Then the url itself,
/// rebuilt absolute.
fn resolveTarget(
    f: *Fetcher,
    url: zurl_core.Url,
    verb: method.Method,
    options: Options,
    d: ?*Diagnostics,
) Error![]const u8 {
    if (options.stream_uri) |named| {
        if (named.len == 0) return fail(d, error.InvalidUrl, &.{
            "--rtsp-stream-uri names an empty uri",
        });
        if (named.len > f.target_storage.len) return failNumber(
            d,
            error.InvalidUrl,
            "--rtsp-stream-uri is longer than the ",
            target.max_target_bytes,
            " bytes zurl writes on an rtsp request line",
        );
        @memcpy(f.target_storage[0..named.len], named);
        return f.target_storage[0..named.len];
    }

    if (verb.allowsAsterisk()) return server_target;

    return target.build(&f.target_storage, url) catch |err|
        return fail(d, error.InvalidUrl, &.{target.describe(err)});
}

/// Builds the whole request head into `f.request_writer`.
///
/// **Every part goes through `zurl_rtsp.request`, which is the gate.** A
/// refusal here happens before the dial, so a flag that could forge a
/// header costs no connection.
fn buildRequest(
    f: *Fetcher,
    verb: method.Method,
    line_target: []const u8,
    cseq: u64,
    authorization: ?[]const u8,
    payload: []const u8,
    options: Options,
    d: ?*Diagnostics,
) Error!void {
    f.request_writer.reset();
    const w = &f.request_writer;

    w.requestLine(verb, line_target) catch |err| return reportRequest(err, d);
    w.headerNumber(reply.cseq_header, cseq) catch |err| return reportRequest(err, d);

    if (options.user_agent.len != 0 and !namesHeader(options.headers, "User-Agent")) {
        w.header("User-Agent", options.user_agent) catch |err| return reportRequest(err, d);
    }

    if (options.session_id) |id| {
        if (!namesHeader(options.headers, reply.session_header)) {
            w.header(reply.session_header, id) catch |err| return reportRequest(err, d);
        }
    }

    // **A `SETUP` with no transport is refused rather than sent.** RFC
    // 2326 section 12.39 makes `Transport` required on a `SETUP`, and a
    // server answers one without it with 461. Inventing a transport here
    // would name a UDP port this build never opens, so the request would
    // set up a stream that goes nowhere.
    if (options.transport) |spec| {
        if (!namesHeader(options.headers, "Transport")) {
            w.header("Transport", spec) catch |err| return reportRequest(err, d);
        }
    } else if (verb == .setup and !namesHeader(options.headers, "Transport")) {
        return fail(d, error.InvalidUrl, &.{
            "an rtsp SETUP names a transport, RFC 2326 section 12.39, and none was given: use --rtsp-transport",
        });
    }

    if (verb == .describe and !namesHeader(options.headers, "Accept")) {
        w.header("Accept", describe_accept) catch |err| return reportRequest(err, d);
    }

    if (authorization) |value| {
        if (!namesHeader(options.headers, "Authorization")) {
            w.header("Authorization", value) catch |err| return reportRequest(err, d);
        }
    }

    if (payload.len != 0) {
        const content_type = if (options.body) |source| source.content_type else null;
        if (content_type) |kind| {
            if (!namesHeader(options.headers, "Content-Type")) {
                w.header("Content-Type", kind) catch |err| return reportRequest(err, d);
            }
        }
        // **`Content-Length` is written here and nowhere else.** A caller
        // that wrote one with `-H` would give a server two, and a server
        // that read the caller's would read the request after this one as
        // part of this body.
        if (namesHeader(options.headers, "Content-Length")) return fail(d, error.InvalidUrl, &.{
            "a Content-Length header was given with a body, and zurl writes that header itself: two of them let a server read the next request as part of this body",
        });
        w.headerNumber("Content-Length", payload.len) catch |err| return reportRequest(err, d);
    }

    for (options.headers) |one| {
        w.header(one.name, one.value) catch |err| return reportRequest(err, d);
    }

    w.end() catch |err| return reportRequest(err, d);
}

/// Whether the caller's own headers name `name`.
fn namesHeader(headers: []const Header, name: []const u8) bool {
    for (headers) |one| {
        if (std.ascii.eqlIgnoreCase(one.name, name)) return true;
    }
    return false;
}

/// The `Authorization` value this request carries, or null for none.
///
/// The url's userinfo first, then `-u`, then a netrc entry for the url's
/// host. That is the order `zurl.authorize` keeps for HTTP and the order
/// curl keeps here: measured, `-u u:p` reached the wire as
/// `Authorization: Basic dTpw`.
///
/// **A caller's own `-H Authorization` wins over all three**, and this
/// build then writes none of its own, which is what curl does with a
/// `-H Authorization`.
///
/// **The value is preemptive `Basic` and nothing else.** A `401` that
/// comes back is returned to the caller unanswered. See the module
/// comment.
fn resolveAuthorization(
    f: *Fetcher,
    url: zurl_core.Url,
    options: Options,
    source: *CredentialSource,
    d: ?*Diagnostics,
) Error!?[]const u8 {
    if (namesHeader(options.headers, "Authorization")) {
        source.* = .header;
        return null;
    }

    var decoded: [max_credential_bytes * 2]u8 = undefined;
    // The scratch above holds a password in the clear on its way to the
    // encoder, so it is zeroed before this returns on every path.
    defer std.crypto.secureZero(u8, &decoded);

    const credential: zurl_core.auth.Credentials = found: {
        if (url.user) |raw_user| {
            source.* = .userinfo;
            if (raw_user.len > max_credential_bytes) return failCredentialSize(d);
            const user = zurl_core.url.percentDecode(
                decoded[0..raw_user.len],
                raw_user,
            ) catch return fail(d, error.InvalidUrl, &.{
                "the user name in this url holds a percent escape that is not an escape",
            });

            const password = if (url.password) |raw_password| pw: {
                if (raw_password.len > max_credential_bytes) return failCredentialSize(d);
                break :pw zurl_core.url.percentDecode(
                    decoded[max_credential_bytes..][0..raw_password.len],
                    raw_password,
                ) catch return fail(d, error.InvalidUrl, &.{
                    "the password in this url holds a percent escape that is not an escape",
                });
            } else "";

            break :found .{ .user = user, .password = password };
        }

        if (options.credentials) |c| {
            source.* = .options;
            break :found c;
        }

        if (options.netrc_text) |text| {
            if (zurl_core.netrc.lookup(text, url.host)) |entry| {
                source.* = .netrc;
                break :found .{
                    .user = entry.login orelse "",
                    .password = entry.password orelse "",
                };
            }
        }

        source.* = .none;
        return null;
    };

    if (credential.user.len > max_credential_bytes or
        credential.password.len > max_credential_bytes)
    {
        return failCredentialSize(d);
    }

    const value = zurl_core.auth.basicValue(&f.authorization_storage, credential) catch
        return failCredentialSize(d);
    return value;
}

/// Reads the whole request body into memory.
///
/// **Bounded before it is read and again while it is read.** A source that
/// names its own length is checked before a byte is taken, and a source
/// with no length is checked on every chunk.
fn readPayload(f: *Fetcher, source: Source, d: ?*Diagnostics) Error![]u8 {
    if (source.len) |named| {
        if (named > max_request_body_bytes) return failNumber(
            d,
            error.FileSizeExceeded,
            "the body is larger than the ",
            max_request_body_bytes,
            " bytes zurl sends in one rtsp request",
        );
    }

    var raw: std.ArrayList(u8) = .empty;
    errdefer raw.deinit(f.allocator);

    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = source.read(source.ctx, &chunk, chunk.len);
        if (n == 0) break;
        if (n < 0) return fail(d, error.ReadError, &.{
            "zurl did not read the body this rtsp request sends",
        });
        const taken: usize = @intCast(n);
        if (@as(u64, taken) > max_request_body_bytes -| raw.items.len) return failNumber(
            d,
            error.FileSizeExceeded,
            "the body is larger than the ",
            max_request_body_bytes,
            " bytes zurl sends in one rtsp request",
        );
        raw.appendSlice(f.allocator, chunk[0..taken]) catch
            return Diagnostics.record(d, error.OutOfMemory, .{});
    }

    return raw.toOwnedSlice(f.allocator) catch
        return Diagnostics.record(d, error.OutOfMemory, .{});
}

/// Flushes a `zurl_net.Connection`, for the session's channel.
fn flushConnection(ctx: ?*anyopaque) Io.Writer.Error!void {
    const connection: *zurl_net.Connection = @ptrCast(@alignCast(ctx.?));
    connection.flush() catch return error.WriteFailed;
}

/// The `zurl_core.Error` a reply fault carries.
fn receiveErrorOf(err: Session.ReceiveError) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.OperationTimedOut => error.OperationTimedOut,
        error.Canceled => error.AbortedByCallback,
        error.BodyTooLarge, error.StreamTooLong => error.FileSizeExceeded,
        error.LineTooLong => error.HeaderLineTooLarge,
        error.HeadTooLarge => error.ResponseHeadTooLarge,
        // `HeadWithoutLineFeed` is here and not below with the weird
        // replies: only a change inside `Session` can raise it, so it says
        // this end could not read the reply and never that the server sent
        // a bad one.
        error.ReadFailed, error.ReadTimeoutUnsupported, error.HeadWithoutLineFeed => error.ReadError,
        // Everything else is a reply this session cannot go on from.
        error.SequenceMismatch,
        error.InterleavedData,
        error.EndOfStream,
        error.BadStatusLine,
        error.BadStatusCode,
        error.BadVersion,
        error.BadHeaderLine,
        error.NoSequenceNumber,
        error.BadSequenceNumber,
        error.BadContentLength,
        => error.WeirdServerReply,
    };
}

/// The `zurl_core.Error` a body read fault carries.
fn readErrorOf(err: zurl_net.bounded.ExactError) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.OperationTimedOut => error.OperationTimedOut,
        error.Canceled => error.AbortedByCallback,
        error.StreamTooLong => error.FileSizeExceeded,
        // **A short body is `PartialFile` and never a whole answer.** The
        // server named a length and sent less, so a caller that got the
        // bytes anyway would have a truncated description and no sign.
        error.EndOfStream => error.PartialFile,
        error.ReadFailed, error.ReadTimeoutUnsupported => error.ReadError,
    };
}

/// The sentence a body read fault carries.
fn bodyFaultOf(err: zurl_net.bounded.ExactError) []const u8 {
    return switch (err) {
        error.EndOfStream => "the rtsp server closed before it had sent the body its Content-Length announced",
        error.OutOfMemory => "zurl ran out of memory reading an rtsp body",
        error.StreamTooLong => "the rtsp server sent more body than zurl reads",
        error.ReadFailed => "zurl did not read the rtsp body",
        error.OperationTimedOut => "the rtsp server sent no byte of its body for as long as zurl waits",
        error.ReadTimeoutUnsupported => "this build has no concurrency, so an rtsp body read cannot be bounded",
        error.Canceled => "the rtsp body read was stopped from outside",
    };
}

/// Reports a request head this build would not write.
fn reportRequest(err: request.Error, d: ?*Diagnostics) Error {
    return fail(d, error.InvalidUrl, &.{request.describe(err)});
}

/// Reports a reply the caller asked to treat as a failure.
fn failStatus(d: ?*Diagnostics, s: reply.Status) Error {
    var digits: [8]u8 = undefined;
    const text = std.fmt.bufPrint(&digits, "{d}", .{s.code}) catch digits[0..0];
    return fail(d, error.HttpReturnedError, &.{
        "the rtsp server answered ",
        text,
        " ",
        s.reason,
    });
}

/// Reports a write that did not reach the server.
fn reportWrite(connection: *zurl_net.Connection, d: ?*Diagnostics) Error {
    const cause = connection.writeError() orelse return fail(d, error.WriteError, &.{
        "zurl did not write the rtsp request",
    });
    return fail(d, error.WriteError, &.{
        "zurl did not write the rtsp request: ",
        @errorName(cause),
    });
}

/// Reports a dial fault with the sentence `zurl-net` holds for it.
fn reportSetup(err: zurl_net.errors.SetupError, host: []const u8, d: ?*Diagnostics) Error {
    const mapping = zurl_net.errors.map(err);
    if (mapping.message) |text| return fail(d, mapping.err, &.{ host, ": ", text });
    return fail(d, mapping.err, &.{ host, ": ", @errorName(err) });
}

/// Reports a credential longer than this package sends.
fn failCredentialSize(d: ?*Diagnostics) Error {
    return failNumber(
        d,
        error.CredentialTooLarge,
        "the credential for this url is longer than the ",
        max_credential_bytes,
        " bytes one rtsp Authorization header carries",
    );
}

/// Writes `parts`, one after another, into `d`'s own message storage,
/// records `err` with that message, and returns `err`.
fn fail(d: ?*Diagnostics, err: Error, parts: []const []const u8) Error {
    const t = d orelse return err;
    const out: []u8 = &t.message_storage;
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

/// Returns the dispatch entry for the `rtsp` scheme.
///
/// `Front` is the front package's own namespace, taken as a comptime
/// parameter. Passing the namespace rather than importing it is what keeps
/// this package free of a `zurl` import.
///
/// **`f` must outlive every transfer the client runs on this scheme**, and
/// must not move: the entry carries `f` as its opaque pointer, and the
/// body reader and the head block point inside it.
pub fn protocol(f: *Fetcher, comptime Front: type) Front.protocol.Protocol {
    return .{
        .scheme = scheme,
        .default_port = default_port,
        .ptr = f,
        .vtable = &Dispatch(Front).vtable,
        // This package dials the origin itself and reads no proxy field,
        // so a transfer that named a proxy is refused by name rather than
        // run direct. curl carries rtsp through a proxy and this build
        // does not. See `Front.protocol.Unread`.
        .unread = .{ .proxy = true },
    };
}

/// The vtable for one front package. One instantiation for each `Front`,
/// and each one holds a single comptime constant, so the table lives in
/// the binary's own read-only data and never on a stack.
fn Dispatch(comptime Front: type) type {
    return struct {
        const vtable: Front.protocol.Protocol.VTable = .{ .perform = performRtsp };

        fn performRtsp(
            ptr: ?*anyopaque,
            c: *Front.Client,
            url: zurl_core.Url,
            options: Front.Transfer.Options,
            d: ?*Diagnostics,
        ) Error!Front.Response {
            _ = c;
            const f: *Fetcher = @ptrCast(@alignCast(ptr.?));
            const answer = try f.open(url, translate(options), d);
            return .{
                // curl reports the reply status as `%{http_code}`,
                // measured: an `OPTIONS` that worked printed `200`.
                .status = answer.status,
                .content_length = answer.length,
                .transfer_encoding = .none,
                .body = answer.reader,
                // **The reply head reaches `-i` and `-v`.** curl treats an
                // RTSP head the way it treats an HTTP one, measured:
                // `curl -s -i rtsp://host/stream` printed it.
                .headers = answer.head,
                .final_headers = answer.head,
            };
        }

        /// Reads the front package's own options into this package's.
        ///
        /// **`--max-filesize` narrows the bound and never widens it**, and
        /// **`--speed-time` narrows the wait the same way**, for the
        /// reason `zurl_gopher` gives.
        fn translate(options: Front.Transfer.Options) Options {
            return .{
                .connect_timeout = options.connect_timeout,
                .max_body_bytes = if (options.max_size == 0)
                    default_max_body_bytes
                else
                    @min(options.max_size, default_max_body_bytes),
                .read_timeout = zurl_net.bounded.stallTimeout(
                    options.low_speed_limit,
                    options.low_speed_time_s,
                    default_read_timeout_s,
                ),
                .tcp_no_delay = options.tcp_no_delay,
                // **`--rtsp-request` first and `-X` second.** Both name a
                // method, and the flag that says so by name wins over the
                // one that means something else for every other protocol.
                .method_name = options.rtsp_request orelse options.custom_request,
                .stream_uri = options.rtsp_stream_uri,
                .session_id = options.rtsp_session_id,
                .transport = options.rtsp_transport,
                .headers = options.headers,
                .credentials = options.credentials,
                .netrc_text = options.netrc_text,
                .body = if (options.body) |source|
                    .{
                        .len = source.len,
                        .ctx = source.ctx,
                        .read = source.read,
                        .content_type = source.content_type,
                    }
                else
                    null,
                .user_agent = options.user_agent,
                .fail_on_error = options.fail_on_error,
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
///
/// A change to `zurl.protocol.Protocol` that this stub does not follow is
/// a compile error at the call in `src/cli/run.zig`, which is where the
/// real types meet.
const StubFront = struct {
    const Client = struct {};

    const Transfer = struct {
        const BodySource = struct {
            len: ?u64,
            ctx: *anyopaque,
            read: *const fn (ctx: *anyopaque, buffer: [*]u8, len: usize) callconv(.c) isize,
            rewind: ?*const fn (ctx: *anyopaque) callconv(.c) bool = null,
            content_type: ?[]const u8 = null,
        };

        const Options = struct {
            connect_timeout: Io.Timeout = .none,
            low_speed_limit: u64 = 1,
            low_speed_time_s: u32 = 300,
            max_size: u64 = 0,
            tcp_no_delay: bool = true,
            headers: []const std.http.Header = &.{},
            credentials: ?zurl_core.auth.Credentials = null,
            netrc_text: ?[]const u8 = null,
            body: ?BodySource = null,
            user_agent: []const u8 = default_user_agent,
            fail_on_error: bool = false,
            custom_request: ?[]const u8 = null,
            rtsp_request: ?[]const u8 = null,
            rtsp_stream_uri: ?[]const u8 = null,
            rtsp_session_id: ?[]const u8 = null,
            rtsp_transport: ?[]const u8 = null,
            connect_to: []const zurl_net.override.HostOverride = &.{},
        };
    };

    const Response = struct {
        status: u16,
        content_length: ?u64,
        transfer_encoding: std.http.TransferEncoding,
        body: *Io.Reader,
        effective_url: []const u8 = "",
        headers: ?[]const u8 = null,
        final_headers: ?[]const u8 = null,
    };

    const protocol = struct {
        // The stub keeps the shape of `zurl.protocol.Unread`.
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

/// Parses `text` the way `zurl.Client` does, with this scheme registered.
pub fn parseRtspUrl(text: []const u8) !zurl_core.Url {
    var schemes: zurl_core.url.Schemes = .empty;
    try schemes.add(.{ .name = scheme, .default_port = default_port });
    return zurl_core.url.parseWith(text, &schemes);
}

test {
    _ = test_server;
}

test "the package names one scheme and the port curl dials" {
    // curl 8.21.0's `--version` lists `rtsp` and no `rtsps`, measured, so
    // there is no TLS twin to register.
    try testing.expectEqualStrings("rtsp", scheme);
    try testing.expectEqual(@as(?u16, 554), default_port);
}

test "the dispatch entry refuses a proxy by name rather than run direct" {
    // **`-x` must not fail open.** Measured: `curl -x http://127.0.0.1:9/
    // rtsp://...` exited 7, which is a proxy curl tried and could not
    // reach. This build dials the origin itself, so it refuses with exit 4
    // rather than connect direct.
    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    const entry = f.protocol(StubFront);
    try testing.expect(entry.unread.proxy);
    // This package does read a credential, so it says nothing about one.
    try testing.expect(!entry.unread.credentials);
    try testing.expectEqualStrings("rtsp", entry.scheme);
}

test "the default request is the one curl sends, byte for byte" {
    // Measured: `curl rtsp://127.0.0.1:8554/stream` put
    // `OPTIONS * RTSP/1.0`, `CSeq: 1`, `User-Agent: curl/8.21.0`, and an
    // empty line on the wire, with the path of the url nowhere in it.
    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    f.session.next_cseq = Session.first_cseq;
    const url = try parseRtspUrl("rtsp://127.0.0.1:8554/stream");
    const line_target = try f.resolveTarget(url, default_method, .{}, null);
    try testing.expectEqualStrings("*", line_target);

    try f.buildRequest(default_method, line_target, 1, null, "", .{}, null);
    try testing.expectEqualStrings(
        "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: zurl/0.1\r\n\r\n",
        f.request_writer.written(),
    );
}

test "a named method writes an absolute target, which curl cannot do at all" {
    // curl's command line sent `OPTIONS *` for `-X DESCRIBE`, measured. RFC
    // 2326 section 6.1 makes the target of a DESCRIBE an absolute url.
    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    const url = try parseRtspUrl("rtsp://127.0.0.1:8554/stream");
    const line_target = try f.resolveTarget(url, .describe, .{}, null);
    try testing.expectEqualStrings("rtsp://127.0.0.1:8554/stream", line_target);

    try f.buildRequest(.describe, line_target, 2, null, "", .{}, null);
    try testing.expectEqualStrings(
        "DESCRIBE rtsp://127.0.0.1:8554/stream RTSP/1.0\r\n" ++
            "CSeq: 2\r\n" ++
            "User-Agent: zurl/0.1\r\n" ++
            "Accept: application/sdp\r\n" ++
            "\r\n",
        f.request_writer.written(),
    );
}

test "a stream uri from the flag wins over the url, because a track has no url" {
    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    const url = try parseRtspUrl("rtsp://127.0.0.1:8554/stream");
    const line_target = try f.resolveTarget(url, .setup, .{
        .stream_uri = "rtsp://127.0.0.1:8554/stream/trackID=0",
    }, null);
    try testing.expectEqualStrings("rtsp://127.0.0.1:8554/stream/trackID=0", line_target);

    // And it wins for an OPTIONS too, which otherwise writes `*`.
    const asterisked = try f.resolveTarget(url, .options, .{
        .stream_uri = "rtsp://h/s",
    }, null);
    try testing.expectEqualStrings("rtsp://h/s", asterisked);
}

test "a SETUP with no transport is refused rather than sent" {
    // **RFC 2326 section 12.39 makes `Transport` required on a `SETUP`**,
    // and a server answers one without it with 461. Inventing a transport
    // would name a UDP port this build never opens.
    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var d: Diagnostics = .{};
    try testing.expectError(error.InvalidUrl, f.buildRequest(
        .setup,
        "rtsp://h/s",
        1,
        null,
        "",
        .{},
        &d,
    ));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "--rtsp-transport") != null);

    // With one, the header goes out.
    try f.buildRequest(.setup, "rtsp://h/s", 1, null, "", .{
        .transport = "RTP/AVP;unicast;client_port=4588-4589",
    }, null);
    try testing.expect(std.mem.indexOf(
        u8,
        f.request_writer.written(),
        "Transport: RTP/AVP;unicast;client_port=4588-4589\r\n",
    ) != null);

    // A `-H Transport` counts as naming one, so the flag is not required
    // and no second header goes out.
    try f.buildRequest(.setup, "rtsp://h/s", 1, null, "", .{
        .headers = &.{.{ .name = "Transport", .value = "RTP/AVP/TCP;interleaved=0-1" }},
    }, null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(
        u8,
        f.request_writer.written(),
        "Transport:",
    ));
}

test "a session identifier from the flag reaches the header" {
    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    try f.buildRequest(.play, "rtsp://h/s", 3, null, "", .{
        .session_id = "12345678",
    }, null);
    try testing.expectEqualStrings(
        "PLAY rtsp://h/s RTSP/1.0\r\nCSeq: 3\r\nUser-Agent: zurl/0.1\r\nSession: 12345678\r\n\r\n",
        f.request_writer.written(),
    );
}

test "a flag that would forge a header is refused before any dial" {
    // **The injection refusal of this package, at the one place a flag
    // reaches a line.** `--rtsp-session-id`, `--rtsp-transport`, and
    // `--rtsp-stream-uri` all land in a header or a request line.
    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var d: Diagnostics = .{};
    try testing.expectError(error.InvalidUrl, f.buildRequest(.play, "rtsp://h/s", 1, null, "", .{
        .session_id = "1\r\nRange: npt=0-",
    }, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "NUL, a CR, or an LF") != null);

    try testing.expectError(error.InvalidUrl, f.buildRequest(.setup, "rtsp://h/s", 1, null, "", .{
        .transport = "RTP/AVP\r\nSession: stolen",
    }, &d));

    try testing.expectError(error.InvalidUrl, f.buildRequest(
        .describe,
        "rtsp://h/s\r\nTEARDOWN rtsp://h/s RTSP/1.0",
        1,
        null,
        "",
        .{},
        &d,
    ));

    try testing.expectError(error.InvalidUrl, f.buildRequest(.play, "rtsp://h/s", 1, null, "", .{
        .headers = &.{.{ .name = "X", .value = "a\r\nSession: stolen" }},
    }, &d));
    try testing.expectError(error.InvalidUrl, f.buildRequest(.play, "rtsp://h/s", 1, null, "", .{
        .headers = &.{.{ .name = "X\r\nY", .value = "v" }},
    }, &d));
}

test "a credential becomes the header curl builds, and never the request line" {
    // Measured: `-u u:p` reached the wire as `Authorization: Basic dTpw`,
    // and the request line carried no credential at all.
    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var source: CredentialSource = .none;
    const value = (try f.resolveAuthorization(
        try parseRtspUrl("rtsp://h/s"),
        .{ .credentials = .{ .user = "u", .password = "p" } },
        &source,
        null,
    )).?;
    try testing.expectEqualStrings("Basic dTpw", value);
    try testing.expectEqual(CredentialSource.options, source);

    // The url's own userinfo comes first, and it never reaches the target.
    const from_url = (try f.resolveAuthorization(
        try parseRtspUrl("rtsp://u:p@h/s"),
        .{ .credentials = .{ .user = "other", .password = "other" } },
        &source,
        null,
    )).?;
    try testing.expectEqualStrings("Basic dTpw", from_url);
    try testing.expectEqual(CredentialSource.userinfo, source);

    // A netrc entry is last.
    const from_netrc = (try f.resolveAuthorization(
        try parseRtspUrl("rtsp://cam.test/s"),
        .{ .netrc_text = "machine cam.test login u password p\n" },
        &source,
        null,
    )).?;
    try testing.expectEqualStrings("Basic dTpw", from_netrc);
    try testing.expectEqual(CredentialSource.netrc, source);

    // With nobody naming one, no header goes out.
    try testing.expectEqual(
        @as(?[]const u8, null),
        try f.resolveAuthorization(try parseRtspUrl("rtsp://h/s"), .{}, &source, null),
    );
    try testing.expectEqual(CredentialSource.none, source);
}

test "a caller's own Authorization header wins and this build writes none" {
    // What curl does with a `-H Authorization`. Two of the header would
    // let a server pick which credential to believe.
    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var source: CredentialSource = .none;
    try testing.expectEqual(@as(?[]const u8, null), try f.resolveAuthorization(
        try parseRtspUrl("rtsp://u:p@h/s"),
        .{ .headers = &.{.{ .name = "authorization", .value = "Bearer t" }} },
        &source,
        null,
    ));
    try testing.expectEqual(CredentialSource.header, source);

    try f.buildRequest(.play, "rtsp://h/s", 1, "Basic dTpw", "", .{
        .headers = &.{.{ .name = "Authorization", .value = "Bearer t" }},
    }, null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(
        u8,
        f.request_writer.written(),
        "Authorization",
    ));
    try testing.expect(std.mem.indexOf(u8, f.request_writer.written(), "Bearer t") != null);
    try testing.expect(std.mem.indexOf(u8, f.request_writer.written(), "dTpw") == null);
}

test "a body is written with a length, and only for the two methods that take one" {
    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    try f.buildRequest(.set_parameter, "rtsp://h/s", 4, null, "barparam: barstuff\r\n", .{}, null);
    try testing.expect(std.mem.indexOf(
        u8,
        f.request_writer.written(),
        "Content-Length: 20\r\n",
    ) != null);

    // A `Content-Length` from `-H` beside a body is refused: two of them
    // let a server read the next request as part of this body.
    var d: Diagnostics = .{};
    try testing.expectError(error.InvalidUrl, f.buildRequest(
        .set_parameter,
        "rtsp://h/s",
        4,
        null,
        "x",
        .{ .headers = &.{.{ .name = "Content-Length", .value = "99" }} },
        &d,
    ));
}

test "a caller's own header of a name this build writes wins over this build's" {
    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    try f.buildRequest(.describe, "rtsp://h/s", 1, null, "", .{
        .headers = &.{
            .{ .name = "Accept", .value = "application/sdp+xml" },
            .{ .name = "user-agent", .value = "mine/1" },
        },
    }, null);
    const head = f.request_writer.written();
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, head, "Accept:"));
    try testing.expect(std.mem.indexOf(u8, head, "application/sdp+xml") != null);
    try testing.expect(std.mem.indexOf(u8, head, "zurl/0.1") == null);
    try testing.expect(std.mem.indexOf(u8, head, "mine/1") != null);

    // Every name this build writes itself is in one list, so a name added
    // to the head has to be added there too.
    for (owned_headers) |name| try testing.expect(name.len != 0);
}

test "every reply fault maps to an error a caller can act on" {
    // A switch with no else arm, so a fault added to `Session` cannot land
    // on whatever the last arm happened to be.
    try testing.expectEqual(Error.WeirdServerReply, receiveErrorOf(error.SequenceMismatch));
    try testing.expectEqual(Error.WeirdServerReply, receiveErrorOf(error.InterleavedData));
    try testing.expectEqual(Error.WeirdServerReply, receiveErrorOf(error.NoSequenceNumber));
    try testing.expectEqual(Error.FileSizeExceeded, receiveErrorOf(error.BodyTooLarge));
    try testing.expectEqual(Error.HeaderLineTooLarge, receiveErrorOf(error.LineTooLong));
    try testing.expectEqual(Error.ResponseHeadTooLarge, receiveErrorOf(error.HeadTooLarge));
    try testing.expectEqual(Error.OperationTimedOut, receiveErrorOf(error.OperationTimedOut));

    // A body shorter than its own announced length is `PartialFile` and
    // never a whole answer.
    try testing.expectEqual(Error.PartialFile, readErrorOf(error.EndOfStream));
    try testing.expectEqual(@as(u32, 18), zurl_core.errors.curlCode(readErrorOf(error.EndOfStream)));

    // Exit 8 for a reply this build cannot read, which is curl's code.
    try testing.expectEqual(
        @as(u32, 8),
        zurl_core.errors.curlCode(receiveErrorOf(error.SequenceMismatch)),
    );
}

test "every credential source names itself" {
    const every = [_]CredentialSource{ .userinfo, .options, .netrc, .header, .none };
    for (every) |source| {
        try testing.expect(source.describe().len != 0);
        for (every) |other| {
            if (source == other) continue;
            try testing.expect(!std.mem.eql(u8, source.describe(), other.describe()));
        }
    }
}

test "the rtsp translation carries --connect-to into this package" {
    // A translation that dropped the field would leave both flags working
    // in a unit test and doing nothing on the command line.
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
