//! Runs one `ws://` or `wss://` transfer: the dial, the opening
//! handshake, and the frames that follow it.
//!
//! **A WebSocket transfer starts as an HTTP request.** That is what makes
//! this package different from every other protocol package here: the
//! first thing on the wire is a `GET` with an `Upgrade:` line, and only
//! the answer to it turns the connection into a frame stream. So this file
//! carries a small HTTP client of its own, in `handshake.zig`, rather than
//! import `zurl-http`: a protocol package imports `zurl-core` and
//! `zurl-net` and nothing else of ours, and an import of the HTTP engine
//! would make this package impossible to leave out of a build that keeps
//! HTTP.
//!
//! **The handshake proves the peer speaks WebSocket, and nothing else
//! does.** `Sec-WebSocket-Accept` is that proof. See `open` and
//! `handshake.acceptMatches`: a peer that answers `101` with a wrong value
//! fails the transfer, because a client that accepted it would upgrade to
//! any server at all.
//!
//! **Every frame this client writes is masked with a fresh key.** RFC 6455
//! section 5.3 requires it, `Session.writeControl` is the only writer, and
//! the key comes from `io.randomSecure` for each frame. See `Session`.
//!
//! **The transfer reads.** curl's own WebSocket support in the command
//! line tool receives: it writes the payload of the data frames to
//! standard output and sends none of its own. zurl does the same. A ping
//! is answered with a pong and a close is answered with a close, so a
//! server that keeps the rules sees a client that keeps them too.
//!
//! **A `Fetcher` must not move once `open` has run.** The body reader it
//! hands back points into this value.
//!
//! **The answer is bounded.** A frame header can claim a payload of nearly
//! 2^63 octets, and a server can send frames forever.
//! `Options.max_response_bytes` is the bound over the whole transfer, and
//! a peer past it gets `error.FileSizeExceeded`, exit 63, with no octet of
//! the answer reaching the output.
//!
//! **The frames that carry no answer octet are bounded separately.** A
//! ping and a data frame with an empty payload are both legal, and
//! `max_response_bytes` counts neither, so neither moves the size bound at
//! all. `max_empty_frames` is the count of them over one transfer, and
//! passing it is `error.WeirdServerReply`, exit 8.
//!
//! What this does not do: no subprotocol and no extension, so this client
//! offers neither and refuses an answer that names one. No data frame
//! goes out, so `-d` on a `ws://` url sends nothing. No UTF-8 check on a
//! text frame's payload, because zurl writes the payload through as
//! octets, the way it writes every other body.
//!
//! This file imports `zurl-core` and `zurl-net`. It does not import
//! `zurl`, and it never will. See `protocol`.

const Fetcher = @This();

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_net = @import("zurl-net");

const close = @import("close.zig");
const frame = @import("frame.zig");
const handshake = @import("handshake.zig");
const target = @import("target.zig");
const WsSession = @import("Session.zig");

const Io = std.Io;
const Error = zurl_core.Error;
const Diagnostics = zurl_core.Diagnostics;
const Credentials = zurl_core.auth.Credentials;

/// The plain scheme this package handles.
pub const scheme = "ws";

/// The encrypted scheme this package handles. The same frames, on a TLS
/// session.
pub const secure_scheme = "wss";

/// The port a `ws://` url uses when it names none.
///
/// 80, the HTTP port, because the opening handshake **is** an HTTP
/// request. RFC 6455 section 3 says so.
pub const default_port: ?u16 = 80;

/// The port a `wss://` url uses when it names none. 443, for the same
/// reason `default_port` is 80.
pub const secure_default_port: ?u16 = 443;

/// The status a WebSocket transfer reports.
///
/// 101, the status the server wrote. Unlike gopher or FTP, a WebSocket
/// transfer really does carry an HTTP status, and reporting the peer's own
/// number is what lets `-w '%{http_code}'` say what happened.
pub const switching_protocols: u16 = 101;

/// How many octets of payload this package reads by default.
///
/// A WebSocket carries frames until somebody closes, so the protocol puts
/// no length on the answer at all. Without a bound a server that keeps
/// sending holds this process for as long as it likes and fills memory
/// while it does.
///
/// 16 MiB is the same number `zurl-gopher` uses for an answer of the same
/// shape. `Options.max_response_bytes` narrows it, and `--max-filesize`
/// narrows that.
pub const default_max_response_bytes: u64 = 16 * 1024 * 1024;

/// How many frames that carry no answer octet one transfer reads.
///
/// **A frame is empty here when it puts no octet into `collected`.** Two
/// shapes do that. A control payload never reaches `collected` at all, so
/// `max_response_bytes` counts none of it, and a ping is answered with a
/// pong. A data frame or a continuation frame with a payload of zero
/// octets is legal in RFC 6455 section 5.4, and it reaches `collected`
/// with nothing to add. A peer that sends either for ever therefore made
/// this end read, and for a ping also write, for ever, with no counter of
/// any kind moving. This is that counter. Passing it is
/// `error.WeirdServerReply`, exit 8.
///
/// **It counts every frame kind and not the control frames alone.** The
/// first version of this bound counted the control frames, because a
/// control frame looked like the one thing a peer could send for free. A
/// data frame of `82 00` is two octets and just as free, and it went
/// round the read loop with every bound of the transfer standing still.
/// One counter over both shapes is what closes that, and a new frame kind
/// that carries no answer octet is counted by the same line.
///
/// RFC 6455 puts no rate on a ping and no rule on an empty frame. A real
/// session sends a ping every few seconds and an empty frame almost never,
/// and a zurl transfer ends at the peer's close, so this is far past any
/// honest peer and short of a flood.
pub const max_empty_frames: usize = 1024;

/// How much room the connection keeps for octets read and not taken yet.
pub const read_buffer_len: usize = 8192;

/// How long one read may wait with no octet arriving.
///
/// **A WebSocket ends when somebody closes, so a peer that says nothing
/// holds this process forever.** `--connect-timeout` covers the dial and
/// the handshake and nothing after them.
///
/// 300 seconds is curl's own `--speed-time` default, and this is the same
/// question: how long a transfer may make no progress. `--speed-time`
/// narrows it and never widens it.
pub const default_read_timeout_s: u32 = 300;

/// `default_read_timeout_s`, as a `std.Io.Timeout`.
pub const default_read_timeout: Io.Timeout = .{
    .duration = .{ .raw = .fromSeconds(default_read_timeout_s), .clock = .awake },
};

/// How many redirects one transfer follows when the caller asks for none
/// in particular.
pub const default_max_redirects: u32 = 10;

/// How many octets of a credential this package holds.
pub const max_credential_bytes: usize = 512;

/// The trust store a `wss` session verifies against, and the way to fill
/// it.
///
/// **A `wss` session verifies exactly as an `https` session does.** The
/// bundle here is the one the front package loads for HTTP, so a
/// `--cacert` moves both or neither. A build that leaves this null cannot
/// open a `wss` session at all: `open` reports `error.SslConnectError` and
/// says the build gave it no trust store, rather than fall back to a
/// session that verifies nothing.
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
    /// before the handshake, and only for a `wss` url.
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
    /// The bound on the whole answer. See `default_max_response_bytes`.
    max_response_bytes: u64 = default_max_response_bytes,
    /// How long one read may wait with no octet arriving. See
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
    /// The trust store for a `wss` session. See `Trust`.
    trust: ?Trust = null,
    /// What goes in the `User-Agent:` line. This is `-A`.
    user_agent: []const u8 = "zurl/0.1",
    /// The credential the handshake sends as `Basic`. This is `-u`, and a
    /// url userinfo outranks it. Null for a transfer that names none.
    credentials: ?Credentials = null,
    /// The text of a `.netrc` file, already read by the caller.
    netrc_text: ?[]const u8 = null,
    /// How many redirects to follow, or null to report a 3xx unfollowed.
    /// This is `-L` together with `--max-redirs`.
    max_redirects: ?u32 = null,
    /// Which schemes a redirect may move this transfer to. This is
    /// `--proto-redir`, and `zurl_core.redirect` holds the whole rule.
    redirect_protocols: zurl_core.redirect.Set = zurl_core.redirect.redirect_default,
    /// Where a url naming one host and port dials instead. This is
    /// `--resolve` and `--connect-to`.
    ///
    /// **An entry moves the dial and nothing else.** The `Host:` line of
    /// the handshake and `tlsOptions` both read `url.host`, so a `wss`
    /// peer at the dialed address must still hold a certificate for the
    /// name the url wrote. Each hop of a redirect chain reads this list
    /// again, the same way the HTTP engine does. See `zurl_net.override`.
    connect_to: []const zurl_net.override.HostOverride = &.{},
};

allocator: std.mem.Allocator,
io: Io,
/// The payload of the transfer in play, or null when none is held. `open`
/// frees this before it reads another, and `deinit` frees it.
answer: ?[]u8,
/// Reads `answer`. Valid only while `answer` holds something.
body: Io.Reader,
/// Backs the request head.
request_storage: [handshake.max_request_bytes]u8,
/// Backs the response head that `handshake.readResponse` fills.
response_storage: handshake.ResponseStorage,
/// Backs one redirect target's text. The url of the next hop points into
/// this, so it must live as long as that hop does.
target_storage: [target.max_target_bytes]u8,
/// Backs the url text of the hop in play, which becomes
/// `Response.effective_url`.
effective_storage: [target.max_target_bytes]u8,
effective_len: usize,
/// Backs the decoded userinfo of a url.
credential_storage: [max_credential_bytes * 2]u8,
/// Backs the `Authorization:` value.
authorization_storage: [max_credential_bytes * 3]u8,
/// Backs the payload of one control frame that arrived.
control_storage: [frame.max_control_payload_bytes]u8,
/// Backs the cleaned reason of a close frame. See `close.parse`: the
/// reason is a peer's text and it is cleaned before it can reach output.
reason_storage: [close.max_reason_bytes]u8,
/// Backs a sentence that names the close code and the cleaned reason.
close_message_storage: [close.max_reason_bytes + 64]u8,
/// The status of the last head this `Fetcher` read. Filled by `openOnce`
/// and read by `open` when a redirect is not followed.
last_status: u16,

/// A `Fetcher` that holds no answer yet.
pub fn init(allocator: std.mem.Allocator, io: Io) Fetcher {
    return .{
        .allocator = allocator,
        .io = io,
        .answer = null,
        .body = undefined,
        .request_storage = undefined,
        .response_storage = .{},
        .target_storage = undefined,
        .effective_storage = undefined,
        .effective_len = 0,
        .credential_storage = undefined,
        .authorization_storage = undefined,
        .control_storage = undefined,
        .reason_storage = undefined,
        .close_message_storage = undefined,
        .last_status = 0,
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

/// The answer of one WebSocket transfer.
pub const Body = struct {
    /// Streams the payload of every data frame, joined. Valid until the
    /// next `open` on this `Fetcher`, or until `deinit`.
    reader: *Io.Reader,
    /// How many octets the payload holds.
    length: u64,
    /// The status the handshake answered with. Always
    /// `switching_protocols` for a transfer that got this far.
    status: u16,
    /// The close code the peer sent, or null when it closed the socket
    /// with no close frame and null when it wrote a close frame with an
    /// empty payload.
    close_code: ?u16,
    /// The peer's close reason, cleaned and bounded by `close.parse`.
    /// Points into this `Fetcher`.
    close_reason: []const u8,
    /// The url of the last hop, which is the first url unless a redirect
    /// moved the transfer. Points into this `Fetcher` when a redirect
    /// happened, and it is empty otherwise.
    effective_url: []const u8,
};

/// Whether `url` asks for a TLS session.
///
/// The scheme and nothing else. Compared without regard to case, per RFC
/// 3986, so `WSS://` is as encrypted as `wss://`.
pub fn isSecure(url: zurl_core.Url) bool {
    return std.ascii.eqlIgnoreCase(url.scheme, secure_scheme);
}

/// Runs one transfer and returns its answer.
///
/// Frees whatever the previous call held first, so a `Fetcher` never holds
/// two answers at once.
///
/// The faults, and the exit code each carries:
///
/// - a url this package cannot write a request for is `error.InvalidUrl`,
///   exit 3.
/// - a peer that does not accept a connection is `error.CouldNotConnect`,
///   exit 7.
/// - a peer certificate that does not verify is
///   `error.PeerFailedVerification`, exit 60, the same answer an `https`
///   url gets.
/// - a `Sec-WebSocket-Accept` that is not the digest of the key this
///   transfer sent is `error.WeirdServerReply`, exit 8. So is a masked
///   server frame, a reserved bit, a reserved opcode, and a close frame
///   whose payload RFC 6455 does not allow.
/// - a status other than 101 that this transfer did not follow is
///   `error.HttpReturnedError`, exit 22.
/// - an answer past `options.max_response_bytes` is
///   `error.FileSizeExceeded`, exit 63, and no octet of it is returned.
pub fn open(f: *Fetcher, url: zurl_core.Url, options: Options, d: ?*Diagnostics) Error!Body {
    f.release();
    f.effective_len = 0;

    var current = url;
    var hops: u32 = 0;
    // **The credential does not cross a redirect.** A redirect target is
    // the server's text, so the host it names is another origin whatever
    // it says. `zurl.Client` keeps the same rule for a handoff between
    // protocol packages, and `zurl-http` keeps it for a hop inside HTTP.
    var hop_options = options;

    while (true) {
        const outcome = try f.openOnce(current, hop_options, d);
        switch (outcome) {
            .body => |body| return body,
            .redirect => |location| {
                const limit = options.max_redirects orelse return failStatus(
                    d,
                    error.HttpReturnedError,
                    f.last_status,
                    "the websocket handshake was answered with a redirect, and zurl was not asked to follow one",
                );
                if (hops >= limit) return fail(d, error.TooManyRedirects, &.{
                    "the websocket handshake was redirected more times than zurl follows",
                });
                hops += 1;

                const text = target.resolve(&f.target_storage, current, location) catch |err|
                    return reportTarget(err, d);

                // **The scheme rule, and it is `zurl_core.redirect`'s.** A
                // server that could move a transfer to another protocol
                // could point it at anything this build speaks.
                const next_scheme = schemeOf(text);
                if (!options.redirect_protocols.hasScheme(next_scheme)) {
                    return fail(d, error.UnsupportedProtocol, &.{
                        "a redirect named a protocol this transfer may not follow into: ",
                        next_scheme,
                    });
                }
                if (!std.ascii.eqlIgnoreCase(next_scheme, scheme) and
                    !std.ascii.eqlIgnoreCase(next_scheme, secure_scheme))
                {
                    return fail(d, error.UnsupportedProtocol, &.{
                        "a websocket handshake was redirected to ",
                        next_scheme,
                        ", and this package opens ws and wss alone",
                    });
                }

                // **The base of a hop must not live in the buffer that hop
                // writes into.** `zurl_core.url.parse` returns slices that
                // borrow their input, so a `current` parsed out of
                // `target_storage` would give `target.resolve` a base and a
                // destination in the same memory. `std.Io.Writer.write` is
                // a `@memcpy`, and `@memcpy` refuses arguments that alias:
                // two relative hops in a row aborted the process.
                //
                // So the text is copied into `effective_storage` first, and
                // the base is parsed out of the copy. Two buffers, and the
                // resolve of the next hop reads one and writes the other.
                // `lib/zurl-http/h1.zig` splits its chain scratch for the
                // same reason. See `nextTarget` there.
                f.effective_len = text.len;
                @memcpy(f.effective_storage[0..text.len], text);
                const kept = f.effective_storage[0..f.effective_len];
                current = parseUrl(kept) catch |err| return Diagnostics.record(d, err, .{ .url = kept });
                hop_options.credentials = null;
                // **And the netrc file, which is stricter than curl and
                // than `zurl.Client`.** A netrc `default` entry answers for
                // any host at all, so a file holding one would hand a
                // credential to the host a server chose. `zurl.Client`
                // keeps `netrc_text` across a protocol handoff for curl
                // parity, and `--location-trusted` is the flag that opts
                // back in there. No such flag reaches this package, so the
                // strict answer is the only one available here. See
                // `Client.perform`.
                hop_options.netrc_text = null;
            },
        }
    }
}

/// What one hop ended with.
const Outcome = union(enum) {
    body: Body,
    /// The peer answered a 3xx and named this target. Points into
    /// `response_storage`.
    redirect: []const u8,
};

/// Runs one hop: the dial, the handshake, and the frames when the
/// handshake succeeded.
fn openOnce(f: *Fetcher, url: zurl_core.Url, options: Options, d: ?*Diagnostics) Error!Outcome {
    const port = url.port orelse return fail(d, error.InvalidUrl, &.{
        "a websocket url names a port, and this one names none",
    });
    // **`--resolve` and `--connect-to` move this dial and nothing else.**
    // `handshake.writeRequest` below writes the `Host` header from `url`,
    // and `tlsOptions` reads `url.host`, so a `wss` peer at the dialed
    // address must still hold a certificate for the name the url wrote.
    // See `zurl_net.override`.
    const target_peer = zurl_net.override.dialTarget(options.connect_to, url.host, port);
    // A host that does not read and a host name no resolver can look up
    // are two faults, exit 3 and exit 6. See `zurl_net.errors.hostInit`.
    const host = zurl_net.tcp.Host.init(target_peer.host) catch |err| return fail(d, zurl_net.errors.hostInit(err).err, &.{
        target_peer.faultPrefix(err),
        target_peer.host,
    });

    const authorization = try f.buildAuthorization(url, options, d);
    var key: [handshake.key_text_len]u8 = undefined;
    handshake.drawKey(f.io, &key) catch return fail(d, error.SslConnectError, &.{
        "this system gave zurl no entropy, so the websocket key cannot be drawn, and a key a peer can guess proves nothing",
    });

    const request = handshake.writeRequest(&f.request_storage, .{
        .url = url,
        .key = &key,
        .user_agent = options.user_agent,
        .authorization = authorization,
    }) catch |err| switch (err) {
        error.RequestTooLong => return fail(d, error.InvalidUrl, &.{
            "the websocket handshake request this url needs is longer than zurl writes",
        }),
        error.HeaderHasFramingByte => return fail(d, error.InvalidUrl, &.{
            "a value of the websocket handshake holds a NUL, a CR, or an LF, and any of the three would end the header line and write a header of its own",
        }),
    };

    const tls = try f.tlsOptions(url, options, d);

    // **The dial and the handshake share one deadline.** A peer that
    // completes the TCP handshake and never sends a ServerHello would
    // otherwise hold this transfer forever.
    var connection: zurl_net.Connection = undefined;
    zurl_net.bounded.setup(&connection, f.io, options.connect_timeout, .{
        .allocator = f.allocator,
        .io = f.io,
        .host = host,
        .port = target_peer.port,
        .read_buffer_len = read_buffer_len,
        .tls = tls,
        .no_delay = options.tcp_no_delay,
    }) catch |err| return reportSetup(err, url.host, d);
    // One connection carries one WebSocket, and the session ends with it.
    defer connection.deinit();

    connection.writer().writeAll(request) catch return reportWrite(&connection, d);
    connection.flush() catch return reportWrite(&connection, d);

    const response = handshake.readResponse(
        connection.reader(),
        f.io,
        &f.response_storage,
        options.read_timeout,
    ) catch |err| return reportHead(err, &connection, d);
    f.last_status = response.status;

    if (response.status != switching_protocols) {
        // **A 3xx goes back to `open`, which is the one place that reads
        // the redirect policy.**
        if (response.status >= 300 and response.status < 400) {
            if (response.location) |location| return .{ .redirect = location };
            return failStatus(
                d,
                error.HttpReturnedError,
                response.status,
                "the websocket handshake was answered with a redirect that named no location",
            );
        }
        return failStatus(
            d,
            error.HttpReturnedError,
            response.status,
            "the websocket upgrade was refused: the server answered a status other than 101",
        );
    }

    // **The four checks RFC 6455 section 4.2.2 asks a client to make, and
    // the transfer fails on any one of them.** A client that made none of
    // them would upgrade to whatever answered `101`.
    if (!response.upgrade_ok) return fail(d, error.WeirdServerReply, &.{
        "the websocket handshake answered 101 with no Upgrade: websocket line",
    });
    if (!response.connection_ok) return fail(d, error.WeirdServerReply, &.{
        "the websocket handshake answered 101 with no Connection: Upgrade line",
    });
    const offered = response.accept orelse return fail(d, error.WeirdServerReply, &.{
        "the websocket handshake answered 101 with no Sec-WebSocket-Accept line, so nothing proves the peer speaks websocket",
    });
    if (!handshake.acceptMatches(&key, offered)) return fail(d, error.WeirdServerReply, &.{
        "the Sec-WebSocket-Accept value is not the digest of the key zurl sent, so the peer did not answer this handshake",
    });
    // This client offers no extension and no subprotocol, so an answer
    // that names one is describing a stream this build does not read. An
    // extension can change what the reserved bits and the payload mean.
    if (response.named_extension) return fail(d, error.WeirdServerReply, &.{
        "the websocket handshake named an extension that zurl never offered",
    });
    if (response.named_subprotocol) return fail(d, error.WeirdServerReply, &.{
        "the websocket handshake named a subprotocol that zurl never offered",
    });

    return .{ .body = try f.readFrames(&connection, options, d) };
}

/// Reads frames until the peer closes, and returns the payload joined.
///
/// **Every bound the transfer keeps is here.** The size bound counts every
/// octet of data payload, a frame that declares more than the room left is
/// refused before anything is read, and the stall bound stops a peer that
/// says nothing.
///
/// **The size bound alone is not enough**, because a frame can turn this
/// loop and add no octet to the answer. The stall bound does not catch
/// that peer either: octets keep arriving, so no read waits. See
/// `max_empty_frames`, which is the bound for a frame of that shape, and
/// it counts a control frame and an empty data frame together.
fn readFrames(
    f: *Fetcher,
    connection: *zurl_net.Connection,
    options: Options,
    d: ?*Diagnostics,
) Error!Body {
    var session: WsSession = .{
        .io = f.io,
        .channel = .{
            .reader = connection.reader(),
            .writer = connection.writer(),
            .ctx = connection,
            .flush = flushConnection,
        },
    };

    var collected: std.ArrayList(u8) = .empty;
    errdefer collected.deinit(f.allocator);

    var close_code: ?u16 = null;
    var close_reason: []const u8 = "";
    // See `max_empty_frames`. A frame that puts no octet into `collected`
    // is a frame `max_response_bytes` does not count.
    var empty_frames: usize = 0;

    while (true) {
        const header = session.readHeader(options.read_timeout) catch |err| switch (err) {
            // The peer closed between frames. RFC 6455 section 7.1.5 calls
            // that an abnormal closure, and curl ends the transfer there
            // rather than fail it, because everything already read is
            // good.
            error.EndOfStream => break,
            else => return reportFrame(err, connection, d),
        };

        // **The bound on work that yields no answer, and it is one line
        // for every frame kind.** A control frame carries no answer octet
        // whatever its payload, and a data frame of zero octets carries
        // none either. Both are counted here, before the arms below split
        // them apart, so a frame kind added later cannot slip past it.
        if (header.opcode.isControl() or header.payload_len == 0) {
            empty_frames += 1;
            if (empty_frames > max_empty_frames) return fail(d, error.WeirdServerReply, &.{
                "the websocket peer sent more frames that carry no octet of the answer than zurl reads in one transfer, so this transfer was making no progress: the peer is sending empty frames in place of data",
            });
        }

        if (header.opcode.isControl()) {
            const length: usize = @intCast(header.payload_len);
            const payload = f.control_storage[0..length];
            session.readPayload(payload, options.read_timeout) catch |err|
                return reportPayload(err, connection, d);

            switch (header.opcode) {
                // **A ping is answered.** RFC 6455 section 5.5.2 says a
                // pong must carry the ping's own payload, so the answer
                // says which ping it answers.
                .ping => session.writeControl(.pong, payload) catch
                    return reportControlWrite(connection, d),
                .pong => {},
                .close => {
                    const parsed = close.parse(payload, &f.reason_storage) catch |err|
                        return reportClose(err, d);
                    close_code = parsed.code;
                    close_reason = parsed.reason;
                    // The close handshake: answer with a close of our own,
                    // then stop reading. RFC 6455 section 5.5.1.
                    var code_storage: [2]u8 = undefined;
                    session.writeControl(.close, close.write(&code_storage, close.normal)) catch
                        return reportControlWrite(connection, d);
                    break;
                },
                else => unreachable, // `frame.decode` refused every other control opcode.
            }
            continue;
        }

        // **The size bound, read before one octet of payload is.** A
        // frame that declares more than the room left is refused with
        // nothing allocated for it, so a 2^62 declaration costs this
        // process nothing.
        //
        // **The subtraction saturates and does not rest on an
        // invariant.** Every append below is bounded by this same
        // comparison, so `collected.items.len` stays at or under the
        // limit today. In a release build an unsigned subtraction that
        // wrapped would give a room of nearly 2^64 and the bound would
        // silently stop existing for the rest of the transfer, so the
        // spelling that cannot wrap is the one to use.
        const room = options.max_response_bytes -| collected.items.len;
        if (header.payload_len > room) return failNumber(
            d,
            error.FileSizeExceeded,
            "a websocket frame declared more payload than the ",
            options.max_response_bytes,
            " octets zurl reads from one transfer",
        );

        const length: usize = @intCast(header.payload_len);
        const at = collected.items.len;
        collected.resize(f.allocator, at + length) catch
            return Diagnostics.record(d, error.OutOfMemory, .{});
        session.readPayload(collected.items[at..], options.read_timeout) catch |err|
            return reportPayload(err, connection, d);
    }

    const answer = collected.toOwnedSlice(f.allocator) catch
        return Diagnostics.record(d, error.OutOfMemory, .{});
    f.answer = answer;
    f.body = .fixed(answer);

    // **The peer's reason reaches a message only through `close.parse`.**
    // It is bounded and every byte outside printable ASCII is already a
    // `?`, so it cannot draw a line of its own or move a cursor.
    if (close_code) |code| {
        if (code != 1000 and code != 1001) f.recordClose(d, code, close_reason);
    }

    return .{
        .reader = &f.body,
        .length = answer.len,
        .status = switching_protocols,
        .close_code = close_code,
        .close_reason = close_reason,
        .effective_url = if (f.effective_len == 0) "" else f.effective_storage[0..f.effective_len],
    };
}

/// Writes a sentence naming the close code and the cleaned reason into
/// `d`, without failing the transfer.
///
/// A close code other than 1000 or 1001 says the peer ended the session
/// for a reason of its own. Everything already read is still good, so this
/// is a note and not a fault, which is how curl treats the same close.
fn recordClose(f: *Fetcher, d: ?*Diagnostics, code: u16, reason: []const u8) void {
    const target_d = d orelse return;
    var writer: Io.Writer = .fixed(&f.close_message_storage);
    writer.print("the websocket peer closed with code {d}", .{code}) catch {};
    if (reason.len != 0) {
        writer.writeAll(": ") catch {};
        writer.writeAll(reason) catch {};
    }
    target_d.message = writer.buffered();
}

/// `Connection.flush`, as the function pointer a `line.Channel` holds.
///
/// An encrypted connection has a plaintext buffer and a ciphertext buffer
/// in a row, and flushing only the first leaves the frame inside the
/// process.
///
/// The cause of a failed flush is dropped here and read back through
/// `Connection.writeError`, because `line.Channel` names one error for
/// every writer it can carry. `reportControlWrite` is the reader.
fn flushConnection(ctx: ?*anyopaque) Io.Writer.Error!void {
    const connection: *zurl_net.Connection = @ptrCast(@alignCast(ctx.?));
    connection.flush() catch return error.WriteFailed;
}

/// The `Authorization:` value this handshake carries, or null for a
/// transfer with no credential.
///
/// The url's userinfo outranks `-u`, which outranks a netrc entry, which
/// is the order every other protocol package here keeps and the order curl
/// keeps. A transfer that names none sends no header, because a header
/// with an empty credential is a credential the user never chose.
///
/// **The userinfo is percent-decoded and the other two are not**, which is
/// what curl does: a url writes a credential escaped, and `-u` and a netrc
/// file are read as they are written.
fn buildAuthorization(
    f: *Fetcher,
    url: zurl_core.Url,
    options: Options,
    d: ?*Diagnostics,
) Error!?[]const u8 {
    const resolved: Credentials = found: {
        if (url.user) |raw_user| {
            if (raw_user.len > max_credential_bytes) return failCredentialSize(d);
            const user = zurl_core.url.percentDecode(
                f.credential_storage[0..raw_user.len],
                raw_user,
            ) catch return fail(d, error.InvalidUrl, &.{
                "the user name in this url holds a percent escape that is not an escape",
            });
            const password = if (url.password) |raw| pw: {
                if (raw.len > max_credential_bytes) return failCredentialSize(d);
                break :pw zurl_core.url.percentDecode(
                    f.credential_storage[max_credential_bytes..][0..raw.len],
                    raw,
                ) catch return fail(d, error.InvalidUrl, &.{
                    "the password in this url holds a percent escape that is not an escape",
                });
            } else "";
            break :found .{ .user = user, .password = password };
        }
        if (options.credentials) |c| break :found c;
        if (options.netrc_text) |text| {
            if (zurl_core.netrc.lookup(text, url.host)) |entry| {
                break :found .{
                    .user = entry.login orelse "",
                    .password = entry.password orelse "",
                };
            }
        }
        return null;
    };

    return zurl_core.auth.basicValue(&f.authorization_storage, resolved) catch
        return failCredentialSize(d);
}

fn failCredentialSize(d: ?*Diagnostics) Error {
    return fail(d, error.CredentialTooLarge, &.{
        "the credential for this websocket url is longer than zurl sends in one Authorization line",
    });
}

/// The scheme of a url text, or an empty slice when it names none.
fn schemeOf(text: []const u8) []const u8 {
    const colon = std.mem.indexOfScalar(u8, text, ':') orelse return "";
    return text[0..colon];
}

/// Parses `text` the way `zurl.Client` does, with both schemes
/// registered.
fn parseUrl(text: []const u8) zurl_core.url.ParseError!zurl_core.Url {
    var schemes: zurl_core.url.Schemes = .empty;
    schemes.add(.{ .name = scheme, .default_port = default_port }) catch return error.InvalidUrl;
    schemes.add(.{ .name = secure_scheme, .default_port = secure_default_port }) catch
        return error.InvalidUrl;
    return zurl_core.url.parseWith(text, &schemes);
}

/// The TLS options one `wss` hop opens with, or null for a plain `ws` hop.
///
/// **This is the one place in this package that turns peer verification
/// off, and it reads `options.insecure` and nothing else.** A function and
/// not four lines inside `openOnce`, so a test can name both answers and
/// prove that no input other than the flag can reach the second one.
///
/// **A build with no trust store cannot open a `wss` session.** The `null`
/// arm below reports `error.SslConnectError` rather than fall back to
/// `.none`, because a fallback there is exactly the hole this package must
/// not open: `wss` would then be a way to reach a TLS session with no
/// verification at all.
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
            .alpn_protocols = zurl_net.Connection.alpn_http_1_1,
        };
    }

    const trust = options.trust orelse return fail(d, error.SslConnectError, &.{
        "this build gave the websocket package no trust store, so it cannot verify a wss peer",
    });
    try trust.load(trust.ptr);

    return .{
        .host = .{ .explicit = url.host },
        .trust = .{ .bundle = .{ .lock = trust.lock, .bundle = trust.bundle } },
        .min_version = options.tls_min_version,
        .max_version = options.tls_max_version,
        // **`http/1.1` and nothing else.** RFC 6455 section 4.1 upgrades
        // an HTTP/1.1 connection, and RFC 9113 section 8.1 has no such
        // upgrade at all: an `h2` offer here would name a protocol on
        // which this handshake cannot happen.
        .alpn_protocols = zurl_net.Connection.alpn_http_1_1,
        // `allow_truncation_attacks` keeps its default, which is false. A
        // WebSocket ends when somebody closes, so a middle box that cut
        // the connection early would otherwise hand a short answer up as a
        // whole one.
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
        "zurl did not write the websocket handshake",
    });
    return fail(d, error.WriteError, &.{
        "zurl did not write the websocket handshake: ",
        @errorName(cause),
    });
}

/// Reports a control frame that did not reach the peer.
fn reportControlWrite(connection: *zurl_net.Connection, d: ?*Diagnostics) Error {
    const cause = connection.writeError() orelse return fail(d, error.WriteError, &.{
        "zurl did not write a websocket control frame",
    });
    return fail(d, error.WriteError, &.{
        "zurl did not write a websocket control frame: ",
        @errorName(cause),
    });
}

/// Reports a response head that did not read.
fn reportHead(
    err: handshake.ReadError,
    connection: *zurl_net.Connection,
    d: ?*Diagnostics,
) Error {
    return switch (err) {
        error.MalformedHead => fail(d, error.WeirdServerReply, &.{
            "the answer to the websocket handshake is not an HTTP response head",
        }),
        error.HeadTooLarge => fail(d, error.ResponseHeadTooLarge, &.{
            "the answer to the websocket handshake carried a head larger than zurl reads",
        }),
        error.LineTooLong => fail(d, error.HeaderLineTooLarge, &.{
            "the answer to the websocket handshake carried a head line longer than zurl reads",
        }),
        error.EndOfStream => fail(d, error.WeirdServerReply, &.{
            "the peer closed before it finished answering the websocket handshake",
        }),
        else => reportRead(@errorCast(err), connection, d),
    };
}

/// Reports a frame header that did not read.
fn reportFrame(
    err: WsSession.ReadError,
    connection: *zurl_net.Connection,
    d: ?*Diagnostics,
) Error {
    return switch (err) {
        error.ServerFrameMasked => fail(d, error.WeirdServerReply, &.{
            "the server masked a websocket frame, and RFC 6455 says a server must not",
        }),
        error.ReservedBitSet => fail(d, error.WeirdServerReply, &.{
            "a websocket frame set a reserved bit, which names an extension zurl never offered",
        }),
        error.ReservedOpcode => fail(d, error.WeirdServerReply, &.{
            "a websocket frame carried an opcode RFC 6455 keeps for later",
        }),
        error.BadControlFrame => fail(d, error.WeirdServerReply, &.{
            "a websocket control frame was split or longer than the 125 octets RFC 6455 allows one",
        }),
        error.NonMinimalLength => fail(d, error.WeirdServerReply, &.{
            "a websocket frame wrote its length in a longer form than it needs, which RFC 6455 forbids",
        }),
        error.LengthTooLarge => fail(d, error.WeirdServerReply, &.{
            "a websocket frame declared a length with its top bit set, which RFC 6455 forbids",
        }),
        // Not a shape on the wire. `Session.readHeader` reads exactly the
        // octets the prefix named, so this says a caller sized its read
        // wrongly and never that the peer did anything.
        error.HeaderLengthMismatch => fail(d, error.ReadError, &.{
            "zurl read the wrong number of octets for a websocket frame header",
        }),
        error.MessageOutOfOrder => fail(d, error.WeirdServerReply, &.{
            "the server sent a websocket continuation frame with no message open, or started a new message before it finished the last one, and RFC 6455 section 5.4 says a reader must refuse both",
        }),
        error.EndOfStream => fail(d, error.PartialFile, &.{
            "the peer closed in the middle of a websocket frame header",
        }),
        else => reportRead(@errorCast(err), connection, d),
    };
}

/// Reports a payload that did not read.
fn reportPayload(
    err: zurl_net.bounded.ExactError,
    connection: *zurl_net.Connection,
    d: ?*Diagnostics,
) Error {
    if (err == error.EndOfStream) return fail(d, error.PartialFile, &.{
        "the peer closed in the middle of a websocket frame payload",
    });
    return reportRead(@errorCast(err), connection, d);
}

/// Reports a close frame whose payload RFC 6455 does not allow.
fn reportClose(err: close.ParseError, d: ?*Diagnostics) Error {
    return switch (err) {
        error.ShortPayload => fail(d, error.WeirdServerReply, &.{
            "a websocket close frame carried one octet, which is neither a status code nor an absent one",
        }),
        error.ReservedCode => fail(d, error.WeirdServerReply, &.{
            "a websocket close frame named a status code RFC 6455 says must never travel",
        }),
    };
}

/// Reports a read fault that came off the socket.
fn reportRead(
    err: zurl_net.bounded.ReadError,
    connection: *zurl_net.Connection,
    d: ?*Diagnostics,
) Error {
    return switch (err) {
        error.OutOfMemory => Diagnostics.record(d, error.OutOfMemory, .{}),
        error.StreamTooLong => fail(d, error.FileSizeExceeded, &.{
            "the websocket peer wrote more than zurl reads from one transfer",
        }),
        error.OperationTimedOut => fail(d, error.OperationTimedOut, &.{
            "the websocket peer sent no octet for as long as zurl waits, and a websocket ends only when somebody closes",
        }),
        error.ReadTimeoutUnsupported => fail(d, error.ReadError, &.{
            "this build has no concurrency, so a websocket read cannot be bounded, and an unbounded one would wait for a peer that may never answer",
        }),
        error.Canceled => fail(d, error.AbortedByCallback, &.{
            "the websocket read was stopped from outside",
        }),
        error.ReadFailed => {
            const cause = connection.readError() orelse return fail(d, error.ReadError, &.{
                "zurl did not read the websocket answer",
            });
            return fail(d, error.ReadError, &.{
                "zurl did not read the websocket answer: ",
                @errorName(cause),
            });
        },
    };
}

/// Reports a redirect target this package will not open.
fn reportTarget(err: target.ResolveError, d: ?*Diagnostics) Error {
    return switch (err) {
        error.UnsafeLocation => fail(d, error.InvalidUrl, &.{
            "the redirect target holds a byte no url may carry, and it would end the request line of the next hop",
        }),
        error.EmptyLocation => fail(d, error.InvalidUrl, &.{
            "the redirect named an empty location",
        }),
        error.RelativeTarget => fail(d, error.InvalidUrl, &.{
            "the redirect target is a relative reference that zurl does not merge for a websocket url",
        }),
        error.TargetTooLong => fail(d, error.InvalidUrl, &.{
            "the redirect target is longer than zurl reads",
        }),
    };
}

/// Writes `parts`, one after another, into `d`'s own message storage,
/// records `err` with that message, and returns `err`.
///
/// The text goes into `Diagnostics.message_storage` because a sentence may
/// name a host this package holds in a buffer it reuses, so a borrowed
/// message would read the next transfer's url.
fn fail(d: ?*Diagnostics, err: Error, parts: []const []const u8) Error {
    const target_d = d orelse return err;
    const out: []u8 = &target_d.message_storage;
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

/// `fail` for a fault that also names the peer's status.
fn failStatus(d: ?*Diagnostics, err: Error, status: u16, message: []const u8) Error {
    const target_d = d orelse return err;
    target_d.status = status;
    return fail(d, err, &.{message});
}

/// Returns the dispatch entry for the plain `ws` scheme.
///
/// `Front` is the front package's own namespace, taken as a comptime
/// parameter. Passing the namespace rather than importing it is what keeps
/// this package free of a `zurl` import: the front package imports no
/// protocol package, and no protocol package imports the front package, so
/// a build can leave any protocol out and a program outside this
/// repository can bring its own in.
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
        // run direct. curl carries ws and wss through a proxy and this
        // build does not. See `Front.protocol.Unread`.
        .unread = .{ .proxy = true },
    };
}

/// Returns the dispatch entry for the `wss` scheme. See `protocol`.
pub fn secureProtocol(f: *Fetcher, comptime Front: type) Front.protocol.Protocol {
    return .{
        .scheme = secure_scheme,
        .default_port = secure_default_port,
        .ptr = f,
        .vtable = &Dispatch(Front).vtable,
        // This package dials the origin itself and reads no proxy field,
        // so a transfer that named a proxy is refused by name rather than
        // run direct. curl carries ws and wss through a proxy and this
        // build does not. See `Front.protocol.Unread`.
        .unread = .{ .proxy = true },
    };
}

/// The vtable for one front package. One instantiation for each `Front`,
/// and each one holds a single comptime constant, so the table lives in
/// the binary's own read-only data and never on a stack.
fn Dispatch(comptime Front: type) type {
    return struct {
        const vtable: Front.protocol.Protocol.VTable = .{ .perform = performWs };

        fn performWs(
            ptr: ?*anyopaque,
            c: *Front.Client,
            url: zurl_core.Url,
            options: Front.Transfer.Options,
            d: ?*Diagnostics,
        ) Error!Front.Response {
            const f: *Fetcher = @ptrCast(@alignCast(ptr.?));
            const body = try f.open(url, translate(c, options), d);
            return .{
                .status = body.status,
                .content_length = body.length,
                .transfer_encoding = .none,
                .body = body.reader,
                .effective_url = body.effective_url,
            };
        }

        /// Reads the front package's own options into this package's.
        ///
        /// **`--max-filesize` narrows the bound and never widens it.** A
        /// zero there means the user named none, so the package bound
        /// stands.
        ///
        /// **`--speed-time` narrows the wait the same way.** The front
        /// package's stall guard cannot reach this transfer:
        /// `Client.perform` clears `body_stack_live` before it dispatches,
        /// and this package returns a reader over memory whose octets are
        /// all read before `open` returns.
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
                .insecure = options.insecure,
                .tls_min_version = options.tls_min_version,
                .tls_max_version = options.tls_max_version,
                .trust = .{
                    .lock = materials.lock,
                    .bundle = materials.bundle,
                    .ptr = materials.ptr,
                    .load = materials.load,
                },
                .user_agent = options.user_agent,
                .credentials = options.credentials,
                .netrc_text = options.netrc_text,
                .max_redirects = switch (options.redirects) {
                    .unfollowed => null,
                    .follow => |limit| limit,
                },
                .redirect_protocols = options.redirect_protocols,
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

    const Redirects = union(enum) { unfollowed, follow: u32 };

    const Transfer = struct {
        const Options = struct {
            connect_timeout: Io.Timeout = .none,
            low_speed_limit: u64 = 1,
            low_speed_time_s: u32 = 300,
            max_size: u64 = 0,
            tcp_no_delay: bool = true,
            insecure: bool = false,
            tls_min_version: zurl_core.tls.MinVersion = .floor,
            tls_max_version: zurl_core.tls.Version = .highest,
            user_agent: []const u8 = "zurl/0.1",
            credentials: ?Credentials = null,
            netrc_text: ?[]const u8 = null,
            redirects: Redirects = .{ .follow = 10 },
            redirect_protocols: zurl_core.redirect.Set = zurl_core.redirect.redirect_default,
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

test {
    _ = close;
    _ = frame;
    _ = handshake;
    _ = target;
    _ = WsSession;
    _ = test_server;
}

test "both schemes name the ports RFC 6455 gives them" {
    try testing.expectEqualStrings("ws", scheme);
    try testing.expectEqualStrings("wss", secure_scheme);
    try testing.expectEqual(@as(?u16, 80), default_port);
    try testing.expectEqual(@as(?u16, 443), secure_default_port);
}

test "both schemes share one vtable, because they share one protocol" {
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    const plain = f.protocol(StubFront);
    const secure = f.secureProtocol(StubFront);
    try testing.expectEqual(plain.vtable, secure.vtable);
    try testing.expectEqualStrings("ws", plain.scheme);
    try testing.expectEqualStrings("wss", secure.scheme);
    try testing.expectEqual(@as(?u16, 80), plain.default_port);
    try testing.expectEqual(@as(?u16, 443), secure.default_port);
}

/// Runs one transfer against `server` and returns its answer.
fn fetch(
    f: *Fetcher,
    server: *const test_server.Server,
    path: []const u8,
    options: Options,
    d: ?*Diagnostics,
) Error!Body {
    var url_buffer: [128]u8 = undefined;
    const text = std.fmt.bufPrint(
        &url_buffer,
        "ws://127.0.0.1:{d}{s}",
        .{ server.port(), path },
    ) catch return error.InvalidUrl;
    return f.open(try parseUrl(text), options, d);
}

/// Reads the whole body of `body`. The caller frees it.
fn drain(body: Body) ![]u8 {
    return body.reader.allocRemaining(testing.allocator, .unlimited);
}

test "a whole exchange: the request goes out, the payload comes back, and the close is answered" {
    var frames: [256]u8 = undefined;
    var at: usize = 0;
    at += test_server.serverFrame(frames[at..], .text, "hello ws", true).len;
    at += test_server.serverFrame(frames[at..], .binary, " and more", true).len;
    at += test_server.serverFrame(frames[at..], .close, "\x03\xe8", true).len;

    var server: test_server.Server = undefined;
    try server.start(.{ .frames = frames[0..at], .expect_client_frames = 1 });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    const body = try fetch(&f, &server, "/chat?room=1", .{}, null);

    // The payload of every data frame, joined, which is what curl's own
    // tool writes to standard output.
    const contents = try drain(body);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("hello ws and more", contents);
    try testing.expectEqual(@as(u16, 101), body.status);
    try testing.expectEqual(@as(?u16, 1000), body.close_code);

    // The request head carries the five lines RFC 6455 section 4.1 asks
    // for.
    const head = server.received();
    try testing.expect(std.mem.startsWith(u8, head, "GET /chat?room=1 HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, head, "\r\nUpgrade: websocket\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "\r\nConnection: Upgrade\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "\r\nSec-WebSocket-Version: 13\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "\r\nSec-WebSocket-Key: ") != null);

    // The close the client sent back is masked, which RFC 6455 section 5.1
    // requires of every client frame.
    server.awaitDone();
    try testing.expectEqual(@as(usize, 1), server.clientFrames());
    try testing.expectEqual(frame.Opcode.close, server.clientOpcode(0));
    try testing.expect(server.clientMasked(0));
}

test "a wrong Sec-WebSocket-Accept fails the transfer" {
    // **This is the check that makes the handshake prove anything.** The
    // server answers 101 with every other line right, and one value wrong.
    var frames: [64]u8 = undefined;
    const written = test_server.serverFrame(&frames, .text, "should never be read", true);

    var server: test_server.Server = undefined;
    try server.start(.{
        .accept = .{ .text = "AAAAAAAAAAAAAAAAAAAAAAAAAAA=" },
        .frames = written,
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    try testing.expectError(
        error.WeirdServerReply,
        fetch(&f, &server, "/chat", .{}, &d),
    );
    try testing.expect(std.mem.indexOf(u8, d.message.?, "Sec-WebSocket-Accept") != null);
    try testing.expectEqual(@as(?u32, 8), d.curl_code);
}

test "a 101 with no Sec-WebSocket-Accept at all fails the transfer" {
    var server: test_server.Server = undefined;
    try server.start(.{ .accept = .none });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    try testing.expectError(error.WeirdServerReply, fetch(&f, &server, "/chat", .{}, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "nothing proves") != null);
}

test "a 101 with no upgrade lines fails the transfer" {
    var server: test_server.Server = undefined;
    try server.start(.{ .write_upgrade_headers = false });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    try testing.expectError(error.WeirdServerReply, fetch(&f, &server, "/chat", .{}, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "Upgrade") != null);
}

test "an extension or a subprotocol the transfer never offered fails it" {
    var server: test_server.Server = undefined;
    try server.start(.{ .extra_headers = "Sec-WebSocket-Extensions: permessage-deflate\r\n" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    try testing.expectError(error.WeirdServerReply, fetch(&f, &server, "/chat", .{}, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "extension") != null);

    var second: test_server.Server = undefined;
    try second.start(.{ .extra_headers = "Sec-WebSocket-Protocol: chat\r\n" });
    defer second.stop();

    var g: Fetcher = .init(testing.allocator, testing.io);
    defer g.deinit();
    var second_d: Diagnostics = .{};
    try testing.expectError(error.WeirdServerReply, fetch(&g, &second, "/chat", .{}, &second_d));
    try testing.expect(std.mem.indexOf(u8, second_d.message.?, "subprotocol") != null);
}

test "a masked frame from the server fails the transfer" {
    // RFC 6455 section 5.1: a server must not mask. A client that read the
    // four key octets as payload would let a peer choose whether its own
    // text is read as a key or as data.
    var frames: [64]u8 = undefined;
    var header_storage: [frame.max_header_bytes]u8 = undefined;
    const header = frame.encode(&header_storage, .{
        .fin = true,
        .opcode = .text,
        .masked = true,
        .payload_len = 5,
        .mask_key = .{ 0x37, 0xfa, 0x21, 0x3d },
    });
    @memcpy(frames[0..header.len], header);
    var payload: [5]u8 = "Hello".*;
    frame.applyMask(&payload, .{ 0x37, 0xfa, 0x21, 0x3d }, 0);
    @memcpy(frames[header.len..][0..5], &payload);

    var server: test_server.Server = undefined;
    try server.start(.{ .frames = frames[0 .. header.len + 5] });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    try testing.expectError(error.WeirdServerReply, fetch(&f, &server, "/chat", .{}, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "masked") != null);
}

test "a continuation frame with no message open fails the transfer" {
    // RFC 6455 section 5.4: a `continuation` frame continues the message
    // the last non-final frame started. With no message open there is
    // nothing to continue. A reader that kept no fragmentation state
    // wrote these five octets to standard output as a message of their
    // own.
    var frames: [64]u8 = undefined;
    const written = test_server.serverFrame(&frames, .continuation, "Hello", true);

    var server: test_server.Server = undefined;
    try server.start(.{ .frames = written });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    try testing.expectError(error.WeirdServerReply, fetch(&f, &server, "/chat", .{}, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "continuation") != null);
}

test "a message split into fragments reads whole, and a second start in the middle fails" {
    // The legal shape first: "Hel" as a non-final text frame and "lo" as
    // the continuation that finishes it. Both halves must reach the body.
    var frames: [128]u8 = undefined;
    var at: usize = 0;
    at += test_server.serverFrame(frames[at..], .text, "Hel", false).len;
    at += test_server.serverFrame(frames[at..], .continuation, "lo", true).len;
    at += test_server.serverFrame(frames[at..], .close, "\x03\xe8", true).len;

    var server: test_server.Server = undefined;
    try server.start(.{ .frames = frames[0..at] });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    const body = try fetch(&f, &server, "/chat", .{}, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("Hello", contents);

    // And the shape section 5.4 refuses: a new message that starts while
    // the last one is unfinished.
    var bad: [128]u8 = undefined;
    var bad_at: usize = 0;
    bad_at += test_server.serverFrame(bad[bad_at..], .text, "Hel", false).len;
    bad_at += test_server.serverFrame(bad[bad_at..], .text, "lo", true).len;

    var bad_server: test_server.Server = undefined;
    try bad_server.start(.{ .frames = bad[0..bad_at] });
    defer bad_server.stop();

    var g: Fetcher = .init(testing.allocator, testing.io);
    defer g.deinit();
    var d: Diagnostics = .{};
    try testing.expectError(error.WeirdServerReply, fetch(&g, &bad_server, "/chat", .{}, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "continuation") != null);
}

test "a frame that declares more payload than the bound is refused before it is read" {
    // The header claims a terabyte and carries no payload at all, so a
    // client that allocated on the declaration would ask for a terabyte.
    var frames: [16]u8 = undefined;
    var header_storage: [frame.max_header_bytes]u8 = undefined;
    const header = frame.encode(&header_storage, .{
        .fin = true,
        .opcode = .binary,
        .masked = false,
        .payload_len = @as(u64, 1) << 40,
    });
    @memcpy(frames[0..header.len], header);

    var server: test_server.Server = undefined;
    try server.start(.{ .frames = frames[0..header.len] });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    try testing.expectError(
        error.FileSizeExceeded,
        fetch(&f, &server, "/chat", .{}, &d),
    );
    try testing.expectEqual(@as(?u32, 63), d.curl_code);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "declared more payload") != null);
}

test "a run of frames past the bound is refused, and the bound counts them together" {
    var frames: [256]u8 = undefined;
    var at: usize = 0;
    at += test_server.serverFrame(frames[at..], .text, "0123456789", true).len;
    at += test_server.serverFrame(frames[at..], .text, "0123456789", true).len;

    var server: test_server.Server = undefined;
    try server.start(.{ .frames = frames[0..at] });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    try testing.expectError(
        error.FileSizeExceeded,
        fetch(&f, &server, "/chat", .{ .max_response_bytes = 15 }, null),
    );

    // The same two frames under a bound that fits them read whole. So the
    // refusal above is the bound and not the frames.
    var second: test_server.Server = undefined;
    try second.start(.{ .frames = frames[0..at] });
    defer second.stop();

    var g: Fetcher = .init(testing.allocator, testing.io);
    defer g.deinit();
    const body = try fetch(&g, &second, "/chat", .{ .max_response_bytes = 20 }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("01234567890123456789", contents);
}

test "a ping is answered with a pong that carries the ping's own payload" {
    var frames: [256]u8 = undefined;
    var at: usize = 0;
    at += test_server.serverFrame(frames[at..], .ping, "keepalive", true).len;
    at += test_server.serverFrame(frames[at..], .text, "after", true).len;
    at += test_server.serverFrame(frames[at..], .close, "\x03\xe8", true).len;

    var server: test_server.Server = undefined;
    try server.start(.{ .frames = frames[0..at], .expect_client_frames = 2 });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    const body = try fetch(&f, &server, "/chat", .{}, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);
    // A ping carries no message, so its payload never reaches the body.
    try testing.expectEqualStrings("after", contents);

    server.awaitDone();
    try testing.expectEqual(@as(usize, 2), server.clientFrames());
    try testing.expectEqual(frame.Opcode.pong, server.clientOpcode(0));
    try testing.expectEqualStrings("keepalive", server.clientPayload(0));
    try testing.expectEqual(frame.Opcode.close, server.clientOpcode(1));

    // **Every client frame is masked, and each one carries its own key.**
    // RFC 6455 section 5.3 asks for both. Two frames under one key hand an
    // attacker the exclusive-or of the two payloads.
    try testing.expect(server.clientMasked(0));
    try testing.expect(server.clientMasked(1));
    try testing.expect(!std.mem.eql(
        u8,
        &server.clientMaskKey(0),
        &server.clientMaskKey(1),
    ));
}

test "a peer that pings for ever is refused instead of answered for ever" {
    // **One of the two things a peer can send that the answer bound does
    // not count.** A control payload never reaches `collected`, so
    // `max_response_bytes` never fires for it, and every ping is answered
    // with a pong. Two octets on the wire bought one answer, for ever, and
    // `-m` is off by default. The empty data frame below is the other one.
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    var i: usize = 0;
    while (i < max_empty_frames + 1) : (i += 1) {
        var one: [frame.max_header_bytes]u8 = undefined;
        const written = test_server.serverFrame(&one, .ping, "", true);
        try script.appendSlice(testing.allocator, written);
    }

    var server: test_server.Server = undefined;
    try server.start(.{
        .frames = script.items,
        .expect_client_frames = test_server.max_client_frames,
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    try testing.expectError(
        error.WeirdServerReply,
        fetch(&f, &server, "/chat", .{}, &d),
    );
    try testing.expectEqual(@as(?u32, 8), d.curl_code);
}

test "a peer that sends empty data frames for ever is refused instead of read for ever" {
    // **The other thing a peer can send for nothing, and the one the
    // control bound above did not cover.** `82 00` is a legal binary frame
    // with no payload. It passes the room check, because zero is never
    // more than the room left, it adds no octet to `collected`, and the
    // loop goes round again. The size bound therefore stands still while
    // the peer writes two octets a turn, and the stall bound never fires
    // because octets keep arriving.
    //
    // The script holds one frame more than the bound, so the refusal
    // arrives after a known number of frames and not after a wait.
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    var i: usize = 0;
    while (i < max_empty_frames + 1) : (i += 1) {
        var one: [frame.max_header_bytes]u8 = undefined;
        const written = test_server.serverFrame(&one, .binary, "", true);
        try script.appendSlice(testing.allocator, written);
    }

    var server: test_server.Server = undefined;
    try server.start(.{ .frames = script.items });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    // **The size bound is wide open here**, so nothing but the frame count
    // can end this transfer. That is the whole point: a run with
    // `--max-filesize 16` read 200 000 of these frames and exited 0.
    try testing.expectError(
        error.WeirdServerReply,
        fetch(&f, &server, "/chat", .{}, &d),
    );
    try testing.expectEqual(@as(?u32, 8), d.curl_code);
    // The message must name what the peer did, so a user reads it and
    // knows the fault is at the other end.
    try testing.expect(std.mem.indexOf(u8, d.message.?, "no octet of the answer") != null);
}

test "a handful of empty data frames does not fail a transfer" {
    // **The bound is a count and never a refusal of the first one.** RFC
    // 6455 section 5.4 allows a data frame with no payload and allows a
    // continuation frame with no payload, so a peer that sends a few is
    // keeping the rules and must be read.
    var frames: [256]u8 = undefined;
    var at: usize = 0;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        at += test_server.serverFrame(frames[at..], .binary, "", true).len;
    }
    at += test_server.serverFrame(frames[at..], .text, "payload", true).len;
    at += test_server.serverFrame(frames[at..], .close, "\x03\xe8", true).len;

    var server: test_server.Server = undefined;
    try server.start(.{ .frames = frames[0..at], .expect_client_frames = 1 });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    const body = try fetch(&f, &server, "/chat", .{}, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);
    // An empty frame adds nothing, so the answer is the one frame that
    // carried something.
    try testing.expectEqualStrings("payload", contents);
}

test "a close reason reaches a message with its control bytes gone" {
    // The reason is the peer's own text. `close.parse` bounds it and
    // replaces every byte outside printable ASCII, so it cannot draw a
    // line that reads like one of zurl's own.
    var frames: [256]u8 = undefined;
    var at: usize = 0;
    at += test_server.serverFrame(frames[at..], .text, "data", true).len;
    at += test_server.serverFrame(
        frames[at..],
        .close,
        "\x03\xf1" ++ "policy\x1b[31m\nzurl: forged",
        true,
    ).len;

    var server: test_server.Server = undefined;
    try server.start(.{ .frames = frames[0..at], .expect_client_frames = 1 });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    const body = try fetch(&f, &server, "/chat", .{}, &d);
    const contents = try drain(body);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("data", contents);

    try testing.expectEqual(@as(?u16, 1009), body.close_code);
    try testing.expectEqualStrings("policy?[31m?zurl: forged", body.close_reason);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "1009") != null);
    try testing.expect(std.mem.indexOfScalar(u8, d.message.?, '\n') == null);
    try testing.expect(std.mem.indexOfScalar(u8, d.message.?, 0x1b) == null);
}

test "a close frame with a status code RFC 6455 forbids fails the transfer" {
    // 1006 names a closure that by definition never arrives on the wire,
    // so a peer that writes it is forging the reason a transfer ended.
    var frames: [64]u8 = undefined;
    const written = test_server.serverFrame(&frames, .close, "\x03\xee", true);

    var server: test_server.Server = undefined;
    try server.start(.{ .frames = written });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    try testing.expectError(error.WeirdServerReply, fetch(&f, &server, "/chat", .{}, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "must never travel") != null);
}

test "a peer that closes between frames ends the transfer with what it sent" {
    var frames: [64]u8 = undefined;
    const written = test_server.serverFrame(&frames, .text, "partial", true);

    var server: test_server.Server = undefined;
    try server.start(.{ .frames = written });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    const body = try fetch(&f, &server, "/chat", .{}, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("partial", contents);
    try testing.expectEqual(@as(?u16, null), body.close_code);
}

test "a peer that closes inside a frame fails the transfer" {
    var frames: [64]u8 = undefined;
    const written = test_server.serverFrame(&frames, .text, "abcdefgh", true);

    var server: test_server.Server = undefined;
    // Two octets of the payload are missing.
    try server.start(.{ .frames = written[0 .. written.len - 2] });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    try testing.expectError(error.PartialFile, fetch(&f, &server, "/chat", .{}, &d));
    try testing.expectEqual(@as(?u32, 18), d.curl_code);
}

test "a status other than 101 is the peer's own number, and the transfer fails" {
    var server: test_server.Server = undefined;
    try server.start(.{ .status_line = "HTTP/1.1 403 Forbidden", .accept = .none });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    try testing.expectError(error.HttpReturnedError, fetch(&f, &server, "/chat", .{}, &d));
    try testing.expectEqual(@as(?u16, 403), d.status);
    try testing.expectEqual(@as(?u32, 22), d.curl_code);
}

/// The redirect policy a WebSocket transfer needs to follow a hop.
///
/// **`zurl_core.redirect.redirect_default` does not name `ws`.** curl's
/// own `--proto-redir` default is `http,https,ftp,ftps`, and zurl's is the
/// same list, so a redirect into a WebSocket url is refused unless the
/// user asked for it. A test that wants the hop followed has to say so,
/// exactly as a user would with `--proto-redir +ws`.
const ws_redirects: zurl_core.redirect.Set = .init(&.{ .ws, .wss });

test "the redirect default does not name ws, so a hop into one is refused" {
    // Measured against curl 8.21.0's documented default for
    // `--proto-redir`, which is `http,https,ftp,ftps`.
    try testing.expect(!zurl_core.redirect.redirect_default.hasScheme("ws"));
    try testing.expect(!zurl_core.redirect.redirect_default.hasScheme("wss"));

    var first: test_server.Server = undefined;
    try first.start(.{
        .status_line = "HTTP/1.1 302 Found",
        .write_upgrade_headers = false,
        .accept = .none,
        .extra_headers = "Location: ws://127.0.0.1:1/next\r\n",
    });
    defer first.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    try testing.expectError(
        error.UnsupportedProtocol,
        fetch(&f, &first, "/chat", .{ .max_redirects = 10 }, &d),
    );
    try testing.expect(std.mem.indexOf(u8, d.message.?, "may not follow into") != null);
}

test "a redirect is followed when the caller asked for one" {
    var frames: [128]u8 = undefined;
    var at: usize = 0;
    at += test_server.serverFrame(frames[at..], .text, "moved here", true).len;
    at += test_server.serverFrame(frames[at..], .close, "\x03\xe8", true).len;

    var second: test_server.Server = undefined;
    try second.start(.{ .frames = frames[0..at], .expect_client_frames = 1 });
    defer second.stop();

    var location: [96]u8 = undefined;
    const header_line = try std.fmt.bufPrint(
        &location,
        "Location: ws://127.0.0.1:{d}/next\r\n",
        .{second.port()},
    );

    var first: test_server.Server = undefined;
    try first.start(.{
        .status_line = "HTTP/1.1 302 Found",
        .write_upgrade_headers = false,
        .accept = .none,
        .extra_headers = header_line,
    });
    defer first.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    const body = try fetch(&f, &first, "/chat", .{
        .max_redirects = 10,
        .redirect_protocols = ws_redirects,
    }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("moved here", contents);
    try testing.expect(std.mem.endsWith(u8, body.effective_url, "/next"));
    try testing.expect(std.mem.startsWith(u8, second.received(), "GET /next HTTP/1.1\r\n"));
}

test "a redirect is not followed when the caller asked for none" {
    var first: test_server.Server = undefined;
    try first.start(.{
        .status_line = "HTTP/1.1 302 Found",
        .write_upgrade_headers = false,
        .accept = .none,
        .extra_headers = "Location: ws://127.0.0.1:1/next\r\n",
    });
    defer first.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    try testing.expectError(
        error.HttpReturnedError,
        fetch(&f, &first, "/chat", .{ .max_redirects = null }, &d),
    );
    try testing.expectEqual(@as(?u16, 302), d.status);
}

test "a redirect into a protocol the policy forbids never opens" {
    // `zurl_core.redirect` holds the whole rule. A server that could move
    // a transfer to `file` could read any file the user can read.
    var first: test_server.Server = undefined;
    try first.start(.{
        .status_line = "HTTP/1.1 302 Found",
        .write_upgrade_headers = false,
        .accept = .none,
        .extra_headers = "Location: file:///etc/passwd\r\n",
    });
    defer first.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    try testing.expectError(
        error.UnsupportedProtocol,
        fetch(&f, &first, "/chat", .{
            .max_redirects = 10,
            .redirect_protocols = ws_redirects,
        }, &d),
    );
    try testing.expectEqual(@as(?u32, 1), d.curl_code);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "may not follow into") != null);
}

test "a redirect a policy permits but this package cannot open is refused" {
    // `--proto-redir` may name `http`, which this package does not speak.
    // The refusal says so, rather than open a scheme it cannot read.
    var first: test_server.Server = undefined;
    try first.start(.{
        .status_line = "HTTP/1.1 302 Found",
        .write_upgrade_headers = false,
        .accept = .none,
        .extra_headers = "Location: http://127.0.0.1:1/next\r\n",
    });
    defer first.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    try testing.expectError(
        error.UnsupportedProtocol,
        fetch(&f, &first, "/chat", .{ .max_redirects = 10 }, &d),
    );
    try testing.expect(std.mem.indexOf(u8, d.message.?, "ws and wss alone") != null);
}

test "a redirect target holding a framing byte never reaches a request line" {
    var first: test_server.Server = undefined;
    try first.start(.{
        .status_line = "HTTP/1.1 302 Found",
        .write_upgrade_headers = false,
        .accept = .none,
        // The fixture writes the head line by line, so the injected line
        // arrives as a header of its own, and the reader hands the value
        // up with no CR in it. The bytes a real server can smuggle are the
        // ones a single line can carry, and a raw space is one of them.
        .extra_headers = "Location: /a b\r\n",
    });
    defer first.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    try testing.expectError(
        error.InvalidUrl,
        fetch(&f, &first, "/chat", .{ .max_redirects = 10 }, &d),
    );
}

test "a redirect chain longer than the limit is refused" {
    // **A chain, and not a limit of zero.** This test used to pass
    // `max_redirects = 0`, so no hop was ever walked and it proved the
    // same thing as "a redirect is not followed when the caller asked for
    // none". A limit of one walks the first hop for real and refuses the
    // second, which is the rule the name claims.
    var second_location: [96]u8 = undefined;
    var second: test_server.Server = undefined;
    try second.start(.{
        .status_line = "HTTP/1.1 302 Found",
        .write_upgrade_headers = false,
        .accept = .none,
        .extra_headers = "Location: /third\r\n",
    });
    defer second.stop();

    const first_line = try std.fmt.bufPrint(
        &second_location,
        "Location: ws://127.0.0.1:{d}/second\r\n",
        .{second.port()},
    );

    var first: test_server.Server = undefined;
    try first.start(.{
        .status_line = "HTTP/1.1 302 Found",
        .write_upgrade_headers = false,
        .accept = .none,
        .extra_headers = first_line,
    });
    defer first.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    try testing.expectError(error.TooManyRedirects, fetch(&f, &first, "/chat", .{
        .max_redirects = 1,
        .redirect_protocols = ws_redirects,
    }, &d));
    try testing.expectEqual(@as(?u32, 47), d.curl_code);
    // The first hop really ran: the second fixture answered a request.
    try testing.expect(std.mem.startsWith(u8, second.received(), "GET /second HTTP/1.1\r\n"));
}

test "a second hop may be relative to the target the first hop named" {
    // **The abort this test exists for.** `open` parsed the base of the
    // next hop out of `target_storage`, the same buffer `target.resolve`
    // writes into. A second hop whose `Location` is relative then copied a
    // region onto itself, and `@memcpy` refuses arguments that alias, so
    // the process died in Debug and in ReleaseSafe alike. One hop cannot
    // reach it: the first base is the caller's own url.
    //
    // The second target here is authority-relative, so it takes the scheme
    // of the hop before it, and that scheme is the slice that aliased.
    var frames: [128]u8 = undefined;
    var at: usize = 0;
    at += test_server.serverFrame(frames[at..], .text, "arrived", true).len;
    at += test_server.serverFrame(frames[at..], .close, "\x03\xe8", true).len;

    var third: test_server.Server = undefined;
    try third.start(.{ .frames = frames[0..at], .expect_client_frames = 1 });
    defer third.stop();

    var second_storage: [96]u8 = undefined;
    const second_line = try std.fmt.bufPrint(
        &second_storage,
        "Location: //127.0.0.1:{d}/third\r\n",
        .{third.port()},
    );
    var second: test_server.Server = undefined;
    try second.start(.{
        .status_line = "HTTP/1.1 302 Found",
        .write_upgrade_headers = false,
        .accept = .none,
        .extra_headers = second_line,
    });
    defer second.stop();

    var first_storage: [96]u8 = undefined;
    const first_line = try std.fmt.bufPrint(
        &first_storage,
        "Location: ws://127.0.0.1:{d}/second\r\n",
        .{second.port()},
    );
    var first: test_server.Server = undefined;
    try first.start(.{
        .status_line = "HTTP/1.1 302 Found",
        .write_upgrade_headers = false,
        .accept = .none,
        .extra_headers = first_line,
    });
    defer first.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    const body = try fetch(&f, &first, "/chat", .{
        .max_redirects = 10,
        .redirect_protocols = ws_redirects,
    }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("arrived", contents);
    try testing.expect(std.mem.endsWith(u8, body.effective_url, "/third"));
    try testing.expect(std.mem.startsWith(u8, third.received(), "GET /third HTTP/1.1\r\n"));
}

test "a credential reaches the handshake as a Basic line" {
    var frames: [64]u8 = undefined;
    const written = test_server.serverFrame(&frames, .close, "\x03\xe8", true);

    var server: test_server.Server = undefined;
    try server.start(.{ .frames = written, .expect_client_frames = 1 });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    _ = try fetch(&f, &server, "/chat", .{
        .credentials = .{ .user = "alice", .password = "s3cret" },
    }, null);

    // `Basic ` and the base64 of `alice:s3cret`.
    try testing.expect(std.mem.indexOf(
        u8,
        server.received(),
        "Authorization: Basic YWxpY2U6czNjcmV0\r\n",
    ) != null);
}

test "a transfer with no credential sends no Authorization line" {
    var frames: [64]u8 = undefined;
    const written = test_server.serverFrame(&frames, .close, "\x03\xe8", true);

    var server: test_server.Server = undefined;
    try server.start(.{ .frames = written, .expect_client_frames = 1 });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    _ = try fetch(&f, &server, "/chat", .{}, null);
    try testing.expect(std.mem.indexOf(u8, server.received(), "Authorization:") == null);
}

test "a wss url with no trust store cannot open a session at all" {
    // **The fallback this arm exists to refuse.** A `wss` session that
    // opened with `.none` would verify nothing, so `wss` would become a
    // way to reach an unverified TLS session.
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    const url = try parseUrl("wss://example.com/chat");
    var d: Diagnostics = .{};
    try testing.expectError(
        error.SslConnectError,
        f.tlsOptions(url, .{ .trust = null }, &d),
    );
    try testing.expect(std.mem.indexOf(u8, d.message.?, "no trust store") != null);
}

test "the tls options verify the peer unless -k said not to" {
    var client: StubFront.Client = .{};
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const plain = try f.tlsOptions(try parseUrl("ws://example.com/chat"), .{}, null);
    try testing.expectEqual(@as(?zurl_net.Connection.Tls, null), plain);

    const trust = client.tlsMaterials();
    const verified = (try f.tlsOptions(
        try parseUrl("wss://example.com/chat"),
        .{ .trust = trust },
        null,
    )).?;
    try testing.expectEqualStrings("example.com", verified.host.explicit);
    switch (verified.trust) {
        .bundle => {},
        else => return error.TestUnexpectedResult,
    }
    // The roots load once, and only for an encrypted url.
    try testing.expectEqual(@as(usize, 1), client.loads);

    // **`-k` is the one input that reaches the other answer.**
    const insecure = (try f.tlsOptions(
        try parseUrl("wss://example.com/chat"),
        .{ .trust = trust, .insecure = true },
        null,
    )).?;
    try testing.expectEqual(zurl_net.Connection.HostCheck.none, insecure.host);
    switch (insecure.trust) {
        .none => {},
        else => return error.TestUnexpectedResult,
    }
    // `-k` never loads the roots, so it never reads a certificate file.
    try testing.expectEqual(@as(usize, 1), client.loads);
}

test "the alpn offer names http/1.1 and never h2" {
    // RFC 6455 section 4.1 upgrades an HTTP/1.1 connection, and RFC 9113
    // has no such upgrade, so an `h2` offer would name a protocol on which
    // this handshake cannot happen.
    var client: StubFront.Client = .{};
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    const options = (try f.tlsOptions(
        try parseUrl("wss://example.com/chat"),
        .{ .trust = client.tlsMaterials() },
        null,
    )).?;
    try testing.expectEqual(@as(usize, 1), options.alpn_protocols.len);
    try testing.expectEqualStrings("http/1.1", options.alpn_protocols[0]);
}

test "a peer that never answers ends the transfer instead of holding it" {
    var server: test_server.Server = undefined;
    try server.start(.{
        // A head that never ends, so the client waits for a line that
        // never comes.
        .status_line = "HTTP/1.1 101 Switching Protocols",
        .accept = .none,
        .expect_client_frames = 1,
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    // The fixture writes a whole head and then reads, so the client sees a
    // 101 with no accept value. That is the refusal, and it arrives rather
    // than a wait.
    try testing.expectError(error.WeirdServerReply, fetch(&f, &server, "/chat", .{}, &d));
}

test "a url that names no port never dials" {
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    var d: Diagnostics = .{};
    const url: zurl_core.Url = .{
        .scheme = "ws",
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

test "--connect-to moves a websocket dial and --resolve reaches this package too" {
    // The defect this closes: this package read no `connect_to`, so a
    // user who named either flag got a dial to the url's own host and no
    // diagnostic.
    //
    // **No test here touches a resolver.** The url names `127.0.0.2:1`,
    // which refuses at once, so the flag is the only thing that can reach
    // the fixture.
    var frames: [64]u8 = undefined;
    const at = test_server.serverFrame(&frames, .close, "\x03\xe8", true).len;

    var server: test_server.Server = undefined;
    try server.start(.{ .frames = frames[0..at] });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    const url = try parseUrl("ws://127.0.0.2:1/chat");

    var bare: Diagnostics = .{};
    try testing.expectError(error.CouldNotConnect, f.open(url, .{}, &bare));
    try testing.expectEqual(@as(usize, 0), server.connections());

    const body = try f.open(url, .{ .connect_to = &.{.{
        .from_host = "127.0.0.2",
        .from_port = 1,
        .to_host = "127.0.0.1",
        .to_port = server.port(),
    }} }, null);
    _ = body;
    try testing.expectEqual(@as(usize, 1), server.connections());

    // **The `Host:` line still names the url's own host.** A moved dial
    // must not rewrite the handshake, and for `wss` the same text is the
    // name the certificate is checked against.
    try testing.expect(std.mem.indexOf(u8, server.received(), "Host: 127.0.0.2:1") != null);
    try testing.expect(std.mem.indexOf(u8, server.received(), "Host: 127.0.0.1") == null);
}

test "a moved dial leaves a wss certificate checked against the url's own name" {
    // **The rule that keeps this flag from becoming a second `-k`.**
    var client: StubFront.Client = .{};
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const secure = try parseUrl("wss://example.com/chat");
    const overrides: []const zurl_net.override.HostOverride = &.{.{
        .from_host = "example.com",
        .from_port = 443,
        .to_host = "127.0.0.1",
        .to_port = 9999,
    }};

    // The entry does move the dial.
    const moved = zurl_net.override.dialTarget(overrides, secure.host, secure.port.?);
    try testing.expectEqualStrings("127.0.0.1", moved.host);
    try testing.expectEqual(@as(u16, 9999), moved.port);

    // And it reaches neither the name nor the trust decision.
    const tls = (try f.tlsOptions(secure, .{
        .trust = client.tlsMaterials(),
        .connect_to = overrides,
    }, null)).?;
    try testing.expect(tls.host == .explicit);
    try testing.expectEqualStrings("example.com", tls.host.explicit);
    try testing.expect(tls.trust == .bundle);
}

test "the websocket translation carries --connect-to into this package" {
    var client: StubFront.Client = .{};
    const D = Dispatch(StubFront);
    try testing.expectEqual(@as(usize, 0), D.translate(&client, .{}).connect_to.len);

    const overrides: []const zurl_net.override.HostOverride = &.{.{
        .from_host = "a.test",
        .to_host = "127.0.0.1",
        .to_port = 9,
    }};
    const carried = D.translate(&client, .{ .connect_to = overrides });
    try testing.expectEqual(@as(usize, 1), carried.connect_to.len);
    try testing.expectEqualStrings("a.test", carried.connect_to[0].from_host);
}
