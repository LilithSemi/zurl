//! Runs one `pop3://` or `pop3s://` transfer: the dialogue, the login, the
//! command, and the answer.
//!
//! A `Fetcher` owns the answer of the transfer in play. `open` frees
//! whatever the last call left and holds the new answer, so one `Fetcher`
//! serves one transfer at a time, the same rule `zurl.Client` keeps for
//! its own HTTP exchange.
//!
//! **A `Fetcher` must not move once `open` has run.** The body reader it
//! hands back points into this value, and so do the dialogue's own reader
//! and writer.
//!
//! **One package owns both schemes.** RFC 1939 names the dialogue, and
//! `pop3s` changes neither the commands nor the answers: it puts the same
//! two inside TLS. `protocol` and `secureProtocol` build the two dispatch
//! entries, and both point at one vtable that reads `url.scheme`. The two
//! carry different default ports, 110 and 995, which is what curl uses.
//!
//! **What a transfer sends.** The command order is curl's own, measured
//! against curl 8.21.0 on a loopback RFC 1939 fixture:
//!
//!     [STLS], USER and PASS or APOP, LIST or RETR or a --request
//!     command, then QUIT
//!
//! curl sends `CAPA` first and zurl does not. curl reads that answer for
//! two things it has and zurl does not: a SASL mechanism list, and whether
//! `STLS` is offered. zurl offers no SASL, and it learns about `STLS` by
//! sending it, which is one round trip fewer and gives the same answer for
//! `--ssl-reqd`: a refusal is exit 64 and **no credential goes out**.
//!
//! **A url with no path lists and a url with a path retrieves.** That is
//! curl's rule, measured. See `target.Target`.
//!
//! **A login happens only when somebody named a credential.** curl does
//! the same, measured: `pop3://h/` with no `-u` and no userinfo sends no
//! `USER` at all. RFC 1939 has no anonymous login to fall back on, so
//! inventing one would send a name the user did not choose.
//!
//! This file imports `zurl-core` and `zurl-net`. It does not import
//! `zurl`, and it never will. See `protocol`.

const Fetcher = @This();

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_net = @import("zurl-net");

const command = @import("command.zig");
const response = @import("response.zig");
const target = @import("target.zig");
const Control = @import("Control.zig");

const Io = std.Io;
const Error = zurl_core.Error;
const Diagnostics = zurl_core.Diagnostics;

/// The plain scheme this package handles.
pub const scheme = "pop3";

/// The encrypted scheme this package handles.
pub const secure_scheme = "pop3s";

/// The port a `pop3://` url uses when it names none. RFC 1939.
pub const default_port: ?u16 = 110;

/// The port a `pop3s://` url uses when it names none.
///
/// 995, the implicit TLS port. `zurl_core.url.defaultPort` already held
/// the same number.
pub const secure_default_port: ?u16 = 995;

/// The status a POP3 transfer reports.
///
/// Zero. RFC 1939 answers `+OK` and `-ERR` and has no HTTP status. curl
/// prints `000` for `%{http_code}` on a `pop3://` url that worked.
pub const status: u16 = 0;

/// How many bytes of answer this package reads by default.
///
/// A POP3 body ends at a line holding one period, and the server chooses
/// when to write it, so the bound stands on its own.
///
/// 16 MiB, the number `zurl-dict`, `zurl-gopher`, `zurl-tftp`, and
/// `zurl-ftp` keep. `Options.max_response_bytes` raises it, and
/// `--max-filesize` narrows it.
pub const default_max_response_bytes: u64 = 16 * 1024 * 1024;

/// How much room a connection keeps for bytes read and not taken yet.
pub const read_buffer_len: usize = 8192;

/// How much room the plain stream of an `STLS` upgrade keeps.
///
/// The upgrade reads one greeting and one `STLS` answer, so it is far
/// smaller than a message. It is its own number because the buffers behind
/// it are fields of this value and every byte of them is paid for by every
/// transfer, `pop3://` included.
pub const upgrade_buffer_len: usize = 1024;

/// How long one read may wait with no byte arriving.
///
/// **Every wait a POP3 transfer makes needs this.** An answer that never
/// arrives holds the connection, and a body whose closing period never
/// arrives holds the transfer. `--connect-timeout` covers the dial and the
/// handshake and nothing after them.
///
/// 300 seconds is curl's own `--speed-time` default, and this is the same
/// question. `--speed-time` narrows it and never widens it.
pub const default_read_timeout_s: u32 = 300;

/// `default_read_timeout_s`, as a `std.Io.Timeout`.
pub const default_read_timeout: Io.Timeout = .{
    .duration = .{ .raw = .fromSeconds(default_read_timeout_s), .clock = .awake },
};

/// How many bytes of credential this decodes out of a url.
///
/// A user name and a password each have to fit in one command line, and
/// `command.max_command_bytes` is the bound on that. This is the smaller
/// number, so a user meets it here with a sentence that names the
/// credential rather than the command.
pub const max_credential_bytes: usize = 512;

/// How many bytes of an APOP timestamp this keeps.
///
/// RFC 1939 section 7 makes it a process id, a clock, and a host name in
/// angle brackets. This is far past any of them, and a greeting whose
/// timestamp is longer simply logs in with `USER` and `PASS` instead.
pub const max_timestamp_bytes: usize = 256;

/// Where the transfer got the credential it sent.
///
/// A message that says only "the credential" leaves a user with three
/// places to look. This names the one.
pub const CredentialSource = enum {
    /// The user name and password in the url itself.
    userinfo,
    /// `Transfer.Options.credentials`, which `-u` fills.
    options,
    /// A `machine` or a `default` entry of the netrc text.
    netrc,
    /// Nobody named one, so the transfer logged in not at all.
    none,

    /// Names this source for a message to a user. Names the source and
    /// never the credential, which is a secret.
    pub fn describe(s: CredentialSource) []const u8 {
        return switch (s) {
            .userinfo => "the user name and password in the url",
            .options => "the -u option",
            .netrc => "the netrc file",
            .none => "no credential at all",
        };
    }
};

/// One user name and password, ready to send.
pub const Credentials = struct {
    user: []const u8,
    password: []const u8,
};

/// How the transfer puts TLS on the connection.
pub const TlsMode = enum {
    /// No TLS at all. This is a plain `pop3://` url.
    none,
    /// The handshake runs as soon as the socket opens, before the
    /// greeting. This is `pop3s://`, on port 995.
    implicit,
    /// The greeting arrives in the clear, then `STLS`, then the
    /// handshake. RFC 2595. This is `--ssl-reqd` on a `pop3://` url.
    explicit,
};

/// The trust store an encrypted session verifies against, and the way to
/// fill it.
///
/// **A `pop3s` session verifies exactly as an `https` session does.** The
/// bundle here is the one the front package loads for HTTP, so a
/// `--cacert` moves both or neither. A build that leaves this null cannot
/// open an encrypted session at all: `open` reports
/// `error.SslConnectError` and says the build gave it no trust store,
/// rather than fall back to a session that verifies nothing.
///
/// The shape matches `zurl.Client.TlsMaterials` field for field. It is
/// written out here because this package must build with no `zurl` in its
/// import table.
pub const Trust = struct {
    lock: *Io.RwLock,
    bundle: *std.crypto.Certificate.Bundle,
    /// Passed back to `load`.
    ptr: *anyopaque,
    /// Fills `bundle` from the sources the transfer named. Called once,
    /// before the handshake, and only for a transfer that speaks TLS.
    load: *const fn (ptr: *anyopaque) Error!void,
};

/// What one transfer may ask for.
///
/// A struct of this package's own, and not `zurl.Transfer.Options`,
/// because this package must build with no `zurl` in its import table.
/// `Dispatch` fills it from the front package's own options.
pub const Options = struct {
    /// A cap on the dial, the `STLS` step, and the handshake together.
    /// `.none` waits for as long as the operating system does.
    connect_timeout: Io.Timeout = .none,
    /// The bound on the answer. See `default_max_response_bytes`.
    max_response_bytes: u64 = default_max_response_bytes,
    /// How long one read may wait with no byte arriving. See
    /// `default_read_timeout_s`.
    read_timeout: Io.Timeout = default_read_timeout,
    /// Whether to turn Nagle's algorithm off. False is `--no-tcp-nodelay`.
    tcp_no_delay: bool = true,
    /// Whether to accept a peer certificate that does not verify. This is
    /// `-k`/`--insecure`, and it reaches nothing but `sessionOptions`.
    insecure: bool = false,
    /// The lowest TLS version to keep. `--tlsv1.2` and `--tlsv1.3`.
    tls_min_version: zurl_core.tls.MinVersion = .floor,
    /// The highest TLS version to keep. `--tls-max`.
    tls_max_version: zurl_core.tls.Version = .highest,
    /// The trust store for an encrypted session. See `Trust`.
    trust: ?Trust = null,
    /// How the connection gets TLS. See `TlsMode`.
    tls: TlsMode = .none,
    /// The credential `-u` named, or null.
    credentials: ?Credentials = null,
    /// The text of a netrc file the caller already read, or null. This is
    /// `--netrc` and `--netrc-file`.
    netrc_text: ?[]const u8 = null,
    /// The command `-X`/`--request` named, or null for the command the url
    /// implies. The whole value is the command line, so `TOP 1 0` is a
    /// verb and an argument.
    custom_request: ?[]const u8 = null,
    /// The token `--oauth2-bearer` named, or null. See
    /// `zurl_net.sasl.choose`.
    bearer_token: ?[]const u8 = null,
    /// The identity `--sasl-authzid` named, or null.
    sasl_authzid: ?[]const u8 = null,
    /// Whether to put the first SASL message on the `AUTH` line itself.
    /// This is `--sasl-ir`.
    sasl_ir: bool = false,
    /// The value `--login-options` named, or null.
    login_options: ?[]const u8 = null,
    /// Where a url naming one host and port dials instead. This is
    /// `--resolve` and `--connect-to`.
    ///
    /// **An entry moves the dial and nothing else.** `tlsOptions` reads
    /// `url.host`, so a `pop3s` peer at the dialed address must still hold
    /// a certificate for the name the url wrote. The `OAUTHBEARER` message
    /// names the url's host and port too, because it names the service the
    /// user asked for. See `zurl_net.override`.
    connect_to: []const zurl_net.override.HostOverride = &.{},
};

/// How many bytes of a `CAPA` answer this reads.
///
/// A `CAPA` answer names a dozen or two capabilities, each a short line.
/// This is past every one measured, and it is a bound because the answer
/// is a multi-line body a server chooses the length of.
pub const max_capability_bytes: u64 = 8192;

allocator: std.mem.Allocator,
io: Io,
/// The answer of the transfer in play, or null when none is held.
answer: ?[]u8,
/// Reads `answer`. Valid only while `answer` holds something.
body: Io.Reader,
/// The command and response dialogue. Points at whichever channel is live.
control: Control,
/// The url path, decoded.
path: target.Target,
/// Holds a credential decoded out of a url's userinfo, the user first and
/// the password after it.
credential_storage: [max_credential_bytes * 2]u8,
/// Holds the APOP timestamp of the greeting.
///
/// A copy, and not a slice of the greeting, because the greeting borrows
/// the dialogue's one line buffer and the next read overwrites it.
timestamp_storage: [max_timestamp_bytes]u8,
/// How much of `timestamp_storage` is filled. Zero when the greeting
/// offered no APOP.
timestamp_len: usize,
/// Holds the `APOP user digest` argument as it is built.
apop_storage: [max_credential_bytes + 40]u8,
/// Holds one encoded SASL message as it is built.
///
/// **Wiped whichever way `open` leaves**, because the encoded form of a
/// `PLAIN` message is the password with nothing but base64 over it.
sasl_storage: [zurl_net.sasl.max_message_bytes]u8,
/// Holds one decoded server challenge.
challenge_storage: [zurl_net.sasl.max_challenge_bytes]u8,
/// The host and the port this transfer dialed.
///
/// Fields, because `OAUTHBEARER` puts both in its message, RFC 7628
/// section 3.1.
host: []const u8,
port: u16,
/// The plain stream an `STLS` upgrade speaks over, before the handshake.
/// Fields, and not locals of the step, because the dialogue holds pointers
/// into them and the step returns before the dialogue moves to the
/// session.
upgrade_reader: std.Io.net.Stream.Reader,
upgrade_writer: std.Io.net.Stream.Writer,
upgrade_read_storage: [upgrade_buffer_len]u8,
upgrade_write_storage: [upgrade_buffer_len]u8,
/// What the `STLS` step recorded. See `runUpgrade`.
upgrade_fault: ?UpgradeFault,
/// How long one read may wait with no byte arriving.
///
/// A field, and not a parameter of the step, because `runUpgrade` runs
/// inside the connect race and takes only the opaque pointer. `open` sets
/// it before the race starts.
stall: Io.Timeout,

/// Why the `STLS` step stopped.
///
/// **A task that loses the connect race returns nothing**, so the step
/// records its reason here and `open` reads it back. That is the same rule
/// `zurl_net.bounded.Setup.no_delay_error` follows.
const UpgradeFault = struct {
    err: Error,
    message: []const u8,
};

/// A `Fetcher` that holds no answer yet.
pub fn init(allocator: std.mem.Allocator, io: Io) Fetcher {
    return .{
        .allocator = allocator,
        .io = io,
        .answer = null,
        .body = undefined,
        .control = undefined,
        .path = .empty,
        .credential_storage = undefined,
        .timestamp_storage = undefined,
        .timestamp_len = 0,
        .apop_storage = undefined,
        .sasl_storage = undefined,
        .challenge_storage = undefined,
        .host = "",
        .port = 0,
        .upgrade_reader = undefined,
        .upgrade_writer = undefined,
        .upgrade_read_storage = undefined,
        .upgrade_write_storage = undefined,
        .upgrade_fault = null,
        .stall = default_read_timeout,
    };
}

/// Frees the answer this `Fetcher` holds, and wipes every buffer a
/// credential passed through. Safe to call more than once, and safe on a
/// `Fetcher` that never opened anything.
pub fn deinit(f: *Fetcher) void {
    f.release();
    f.wipe();
}

fn release(f: *Fetcher) void {
    const held = f.answer orelse return;
    f.allocator.free(held);
    f.answer = null;
}

/// Zeroes every buffer a credential passed through.
///
/// `credential_storage` holds the decoded userinfo of a url, `apop_storage`
/// holds the `APOP` argument, and `sasl_storage` holds the encoded `PLAIN`
/// message, which is the password with nothing but base64 over it. The
/// challenge buffer holds no secret and is wiped with them, so that one
/// rule covers the four and nobody has to work out which of them left a
/// password behind.
///
/// `open` runs this whichever way it leaves, and `deinit` runs it again so
/// that a caller who stops part way through still leaves nothing.
fn wipe(f: *Fetcher) void {
    std.crypto.secureZero(u8, &f.credential_storage);
    std.crypto.secureZero(u8, &f.apop_storage);
    std.crypto.secureZero(u8, &f.sasl_storage);
    std.crypto.secureZero(u8, &f.challenge_storage);
}

/// The answer of one POP3 transfer.
pub const Body = struct {
    /// Streams the answer. Valid until the next `open` on this `Fetcher`,
    /// or until `deinit`, whichever comes first.
    reader: *Io.Reader,
    /// How many bytes the answer holds. Always known, because the whole
    /// answer is read before this returns.
    length: u64,
    /// Whether the transfer listed the mailbox rather than fetch one
    /// message.
    listing: bool,
    /// Whether the transfer logged in with `APOP` rather than `USER` and
    /// `PASS`. A caller reads it to know the password stayed off the
    /// network.
    apop: bool,
};

/// Whether `url` asks for a TLS session on the connection.
///
/// The scheme and nothing else. Compared without regard to case, per RFC
/// 3986, so `POP3S://` is as encrypted as `pop3s://`.
pub fn isSecure(url: zurl_core.Url) bool {
    return std.ascii.eqlIgnoreCase(url.scheme, secure_scheme);
}

/// The verb of a `--request` value, and the argument after it.
///
/// The value is a whole command line, so `TOP 1 0` is the verb `TOP` and
/// the argument `1 0`. A value with no space is a verb with no argument.
///
/// **Nothing is checked here.** The value is a user's own text, and the
/// gate that keeps a forged line ending out of it is `Control.send`.
pub fn splitRequest(value: []const u8) struct { verb: []const u8, argument: ?[]const u8 } {
    const space = std.mem.indexOfScalar(u8, value, ' ') orelse
        return .{ .verb = value, .argument = null };
    return .{ .verb = value[0..space], .argument = value[space + 1 ..] };
}

/// Runs one transfer and returns its answer.
///
/// Frees whatever the previous call held first, so a `Fetcher` never holds
/// two answers at once.
///
/// The faults, and the exit code each carries:
///
/// - a url path whose decoded form holds a control byte is
///   `error.InvalidUrl`, exit 3, and no socket opens at all. curl refuses
///   the same url with the same code, measured, but only after it has
///   dialed.
/// - a peer that does not accept a connection is `error.CouldNotConnect`,
///   exit 7.
/// - an answer that is neither `+OK` nor `-ERR` is
///   `error.WeirdServerReply`, exit 8.
/// - a `-ERR` to `USER`, to `PASS`, or to `APOP` is `error.LoginDenied`,
///   exit 67, which is curl's own code, measured.
/// - a `-ERR` to the transfer's own command is `error.WeirdServerReply`,
///   exit 8, which is curl's own code, measured against a fixture that
///   refuses `RETR`.
/// - a refused `STLS` under `--ssl-reqd` is `error.UseSslFailed`, exit 64,
///   and no credential goes out.
pub fn open(f: *Fetcher, url: zurl_core.Url, options: Options, d: ?*Diagnostics) Error!Body {
    f.release();
    f.upgrade_fault = null;
    f.timestamp_len = 0;
    f.stall = options.read_timeout;
    // **The credential lives no longer than the transfer.** See `wipe`.
    defer f.wipe();

    // **The url is read before anything is dialed.** A path that could
    // forge a command is refused here, with no socket opened at all.
    f.path.parse(url.path) catch |err| return reportPath(err, d);

    var credential_source: CredentialSource = undefined;
    const credentials = try f.resolveCredentials(url, options, &credential_source, d);

    const port = url.port orelse return fail(d, error.InvalidUrl, &.{
        "a pop3 url names a port, and this one names none",
    });
    // **`--resolve` and `--connect-to` move this dial and nothing else.**
    // `tlsOptions` below reads `url.host`, and the two fields under it
    // keep the url's own host and port, because an `OAUTHBEARER` message
    // names the service the user asked for and never the address the dial
    // reached. See `zurl_net.override`.
    const target_peer = zurl_net.override.dialTarget(options.connect_to, url.host, port);
    // A host that does not read and a host name no resolver can look up
    // are two faults, exit 3 and exit 6. See `zurl_net.errors.hostInit`.
    const host = zurl_net.tcp.Host.init(target_peer.host) catch |err| return fail(d, zurl_net.errors.hostInit(err).err, &.{
        target_peer.faultPrefix(err),
        target_peer.host,
    });
    // `OAUTHBEARER` names both in its message. See `host`.
    f.host = url.host;
    f.port = port;

    const tls = try tlsOptions(url.host, options, d);

    // **The dial, the `STLS` step, and the handshake share one deadline.**
    // See `zurl_net.bounded.Setup.upgrade`.
    var connection: zurl_net.Connection = undefined;
    zurl_net.bounded.setup(&connection, f.io, options.connect_timeout, .{
        .allocator = f.allocator,
        .io = f.io,
        .host = host,
        .port = target_peer.port,
        .read_buffer_len = read_buffer_len,
        .tls = tls,
        .no_delay = options.tcp_no_delay,
        .upgrade = if (options.tls == .explicit)
            .{ .ctx = f, .run = runUpgrade }
        else
            null,
    }) catch |err| return f.reportSetup(err, url.host, d);
    // The connection lives for exactly this transfer. RFC 1939 lets a
    // session hold many commands, and this package keeps no pool: a pool
    // has to know when a protocol is finished with a connection, and
    // nothing above this asks.
    defer connection.deinit();

    const channel: Control.Channel = .{
        .reader = connection.reader(),
        .writer = connection.writer(),
        .ctx = &connection,
        .flush = flushConnection,
    };
    // **An explicit upgrade was already speaking**, over the plain stream,
    // and the greeting and the `STLS` answer are already read. So it keeps
    // the dialogue it has and only changes where the bytes go.
    if (options.tls == .explicit) {
        f.control.retarget(channel);
    } else {
        f.control.init(f.io, channel, options.read_timeout);

        const greeting = try f.expect(&connection, null, null, d);
        if (!greeting.ok) return failResponse(d, error.WeirdServerReply, "the pop3 server refused this connection in its greeting", greeting);

        // **The APOP timestamp is kept only when the greeting was
        // protected.** See `login` for why an `STLS` session never uses
        // one.
        f.keepTimestamp(greeting.text);
    }

    if (credentials) |c| try f.login(&connection, c, credential_source, options, d);
    const used_apop = credentials != null and f.timestamp_len != 0;

    const request: struct { verb: []const u8, argument: ?[]const u8 } = request: {
        if (options.custom_request) |value| {
            const split = splitRequest(value);
            break :request .{ .verb = split.verb, .argument = split.argument };
        }
        if (f.path.listing) break :request .{ .verb = command.list, .argument = null };
        break :request .{ .verb = command.retr, .argument = f.path.id };
    };

    const start = try f.expect(&connection, request.verb, request.argument, d);
    if (!start.ok) {
        return failResponse(d, error.WeirdServerReply, "the pop3 server refused the command this transfer sent", start);
    }

    // **The verb decides how the next bytes are read**, and reading it
    // wrong leaves the session out of step for good. See
    // `command.isMultiline`.
    const answer = if (command.isMultiline(request.verb, request.argument))
        try f.readBody(&connection, options, d)
    else
        f.allocator.alloc(u8, 0) catch return Diagnostics.record(d, error.OutOfMemory, .{});
    errdefer f.allocator.free(answer);

    // `QUIT` is a courtesy and never a gate. The answer is already read,
    // so a server that will not say goodbye has cost this transfer
    // nothing. It is also what makes a `DELE` permanent, which is why it
    // goes out even for a transfer that read no body.
    f.control.send(command.quit, null) catch {};

    f.answer = answer;
    f.body = .fixed(answer);
    return .{
        .reader = &f.body,
        .length = answer.len,
        .listing = f.path.listing and options.custom_request == null,
        .apop = used_apop,
    };
}

/// Keeps the APOP timestamp of `greeting`, when it carries one.
///
/// A copy into this value's own storage, because `greeting` borrows the
/// dialogue's one line buffer and the next read overwrites it.
///
/// A timestamp longer than `max_timestamp_bytes` is dropped, and the
/// session then logs in with `USER` and `PASS`. That is a weaker login and
/// never a wrong one, and no real server writes one that long.
fn keepTimestamp(f: *Fetcher, greeting: []const u8) void {
    const stamp = response.apopTimestamp(greeting) orelse return;
    if (stamp.len > f.timestamp_storage.len) return;
    @memcpy(f.timestamp_storage[0..stamp.len], stamp);
    f.timestamp_len = stamp.len;
}

/// Sends one command, when there is one, and reads its single-line answer.
///
/// A null `verb` reads an answer with no command before it, which is the
/// greeting.
///
/// `connection` is read for one thing: the cause behind a `ReadFailed` or
/// a `WriteFailed`. It is optional so every step of the session below can
/// run over two buffers in a test, with no socket at all.
fn expect(
    f: *Fetcher,
    connection: ?*zurl_net.Connection,
    verb: ?[]const u8,
    argument: ?[]const u8,
    d: ?*Diagnostics,
) Error!response.Response {
    if (verb) |name| {
        f.control.send(name, argument) catch |err| return reportControl(err, connection, name, d);
    }
    return f.control.readResponse() catch |err| return reportControl(err, connection, verb orelse "the greeting", d);
}

/// Logs in, with `APOP` when the greeting offered it and `USER` and `PASS`
/// otherwise.
///
/// **`APOP` keeps the password off the network.** RFC 1939 section 7 makes
/// the digest MD5 over the server's timestamp and the password, so a
/// listener on the path reads a digest and never the secret. curl prefers
/// it too, measured: a greeting ending `<1896.697170952@dbc.mtview.ca.us>`
/// makes curl send `APOP` and no `PASS` at all, and the digest zurl builds
/// is the same 32 characters.
///
/// **An `STLS` session never uses `APOP`, and that is the interesting
/// rule.** The timestamp of an explicit session arrives before the
/// handshake, so it is text an active attacker on the path can choose. A
/// digest over chosen text is a digest an attacker can make useful to
/// itself. `open` therefore keeps no timestamp for an explicit session,
/// and the login inside the session is `USER` and `PASS`, which TLS is
/// already protecting.
///
/// A `-ERR` to any of the three is `error.LoginDenied`, exit 67, which is
/// curl's own code, measured against a fixture refusing `USER` and one
/// refusing `PASS`.
fn login(
    f: *Fetcher,
    connection: ?*zurl_net.Connection,
    credentials: Credentials,
    source: CredentialSource,
    options: Options,
    d: ?*Diagnostics,
) Error!void {
    // **`APOP` first when the greeting offers it**, because the password
    // never crosses the network and it costs no round trip at all. curl
    // prefers it too, measured. An `STLS` session keeps no timestamp, so
    // this never runs there: see `open`.
    if (f.timestamp_len != 0) {
        const digest = command.apopDigest(
            f.timestamp_storage[0..f.timestamp_len],
            credentials.password,
        );
        const argument = std.fmt.bufPrint(&f.apop_storage, "{s} {s}", .{
            credentials.user, &digest,
        }) catch return failCredentialSize(d);

        const answer = try f.expect(connection, command.apop, argument, d);
        if (answer.ok) return;
        return failCredential(d, error.LoginDenied, source, "the pop3 server refused the APOP login built from ", answer);
    }

    // **One `CAPA` command, and it is the only way to learn the SASL
    // list.** RFC 1939 gives a greeting no room to name a capability, so
    // unlike IMAP there is nothing to read for free. curl sends the same
    // command and reads the same `SASL` line, measured.
    //
    // **A `-ERR` to `CAPA` is not a fault.** RFC 2449 is an extension, and
    // a server from before it answers `-ERR`. The login then falls back to
    // `USER` and `PASS`, which is what this package always did.
    if (try f.saslLogin(connection, credentials, source, options, d)) return;

    const user_answer = try f.expect(connection, command.user, credentials.user, d);
    if (!user_answer.ok) {
        return failCredential(d, error.LoginDenied, source, "the pop3 server refused the user name from ", user_answer);
    }

    const pass_answer = try f.expect(connection, command.pass, credentials.password, d);
    if (pass_answer.ok) return;
    return failCredential(d, error.LoginDenied, source, "the pop3 server did not accept the credential from ", pass_answer);
}

/// Logs in with SASL, and says whether it did.
///
/// False means the server offers no mechanism this build speaks, and the
/// caller then falls back to `USER` and `PASS`. **That fallback is better
/// than curl's**, measured: a `CAPA` answer naming no `SASL` and no `USER`
/// drew exit 67 from curl 8.21.0 with no login attempted at all, where
/// this build logs in the way it always did.
///
/// **A failed SASL exchange never falls back.** A second attempt with a
/// cleartext `USER` and `PASS` after a refusal is a downgrade a server, or
/// somebody on the path, could ask for.
fn saslLogin(
    f: *Fetcher,
    connection: ?*zurl_net.Connection,
    credentials: Credentials,
    source: CredentialSource,
    options: Options,
    d: ?*Diagnostics,
) Error!bool {
    const capa = try f.expect(connection, command.capa, null, d);
    var offer: zurl_net.sasl.Offer = .empty;
    if (capa.ok) {
        const body = try f.readCapabilities(connection, d);
        defer f.allocator.free(body);
        if (command.saslMechanisms(body)) |names| offer.addSpaceSeparated(names);
    }

    const wanted: ?[]const u8 = if (options.login_options) |value|
        zurl_net.sasl.loginOptionMechanism(value) orelse return fail(d, error.LoginDenied, &.{
            "--login-options takes a value of the form AUTH=<mechanism>, and this one is not that form",
        })
    else
        null;

    const chosen = zurl_net.sasl.choose(.{
        .offer = offer,
        .has_bearer_token = options.bearer_token != null,
        .wanted = wanted,
    }) catch |err| return failChoice(d, err, wanted orelse "");

    const mechanism = chosen orelse {
        if (options.bearer_token != null) return fail(d, error.LoginDenied, &.{
            "--oauth2-bearer needs a server offering XOAUTH2 or OAUTHBEARER, and this one offers neither",
        });
        return false;
    };

    try f.authenticate(connection, mechanism, credentials, source, options, d);
    return true;
}

/// Reads the body of a `CAPA` answer, under a bound of this package's own.
///
/// The bound is `max_capability_bytes` and not the transfer's own, because
/// a capability list is not the answer a user asked for and
/// `--max-filesize` names the answer.
fn readCapabilities(
    f: *Fetcher,
    connection: ?*zurl_net.Connection,
    d: ?*Diagnostics,
) Error![]u8 {
    return f.control.readBody(f.allocator, max_capability_bytes) catch |err| switch (err) {
        error.OutOfMemory => Diagnostics.record(d, error.OutOfMemory, .{}),
        error.StreamTooLong => failNumber(
            d,
            error.WeirdServerReply,
            "the pop3 server wrote a CAPA answer longer than the ",
            max_capability_bytes,
            " bytes zurl reads",
        ),
        else => |rest| reportControl(rest, connection, command.capa, d),
    };
}

/// Runs one SASL exchange with `AUTH`.
///
/// RFC 1734 and RFC 5034: the client writes `AUTH <mechanism>`, the server
/// answers `+ <challenge>` for each message it wants, and the client
/// answers each with one line of base64. The exchange ends at a `+OK` or a
/// `-ERR`.
fn authenticate(
    f: *Fetcher,
    connection: ?*zurl_net.Connection,
    mechanism: zurl_net.sasl.Mechanism,
    credentials: Credentials,
    source: CredentialSource,
    options: Options,
    d: ?*Diagnostics,
) Error!void {
    const fields: zurl_net.sasl.Fields = .{
        .authzid = options.sasl_authzid,
        .authcid = credentials.user,
        .password = credentials.password,
        .bearer_token = options.bearer_token,
        .host = f.host,
        .port = f.port,
    };
    // **Every field is checked before the `AUTH` command goes out**, so a
    // field that cannot travel never opens an exchange this client has to
    // abandon.
    fields.checkAll(mechanism) catch |err| return failSasl(d, err);

    var argument_storage: [zurl_net.sasl.max_message_bytes + 32]u8 = undefined;
    const initial: ?[]const u8 = if (options.sasl_ir and mechanism.hasInitialResponse())
        try f.saslMessage(mechanism, "", fields, d)
    else
        null;
    const argument = if (initial) |text|
        std.fmt.bufPrint(&argument_storage, "{s} {s}", .{ mechanism.name(), text }) catch
            return failSasl(d, error.MessageTooLong)
    else
        mechanism.name();

    f.control.send(command.auth, argument) catch |err|
        return reportControl(err, connection, command.auth, d);

    var step: usize = if (initial != null) 1 else 0;
    while (true) {
        const next = f.control.readAuthLine() catch |err|
            return reportControl(err, connection, command.auth, d);
        switch (next) {
            .done => |end| {
                if (end.ok) return;
                return failCredential(
                    d,
                    error.LoginDenied,
                    source,
                    "the pop3 server did not accept the credential from ",
                    end,
                );
            },
            .challenge => |encoded| {
                const challenge = f.readChallenge(encoded, d) catch |err| {
                    f.control.sendAuthResponse(command.auth_cancel) catch {};
                    return err;
                };
                const answer = f.saslStep(mechanism, step, challenge, fields, d) catch |err| {
                    f.control.sendAuthResponse(command.auth_cancel) catch {};
                    return err;
                };
                step += 1;
                f.control.sendAuthResponse(answer) catch |err|
                    return reportControl(err, connection, command.auth, d);
            },
        }
    }
}

/// Reads one server challenge out of a `+` line.
fn readChallenge(f: *Fetcher, text: []const u8, d: ?*Diagnostics) Error![]const u8 {
    const encoded = std.mem.trim(u8, text, " \t");
    return zurl_net.sasl.decodeChallenge(&f.challenge_storage, encoded) catch |err| switch (err) {
        error.ChallengeTooLong => failNumber(
            d,
            error.WeirdServerReply,
            "the pop3 server wrote a SASL challenge longer than the ",
            zurl_net.sasl.max_challenge_text_bytes,
            " bytes zurl reads",
        ),
        error.ChallengeMalformed => fail(d, error.WeirdServerReply, &.{
            "the pop3 server wrote a SASL challenge that is not base64",
        }),
    };
}

/// Writes the message of step `step` of `mechanism`. See
/// `zurl_smtp.Fetcher.saslStep`.
fn saslStep(
    f: *Fetcher,
    mechanism: zurl_net.sasl.Mechanism,
    step: usize,
    challenge: []const u8,
    fields: zurl_net.sasl.Fields,
    d: ?*Diagnostics,
) Error![]const u8 {
    if (mechanism == .login and step == 1) {
        return zurl_net.sasl.loginField(&f.sasl_storage, fields.password) catch |err|
            return failSasl(d, err);
    }
    if (step > 1 or (mechanism != .login and step > 0)) {
        return fail(d, error.WeirdServerReply, &.{
            "the pop3 server asked for another SASL message after the exchange had finished",
        });
    }
    return f.saslMessage(mechanism, challenge, fields, d);
}

/// Writes the first message of `mechanism`.
fn saslMessage(
    f: *Fetcher,
    mechanism: zurl_net.sasl.Mechanism,
    challenge: []const u8,
    fields: zurl_net.sasl.Fields,
    d: ?*Diagnostics,
) Error![]const u8 {
    const built = switch (mechanism) {
        .plain => zurl_net.sasl.plainMessage(&f.sasl_storage, fields),
        .login => zurl_net.sasl.loginField(&f.sasl_storage, fields.authcid),
        .cram_md5 => zurl_net.sasl.cramMd5Message(&f.sasl_storage, challenge, fields),
        .xoauth2 => zurl_net.sasl.xoauth2Message(&f.sasl_storage, fields),
        .oauthbearer => zurl_net.sasl.oauthbearerMessage(&f.sasl_storage, fields),
    };
    return built catch |err| failSasl(d, err);
}

/// Turns a message that could not be built into a sentence.
fn failSasl(d: ?*Diagnostics, err: zurl_net.sasl.WriteError) Error {
    return switch (err) {
        error.FieldHasSeparator => fail(d, error.InvalidUrl, &.{
            "a field of this credential holds a NUL, a CR, an LF, or a byte a SASL message reads as a separator, and any of them would send a field the credential never named",
        }),
        error.MessageTooLong => failNumber(
            d,
            error.CredentialTooLarge,
            "this credential does not fit the ",
            zurl_net.sasl.max_message_bytes,
            " bytes zurl writes in one SASL message",
        ),
    };
}

/// Turns a mechanism that could not be chosen into a sentence.
fn failChoice(d: ?*Diagnostics, err: zurl_net.sasl.ChooseError, named: []const u8) Error {
    return switch (err) {
        error.MechanismNotBuiltIn => fail(d, error.LoginDenied, &.{
            "--login-options names the SASL mechanism ",
            named,
            ", and this build speaks OAUTHBEARER, XOAUTH2, CRAM-MD5, PLAIN, and LOGIN",
        }),
        error.MechanismNotOffered => fail(d, error.LoginDenied, &.{
            "--login-options names the SASL mechanism ",
            named,
            ", and this server does not offer it",
        }),
        error.MechanismNeedsOtherCredential => fail(d, error.LoginDenied, &.{
            "--login-options names the SASL mechanism ",
            named,
            ", and it takes the other of a password and a bearer token: XOAUTH2 and OAUTHBEARER take --oauth2-bearer, and the rest take -u",
        }),
    };
}

/// Reads a multi-line body and maps every fault onto a `zurl_core.Error`.
fn readBody(
    f: *Fetcher,
    connection: *zurl_net.Connection,
    options: Options,
    d: ?*Diagnostics,
) Error![]u8 {
    return f.control.readBody(f.allocator, options.max_response_bytes) catch |err| switch (err) {
        error.OutOfMemory => Diagnostics.record(d, error.OutOfMemory, .{}),
        error.StreamTooLong => failNumber(
            d,
            error.FileSizeExceeded,
            "the pop3 server wrote more than the ",
            options.max_response_bytes,
            " bytes zurl reads from one transfer",
        ),
        else => |rest| reportControl(rest, connection, "the message body", d),
    };
}

/// The credential this transfer sends, or null when nobody named one.
///
/// The url's userinfo first, then `-u`, then a netrc entry for the url's
/// host. That is the order `zurl.authorize` keeps for HTTP and the order
/// curl keeps for POP3, measured: `pop3://bob:pw@h/1` sends `USER bob`,
/// and `-u alice:s3cret` on a url with no userinfo sends `USER alice`.
///
/// **Null is a real answer and not a fault.** curl sends no `USER` at all
/// for a url with no credential, measured, and RFC 1939 has no anonymous
/// login to fall back on.
///
/// **The userinfo is percent-decoded and the other two are not.** A url
/// writes a credential escaped, so `%40` in a password is an `@` and not
/// three characters. `-u` and a netrc file are read as they are written,
/// which is what curl does.
///
/// **A credential that could forge a command never reaches one.**
/// `Control.send` refuses a NUL, a CR, or an LF in any part of a command
/// line, so a forged `USER` or `PASS` is refused at the socket whatever
/// source it came from. This function refuses the same three bytes first,
/// so the message names the credential and its source rather than the
/// command. curl instead strips a raw CR out of a `-u` value and sends the
/// rest, measured: `-u $'al\rice:pw'` reaches the wire from curl as
/// `USER alice`. zurl refuses it, because a credential that was changed on
/// its way to the wire is not the credential the user gave.
fn resolveCredentials(
    f: *Fetcher,
    url: zurl_core.Url,
    options: Options,
    source: *CredentialSource,
    d: ?*Diagnostics,
) Error!?Credentials {
    const resolved: ?Credentials = found: {
        if (url.user) |raw_user| {
            source.* = .userinfo;
            if (raw_user.len > max_credential_bytes) return failCredentialSize(d);
            const user = zurl_core.url.percentDecode(
                f.credential_storage[0..raw_user.len],
                raw_user,
            ) catch return fail(d, error.InvalidUrl, &.{
                "the user name in this url holds a percent escape that is not an escape",
            });

            const password = if (url.password) |raw_password| pw: {
                if (raw_password.len > max_credential_bytes) return failCredentialSize(d);
                break :pw zurl_core.url.percentDecode(
                    f.credential_storage[max_credential_bytes..][0..raw_password.len],
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
        break :found null;
    };

    const c = resolved orelse return null;
    // **The injection refusal for a credential.** See the doc comment.
    if (zurl_net.line.hasFramingByte(c.user) or zurl_net.line.hasFramingByte(c.password)) {
        return fail(d, error.InvalidUrl, &.{
            "the credential from ",
            source.*.describe(),
            " holds a NUL, a CR, or an LF, and any of the three would end the pop3 command line and write a command of its own",
        });
    }
    if (c.user.len > max_credential_bytes or c.password.len > max_credential_bytes) {
        return failCredentialSize(d);
    }
    return c;
}

/// The TLS options a session opens with, or null for a plain hop.
///
/// **This is the one place in this package that turns peer verification
/// off, and it reads `options.insecure` and nothing else.** A function and
/// not a few lines inside `open`, so a test can name both answers and
/// prove that no other input can reach the second one. `zurl_ftp` and
/// `zurl_gopher` keep the same shape.
///
/// Both halves of the check go together, the way curl does it. A host name
/// check is worthless against a peer whose chain nobody trusts, and a
/// trusted chain for the wrong host is worthless too.
///
/// **A build with no trust store cannot open an encrypted session.** The
/// `null` arm reports `error.SslConnectError` rather than fall back to
/// `.none`, because that fallback is exactly the hole this package must
/// not open.
///
/// An explicit upgrade dials in the clear and hands shakes after `STLS`,
/// so the options are the same and only the moment differs.
fn tlsOptions(
    host: []const u8,
    options: Options,
    d: ?*Diagnostics,
) Error!?zurl_net.Connection.Tls {
    if (options.tls == .none) return null;
    return try sessionOptions(host, options, d);
}

/// The options one TLS session opens with.
fn sessionOptions(
    host: []const u8,
    options: Options,
    d: ?*Diagnostics,
) Error!zurl_net.Connection.Tls {
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
        "this build gave the pop3 package no trust store, so it cannot verify a pop3s peer",
    });
    try trust.load(trust.ptr);

    return .{
        .host = .{ .explicit = host },
        .trust = .{ .bundle = .{ .lock = trust.lock, .bundle = trust.bundle } },
        .min_version = options.tls_min_version,
        .max_version = options.tls_max_version,
        // **No ALPN extension at all.** RFC 7301 needs a registered
        // protocol name and POP3 has none.
        .alpn_protocols = &.{},
        // `allow_truncation_attacks` keeps its default, which is false. A
        // POP3 body ends at a period the server writes, so a middle box
        // that cut the session early is already caught by the missing
        // terminator, and a session that ends with no `close_notify` is
        // still a fault to report and never one to pass over.
    };
}

/// The `STLS` step, run inside the connect race.
///
/// **This runs on a plain stream and it sends no credential.** RFC 2595
/// puts the greeting and `STLS` before the handshake, so those two cross
/// in the clear and nothing else does. `USER` and `PASS` go out after the
/// handshake, from `open`.
///
/// Returns false for a step that did not finish, and records why in
/// `upgrade_fault`, because a task that loses the race returns nothing.
fn runUpgrade(ctx: *anyopaque, io: Io, stream: std.Io.net.Stream) bool {
    const f: *Fetcher = @ptrCast(@alignCast(ctx));
    f.upgrade_fault = f.upgradeStep(io, stream);
    return f.upgrade_fault == null;
}

/// Runs the step, and returns why it stopped, or null when it worked.
///
/// A returned value and not an error union, because every arm has a
/// sentence as well as a name and the two belong together.
fn upgradeStep(f: *Fetcher, io: Io, stream: std.Io.net.Stream) ?UpgradeFault {
    f.upgrade_reader = .init(stream, io, &f.upgrade_read_storage);
    f.upgrade_writer = .init(stream, io, &f.upgrade_write_storage);
    f.control.init(io, .{
        .reader = &f.upgrade_reader.interface,
        .writer = &f.upgrade_writer.interface,
        .ctx = &f.upgrade_writer,
        .flush = flushStream,
    }, f.stall);

    const greeting = f.control.readResponse() catch |err| return .{
        .err = responseFault(err),
        .message = "zurl did not read the pop3 greeting before STLS",
    };
    if (!greeting.ok) return .{
        .err = error.WeirdServerReply,
        .message = "the pop3 server refused this connection in its greeting, so STLS was never sent",
    };

    const answer = f.control.ask(command.stls, null) catch |err| return .{
        .err = responseFault(err),
        .message = "zurl did not read the answer to STLS",
    };
    if (!answer.ok) return .{
        .err = error.UseSslFailed,
        .message = "the pop3 server refused STLS, and zurl sends no credential over a connection that was asked to be encrypted and is not",
    };

    // **Nothing may be held across the handshake.** A server that wrote
    // bytes behind its `+OK` wrote them in cleartext, and carrying them
    // into the session would hand a caller text the peer chose as though
    // TLS had protected it.
    if (f.control.buffered() != 0) return .{
        .err = error.UseSslFailed,
        .message = "the pop3 server wrote more bytes behind its STLS answer, and those bytes are not inside the session",
    };

    return null;
}

/// Empties both buffers of a `zurl_net.Connection`. See
/// `zurl_net.line.Channel.flush`.
fn flushConnection(ctx: ?*anyopaque) Io.Writer.Error!void {
    const connection: *zurl_net.Connection = @ptrCast(@alignCast(ctx.?));
    connection.flush() catch return error.WriteFailed;
}

/// Empties the buffer of a plain stream writer, which is what the `STLS`
/// step writes through.
fn flushStream(ctx: ?*anyopaque) Io.Writer.Error!void {
    const writer: *std.Io.net.Stream.Writer = @ptrCast(@alignCast(ctx.?));
    return writer.interface.flush();
}

/// The `zurl_core.Error` one dialogue fault means.
///
/// Every name is listed, so a new one in `Control.Error` is a compile
/// error here and never a fault that reaches a user under the wrong
/// number.
fn responseFault(err: Control.Error) Error {
    return switch (err) {
        error.ResponseMalformed, error.LineTooLong => error.WeirdServerReply,
        error.EndOfStream => error.PartialFile,
        error.OperationTimedOut => error.OperationTimedOut,
        error.Canceled => error.AbortedByCallback,
        error.OutOfMemory => error.OutOfMemory,
        error.StreamTooLong => error.FileSizeExceeded,
        error.ReadFailed, error.ReadTimeoutUnsupported => error.ReadError,
        error.WriteFailed => error.WriteError,
        error.ArgumentHasFramingByte, error.CommandTooLong => error.InvalidUrl,
    };
}

/// Reports a fault on the connection, with the command it happened on.
fn reportControl(
    err: Control.Error,
    connection: ?*zurl_net.Connection,
    verb: []const u8,
    d: ?*Diagnostics,
) Error {
    const mapped = responseFault(err);
    const cause: []const u8 = switch (err) {
        error.ReadFailed => name: {
            const live = connection orelse break :name @errorName(err);
            const inner = live.readError() orelse break :name @errorName(err);
            break :name @errorName(inner);
        },
        error.WriteFailed => name: {
            const live = connection orelse break :name @errorName(err);
            const inner = live.writeError() orelse break :name @errorName(err);
            break :name @errorName(inner);
        },
        else => @errorName(err),
    };
    return fail(d, mapped, &.{
        "the pop3 connection failed on ",
        verb,
        ": ",
        cause,
    });
}

/// Reports a dial or handshake fault.
///
/// **An `STLS` step that failed reports its own reason**, which it
/// recorded before the race ended. Without that a user would read only
/// `error.SslConnectError` and never learn that the server refused the
/// command.
fn reportSetup(
    f: *Fetcher,
    err: zurl_net.errors.SetupError,
    host: []const u8,
    d: ?*Diagnostics,
) Error {
    if (err == error.UpgradeFailed) {
        if (f.upgrade_fault) |recorded| {
            return fail(d, recorded.err, &.{ host, ": ", recorded.message });
        }
    }
    const mapping = zurl_net.errors.map(err);
    if (mapping.message) |text| return fail(d, mapping.err, &.{ host, ": ", text });
    return fail(d, mapping.err, &.{ host, ": ", @errorName(err) });
}

/// Reports a url path this package will not send.
fn reportPath(err: target.ParseError, d: ?*Diagnostics) Error {
    return switch (err) {
        // **The injection refusal at the url.** See
        // `target.ParseError.PathHasControlByte`.
        error.PathHasControlByte => fail(d, error.InvalidUrl, &.{
            "the path of this url holds a control byte, and a CR or an LF in one would end a pop3 command line and write a command of its own",
        }),
        error.InvalidEscape => fail(d, error.InvalidUrl, &.{
            "the path of this url holds a percent escape that is not an escape",
        }),
        error.PathTooLong => failNumber(
            d,
            error.InvalidUrl,
            "the path of this url is longer than the ",
            target.max_id_bytes,
            " bytes zurl reads",
        ),
    };
}

/// Writes `parts`, one after another, into `d`'s own message storage,
/// records `err` with that message, and returns `err`.
///
/// The text goes into `Diagnostics.message_storage` because the sentence
/// names an answer this package holds in a buffer it reuses, so a borrowed
/// message would read the next transfer's answer.
fn fail(d: ?*Diagnostics, err: Error, parts: []const []const u8) Error {
    const record = d orelse return err;
    const out: []u8 = &record.message_storage;
    var at: usize = 0;
    for (parts) |part| {
        const n = @min(out.len - at, part.len);
        @memcpy(out[at..][0..n], part[0..n]);
        at += n;
    }
    return Diagnostics.record(d, err, .{ .message = out[0..at] });
}

/// `fail`, with the server's own answer on the end of the sentence.
///
/// **The answer text is the server's and it goes to a user's terminal**,
/// so only the first two hundred bytes reach the message.
fn failResponse(d: ?*Diagnostics, err: Error, sentence: []const u8, answer: response.Response) Error {
    const word = if (answer.ok) response.ok_prefix else response.err_prefix;
    const shown = answer.text[0..@min(answer.text.len, 200)];
    return fail(d, err, &.{ sentence, ": ", word, " ", shown });
}

/// `failResponse`, with the credential source named instead of a fixed
/// sentence tail.
fn failCredential(
    d: ?*Diagnostics,
    err: Error,
    source: CredentialSource,
    sentence: []const u8,
    answer: response.Response,
) Error {
    const word = if (answer.ok) response.ok_prefix else response.err_prefix;
    const shown = answer.text[0..@min(answer.text.len, 200)];
    return fail(d, err, &.{ sentence, source.describe(), ": ", word, " ", shown });
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

/// Reports a credential longer than this package sends.
fn failCredentialSize(d: ?*Diagnostics) Error {
    return failNumber(
        d,
        error.CredentialTooLarge,
        "the credential for this url is longer than the ",
        max_credential_bytes,
        " bytes one pop3 command line carries",
    );
}

/// Returns the dispatch entry for the plain `pop3` scheme.
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
        // run direct. curl carries pop3 through a proxy and this build
        // does not. See `Front.protocol.Unread`.
        .unread = .{ .proxy = true },
    };
}

/// Returns the dispatch entry for the `pop3s` scheme. See `protocol`.
///
/// The port is 995 and not 110, because `pop3s://` is implicit TLS and
/// that is the port implicit TLS uses.
pub fn secureProtocol(f: *Fetcher, comptime Front: type) Front.protocol.Protocol {
    return .{
        .scheme = secure_scheme,
        .default_port = secure_default_port,
        .ptr = f,
        .vtable = &Dispatch(Front).vtable,
        // This package dials the origin itself and reads no proxy field,
        // so a transfer that named a proxy is refused by name rather than
        // run direct. curl carries pop3 through a proxy and this build
        // does not. See `Front.protocol.Unread`.
        .unread = .{ .proxy = true },
    };
}

/// The vtable for one front package. One instantiation for each `Front`,
/// and each one holds a single comptime constant, so the table lives in
/// the binary's own read-only data and never on a stack.
fn Dispatch(comptime Front: type) type {
    return struct {
        const vtable: Front.protocol.Protocol.VTable = .{ .perform = performPop3 };

        fn performPop3(
            ptr: ?*anyopaque,
            c: *Front.Client,
            url: zurl_core.Url,
            options: Front.Transfer.Options,
            d: ?*Diagnostics,
        ) Error!Front.Response {
            const f: *Fetcher = @ptrCast(@alignCast(ptr.?));
            const body = try f.open(url, translate(c, url, options), d);
            return .{
                .status = status,
                .content_length = body.length,
                .transfer_encoding = .none,
                .body = body.reader,
            };
        }

        /// Reads the front package's own options into this package's.
        ///
        /// **`--max-filesize` narrows the bound and never widens it**, and
        /// **`--speed-time` narrows the wait the same way**, for the
        /// reasons `zurl_gopher` gives: the front package's stall guard
        /// cannot reach a transfer whose body is already in memory, so the
        /// flag has to reach the wait inside `open` instead.
        ///
        /// **The scheme decides the TLS mode.** `pop3s://` is implicit,
        /// and `pop3://` with `--ssl-reqd` is an explicit `STLS`.
        fn translate(
            c: *Front.Client,
            url: zurl_core.Url,
            options: Front.Transfer.Options,
        ) Options {
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
                .tls = if (isSecure(url))
                    .implicit
                else if (options.ftp_ssl_required)
                    .explicit
                else
                    .none,
                .credentials = if (options.credentials) |credential|
                    .{ .user = credential.user, .password = credential.password }
                else
                    null,
                .netrc_text = options.netrc_text,
                .custom_request = options.custom_request,
                .bearer_token = options.bearer_token,
                .sasl_authzid = options.sasl_authzid,
                .sasl_ir = options.sasl_ir,
                .login_options = options.login_options,
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
            credentials: ?zurl_core.auth.Credentials = null,
            netrc_text: ?[]const u8 = null,
            custom_request: ?[]const u8 = null,
            ftp_ssl_required: bool = false,
            bearer_token: ?[]const u8 = null,
            sasl_authzid: ?[]const u8 = null,
            sasl_ir: bool = false,
            login_options: ?[]const u8 = null,
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

/// Parses `text` the way `zurl.Client` does, with both schemes registered.
fn parsePop3Url(text: []const u8) !zurl_core.Url {
    var schemes: zurl_core.url.Schemes = .empty;
    try schemes.add(.{ .name = scheme, .default_port = default_port });
    try schemes.add(.{ .name = secure_scheme, .default_port = secure_default_port });
    return zurl_core.url.parseWith(text, &schemes);
}

test {
    _ = command;
    _ = response;
    _ = target;
    _ = Control;
    _ = test_server;
}

test "the two schemes name the two ports curl dials" {
    try testing.expectEqualStrings("pop3", scheme);
    try testing.expectEqualStrings("pop3s", secure_scheme);
    try testing.expectEqual(@as(?u16, 110), default_port);
    try testing.expectEqual(@as(?u16, 995), secure_default_port);
}

test "both schemes share one vtable, because they share one protocol" {
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const plain = f.protocol(StubFront);
    const secure = f.secureProtocol(StubFront);
    try testing.expectEqual(plain.vtable, secure.vtable);
    try testing.expectEqual(@as(?*anyopaque, &f), plain.ptr);
    try testing.expectEqual(@as(?*anyopaque, &f), secure.ptr);
}

test "isSecure reads the scheme and nothing else" {
    try testing.expect(isSecure(try parsePop3Url("pop3s://h/1")));
    try testing.expect(isSecure(try parsePop3Url("POP3S://h/1")));
    try testing.expect(!isSecure(try parsePop3Url("pop3://h/1")));
    // The port does not decide it. A `pop3://` url on 995 is still plain.
    try testing.expect(!isSecure(try parsePop3Url("pop3://h:995/1")));
}

test "a --request value splits into a verb and the rest" {
    {
        const r = splitRequest("STAT");
        try testing.expectEqualStrings("STAT", r.verb);
        try testing.expectEqual(@as(?[]const u8, null), r.argument);
    }
    {
        const r = splitRequest("TOP 1 0");
        try testing.expectEqualStrings("TOP", r.verb);
        try testing.expectEqualStrings("1 0", r.argument.?);
    }
    {
        const r = splitRequest("DELE 2");
        try testing.expectEqualStrings("DELE", r.verb);
        try testing.expectEqualStrings("2", r.argument.?);
    }
    {
        // A trailing space is an empty argument, which still writes the
        // space. `LIST ` and `LIST` are different commands.
        const r = splitRequest("LIST ");
        try testing.expectEqualStrings("LIST", r.verb);
        try testing.expectEqualStrings("", r.argument.?);
    }
}

test "the default options ask for no TLS and no custom command" {
    const o: Options = .{};
    try testing.expectEqual(TlsMode.none, o.tls);
    try testing.expect(!o.insecure);
    try testing.expectEqual(@as(?[]const u8, null), o.custom_request);
    try testing.expectEqual(@as(?Credentials, null), o.credentials);
}

/// How long a test lets a dial or a handshake take.
///
/// **Every test in this file needs this.** `Options.connect_timeout`
/// defaults to `.none`, and a test that asks for TLS against a fixture
/// that speaks none would leave the handshake waiting for a ServerHello
/// that never comes.
const test_connect_timeout: Io.Timeout = .{
    .duration = .{ .raw = .fromSeconds(10), .clock = .awake },
};

/// Runs a whole transfer against the fixture and returns the body.
///
/// Fills in a connect bound for a caller that named none, so no test in
/// this file can wait on a dial or a handshake forever.
///
/// The caller frees nothing and calls `server.stop` itself.
fn fetch(
    f: *Fetcher,
    server: *test_server.Server,
    path: []const u8,
    options: Options,
    d: ?*Diagnostics,
) !Body {
    var url_buffer: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "pop3://127.0.0.1:{d}{s}", .{ server.port(), path });
    var bounded_options = options;
    if (bounded_options.connect_timeout == .none) {
        bounded_options.connect_timeout = test_connect_timeout;
    }
    return f.open(try parsePop3Url(text), bounded_options, d);
}

/// Reads the whole body of a transfer into a slice the caller frees.
fn drain(body: Body) ![]u8 {
    return body.reader.allocRemaining(testing.allocator, .unlimited);
}

const test_credentials: Credentials = .{ .user = "alice", .password = "s3cret" };

test "a retrieval sends the commands curl sends, in curl's order" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/1", .{ .credentials = test_credentials }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);

    // **The dot-stuffing round trip.** The fixture doubled the period on
    // `.hidden` and the client took it off, so the message arrives as its
    // author wrote it.
    try testing.expectEqualStrings("Subject: hi\r\n\r\nbody line\r\n.hidden\r\n", contents);
    try testing.expect(!body.listing);
    try testing.expect(!body.apop);

    server.wait();
    // Measured from curl 8.21.0 against a loopback fixture, in this
    // order, `CAPA` included.
    //
    // **The `CAPA` line is new, and this assertion changed with SASL.**
    // It used to read without one, because this package had no mechanism
    // to look for and learned about `STLS` by sending it. A SASL login
    // has to know what the server offers, and RFC 1939 gives a greeting
    // no room to name a capability, so `CAPA` is the only way to ask.
    // This fixture answers `-ERR`, which is what a server from before RFC
    // 2449 answers, and the login falls back to `USER` and `PASS` exactly
    // as it always did. The tags of the two programs now match.
    try testing.expectEqualStrings(
        "CAPA\nUSER alice\nPASS s3cret\nRETR 1\nQUIT",
        server.commands(),
    );
    try testing.expectEqual(@as(usize, 1), server.connections());
}

test "a url with no path lists the mailbox" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/", .{ .credentials = test_credentials }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("1 200\r\n2 120\r\n", contents);
    try testing.expect(body.listing);

    server.wait();
    try testing.expectEqualStrings(
        // The `CAPA` is the SASL discovery command. See the retrieval
        // test above for why it is here and why the login behind it did
        // not change.
        "CAPA\nUSER alice\nPASS s3cret\nLIST\nQUIT",
        server.commands(),
    );
}

test "a url with no credential logs in not at all, the way curl does" {
    // Measured: `pop3://h/` with no `-u` and no userinfo sends no `USER`
    // from curl either. RFC 1939 has no anonymous login to fall back on.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/", .{}, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("1 200\r\n2 120\r\n", contents);

    server.wait();
    try testing.expectEqualStrings("LIST\nQUIT", server.commands());
}

test "a greeting that offers APOP puts a digest on the wire and never the password" {
    // **The password never crosses the network.** Measured against curl
    // 8.21.0 with the same greeting: curl sends the same `APOP` line and
    // no `PASS` at all.
    var server: test_server.Server = undefined;
    try server.start(.{ .greeting = "+OK ready <1896.697170952@dbc.mtview.ca.us>" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/1", .{
        .credentials = .{ .user = "mrose", .password = "tanstaaf" },
    }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);
    try testing.expect(body.apop);

    server.wait();
    // The digest is the one RFC 1939 section 7 prints for this timestamp
    // and this password.
    try testing.expectEqualStrings(
        "APOP mrose c4c9334bac560ecc979e58001b3e22fb\nRETR 1\nQUIT",
        server.commands(),
    );
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, server.commands(), "tanstaaf"),
    );
}

test "a --request value replaces the command the url implies" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    // `STAT` is a single-line answer, so the body is empty and the session
    // stays in step for the `QUIT` after it.
    const body = try fetch(&f, &server, "/", .{
        .credentials = test_credentials,
        .custom_request = "STAT",
    }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("", contents);
    try testing.expect(!body.listing);

    server.wait();
    try testing.expectEqualStrings(
        // The `CAPA` is the SASL discovery command. See the retrieval
        // test above.
        "CAPA\nUSER alice\nPASS s3cret\nSTAT\nQUIT",
        server.commands(),
    );
}

test "a --request DELE marks a message, and QUIT is what makes it happen" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/", .{
        .credentials = test_credentials,
        .custom_request = "DELE 1",
    }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);

    server.wait();
    try testing.expectEqualStrings(
        // The `CAPA` is the SASL discovery command. See the retrieval
        // test above.
        "CAPA\nUSER alice\nPASS s3cret\nDELE 1\nQUIT",
        server.commands(),
    );
}

test "a path that could forge a command is refused, and no socket opens" {
    // **The injection proof through a whole transfer.** The fixture never
    // accepts a connection, because the refusal happens before the dial.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const forged = [_][]const u8{
        "/1%0d%0aDELE%202",
        "/1%0aDELE%202",
        "/1%0dDELE%202",
        "/1%00",
        "/%0d%0aQUIT",
        "/1%09two",
        "/1%0bx",
    };
    for (forged) |path| {
        var d: Diagnostics = .{};
        try testing.expectError(
            error.InvalidUrl,
            fetch(&f, &server, path, .{ .credentials = test_credentials }, &d),
        );
        try testing.expect(std.mem.indexOf(u8, d.message.?, "control byte") != null);
    }
    try testing.expectEqual(@as(usize, 0), server.connections());
}

test "a credential that could forge a command is refused, and no socket opens" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const forged = [_]Credentials{
        .{ .user = "al\r\nPASS x", .password = "pw" },
        .{ .user = "al\nDELE 1", .password = "pw" },
        .{ .user = "al\rQUIT", .password = "pw" },
        .{ .user = "al\x00ice", .password = "pw" },
        .{ .user = "alice", .password = "pw\r\nDELE 1" },
        .{ .user = "alice", .password = "pw\nQUIT" },
        .{ .user = "alice", .password = "pw\rx" },
        .{ .user = "alice", .password = "pw\x00" },
    };
    for (forged) |credential| {
        var d: Diagnostics = .{};
        try testing.expectError(
            error.InvalidUrl,
            fetch(&f, &server, "/1", .{ .credentials = credential }, &d),
        );
        try testing.expect(std.mem.indexOf(u8, d.message.?, "the -u option") != null);
    }
    try testing.expectEqual(@as(usize, 0), server.connections());
}

test "a url userinfo that decodes into a forged command is refused" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var url_buffer: [256]u8 = undefined;
    const text = try std.fmt.bufPrint(
        &url_buffer,
        "pop3://bob%0d%0aDELE%201:pw@127.0.0.1:{d}/1",
        .{server.port()},
    );
    var d: Diagnostics = .{};
    var options: Options = .{ .connect_timeout = test_connect_timeout };
    _ = &options;
    try testing.expectError(
        error.InvalidUrl,
        f.open(try parsePop3Url(text), options, &d),
    );
    try testing.expect(std.mem.indexOf(u8, d.message.?, "the user name and password in the url") != null);
    try testing.expectEqual(@as(usize, 0), server.connections());
}

test "a -ERR to USER or to PASS is a login denial, which is curl's exit 67" {
    for ([_]test_server.Script{
        .{ .user = "-ERR no such user" },
        .{ .pass = "-ERR wrong password" },
    }) |script| {
        var server: test_server.Server = undefined;
        try server.start(script);
        defer server.stop();

        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();

        var d: Diagnostics = .{};
        try testing.expectError(
            error.LoginDenied,
            fetch(&f, &server, "/1", .{ .credentials = test_credentials }, &d),
        );
        try testing.expect(std.mem.indexOf(u8, d.message.?, "the -u option") != null);
    }
}

test "a -ERR to the transfer's own command is curl's exit 8" {
    // Measured: a fixture answering `-ERR` to `RETR` makes curl exit 8,
    // `Weird server reply`, and not 78.
    var server: test_server.Server = undefined;
    try server.start(.{ .retr_refused = "-ERR no such message" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(
        error.WeirdServerReply,
        fetch(&f, &server, "/9", .{ .credentials = test_credentials }, &d),
    );
    try testing.expect(std.mem.indexOf(u8, d.message.?, "no such message") != null);
}

test "a greeting that is neither +OK nor -ERR ends the transfer at once" {
    // curl waits for a line it can read and gives up at its own timeout,
    // exit 28, measured. zurl reads one line and says what is wrong, exit
    // 8, which names the fault instead of the wait.
    var server: test_server.Server = undefined;
    try server.start(.{ .greeting = "220 not a pop3 server" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(
        error.WeirdServerReply,
        fetch(&f, &server, "/1", .{ .credentials = test_credentials }, &d),
    );
}

test "a peer that greets and says nothing more ends the transfer at the bound" {
    var server: test_server.Server = undefined;
    try server.startSilent();
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    const short: Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(300), .clock = .awake } };
    try testing.expectError(error.OperationTimedOut, fetch(&f, &server, "/1", .{
        .credentials = test_credentials,
        .read_timeout = short,
    }, &d));
}

test "a body larger than the bound ends the transfer" {
    var server: test_server.Server = undefined;
    try server.start(.{ .body = "0123456789\r\n0123456789\r\n" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(error.FileSizeExceeded, fetch(&f, &server, "/1", .{
        .credentials = test_credentials,
        .max_response_bytes = 12,
    }, &d));
}

test "a refused STLS sends no credential at all" {
    // **The rule this test exists for.** A transfer that asked for TLS and
    // carried on without it would send the password in the clear. curl
    // answers the same shape with exit 64 and sends no `USER`, measured.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    // `-k` stands in for a trust store, because this fixture speaks no
    // TLS and the refusal under test happens before any handshake.
    try testing.expectError(error.UseSslFailed, fetch(&f, &server, "/1", .{
        .credentials = test_credentials,
        .tls = .explicit,
        .insecure = true,
    }, &d));

    server.wait();
    try testing.expectEqualStrings("STLS", server.commands());
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, server.commands(), "s3cret"),
    );
}

test "a server that writes behind its STLS answer does not get those bytes trusted" {
    // Bytes written before the handshake are cleartext the peer chose.
    // Carrying them into the session would hand a caller text that TLS
    // never protected.
    var server: test_server.Server = undefined;
    try server.start(.{
        .stls = "+OK begin TLS negotiation",
        .stls_trailer = "+OK logged in\r\n",
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(error.UseSslFailed, fetch(&f, &server, "/1", .{
        .credentials = test_credentials,
        .tls = .explicit,
        .insecure = true,
    }, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "behind its STLS answer") != null);
}

test "an STLS that the peer accepts and then speaks no TLS ends at the connect bound" {
    var server: test_server.Server = undefined;
    try server.start(.{ .stls = "+OK begin TLS negotiation" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    const short: Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(500), .clock = .awake } };
    try testing.expectError(error.OperationTimedOut, fetch(&f, &server, "/1", .{
        .credentials = test_credentials,
        .tls = .explicit,
        .insecure = true,
        .connect_timeout = short,
    }, &d));

    server.wait();
    // The credential never crossed, and the handshake was bounded.
    try testing.expectEqualStrings("STLS", server.commands());
}

test "a build with no trust store cannot open an encrypted session" {
    // **The fallback this package must not have.** A null trust store is a
    // refusal and never a session that verifies nothing.
    var d: Diagnostics = .{};
    for ([_]TlsMode{ .implicit, .explicit }) |mode| {
        try testing.expectError(error.SslConnectError, tlsOptions("mail.example.com", .{
            .tls = mode,
            .trust = null,
        }, &d));
    }
    // A plain hop asks for no session at all, so it needs no store.
    try testing.expectEqual(
        @as(?zurl_net.Connection.Tls, null),
        try tlsOptions("mail.example.com", .{ .tls = .none, .trust = null }, &d),
    );
}

test "only -k turns verification off, and it turns both halves off together" {
    var client: StubFront.Client = .{};
    const trust = client.tlsMaterials();

    const verified = (try tlsOptions("mail.example.com", .{
        .tls = .implicit,
        .trust = trust,
    }, null)).?;
    try testing.expectEqualStrings("mail.example.com", verified.host.explicit);
    try testing.expect(verified.trust != .none);
    try testing.expectEqual(@as(usize, 1), client.loads);

    const insecure = (try tlsOptions("mail.example.com", .{
        .tls = .implicit,
        .trust = trust,
        .insecure = true,
    }, null)).?;
    try testing.expectEqual(zurl_net.Connection.HostCheck.none, insecure.host);
    try testing.expectEqual(zurl_net.Connection.TrustCheck.none, insecure.trust);
}

test "no option but -k can reach a session that verifies nothing" {
    // A build that grew a second way to `.none` fails here.
    var client: StubFront.Client = .{};
    const trust = client.tlsMaterials();

    const moved = [_]Options{
        .{ .tls = .implicit, .trust = trust, .tcp_no_delay = false },
        .{ .tls = .implicit, .trust = trust, .max_response_bytes = 1 },
        .{ .tls = .implicit, .trust = trust, .tls_min_version = .tls_1_3 },
        .{ .tls = .implicit, .trust = trust, .tls_max_version = .tls_1_2 },
        .{ .tls = .implicit, .trust = trust, .credentials = test_credentials },
        .{ .tls = .implicit, .trust = trust, .netrc_text = "machine h login a password b" },
        .{ .tls = .implicit, .trust = trust, .custom_request = "STAT" },
        .{ .tls = .explicit, .trust = trust },
        // A moved dial is one more input that must not reach the check.
        // `open` hands this function `url.host`, so the name a `pop3s`
        // certificate answers for stays the name the url wrote.
        .{
            .tls = .implicit,
            .trust = trust,
            .connect_to = &.{.{ .to_host = "127.0.0.1", .to_port = 9 }},
        },
    };
    for (moved) |options| {
        const session = (try tlsOptions("mail.example.com", options, null)).?;
        try testing.expectEqualStrings("mail.example.com", session.host.explicit);
        try testing.expect(session.trust != .none);
        try testing.expectEqual(@as(usize, 0), session.alpn_protocols.len);
    }
}

/// A `CAPA` body naming `mechanisms` on its `SASL` line.
fn capaOffering(comptime mechanisms: []const u8) []const u8 {
    return "TOP\r\nUIDL\r\nSASL " ++ mechanisms ++ "\r\nUSER\r\n";
}

/// The base64 of `text`, for a test that names a challenge as it travels.
fn encode(out: []u8, text: []const u8) []const u8 {
    const encoder = std.base64.standard.Encoder;
    return encoder.encode(out[0..encoder.calcSize(text.len)], text);
}

test "a PLAIN login reaches the server with the bytes curl sends" {
    // **Measured from curl 8.21.0** on a loopback POP3 fixture whose
    // `CAPA` answer names `SASL PLAIN`: `AUTH PLAIN`, then
    // `AGFsaWNlAHMzY3JldA==` on its own line.
    var server: test_server.Server = undefined;
    try server.start(.{ .capa = capaOffering("PLAIN") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/1", .{ .credentials = test_credentials }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);

    server.wait();
    try testing.expectEqualStrings(
        "CAPA\nAUTH PLAIN\nAGFsaWNlAHMzY3JldA==\nRETR 1\nQUIT",
        server.commands(),
    );
    // **Neither the user name nor the password is on the wire in the
    // clear.** They are inside the base64 above, which is the whole of
    // what `PLAIN` gives.
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, server.commands(), "s3cret"),
    );
}

test "a server whose CAPA names no SASL logs in with USER and PASS" {
    // **This fallback is better than curl's.** Measured: a `CAPA` answer
    // naming no `SASL` and no `USER` drew exit 67 from curl 8.21.0 with
    // no login attempted at all. This build logs in the way it always
    // did.
    var server: test_server.Server = undefined;
    try server.start(.{ .capa = "TOP\r\nUIDL\r\n" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/1", .{ .credentials = test_credentials }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);

    server.wait();
    try testing.expectEqualStrings(
        "CAPA\nUSER alice\nPASS s3cret\nRETR 1\nQUIT",
        server.commands(),
    );
}

test "a server offering only mechanisms this build has no code for falls back too" {
    var server: test_server.Server = undefined;
    try server.start(.{ .capa = capaOffering("GSSAPI NTLM") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/1", .{ .credentials = test_credentials }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);

    server.wait();
    try testing.expectEqualStrings(
        "CAPA\nUSER alice\nPASS s3cret\nRETR 1\nQUIT",
        server.commands(),
    );
}

test "the strongest mechanism the server offers is the one used" {
    var challenge_storage: [64]u8 = undefined;
    const challenge = encode(&challenge_storage, "<1896.697170952@fixture>");

    var server: test_server.Server = undefined;
    try server.start(.{
        .capa = capaOffering("PLAIN LOGIN CRAM-MD5"),
        .auth_challenges = &.{challenge},
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/1", .{ .credentials = test_credentials }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);

    server.wait();
    // Measured: curl picked `CRAM-MD5` off this list and wrote exactly
    // this response for this challenge and this credential.
    try testing.expectEqualStrings(
        "CAPA\n" ++
            "AUTH CRAM-MD5\n" ++
            "YWxpY2UgMDJmZmVhNTc2NDEyYWNiYzUyNWU0ZDgyNTE0NmY5ZmM=\n" ++
            "RETR 1\n" ++
            "QUIT",
        server.commands(),
    );
}

test "APOP still wins over SASL, and it costs no CAPA at all" {
    // **The password never crosses the network either way**, and `APOP`
    // needs no round trip to find out what the server offers. curl
    // prefers it too, measured. The `CAPA` command is not sent at all,
    // which is why every APOP test written before SASL is unchanged.
    var server: test_server.Server = undefined;
    try server.start(.{
        .greeting = "+OK fixture ready <1896.697170952@dbc.mtview.ca.us>",
        .capa = capaOffering("PLAIN CRAM-MD5"),
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/1", .{
        .credentials = .{ .user = "mrose", .password = "tanstaaf" },
    }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);
    try testing.expect(body.apop);

    server.wait();
    // The digest is the worked example of RFC 1939 section 7.
    try testing.expectEqualStrings(
        "APOP mrose c4c9334bac560ecc979e58001b3e22fb\nRETR 1\nQUIT",
        server.commands(),
    );
}

test "a LOGIN exchange answers two challenges, the user then the password" {
    var user_storage: [32]u8 = undefined;
    var pass_storage: [32]u8 = undefined;

    var server: test_server.Server = undefined;
    try server.start(.{
        .capa = capaOffering("LOGIN"),
        .auth_challenges = &.{
            encode(&user_storage, "Username:"),
            encode(&pass_storage, "Password:"),
        },
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/1", .{ .credentials = test_credentials }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);

    server.wait();
    try testing.expectEqualStrings(
        "CAPA\nAUTH LOGIN\nYWxpY2U=\nczNjcmV0\nRETR 1\nQUIT",
        server.commands(),
    );
}

test "--sasl-ir puts the first message on the AUTH line" {
    var server: test_server.Server = undefined;
    try server.start(.{ .capa = capaOffering("PLAIN") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/1", .{
        .credentials = test_credentials,
        .sasl_ir = true,
    }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);

    server.wait();
    // Measured from curl 8.21.0 with `--sasl-ir` on the same fixture.
    try testing.expectEqualStrings(
        "CAPA\nAUTH PLAIN AGFsaWNlAHMzY3JldA==\nRETR 1\nQUIT",
        server.commands(),
    );
}

test "--sasl-authzid names the identity to act as" {
    var server: test_server.Server = undefined;
    try server.start(.{ .capa = capaOffering("PLAIN") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/1", .{
        .credentials = test_credentials,
        .sasl_authzid = "admin",
    }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);

    server.wait();
    try testing.expectEqualStrings(
        "CAPA\nAUTH PLAIN\nYWRtaW4AYWxpY2UAczNjcmV0\nRETR 1\nQUIT",
        server.commands(),
    );
}

test "--login-options names one mechanism, and a bad one ends the transfer" {
    var server: test_server.Server = undefined;
    try server.start(.{ .capa = capaOffering("PLAIN LOGIN CRAM-MD5") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/1", .{
        .credentials = test_credentials,
        .login_options = "AUTH=PLAIN",
    }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);

    server.wait();
    // The same offer with no option draws `CRAM-MD5`.
    try testing.expectEqualStrings(
        "CAPA\nAUTH PLAIN\nAGFsaWNlAHMzY3JldA==\nRETR 1\nQUIT",
        server.commands(),
    );

    // A mechanism the server did not offer is exit 67, and the `AUTH`
    // never goes out. curl answers the same case the same way, measured.
    var second: test_server.Server = undefined;
    try second.start(.{ .capa = capaOffering("PLAIN") });
    defer second.stop();
    var g: Fetcher = .init(testing.allocator, testing.io);
    defer g.deinit();
    var d: Diagnostics = .{};
    try testing.expectError(error.LoginDenied, fetch(&g, &second, "/1", .{
        .credentials = test_credentials,
        .login_options = "AUTH=CRAM-MD5",
    }, &d));
    try testing.expectEqual(@as(u8, 67), d.curl_code);
    second.wait();
    try testing.expectEqualStrings("CAPA", second.commands());
}

test "a refused SASL exchange never falls back to USER and PASS" {
    // **A downgrade a server could ask for.** A client that answered a
    // `-ERR` by sending `USER` and `PASS` would hand the password in the
    // clear to any server that refused the stronger mechanism.
    var server: test_server.Server = undefined;
    try server.start(.{
        .capa = capaOffering("PLAIN"),
        .auth_reply = "-ERR authentication failed",
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(error.LoginDenied, fetch(&f, &server, "/1", .{
        .credentials = test_credentials,
    }, &d));
    try testing.expectEqual(@as(u8, 67), d.curl_code);
    try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, d.message.?, "s3cret"));

    server.wait();
    // No `USER`, no `PASS`, and no `RETR`.
    try testing.expectEqualStrings(
        "CAPA\nAUTH PLAIN\nAGFsaWNlAHMzY3JldA==",
        server.commands(),
    );
}

test "a challenge that is not base64 cancels the exchange with an asterisk" {
    var server: test_server.Server = undefined;
    try server.start(.{
        .capa = capaOffering("CRAM-MD5"),
        .auth_challenges = &.{"not base64!"},
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(error.WeirdServerReply, fetch(&f, &server, "/1", .{
        .credentials = test_credentials,
    }, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "base64") != null);

    server.wait();
    try testing.expectEqualStrings("CAPA\nAUTH CRAM-MD5\n*", server.commands());
}

test "--oauth2-bearer picks OAUTHBEARER, which names the host and the port" {
    var server: test_server.Server = undefined;
    try server.start(.{ .capa = capaOffering("PLAIN XOAUTH2 OAUTHBEARER") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/1", .{
        .credentials = .{ .user = "alice", .password = "" },
        .bearer_token = "tok123",
    }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);

    server.wait();
    var raw_storage: [256]u8 = undefined;
    const raw = try std.fmt.bufPrint(
        &raw_storage,
        "n,a=alice,\x01host=127.0.0.1\x01port={d}\x01auth=Bearer tok123\x01\x01",
        .{server.port()},
    );
    var encoded_storage: [512]u8 = undefined;
    var want_storage: [512]u8 = undefined;
    const want = try std.fmt.bufPrint(
        &want_storage,
        "CAPA\nAUTH OAUTHBEARER\n{s}\nRETR 1\nQUIT",
        .{encode(&encoded_storage, raw)},
    );
    try testing.expectEqualStrings(want, server.commands());
}

test "a credential that could forge a SASL field is refused, and no socket opens" {
    const forged = [_][]const u8{ "s3cret\x00admin", "\x00", "s3cret\r\nDELE 1", "s3cret\n" };
    for (forged) |text| {
        var server: test_server.Server = undefined;
        try server.start(.{ .capa = capaOffering("PLAIN") });
        defer server.stop();

        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();

        var d: Diagnostics = .{};
        try testing.expectError(error.InvalidUrl, fetch(&f, &server, "/1", .{
            .credentials = .{ .user = "alice", .password = text },
        }, &d));
        try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, d.message.?, "s3cret"));
        try testing.expectEqual(@as(usize, 0), server.connections());
    }
}

test "an authzid that could forge a field is refused before the AUTH" {
    var server: test_server.Server = undefined;
    try server.start(.{ .capa = capaOffering("PLAIN") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    try testing.expectError(error.InvalidUrl, fetch(&f, &server, "/1", .{
        .credentials = test_credentials,
        .sasl_authzid = "admin\x00root",
    }, null));

    server.wait();
    // The `AUTH` never went out, so no field of it reached the server.
    try testing.expectEqualStrings("CAPA", server.commands());
}

test "every buffer a credential passed through is zeroed when the transfer ends" {
    var server: test_server.Server = undefined;
    try server.start(.{ .capa = capaOffering("PLAIN") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var url_buffer: [512]u8 = undefined;
    const url = try std.fmt.bufPrint(
        &url_buffer,
        "pop3://alice:s3cret@127.0.0.1:{d}/1",
        .{server.port()},
    );
    const body = try f.open(try parsePop3Url(url), .{
        .connect_timeout = test_connect_timeout,
    }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);

    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, &f.credential_storage, "s3cret"),
    );
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, &f.sasl_storage, "AGFsaWNlAHMzY3JldA=="),
    );
    for (f.credential_storage) |byte| try testing.expectEqual(@as(u8, 0), byte);
    for (f.sasl_storage) |byte| try testing.expectEqual(@as(u8, 0), byte);
    for (f.apop_storage) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "a CAPA answer larger than the bound ends the transfer" {
    // **A capability list is a body a server chooses the length of.** It
    // is bounded by this package's own number and not by
    // `--max-filesize`, which names the answer a user asked for.
    var long_storage: [max_capability_bytes + 4096]u8 = undefined;
    @memset(&long_storage, 'x');
    // Every line is one long word, so no `SASL` line is ever found and
    // the body simply grows.
    var i: usize = 40;
    while (i < long_storage.len) : (i += 40) {
        long_storage[i] = '\r';
        long_storage[i + 1] = '\n';
    }

    var server: test_server.Server = undefined;
    try server.start(.{ .capa = &long_storage });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(error.WeirdServerReply, fetch(&f, &server, "/1", .{
        .credentials = test_credentials,
    }, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "CAPA") != null);
}

test "--connect-to moves a pop3 dial and --resolve reaches this package too" {
    // The defect this closes: this package read no `connect_to`, so a
    // user who named either flag got a dial to the url's own host and no
    // diagnostic. curl 8.21.0 applies both to `pop3` and `pop3s`,
    // measured.
    //
    // **No test here touches a resolver.** The url names `127.0.0.2:1`,
    // which refuses at once, so the flag is the only thing that can reach
    // the fixture.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    const url = try parsePop3Url("pop3://127.0.0.2:1/1");

    var bare: Diagnostics = .{};
    try testing.expectError(error.CouldNotConnect, f.open(url, .{
        .connect_timeout = test_connect_timeout,
        .credentials = test_credentials,
    }, &bare));
    try testing.expectEqual(@as(usize, 0), server.connections());

    const body = try f.open(url, .{
        .connect_timeout = test_connect_timeout,
        .credentials = test_credentials,
        .connect_to = &.{.{
            .from_host = "127.0.0.2",
            .from_port = 1,
            .to_host = "127.0.0.1",
            .to_port = server.port(),
        }},
    }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);
    try testing.expect(contents.len > 0);
    try testing.expectEqual(@as(usize, 1), server.connections());
}

test "the pop3 translation carries --connect-to into this package" {
    var client: StubFront.Client = .{};
    const D = Dispatch(StubFront);
    const url = try parsePop3Url("pop3://example.com/1");

    try testing.expectEqual(@as(usize, 0), D.translate(&client, url, .{}).connect_to.len);

    const overrides: []const zurl_net.override.HostOverride = &.{.{
        .from_host = "a.test",
        .to_host = "127.0.0.1",
        .to_port = 9,
    }};
    const carried = D.translate(&client, url, .{ .connect_to = overrides });
    try testing.expectEqual(@as(usize, 1), carried.connect_to.len);
    try testing.expectEqualStrings("a.test", carried.connect_to[0].from_host);
}
