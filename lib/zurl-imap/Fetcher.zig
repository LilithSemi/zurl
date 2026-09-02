//! Runs one `imap://` or `imaps://` transfer: the tagged dialogue, the
//! login, the command, and the answer.
//!
//! A `Fetcher` owns the answer of the transfer in play. `open` frees
//! whatever the last call left and holds the new answer, so one `Fetcher`
//! serves one transfer at a time.
//!
//! **A `Fetcher` must not move once `open` has run.** The body reader it
//! hands back points into this value, and so do the dialogue's own reader
//! and writer.
//!
//! **One package owns both schemes.** RFC 3501 names the dialogue, and
//! `imaps` changes neither the commands nor the answers: it puts the same
//! two inside TLS. `protocol` and `secureProtocol` build the two dispatch
//! entries, and both point at one vtable that reads `url.scheme`. The two
//! carry different default ports, 143 and 993, which is what curl uses.
//!
//! **What a transfer sends.** The command order is curl's own, measured
//! against curl 8.21.0 on a loopback RFC 3501 fixture:
//!
//!     imap://h/                    LOGIN, LIST "" *, LOGOUT
//!     imap://h/INBOX               LOGIN, LIST "INBOX" *, LOGOUT
//!     imap://h/INBOX;UID=1         LOGIN, SELECT INBOX, UID FETCH 1 BODY[], LOGOUT
//!     imap://h/INBOX;MAILINDEX=2   LOGIN, SELECT INBOX, FETCH 2 BODY[], LOGOUT
//!     -X 'FETCH 1 BODY[HEADER]'    LOGIN, SELECT INBOX, the command, LOGOUT
//!
//! with `STARTTLS` before `LOGIN` for an explicit TLS transfer.
//!
//! curl sends `CAPABILITY` first and zurl does not, so every tag of a zurl
//! session is one lower than curl's. curl reads that answer for a SASL
//! mechanism list, which zurl has none of, and for whether `STARTTLS` is
//! offered, which zurl learns by sending the command. Either way a refusal
//! under `--ssl-reqd` is exit 64 and **no credential goes out**.
//!
//! **A login happens only when somebody named a credential.** curl does
//! the same, measured: `imap://h/` with no `-u` and no userinfo sends no
//! `LOGIN` at all.
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
pub const scheme = "imap";

/// The encrypted scheme this package handles.
pub const secure_scheme = "imaps";

/// The port an `imap://` url uses when it names none. RFC 3501.
pub const default_port: ?u16 = 143;

/// The port an `imaps://` url uses when it names none.
pub const secure_default_port: ?u16 = 993;

/// The status an IMAP transfer reports.
///
/// Zero. RFC 3501 answers `OK`, `NO`, and `BAD` and has no HTTP status.
pub const status: u16 = 0;

/// How many bytes of answer this package reads by default.
///
/// 16 MiB, the number every other protocol package here keeps.
/// `Options.max_response_bytes` raises it, and `--max-filesize` narrows
/// it.
pub const default_max_response_bytes: u64 = 16 * 1024 * 1024;

/// How much room a connection keeps for bytes read and not taken yet.
pub const read_buffer_len: usize = 8192;

/// How much room the plain stream of a `STARTTLS` upgrade keeps.
pub const upgrade_buffer_len: usize = 1024;

/// How long one read may wait with no byte arriving.
///
/// 300 seconds is curl's own `--speed-time` default. `--speed-time`
/// narrows it and never widens it.
pub const default_read_timeout_s: u32 = 300;

/// `default_read_timeout_s`, as a `std.Io.Timeout`.
pub const default_read_timeout: Io.Timeout = .{
    .duration = .{ .raw = .fromSeconds(default_read_timeout_s), .clock = .awake },
};

/// How many bytes of credential this decodes out of a url.
///
/// `command.quote` sizes its output buffer from this number, because a
/// credential goes through the same gate a mailbox name does. See
/// `quoteCredential`.
pub const max_credential_bytes: usize = command.max_quoted_input_bytes;

/// Where the transfer got the credential it sent.
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
    /// No TLS at all. This is a plain `imap://` url.
    none,
    /// The handshake runs as soon as the socket opens, before the
    /// greeting. This is `imaps://`, on port 993.
    implicit,
    /// The greeting arrives in the clear, then `STARTTLS`, then the
    /// handshake. RFC 2595. This is `--ssl-reqd` on an `imap://` url.
    explicit,
};

/// The trust store an encrypted session verifies against, and the way to
/// fill it.
///
/// **An `imaps` session verifies exactly as an `https` session does.** A
/// build that leaves this null cannot open an encrypted session at all:
/// `open` reports `error.SslConnectError` rather than fall back to a
/// session that verifies nothing.
///
/// The shape matches `zurl.Client.TlsMaterials` field for field. It is
/// written out here because this package must build with no `zurl` in its
/// import table.
pub const Trust = struct {
    lock: *Io.RwLock,
    bundle: *std.crypto.Certificate.Bundle,
    /// Passed back to `load`.
    ptr: *anyopaque,
    /// Fills `bundle` from the sources the transfer named.
    load: *const fn (ptr: *anyopaque) Error!void,
};

/// What one transfer may ask for.
pub const Options = struct {
    /// A cap on the dial, the `STARTTLS` step, and the handshake together.
    connect_timeout: Io.Timeout = .none,
    /// The bound on the answer. See `default_max_response_bytes`.
    max_response_bytes: u64 = default_max_response_bytes,
    /// How long one read may wait with no byte arriving.
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
    /// The text of a netrc file the caller already read, or null.
    netrc_text: ?[]const u8 = null,
    /// The command `-X`/`--request` named, or null for the command the url
    /// implies. The whole value is the command line after the tag, so
    /// `FETCH 1 BODY[HEADER]` is one value.
    custom_request: ?[]const u8 = null,
    /// The token `--oauth2-bearer` named, or null. See
    /// `zurl_net.sasl.choose`.
    bearer_token: ?[]const u8 = null,
    /// The identity `--sasl-authzid` named, or null.
    sasl_authzid: ?[]const u8 = null,
    /// Whether to put the first SASL message on the `AUTHENTICATE` line
    /// itself. This is `--sasl-ir`.
    sasl_ir: bool = false,
    /// The value `--login-options` named, or null.
    login_options: ?[]const u8 = null,
    /// Where a url naming one host and port dials instead. This is
    /// `--resolve` and `--connect-to`.
    ///
    /// **An entry moves the dial and nothing else.** `tlsOptions` reads
    /// `url.host`, so an `imaps` peer at the dialed address must still
    /// hold a certificate for the name the url wrote. The `OAUTHBEARER`
    /// message names the url's host and port too, because it names the
    /// service the user asked for. See `zurl_net.override`.
    connect_to: []const zurl_net.override.HostOverride = &.{},
};

/// How many bytes of a capability list this keeps.
///
/// A busy server names a few dozen capabilities and each is a short word.
/// This is past every list measured, and a server whose list is longer
/// simply has the rest of it dropped: a mechanism that did not fit is a
/// mechanism this transfer does not use, which is the same answer as a
/// server that never named it.
pub const max_capability_bytes: usize = 1024;

allocator: std.mem.Allocator,
io: Io,
/// The answer of the transfer in play, or null when none is held.
answer: ?[]u8,
/// Reads `answer`. Valid only while `answer` holds something.
body: Io.Reader,
/// The tagged command dialogue. Points at whichever channel is live.
control: Control,
/// The url path, decoded.
path: target.Target,
/// Holds a credential decoded out of a url's userinfo, the user first and
/// the password after it.
credential_storage: [max_credential_bytes * 2]u8,
/// Holds the mailbox name in the form a command carries it.
quoted_storage: [command.max_quoted_bytes]u8,
/// Holds the capability list of the greeting.
///
/// A copy, and not a slice of the greeting, because the greeting borrows
/// the dialogue's one line buffer and the next read overwrites it.
capability_storage: [max_capability_bytes]u8,
/// How much of `capability_storage` is filled. Zero when the greeting
/// carried no `[CAPABILITY ...]` response code.
capability_len: usize,
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
/// section 3.1, and `login` runs deep enough that passing the url down to
/// it would thread one parameter through four functions that read neither.
host: []const u8,
port: u16,
/// The plain stream a `STARTTLS` upgrade speaks over, before the
/// handshake.
upgrade_reader: std.Io.net.Stream.Reader,
upgrade_writer: std.Io.net.Stream.Writer,
upgrade_read_storage: [upgrade_buffer_len]u8,
upgrade_write_storage: [upgrade_buffer_len]u8,
/// What the `STARTTLS` step recorded. See `runUpgrade`.
upgrade_fault: ?UpgradeFault,
/// How long one read may wait with no byte arriving.
stall: Io.Timeout,

/// Why the `STARTTLS` step stopped.
///
/// **A task that loses the connect race returns nothing**, so the step
/// records its reason here and `open` reads it back.
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
        .quoted_storage = undefined,
        .capability_storage = undefined,
        .capability_len = 0,
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
/// credential passed through. Safe to call more than once.
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
/// `credential_storage` holds the decoded userinfo of a url,
/// `quoted_storage` holds the password in the form a `LOGIN` line carries
/// it, and `sasl_storage` holds the encoded `PLAIN` message, which is the
/// password with nothing but base64 over it. The challenge buffer holds no
/// secret and is wiped with them, so that one rule covers the four and
/// nobody has to work out which of them left a password behind.
///
/// `open` runs this whichever way it leaves, and `deinit` runs it again so
/// that a caller who stops part way through still leaves nothing.
fn wipe(f: *Fetcher) void {
    std.crypto.secureZero(u8, &f.credential_storage);
    std.crypto.secureZero(u8, &f.quoted_storage);
    std.crypto.secureZero(u8, &f.sasl_storage);
    std.crypto.secureZero(u8, &f.challenge_storage);
}

/// The answer of one IMAP transfer.
pub const Body = struct {
    /// Streams the answer. Valid until the next `open` on this `Fetcher`.
    reader: *Io.Reader,
    /// How many bytes the answer holds.
    length: u64,
    /// Whether the transfer named mailboxes rather than fetch a message.
    listing: bool,
};

/// Whether `url` asks for a TLS session on the connection.
///
/// The scheme and nothing else. Compared without regard to case, per RFC
/// 3986, so `IMAPS://` is as encrypted as `imaps://`.
pub fn isSecure(url: zurl_core.Url) bool {
    return std.ascii.eqlIgnoreCase(url.scheme, secure_scheme);
}

/// Runs one transfer and returns its answer.
///
/// The faults, and the exit code each carries. Every one was measured
/// against curl 8.21.0 on a loopback IMAP fixture:
///
/// - a url path whose decoded form holds a control byte is
///   `error.InvalidUrl`, exit 3, and no socket opens at all. curl refuses
///   the same url with the same code, but only after it has logged in.
/// - a peer that does not accept a connection is `error.CouldNotConnect`,
///   exit 7.
/// - a line nothing can read is `error.WeirdServerReply`, exit 8.
/// - a `NO` to `LOGIN` or to `SELECT` is `error.LoginDenied`, exit 67.
/// - a `NO` to a `FETCH` is `error.RemoteFileNotFound`, exit 78.
/// - a `NO` to a `LIST`, or to a `--request` command, is
///   `error.QuoteError`, exit 21.
/// - a refused `STARTTLS` under `--ssl-reqd` is `error.UseSslFailed`, exit
///   64, and no credential goes out.
pub fn open(f: *Fetcher, url: zurl_core.Url, options: Options, d: ?*Diagnostics) Error!Body {
    f.release();
    f.upgrade_fault = null;
    f.stall = options.read_timeout;
    f.capability_len = 0;
    // **The credential lives no longer than the transfer.** See `wipe`.
    defer f.wipe();

    // **The url is read before anything is dialed.** A mailbox name that
    // could forge a command is refused here, with no socket opened at all.
    f.path.parse(url.path) catch |err| return reportPath(err, d);

    var credential_source: CredentialSource = undefined;
    const credentials = try f.resolveCredentials(url, options, &credential_source, d);

    const port = url.port orelse return fail(d, error.InvalidUrl, &.{
        "an imap url names a port, and this one names none",
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

    // **The dial, the `STARTTLS` step, and the handshake share one
    // deadline.** See `zurl_net.bounded.Setup.upgrade`.
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
    defer connection.deinit();

    const channel: Control.Channel = .{
        .reader = connection.reader(),
        .writer = connection.writer(),
        .ctx = &connection,
        .flush = flushConnection,
    };
    // **An explicit upgrade was already speaking**, and `retarget` keeps
    // the tag counter as well as the storage, so no tag is used twice.
    if (options.tls == .explicit) {
        f.control.retarget(channel);
    } else {
        f.control.init(f.io, channel, options.read_timeout);

        const greeting = f.control.readGreetingLine() catch |err| return reportControl(err, &connection, "the greeting", d);
        const word = greeting.status orelse return fail(d, error.WeirdServerReply, &.{
            "the imap server greeted this connection with a line that carries no status word",
        });
        if (!word.isPositive()) return fail(d, error.WeirdServerReply, &.{
            "the imap server refused this connection in its greeting",
        });

        // **The greeting may already name every capability.** RFC 3501
        // section 7.1 lets a server write a `[CAPABILITY ...]` response
        // code in it, and most do. Keeping it here saves the whole
        // `CAPABILITY` round trip that curl always spends.
        f.keepCapabilities(greeting.text);
    }

    // **A `PREAUTH` greeting means the connection is already logged in**,
    // and RFC 3501 section 7.1.1 forbids `LOGIN` after one. This package
    // does not read the greeting back for that, because it logs in only
    // when a credential was named and a caller that named one meant it.
    if (credentials) |c| try f.login(&connection, c, credential_source, options, d);

    const answer = try f.runRequest(&connection, options, d);
    errdefer f.allocator.free(answer);

    // `LOGOUT` is a courtesy and never a gate. The answer is already read,
    // so a server that will not say goodbye has cost this transfer
    // nothing.
    if (f.control.send(&.{command.logout})) |_| {} else |_| {}

    f.answer = answer;
    f.body = .fixed(answer);
    return .{
        .reader = &f.body,
        .length = answer.len,
        .listing = options.custom_request == null and !f.path.fetches(),
    };
}

/// Sends the command the url or `--request` names, and reads its answer.
///
/// **A `SELECT` comes first for anything that reads a message.** RFC 3501
/// makes `FETCH` a command of the selected state, so a `FETCH` with no
/// mailbox open is a `BAD`. curl sends the same `SELECT`, measured, and it
/// sends one for a `--request` command too whenever the url names a
/// mailbox.
fn runRequest(
    f: *Fetcher,
    connection: *zurl_net.Connection,
    options: Options,
    d: ?*Diagnostics,
) Error![]u8 {
    const max_bytes = options.max_response_bytes;

    // A url with no mailbox and no custom command lists every mailbox.
    if (options.custom_request == null and !f.path.fetches()) {
        const reference = try f.quoteMailbox(f.path.mailbox, d);
        const out = try f.run(connection, &.{
            command.list, " ", reference, " ", command.list_all_pattern,
        }, .untagged, max_bytes, command.list, d);
        if (!out.status.isPositive()) {
            f.allocator.free(out.body);
            return failStatus(d, error.QuoteError, "the imap server refused the LIST this url names", out);
        }
        return out.body;
    }

    // Everything else needs a mailbox open first.
    if (f.path.mailbox.len != 0) {
        const mailbox = try f.quoteMailbox(f.path.mailbox, d);
        const out = try f.run(connection, &.{
            command.select, " ", mailbox,
        }, .discard, max_bytes, command.select, d);
        f.allocator.free(out.body);
        if (!out.status.isPositive()) {
            // curl answers a refused `SELECT` with exit 67 and the
            // sentence `Select failed`, measured, and not with 78.
            return failStatus(d, error.LoginDenied, "the imap server refused the mailbox this url names", out);
        }
    }

    if (options.custom_request) |value| {
        const out = try f.run(connection, &.{value}, .untagged, max_bytes, value, d);
        if (!out.status.isPositive()) {
            f.allocator.free(out.body);
            return failStatus(d, error.QuoteError, "the imap server refused the command --request named", out);
        }
        return out.body;
    }

    // **A UID and a mail index are different commands.** See
    // `target.Addressing`.
    const out = switch (f.path.addressing) {
        .uid => try f.run(connection, &.{
            command.uid, " ", command.fetch, " ", f.path.id, " ", command.whole_message,
        }, .literal, max_bytes, command.fetch, d),
        .index => try f.run(connection, &.{
            command.fetch, " ", f.path.id, " ", command.whole_message,
        }, .literal, max_bytes, command.fetch, d),
        .none => unreachable,
    };
    if (!out.status.isPositive()) {
        f.allocator.free(out.body);
        return failStatus(d, error.RemoteFileNotFound, "the imap server refused the message this url names", out);
    }
    return out.body;
}

/// Sends one command and reads its whole answer, mapping every fault onto
/// a `zurl_core.Error`.
fn run(
    f: *Fetcher,
    connection: ?*zurl_net.Connection,
    parts: []const []const u8,
    mode: Control.Mode,
    max_bytes: u64,
    verb: []const u8,
    d: ?*Diagnostics,
) Error!Control.Outcome {
    return f.control.run(f.allocator, parts, mode, max_bytes) catch |err| switch (err) {
        error.OutOfMemory => Diagnostics.record(d, error.OutOfMemory, .{}),
        error.StreamTooLong => failNumber(
            d,
            error.FileSizeExceeded,
            "the imap server wrote more than the ",
            max_bytes,
            " bytes zurl reads from one transfer",
        ),
        else => |rest| reportControl(rest, connection, verb, d),
    };
}

/// Writes `name` in the form a command carries it.
///
/// See `command.quote`: a name that is not an atom goes inside double
/// quotes, and a `"` or a `\` inside it is escaped, so a name can never
/// close its own argument.
fn quoteMailbox(f: *Fetcher, name: []const u8, d: ?*Diagnostics) Error![]const u8 {
    return command.quote(&f.quoted_storage, name) catch failNumber(
        d,
        error.InvalidUrl,
        "the mailbox this url names does not fit the ",
        command.max_quoted_bytes,
        " bytes one imap command line carries for it",
    );
}

/// Writes a credential field in the form a command carries it.
///
/// **Every text a command line carries goes through `command.quote`, and
/// not the mailbox alone.** `zurl_net.line.write` enforces line framing,
/// and IMAP has a grammar one layer above that: a `LOGIN` argument holding
/// a space is two arguments, and one holding `{5+}` is a LITERAL+ count
/// that makes the server read this client's next command as literal data.
/// A plain space in a password sent the wrong secret. curl runs both
/// fields through `imap_atom()` for the same reason.
///
/// `out` is the caller's, because a `LOGIN` carries two of these at once
/// and one buffer cannot hold both.
fn quoteCredential(
    out: []u8,
    text: []const u8,
    d: ?*Diagnostics,
) Error![]const u8 {
    return command.quote(out, text) catch failNumber(
        d,
        error.CredentialTooLarge,
        "the credential this transfer names does not fit the ",
        command.max_quoted_bytes,
        " bytes one imap command line carries for it",
    );
}

/// Keeps the `[CAPABILITY ...]` list of a greeting or an `OK` line.
///
/// RFC 3501 section 7.1 writes the response code as `[CAPABILITY IMAP4rev1
/// AUTH=PLAIN] ready`. A line carrying no such code leaves the list empty,
/// and `login` then spends a `CAPABILITY` command to get one.
///
/// A copy, because the text borrows the dialogue's one line buffer.
fn keepCapabilities(f: *Fetcher, text: []const u8) void {
    const bracket = std.mem.indexOfScalar(u8, text, '[') orelse return;
    const close = std.mem.indexOfScalarPos(u8, text, bracket, ']') orelse return;
    const code = text[bracket + 1 .. close];
    const keyword = "CAPABILITY";
    if (code.len <= keyword.len) return;
    if (!std.ascii.eqlIgnoreCase(code[0..keyword.len], keyword)) return;
    // The keyword must be a whole word, so a code named `CAPABILITYX` is
    // another code.
    if (code[keyword.len] != ' ' and code[keyword.len] != '\t') return;

    const list = code[keyword.len..];
    const n = @min(list.len, f.capability_storage.len);
    @memcpy(f.capability_storage[0..n], list[0..n]);
    f.capability_len = n;
}

/// The capability list this transfer knows.
fn capabilities(f: *const Fetcher) []const u8 {
    return f.capability_storage[0..f.capability_len];
}

/// Logs in, with SASL when the server offers a mechanism and with `LOGIN`
/// when it does not.
///
/// **The order is SASL first, and `LOGIN` is the fallback.** RFC 3501
/// section 6.2.3 sends the password in the clear, and many servers now
/// refuse it. `zurl_net.sasl.choose` picks the mechanism, and its order is
/// curl's own, measured.
///
/// **`LOGINDISABLED` is honoured.** A server that names it has said the
/// cleartext `LOGIN` will be refused whatever credential it carries, so
/// sending one would put the password on the wire for a command the server
/// already said no to. That is `error.LoginDenied`, exit 67, with no
/// command sent. curl sends the `LOGIN` anyway.
///
/// **A failed SASL exchange never falls back to `LOGIN`.** A second
/// attempt with a weaker mechanism after a refusal is a downgrade a
/// server, or somebody on the path, could ask for.
///
/// A `NO` or a `BAD` is `error.LoginDenied`, exit 67, which is curl's own
/// code, measured against a fixture answering `NO` to `LOGIN`.
fn login(
    f: *Fetcher,
    connection: ?*zurl_net.Connection,
    credentials: Credentials,
    source: CredentialSource,
    options: Options,
    d: ?*Diagnostics,
) Error!void {
    // **One `CAPABILITY` command, and only when the greeting named
    // none.** curl always sends one, measured, which is why its tags run
    // one higher than zurl's.
    if (f.capability_len == 0) {
        const out = try f.run(
            connection,
            &.{command.capability},
            .untagged,
            options.max_response_bytes,
            command.capability,
            d,
        );
        defer f.allocator.free(out.body);
        // The list arrives as an untagged `* CAPABILITY ...` line. A
        // server that answered `NO` has named nothing, and the login
        // below then falls back to `LOGIN` the way it always did.
        if (out.status.isPositive()) f.keepUntaggedCapabilities(out.body);
    }

    var offer: zurl_net.sasl.Offer = .empty;
    offer.addImapCapabilities(f.capabilities());

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

    if (chosen) |mechanism| {
        return f.authenticate(connection, mechanism, credentials, source, options, d);
    }

    if (options.bearer_token != null) return fail(d, error.LoginDenied, &.{
        "--oauth2-bearer needs a server offering XOAUTH2 or OAUTHBEARER, and this one offers neither",
    });
    if (zurl_net.sasl.imapLoginDisabled(f.capabilities())) {
        return failCredential(
            d,
            error.LoginDenied,
            source,
            "this imap server names LOGINDISABLED and offers no SASL mechanism zurl speaks, so it cannot take the credential from ",
            null,
        );
    }

    return f.plainLogin(connection, credentials, source, options, d);
}

/// Keeps the capability list of an untagged `* CAPABILITY ...` line.
///
/// `body` is every untagged line of the answer, each with a `CRLF` after
/// it, which is what `Control.Mode.untagged` gives.
fn keepUntaggedCapabilities(f: *Fetcher, body: []const u8) void {
    var it = std.mem.splitSequence(u8, body, "\r\n");
    while (it.next()) |line| {
        const bare = std.mem.trim(u8, line, " \t");
        if (!std.mem.startsWith(u8, bare, "* ")) continue;
        const rest = std.mem.trim(u8, bare[2..], " \t");
        const keyword = "CAPABILITY";
        if (rest.len <= keyword.len) continue;
        if (!std.ascii.eqlIgnoreCase(rest[0..keyword.len], keyword)) continue;
        if (rest[keyword.len] != ' ' and rest[keyword.len] != '\t') continue;

        const list = rest[keyword.len..];
        const n = @min(list.len, f.capability_storage.len);
        @memcpy(f.capability_storage[0..n], list[0..n]);
        f.capability_len = n;
        return;
    }
}

/// Sends `LOGIN`.
///
/// **`LOGIN` sends the password in the clear**, which is why `--ssl-reqd`
/// and `imaps://` exist. RFC 3501 section 6.2.3 says so itself. It is the
/// fallback for a server that offers no SASL mechanism this build speaks,
/// and curl falls back the same way, measured against a fixture whose
/// capability list names no `AUTH=`.
///
/// **Both arguments go through `command.quote`**, the same gate a mailbox
/// name passes. See `quoteCredential`.
fn plainLogin(
    f: *Fetcher,
    connection: ?*zurl_net.Connection,
    credentials: Credentials,
    source: CredentialSource,
    options: Options,
    d: ?*Diagnostics,
) Error!void {
    // Two buffers, because the two arguments are on one line together.
    // `resolveCredentials` bounds each field at `max_credential_bytes`,
    // which is the text `command.max_quoted_bytes` is sized for. The
    // password buffer is a field, so `wipe` reaches it: a local would go
    // back to the stack holding the password in the clear.
    var user_storage: [command.max_quoted_bytes]u8 = undefined;
    const user = try quoteCredential(&user_storage, credentials.user, d);
    const password = try quoteCredential(&f.quoted_storage, credentials.password, d);

    // The answer is thrown away, and the bound is still the caller's own:
    // a server may write an untagged literal before the tagged answer, and
    // those octets have to be read off the wire whatever happens to them.
    const out = try f.run(connection, &.{
        command.login, " ", user, " ", password,
    }, .discard, options.max_response_bytes, command.login, d);
    f.allocator.free(out.body);
    if (out.status.isPositive()) return;
    return failCredential(d, error.LoginDenied, source, "the imap server did not accept the credential from ", out);
}

/// Runs one SASL exchange with `AUTHENTICATE`.
///
/// RFC 3501 section 6.2.2: the client writes `AUTHENTICATE <mechanism>`,
/// the server answers `+ <challenge>` for each message it wants, and the
/// client answers each with one line of base64. The exchange ends at the
/// tag the command carried.
///
/// **A challenge this client cannot answer is cancelled with `*`.** RFC
/// 3501 section 6.2.2 gives a client one asterisk on a line of its own to
/// end an exchange, and a client that walked away without it would leave
/// the server reading the next command as a response.
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
    // **Every field is checked before the command goes out**, so a field
    // that cannot travel never opens an exchange this client has to
    // abandon. See `zurl_smtp.Fetcher.authenticate`.
    fields.checkAll(mechanism) catch |err| return failSasl(d, err);

    const initial: ?[]const u8 = if (options.sasl_ir and mechanism.hasInitialResponse())
        try f.saslMessage(mechanism, "", fields, d)
    else
        null;

    const tag = if (initial) |text|
        f.control.send(&.{ command.authenticate, " ", mechanism.name(), " ", text }) catch |err|
            return reportControl(err, connection, command.authenticate, d)
    else
        f.control.send(&.{ command.authenticate, " ", mechanism.name() }) catch |err|
            return reportControl(err, connection, command.authenticate, d);

    var step: usize = if (initial != null) 1 else 0;
    // One counter for the whole exchange, so a server writing untagged
    // lines for ever ends it. See `Control.readAuthLine`.
    var lines: usize = 0;
    while (true) {
        const next = f.control.readAuthLine(tag, &lines) catch |err|
            return reportControl(err, connection, command.authenticate, d);
        switch (next) {
            .done => |end| {
                if (end.status.isPositive()) return;
                return failCredentialText(
                    d,
                    error.LoginDenied,
                    source,
                    "the imap server did not accept the credential from ",
                    end.text,
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
                    return reportControl(err, connection, command.authenticate, d);
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
            "the imap server wrote a SASL challenge longer than the ",
            zurl_net.sasl.max_challenge_text_bytes,
            " bytes zurl reads",
        ),
        error.ChallengeMalformed => fail(d, error.WeirdServerReply, &.{
            "the imap server wrote a SASL challenge that is not base64",
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
            "the imap server asked for another SASL message after the exchange had finished",
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

/// The credential this transfer sends, or null when nobody named one.
///
/// The url's userinfo first, then `-u`, then a netrc entry for the url's
/// host. That is curl's own order for IMAP, measured.
///
/// **Null is a real answer and not a fault.** curl sends no `LOGIN` at all
/// for a url with no credential, measured.
///
/// **The userinfo is percent-decoded and the other two are not**, which is
/// what curl does.
///
/// **A credential that could forge a command never reaches one.**
/// `Control.send` refuses a NUL, a CR, or an LF in any part of a command
/// line, so a forged `LOGIN` is refused at the socket whatever source it
/// came from. This function refuses the same three bytes first, so the
/// message names the credential and its source rather than the command.
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
            " holds a NUL, a CR, or an LF, and any of the three would end the imap command line and write a command of its own",
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
/// off, and it reads `options.insecure` and nothing else.**
///
/// **A build with no trust store cannot open an encrypted session.** The
/// `null` arm reports `error.SslConnectError` rather than fall back to
/// `.none`.
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
        "this build gave the imap package no trust store, so it cannot verify an imaps peer",
    });
    try trust.load(trust.ptr);

    return .{
        .host = .{ .explicit = host },
        .trust = .{ .bundle = .{ .lock = trust.lock, .bundle = trust.bundle } },
        .min_version = options.tls_min_version,
        .max_version = options.tls_max_version,
        // **No ALPN extension at all.** RFC 7301 needs a registered
        // protocol name and IMAP has none.
        .alpn_protocols = &.{},
    };
}

/// The `STARTTLS` step, run inside the connect race.
///
/// **This runs on a plain stream and it sends no credential.** RFC 2595
/// puts the greeting and `STARTTLS` before the handshake, so those two
/// cross in the clear and nothing else does. `LOGIN` goes out after the
/// handshake, from `open`.
fn runUpgrade(ctx: *anyopaque, io: Io, stream: std.Io.net.Stream) bool {
    const f: *Fetcher = @ptrCast(@alignCast(ctx));
    f.upgrade_fault = f.upgradeStep(io, stream);
    return f.upgrade_fault == null;
}

/// Runs the step, and returns why it stopped, or null when it worked.
fn upgradeStep(f: *Fetcher, io: Io, stream: std.Io.net.Stream) ?UpgradeFault {
    f.upgrade_reader = .init(stream, io, &f.upgrade_read_storage);
    f.upgrade_writer = .init(stream, io, &f.upgrade_write_storage);
    f.control.init(io, .{
        .reader = &f.upgrade_reader.interface,
        .writer = &f.upgrade_writer.interface,
        .ctx = &f.upgrade_writer,
        .flush = flushStream,
    }, f.stall);

    const greeting = f.control.readGreeting() catch |err| return .{
        .err = controlFault(err),
        .message = "zurl did not read the imap greeting before STARTTLS",
    };
    if (!greeting.isPositive()) return .{
        .err = error.WeirdServerReply,
        .message = "the imap server refused this connection in its greeting, so STARTTLS was never sent",
    };

    // The answer keeps no body. The bound is small on purpose: this runs
    // before the handshake, on a plain stream, so anything the peer writes
    // here is cleartext it chose, and there is no reason to read a
    // kilobyte of it.
    const out = f.control.run(f.allocator, &.{command.starttls}, .discard, 1024) catch |err| return .{
        .err = controlFault(err),
        .message = "zurl did not read the answer to STARTTLS",
    };
    f.allocator.free(out.body);
    if (!out.status.isPositive()) return .{
        .err = error.UseSslFailed,
        .message = "the imap server refused STARTTLS, and zurl sends no credential over a connection that was asked to be encrypted and is not",
    };

    // **Nothing may be held across the handshake.** A server that wrote
    // bytes behind its `OK` wrote them in cleartext, and carrying them
    // into the session would hand a caller text the peer chose as though
    // TLS had protected it.
    if (f.control.buffered() != 0) return .{
        .err = error.UseSslFailed,
        .message = "the imap server wrote more bytes behind its STARTTLS answer, and those bytes are not inside the session",
    };

    return null;
}

/// Empties both buffers of a `zurl_net.Connection`.
fn flushConnection(ctx: ?*anyopaque) Io.Writer.Error!void {
    const connection: *zurl_net.Connection = @ptrCast(@alignCast(ctx.?));
    connection.flush() catch return error.WriteFailed;
}

/// Empties the buffer of a plain stream writer.
fn flushStream(ctx: ?*anyopaque) Io.Writer.Error!void {
    const writer: *std.Io.net.Stream.Writer = @ptrCast(@alignCast(ctx.?));
    return writer.interface.flush();
}

/// The `zurl_core.Error` one dialogue fault means.
///
/// Every name is listed, so a new one in `Control.Error` is a compile
/// error here and never a fault that reaches a user under the wrong
/// number.
fn controlFault(err: Control.Error) Error {
    return switch (err) {
        error.ResponseMalformed,
        error.ResponseMalformedTagged,
        error.LineTooLong,
        error.TooManyUntaggedLines,
        error.UnexpectedContinuation,
        => error.WeirdServerReply,
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
    const mapped = controlFault(err);
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
    return fail(d, mapped, &.{ "the imap connection failed on ", verb, ": ", cause });
}

/// Reports a dial or handshake fault.
///
/// **A `STARTTLS` step that failed reports its own reason**, which it
/// recorded before the race ended.
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
        // **The injection refusal at the url.**
        error.PathHasControlByte => fail(d, error.InvalidUrl, &.{
            "the mailbox this url names holds a control byte, and a CR or an LF in one would end an imap command line and write a command of its own",
        }),
        error.InvalidEscape => fail(d, error.InvalidUrl, &.{
            "the path of this url holds a percent escape that is not an escape",
        }),
        error.PathTooLong => failNumber(
            d,
            error.InvalidUrl,
            "the mailbox this url names is longer than the ",
            target.max_mailbox_bytes,
            " bytes zurl reads",
        ),
        error.UnknownParameter => fail(d, error.InvalidUrl, &.{
            "this url names a parameter zurl does not read, and zurl will not answer a url it read only part of: it reads ;UID= and ;MAILINDEX= and no other",
        }),
        error.InvalidMessageNumber => fail(d, error.InvalidUrl, &.{
            "the message this url names is not a number, and RFC 3501 makes both a UID and a mail index a number",
        }),
    };
}

/// Writes `parts`, one after another, into `d`'s own message storage,
/// records `err` with that message, and returns `err`.
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

/// The word a status carries, for a message to a user.
fn statusName(s: response.Status) []const u8 {
    return switch (s) {
        .ok => "OK",
        .no => "NO",
        .bad => "BAD",
        .preauth => "PREAUTH",
        .bye => "BYE",
    };
}

/// `fail`, with the server's own answer on the end of the sentence.
///
/// **The answer text is the server's and it goes to a user's terminal**,
/// so only the first two hundred bytes reach the message.
fn failStatus(d: ?*Diagnostics, err: Error, sentence: []const u8, out: Control.Outcome) Error {
    const shown = out.text[0..@min(out.text.len, 200)];
    return fail(d, err, &.{ sentence, ": ", statusName(out.status), " ", shown });
}

/// `failStatus`, with the credential source named instead of a fixed
/// sentence tail.
fn failCredential(
    d: ?*Diagnostics,
    err: Error,
    source: CredentialSource,
    sentence: []const u8,
    out: ?Control.Outcome,
) Error {
    const answer = out orelse return fail(d, err, &.{ sentence, source.describe() });
    const shown = answer.text[0..@min(answer.text.len, 200)];
    return fail(d, err, &.{ sentence, source.describe(), ": ", statusName(answer.status), " ", shown });
}

/// `failCredential` for an answer that is a line and not an `Outcome`.
///
/// A SASL exchange ends at a tagged line that `Control.readAuthLine` hands
/// back whole, and there is no body to name beside it.
fn failCredentialText(
    d: ?*Diagnostics,
    err: Error,
    source: CredentialSource,
    sentence: []const u8,
    text: []const u8,
) Error {
    const shown = text[0..@min(text.len, 200)];
    return fail(d, err, &.{ sentence, source.describe(), ": ", shown });
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
        " bytes one imap command line carries",
    );
}

/// Returns the dispatch entry for the plain `imap` scheme.
///
/// `Front` is the front package's own namespace, taken as a comptime
/// parameter. Passing the namespace rather than importing it is what keeps
/// this package free of a `zurl` import.
///
/// **`f` must outlive every transfer the client runs on either scheme**,
/// and must not move.
pub fn protocol(f: *Fetcher, comptime Front: type) Front.protocol.Protocol {
    return .{
        .scheme = scheme,
        .default_port = default_port,
        .ptr = f,
        .vtable = &Dispatch(Front).vtable,
        // This package dials the origin itself and reads no proxy field,
        // so a transfer that named a proxy is refused by name rather than
        // run direct. curl carries imap through a proxy and this build
        // does not. See `Front.protocol.Unread`.
        .unread = .{ .proxy = true },
    };
}

/// Returns the dispatch entry for the `imaps` scheme. See `protocol`.
pub fn secureProtocol(f: *Fetcher, comptime Front: type) Front.protocol.Protocol {
    return .{
        .scheme = secure_scheme,
        .default_port = secure_default_port,
        .ptr = f,
        .vtable = &Dispatch(Front).vtable,
        // This package dials the origin itself and reads no proxy field,
        // so a transfer that named a proxy is refused by name rather than
        // run direct. curl carries imap through a proxy and this build
        // does not. See `Front.protocol.Unread`.
        .unread = .{ .proxy = true },
    };
}

/// The vtable for one front package.
fn Dispatch(comptime Front: type) type {
    return struct {
        const vtable: Front.protocol.Protocol.VTable = .{ .perform = performImap };

        fn performImap(
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
        /// **`--speed-time` narrows the wait the same way.**
        ///
        /// **The scheme decides the TLS mode.** `imaps://` is implicit,
        /// and `imap://` with `--ssl-reqd` is an explicit `STARTTLS`.
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
/// thing: `protocol` needs the shape and never the package.
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
fn parseImapUrl(text: []const u8) !zurl_core.Url {
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
    try testing.expectEqualStrings("imap", scheme);
    try testing.expectEqualStrings("imaps", secure_scheme);
    try testing.expectEqual(@as(?u16, 143), default_port);
    try testing.expectEqual(@as(?u16, 993), secure_default_port);
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
    try testing.expect(isSecure(try parseImapUrl("imaps://h/INBOX")));
    try testing.expect(isSecure(try parseImapUrl("IMAPS://h/INBOX")));
    try testing.expect(!isSecure(try parseImapUrl("imap://h/INBOX")));
    try testing.expect(!isSecure(try parseImapUrl("imap://h:993/INBOX")));
}

/// How long a test lets a dial or a handshake take.
const test_connect_timeout: Io.Timeout = .{
    .duration = .{ .raw = .fromSeconds(10), .clock = .awake },
};

/// Runs a whole transfer against the fixture and returns the body.
fn fetch(
    f: *Fetcher,
    server: *test_server.Server,
    path: []const u8,
    options: Options,
    d: ?*Diagnostics,
) !Body {
    var url_buffer: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "imap://127.0.0.1:{d}{s}", .{ server.port(), path });
    var bounded_options = options;
    if (bounded_options.connect_timeout == .none) {
        bounded_options.connect_timeout = test_connect_timeout;
    }
    return f.open(try parseImapUrl(text), bounded_options, d);
}

fn drain(body: Body) ![]u8 {
    return body.reader.allocRemaining(testing.allocator, .unlimited);
}

const test_credentials: Credentials = .{ .user = "alice", .password = "s3cret" };

test "a UID fetch sends the commands curl sends, in curl's order" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/INBOX;UID=1", .{ .credentials = test_credentials }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);
    // **Only the octets of the literal reach the caller**, which is byte
    // for byte what curl writes out.
    try testing.expectEqualStrings("Subject: hi\r\n\r\nbody\r\n", contents);
    try testing.expect(!body.listing);

    server.wait();
    // Measured from curl 8.21.0. curl also sends `CAPABILITY` first, which
    // moves every tag on by one: see `open`.
    try testing.expectEqualStrings(
        "A001 LOGIN alice s3cret\n" ++
            "A002 SELECT INBOX\n" ++
            "A003 UID FETCH 1 BODY[]\n" ++
            "A004 LOGOUT",
        server.commands(),
    );
    try testing.expectEqual(@as(usize, 1), server.connections());
}

test "a mail index fetch sends FETCH and never UID FETCH" {
    // **The two are different numbers.** A UID belongs to the message for
    // as long as the mailbox lives, and a mail index changes when another
    // message is deleted.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/INBOX;MAILINDEX=2", .{ .credentials = test_credentials }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);

    server.wait();
    try testing.expectEqualStrings(
        "A001 LOGIN alice s3cret\nA002 SELECT INBOX\nA003 FETCH 2 BODY[]\nA004 LOGOUT",
        server.commands(),
    );
}

test "a url with no mailbox lists every mailbox" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/", .{ .credentials = test_credentials }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings(
        "* LIST (\\HasNoChildren) \"/\" INBOX\r\n* LIST (\\HasNoChildren) \"/\" Sent\r\n",
        contents,
    );
    try testing.expect(body.listing);

    server.wait();
    try testing.expectEqualStrings(
        "A001 LOGIN alice s3cret\nA002 LIST \"\" *\nA003 LOGOUT",
        server.commands(),
    );
}

test "a url with a mailbox and no message lists under that mailbox" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/INBOX", .{ .credentials = test_credentials }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);

    server.wait();
    try testing.expectEqualStrings(
        "A001 LOGIN alice s3cret\nA002 LIST INBOX *\nA003 LOGOUT",
        server.commands(),
    );
}

test "a mailbox name that is not an atom reaches the wire quoted" {
    // Measured against curl 8.21.0: `imap://h/My%20Box;UID=1` reaches the
    // wire as `SELECT "My Box"`.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/My%20Box;UID=1", .{ .credentials = test_credentials }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);

    server.wait();
    try testing.expectEqualStrings(
        "A001 LOGIN alice s3cret\n" ++
            "A002 SELECT \"My Box\"\n" ++
            "A003 UID FETCH 1 BODY[]\n" ++
            "A004 LOGOUT",
        server.commands(),
    );
}

test "a quote in a mailbox name cannot close its own argument" {
    // **The second injection gate.** Without the escape the wire would
    // read `SELECT "My" INBOX"`, and the server would take `INBOX` as an
    // argument the url never named. Measured: curl escapes it the same
    // way.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/My%22%20INBOX;UID=1", .{
        .credentials = test_credentials,
    }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);

    server.wait();
    try testing.expectEqualStrings(
        "A001 LOGIN alice s3cret\n" ++
            "A002 SELECT \"My\\\" INBOX\"\n" ++
            "A003 UID FETCH 1 BODY[]\n" ++
            "A004 LOGOUT",
        server.commands(),
    );
}

test "a credential goes through the same quoting gate a mailbox does" {
    // **The gate that ran on one argument and not on its siblings.** A
    // mailbox name went through `command.quote` and the two `LOGIN`
    // arguments did not, although all three sit on a command line under
    // the same RFC 3501 grammar.
    //
    // A password holding `{5+}` is the reason this matters: against a
    // LITERAL+ server, RFC 7888, the five octets after that line are
    // literal data, and those five octets are this client's own `A002 `.
    // The rest of the next command is then read as more `LOGIN`
    // arguments, and the session desyncs until the stall bound. A password
    // holding a plain space simply sent the wrong secret.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/INBOX;UID=1", .{
        .credentials = .{ .user = "alice smith", .password = "pw {5+}" },
    }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);

    server.wait();
    try testing.expectEqualStrings(
        "A001 LOGIN \"alice smith\" \"pw {5+}\"\n" ++
            "A002 SELECT INBOX\n" ++
            "A003 UID FETCH 1 BODY[]\n" ++
            "A004 LOGOUT",
        server.commands(),
    );
}

test "a quote in a credential cannot close its own argument" {
    // The sibling of the mailbox rule above, and the same escape.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/INBOX;UID=1", .{
        .credentials = .{ .user = "alice", .password = "a\" LOGOUT" },
    }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);

    server.wait();
    try testing.expectEqualStrings(
        "A001 LOGIN alice \"a\\\" LOGOUT\"\n" ++
            "A002 SELECT INBOX\n" ++
            "A003 UID FETCH 1 BODY[]\n" ++
            "A004 LOGOUT",
        server.commands(),
    );
}

test "a url with no credential logs in not at all, the way curl does" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/", .{}, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);

    server.wait();
    try testing.expectEqualStrings("A001 LIST \"\" *\nA002 LOGOUT", server.commands());
}

test "a --request command replaces the one the url implies, after the SELECT" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/INBOX", .{
        .credentials = test_credentials,
        .custom_request = "FETCH 1 BODY[HEADER]",
    }, null);
    const contents = try drain(body);
    defer testing.allocator.free(contents);
    try testing.expect(!body.listing);

    server.wait();
    // Measured: curl sends the `SELECT` and then the command as written.
    try testing.expectEqualStrings(
        "A001 LOGIN alice s3cret\n" ++
            "A002 SELECT INBOX\n" ++
            "A003 FETCH 1 BODY[HEADER]\n" ++
            "A004 LOGOUT",
        server.commands(),
    );
}

test "a mailbox that could forge a command is refused, and no socket opens" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const forged = [_][]const u8{
        "/IN%0d%0aA002%20LOGOUT",
        "/IN%0aA002%20LOGOUT",
        "/IN%0dA002%20LOGOUT",
        "/IN%00BOX",
        "/%0d%0a;UID=1",
        "/IN%09BOX;UID=1",
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

test "a message number that could forge a command is refused, and no socket opens" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    for ([_][]const u8{
        "/INBOX;UID=1%0d%0aA003%20LOGOUT",
        "/INBOX;MAILINDEX=1%0aA003%20LOGOUT",
    }) |path| {
        var d: Diagnostics = .{};
        try testing.expectError(
            error.InvalidUrl,
            fetch(&f, &server, path, .{ .credentials = test_credentials }, &d),
        );
    }
    // A number that is not digits never reaches a command line at all.
    for ([_][]const u8{ "/INBOX;UID=1%20LOGOUT", "/INBOX;UID=abc" }) |path| {
        var d: Diagnostics = .{};
        try testing.expectError(
            error.InvalidUrl,
            fetch(&f, &server, path, .{ .credentials = test_credentials }, &d),
        );
        try testing.expect(std.mem.indexOf(u8, d.message.?, "not a number") != null);
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
        .{ .user = "al\r\nA002 LOGOUT", .password = "pw" },
        .{ .user = "al\nA002 LOGOUT", .password = "pw" },
        .{ .user = "al\rice", .password = "pw" },
        .{ .user = "al\x00ice", .password = "pw" },
        .{ .user = "alice", .password = "pw\r\nA002 DELETE INBOX" },
        .{ .user = "alice", .password = "pw\nA002 LOGOUT" },
        .{ .user = "alice", .password = "pw\rx" },
        .{ .user = "alice", .password = "pw\x00" },
    };
    for (forged) |credential| {
        var d: Diagnostics = .{};
        try testing.expectError(
            error.InvalidUrl,
            fetch(&f, &server, "/INBOX;UID=1", .{ .credentials = credential }, &d),
        );
        try testing.expect(std.mem.indexOf(u8, d.message.?, "the -u option") != null);
    }
    try testing.expectEqual(@as(usize, 0), server.connections());
}

test "the exit code of a refusal is curl's own, for each of the four commands" {
    // Measured against curl 8.21.0 on a loopback fixture, one command
    // refused at a time.
    const rows = [_]struct {
        script: test_server.Script,
        path: []const u8,
        err: Error,
    }{
        .{ .script = .{ .login = "NO wrong password" }, .path = "/INBOX;UID=1", .err = error.LoginDenied },
        .{ .script = .{ .select = "NO no such mailbox" }, .path = "/INBOX;UID=1", .err = error.LoginDenied },
        .{ .script = .{ .fetch = "NO no such message" }, .path = "/INBOX;UID=1", .err = error.RemoteFileNotFound },
        .{ .script = .{ .list = "NO cannot list" }, .path = "/", .err = error.QuoteError },
    };
    for (rows) |row| {
        var server: test_server.Server = undefined;
        try server.start(row.script);
        defer server.stop();

        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();

        var d: Diagnostics = .{};
        try testing.expectError(
            row.err,
            fetch(&f, &server, row.path, .{ .credentials = test_credentials }, &d),
        );
    }
}

test "a BAD to a --request command is curl's exit 21" {
    var server: test_server.Server = undefined;
    try server.start(.{ .unknown = "BAD unknown command" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(error.QuoteError, fetch(&f, &server, "/INBOX", .{
        .credentials = test_credentials,
        .custom_request = "FROBNICATE 1",
    }, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "unknown command") != null);
}

test "a greeting that is not an untagged status ends the transfer at once" {
    var server: test_server.Server = undefined;
    try server.start(.{ .greeting = "220 not an imap server" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(
        error.WeirdServerReply,
        fetch(&f, &server, "/INBOX;UID=1", .{ .credentials = test_credentials }, &d),
    );
}

test "a greeting of BYE ends the transfer and sends no credential" {
    var server: test_server.Server = undefined;
    try server.start(.{ .greeting = "* BYE this server is full" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(
        error.WeirdServerReply,
        fetch(&f, &server, "/INBOX;UID=1", .{ .credentials = test_credentials }, &d),
    );
    server.wait();
    try testing.expectEqualStrings("", server.commands());
}

test "a peer that greets and says nothing more ends the transfer at the bound" {
    var server: test_server.Server = undefined;
    try server.startSilent();
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    const short: Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(300), .clock = .awake } };
    try testing.expectError(error.OperationTimedOut, fetch(&f, &server, "/INBOX;UID=1", .{
        .credentials = test_credentials,
        .read_timeout = short,
    }, &d));
}

test "a message larger than the bound ends the transfer" {
    var server: test_server.Server = undefined;
    try server.start(.{ .body = "0123456789abcdefghij" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(error.FileSizeExceeded, fetch(&f, &server, "/INBOX;UID=1", .{
        .credentials = test_credentials,
        .max_response_bytes = 8,
    }, &d));
}

test "a refused STARTTLS sends no credential at all" {
    // **The rule this test exists for.** A transfer that asked for TLS and
    // carried on without it would send the password in the clear. curl
    // answers the same shape with exit 64 and sends no `LOGIN`, measured.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(error.UseSslFailed, fetch(&f, &server, "/INBOX;UID=1", .{
        .credentials = test_credentials,
        .tls = .explicit,
        .insecure = true,
    }, &d));

    server.wait();
    try testing.expectEqualStrings("A001 STARTTLS", server.commands());
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, server.commands(), "s3cret"),
    );
}

test "a server that writes behind its STARTTLS answer does not get those bytes trusted" {
    var server: test_server.Server = undefined;
    try server.start(.{
        .starttls = "OK begin TLS negotiation",
        .starttls_trailer = "A002 OK logged in\r\n",
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(error.UseSslFailed, fetch(&f, &server, "/INBOX;UID=1", .{
        .credentials = test_credentials,
        .tls = .explicit,
        .insecure = true,
    }, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "behind its STARTTLS answer") != null);
}

test "a STARTTLS the peer accepts and then speaks no TLS ends at the connect bound" {
    var server: test_server.Server = undefined;
    try server.start(.{ .starttls = "OK begin TLS negotiation" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    const short: Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(500), .clock = .awake } };
    try testing.expectError(error.OperationTimedOut, fetch(&f, &server, "/INBOX;UID=1", .{
        .credentials = test_credentials,
        .tls = .explicit,
        .insecure = true,
        .connect_timeout = short,
    }, &d));

    server.wait();
    try testing.expectEqualStrings("A001 STARTTLS", server.commands());
}

test "a build with no trust store cannot open an encrypted session" {
    var d: Diagnostics = .{};
    for ([_]TlsMode{ .implicit, .explicit }) |mode| {
        try testing.expectError(error.SslConnectError, tlsOptions("mail.example.com", .{
            .tls = mode,
            .trust = null,
        }, &d));
    }
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
    var client: StubFront.Client = .{};
    const trust = client.tlsMaterials();

    const moved = [_]Options{
        .{ .tls = .implicit, .trust = trust, .tcp_no_delay = false },
        .{ .tls = .implicit, .trust = trust, .max_response_bytes = 1 },
        .{ .tls = .implicit, .trust = trust, .tls_min_version = .tls_1_3 },
        .{ .tls = .implicit, .trust = trust, .tls_max_version = .tls_1_2 },
        .{ .tls = .implicit, .trust = trust, .credentials = test_credentials },
        .{ .tls = .implicit, .trust = trust, .netrc_text = "machine h login a password b" },
        .{ .tls = .implicit, .trust = trust, .custom_request = "NOOP" },
        .{ .tls = .explicit, .trust = trust },
        // A moved dial is one more input that must not reach the check.
        // `open` hands this function `url.host`, so the name an `imaps`
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

/// A greeting whose capability list names `mechanisms`.
fn greetingOffering(comptime mechanisms: []const u8) []const u8 {
    return "* OK [CAPABILITY IMAP4rev1 " ++ mechanisms ++ "] fixture ready";
}

/// The base64 of `text`, for a test that names a challenge as it travels.
fn encode(out: []u8, text: []const u8) []const u8 {
    const encoder = std.base64.standard.Encoder;
    return encoder.encode(out[0..encoder.calcSize(text.len)], text);
}

test "a PLAIN login reaches the server with the bytes curl sends" {
    // **Measured from curl 8.21.0** on a loopback IMAP fixture whose
    // capability list names `AUTH=PLAIN`: `AUTHENTICATE PLAIN`, then
    // `AGFsaWNlAHMzY3JldA==` on its own line.
    var server: test_server.Server = undefined;
    try server.start(.{ .greeting = greetingOffering("AUTH=PLAIN") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/INBOX;UID=1", .{
        .credentials = test_credentials,
    }, null);
    const text = try drain(body);
    defer testing.allocator.free(text);

    server.wait();
    // **No `CAPABILITY` command.** The greeting already named the list,
    // which is one round trip curl always spends and zurl does not.
    try testing.expectEqualStrings(
        "A001 AUTHENTICATE PLAIN\n" ++
            "AGFsaWNlAHMzY3JldA==\n" ++
            "A002 SELECT INBOX\n" ++
            "A003 UID FETCH 1 BODY[]\n" ++
            "A004 LOGOUT",
        server.commands(),
    );
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, server.commands(), "s3cret"),
    );
}

test "a greeting that names no capability draws one CAPABILITY command" {
    // **One round trip, and only when the greeting named nothing.** RFC
    // 3501 section 7.1 lets a server leave the response code out, and a
    // client that then guessed would either send a cleartext `LOGIN` to a
    // server that refuses it or send nothing at all.
    var server: test_server.Server = undefined;
    try server.start(.{
        .greeting = "* OK fixture ready",
        .capability_untagged = &.{"* CAPABILITY IMAP4rev1 AUTH=PLAIN"},
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/INBOX;UID=1", .{
        .credentials = test_credentials,
    }, null);
    const text = try drain(body);
    defer testing.allocator.free(text);

    server.wait();
    try testing.expectEqualStrings(
        "A001 CAPABILITY\n" ++
            "A002 AUTHENTICATE PLAIN\n" ++
            "AGFsaWNlAHMzY3JldA==\n" ++
            "A003 SELECT INBOX\n" ++
            "A004 UID FETCH 1 BODY[]\n" ++
            "A005 LOGOUT",
        server.commands(),
    );
}

test "a server that offers no mechanism this build speaks falls back to LOGIN" {
    // curl falls back the same way, measured against a fixture whose
    // capability list names no `AUTH=`. This is the path every IMAP test
    // written before SASL takes, which is why none of them changed.
    var server: test_server.Server = undefined;
    try server.start(.{ .greeting = greetingOffering("AUTH=GSSAPI IDLE") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/INBOX;UID=1", .{
        .credentials = test_credentials,
    }, null);
    const text = try drain(body);
    defer testing.allocator.free(text);

    server.wait();
    try testing.expectEqualStrings(
        "A001 LOGIN alice s3cret\n" ++
            "A002 SELECT INBOX\n" ++
            "A003 UID FETCH 1 BODY[]\n" ++
            "A004 LOGOUT",
        server.commands(),
    );
}

test "a server naming LOGINDISABLED and no usable mechanism sends no LOGIN at all" {
    // **Where zurl and curl part.** RFC 3501 section 6.2.3 lets a server
    // say the cleartext `LOGIN` will be refused whatever credential it
    // carries. curl sends one anyway, which puts the password on the wire
    // for a command the server already said no to.
    var server: test_server.Server = undefined;
    try server.start(.{ .greeting = greetingOffering("LOGINDISABLED AUTH=GSSAPI") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(error.LoginDenied, fetch(&f, &server, "/INBOX;UID=1", .{
        .credentials = test_credentials,
    }, &d));
    try testing.expectEqual(@as(u8, 67), d.curl_code);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "LOGINDISABLED") != null);
    try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, d.message.?, "s3cret"));

    server.wait();
    // Nothing at all reached the server.
    try testing.expectEqualStrings("", server.commands());
}

test "the strongest mechanism the server offers is the one used" {
    var challenge_storage: [64]u8 = undefined;
    const challenge = encode(&challenge_storage, "<1896.697170952@fixture>");

    var server: test_server.Server = undefined;
    try server.start(.{
        .greeting = greetingOffering("AUTH=PLAIN AUTH=LOGIN AUTH=CRAM-MD5"),
        .auth_challenges = &.{challenge},
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/INBOX;UID=1", .{
        .credentials = test_credentials,
    }, null);
    const text = try drain(body);
    defer testing.allocator.free(text);

    server.wait();
    // Measured: curl picked `CRAM-MD5` off this list and wrote exactly
    // this response for this challenge and this credential.
    try testing.expectEqualStrings(
        "A001 AUTHENTICATE CRAM-MD5\n" ++
            "YWxpY2UgMDJmZmVhNTc2NDEyYWNiYzUyNWU0ZDgyNTE0NmY5ZmM=\n" ++
            "A002 SELECT INBOX\n" ++
            "A003 UID FETCH 1 BODY[]\n" ++
            "A004 LOGOUT",
        server.commands(),
    );
}

test "--sasl-ir puts the first message on the AUTHENTICATE line" {
    var server: test_server.Server = undefined;
    try server.start(.{ .greeting = greetingOffering("AUTH=PLAIN") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/INBOX;UID=1", .{
        .credentials = test_credentials,
        .sasl_ir = true,
    }, null);
    const text = try drain(body);
    defer testing.allocator.free(text);

    server.wait();
    // Measured from curl 8.21.0 with `--sasl-ir` on the same fixture.
    try testing.expectEqualStrings(
        "A001 AUTHENTICATE PLAIN AGFsaWNlAHMzY3JldA==\n" ++
            "A002 SELECT INBOX\n" ++
            "A003 UID FETCH 1 BODY[]\n" ++
            "A004 LOGOUT",
        server.commands(),
    );
}

test "--sasl-authzid names the identity to act as" {
    var server: test_server.Server = undefined;
    try server.start(.{ .greeting = greetingOffering("AUTH=PLAIN") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/INBOX;UID=1", .{
        .credentials = test_credentials,
        .sasl_authzid = "admin",
    }, null);
    const text = try drain(body);
    defer testing.allocator.free(text);

    server.wait();
    try testing.expectEqualStrings(
        "A001 AUTHENTICATE PLAIN\n" ++
            "YWRtaW4AYWxpY2UAczNjcmV0\n" ++
            "A002 SELECT INBOX\n" ++
            "A003 UID FETCH 1 BODY[]\n" ++
            "A004 LOGOUT",
        server.commands(),
    );
}

test "--login-options names one mechanism, and a bad one ends the transfer" {
    var server: test_server.Server = undefined;
    try server.start(.{ .greeting = greetingOffering("AUTH=PLAIN AUTH=LOGIN AUTH=CRAM-MD5") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/INBOX;UID=1", .{
        .credentials = test_credentials,
        .login_options = "AUTH=PLAIN",
    }, null);
    const text = try drain(body);
    defer testing.allocator.free(text);

    server.wait();
    // The same offer with no option draws `CRAM-MD5`, as the test above
    // shows.
    try testing.expectEqualStrings(
        "A001 AUTHENTICATE PLAIN\n" ++
            "AGFsaWNlAHMzY3JldA==\n" ++
            "A002 SELECT INBOX\n" ++
            "A003 UID FETCH 1 BODY[]\n" ++
            "A004 LOGOUT",
        server.commands(),
    );

    // A mechanism the server did not offer is exit 67 with no command
    // sent, which is curl's own answer, measured.
    var second: test_server.Server = undefined;
    try second.start(.{ .greeting = greetingOffering("AUTH=PLAIN") });
    defer second.stop();
    var g: Fetcher = .init(testing.allocator, testing.io);
    defer g.deinit();
    var d: Diagnostics = .{};
    try testing.expectError(error.LoginDenied, fetch(&g, &second, "/INBOX;UID=1", .{
        .credentials = test_credentials,
        .login_options = "AUTH=CRAM-MD5",
    }, &d));
    try testing.expectEqual(@as(u8, 67), d.curl_code);
    second.wait();
    try testing.expectEqualStrings("", second.commands());
}

test "a refused SASL exchange never falls back to a cleartext LOGIN" {
    // **A downgrade a server could ask for.** A client that answered a
    // `NO` by sending `LOGIN` would hand the password in the clear to any
    // server, or anybody on the path, that refused the stronger
    // mechanism.
    var server: test_server.Server = undefined;
    try server.start(.{
        .greeting = greetingOffering("AUTH=PLAIN"),
        .authenticate = "NO authentication failed",
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(error.LoginDenied, fetch(&f, &server, "/INBOX;UID=1", .{
        .credentials = test_credentials,
    }, &d));
    try testing.expectEqual(@as(u8, 67), d.curl_code);
    try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, d.message.?, "s3cret"));

    server.wait();
    // No `LOGIN`, and no `SELECT`. The transfer ended at the refusal.
    try testing.expectEqualStrings(
        "A001 AUTHENTICATE PLAIN\nAGFsaWNlAHMzY3JldA==",
        server.commands(),
    );
}

test "a challenge that is not base64 cancels the exchange with an asterisk" {
    var server: test_server.Server = undefined;
    try server.start(.{
        .greeting = greetingOffering("AUTH=CRAM-MD5"),
        .auth_challenges = &.{"not base64!"},
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(error.WeirdServerReply, fetch(&f, &server, "/INBOX;UID=1", .{
        .credentials = test_credentials,
    }, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "base64") != null);

    server.wait();
    // **The exchange was cancelled.** A server left waiting for a
    // response would read the next command as one.
    try testing.expectEqualStrings("A001 AUTHENTICATE CRAM-MD5\n*", server.commands());
}

test "--oauth2-bearer picks OAUTHBEARER, which names the host and the port" {
    var server: test_server.Server = undefined;
    try server.start(.{ .greeting = greetingOffering("AUTH=PLAIN AUTH=XOAUTH2 AUTH=OAUTHBEARER") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/INBOX;UID=1", .{
        .credentials = .{ .user = "alice", .password = "" },
        .bearer_token = "tok123",
    }, null);
    const text = try drain(body);
    defer testing.allocator.free(text);

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
        "A001 AUTHENTICATE OAUTHBEARER\n{s}\n" ++
            "A002 SELECT INBOX\nA003 UID FETCH 1 BODY[]\nA004 LOGOUT",
        .{encode(&encoded_storage, raw)},
    );
    try testing.expectEqualStrings(want, server.commands());
}

test "a credential that could forge a SASL field is refused, and no socket opens" {
    // **The NUL rule, proved through a whole transfer.** A NUL in the
    // password moves the `PLAIN` separator, and base64 hides it from
    // `zurl_net.line.write`.
    const forged = [_][]const u8{ "s3cret\x00admin", "\x00", "s3cret\r\nA002 LOGOUT", "s3cret\n" };
    for (forged) |text| {
        var server: test_server.Server = undefined;
        try server.start(.{ .greeting = greetingOffering("AUTH=PLAIN") });
        defer server.stop();

        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();

        var d: Diagnostics = .{};
        try testing.expectError(error.InvalidUrl, fetch(&f, &server, "/INBOX;UID=1", .{
            .credentials = .{ .user = "alice", .password = text },
        }, &d));
        try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, d.message.?, "s3cret"));
        try testing.expectEqual(@as(usize, 0), server.connections());
    }
}

test "an authzid that could forge a field is refused before the AUTHENTICATE" {
    var server: test_server.Server = undefined;
    try server.start(.{ .greeting = greetingOffering("AUTH=PLAIN") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    try testing.expectError(error.InvalidUrl, fetch(&f, &server, "/INBOX;UID=1", .{
        .credentials = test_credentials,
        .sasl_authzid = "admin\x00root",
    }, null));

    server.wait();
    // The command never went out, so no field of it reached the server.
    try testing.expectEqualStrings("", server.commands());
}

test "every buffer a credential passed through is zeroed when the transfer ends" {
    var server: test_server.Server = undefined;
    try server.start(.{ .greeting = greetingOffering("AUTH=PLAIN") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var url_buffer: [512]u8 = undefined;
    const url = try std.fmt.bufPrint(
        &url_buffer,
        "imap://alice:s3cret@127.0.0.1:{d}/INBOX;UID=1",
        .{server.port()},
    );
    const body = try f.open(try parseImapUrl(url), .{
        .connect_timeout = test_connect_timeout,
    }, null);
    const text = try drain(body);
    defer testing.allocator.free(text);

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
    // The `LOGIN` fallback writes the password into this one, so it is
    // wiped whether SASL ran or not.
    for (f.quoted_storage) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "the cleartext LOGIN path wipes its password buffer too" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/INBOX;UID=1", .{
        .credentials = test_credentials,
    }, null);
    const text = try drain(body);
    defer testing.allocator.free(text);

    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, &f.quoted_storage, "s3cret"),
    );
    for (f.quoted_storage) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "a capability list is read only from a whole CAPABILITY word" {
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    f.capability_len = 0;
    f.keepCapabilities("[CAPABILITY IMAP4rev1 AUTH=PLAIN] ready");
    try testing.expectEqualStrings(" IMAP4rev1 AUTH=PLAIN", f.capabilities());

    // **A code that is not `CAPABILITY` names nothing.** `[ALERT]` and
    // `[UIDVALIDITY 1]` are ordinary response codes, and a reader that
    // took either would look for mechanisms in the wrong text.
    f.capability_len = 0;
    f.keepCapabilities("[ALERT] the mailbox is nearly full");
    try testing.expectEqualStrings("", f.capabilities());

    f.capability_len = 0;
    f.keepCapabilities("[CAPABILITYX AUTH=PLAIN] ready");
    try testing.expectEqualStrings("", f.capabilities());

    f.capability_len = 0;
    f.keepCapabilities("fixture ready");
    try testing.expectEqualStrings("", f.capabilities());

    // The word is read without regard to case, which RFC 3501 allows.
    f.capability_len = 0;
    f.keepCapabilities("[capability IMAP4rev1] ready");
    try testing.expectEqualStrings(" IMAP4rev1", f.capabilities());
}

test "--connect-to moves an imap dial and --resolve reaches this package too" {
    // The defect this closes: this package read no `connect_to`, so a
    // user who named either flag got a dial to the url's own host and no
    // diagnostic. curl 8.21.0 applies both to `imap` and `imaps`,
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
    const url = try parseImapUrl("imap://127.0.0.2:1/INBOX;UID=1");

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

test "the imap translation carries --connect-to into this package" {
    var client: StubFront.Client = .{};
    const D = Dispatch(StubFront);
    const url = try parseImapUrl("imap://example.com/INBOX;UID=1");

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
