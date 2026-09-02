//! Runs one `smtp://` or `smtps://` transfer: the greeting, the `EHLO`,
//! the envelope, and the message.
//!
//! **This is the one protocol package that sends rather than fetches.**
//! Everything else in this repository asks a server for bytes. This one
//! hands a server a message and reads back whether it took it, so the body
//! of the transfer is the empty answer and the interesting part is the
//! `DATA` phase.
//!
//! **A `Fetcher` must not move once `open` has run.** The body reader it
//! hands back points into this value, and so do the dialogue's own reader
//! and writer.
//!
//! **What a transfer sends.** The command order is curl's own, measured
//! against curl 8.21.0 on a loopback RFC 5321 fixture:
//!
//!     [STARTTLS,] EHLO name, MAIL FROM:<sender>, one RCPT TO:<...> for
//!     each recipient, DATA, the message, then QUIT
//!
//! with `HELO name` in place of `EHLO name` when the server does not know
//! the newer command. The name comes from the url path, and `localhost`
//! when the url names none.
//!
//! **The two rules that keep this safe**, each with its own section in the
//! file that holds it:
//!
//! - **No command can carry a forged line ending.** Every command goes out
//!   through `Control.send`. An address is checked a second time, earlier,
//!   so the message names the flag and not the command. curl 8.21.0 does
//!   **not** keep this rule: measured, a CR and an LF inside `--mail-rcpt`
//!   put a second recipient on the wire.
//! - **The message is dot-stuffed.** A body line of one period would end
//!   the `DATA` phase, and every byte after it would be read as an SMTP
//!   command. See `message`.
//!
//! **This package sends no credential.** It has no `AUTH` command at all,
//! so a transfer that named one with `-u` or with a url userinfo is
//! refused by name, `error.NotBuiltIn`, exit 4. It is not run
//! unauthenticated: a message sent with no credential after the user asked
//! for one is a control that failed open, and the server's own `530` sends
//! the user to look at the server. The refusal is declared in `protocol`
//! and raised by the front package. See `Front.protocol.Unread`.
//!
//! **This package carries no proxy either**, for the same reason and with
//! the same answer.
//!
//! This file imports `zurl-core` and `zurl-net`. It does not import
//! `zurl`, and it never will. See `protocol`.

const Fetcher = @This();

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_net = @import("zurl-net");

const command = @import("command.zig");
const message = @import("message.zig");
const Control = @import("Control.zig");

const Io = std.Io;
const Error = zurl_core.Error;
const Diagnostics = zurl_core.Diagnostics;

/// The plain scheme this package handles.
pub const scheme = "smtp";

/// The encrypted scheme this package handles.
pub const secure_scheme = "smtps";

/// The port an `smtp://` url uses when it names none. RFC 5321.
pub const default_port: ?u16 = 25;

/// The port an `smtps://` url uses when it names none.
///
/// 465, the implicit TLS port. `zurl_core.url.defaultPort` already held
/// the same number.
pub const secure_default_port: ?u16 = 465;

/// The status an SMTP transfer reports.
///
/// Zero. RFC 5321 has reply codes and no HTTP status.
pub const status: u16 = 0;

/// How many bytes of message this sends.
///
/// **A message goes out whole or not at all**, so it is read into memory
/// first: the dot-stuffing rule works line by line and a sender that
/// streamed the body would have to hold a partial line anyway. 16 MiB, the
/// number every other protocol package here keeps for its own answer.
/// `Options.max_message_bytes` narrows or raises it.
pub const default_max_message_bytes: u64 = 16 * 1024 * 1024;

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

/// How many bytes of an address this sends.
///
/// RFC 5321 section 4.5.3.1.3 sets the reverse path at 256 octets. This is
/// larger, because a server may take more, and it is a bound because the
/// address goes into one command line.
pub const max_address_bytes: usize = 512;

/// How many bytes of an `EHLO` name this sends.
pub const max_name_bytes: usize = 256;

/// How many bytes of credential this decodes out of a url.
///
/// The same number `zurl-pop3` and `zurl-imap` keep, so one credential
/// reaches all three mail protocols or none of them. A user name and a
/// password each have to fit in one SASL message, and
/// `zurl_net.sasl.max_message_bytes` is the bound on that. This is the
/// smaller number, so a user meets it here with a sentence that names the
/// credential rather than the command.
pub const max_credential_bytes: usize = 512;

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
    /// Nobody named one, so the transfer authenticated not at all.
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

/// The `EHLO` name a url that names none carries.
///
/// RFC 5321 section 4.1.1.1 asks for the client's own fully qualified
/// domain name. This process does not know one it can trust: a host name
/// read from the operating system is often not a name the network can
/// resolve, and sending it tells every server on the path what this
/// machine is called. curl sends it anyway, measured. zurl sends
/// `localhost`, which is a legal domain and names nothing about the
/// machine, and the url path is how a caller names a real one.
pub const default_name = "localhost";

/// How the transfer puts TLS on the connection.
pub const TlsMode = enum {
    /// No TLS at all. This is a plain `smtp://` url.
    none,
    /// The handshake runs as soon as the socket opens, before the
    /// greeting. This is `smtps://`, on port 465.
    implicit,
    /// The greeting and the first `EHLO` arrive in the clear, then
    /// `STARTTLS`, then the handshake. RFC 3207. This is `--ssl-reqd` on
    /// an `smtp://` url.
    explicit,
};

/// The trust store an encrypted session verifies against.
///
/// **An `smtps` session verifies exactly as an `https` session does.** A
/// build that leaves this null cannot open an encrypted session at all.
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

/// Where the message comes from.
///
/// The shape matches `zurl_http.engine.Body` field for field, because
/// `src/cli/body.zig` fills one of those from `-T` and from the `-d`
/// family alike. It is written out here because this package must build
/// with no `zurl` and no `zurl-http` in its import table.
pub const Source = struct {
    /// How many bytes `read` produces in total, or null when the count is
    /// not known before the body goes out, which is what a pipe gives.
    len: ?u64,
    /// The state `read` acts on.
    ctx: *anyopaque,
    /// Fills up to `len` bytes of `buffer` and returns how many bytes it
    /// wrote. Zero says the body has ended, and a negative value says the
    /// source could not be read.
    read: *const fn (ctx: *anyopaque, buffer: [*]u8, len: usize) callconv(.c) isize,
};

/// What one transfer may ask for.
pub const Options = struct {
    /// A cap on the dial, the `STARTTLS` step, and the handshake together.
    connect_timeout: Io.Timeout = .none,
    /// The bound on the message. See `default_max_message_bytes`.
    max_message_bytes: u64 = default_max_message_bytes,
    /// How long one read may wait with no byte arriving.
    read_timeout: Io.Timeout = default_read_timeout,
    /// Whether to turn Nagle's algorithm off. False is `--no-tcp-nodelay`.
    tcp_no_delay: bool = true,
    /// Whether to accept a peer certificate that does not verify. This is
    /// `-k`/`--insecure`, and it reaches nothing but `sessionOptions`.
    insecure: bool = false,
    /// The lowest TLS version to keep.
    tls_min_version: zurl_core.tls.MinVersion = .floor,
    /// The highest TLS version to keep.
    tls_max_version: zurl_core.tls.Version = .highest,
    /// The trust store for an encrypted session. See `Trust`.
    trust: ?Trust = null,
    /// How the connection gets TLS. See `TlsMode`.
    tls: TlsMode = .none,
    /// The envelope sender, or null for the null reverse path `<>`, which
    /// is what curl sends for a transfer that names none, measured.
    mail_from: ?[]const u8 = null,
    /// The envelope recipients, in the order the `RCPT TO` commands go
    /// out. A transfer with none is refused.
    mail_rcpt: []const []const u8 = &.{},
    /// Where the message comes from. A transfer with none is refused.
    body: ?Source = null,
    /// The credential `-u` named, or null.
    credentials: ?Credentials = null,
    /// The text of a netrc file the caller already read, or null. This is
    /// `--netrc` and `--netrc-file`.
    netrc_text: ?[]const u8 = null,
    /// The token `--oauth2-bearer` named, or null.
    ///
    /// A bearer token and a password are different credentials, so a
    /// transfer that has one uses `XOAUTH2` or `OAUTHBEARER` and never
    /// `PLAIN`. See `zurl_net.sasl.choose`.
    bearer_token: ?[]const u8 = null,
    /// The identity `--sasl-authzid` named, or null. See
    /// `zurl_net.sasl.Fields.authzid`.
    sasl_authzid: ?[]const u8 = null,
    /// Whether to put the first SASL message on the `AUTH` line itself.
    /// This is `--sasl-ir`.
    sasl_ir: bool = false,
    /// The value `--login-options` named, or null. See
    /// `zurl_net.sasl.loginOptionMechanism`.
    login_options: ?[]const u8 = null,
    /// Where a url naming one host and port dials instead. This is
    /// `--resolve` and `--connect-to`.
    ///
    /// **An entry moves the dial and nothing else.** `tlsOptions` reads
    /// `url.host`, so an `smtps` peer at the dialed address must still
    /// hold a certificate for the name the url wrote. The `OAUTHBEARER`
    /// message names the url's host and port too, because it names the
    /// service the user asked for. See `zurl_net.override`.
    connect_to: []const zurl_net.override.HostOverride = &.{},
};

allocator: std.mem.Allocator,
io: Io,
/// The octets of the `DATA` phase, or null when none is held.
payload: ?[]u8,
/// The empty answer of a send. A transfer that sent a message has no body
/// to give back, and a caller still needs a reader.
body: Io.Reader,
/// The command and reply dialogue.
control: Control,
/// Holds the `EHLO` name, decoded out of the url path.
name_storage: [max_name_bytes]u8,
/// Holds the `SIZE=` parameter of a `MAIL FROM`.
size_storage: [24]u8,
/// Holds a credential decoded out of a url's userinfo, the user first and
/// the password after it.
///
/// **Wiped whichever way `open` leaves.** See `wipe`.
credential_storage: [max_credential_bytes * 2]u8,
/// Holds one encoded SASL message as it is built.
///
/// **Wiped whichever way `open` leaves**, because the encoded form of a
/// `PLAIN` message is the password with nothing but base64 over it.
sasl_storage: [zurl_net.sasl.max_message_bytes]u8,
/// Holds one decoded server challenge.
challenge_storage: [zurl_net.sasl.max_challenge_bytes]u8,
/// The plain stream a `STARTTLS` upgrade speaks over, before the
/// handshake.
upgrade_reader: std.Io.net.Stream.Reader,
upgrade_writer: std.Io.net.Stream.Writer,
upgrade_read_storage: [upgrade_buffer_len]u8,
upgrade_write_storage: [upgrade_buffer_len]u8,
/// What the `STARTTLS` step recorded. See `runUpgrade`.
upgrade_fault: ?UpgradeFault,
/// The `EHLO` name the upgrade step sends. A field because the step runs
/// inside the connect race and takes only the opaque pointer.
upgrade_name: []const u8,
/// How long one read may wait with no byte arriving.
stall: Io.Timeout,

/// Why the `STARTTLS` step stopped.
const UpgradeFault = struct {
    err: Error,
    message: []const u8,
};

/// A `Fetcher` that holds no message yet.
pub fn init(allocator: std.mem.Allocator, io: Io) Fetcher {
    return .{
        .allocator = allocator,
        .io = io,
        .payload = null,
        .body = undefined,
        .control = undefined,
        .name_storage = undefined,
        .size_storage = undefined,
        .credential_storage = undefined,
        .sasl_storage = undefined,
        .challenge_storage = undefined,
        .upgrade_reader = undefined,
        .upgrade_writer = undefined,
        .upgrade_read_storage = undefined,
        .upgrade_write_storage = undefined,
        .upgrade_fault = null,
        .upgrade_name = default_name,
        .stall = default_read_timeout,
    };
}

/// Frees the message this `Fetcher` holds, and wipes every buffer a
/// credential passed through. Safe to call more than once.
pub fn deinit(f: *Fetcher) void {
    f.release();
    f.wipe();
}

fn release(f: *Fetcher) void {
    const held = f.payload orelse return;
    f.allocator.free(held);
    f.payload = null;
}

/// Zeroes every buffer a credential passed through.
///
/// **Two of the three held the password in the clear.**
/// `credential_storage` holds the decoded userinfo of a url, and
/// `sasl_storage` holds the encoded `PLAIN` message, which is the password
/// with nothing but base64 over it. A freed or reused page goes to the
/// next caller to read, so both are zeroed rather than left. The challenge
/// buffer is the server's own text and holds no secret; it is wiped with
/// the others so that one rule covers the three and nobody has to work out
/// which of them left a password behind.
///
/// `open` runs this whichever way it leaves, and `deinit` runs it again so
/// that a caller who stops part way through still leaves nothing.
/// `zurl_ssh.Authenticator.deinit` keeps the same pair of rules.
fn wipe(f: *Fetcher) void {
    std.crypto.secureZero(u8, &f.credential_storage);
    std.crypto.secureZero(u8, &f.sasl_storage);
    std.crypto.secureZero(u8, &f.challenge_storage);
}

/// The answer of one SMTP transfer.
pub const Body = struct {
    /// An empty reader. A send has no body to give back, and a caller
    /// still needs one.
    reader: *Io.Reader,
    /// Zero, always.
    length: u64,
    /// How many recipients the server accepted.
    accepted: usize,
    /// How many octets of message went out, the stuffing and the
    /// terminator counted.
    sent: u64,
};

/// Whether `url` asks for a TLS session on the connection.
///
/// The scheme and nothing else. Compared without regard to case, per RFC
/// 3986, so `SMTPS://` is as encrypted as `smtps://`.
pub fn isSecure(url: zurl_core.Url) bool {
    return std.ascii.eqlIgnoreCase(url.scheme, secure_scheme);
}

/// Whether `text` could end a command line and write a second one.
///
/// **This is the check curl 8.21.0 does not make.** Measured, on a
/// loopback fixture:
///
///     curl --mail-rcpt $'c@d>\r\nRCPT TO:<evil@x'
///         wire: RCPT TO:<c@d>, then RCPT TO:<evil@x>
///
/// The message then goes to a recipient the user never named, and the
/// same text in `--mail-from` does the same thing. `Control.send` refuses
/// it at the socket; this is the earlier check, so the message names the
/// flag rather than the command.
pub fn addressIsSafe(text: []const u8) bool {
    return !zurl_net.line.hasFramingByte(text);
}

/// Runs one transfer and returns its answer.
///
/// The faults, and the exit code each carries. Every one was measured
/// against curl 8.21.0 on a loopback SMTP fixture:
///
/// - an address that could forge a command is `error.InvalidUrl`, exit 3,
///   and no socket opens at all. **curl sends it.**
/// - a transfer with no recipient, or with no message, is
///   `error.InvalidUrl`, exit 3, before any socket.
/// - a peer that does not accept a connection is `error.CouldNotConnect`,
///   exit 7.
/// - a reply nothing can read is `error.WeirdServerReply`, exit 8.
/// - a refused `MAIL FROM`, `RCPT TO`, or `DATA` is `error.SendError`,
///   exit 55, which is curl's own code.
/// - a message the server refuses after the `DATA` phase is
///   `error.WeirdServerReply`, exit 8, which is curl's own code.
/// - a refused `STARTTLS` under `--ssl-reqd` is `error.UseSslFailed`, exit
///   64, and no address and no message go out.
pub fn open(f: *Fetcher, url: zurl_core.Url, options: Options, d: ?*Diagnostics) Error!Body {
    f.release();
    f.upgrade_fault = null;
    f.stall = options.read_timeout;
    // **The credential lives no longer than the transfer.** See `wipe`.
    defer f.wipe();

    // **Everything the transfer needs is checked before anything is
    // dialed.** An address that could forge a command, a transfer with no
    // recipient, and a transfer with no message are each refused here,
    // with no socket opened at all.
    const name = try f.helloName(url, d);
    f.upgrade_name = name;

    var credential_source: CredentialSource = undefined;
    const credentials = try f.resolveCredentials(url, options, &credential_source, d);

    if (options.mail_from) |from| {
        if (!addressIsSafe(from)) return failAddress(d, "--mail-from", from);
        if (from.len > max_address_bytes) return failAddressSize(d, "--mail-from");
    }
    if (options.mail_rcpt.len == 0) return fail(d, error.InvalidUrl, &.{
        "an smtp transfer needs at least one recipient, and none was given: use --mail-rcpt",
    });
    for (options.mail_rcpt) |to| {
        if (!addressIsSafe(to)) return failAddress(d, "--mail-rcpt", to);
        if (to.len > max_address_bytes) return failAddressSize(d, "--mail-rcpt");
    }

    const source = options.body orelse return fail(d, error.InvalidUrl, &.{
        "an smtp transfer needs a message, and none was given: use -T or -d",
    });

    // **The message is read and stuffed before the dial**, so a body that
    // cannot be read costs no connection, and so the `SIZE=` parameter of
    // `MAIL FROM` can carry the real count.
    const payload = try f.buildMessage(source, options, d);
    errdefer f.allocator.free(payload);

    const port = url.port orelse return fail(d, error.InvalidUrl, &.{
        "an smtp url names a port, and this one names none",
    });
    // **`--resolve` and `--connect-to` move this dial and nothing else.**
    // `tlsOptions` below reads `url.host`, and so does the `OAUTHBEARER`
    // message, because that message names the service the user asked for
    // and never the address the dial reached. See `zurl_net.override`.
    const target = zurl_net.override.dialTarget(options.connect_to, url.host, port);
    // A host that does not read and a host name no resolver can look up
    // are two faults, exit 3 and exit 6. See `zurl_net.errors.hostInit`.
    const host = zurl_net.tcp.Host.init(target.host) catch |err| return fail(d, zurl_net.errors.hostInit(err).err, &.{
        target.faultPrefix(err),
        target.host,
    });

    const tls = try tlsOptions(url.host, options, d);

    var connection: zurl_net.Connection = undefined;
    zurl_net.bounded.setup(&connection, f.io, options.connect_timeout, .{
        .allocator = f.allocator,
        .io = f.io,
        .host = host,
        .port = target.port,
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
    if (options.tls == .explicit) {
        f.control.retarget(channel);
    } else {
        f.control.init(f.io, channel, options.read_timeout);

        const greeting = try f.expect(&connection, null, "the greeting", d);
        if (!greeting.isPositive()) {
            return failReply(d, error.WeirdServerReply, "the smtp server did not greet this connection", greeting);
        }
    }

    // **`EHLO` runs again after a `STARTTLS`.** RFC 3207 section 4.2 says
    // so: the session starts over inside TLS, and the capability list the
    // server gave in the clear is a list an attacker on the path could
    // have written.
    const capabilities = try f.hello(&connection, name, d);
    const wants_size = command.announces(capabilities, command.size_keyword);

    // **The login runs before the envelope, and a failed one ends the
    // transfer.** No address and no message go out after a refused
    // `AUTH`. See `authenticate`.
    if (credentials) |c| {
        try f.authenticate(&connection, capabilities, c, credential_source, url, options, d);
    } else if (options.bearer_token != null) {
        return fail(d, error.LoginDenied, &.{
            "--oauth2-bearer names a token and no user name, and a SASL bearer login carries both: name the user with -u",
        });
    }

    const sender = options.mail_from orelse "";
    const size_parameter: []const u8 = if (wants_size)
        std.fmt.bufPrint(&f.size_storage, "{s}{d}", .{
            command.size_parameter, payload.len,
        }) catch ""
    else
        "";
    const mail = try f.expect(&connection, &.{
        command.mail, sender, command.path_close, size_parameter,
    }, "MAIL FROM", d);
    if (!mail.isPositive()) {
        return failReply(d, error.SendError, "the smtp server refused the sender this transfer names", mail);
    }

    var accepted: usize = 0;
    for (options.mail_rcpt) |to| {
        const answer = try f.expect(&connection, &.{ command.rcpt, to, command.path_close }, "RCPT TO", d);
        // **One refused recipient ends the transfer.** RFC 5321 lets a
        // client go on with the recipients that were taken, and curl does
        // the same by default. zurl does not: a send that reached some of
        // the people it named and said nothing about the rest is a send a
        // user would read as complete.
        if (!answer.isPositive()) {
            return failReply(d, error.SendError, "the smtp server refused a recipient this transfer names", answer);
        }
        accepted += 1;
    }

    const go = try f.expect(&connection, &.{command.data}, "DATA", d);
    if (!go.isIntermediate()) {
        return failReply(d, error.SendError, "the smtp server did not ask for the message", go);
    }

    // **The message goes out already stuffed.** See `message`.
    const accepted_reply = f.control.sendMessage(payload) catch |err| return reportControl(err, &connection, "the message", d);
    if (!accepted_reply.isPositive()) {
        return failReply(d, error.WeirdServerReply, "the smtp server did not accept the message", accepted_reply);
    }

    // `QUIT` is a courtesy and never a gate. The answer is already read.
    f.control.send(&.{command.quit}) catch {};

    f.payload = payload;
    f.body = .fixed("");
    return .{
        .reader = &f.body,
        .length = 0,
        .accepted = accepted,
        .sent = payload.len,
    };
}

/// The credential this transfer sends, or null when nobody named one.
///
/// The url's userinfo first, then `-u`, then a netrc entry for the url's
/// host. That is the order `zurl-pop3` and `zurl-imap` keep, and the order
/// curl keeps for all three mail protocols, measured.
///
/// **Null is a real answer and not a fault.** A transfer that names no
/// credential sends no `AUTH` at all, which is what curl does: measured, a
/// `smtp://` url with no `-u` and no userinfo drew no `AUTH` from curl
/// even on a server offering three mechanisms.
///
/// **The userinfo is percent-decoded and the other two are not.** A url
/// writes a credential escaped, so `%40` in a password is an `@` and not
/// three characters. `-u` and a netrc file are read as they are written,
/// which is what curl does.
///
/// **A credential that could forge a command or a SASL field never
/// reaches one.** `zurl_net.sasl.Fields.check` refuses a NUL, a CR, an LF,
/// and a `\x01` before any encode runs, and `Control.send` refuses the
/// three framing bytes again at the socket. This function refuses the
/// framing bytes first, so the message names the credential and its source
/// rather than the command.
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
    if (c.user.len > max_credential_bytes or c.password.len > max_credential_bytes) {
        return failCredentialSize(d);
    }
    if (zurl_net.line.hasFramingByte(c.user) or zurl_net.line.hasFramingByte(c.password)) {
        return fail(d, error.InvalidUrl, &.{
            "the credential from ",
            source.describe(),
            " holds a NUL, a CR, or an LF, and any of the three would end the command line and write a command of its own",
        });
    }
    return c;
}

fn failCredentialSize(d: ?*Diagnostics) Error {
    return failNumber(
        d,
        error.CredentialTooLarge,
        "the credential this transfer names is longer than the ",
        max_credential_bytes,
        " bytes zurl sends in one smtp login",
    );
}

/// Logs in with SASL, and refuses the transfer when it cannot.
///
/// **A failed `AUTH` never falls back to an unauthenticated send.** That
/// is the whole reason `-u` used to be refused by name here. A message
/// that reached a server with no credential after the user named one is a
/// control that failed open, and the exit code would have said the send
/// worked. So every path out of this function that did not authenticate is
/// an error, and `MAIL FROM` is never reached.
///
/// The faults, and the exit code each carries:
///
/// - a server that named no mechanism this build speaks is
///   `error.LoginDenied`, exit 67, and no address goes out. **curl sends
///   the message unauthenticated instead**, measured: `-u alice:s3cret`
///   against a fixture whose `EHLO` answer named no `AUTH` drew no `AUTH`
///   from curl, then a `MAIL FROM`, then exit 0. A user who asked for a
///   credential and got a send without one has been told the wrong thing.
/// - a `--login-options` naming a mechanism this build does not speak, or
///   one the server did not offer, is `error.LoginDenied`, exit 67. curl
///   answers the second with the same code, measured.
/// - a `535` to the exchange is `error.LoginDenied`, exit 67, which is
///   curl's own code, measured against a fixture refusing every
///   mechanism.
fn authenticate(
    f: *Fetcher,
    connection: *zurl_net.Connection,
    capabilities: []const u8,
    credentials: Credentials,
    source: CredentialSource,
    url: zurl_core.Url,
    options: Options,
    d: ?*Diagnostics,
) Error!void {
    const advertised = command.parameters(capabilities, command.auth_keyword);

    var offer: zurl_net.sasl.Offer = .empty;
    if (advertised) |names| offer.addSpaceSeparated(names);

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
        if (advertised == null) return failCredential(
            d,
            error.LoginDenied,
            source,
            "this smtp server offers no AUTH at all, so zurl cannot send the credential from ",
            null,
        );
        if (options.bearer_token != null) return fail(d, error.LoginDenied, &.{
            "--oauth2-bearer needs a server offering XOAUTH2 or OAUTHBEARER, and this one offers neither",
        });
        return failCredential(
            d,
            error.LoginDenied,
            source,
            "this smtp server offers no SASL mechanism zurl speaks, so it cannot take the credential from ",
            null,
        );
    };

    const fields: zurl_net.sasl.Fields = .{
        .authzid = options.sasl_authzid,
        .authcid = credentials.user,
        .password = credentials.password,
        .bearer_token = options.bearer_token,
        .host = url.host,
        .port = url.port orelse 0,
    };

    // **Every field is checked before the `AUTH` command goes out**, and
    // not when the message that carries it is built. A field that cannot
    // travel would otherwise open an exchange this client has to abandon,
    // and the server would hold a half-run login. `--sasl-authzid` is the
    // field this catches and no other check reads.
    fields.checkAll(mechanism) catch |err| return failSasl(d, err);

    // **The exchange, and every message of it is bounded.** The first
    // message goes on the `AUTH` line under `--sasl-ir` and behind a
    // challenge without it. `LOGIN` is the one mechanism with a second
    // message, and `CRAM-MD5` is the one with no first message at all.
    const initial: ?[]const u8 = if (options.sasl_ir and mechanism.hasInitialResponse())
        try f.saslMessage(mechanism, "", fields, d)
    else
        null;

    var reply = if (initial) |text|
        try f.expect(connection, &.{ command.auth, " ", mechanism.name(), " ", text }, command.auth, d)
    else
        try f.expect(connection, &.{ command.auth, " ", mechanism.name() }, command.auth, d);

    // A `LOGIN` that put the user name on the `AUTH` line still owes the
    // password, so the step counter runs whether or not the first message
    // went out early.
    var step: usize = if (initial != null) 1 else 0;
    while (reply.isIntermediate()) {
        const challenge = f.readChallenge(reply.text, d) catch |err| {
            // **The exchange is cancelled before this leaves.** A server
            // left waiting for a response would read the next command as
            // one. See `command.auth_cancel`.
            f.control.send(&.{command.auth_cancel}) catch {};
            return err;
        };
        const answer = try f.saslStep(mechanism, step, challenge, fields, d);
        step += 1;
        reply = try f.expect(connection, &.{answer}, command.auth, d);
    }

    if (reply.isPositive()) return;
    return failCredential(
        d,
        error.LoginDenied,
        source,
        "the smtp server did not accept the credential from ",
        reply,
    );
}

/// Reads one server challenge out of a `334` reply.
fn readChallenge(f: *Fetcher, text: []const u8, d: ?*Diagnostics) Error![]const u8 {
    const encoded = std.mem.trim(u8, text, " \t");
    return zurl_net.sasl.decodeChallenge(&f.challenge_storage, encoded) catch |err| switch (err) {
        error.ChallengeTooLong => failNumber(
            d,
            error.WeirdServerReply,
            "the smtp server wrote a SASL challenge longer than the ",
            zurl_net.sasl.max_challenge_text_bytes,
            " bytes zurl reads",
        ),
        error.ChallengeMalformed => fail(d, error.WeirdServerReply, &.{
            "the smtp server wrote a SASL challenge that is not base64",
        }),
    };
}

/// Writes the message of step `step` of `mechanism`.
///
/// Step zero is the first message. `LOGIN` is the only mechanism with a
/// step one, and it is the password.
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
            "the smtp server asked for another SASL message after the exchange had finished",
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

/// Sends `EHLO`, and `HELO` when the server does not know it.
///
/// Returns the text of the answer that worked, which names what the server
/// can do. It borrows the dialogue's reply storage, so the caller must
/// read it before the next command.
///
/// **The fallback is what RFC 5321 section 3.2 asks for**, and it is what
/// curl does: measured against a fixture answering `500` to `EHLO`, curl
/// sends `HELO` next and the transfer runs.
fn hello(
    f: *Fetcher,
    connection: ?*zurl_net.Connection,
    name: []const u8,
    d: ?*Diagnostics,
) Error![]const u8 {
    const extended = try f.expect(connection, &.{ command.ehlo, " ", name }, command.ehlo, d);
    if (extended.isPositive()) return extended.text;

    const plain = try f.expect(connection, &.{ command.helo, " ", name }, command.helo, d);
    if (plain.isPositive()) return plain.text;
    return failReply(d, error.WeirdServerReply, "the smtp server answered neither EHLO nor HELO", plain);
}

/// The name the `EHLO` carries.
///
/// The url path, decoded, or `default_name` for a url that names none.
/// curl reads the same field, measured: `smtp://h/mail.example.com` sends
/// `EHLO mail.example.com`.
///
/// **A name that could forge a command is refused before any socket
/// opens.** `zurl_core.url.parse` already refuses a raw control byte in a
/// path, so a percent escape is the only way one can arrive, and it
/// becomes a byte only at the decode here.
fn helloName(f: *Fetcher, url: zurl_core.Url, d: ?*Diagnostics) Error![]const u8 {
    const path = url.path;
    const body = if (std.mem.startsWith(u8, path, "/")) path[1..] else path;
    if (body.len == 0) return default_name;
    if (body.len > f.name_storage.len) return failNumber(
        d,
        error.InvalidUrl,
        "the EHLO name in this url is longer than the ",
        max_name_bytes,
        " bytes zurl sends",
    );

    const decoded = zurl_core.url.percentDecode(&f.name_storage, body) catch
        return fail(d, error.InvalidUrl, &.{
            "the path of this url holds a percent escape that is not an escape",
        });
    if (zurl_core.url.hasControlByte(decoded)) return fail(d, error.InvalidUrl, &.{
        "the EHLO name in this url holds a control byte, and a CR or an LF in one would end the EHLO line and write a command of its own",
    });
    return decoded;
}

/// Reads the whole message and turns it into the octets of a `DATA` phase.
///
/// The result belongs to the caller, which must free it.
///
/// **The read is bounded before the buffer grows.** A source that names a
/// length larger than the bound is refused before one byte is read, and a
/// source that names none is read until it passes the bound.
fn buildMessage(f: *Fetcher, source: Source, options: Options, d: ?*Diagnostics) Error![]u8 {
    const max_bytes = options.max_message_bytes;
    if (source.len) |named| {
        if (named > max_bytes) return failNumber(
            d,
            error.FileSizeExceeded,
            "the message is larger than the ",
            max_bytes,
            " bytes zurl sends in one smtp transfer",
        );
    }

    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(f.allocator);

    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = source.read(source.ctx, &chunk, chunk.len);
        if (n == 0) break;
        if (n < 0) return fail(d, error.ReadError, &.{
            "zurl did not read the message this transfer sends",
        });
        const taken: usize = @intCast(n);
        if (@as(u64, taken) > max_bytes -| raw.items.len) return failNumber(
            d,
            error.FileSizeExceeded,
            "the message is larger than the ",
            max_bytes,
            " bytes zurl sends in one smtp transfer",
        );
        raw.appendSlice(f.allocator, chunk[0..taken]) catch
            return Diagnostics.record(d, error.OutOfMemory, .{});
    }

    const needed = message.writtenLen(raw.items);
    if (@as(u64, needed) > max_bytes) return failNumber(
        d,
        error.FileSizeExceeded,
        "the message, with the dot-stuffing RFC 5321 asks for, is larger than the ",
        max_bytes,
        " bytes zurl sends in one smtp transfer",
    );

    const out = f.allocator.alloc(u8, needed) catch
        return Diagnostics.record(d, error.OutOfMemory, .{});
    errdefer f.allocator.free(out);
    // `needed` came from the same function, so this cannot be short.
    _ = message.write(out, raw.items) catch return fail(d, error.WriteError, &.{
        "zurl could not build the message this transfer sends",
    });
    return out;
}

/// Sends one command, when there is one, and reads the whole reply.
///
/// A null `parts` reads a reply with no command before it, which is the
/// greeting.
fn expect(
    f: *Fetcher,
    connection: ?*zurl_net.Connection,
    parts: ?[]const []const u8,
    verb: []const u8,
    d: ?*Diagnostics,
) Error!Control.Reply {
    if (parts) |line| {
        f.control.send(line) catch |err| return reportControl(err, connection, verb, d);
    }
    return f.control.readReply() catch |err| return reportControl(err, connection, verb, d);
}

/// The TLS options a session opens with, or null for a plain hop.
///
/// **This is the one place in this package that turns peer verification
/// off, and it reads `options.insecure` and nothing else.**
///
/// **A build with no trust store cannot open an encrypted session.**
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
        "this build gave the smtp package no trust store, so it cannot verify an smtps peer",
    });
    try trust.load(trust.ptr);

    return .{
        .host = .{ .explicit = host },
        .trust = .{ .bundle = .{ .lock = trust.lock, .bundle = trust.bundle } },
        .min_version = options.tls_min_version,
        .max_version = options.tls_max_version,
        // **No ALPN extension at all.** RFC 7301 needs a registered
        // protocol name and SMTP has none.
        .alpn_protocols = &.{},
    };
}

/// The `STARTTLS` step, run inside the connect race.
///
/// **This runs on a plain stream and it sends no address and no
/// message.** RFC 3207 puts the greeting, an `EHLO`, and `STARTTLS` before
/// the handshake. Those three cross in the clear and nothing else does:
/// `MAIL FROM`, `RCPT TO`, and the message go out after the handshake,
/// from `open`, and `open` sends a second `EHLO` inside the session
/// because the first answer is not one this client can trust.
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

    const greeting = f.control.readReply() catch |err| return .{
        .err = replyFault(err),
        .message = "zurl did not read the smtp greeting before STARTTLS",
    };
    if (!greeting.isPositive()) return .{
        .err = error.WeirdServerReply,
        .message = "the smtp server did not greet this connection, so STARTTLS was never sent",
    };

    // RFC 3207 needs an `EHLO` before `STARTTLS`, because `STARTTLS` is
    // itself an extension. The answer is read and thrown away: it arrived
    // in the clear, so nothing in it can be trusted, and `open` asks
    // again inside the session.
    const opening = f.control.ask(&.{ command.ehlo, " ", f.upgrade_name }) catch |err| return .{
        .err = replyFault(err),
        .message = "zurl did not read the answer to the EHLO before STARTTLS",
    };
    if (!opening.isPositive()) return .{
        .err = error.WeirdServerReply,
        .message = "the smtp server refused EHLO, so STARTTLS was never sent",
    };

    const answer = f.control.ask(&.{command.starttls}) catch |err| return .{
        .err = replyFault(err),
        .message = "zurl did not read the answer to STARTTLS",
    };
    if (!answer.isPositive()) return .{
        .err = error.UseSslFailed,
        .message = "the smtp server refused STARTTLS, and zurl sends no address and no message over a connection that was asked to be encrypted and is not",
    };

    // **Nothing may be held across the handshake.** A server that wrote
    // bytes behind its `220` wrote them in cleartext.
    if (f.control.buffered() != 0) return .{
        .err = error.UseSslFailed,
        .message = "the smtp server wrote more bytes behind its STARTTLS answer, and those bytes are not inside the session",
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
/// error here.
fn replyFault(err: Control.Error) Error {
    return switch (err) {
        error.ReplyMalformed,
        error.ReplyTooManyLines,
        error.ReplyTooLong,
        error.LineTooLong,
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
    const mapped = replyFault(err);
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
    return fail(d, mapped, &.{ "the smtp connection failed on ", verb, ": ", cause });
}

/// Reports a dial or handshake fault.
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

/// `fail`, with the server's own reply on the end of the sentence.
///
/// **The reply text is the server's and it goes to a user's terminal**, so
/// only the code and the first line reach the message.
fn failReply(d: ?*Diagnostics, err: Error, sentence: []const u8, answer: Control.Reply) Error {
    var digits: [8]u8 = undefined;
    const code = std.fmt.bufPrint(&digits, "{d}", .{answer.code}) catch digits[0..0];
    const first = answer.text[0 .. std.mem.indexOfScalar(u8, answer.text, '\n') orelse answer.text.len];
    const shown = first[0..@min(first.len, 200)];
    return fail(d, err, &.{ sentence, ": ", code, " ", shown });
}

/// Reports a login that did not happen, and names where the credential
/// came from.
///
/// **The credential itself is never written.** The source names one of
/// three places for a user to look, and the server's own words say what it
/// answered. `answer` is null when no command went out at all.
fn failCredential(
    d: ?*Diagnostics,
    err: Error,
    source: CredentialSource,
    sentence: []const u8,
    answer: ?Control.Reply,
) Error {
    const reply = answer orelse return fail(d, err, &.{ sentence, source.describe() });
    var digits: [8]u8 = undefined;
    const code = std.fmt.bufPrint(&digits, "{d}", .{reply.code}) catch digits[0..0];
    const first = reply.text[0 .. std.mem.indexOfScalar(u8, reply.text, '\n') orelse reply.text.len];
    const shown = first[0..@min(first.len, 200)];
    return fail(d, err, &.{ sentence, source.describe(), ": ", code, " ", shown });
}

/// Reports an address that could forge a command.
///
/// **The address is not printed.** It is a user's own text and it holds a
/// CR or an LF, so writing it to a terminal would put the forged line on
/// the terminal too. The flag is what a user needs to know.
fn failAddress(d: ?*Diagnostics, flag: []const u8, address: []const u8) Error {
    _ = address;
    return fail(d, error.InvalidUrl, &.{
        "the address ",
        flag,
        " names holds a NUL, a CR, or an LF, and any of the three would end the smtp command line and write a command of its own, such as a second RCPT TO",
    });
}

/// Reports an address longer than this package sends.
fn failAddressSize(d: ?*Diagnostics, flag: []const u8) Error {
    var digits: [20]u8 = undefined;
    const text = std.fmt.bufPrint(&digits, "{d}", .{max_address_bytes}) catch digits[0..0];
    return fail(d, error.InvalidUrl, &.{
        "the address ",
        flag,
        " names is longer than the ",
        text,
        " bytes one smtp command line carries",
    });
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

/// Returns the dispatch entry for the plain `smtp` scheme.
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
        // **One gap, and it fails open when it is silent.** This package
        // dials the origin itself and reads no proxy field, so a transfer
        // that named one reached the origin direct. It is refused by name
        // instead. See `Front.protocol.Unread`.
        //
        // **`credentials` is no longer a gap.** This package sent no
        // credential at all until SASL landed, so `-u` was refused here
        // with exit 4 rather than let a message go out unauthenticated.
        // `authenticate` now sends it, and a login that fails still ends
        // the transfer before `MAIL FROM`.
        .unread = .{ .proxy = true },
    };
}

/// Returns the dispatch entry for the `smtps` scheme. See `protocol`.
pub fn secureProtocol(f: *Fetcher, comptime Front: type) Front.protocol.Protocol {
    return .{
        .scheme = secure_scheme,
        .default_port = secure_default_port,
        .ptr = f,
        .vtable = &Dispatch(Front).vtable,
        // One gap, and `credentials` is no longer one of them. See
        // `protocol`.
        .unread = .{ .proxy = true },
    };
}

/// The vtable for one front package.
fn Dispatch(comptime Front: type) type {
    return struct {
        const vtable: Front.protocol.Protocol.VTable = .{ .perform = performSmtp };

        fn performSmtp(
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
        /// **The scheme decides the TLS mode.** `smtps://` is implicit,
        /// and `smtp://` with `--ssl-reqd` is an explicit `STARTTLS`.
        fn translate(
            c: *Front.Client,
            url: zurl_core.Url,
            options: Front.Transfer.Options,
        ) Options {
            const materials = c.tlsMaterials();
            return .{
                .connect_timeout = options.connect_timeout,
                .max_message_bytes = if (options.max_size == 0)
                    default_max_message_bytes
                else
                    @min(options.max_size, default_max_message_bytes),
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
                .mail_from = options.mail_from,
                .mail_rcpt = options.mail_rcpt,
                .body = if (options.body) |source|
                    .{ .len = source.len, .ctx = source.ctx, .read = source.read }
                else
                    null,
                .credentials = if (options.credentials) |named|
                    .{ .user = named.user, .password = named.password }
                else
                    null,
                .netrc_text = options.netrc_text,
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
        /// The shape of `zurl.Transfer.Body`. Named apart from this file's
        /// own `Body` so the two cannot be read for each other: one is
        /// where a message comes from and the other is what a transfer
        /// gives back.
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
            insecure: bool = false,
            tls_min_version: zurl_core.tls.MinVersion = .floor,
            tls_max_version: zurl_core.tls.Version = .highest,
            mail_from: ?[]const u8 = null,
            mail_rcpt: []const []const u8 = &.{},
            body: ?BodySource = null,
            ftp_ssl_required: bool = false,
            credentials: ?zurl_core.auth.Credentials = null,
            netrc_text: ?[]const u8 = null,
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

/// A message source over a slice, the shape `src/cli/body.zig` builds from
/// `-T` and from `-d`.
const Slice = struct {
    bytes: []const u8,
    at: usize = 0,

    fn source(s: *Slice) Source {
        return .{ .len = s.bytes.len, .ctx = s, .read = readSlice };
    }

    /// A source that does not know its own length, which is what a pipe
    /// gives.
    fn unknownSource(s: *Slice) Source {
        return .{ .len = null, .ctx = s, .read = readSlice };
    }

    fn readSlice(ctx: *anyopaque, buffer: [*]u8, len: usize) callconv(.c) isize {
        const s: *Slice = @ptrCast(@alignCast(ctx));
        const take = @min(len, s.bytes.len - s.at);
        @memcpy(buffer[0..take], s.bytes[s.at..][0..take]);
        s.at += take;
        return @intCast(take);
    }
};

/// A source that always fails, which is what an unreadable file gives.
const Broken = struct {
    fn source(b: *Broken) Source {
        return .{ .len = null, .ctx = b, .read = readBroken };
    }

    fn readBroken(ctx: *anyopaque, buffer: [*]u8, len: usize) callconv(.c) isize {
        _ = ctx;
        _ = buffer;
        _ = len;
        return -1;
    }
};

/// Parses `text` the way `zurl.Client` does, with both schemes registered.
fn parseSmtpUrl(text: []const u8) !zurl_core.Url {
    var schemes: zurl_core.url.Schemes = .empty;
    try schemes.add(.{ .name = scheme, .default_port = default_port });
    try schemes.add(.{ .name = secure_scheme, .default_port = secure_default_port });
    return zurl_core.url.parseWith(text, &schemes);
}

test {
    _ = command;
    _ = message;
    _ = Control;
    _ = test_server;
}

test "the two schemes name the two ports curl dials" {
    try testing.expectEqualStrings("smtp", scheme);
    try testing.expectEqualStrings("smtps", secure_scheme);
    try testing.expectEqual(@as(?u16, 25), default_port);
    try testing.expectEqual(@as(?u16, 465), secure_default_port);
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
    try testing.expect(isSecure(try parseSmtpUrl("smtps://h/")));
    try testing.expect(isSecure(try parseSmtpUrl("SMTPS://h/")));
    try testing.expect(!isSecure(try parseSmtpUrl("smtp://h/")));
    try testing.expect(!isSecure(try parseSmtpUrl("smtp://h:465/")));
}

test "an address that could forge a command is not safe, and curl sends it" {
    // **The check curl 8.21.0 does not make.** Measured: the first row
    // below puts a second `RCPT TO` on the wire from curl.
    const forged = [_][]const u8{
        "c@d>\r\nRCPT TO:<evil@x",
        "c@d>\nRCPT TO:<evil@x",
        "c@d>\rRCPT TO:<evil@x",
        "c@d\x00",
        "\r\n",
        "\n",
        "\r",
        "\x00",
        "a@b>\r\nDATA",
    };
    for (forged) |address| try testing.expect(!addressIsSafe(address));

    // An ordinary address is safe, and so is one with the odd bytes a real
    // address may hold.
    for ([_][]const u8{
        "a@b.example",
        "",
        "first.last+tag@example.test",
        "a b@example.test",
        "\"quoted local\"@example.test",
    }) |address| try testing.expect(addressIsSafe(address));
}

/// How long a test lets a dial or a handshake take.
const test_connect_timeout: Io.Timeout = .{
    .duration = .{ .raw = .fromSeconds(10), .clock = .awake },
};

/// Runs a whole transfer against the fixture.
fn send(
    f: *Fetcher,
    server: *test_server.Server,
    path: []const u8,
    options: Options,
    d: ?*Diagnostics,
) !Body {
    var url_buffer: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "smtp://127.0.0.1:{d}{s}", .{ server.port(), path });
    var bounded_options = options;
    if (bounded_options.connect_timeout == .none) {
        bounded_options.connect_timeout = test_connect_timeout;
    }
    return f.open(try parseSmtpUrl(text), bounded_options, d);
}

test "a send reaches the server with the commands curl sends, in curl's order" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "Subject: hi\r\n\r\nbody line\r\n" };
    const out = try send(&f, &server, "/mail.example.com", .{
        .mail_from = "a@b.example",
        .mail_rcpt = &.{"c@d.example"},
        .body = body.source(),
    }, null);
    try testing.expectEqual(@as(usize, 1), out.accepted);
    try testing.expectEqual(@as(u64, 0), out.length);

    server.wait();
    // Measured from curl 8.21.0, in this order. The `SIZE=` parameter goes
    // out because the fixture's `EHLO` answer names the extension.
    try testing.expectEqualStrings(
        "EHLO mail.example.com\n" ++
            "MAIL FROM:<a@b.example> SIZE=29\n" ++
            "RCPT TO:<c@d.example>\n" ++
            "DATA\n" ++
            "QUIT",
        server.commands(),
    );
    try testing.expectEqualStrings("Subject: hi\r\n\r\nbody line\r\n", server.body());
    try testing.expectEqual(@as(usize, 1), server.connections());
}

test "a message with a line of one period arrives whole" {
    // **The dot-stuffing proof, through a whole transfer.** The fixture
    // ends the `DATA` phase at an unstuffed period line and logs whatever
    // follows as commands, so a client that did not stuff would leave
    // `RCPT TO:<evil@x>` in the command log and a short message in the
    // body.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const author = "line one\r\n.\r\nRCPT TO:<evil@x>\r\nline three\r\n";
    var body: Slice = .{ .bytes = author };
    const out = try send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
    }, null);
    try testing.expectEqual(@as(usize, 1), out.accepted);

    server.wait();
    // The message arrived byte for byte as its author wrote it.
    try testing.expectEqualStrings(author, server.body());
    // And the forged line is not in the command log.
    try testing.expectEqualStrings(
        // The `SIZE=` names the stuffed length, which is two bytes more
        // than the author wrote: one for the added period and three for
        // the terminator, less the ending the body already had.
        "EHLO h\nMAIL FROM:<a@b> SIZE=47\nRCPT TO:<c@d>\nDATA\nQUIT",
        server.commands(),
    );
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, server.commands(), "evil@x"),
    );
}

test "a message written with bare line feeds is stuffed too" {
    // **Where zurl and curl differ.** curl stuffs only after a `CRLF`, so
    // this body reaches a server from curl with a bare period line in the
    // middle of it, and the server reads the rest as commands. Measured.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "line one\n.\nRCPT TO:<evil@x>\nline three\n" };
    _ = try send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
    }, null);

    server.wait();
    // The message arrives with the endings RFC 5321 asks for, and whole.
    try testing.expectEqualStrings(
        "line one\r\n.\r\nRCPT TO:<evil@x>\r\nline three\r\n",
        server.body(),
    );
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, server.commands(), "evil@x"),
    );
}

test "a url that names no path sends a name that says nothing about this machine" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "hi\r\n" };
    _ = try send(&f, &server, "/", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
    }, null);

    server.wait();
    try testing.expect(std.mem.startsWith(u8, server.commands(), "EHLO localhost\n"));
}

test "a transfer with no sender sends the null reverse path, the way curl does" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "hi\r\n" };
    _ = try send(&f, &server, "/h", .{
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
    }, null);

    server.wait();
    try testing.expect(std.mem.indexOf(u8, server.commands(), "MAIL FROM:<> SIZE=") != null);
}

test "every recipient gets its own RCPT TO, in the order they were named" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "hi\r\n" };
    const out = try send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{ "c@d", "e@f", "g@h" },
        .body = body.source(),
    }, null);
    try testing.expectEqual(@as(usize, 3), out.accepted);

    server.wait();
    try testing.expect(std.mem.indexOf(
        u8,
        server.commands(),
        "RCPT TO:<c@d>\nRCPT TO:<e@f>\nRCPT TO:<g@h>\n",
    ) != null);
}

test "a server that does not know EHLO gets a HELO, and the transfer runs" {
    // Measured: a fixture answering `500` to `EHLO` makes curl send `HELO`
    // next, and the send goes through.
    var server: test_server.Server = undefined;
    try server.start(.{ .ehlo = &.{"500 unknown command"} });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "hi\r\n" };
    _ = try send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
    }, null);

    server.wait();
    // No `SIZE=` this time: a `HELO` answer names no extension.
    try testing.expectEqualStrings(
        "EHLO h\nHELO h\nMAIL FROM:<a@b>\nRCPT TO:<c@d>\nDATA\nQUIT",
        server.commands(),
    );
    try testing.expectEqualStrings("hi\r\n", server.body());
}

test "a server that names no SIZE extension gets a plain MAIL FROM" {
    var server: test_server.Server = undefined;
    try server.start(.{ .ehlo = &.{ "250-fixture", "250 PIPELINING" } });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "hi\r\n" };
    _ = try send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
    }, null);

    server.wait();
    try testing.expect(std.mem.indexOf(u8, server.commands(), "MAIL FROM:<a@b>\n") != null);
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, server.commands(), "SIZE="),
    );
}

test "an address that could forge a command is refused, and no socket opens" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const forged = [_][]const u8{
        "c@d>\r\nRCPT TO:<evil@x",
        "c@d>\nRCPT TO:<evil@x",
        "c@d>\rRCPT TO:<evil@x",
        "c@d\x00",
        "\r\nDATA",
    };
    for (forged) |address| {
        {
            var body: Slice = .{ .bytes = "hi\r\n" };
            var d: Diagnostics = .{};
            try testing.expectError(error.InvalidUrl, send(&f, &server, "/h", .{
                .mail_from = address,
                .mail_rcpt = &.{"c@d"},
                .body = body.source(),
            }, &d));
            try testing.expect(std.mem.indexOf(u8, d.message.?, "--mail-from") != null);
            // The forged text itself is not printed back at a terminal.
            try testing.expectEqual(
                @as(?usize, null),
                std.mem.indexOf(u8, d.message.?, "evil@x"),
            );
        }
        {
            var body: Slice = .{ .bytes = "hi\r\n" };
            var d: Diagnostics = .{};
            try testing.expectError(error.InvalidUrl, send(&f, &server, "/h", .{
                .mail_from = "a@b",
                .mail_rcpt = &.{ "c@d", address },
                .body = body.source(),
            }, &d));
            try testing.expect(std.mem.indexOf(u8, d.message.?, "--mail-rcpt") != null);
        }
    }
    try testing.expectEqual(@as(usize, 0), server.connections());
}

test "an EHLO name that could forge a command is refused, and no socket opens" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    for ([_][]const u8{
        "/h%0d%0aMAIL%20FROM:<evil@x>",
        "/h%0aQUIT",
        "/h%0dQUIT",
        "/h%00",
        "/%09h",
    }) |path| {
        var body: Slice = .{ .bytes = "hi\r\n" };
        var d: Diagnostics = .{};
        try testing.expectError(error.InvalidUrl, send(&f, &server, path, .{
            .mail_from = "a@b",
            .mail_rcpt = &.{"c@d"},
            .body = body.source(),
        }, &d));
        try testing.expect(std.mem.indexOf(u8, d.message.?, "control byte") != null);
    }
    try testing.expectEqual(@as(usize, 0), server.connections());
}

test "a transfer with no recipient and one with no message are refused before any socket" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    {
        var body: Slice = .{ .bytes = "hi\r\n" };
        var d: Diagnostics = .{};
        try testing.expectError(error.InvalidUrl, send(&f, &server, "/h", .{
            .mail_from = "a@b",
            .body = body.source(),
        }, &d));
        try testing.expect(std.mem.indexOf(u8, d.message.?, "--mail-rcpt") != null);
    }
    {
        var d: Diagnostics = .{};
        try testing.expectError(error.InvalidUrl, send(&f, &server, "/h", .{
            .mail_from = "a@b",
            .mail_rcpt = &.{"c@d"},
        }, &d));
        try testing.expect(std.mem.indexOf(u8, d.message.?, "-T or -d") != null);
    }
    try testing.expectEqual(@as(usize, 0), server.connections());
}

test "a refused MAIL FROM, RCPT TO, or DATA is curl's exit 55" {
    const rows = [_]test_server.Script{
        .{ .mail = "550 sender refused" },
        .{ .rcpt = "550 recipient refused" },
        .{ .data = "550 not now" },
    };
    for (rows) |script| {
        var server: test_server.Server = undefined;
        try server.start(script);
        defer server.stop();

        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();

        var body: Slice = .{ .bytes = "hi\r\n" };
        var d: Diagnostics = .{};
        try testing.expectError(error.SendError, send(&f, &server, "/h", .{
            .mail_from = "a@b",
            .mail_rcpt = &.{"c@d"},
            .body = body.source(),
        }, &d));
    }
}

test "one refused recipient ends the transfer and the message is not sent" {
    // **A send that reached some of the people it named and said nothing
    // about the rest is a send a user would read as complete.** RFC 5321
    // lets a client go on, and curl does by default. zurl does not.
    var server: test_server.Server = undefined;
    try server.start(.{ .rcpt = "550 no such user" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "hi\r\n" };
    var d: Diagnostics = .{};
    try testing.expectError(error.SendError, send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{ "c@d", "e@f" },
        .body = body.source(),
    }, &d));

    server.wait();
    // The second recipient was never named, and no `DATA` went out.
    try testing.expectEqualStrings(
        "EHLO h\nMAIL FROM:<a@b> SIZE=7\nRCPT TO:<c@d>",
        server.commands(),
    );
    try testing.expectEqualStrings("", server.body());
}

test "a message the server refuses after the DATA phase is curl's exit 8" {
    var server: test_server.Server = undefined;
    try server.start(.{ .body_reply = "554 message rejected" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "hi\r\n" };
    var d: Diagnostics = .{};
    try testing.expectError(error.WeirdServerReply, send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
    }, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "message rejected") != null);
}

test "a greeting that is not positive ends the transfer and sends nothing" {
    var server: test_server.Server = undefined;
    try server.start(.{ .greeting = "554 no service here" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "hi\r\n" };
    var d: Diagnostics = .{};
    try testing.expectError(error.WeirdServerReply, send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
    }, &d));

    server.wait();
    try testing.expectEqualStrings("", server.commands());
}

test "a peer that greets and says nothing more ends the transfer at the bound" {
    var server: test_server.Server = undefined;
    try server.startSilent();
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "hi\r\n" };
    var d: Diagnostics = .{};
    const short: Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(300), .clock = .awake } };
    try testing.expectError(error.OperationTimedOut, send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
        .read_timeout = short,
    }, &d));
}

test "a message larger than the bound is refused before any socket opens" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    // A source that names its own length is refused before one byte is
    // read.
    {
        var body: Slice = .{ .bytes = "0123456789abcdefghij" };
        var d: Diagnostics = .{};
        try testing.expectError(error.FileSizeExceeded, send(&f, &server, "/h", .{
            .mail_from = "a@b",
            .mail_rcpt = &.{"c@d"},
            .body = body.source(),
            .max_message_bytes = 8,
        }, &d));
        try testing.expectEqual(@as(usize, 0), body.at);
    }
    // A source that names none is read until it passes the bound.
    {
        var body: Slice = .{ .bytes = "0123456789abcdefghij" };
        var d: Diagnostics = .{};
        try testing.expectError(error.FileSizeExceeded, send(&f, &server, "/h", .{
            .mail_from = "a@b",
            .mail_rcpt = &.{"c@d"},
            .body = body.unknownSource(),
            .max_message_bytes = 8,
        }, &d));
    }
    try testing.expectEqual(@as(usize, 0), server.connections());
}

test "a message the process cannot read ends the transfer before any socket" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var broken: Broken = .{};
    var d: Diagnostics = .{};
    try testing.expectError(error.ReadError, send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = broken.source(),
    }, &d));
    try testing.expectEqual(@as(usize, 0), server.connections());
}

test "a refused STARTTLS sends no address and no message" {
    // **The rule this test exists for.** A transfer that asked for TLS and
    // carried on without it would hand a message to a peer that nothing
    // verified. curl answers the same shape with exit 64, measured.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "hi\r\n" };
    var d: Diagnostics = .{};
    try testing.expectError(error.UseSslFailed, send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
        .tls = .explicit,
        .insecure = true,
    }, &d));

    server.wait();
    // RFC 3207 needs an `EHLO` before `STARTTLS`, and nothing else went
    // out.
    try testing.expectEqualStrings("EHLO h\nSTARTTLS", server.commands());
    try testing.expectEqualStrings("", server.body());
}

test "a server that writes behind its STARTTLS answer does not get those bytes trusted" {
    var server: test_server.Server = undefined;
    try server.start(.{
        .starttls = "220 ready to start TLS",
        .starttls_trailer = "250 fixture\r\n",
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "hi\r\n" };
    var d: Diagnostics = .{};
    try testing.expectError(error.UseSslFailed, send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
        .tls = .explicit,
        .insecure = true,
    }, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "behind its STARTTLS answer") != null);
}

test "a STARTTLS the peer accepts and then speaks no TLS ends at the connect bound" {
    var server: test_server.Server = undefined;
    try server.start(.{ .starttls = "220 ready to start TLS" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "hi\r\n" };
    var d: Diagnostics = .{};
    const short: Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(500), .clock = .awake } };
    try testing.expectError(error.OperationTimedOut, send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
        .tls = .explicit,
        .insecure = true,
        .connect_timeout = short,
    }, &d));

    server.wait();
    try testing.expectEqualStrings("EHLO h\nSTARTTLS", server.commands());
    try testing.expectEqualStrings("", server.body());
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
        .{ .tls = .implicit, .trust = trust, .max_message_bytes = 1 },
        .{ .tls = .implicit, .trust = trust, .tls_min_version = .tls_1_3 },
        .{ .tls = .implicit, .trust = trust, .tls_max_version = .tls_1_2 },
        .{ .tls = .implicit, .trust = trust, .mail_from = "a@b" },
        .{ .tls = .implicit, .trust = trust, .mail_rcpt = &.{"c@d"} },
        .{ .tls = .explicit, .trust = trust },
        // A moved dial is one more input that must not reach the check.
        // `open` hands this function `url.host`, so the name an `smtps`
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

/// The `EHLO` answer of a fixture offering `mechanisms`.
///
/// Written as a `250-AUTH` middle line, which is the shape a real server
/// writes and the shape `zurl_net.reply.Collector` keeps whole.
fn ehloOffering(comptime mechanisms: []const u8) []const []const u8 {
    return &.{ "250-fixture", "250-SIZE 1000000", "250-AUTH " ++ mechanisms, "250 8BITMIME" };
}

/// The base64 of `text`, for a test that names a challenge as it travels.
fn encode(out: []u8, text: []const u8) []const u8 {
    const encoder = std.base64.standard.Encoder;
    return encoder.encode(out[0..encoder.calcSize(text.len)], text);
}

test "a PLAIN login reaches the server with the bytes curl sends" {
    // **Measured from curl 8.21.0**, on a loopback fixture offering
    // `PLAIN` alone: `AUTH PLAIN`, then `AGFsaWNlAHMzY3JldA==` on its own
    // line, which decodes to `\x00alice\x00s3cret`.
    var server: test_server.Server = undefined;
    try server.start(.{ .ehlo = ehloOffering("PLAIN") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "hi\r\n" };
    _ = try send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
        .credentials = .{ .user = "alice", .password = "s3cret" },
    }, null);

    server.wait();
    try testing.expectEqualStrings(
        "EHLO h\n" ++
            "AUTH PLAIN\n" ++
            "AGFsaWNlAHMzY3JldA==\n" ++
            "MAIL FROM:<a@b> SIZE=7\n" ++
            "RCPT TO:<c@d>\n" ++
            "DATA\n" ++
            "QUIT",
        server.commands(),
    );
    // **The password is nowhere on the wire in the clear.** It is inside
    // the base64 above, which is the whole of what `PLAIN` gives.
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, server.commands(), "s3cret"),
    );
}

test "the login runs before the envelope, and a refused one sends no message" {
    // **The failure the P2 review caught, closed.** A `535` used to be
    // impossible here because there was no `AUTH` at all; now it is
    // possible, and it must not turn into an unauthenticated send. No
    // `MAIL FROM`, no `RCPT TO`, and no `DATA` may follow it.
    var server: test_server.Server = undefined;
    try server.start(.{
        .ehlo = ehloOffering("PLAIN"),
        .auth_reply = "535 authentication failed",
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    var body: Slice = .{ .bytes = "hi\r\n" };
    try testing.expectError(error.LoginDenied, send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
        .credentials = .{ .user = "alice", .password = "s3cret" },
    }, &d));
    // curl's own code for a refused mail login, measured.
    try testing.expectEqual(@as(u8, 67), d.curl_code);
    // The message names where the credential came from and never the
    // credential.
    try testing.expect(std.mem.indexOf(u8, d.message.?, "-u option") != null);
    try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, d.message.?, "s3cret"));

    server.wait();
    try testing.expectEqualStrings("EHLO h\nAUTH PLAIN\nAGFsaWNlAHMzY3JldA==", server.commands());
    try testing.expectEqualStrings("", server.body());
}

test "the strongest mechanism the server offers is the one used" {
    // Measured: curl picks `CRAM-MD5` off this list, on all three
    // protocols. See `zurl_net.sasl.choose` for why the order runs that
    // way.
    var challenge_storage: [64]u8 = undefined;
    const challenge = encode(&challenge_storage, "<1896.697170952@fixture>");

    var server: test_server.Server = undefined;
    try server.start(.{
        .ehlo = ehloOffering("PLAIN LOGIN CRAM-MD5"),
        .auth_challenges = &.{challenge},
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "hi\r\n" };
    _ = try send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
        .credentials = .{ .user = "alice", .password = "s3cret" },
    }, null);

    server.wait();
    // Byte for byte what curl 8.21.0 wrote for the same challenge and the
    // same credential.
    try testing.expectEqualStrings(
        "EHLO h\n" ++
            "AUTH CRAM-MD5\n" ++
            "YWxpY2UgMDJmZmVhNTc2NDEyYWNiYzUyNWU0ZDgyNTE0NmY5ZmM=\n" ++
            "MAIL FROM:<a@b> SIZE=7\n" ++
            "RCPT TO:<c@d>\n" ++
            "DATA\n" ++
            "QUIT",
        server.commands(),
    );
}

test "a LOGIN exchange answers two challenges, the user then the password" {
    var user_storage: [32]u8 = undefined;
    var pass_storage: [32]u8 = undefined;
    const user_challenge = encode(&user_storage, "Username:");
    const pass_challenge = encode(&pass_storage, "Password:");

    var server: test_server.Server = undefined;
    try server.start(.{
        .ehlo = ehloOffering("LOGIN"),
        .auth_challenges = &.{ user_challenge, pass_challenge },
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "hi\r\n" };
    _ = try send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
        .credentials = .{ .user = "alice", .password = "s3cret" },
    }, null);

    server.wait();
    // Measured from curl 8.21.0 on a fixture offering `LOGIN` alone.
    try testing.expectEqualStrings(
        "EHLO h\n" ++
            "AUTH LOGIN\n" ++
            "YWxpY2U=\n" ++
            "czNjcmV0\n" ++
            "MAIL FROM:<a@b> SIZE=7\n" ++
            "RCPT TO:<c@d>\n" ++
            "DATA\n" ++
            "QUIT",
        server.commands(),
    );
}

test "--sasl-ir puts the first message on the AUTH line and saves a round trip" {
    var server: test_server.Server = undefined;
    try server.start(.{ .ehlo = ehloOffering("PLAIN") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "hi\r\n" };
    _ = try send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
        .credentials = .{ .user = "alice", .password = "s3cret" },
        .sasl_ir = true,
    }, null);

    server.wait();
    // Measured: `--sasl-ir` drew exactly this one line from curl where
    // the same command without it drew two.
    try testing.expectEqualStrings(
        "EHLO h\n" ++
            "AUTH PLAIN AGFsaWNlAHMzY3JldA==\n" ++
            "MAIL FROM:<a@b> SIZE=7\n" ++
            "RCPT TO:<c@d>\n" ++
            "DATA\n" ++
            "QUIT",
        server.commands(),
    );
}

test "--sasl-ir on LOGIN sends only the user name early, the way curl does" {
    var pass_storage: [32]u8 = undefined;
    const pass_challenge = encode(&pass_storage, "Password:");

    var user_storage: [32]u8 = undefined;
    var server: test_server.Server = undefined;
    try server.start(.{
        .ehlo = ehloOffering("LOGIN"),
        .auth_challenges = &.{ encode(&user_storage, "Username:"), pass_challenge },
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "hi\r\n" };
    _ = try send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
        .credentials = .{ .user = "alice", .password = "s3cret" },
        .sasl_ir = true,
    }, null);

    server.wait();
    // Measured: curl wrote `AUTH LOGIN YWxpY2U=` and then answered the
    // password challenge on its own line. The user name goes early and
    // the password never does.
    try testing.expectEqualStrings(
        "EHLO h\n" ++
            "AUTH LOGIN YWxpY2U=\n" ++
            "czNjcmV0\n" ++
            "MAIL FROM:<a@b> SIZE=7\n" ++
            "RCPT TO:<c@d>\n" ++
            "DATA\n" ++
            "QUIT",
        server.commands(),
    );
}

test "--sasl-authzid names the identity to act as, and PLAIN carries it" {
    var server: test_server.Server = undefined;
    try server.start(.{ .ehlo = ehloOffering("PLAIN") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "hi\r\n" };
    _ = try send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
        .credentials = .{ .user = "alice", .password = "s3cret" },
        .sasl_authzid = "admin",
    }, null);

    server.wait();
    // Measured: `--sasl-authzid admin` put `admin\x00alice\x00s3cret` on
    // the wire from curl, which is this base64.
    try testing.expectEqualStrings(
        "EHLO h\n" ++
            "AUTH PLAIN\n" ++
            "YWRtaW4AYWxpY2UAczNjcmV0\n" ++
            "MAIL FROM:<a@b> SIZE=7\n" ++
            "RCPT TO:<c@d>\n" ++
            "DATA\n" ++
            "QUIT",
        server.commands(),
    );
}

test "--login-options names one mechanism, and it outranks the order" {
    var server: test_server.Server = undefined;
    try server.start(.{ .ehlo = ehloOffering("PLAIN LOGIN CRAM-MD5") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "hi\r\n" };
    _ = try send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
        .credentials = .{ .user = "alice", .password = "s3cret" },
        .login_options = "AUTH=PLAIN",
    }, null);

    server.wait();
    // Measured: the same offer with no option drew `AUTH CRAM-MD5` from
    // curl, and with this option it drew `AUTH PLAIN`.
    try testing.expectEqualStrings(
        "EHLO h\n" ++
            "AUTH PLAIN\n" ++
            "AGFsaWNlAHMzY3JldA==\n" ++
            "MAIL FROM:<a@b> SIZE=7\n" ++
            "RCPT TO:<c@d>\n" ++
            "DATA\n" ++
            "QUIT",
        server.commands(),
    );
}

test "a --login-options the server cannot meet ends the transfer with no AUTH" {
    // **Measured from curl 8.21.0**, which answers the same case with
    // exit 67 and sends no `AUTH` at all.
    var server: test_server.Server = undefined;
    try server.start(.{ .ehlo = ehloOffering("PLAIN LOGIN") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    var body: Slice = .{ .bytes = "hi\r\n" };
    try testing.expectError(error.LoginDenied, send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
        .credentials = .{ .user = "alice", .password = "s3cret" },
        .login_options = "AUTH=CRAM-MD5",
    }, &d));
    try testing.expectEqual(@as(u8, 67), d.curl_code);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "CRAM-MD5") != null);

    server.wait();
    try testing.expectEqualStrings("EHLO h", server.commands());
}

test "a --login-options naming a mechanism this build has no code for is refused by name" {
    var server: test_server.Server = undefined;
    try server.start(.{ .ehlo = ehloOffering("PLAIN GSSAPI") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    var body: Slice = .{ .bytes = "hi\r\n" };
    try testing.expectError(error.LoginDenied, send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
        .credentials = .{ .user = "alice", .password = "s3cret" },
        .login_options = "AUTH=GSSAPI",
    }, &d));
    // The sentence names the mechanism and lists the ones this build has.
    try testing.expect(std.mem.indexOf(u8, d.message.?, "GSSAPI") != null);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "PLAIN") != null);

    // And a value that is not the `AUTH=` form is refused too, rather
    // than read as a mechanism name.
    var second: test_server.Server = undefined;
    try second.start(.{ .ehlo = ehloOffering("PLAIN") });
    defer second.stop();
    var g: Fetcher = .init(testing.allocator, testing.io);
    defer g.deinit();
    var body2: Slice = .{ .bytes = "hi\r\n" };
    try testing.expectError(error.LoginDenied, send(&g, &second, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body2.source(),
        .credentials = .{ .user = "alice", .password = "s3cret" },
        .login_options = "PLAIN",
    }, null));
}

test "a server offering no AUTH refuses the transfer rather than send it unauthenticated" {
    // **This is where zurl and curl part, and it is deliberate.**
    // Measured: `-u alice:s3cret` against a fixture whose `EHLO` answer
    // names no `AUTH` drew no `AUTH` from curl, then `MAIL FROM`, then
    // the message, then exit 0. A user who named a credential and got a
    // send without one has been told the wrong thing.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    var body: Slice = .{ .bytes = "hi\r\n" };
    try testing.expectError(error.LoginDenied, send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
        .credentials = .{ .user = "alice", .password = "s3cret" },
    }, &d));
    try testing.expectEqual(@as(u8, 67), d.curl_code);

    server.wait();
    // Nothing after the `EHLO`. No address and no message went out.
    try testing.expectEqualStrings("EHLO h", server.commands());
    try testing.expectEqualStrings("", server.body());
}

test "a server offering only mechanisms this build has no code for is refused too" {
    var server: test_server.Server = undefined;
    try server.start(.{ .ehlo = ehloOffering("GSSAPI NTLM DIGEST-MD5") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    var body: Slice = .{ .bytes = "hi\r\n" };
    try testing.expectError(error.LoginDenied, send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
        .credentials = .{ .user = "alice", .password = "s3cret" },
    }, &d));
    try testing.expectEqual(@as(u8, 67), d.curl_code);

    server.wait();
    try testing.expectEqualStrings("EHLO h", server.commands());
}

test "a transfer with no credential sends no AUTH, whatever the server offers" {
    // curl does the same, measured: a url with no `-u` and no userinfo
    // drew no `AUTH` from curl even on a server offering three
    // mechanisms.
    var server: test_server.Server = undefined;
    try server.start(.{ .ehlo = ehloOffering("PLAIN LOGIN CRAM-MD5") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "hi\r\n" };
    _ = try send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
    }, null);

    server.wait();
    try testing.expectEqualStrings(
        "EHLO h\nMAIL FROM:<a@b> SIZE=7\nRCPT TO:<c@d>\nDATA\nQUIT",
        server.commands(),
    );
}

test "a credential in the url userinfo logs in, and it is percent-decoded" {
    var server: test_server.Server = undefined;
    try server.start(.{ .ehlo = ehloOffering("PLAIN") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var url_buffer: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(
        &url_buffer,
        "smtp://alice:s3%40cret@127.0.0.1:{d}/h",
        .{server.port()},
    );
    var body: Slice = .{ .bytes = "hi\r\n" };
    _ = try f.open(try parseSmtpUrl(text), .{
        .connect_timeout = test_connect_timeout,
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
    }, null);

    server.wait();
    // `s3%40cret` is `s3@cret`, so the message is
    // `\x00alice\x00s3@cret`.
    var raw: [64]u8 = undefined;
    try testing.expectEqualStrings(
        "\x00alice\x00s3@cret",
        try zurl_net.sasl.decodeChallenge(&raw, "AGFsaWNlAHMzQGNyZXQ="),
    );
    try testing.expectEqualStrings(
        "EHLO h\n" ++
            "AUTH PLAIN\n" ++
            "AGFsaWNlAHMzQGNyZXQ=\n" ++
            "MAIL FROM:<a@b> SIZE=7\n" ++
            "RCPT TO:<c@d>\n" ++
            "DATA\n" ++
            "QUIT",
        server.commands(),
    );
}

test "a credential that could forge a field is refused, and no socket opens" {
    // **The NUL rule, proved through a whole transfer.** A NUL in the
    // password would move the `PLAIN` separator and hand the server a
    // credential the user never wrote, and base64 hides it from
    // `zurl_net.line.write`. A CR or an LF would end the command line.
    // All of them are refused before the dial.
    const forged = [_][]const u8{
        "s3cret\x00admin",
        "\x00",
        "s3cret\r\nQUIT",
        "s3cret\nMAIL FROM:<evil@x>",
        "s3cret\r",
    };
    for (forged) |text| {
        var server: test_server.Server = undefined;
        try server.start(.{ .ehlo = ehloOffering("PLAIN") });
        defer server.stop();

        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();

        var body: Slice = .{ .bytes = "hi\r\n" };
        var d: Diagnostics = .{};
        try testing.expectError(error.InvalidUrl, send(&f, &server, "/h", .{
            .mail_from = "a@b",
            .mail_rcpt = &.{"c@d"},
            .body = body.source(),
            .credentials = .{ .user = "alice", .password = text },
        }, &d));
        // The credential is never written into the message.
        try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, d.message.?, "s3cret"));
        try testing.expectEqual(@as(usize, 0), server.connections());
    }
}

test "an authzid that could forge a field is refused after the dial and before the AUTH" {
    // **The authzid is the third field, and it reaches the wire first.**
    // A NUL in it forges the authcid, so `admin\x00root` would log in as
    // `root` with the user's own name nowhere in the message. It arrives
    // through `--sasl-authzid`, which no other check reads, so this is
    // the one that catches it.
    var server: test_server.Server = undefined;
    try server.start(.{ .ehlo = ehloOffering("PLAIN") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    var body: Slice = .{ .bytes = "hi\r\n" };
    try testing.expectError(error.InvalidUrl, send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
        .credentials = .{ .user = "alice", .password = "s3cret" },
        .sasl_authzid = "admin\x00root",
    }, &d));

    server.wait();
    // The `AUTH` never went out, so no field of it reached the server.
    try testing.expectEqualStrings("EHLO h", server.commands());
}

test "a challenge that is not base64, or is too long, ends the exchange" {
    // **A challenge is the peer's own text.** Neither of these may reach
    // the decoder as a length to trust.
    var server: test_server.Server = undefined;
    try server.start(.{
        .ehlo = ehloOffering("CRAM-MD5"),
        .auth_challenges = &.{"not base64!"},
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    var body: Slice = .{ .bytes = "hi\r\n" };
    try testing.expectError(error.WeirdServerReply, send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
        .credentials = .{ .user = "alice", .password = "s3cret" },
    }, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "base64") != null);

    server.wait();
    // **The exchange was cancelled before the session ended.** A server
    // left waiting for a response would read the next command as one.
    try testing.expectEqualStrings("EHLO h\nAUTH CRAM-MD5\n*", server.commands());
}

test "--oauth2-bearer picks a bearer mechanism, and OAUTHBEARER outranks XOAUTH2" {
    var server: test_server.Server = undefined;
    try server.start(.{ .ehlo = ehloOffering("PLAIN XOAUTH2 OAUTHBEARER") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var url_buffer: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "smtp://127.0.0.1:{d}/h", .{server.port()});
    var body: Slice = .{ .bytes = "hi\r\n" };
    _ = try f.open(try parseSmtpUrl(text), .{
        .connect_timeout = test_connect_timeout,
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
        .credentials = .{ .user = "alice", .password = "" },
        .bearer_token = "tok123",
    }, null);

    server.wait();
    // The message carries the host and the port this transfer dialed,
    // which is what RFC 7628 section 3.1 asks for and what curl writes,
    // measured.
    var expected_storage: [256]u8 = undefined;
    const raw = try std.fmt.bufPrint(
        &expected_storage,
        "n,a=alice,\x01host=127.0.0.1\x01port={d}\x01auth=Bearer tok123\x01\x01",
        .{server.port()},
    );
    var encoded_storage: [512]u8 = undefined;
    var expected: [512]u8 = undefined;
    const want = try std.fmt.bufPrint(&expected, "EHLO h\nAUTH OAUTHBEARER\n{s}\n" ++
        "MAIL FROM:<a@b> SIZE=7\nRCPT TO:<c@d>\nDATA\nQUIT", .{
        encode(&encoded_storage, raw),
    });
    try testing.expectEqualStrings(want, server.commands());
}

test "XOAUTH2 is used when the server offers no OAUTHBEARER" {
    var server: test_server.Server = undefined;
    try server.start(.{ .ehlo = ehloOffering("PLAIN XOAUTH2") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "hi\r\n" };
    _ = try send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
        .credentials = .{ .user = "alice", .password = "" },
        .bearer_token = "tok123",
    }, null);

    server.wait();
    // Byte for byte what curl 8.21.0 wrote for the same token.
    try testing.expectEqualStrings(
        "EHLO h\n" ++
            "AUTH XOAUTH2\n" ++
            "dXNlcj1hbGljZQFhdXRoPUJlYXJlciB0b2sxMjMBAQ==\n" ++
            "MAIL FROM:<a@b> SIZE=7\n" ++
            "RCPT TO:<c@d>\n" ++
            "DATA\n" ++
            "QUIT",
        server.commands(),
    );
}

test "a bearer token with no bearer mechanism offered is refused, not sent as a password" {
    // Measured: curl answers the same case with exit 67 and sends no
    // `AUTH`. A token written into a `PLAIN` password field would hand a
    // server a secret it cannot use and cannot be asked to forget.
    var server: test_server.Server = undefined;
    try server.start(.{ .ehlo = ehloOffering("PLAIN LOGIN CRAM-MD5") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    var body: Slice = .{ .bytes = "hi\r\n" };
    try testing.expectError(error.LoginDenied, send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
        .credentials = .{ .user = "alice", .password = "" },
        .bearer_token = "tok123",
    }, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "--oauth2-bearer") != null);
    try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, d.message.?, "tok123"));

    server.wait();
    try testing.expectEqualStrings("EHLO h", server.commands());
}

test "a netrc entry logs in when no other source named a credential" {
    var server: test_server.Server = undefined;
    try server.start(.{ .ehlo = ehloOffering("PLAIN") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var body: Slice = .{ .bytes = "hi\r\n" };
    _ = try send(&f, &server, "/h", .{
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
        .netrc_text = "machine 127.0.0.1 login alice password s3cret\n",
    }, null);

    server.wait();
    try testing.expectEqualStrings(
        "EHLO h\n" ++
            "AUTH PLAIN\n" ++
            "AGFsaWNlAHMzY3JldA==\n" ++
            "MAIL FROM:<a@b> SIZE=7\n" ++
            "RCPT TO:<c@d>\n" ++
            "DATA\n" ++
            "QUIT",
        server.commands(),
    );
}

test "every buffer a credential passed through is zeroed when the transfer ends" {
    // **The wipe, proved.** `credential_storage` held the decoded
    // userinfo and `sasl_storage` held the encoded `PLAIN` message, which
    // is the password with nothing but base64 over it. Both are wiped
    // whichever way `open` leaves.
    var server: test_server.Server = undefined;
    try server.start(.{ .ehlo = ehloOffering("PLAIN") });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var url_buffer: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(
        &url_buffer,
        "smtp://alice:s3cret@127.0.0.1:{d}/h",
        .{server.port()},
    );
    var body: Slice = .{ .bytes = "hi\r\n" };
    _ = try f.open(try parseSmtpUrl(text), .{
        .connect_timeout = test_connect_timeout,
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
    }, null);

    // Neither the password nor its encoded form is anywhere in the
    // buffers that carried them.
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, &f.credential_storage, "s3cret"),
    );
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, &f.sasl_storage, "AGFsaWNlAHMzY3JldA=="),
    );
    // And every byte of both really is zero.
    for (f.credential_storage) |byte| try testing.expectEqual(@as(u8, 0), byte);
    for (f.sasl_storage) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "the buffers are wiped on the error path too" {
    // A refused login is the path a wipe is easiest to forget on, and it
    // is the path where the buffer holds the most.
    var server: test_server.Server = undefined;
    try server.start(.{
        .ehlo = ehloOffering("PLAIN"),
        .auth_reply = "535 authentication failed",
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var url_buffer: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(
        &url_buffer,
        "smtp://alice:s3cret@127.0.0.1:{d}/h",
        .{server.port()},
    );
    var body: Slice = .{ .bytes = "hi\r\n" };
    try testing.expectError(error.LoginDenied, f.open(try parseSmtpUrl(text), .{
        .connect_timeout = test_connect_timeout,
        .mail_from = "a@b",
        .mail_rcpt = &.{"c@d"},
        .body = body.source(),
    }, null));

    for (f.credential_storage) |byte| try testing.expectEqual(@as(u8, 0), byte);
    for (f.sasl_storage) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "a credential now reaches this package rather than being refused by name" {
    // **The declaration this task changed.** `unread.credentials` was
    // true here, and `zurl.Client.refuseUnread` turned `-u` on an
    // `smtp://` url into exit 4 before any dial. SASL closes the gap, so
    // the field is gone and the credential reaches `authenticate`.
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const plain = f.protocol(StubFront);
    const secure = f.secureProtocol(StubFront);
    try testing.expect(!plain.unread.credentials);
    try testing.expect(!secure.unread.credentials);
    // The proxy gap is still real: this package dials the origin itself.
    try testing.expect(plain.unread.proxy);
    try testing.expect(secure.unread.proxy);
}

test "--connect-to moves an smtp dial and --resolve reaches this package too" {
    // The defect this closes: this package read no `connect_to`, so a
    // user who named either flag got a dial to the url's own host and no
    // diagnostic. curl 8.21.0 applies both to `smtp` and `smtps`,
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
    const url = try parseSmtpUrl("smtp://127.0.0.2:1/mail.example.com");

    var first: Slice = .{ .bytes = "Subject: hi\r\n\r\nbody\r\n" };
    var bare: Diagnostics = .{};
    try testing.expectError(error.CouldNotConnect, f.open(url, .{
        .connect_timeout = test_connect_timeout,
        .mail_from = "a@b.example",
        .mail_rcpt = &.{"c@d.example"},
        .body = first.source(),
    }, &bare));
    try testing.expectEqual(@as(usize, 0), server.connections());

    var second: Slice = .{ .bytes = "Subject: hi\r\n\r\nbody\r\n" };
    const out = try f.open(url, .{
        .connect_timeout = test_connect_timeout,
        .mail_from = "a@b.example",
        .mail_rcpt = &.{"c@d.example"},
        .body = second.source(),
        .connect_to = &.{.{
            .from_host = "127.0.0.2",
            .from_port = 1,
            .to_host = "127.0.0.1",
            .to_port = server.port(),
        }},
    }, null);
    try testing.expectEqual(@as(usize, 1), out.accepted);
    try testing.expectEqual(@as(usize, 1), server.connections());

    server.wait();
    // The `EHLO` still names the url's own path argument, which is the
    // name the user asked to be known by and never the dialed address.
    try testing.expect(std.mem.indexOf(u8, server.commands(), "EHLO mail.example.com") != null);
}

test "the smtp translation carries --connect-to into this package" {
    var client: StubFront.Client = .{};
    const D = Dispatch(StubFront);
    const url = try parseSmtpUrl("smtp://example.com/mail.example.com");

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
