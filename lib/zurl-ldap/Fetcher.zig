//! Runs one `ldap://` or `ldaps://` transfer: the dial, the bind, the
//! search, and the text the entries become.
//!
//! A `Fetcher` owns the answer of the transfer in play. `open` frees
//! whatever the last call left and holds the new answer, so one `Fetcher`
//! serves one transfer at a time, the same rule `zurl.Client` keeps for
//! its own HTTP exchange.
//!
//! **A `Fetcher` must not move once `open` has run.** The body reader it
//! hands back points into this value, and so do the session's buffers.
//!
//! **One package owns both schemes.** RFC 4511 names the operations and
//! `ldaps` changes none of them: it puts the same ones inside TLS.
//! `protocol` and `secureProtocol` build the two dispatch entries, and
//! both point at one vtable that reads `url.scheme`. The two carry
//! different default ports, 389 and 636, which is what curl dials.
//!
//! ## What a transfer sends
//!
//! The order is curl's own, read off curl 8.21.0 through a byte-logging
//! relay to a real slapd 2.6.13:
//!
//! ```
//! [StartTLS], BindRequest, SearchRequest, UnbindRequest
//! ```
//!
//! **A bind always goes out, even with no credential.** curl sends the
//! anonymous simple bind `30 0c 02 01 01 60 07 02 01 03 04 00 80 00` for
//! a url with no `-u` and no userinfo, measured. RFC 4511 section 5.1.1
//! makes an anonymous bind a real operation and not the absence of one, so
//! this is not the POP3 rule where no credential means no login at all.
//!
//! ## What a transfer writes
//!
//! `ldif.zig` holds the format and the one rule that decides whether a
//! value is written as itself or in base64. It is curl's format, measured,
//! and the two places it differs are named there.
//!
//! ## What this build does not do
//!
//! - **No SASL.** RFC 4511 section 4.2 gives `AuthenticationChoice` a
//!   `sasl [3]` arm and this writes only `simple [0]`. There is no flag
//!   and no url form in zurl that asks for SASL, so the refusal is on the
//!   two inputs that could name one: a `-u` user name holding curl's
//!   `;AUTH=` spelling is `error.NotBuiltIn`, exit 4, and a server that
//!   answers the bind with `authMethodNotSupported` or
//!   `strongerAuthRequired` is reported with those words rather than
//!   retried by a weaker method.
//! - **No referral is followed.** A `SearchResultReference` names another
//!   server, and following it would send the bind credential to a host the
//!   **server** chose and not the user. curl does not follow one either,
//!   and it does worse: measured, curl stops the whole search at the first
//!   reference and drops every entry after it. This build reads past a
//!   reference and carries on to the `SearchResultDone`, so it returns the
//!   entries curl loses. See `runSearch`.
//! - **No modify, add, delete, or compare.** Nothing here writes to a
//!   directory. `-X` names no LDAP operation, the way it names a POP3 or
//!   an IMAP command, because a request that changed a directory should
//!   not be one letter away from one that reads it.
//! - **No controls.** See `message.zig`.
//! - **No connection reuse.** The session ends with an `UnbindRequest`,
//!   which RFC 4511 section 4.3 says the server answers by closing.
//!
//! This file imports `zurl-core` and `zurl-net`. It does not import
//! `zurl`, and it never will. See `protocol`.

const Fetcher = @This();

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_net = @import("zurl-net");

const filter = @import("filter.zig");
const ldif = @import("ldif.zig");
const message = @import("message.zig");
const target = @import("target.zig");
const Session = @import("Session.zig");

const Io = std.Io;
const Error = zurl_core.Error;
const Diagnostics = zurl_core.Diagnostics;

/// The plain scheme this package handles.
pub const scheme = "ldap";

/// The encrypted scheme this package handles.
pub const secure_scheme = "ldaps";

/// The port an `ldap://` url uses when it names none. RFC 4516 section 2.
pub const default_port: ?u16 = 389;

/// The port an `ldaps://` url uses when it names none.
///
/// 636, the implicit TLS port, which is what curl dials for `ldaps://`.
pub const secure_default_port: ?u16 = 636;

/// How many bytes of answer this package writes by default.
///
/// A search answer has no length: the server sends entries until it sends
/// a `SearchResultDone`, and it chooses how many. 16 MiB is the number
/// every other non-HTTP package here keeps, and `--max-filesize` narrows
/// it.
pub const default_max_response_bytes: u64 = 16 * 1024 * 1024;

/// How many messages one search may read.
///
/// **A bound on round trips and not on bytes.** A server that sends an
/// entry with no attributes writes a handful of bytes of output for each
/// one, so the size bound alone would let it hold this transfer for a very
/// long time. 100 000 is far past any search a person runs and it ends
/// such a server by name.
///
/// A search that meets it is `error.FileSizeExceeded`, exit 63, with a
/// sentence that names the number.
pub const max_messages: usize = 100_000;

/// How much room the connection keeps for bytes read and not taken yet.
pub const read_buffer_len: usize = 16384;

/// How much room the plain stream of a StartTLS upgrade keeps.
///
/// The upgrade writes one `ExtendedRequest` and reads one
/// `ExtendedResponse`, and neither is large. It is its own number because
/// the buffers behind it are fields of this value and every transfer pays
/// for them, an `ldap://` one included.
pub const upgrade_buffer_len: usize = 1024;

/// How long one read may wait with no byte arriving.
///
/// **Every wait an LDAP transfer makes needs this.** A search ends at a
/// `SearchResultDone` the server chooses to send, so a server that sends
/// nothing holds the transfer. `--connect-timeout` covers the dial and the
/// handshake and nothing after them.
///
/// 300 seconds is curl's own `--speed-time` default, and this is the same
/// question. `--speed-time` narrows it and never widens it.
pub const default_read_timeout_s: u32 = 300;

/// `default_read_timeout_s`, as a `std.Io.Timeout`.
pub const default_read_timeout: Io.Timeout = .{
    .duration = .{ .raw = .fromSeconds(default_read_timeout_s), .clock = .awake },
};

/// How many bytes of bind name and password this sends.
///
/// The name is a distinguished name, so it takes the bound
/// `target.max_dn_bytes` puts on the one in a url. The password is its
/// own, smaller number.
pub const max_bind_dn_bytes: usize = target.max_dn_bytes;

/// How many bytes of password this sends.
pub const max_password_bytes: usize = 1024;

/// How many bytes of the server's own `diagnosticMessage` reach a
/// diagnostic.
///
/// The text is the server's, and it goes to a user's terminal, so only the
/// first part of it is shown. `src/cli/safe.zig` is what makes it
/// printable after that.
pub const max_diagnostic_bytes: usize = 200;

/// The spelling curl gives a SASL mechanism inside a user name.
///
/// `-u 'name;AUTH=DIGEST-MD5'`. See the module doc comment: a bind name
/// holding it is refused rather than sent as part of a distinguished name
/// the user did not write.
pub const sasl_marker = ";AUTH=";

/// Where the transfer got the credential it sent.
pub const CredentialSource = enum {
    /// The user name and password in the url itself.
    userinfo,
    /// `Transfer.Options.credentials`, which `-u` fills.
    options,
    /// A `machine` or a `default` entry of the netrc text.
    netrc,
    /// Nobody named one, so the bind was anonymous.
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

/// One bind name and password, ready to send.
pub const Credentials = struct {
    /// The `name` of the `BindRequest`, which RFC 4511 section 4.2 makes
    /// a distinguished name. Empty is the anonymous bind.
    dn: []const u8,
    password: []const u8,
};

/// How the transfer puts TLS on the connection.
pub const TlsMode = enum {
    /// No TLS at all. This is a plain `ldap://` url.
    none,
    /// The handshake runs as soon as the socket opens. This is
    /// `ldaps://`, on port 636.
    implicit,
    /// The connection opens in the clear, then StartTLS, then the
    /// handshake. RFC 4511 section 4.14. This is `--ssl-reqd` on an
    /// `ldap://` url.
    explicit,
};

/// The trust store an encrypted session verifies against, and the way to
/// fill it.
///
/// **An `ldaps` session verifies exactly as an `https` session does.** The
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
pub const Options = struct {
    /// A cap on the dial, the StartTLS step, and the handshake together.
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
    /// The lowest TLS version to keep.
    tls_min_version: zurl_core.tls.MinVersion = .floor,
    /// The highest TLS version to keep.
    tls_max_version: zurl_core.tls.Version = .highest,
    /// The trust store for an encrypted session. See `Trust`.
    trust: ?Trust = null,
    /// How the connection gets TLS. See `TlsMode`.
    tls: TlsMode = .none,
    /// The credential `-u` named, or null.
    credentials: ?Credentials = null,
    /// The text of a netrc file the caller already read, or null.
    netrc_text: ?[]const u8 = null,
    /// The `sizeLimit` of the `SearchRequest`. Zero is the server's own
    /// limit, which is what curl sends.
    size_limit: i64 = 0,
    /// The `timeLimit` of the `SearchRequest`, in seconds. Zero is the
    /// server's own limit.
    time_limit: i64 = 0,
    /// Where a url naming one host and port dials instead. This is
    /// `--resolve` and `--connect-to`.
    ///
    /// **An entry moves the dial and nothing else.** `tlsOptions` reads
    /// `url.host`, so an `ldaps` peer at the dialed address must still
    /// hold a certificate for the name the url wrote. See
    /// `zurl_net.override`.
    connect_to: []const zurl_net.override.HostOverride = &.{},
};

allocator: std.mem.Allocator,
io: Io,
/// The answer of the transfer in play, or null when none is held.
answer: ?[]u8,
/// Reads `answer`. Valid only while `answer` holds something.
body: Io.Reader,
/// The message dialogue. Points at whichever channel is live.
session: Session,
/// Builds one request at a time.
request: message.RequestWriter,
/// Holds the decoded parts of the url.
url_storage: target.Storage,
/// Holds a credential decoded out of a url's userinfo, the name first and
/// the password after it.
credential_storage: [max_bind_dn_bytes + max_password_bytes]u8,
/// The plain stream a StartTLS upgrade speaks over, before the handshake.
/// Fields, and not locals of the step, because the session holds pointers
/// into them and the step returns before the session moves on.
upgrade_reader: std.Io.net.Stream.Reader,
upgrade_writer: std.Io.net.Stream.Writer,
upgrade_read_storage: [upgrade_buffer_len]u8,
upgrade_write_storage: [upgrade_buffer_len]u8,
/// What the StartTLS step recorded. See `runUpgrade`.
upgrade_fault: ?UpgradeFault,
/// How long one read may wait with no byte arriving.
///
/// A field, and not a parameter of the step, because `runUpgrade` runs
/// inside the connect race and takes only the opaque pointer.
stall: Io.Timeout,

/// Why the StartTLS step stopped.
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
        // The session's buffer outlives one transfer, so it is made here
        // and `begin` starts each dialogue over it.
        .session = .init(allocator, io),
        .request = .init(),
        .url_storage = undefined,
        .credential_storage = undefined,
        .upgrade_reader = undefined,
        .upgrade_writer = undefined,
        .upgrade_read_storage = undefined,
        .upgrade_write_storage = undefined,
        .upgrade_fault = null,
        .stall = default_read_timeout,
    };
}

/// Frees what this `Fetcher` holds. Safe to call more than once, and safe
/// on a `Fetcher` that never opened anything.
pub fn deinit(f: *Fetcher) void {
    f.release();
    f.session.deinit();
    f.wipe();
}

/// Frees the answer, after wiping it.
///
/// **The answer is a directory entry in the clear**, and a `userPassword`
/// is an attribute like any other, so the bytes are zeroed before the
/// free. That is the rule `zurl-scp` records.
fn release(f: *Fetcher) void {
    const held = f.answer orelse return;
    std.crypto.secureZero(u8, held);
    f.allocator.free(held);
    f.answer = null;
    // **The body reader is pointed at nothing, not left pointing at the
    // freed slice.** A caller that reads the `Body` of a transfer that
    // failed is outside the contract either way, and an empty read is a
    // better answer to that than a read of memory this just gave back.
    f.body = .fixed("");
}

/// Zeroes every buffer that held a credential or a directory entry.
fn wipe(f: *Fetcher) void {
    std.crypto.secureZero(u8, &f.credential_storage);
    // The request writer held the bind password.
    std.crypto.secureZero(u8, &f.request.bytes);
    f.request.reset();
}

/// The answer of one LDAP transfer.
pub const Body = struct {
    /// Streams the answer. Valid until the next `open` on this `Fetcher`,
    /// or until `deinit`, whichever comes first.
    reader: *Io.Reader,
    /// How many bytes the answer holds.
    length: u64,
    /// The `resultCode` of the `SearchResultDone`.
    ///
    /// **curl reports this as `%{http_code}`**, measured: a search that
    /// worked printed `000` and one whose base object was not there
    /// printed `032`, which is `noSuchObject`. A failing search does not
    /// return a `Body` at all, so this is `success` or
    /// `sizeLimitExceeded`.
    status: message.ResultCode,
    /// How many `SearchResultEntry` messages the search returned.
    entries: usize,
    /// How many `SearchResultReference` messages it returned. None of
    /// them was followed. See the module doc comment.
    references: usize,
    /// Whether the bind sent a credential somebody named.
    bound: bool,
};

/// Whether `url` asks for a TLS session on the connection.
///
/// The scheme and nothing else. Compared without regard to case, per RFC
/// 3986, so `LDAPS://` is as encrypted as `ldaps://`.
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
/// - a url this build will not send is `error.InvalidUrl`, exit 3, and no
///   socket opens at all. curl answers a bad scope and a bad url with the
///   same code, measured.
/// - a filter that does not parse is `error.InvalidUrl`, exit 3. curl
///   answers `error.LdapSearchFailed`, exit 39, for the same filter,
///   measured, and it answers it **after it has dialed and bound**. This
///   build refuses before it opens a socket, so a filter a user mistyped
///   never sends a credential anywhere.
/// - a peer that does not accept a connection is `error.CouldNotConnect`,
///   exit 7.
/// - a peer certificate that does not verify is
///   `error.PeerFailedVerification`, exit 60.
/// - a refused StartTLS under `--ssl-reqd` is `error.UseSslFailed`, exit
///   64, **and no credential goes out**.
/// - a bind the server refused is `error.LoginDenied`, exit 67, when the
///   result code is `invalidCredentials`, and `error.LdapCannotBind`, exit
///   38, otherwise. Both are curl's own codes, measured.
/// - a search the server refused is `error.LdapSearchFailed`, exit 39,
///   which is curl's own code, measured.
/// - an answer past `options.max_response_bytes` is
///   `error.FileSizeExceeded`, exit 63.
pub fn open(f: *Fetcher, url: zurl_core.Url, options: Options, d: ?*Diagnostics) Error!Body {
    f.release();
    f.upgrade_fault = null;
    f.stall = options.read_timeout;
    // The credential and the last request live in this value between
    // transfers, so both are zeroed on every path out.
    defer f.wipe();

    // **The url is read before anything is dialed**, and so is the
    // filter. A url this build will not send costs no socket and sends no
    // credential.
    const t = target.parse(&f.url_storage, url) catch |err| return reportTarget(err, d);
    f.request.reset();
    // The filter is built once here to prove it parses. `runSearch`
    // builds the real request later, with the message id it will carry.
    message.writeSearch(&f.request, 1, &t, options.size_limit, options.time_limit) catch |err|
        return reportRequest(err, d);

    var credential_source: CredentialSource = undefined;
    const credentials = try f.resolveCredentials(url, options, &credential_source, d);

    const port = url.port orelse return fail(d, error.InvalidUrl, &.{
        "an ldap url names a port, and this one names none",
    });
    // **`--resolve` and `--connect-to` move this dial and nothing else.**
    // `tlsOptions` below reads `url.host`, so an `ldaps` peer at the
    // dialed address must still hold a certificate for the name the url
    // wrote. See `zurl_net.override`.
    const target_peer = zurl_net.override.dialTarget(options.connect_to, url.host, port);
    // A host that does not read and a host name no resolver can look up
    // are two faults, exit 3 and exit 6. See `zurl_net.errors.hostInit`.
    const host = zurl_net.tcp.Host.init(target_peer.host) catch |err| return fail(d, zurl_net.errors.hostInit(err).err, &.{
        target_peer.faultPrefix(err),
        target_peer.host,
    });

    const tls = try tlsOptions(url.host, options, d);

    // **The dial, the StartTLS step, and the handshake share one
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

    const channel: zurl_net.line.Channel = .{
        .reader = connection.reader(),
        .writer = connection.writer(),
        .ctx = &connection,
        .flush = flushConnection,
    };
    // **An explicit upgrade was already speaking**, over the plain stream,
    // so it keeps the session it has and only changes where the bytes go.
    // The message ids run on across the change, which is what
    // `Session.retarget` is for.
    if (options.tls == .explicit) {
        f.session.retarget(channel);
    } else {
        f.session.begin(channel, options.read_timeout);
    }
    // The session buffer holds whatever the last entry was.
    defer f.session.wipe();

    try f.runBind(&connection, credentials, credential_source, d);

    var collected: std.ArrayList(u8) = .empty;
    // **Wiped before it is freed, the same as `release` does.** These are
    // directory entries, and a `userPassword` is an attribute like any
    // other. Every failure after the first entry is written reaches this,
    // and it was the one free in this package that skipped the rule.
    errdefer {
        std.crypto.secureZero(u8, collected.items);
        collected.deinit(f.allocator);
    }
    var sink: ldif.Sink = .{
        .gpa = f.allocator,
        .out = &collected,
        .limit = options.max_response_bytes,
    };
    const outcome = try f.runSearch(&connection, &t, options, &sink, d);

    // The unbind is a courtesy and never a gate. RFC 4511 section 4.3 says
    // the server answers it by closing, so there is nothing to read after
    // it and a server that will not take it has cost this transfer
    // nothing.
    f.sendUnbind() catch {};

    const answer = collected.toOwnedSlice(f.allocator) catch
        return Diagnostics.record(d, error.OutOfMemory, .{});
    f.answer = answer;
    f.body = .fixed(answer);
    return .{
        .reader = &f.body,
        .length = answer.len,
        .status = outcome.code,
        .entries = outcome.entries,
        .references = outcome.references,
        .bound = credentials.dn.len != 0 or credentials.password.len != 0,
    };
}

/// What one search returned.
const Outcome = struct {
    code: message.ResultCode,
    entries: usize,
    references: usize,
};

/// Sends the `BindRequest` and reads its answer.
///
/// **A bind always goes out.** An empty name and an empty password is the
/// anonymous simple bind, which is what curl sends for a url with no
/// credential, measured. RFC 4511 section 5.1.1 makes it a real operation.
fn runBind(
    f: *Fetcher,
    connection: ?*zurl_net.Connection,
    credentials: Credentials,
    source: CredentialSource,
    d: ?*Diagnostics,
) Error!void {
    const id = f.session.takeId() catch return fail(d, error.LdapCannotBind, &.{
        "this ldap session has sent every message id RFC 4511 allows",
    });
    message.writeBind(&f.request, id, credentials.dn, credentials.password) catch |err|
        return reportRequest(err, d);
    f.session.send(f.request.written()) catch |err|
        return reportSession(err, connection, "the bind request", d);

    const m = f.session.receive(id) catch |err|
        return reportSession(err, connection, "the bind answer", d);
    if (m.kind != .bind_response) return fail(d, error.LdapCannotBind, &.{
        "the ldap server answered the bind with an operation that is not a BindResponse",
    });

    const r = message.result(m.op) catch |err| return reportResultCode(m, err, d);
    if (r.code == .success) return;

    // **A server asking for SASL is reported with its own words**, and
    // nothing weaker is tried. See the module doc comment.
    const mapped = mapResultCode(r.code, error.LdapCannotBind);
    return failResult(d, mapped, &.{
        "the ldap server refused the bind built from ",
        source.describe(),
        ": ",
    }, r);
}

/// Sends the `SearchRequest`, reads every reply, and writes the text.
///
/// **A `SearchResultReference` is read past and never followed.** It names
/// another server, and following one would send the bind credential to a
/// host the server chose. curl 8.21.0 does worse than not follow it:
/// measured, it stops the search at the first reference and prints no
/// entry after it. This build counts the reference, writes nothing for it,
/// and carries on to the `SearchResultDone`, so a subtree holding a
/// referral gives every entry that is actually in it.
///
/// **`sizeLimitExceeded` ends the search and is not a failure.** curl
/// reads it as a completed search, measured in its own source and in its
/// exit code, and it prints the entries that did arrive. So does this.
fn runSearch(
    f: *Fetcher,
    connection: *zurl_net.Connection,
    t: *const target.Target,
    options: Options,
    sink: *ldif.Sink,
    d: ?*Diagnostics,
) Error!Outcome {
    const id = f.session.takeId() catch return fail(d, error.LdapSearchFailed, &.{
        "this ldap session has sent every message id RFC 4511 allows",
    });
    message.writeSearch(&f.request, id, t, options.size_limit, options.time_limit) catch |err|
        return reportRequest(err, d);
    f.session.send(f.request.written()) catch |err|
        return reportSession(err, connection, "the search request", d);

    var entries: usize = 0;
    var references: usize = 0;
    var seen: usize = 0;
    while (true) {
        // **The bound on round trips.** See `max_messages`.
        if (seen == max_messages) return failNumber(
            d,
            error.FileSizeExceeded,
            "the ldap server sent more than the ",
            max_messages,
            " messages zurl reads from one search",
        );
        seen += 1;

        const m = f.session.receive(id) catch |err|
            return reportSession(err, connection, "a search answer", d);

        switch (m.kind) {
            .search_entry => {
                entries += 1;
                try writeEntry(m, sink, d);
            },
            .search_reference => {
                references += 1;
                // Nothing is written for it, which is what curl's output
                // holds for one too.
            },
            .search_done => {
                const r = message.result(m.op) catch |err| return reportResultCode(m, err, d);
                switch (r.code) {
                    .success, .size_limit_exceeded => return .{
                        .code = r.code,
                        .entries = entries,
                        .references = references,
                    },
                    else => return failResult(d, mapResultCode(r.code, error.LdapSearchFailed), &.{
                        "the ldap server refused the search: ",
                    }, r),
                }
            },
            .bind_response, .extended_response => return fail(d, error.LdapSearchFailed, &.{
                "the ldap server answered the search with an operation that answers no search",
            }),
        }
    }
}

/// Writes one `SearchResultEntry` into the answer.
fn writeEntry(m: message.Message, sink: *ldif.Sink, d: ?*Diagnostics) Error!void {
    var e = message.entry(m.op) catch |err| return reportRead(err, "a search result entry", d);
    ldif.writeDn(sink, e.dn) catch |err| return reportSink(err, d);

    while (true) {
        const attribute = message.nextAttribute(&e.attributes) catch |err|
            return reportRead(err, "an attribute of a search result entry", d);
        const one = attribute orelse break;

        var values = one.values;
        var count: usize = 0;
        while (true) {
            const value = message.nextValue(&values) catch |err|
                return reportRead(err, "a value of a search result entry", d);
            const bytes = value orelse break;
            count += 1;
            ldif.writeValue(sink, one.description, bytes) catch |err| return reportSink(err, d);
        }

        // An attribute the server sent with no values writes one line and
        // no blank line. See `ldif.zig`.
        if (count == 0) {
            ldif.writeEmptyAttribute(sink, one.description) catch |err| return reportSink(err, d);
        } else {
            ldif.writeAttributeEnd(sink) catch |err| return reportSink(err, d);
        }
    }

    ldif.writeEntryEnd(sink) catch |err| return reportSink(err, d);
}

/// Sends the `UnbindRequest`.
fn sendUnbind(f: *Fetcher) !void {
    const id = try f.session.takeId();
    try message.writeUnbind(&f.request, id);
    try f.session.send(f.request.written());
}

/// The `zurl_core.Error` an LDAP result code carries.
///
/// **This is curl's own map, `oldap_map_error` of `lib/openldap.c`, read
/// in the source and confirmed against the binary.** Four codes get a name
/// of their own and every other one gets the caller's default, which is
/// `LdapCannotBind` for a bind and `LdapSearchFailed` for a search.
///
/// Measured against curl 8.21.0 on a real slapd 2.6.13: a wrong password
/// gave exit 67, a bind name that is not a distinguished name gave exit
/// 38, and a base object that is not in the directory gave exit 39.
pub fn mapResultCode(code: message.ResultCode, default: Error) Error {
    return switch (code) {
        .invalid_credentials => error.LoginDenied,
        .protocol_error => error.UnsupportedProtocol,
        .insufficient_access_rights => error.FtpAccessDenied,
        else => default,
    };
}

/// The credential this transfer binds with, or the anonymous one.
///
/// The url's userinfo first, then `-u`, then a netrc entry for the url's
/// host. That is the order `zurl.authorize` keeps for HTTP and the order
/// curl keeps here.
///
/// **The name is the bind DN and not a user name.** RFC 4511 section 4.2
/// makes the `name` of a `BindRequest` an `LDAPDN`, so `-u` carries
/// something like `cn=admin,dc=example,dc=com`. curl passes the value
/// straight through as the bind DN, measured: `-u 'cn=admin,dc=zurl,
/// dc=test:secret'` reached the wire as `04 18 "cn=admin,dc=zurl,dc=test"
/// 80 06 "secret"`.
///
/// **The userinfo is percent-decoded and the other two are not.** A url
/// writes a credential escaped, so `%3D` in a bind DN is an `=`. `-u` and
/// a netrc file are read as they are written, which is what curl does.
///
/// **No byte of a credential needs a gate here, and that is worth saying
/// once.** BER counts the octets in front of a value, so a CR, an LF, or a
/// NUL in a password is data on the wire and can end nothing. Every line
/// protocol in this repository has to refuse those three; this one does
/// not, and `message.zig`'s test "a password of any bytes at all reaches
/// the wire whole" is the proof.
///
/// **A name holding curl's `;AUTH=` is refused.** See the module doc
/// comment: this build has no SASL, and sending that text as part of a
/// distinguished name would bind as a name the user did not write.
fn resolveCredentials(
    f: *Fetcher,
    url: zurl_core.Url,
    options: Options,
    source: *CredentialSource,
    d: ?*Diagnostics,
) Error!Credentials {
    const resolved: Credentials = found: {
        if (url.user) |raw_user| {
            source.* = .userinfo;
            if (raw_user.len > max_bind_dn_bytes) return failCredentialSize(d);
            const dn = zurl_core.url.percentDecode(
                f.credential_storage[0..raw_user.len],
                raw_user,
            ) catch return fail(d, error.InvalidUrl, &.{
                "the bind name in this url holds a percent escape that is not an escape",
            });

            const password = if (url.password) |raw_password| pw: {
                if (raw_password.len > max_password_bytes) return failCredentialSize(d);
                break :pw zurl_core.url.percentDecode(
                    f.credential_storage[max_bind_dn_bytes..][0..raw_password.len],
                    raw_password,
                ) catch return fail(d, error.InvalidUrl, &.{
                    "the password in this url holds a percent escape that is not an escape",
                });
            } else "";

            break :found .{ .dn = dn, .password = password };
        }

        if (options.credentials) |c| {
            source.* = .options;
            break :found c;
        }

        if (options.netrc_text) |text| {
            if (zurl_core.netrc.lookup(text, url.host)) |entry| {
                source.* = .netrc;
                break :found .{
                    .dn = entry.login orelse "",
                    .password = entry.password orelse "",
                };
            }
        }

        source.* = .none;
        break :found .{ .dn = "", .password = "" };
    };

    if (std.mem.indexOf(u8, resolved.dn, sasl_marker) != null) {
        return fail(d, error.NotBuiltIn, &.{
            "the bind name from ",
            source.*.describe(),
            " names a SASL mechanism with ;AUTH=, and this build of zurl sends only the simple bind of RFC 4511 section 4.2",
        });
    }
    if (resolved.dn.len > max_bind_dn_bytes or resolved.password.len > max_password_bytes) {
        return failCredentialSize(d);
    }
    // **A control byte in a bind name is refused, and not because BER
    // needs it.** BER carries any byte. The name reaches a diagnostic
    // when the bind fails, and a distinguished name RFC 4514 writes holds
    // no raw control byte, so one here is a name nobody meant.
    if (filter.hasControlByte(resolved.dn)) {
        return fail(d, error.InvalidUrl, &.{
            "the bind name from ",
            source.*.describe(),
            " holds a control byte, and no distinguished name RFC 4514 writes holds one",
        });
    }
    return resolved;
}

/// The TLS options a session opens with, or null for a plain hop.
///
/// **This is the one place in this package that turns peer verification
/// off, and it reads `options.insecure` and nothing else.** A function and
/// not a few lines inside `open`, so a test can name both answers and
/// prove that no other input can reach the second one. `zurl-pop3`,
/// `zurl-ftp`, and `zurl-gopher` keep the same shape.
///
/// **A build with no trust store cannot open an encrypted session.** The
/// `null` arm reports `error.SslConnectError` rather than fall back to
/// `.none`, because that fallback is exactly the hole this package must
/// not open.
fn tlsOptions(host: []const u8, options: Options, d: ?*Diagnostics) Error!?zurl_net.Connection.Tls {
    if (options.tls == .none) return null;
    return try sessionOptions(host, options, d);
}

/// The options one TLS session opens with.
fn sessionOptions(host: []const u8, options: Options, d: ?*Diagnostics) Error!zurl_net.Connection.Tls {
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
        "this build gave the ldap package no trust store, so it cannot verify an ldaps peer",
    });
    try trust.load(trust.ptr);

    return .{
        .host = .{ .explicit = host },
        .trust = .{ .bundle = .{ .lock = trust.lock, .bundle = trust.bundle } },
        .min_version = options.tls_min_version,
        .max_version = options.tls_max_version,
        // **No ALPN extension at all.** RFC 7301 needs a registered
        // protocol name and LDAP has none.
        .alpn_protocols = &.{},
        // `allow_truncation_attacks` keeps its default, which is false. A
        // search ends at a `SearchResultDone` the server sends, so a
        // middle box that cut the session early is already caught by the
        // missing message, and a session that ends with no `close_notify`
        // is still a fault to report.
    };
}

/// The StartTLS step, run inside the connect race.
///
/// **This runs on a plain stream and it sends no credential.** RFC 4511
/// section 4.14 puts the extended operation before the handshake, so that
/// one exchange crosses in the clear and nothing else does. The
/// `BindRequest` goes out after the handshake, from `open`.
fn runUpgrade(ctx: *anyopaque, io: Io, stream: std.Io.net.Stream) bool {
    const f: *Fetcher = @ptrCast(@alignCast(ctx));
    f.upgrade_fault = f.upgradeStep(io, stream);
    return f.upgrade_fault == null;
}

/// Runs the step, and returns why it stopped, or null when it worked.
fn upgradeStep(f: *Fetcher, io: Io, stream: std.Io.net.Stream) ?UpgradeFault {
    f.upgrade_reader = .init(stream, io, &f.upgrade_read_storage);
    f.upgrade_writer = .init(stream, io, &f.upgrade_write_storage);
    // The step runs as a raced task, and `bounded.setup` hands it the `Io`
    // that task runs on. It is the same value `init` was given, and it is
    // taken from here rather than assumed so a caller that races on
    // another one still reads and writes on the right one.
    f.session.io = io;
    f.session.begin(.{
        .reader = &f.upgrade_reader.interface,
        .writer = &f.upgrade_writer.interface,
        .ctx = &f.upgrade_writer,
        .flush = flushStream,
    }, f.stall);

    const id = f.session.takeId() catch return .{
        .err = error.UseSslFailed,
        .message = "this ldap session has no message id left for StartTLS",
    };
    message.writeStartTls(&f.request, id) catch return .{
        .err = error.UseSslFailed,
        .message = "zurl did not build the StartTLS request",
    };
    f.session.send(f.request.written()) catch return .{
        .err = error.UseSslFailed,
        .message = "zurl did not write the StartTLS request",
    };

    const m = f.session.receive(id) catch return .{
        .err = error.UseSslFailed,
        .message = "zurl did not read the answer to StartTLS",
    };
    if (m.kind != .extended_response) return .{
        .err = error.UseSslFailed,
        .message = "the ldap server answered StartTLS with an operation that is not an ExtendedResponse",
    };

    const r = message.result(m.op) catch return .{
        .err = error.UseSslFailed,
        .message = "the ldap server answered StartTLS with a result zurl cannot read",
    };
    if (r.code != .success) return .{
        .err = error.UseSslFailed,
        .message = "the ldap server refused StartTLS, and zurl sends no credential over a connection that was asked to be encrypted and is not",
    };

    // **Nothing may be held across the handshake.** A server that wrote
    // bytes behind its answer wrote them in cleartext, and carrying them
    // into the session would hand a caller text a listener could have
    // chosen.
    if (f.session.buffered() != 0) return .{
        .err = error.UseSslFailed,
        .message = "the ldap server wrote more bytes behind its StartTLS answer, and those bytes are not inside the session",
    };

    return null;
}

/// Empties both buffers of a `zurl_net.Connection`.
fn flushConnection(ctx: ?*anyopaque) Io.Writer.Error!void {
    const connection: *zurl_net.Connection = @ptrCast(@alignCast(ctx.?));
    connection.flush() catch return error.WriteFailed;
}

/// Empties the buffer of a plain stream writer, which the StartTLS step
/// writes through.
fn flushStream(ctx: ?*anyopaque) Io.Writer.Error!void {
    const writer: *std.Io.net.Stream.Writer = @ptrCast(@alignCast(ctx.?));
    return writer.interface.flush();
}

/// The `zurl_core.Error` one session fault means.
///
/// Every name is listed, so a new one in `Session.Error` is a compile
/// error here and never a fault that reaches a user under the wrong
/// number.
fn sessionFault(err: Session.Error) Error {
    return switch (err) {
        // A message this build cannot read is a server speaking something
        // that is not the LDAP this build knows.
        error.Truncated,
        error.TagTooLarge,
        error.IndefiniteLength,
        error.LengthTooLarge,
        error.NestingTooDeep,
        error.UnexpectedTag,
        error.ValueOutOfRange,
        error.WrongForm,
        error.UnknownOperation,
        error.UnknownResultCode,
        error.MessageIdMismatch,
        error.ServerDisconnecting,
        => error.WeirdServerReply,
        // A bound this build keeps, and not a fault on the wire.
        error.ElementTooLarge, error.MessageTooLarge => error.FileSizeExceeded,
        error.MessageIdExhausted => error.LdapSearchFailed,
        error.EndOfStream => error.PartialFile,
        error.OperationTimedOut => error.OperationTimedOut,
        error.Canceled => error.AbortedByCallback,
        error.OutOfMemory => error.OutOfMemory,
        error.ReadFailed, error.ReadTimeoutUnsupported => error.ReadError,
        error.WriteFailed => error.WriteError,
    };
}

/// Reports a fault on the session, with the step it happened on.
fn reportSession(
    err: Session.Error,
    connection: ?*zurl_net.Connection,
    step: []const u8,
    d: ?*Diagnostics,
) Error {
    const mapped = sessionFault(err);
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
    return fail(d, mapped, &.{ "the ldap connection failed on ", step, ": ", cause });
}

/// Reports a message this build could not read.
fn reportRead(err: message.ReadError, what: []const u8, d: ?*Diagnostics) Error {
    return fail(d, sessionFault(err), &.{
        "zurl could not read ",
        what,
        ": ",
        @errorName(err),
    });
}

/// Reports a result whose code this build has no name for.
///
/// **The number is kept.** A user who reads "the server answered 91" can
/// look 91 up; one who reads "a code with no name" cannot.
fn reportResultCode(m: message.Message, err: message.ReadError, d: ?*Diagnostics) Error {
    if (err != error.UnknownResultCode) {
        return reportRead(err, "the result of an ldap operation", d);
    }
    const number = message.resultCodeNumber(m.op) catch
        return reportRead(err, "the result of an ldap operation", d);
    var digits: [12]u8 = undefined;
    const text = std.fmt.bufPrint(&digits, "{d}", .{number}) catch digits[0..0];
    return fail(d, error.WeirdServerReply, &.{
        "the ldap server answered with result code ",
        text,
        ", which RFC 4511 does not name",
    });
}

/// Every fault building one request can report.
///
/// The two sets merge by name, which is why `ber.Writer.Error` calls its
/// own unbalanced case `NothingOpen` and `filter.ParseError` keeps
/// `Unbalanced`: one name for the two would give the switch below one arm
/// for a fault in a url and a fault in this build, which are two different
/// sentences to a user.
const RequestFault = filter.ParseError || message.RequestWriter.Error;

/// Reports a request this build would not send.
fn reportRequest(err: RequestFault, d: ?*Diagnostics) Error {
    const sentence: []const u8 = switch (err) {
        error.Unbalanced => "the filter in this url does not start with ( or does not end with )",
        error.Truncated => "the filter in this url ends in the middle of an item",
        error.TrailingText => "the filter in this url carries text after its closing parenthesis",
        error.NestingTooDeep => "the filter in this url nests deeper than zurl reads",
        error.NotNeedsOneFilter => "a ! in the filter of this url holds no filter, or more than one",
        error.FilterTooLong => "the filter in this url is longer than zurl reads",
        error.BadAttribute => "the filter in this url names an attribute holding a byte RFC 4512 gives no attribute description",
        error.MissingFilterType => "an item of the filter in this url carries no =, ~=, >=, or <=",
        error.UnescapedParen => "a value in the filter of this url holds a bare ( or ), and RFC 4515 writes each as \\28 and \\29",
        error.UnescapedAsterisk => "a value in the filter of this url holds a bare *, and RFC 4515 writes it as \\2a",
        error.UnescapedNul => "a value in the filter of this url holds a NUL, and RFC 4515 writes it as \\00",
        error.BadEscape => "a \\ in the filter of this url is not followed by two hexadecimal digits",
        error.ValueTooLong => "a value in the filter of this url is longer than zurl sends",
        error.EmptySubstring => "a substring match in the filter of this url asserts nothing at all",
        error.BadExtensibleMatch => "an extensible match in the filter of this url names neither a matching rule nor an attribute",
        error.NoRoom => "the request this url asks for is longer than zurl sends",
        error.TooDeep => "the request this url asks for nests deeper than zurl writes",
        // A programmer error in this package and not a fault in the url.
        // It is reported and never asserted, so a caller of the module
        // cannot crash a process with it.
        error.NothingOpen => "zurl built a malformed ldap request, which is a defect in zurl",
    };
    return fail(d, error.InvalidUrl, &.{sentence});
}

/// Reports a url this package will not send.
fn reportTarget(err: target.ParseError, d: ?*Diagnostics) Error {
    const sentence: []const u8 = switch (err) {
        error.InvalidEscape => "this url holds a percent escape that is not an escape",
        error.DnTooLong => "the distinguished name in this url is longer than zurl sends",
        error.DnHasControlByte => "the distinguished name in this url holds a control byte, and a newline in one would draw a line in the answer that reads like another entry",
        error.TooManyAttributes => "this url names more attributes than zurl asks for",
        error.BadAttribute => "this url names an attribute holding a byte RFC 4512 gives no attribute description",
        error.BadScope => "the scope in this url is not base, one, or sub",
        error.FilterTooLong => "the filter in this url is longer than zurl reads",
        error.FilterHasControlByte => "the filter in this url holds a control byte",
        error.TooManyParts => "this url carries more than the five parts RFC 4516 names",
        error.ExtensionUnsupported => "this url names an LDAP url extension, and this build of zurl carries none, so it will not run a url whose extension it would have to ignore",
    };
    return fail(d, error.InvalidUrl, &.{sentence});
}

/// Reports a fault writing the answer.
fn reportSink(err: ldif.Error, d: ?*Diagnostics) Error {
    return switch (err) {
        error.OutOfMemory => Diagnostics.record(d, error.OutOfMemory, .{}),
        error.AnswerTooLarge => fail(d, error.FileSizeExceeded, &.{
            "the ldap answer is longer than the bytes zurl reads from one transfer",
        }),
        error.FieldTooLarge => fail(d, error.WeirdServerReply, &.{
            "the ldap server sent a name or a value longer than zurl writes",
        }),
        // **The refusal that keeps a server from drawing its own entry.**
        // See `ldif.checkAttribute`.
        error.BadAttributeDescription => fail(d, error.WeirdServerReply, &.{
            "the ldap server sent an attribute description holding a byte RFC 4512 gives no attribute description, and such a name written into the answer would draw a line of the server's own choosing",
        }),
    };
}

/// Reports a dial or handshake fault.
///
/// **A StartTLS step that failed reports its own reason**, which it
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

/// `fail`, with the result code's own words and the server's own words on
/// the end of the sentence.
///
/// **The server's text is bounded here and sanitised later.** Only the
/// first `max_diagnostic_bytes` reach the message, and `src/cli/safe.zig`
/// is what makes those printable.
fn failResult(
    d: ?*Diagnostics,
    err: Error,
    parts: []const []const u8,
    r: message.Result,
) Error {
    const shown = r.diagnostic[0..@min(r.diagnostic.len, max_diagnostic_bytes)];
    var all: [8][]const u8 = undefined;
    var at: usize = 0;
    for (parts) |part| {
        if (at == all.len - 2) break;
        all[at] = part;
        at += 1;
    }
    all[at] = r.code.describe();
    at += 1;
    if (shown.len != 0) {
        all[at] = ": ";
        at += 1;
        if (at < all.len) {
            all[at] = shown;
            at += 1;
        }
    }
    return fail(d, err, all[0..at]);
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
        max_bind_dn_bytes,
        " bytes one ldap bind name carries",
    );
}

/// Returns the dispatch entry for the plain `ldap` scheme.
///
/// `Front` is the front package's own namespace, taken as a comptime
/// parameter. Passing the namespace rather than importing it is what keeps
/// this package free of a `zurl` import.
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
        // run direct. curl carries ldap through a proxy and this build
        // does not. See `Front.protocol.Unread`.
        .unread = .{ .proxy = true },
    };
}

/// Returns the dispatch entry for the `ldaps` scheme. See `protocol`.
///
/// The port is 636 and not 389, because `ldaps://` is implicit TLS and
/// that is the port implicit TLS uses.
pub fn secureProtocol(f: *Fetcher, comptime Front: type) Front.protocol.Protocol {
    return .{
        .scheme = secure_scheme,
        .default_port = secure_default_port,
        .ptr = f,
        .vtable = &Dispatch(Front).vtable,
        .unread = .{ .proxy = true },
    };
}

/// The vtable for one front package. One instantiation for each `Front`,
/// and each one holds a single comptime constant, so the table lives in
/// the binary's own read-only data and never on a stack.
fn Dispatch(comptime Front: type) type {
    return struct {
        const vtable: Front.protocol.Protocol.VTable = .{ .perform = performLdap };

        fn performLdap(
            ptr: ?*anyopaque,
            c: *Front.Client,
            url: zurl_core.Url,
            options: Front.Transfer.Options,
            d: ?*Diagnostics,
        ) Error!Front.Response {
            const f: *Fetcher = @ptrCast(@alignCast(ptr.?));
            const body = try f.open(url, translate(c, url, options), d);
            return .{
                // curl reports the LDAP result code as `%{http_code}`,
                // measured: a search that worked printed `000`.
                .status = @intCast(@intFromEnum(body.status)),
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
        /// **The scheme decides the TLS mode.** `ldaps://` is implicit,
        /// and `ldap://` with `--ssl-reqd` is a StartTLS.
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
                    .{ .dn = credential.user, .password = credential.password }
                else
                    null,
                .netrc_text = options.netrc_text,
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
            ftp_ssl_required: bool = false,
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
pub fn parseLdapUrl(text: []const u8) !zurl_core.Url {
    var schemes: zurl_core.url.Schemes = .empty;
    try schemes.add(.{ .name = scheme, .default_port = default_port });
    try schemes.add(.{ .name = secure_scheme, .default_port = secure_default_port });
    return zurl_core.url.parseWith(text, &schemes);
}

test {
    _ = test_server;
}

test "the two schemes name the two ports curl dials" {
    try testing.expectEqualStrings("ldap", scheme);
    try testing.expectEqualStrings("ldaps", secure_scheme);
    try testing.expectEqual(@as(?u16, 389), default_port);
    try testing.expectEqual(@as(?u16, 636), secure_default_port);
}

test "both schemes share one vtable, because they share one protocol" {
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    const plain = f.protocol(StubFront);
    const secure = f.secureProtocol(StubFront);
    try testing.expect(plain.vtable == secure.vtable);
    try testing.expectEqualStrings("ldap", plain.scheme);
    try testing.expectEqualStrings("ldaps", secure.scheme);
}

test "both dispatch entries refuse a proxy by name rather than run direct" {
    // **`-x` must not fail open.** This package dials the origin itself
    // and reads no proxy field, so a transfer that named a proxy is
    // refused with exit 4 rather than connected direct. Eight other
    // packages here keep the same rule.
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    try testing.expect(f.protocol(StubFront).unread.proxy);
    try testing.expect(f.secureProtocol(StubFront).unread.proxy);
    // This package does read a credential, so it says nothing about one.
    try testing.expect(!f.protocol(StubFront).unread.credentials);
    try testing.expect(!f.secureProtocol(StubFront).unread.credentials);
}

test "isSecure reads the scheme and nothing else" {
    try testing.expect(isSecure(try parseLdapUrl("ldaps://h/dc=a")));
    try testing.expect(isSecure(try parseLdapUrl("LDAPS://h/dc=a")));
    try testing.expect(!isSecure(try parseLdapUrl("ldap://h/dc=a")));
}

test "curl's result code map is this build's result code map" {
    // Read in curl's `oldap_map_error` and confirmed against the binary:
    // a wrong password gave exit 67 and a bind name that is not a
    // distinguished name gave exit 38.
    const errors = zurl_core.errors;
    try testing.expectEqual(@as(u32, 67), errors.curlCode(
        mapResultCode(.invalid_credentials, error.LdapCannotBind),
    ));
    try testing.expectEqual(@as(u32, 38), errors.curlCode(
        mapResultCode(.invalid_dn_syntax, error.LdapCannotBind),
    ));
    try testing.expectEqual(@as(u32, 39), errors.curlCode(
        mapResultCode(.no_such_object, error.LdapSearchFailed),
    ));
    try testing.expectEqual(@as(u32, 1), errors.curlCode(
        mapResultCode(.protocol_error, error.LdapSearchFailed),
    ));
    try testing.expectEqual(@as(u32, 9), errors.curlCode(
        mapResultCode(.insufficient_access_rights, error.LdapSearchFailed),
    ));
    // A bind failure and a search failure take different defaults, so the
    // same code lands on two numbers depending on which operation it
    // answered. That is curl's shape too.
    try testing.expectEqual(@as(u32, 38), errors.curlCode(
        mapResultCode(.unwilling_to_perform, error.LdapCannotBind),
    ));
    try testing.expectEqual(@as(u32, 39), errors.curlCode(
        mapResultCode(.unwilling_to_perform, error.LdapSearchFailed),
    ));
}

test "every session fault has a zurl error and none of them is a crash" {
    // The switch in `sessionFault` names every member, so a new one in
    // `Session.Error` is a compile error here. This walks the set and
    // proves each name has a number.
    inline for (@typeInfo(Session.Error).error_set.?) |field| {
        const err = @field(Session.Error, field.name);
        const mapped = sessionFault(err);
        _ = zurl_core.errors.curlCode(mapped);
    }
}

test "tlsOptions is the one place verification is turned off" {
    var client: StubFront.Client = .{};
    const materials = client.tlsMaterials();

    // A plain hop opens no session and reads no certificate file.
    try testing.expectEqual(@as(?zurl_net.Connection.Tls, null), try tlsOptions("h", .{
        .tls = .none,
        .trust = materials,
    }, null));
    try testing.expectEqual(@as(usize, 0), client.loads);

    // An encrypted hop verifies the host and the chain.
    const verified = (try tlsOptions("h", .{ .tls = .implicit, .trust = materials }, null)).?;
    try testing.expectEqualStrings("h", verified.host.explicit);
    try testing.expect(verified.trust == .bundle);
    try testing.expectEqual(@as(usize, 1), client.loads);

    // `-k` is the one input that reaches the other answer.
    const insecure = (try tlsOptions("h", .{
        .tls = .implicit,
        .trust = materials,
        .insecure = true,
    }, null)).?;
    try testing.expect(insecure.host == .none);
    try testing.expect(insecure.trust == .none);
    // `-k` loads no trust roots, because it verifies nothing.
    try testing.expectEqual(@as(usize, 1), client.loads);
}

test "a build with no trust store cannot open an ldaps session at all" {
    // The fallback this arm refuses is the hole: `ldaps` would then be a
    // way to reach a TLS session with no verification.
    var d: Diagnostics = .{};
    try testing.expectError(
        error.SslConnectError,
        tlsOptions("h", .{ .tls = .implicit, .trust = null }, &d),
    );
    try testing.expect(std.mem.indexOf(u8, d.message.?, "trust store") != null);
}

test "an ldaps session offers no ALPN protocol, because LDAP has none" {
    var client: StubFront.Client = .{};
    const session = (try tlsOptions("h", .{
        .tls = .implicit,
        .trust = client.tlsMaterials(),
    }, null)).?;
    try testing.expectEqual(@as(usize, 0), session.alpn_protocols.len);
}

test "a moved dial leaves an ldaps certificate checked against the url's own name" {
    // **The rule that keeps this flag from becoming a second `-k`.**
    // `open` hands this function `url.host`, so an `ldaps` peer at the
    // dialed address still has to hold a certificate for the name the url
    // wrote.
    var client: StubFront.Client = .{};
    const overrides: []const zurl_net.override.HostOverride = &.{.{
        .from_host = "dir.example.com",
        .from_port = 636,
        .to_host = "127.0.0.1",
        .to_port = 9999,
    }};

    const moved = zurl_net.override.dialTarget(overrides, "dir.example.com", 636);
    try testing.expectEqualStrings("127.0.0.1", moved.host);
    try testing.expectEqual(@as(u16, 9999), moved.port);

    const session = (try tlsOptions("dir.example.com", .{
        .tls = .implicit,
        .trust = client.tlsMaterials(),
        .connect_to = overrides,
    }, null)).?;
    try testing.expectEqualStrings("dir.example.com", session.host.explicit);
    try testing.expect(session.trust == .bundle);
}

test "the ldap translation carries --connect-to into this package" {
    var client: StubFront.Client = .{};
    const D = Dispatch(StubFront);
    const url = try parseLdapUrl("ldap://example.com/dc=a");

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
