//! Runs one `ftp://` or `ftps://` transfer: the control dialogue, the
//! login, the passive data connection, and the answer.
//!
//! A `Fetcher` owns the answer of the transfer in play. `open` frees
//! whatever the last call left and holds the new answer, so one `Fetcher`
//! serves one transfer at a time, the same rule `zurl.Client` keeps for
//! its own HTTP exchange.
//!
//! **A `Fetcher` must not move once `open` has run.** The body reader it
//! hands back points into this value, and so do the control dialogue's own
//! reader and writer.
//!
//! **One package owns both schemes.** RFC 959 names the dialogue, and
//! `ftps` changes neither the commands nor the answers: it puts the same
//! two inside TLS. `protocol` and `secureProtocol` build the two dispatch
//! entries, and both point at one vtable that reads `url.scheme`. The two
//! carry different default ports, 21 and 990, which is what curl uses.
//!
//! **Passive mode only.** `EPSV` first, `PASV` when the server refuses it,
//! and `PASV` alone when `--disable-epsv` asks for that.
//! Active mode, which is `PORT` and `EPRT`, is out of scope: it asks this
//! process to listen for an inbound connection, which needs a listener,
//! a reachable address, and a rule about who may connect to it. curl's
//! `-P`/`--ftp-port` is that flag and zurl does not have it.
//!
//! **The address a `PASV` answer names is ignored, and the data connection
//! reuses the address the control connection reached.** See `dataTarget`.
//! The answer's address is attacker-controlled, and dialing it turns this
//! client into a port scanner or a relay. The reused address is numeric on
//! purpose: a second dial by host name asks a resolver again, and an
//! answer that changed between the two dials moves the data connection to
//! a machine the ftp server never named.
//!
//! What this does not do: no upload, so `-T` on an `ftp://` url is not a
//! `STOR`. No `PWD`, which curl sends and reads for its own `--ftp-method`
//! choice. No `--ftp-method` at all: every directory of the path is its
//! own `CWD`, which is curl's own default, `multicwd`. No `MDTM`, no
//! `--ftp-create-dirs`, no `--ftp-pret`, no `--ftp-account`, and no
//! `CCC`.
//!
//! This file imports `zurl-core` and `zurl-net`. It does not import
//! `zurl`, and it never will. See `protocol`.

const Fetcher = @This();

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_net = @import("zurl-net");

const command = @import("command.zig");
const reply = @import("reply.zig");
const target = @import("target.zig");
const Control = @import("Control.zig");

const Io = std.Io;
const Error = zurl_core.Error;
const Diagnostics = zurl_core.Diagnostics;

/// The plain scheme this package handles.
pub const scheme = "ftp";

/// The encrypted scheme this package handles.
pub const secure_scheme = "ftps";

/// The port an `ftp://` url uses when it names none. RFC 959.
pub const default_port: ?u16 = 21;

/// The port an `ftps://` url uses when it names none.
///
/// 990, which is the implicit TLS port. curl 8.21.0 dials it for
/// `ftps://127.0.0.1/x`, measured with `curl -v`, and starts the handshake
/// on connect. `zurl_core.url.defaultPort` already held the same number.
pub const secure_default_port: ?u16 = 990;

/// The status an FTP transfer reports.
///
/// Zero. RFC 959 has reply codes and no HTTP status, and the two are not
/// the same thing: a `226` is not a `200`. curl prints `000` for
/// `%{http_code}` on an `ftp://` url that worked.
pub const status: u16 = 0;

/// How many bytes of answer this package reads by default.
///
/// An FTP data connection carries no length of its own: the server writes
/// and closes. `SIZE` gives a number before the transfer, but a server is
/// free to send more than it said, so the bound stands on its own.
///
/// 16 MiB, the number `zurl-dict`, `zurl-gopher`, and `zurl-tftp` keep.
/// `Options.max_response_bytes` raises it, and `--max-filesize` narrows
/// it.
pub const default_max_response_bytes: u64 = 16 * 1024 * 1024;

/// How much room a connection keeps for bytes read and not taken yet.
pub const read_buffer_len: usize = 8192;

/// How much room the written form of one address takes, port included.
///
/// `std.Io.net.IpAddress.format` writes an IPv6 address as
/// `[address]:port`. The longest address text is the 45 characters of an
/// IPv4-mapped form such as `ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255`,
/// and the brackets, the colon, and five port digits add eight more. 64 is
/// that number rounded up, so the print never has to be truncated.
pub const max_address_text: usize = 64;

/// How much room the plain stream of an `AUTH TLS` upgrade keeps.
///
/// The upgrade reads one greeting and one `AUTH` answer, so it is far
/// smaller than a data connection. It is its own number because the
/// buffers behind it are fields of this value and every byte of them is
/// paid for by every transfer, `ftp://` included.
pub const upgrade_buffer_len: usize = 1024;

/// How long one read may wait with no byte arriving.
///
/// **Every wait an FTP transfer makes needs this.** A reply that never
/// arrives holds the control connection, and a data connection that
/// carries nothing and never closes holds the transfer. `--connect-timeout`
/// covers the dial and the handshake and nothing after them.
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
    /// Nobody named one, so the transfer logged in anonymously.
    anonymous,

    /// Names this source for a message to a user. Names the source and
    /// never the credential, which is a secret.
    pub fn describe(s: CredentialSource) []const u8 {
        return switch (s) {
            .userinfo => "the user name and password in the url",
            .options => "the -u option",
            .netrc => "the netrc file",
            .anonymous => "the anonymous login",
        };
    }
};

/// One user name and password, ready to send.
pub const Credentials = struct {
    user: []const u8,
    password: []const u8,
};

/// How the transfer puts TLS on the control connection.
pub const TlsMode = enum {
    /// No TLS at all. This is a plain `ftp://` url.
    none,
    /// The handshake runs as soon as the socket opens, before the
    /// greeting. This is `ftps://`, and it is what curl does: measured,
    /// `curl ftps://host/` dials 990 and writes a ClientHello with no
    /// command before it.
    implicit,
    /// The greeting arrives in the clear, then `AUTH TLS`, then the
    /// handshake. RFC 4217. This is `--ssl-reqd` on an `ftp://` url, and
    /// it is what curl sends for that flag, measured.
    explicit,
};

/// The trust store an encrypted session verifies against, and the way to
/// fill it.
///
/// **An `ftps` session verifies exactly as an `https` session does.** The
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
    /// before the first handshake, and only for a transfer that speaks
    /// TLS.
    load: *const fn (ptr: *anyopaque) Error!void,
};

/// What one transfer may ask for.
///
/// A struct of this package's own, and not `zurl.Transfer.Options`,
/// because this package must build with no `zurl` in its import table.
/// `Dispatch` fills it from the front package's own options.
pub const Options = struct {
    /// A cap on the dial, the `AUTH TLS` step, and the handshake
    /// together. `.none` waits for as long as the operating system does.
    connect_timeout: Io.Timeout = .none,
    /// The bound on the answer. See `default_max_response_bytes`.
    max_response_bytes: u64 = default_max_response_bytes,
    /// How long one read may wait with no byte arriving. See
    /// `default_read_timeout_s`.
    read_timeout: Io.Timeout = default_read_timeout,
    /// Whether to turn Nagle's algorithm off. False is `--no-tcp-nodelay`.
    tcp_no_delay: bool = true,
    /// Whether to accept a peer certificate that does not verify. This is
    /// `-k`/`--insecure`, and it reaches nothing but `tlsOptions`.
    insecure: bool = false,
    /// The lowest TLS version to keep. `--tlsv1.2` and `--tlsv1.3`.
    tls_min_version: zurl_core.tls.MinVersion = .floor,
    /// The highest TLS version to keep. `--tls-max`.
    tls_max_version: zurl_core.tls.Version = .highest,
    /// The trust store for an encrypted session. See `Trust`.
    trust: ?Trust = null,
    /// How the control connection gets TLS. See `TlsMode`.
    tls: TlsMode = .none,
    /// The credential `-u` named, or null.
    credentials: ?Credentials = null,
    /// The text of a netrc file the caller already read, or null. This is
    /// `--netrc` and `--netrc-file`.
    netrc_text: ?[]const u8 = null,
    /// Whether a directory url lists names alone. This is `-l`, and it
    /// chooses `NLST` over `LIST`.
    list_only: bool = false,
    /// Whether every transfer uses the ASCII representation type.
    ///
    /// This is `-B`/`--use-ascii`. A listing is already `TYPE A`, so this
    /// changes only a file url: the transfer sends `TYPE A` for the file
    /// as well, and it converts the answer the way RFC 959 asks a
    /// receiver to. See `open`, which reads this once for both halves.
    use_ascii: bool = false,
    /// Whether `EPSV` stays out of the dialogue.
    ///
    /// This is `--disable-epsv`. The transfer sends `PASV` alone, for a
    /// server or a middlebox that answers `EPSV` with something the
    /// session cannot carry on from. **It does not make the address a
    /// `227` answer names any more trusted.** See `dataTarget`.
    disable_epsv: bool = false,
    /// Where the transfer resumes from, in bytes. Zero is the whole file.
    /// This is `-C`/`--continue-at`, and it becomes a `REST` command.
    resume_from: u64 = 0,
    /// The `-r`/`--range` value, exactly as the `Range` header writes it,
    /// or null. See `restFromRange`: only the open-ended form applies to
    /// FTP, and every other form is refused rather than half honoured.
    range: ?[]const u8 = null,
    /// Whether the address a `227` answer names may be dialed.
    ///
    /// **False is the default and it must stay false.** See `dataTarget`.
    /// This is curl's `--no-ftp-skip-pasv-ip`, and curl's own default is
    /// the same as this one.
    trust_pasv_address: bool = false,
    /// Where a url naming one host and port dials instead. This is
    /// `--resolve` and `--connect-to`.
    ///
    /// **An entry moves both dials and nothing else.** The control
    /// connection goes to the address the entry names, and the data
    /// connection follows it on its own, because `dataTarget` reuses the
    /// address the control connection reached and reads neither this
    /// field nor the address a `227` answer holds. A data connection left
    /// on the url's own host would reach a second machine, which is not
    /// what the user asked for.
    ///
    /// **It never reaches the name an `ftps` certificate is checked
    /// against.** `sessionOptions` takes `url.host` for both connections,
    /// so a peer at the dialed address must still hold a certificate for
    /// the name the url wrote. Any other reading would make this flag a
    /// way to turn verification off with no `-k`.
    ///
    /// curl behaves the same way, measured against a loopback RFC 959
    /// server: `curl --connect-to h:21:127.0.0.1:PORT ftp://h/f.txt` put
    /// the control connection on the loopback address and then opened the
    /// data connection to the same address, on the port the `227` answer
    /// named, while it said `Skip 10.99.99.99 for data connection`.
    ///
    /// See `zurl_net.override`.
    connect_to: []const zurl_net.override.HostOverride = &.{},
};

allocator: std.mem.Allocator,
io: Io,
/// The answer of the transfer in play, or null when none is held.
answer: ?[]u8,
/// Reads `answer`. Valid only while `answer` holds something.
body: Io.Reader,
/// The command and reply dialogue. Points at whichever channel is live.
control: Control,
/// The url path, decoded and split.
path: target.Target,
/// Holds a credential decoded out of a url's userinfo, the user first and
/// the password after it.
credential_storage: [max_credential_bytes * 2]u8,
/// The plain stream an `AUTH TLS` upgrade speaks over, before the
/// handshake. Fields, and not locals of the step, because the dialogue
/// holds pointers into them and the step returns before the dialogue
/// moves to the session.
upgrade_reader: std.Io.net.Stream.Reader,
upgrade_writer: std.Io.net.Stream.Writer,
upgrade_read_storage: [upgrade_buffer_len]u8,
upgrade_write_storage: [upgrade_buffer_len]u8,
/// What the `AUTH TLS` step recorded. See `runUpgrade`.
upgrade_fault: ?UpgradeFault,
/// How long one reply read may wait with no byte arriving.
///
/// A field, and not a parameter of the step, because `runUpgrade` runs
/// inside the connect race and takes only the opaque pointer. `open` sets
/// it before the race starts.
stall: Io.Timeout,

/// Why the `AUTH TLS` step stopped.
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
        .upgrade_reader = undefined,
        .upgrade_writer = undefined,
        .upgrade_read_storage = undefined,
        .upgrade_write_storage = undefined,
        .upgrade_fault = null,
        .stall = default_read_timeout,
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

/// The answer of one FTP transfer.
pub const Body = struct {
    /// Streams the answer. Valid until the next `open` on this `Fetcher`,
    /// or until `deinit`, whichever comes first.
    reader: *Io.Reader,
    /// How many bytes the answer holds. Always known, because the whole
    /// answer is read before this returns.
    length: u64,
    /// What the server answered to `SIZE`, or null when it answered no
    /// number or the transfer sent no `SIZE`. It is the size of the whole
    /// file and not of the bytes read, so a resumed transfer reports the
    /// file's size here and the bytes it took in `length`.
    size: ?u64,
    /// Whether the transfer listed a directory rather than fetch a file.
    listing: bool,
};

/// Whether `url` asks for a TLS session on the control connection.
///
/// The scheme and nothing else. Compared without regard to case, per RFC
/// 3986, so `FTPS://` is as encrypted as `ftps://`.
pub fn isSecure(url: zurl_core.Url) bool {
    return std.ascii.eqlIgnoreCase(url.scheme, secure_scheme);
}

/// Every fault picking the data connection's target can report.
pub const DataTargetError = error{
    /// This build could not read the numeric address the control
    /// connection reached, so there is no address to reuse.
    ///
    /// **The transfer stops here rather than look the host name up a
    /// second time.** The second lookup is the hole this function closes.
    /// See `zurl_net.tcp.peerAddress`: only a build for Windows or WASI
    /// lands here, because Zig 0.16 gives `std.posix.getpeername` no body
    /// for either one.
    ControlPeerUnknown,
};

/// Where the data connection dials.
///
/// **This is the security decision of this package, and the answer is that
/// the server names the port and never the address.**
///
/// A `227` answer to `PASV` carries four address bytes, and those bytes
/// are whatever the server wrote. A hostile server, or one somebody else
/// took, can name any address at all: a machine inside the network that
/// runs this client, a service on the loopback interface, or a third party
/// it wants traffic sent to. A client that dialed the answer would be a
/// port scanner and a relay that anybody with an FTP url can point.
///
/// So `trust_address` is false and the dial goes to `control_peer`, which
/// is the numeric address the control connection already reached. curl
/// does exactly this: `--ftp-skip-pasv-ip` has been **on by default since
/// 7.74.0**, and its manual page says curl "reuses the same IP address it
/// already uses for the control connection". Measured against curl 8.21.0
/// with a server that answers `227 ... (203,0,113,7,p1,p2)` while
/// listening on 127.0.0.1: curl downloads the file, so it ignored the
/// address. The same server with `--no-ftp-skip-pasv-ip` hangs on
/// 203.0.113.7 until the command is killed.
///
/// **The address, and never the host name the url wrote.** This function
/// took the name once, and a name is looked up again on every dial. An
/// FTP session runs a login, a directory walk, an `EPSV` or a `PASV`, a
/// `TYPE`, and the `RETR` itself between the two dials, so a record with a
/// short life is asked again in that window and may be answered
/// differently. A client that dialed the name a second time would let
/// whoever answers the lookup pick where the data connection goes, which
/// is the same choice ignoring the `227` address exists to take away from
/// the server. The same gap opens with no attacker: a host behind round
/// robin records, or one with both an `A` record and an `AAAA` record,
/// puts the two connections on two machines and the transfer stops.
///
/// `--no-ftp-skip-pasv-ip` is the flag that turns the rule off in curl.
/// zurl has no such flag, so `trust_address` is reachable only from a
/// caller setting `Options.trust_pasv_address` itself.
///
/// An `EPSV` answer names no address at all, RFC 2428, so this function
/// has nothing to ignore for one. That is the second reason `EPSV` is
/// tried first. A `trust_address` transfer whose answer names no address
/// reuses the control peer the same way, because there is nothing else to
/// read.
///
/// The port is always the server's. RFC 959 gives the server the port and
/// this function keeps that half of the answer, whatever it does with the
/// address half.
pub fn dataTarget(
    control_peer: ?std.Io.net.IpAddress,
    peer: reply.DataPeer,
    trust_address: bool,
) DataTargetError!std.Io.net.IpAddress {
    if (trust_address) {
        // A `227` answer carries four bytes, so the address it names is
        // always IPv4.
        if (peer.address) |quad| return .{ .ip4 = .{ .bytes = quad, .port = peer.port } };
    }
    var address = control_peer orelse return error.ControlPeerUnknown;
    // The control peer carries the control connection's port, and this
    // connection goes to the one the server named.
    address.setPort(peer.port);
    return address;
}

/// The `REST` offset a `-r`/`--range` value asks for, or an error for a
/// value that FTP cannot answer.
///
/// **RFC 959 has a start and no end.** `REST n` says where the transfer
/// begins, and `RETR` then sends the rest of the file. There is no command
/// that says where to stop. So:
///
/// - `bytes=5-` is exactly `REST 5`, and it is answered.
/// - `bytes=5-15` has an end. curl answers it by sending `REST 5`, reading
///   eleven bytes, and then sending `ABOR` to get the control connection
///   back, measured. zurl refuses it instead, with `error.RangeError`,
///   exit 33, before any command goes out. Closing the data connection
///   early leaves the control connection in a state that needs `ABOR` to
///   recover, and a session that gets that wrong reads the answer to one
///   command as the answer to another. That is the defect this package
///   spends most of its care on, and a partly implemented `-r` would open
///   it again.
/// - `bytes=-100`, the last hundred bytes, is refused for the same reason:
///   it needs the size first, and then it still needs an end.
/// - A list of ranges is refused: one `RETR` cannot answer two.
///
/// `--help` says all four, so a user who reads the refusal knows what to
/// type instead.
pub fn restFromRange(value: []const u8) error{RangeError}!u64 {
    const spec = if (std.mem.startsWith(u8, value, "bytes="))
        value["bytes=".len..]
    else
        value;
    if (std.mem.indexOfScalar(u8, spec, ',') != null) return error.RangeError;
    if (!std.mem.endsWith(u8, spec, "-")) return error.RangeError;
    const start = spec[0 .. spec.len - 1];
    if (start.len == 0) return error.RangeError;
    return std.fmt.parseInt(u64, start, 10) catch error.RangeError;
}

/// Runs one transfer and returns its answer.
///
/// Frees whatever the previous call held first, so a `Fetcher` never holds
/// two answers at once.
///
/// **The order the commands go out in is curl's own**, measured against
/// curl 8.21.0 on a loopback RFC 959 server:
///
///     USER, PASS, [PBSZ, PROT], CWD for each directory,
///     EPSV or PASV, TYPE, [SIZE], [REST], RETR or LIST or NLST
///
/// with `AUTH TLS` before `USER` for an explicit TLS transfer, and `QUIT`
/// at the end. curl also sends `PWD` after `PASS` and reads the answer for
/// its own `--ftp-method` choice. zurl has no such flag and sends no
/// `PWD`.
///
/// The faults, and the exit code each carries:
///
/// - a url path whose decoded form holds a control byte is
///   `error.InvalidUrl`, exit 3, and no command goes out. curl refuses the
///   same url with the same code, measured.
/// - a peer that does not accept a connection is `error.CouldNotConnect`,
///   exit 7.
/// - a reply nothing can read is `error.WeirdServerReply`, exit 8.
/// - a `CWD` the server refused is `error.FtpAccessDenied`, exit 9.
/// - a `PASV` or an `EPSV` the server refused is
///   `error.FtpWeirdPasvReply`, exit 13, and a `227` nobody can read is
///   `error.FtpWeird227Format`, exit 14.
/// - a `TYPE` the server refused is `error.FtpCouldNotSetType`, exit 17.
/// - a transfer the server ended with something other than a 2yz reply is
///   `error.PartialFile`, exit 18.
/// - a `REST` the server refused is `error.FtpCouldNotUseRest`, exit 31.
/// - a peer certificate that does not verify is
///   `error.PeerFailedVerification`, exit 60.
/// - an `AUTH TLS`, a `PBSZ`, or a `PROT` the server refused is
///   `error.UseSslFailed`, exit 64. **There is no fallback to a session
///   with no TLS.**
/// - a login the server refused is `error.LoginDenied`, exit 67.
/// - a `RETR`, a `LIST`, or an `NLST` the server refused is
///   `error.RemoteFileNotFound`, exit 78.
///
/// Every one of these is curl's own number for the same shape, measured.
pub fn open(f: *Fetcher, url: zurl_core.Url, options: Options, d: ?*Diagnostics) Error!Body {
    f.release();
    f.upgrade_fault = null;
    f.stall = options.read_timeout;

    // **The url is read before anything is dialed.** A path that could
    // forge a command is refused here, with no socket opened at all.
    f.path.parse(url.path) catch |err| return reportPath(err, d);

    var credential_source: CredentialSource = undefined;
    const credentials = try f.resolveCredentials(url, options, &credential_source, d);

    // `-r` is read before the dial too, so a range FTP cannot answer costs
    // no connection. See `restFromRange`.
    const rest_offset: u64 = offset: {
        if (options.range) |value| {
            break :offset restFromRange(value) catch return fail(d, error.RangeError, &.{
                "an ftp transfer restarts at an offset and has no way to stop at one, so only an open ended range such as 5- applies: ",
                value,
            });
        }
        break :offset options.resume_from;
    };

    const port = url.port orelse return fail(d, error.InvalidUrl, &.{
        "an ftp url names a port, and this one names none",
    });
    // **`--resolve` and `--connect-to` move both dials and nothing else.**
    // The data connection follows this target on its own, because
    // `dataTarget` reuses the address the control connection reached.
    // `controlTlsOptions` and `dataTlsOptions` both read `url.host`, so an
    // `ftps` peer at the dialed address still has to hold a certificate
    // for the name the url wrote. See `zurl_net.override`.
    const target_peer = zurl_net.override.dialTarget(options.connect_to, url.host, port);
    // A host that does not read and a host name no resolver can look up
    // are two faults, exit 3 and exit 6. See `zurl_net.errors.hostInit`.
    const host = zurl_net.tcp.Host.init(target_peer.host) catch |err| return fail(d, zurl_net.errors.hostInit(err).err, &.{
        target_peer.faultPrefix(err),
        target_peer.host,
    });

    const tls = try f.controlTlsOptions(url, options, d);

    // **The dial, the `AUTH TLS` step, and the handshake share one
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
    // The connection lives for exactly this transfer. RFC 959 lets a
    // session hold many transfers, and this package keeps none: a pool
    // has to know when a protocol is finished with a connection, and
    // nothing above this asks.
    defer connection.deinit();

    // The dialogue moves onto the connection.
    //
    // **An explicit upgrade was already speaking**, over the plain stream,
    // and the greeting and the `AUTH TLS` answer are already read. So it
    // keeps the dialogue it has and only changes where the bytes go, which
    // is what `Control.retarget` is for. Every other transfer starts its
    // dialogue here.
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
    }

    if (options.tls != .explicit) {
        const greeting = try f.expect(&connection, null, null, d);
        if (!greeting.isPositive()) return failReply(d, error.WeirdServerReply, "the ftp server did not greet this connection", greeting);
    }

    try f.login(&connection, credentials, credential_source, d);

    // **`PBSZ 0` and `PROT P` are what protect the data connection.**
    // RFC 4217 section 9: without them the data connection is in the
    // clear, whatever the control connection is. So a transfer that has
    // TLS and cannot get `PROT P` fails, and never carries on.
    if (options.tls != .none) try f.protectData(&connection, d);

    for (f.path.dirs()) |directory| {
        const answer = try f.expect(&connection, command.cwd, directory, d);
        if (!answer.isPositive()) return failReply(d, error.FtpAccessDenied, "the ftp server refused to change to a directory this url names", answer);
    }

    const data_peer = try f.openPassive(&connection, options, d);

    // **This is the one answer to "is this an ASCII transfer".** It picks
    // the representation type below, and it picks the conversion the
    // receiver owes further down. The two must never differ: a `TYPE A`
    // whose answer keeps every `CRLF` reaches a user with the line ending
    // of the server's system, and a `TYPE I` whose answer loses a `CR`
    // is a corrupt file. So both read this constant and neither computes
    // the question again.
    //
    // A listing is text and a file is bytes. curl sends `TYPE A` for the
    // first and `TYPE I` for the second, measured. `-B`/`--use-ascii`
    // asks for `TYPE A` on the second as well.
    const ascii = f.path.listing or options.use_ascii;
    const representation: []const u8 = if (ascii) "A" else "I";
    const type_answer = try f.expect(&connection, command.type_, representation, d);
    if (!type_answer.isPositive()) return failReply(d, error.FtpCouldNotSetType, "the ftp server refused the representation type this transfer needs", type_answer);

    const size = if (f.path.listing) null else try f.askSize(&connection, d);

    if (rest_offset != 0) {
        const answer = try f.expectNumber(&connection, command.rest, rest_offset, d);
        if (!answer.isIntermediate() and !answer.isPositive()) {
            return failReply(d, error.FtpCouldNotUseRest, "the ftp server refused to restart the transfer at an offset, so -C and an open ended -r cannot be answered", answer);
        }
    }

    const verb = if (!f.path.listing)
        command.retr
    else if (options.list_only)
        command.nlst
    else
        command.list;
    const argument: ?[]const u8 = if (f.path.listing) null else f.path.name;

    const start = try f.expect(&connection, verb, argument, d);
    if (!start.isPositive() and start.class() != 1) {
        return failReply(d, error.RemoteFileNotFound, "the ftp server refused to send what this url names", start);
    }

    // **The data connection dials the address the control connection
    // reached, and verifies against the name the url wrote.** The address
    // comes from the open socket, so the data connection asks no resolver
    // and cannot be sent elsewhere by a second lookup. The name is the
    // url's own, whatever `--connect-to` moved the dial to. See
    // `readData` and `dataTarget`.
    const answer = try f.readData(connection.peer, url.host, data_peer, options, d);
    errdefer f.allocator.free(answer);

    // **An ASCII transfer arrives as NVT-ASCII, and this is the half of
    // that type the receiver owes.** RFC 959 section 3.1.1.1 puts the
    // bytes on the wire with `CRLF` at the end of a line, and it asks the
    // receiver to write the line ending its own system uses. On this one
    // that is `LF`. curl does the same conversion: measured, the same
    // fixture writing `f.txt\r\nsub\r\n` reaches curl's standard output
    // as `f.txt\nsub\n`.
    //
    // `ascii` is the constant that sent `TYPE A` above, and nothing else
    // decides this. A `TYPE I` transfer is bytes and never text, so
    // nothing here touches one.
    //
    // The length shrinks and the allocation does not. `answer` is what
    // `release` frees, so it must stay the slice the allocator handed out.
    const body_len = if (ascii) stripCarriageReturns(answer) else answer.len;

    // **The transfer is not over until the control connection says so.**
    // The data connection closing is the server's half. A `426` here says
    // the server gave up part way through, and curl answers that with
    // exit 18, measured.
    const finish = try f.expect(&connection, null, null, d);
    if (!finish.isPositive()) {
        return failReply(d, error.PartialFile, "the ftp server did not report the transfer complete", finish);
    }

    // `QUIT` is a courtesy and never a gate. The answer is already read,
    // so a server that will not say goodbye has cost this transfer
    // nothing.
    f.control.send(command.quit, null) catch {};

    f.answer = answer;
    f.body = .fixed(answer[0..body_len]);
    return .{
        .reader = &f.body,
        .length = body_len,
        .size = size,
        .listing = f.path.listing,
    };
}

/// Sends one command, when there is one, and reads the whole reply.
///
/// A null `verb` reads a reply with no command before it, which is the
/// greeting and the reply that ends a transfer.
///
/// `connection` is read for one thing: the cause behind a `ReadFailed` or
/// a `WriteFailed`. It is optional so every step of the session below can
/// run over two buffers in a test, with no socket at all. That is what
/// lets a test pin the exact commands a login or a `PROT P` writes, and
/// the fault each answer earns, without a live server.
fn expect(
    f: *Fetcher,
    connection: ?*zurl_net.Connection,
    verb: ?[]const u8,
    argument: ?[]const u8,
    d: ?*Diagnostics,
) Error!reply.Reply {
    if (verb) |name| {
        f.control.send(name, argument) catch |err| return reportControl(err, connection, name, d);
    }
    return f.control.readReply() catch |err| return reportControl(err, connection, verb orelse "the reply", d);
}

/// `expect`, for a command whose argument is a number this package
/// computed.
fn expectNumber(
    f: *Fetcher,
    connection: ?*zurl_net.Connection,
    verb: []const u8,
    value: u64,
    d: ?*Diagnostics,
) Error!reply.Reply {
    f.control.sendNumber(verb, value) catch |err| return reportControl(err, connection, verb, d);
    return f.control.readReply() catch |err| return reportControl(err, connection, verb, d);
}

/// Sends `USER` and, when the server asks for one, `PASS`.
///
/// A server that answers `USER` with a 2yz reply has logged the user in
/// already and wants no password, which is what an anonymous server with
/// no password set does. A 3yz reply asks for the password. Anything else
/// is `error.LoginDenied`, exit 67, which is curl's own code, measured
/// against a server answering `530`.
fn login(
    f: *Fetcher,
    connection: ?*zurl_net.Connection,
    credentials: Credentials,
    source: CredentialSource,
    d: ?*Diagnostics,
) Error!void {
    const user_answer = try f.expect(connection, command.user, credentials.user, d);
    if (user_answer.isPositive()) return;
    if (!user_answer.isIntermediate()) {
        return failCredential(d, error.LoginDenied, source, "the ftp server refused the user name from ", user_answer);
    }

    const pass_answer = try f.expect(connection, command.pass, credentials.password, d);
    if (pass_answer.isPositive()) return;
    // A server may answer `PASS` with `332`, which asks for an `ACCT`.
    // zurl has no `--ftp-account`, so it cannot answer, and saying so by
    // name beats sending nothing and waiting.
    return failCredential(d, error.LoginDenied, source, "the ftp server did not accept the credential from ", pass_answer);
}

/// Sends `PBSZ 0` and `PROT P`, which put the data connection inside the
/// TLS session.
///
/// **A refusal ends the transfer.** RFC 4217 section 9 makes `PROT P` the
/// thing that protects the data connection, so a transfer that asked for
/// TLS and carried on without it would send the file, and the listing that
/// names it, in the clear. curl answers the same shape with exit 64,
/// `CURLE_USE_SSL_FAILED`.
///
/// `PBSZ 0` is the only value TLS allows, RFC 4217 section 9: TLS frames
/// its own records, so there is no protection buffer to size.
fn protectData(f: *Fetcher, connection: ?*zurl_net.Connection, d: ?*Diagnostics) Error!void {
    const pbsz = try f.expect(connection, command.pbsz, "0", d);
    if (!pbsz.isPositive()) {
        return failReply(d, error.UseSslFailed, "the ftp server refused PBSZ 0, so the data connection cannot be protected", pbsz);
    }
    const prot = try f.expect(connection, command.prot, "P", d);
    if (!prot.isPositive()) {
        return failReply(d, error.UseSslFailed, "the ftp server refused PROT P, so the data connection would carry the file in the clear", prot);
    }
}

/// Asks the server for the size of the file.
///
/// Returns null when the server answered no number. A server that does not
/// implement `SIZE`, or one that answers it with text, is not a fault: the
/// transfer runs and the progress meter reports an unknown total, which is
/// what curl does.
///
/// **A `550` is different.** curl reads that as "the file does not exist"
/// and exits 78, measured against a server answering `550 Not a plain
/// file` to `SIZE`. So does this.
fn askSize(f: *Fetcher, connection: ?*zurl_net.Connection, d: ?*Diagnostics) Error!?u64 {
    const answer = try f.expect(connection, command.size, f.path.name, d);
    if (answer.code == 550) {
        return failReply(d, error.RemoteFileNotFound, "the ftp server answered 550 to SIZE, so the file this url names is not there", answer);
    }
    if (!answer.isPositive()) return null;
    return reply.parseSize(answer.text);
}

/// Asks the server to listen for the data connection.
///
/// **`EPSV` first, and `PASV` when the server refuses it.** RFC 2428 makes
/// `EPSV` the newer command, it works over IPv6, and its answer names no
/// address at all, which is one fewer thing this client has to ignore.
/// curl sends the two in this order, measured.
///
/// **`Options.disable_epsv` sends `PASV` alone.** This is
/// `--disable-epsv`, and it is for a server or a middlebox that answers
/// `EPSV` with something the session cannot carry on from. The `PASV`
/// path is the one that already runs when a server refuses `EPSV`, so
/// the flag removes a command and adds no code path.
///
/// **The flag does not make the `227` address trusted.** `readData` dials
/// what `dataTarget` picks, which is the address the control connection
/// reached whatever the answer names, and this function passes `Options`
/// through unchanged.
///
/// A server that refuses every command this sent is
/// `error.FtpWeirdPasvReply`, exit 13, which is curl's own code. The
/// message names only the commands that went out, so a user does not look
/// in a log for an `EPSV` this transfer never sent.
fn openPassive(
    f: *Fetcher,
    connection: ?*zurl_net.Connection,
    options: Options,
    d: ?*Diagnostics,
) Error!reply.DataPeer {
    if (!options.disable_epsv) {
        const epsv = try f.expect(connection, command.epsv, null, d);
        if (epsv.isPositive()) {
            return reply.parseEpsv(epsv.text) catch {
                return failReply(d, error.FtpWeirdPasvReply, "the ftp server answered EPSV with something that names no port", epsv);
            };
        }
    }

    const pasv = try f.expect(connection, command.pasv, null, d);
    if (!pasv.isPositive()) {
        const sentence = if (options.disable_epsv)
            "the ftp server refused PASV, --disable-epsv keeps EPSV out of this transfer, and zurl speaks no active mode"
        else
            "the ftp server refused both EPSV and PASV, and zurl speaks no active mode";
        return failReply(d, error.FtpWeirdPasvReply, sentence, pasv);
    }
    return reply.parsePasv(pasv.text) catch {
        return failReply(d, error.FtpWeird227Format, "the ftp server answered PASV with something that is not six numbers in brackets", pasv);
    };
}

/// Opens the data connection, reads the whole answer, and closes it.
///
/// **The dial goes to `control_peer` and not to the address the server
/// named, and not to a host name either.** See `dataTarget`.
///
/// **`control_peer` and `verify_host` are two different things, and the
/// second is not an address at all.** `control_peer` is the numeric
/// address the control connection reached, which is where this one goes
/// too: a data connection on a second machine reaches no transfer.
/// `verify_host` is the name the url wrote, which is the name an `ftps`
/// certificate is checked against, and `--connect-to` never moves it.
///
/// This function asks no resolver. `control_peer` is already an address,
/// so nothing here can be answered differently the second time.
///
/// The connection carries TLS whenever the control connection does,
/// because `PROT P` has already gone out and a plain data connection after
/// it would make that command a lie.
fn readData(
    f: *Fetcher,
    control_peer: ?std.Io.net.IpAddress,
    verify_host: []const u8,
    peer: reply.DataPeer,
    options: Options,
    d: ?*Diagnostics,
) Error![]u8 {
    // **The one fault here is a build that cannot read the address, and
    // it is not a url fault.** `dataTarget` never resolves and never
    // parses, so there is no bad host to report. A build that landed here
    // refuses the transfer rather than look the url's host name up a
    // second time, because that second lookup is the defect the address
    // closes. See `DataTargetError.ControlPeerUnknown`.
    const address = dataTarget(control_peer, peer, options.trust_pasv_address) catch |err| switch (err) {
        error.ControlPeerUnknown => return fail(d, error.CouldNotConnect, &.{
            "this build cannot read the address the ftp control connection reached, and an ftp data connection must dial that address rather than look the host name up a second time",
        }),
    };
    // The text of the address, for a fault a user reads. It is written
    // once and borrowed by every report below, so the buffer outlives all
    // of them.
    var target_text: [max_address_text]u8 = undefined;
    const host_text = std.fmt.bufPrint(&target_text, "{f}", .{address}) catch "the ftp data peer";

    const tls = try f.dataTlsOptions(verify_host, options, d);

    var data: zurl_net.Connection = undefined;
    zurl_net.bounded.setup(&data, f.io, options.connect_timeout, .{
        .allocator = f.allocator,
        .io = f.io,
        .host = .{ .address = address },
        .port = peer.port,
        .read_buffer_len = read_buffer_len,
        .tls = tls,
        .no_delay = options.tcp_no_delay,
    }) catch |err| return f.reportSetup(err, host_text, d);
    defer data.deinit();

    // Two bounds on one read: the size and the wait. An FTP data
    // connection ends only when the peer closes, so the protocol itself
    // ends neither one.
    return zurl_net.bounded.readToEnd(
        &data,
        f.io,
        f.allocator,
        options.max_response_bytes,
        options.read_timeout,
    ) catch |err| switch (err) {
        error.OutOfMemory => return Diagnostics.record(d, error.OutOfMemory, .{}),
        error.StreamTooLong => return failNumber(
            d,
            error.FileSizeExceeded,
            "the ftp server wrote more than the ",
            options.max_response_bytes,
            " bytes zurl reads from one transfer, which ends only when the peer closes",
        ),
        error.ReadFailed => return reportRead(&data, d),
        error.OperationTimedOut => return fail(d, error.OperationTimedOut, &.{
            "the ftp data connection sent no byte for as long as zurl waits, and the transfer ends only when the peer closes",
        }),
        error.ReadTimeoutUnsupported => return fail(d, error.ReadError, &.{
            "this build has no concurrency, so an ftp read cannot be bounded, and an unbounded one would wait for a peer that may never answer",
        }),
        error.Canceled => return fail(d, error.AbortedByCallback, &.{
            "the ftp transfer was stopped from outside",
        }),
    };
}

/// Turns every `CRLF` in `text` into an `LF`, in place, and returns how
/// many bytes the result holds.
///
/// This is the receiving half of the RFC 959 ASCII representation type.
/// The sender writes NVT-ASCII, where a line ends `CRLF`, and the receiver
/// writes the ending its own system uses. curl does the same, measured.
///
/// **A `CR` that is not before an `LF` stays.** It is data, not a line
/// ending, and a listing that carries one in a file name must keep it or
/// the name changes.
///
/// The text only ever shrinks, so this reads and writes one buffer.
fn stripCarriageReturns(text: []u8) usize {
    var read: usize = 0;
    var write: usize = 0;
    while (read < text.len) : (read += 1) {
        if (text[read] == '\r' and read + 1 < text.len and text[read + 1] == '\n') continue;
        text[write] = text[read];
        write += 1;
    }
    return write;
}

/// The credential this transfer sends, in curl's own order.
///
/// The url's userinfo first, then `-u`, then a netrc entry for the url's
/// host, then the anonymous login. That is the order `zurl.authorize`
/// keeps for HTTP, and curl keeps the same one for FTP: measured,
/// `ftp://bob:pw@host/f` sends `USER bob`, and `-u alice:s3cret` on a url
/// with no userinfo sends `USER alice`.
///
/// **The userinfo is percent-decoded and the other two are not.** A url
/// writes a credential escaped, so `%40` in a password is an `@` and not
/// three characters. `-u` and a netrc file are read as they are written,
/// which is what curl does: measured, `-u 'u:p%0d%0aQUIT'` reaches the
/// wire from curl as `PASS p%0d%0aQUIT`, with no decode at all.
///
/// **A credential that could forge a command never reaches one.**
/// `command.write` refuses a NUL, a CR, or an LF in any argument, so a
/// forged `USER` or `PASS` is refused at the socket whatever source it
/// came from. This function refuses the same three bytes first, so the
/// message names the credential and its source rather than the command.
/// curl refuses a url userinfo holding `%0d%0a` with exit 3 too, measured;
/// it accepts the same bytes from `-u` because it does not decode them.
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

        source.* = .anonymous;
        break :found .{ .user = command.anonymous_user, .password = command.anonymous_password };
    };

    // **The injection refusal for a credential.** See the doc comment.
    if (zurl_core.url.hasFramingByte(resolved.user) or
        zurl_core.url.hasFramingByte(resolved.password))
    {
        return fail(d, error.InvalidUrl, &.{
            "the credential from ",
            source.*.describe(),
            " holds a NUL, a CR, or an LF, and any of the three would end the ftp command line and write a command of its own",
        });
    }
    return resolved;
}

/// The TLS options the control connection opens with, or null for a plain
/// `ftp://` hop.
///
/// **This is the one place in this package that turns peer verification
/// off, and it reads `options.insecure` and nothing else.** A function and
/// not a few lines inside `open`, so a test can name both answers and
/// prove that no other input can reach the second one. `zurl_gopher` and
/// `zurl_http.h1` keep the same shape.
///
/// Both halves of the check go together, the way curl does it. A host name
/// check is worthless against a peer whose chain nobody trusts, and a
/// trusted chain for the wrong host is worthless too.
///
/// **A build with no trust store cannot open an encrypted session.** The
/// `null` arm reports `error.SslConnectError` rather than fall back to
/// `.none`, because that fallback is exactly the hole this package must
/// not open.
fn controlTlsOptions(
    f: *Fetcher,
    url: zurl_core.Url,
    options: Options,
    d: ?*Diagnostics,
) Error!?zurl_net.Connection.Tls {
    _ = f;
    // An explicit upgrade dials in the clear and hands shakes after
    // `AUTH TLS`, so the options are the same and only the moment differs.
    if (options.tls == .none) return null;
    return try sessionOptions(url.host, options, d);
}

/// The TLS options the data connection opens with, or null for a data
/// connection that carries no TLS.
///
/// **The data connection is protected whenever the control connection
/// is.** `PROT P` has already gone out by the time this is read, and a
/// plain data connection after that command would make it a lie: the file
/// would cross the network in the clear while the session said it would
/// not.
///
/// It verifies against the same trust store, and it checks the same host
/// name, because it is the same server. `-k` turns both off together, and
/// nothing else does.
///
/// **`verify_host` is the name the url wrote and never the address the
/// dial went to.** A `--connect-to` moves both dials, and a certificate
/// checked against the moved address would let that flag stand in for
/// `-k`. See `Options.connect_to`.
fn dataTlsOptions(
    f: *Fetcher,
    verify_host: []const u8,
    options: Options,
    d: ?*Diagnostics,
) Error!?zurl_net.Connection.Tls {
    _ = f;
    if (options.tls == .none) return null;
    return try sessionOptions(verify_host, options, d);
}

/// The options one TLS session opens with. Read by both connections, so
/// neither can drift from the other.
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
        "this build gave the ftp package no trust store, so it cannot verify an ftps peer",
    });
    try trust.load(trust.ptr);

    return .{
        .host = .{ .explicit = host },
        .trust = .{ .bundle = .{ .lock = trust.lock, .bundle = trust.bundle } },
        .min_version = options.tls_min_version,
        .max_version = options.tls_max_version,
        // **No ALPN extension at all.** RFC 7301 needs a registered
        // protocol name and FTP has none. An offer of `http/1.1` would
        // name a protocol this hop does not speak.
        .alpn_protocols = &.{},
        // `allow_truncation_attacks` keeps its default, which is false,
        // and **the default is load-bearing on the data connection**. An
        // FTP transfer ends when the peer closes, so a middle box that cut
        // the connection early would otherwise hand a short file up as a
        // whole one. The `226` on the control connection is a second
        // check, and it is one the same middle box cannot forge inside the
        // session, but a session that ends with no `close_notify` is still
        // a fault to report and never one to pass over.
    };
}

/// The `AUTH TLS` step, run inside the connect race.
///
/// **This runs on a plain stream and it sends no credential.** RFC 4217
/// puts the greeting and `AUTH TLS` before the handshake, so those two
/// bytes cross in the clear and nothing else does. `USER` and `PASS` go
/// out after the handshake, from `open`.
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

    const greeting = f.control.readReply() catch |err| return .{
        .err = replyFault(err),
        .message = "zurl did not read the ftp greeting before AUTH TLS",
    };
    if (!greeting.isPositive()) return .{
        .err = error.WeirdServerReply,
        .message = "the ftp server did not greet this connection, so AUTH TLS was never sent",
    };

    const answer = f.control.ask(command.auth, "TLS") catch |err| return .{
        .err = replyFault(err),
        .message = "zurl did not read the answer to AUTH TLS",
    };
    if (!answer.isPositive()) return .{
        .err = error.UseSslFailed,
        .message = "the ftp server refused AUTH TLS, and zurl sends no credential over a connection that was asked to be encrypted and is not",
    };

    // **Nothing may be held across the handshake.** A server that wrote
    // bytes behind its `234` wrote them in cleartext, and carrying them
    // into the session would hand a caller text the peer chose as though
    // TLS had protected it.
    if (f.control.buffered() != 0) return .{
        .err = error.UseSslFailed,
        .message = "the ftp server wrote more bytes behind its AUTH TLS answer, and those bytes are not inside the session",
    };

    return null;
}

/// Empties both buffers of a `zurl_net.Connection`. See
/// `Control.Channel.flush`.
fn flushConnection(ctx: ?*anyopaque) Io.Writer.Error!void {
    const connection: *zurl_net.Connection = @ptrCast(@alignCast(ctx.?));
    connection.flush() catch return error.WriteFailed;
}

/// Empties the buffer of a plain stream writer, which is what the
/// `AUTH TLS` step writes through.
fn flushStream(ctx: ?*anyopaque) Io.Writer.Error!void {
    const writer: *std.Io.net.Stream.Writer = @ptrCast(@alignCast(ctx.?));
    return writer.interface.flush();
}

/// The `zurl_core.Error` one control fault means.
///
/// Every name is listed, so a new one in `Control.Error` is a compile
/// error here and never a fault that reaches a user under the wrong
/// number.
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
        error.ReadFailed, error.ReadTimeoutUnsupported, error.StreamTooLong => error.ReadError,
        error.WriteFailed => error.WriteError,
        error.ArgumentHasFramingByte => error.InvalidUrl,
        error.CommandTooLong => error.InvalidUrl,
    };
}

/// Reports a fault on the control connection, with the command it happened
/// on.
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
    return fail(d, mapped, &.{
        "the ftp control connection failed on ",
        verb,
        ": ",
        cause,
    });
}

/// Reports a dial or handshake fault.
///
/// **An `AUTH TLS` step that failed reports its own reason**, which it
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

/// Reports a read on the data connection that did not finish.
fn reportRead(connection: *zurl_net.Connection, d: ?*Diagnostics) Error {
    const cause = connection.readError() orelse return fail(d, error.ReadError, &.{
        "zurl did not read the ftp data connection",
    });
    return fail(d, error.ReadError, &.{
        "zurl did not read the ftp data connection: ",
        @errorName(cause),
    });
}

/// Reports a url path this package will not send.
fn reportPath(err: target.ParseError, d: ?*Diagnostics) Error {
    return switch (err) {
        // **The injection refusal at the url.** See
        // `target.ParseError.PathHasControlByte`.
        error.PathHasControlByte => fail(d, error.InvalidUrl, &.{
            "the path of this url holds a control byte, and a CR or an LF in one would end an ftp command line and write a command of its own",
        }),
        error.InvalidEscape => fail(d, error.InvalidUrl, &.{
            "the path of this url holds a percent escape that is not an escape",
        }),
        error.PathTooLong => failNumber(
            d,
            error.InvalidUrl,
            "the path of this url is longer than the ",
            target.max_path_bytes,
            " bytes zurl reads",
        ),
        error.TooManyComponents => failNumber(
            d,
            error.InvalidUrl,
            "the path of this url names more than the ",
            target.max_components,
            " directories zurl changes into",
        ),
    };
}

/// Writes `parts`, one after another, into `d`'s own message storage,
/// records `err` with that message, and returns `err`.
///
/// The text goes into `Diagnostics.message_storage` because the sentence
/// names a reply this package holds in a buffer it reuses, so a borrowed
/// message would read the next transfer's reply.
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
/// only the code and the first line reach the message. A server that wrote
/// a hundred lines of banner would otherwise fill the diagnostic with
/// them.
fn failReply(d: ?*Diagnostics, err: Error, sentence: []const u8, answer: reply.Reply) Error {
    var digits: [8]u8 = undefined;
    const code = std.fmt.bufPrint(&digits, "{d}", .{answer.code}) catch digits[0..0];
    const first = answer.text[0 .. std.mem.indexOfScalar(u8, answer.text, '\n') orelse answer.text.len];
    const shown = first[0..@min(first.len, 200)];
    return fail(d, err, &.{ sentence, ": ", code, " ", shown });
}

/// `failReply`, with the credential source named instead of a fixed
/// sentence tail.
fn failCredential(
    d: ?*Diagnostics,
    err: Error,
    source: CredentialSource,
    sentence: []const u8,
    answer: reply.Reply,
) Error {
    var digits: [8]u8 = undefined;
    const code = std.fmt.bufPrint(&digits, "{d}", .{answer.code}) catch digits[0..0];
    const first = answer.text[0 .. std.mem.indexOfScalar(u8, answer.text, '\n') orelse answer.text.len];
    const shown = first[0..@min(first.len, 200)];
    return fail(d, err, &.{ sentence, source.describe(), ": ", code, " ", shown });
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
        "the credential in this url is longer than the ",
        max_credential_bytes,
        " bytes one ftp command line carries",
    );
}

/// Returns the dispatch entry for the plain `ftp` scheme.
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
        // run direct. curl carries ftp through a proxy and this build does
        // not. See `Front.protocol.Unread`.
        .unread = .{ .proxy = true },
    };
}

/// Returns the dispatch entry for the `ftps` scheme. See `protocol`.
///
/// The port is 990 and not 21, because `ftps://` is implicit TLS and that
/// is the port implicit TLS uses. curl dials the same number, measured.
pub fn secureProtocol(f: *Fetcher, comptime Front: type) Front.protocol.Protocol {
    return .{
        .scheme = secure_scheme,
        .default_port = secure_default_port,
        .ptr = f,
        .vtable = &Dispatch(Front).vtable,
        // This package dials the origin itself and reads no proxy field,
        // so a transfer that named a proxy is refused by name rather than
        // run direct. curl carries ftp through a proxy and this build does
        // not. See `Front.protocol.Unread`.
        .unread = .{ .proxy = true },
    };
}

/// The vtable for one front package. One instantiation for each `Front`,
/// and each one holds a single comptime constant, so the table lives in
/// the binary's own read-only data and never on a stack.
fn Dispatch(comptime Front: type) type {
    return struct {
        const vtable: Front.protocol.Protocol.VTable = .{ .perform = performFtp };

        fn performFtp(
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
        /// **The scheme decides the TLS mode.** `ftps://` is implicit,
        /// which is what curl does, and `ftp://` with `--ssl-reqd` is
        /// explicit `AUTH TLS`. A build that has neither speaks plain FTP.
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
                .list_only = options.list_only,
                .use_ascii = options.use_ascii,
                .disable_epsv = options.ftp_disable_epsv,
                .resume_from = options.resume_from,
                .range = options.range,
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
            list_only: bool = false,
            use_ascii: bool = false,
            resume_from: u64 = 0,
            range: ?[]const u8 = null,
            ftp_ssl_required: bool = false,
            ftp_disable_epsv: bool = false,
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
fn parseFtpUrl(text: []const u8) !zurl_core.Url {
    var schemes: zurl_core.url.Schemes = .empty;
    try schemes.add(.{ .name = scheme, .default_port = default_port });
    try schemes.add(.{ .name = secure_scheme, .default_port = secure_default_port });
    return zurl_core.url.parseWith(text, &schemes);
}

test {
    _ = command;
    _ = reply;
    _ = target;
    _ = Control;
    _ = test_server;
}

test "the two schemes name the two ports curl dials" {
    try testing.expectEqualStrings("ftp", scheme);
    try testing.expectEqualStrings("ftps", secure_scheme);
    try testing.expectEqual(@as(?u16, 21), default_port);
    try testing.expectEqual(@as(?u16, 990), secure_default_port);
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
    try testing.expect(isSecure(try parseFtpUrl("ftps://h/f")));
    try testing.expect(isSecure(try parseFtpUrl("FTPS://h/f")));
    try testing.expect(!isSecure(try parseFtpUrl("ftp://h/f")));
    // The port does not decide it. An `ftp://` url on 990 is still plain.
    try testing.expect(!isSecure(try parseFtpUrl("ftp://h:990/f")));
}

/// The address a control connection reached, for a test of `dataTarget`.
fn controlAt(bytes: [4]u8, port: u16) std.Io.net.IpAddress {
    return .{ .ip4 = .{ .bytes = bytes, .port = port } };
}

test "the data connection dials the control peer's address and never the PASV address" {
    // **The security decision of this package.** See `dataTarget`. The
    // reply names the port and nothing else.
    const control = controlAt(.{ 198, 51, 100, 4 }, 21);
    const foreign: reply.DataPeer = .{ .address = .{ 203, 0, 113, 7 }, .port = 1025 };

    const picked = try dataTarget(control, foreign, false);
    try testing.expect(picked == .ip4);
    try testing.expectEqual([4]u8{ 198, 51, 100, 4 }, picked.ip4.bytes);
    // The port is the server's half of the answer, and it is kept.
    try testing.expectEqual(@as(u16, 1025), picked.ip4.port);

    // An address that looks harmless is ignored just the same. The rule
    // is not about which address it is.
    const same: reply.DataPeer = .{ .address = .{ 127, 0, 0, 1 }, .port = 1025 };
    const second = try dataTarget(controlAt(.{ 10, 0, 0, 5 }, 21), same, false);
    try testing.expectEqual([4]u8{ 10, 0, 0, 5 }, second.ip4.bytes);

    // An `EPSV` answer carries no address at all, so there is nothing to
    // ignore, and both settings reuse the control peer.
    const epsv: reply.DataPeer = .{ .address = null, .port = 1025 };
    const loopback = controlAt(.{ 127, 0, 0, 1 }, 21);
    try testing.expectEqual(
        [4]u8{ 127, 0, 0, 1 },
        (try dataTarget(loopback, epsv, false)).ip4.bytes,
    );
    try testing.expectEqual(
        [4]u8{ 127, 0, 0, 1 },
        (try dataTarget(loopback, epsv, true)).ip4.bytes,
    );
}

test "the data connection takes an address and never a name, so no second lookup can move it" {
    // **The defect this closes.** `dataTarget` took the control host's
    // text, and `readData` then handed that text to
    // `zurl_net.tcp.Host.init`, which reads a name as a name and dials it
    // through a fresh lookup. An FTP session runs a login, a directory
    // walk, an `EPSV` or `PASV`, a `TYPE`, and the `RETR` between the two
    // dials, so a resolver that answered the second lookup differently
    // sent the data connection to a machine the ftp server never named.
    // A host behind round robin records, or one with both an `A` and an
    // `AAAA` record, split the two connections the same way with no
    // attacker at all.
    //
    // The type is the fix: this function hands back an
    // `std.Io.net.IpAddress` and has no way to name a host, so no lookup
    // is left to answer. The whole file holds no `Host.init` on the data
    // path any more.
    const control = controlAt(.{ 198, 51, 100, 4 }, 21);
    const answer: reply.DataPeer = .{ .address = null, .port = 50000 };
    const picked = try dataTarget(control, answer, false);
    try testing.expect(@TypeOf(picked) == std.Io.net.IpAddress);

    // An IPv6 control connection is reused the same way, with the port
    // the answer named.
    var six: std.Io.net.IpAddress = .{ .ip6 = .loopback(21) };
    const over_six = try dataTarget(six, answer, false);
    try testing.expect(over_six == .ip6);
    try testing.expectEqual(@as(u16, 50000), over_six.ip6.port);
    // The control peer itself is not written through. `dataTarget` takes
    // it by value, so the caller's connection keeps its own port.
    six.setPort(21);
    try testing.expectEqual(@as(u16, 21), six.ip6.port);
}

test "a build that cannot read the control peer refuses rather than look the name up again" {
    // **Falling back to the host name is the defect, so there is no
    // fallback.** Only a build for Windows or WASI reaches this, where
    // Zig 0.16 gives `std.posix.getpeername` no body. See
    // `DataTargetError.ControlPeerUnknown`.
    const answer: reply.DataPeer = .{ .address = null, .port = 1025 };
    try testing.expectError(error.ControlPeerUnknown, dataTarget(null, answer, false));

    // A caller that trusts the `227` address has an address of its own,
    // so it needs no control peer at all.
    const named: reply.DataPeer = .{ .address = .{ 203, 0, 113, 7 }, .port = 1025 };
    try testing.expectEqual(
        [4]u8{ 203, 0, 113, 7 },
        (try dataTarget(null, named, true)).ip4.bytes,
    );
    // And one that trusts an answer naming no address still has nothing.
    try testing.expectError(error.ControlPeerUnknown, dataTarget(null, answer, true));
}

test "only a caller that asks for it reaches the address the server named" {
    // This is curl's `--no-ftp-skip-pasv-ip`, and zurl exposes no flag for
    // it. The arm exists so the rule above is a decision and not an
    // accident of there being no other code path.
    const control = controlAt(.{ 198, 51, 100, 4 }, 21);
    const foreign: reply.DataPeer = .{ .address = .{ 203, 0, 113, 7 }, .port = 1025 };
    const picked = try dataTarget(control, foreign, true);
    try testing.expectEqual([4]u8{ 203, 0, 113, 7 }, picked.ip4.bytes);
    try testing.expectEqual(@as(u16, 1025), picked.ip4.port);
}

test "the default options ignore the PASV address, the way curl 7.74.0 and later do" {
    const o: Options = .{};
    try testing.expect(!o.trust_pasv_address);
    try testing.expectEqual(TlsMode.none, o.tls);
    try testing.expect(!o.list_only);
    try testing.expectEqual(@as(u64, 0), o.resume_from);
    try testing.expect(!o.insecure);
    // A transfer that named no flag sends `TYPE I` for a file and tries
    // `EPSV` before `PASV`, which is what curl does with no flag either.
    try testing.expect(!o.use_ascii);
    try testing.expect(!o.disable_epsv);
}

/// A `Fetcher` whose control dialogue runs over two buffers.
///
/// **This is what lets a test drive one step of a session with no socket
/// at all**: the exact commands a login writes, and the fault each answer
/// earns. Every step of `open` takes an optional connection for exactly
/// this reason. See `expect`.
const Bench = struct {
    f: Fetcher,
    reader: Io.Reader,
    sent: std.Io.Writer.Allocating,

    fn init(b: *Bench, server_says: []const u8) void {
        b.f = .init(testing.allocator, testing.io);
        b.reader = .fixed(server_says);
        b.sent = .init(testing.allocator);
        b.f.control.init(testing.io, .{
            .reader = &b.reader,
            .writer = &b.sent.writer,
            .ctx = b,
            .flush = flush,
        }, .none);
    }

    fn deinit(b: *Bench) void {
        b.sent.deinit();
        b.f.deinit();
    }

    fn flush(ctx: ?*anyopaque) Io.Writer.Error!void {
        _ = ctx;
    }

    fn wire(b: *Bench) []const u8 {
        return b.sent.written();
    }
};

/// How long a test lets a dial or a handshake take.
///
/// **Every test in this file needs this, and one of them found out the
/// hard way.** `Options.connect_timeout` defaults to `.none`, and a test
/// that asked for TLS against a fixture that speaks none left the
/// handshake waiting for a ServerHello that never came. The fixture, for
/// its part, was reading the ClientHello as a command line. Neither side
/// moved again. `--connect-timeout` is what bounds that in a real run, and
/// this is what bounds it here.
const test_connect_timeout: Io.Timeout = .{
    .duration = .{ .raw = .fromSeconds(10), .clock = .awake },
};

/// Runs a whole transfer against the fixture and returns the body.
///
/// Fills in a connect bound for a caller that named none, so no test in
/// this file can wait on a dial or a handshake forever. See
/// `test_connect_timeout`.
///
/// The caller frees the result and calls `server.stop` itself.
fn fetch(
    f: *Fetcher,
    server: *test_server.Server,
    path: []const u8,
    options: Options,
    d: ?*Diagnostics,
) !Body {
    var url_buffer: [256]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "ftp://127.0.0.1:{d}{s}", .{ server.port(), path });
    var bounded_options = options;
    if (bounded_options.connect_timeout == .none) {
        bounded_options.connect_timeout = test_connect_timeout;
    }
    return f.open(try parseFtpUrl(text), bounded_options, d);
}

test "a download reaches the server with the commands curl sends, in curl's order" {
    var server: test_server.Server = undefined;
    try server.start(.{ .body = "hello ftp body\n" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/f.txt", .{}, null);
    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("hello ftp body\n", contents);
    try testing.expectEqual(@as(u64, 15), body.length);
    try testing.expectEqual(@as(?u64, 15), body.size);
    try testing.expect(!body.listing);

    server.wait();
    // Measured from curl 8.21.0 against a loopback server, in this order.
    // curl also sends `PWD` after `PASS`, and zurl does not: see `open`.
    try testing.expectEqualStrings(
        "USER anonymous\nPASS ftp@example.com\nEPSV\nTYPE I\nSIZE f.txt\nRETR f.txt\nQUIT",
        server.commands(),
    );
    try testing.expectEqual(@as(usize, 1), server.connections());
    try testing.expectEqual(@as(usize, 1), server.dataConnections());
}

test "a directory url lists, and -l asks for the names alone" {
    {
        var server: test_server.Server = undefined;
        try server.start(.{});
        defer server.stop();

        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();

        const body = try fetch(&f, &server, "/", .{}, null);
        try testing.expect(body.listing);
        try testing.expectEqual(@as(?u64, null), body.size);

        const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
        defer testing.allocator.free(contents);
        try testing.expect(std.mem.indexOf(u8, contents, "-rw-r--r--") != null);

        server.wait();
        // `TYPE A` and `LIST`, and no `SIZE` at all. Measured.
        try testing.expectEqualStrings(
            "USER anonymous\nPASS ftp@example.com\nEPSV\nTYPE A\nLIST\nQUIT",
            server.commands(),
        );
    }
    {
        var server: test_server.Server = undefined;
        try server.start(.{});
        defer server.stop();

        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();

        const body = try fetch(&f, &server, "/", .{ .list_only = true }, null);
        const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
        defer testing.allocator.free(contents);
        // The fixture writes `f.txt\r\nsub\r\n`, which is NVT-ASCII. A
        // listing is `TYPE A`, so the receiver writes the line ending this
        // system uses. curl writes the same bytes, measured.
        try testing.expectEqualStrings("f.txt\nsub\n", contents);

        server.wait();
        try testing.expectEqualStrings(
            "USER anonymous\nPASS ftp@example.com\nEPSV\nTYPE A\nNLST\nQUIT",
            server.commands(),
        );
    }
}

test "a listing arrives as NVT-ASCII and reaches the caller with this system's line ending" {
    // The receiving half of the RFC 959 ASCII representation type, and
    // what curl does. A file download is `TYPE I` and is never touched.
    {
        var text = "f.txt\r\nsub\r\n".*;
        try testing.expectEqualStrings("f.txt\nsub\n", text[0..stripCarriageReturns(&text)]);
    }
    {
        // A `CR` that is not before an `LF` is data and stays.
        var text = "a\rb\r\nc\r".*;
        try testing.expectEqualStrings("a\rb\nc\r", text[0..stripCarriageReturns(&text)]);
    }
    {
        var text = "no endings at all".*;
        try testing.expectEqualStrings("no endings at all", text[0..stripCarriageReturns(&text)]);
    }
    {
        var text = "".*;
        try testing.expectEqual(@as(usize, 0), stripCarriageReturns(&text));
    }

    // And a file download keeps every byte, `CRLF` included.
    var server: test_server.Server = undefined;
    try server.start(.{ .body = "one\r\ntwo\r\n" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/f.txt", .{}, null);
    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("one\r\ntwo\r\n", contents);
}

test "-l changes nothing for a url that names a file" {
    // `-l` asks for names alone, and a file is not a list of names. curl
    // reads the flag the same way: it changes `LIST` to `NLST` and touches
    // no `RETR`.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    _ = try fetch(&f, &server, "/f.txt", .{ .list_only = true }, null);
    server.wait();
    try testing.expect(std.mem.indexOf(u8, server.commands(), "RETR f.txt") != null);
    try testing.expect(std.mem.indexOf(u8, server.commands(), "NLST") == null);
}

test "every directory of the path is its own CWD" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    _ = try fetch(&f, &server, "/a/b/c.txt", .{}, null);
    server.wait();
    // Measured: curl sends `CWD a`, `CWD b`, and then `SIZE c.txt`.
    try testing.expectEqualStrings(
        "USER anonymous\nPASS ftp@example.com\nCWD a\nCWD b\nEPSV\nTYPE I\nSIZE c.txt\nRETR c.txt\nQUIT",
        server.commands(),
    );
}

test "a multi-line greeting does not put the session one answer out of step" {
    // **The defect this test exists for.** A reader that stopped at the
    // first line of the greeting would read the rest of it as the answer
    // to `USER`, and every answer after it would belong to the command
    // before it. The download would then read the answer to `PASS`.
    var server: test_server.Server = undefined;
    try server.start(.{
        .greeting = &.{
            "220-Welcome to the fixture",
            "  line two, and 220 is not the end",
            "230 Not a real code either",
            "220-still open",
            "220 Ready",
        },
        .body = "the whole body arrived\n",
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/f.txt", .{}, null);
    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("the whole body arrived\n", contents);
}

test "the address a PASV answer names is ignored, and the transfer still runs" {
    // **The security test of this package.** The fixture listens on
    // 127.0.0.1 and answers `227 ... (203,0,113,7,...)`. A client that
    // dialed the answer would reach a machine it was never asked to reach,
    // and this transfer would not finish. It finishes, so the address went
    // nowhere. curl behaves the same way by default, measured.
    var server: test_server.Server = undefined;
    try server.start(.{
        .epsv = false,
        .pasv_address = .{ 203, 0, 113, 7 },
        .body = "the data connection went to the control host\n",
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/f.txt", .{}, null);
    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("the data connection went to the control host\n", contents);

    server.wait();
    try testing.expectEqual(@as(usize, 1), server.dataConnections());
}

test "EPSV first, and PASV when the server refuses it" {
    var server: test_server.Server = undefined;
    try server.start(.{ .epsv = false });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    _ = try fetch(&f, &server, "/f.txt", .{}, null);
    server.wait();
    // Measured: curl sends `EPSV`, reads the refusal, and sends `PASV`.
    try testing.expect(std.mem.indexOf(u8, server.commands(), "EPSV\nPASV\n") != null);
}

test "-B sends TYPE A for a file url, and no flag sends TYPE I" {
    // A listing is `TYPE A` with no flag at all, and that half is pinned
    // above. This pins the other half: `-B`/`--use-ascii` puts a file
    // transfer into the ASCII representation type too. curl sends the
    // same command for the same flag.
    {
        var server: test_server.Server = undefined;
        try server.start(.{});
        defer server.stop();

        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();

        _ = try fetch(&f, &server, "/f.txt", .{ .use_ascii = true }, null);
        server.wait();
        try testing.expect(std.mem.indexOf(u8, server.commands(), "TYPE A") != null);
        try testing.expect(std.mem.indexOf(u8, server.commands(), "TYPE I") == null);
        // The flag changes the representation type and nothing else. A
        // file is still a `RETR` and it still asks for the size.
        try testing.expect(std.mem.indexOf(u8, server.commands(), "RETR f.txt") != null);
        try testing.expect(std.mem.indexOf(u8, server.commands(), "SIZE f.txt") != null);
    }
    {
        var server: test_server.Server = undefined;
        try server.start(.{});
        defer server.stop();

        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();

        _ = try fetch(&f, &server, "/f.txt", .{}, null);
        server.wait();
        try testing.expect(std.mem.indexOf(u8, server.commands(), "TYPE I") != null);
        try testing.expect(std.mem.indexOf(u8, server.commands(), "TYPE A") == null);
    }
}

test "-B converts a file body to this system's line ending, and no flag keeps every byte" {
    // **The command and the conversion are one answer.** A `TYPE A` file
    // whose `CRLF` survived would reach a user with the line ending of
    // the server's system, and a `TYPE I` file that lost a `CR` would be
    // corrupt. `open` reads one constant for both, so this test fails the
    // moment the two drift.
    {
        var server: test_server.Server = undefined;
        try server.start(.{ .body = "one\r\ntwo\r\n" });
        defer server.stop();

        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();

        const body = try fetch(&f, &server, "/f.txt", .{ .use_ascii = true }, null);
        const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
        defer testing.allocator.free(contents);
        try testing.expectEqualStrings("one\ntwo\n", contents);
        try testing.expectEqual(@as(u64, 8), body.length);
    }
    {
        var server: test_server.Server = undefined;
        try server.start(.{ .body = "one\r\ntwo\r\n" });
        defer server.stop();

        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();

        const body = try fetch(&f, &server, "/f.txt", .{}, null);
        const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
        defer testing.allocator.free(contents);
        try testing.expectEqualStrings("one\r\ntwo\r\n", contents);
        try testing.expectEqual(@as(u64, 10), body.length);
    }
}

test "--disable-epsv sends PASV alone, and no flag sends EPSV first" {
    // The fixture answers `EPSV` in both halves, so the command log is
    // the whole proof: the flag is what keeps `EPSV` off the wire, and
    // not a server that refused it.
    {
        var server: test_server.Server = undefined;
        try server.start(.{ .body = "the PASV only path still runs\n" });
        defer server.stop();

        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();

        const body = try fetch(&f, &server, "/f.txt", .{ .disable_epsv = true }, null);
        const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
        defer testing.allocator.free(contents);
        try testing.expectEqualStrings("the PASV only path still runs\n", contents);

        server.wait();
        try testing.expect(std.mem.indexOf(u8, server.commands(), "PASV") != null);
        try testing.expect(std.mem.indexOf(u8, server.commands(), "EPSV") == null);
        try testing.expectEqual(@as(usize, 1), server.dataConnections());
    }
    {
        var server: test_server.Server = undefined;
        try server.start(.{});
        defer server.stop();

        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();

        _ = try fetch(&f, &server, "/f.txt", .{}, null);
        server.wait();
        try testing.expect(std.mem.indexOf(u8, server.commands(), "EPSV") != null);
        try testing.expect(std.mem.indexOf(u8, server.commands(), "PASV") == null);
    }
}

test "--disable-epsv dials the control peer and never the address the 227 answer names" {
    // **The flag must not weaken `dataTarget`.** The `PASV` path is the
    // one that carries an address, and a flag that removed `EPSV` would
    // be a way to reach that address on every transfer. The fixture
    // listens on 127.0.0.1 and answers `227 ... (203,0,113,7,...)`, so a
    // client that dialed the answer would never finish this transfer.
    var server: test_server.Server = undefined;
    try server.start(.{
        .pasv_address = .{ 203, 0, 113, 7 },
        .body = "the data connection went to the control host\n",
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/f.txt", .{ .disable_epsv = true }, null);
    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("the data connection went to the control host\n", contents);

    server.wait();
    try testing.expectEqual(@as(usize, 1), server.dataConnections());
}

test "a control byte in the path is refused before any connection opens" {
    // **The injection proof at the transfer.** Each url below would end a
    // command line and write a command of its own behind it. Not one of
    // them reaches a socket.
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    for ([_][]const u8{
        "/a%0d%0aQUIT",
        "/a%0aDELE%20important",
        "/dir%0d%0aRETR%20secret/f.txt",
        "/a%00b",
        "/a%09b",
        "/%0d%0aUSER%20root",
    }) |path| {
        var d: Diagnostics = .{};
        try testing.expectError(error.InvalidUrl, fetch(&f, &server, path, .{}, &d));
        try testing.expectEqual(@as(u32, 3), d.curl_code.?);
    }

    // The fixture never accepted a connection at all.
    try testing.expectEqual(@as(usize, 0), server.connections());
}

test "a credential that could forge a command is refused before any connection opens" {
    var server: test_server.Server = undefined;
    try server.start(.{});
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var url_buffer: [256]u8 = undefined;

    // From the url's own userinfo. curl refuses the same url with exit 3,
    // measured.
    for ([_][]const u8{
        "a%0d%0aPASS%20x:p",
        "u:p%0d%0aQUIT",
        "u%00x:p",
        "u:p%0ASTOR%20evil",
    }) |userinfo| {
        const text = try std.fmt.bufPrint(&url_buffer, "ftp://{s}@127.0.0.1:{d}/f.txt", .{ userinfo, server.port() });
        var d: Diagnostics = .{};
        try testing.expectError(error.InvalidUrl, f.open(
            try parseFtpUrl(text),
            .{ .connect_timeout = test_connect_timeout },
            &d,
        ));
        try testing.expectEqual(@as(u32, 3), d.curl_code.?);
    }

    // And from `-u`, which curl does not decode and therefore sends. zurl
    // refuses the raw bytes whatever source they came from.
    for ([_]Credentials{
        .{ .user = "alice\r\nPASS hunter2", .password = "x" },
        .{ .user = "alice", .password = "x\r\nDELE important" },
        .{ .user = "alice", .password = "x\x00y" },
    }) |credential| {
        var d: Diagnostics = .{};
        try testing.expectError(
            error.InvalidUrl,
            fetch(&f, &server, "/f.txt", .{ .credentials = credential }, &d),
        );
        try testing.expectEqual(@as(u32, 3), d.curl_code.?);
    }

    try testing.expectEqual(@as(usize, 0), server.connections());
}

test "the credential comes from the url, then -u, then netrc, then anonymous" {
    // curl's own order, and the one `zurl.authorize` keeps for HTTP.
    const rows = [_]struct {
        userinfo: []const u8,
        options: Options,
        want: []const u8,
    }{
        .{ .userinfo = "bob:pw@", .options = .{}, .want = "USER bob\nPASS pw\n" },
        .{
            .userinfo = "bob:pw@",
            .options = .{ .credentials = .{ .user = "alice", .password = "s3cret" } },
            .want = "USER bob\nPASS pw\n",
        },
        .{
            .userinfo = "",
            .options = .{ .credentials = .{ .user = "alice", .password = "s3cret" } },
            .want = "USER alice\nPASS s3cret\n",
        },
        .{
            .userinfo = "",
            .options = .{ .netrc_text = "machine 127.0.0.1 login carol password nrpw" },
            .want = "USER carol\nPASS nrpw\n",
        },
        .{ .userinfo = "", .options = .{}, .want = "USER anonymous\nPASS ftp@example.com\n" },
        // A url writes its credential escaped, so `%40` is an `@`. curl
        // decodes the userinfo and nothing else, measured.
        .{ .userinfo = "a%40b:p%20q@", .options = .{}, .want = "USER a@b\nPASS p q\n" },
    };

    for (rows) |row| {
        var server: test_server.Server = undefined;
        try server.start(.{});
        defer server.stop();

        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();

        var url_buffer: [256]u8 = undefined;
        const text = try std.fmt.bufPrint(&url_buffer, "ftp://{s}127.0.0.1:{d}/f.txt", .{ row.userinfo, server.port() });
        var options = row.options;
        options.connect_timeout = test_connect_timeout;
        _ = try f.open(try parseFtpUrl(text), options, null);

        server.wait();
        try testing.expect(std.mem.startsWith(u8, server.commands(), row.want));
    }
}

test "-C sends REST before RETR, and the server sends the rest of the file" {
    var server: test_server.Server = undefined;
    try server.start(.{ .body = "0123456789abcdef" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const body = try fetch(&f, &server, "/f.txt", .{ .resume_from = 10 }, null);
    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("abcdef", contents);
    // `size` is the whole file and `length` is what this transfer took.
    try testing.expectEqual(@as(?u64, 16), body.size);
    try testing.expectEqual(@as(u64, 6), body.length);

    server.wait();
    // Measured: curl sends `SIZE`, then `REST 10`, then `RETR`.
    try testing.expect(std.mem.indexOf(u8, server.commands(), "SIZE f.txt\nREST 10\nRETR f.txt") != null);
}

test "an open ended -r is a REST, and every other form is refused with no connection" {
    {
        var server: test_server.Server = undefined;
        try server.start(.{ .body = "0123456789" });
        defer server.stop();

        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();

        const body = try fetch(&f, &server, "/f.txt", .{ .range = "bytes=4-" }, null);
        const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
        defer testing.allocator.free(contents);
        try testing.expectEqualStrings("456789", contents);

        server.wait();
        try testing.expect(std.mem.indexOf(u8, server.commands(), "REST 4\n") != null);
    }
    {
        var server: test_server.Server = undefined;
        try server.start(.{});
        defer server.stop();

        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();

        for ([_][]const u8{ "bytes=5-15", "bytes=-100", "bytes=0-9,20-29" }) |value| {
            var d: Diagnostics = .{};
            try testing.expectError(
                error.RangeError,
                fetch(&f, &server, "/f.txt", .{ .range = value }, &d),
            );
            try testing.expectEqual(@as(u32, 33), d.curl_code.?);
        }
        // Refused before the dial, so nothing was opened.
        try testing.expectEqual(@as(usize, 0), server.connections());
    }
}

test "each answer the server refuses carries curl's own exit code" {
    const rows = [_]struct {
        script: test_server.Script,
        path: []const u8,
        want: Error,
        code: u32,
    }{
        // Measured against curl 8.21.0 on a loopback server, one row for
        // each.
        .{ .script = .{ .pass = "530 Login incorrect" }, .path = "/f.txt", .want = error.LoginDenied, .code = 67 },
        .{ .script = .{ .user = "530 Not logged in" }, .path = "/f.txt", .want = error.LoginDenied, .code = 67 },
        .{ .script = .{ .cwd = "550 No such directory" }, .path = "/a/f.txt", .want = error.FtpAccessDenied, .code = 9 },
        .{ .script = .{ .type = "500 TYPE refused" }, .path = "/f.txt", .want = error.FtpCouldNotSetType, .code = 17 },
        .{ .script = .{ .size = "550 Not a plain file" }, .path = "/f.txt", .want = error.RemoteFileNotFound, .code = 78 },
        .{ .script = .{ .transfer_refused = "550 No such file" }, .path = "/f.txt", .want = error.RemoteFileNotFound, .code = 78 },
        .{ .script = .{ .transfer_end = "426 Transfer aborted" }, .path = "/f.txt", .want = error.PartialFile, .code = 18 },
        .{
            .script = .{ .epsv = false, .pasv_reply = "227 Entering Passive Mode blah blah" },
            .path = "/f.txt",
            .want = error.FtpWeird227Format,
            .code = 14,
        },
        .{
            .script = .{ .epsv = false, .pasv_reply = "500 PASV not understood" },
            .path = "/f.txt",
            .want = error.FtpWeirdPasvReply,
            .code = 13,
        },
        .{ .script = .{ .greeting = &.{"500 Go away"} }, .path = "/f.txt", .want = error.WeirdServerReply, .code = 8 },
        .{ .script = .{ .greeting = &.{"not a reply at all"} }, .path = "/f.txt", .want = error.WeirdServerReply, .code = 8 },
    };

    for (rows) |row| {
        var server: test_server.Server = undefined;
        try server.start(row.script);
        defer server.stop();

        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();

        var d: Diagnostics = .{};
        try testing.expectError(row.want, fetch(&f, &server, row.path, .{}, &d));
        try testing.expectEqual(row.code, d.curl_code.?);
    }
}

test "a REST the server refuses is exit 31, and the file is not fetched anyway" {
    var server: test_server.Server = undefined;
    try server.start(.{ .rest = "502 REST not implemented" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(
        error.FtpCouldNotUseRest,
        fetch(&f, &server, "/f.txt", .{ .resume_from = 10 }, &d),
    );
    try testing.expectEqual(@as(u32, 31), d.curl_code.?);

    server.wait();
    // No `RETR` went out. A transfer that fetched the whole file after a
    // refused `REST` would write the first ten bytes again, over the ten
    // the caller already has.
    try testing.expect(std.mem.indexOf(u8, server.commands(), "RETR") == null);
}

test "an answer past the size bound is refused and no byte of it comes back" {
    var big: [4096]u8 = undefined;
    @memset(&big, 'x');

    // Exactly the bound is read.
    {
        var server: test_server.Server = undefined;
        try server.start(.{ .body = big[0..1000] });
        defer server.stop();

        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();

        const body = try fetch(&f, &server, "/f.txt", .{ .max_response_bytes = 1000 }, null);
        try testing.expectEqual(@as(u64, 1000), body.length);
    }
    // One byte past it is not.
    {
        var server: test_server.Server = undefined;
        try server.start(.{ .body = big[0..1001] });
        defer server.stop();

        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();

        var d: Diagnostics = .{};
        try testing.expectError(
            error.FileSizeExceeded,
            fetch(&f, &server, "/f.txt", .{ .max_response_bytes = 1000 }, &d),
        );
        try testing.expectEqual(@as(u32, 63), d.curl_code.?);
    }
}

test "a server that never greets does not hold the transfer forever" {
    // **The bound on the control dialogue.** The connect succeeds, so the
    // dial is over, and the greeting never comes. Without
    // `zurl_net.bounded.readLine` this waits for as long as the peer
    // likes.
    var server: test_server.Server = undefined;
    try server.startSilent();
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    const short: Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(150), .clock = .awake } };
    try testing.expectError(
        error.OperationTimedOut,
        fetch(&f, &server, "/f.txt", .{ .read_timeout = short }, &d),
    );
    try testing.expectEqual(@as(u32, 28), d.curl_code.?);
}

test "an AUTH TLS the server refuses sends no credential and exits 64" {
    // **The rule this test holds: there is no fallback to plaintext.**
    // curl answers the same shape with exit 64 and sends no `USER`,
    // measured with `--ssl-reqd` against a server answering `504` to
    // `AUTH`.
    var server: test_server.Server = undefined;
    try server.start(.{ .auth = "504 AUTH not supported" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(
        error.UseSslFailed,
        fetch(&f, &server, "/f.txt", .{ .tls = .explicit, .insecure = true }, &d),
    );
    try testing.expectEqual(@as(u32, 64), d.curl_code.?);

    server.wait();
    // `AUTH TLS` went out, and nothing after it. No user name, no
    // password, and no file name.
    try testing.expectEqualStrings("AUTH TLS", server.commands());
}

test "an AUTH TLS the server accepts starts a handshake and never sends a credential in the clear" {
    // The fixture speaks no TLS, so the handshake goes nowhere. That is
    // the point, and it proves two things at once.
    //
    // **The credential never goes out.** `AUTH TLS` is the last command
    // the server sees. No `USER`, no `PASS`, and no file name follow it,
    // whether the handshake works or not.
    //
    // **The handshake is bounded.** RFC 4217 puts a command, a reply, and
    // a handshake between the dial and the login, and all three run inside
    // one `--connect-timeout`. Without that, a peer that answers `234` and
    // then says nothing holds the transfer forever. See
    // `zurl_net.bounded.Setup.upgrade`.
    var server: test_server.Server = undefined;
    try server.start(.{ .auth = "234 Proceed with negotiation" });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const short: Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(300), .clock = .awake } };
    var d: Diagnostics = .{};
    try testing.expectError(error.OperationTimedOut, fetch(
        &f,
        &server,
        "/f.txt",
        .{ .tls = .explicit, .insecure = true, .connect_timeout = short },
        &d,
    ));
    try testing.expectEqual(@as(u32, 28), d.curl_code.?);

    server.wait();
    // The fixture read `AUTH TLS` and then the bytes of a ClientHello,
    // which is not a command line, so nothing else was logged.
    try testing.expect(std.mem.startsWith(u8, server.commands(), "AUTH TLS"));
    try testing.expect(std.mem.indexOf(u8, server.commands(), "USER") == null);
    try testing.expect(std.mem.indexOf(u8, server.commands(), "PASS") == null);
    try testing.expect(std.mem.indexOf(u8, server.commands(), "RETR") == null);
}

test "PBSZ 0 and PROT P go out after the login, and a refusal ends the transfer" {
    // The fixture speaks no TLS, so this drives the step over two buffers
    // instead. See `Bench`.
    {
        var b: Bench = undefined;
        b.init("200 PBSZ=0\r\n200 PROT set\r\n");
        defer b.deinit();

        try b.f.protectData(null, null);
        try testing.expectEqualStrings("PBSZ 0\r\nPROT P\r\n", b.wire());
    }
    {
        // **A `PROT P` the server refuses ends the transfer.** Carrying on
        // would send the file in the clear while the session said it would
        // not.
        var b: Bench = undefined;
        b.init("200 PBSZ=0\r\n534 Request denied for policy reasons\r\n");
        defer b.deinit();

        var d: Diagnostics = .{};
        try testing.expectError(error.UseSslFailed, b.f.protectData(null, &d));
        try testing.expectEqual(@as(u32, 64), d.curl_code.?);
    }
    {
        var b: Bench = undefined;
        b.init("503 PBSZ not understood\r\n");
        defer b.deinit();

        var d: Diagnostics = .{};
        try testing.expectError(error.UseSslFailed, b.f.protectData(null, &d));
        try testing.expectEqual(@as(u32, 64), d.curl_code.?);
        // `PROT P` never went out after the refusal.
        try testing.expectEqualStrings("PBSZ 0\r\n", b.wire());
    }
}

test "a server that logs the user in at USER is not asked for a password" {
    // A `230` to `USER` means the login is done. A client that sent `PASS`
    // anyway would put a password on the wire the server never asked for.
    var b: Bench = undefined;
    b.init("230 Logged in, no password needed\r\n");
    defer b.deinit();

    try b.f.login(null, .{ .user = "anonymous", .password = "ftp@example.com" }, .anonymous, null);
    try testing.expectEqualStrings("USER anonymous\r\n", b.wire());
}

test "a login fault names the source of the credential and never the credential" {
    var b: Bench = undefined;
    b.init("331 Password required\r\n530 Login incorrect\r\n");
    defer b.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(
        error.LoginDenied,
        b.f.login(null, .{ .user = "alice", .password = "s3cret" }, .options, &d),
    );
    try testing.expectEqual(@as(u32, 67), d.curl_code.?);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "the -u option") != null);
    // The password is a secret and a diagnostic is printed and pasted into
    // bug reports.
    try testing.expect(std.mem.indexOf(u8, d.message.?, "s3cret") == null);
}

test "a 332 asking for an account is a named refusal and not a wait" {
    // zurl has no `--ftp-account`, so it cannot answer `332`. Saying so
    // beats sending nothing and waiting for a server that will not move.
    var b: Bench = undefined;
    b.init("331 Password required\r\n332 Need account for login\r\n");
    defer b.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(
        error.LoginDenied,
        b.f.login(null, .{ .user = "alice", .password = "s3cret" }, .options, &d),
    );
    try testing.expectEqual(@as(u32, 67), d.curl_code.?);
}

test "a SIZE the server does not implement is not a fault, and a 550 is" {
    {
        var b: Bench = undefined;
        b.init("502 SIZE not implemented\r\n");
        defer b.deinit();
        b.f.path.name = "f.txt";

        try testing.expectEqual(@as(?u64, null), try b.f.askSize(null, null));
    }
    {
        var b: Bench = undefined;
        b.init("213 not a number\r\n");
        defer b.deinit();
        b.f.path.name = "f.txt";

        try testing.expectEqual(@as(?u64, null), try b.f.askSize(null, null));
    }
    {
        var b: Bench = undefined;
        b.init("550 Not a plain file\r\n");
        defer b.deinit();
        b.f.path.name = "f.txt";

        var d: Diagnostics = .{};
        try testing.expectError(error.RemoteFileNotFound, b.f.askSize(null, &d));
        try testing.expectEqual(@as(u32, 78), d.curl_code.?);
    }
}

test "an ftps session verifies the peer, and -k is the one input that stops it" {
    var client: StubFront.Client = .{};
    const trust: Trust = client.tlsMaterials();

    // A plain `ftp://` hop opens no session and reads no certificate.
    {
        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();
        const none = try f.controlTlsOptions(
            try parseFtpUrl("ftp://example.com/f"),
            .{ .tls = .none, .trust = trust },
            null,
        );
        try testing.expectEqual(@as(?zurl_net.Connection.Tls, null), none);
        try testing.expectEqual(@as(usize, 0), client.loads);
    }

    // An `ftps://` hop verifies the chain and the host name, against the
    // bundle the front package loads for HTTP.
    {
        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();
        const session = (try f.controlTlsOptions(
            try parseFtpUrl("ftps://example.com/f"),
            .{ .tls = .implicit, .trust = trust },
            null,
        )).?;
        try testing.expectEqualStrings("example.com", session.host.explicit);
        try testing.expectEqual(&client.bundle, session.trust.bundle.bundle);
        try testing.expectEqual(&client.lock, session.trust.bundle.lock);
        try testing.expectEqual(@as(usize, 1), client.loads);
        // RFC 7301 needs a registered name, and FTP has none.
        try testing.expectEqual(@as(usize, 0), session.alpn_protocols.len);
        // A cut session is a fault and never a short file. See
        // `sessionOptions`.
        try testing.expect(!session.allow_truncation_attacks);
    }

    // `-k` turns both halves off together, the way curl does.
    {
        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();
        const session = (try f.controlTlsOptions(
            try parseFtpUrl("ftps://example.com/f"),
            .{ .tls = .implicit, .trust = trust, .insecure = true },
            null,
        )).?;
        try testing.expectEqual(zurl_net.Connection.HostCheck.none, session.host);
        try testing.expectEqual(zurl_net.Connection.TrustCheck.none, session.trust);
    }

    // **A build with no trust store cannot open a session at all.** The
    // fallback this refuses is the hole this package must not open.
    {
        var f: Fetcher = .init(testing.allocator, testing.io);
        defer f.deinit();
        var d: Diagnostics = .{};
        try testing.expectError(error.SslConnectError, f.controlTlsOptions(
            try parseFtpUrl("ftps://example.com/f"),
            .{ .tls = .implicit, .trust = null },
            &d,
        ));
        try testing.expect(std.mem.indexOf(u8, d.message.?, "trust store") != null);
    }
}

test "the data connection is protected whenever the control connection is" {
    // **`PROT P` would be a lie otherwise.** The data connection verifies
    // the same host against the same store, and `-k` is again the one
    // input that stops it.
    var client: StubFront.Client = .{};
    const trust: Trust = client.tlsMaterials();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    // No TLS on the control connection means none on the data connection.
    try testing.expectEqual(
        @as(?zurl_net.Connection.Tls, null),
        try f.dataTlsOptions("example.com", .{ .tls = .none, .trust = trust }, null),
    );

    for ([_]TlsMode{ .implicit, .explicit }) |mode| {
        const session = (try f.dataTlsOptions("example.com", .{ .tls = mode, .trust = trust }, null)).?;
        try testing.expectEqualStrings("example.com", session.host.explicit);
        try testing.expectEqual(&client.bundle, session.trust.bundle.bundle);
        try testing.expect(!session.allow_truncation_attacks);
    }

    // No trust store is a refusal here too, and never a plain data
    // connection under a `PROT P` that already went out.
    var d: Diagnostics = .{};
    try testing.expectError(
        error.SslConnectError,
        f.dataTlsOptions("example.com", .{ .tls = .implicit, .trust = null }, &d),
    );
}

test "no option other than -k moves an ftps session off verification" {
    // A build that grew a second way to reach `.none` fails here.
    var client: StubFront.Client = .{};
    const trust: Trust = client.tlsMaterials();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const url = try parseFtpUrl("ftps://example.com/f");
    const variants = [_]Options{
        .{ .tls = .implicit, .trust = trust, .tcp_no_delay = false },
        .{ .tls = .implicit, .trust = trust, .max_response_bytes = 1 },
        .{ .tls = .implicit, .trust = trust, .tls_min_version = .tls_1_3 },
        .{ .tls = .implicit, .trust = trust, .list_only = true },
        .{ .tls = .implicit, .trust = trust, .resume_from = 99 },
        .{ .tls = .implicit, .trust = trust, .trust_pasv_address = true },
        .{ .tls = .explicit, .trust = trust },
        // A moved dial is one more input that must not reach the check.
        .{
            .tls = .implicit,
            .trust = trust,
            .connect_to = &.{.{ .to_host = "127.0.0.1", .to_port = 9 }},
        },
    };
    for (variants) |options| {
        const session = (try f.controlTlsOptions(url, options, null)).?;
        try testing.expectEqualStrings("example.com", session.host.explicit);
        try testing.expect(session.trust == .bundle);
    }
}

test "an open ended range becomes a REST offset, and every other form is refused" {
    try testing.expectEqual(@as(u64, 5), try restFromRange("bytes=5-"));
    try testing.expectEqual(@as(u64, 0), try restFromRange("bytes=0-"));
    try testing.expectEqual(@as(u64, 4096), try restFromRange("4096-"));

    // Each of these has an end, or two, and RFC 959 has no command for
    // one. See `restFromRange`.
    for ([_][]const u8{
        "bytes=5-15",
        "bytes=-100",
        "bytes=0-9,20-29",
        "bytes=",
        "bytes=x-",
        "bytes=5",
        "",
        "-",
    }) |value| {
        try testing.expectError(error.RangeError, restFromRange(value));
    }
}

test "--connect-to moves the ftp control dial, and the data connection follows it" {
    // **The reported defect, and the half of it that is easy to miss.**
    // This package read no `connect_to` at all, so a user who named
    // `--connect-to` or `--resolve` reached the url's own host and got no
    // diagnostic.
    //
    // The data connection is the second half. `dataTarget` dials the
    // **numeric address the control connection reached** and never the
    // address a `227` answer names, so a data connection left on the url's
    // own host would reach a second machine and the transfer would stop.
    // curl 8.21.0 does the same, measured against a loopback RFC 959
    // fixture that answered `227 ... (10,99,99,99,...)`: curl said
    // `Skip 10.99.99.99 for data connection` and then dialed the address
    // the control connection had reached, on the port the answer named.
    //
    // **No test here touches a resolver, and neither does the transfer.**
    // The url names `127.0.0.2:1`, which refuses at once, so the flag is
    // the only thing that can reach the fixture. The data connection asks
    // no resolver either, whatever the url named: `dataTarget` hands back
    // an address and has no way to name a host.
    var server: test_server.Server = undefined;
    try server.start(.{
        .epsv = false,
        .pasv_address = .{ 203, 0, 113, 7 },
        .body = "moved by --connect-to\n",
    });
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    const url = try parseFtpUrl("ftp://127.0.0.2:1/f.txt");

    // Without an entry the dial goes where the url says and is refused.
    var bare: Diagnostics = .{};
    try testing.expectError(error.CouldNotConnect, f.open(url, .{
        .connect_timeout = test_connect_timeout,
    }, &bare));
    try testing.expectEqual(@as(usize, 0), server.connections());

    const body = try f.open(url, .{
        .connect_timeout = test_connect_timeout,
        .connect_to = &.{.{
            .from_host = "127.0.0.2",
            .from_port = 1,
            .to_host = "127.0.0.1",
            .to_port = server.port(),
        }},
    }, null);
    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("moved by --connect-to\n", contents);

    server.wait();
    try testing.expectEqual(@as(usize, 1), server.connections());
    // The proof the data connection followed the control connection: the
    // fixture listens on 127.0.0.1 alone, and it counted the dial.
    try testing.expectEqual(@as(usize, 1), server.dataConnections());
}

test "a moved dial leaves an ftps certificate checked against the url's own name" {
    // **The rule that keeps this flag from becoming a second `-k`.** Both
    // connections dial the address the entry names, and both check the
    // certificate against the name the url wrote. `readData` takes the
    // two as separate arguments for exactly this reason.
    var client: StubFront.Client = .{};
    const trust: Trust = client.tlsMaterials();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const url = try parseFtpUrl("ftps://example.com/f.txt");
    const overrides: []const zurl_net.override.HostOverride = &.{.{
        .from_host = "example.com",
        .from_port = 990,
        .to_host = "127.0.0.1",
        .to_port = 9999,
    }};

    // The entry does move the dial.
    const moved = zurl_net.override.dialTarget(overrides, url.host, url.port.?);
    try testing.expectEqualStrings("127.0.0.1", moved.host);
    try testing.expectEqual(@as(u16, 9999), moved.port);

    // The control session still names the url's host.
    const control = (try f.controlTlsOptions(url, .{
        .tls = .implicit,
        .trust = trust,
        .connect_to = overrides,
    }, null)).?;
    try testing.expectEqualStrings("example.com", control.host.explicit);
    try testing.expect(control.trust == .bundle);

    // And so does the data session, which `open` hands `url.host` and
    // never the dialed address.
    const data = (try f.dataTlsOptions("example.com", .{
        .tls = .implicit,
        .trust = trust,
        .connect_to = overrides,
    }, null)).?;
    try testing.expectEqualStrings("example.com", data.host.explicit);
    try testing.expect(data.trust == .bundle);
}

test "the ftp translation carries --connect-to into this package" {
    // A translation that dropped the field would leave both flags working
    // in a unit test and doing nothing on the command line.
    var client: StubFront.Client = .{};
    const D = Dispatch(StubFront);
    const url = try parseFtpUrl("ftp://example.com/f.txt");

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
