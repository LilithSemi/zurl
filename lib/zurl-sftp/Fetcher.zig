//! Runs one `sftp://` transfer: the dial, the login, the subsystem, and
//! the file.
//!
//! **A `Fetcher` must not move once `open` has run.** The body reader it
//! hands back points into this value.
//!
//! **The answer is bounded.** `Options.max_response_bytes` is the bound on
//! what one transfer reads, and a file past it is `error.FileSizeExceeded`,
//! exit 63. **`--max-filesize` sets that bound and may raise it**, which
//! this package and `zurl-scp` alone do among the twelve that hold an
//! answer in memory. See `default_max_response_bytes` and
//! `Dispatch.translate`.
//!
//! ## What a url names
//!
//! The path is percent-decoded and sent to the server as it is written. An
//! absolute path is absolute on the server, and a relative one is relative
//! to the login directory, which is what `sftp-server` does with it.
//! Measured against curl 8.21.0 and OpenSSH 10.5p1: `sftp://host/etc/hostname`
//! read `/etc/hostname`.
//!
//! **A path that ends in `/` is a directory listing**, which is what curl
//! does. The body is the server's own `ls -l` text, one entry to a line,
//! and `-l` gives the file names alone. Both were measured against curl.
//!
//! ## Nothing here names an output file
//!
//! A listing puts the server's file names in the **body**, where they are
//! bytes like any other. **No file name from a server reaches the
//! filesystem in this build**: `-O` takes its name from the url, and
//! `src/cli/output.zig`'s `checkName` is the one function that judges such
//! a name. A later build that took a name from a listing sends it through
//! that function and writes no second copy of the rule.

const Fetcher = @This();

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_net = @import("zurl-net");
const zurl_ssh = @import("zurl-ssh");

const protocol_wire = @import("protocol.zig");
const Session = @import("Session.zig");

const Diagnostics = zurl_core.Diagnostics;
const Error = zurl_core.Error;
const Io = std.Io;

/// The url scheme this package handles.
pub const scheme = "sftp";

/// The port a url of this scheme uses when it names none.
///
/// 22, which RFC 4253 assigns and which curl 8.21.0 dials, measured.
pub const default_port: ?u16 = 22;

/// The status an SFTP transfer reports.
///
/// Zero, because SFTP has no status of its own. curl prints `000` for
/// `%{http_code}` on a protocol with none.
pub const status: u16 = 0;

/// How many bytes of answer this package reads by default.
///
/// 16 MiB, the number every in-memory protocol package of this repository
/// keeps: `zurl-ftp`, `zurl-dict`, `zurl-gopher`, `zurl-imap`, `zurl-ldap`,
/// `zurl-mqtt`, `zurl-pop3`, `zurl-telnet`, `zurl-tftp`, and `zurl-ws`.
///
/// **A file on a server can be any size, and this package holds the whole
/// answer in memory.** `download` collects every chunk into one list and
/// hands the list to the caller, so the bound on the answer is the bound
/// on the memory one transfer asks for. The stated size a server writes
/// before the transfer is not that bound, because a server is free to
/// state one number and send another.
///
/// **2 GiB was the number here, and it was eight times the memory of the
/// target machine.** zurl is built for a board with 256 MB of RAM.
/// Measured at ReleaseFast, a 200 MiB answer held 192 MiB resident and
/// reached 452 MiB of accounted allocation while the list grew, so the
/// old ceiling let one server drive this process past the memory of the
/// machine it runs on.
///
/// `Options.max_response_bytes` is this bound, and **`--max-filesize`
/// sets it and may raise it**. This package and `zurl-scp` are the two
/// that let the flag raise the default, and `Dispatch.translate` says
/// why: a protocol whose whole job is moving files cannot hold a default
/// that no flag reaches, or a file of 17 MB becomes one this build
/// refuses to move. The user owns what a large number costs on a small
/// machine, the way they own `-Doptimize`.
pub const default_max_response_bytes: u64 = 16 * 1024 * 1024;

/// How long one read may wait with no byte arriving.
///
/// 300 seconds, which is curl's own `--speed-time` default.
/// `--speed-time` narrows it and never widens it.
pub const default_read_timeout_s: u32 = 300;

/// `default_read_timeout_s`, as a `std.Io.Timeout`.
pub const default_read_timeout: Io.Timeout = .{
    .duration = .{ .raw = .fromSeconds(default_read_timeout_s), .clock = .awake },
};

/// How many bytes of the file this reads in one `SSH_FXP_READ`.
pub const chunk_bytes: usize = protocol_wire.max_read_bytes;

/// The largest credential this reads out of a url.
pub const max_credential_bytes: usize = 512;

/// How many directory entries one listing may hold.
///
/// A server writes the count, and a listing is read into memory. 65536
/// entries at a bounded line each is the bound on both.
pub const max_listing_entries: u64 = 65536;

/// How many `SSH_FXP_READDIR` round trips one listing may take.
///
/// **A loop that counts entries does not bound round trips.** A server
/// that answers a directory read with a batch of no names moves nothing,
/// and `Session.readDirectory` ends the walk on such a batch. This is the
/// second bound: one round trip may carry one entry, so a listing that has
/// taken more round trips than `max_listing_entries` is a server that
/// makes no progress.
pub const max_listing_requests: u64 = max_listing_entries;

/// Where the octets this transfer sends come from.
///
/// The shape matches `zurl_http.engine.Body` field for field, because
/// `src/cli/body.zig` fills one of those from `-T`. It is written out here
/// because this package must build with no `zurl` in its import table.
pub const Source = struct {
    len: ?u64,
    ctx: *anyopaque,
    read: *const fn (ctx: *anyopaque, buffer: [*]u8, len: usize) callconv(.c) isize,
};

/// A user name and a password, as this package sends them.
pub const Credentials = struct {
    user: []const u8,
    password: []const u8,
};

/// Where a credential came from, for a message a person reads.
pub const CredentialSource = enum {
    userinfo,
    options,
    netrc,
    /// The login name the caller read from the environment.
    environment,

    pub fn describe(s: CredentialSource) []const u8 {
        return switch (s) {
            .userinfo => "the user name and password in the url",
            .options => "-u",
            .netrc => "the netrc file",
            .environment => "the login name of this account",
        };
    }
};

/// What one transfer may ask for.
pub const Options = struct {
    /// A cap on the dial.
    connect_timeout: Io.Timeout = .none,
    /// The bound on the answer. See `default_max_response_bytes`.
    max_response_bytes: u64 = default_max_response_bytes,
    /// How long one read may wait with no byte arriving.
    read_timeout: Io.Timeout = default_read_timeout,
    /// The slowest acceptable rate, in bytes each second, with both
    /// directions counted. Zero turns the rate rule off. This is
    /// `--speed-limit`.
    ///
    /// **`read_timeout` is not this bound.** That one says how long one
    /// read may wait, and it starts again at every byte that arrives, so
    /// a server that writes one byte just before each wait runs out
    /// passes it for ever. See `zurl_ssh.Transport.rateDeadline`.
    low_speed_limit: u64 = 0,
    /// How long the rate may stay under `low_speed_limit`, in seconds.
    /// Zero turns the rate rule off. This is `--speed-time`.
    low_speed_time_s: u32 = 0,
    /// Whether to turn Nagle's algorithm off.
    tcp_no_delay: bool = true,
    /// `-u`.
    credentials: ?Credentials = null,
    /// `--netrc-file` text, already read by the caller.
    netrc_text: ?[]const u8 = null,
    /// The login name to use when the url and `-u` name none. The caller
    /// reads it from the environment, because this package reads none.
    default_user: ?[]const u8 = null,
    /// The user's home directory, which the caller read. It is where the
    /// default `known_hosts` and the default private key are looked for.
    home: ?[]const u8 = null,
    /// `--knownhosts`.
    known_hosts_path: ?[]const u8 = null,
    /// `--hostpubmd5`.
    host_pub_md5: ?[]const u8 = null,
    /// `--hostpubsha256`.
    host_pub_sha256: ?[]const u8 = null,
    /// `-k`. **The one field here that turns a check off.**
    insecure: bool = false,
    /// `-l`: the names alone rather than the server's `ls -l` text.
    list_only: bool = false,
    /// `-C`: where a download starts.
    resume_from: u64 = 0,
    /// What to send, or null for a download. This is `-T`.
    body: ?Source = null,
    /// Where a url naming one host and port dials instead. This is
    /// `--resolve` and `--connect-to`.
    ///
    /// **An entry moves the dial and it never moves the host key check.**
    /// The `known_hosts` lookup is keyed on the name the url wrote, so a
    /// redirected dial reaches a machine whose key is not the record for
    /// that name, and the connection is refused with exit 60. A first
    /// connection to a name with no record is refused too, and this
    /// package writes no `known_hosts` file, so the flag can neither pass
    /// a wrong key nor add a record. See `zurl_ssh.Client.Options.dial`.
    connect_to: []const zurl_net.override.HostOverride = &.{},
};

allocator: std.mem.Allocator,
io: Io,

/// The answer of the transfer in play, or null when none is held.
answer: ?[]u8,
/// Reads `answer`. Valid only while `answer` holds something.
body: Io.Reader,

/// Holds a credential decoded out of a url's userinfo.
credential_storage: [max_credential_bytes * 2]u8,
/// Holds the path decoded out of the url.
path_storage: [protocol_wire.max_path_bytes]u8,
/// Holds the path of the `known_hosts` file that was read.
known_hosts_path_storage: [std.Io.Dir.max_path_bytes]u8,

/// A `Fetcher` that holds no answer yet.
pub fn init(allocator: std.mem.Allocator, io: Io) Fetcher {
    return .{
        .allocator = allocator,
        .io = io,
        .answer = null,
        .body = undefined,
        .credential_storage = undefined,
        .path_storage = undefined,
        .known_hosts_path_storage = undefined,
    };
}

/// Frees the answer this `Fetcher` holds. Safe to call more than once.
///
/// **The credential goes with it.** A `Fetcher` is reused across
/// transfers, so the password a url carried is wiped here as well as at
/// the end of each transfer.
pub fn deinit(f: *Fetcher) void {
    f.release();
    std.crypto.secureZero(u8, &f.credential_storage);
}

/// Frees the answer.
///
/// **The answer is the file, in the clear.** A private file that a
/// transfer read stays in that memory until something writes over it, so
/// it is wiped before the allocator may hand it to anything else.
fn release(f: *Fetcher) void {
    const held = f.answer orelse return;
    std.crypto.secureZero(u8, held);
    f.allocator.free(held);
    f.answer = null;
}

/// The answer of one SFTP transfer.
pub const Body = struct {
    reader: *Io.Reader,
    length: u64,
};

/// Runs one transfer and returns its answer.
///
/// The faults, and the exit code each carries:
///
/// - a host key that is not in `known_hosts`, or one that is and does not
///   match, is `error.PeerFailedVerification`, exit 60. curl answers 60
///   for both, measured.
/// - a login the server refused is `error.LoginDenied`, exit 67.
/// - a file the server has not got is `error.RemoteFileNotFound`, exit 78.
///   curl answers 78, measured.
/// - a file the server would not open is `error.FtpAccessDenied`, exit 9,
///   which is `CURLE_REMOTE_ACCESS_DENIED`.
/// - a key exchange that did not finish is `error.SslConnectError`,
///   exit 35.
/// - anything the peer said that this build could not use is
///   `error.WeirdServerReply`, exit 8.
pub fn open(f: *Fetcher, url: zurl_core.Url, options: Options, d: ?*Diagnostics) Error!Body {
    f.release();
    // **The password lives no longer than the transfer that sends it.**
    // `resolveCredentials` decodes it into this buffer, `Authenticator`
    // copies it into a request it wipes itself, and nothing after the
    // login reads it again.
    defer std.crypto.secureZero(u8, &f.credential_storage);

    const port = url.port orelse return fail(d, error.InvalidUrl, &.{
        "an sftp url names a port, and this one names none",
    });

    var source: CredentialSource = undefined;
    const credentials = try f.resolveCredentials(url, options, &source, d);
    const path = try f.resolvePath(url, d);

    // **The pins are checked for their spelling before a socket opens.** A
    // fingerprint that was mistyped is a usage fault now rather than a
    // trust failure after the handshake.
    zurl_ssh.knownhosts.checkPinText(
        options.host_pub_md5,
        options.host_pub_sha256,
    ) catch |err| return fail(d, error.CredentialTooLarge, &.{switch (err) {
        error.HostPubMd5Invalid => "--hostpubmd5 takes the 32 hexadecimal digits of an MD5 digest, which is what `ssh-keygen -E md5` prints with the colons taken out",
        error.HostPubSha256Invalid => "--hostpubsha256 takes the base64 of a SHA-256 digest, which is what `ssh-keygen -l` prints after `SHA256:`",
    }});

    var policy: zurl_ssh.knownhosts.Policy = .{
        .md5_pin = options.host_pub_md5,
        .sha256_pin = options.host_pub_sha256,
        .insecure = options.insecure,
    };

    // **The file is read only when nothing else has already decided.** A
    // pin answers on its own, which is what curl does, and `-k` skips the
    // check altogether.
    var opened: ?zurl_ssh.knownhosts.Opened = null;
    defer if (opened) |*held| held.close(f.allocator);
    if (policy.md5_pin == null and policy.sha256_pin == null and !policy.insecure) {
        if (zurl_ssh.knownhosts.read(f.allocator, f.io, .{
            .path = options.known_hosts_path,
            .home = options.home,
        }, &f.known_hosts_path_storage)) |held| {
            opened = held;
            policy.known_hosts = held.text;
            policy.known_hosts_path = held.path;
        } else |err| switch (err) {
            error.OutOfMemory => return Diagnostics.record(d, error.OutOfMemory, .{}),
            // Every one of these leaves the host unknown, and the message
            // is what tells them apart. None of them is a transfer.
            error.KnownHostsNotFound, error.KnownHostsHomeUnknown => {},
            else => policy.known_hosts_unreadable = true,
        }
    }

    var checker: zurl_ssh.knownhosts.Checker = .{ .policy = policy };

    // **`--resolve` and `--connect-to` move the dial and nothing else.**
    // `peer` below stays the name the url wrote, and that is the name the
    // `known_hosts` record is looked up under. See
    // `zurl_ssh.Client.Options.dial`.
    const target = zurl_net.override.dialTarget(options.connect_to, url.host, port);

    var client: zurl_ssh.Client = undefined;
    client.open(f.allocator, f.io, .{
        .peer = .{ .host = url.host, .port = port },
        .dial = .{ .host = target.host, .port = target.port },
        .verifier = checker.verifier(),
        .user = credentials.user,
        .password = if (credentials.password.len == 0) null else credentials.password,
        .key_location = .{ .home = options.home },
        .connect_timeout = options.connect_timeout,
        .stall = options.read_timeout,
        .low_speed_limit = options.low_speed_limit,
        .low_speed_time_s = options.low_speed_time_s,
        .tcp_no_delay = options.tcp_no_delay,
    }) catch |err| return f.reportClient(err, &client, &checker, url, source, d);
    defer client.close();

    var session: Session = undefined;
    session.init(f.allocator, &client.channel, .{}) catch |err| return switch (err) {
        error.OutOfMemory => Diagnostics.record(d, error.OutOfMemory, .{}),
        error.PacketLengthInvalid => fail(d, error.ReadError, &.{
            "zurl asked for an sftp packet bound it cannot frame",
        }),
    };
    defer session.deinit();

    client.channel.requestSubsystem(protocol_wire.subsystem_name) catch |err|
        return f.reportChannel(err, &client, d);
    session.start() catch |err| return f.reportSession(err, &session, d);

    if (options.body) |body_source| {
        try f.upload(&session, path, body_source, options, d);
        f.answer = f.allocator.alloc(u8, 0) catch
            return Diagnostics.record(d, error.OutOfMemory, .{});
        f.body = .fixed(f.answer.?);
        return .{ .reader = &f.body, .length = 0 };
    }

    const answer = if (path.len != 0 and path[path.len - 1] == '/')
        try f.listing(&session, path, options, d)
    else
        try f.download(&session, path, options, d);

    f.answer = answer;
    f.body = .fixed(answer);
    return .{ .reader = &f.body, .length = answer.len };
}

/// Reads one file into memory.
fn download(
    f: *Fetcher,
    session: *Session,
    path: []const u8,
    options: Options,
    d: ?*Diagnostics,
) Error![]u8 {
    const handle = session.open(path, protocol_wire.open_read) catch |err|
        return f.reportSession(err, session, d);
    // **The close runs whichever way this leaves.** A handle a client
    // never closes is a handle the server holds until the session ends.
    defer session.close(handle) catch {};

    // The size is read for the progress meter and for the bound. **A
    // server that sent no size said nothing about the size**, so the
    // bound is still checked as the bytes arrive.
    const attributes = session.fstat(handle) catch |err|
        return f.reportSession(err, session, d);
    if (attributes.isDirectory()) return fail(d, error.RemoteFileNotFound, &.{
        "this path names a directory on the server, and a directory is read with a url that ends in a slash",
    });
    if (attributes.size) |size| {
        if (size > options.max_response_bytes) return failNumber(
            d,
            error.FileSizeExceeded,
            "the file on the server is longer than the ",
            options.max_response_bytes,
            " bytes zurl reads in one transfer",
        );
    }

    var collected: std.ArrayList(u8) = .empty;
    errdefer collected.deinit(f.allocator);

    var offset: u64 = options.resume_from;
    var chunk: [chunk_bytes]u8 = undefined;
    while (true) {
        const taken = session.read(handle, offset, &chunk) catch |err|
            return f.reportSession(err, session, d);
        // **Only `SSH_FX_EOF` gets here with a zero.** `Session.read`
        // refuses an empty data reply, so a server cannot end the file by
        // answering with no bytes.
        if (taken == 0) break;
        if (@as(u64, collected.items.len) + taken > options.max_response_bytes) {
            return failNumber(
                d,
                error.FileSizeExceeded,
                "the file on the server is longer than the ",
                options.max_response_bytes,
                " bytes zurl reads in one transfer",
            );
        }
        collected.appendSlice(f.allocator, chunk[0..taken]) catch
            return Diagnostics.record(d, error.OutOfMemory, .{});
        // **The offset is a `u64` the user gave with `-C`.** A file that
        // is longer than the addresses the protocol has is a file no
        // server holds, and an add that wrapped would ask for the start of
        // the file again.
        offset = std.math.add(u64, offset, taken) catch return fail(d, error.FileSizeExceeded, &.{
            "this download passed the largest offset an sftp read names",
        });
    }

    if (transferIsShort(attributes.size, options.resume_from, collected.items.len)) {
        return failNumber(
            d,
            error.PartialFile,
            "the sftp server said the file holds ",
            attributes.size.?,
            " bytes and then ended the transfer early",
        );
    }

    return collected.toOwnedSlice(f.allocator) catch
        Diagnostics.record(d, error.OutOfMemory, .{});
}

/// Whether a download that has ended is shorter than the server said.
///
/// **The size the server stated is a promise, and a short file breaks
/// it.** `Session.read` refuses an empty data reply, so the file cannot be
/// cut that way any more, and this closes the other half: a server that
/// answers `SSH_FX_EOF` early hands back a piece of the file, and a client
/// with nothing to compare against reports a transfer that worked.
///
/// `stated` is null when the server named no size, and then there is
/// nothing to compare against and nothing is refused. A file that grew
/// while it was read is not short, so only a shortfall is a fault. `-C`
/// starts the read part way in, so the bytes to expect are what is left
/// after that point.
fn transferIsShort(stated: ?u64, resume_from: u64, taken: u64) bool {
    const size = stated orelse return false;
    const start = @min(resume_from, size);
    return taken < size - start;
}

/// Reads a directory listing into memory.
///
/// The body is the server's `longname` for each entry, which is its own
/// `ls -l` text, or the file names alone with `-l`. Both were measured
/// against curl 8.21.0.
fn listing(
    f: *Fetcher,
    session: *Session,
    path: []const u8,
    options: Options,
    d: ?*Diagnostics,
) Error![]u8 {
    const handle = session.openDirectory(
        path,
    ) catch |err|
        return f.reportSession(err, session, d);
    defer session.close(handle) catch {};

    var collected: std.ArrayList(u8) = .empty;
    errdefer collected.deinit(f.allocator);

    var entries: u64 = 0;
    // **The round trips are bounded as well as the entries.** The entry
    // count rises only inside the inner loop, so a bound on entries alone
    // never fires against a server that answers every `SSH_FXP_READDIR`
    // with a batch this side reads no name from.
    var requests: u64 = 0;
    while (true) {
        requests += 1;
        if (requests > max_listing_requests) return failNumber(
            d,
            error.WeirdServerReply,
            "the sftp server answered more than ",
            max_listing_requests,
            " directory reads without ending the listing",
        );
        var batch = (session.readDirectory(handle) catch |err|
            return f.reportSession(err, session, d)) orelse break;
        while (batch.iterator.next() catch |err| return f.reportSession(err, session, d)) |name| {
            entries += 1;
            if (entries > max_listing_entries) return failNumber(
                d,
                error.FileSizeExceeded,
                "this directory holds more than the ",
                max_listing_entries,
                " entries zurl lists",
            );
            // **The server chose this text.** It goes into the body, which
            // is where every other protocol's answer goes, and it never
            // names a file zurl writes. See the module comment.
            const text = if (options.list_only) name.filename else name.longname;
            if (@as(u64, collected.items.len) + text.len + 1 > options.max_response_bytes) {
                return failNumber(
                    d,
                    error.FileSizeExceeded,
                    "the listing is longer than the ",
                    options.max_response_bytes,
                    " bytes zurl reads in one transfer",
                );
            }
            collected.appendSlice(f.allocator, text) catch
                return Diagnostics.record(d, error.OutOfMemory, .{});
            collected.append(f.allocator, '\n') catch
                return Diagnostics.record(d, error.OutOfMemory, .{});
        }
    }

    return collected.toOwnedSlice(f.allocator) catch
        Diagnostics.record(d, error.OutOfMemory, .{});
}

/// Writes one file from the caller's source.
fn upload(
    f: *Fetcher,
    session: *Session,
    path: []const u8,
    source: Source,
    options: Options,
    d: ?*Diagnostics,
) Error!void {
    _ = options;
    const flags = protocol_wire.open_write |
        protocol_wire.open_create |
        protocol_wire.open_truncate;
    const handle = session.open(path, flags) catch |err|
        return f.reportSession(err, session, d);

    var offset: u64 = 0;
    var chunk: [protocol_wire.max_write_bytes]u8 = undefined;
    while (true) {
        const n = source.read(source.ctx, &chunk, chunk.len);
        if (n < 0) {
            session.close(handle) catch {};
            return fail(d, error.ReadError, &.{
                "zurl did not read what it was told to send to the sftp server",
            });
        }
        if (n == 0) break;
        const taken: usize = @intCast(n);
        // **The callback reports the count and this side gave the room.**
        // A count past the buffer would read past its end, so it is a
        // named refusal rather than a slice this build cannot make.
        if (taken > chunk.len) {
            session.close(handle) catch {};
            return fail(d, error.ReadError, &.{
                "zurl was told more bytes were read for this upload than it asked for",
            });
        }
        session.write(handle, offset, chunk[0..taken]) catch |err| {
            session.close(handle) catch {};
            return f.reportSession(err, session, d);
        };
        offset += taken;
    }

    // **The close is not a formality on an upload.** The draft lets a
    // server report a write it deferred here, so a client that dropped
    // this answer would call a failed upload a good one.
    session.close(handle) catch |err| return f.reportSession(err, session, d);
}

/// The credential this transfer sends, in curl's own order.
///
/// The url's userinfo first, then `-u`, then a netrc entry for the url's
/// host, then the login name of this account, which the caller read from
/// the environment. That is the order `zurl_ftp` keeps, with the anonymous
/// login replaced: **SSH has no anonymous account**, so a transfer with no
/// name at all is refused rather than run as somebody.
///
/// **The userinfo is percent-decoded and the other two are not**, which is
/// what curl does and what `zurl_ftp` records in the same words.
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
            if (raw_user.len > max_credential_bytes) return fail(d, error.CredentialTooLarge, &.{
                "the user name in this url is longer than zurl sends",
            });
            const user = zurl_core.url.percentDecode(
                f.credential_storage[0..raw_user.len],
                raw_user,
            ) catch return fail(d, error.InvalidUrl, &.{
                "the user name in this url holds a percent escape that is not an escape",
            });

            const password = if (url.password) |raw_password| pw: {
                if (raw_password.len > max_credential_bytes) {
                    return fail(d, error.CredentialTooLarge, &.{
                        "the password in this url is longer than zurl sends",
                    });
                }
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

        if (options.default_user) |name| {
            if (name.len != 0) {
                source.* = .environment;
                break :found .{ .user = name, .password = "" };
            }
        }

        return fail(d, error.LoginDenied, &.{
            "this sftp url names no user, and ssh has no anonymous account: write the name in the url or give it with -u",
        });
    };

    if (resolved.user.len == 0) return fail(d, error.LoginDenied, &.{
        "the user name from ",
        source.*.describe(),
        " is empty, and ssh has no anonymous account",
    });
    if (resolved.user.len > zurl_ssh.userauth.max_user_bytes) {
        return fail(d, error.CredentialTooLarge, &.{
            "the user name is longer than an ssh user name may be",
        });
    }
    return resolved;
}

/// The remote path this transfer names.
///
/// The url's path, percent-decoded. **A NUL is refused**: the path goes
/// into a length-prefixed SSH string, so a NUL cannot end it early on the
/// wire, and a server that copies the name into a C string would cut it
/// there. Refusing costs nothing and closes the difference between what
/// zurl asked for and what the server acted on.
fn resolvePath(f: *Fetcher, url: zurl_core.Url, d: ?*Diagnostics) Error![]const u8 {
    if (url.path.len > f.path_storage.len) return fail(d, error.InvalidUrl, &.{
        "the path in this url is longer than zurl sends to an sftp server",
    });
    const decoded = zurl_core.url.percentDecode(
        f.path_storage[0..url.path.len],
        url.path,
    ) catch return fail(d, error.InvalidUrl, &.{
        "the path in this url holds a percent escape that is not an escape",
    });
    if (std.mem.indexOfScalar(u8, decoded, 0) != null) return fail(d, error.InvalidUrl, &.{
        "the path in this url holds a NUL, and a server that copied it into a C string would act on a shorter path than zurl asked for",
    });
    if (decoded.len == 0) return ".";
    return decoded;
}

/// Reports a fault from `Client.open`, naming the step that stopped.
fn reportClient(
    f: *Fetcher,
    err: zurl_ssh.Client.Error,
    client: *zurl_ssh.Client,
    checker: *const zurl_ssh.knownhosts.Checker,
    url: zurl_core.Url,
    source: CredentialSource,
    d: ?*Diagnostics,
) Error {
    _ = f;
    defer client.close();

    // **The trust decision is reported before anything else**, because it
    // is the one a person has to act on and because the four answers have
    // four different fixes.
    const file_name = if (checker.policy.known_hosts_path.len != 0)
        checker.policy.known_hosts_path
    else
        "any known_hosts file zurl could read";

    switch (err) {
        error.HostKeyUnknown => {
            // **The counters are read here and nowhere else.** A line that
            // was skipped is a reason the host was not found, and a user
            // who is told nothing about it adds a second line that is
            // skipped for the same reason.
            const skipped = checker.counters.over_length +
                checker.counters.malformed +
                checker.counters.other_algorithm +
                checker.counters.certificate_authority_lines;
            var digits: [20]u8 = undefined;
            const count = std.fmt.bufPrint(&digits, "{d}", .{skipped}) catch digits[0..0];
            return fail(d, error.PeerFailedVerification, &.{
                "the host key of ",
                url.host,
                " is not in ",
                file_name,
                ": run `ssh-keyscan` and add it, or pin it with --hostpubsha256. zurl does not ask, and it does not add the key on its own",
                if (skipped != 0) ". zurl could not read " else "",
                if (skipped != 0) count else "",
                if (skipped != 0) " line(s) of that file" else "",
            });
        },
        // **The host is on record and this key type is not.** A message
        // that said the host was unknown would send the user to
        // `ssh-keyscan`, and `ssh-keyscan` would write the key that is in
        // front of them into the file beside the record they already
        // have. That is the one wrong message that helps an attacker.
        error.HostKeyAlgorithmUnknown => return fail(d, error.PeerFailedVerification, &.{
            "the host key of ",
            url.host,
            " is in ",
            file_name,
            " under a key type zurl cannot verify. zurl verifies ssh-ed25519 keys only, and the key this server presented is not the one on record. do not run `ssh-keyscan`: it would add this key beside the record. check the key with `ssh` first, or pin it with --hostpubsha256",
        }),
        error.HostKeyChanged => return fail(d, error.PeerFailedVerification, &.{
            "the host key of ",
            url.host,
            if (checker.pinned)
                " is not the one --hostpubsha256 or --hostpubmd5 named"
            else
                " is not the one on record. an attacker between zurl and the host looks like this. zurl does not update the record",
        }),
        error.HostKeyRejected => return fail(d, error.PeerFailedVerification, &.{
            "the host key of ",
            url.host,
            " is marked @revoked in known_hosts",
        }),
        error.HostKeyCheckFailed => return fail(d, error.PeerFailedVerification, &.{
            "zurl could not read the known_hosts file it was told to use, so it cannot say whether the host key of ",
            url.host,
            " is right",
        }),
        else => {},
    }

    return switch (client.phase) {
        .dial => reportDial(client, url.host, d),
        .handshake => fail(d, error.SslConnectError, &.{
            "the ssh key exchange with ",
            url.host,
            " did not finish: ",
            @errorName(err),
        }),
        .authenticate => switch (err) {
            error.AuthenticationFailed, error.NoUsableAuthMethod => fail(d, error.LoginDenied, &.{
                "the ssh server refused the credential from ",
                source.describe(),
                ". zurl signs with an ed25519 key under ~/.ssh and sends a password, and the server named what it takes",
            }),
            error.PrivateKeyPassphraseWrong => fail(d, error.LoginDenied, &.{
                "the private key needs a passphrase, and zurl has no way to ask for one",
            }),
            else => fail(d, error.LoginDenied, &.{
                "the ssh login stopped: ",
                @errorName(err),
            }),
        },
        .channel => fail(d, error.WeirdServerReply, &.{
            "the ssh server would not open a session channel: ",
            @errorName(err),
        }),
    };
}

fn reportChannel(
    f: *Fetcher,
    err: zurl_ssh.Channel.Error,
    client: *zurl_ssh.Client,
    d: ?*Diagnostics,
) Error {
    _ = f;
    _ = client;
    return switch (err) {
        error.ChannelRequestRefused => fail(d, error.WeirdServerReply, &.{
            "the ssh server refused the sftp subsystem: it may be turned off in its configuration, and OpenSSH names it with a `Subsystem sftp` line",
        }),
        error.OutOfMemory => Diagnostics.record(d, error.OutOfMemory, .{}),
        else => fail(d, error.WeirdServerReply, &.{
            "the ssh channel stopped: ",
            @errorName(err),
        }),
    };
}

/// Reports a fault from the SFTP session, with the server's own status
/// where there is one.
fn reportSession(
    f: *Fetcher,
    err: Session.Error,
    session: *const Session,
    d: ?*Diagnostics,
) Error {
    _ = f;
    if (err == error.ServerFault) {
        const held = session.lastStatus() orelse return fail(d, error.WeirdServerReply, &.{
            "the sftp server reported a fault and said nothing about it",
        });
        const own = held.status.text() orelse "the server reported a code this build does not name";
        return switch (held.status) {
            .no_such_file => fail(d, error.RemoteFileNotFound, &.{ "sftp: ", own }),
            .permission_denied => fail(d, error.FtpAccessDenied, &.{ "sftp: ", own }),
            // **The server's own message is not quoted here.** It is the
            // peer's text and nothing has made it safe for a terminal.
            else => fail(d, error.WeirdServerReply, &.{ "sftp: ", own }),
        };
    }
    return switch (err) {
        error.OutOfMemory => Diagnostics.record(d, error.OutOfMemory, .{}),
        error.VersionUnsupported => fail(d, error.WeirdServerReply, &.{
            "the sftp server does not speak version 3, which is the version OpenSSH speaks and the one zurl offers",
        }),
        error.PacketTruncated => fail(d, error.PartialFile, &.{
            "the ssh channel ended in the middle of an sftp packet",
        }),
        error.PacketLengthInvalid => fail(d, error.WeirdServerReply, &.{
            "the sftp server wrote a packet length zurl does not read",
        }),
        error.OperationTimedOut => fail(d, error.OperationTimedOut, &.{
            "the sftp server sent no byte for as long as zurl waits",
        }),
        // The rate rule and the wait give different sentences on purpose.
        // A peer that says nothing and a peer that drips are different
        // peers, and the second one is the flag the user set.
        error.TransferTooSlow => fail(d, error.OperationTimedOut, &.{
            "the sftp transfer stayed under the rate --speed-limit named for as long as --speed-time allows",
        }),
        error.Canceled => fail(d, error.AbortedByCallback, &.{
            "the sftp transfer was stopped from outside",
        }),
        else => fail(d, error.WeirdServerReply, &.{
            "the sftp exchange stopped: ",
            @errorName(err),
        }),
    };
}

/// Reports a dial fault with the sentence `zurl-net` holds for it.
///
/// The mapping comes from `Client.dial_fault`, which `zurl-ssh` fills in
/// at the one place a `SetupError` is still narrow enough to map.
fn reportDial(client: *const zurl_ssh.Client, host: []const u8, d: ?*Diagnostics) Error {
    const mapping = client.dial_fault orelse return fail(d, error.CouldNotConnect, &.{
        host,
        ": zurl did not open a connection",
    });
    if (mapping.message) |text| return fail(d, mapping.err, &.{ host, ": ", text });
    return fail(d, mapping.err, &.{ host, ": zurl did not open a connection" });
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

/// Returns the dispatch entry for the `sftp` scheme.
///
/// `Front` is the front package's own namespace, taken as a comptime
/// parameter. Passing the namespace rather than importing it is what keeps
/// this package free of a `zurl` import.
///
/// **`f` must outlive every transfer the client runs on this scheme**, and
/// must not move.
pub fn protocol(f: *Fetcher, comptime Front: type) Front.protocol.Protocol {
    return .{
        .scheme = scheme,
        .default_port = default_port,
        .ptr = f,
        .vtable = &Dispatch(Front).vtable,
        // This package dials the origin itself and reads no proxy field,
        // so a transfer that named a proxy is refused by name rather than
        // run direct. See `Front.protocol.Unread`.
        .unread = .{ .proxy = true },
    };
}

/// The vtable for one front package.
fn Dispatch(comptime Front: type) type {
    return struct {
        const vtable: Front.protocol.Protocol.VTable = .{ .perform = performSftp };

        fn performSftp(
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
        /// **`--max-filesize` sets the bound here, and may raise it.** See
        /// `zurl_scp.Fetcher.translate`, which says why these two packages
        /// differ from the ten that only narrow: they move files, so a
        /// default no flag could raise would stop this build moving a file
        /// of 17 MB at all. The default stays the house 16 MiB, because the
        /// whole transfer is held in memory and the smallest target has
        /// 256 MB of it.
        ///
        /// **`--speed-time` still only narrows the wait**, for the reason
        /// every other protocol package gives: the front package's stall
        /// guard cannot reach a transfer whose body is already in memory.
        ///
        /// **`--speed-limit` is carried through as well, and it is the
        /// bound that catches the byte drip.** `zurl.body` wraps a
        /// streaming body in `zurl_stream.Stall`, which is where the ten
        /// packages that stream get their rate rule. This package hands
        /// the front package a body that is already whole, so that
        /// decorator sees one instant read and judges nothing. The rule
        /// therefore has to run where the bytes actually arrive, which is
        /// `zurl_ssh.Transport`. See `zurl_ssh.Transport.rateDeadline`.
        fn translate(options: Front.Transfer.Options) Options {
            return .{
                .connect_timeout = options.connect_timeout,
                .max_response_bytes = if (options.max_size == 0)
                    default_max_response_bytes
                else
                    options.max_size,
                .read_timeout = zurl_net.bounded.stallTimeout(
                    options.low_speed_limit,
                    options.low_speed_time_s,
                    default_read_timeout_s,
                ),
                .low_speed_limit = options.low_speed_limit,
                .low_speed_time_s = options.low_speed_time_s,
                .tcp_no_delay = options.tcp_no_delay,
                .credentials = if (options.credentials) |credential|
                    .{ .user = credential.user, .password = credential.password }
                else
                    null,
                .netrc_text = options.netrc_text,
                .default_user = options.ssh_user,
                .home = options.ssh_home,
                .known_hosts_path = options.ssh_known_hosts,
                .host_pub_md5 = options.ssh_host_pub_md5,
                .host_pub_sha256 = options.ssh_host_pub_sha256,
                .insecure = options.insecure,
                .list_only = options.list_only,
                .resume_from = options.resume_from,
                .body = if (options.body) |body|
                    .{ .len = body.len, .ctx = body.ctx, .read = body.read }
                else
                    null,
                .connect_to = options.connect_to,
            };
        }
    };
}

const testing = std.testing;

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
            insecure: bool = false,
            credentials: ?zurl_core.auth.Credentials = null,
            netrc_text: ?[]const u8 = null,
            list_only: bool = false,
            resume_from: u64 = 0,
            body: ?Source = null,
            ssh_user: ?[]const u8 = null,
            ssh_home: ?[]const u8 = null,
            ssh_known_hosts: ?[]const u8 = null,
            ssh_host_pub_md5: ?[]const u8 = null,
            ssh_host_pub_sha256: ?[]const u8 = null,
            connect_to: []const zurl_net.override.HostOverride = &.{},
        };
    };

    const Response = struct {
        status: u16,
        content_length: ?u64,
        transfer_encoding: std.http.TransferEncoding,
        body: *Io.Reader,
    };

    const protocol = struct {
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

test "a download shorter than the size the server stated is a fault" {
    // The whole file arrived.
    try testing.expect(!transferIsShort(100, 0, 100));
    // One byte less than the server promised.
    try testing.expect(transferIsShort(100, 0, 99));
    try testing.expect(transferIsShort(100, 0, 0));
    // A file that grew while it was read is not a short one.
    try testing.expect(!transferIsShort(100, 0, 140));
    // **A server that named no size named nothing to compare against.**
    try testing.expect(!transferIsShort(null, 0, 0));
    // `-C` starts part way in, so what is left is what is expected.
    try testing.expect(!transferIsShort(100, 60, 40));
    try testing.expect(transferIsShort(100, 60, 39));
    // A resume point past the end of the file expects nothing, and the
    // subtraction never wraps.
    try testing.expect(!transferIsShort(100, 500, 0));
    try testing.expect(!transferIsShort(0, std.math.maxInt(u64), 0));
}

test "the round trips of a listing are bounded as well as its entries" {
    // A bound that counts entries never fires against a server that
    // answers every read with a batch this side takes no entry from. The
    // two bounds are equal, because one round trip carries one entry at
    // the least.
    try testing.expectEqual(max_listing_entries, max_listing_requests);
    try testing.expect(max_listing_requests > 0);
}

test "the dispatch entry names the scheme and the port RFC 4253 assigns" {
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const entry = f.protocol(StubFront);
    try testing.expectEqualStrings("sftp", entry.scheme);
    try testing.expectEqual(@as(?u16, 22), entry.default_port);
    // This package dials the origin itself, so a proxy is refused by name
    // rather than dropped.
    try testing.expect(entry.unread.proxy);
    try testing.expect(!entry.unread.credentials);
}

test "--max-filesize sets the bound here, and may raise it" {
    // See the test of the same name in `zurl-scp`, and
    // `Dispatch.translate` above, for why these two packages let the flag
    // raise the bound where the ten other in-memory packages only narrow.
    const D = Dispatch(StubFront);

    // No flag keeps the house default.
    try testing.expectEqual(
        default_max_response_bytes,
        D.translate(.{}).max_response_bytes,
    );

    // A smaller number narrows, as it always did.
    try testing.expectEqual(
        @as(u64, 1024),
        D.translate(.{ .max_size = 1024 }).max_response_bytes,
    );

    // A larger number raises. This is the line that changed.
    try testing.expectEqual(
        default_max_response_bytes * 4,
        D.translate(.{ .max_size = default_max_response_bytes * 4 }).max_response_bytes,
    );
}

test "the answer bound is the number every in-memory package of this repository keeps" {
    // **This package holds the whole answer in memory**, so the bound on
    // the answer is the bound on the memory one transfer asks for. 2 GiB
    // stood here once, which is eight times the memory of the machine zurl
    // is built for. See `default_max_response_bytes`.
    try testing.expectEqual(@as(u64, 16 * 1024 * 1024), default_max_response_bytes);
    // The field default follows the constant, so a caller that names no
    // bound gets the same number.
    // `zurl-scp` reads a file into memory the same way and keeps the same
    // number. It cannot be imported here, because the build gives this
    // package `zurl-core`, `zurl-net`, and `zurl-ssh` and nothing else, so
    // the number is pinned in that package's own test of this name.
    const o: Options = .{};
    try testing.expectEqual(default_max_response_bytes, o.max_response_bytes);
}

test "an answer past the bound is refused with a sentence that names the number" {
    // A user who meets this bound must be able to see what it is and what
    // to do about it, so the fault carries the number and never only a
    // name. Both places `download` checks the bound report through this
    // one call: the size the server states before the transfer, and the
    // bytes as they arrive.
    var d: zurl_core.Diagnostics = .{};
    // `failNumber` reports the fault as a value, so the name is compared
    // and never caught.
    try testing.expectEqual(Error.FileSizeExceeded, failNumber(
        &d,
        error.FileSizeExceeded,
        "the file on the server is longer than the ",
        default_max_response_bytes,
        " bytes zurl reads in one transfer",
    ));
    const message = d.message orelse return error.TestExpectedMessage;
    try testing.expect(std.mem.indexOf(u8, message, "16777216") != null);
    try testing.expect(std.mem.indexOf(u8, message, "longer than") != null);
}

test "the trust flags reach this package unchanged" {
    const D = Dispatch(StubFront);
    const plain = D.translate(.{});
    try testing.expect(!plain.insecure);
    try testing.expectEqual(@as(?[]const u8, null), plain.known_hosts_path);

    const named = D.translate(.{
        .insecure = true,
        .ssh_known_hosts = "/tmp/kh",
        .ssh_host_pub_sha256 = "abc",
        .ssh_host_pub_md5 = "def",
    });
    try testing.expect(named.insecure);
    try testing.expectEqualStrings("/tmp/kh", named.known_hosts_path.?);
    try testing.expectEqualStrings("abc", named.host_pub_sha256.?);
    try testing.expectEqualStrings("def", named.host_pub_md5.?);
}

test "a url with no user is refused, because ssh has no anonymous account" {
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var source: CredentialSource = undefined;
    var d: zurl_core.Diagnostics = .{};
    const url = try zurl_core.url.parse("http://host/f");
    // **An anonymous login is what FTP has and SSH has not.** A build that
    // guessed a name would log in as somebody the user did not name.
    try testing.expectError(error.LoginDenied, f.resolveCredentials(url, .{}, &source, &d));
    try testing.expect(d.message != null);
}

test "the credential order is the url, then -u, then netrc, then the login name" {
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var source: CredentialSource = undefined;
    {
        const url = try zurl_core.url.parse("http://alice:s3cret@host/f");
        const found = try f.resolveCredentials(url, .{
            .credentials = .{ .user = "bob", .password = "other" },
        }, &source, null);
        try testing.expectEqualStrings("alice", found.user);
        try testing.expectEqualStrings("s3cret", found.password);
        try testing.expectEqual(CredentialSource.userinfo, source);
    }
    {
        const url = try zurl_core.url.parse("http://host/f");
        const found = try f.resolveCredentials(url, .{
            .credentials = .{ .user = "bob", .password = "other" },
            .default_user = "fallback",
        }, &source, null);
        try testing.expectEqualStrings("bob", found.user);
        try testing.expectEqual(CredentialSource.options, source);
    }
    {
        const url = try zurl_core.url.parse("http://host/f");
        const found = try f.resolveCredentials(url, .{
            .netrc_text = "machine host login carol password pw\n",
            .default_user = "fallback",
        }, &source, null);
        try testing.expectEqualStrings("carol", found.user);
        try testing.expectEqual(CredentialSource.netrc, source);
    }
    {
        const url = try zurl_core.url.parse("http://host/f");
        const found = try f.resolveCredentials(url, .{
            .default_user = "fallback",
        }, &source, null);
        try testing.expectEqualStrings("fallback", found.user);
        try testing.expectEqual(CredentialSource.environment, source);
    }
}

test "a userinfo credential is percent-decoded and the others are not" {
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var source: CredentialSource = undefined;
    const url = try zurl_core.url.parse("http://a%40b:p%40w@host/f");
    const found = try f.resolveCredentials(url, .{}, &source, null);
    try testing.expectEqualStrings("a@b", found.user);
    try testing.expectEqualStrings("p@w", found.password);

    const plain = try zurl_core.url.parse("http://host/f");
    const given = try f.resolveCredentials(plain, .{
        .credentials = .{ .user = "a%40b", .password = "p%40w" },
    }, &source, null);
    try testing.expectEqualStrings("a%40b", given.user);
}

test "a path with a NUL in it is refused before it reaches the server" {
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var d: zurl_core.Diagnostics = .{};
    const url = try zurl_core.url.parse("http://host/a%00b");
    // A server that copied the name into a C string would act on `/a` and
    // report success for a path zurl never asked for.
    try testing.expectError(error.InvalidUrl, f.resolvePath(url, &d));
    try testing.expect(d.message != null);
}

test "a path is percent-decoded and an empty one names the login directory" {
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const spaced = try zurl_core.url.parse("http://host/a%20b.txt");
    try testing.expectEqualStrings("/a b.txt", try f.resolvePath(spaced, null));

    const listing_url = try zurl_core.url.parse("http://host/srv/");
    try testing.expectEqualStrings("/srv/", try f.resolvePath(listing_url, null));
}

test "the status the whole package reports is zero, because sftp has none" {
    try testing.expectEqual(@as(u16, 0), status);
}

test "the sftp translation carries --connect-to into this package" {
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

test "--speed-limit reaches the layer that reads the bytes" {
    // See `zurl_scp.Fetcher`'s test of the same name for why these two
    // packages carry the number down themselves: the body they hand the
    // front package is already whole, so `zurl_stream.Stall` never sees
    // the reads, and the rate rule has to run in `zurl_ssh.Transport`.
    const D = Dispatch(StubFront);

    const named = D.translate(.{ .low_speed_limit = 512, .low_speed_time_s = 45 });
    try testing.expectEqual(@as(u64, 512), named.low_speed_limit);
    try testing.expectEqual(@as(u32, 45), named.low_speed_time_s);

    const off = D.translate(.{ .low_speed_limit = 0, .low_speed_time_s = 45 });
    try testing.expectEqual(@as(u64, 0), off.low_speed_limit);
}
