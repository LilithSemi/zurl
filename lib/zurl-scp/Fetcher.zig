//! Runs one `scp://` transfer: the dial, the login, the `exec` channel, and
//! the rcp dialogue.
//!
//! **A `Fetcher` must not move once `open` has run.** The body reader it
//! hands back points into this value, and so does the standard error sink
//! it gives the channel.
//!
//! # The path reaches a shell, and that is the whole risk of this package
//!
//! `scp://` runs the `scp` binary on the far side over an `exec` request,
//! and RFC 4254 section 6.5 says the server runs the command "as if" a
//! shell had read it. **A path from a url is interpolated into that
//! command.** A build that did not quote it would turn
//! `scp://host/a;id` into a second command on somebody else's machine.
//!
//! `zurl_scp.command` is the one place that builds a command, and it states
//! the rule: **the whole path in single quotes, every embedded `'` written
//! as `'"'"'`, a NUL refused, and an empty or over-long path refused.**
//! This file calls it and builds no command of its own.
//!
//! # Nothing the server says names a file
//!
//! The server's `C` line carries a mode, a size, and a name, and the server
//! chose all three.
//!
//! - **The size bounds the read and the caller bounds the size.**
//!   `Options.max_response_bytes` is checked against the size before one
//!   byte is allocated, and again as the bytes arrive.
//! - **The name never reaches the filesystem.** `-O` takes its name from
//!   the url, which is what `src/cli/output.zig`'s `checkName` judges, and
//!   that is the one function in zurl that decides such a thing. The name
//!   here reaches a diagnostic and nothing else.
//! - **The mode is read and never applied.** A file this build writes gets
//!   the mode every other output file gets, under the process umask, so a
//!   server that answered `C4755` hands nobody a setuid file.
//!
//! # A failed remote command is not a good transfer
//!
//! RFC 4254 section 6.10 gives the command's exit status, and **this build
//! reads it**. A remote `scp` that could not open the file writes a
//! diagnostic and exits non-zero, and a client that took the empty body and
//! stopped there would report a successful transfer of nothing. A status
//! that is not zero is a fault, and **so is a channel that closed with no
//! status at all**: a server that said nothing about how the command ended
//! said nothing this build may read as success.
//!
//! # What this does not do
//!
//! No recursion, so a `D` line is refused by name and there is no `-r`.
//! No resume, so `-C` does not reach this scheme: the rcp protocol has no
//! offset and a partial file would be silently wrong. No directory listing,
//! because a remote `scp` lists nothing. `-T` uploads, and it needs a length
//! it can write on the `C` line, so standard input is refused by name.

const Fetcher = @This();

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_net = @import("zurl-net");
const zurl_ssh = @import("zurl-ssh");

const command = @import("command.zig");
const protocol_wire = @import("protocol.zig");
const Session = @import("Session.zig");

const Diagnostics = zurl_core.Diagnostics;
const Error = zurl_core.Error;
const Io = std.Io;

/// The url scheme this package handles.
pub const scheme = "scp";

/// The port a url of this scheme uses when it names none.
///
/// 22, which RFC 4253 assigns and which curl 8.21.0 dials, measured.
pub const default_port: ?u16 = 22;

/// The status an scp transfer reports.
///
/// Zero, because scp has no status of its own. curl prints `000` for
/// `%{http_code}` on a protocol with none.
pub const status: u16 = 0;

/// How many bytes of answer this package reads by default.
///
/// 16 MiB, which is what `zurl_sftp` keeps, and what every other in-memory
/// protocol package of this repository keeps, for the same reason: a file
/// on a server can be any size, this package holds the whole answer in
/// memory, and a transfer with no bound would be a transfer the server
/// chooses the memory for.
///
/// **2 GiB was the number here, and it was eight times the memory of the
/// target machine.** The `C` line of the scp protocol states a size before
/// the bytes arrive, and that statement is the server's own text, so it
/// bounds nothing. See `zurl_sftp.Fetcher.default_max_response_bytes` for
/// the measurement.
///
/// `Options.max_response_bytes` is this bound, and **`--max-filesize`
/// sets it and may raise it**. See `Dispatch.translate` for why this
/// package and `zurl-sftp` are the two that let a flag raise a default.
pub const default_max_response_bytes: u64 = 16 * 1024 * 1024;

/// How long one read may wait with no byte arriving.
///
/// 300 seconds, which is curl's own `--speed-time` default.
pub const default_read_timeout_s: u32 = 300;

/// `default_read_timeout_s`, as a `std.Io.Timeout`.
pub const default_read_timeout: Io.Timeout = .{
    .duration = .{ .raw = .fromSeconds(default_read_timeout_s), .clock = .awake },
};

/// How many bytes of the file this moves in one step.
pub const chunk_bytes: usize = 32 * 1024;

/// The largest credential this reads out of a url.
pub const max_credential_bytes: usize = 512;

/// How many bytes of the remote command's standard error this keeps.
///
/// 512. The remote `scp` writes its diagnostic there, and a person reading
/// a failure wants it. **It is the peer's own text**, so it goes through
/// `zurl_ssh.userauth.sanitizeBanner` before it reaches a message.
pub const max_stderr_bytes: usize = 512;

/// The mode this build writes on the `C` line of an upload.
///
/// 0644. This side has no mode to send: the body arrives through a callback
/// and not through a file this package opened. curl sends the local file's
/// own mode, and this build sends one it can defend, because a mode it
/// guessed would be a wrong mode written with confidence.
pub const upload_mode: u16 = 0o644;

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
    /// The user's home directory, which the caller read.
    home: ?[]const u8 = null,
    /// `--knownhosts`.
    known_hosts_path: ?[]const u8 = null,
    /// `--hostpubmd5`.
    host_pub_md5: ?[]const u8 = null,
    /// `--hostpubsha256`.
    host_pub_sha256: ?[]const u8 = null,
    /// `-k`. **The one field here that turns a check off.**
    insecure: bool = false,
    /// `-C`. The rcp protocol carries no offset, so anything but zero is
    /// refused by name rather than answered with a whole file.
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
path_storage: [command.max_path_bytes]u8,
/// Holds the remote command while it is built.
command_storage: [command.max_command_bytes]u8,
/// Holds the `exec` request while `Channel` builds it.
request_storage: [command.max_command_bytes + zurl_ssh.connection.max_control_bytes]u8,
/// Holds the path of the `known_hosts` file that was read.
known_hosts_path_storage: [std.Io.Dir.max_path_bytes]u8,

/// Holds what the remote command wrote to standard error. **The peer's own
/// text**, and it is sanitized before it reaches a message.
stderr_storage: [max_stderr_bytes]u8,
stderr_len: usize,

/// A `Fetcher` that holds no answer yet.
pub fn init(allocator: std.mem.Allocator, io: Io) Fetcher {
    return .{
        .allocator = allocator,
        .io = io,
        .answer = null,
        .body = undefined,
        .credential_storage = undefined,
        .path_storage = undefined,
        .command_storage = undefined,
        .request_storage = undefined,
        .known_hosts_path_storage = undefined,
        .stderr_storage = undefined,
        .stderr_len = 0,
    };
}

/// Frees the answer this `Fetcher` holds. Safe to call more than once.
///
/// **The credential goes with it.** A `Fetcher` is reused across transfers,
/// so the password a url carried is wiped here as well as at the end of
/// each transfer.
pub fn deinit(f: *Fetcher) void {
    f.release();
    std.crypto.secureZero(u8, &f.credential_storage);
}

/// Frees the answer.
///
/// **The answer is the file, in the clear.** A private file that a transfer
/// read stays in that memory until something writes over it, so it is wiped
/// before the allocator may hand it to anything else.
fn release(f: *Fetcher) void {
    const held = f.answer orelse return;
    std.crypto.secureZero(u8, held);
    f.allocator.free(held);
    f.answer = null;
}

/// The answer of one scp transfer.
pub const Body = struct {
    reader: *Io.Reader,
    length: u64,
};

/// Runs one transfer and returns its answer.
///
/// The faults, and the exit code each carries:
///
/// - a host key that is not in `known_hosts`, or one that is and does not
///   match, is `error.PeerFailedVerification`, exit 60.
/// - a login the server refused is `error.LoginDenied`, exit 67.
/// - a remote `scp` that said the file is not there is
///   `error.RemoteFileNotFound`, exit 78, which is what this build answers
///   for the same url over `sftp://`.
/// - a remote `scp` that said permission is `error.FtpAccessDenied`, exit 9.
/// - a path that will not quote is `error.InvalidUrl`, exit 3.
/// - a remote command that exited non-zero, or one that ended with no exit
///   status at all, is `error.QuoteError`, exit 21.
/// - the channel ending in the middle of the file is `error.PartialFile`,
///   exit 18.
pub fn open(f: *Fetcher, url: zurl_core.Url, options: Options, d: ?*Diagnostics) Error!Body {
    f.release();
    f.stderr_len = 0;
    // **The password lives no longer than the transfer that sends it.**
    // `resolveCredentials` decodes it into this buffer, `Authenticator`
    // copies it into a request it wipes itself, and nothing after the login
    // reads it again.
    defer std.crypto.secureZero(u8, &f.credential_storage);

    const port = url.port orelse return fail(d, error.InvalidUrl, &.{
        "an scp url names a port, and this one names none",
    });

    var source: CredentialSource = undefined;
    const credentials = try f.resolveCredentials(url, options, &source, d);
    const path = try f.resolvePath(url, d);

    // **The command is built before a socket opens.** A path that cannot be
    // quoted is a usage fault now rather than a connection spent on a
    // transfer that was never going to run.
    const line = command.build(
        &f.command_storage,
        if (options.body == null) .download else .upload,
        path,
    ) catch |err| return fail(d, error.InvalidUrl, &.{switch (err) {
        error.PathEmpty => "this scp url names no path, and a remote scp needs one",
        error.PathHasNul => "the path in this url holds a NUL, and the shell on the far side would cut the path there and act on a shorter one than zurl asked for",
        error.PathTooLong => "the path in this url is longer than zurl sends to a remote scp",
        error.CommandTooLong => "the path in this url does not fit the command zurl sends to a remote scp",
    }});

    if (options.resume_from != 0) return fail(d, error.RangeError, &.{
        "the scp protocol carries no offset, so -C does not reach an scp url: use sftp://, which does",
    });

    if (options.body) |body_source| {
        if (body_source.len == null) return fail(d, error.ReadError, &.{
            "an scp upload writes the length of the file before the bytes, so zurl cannot send a body whose length it does not know: name a file with -T rather than standard input",
        });
    }

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
        // **Standard error is not the body.** It goes here, where a
        // failure message can read it, and never into the file.
        .stderr = .{ .ctx = f, .write = takeStderr },
    }) catch |err| return f.reportClient(err, &client, &checker, url, source, d);
    defer client.close();

    client.channel.requestExec(&f.request_storage, line) catch |err|
        return f.reportChannel(err, d);

    var session: Session = undefined;
    session.init(&client.channel);
    // **The staging buffer holds the file in the clear.** A private file
    // that a transfer read stays in that memory until something writes over
    // it, and this value sits on the stack of a program that carries on
    // afterwards.
    defer session.wipe();

    const answer = if (options.body) |body_source|
        try f.upload(&session, path, body_source, d)
    else
        try f.download(&session, options, d);
    errdefer f.allocator.free(answer);

    // **The exit status is read after the file and before the answer is
    // handed back.** A remote command that failed must not look like a
    // transfer that worked.
    try f.checkExit(&client, &session, d);

    f.answer = answer;
    f.body = .fixed(answer);
    return .{ .reader = &f.body, .length = answer.len };
}

/// Reads one file off the server.
fn download(
    f: *Fetcher,
    session: *Session,
    options: Options,
    d: ?*Diagnostics,
) Error![]u8 {
    session.beginDownload() catch |err| return f.reportSession(err, session, d);

    const file = (session.nextFile() catch |err|
        return f.reportSession(err, session, d)) orelse
        return fail(d, error.RemoteFileNotFound, &.{
            "the remote scp sent no file and said nothing about why",
        });

    // **The size is the server's and the bound is zurl's.** It is checked
    // before one byte is allocated, and again as the bytes arrive, because
    // a server that named a small size may still write a large file.
    if (file.size > options.max_response_bytes) return failNumber(
        d,
        error.FileSizeExceeded,
        "the file on the server is longer than the ",
        options.max_response_bytes,
        " bytes zurl reads in one transfer",
    );

    var collected: std.ArrayList(u8) = .empty;
    errdefer collected.deinit(f.allocator);

    var chunk: [chunk_bytes]u8 = undefined;
    while (true) {
        const taken = session.readBody(&chunk) catch |err|
            return f.reportSession(err, session, d);
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
    }

    // **The status byte behind the file is read.** A remote `scp` reports a
    // read it could not finish there, and a build that stopped at the last
    // body byte would call a truncated file whole.
    session.endFile() catch |err| return f.reportSession(err, session, d);

    if (collected.items.len != file.size) return fail(d, error.PartialFile, &.{
        "the remote scp sent fewer bytes than the size it named",
    });

    return collected.toOwnedSlice(f.allocator) catch
        Diagnostics.record(d, error.OutOfMemory, .{});
}

/// Writes one file onto the server.
///
/// The `C` line carries the **basename** of the url's path, because the
/// path itself is already in the `exec` command. That is what the measured
/// transcript shows curl doing.
fn upload(
    f: *Fetcher,
    session: *Session,
    path: []const u8,
    source: Source,
    d: ?*Diagnostics,
) Error![]u8 {
    const name = protocol_wire.baseName(path);
    protocol_wire.checkName(name) catch return fail(d, error.InvalidUrl, &.{
        "the last part of this url's path is not one file name, and an scp upload writes one on its C line",
    });
    const length = source.len orelse return fail(d, error.ReadError, &.{
        "an scp upload writes the length of the file before the bytes",
    });

    session.beginUpload() catch |err| return f.reportSession(err, session, d);
    session.sendFileLine(upload_mode, length, name) catch |err|
        return f.reportSession(err, session, d);

    var sent: u64 = 0;
    var chunk: [chunk_bytes]u8 = undefined;
    while (sent < length) {
        const want: usize = @intCast(@min(@as(u64, chunk.len), length - sent));
        const taken = readBound(source.read(source.ctx, &chunk, want), want) catch |err|
            return fail(d, error.ReadError, &.{switch (err) {
                error.SourceFailed => "zurl did not read what it was told to send to the scp server",
                error.SourceOverran => "zurl was told more bytes were read for this upload than it asked for",
            }});
        if (taken == 0) break;
        session.writeBody(chunk[0..taken]) catch |err|
            return f.reportSession(err, session, d);
        sent += taken;
    }

    // **A body shorter than the length on the `C` line is a fault.** The
    // remote reads exactly the number it was given, so a short body would
    // leave it waiting and the next byte would be read as file content.
    if (sent != length) return fail(d, error.ReadError, &.{
        "zurl told the scp server a length and then read fewer bytes than that",
    });

    session.finishFile() catch |err| return f.reportSession(err, session, d);

    return f.allocator.alloc(u8, 0) catch
        Diagnostics.record(d, error.OutOfMemory, .{});
}

/// Reads the count a body callback reported, and refuses one it cannot use.
///
/// **The callback reports the count and this side gave the room.** A count
/// past what was asked for would read past the end of the buffer, so it is
/// a named refusal rather than a slice this build cannot make. A negative
/// count is the callback saying it could not read.
fn readBound(reported: isize, want: usize) error{ SourceFailed, SourceOverran }!usize {
    if (reported < 0) return error.SourceFailed;
    const taken: u64 = @intCast(reported);
    if (taken > want) return error.SourceOverran;
    return @intCast(taken);
}

/// Ends the channel and reads the remote command's exit status.
///
/// **A null status is not a success.** See this module's own comment.
fn checkExit(
    f: *Fetcher,
    client: *zurl_ssh.Client,
    session: *const Session,
    d: ?*Diagnostics,
) Error!void {
    _ = session;
    // The end of file says this side will write no more, which is what a
    // remote `scp -t` waits for before it reports its status.
    client.channel.sendEof() catch {};
    client.channel.close() catch |err| return fail(d, error.WeirdServerReply, &.{
        "the ssh channel did not close: ",
        @errorName(err),
    });

    if (client.channel.exitSignal()) |signal| {
        var safe: [zurl_ssh.Channel.max_signal_name_bytes]u8 = undefined;
        return fail(d, error.QuoteError, &.{
            "the remote scp was killed by SIG",
            zurl_ssh.userauth.sanitizeBanner(&safe, signal.name),
        });
    }

    const code = client.channel.exitStatus() orelse return fail(d, error.QuoteError, &.{
        "the remote scp closed the channel without an exit status, so zurl cannot say the transfer worked",
    });
    if (code == 0) return;

    // The remote's own diagnostic is the useful half of this message, and
    // it is the peer's text, so it is sanitized before it is printed.
    // **The remote `scp` names itself in every message it writes**, measured
    // against OpenSSH 10.5p1, so nothing is put in front of its words: a
    // second `scp:` would say nothing and cost a line.
    var safe: [max_stderr_bytes]u8 = undefined;
    const text = zurl_ssh.userauth.sanitizeBanner(&safe, f.stderrText());
    var digits: [20]u8 = undefined;
    const number = std.fmt.bufPrint(&digits, "{d}", .{code}) catch digits[0..0];
    return fail(d, classify(text), &.{
        "the remote scp exited ",
        number,
        if (text.len == 0) "" else ": ",
        text,
    });
}

/// Which exit code a remote `scp` fault carries.
///
/// **The classification reads the remote's own words, and it only chooses
/// between three exit codes.** It never decides whether the transfer
/// failed: that is the exit status and the control byte, and both are read
/// before this runs.
///
/// curl answers `CURLE_SSH`, 79, for every one of these, and this build has
/// no row for 79. 78 and 9 are the numbers this same build answers for the
/// same two faults over `sftp://`, so a script that reads an exit code gets
/// one answer for both SSH schemes.
fn classify(text: []const u8) Error {
    if (std.mem.indexOf(u8, text, "No such file") != null) return error.RemoteFileNotFound;
    if (std.mem.indexOf(u8, text, "not a regular file") != null) return error.RemoteFileNotFound;
    if (std.mem.indexOf(u8, text, "Permission denied") != null) return error.FtpAccessDenied;
    if (std.mem.indexOf(u8, text, "Is a directory") != null) return error.FtpAccessDenied;
    return error.QuoteError;
}

/// What the remote command wrote to standard error, cut to fit.
pub fn stderrText(f: *const Fetcher) []const u8 {
    return f.stderr_storage[0..f.stderr_len];
}

/// Keeps the head of the remote command's standard error.
///
/// **The head and not the tail**, because the first line is the one that
/// says what went wrong and the rest is a remote `scp` repeating itself.
fn takeStderr(ctx: ?*anyopaque, text: []const u8) void {
    const f: *Fetcher = @ptrCast(@alignCast(ctx.?));
    const room = f.stderr_storage.len - f.stderr_len;
    if (room == 0) return;
    const take = @min(room, text.len);
    @memcpy(f.stderr_storage[f.stderr_len..][0..take], text[0..take]);
    f.stderr_len += take;
}

/// The credential this transfer sends, in curl's own order.
///
/// The url's userinfo first, then `-u`, then a netrc entry for the url's
/// host, then the login name of this account. **SSH has no anonymous
/// account**, so a transfer with no name at all is refused rather than run
/// as somebody.
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
            "this scp url names no user, and ssh has no anonymous account: write the name in the url or give it with -u",
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
/// The url's path, percent-decoded. **The decoded bytes are what
/// `command.quote` wraps**, so a percent escape cannot turn into a shell
/// metacharacter after the quoting ran: the quoting is the last thing that
/// touches the path.
fn resolvePath(f: *Fetcher, url: zurl_core.Url, d: ?*Diagnostics) Error![]const u8 {
    if (url.path.len > f.path_storage.len) return fail(d, error.InvalidUrl, &.{
        "the path in this url is longer than zurl sends to a remote scp",
    });
    const decoded = zurl_core.url.percentDecode(
        f.path_storage[0..url.path.len],
        url.path,
    ) catch return fail(d, error.InvalidUrl, &.{
        "the path in this url holds a percent escape that is not an escape",
    });
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
        // front of them into the file beside the record they already have.
        // That is the one wrong message that helps an attacker.
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

fn reportChannel(f: *Fetcher, err: zurl_ssh.Channel.Error, d: ?*Diagnostics) Error {
    _ = f;
    return switch (err) {
        error.ChannelRequestRefused => fail(d, error.QuoteError, &.{
            "the ssh server refused to run a command: an account with a forced command or an internal-sftp shell takes sftp:// and not scp://",
        }),
        error.OutOfMemory => Diagnostics.record(d, error.OutOfMemory, .{}),
        else => fail(d, error.WeirdServerReply, &.{
            "the ssh channel stopped: ",
            @errorName(err),
        }),
    };
}

/// Reports a fault from the rcp dialogue, with the remote's own words where
/// there are any.
fn reportSession(
    f: *Fetcher,
    err: Session.Error,
    session: *const Session,
    d: ?*Diagnostics,
) Error {
    if (err == error.RemoteFault) {
        // **The remote's message is sanitized before it is printed.** It is
        // the peer's text and a control byte in it would let a later log
        // line pretend to be a different line.
        var safe: [Session.max_message_bytes]u8 = undefined;
        const text = zurl_ssh.userauth.sanitizeBanner(&safe, session.lastMessage());
        if (text.len == 0) return fail(d, error.QuoteError, &.{
            "the remote scp reported a fault and said nothing about it",
        });
        // **The remote names itself in its own message**, measured, so a
        // second `scp:` in front of it would say nothing.
        return fail(d, classify(text), &.{text});
    }
    _ = f;
    return switch (err) {
        error.OutOfMemory => Diagnostics.record(d, error.OutOfMemory, .{}),
        error.PartialFile, error.ChannelClosed, error.EndOfStream => fail(d, error.PartialFile, &.{
            "the ssh channel ended in the middle of the scp transfer",
        }),
        error.DirectoryUnsupported => fail(d, error.RemoteFileNotFound, &.{
            "this path names a directory on the server, and zurl transfers one file over scp: use sftp:// with a url that ends in a slash to list it",
        }),
        // **A control line this build will not read is its own sentence.**
        // Every field on it is the server's, and each of these names which
        // field zurl would not take.
        error.NameInvalid => fail(d, error.WeirdServerReply, &.{
            "the remote scp named the file with a name zurl will not read: a name holding a path separator or a control byte is refused rather than carried further",
        }),
        error.ModeInvalid => fail(d, error.WeirdServerReply, &.{
            "the remote scp wrote a file mode zurl does not read",
        }),
        error.SizeInvalid => fail(d, error.WeirdServerReply, &.{
            "the remote scp wrote a file size zurl does not read",
        }),
        error.LineEmpty, error.LineTypeUnknown, error.LineMalformed, error.LineTooLong, error.TimeInvalid => fail(d, error.WeirdServerReply, &.{
            "the remote scp wrote a control line zurl does not read: ",
            @errorName(err),
        }),
        error.ControlLineFlood => fail(d, error.WeirdServerReply, &.{
            "the remote scp wrote control lines and never named a file",
        }),
        error.StatusUnknown => fail(d, error.WeirdServerReply, &.{
            "the remote scp answered with a status byte zurl does not name",
        }),
        error.OperationTimedOut => fail(d, error.OperationTimedOut, &.{
            "the remote scp sent no byte for as long as zurl waits",
        }),
        // The rate rule and the wait give different sentences on purpose.
        // A peer that says nothing and a peer that drips are different
        // peers, and the second one is the flag the user set.
        error.TransferTooSlow => fail(d, error.OperationTimedOut, &.{
            "the scp transfer stayed under the rate --speed-limit named for as long as --speed-time allows",
        }),
        error.Canceled => fail(d, error.AbortedByCallback, &.{
            "the scp transfer was stopped from outside",
        }),
        else => fail(d, error.WeirdServerReply, &.{
            "the scp exchange stopped: ",
            @errorName(err),
        }),
    };
}

/// Reports a dial fault with the sentence `zurl-net` holds for it.
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

/// Returns the dispatch entry for the `scp` scheme.
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
        // This package dials the origin itself and reads no proxy field.
        .unread = .{ .proxy = true },
    };
}

/// The vtable for one front package.
fn Dispatch(comptime Front: type) type {
    return struct {
        const vtable: Front.protocol.Protocol.VTable = .{ .perform = performScp };

        fn performScp(
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
        /// **`--max-filesize` sets the bound here, and may raise it.** This
        /// is the one place that differs from the ten protocol packages
        /// that only narrow, and the reason is what this protocol is for.
        ///
        /// `default_max_response_bytes` is 16 MiB, the house value, because
        /// the whole transfer is held in memory and the smallest target
        /// this build aims at has 256 MB of it. For a package that answers
        /// a short reply, that bound is never reached. `scp` moves files,
        /// so a default that no flag could raise would stop this build
        /// moving a file of 17 MB at all, which is not a bound, it is a
        /// missing feature.
        ///
        /// A number the user wrote is a choice this build keeps, the same
        /// way it keeps `-Doptimize`. The user owns what a large number
        /// costs on a small machine.
        ///
        /// curl holds `--max-filesize` to FTP, HTTP and MQTT, so curl
        /// answers an `scp` url with no bound of this kind at all: it
        /// writes the body out as it arrives and holds none of it. That is
        /// the real answer here too, and it needs a streaming body through
        /// the front package, which no protocol package has yet.
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

test "the dispatch entry names the scheme and the port RFC 4253 assigns" {
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const entry = f.protocol(StubFront);
    try testing.expectEqualStrings("scp", entry.scheme);
    try testing.expectEqual(@as(?u16, 22), entry.default_port);
    try testing.expect(entry.unread.proxy);
    try testing.expect(!entry.unread.credentials);
}

test "--max-filesize sets the bound here, and may raise it" {
    // **This package and `zurl-sftp` are the two that let the flag raise
    // the bound.** The ten other in-memory packages only narrow it. See
    // `Dispatch.translate` for why: a protocol whose job is moving files
    // cannot hold a default that no flag reaches, or a file of 17 MB
    // becomes one this build refuses to move.
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

    // A larger number raises. This is the line that changed, and the
    // transfer it allows is the one the 16 MiB default would refuse.
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
    const o: Options = .{};
    try testing.expectEqual(default_max_response_bytes, o.max_response_bytes);
    // `zurl-sftp` keeps the same number and pins it in a test of this
    // name. It cannot be imported here: the build gives this package
    // `zurl-core`, `zurl-net`, and `zurl-ssh` and nothing else.
}

test "an answer past the bound is refused with a sentence that names the number" {
    // A user who meets this bound must be able to see what it is and what
    // to do about it, so the fault carries the number and never only a
    // name. Both places `download` checks the bound report through this
    // one call: the size the `C` line states, and the bytes as they
    // arrive.
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
    try testing.expectError(error.LoginDenied, f.resolveCredentials(url, .{}, &source, &d));
    try testing.expect(d.message != null);
}

test "a path is percent-decoded before it is quoted" {
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const spaced = try zurl_core.url.parse("http://host/a%20b.txt");
    const decoded = try f.resolvePath(spaced, null);
    try testing.expectEqualStrings("/a b.txt", decoded);

    // **The quoting is the last thing that touches the path**, so the
    // decoded space is data and never a second word.
    var storage: [command.max_command_bytes]u8 = undefined;
    try testing.expectEqualStrings(
        "scp -pf '/a b.txt'",
        try command.build(&storage, .download, decoded),
    );
}

test "a percent-escaped metacharacter is quoted and never run" {
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    // `%3B` is a semicolon and `%60` is a backtick. A build that quoted
    // before it decoded would put a live semicolon in the command.
    const url = try zurl_core.url.parse("http://host/a%3Bid%60x%60");
    const decoded = try f.resolvePath(url, null);
    try testing.expectEqualStrings("/a;id`x`", decoded);

    var storage: [command.max_command_bytes]u8 = undefined;
    try testing.expectEqualStrings(
        "scp -pf '/a;id`x`'",
        try command.build(&storage, .download, decoded),
    );
}

test "a path with a NUL never becomes a command" {
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    const url = try zurl_core.url.parse("http://host/a%00b");
    const decoded = try f.resolvePath(url, null);
    var storage: [command.max_command_bytes]u8 = undefined;
    try testing.expectError(
        error.PathHasNul,
        command.build(&storage, .download, decoded),
    );
}

test "the remote's own words choose between three exit codes and no more" {
    // The classification never decides whether the transfer failed. It runs
    // only after an exit status or a control byte already said so.
    try testing.expectEqual(
        Error.RemoteFileNotFound,
        classify("scp: /nope: No such file or directory"),
    );
    try testing.expectEqual(
        Error.FtpAccessDenied,
        classify("scp: /root/x: Permission denied"),
    );
    try testing.expectEqual(
        Error.FtpAccessDenied,
        classify("scp: /srv: Is a directory"),
    );
    try testing.expectEqual(Error.QuoteError, classify(""));
    try testing.expectEqual(Error.QuoteError, classify("something else went wrong"));
}

test "the standard error sink keeps the head and never runs past its buffer" {
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    takeStderr(&f, "first line\n");
    try testing.expectEqualStrings("first line\n", f.stderrText());

    var flood: [max_stderr_bytes * 2]u8 = undefined;
    @memset(&flood, 'x');
    takeStderr(&f, &flood);
    try testing.expectEqual(max_stderr_bytes, f.stderrText().len);
    // The head survived, which is the line that says what went wrong.
    try testing.expectEqualStrings("first line\n", f.stderrText()[0..11]);
}

test "the request buffer holds the longest command this build sends" {
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    // `Channel.requestExec` needs the command plus the control bytes of the
    // request around it, and a buffer one byte short would refuse the
    // longest path this build already accepted.
    try testing.expect(
        f.request_storage.len >= f.command_storage.len + zurl_ssh.connection.max_control_bytes,
    );
}

test "a body callback that reports more than it was given is refused" {
    // A count past the room this side gave would read past the end of the
    // buffer. It is a named refusal, and never a slice this build makes.
    try testing.expectEqual(@as(usize, 0), try readBound(0, 32));
    try testing.expectEqual(@as(usize, 32), try readBound(32, 32));
    try testing.expectError(error.SourceOverran, readBound(33, 32));
    try testing.expectError(error.SourceOverran, readBound(std.math.maxInt(isize), 32));
    try testing.expectError(error.SourceFailed, readBound(-1, 32));
    try testing.expectError(error.SourceFailed, readBound(std.math.minInt(isize), 32));
}

test "the credential is wiped and not only dropped" {
    // **A password stays in memory until something writes over it.** A
    // `Fetcher` is reused across transfers, so the buffer a url's password
    // was decoded into is wiped at the end of each one and again at
    // `deinit`.
    //
    // The answer is wiped the same way, in `release`, and no test can watch
    // that: the allocator writes its own `undefined` pattern over the block
    // after the free, so what a test read back would be the allocator's
    // byte and not the wipe.
    var f: Fetcher = .init(testing.allocator, testing.io);
    @memset(&f.credential_storage, 0xCD);

    f.deinit();
    for (f.credential_storage) |byte| try testing.expectEqual(@as(u8, 0), byte);
    // Calling it twice is safe and still leaves nothing behind.
    f.deinit();
    for (f.credential_storage) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "the status the whole package reports is zero, because scp has none" {
    try testing.expectEqual(@as(u16, 0), status);
}

test "the scp translation carries --connect-to into this package" {
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

test "an scp dial moves with --connect-to and the host key check keeps the url's name" {
    // **The rule the SSH schemes hold.** `open` hands
    // `zurl_ssh.Client.Options.dial` the moved address and leaves
    // `Options.peer` at the name the url wrote, which is the name a
    // `known_hosts` record is looked up under. So a redirected dial
    // reaches a machine whose key does not match the record for the url's
    // name, and the session is refused with exit 60. This package writes
    // no `known_hosts` file, so the flag cannot add a record either.
    //
    // This test pins the split the call makes, with no socket opened.
    // `zurl_ssh.Client` tests the same split against a live fixture and a
    // recording verifier.
    const overrides: []const zurl_net.override.HostOverride = &.{.{
        .from_host = "known.example",
        .from_port = 22,
        .to_host = "127.0.0.1",
        .to_port = 2222,
    }};
    const moved = zurl_net.override.dialTarget(overrides, "known.example", 22);
    try testing.expectEqualStrings("127.0.0.1", moved.host);
    try testing.expectEqual(@as(u16, 2222), moved.port);
    try testing.expect(moved.overridden);

    // A url that no entry answers for keeps both, which is every transfer
    // that named neither flag.
    const kept = zurl_net.override.dialTarget(overrides, "other.example", 22);
    try testing.expectEqualStrings("other.example", kept.host);
    try testing.expect(!kept.overridden);
}

test "--speed-limit reaches the layer that reads the bytes" {
    // **`--speed-limit` used to be read once, to decide whether the flag
    // was given, and then dropped.** What survived was a stall bound: a
    // wait that starts again at every byte. A server that wrote one byte
    // just before each wait ran out passed a check the user set, and curl
    // would have failed it.
    //
    // The ten packages that stream get the rate rule from
    // `zurl_stream.Stall`, which `zurl.body` wraps their body in. This
    // package hands the front package a body that is already whole, so
    // that decorator sees one instant read and judges nothing. The rule
    // runs in `zurl_ssh.Transport` instead, and this is the wiring that
    // carries the number there.
    const D = Dispatch(StubFront);

    const named = D.translate(.{ .low_speed_limit = 512, .low_speed_time_s = 45 });
    try testing.expectEqual(@as(u64, 512), named.low_speed_limit);
    try testing.expectEqual(@as(u32, 45), named.low_speed_time_s);

    // Zero on either setting turns the rate rule off, the way curl's own
    // watchdog turns off, and the stall bound still stands.
    const off = D.translate(.{ .low_speed_limit = 0, .low_speed_time_s = 45 });
    try testing.expectEqual(@as(u64, 0), off.low_speed_limit);
}
