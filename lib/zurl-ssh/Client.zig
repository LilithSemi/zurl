//! One SSH connection end to end: the dial, the key exchange, the login,
//! and one session channel.
//!
//! This is the value a protocol package builds on. `zurl-sftp` opens a
//! `subsystem` channel over it and `zurl-scp` opens an `exec` one, and
//! neither of them repeats the four steps below.
//!
//! **The trust decision is still the caller's and it still has no
//! default.** `Options.verifier` is `Transport.Options.verifier`, passed
//! straight through. `zurl_ssh.knownhosts.Checker` is what a command line
//! wires into it.
//!
//! **The credentials belong to the caller and this value keeps no copy.**
//! The passphrase and the password are read, used, and never stored here.
//! The private key this value loads from disk is its own, and `deinit`
//! wipes it.
//!
//! The order is the order RFC 4253 and RFC 4252 put them in, and no step
//! may be skipped:
//!
//! 1. dial, with `zurl_net.bounded.setup`;
//! 2. `Transport.handshake`, which is the identification exchange and the
//!    first key exchange, and which asks the verifier before it installs
//!    a key;
//! 3. `Authenticator.authenticate`, over the encrypted transport;
//! 4. `Channel.open`, which is RFC 4254.

const Client = @This();

const std = @import("std");
const zurl_net = @import("zurl-net");

const hostkey = @import("hostkey.zig");
const keyfile = @import("keyfile.zig");
const messages = @import("messages.zig");
const privatekey = @import("privatekey.zig");

const Authenticator = @import("Authenticator.zig");
const Channel = @import("Channel.zig");
const Transport = @import("Transport.zig");

const Io = std.Io;

/// The port RFC 4253 assigns, and the one curl dials for an `sftp` or
/// `scp` url that names none.
pub const default_port: u16 = 22;

/// How much room the connection keeps for bytes read and not taken yet.
pub const read_buffer_len: usize = 32 * 1024;

/// How long one read may wait with no byte arriving.
///
/// An SSH session has no length on the wire, so a peer that never writes
/// and never closes holds this process forever. 300 seconds is curl's own
/// `--speed-time` default, and this is the same question.
pub const default_stall_s: u32 = 300;

/// What one connection needs.
pub const Options = struct {
    /// The host and the port. The verifier gets both.
    ///
    /// **This is the name, and never the address.** `dial` below is where
    /// a connection actually goes, and only that field moves under
    /// `--resolve` or `--connect-to`. See `dial`.
    peer: hostkey.Peer,
    /// Where to open the socket, or null to open it at `peer`.
    ///
    /// **This moves the dial and it must never move the host key check.**
    /// `--connect-to` and `--resolve` fill this, and `peer` above stays
    /// the name the url wrote, which is the name `knownhosts.hostName`
    /// looks up. Two things follow, and both are the point of the split:
    ///
    /// - A redirected dial reaches a machine that holds its own host key.
    ///   That key is compared against the record for the url's name, so it
    ///   does not match and the connection is refused with
    ///   `error.HostKeyChanged`. The flag therefore cannot carry a session
    ///   to another machine and have the check pass.
    /// - A first connection to a name with no record is still
    ///   `error.HostKeyUnknown`, exit 60, and this package writes no
    ///   `known_hosts` file. So the flag cannot add a record either.
    ///
    /// A check keyed on the dialed address would give the opposite and
    /// wrong answer: it would look up whatever machine the flag named,
    /// pass, and leave the user believing they reached the host in the
    /// url.
    ///
    /// curl 8.21.0 does the same, measured:
    /// `curl --connect-to h:22:127.0.0.1:22 sftp://h/tmp/x` said
    /// `SSH: did not find host 'h' in '~/.ssh/known_hosts'` and exited 60,
    /// with the socket on 127.0.0.1. The lookup used the url's name.
    dial: ?hostkey.Peer = null,
    /// **The trust decision, and it has no default.** See
    /// `zurl_ssh.knownhosts`.
    verifier: hostkey.Verifier,
    /// The account to log in as.
    user: []const u8,
    /// The password for `password` and `keyboard-interactive`, or null.
    /// **The caller owns it and wipes it.**
    password: ?[]const u8 = null,
    /// Where the private key is. See `zurl_ssh.keyfile`.
    key_location: keyfile.Location = .{},
    /// The passphrase for an encrypted key, or null. **The caller owns it
    /// and wipes it.**
    key_passphrase: ?[]const u8 = null,
    /// Whether a missing private key stops the connection.
    ///
    /// False, because a server that takes a password needs no key, and a
    /// user with no key at all should not be told to make one. A key that
    /// is there and will not open is still a fault: see `keyfile`.
    key_required: bool = false,
    /// A cap on the dial.
    connect_timeout: Io.Timeout = .none,
    /// How long one read may wait with no byte arriving.
    stall: Io.Timeout = .{
        .duration = .{ .raw = .fromSeconds(default_stall_s), .clock = .awake },
    },
    /// The slowest acceptable rate, in bytes each second, with both
    /// directions counted. Zero turns the rate rule off. This is curl's
    /// `--speed-limit`, and it is a different bound from `stall`. See
    /// `Transport.rateDeadline`.
    low_speed_limit: u64 = 0,
    /// How long the rate may stay under `low_speed_limit`, in seconds.
    /// Zero turns the rate rule off. This is curl's `--speed-time`.
    low_speed_time_s: u32 = 0,
    /// Whether to turn Nagle's algorithm off.
    tcp_no_delay: bool = true,
    /// Where a server banner goes.
    banner: ?Authenticator.BannerSink = null,
    /// Where the remote command's standard error goes.
    stderr: ?Channel.StderrSink = null,
    /// What the channel advertises.
    channel: Channel.Options = .{},
};

/// Why a connection could not be made.
pub const Error =
    zurl_net.errors.SetupError ||
    Transport.InitError ||
    Transport.KexError ||
    Authenticator.Error ||
    Channel.InitError ||
    Channel.Error ||
    keyfile.LoadError;

/// Which step stopped.
///
/// A caller maps a fault onto an exit code, and the four steps carry
/// different ones: a dial that failed is not a login that failed, and a
/// login that failed is not a channel a server would not open.
pub const Phase = enum {
    dial,
    handshake,
    authenticate,
    channel,
};

allocator: std.mem.Allocator,
io: Io,

connection: zurl_net.Connection,
transport: Transport,
authenticator: Authenticator,
channel: Channel,

/// The key this value loaded, which it owns and wipes.
key: ?privatekey.PrivateKey,
/// The path the key came from, for a message a person reads.
key_path_storage: [std.Io.Dir.max_path_bytes]u8,
key_path_len: usize,

/// Why a default key file was passed over, or null.
///
/// **A default key this build cannot read is not a fault by itself.**
/// `keyfile.default_names` holds `id_ecdsa`, `id_rsa` and `id_dsa` on
/// purpose, and this build signs with none of them. It also holds
/// `id_ed25519`, which may be encrypted with a passphrase no caller
/// supplied. In each case the user named no key: `keyfile` picked the
/// file because it was the first default that opened. A build that
/// stopped there could not reach such a host at all, not even with a
/// password the server takes, and that is availability lost for nothing.
/// So the file is passed over, `publickey` is not offered, and the login
/// carries on with whatever else the caller gave.
///
/// **A key the caller named is never passed over.** An explicit
/// `Options.key_location.path` that will not open or will not parse is
/// still a fault from `open`, because the caller asked for that file and
/// nothing else. `Options.key_required` does the same for the defaults.
///
/// **Recovery is never silent.** The fault is kept here so that a caller
/// whose login then fails can say a key was found and not used.
key_skipped: ?keyfile.LoadError,

/// Which step is running, or the last one that ran.
phase: Phase,

/// What `zurl-net` said about a dial that did not work, or null.
///
/// **The mapping is taken here and not by the caller**, because
/// `zurl_net.errors.map` takes a `SetupError` and what leaves this
/// function is the union of five error sets. A caller that narrowed it
/// again would either guess or repeat the table.
dial_fault: ?zurl_net.errors.Mapping,

/// How far along `open` got, so that `deinit` takes down exactly what came
/// up.
started: struct {
    connection: bool = false,
    transport: bool = false,
    channel: bool = false,
},

/// Opens a connection, logs in, and opens one session channel.
///
/// Initializes `c` in place, because `Transport` and `Channel` both hold
/// buffers a caller reads from.
///
/// **`phase` says which step stopped**, and it is set before each one, so
/// a caller reads it after a failure and never has to guess.
pub fn open(c: *Client, gpa: std.mem.Allocator, io: Io, options: Options) Error!void {
    c.allocator = gpa;
    c.io = io;
    c.key = null;
    c.key_path_len = 0;
    c.key_skipped = null;
    c.started = .{};
    c.phase = .dial;
    c.dial_fault = null;

    // **The dial goes to `options.dial`, and the host key check below
    // goes to `options.peer`.** A caller that named neither flag passes
    // the same value in both. See `Options.dial`.
    const where = options.dial orelse options.peer;
    // **`dial_fault` carries the meaning, and the returned name only says
    // the dial is where it stopped.** `Error` here is the union of five
    // sets and holds no `InvalidUrl`, so a host that is neither an
    // address nor a name cannot leave this function under its own name.
    // The caller reads `dial_fault` and reports that, which is how a bad
    // url keeps exit 3 and a name no resolver can look up keeps exit 6.
    // See `zurl_net.errors.hostInit` and `zurl_sftp.reportDial`.
    const host = zurl_net.tcp.Host.init(where.host) catch |err| {
        c.dial_fault = zurl_net.errors.hostInit(err);
        return error.CouldNotResolveHost;
    };
    zurl_net.bounded.setup(&c.connection, io, options.connect_timeout, .{
        .allocator = gpa,
        .io = io,
        .host = host,
        .port = where.port,
        .read_buffer_len = read_buffer_len,
        .tls = null,
        .no_delay = options.tcp_no_delay,
    }) catch |err| {
        c.dial_fault = zurl_net.errors.map(err);
        return err;
    };
    c.started.connection = true;
    errdefer c.close();

    c.phase = .handshake;
    try c.transport.init(gpa, io, .{
        .reader = c.connection.reader(),
        .writer = c.connection.writer(),
        .ctx = &c.connection,
        .flush = flushConnection,
    }, .{
        .peer = options.peer,
        .verifier = options.verifier,
        .stall = options.stall,
        .low_speed_limit = options.low_speed_limit,
        .low_speed_time_s = options.low_speed_time_s,
        // **The transport's rekey backlog is sized from the channel's
        // window here.** This is the one function that holds both numbers,
        // so it is the one place that can tie them together. A peer may
        // have a full window in flight when a key exchange starts, and
        // every payload of it waits in that backlog. See
        // `Channel.backlogBytesNeeded`.
        .backlog_bytes = @max(
            Transport.default_backlog_bytes,
            Channel.backlogBytesNeeded(
                options.channel.window_bytes,
                options.channel.max_packet_bytes,
            ),
        ),
    });
    c.started.transport = true;
    try c.transport.handshake();

    c.phase = .authenticate;
    // **The key is loaded after the handshake and not before it.** A
    // passphrase that a user typed for a host whose key does not check out
    // is a passphrase spent for nothing, and the load reads a file.
    var loaded: privatekey.PrivateKey = undefined;
    if (keyfile.load(
        &loaded,
        gpa,
        io,
        options.key_location,
        options.key_passphrase,
        &c.key_path_storage,
    )) |path| {
        c.key = loaded;
        c.key_path_len = path.len;
    } else |err| switch (err) {
        // No key on disk is not a fault by itself: a server that takes a
        // password needs none. A key that is there and will not open is,
        // and `keyfile` keeps the two apart.
        error.KeyFileNotFound, error.KeyHomeUnknown => if (options.key_required) return err,
        // **A file that is plainly there and plainly wrong is still a
        // fault.** `keyfile.read` passes over a default name that is not
        // there and stops at one it cannot open, because a key with the
        // wrong permissions is a thing a user must be told about, and
        // that answer is kept here.
        error.OutOfMemory,
        error.KeyPathTooLong,
        error.KeyFileUnreadable,
        error.KeyFileTooLong,
        => return err,
        // Everything left is a `zurl_ssh.privatekey.ParseError`: a
        // default name that opened and that this build cannot sign with.
        // See `key_skipped` for why that is not the end of the
        // connection. A passphrase the caller supplied says the caller
        // meant to use a key, so that one is a fault as well.
        else => {
            if (options.key_required) return err;
            if (options.key_location.path != null) return err;
            if (options.key_passphrase != null) return err;
            c.key_skipped = err;
        },
    }

    c.authenticator.init(&c.transport, .{
        .user = options.user,
        .key = if (c.key) |*held| held else null,
        .password = options.password,
        .banner = options.banner,
    });
    try c.authenticator.authenticate();

    c.phase = .channel;
    var channel_options = options.channel;
    channel_options.stderr = options.stderr;
    try c.channel.init(gpa, &c.transport, channel_options);
    c.started.channel = true;
    try c.channel.open();
}

/// The path the private key came from, or an empty slice when none was
/// loaded.
pub fn keyPath(c: *const Client) []const u8 {
    return c.key_path_storage[0..c.key_path_len];
}

fn flushConnection(ctx: ?*anyopaque) Io.Writer.Error!void {
    const connection: *zurl_net.Connection = @ptrCast(@alignCast(ctx.?));
    connection.flush() catch return error.WriteFailed;
}

/// Closes the channel, says goodbye, and takes down everything `open`
/// brought up.
///
/// **A write that does not reach the peer is not a fault here.** The
/// session is over either way, and the counters inside `Transport` are
/// where that recovery stays visible.
pub fn close(c: *Client) void {
    if (c.started.channel) {
        c.channel.close() catch {};
        c.channel.deinit(c.allocator);
        c.started.channel = false;
    }
    if (c.started.transport) {
        c.transport.disconnect(.by_application, "zurl finished the transfer");
        c.transport.deinit();
        c.started.transport = false;
    }
    if (c.key) |*held| {
        held.deinit();
        c.key = null;
    }
    if (c.started.connection) {
        c.connection.deinit();
        c.started.connection = false;
    }
}

const testing = std.testing;

test "the phase names every step, so a fault says which one stopped" {
    // A dial that failed and a login that failed carry different exit
    // codes, and a caller cannot tell them apart from the error alone:
    // both sets overlap. This enum is what it reads instead.
    try testing.expectEqual(@as(usize, 4), @typeInfo(Phase).@"enum".fields.len);
}

test "the default port is the one RFC 4253 assigns" {
    try testing.expectEqual(@as(u16, 22), default_port);
}

const test_server = @import("test_server.zig");

/// A verifier that accepts every key and records the peer it was asked
/// about. The recording is the whole point: it says which name the host
/// key check was keyed on.
const RecordingVerifier = struct {
    host_storage: [64]u8 = undefined,
    host_len: usize = 0,
    port: u16 = 0,
    calls: usize = 0,

    fn verifier(r: *RecordingVerifier) hostkey.Verifier {
        return .{ .ctx = r, .decide = decide };
    }

    fn decide(
        ctx: ?*anyopaque,
        peer: hostkey.Peer,
        key: hostkey.PublicKey,
        blob: []const u8,
    ) hostkey.TrustError!void {
        _ = key;
        _ = blob;
        const r: *RecordingVerifier = @ptrCast(@alignCast(ctx.?));
        const take = @min(peer.host.len, r.host_storage.len);
        @memcpy(r.host_storage[0..take], peer.host[0..take]);
        r.host_len = take;
        r.port = peer.port;
        r.calls += 1;
    }

    fn host(r: *const RecordingVerifier) []const u8 {
        return r.host_storage[0..r.host_len];
    }
};

test "a moved dial leaves the host key checked against the url's own name" {
    // **The rule that keeps `--connect-to` from becoming a way to accept
    // the wrong host's key.** `Options.dial` says where the socket goes.
    // `Options.peer` stays the name the url wrote, and that is the name
    // the verifier is asked about, so it is the name
    // `knownhosts.hostName` looks up.
    //
    // Two things follow. A redirected dial reaches a machine that holds
    // its own key, and that key is compared against the record for the
    // url's name, so it does not match and the session is refused. A
    // first connection to a name with no record is refused too, and this
    // package writes no `known_hosts` file. So the flag can neither pass
    // a wrong key nor add a record for one.
    //
    // curl 8.21.0 keys the lookup the same way, measured:
    // `curl --connect-to h:22:127.0.0.1:22 sftp://h/tmp/x` said
    // `SSH: did not find host 'h' in '~/.ssh/known_hosts'` and exited 60,
    // with the socket already on 127.0.0.1.
    //
    // **No network.** The fixture listens on 127.0.0.1 and the dial goes
    // there. The name below never reaches a resolver, because it never
    // reaches a dial.
    var server: test_server = undefined;
    try server.start(.{
        .auth = .{ .accept_none = true, .methods = "none" },
        .connection = .{ .service = .idle, .accept_request = "subsystem" },
    });
    defer server.stop();

    var recorder: RecordingVerifier = .{};

    var client: Client = undefined;
    try client.open(testing.allocator, testing.io, .{
        // The name the url wrote, which no test here ever looks up.
        .peer = .{ .host = "known.example", .port = 22 },
        // Where `--connect-to` sent the socket.
        .dial = .{ .host = "127.0.0.1", .port = server.port() },
        .verifier = recorder.verifier(),
        .user = "alice",
    });
    defer client.close();

    // The dial landed on the fixture, so the session came up at all.
    try testing.expectEqual(@as(usize, 1), recorder.calls);
    // And the check was asked about the url's own name and port, not
    // about `127.0.0.1` and the fixture's port.
    try testing.expectEqualStrings("known.example", recorder.host());
    try testing.expectEqual(@as(u16, 22), recorder.port);
}

test "a client that names no dial target opens the socket at the peer" {
    // The other half of the rule, and the shape every transfer that named
    // neither flag has: `dial` null means the socket goes to `peer`, so
    // nothing changed for a caller that does not use the field.
    var server: test_server = undefined;
    try server.start(.{
        .auth = .{ .accept_none = true, .methods = "none" },
        .connection = .{ .service = .idle, .accept_request = "subsystem" },
    });
    defer server.stop();

    var recorder: RecordingVerifier = .{};

    var client: Client = undefined;
    try client.open(testing.allocator, testing.io, .{
        .peer = .{ .host = "127.0.0.1", .port = server.port() },
        .verifier = recorder.verifier(),
        .user = "alice",
    });
    defer client.close();

    try testing.expectEqual(@as(usize, 1), recorder.calls);
    try testing.expectEqualStrings("127.0.0.1", recorder.host());
    try testing.expectEqual(server.port(), recorder.port);
}

/// A home directory with a `.ssh` in it, for the two tests below.
const TestHome = struct {
    tmp: testing.TmpDir,
    root_storage: [std.Io.Dir.max_path_bytes]u8,
    root_len: usize,

    fn init(h: *TestHome) !void {
        h.tmp = testing.tmpDir(.{});
        errdefer h.tmp.cleanup();
        try h.tmp.dir.createDirPath(testing.io, keyfile.default_directory);
        h.root_len = try h.tmp.dir.realPath(testing.io, &h.root_storage);
    }

    fn deinit(h: *TestHome) void {
        h.tmp.cleanup();
    }

    fn root(h: *const TestHome) []const u8 {
        return h.root_storage[0..h.root_len];
    }

    fn put(h: *TestHome, name: []const u8, text: []const u8) !void {
        var path_storage: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrint(
            &path_storage,
            "{s}/{s}",
            .{ keyfile.default_directory, name },
        );
        try h.tmp.dir.writeFile(testing.io, .{ .sub_path = path, .data = text });
    }
};

test "a default key this build cannot sign with is passed over and the password still logs in" {
    // **A user whose `~/.ssh` holds only an `id_rsa` could not reach an
    // SSH host at all.** `keyfile` names `id_rsa` on purpose, so the file
    // is found; `privatekey` cannot sign with it; and that refusal used to
    // end the connection, even with a password the server takes. The user
    // asked for nothing here: they named no `--key`, and the login they
    // named was the password.
    //
    // So the file is passed over, `publickey` is never offered, and the
    // password runs. See `Client.key_skipped`.
    var home: TestHome = undefined;
    try home.init();
    defer home.deinit();
    try home.put("id_rsa", privatekey.test_rsa_key);

    var server: test_server = undefined;
    try server.start(.{
        .auth = .{ .user = "alice", .password = "pw", .methods = "publickey,password" },
        .connection = .{ .service = .idle, .accept_request = "subsystem" },
    });
    defer server.stop();

    var recorder: RecordingVerifier = .{};
    var client: Client = undefined;
    try client.open(testing.allocator, testing.io, .{
        .peer = .{ .host = "127.0.0.1", .port = server.port() },
        .verifier = recorder.verifier(),
        .user = "alice",
        .password = "pw",
        .key_location = .{ .home = home.root() },
    });
    defer client.close();

    // **Recovery is never silent.** The key was found, it was not used,
    // and the reason is kept where a caller can read it.
    try testing.expectEqual(
        @as(?keyfile.LoadError, error.PrivateKeyAlgorithmUnsupported),
        client.key_skipped,
    );
    try testing.expectEqual(@as(usize, 0), client.keyPath().len);
}

test "a key the caller named is never passed over" {
    // The other half of the rule. An explicit `--key` is the file the user
    // asked for and nothing else, so one that will not parse is still the
    // fault it always was. `Options.key_required` does the same for the
    // default names.
    var home: TestHome = undefined;
    try home.init();
    defer home.deinit();
    try home.put("id_rsa", privatekey.test_rsa_key);

    var server: test_server = undefined;
    try server.start(.{
        .auth = .{ .user = "alice", .password = "pw", .methods = "publickey,password" },
        .connection = .{ .service = .idle, .accept_request = "subsystem" },
    });
    defer server.stop();

    var named_storage: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const named = try std.fmt.bufPrint(
        &named_storage,
        "{s}/{s}/id_rsa",
        .{ home.root(), keyfile.default_directory },
    );

    var recorder: RecordingVerifier = .{};
    var client: Client = undefined;
    try testing.expectError(error.PrivateKeyAlgorithmUnsupported, client.open(
        testing.allocator,
        testing.io,
        .{
            .peer = .{ .host = "127.0.0.1", .port = server.port() },
            .verifier = recorder.verifier(),
            .user = "alice",
            .password = "pw",
            .key_location = .{ .path = named, .home = home.root() },
        },
    ));
    client.close();
}

test "a default key that will not parse is still a fault when the caller required one" {
    var home: TestHome = undefined;
    try home.init();
    defer home.deinit();
    try home.put("id_rsa", privatekey.test_rsa_key);

    var server: test_server = undefined;
    try server.start(.{
        .auth = .{ .user = "alice", .password = "pw", .methods = "publickey,password" },
        .connection = .{ .service = .idle, .accept_request = "subsystem" },
    });
    defer server.stop();

    var recorder: RecordingVerifier = .{};
    var client: Client = undefined;
    try testing.expectError(error.PrivateKeyAlgorithmUnsupported, client.open(
        testing.allocator,
        testing.io,
        .{
            .peer = .{ .host = "127.0.0.1", .port = server.port() },
            .verifier = recorder.verifier(),
            .user = "alice",
            .password = "pw",
            .key_location = .{ .home = home.root() },
            .key_required = true,
        },
    ));
    client.close();
}
