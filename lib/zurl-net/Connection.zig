//! One open connection, plain or encrypted, behind one reader and one
//! writer.
//!
//! This file owns the buffers a connection needs and the TLS session over
//! `zurl-tls`. A protocol engine above it reads and writes through
//! `std.Io.Reader` and `std.Io.Writer`, and the same two calls serve a
//! plain connection and an encrypted one. That is the whole point of the
//! type: the engine holds no branch on whether TLS is in the way.
//!
//! This file does not dial, which is `tcp.zig`. It frames no protocol. It
//! keeps no connection pool and no session cache. It loads no trust roots:
//! the caller owns the `std.crypto.Certificate.Bundle` and its lock, which
//! is what lets one bundle serve many connections.
//!
//! It also keeps no clock and no bound of its own. A handshake that stalls
//! is not bounded here. See the report for why that bound belongs to the
//! engine that owns the socket.

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_tls = @import("zurl-tls");

const tcp = @import("tcp.zig");

const Connection = @This();

allocator: std.mem.Allocator,
io: std.Io,
/// The one allocation behind every buffer this connection uses. Freed by
/// `deinit`.
storage: []u8,
/// The socket side of the read path. For a plain connection this is the
/// read path. For an encrypted one it carries ciphertext, and the TLS
/// client reads from it.
stream_reader: std.Io.net.Stream.Reader,
/// The socket side of the write path, the mirror of `stream_reader`.
stream_writer: std.Io.net.Stream.Writer,
security: Security,
/// The numeric address this connection reached, or null when this build
/// cannot ask the socket.
///
/// **This is what a protocol reuses when it must open a second connection
/// to the same machine, and a host name is not.** A name reaches a
/// resolver again, and a resolver is free to answer the second lookup with
/// a different address, so a second dial by name lets whoever answers the
/// lookup pick where it goes. FTP has exactly that shape: the data
/// connection is opened many round trips after the control connection, on
/// a port the server names, and `zurl_ftp.Fetcher.dataTarget` reads this
/// field for the address.
///
/// The operating system answers it, so it is the address the socket really
/// reached and never the address this process meant to dial. It carries
/// the port of this connection, so a caller that dials a second port sets
/// its own with `std.Io.net.IpAddress.setPort`.
///
/// **It is the far end of the socket and not always the origin.** A
/// connection opened through a `CONNECT` tunnel or a SOCKS proxy reaches
/// the proxy, so this holds the proxy's address. The one reader of this
/// field today is FTP, which refuses a proxy by name rather than run
/// direct, so the two are the same there. A protocol that both keeps a
/// proxy and reuses this must read `proxy.zig` first.
///
/// **Null is a build that cannot ask and never a connection that failed.**
/// See `tcp.peerAddress`: Zig 0.16 gives `std.posix.getpeername` no body
/// for Windows, and WASI has no such call. A caller that needs the address
/// refuses rather than fall back to a second lookup, because the fallback
/// is the hole this field closes.
peer: ?std.Io.net.IpAddress,
/// The lock that lets one task read this connection while another task
/// writes it. Idle until `shareBetweenTasks` installs it.
///
/// **One task per connection needs no lock, and pays for none.** The read
/// path and the write path of a TLS session use two different keys and two
/// different counters, so they are independent everywhere but one place: a
/// TLS 1.3 `key_update` that asks the client to rotate makes the read path
/// write the keys the write path uses. RFC 8446 section 4.6.3. This lock
/// closes that one window, and nothing else.
///
/// It guards no buffer. The plaintext write buffer holds one task's bytes
/// at a time because the protocol above says so: `zurl-http/h2.zig` writes
/// every frame under its own session lock. This lock exists only for the
/// key rotation, so it is held over arithmetic and never over a syscall.
write_lock: std.Io.Mutex = .init,

/// Whether bytes on this connection are encrypted, and the session when
/// they are.
///
/// A tagged union and not a `?Client`, so `reader` and `writer` switch on
/// a name a reader of this file can see.
pub const Security = union(enum) {
    plain,
    tls: zurl_tls.Client,
};

/// How much room the connection keeps for bytes that were read and not
/// taken yet. This is the default, and a protocol engine that must hold a
/// whole message head in the buffer asks for more.
pub const default_read_buffer_len = 8192;

/// How much room the connection keeps for bytes that were written and not
/// flushed yet. Small on purpose: a writer that fills flushes, so this
/// bounds the memory and never the message.
pub const default_write_buffer_len = 1024;

/// How large one TLS record can be on the wire. The socket buffers of an
/// encrypted connection are this size, because the TLS client asserts it
/// can hold a whole record on each side.
pub const record_buffer_len = zurl_tls.Client.min_buffer_len;

/// Which name the peer certificate must carry.
///
/// `.none` turns the host check off, which is what `curl -k` does. It is
/// spelled out rather than implied by a null, so a build that skips
/// verification says so at the call.
pub const HostCheck = union(enum) {
    none,
    explicit: []const u8,
};

/// Which roots the peer certificate chain must reach.
///
/// `.none` accepts any chain, and `.self_signed` accepts a chain that ends
/// in itself. Neither one authenticates the peer. `.bundle` is the only
/// member that does.
pub const TrustCheck = union(enum) {
    none,
    self_signed,
    bundle: Bundle,
};

/// A caller-owned trust store, and the lock that guards it.
///
/// The connection borrows both for the length of the handshake and never
/// after. One bundle therefore serves every connection a client opens, and
/// this file loads none of it.
pub const Bundle = struct {
    lock: *std.Io.RwLock,
    bundle: *std.crypto.Certificate.Bundle,
};

/// The lowest TLS version a connection will keep.
///
/// Re-exported from `zurl_core.tls`, which owns the enum and the floor of
/// this build, so a caller that holds a `Connection` has a name for it and
/// no second definition exists to drift.
pub const MinVersion = zurl_core.tls.MinVersion;

/// A TLS version a `--tls-max` or a `--tlsv1.x` flag names.
///
/// Re-exported from `zurl_core.tls` for the same reason `MinVersion` is:
/// one definition, and no second one to drift.
pub const Version = zurl_core.tls.Version;

/// The ALPN protocols a connection offers when the caller names none.
///
/// **`h2` first, then `http/1.1`.** Both engines exist now:
/// `zurl-http/h2.zig` reads HTTP/2 and `zurl-http/h1.zig` reads HTTP/1.1,
/// and `h1.sendOn` reads `alpnProtocol` to decide which one speaks. The
/// order is the order of preference, and the peer picks: a server with no
/// HTTP/2 answers `http/1.1`, and a server that answers nothing at all
/// leaves the caller on HTTP/1.1 too.
///
/// A caller that wants one protocol narrows the list rather than change
/// this constant. `engine.Request.http_version` is that narrowing, and
/// `alpn_http_1_1` is the list it names.
pub const alpn_default: []const []const u8 = &.{ "h2", "http/1.1" };

/// The ALPN offer of a caller that asked for HTTP/1.1 alone. This is
/// `--http1.1`.
///
/// A peer cannot choose a protocol it was never offered, so a hop opened
/// with this list speaks HTTP/1.1 whatever the peer can do.
pub const alpn_http_1_1: []const []const u8 = &.{"http/1.1"};

/// The ALPN offer of a caller that asked for HTTP/2 alone. This is
/// `--http2-prior-knowledge`.
///
/// **A peer that has no HTTP/2 ends the handshake.** It has nothing to
/// choose, so RFC 7301 section 3.2 has it answer a `no_application_protocol`
/// alert and the session never opens. That is the point of the flag: a
/// caller who says the peer speaks HTTP/2 is told when it does not, rather
/// than quietly served HTTP/1.1.
///
/// Measured against curl 8.21.0 and an `openssl s_server` offering
/// `http/1.1` alone: `--http2-prior-knowledge` gave
/// `tlsv1 alert no application protocol` and exit 35, while `--http2` on
/// the same server answered on HTTP/1.1 with exit 0.
pub const alpn_http_2: []const []const u8 = &.{"h2"};

/// The ALPN offer of an HTTP/3 transfer. RFC 9114 section 3.1 registers
/// `h3` for HTTP/3 over QUIC.
///
/// **This list goes through a QUIC handshake and never a TLS one.** A
/// TLS session over TCP cannot carry HTTP/3, so a `Tls.alpn_protocols`
/// holding this would offer a protocol the connection cannot speak.
/// `zurl_quic_tls.Handshake.Options.alpn_protocols` is the field that
/// takes it, and the bytes on the wire come from the same encoder
/// `zurl_tls.Client` uses for the three lists above.
///
/// **ALPN is not optional here.** RFC 9001 section 8.1 requires ALPN on
/// every QUIC connection, so an empty list has no wire form and the
/// handshake refuses one. That is the difference from `--no-alpn`, which
/// a TLS session accepts.
pub const alpn_http_3: []const []const u8 = &.{"h3"};

/// What an encrypted connection needs beyond a socket.
pub const Tls = struct {
    host: HostCheck,
    trust: TrustCheck,
    /// The lowest TLS version to keep. This is `--tlsv1.2` and
    /// `--tlsv1.3`.
    ///
    /// **This is checked after the handshake, not before it.** The client
    /// hello offers TLS 1.2 and TLS 1.3, and a floor of TLS 1.3 would have
    /// to drop an entry from the `supported_versions` list to be a bound on
    /// the wire. Dropping an entry shortens the hello, and every length
    /// after that field is computed from it, so the hello would have to be
    /// built a second way. Reading `Client.tls_version` back costs nothing
    /// and asks for none of that.
    ///
    /// `max_version` below can narrow the same list, because a ceiling
    /// **replaces** an entry rather than dropping one. That is the whole
    /// difference between the two fields.
    ///
    /// The cost is one handshake that completes and is then dropped: a
    /// server that offers TLS 1.2 alone answers a `.tls_1_3` floor with a
    /// finished session, and `init` closes it and reports
    /// `error.TlsVersionTooLow`. The peer's certificate was verified
    /// before that point, exactly as on any other session, so nothing is
    /// trusted here that would not have been trusted anyway. No request
    /// byte is ever written: `init` returns the fault, and the caller
    /// never reaches the request.
    min_version: MinVersion = .tls_1_2,
    /// The highest TLS version to keep. This is `--tls-max`.
    ///
    /// **This one is a bound on the wire.** `init` hands it to
    /// `zurl_tls.Client.Options.max_version`, which offers TLS 1.2 alone
    /// for a ceiling of TLS 1.2, so a server that speaks both versions
    /// answers with TLS 1.2 and the transfer runs. That is what curl does
    /// with the same flag, and it is why a ceiling cannot be a check after
    /// the handshake: such a check would fail every TLS 1.3 server, where
    /// curl succeeds.
    ///
    /// The session is still read back afterwards, because a peer that
    /// ignores the offer is untrusted input like any other. A version above
    /// the ceiling is `error.TlsVersionTooHigh`.
    ///
    /// A ceiling of TLS 1.0 or TLS 1.1 is below `min_version`, so no
    /// version is left at all. `init` reports
    /// `error.TlsVersionRangeEmpty` before it writes a byte, rather than
    /// run on a version the user excluded.
    max_version: Version = .highest,
    /// The protocols the ALPN extension offers, in the order of
    /// preference. RFC 7301.
    ///
    /// An empty list sends no extension at all, which is curl's
    /// `--no-alpn`. The default is `alpn_default`, which offers `h2` and
    /// then `http/1.1`.
    ///
    /// **Every site sets this field.** The five that speak a protocol
    /// other than HTTP pass `&.{}`, because a peer must never be offered
    /// `h2` on an IMAPS or an FTPS connection. A site that leaves the
    /// field out gets the HTTP offer, so name it.
    ///
    /// **The peer's answer is checked against this list.** A name outside
    /// it is `error.TlsAlpnProtocolNotOffered` and the session is dropped.
    /// A peer is untrusted input, and a protocol zurl cannot parse must
    /// never reach the engine above. A peer that answers nothing at all is
    /// not a fault: RFC 7301 lets a server that shares no protocol leave
    /// the extension out, and `alpnProtocol` then reports null.
    alpn_protocols: []const []const u8 = alpn_default,
    /// Filled in when `init` returns `error.TlsAlert`. The alert says what
    /// the peer refused, which the error name alone cannot.
    alert: ?*std.crypto.tls.Alert = null,
    /// Where to log the session secrets. Anybody who can read that stream
    /// can decrypt this connection, so this stays null unless a user asks
    /// for it.
    ssl_key_log: ?*zurl_tls.Client.SslKeyLog = null,
    /// Whether the end of the socket is passed up as the end of the
    /// stream, even with no `close_notify` from the peer.
    ///
    /// This is safe for a protocol that carries its own length, which HTTP
    /// does through `Content-Length` and chunked framing. It is not safe
    /// for one that does not, so the default refuses a truncated stream.
    allow_truncation_attacks: bool = false,
};

pub const Options = struct {
    read_buffer_len: usize = default_read_buffer_len,
    write_buffer_len: usize = default_write_buffer_len,
    /// Null for a plain connection.
    tls: ?Tls = null,
};

/// Every fault opening a connection can report.
///
/// Nothing here is collapsed. An expired certificate, a name the
/// certificate does not carry, a chain that reaches no trusted root, and
/// an alert the peer sent all keep their own name, because a caller must
/// answer each one differently and curl gives them different exit codes.
/// `errors.zig` holds the map onto `zurl_core.Error`.
///
/// `error.ReadFailed` and `error.WriteFailed` are members, because
/// `zurl_tls.Client.InitError` declares them, but `init` never returns
/// either. It replaces each with the socket fault that caused it, which
/// `std.Io.net.Stream.Reader` and `.Writer` record. A name that says only
/// "a read failed" is exactly the kind of erased cause this package
/// exists to stop.
pub const InitError = std.mem.Allocator.Error ||
    zurl_tls.Client.InitError ||
    std.Io.net.Stream.Reader.Error ||
    std.Io.net.Stream.Writer.Error ||
    error{
        /// The system gave no entropy for the TLS client random.
        ///
        /// `std.Io.random` would have fallen back to a weaker source
        /// without saying so. A handshake keyed from a guessable random
        /// is worse than a handshake that does not happen, so this asks
        /// for entropy from outside the process and reports the refusal.
        EntropyUnavailable,
        /// The peer chose a TLS version below `Tls.min_version`.
        ///
        /// This is `--tlsv1.3` against a server that offers TLS 1.2 alone.
        /// The session finished and was dropped, and no request byte went
        /// out. curl 8.21.0 refuses the same pair at the handshake and
        /// exits 35, so this maps to `SslConnectError` and exits 35 too.
        TlsVersionTooLow,
        /// The peer chose a TLS version above `Tls.max_version`.
        ///
        /// The client hello already offered nothing higher, so this means
        /// the peer answered with a version it was never offered. A peer
        /// is untrusted input, so that is a fault to name and not an
        /// assert. The session is dropped and no request byte goes out.
        TlsVersionTooHigh,
        /// `Tls.max_version` is below `Tls.min_version`, so no TLS version
        /// is left to offer.
        ///
        /// This is `--tls-max 1.0` and `--tls-max 1.1`: a ceiling under
        /// the TLS 1.2 floor of this build. Reported before the handshake
        /// starts. curl 8.21.0 takes the same flags and fails the same
        /// connection at its own handshake with exit 35, which is what
        /// this maps to.
        TlsVersionRangeEmpty,
    };

/// Why a read on this connection failed. Either the TLS layer refused the
/// record, or the socket under it failed.
pub const ReadError = zurl_tls.Client.ReadError || std.Io.net.Stream.Reader.Error;

/// Why a write on this connection failed. Always the socket: the TLS layer
/// encrypts what it is given and reports the socket fault under it.
pub const WriteError = std.Io.net.Stream.Writer.Error;

/// Takes `stream` and prepares it for reading and writing. When
/// `options.tls` is set, this also completes the TLS handshake, so a
/// return of `void` means the session is up.
///
/// Initializes `c` in place, and not by value, because the TLS client
/// holds the address of `c.stream_reader.interface` and
/// `c.stream_writer.interface`. A connection built on a stack frame and
/// then returned by value would leave the session pointing at a frame that
/// no longer exists.
///
/// `c` owns `stream` only after this returns without an error. On a fault
/// `c` is not initialized, and the caller still owns `stream` and must
/// close it.
///
/// Asserts both buffer lengths are above zero. A zero-length buffer is a
/// caller mistake and never a runtime fault.
pub fn init(
    c: *Connection,
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,
    options: Options,
) InitError!void {
    std.debug.assert(options.read_buffer_len > 0);
    std.debug.assert(options.write_buffer_len > 0);

    const tls_options = options.tls orelse {
        const storage = try allocator.alloc(u8, options.read_buffer_len + options.write_buffer_len);
        c.* = .{
            .allocator = allocator,
            .io = io,
            .storage = storage,
            .stream_reader = .init(stream, io, storage[0..options.read_buffer_len]),
            .stream_writer = .init(stream, io, storage[options.read_buffer_len..]),
            .security = .plain,
            .peer = tcp.peerAddress(stream) catch null,
        };
        return;
    };

    // The socket buffers hold ciphertext, and the TLS client asserts that
    // each of them can hold one whole record. The plaintext read buffer
    // carries a whole record on top of what the caller asked for, so a
    // caller that asks for room to hold a message head still gets it after
    // a record lands.
    const plaintext_read_len = options.read_buffer_len + record_buffer_len;
    const total = record_buffer_len * 2 + plaintext_read_len + options.write_buffer_len;

    const storage = try allocator.alloc(u8, total);
    errdefer allocator.free(storage);

    var at: usize = 0;
    const socket_read = storage[at..][0..record_buffer_len];
    at += record_buffer_len;
    const socket_write = storage[at..][0..record_buffer_len];
    at += record_buffer_len;
    const plaintext_read = storage[at..][0..plaintext_read_len];
    at += plaintext_read_len;
    const plaintext_write = storage[at..][0..options.write_buffer_len];
    at += options.write_buffer_len;
    std.debug.assert(at == storage.len);

    c.* = .{
        .allocator = allocator,
        .io = io,
        .storage = storage,
        .stream_reader = .init(stream, io, socket_read),
        .stream_writer = .init(stream, io, socket_write),
        // The handshake reads and writes through the two fields above, so
        // the session cannot exist until it finishes. `plain` stands here
        // for that window only, and nothing outside this function sees it.
        .security = .plain,
        // Read before the handshake, because it is the socket that
        // answers and the handshake changes nothing about the socket.
        .peer = tcp.peerAddress(stream) catch null,
    };

    // A ceiling under the floor leaves no version to offer, so the
    // handshake never starts. Checked here, before the entropy and before
    // the first byte, because there is nothing to negotiate.
    if (!tls_options.max_version.permitsFloor(tls_options.min_version))
        return error.TlsVersionRangeEmpty;

    var entropy: [zurl_tls.Client.Options.entropy_len]u8 = undefined;
    // The client random and the key share come from this. It is a secret
    // for the length of the handshake and nothing after it.
    defer std.crypto.secureZero(u8, &entropy);
    try io.randomSecure(&entropy);

    const session = zurl_tls.Client.init(&c.stream_reader.interface, &c.stream_writer.interface, .{
        .host = switch (tls_options.host) {
            .none => .no_verification,
            .explicit => |name| .{ .explicit = name },
        },
        .ca = switch (tls_options.trust) {
            .none => .no_verification,
            .self_signed => .self_signed,
            .bundle => |trust| .{ .bundle = .{
                .gpa = allocator,
                .io = io,
                .lock = trust.lock,
                .bundle = trust.bundle,
            } },
        },
        .read_buffer = plaintext_read,
        .write_buffer = plaintext_write,
        .entropy = &entropy,
        .realtime_now = std.Io.Clock.real.now(io),
        .ssl_key_log = tls_options.ssl_key_log,
        .allow_truncation_attacks = tls_options.allow_truncation_attacks,
        .alert = tls_options.alert,
        // The ceiling is a bound on the wire. See `Tls.max_version`.
        .max_version = tls_options.max_version.offer(),
        // And the ALPN offer, which the client hello carries and the
        // client checks the answer against. See `Tls.alpn_protocols`.
        .alpn_protocols = tls_options.alpn_protocols,
    }) catch |err| switch (err) {
        // The TLS client says only that a read or a write failed. The
        // socket knows which fault it was, so report that instead. Both
        // fields are set whenever the matching name arrives.
        error.WriteFailed => return c.stream_writer.err.?,
        error.ReadFailed => return c.stream_reader.err.?,
        else => |e| return e,
    };

    // The floor is read here, from the version the peer and the client
    // agreed on, and the session is dropped when it is not met. See
    // `Tls.min_version` for why the check is here and not in the hello.
    if (!tls_options.min_version.met(session.tls_version)) return error.TlsVersionTooLow;

    // And the ceiling is read back too. The hello offered nothing above
    // it, so this can only fail for a peer that answered with a version it
    // was never offered. A peer is untrusted input, so that is a fault to
    // name and never an assert.
    if (!tls_options.max_version.permits(session.tls_version)) return error.TlsVersionTooHigh;

    // The session is copied into its final place, and it must not move
    // again. `session.reader` and `session.writer` are found from the
    // address of the field they sit in, so `reader` and `writer` below
    // return pointers into `c` and never into a copy.
    c.security = .{ .tls = session };
}

/// Closes the socket and frees the buffers. Anything written and not
/// flushed is dropped.
///
/// This sends no `close_notify`. Call `end` first when the peer should be
/// told the stream finished on purpose.
pub fn deinit(c: *Connection) void {
    c.stream_reader.stream.close(c.io);
    c.allocator.free(c.storage);
    c.* = undefined;
}

/// Makes this connection safe for one task to read while another writes.
///
/// Call it once, after `init`, and only for a protocol that drives the two
/// sides from two tasks. HTTP/2 does; HTTP/1.1 does not, and a connection
/// that nobody shares must not pay for a lock it never contends.
///
/// The lock this installs lives in this connection, so the address of the
/// connection must not change afterward. That already holds: the TLS
/// session keeps the addresses of this connection's own buffers.
///
/// A plain connection needs nothing. It has no key to rotate, and the
/// caller above it is what keeps two tasks off one write buffer.
pub fn shareBetweenTasks(c: *Connection) void {
    switch (c.security) {
        .plain => {},
        .tls => |*session| session.write_lock = .{
            .ctx = c,
            .acquire_fn = acquireWriteLock,
            .release_fn = releaseWriteLock,
        },
    }
}

/// Takes `write_lock`. This is what `zurl_tls.Client.WriteLock` calls.
///
/// **Uncancelable on purpose.** The lock is held over one record's
/// encryption and over one key rotation, and a task that stopped half way
/// through either one would leave the session in a state no later record
/// could be read against. A cancel is honoured at the read or the write
/// that surrounds this, which is where it can be honoured safely.
fn acquireWriteLock(ctx: *anyopaque) void {
    const c: *Connection = @ptrCast(@alignCast(ctx));
    c.write_lock.lockUncancelable(c.io);
}

/// Gives `write_lock` back.
fn releaseWriteLock(ctx: *anyopaque) void {
    const c: *Connection = @ptrCast(@alignCast(ctx));
    c.write_lock.unlock(c.io);
}

/// The read side, plaintext in both cases.
pub fn reader(c: *Connection) *std.Io.Reader {
    return switch (c.security) {
        .plain => &c.stream_reader.interface,
        .tls => |*session| &session.reader,
    };
}

/// The write side, plaintext in both cases.
///
/// Call `Connection.flush` to send what was written. Do not call
/// `writer().flush()` and stop there. On an encrypted connection that call
/// only encrypts the plaintext into the socket buffer, and the bytes stay
/// in that buffer until the socket writer is flushed as well. A caller
/// that flushed only the writer wrote a whole request that never left the
/// process, and then waited for an answer to it.
pub fn writer(c: *Connection) *std.Io.Writer {
    return switch (c.security) {
        .plain => &c.stream_writer.interface,
        .tls => |*session| &session.writer,
    };
}

/// Whether this connection encrypts what it carries.
pub fn isSecure(c: *const Connection) bool {
    return switch (c.security) {
        .plain => false,
        .tls => true,
    };
}

/// Sends everything that was written and not sent yet.
///
/// An encrypted connection has two buffers in a row: the plaintext the
/// caller wrote, and the ciphertext that is on its way to the socket. Both
/// must go, and flushing only the first leaves a whole request inside the
/// process. This is the one call that empties both, which is why a caller
/// uses it instead of `writer().flush()`.
pub fn flush(c: *Connection) WriteError!void {
    switch (c.security) {
        .plain => {},
        .tls => |*session| session.writer.flush() catch return c.writeErrorOrUnexpected(),
    }
    c.stream_writer.interface.flush() catch return c.writeErrorOrUnexpected();
}

/// Sends everything buffered, and tells the peer the stream ended.
///
/// On an encrypted connection this writes `close_notify`, so the peer can
/// tell a finished stream from a cut one. On a plain connection it is a
/// flush.
pub fn end(c: *Connection) WriteError!void {
    switch (c.security) {
        .plain => {},
        .tls => |*session| session.end() catch return c.writeErrorOrUnexpected(),
    }
    c.stream_writer.interface.flush() catch return c.writeErrorOrUnexpected();
}

/// Why the last read failed, or null when none did.
///
/// Call this after a reader returns `error.ReadFailed`. The reader gives
/// one name for every fault, and this is where the cause is kept: an alert
/// the peer sent, a record that did not authenticate, or the socket fault
/// under the session.
pub fn readError(c: *const Connection) ?ReadError {
    return switch (c.security) {
        .plain => c.stream_reader.err,
        .tls => |*session| session.read_err orelse c.stream_reader.err,
    };
}

/// Why the last write failed, or null when none did. Call this after a
/// writer returns `error.WriteFailed`.
pub fn writeError(c: *const Connection) ?WriteError {
    return c.stream_writer.err;
}

/// The ALPN protocol the peer chose, or null when there is none.
///
/// A plain connection has no ALPN, and neither has an encrypted one where
/// the caller offered nothing or the peer answered nothing. So null means
/// only that no protocol was negotiated, and the caller keeps whatever it
/// speaks by default.
///
/// The name is one of the entries `Tls.alpn_protocols` held, because the
/// handshake refuses any other. So a caller may compare it against the
/// list it offered and needs no second check of its own.
pub fn alpnProtocol(c: *const Connection) ?[]const u8 {
    return switch (c.security) {
        .plain => null,
        .tls => |*session| session.alpnProtocol(),
    };
}

/// The alert the peer sent, or null when it sent none.
///
/// A TLS alert carries the peer's own reason for refusing the connection,
/// such as `handshake_failure` or `unknown_ca`. `error.TlsAlert` says only
/// that one arrived.
pub fn alert(c: *const Connection) ?std.crypto.tls.Alert {
    return switch (c.security) {
        .plain => null,
        .tls => |*session| session.alert,
    };
}

/// The socket fault behind a failed write, or `error.Unexpected` when the
/// writer reported a failure and recorded no reason.
///
/// The writer sets `err` on every fault it reports, so the second arm is
/// not reachable. It stays a branch because the alternative, an
/// `unreachable`, is removed in ReleaseFast, which is the build a user
/// runs.
fn writeErrorOrUnexpected(c: *const Connection) WriteError {
    return c.stream_writer.err orelse error.Unexpected;
}

const testing = std.testing;
const builtin = @import("builtin");

/// Opens a connection to a listening loopback server, and closes the
/// socket itself when `init` refuses it.
fn openPlain(c: *Connection, port: u16, options: Options) !void {
    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    const stream = try address.connect(testing.io, .{ .mode = .stream });
    c.init(testing.allocator, testing.io, stream, options) catch |err| {
        // `init` takes the socket only when it succeeds, so a fault here
        // leaves the socket with this function to close.
        stream.close(testing.io);
        return err;
    };
}

test "a plain connection reads and writes through the same two calls a secure one does" {
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(testing.io, .{ .reuse_address = true });
    defer server.deinit(testing.io);

    var c: Connection = undefined;
    try openPlain(&c, server.socket.address.ip4.port, .{});
    defer c.deinit();

    try testing.expect(!c.isSecure());
    // A plain connection ran no handshake, so it negotiated no protocol.
    try testing.expect(c.alpnProtocol() == null);
    try testing.expectEqual(@as(?std.crypto.tls.Alert, null), c.alert());
    try testing.expectEqual(@as(?ReadError, null), c.readError());
    try testing.expectEqual(@as(?WriteError, null), c.writeError());

    const peer = try server.accept(testing.io);
    defer peer.close(testing.io);

    try c.writer().writeAll("hello");
    try c.flush();

    var peer_buffer: [64]u8 = undefined;
    var peer_reader = std.Io.net.Stream.Reader.init(peer, testing.io, &peer_buffer);
    try testing.expectEqualStrings("hello", try peer_reader.interface.take(5));

    // `end` sends what is still buffered as well. On a plain connection
    // it adds nothing else, and this pins that it still sends.
    try c.writer().writeAll("bye");
    try c.end();
    try testing.expectEqualStrings("bye", try peer_reader.interface.take(3));
}

test "a plain connection reads what the peer wrote" {
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(testing.io, .{ .reuse_address = true });
    defer server.deinit(testing.io);

    var c: Connection = undefined;
    try openPlain(&c, server.socket.address.ip4.port, .{});
    defer c.deinit();

    const peer = try server.accept(testing.io);
    defer peer.close(testing.io);

    var peer_buffer: [64]u8 = undefined;
    var peer_writer = std.Io.net.Stream.Writer.init(peer, testing.io, &peer_buffer);
    try peer_writer.interface.writeAll("payload");
    try peer_writer.interface.flush();

    try testing.expectEqualStrings("payload", try c.reader().take(7));
}

test "a connection records the numeric address it reached" {
    // **A protocol that opens a second connection to the same machine
    // reads this and never the host name.** A name reaches a resolver
    // again, and the second answer need not be the first. See the field.
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) return error.SkipZigTest;

    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(testing.io, .{ .reuse_address = true });
    defer server.deinit(testing.io);
    const port = server.socket.address.ip4.port;

    var c: Connection = undefined;
    try openPlain(&c, port, .{});
    defer c.deinit();

    const peer = c.peer orelse return error.TestExpectedPeerAddress;
    try testing.expect(peer == .ip4);
    try testing.expectEqual([4]u8{ 127, 0, 0, 1 }, peer.ip4.bytes);
    // The port of this connection, so a caller that dials a second port
    // must set its own.
    try testing.expectEqual(port, peer.ip4.port);
}

test "a connection asks for the buffer room the caller named" {
    // A protocol engine sizes the read buffer to hold a whole message
    // head. A connection that quietly kept less would fail that engine on
    // a head it was told to accept.
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(testing.io, .{ .reuse_address = true });
    defer server.deinit(testing.io);

    var c: Connection = undefined;
    try openPlain(&c, server.socket.address.ip4.port, .{
        .read_buffer_len = 4096,
        .write_buffer_len = 512,
    });
    defer c.deinit();

    try testing.expectEqual(@as(usize, 4096), c.reader().buffer.len);
    try testing.expectEqual(@as(usize, 512), c.writer().buffer.len);
    try testing.expectEqual(@as(usize, 4096 + 512), c.storage.len);
}

test "a handshake the peer cuts keeps a TLS name, and never a bare read failure" {
    // The only part of the TLS path that can be driven with no network:
    // a peer that reads the Client Hello and then says nothing. That is
    // enough to prove the whole setup runs, that the vendored client is
    // what runs it, and that a fault keeps a name a user can act on.
    //
    // A full handshake needs a TLS server, and neither `std` nor
    // `zurl-tls` has one, so the rest is checked by hand against
    // badssl.com. See the report.
    if (builtin.single_threaded) return error.SkipZigTest;

    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(testing.io, .{ .reuse_address = true });
    defer server.deinit(testing.io);

    var future = try testing.io.concurrent(readThenClose, .{&server});
    defer future.cancel(testing.io);

    const peer_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(server.socket.address.ip4.port) };
    const stream = try peer_address.connect(testing.io, .{ .mode = .stream });

    var peer_alert: std.crypto.tls.Alert = undefined;
    var c: Connection = undefined;
    c.init(testing.allocator, testing.io, stream, .{ .tls = .{
        .host = .{ .explicit = "zurl.test" },
        .trust = .none,
        .alert = &peer_alert,
    } }) catch |err| {
        stream.close(testing.io);
        // The peer cut the handshake. The name says which layer noticed,
        // and `error.ReadFailed`, which says nothing at all, must never
        // be what a caller gets.
        try testing.expect(err != error.ReadFailed);
        try testing.expect(err != error.WriteFailed);
        return;
    };
    c.deinit();
    try testing.expect(false); // a peer that answers nothing cannot finish a handshake
}

/// Accepts one connection, reads the start of the Client Hello, and closes
/// with no answer.
fn readThenClose(server: *std.Io.net.Server) void {
    const stream = server.accept(testing.io) catch return;
    defer stream.close(testing.io);
    var buffer: [512]u8 = undefined;
    var peer_reader = std.Io.net.Stream.Reader.init(stream, testing.io, &buffer);
    _ = peer_reader.interface.take(1) catch return;
}

test "an encrypted connection keeps the floor of this build unless a caller raises it" {
    // A caller that names no floor gets the one `zurl_core.tls` sets, so
    // a `--tlsv1.0` run and a run with no flag reach the same place. Only
    // `--tlsv1.3` moves it.
    const default_options: Tls = .{ .host = .none, .trust = .none };
    try testing.expectEqual(zurl_core.tls.MinVersion.floor, default_options.min_version);
    try testing.expectEqual(zurl_core.tls.MinVersion.tls_1_2, default_options.min_version);

    // The predicate the handshake is measured against, in the two shapes
    // `init` can meet. Measured against real servers: with `--tlsv1.3`,
    // `tls-v1-2.badssl.com:1012` fails 35 for zurl and for curl 8.21.0
    // alike, and `cloudflare.com` succeeds for both.
    try testing.expect(default_options.min_version.met(.tls_1_2));
    const raised: Tls = .{ .host = .none, .trust = .none, .min_version = .tls_1_3 };
    try testing.expect(!raised.min_version.met(.tls_1_2));
    try testing.expect(raised.min_version.met(.tls_1_3));
}

test "an encrypted connection keeps the ceiling of this build unless a caller lowers it" {
    // A caller that names no ceiling offers everything this build offers,
    // so a run with no `--tls-max` is byte for byte the run it always was.
    // Measured on the wire against a loopback listener: the client hello
    // of a bare run and of a `--tls-max 1.3` run carry the same
    // `supported_versions` bytes, `0304 0303`.
    const default_options: Tls = .{ .host = .none, .trust = .none };
    try testing.expectEqual(zurl_core.tls.Version.highest, default_options.max_version);
    try testing.expectEqual(zurl_core.tls.Version.tls_1_3, default_options.max_version);
    try testing.expectEqual(std.crypto.tls.ProtocolVersion.tls_1_3, default_options.max_version.offer());

    // A ceiling of TLS 1.2 narrows the offer, and the same hello then
    // carries `0a0a 0303`: a GREASE entry where TLS 1.3 was. Measured.
    const capped: Tls = .{ .host = .none, .trust = .none, .max_version = .tls_1_2 };
    try testing.expectEqual(std.crypto.tls.ProtocolVersion.tls_1_2, capped.max_version.offer());
    try testing.expect(capped.max_version.permits(.tls_1_2));
    try testing.expect(!capped.max_version.permits(.tls_1_3));

    // And a ceiling below the floor leaves nothing to offer, which `init`
    // reports before it writes a byte.
    const empty: Tls = .{ .host = .none, .trust = .none, .max_version = .tls_1_0 };
    try testing.expect(!empty.max_version.permitsFloor(empty.min_version));
    try testing.expect(capped.max_version.permitsFloor(capped.min_version));
    try testing.expect(default_options.max_version.permitsFloor(default_options.min_version));
}

test "an encrypted connection offers h2 and http/1.1, and a caller may narrow the list" {
    // **zurl must never offer a protocol it cannot parse.** Both names
    // here have an engine behind them: `zurl-http/h2.zig` reads HTTP/2 and
    // `zurl-http/h1.zig` reads HTTP/1.1. The order is the order of
    // preference, and a server picks one entry. Measured against
    // cloudflare.com, github.com and www.google.com: each of the three
    // selected `h2`, which is what curl -v gets from the same three.
    const default_options: Tls = .{ .host = .none, .trust = .none };
    try testing.expectEqual(@as(usize, 2), default_options.alpn_protocols.len);
    try testing.expectEqualStrings("h2", default_options.alpn_protocols[0]);
    try testing.expectEqualStrings("http/1.1", default_options.alpn_protocols[1]);
    try testing.expectEqual(alpn_default.len, default_options.alpn_protocols.len);

    // `--http1.1` narrows the offer to one name. A peer cannot choose a
    // protocol it was never offered, so such a hop speaks HTTP/1.1.
    const one: Tls = .{ .host = .none, .trust = .none, .alpn_protocols = alpn_http_1_1 };
    try testing.expectEqual(@as(usize, 1), one.alpn_protocols.len);
    try testing.expectEqualStrings("http/1.1", one.alpn_protocols[0]);

    // `--no-alpn` empties the list, and an empty list sends no extension
    // at all. That is the hello this client sent before ALPN existed, and
    // it is HTTP/1.1 too, because nothing was offered.
    const suppressed: Tls = .{ .host = .none, .trust = .none, .alpn_protocols = &.{} };
    try testing.expectEqual(@as(usize, 0), suppressed.alpn_protocols.len);
}

test "the HTTP/3 offer is one name, and it is not one a TLS session may carry" {
    // RFC 9114 section 3.1 registers `h3` for HTTP/3 over QUIC. The list
    // lives here beside the other three, so there is one place a reader
    // looks for what zurl offers, whatever the transport is.
    try testing.expectEqual(@as(usize, 1), alpn_http_3.len);
    try testing.expectEqualStrings("h3", alpn_http_3[0]);

    // **No TLS default names it.** A session over TCP cannot speak
    // HTTP/3, so offering `h3` there would let a peer choose a protocol
    // the connection cannot carry.
    for ([_][]const []const u8{ alpn_default, alpn_http_1_1, alpn_http_2 }) |offer| {
        for (offer) |name| try testing.expect(!std.mem.eql(u8, "h3", name));
    }

    // And the field default is still the HTTP over TCP offer, so a site
    // that forgets to name a list never gets the QUIC one.
    const default_options: Tls = .{ .host = .none, .trust = .none };
    try testing.expectEqual(alpn_default.len, default_options.alpn_protocols.len);
}

test "a ceiling below the floor fails before the handshake writes anything" {
    // No socket is dialed and no listener is needed: the check runs
    // before the entropy and before the first byte, so `init` can be
    // asked with a stream that never opens. This drives the predicate
    // that gate reads, which `Connection.init` calls with the same two
    // fields.
    const empty: Tls = .{ .host = .none, .trust = .none, .max_version = .tls_1_1 };
    try testing.expect(!empty.max_version.permitsFloor(.tls_1_2));

    // The floor moves too, and a `--tlsv1.3` beside a `--tls-max 1.2`
    // closes the range from the other side. The CLI reports that pair as
    // a usage fault before any transfer; this is the same rule at the
    // layer that enforces it.
    const raised: Tls = .{ .host = .none, .trust = .none, .min_version = .tls_1_3, .max_version = .tls_1_2 };
    try testing.expect(!raised.max_version.permitsFloor(raised.min_version));
}

test "an encrypted connection sizes its socket buffers for a whole TLS record" {
    // The TLS client asserts that each socket buffer holds one record. A
    // build that sized them from the caller's numbers would fail that
    // assert on the first small buffer a caller asked for, which is a
    // panic and not a fault a user can read.
    try testing.expect(record_buffer_len >= zurl_tls.Client.min_buffer_len);
    try testing.expectEqual(std.crypto.tls.max_ciphertext_record_len, record_buffer_len);
}
