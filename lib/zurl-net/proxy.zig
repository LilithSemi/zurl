//! Reaching an origin through a proxy: the `CONNECT` tunnel and the SOCKS
//! handshakes.
//!
//! **A proxy is untrusted input.** Every byte read here was written by the
//! proxy, and a proxy that is hostile, or merely broken, must not be able
//! to hold this process or fill its memory. So every read is bounded: a
//! `CONNECT` reply has a bound on one line, on the number of lines, and on
//! the whole head, and a SOCKS reply is a fixed number of bytes whose one
//! variable field is bounded by the protocol itself. `bounded.readLine`
//! does the line framing, which is the same call FTP reads its replies
//! with, so no second bounded reader exists here to drift from it.
//!
//! **Each step runs inside the connect deadline.** A step is a
//! `bounded.Upgrade`, which `bounded.setup` runs on the open stream inside
//! the raced task, between the dial and the TLS handshake. So the dial, the
//! proxy dialogue, and the origin handshake share one `--connect-timeout`,
//! and a proxy that answers nothing cannot hold the transfer. That is why
//! every read below passes `.none` for its own stall bound: the bound is
//! outside, and a second one inside would refuse the request in a build
//! with no concurrency even where the caller asked for no bound at all.
//!
//! **Nothing here decides which TLS session verifies which peer.** A step
//! runs on a plain stream. The TLS session that `bounded.setup` starts
//! after it is the session with the origin, and it is verified against the
//! origin's name and the origin's roots. A proxy that speaks TLS itself is
//! a different session, and `zurl-http/h1.zig` is where the two are told
//! apart.
//!
//! What is not here: the request bytes of a proxied cleartext request.
//! Those carry no handshake at all. A cleartext origin through an HTTP
//! proxy is one ordinary request with an absolute-form target, and
//! `zurl-http/h1.zig` writes it, because it is HTTP and this package frames
//! no HTTP.

const std = @import("std");
const zurl_core = @import("zurl-core");

const bounded = @import("bounded.zig");

/// Which protocol the proxy speaks. Re-exported from `zurl_core.proxy`, so
/// one definition serves the policy and the wire and no second one exists
/// to drift.
pub const Kind = zurl_core.proxy.Kind;

/// The largest `CONNECT` reply line this reads, in bytes.
///
/// A status line and a header line are both bounded by this. A proxy that
/// writes a longer one is refused, and the bytes it already wrote are
/// consumed: nothing can resynchronise on a line whose end never arrived.
pub const connect_line_len_max: usize = 4 * 1024;

/// How many lines a `CONNECT` reply head may carry, the status line
/// included.
///
/// A proxy answers a `CONNECT` with a status and a handful of headers.
/// This is far above any real reply and still a bound, so a proxy that
/// writes header lines forever is stopped by a count as well as by a size.
pub const connect_lines_max: usize = 64;

/// The largest whole `CONNECT` reply head this reads, in bytes.
///
/// The two bounds above can each be met by a reply that is still too large
/// together. This counts every byte of the head.
pub const connect_head_len_max: usize = 16 * 1024;

/// How much room the step keeps for bytes read from the proxy and not
/// taken yet.
///
/// Small on purpose. The step reads a short reply and hands the socket on,
/// and everything still in this buffer when the step ends is dropped. See
/// `Failure.ProxySpokeEarly`, which is why dropping it is safe: a proxy
/// that wrote more than its reply wrote bytes nobody asked for, and the
/// step refuses rather than lose them.
const step_read_buffer_len: usize = 1024;

/// How much room the step keeps for bytes written to the proxy and not
/// flushed yet.
const step_write_buffer_len: usize = 1024;

/// The largest host name a SOCKS handshake can carry, in bytes.
///
/// SOCKS5 writes the length of a domain name in one byte, RFC 1928 section
/// 5, so 255 is the protocol's own bound and not one chosen here.
pub const socks_host_len_max: usize = 255;

/// The largest user name or password a SOCKS5 credential exchange can
/// carry, in bytes. RFC 1929 writes each length in one byte.
pub const socks_credential_len_max: usize = 255;

/// Every fault a proxy step can report.
///
/// **One name for each thing a user must do about it.** A proxy that
/// refused the tunnel, a proxy that asked for a credential, and a proxy
/// that wrote bytes this build cannot read are three different problems,
/// and a single "the proxy failed" would leave a user with no next step.
/// `zurl-http/h1.zig` maps each one onto its own message and its own exit
/// code.
pub const Failure = error{
    /// The write to the proxy did not succeed.
    ProxyWriteFailed,
    /// The read from the proxy did not succeed.
    ProxyReadFailed,
    /// The proxy closed before it finished its reply.
    ProxyClosed,
    /// The proxy wrote a reply past one of this file's bounds.
    ProxyReplyTooLarge,
    /// The proxy wrote a reply this build cannot read.
    ProxyReplyMalformed,
    /// The proxy answered the `CONNECT` with a status that is not a 2xx, or
    /// answered the SOCKS request with a refusal.
    ProxyTunnelRefused,
    /// The proxy asked for a credential, or refused the one it was given.
    ProxyAuthRefused,
    /// The proxy offered no authentication method this build can use.
    ProxyAuthUnsupported,
    /// The origin host cannot travel in this SOCKS version. SOCKS4 carries
    /// an IPv4 address alone.
    ProxyAddressUnsupported,
    /// The origin host does not fit the field that must carry it.
    ProxyHostTooLong,
    /// The proxy credential does not fit the field that must carry it.
    ProxyCredentialTooLong,
    /// The origin host has no address, and this SOCKS version resolves it
    /// on this machine.
    ProxyCouldNotResolveHost,
    /// The proxy wrote bytes after its reply, before the tunnel it had just
    /// opened could carry anything.
    ///
    /// **Nothing legitimate reaches this.** Every protocol that goes
    /// through a tunnel here speaks first: a TLS client sends the hello,
    /// and an HTTP client sends the request. So a byte that arrived before
    /// this side wrote anything came from the proxy and not from the
    /// origin. The step refuses instead of dropping it, because a dropped
    /// byte would be a byte of somebody else's choosing removed from the
    /// front of the stream.
    ProxySpokeEarly,
    /// Something outside the step stopped it.
    ProxyCanceled,
};

/// Where a step must reach, which is the origin and never the proxy.
pub const Target = struct {
    /// The origin host, as the url wrote it and with no brackets around an
    /// IPv6 literal.
    host: []const u8,
    port: u16,
};

/// The proxy credential, decoded and ready for the wire.
///
/// **This is the proxy's credential and it authenticates to the proxy.** It
/// never reaches the origin. `zurl-http/engine.zig` names the header rule
/// that keeps the two apart, and this struct has no field an origin
/// credential could sit in.
///
/// `authorization` is the whole `Proxy-Authorization` header value, such as
/// `Basic Ym9iOnB3`. `user` and `password` are the decoded halves, which
/// SOCKS5 needs as two fields. A caller sets whichever the kind uses.
pub const Credential = struct {
    authorization: []const u8 = "",
    user: []const u8 = "",
    password: []const u8 = "",
};

/// What one step does on the open stream.
pub const Step = union(enum) {
    /// An HTTP `CONNECT` tunnel to `Connect.target`.
    connect: Connect,
    /// A SOCKS handshake.
    socks: Socks,
};

/// An HTTP `CONNECT` request and the reply to it.
///
/// **A `CONNECT` request is cleartext, whatever the origin speaks.** The
/// proxy reads every byte of it. So the fields here are exactly the ones a
/// proxy must see and no more: the origin host and port, which the proxy
/// needs to dial, the proxy's own credential, and the user agent. There is
/// no field for an origin credential, no field for the caller's headers,
/// and no field for the request target. Putting any of the three here would
/// hand a secret, or the path the user asked for, to the proxy.
pub const Connect = struct {
    target: Target,
    credential: Credential = .{},
    /// The `User-Agent` value. Empty writes no such line. curl 8.21.0
    /// writes one on a `CONNECT`, measured on a loopback listener.
    user_agent: []const u8 = "",
};

/// A SOCKS handshake to reach `target`.
pub const Socks = struct {
    kind: Kind,
    target: Target,
    credential: Credential = .{},
};

/// One proxy step, ready to run as a `bounded.Upgrade`.
///
/// The runner records its own reason for stopping, because a task that
/// loses the connect race returns nothing at all. `bounded.setup` reports
/// `error.UpgradeFailed`, and the caller reads `failure` beside it for the
/// name that says what to do.
///
/// `io` is filled by `run`, which `bounded.setup` calls with the same
/// `std.Io` the dial used.
pub const Runner = struct {
    step: Step,
    /// Why the step stopped, or null while it has not. Written on every
    /// path that returns false.
    failure: ?Failure = null,

    /// The `bounded.Upgrade` this runner answers to.
    ///
    /// The result borrows `self`, which must outlive the whole of
    /// `bounded.setup`.
    pub fn upgrade(self: *Runner) bounded.Upgrade {
        return .{ .ctx = self, .run = runStep };
    }

    /// The message a user reads for `failure`, or null when the step has
    /// not failed.
    ///
    /// The name alone says which layer refused. Only a sentence says what
    /// the proxy did, and a user who reads `CouldNotConnect` for a proxy
    /// that answered `407` has no way to find the cause.
    ///
    /// **No sentence here holds a credential.** A message is printed,
    /// logged, and pasted into a bug report.
    pub fn cause(self: *const Runner) ?[]const u8 {
        const failed = self.failure orelse return null;
        return switch (failed) {
            error.ProxyWriteFailed => "the write to the proxy did not succeed",
            error.ProxyReadFailed => "the read from the proxy did not succeed",
            error.ProxyClosed => "the proxy closed before it finished its reply",
            error.ProxyReplyTooLarge => "the proxy sent a reply larger than zurl reads",
            error.ProxyReplyMalformed => "the proxy sent a reply zurl cannot read",
            error.ProxyTunnelRefused => "the proxy refused the tunnel to the origin",
            error.ProxyAuthRefused => "the proxy refused the credential, or asked for one",
            error.ProxyAuthUnsupported => "the proxy offered no authentication method zurl can use",
            error.ProxyAddressUnsupported => "socks4 carries an IPv4 address alone, and this origin has none",
            error.ProxyHostTooLong => "the origin host does not fit a socks address field",
            error.ProxyCredentialTooLong => "the proxy credential does not fit a socks field",
            error.ProxyCouldNotResolveHost => "the origin host has no address on this machine",
            error.ProxySpokeEarly => "the proxy wrote bytes before the tunnel could carry any",
            error.ProxyCanceled => "the proxy step was canceled",
        };
    }
};

/// Runs one step, and records why it stopped when it did.
fn runStep(ctx: *anyopaque, io: std.Io, stream: std.Io.net.Stream) bool {
    const self: *Runner = @ptrCast(@alignCast(ctx));

    var read_storage: [step_read_buffer_len]u8 = undefined;
    var write_storage: [step_write_buffer_len]u8 = undefined;
    var reader: std.Io.net.Stream.Reader = .init(stream, io, &read_storage);
    var writer: std.Io.net.Stream.Writer = .init(stream, io, &write_storage);

    const result = switch (self.step) {
        .connect => |c| runConnect(&reader, &writer, io, c),
        .socks => |s| runSocks(&reader, &writer, io, s),
    };
    result catch |err| {
        self.failure = err;
        return false;
    };

    // **Nothing may be left in the reader.** The step's own buffer goes out
    // of scope here, so a byte still in it would be lost from the front of
    // the stream. Every protocol that follows this step speaks first, so a
    // byte that already arrived came from the proxy and is not the
    // origin's. See `Failure.ProxySpokeEarly`.
    if (reader.interface.bufferedLen() != 0) {
        self.failure = error.ProxySpokeEarly;
        return false;
    }
    return true;
}

/// Writes a `CONNECT` request and reads the reply.
///
/// **The request carries the origin host, the origin port, the proxy
/// credential, and the user agent, and nothing else.** The proxy reads
/// every byte of it in cleartext even when the origin speaks TLS, so
/// anything else written here would be a secret handed to the proxy. The
/// host and the port cannot be helped: the proxy has to dial them.
///
/// The bytes and their order match curl 8.21.0, measured on a loopback
/// listener with `-x http://127.0.0.1:PORT -u alice:originpw -U
/// bob:proxypw https://example.com/path?q=1`:
///
///     CONNECT example.com:443 HTTP/1.1
///     Host: example.com:443
///     Proxy-Authorization: Basic Ym9iOnByb3h5cHc=
///     User-Agent: curl/8.21.0
///     Proxy-Connection: Keep-Alive
///
/// **There is no `Authorization` line in that capture and there is none
/// here.** The origin credential `-u` named stayed off the `CONNECT` and
/// went inside the tunnel. The path and the query stayed off it too.
fn runConnect(
    reader: *std.Io.net.Stream.Reader,
    writer: *std.Io.net.Stream.Writer,
    io: std.Io,
    step: Connect,
) Failure!void {
    const w = &writer.interface;
    w.writeAll("CONNECT ") catch return error.ProxyWriteFailed;
    writeAuthority(w, step.target) catch return error.ProxyWriteFailed;
    w.writeAll(" HTTP/1.1\r\nHost: ") catch return error.ProxyWriteFailed;
    writeAuthority(w, step.target) catch return error.ProxyWriteFailed;
    w.writeAll("\r\n") catch return error.ProxyWriteFailed;

    if (step.credential.authorization.len != 0) {
        w.writeAll("Proxy-Authorization: ") catch return error.ProxyWriteFailed;
        w.writeAll(step.credential.authorization) catch return error.ProxyWriteFailed;
        w.writeAll("\r\n") catch return error.ProxyWriteFailed;
    }
    if (step.user_agent.len != 0) {
        w.writeAll("User-Agent: ") catch return error.ProxyWriteFailed;
        w.writeAll(step.user_agent) catch return error.ProxyWriteFailed;
        w.writeAll("\r\n") catch return error.ProxyWriteFailed;
    }
    // curl writes this, measured above. A proxy that reads it keeps the
    // connection open, which is what the pool above needs.
    w.writeAll("Proxy-Connection: Keep-Alive\r\n\r\n") catch return error.ProxyWriteFailed;
    w.flush() catch return error.ProxyWriteFailed;

    return readConnectReply(&reader.interface, io);
}

/// Reads a `CONNECT` reply and answers whether the tunnel is open.
///
/// Three bounds, and a proxy has to pass all three: one line, the number of
/// lines, and the whole head together. The head is read and dropped: a
/// caller has no use for a proxy's own headers, and keeping them would
/// give a proxy a way to fill memory that the bounds above already refuse.
fn readConnectReply(r: *std.Io.Reader, io: std.Io) Failure!void {
    var line_buffer: [connect_line_len_max]u8 = undefined;
    const status_line = try readProxyLine(r, io, &line_buffer);
    const status = try parseStatusLine(status_line);

    var head_len: usize = status_line.len + 2;
    var lines: usize = 1;
    while (true) {
        lines += 1;
        if (lines > connect_lines_max) return error.ProxyReplyTooLarge;
        const line = try readProxyLine(r, io, &line_buffer);
        head_len += line.len + 2;
        if (head_len > connect_head_len_max) return error.ProxyReplyTooLarge;
        // The empty line ends the head. A 2xx answer to a `CONNECT` carries
        // no body, RFC 9110 section 9.3.6, so the next byte belongs to the
        // tunnel.
        if (line.len == 0) break;
    }

    // **A 2xx and nothing else opens the tunnel.** Measured against curl
    // 8.21.0: a proxy answering `403` and a proxy answering `407` each gave
    // exit 7, the same code a refused connection gives, because no
    // connection to the origin exists either way.
    if (status == 407) return error.ProxyAuthRefused;
    if (status < 200 or status > 299) return error.ProxyTunnelRefused;
}

/// Reads one line of a proxy reply, with the line ending taken off.
fn readProxyLine(r: *std.Io.Reader, io: std.Io, out: []u8) Failure![]u8 {
    // `.none` for the stall bound. The whole step runs inside the connect
    // deadline that `bounded.setup` races, so the wait is already bounded,
    // and a second bound here would refuse the request in a build with no
    // concurrency.
    return bounded.readLine(r, io, out, .none) catch |err| switch (err) {
        error.LineTooLong => error.ProxyReplyTooLarge,
        error.EndOfStream => error.ProxyClosed,
        error.OperationTimedOut => error.ProxyReadFailed,
        error.ReadTimeoutUnsupported => error.ProxyReadFailed,
        error.ReadFailed => error.ProxyReadFailed,
        error.StreamTooLong => error.ProxyReplyTooLarge,
        error.OutOfMemory => error.ProxyReadFailed,
        error.Canceled => error.ProxyCanceled,
    };
}

/// Reads the status code out of a `CONNECT` reply's status line.
///
/// The line must start `HTTP/` and carry a three-digit code after the
/// version. Anything else is a reply this build cannot read, which is not
/// the same thing as a refusal: a peer that answers a `CONNECT` with
/// something that is not HTTP is not a proxy at all.
fn parseStatusLine(line: []const u8) Failure!u16 {
    if (!std.mem.startsWith(u8, line, "HTTP/")) return error.ProxyReplyMalformed;
    const space = std.mem.indexOfScalar(u8, line, ' ') orelse return error.ProxyReplyMalformed;
    const rest = line[space + 1 ..];
    if (rest.len < 3) return error.ProxyReplyMalformed;
    const digits = rest[0..3];
    for (digits) |byte| {
        if (!std.ascii.isDigit(byte)) return error.ProxyReplyMalformed;
    }
    // A code and then something that is not a space is not a status line.
    if (rest.len > 3 and rest[3] != ' ') return error.ProxyReplyMalformed;
    return std.fmt.parseInt(u16, digits, 10) catch error.ProxyReplyMalformed;
}

/// Writes `target` as an authority, with brackets around an IPv6 literal.
///
/// A `CONNECT` line reading `CONNECT ::1:443 HTTP/1.1` names no port a
/// proxy can find. RFC 3986 asks for the brackets, and curl writes them.
fn writeAuthority(w: *std.Io.Writer, target: Target) std.Io.Writer.Error!void {
    const bracketed = std.mem.indexOfScalar(u8, target.host, ':') != null;
    if (bracketed) try w.writeByte('[');
    try w.writeAll(target.host);
    if (bracketed) try w.writeByte(']');
    try w.print(":{d}", .{target.port});
}

/// Runs a SOCKS handshake of whichever version `step.kind` names.
fn runSocks(
    reader: *std.Io.net.Stream.Reader,
    writer: *std.Io.net.Stream.Writer,
    io: std.Io,
    step: Socks,
) Failure!void {
    return switch (step.kind) {
        .socks4, .socks4a => runSocks4(reader, writer, io, step),
        .socks5, .socks5h => runSocks5(reader, writer, io, step),
        // `zurl-http/h1.zig` builds this value and never names an HTTP kind
        // here. A branch and not an `unreachable`, because an
        // `unreachable` disappears in the ReleaseFast build a user runs.
        .http, .https => error.ProxyReplyMalformed,
    };
}

/// Runs a SOCKS4 or SOCKS4a handshake.
///
/// The request is `04 01 <port> <address> <user id> 00`, and SOCKS4a adds
/// the host name after the user id. The address of a SOCKS4a request is
/// `0.0.0.x` with a non-zero last byte, which is what tells a server the
/// name follows.
///
/// Measured against curl 8.21.0 on a loopback listener:
///
///     --socks4  http://127.0.0.9/x  ->  04 01 00 50 7f 00 00 09 00
///     --socks4a http://example.com/x ->  04 01 00 50 00 00 00 01 00
///                                        "example.com" 00
///
/// The reply is eight bytes: a zero, a result code, a port, and an address.
/// Code 0x5a is granted, RFC-less but universal, and every other code is a
/// refusal.
fn runSocks4(
    reader: *std.Io.net.Stream.Reader,
    writer: *std.Io.net.Stream.Writer,
    io: std.Io,
    step: Socks,
) Failure!void {
    _ = io;
    const w = &writer.interface;
    const by_name = step.kind == .socks4a;

    var head: [8]u8 = undefined;
    head[0] = 0x04;
    head[1] = 0x01;
    std.mem.writeInt(u16, head[2..4], step.target.port, .big);
    if (by_name) {
        // The `0.0.0.x` form says a host name follows the user id.
        head[4..8].* = .{ 0, 0, 0, 1 };
        if (step.target.host.len > socks_host_len_max) return error.ProxyHostTooLong;
    } else {
        // SOCKS4 carries four address bytes and nothing else. A name has to
        // become an address on this machine before it can travel.
        const address = try resolveIp4(step.target.host);
        head[4..8].* = address;
    }
    w.writeAll(&head) catch return error.ProxyWriteFailed;

    // The user id field. curl puts the proxy user name here, and an empty
    // one is just the terminator. Measured: with no `-U`, curl wrote a lone
    // `00`.
    if (step.credential.user.len > socks_credential_len_max) return error.ProxyCredentialTooLong;
    // A NUL inside the user id would end the field early and put the rest
    // of it where the host name goes.
    if (std.mem.indexOfScalar(u8, step.credential.user, 0) != null) return error.ProxyCredentialTooLong;
    w.writeAll(step.credential.user) catch return error.ProxyWriteFailed;
    w.writeByte(0) catch return error.ProxyWriteFailed;

    if (by_name) {
        if (std.mem.indexOfScalar(u8, step.target.host, 0) != null) return error.ProxyHostTooLong;
        w.writeAll(step.target.host) catch return error.ProxyWriteFailed;
        w.writeByte(0) catch return error.ProxyWriteFailed;
    }
    w.flush() catch return error.ProxyWriteFailed;

    var reply: [8]u8 = undefined;
    try readExact(&reader.interface, &reply);
    // The first byte of a SOCKS4 reply is zero. Anything else is not a
    // SOCKS4 server.
    if (reply[0] != 0x00) return error.ProxyReplyMalformed;
    return switch (reply[1]) {
        0x5a => {},
        // 0x5c and 0x5d are the identd answers, which is a credential
        // question and not a routing one.
        0x5c, 0x5d => error.ProxyAuthRefused,
        else => error.ProxyTunnelRefused,
    };
}

/// Runs a SOCKS5 or SOCKS5h handshake, RFC 1928 and RFC 1929.
///
/// The greeting offers `00`, no authentication, and adds `02`, a user name
/// and a password, when there is a credential to offer. curl 8.21.0 also
/// offers `01`, GSSAPI, measured as `05 02 00 01` with no credential and
/// `05 03 00 01 02` with one. This build has no GSSAPI, so it offers no
/// method it cannot complete: a server that chose `01` would leave the
/// handshake stopped in a place neither side can leave.
///
/// **A method the server names and this side never offered is refused.** A
/// proxy is untrusted input, so an answer outside the offer is a fault to
/// name and never a method to try.
fn runSocks5(
    reader: *std.Io.net.Stream.Reader,
    writer: *std.Io.net.Stream.Writer,
    io: std.Io,
    step: Socks,
) Failure!void {
    _ = io;
    const w = &writer.interface;
    const r = &reader.interface;
    const offers_credential = step.credential.user.len != 0 or step.credential.password.len != 0;

    if (offers_credential) {
        w.writeAll(&.{ 0x05, 0x02, 0x00, 0x02 }) catch return error.ProxyWriteFailed;
    } else {
        w.writeAll(&.{ 0x05, 0x01, 0x00 }) catch return error.ProxyWriteFailed;
    }
    w.flush() catch return error.ProxyWriteFailed;

    var greeting: [2]u8 = undefined;
    try readExact(r, &greeting);
    if (greeting[0] != 0x05) return error.ProxyReplyMalformed;
    switch (greeting[1]) {
        0x00 => {},
        0x02 => {
            if (!offers_credential) return error.ProxyAuthUnsupported;
            try socks5Credential(r, w, step.credential);
        },
        // 0xff is the server saying it accepts none of the offer. Every
        // other value is a method that was never offered.
        else => return error.ProxyAuthUnsupported,
    }

    var head: [4]u8 = .{ 0x05, 0x01, 0x00, 0x00 };
    var address_buffer: [socks_host_len_max + 1]u8 = undefined;
    const address = try socks5Address(&address_buffer, step, &head[3]);
    w.writeAll(&head) catch return error.ProxyWriteFailed;
    w.writeAll(address) catch return error.ProxyWriteFailed;
    var port: [2]u8 = undefined;
    std.mem.writeInt(u16, &port, step.target.port, .big);
    w.writeAll(&port) catch return error.ProxyWriteFailed;
    w.flush() catch return error.ProxyWriteFailed;

    var reply: [4]u8 = undefined;
    try readExact(r, &reply);
    if (reply[0] != 0x05) return error.ProxyReplyMalformed;
    switch (reply[1]) {
        0x00 => {},
        // 0x02 is "connection not allowed by ruleset", which is the proxy
        // refusing this caller rather than failing to reach the origin.
        0x02 => return error.ProxyAuthRefused,
        else => return error.ProxyTunnelRefused,
    }

    // The bound address follows, and it has to be consumed before the
    // tunnel carries anything. Its length depends on the address type,
    // which is one byte the proxy chose, so each arm is bounded on its own
    // and an unknown type is refused rather than skipped by a guess.
    var scratch: [socks_host_len_max]u8 = undefined;
    switch (reply[3]) {
        0x01 => try readExact(r, scratch[0..4]),
        0x03 => {
            var len_byte: [1]u8 = undefined;
            try readExact(r, &len_byte);
            try readExact(r, scratch[0..len_byte[0]]);
        },
        0x04 => try readExact(r, scratch[0..16]),
        else => return error.ProxyReplyMalformed,
    }
    try readExact(r, scratch[0..2]);
}

/// Runs the RFC 1929 user name and password exchange.
///
/// The request is `01 <user len> <user> <password len> <password>`, and the
/// reply is `01 <status>` with a zero status for success. A non-zero status
/// is the proxy refusing the credential.
fn socks5Credential(
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    credential: Credential,
) Failure!void {
    if (credential.user.len > socks_credential_len_max) return error.ProxyCredentialTooLong;
    if (credential.password.len > socks_credential_len_max) return error.ProxyCredentialTooLong;

    w.writeAll(&.{ 0x01, @intCast(credential.user.len) }) catch return error.ProxyWriteFailed;
    w.writeAll(credential.user) catch return error.ProxyWriteFailed;
    w.writeByte(@intCast(credential.password.len)) catch return error.ProxyWriteFailed;
    w.writeAll(credential.password) catch return error.ProxyWriteFailed;
    w.flush() catch return error.ProxyWriteFailed;

    var reply: [2]u8 = undefined;
    try readExact(r, &reply);
    // RFC 1929 names version 1 for this exchange, and it is not the SOCKS
    // version. A server that answers 5 here is answering the wrong
    // dialogue.
    if (reply[0] != 0x01) return error.ProxyReplyMalformed;
    if (reply[1] != 0x00) return error.ProxyAuthRefused;
}

/// Writes the SOCKS5 address of `step.target` into `out`, and records the
/// address type in `atyp`.
///
/// A `socks5h` step sends the name and lets the proxy resolve it. A
/// `socks5` step resolves on this machine and sends the address. That is
/// the whole difference between the two, and it decides whether a local
/// resolver ever learns which host the user asked for.
fn socks5Address(out: []u8, step: Socks, atyp: *u8) Failure![]const u8 {
    // A literal address travels as an address whichever kind asked, because
    // there is nothing to resolve.
    if (std.Io.net.IpAddress.parse(step.target.host, 0)) |address| {
        switch (address) {
            .ip4 => |a| {
                atyp.* = 0x01;
                @memcpy(out[0..4], &a.bytes);
                return out[0..4];
            },
            .ip6 => |a| {
                atyp.* = 0x04;
                @memcpy(out[0..16], &a.bytes);
                return out[0..16];
            },
        }
    } else |_| {}

    if (step.kind == .socks5) {
        // The proxy must not learn the name, so it has to become an address
        // here. This build has no resolver that runs inside a step, so it
        // reports the limit rather than send the name to the proxy anyway,
        // which would turn a `socks5` run into a `socks5h` one behind the
        // user's back.
        return error.ProxyCouldNotResolveHost;
    }

    if (step.target.host.len > socks_host_len_max) return error.ProxyHostTooLong;
    if (step.target.host.len == 0) return error.ProxyHostTooLong;
    atyp.* = 0x03;
    out[0] = @intCast(step.target.host.len);
    @memcpy(out[1..][0..step.target.host.len], step.target.host);
    return out[0 .. 1 + step.target.host.len];
}

/// Reads `step.target.host` as an IPv4 address for a SOCKS4 request.
fn resolveIp4(host: []const u8) Failure![4]u8 {
    const address = std.Io.net.IpAddress.parse(host, 0) catch return error.ProxyAddressUnsupported;
    return switch (address) {
        .ip4 => |a| a.bytes,
        // SOCKS4 has no IPv6 address field at all. curl answers the same
        // pair by refusing the request.
        .ip6 => error.ProxyAddressUnsupported,
    };
}

/// Reads exactly `out.len` bytes, or reports why it could not.
///
/// The length is a constant of the protocol at every call, so this puts no
/// bound of its own on top: the caller's array is the bound.
fn readExact(r: *std.Io.Reader, out: []u8) Failure!void {
    r.readSliceAll(out) catch |err| switch (err) {
        error.EndOfStream => return error.ProxyClosed,
        error.ReadFailed => return error.ProxyReadFailed,
    };
}

const testing = std.testing;

test "a CONNECT status line is read, and anything that is not one is named" {
    try testing.expectEqual(@as(u16, 200), try parseStatusLine("HTTP/1.1 200 Connection established"));
    try testing.expectEqual(@as(u16, 200), try parseStatusLine("HTTP/1.0 200 OK"));
    // A status line with no reason phrase is legal, RFC 9112 section 4.
    try testing.expectEqual(@as(u16, 204), try parseStatusLine("HTTP/1.1 204"));
    try testing.expectEqual(@as(u16, 407), try parseStatusLine("HTTP/1.1 407 Proxy Authentication Required"));

    // A peer that answers something that is not HTTP is not a proxy, and
    // that is not the same thing as a proxy that refused.
    try testing.expectError(error.ProxyReplyMalformed, parseStatusLine("garbage"));
    try testing.expectError(error.ProxyReplyMalformed, parseStatusLine("HTTP/1.1"));
    try testing.expectError(error.ProxyReplyMalformed, parseStatusLine("HTTP/1.1 2xx OK"));
    try testing.expectError(error.ProxyReplyMalformed, parseStatusLine("HTTP/1.1 20 OK"));
    try testing.expectError(error.ProxyReplyMalformed, parseStatusLine("HTTP/1.1 2000 OK"));
    try testing.expectError(error.ProxyReplyMalformed, parseStatusLine(""));
}

test "an authority writes the brackets an IPv6 origin needs" {
    var buffer: [128]u8 = undefined;
    {
        var w: std.Io.Writer = .fixed(&buffer);
        try writeAuthority(&w, .{ .host = "example.com", .port = 443 });
        try testing.expectEqualStrings("example.com:443", w.buffered());
    }
    {
        // Without the brackets a proxy reads `::1:443` and finds no port.
        var w: std.Io.Writer = .fixed(&buffer);
        try writeAuthority(&w, .{ .host = "::1", .port = 8443 });
        try testing.expectEqualStrings("[::1]:8443", w.buffered());
    }
}

test "a socks5 address travels as an address, and a name only where the kind says so" {
    var out: [socks_host_len_max + 1]u8 = undefined;
    var atyp: u8 = 0;

    // An IPv4 literal is an address whichever kind asked.
    const v4 = try socks5Address(&out, .{
        .kind = .socks5,
        .target = .{ .host = "127.0.0.9", .port = 80 },
    }, &atyp);
    try testing.expectEqual(@as(u8, 0x01), atyp);
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 9 }, v4);

    const v6 = try socks5Address(&out, .{
        .kind = .socks5h,
        .target = .{ .host = "::1", .port = 80 },
    }, &atyp);
    try testing.expectEqual(@as(u8, 0x04), atyp);
    try testing.expectEqual(@as(usize, 16), v6.len);
    try testing.expectEqual(@as(u8, 1), v6[15]);

    // `socks5h` sends the name, which is the whole point of the kind.
    const named = try socks5Address(&out, .{
        .kind = .socks5h,
        .target = .{ .host = "example.com", .port = 80 },
    }, &atyp);
    try testing.expectEqual(@as(u8, 0x03), atyp);
    try testing.expectEqual(@as(u8, "example.com".len), named[0]);
    try testing.expectEqualStrings("example.com", named[1..]);

    // **`socks5` never sends the name.** Turning a `socks5` run into a
    // `socks5h` one would tell the proxy every host the user visits, which
    // is the thing the user chose `socks5` to stop.
    try testing.expectError(error.ProxyCouldNotResolveHost, socks5Address(&out, .{
        .kind = .socks5,
        .target = .{ .host = "example.com", .port = 80 },
    }, &atyp));
}

test "a socks5 name longer than the length field is refused, not truncated" {
    var out: [socks_host_len_max + 1]u8 = undefined;
    var atyp: u8 = 0;
    var host: [socks_host_len_max + 1]u8 = @splat('a');

    // A truncated host is a different host, and it is one a proxy would
    // dial.
    try testing.expectError(error.ProxyHostTooLong, socks5Address(&out, .{
        .kind = .socks5h,
        .target = .{ .host = &host, .port = 80 },
    }, &atyp));

    // One byte under the bound still fits.
    const fitting = try socks5Address(&out, .{
        .kind = .socks5h,
        .target = .{ .host = host[0..socks_host_len_max], .port = 80 },
    }, &atyp);
    try testing.expectEqual(@as(usize, socks_host_len_max + 1), fitting.len);
}

test "socks4 carries an IPv4 address alone" {
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 9 }, &(try resolveIp4("127.0.0.9")));
    // SOCKS4 has no field for either of these.
    try testing.expectError(error.ProxyAddressUnsupported, resolveIp4("::1"));
    try testing.expectError(error.ProxyAddressUnsupported, resolveIp4("example.com"));
}

test "every failure name carries a sentence, and no sentence carries a credential" {
    // A user reads the sentence and not the name. A name with no sentence
    // leaves a proxy fault with nothing to act on.
    const names = [_]Failure{
        error.ProxyWriteFailed,        error.ProxyReadFailed,
        error.ProxyClosed,             error.ProxyReplyTooLarge,
        error.ProxyReplyMalformed,     error.ProxyTunnelRefused,
        error.ProxyAuthRefused,        error.ProxyAuthUnsupported,
        error.ProxyAddressUnsupported, error.ProxyHostTooLong,
        error.ProxyCredentialTooLong,  error.ProxyCouldNotResolveHost,
        error.ProxySpokeEarly,         error.ProxyCanceled,
    };
    for (names) |name| {
        var runner: Runner = .{
            .step = .{ .connect = .{ .target = .{ .host = "example.com", .port = 443 } } },
            .failure = name,
        };
        const message = runner.cause().?;
        try testing.expect(message.len != 0);
        // Lower case and no full stop, the shape every other cause in this
        // project has.
        try testing.expect(!std.ascii.isUpper(message[0]));
        try testing.expect(message[message.len - 1] != '.');
    }

    // A runner that has not failed reports nothing at all.
    var fresh: Runner = .{
        .step = .{ .connect = .{ .target = .{ .host = "example.com", .port = 443 } } },
    };
    try testing.expectEqual(@as(?[]const u8, null), fresh.cause());
}

test "the bounds a proxy reply is read under are the ones this file names" {
    // A proxy is untrusted input, so each of these is a bound and not a
    // guess. They are named here so a change to one is a change a reader
    // sees.
    try testing.expectEqual(@as(usize, 4 * 1024), connect_line_len_max);
    try testing.expectEqual(@as(usize, 64), connect_lines_max);
    try testing.expectEqual(@as(usize, 16 * 1024), connect_head_len_max);
    // The two SOCKS bounds are the protocol's own: each length field is one
    // byte wide.
    try testing.expectEqual(@as(usize, 255), socks_host_len_max);
    try testing.expectEqual(@as(usize, 255), socks_credential_len_max);
}
