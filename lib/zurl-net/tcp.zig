//! Opens a TCP stream to a host and a port, with a bound on how long the
//! attempt may take.
//!
//! This file owns the connect and nothing else. It sets up no TLS, which is
//! `Connection.zig`. It frames no protocol. It keeps no connection pool. It
//! never touches a `zurl_core.Diagnostics`, because `errors.zig` is the one
//! place that turns a fault of this package into a fault a user reads.
//!
//! The bound is applied here, around the connect, and not through
//! `std.Io.net.IpAddress.ConnectOptions.timeout`. That field reaches one
//! socket of a lookup that may return many, and the layer under
//! `std.http.Client` panics on a value that is not `.none`. A race against a
//! deadline covers the whole call: the lookup, every address it returned,
//! and the socket connect itself.
//!
//! This file also turns Nagle's algorithm off on every stream it opens.
//! See `setNoDelay` for the measurement that made that necessary.

const std = @import("std");
const builtin = @import("builtin");

/// The check over `/etc/resolv.conf` that runs before a name lookup. See
/// that file: two values there drive the resolver of `std` out of its own
/// buffers, and one of them needs the name to decide.
const resolv = @import("resolv.zig");

/// Every fault a dial can report.
///
/// Each name says what a user must do about it. A name that resolves is
/// apart from a name that connects, and a bound that was reached is apart
/// from a bound this build cannot keep. `errors.zig` maps each one onto
/// `zurl_core.Error`.
pub const DialError = error{
    /// The host name has no address. Every lookup fault lands here,
    /// because the answer is the same for all of them: the name did not
    /// resolve.
    CouldNotResolveHost,
    /// The peer did not accept a connection. Refused, unreachable, and out
    /// of local resources all land here, because curl reports one code,
    /// `CURLE_COULDNT_CONNECT`, for all of them.
    CouldNotConnect,
    /// The connect went over `DialOptions.timeout`, or the operating
    /// system gave up on it first.
    OperationTimedOut,
    /// The caller asked for a timeout, but this build has no concurrency,
    /// so nothing can watch the deadline while the connect runs. The dial
    /// refuses instead of dropping the bound.
    ///
    /// A dropped bound is worse than a named refusal: a caller that asked
    /// for a 15 second cap would wait for the operating system instead,
    /// and nothing would say so. The caller decides what to do next. It
    /// can retry with `.none` and report the degradation, which is what
    /// `zurl.Client` does today.
    ConnectTimeoutUnsupported,
    /// Something outside the dial stopped it.
    Canceled,
    /// The operating system returned something `std.Io` does not name.
    Unexpected,
    /// `/etc/resolv.conf` holds a `search` line longer than the resolver
    /// copies it into. See `resolv.zig`.
    ///
    /// **This is a refusal and not a recovery.** The lookup would write
    /// past a 255 octet array, and the build a user runs makes that write
    /// instead of a panic. Nothing about the name can avoid it, so the
    /// dial stops here and the sentence names the file.
    ResolverSearchListTooLong,
    /// `/etc/resolv.conf` holds `options attempts:0`, and the resolver
    /// divides by that value to get the wait of one attempt.
    ResolverAttemptsZero,
    /// The host name and one search domain of `/etc/resolv.conf` do not
    /// fit together in the array the resolver joins them in.
    ///
    /// A shorter name resolves on the same machine, and so does this name
    /// with a trailing dot, which asks for the root and skips the search
    /// list.
    ResolverSearchNameTooLong,
};

/// Every fault turning Nagle's algorithm off can report.
///
/// None of these stops a transfer. See `setNoDelay` for why, and for what
/// happens to the fault instead.
///
/// The set is `std.posix.SetSockOptError` and one name of this file's own.
/// The `std` set names the errno values a `setsockopt` can give back. The
/// extra name covers a build that has no setter to call at all.
pub const NoDelayError = std.posix.SetSockOptError || error{
    /// This build has no way to set the option. Zig 0.16 gives no
    /// `setsockopt` for Windows, and none for WASI, so a build for either
    /// one leaves Nagle's algorithm on and says so here.
    SocketOptionUnsupported,
};

pub const DialOptions = struct {
    /// A cap on how long the connect may take, the name lookup included.
    /// `.none` waits for as long as the operating system does.
    timeout: std.Io.Timeout = .none,

    /// Where `dial` records a `TCP_NODELAY` that did not take, for a
    /// caller that wants to report it.
    ///
    /// Null throws the fault away, which is right for a caller with
    /// nowhere to put it, such as a test. A caller that reports faults
    /// points this at a slot of its own, and `dial` writes the fault
    /// there. `dial` never clears the slot, so the caller must, or a
    /// fault of one connect reads as a fault of the next.
    ///
    /// The dial succeeds either way. See `setNoDelay`.
    no_delay_error: ?*?NoDelayError = null,

    /// Whether to turn Nagle's algorithm off on the stream. This is
    /// `--no-tcp-nodelay`, which gives false.
    ///
    /// True is the default, because it is what curl does: curl sets
    /// `TCP_NODELAY` on every connection unless the user says otherwise.
    /// A false value leaves the option alone, so the operating system
    /// keeps Nagle's algorithm on, and `no_delay_error` stays null:
    /// nothing was tried, so nothing can fail.
    no_delay: bool = true,
};

/// Where a dial points: an address the url already spelled out, or a name
/// a resolver must look up.
///
/// **A url may name the peer as an address, and an address is not a
/// name.** `std.Io.net.HostName.validate` accepts letters, digits, `-`,
/// and `.`, so it refuses every colon. `zurl_core.url.parse` gives an IPv6
/// host with no brackets, so `http://[::1]:8080/` arrived here as `::1`
/// and stopped at that check. A user read `zurl: (3) InvalidUrl: ::1` for
/// a url that curl 8.21.0 fetches.
///
/// The two members open with two different calls of `std`, and `dial` is
/// the one place that picks between them.
pub const Host = union(enum) {
    /// A name to look up.
    name: std.Io.net.HostName,
    /// An address the url holds. The port inside it means nothing here.
    /// `dial` puts its own port on before it connects.
    address: std.Io.net.IpAddress,

    pub const InitError = error{
        /// The text is neither an address nor a name.
        InvalidHost,
        /// The text is a good host name and is longer than
        /// `max_name_len`.
        ///
        /// **This is a resolution fault and not a url fault.** Every
        /// character of such a name is one a host name allows, so the url
        /// that carries it is well formed. The name only has no encoding
        /// a resolver can send, so no resolver can answer it. A caller
        /// that called this a bad url would send a user to look at text
        /// they wrote correctly.
        ///
        /// curl answers the same name with `CURLE_COULDNT_RESOLVE_HOST`,
        /// exit 6. Measured against curl 8.21.0 with names of 253, 254,
        /// 255, and 300 characters, on `http` and on `ftp`.
        HostNameTooLong,
    };

    /// The longest name this build looks up, counted in the written form
    /// with one trailing dot removed.
    ///
    /// RFC 1035 section 2.3.4 holds an encoded name to 255 octets. The
    /// encoding writes a length octet before each label and a zero octet
    /// at the end, so a written name with no trailing dot reaches that
    /// bound at 253 characters. `std.Io.net.HostName.max_len` says 255,
    /// which counts the written form as if it were the encoding, and is
    /// two too many.
    ///
    /// **Those two characters are a memory fault, not a rounding error.**
    /// The resolver in `std.Io.Threaded` copies the name into a buffer of
    /// `std.Io.net.HostName.max_len` octets and then writes one more
    /// octet for a dot. A name of 255 characters fills the buffer, and
    /// the dot lands one past its end. A name of 254 characters reaches a
    /// failed assertion deeper in the same resolver. Neither fault stops
    /// a build that carries no safety checks: the write happens.
    ///
    /// A server picks the name, because a `Location` header does. So the
    /// bound belongs here, above `std`, and not in the caller.
    ///
    /// Measured against Zig 0.16.0: 253 characters and fewer resolve, 254
    /// and 255 both fault.
    pub const max_name_len = 253;

    /// The written name with one trailing dot removed.
    ///
    /// A trailing dot asks for the root and adds nothing to the encoding,
    /// so it does not count against `max_name_len`. `std` strips one dot
    /// the same way and refuses a second, which leaves the two in step.
    fn withoutRootDot(text: []const u8) []const u8 {
        if (std.mem.endsWith(u8, text, ".")) return text[0 .. text.len - 1];
        return text;
    }

    /// Reads `text` as an address, and as a name when it is not one.
    ///
    /// The address comes first because a name check accepts `127.0.0.1`
    /// as well, and text that already is an address must never reach a
    /// resolver.
    ///
    /// `text` carries no brackets. `zurl_core.url.parse` takes them off an
    /// IPv6 host, and `std.Io.net.IpAddress.parse` reads the bare form.
    ///
    /// **An IPv4 mapped IPv6 address, such as `::ffff:127.0.0.1`, is an
    /// address here and is dialed as one.** It opens an AF_INET6 socket
    /// that reaches the IPv4 address inside it, so the text names the
    /// IPv4 peer by a second spelling.
    ///
    /// That is what curl does, measured against curl 8.21.0 on this
    /// machine: `curl http://[::ffff:127.0.0.1]:18799/` reports
    /// `Established connection to [::ffff:127.0.0.1]` and reaches a
    /// listener bound to `127.0.0.1` alone. So zurl reads it the same
    /// way, and reading it more strictly than curl would refuse a url
    /// curl fetches.
    ///
    /// **A future allow list or deny list on the address must read the
    /// mapped form first.** There is none in this package today, so there
    /// is nothing to get past: no loopback check, no private range check.
    /// A check added later that read only the family would see `.ip6` for
    /// an address that behaves as IPv4, and the mapped spelling would
    /// walk around it.
    ///
    /// An IPv6 address with a scope, such as `fe80::1%eno1`, is neither an
    /// address nor a name here, so it gets `InvalidHost`. Only
    /// `std.Io.net.IpAddress.resolve` reads a scope, and it needs an
    /// `std.Io` to turn the interface name into an index, which this
    /// function does not take.
    /// A name longer than `max_name_len` gets `HostNameTooLong`, which is
    /// a different fault. See that constant: `std` accepts two characters
    /// more than the encoding holds, and its resolver writes past a
    /// buffer for them.
    pub fn init(text: []const u8) InitError!Host {
        if (std.Io.net.IpAddress.parse(text, 0)) |address| {
            return .{ .address = address };
        } else |_| {}
        if (withoutRootDot(text).len > max_name_len) return error.HostNameTooLong;
        return .{ .name = std.Io.net.HostName.init(text) catch return error.InvalidHost };
    }
};

/// Every fault reading the address a stream reached can report.
///
/// Neither name is a fault of the connection. A stream that is open
/// carries bytes whatever this call answers, so a caller decides for
/// itself whether it can carry on without the address.
pub const PeerAddressError = error{
    /// This build has no way to ask the socket. Zig 0.16 gives
    /// `std.posix.getpeername` no body for Windows, and WASI has no such
    /// call at all.
    PeerAddressUnsupported,
    /// The operating system would not name the peer, or named it in an
    /// address family this build does not read.
    PeerAddressUnavailable,
};

/// The numeric address `stream` is connected to, port included.
///
/// **This is what a second dial to the same machine must use, and a host
/// name is not.** A name is text a resolver answers, and a resolver may
/// answer it twice with two different addresses. Between the first dial
/// and the second, an FTP session runs a login, a directory walk, and a
/// `PASV` or `EPSV` exchange, which is many round trips, and a record with
/// a short life may be asked again in that time. So a client that dialed
/// the name a second time would let whoever answers the lookup pick where
/// the second connection goes. The same gap opens with no attacker at all:
/// a host behind round robin records, or one with both an `A` record and
/// an `AAAA` record, puts the two connections on two machines.
///
/// The answer comes from the operating system and not from what this
/// process meant to dial, so it is the address the socket really reached.
///
/// curl reuses the address the same way. Its manual page for
/// `--ftp-skip-pasv-ip`, which is on by default since 7.74.0, says curl
/// "reuses the same IP address it already uses for the control
/// connection".
///
/// **The port belongs to the connection this reads, and a caller that
/// dials a second port must set its own.** `std.Io.net.IpAddress.setPort`
/// is that call. See `zurl_ftp.Fetcher.dataTarget`.
pub fn peerAddress(stream: std.Io.net.Stream) PeerAddressError!std.Io.net.IpAddress {
    // Zig 0.16 gives `std.posix.getpeername` no body for Windows, and WASI
    // has no sockets to ask. The check is comptime, so neither build
    // analyses the call below.
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.PeerAddressUnsupported;
    }
    var storage: std.Io.Threaded.PosixAddress = undefined;
    var length: std.posix.socklen_t = @sizeOf(std.Io.Threaded.PosixAddress);
    std.posix.getpeername(stream.socket.handle, &storage.any, &length) catch
        return error.PeerAddressUnavailable;
    // **The switch names the two families this build dials and nothing
    // else.** `std.Io.Threaded.addressFromPosix` answers a third family
    // with a loopback address, which would send a caller of this function
    // to a machine nobody named.
    return switch (storage.any.family) {
        std.posix.AF.INET => .{ .ip4 = .{
            .port = std.mem.bigToNative(u16, storage.in.port),
            .bytes = @bitCast(storage.in.addr),
        } },
        std.posix.AF.INET6 => .{ .ip6 = .{
            .port = std.mem.bigToNative(u16, storage.in6.port),
            .bytes = storage.in6.addr,
            .flow = storage.in6.flowinfo,
            .interface = .{ .index = storage.in6.scope_id },
        } },
        else => error.PeerAddressUnavailable,
    };
}

/// What a connect to one resolved address, or the lookup that found it,
/// can report.
const ConnectError = std.Io.net.HostName.ConnectError;

/// What a name lookup alone can report.
const LookupError = std.Io.net.HostName.LookupError;

/// Everything the raced task can report: the connect, and the check over
/// `/etc/resolv.conf` that runs before the lookup.
const TaskError = ConnectError || resolv.GuardError;

/// Opens a stream to `host` on `port`, and stops waiting after
/// `options.timeout`.
///
/// Turns Nagle's algorithm off on the stream before it hands it back. See
/// `setNoDelay`.
///
/// The returned stream belongs to the caller, which must close it.
pub fn dial(
    io: std.Io,
    host: Host,
    port: u16,
    options: DialOptions,
) DialError!std.Io.net.Stream {
    const stream = switch (options.timeout) {
        // No bound was asked for, so no second task is needed. This is
        // also the path a build with no concurrency always takes, which
        // is why such a build can still dial.
        .none => connectTask(host, io, port) catch |err| return mapConnectError(err),
        else => try bounded(io, options.timeout, connectTask, .{ host, io, port }),
    };

    // The option goes on here, and not inside `connectTask`, because a
    // connect that lost the race against the deadline is closed and never
    // returned. Only a stream the caller keeps needs the option.
    //
    // `--no-tcp-nodelay` skips the call. It does not set the option to
    // zero: a socket starts with Nagle's algorithm on, so leaving the
    // option alone is what the flag asks for, and a `setsockopt` that
    // could fail is one the flag has no need of.
    if (options.no_delay) setNoDelay(stream, options.no_delay_error);
    return stream;
}

/// Turns Nagle's algorithm off on `stream`, and records a fault in
/// `slot` instead of reporting one.
///
/// **Why this is necessary.** Nagle's algorithm holds a small write back
/// until the peer acknowledges the write before it. A TLS 1.3 client ends
/// its handshake with two small writes: the Finished record, and then the
/// first record of the request. Nagle holds the second one until the peer
/// acknowledges the first, and Linux delays that acknowledgement by up to
/// 40 milliseconds. Every request pays that stall, whatever the peer is
/// and however fast the code above is.
///
/// zurl measured the stall against `1.1.1.1`, a peer about 10
/// milliseconds away. `strace -T` showed the read after the request
/// blocked for 83.8 milliseconds, where the round trip alone accounts for
/// about 10. curl makes the same two small writes and does not stall,
/// because it sets this option on every connection. zurl now does the
/// same.
///
/// **Why a fault here does not stop the transfer.** The option is a
/// latency improvement and never a correctness requirement. A connection
/// with Nagle's algorithm still on carries every byte correctly, only
/// more slowly. curl 8.21.0 takes the same view: it reports
/// `Could not set TCP_NODELAY` at info level, which a user reads only
/// under `-v`, and it continues. A refused transfer would be worse than
/// the stall it replaces.
///
/// The fault is not thrown away, though. It goes into `slot`, and
/// `zurl_net.errors.noDelayMessage` turns it into the sentence a caller
/// reports. `zurl.Client` puts that sentence in `zurl_core.Diagnostics`,
/// where it waits for a verbose mode to print it. Nothing is printed on
/// an ordinary run, which is what curl does.
fn setNoDelay(stream: std.Io.net.Stream, slot: ?*?NoDelayError) void {
    apply(stream) catch |err| {
        if (slot) |target| target.* = err;
    };
}

/// The `setsockopt` call itself, apart from the recording, so a test can
/// read its result.
fn apply(stream: std.Io.net.Stream) NoDelayError!void {
    // Zig 0.16 gives `std.posix.setsockopt` no body for Windows, and WASI
    // has no socket options at all. The check is comptime, so neither
    // build analyses the call below.
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.SocketOptionUnsupported;
    }
    const on: c_int = 1;
    return std.posix.setsockopt(
        stream.socket.handle,
        std.posix.IPPROTO.TCP,
        std.posix.TCP.NODELAY,
        std.mem.asBytes(&on),
    );
}

/// The connect, as its own task, so `bounded` can race it.
///
/// An address opens with `std.Io.net.IpAddress.connect`, which asks no
/// resolver at all. A name goes through `connectName`, which checks
/// `/etc/resolv.conf` first, then looks the name up once for each address
/// family, and then tries every address it got.
fn connectTask(host: Host, io: std.Io, port: u16) TaskError!std.Io.net.Stream {
    switch (host) {
        .name => |name| {
            // The check is inside the task, so the deadline of the caller
            // covers the file read as well as the lookup and the connect.
            try resolv.guard(io, name.bytes);
            return connectName(io, name, port);
        },
        .address => |address| {
            // The port in the parsed address is 0. The port to dial is the
            // one the url named, and it arrives as a parameter.
            var target = address;
            target.setPort(port);
            return target.connect(io, .{ .mode = .stream });
        },
    }
}

/// How many addresses of one family a dial tries at once.
///
/// The two families together reach `2 * addresses_per_family`, which is
/// the size of the result queue below, so no connect can ever wait for
/// room in it. It is also the bound on how many sockets one hostile
/// answer can open, and it is the bound
/// `std.Io.net.HostName.connectMany` keeps with its 32 entry lookup
/// queue.
const addresses_per_family = 16;

/// The queue one lookup fills. `std.Io.net.HostName.lookup` promises not
/// to block on a queue of 16 or more, and `std` gives it 32.
const lookup_queue_len = 32;

/// Opens a stream to `name` on `port`, and reports the first address that
/// answers.
///
/// **This exists instead of `std.Io.net.HostName.connect` because that
/// call sends the `A` query and the `AAAA` query on one socket, and the
/// resolver behind it can then let a later datagram overwrite an answer
/// it already accepted.** The receive buffer of `std.Io.Threaded.lookupDns`
/// is handed out as the part of one array that no accepted answer holds
/// yet, but a datagram the resolver skips still takes room in that array
/// and does not move the index. So after one skipped datagram, the array
/// the next receive writes into overlaps the answer the resolver already
/// accepted, and that answer is not read until every query is answered.
/// The bytes finally read can be bytes that arrived after the source
/// address and the query id were checked.
///
/// The second datagram is never checked at all, so the attacker pays for
/// the source port alone and not for the port and the query id together.
/// That is about 2^16 times cheaper than a spoofed answer has to be. For
/// `http`, and for every plaintext protocol in this repository, the
/// result is that zurl connects to the attacker's address. For `https`
/// the certificate check still stands, so it ends at a failed handshake.
///
/// **One query for each socket closes it.** The resolver leaves its send
/// loop as soon as no query is outstanding, so with a single query the
/// accepted answer is read before any further datagram can be received,
/// and no later datagram can reach the array it sits in. So this splits
/// the lookup by address family: each family asks its own question on its
/// own socket, with its own random source port and its own query id.
/// `std.Io.net.HostName.LookupOptions.family` is what carries that, and
/// `std.Io.net.HostName.connect` has no way to pass it.
///
/// The two families run together, so the lookup still costs one round
/// trip and not two. Every address of both families is then dialed at
/// once, and the first stream that answers wins, which is what
/// `connectMany` does. Every other stream is closed.
fn connectName(
    io: std.Io,
    name: std.Io.net.HostName,
    port: u16,
) ConnectError!std.Io.net.Stream {
    var results_buffer: [2 * addresses_per_family]ConnectError!std.Io.net.Stream = undefined;
    var results: std.Io.Queue(ConnectError!std.Io.net.Stream) = .init(&results_buffer);

    var both = io.async(connectBothFamilies, .{ io, name, port, &results });
    defer {
        both.cancel(io) catch {};
        // Every stream that arrived after the winner is closed here. A
        // loser left open is a socket the peer holds until this process
        // ends.
        while (results.getOneUncancelable(io)) |loser| {
            if (loser) |stream| stream.close(io) else |_| {}
        } else |err| switch (err) {
            error.Closed => {},
        }
    }

    var connect_error: ?ConnectError = null;
    while (results.getOne(io)) |result| {
        if (result) |stream| {
            return stream;
        } else |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => |e| connect_error = e,
        }
    } else |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Closed => {
            // No address answered. A lookup that failed says more than a
            // connect that failed, so it is reported first.
            try both.await(io);
            return connect_error orelse error.UnknownHostName;
        },
    }
}

/// Looks `name` up in both address families at once and dials every
/// address either one returns.
///
/// Closes `results` before it returns, which is what tells `connectName`
/// that no further stream is coming.
fn connectBothFamilies(
    io: std.Io,
    name: std.Io.net.HostName,
    port: u16,
    results: *std.Io.Queue(ConnectError!std.Io.net.Stream),
) LookupError!void {
    defer results.close(io);

    var ip6 = io.async(connectFamily, .{ io, name, port, std.Io.net.IpAddress.Family.ip6, results });
    var ip4 = io.async(connectFamily, .{ io, name, port, std.Io.net.IpAddress.Family.ip4, results });
    const ip6_result = ip6.await(io);
    const ip4_result = ip4.await(io);

    // One family is enough. A host with an `A` record and no `AAAA`
    // record is ordinary, and the empty half of it is not a fault.
    ip6_result catch |ip6_error| {
        ip4_result catch |ip4_error| return worseLookupError(ip6_error, ip4_error);
    };
}

/// Looks `name` up in one family and dials every address it answered
/// with.
///
/// The family is what makes this safe. See `connectName`.
fn connectFamily(
    io: std.Io,
    name: std.Io.net.HostName,
    port: u16,
    family: std.Io.net.IpAddress.Family,
    results: *std.Io.Queue(ConnectError!std.Io.net.Stream),
) LookupError!void {
    var addresses: [addresses_per_family]std.Io.net.IpAddress = undefined;
    const found = try lookupFamily(io, name, port, family, &addresses);

    var group: std.Io.Group = .init;
    defer group.cancel(io);
    for (addresses[0..found]) |address| {
        group.async(io, enqueueConnection, .{ io, address, results });
    }
    return group.await(io);
}

/// Puts every address of `name` in `family` into `out`, and reports how
/// many it wrote.
///
/// **The family goes to the resolver and is not a filter over the
/// answer.** `std.Io.net.HostName.LookupOptions.family` makes the
/// resolver send one query and leave its receive loop as soon as that one
/// query is answered. A filter here would leave both queries on one
/// socket, which is the defect `connectName` describes.
///
/// An answer with more addresses than `out` holds is read to the end and
/// the extra addresses are dropped. The lookup must be drained whatever
/// happens, because it is another task and it waits for room.
fn lookupFamily(
    io: std.Io,
    name: std.Io.net.HostName,
    port: u16,
    family: std.Io.net.IpAddress.Family,
    out: []std.Io.net.IpAddress,
) LookupError!usize {
    var lookup_buffer: [lookup_queue_len]std.Io.net.HostName.LookupResult = undefined;
    var queue: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&lookup_buffer);

    // The canonical name is left out on purpose. Nothing above this file
    // reads it, and asking for it makes the resolver expand a `CNAME`
    // record of the answer into a buffer of the caller.
    var lookup = io.async(std.Io.net.HostName.lookup, .{ name, io, &queue, .{
        .port = port,
        .family = family,
    } });
    defer lookup.cancel(io) catch {};

    var found: usize = 0;
    while (queue.getOne(io)) |result| switch (result) {
        .address => |address| {
            if (found == out.len) continue;
            out[found] = address;
            found += 1;
        },
        .canonical_name => continue,
    } else |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Closed => {},
    }

    // The lookup reports why it found nothing. With an address in hand
    // there is nothing left to report, and the `defer` above still waits
    // for the task.
    if (found == 0) try lookup.await(io);
    return found;
}

/// Dials one address and puts the result, good or bad, into `results`.
///
/// A stream this cannot hand over is closed here. A stream left behind is
/// a socket the peer holds open for nothing.
fn enqueueConnection(
    io: std.Io,
    address: std.Io.net.IpAddress,
    results: *std.Io.Queue(ConnectError!std.Io.net.Stream),
) std.Io.Cancelable!void {
    const result: ConnectError!std.Io.net.Stream = address.connect(io, .{ .mode = .stream }) catch |err| switch (err) {
        error.Canceled => |e| return e,
        // Every other fault of a connect belongs to the caller, which
        // reports one of them when no address answered at all.
        else => |e| e,
    };
    errdefer if (result) |stream| stream.close(io) else |_| {};

    results.putOne(io, result) catch |err| switch (err) {
        error.Canceled => |e| return e,
        // `connectName` closes the queue only after both families have
        // returned, and both wait for this task. The branch stays because
        // a stream dropped here would be a leaked socket, and it is not
        // an `unreachable`, which the build a user runs removes.
        error.Closed => if (result) |stream| stream.close(io) else |_| {},
    };
}

/// The more useful of two lookup faults.
///
/// `UnknownHostName` and `NoAddressReturned` are what the empty half of a
/// single stack host answers with, so a fault with any other name says
/// more about what went wrong and is reported instead. A cancel outranks
/// both, because it means something outside the dial stopped it.
fn worseLookupError(first: LookupError, second: LookupError) LookupError {
    if (first == error.Canceled or second == error.Canceled) return error.Canceled;
    if (!namesNoAddress(first)) return first;
    if (!namesNoAddress(second)) return second;
    return first;
}

/// Whether `err` only says that this family holds no address for the
/// name.
fn namesNoAddress(err: LookupError) bool {
    return err == error.UnknownHostName or err == error.NoAddressReturned;
}

/// The deadline, as its own task.
fn deadlineTask(io: std.Io, timeout: std.Io.Timeout) std.Io.Cancelable!void {
    return timeout.sleep(io);
}

/// The two tasks `bounded` races. `std.Io.Select` reports whichever
/// finishes first.
const Attempt = union(enum) {
    stream: TaskError!std.Io.net.Stream,
    deadline: std.Io.Cancelable!void,
};

/// Runs `task` against `timeout` and reports whichever finished first.
///
/// `task` is a parameter, and not the connect itself, so a test can race a
/// task that never finishes. That test needs no peer and no network, which
/// is the only way this file's deadline behaviour can be pinned offline.
///
/// A stream that arrived after the caller stopped waiting is closed, not
/// leaked. `std.Io.Select.cancel` waits for every task, so a connect that
/// completed at the deadline is still reported to `end`.
fn bounded(
    io: std.Io,
    timeout: std.Io.Timeout,
    comptime task: anytype,
    args: std.meta.ArgsTuple(@TypeOf(task)),
) DialError!std.Io.net.Stream {
    var results: [2]Attempt = undefined;
    var race: std.Io.Select(Attempt) = .init(io, &results);

    // A build with no concurrency cannot stop a connect that hangs. Refuse
    // the dial. A silently dropped bound is worse than a named refusal.
    race.concurrent(.stream, task, args) catch |err| switch (err) {
        error.ConcurrencyUnavailable => return error.ConnectTimeoutUnsupported,
    };
    race.concurrent(.deadline, deadlineTask, .{ io, timeout }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            end(io, &race);
            return error.ConnectTimeoutUnsupported;
        },
    };

    const first = race.await() catch |err| switch (err) {
        error.Canceled => {
            end(io, &race);
            return error.Canceled;
        },
    };

    switch (first) {
        .stream => |result| {
            end(io, &race);
            return result catch |err| mapConnectError(err);
        },
        .deadline => |slept| {
            end(io, &race);
            slept catch |err| switch (err) {
                error.Canceled => return error.Canceled,
            };
            return error.OperationTimedOut;
        },
    }
}

/// Ends `race` and closes a stream that arrived after the caller stopped
/// waiting for one.
fn end(io: std.Io, race: *std.Io.Select(Attempt)) void {
    while (race.cancel()) |result| switch (result) {
        .stream => |connected| if (connected) |stream| stream.close(io) else |_| {},
        .deadline => {},
    };
}

/// Maps a connect fault, or a fault of the check over
/// `/etc/resolv.conf`, onto `DialError`.
///
/// The switch names every member. There is no `else`, so a new name in
/// `std` is a compile error here, where somebody reads it, and never a
/// silent fall into `CouldNotConnect`.
fn mapConnectError(err: TaskError) DialError {
    return switch (err) {
        // The resolver of this build cannot use `/etc/resolv.conf` for
        // this name without leaving a buffer. Each one keeps its own
        // name, because each one names a different line of the file.
        // See `resolv.zig`.
        error.ResolverSearchListTooLong => error.ResolverSearchListTooLong,
        error.ResolverAttemptsZero => error.ResolverAttemptsZero,
        error.ResolverSearchNameTooLong => error.ResolverSearchNameTooLong,

        // The name did not resolve. Every one of these is a lookup fault,
        // and a user answers all of them the same way: check the name and
        // check the resolver.
        error.UnknownHostName,
        error.ResolvConfParseFailed,
        error.InvalidDnsARecord,
        error.InvalidDnsAAAARecord,
        error.InvalidDnsCnameRecord,
        error.NameServerFailure,
        error.NoAddressReturned,
        error.DetectingNetworkConfigurationFailed,
        => error.CouldNotResolveHost,

        // The operating system gave up on the connect before the caller's
        // own bound did. It is still a timeout, so it keeps that name.
        error.Timeout => error.OperationTimedOut,

        error.Canceled => error.Canceled,
        error.Unexpected => error.Unexpected,

        // The name resolved and the connection did not happen. curl
        // reports one code for all of these, so zurl does too.
        error.AddressUnavailable,
        error.AddressInUse,
        error.AddressFamilyUnsupported,
        error.SystemResources,
        error.ConnectionPending,
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.HostUnreachable,
        error.NetworkUnreachable,
        error.OptionUnsupported,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        error.ProtocolUnsupportedBySystem,
        error.ProtocolUnsupportedByAddressFamily,
        error.SocketModeUnsupported,
        error.AccessDenied,
        error.WouldBlock,
        error.NetworkDown,
        => error.CouldNotConnect,
    };
}

const testing = std.testing;

/// A loopback address. `Host.init` reads it as an address, so a dial to
/// this text asks no resolver and never reaches the network.
const loopback = "127.0.0.1";

/// The IPv6 loopback address. Every test that uses it says why it needs
/// the second family.
const loopback6 = "::1";

/// `loopback` as a dial target.
fn loopbackHost() Host {
    // The text is a constant in this file, so text that does not read as
    // a host is a programmer error and never a runtime fault.
    return Host.init(loopback) catch unreachable;
}

/// A `std.Io.Timeout` of `ms` milliseconds on the awake clock.
fn millis(ms: i64) std.Io.Timeout {
    return .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
}

/// A threaded `Io` whose `concurrent` always reports
/// `error.ConcurrencyUnavailable`, on any build.
///
/// A build compiled with no concurrency at all used to be the only way to
/// see that error out of an ordinary `Io.concurrent` call. `concurrent_limit
/// = .nothing` forces the same answer out of an ordinary threaded `Io`, so
/// a test that pins what happens when the bound cannot be raced no longer
/// needs a build that no longer exists.
///
/// The caller must `deinit` the result.
fn noConcurrencyIo() std.Io.Threaded {
    return .init(testing.allocator, .{ .concurrent_limit = .nothing });
}

test "a dial with no bound reaches a listening port" {
    var address = try std.Io.net.IpAddress.parse(loopback, 0);
    var server = try address.listen(testing.io, .{ .reuse_address = true });
    defer server.deinit(testing.io);

    const stream = try dial(testing.io, loopbackHost(), server.socket.address.ip4.port, .{});
    stream.close(testing.io);
}

test "a dial to a closed port reports the connection, not the name" {
    // **The socket stays bound, and nothing listens on it.** An operating
    // system refuses a connect to a bound socket with no listener behind
    // it, and it lets no other socket take that port meanwhile. A test
    // that reads the number and closes the socket leaves the port free,
    // and another test binary of a parallel suite can take it between the
    // two steps. This dial would then reach a stranger and wait for an
    // answer that never comes. `zurl-http/test_server.closedPort` holds a
    // port the same way, for the tests of the layers above this one.
    var address = try std.Io.net.IpAddress.parse(loopback, 0);
    const held = try address.bind(testing.io, .{ .mode = .stream });
    defer held.close(testing.io);
    const port = held.address.getPort();

    try testing.expectError(
        error.CouldNotConnect,
        dial(testing.io, loopbackHost(), port, .{}),
    );
}

test "a bound that is not reached leaves an ordinary dial alone" {
    var address = try std.Io.net.IpAddress.parse(loopback, 0);
    var server = try address.listen(testing.io, .{ .reuse_address = true });
    defer server.deinit(testing.io);

    const stream = dial(
        testing.io,
        loopbackHost(),
        server.socket.address.ip4.port,
        .{ .timeout = millis(30_000) },
    ) catch |err| switch (err) {
        // A build with no concurrency cannot race at all; the test below
        // covers that. A threaded build that lands here could not get a
        // concurrent task for an ordinary dial, which is a regression and
        // not an expected limit.
        error.ConnectTimeoutUnsupported => {
            if (builtin.single_threaded) return error.SkipZigTest;
            return err;
        },
        else => |e| return e,
    };
    stream.close(testing.io);
}

test "a bound that is reached reports a timeout, not a refused connection" {
    if (builtin.single_threaded) return error.SkipZigTest;

    // The task never finishes, so the deadline must be what ends the race.
    // A real connect cannot stand in here: a connect to loopback finishes
    // at once, and a connect to anything else would reach the network.
    try testing.expectError(
        error.OperationTimedOut,
        bounded(testing.io, millis(20), stallTask, .{testing.io}),
    );
}

test "a stream that arrives after the deadline goes through the close path" {
    if (builtin.single_threaded) return error.SkipZigTest;

    // The task connects to a live listener and then finishes after the
    // deadline, so the race ends while a real socket is still in flight.
    // `end` is the only code that can close that socket, and this drives
    // it with a live stream in hand.
    //
    // This proves the branch runs and that the race still reports the
    // timeout. It does not observe the descriptor itself, because a leak
    // can only be seen from the peer, and a read that waits for a peer
    // that never closes would hang the suite rather than fail it.
    var address = try std.Io.net.IpAddress.parse(loopback, 0);
    var server = try address.listen(testing.io, .{ .reuse_address = true });
    defer server.deinit(testing.io);
    const port = server.socket.address.ip4.port;

    try testing.expectError(
        error.OperationTimedOut,
        bounded(testing.io, millis(20), lateConnectTask, .{ testing.io, port }),
    );

    const stream = try dial(testing.io, loopbackHost(), port, .{});
    stream.close(testing.io);
}

test "a bound this build cannot keep is refused, not dropped" {
    var no_concurrency = noConcurrencyIo();
    defer no_concurrency.deinit();
    const io = no_concurrency.io();

    // Port 9 is discard, and nothing listens on it here, so a dial that
    // did run would fail as a refused connection. The refusal must come
    // first, because the bound could not be raced at all.
    try testing.expectError(
        error.ConnectTimeoutUnsupported,
        dial(io, loopbackHost(), 9, .{ .timeout = millis(30_000) }),
    );
}

test "a build with no concurrency still dials when no bound was asked for" {
    // The refusal above must be about the bound, and never about the
    // dial. A caller that asks for no bound gets a working dial in every
    // build.
    var address = try std.Io.net.IpAddress.parse(loopback, 0);
    var server = try address.listen(testing.io, .{ .reuse_address = true });
    defer server.deinit(testing.io);

    const stream = try dial(testing.io, loopbackHost(), server.socket.address.ip4.port, .{});
    stream.close(testing.io);
}

test "every connect fault keeps a name a user can act on" {
    // The map has no `else`, so this cannot drift without a compile
    // error. The test says the three groups out loud: a name that did not
    // resolve, a peer that did not answer, and a bound the system reached
    // on its own.
    try testing.expectEqual(DialError.CouldNotResolveHost, mapConnectError(error.UnknownHostName));
    try testing.expectEqual(DialError.CouldNotResolveHost, mapConnectError(error.NameServerFailure));
    try testing.expectEqual(DialError.CouldNotConnect, mapConnectError(error.ConnectionRefused));
    try testing.expectEqual(DialError.CouldNotConnect, mapConnectError(error.NetworkUnreachable));
    try testing.expectEqual(DialError.OperationTimedOut, mapConnectError(error.Timeout));
    try testing.expectEqual(DialError.Canceled, mapConnectError(error.Canceled));
    try testing.expectEqual(DialError.Unexpected, mapConnectError(error.Unexpected));
}

test "Host.init reads an address as an address and a name as a name" {
    // An address must never reach a resolver, and a name must always
    // reach one. A name check alone accepts `127.0.0.1`, so the order of
    // the two reads is what keeps them apart.
    try testing.expect(try Host.init("127.0.0.1") == .address);
    try testing.expect(try Host.init("::1") == .address);
    try testing.expect(try Host.init("2606:4700:4700::1111") == .address);
    try testing.expect(try Host.init("::ffff:1.1.1.1") == .address);
    try testing.expect(try Host.init("example.com") == .name);
    // A label of digits is a name and not an address. Reading it as an
    // address would send the dial to a peer nobody named.
    try testing.expect(try Host.init("1234") == .name);
}

test "Host.init refuses text that is neither an address nor a name" {
    // The url layer already refuses a control byte and a space, so these
    // are the shapes that get past it. A scope needs a lookup of the
    // interface name, which `Host.init` cannot do, so it is refused here
    // rather than dropped.
    //
    // **Each of these is a bad url and not a name that did not resolve.**
    // `InvalidHost` is what carries that meaning, and the bound on the
    // length carries the other one. See `Host.InitError.HostNameTooLong`.
    const refused = [_][]const u8{ "", "::1%eno1", "fe80::1%25eno1", "host_name.com", "-lead" };
    for (refused) |text| {
        try testing.expectError(error.InvalidHost, Host.init(text));
    }
}

test "a dial reaches a listening port over IPv6" {
    // The IPv6 half of the first test in this file. `::1` is loopback, so
    // this reaches no network, and it is the one shape a host name check
    // can never accept: it holds colons.
    var address = try std.Io.net.IpAddress.parse(loopback6, 0);
    var server = address.listen(testing.io, .{ .reuse_address = true }) catch |err| switch (err) {
        // A machine with the IPv6 stack turned off cannot bind `::1` at
        // all. That is the machine and not this code, so the test stands
        // aside rather than report a fault it did not find.
        error.AddressFamilyUnsupported, error.AddressUnavailable => return error.SkipZigTest,
        else => |e| return e,
    };
    defer server.deinit(testing.io);

    const stream = try dial(testing.io, try Host.init(loopback6), server.socket.address.getPort(), .{});
    stream.close(testing.io);
}

/// Whether this build can set a socket option at all. See `apply`.
const can_set_socket_options = builtin.os.tag != .windows and builtin.os.tag != .wasi;

/// Reads `TCP_NODELAY` back off `stream`.
///
/// This is the only way a test can see the option. `setNoDelay` reports
/// nothing when the option takes, which is the whole point of it, so the
/// socket itself is what a test must ask.
fn readNoDelay(stream: std.Io.net.Stream) !bool {
    var value: c_int = -1;
    var len: std.posix.socklen_t = @sizeOf(c_int);
    const rc = std.posix.system.getsockopt(
        stream.socket.handle,
        std.posix.IPPROTO.TCP,
        std.posix.TCP.NODELAY,
        @ptrCast(&value),
        &len,
    );
    if (std.posix.errno(rc) != .SUCCESS) return error.TestGetSockOptFailed;
    return value != 0;
}

test "a dial turns Nagle's algorithm off on the stream it hands back" {
    // This is the defect the option closes. Nagle held the first request
    // record back until the peer acknowledged the TLS Finished record
    // before it, and Linux delays that acknowledgement by up to 40
    // milliseconds. Measured against `1.1.1.1`: the read after the
    // request blocked for 89.9 ms without the option and 38.1 ms with it,
    // over eight runs each.
    //
    // The test reaches no network. It dials a listener on loopback and
    // then asks the socket what the option holds.
    if (!can_set_socket_options) return error.SkipZigTest;

    var address = try std.Io.net.IpAddress.parse(loopback, 0);
    var server = try address.listen(testing.io, .{ .reuse_address = true });
    defer server.deinit(testing.io);

    const stream = try dial(testing.io, loopbackHost(), server.socket.address.ip4.port, .{});
    defer stream.close(testing.io);

    try testing.expect(try readNoDelay(stream));
}

test "a dial asked for no_delay false leaves Nagle's algorithm on" {
    // **`--no-tcp-nodelay` is real behaviour, not a no-op.** zurl turns
    // Nagle's algorithm off on every connection, so the flag has something
    // to turn back on. The socket itself is what answers here, the same
    // way the test above asks it about the default.
    //
    // The slot stays empty too: nothing was tried, so nothing can fail,
    // and a sentence about a `TCP_NODELAY` that did not take would be
    // wrong for a dial that never asked for one.
    if (!can_set_socket_options) return error.SkipZigTest;

    var address = try std.Io.net.IpAddress.parse(loopback, 0);
    var server = try address.listen(testing.io, .{ .reuse_address = true });
    defer server.deinit(testing.io);

    var recorded: ?NoDelayError = null;
    const stream = try dial(testing.io, loopbackHost(), server.socket.address.ip4.port, .{
        .no_delay = false,
        .no_delay_error = &recorded,
    });
    defer stream.close(testing.io);

    try testing.expect(!try readNoDelay(stream));
    try testing.expectEqual(@as(?NoDelayError, null), recorded);
}

test "a dial that sets the option records no fault" {
    // The slot is for a fault and never for a report of success. A dial
    // that leaves something in it on an ordinary run would put a sentence
    // in front of a user for a connection that is not slow at all.
    if (!can_set_socket_options) return error.SkipZigTest;

    var address = try std.Io.net.IpAddress.parse(loopback, 0);
    var server = try address.listen(testing.io, .{ .reuse_address = true });
    defer server.deinit(testing.io);

    var recorded: ?NoDelayError = null;
    const stream = try dial(testing.io, loopbackHost(), server.socket.address.ip4.port, .{
        .no_delay_error = &recorded,
    });
    defer stream.close(testing.io);

    try testing.expectEqual(@as(?NoDelayError, null), recorded);
}

test "an option that does not take is recorded and does not fail the caller" {
    // `TCP_NODELAY` belongs to TCP, so a UDP socket refuses it. That is
    // the shape of every "this transport has no such option" fault, and
    // it needs no network: the socket is bound to loopback and nothing is
    // ever sent on it.
    //
    // The rule this pins is the one curl follows. curl reports
    // `Could not set TCP_NODELAY` at info level and carries on, because a
    // connection with Nagle's algorithm still on carries every byte
    // correctly and is only slower.
    if (!can_set_socket_options) return error.SkipZigTest;

    var address = try std.Io.net.IpAddress.parse(loopback, 0);
    const socket = try address.bind(testing.io, .{ .mode = .dgram });
    defer socket.close(testing.io);
    const stream: std.Io.net.Stream = .{ .socket = socket };

    var recorded: ?NoDelayError = null;
    // No error comes back. `setNoDelay` returns void on purpose.
    setNoDelay(stream, &recorded);

    try testing.expect(recorded != null);
}

test "a caller that wants no record still dials" {
    // `no_delay_error` defaults to null, and a null slot must be safe.
    // Every test above this file's own, and every caller that does not
    // report, passes one.
    if (!can_set_socket_options) return error.SkipZigTest;

    var address = try std.Io.net.IpAddress.parse(loopback, 0);
    const socket = try address.bind(testing.io, .{ .mode = .dgram });
    defer socket.close(testing.io);

    setNoDelay(.{ .socket = socket }, null);
}

test "a lookup fault and a connect fault do not share one name" {
    // curl exits 6 for one and 7 for the other, and a user reads those
    // two numbers differently. A single name for both would send a script
    // down the wrong branch.
    try testing.expect(mapConnectError(error.UnknownHostName) != mapConnectError(error.ConnectionRefused));
}

/// A task that never finishes on its own, with the signature `bounded`
/// races. It sleeps for an hour, so only a cancel ends it.
fn stallTask(io: std.Io) TaskError!std.Io.net.Stream {
    const hour: std.Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(3600), .clock = .awake } };
    try hour.sleep(io);
    return error.ConnectionRefused;
}

/// A task that opens a real stream and then finishes after any short
/// deadline, so the race ends with a connected socket still in flight.
///
/// The cancel is swallowed on purpose, which no production task does. It
/// makes the task hand back a live stream after the race has already
/// ended, and that is the one case `end` exists for.
fn lateConnectTask(io: std.Io, port: u16) TaskError!std.Io.net.Stream {
    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    const stream = try address.connect(io, .{ .mode = .stream });
    const pause: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(200), .clock = .awake } };
    pause.sleep(io) catch {};
    return stream;
}

test "a name longer than the encoding holds is refused before a resolver sees it" {
    // **`std` accepts two characters more than an encoded name holds, and
    // its resolver writes past a buffer for them.** See
    // `Host.max_name_len`. The fault is not a panic in a shipped build,
    // where the safety checks are gone, so the bound has to sit here.
    //
    // A server picks the name. `zurl -L` with an answer of
    // `Location: http://<255 characters>/` reached the write, measured
    // against a build with the checks on.
    var name: [255]u8 = undefined;
    for (&name, 0..) |*byte, i| byte.* = if ((i + 1) % 64 == 0) '.' else 'a';

    // 253 is the longest an encoded name holds, so it resolves.
    _ = try Host.init(name[0..253]);

    // 254 reaches a failed assertion in the resolver, and 255 writes one
    // octet past the end of its buffer. Both stop here instead.
    //
    // **The name they get is not `InvalidHost`.** Every character of
    // these two is one a host name allows, so the url is well formed and
    // only the lookup is impossible. curl exits 6 for them and 3 for a
    // bad url. See `Host.InitError.HostNameTooLong`.
    try testing.expectError(error.HostNameTooLong, Host.init(name[0..254]));
    try testing.expectError(error.HostNameTooLong, Host.init(name[0..255]));
}

test "a name over the bound and a name that does not read are two different faults" {
    // The two exit codes are 6 and 3, and a script reads them
    // differently. One error name for both would make the pair
    // impossible to keep apart above this file.
    var name: [300]u8 = undefined;
    for (&name, 0..) |*byte, i| byte.* = if ((i + 1) % 64 == 0) '.' else 'a';

    try testing.expectError(error.HostNameTooLong, Host.init(name[0..300]));
    // A scope makes the text neither an address nor a name, and it is far
    // below the bound, so nothing about its length can answer for it.
    try testing.expectError(error.InvalidHost, Host.init("fe80::1%eno1"));
}

test "a trailing dot does not count against the name bound" {
    // A trailing dot asks for the root. The encoding writes the root as
    // the zero octet it already ends with, so the dot adds nothing and
    // must not cost a character. `std` strips one the same way.
    var name: [255]u8 = undefined;
    for (&name, 0..) |*byte, i| byte.* = if ((i + 1) % 64 == 0) '.' else 'a';
    name[253] = '.';

    // 253 characters and the dot: the encoding still holds it.
    _ = try Host.init(name[0..254]);

    // 254 characters and a dot is one too many, dot or not.
    name[254] = '.';
    try testing.expectError(error.HostNameTooLong, Host.init(name[0..255]));
}

/// Whether this build can ask a socket who it reached. See `peerAddress`.
const can_read_peer_address = builtin.os.tag != .windows and builtin.os.tag != .wasi;

test "a dial names the numeric address it reached, and not the text it was given" {
    // **The address is what a second connection to the same machine must
    // dial.** A name would be looked up again, and a resolver is free to
    // answer the second lookup with a different address. See
    // `peerAddress`.
    if (!can_read_peer_address) return error.SkipZigTest;

    var address = try std.Io.net.IpAddress.parse(loopback, 0);
    var server = try address.listen(testing.io, .{ .reuse_address = true });
    defer server.deinit(testing.io);
    const port = server.socket.address.ip4.port;

    const stream = try dial(testing.io, loopbackHost(), port, .{});
    defer stream.close(testing.io);

    const peer = try peerAddress(stream);
    try testing.expect(peer == .ip4);
    try testing.expectEqual([4]u8{ 127, 0, 0, 1 }, peer.ip4.bytes);
    // The port is the one this connection reached, so a caller that dials
    // a second port must set its own.
    try testing.expectEqual(port, peer.ip4.port);
}

test "the address a dial reached opens a second connection to the same machine" {
    // This is the whole use of `peerAddress`: the second dial takes the
    // numeric address of the first and the port it wants, and asks no
    // resolver at all.
    if (!can_read_peer_address) return error.SkipZigTest;

    var address = try std.Io.net.IpAddress.parse(loopback, 0);
    var server = try address.listen(testing.io, .{ .reuse_address = true });
    defer server.deinit(testing.io);
    const port = server.socket.address.ip4.port;

    const first = try dial(testing.io, loopbackHost(), port, .{});
    defer first.close(testing.io);

    var reached = try peerAddress(first);
    // A second port on the same machine, which is the shape an FTP data
    // connection has. Here the two ports are the same, because one
    // listener is all this test needs.
    reached.setPort(port);
    const second = try dial(testing.io, .{ .address = reached }, port, .{});
    defer second.close(testing.io);

    try testing.expectEqual(reached.ip4.bytes, (try peerAddress(second)).ip4.bytes);
}

test "a socket that reached nobody names no peer" {
    // A bound socket with no connection behind it is what `getpeername`
    // refuses, and the refusal must keep its own name. A caller that read
    // a loopback address here would dial its own machine.
    if (!can_read_peer_address) return error.SkipZigTest;

    var address = try std.Io.net.IpAddress.parse(loopback, 0);
    const socket = try address.bind(testing.io, .{ .mode = .stream });
    defer socket.close(testing.io);

    try testing.expectError(
        error.PeerAddressUnavailable,
        peerAddress(.{ .socket = socket }),
    );
}

test "a dial over IPv6 names an IPv6 peer" {
    // The second family, so the conversion of both is driven. `::1` is
    // loopback, so this reaches no network.
    if (!can_read_peer_address) return error.SkipZigTest;

    var address = try std.Io.net.IpAddress.parse(loopback6, 0);
    var server = address.listen(testing.io, .{ .reuse_address = true }) catch |err| switch (err) {
        // A machine with the IPv6 stack turned off cannot bind `::1`.
        error.AddressFamilyUnsupported, error.AddressUnavailable => return error.SkipZigTest,
        else => |e| return e,
    };
    defer server.deinit(testing.io);
    const port = server.socket.address.getPort();

    const stream = try dial(testing.io, try Host.init(loopback6), port, .{});
    defer stream.close(testing.io);

    const peer = try peerAddress(stream);
    try testing.expect(peer == .ip6);
    try testing.expectEqual(
        [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        peer.ip6.bytes,
    );
    try testing.expectEqual(port, peer.ip6.port);
}

/// `localhost` as a name to look up.
///
/// RFC 6761 section 6.3.3 makes every resolver answer this name with the
/// loopback addresses, and `/etc/hosts` holds it as well, so a lookup of
/// it reaches no network and no nameserver.
fn localhostName() std.Io.net.HostName {
    // The text is a constant in this file, so text that does not read as
    // a host name is a programmer error and never a runtime fault.
    return std.Io.net.HostName.init("localhost") catch unreachable;
}

test "a dial by name reaches a listening port" {
    // **The one test that drives the whole name path.** Every other dial
    // of this file passes an address, which asks no resolver at all, so
    // without this test `connectName`, `connectBothFamilies`,
    // `connectFamily`, `lookupFamily`, and the check over
    // `/etc/resolv.conf` would all be unread by the suite.
    //
    // The listener is bound to the IPv4 loopback address alone, and
    // `localhost` answers with both families, so the IPv6 half of the
    // dial fails and the IPv4 half wins. That is the losing-address path
    // as well as the winning one.
    var address = try std.Io.net.IpAddress.parse(loopback, 0);
    var server = try address.listen(testing.io, .{ .reuse_address = true });
    defer server.deinit(testing.io);

    const stream = try dial(testing.io, .{ .name = localhostName() }, server.socket.address.ip4.port, .{});
    stream.close(testing.io);
}

test "a lookup asks for one family, so one socket carries one query" {
    // **This is the fix for the answer a later datagram can overwrite.**
    // The resolver of `std` puts the `A` query and the `AAAA` query on
    // one socket and reads into one array, and it does not leave its
    // receive loop while either query is outstanding. A datagram it skips
    // still takes room in that array without moving the index, so the
    // next receive is given an array that overlaps an answer already
    // accepted, and that answer is parsed only after the loop ends.
    //
    // A lookup that asks for one family sends one query, so the loop ends
    // as soon as that query is answered and no later datagram can reach
    // the array. See `connectName`.
    //
    // The family here reaches the resolver and is not a filter over the
    // answer. That cannot be seen from outside, so what this test pins is
    // the observable half: a lookup for one family answers with addresses
    // of that family alone.
    var addresses: [addresses_per_family]std.Io.net.IpAddress = undefined;

    const ip4_len = try lookupFamily(testing.io, localhostName(), 80, .ip4, &addresses);
    try testing.expect(ip4_len != 0);
    for (addresses[0..ip4_len]) |address| try testing.expect(address == .ip4);

    // A machine with the IPv6 stack turned off still answers this lookup,
    // because the answer comes from `/etc/hosts` or from RFC 6761 and not
    // from a socket. A machine whose `/etc/hosts` names no IPv6 loopback
    // is not a fault of this code, so an empty answer stands aside.
    const ip6_len = lookupFamily(testing.io, localhostName(), 80, .ip6, &addresses) catch 0;
    for (addresses[0..ip6_len]) |address| try testing.expect(address == .ip6);
}

test "one family with no address does not fail a dial the other family can make" {
    // A host with an `A` record and no `AAAA` record is ordinary. The
    // empty half of it answers `UnknownHostName` or `NoAddressReturned`,
    // and neither one may end a dial the other half can complete.
    try testing.expectEqual(
        LookupError.NameServerFailure,
        worseLookupError(error.UnknownHostName, error.NameServerFailure),
    );
    try testing.expectEqual(
        LookupError.NameServerFailure,
        worseLookupError(error.NameServerFailure, error.NoAddressReturned),
    );
    // Two halves that both found nothing say only that, and the name is
    // kept.
    try testing.expectEqual(
        LookupError.UnknownHostName,
        worseLookupError(error.UnknownHostName, error.NoAddressReturned),
    );
    // A cancel outranks both, because something outside the dial stopped
    // it and no name of the resolver describes that.
    try testing.expectEqual(
        LookupError.Canceled,
        worseLookupError(error.NameServerFailure, error.Canceled),
    );
    try testing.expectEqual(
        LookupError.Canceled,
        worseLookupError(error.Canceled, error.NameServerFailure),
    );
}

test "a resolver configuration the lookup cannot use is a resolve fault" {
    // The three refusals of `resolv.zig` reach a user as exit 6, the same
    // as any other name that did not resolve, because that is what a
    // script must act on. The sentence is what says the file is the
    // reason, and `errors.zig` holds it.
    try testing.expectEqual(
        DialError.ResolverSearchListTooLong,
        mapConnectError(error.ResolverSearchListTooLong),
    );
    try testing.expectEqual(
        DialError.ResolverAttemptsZero,
        mapConnectError(error.ResolverAttemptsZero),
    );
    try testing.expectEqual(
        DialError.ResolverSearchNameTooLong,
        mapConnectError(error.ResolverSearchNameTooLong),
    );
}

test "an IPv4 mapped IPv6 address is read as an address, the way curl reads it" {
    // `::ffff:127.0.0.1` names the IPv4 loopback address in IPv6 form. It
    // is dialed on an AF_INET6 socket that reaches the IPv4 address
    // inside it.
    //
    // **Measured against curl 8.21.0 before this was pinned.**
    // `curl http://[::ffff:127.0.0.1]:18799/` against a listener bound to
    // `127.0.0.1` alone reported
    // `Established connection to [::ffff:127.0.0.1]` and fetched the
    // page. So curl dials the mapped form as an address, and zurl reads
    // it the same way. Reading it more strictly would refuse a url curl
    // fetches.
    //
    // There is no allow list and no deny list on an address anywhere in
    // this package, so there is nothing here for the second spelling to
    // get past. See `Host.init`: a check added later must read the mapped
    // form first.
    const host = try Host.init("::ffff:127.0.0.1");
    try testing.expect(host == .address);
    try testing.expect(host.address == .ip6);

    // The last four octets are the IPv4 address, behind the `ffff`
    // marker. This is the shape a later check would have to read.
    const bytes = host.address.ip6.bytes;
    try testing.expectEqual([2]u8{ 0xff, 0xff }, bytes[10..12].*);
    try testing.expectEqual([4]u8{ 127, 0, 0, 1 }, bytes[12..16].*);
}

test "the bound counts characters and does not refuse an address" {
    // An address never reaches a resolver, so the bound must not read it.
    // The longest address text is far below the bound, and this pins that
    // the address arm still comes first.
    const host = try Host.init("255.255.255.255");
    try testing.expect(host == .address);
}
