//! What a proxy url says, and which hosts reach no proxy at all.
//!
//! This file does no I/O. It reads the text of `-x`, of `--socks5`, and of
//! the `http_proxy`, `https_proxy`, `all_proxy`, and `no_proxy` environment
//! variables, and it answers two questions: which proxy a transfer uses,
//! and whether a given host is excluded from it. The dial belongs to
//! `zurl-net`, and the request bytes belong to `zurl-http`.
//!
//! **A proxy is a second destination beside the origin, and the two are
//! never the same peer.** Everything about keeping them apart starts here:
//! `Spec` carries the proxy host, the proxy port, and the proxy credential,
//! and no field of it can hold an origin credential. `zurl-http/engine.zig`
//! carries the mirror rule for the header names.
//!
//! Every rule below is measured against curl 8.21.0. The measurements are
//! written beside each rule, because a `no_proxy` entry that matches one
//! host too many sends traffic to a proxy the user excluded.

const std = @import("std");

const url = @import("url.zig");

/// Which protocol a proxy speaks, which the scheme of the proxy url
/// selects.
///
/// **`socks5` and `socks5h` are two different rules and not two spellings
/// of one.** `socks5` resolves the origin host on this machine and sends
/// the address to the proxy. `socks5h` sends the name and lets the proxy
/// resolve it. The second is what a user behind a proxy usually wants: the
/// name may resolve only on the far side, and a lookup on this machine
/// tells a local resolver every host the user visits. `socks4` and `socks4a`
/// divide the same way.
pub const Kind = enum {
    /// An HTTP proxy. A cleartext origin goes through it as one request in
    /// the absolute form. An origin that speaks TLS goes through a
    /// `CONNECT` tunnel.
    http,
    /// The same as `http`, and the hop to the proxy itself speaks TLS.
    /// `--proxy-insecure`, `--proxy-cacert`, and `--proxy-capath` control
    /// that handshake, and they control no other one.
    https,
    /// SOCKS4. The origin host is resolved on this machine.
    socks4,
    /// SOCKS4a. The proxy resolves the origin host.
    socks4a,
    /// SOCKS5. The origin host is resolved on this machine.
    socks5,
    /// SOCKS5, and the proxy resolves the origin host. This is `socks5h`
    /// and `--socks5-hostname`.
    socks5h,

    /// Whether this kind resolves the origin host on this machine.
    ///
    /// True for `socks4` and `socks5`, which send an address to the proxy.
    /// False for every other kind: an HTTP proxy reads the host name out of
    /// the request or the `CONNECT` line, and `socks4a` and `socks5h` carry
    /// the name in the handshake.
    pub fn resolvesLocally(k: Kind) bool {
        return switch (k) {
            .socks4, .socks5 => true,
            .http, .https, .socks4a, .socks5h => false,
        };
    }

    /// Whether this kind puts TLS on the hop to the proxy itself.
    ///
    /// **Read this for the proxy handshake and never for the origin one.**
    /// A `CONNECT` tunnel through a cleartext proxy still carries a TLS
    /// origin inside it, and that inner handshake is verified against the
    /// origin. See `zurl-http/h1.zig`, which keeps the two setups in two
    /// functions for that reason.
    pub fn isSecure(k: Kind) bool {
        return k == .https;
    }

    /// Whether this kind speaks SOCKS rather than HTTP.
    pub fn isSocks(k: Kind) bool {
        return switch (k) {
            .socks4, .socks4a, .socks5, .socks5h => true,
            .http, .https => false,
        };
    }

    /// The port a proxy url of this kind uses when it names none.
    ///
    /// Measured against curl 8.21.0, by reading the address it dialed:
    /// `-x http://127.0.0.1` dials port 80, `-x https://127.0.0.1` dials
    /// 443, and each of `socks4`, `socks4a`, `socks5`, and `socks5h` dials
    /// 1080. curl's manual still names 1080 as the default for every kind,
    /// and the program does not do that, so the measurement is what is
    /// written here.
    pub fn defaultPort(k: Kind) u16 {
        return switch (k) {
            .http => 80,
            .https => 443,
            .socks4, .socks4a, .socks5, .socks5h => 1080,
        };
    }

    /// The scheme text of this kind, for a message to a user.
    pub fn schemeName(k: Kind) []const u8 {
        return switch (k) {
            .http => "http",
            .https => "https",
            .socks4 => "socks4",
            .socks4a => "socks4a",
            .socks5 => "socks5",
            .socks5h => "socks5h",
        };
    }
};

/// One proxy, as a proxy url names it.
///
/// Every text field borrows from the url text, so the caller must keep that
/// text alive for as long as it keeps the `Spec`.
///
/// **`user` and `password` are the proxy credential and nothing else.**
/// They authenticate to the proxy: they reach a `Proxy-Authorization`
/// header or a SOCKS5 username and password exchange. They never reach the
/// origin server. The origin credential comes from the origin url, from
/// `-u`, or from a netrc entry, and it never reaches the proxy.
pub const Spec = struct {
    kind: Kind,
    /// The proxy host, with no brackets around an IPv6 literal, the same
    /// way `zurl_core.url.parse` reports an origin host.
    host: []const u8,
    port: u16,
    /// The user name in the proxy url, still percent-encoded, or empty when
    /// the url named none. `zurl_core.url.parse` leaves an origin userinfo
    /// encoded for the same reason: a password holding `%40` is not the
    /// password holding `@` until somebody decodes it.
    user: []const u8 = "",
    /// The password in the proxy url, still percent-encoded, or empty when
    /// the url named none.
    password: []const u8 = "",

    /// Whether this spec carries a credential of any kind.
    pub fn hasCredential(s: Spec) bool {
        return s.user.len != 0 or s.password.len != 0;
    }
};

/// Every fault reading a proxy url can report.
pub const ParseError = error{
    /// The text is not a usable proxy url: it names no host, it names a
    /// port that is not a number or is zero, or it holds a byte that may
    /// not travel.
    InvalidProxy,
    /// The scheme is a scheme, and this build does not speak it. curl
    /// answers the same text with `Unsupported proxy scheme`.
    UnsupportedProxyScheme,
};

/// The largest proxy url this reads, in bytes.
///
/// A proxy url comes from a command line or from the environment, and both
/// are untrusted input. The host alone is bounded by
/// `std.Io.net.HostName.max_len`, and a credential can be long, so this is
/// far above any real value and still a bound.
pub const url_len_max: usize = 8 * 1024;

/// Reads one proxy url.
///
/// The grammar is `[scheme://][user[:password]@]host[:port][/anything]`.
/// A url with no scheme is an HTTP proxy, which is what curl does: `-x
/// 127.0.0.1:3128` and `-x http://127.0.0.1:3128` dial the same peer.
/// Measured against curl 8.21.0, which sent the same absolute-form request
/// through both.
///
/// A path after the authority is read and dropped. A proxy has no path, and
/// curl accepts one and ignores it.
///
/// An IPv6 host must carry brackets, `http://[::1]:3128`, because a bare
/// IPv6 literal and a `host:port` pair cannot be told apart. The brackets
/// come off the answer, so `Spec.host` reads the way an origin host does.
///
/// The scheme is matched without regard to case, per RFC 3986.
pub fn parse(text: []const u8) ParseError!Spec {
    return (try parseParts(text)).spec;
}

/// A parsed proxy url, and whether the text named a port of its own.
///
/// `parseAs` needs the second answer. A url with no port took the default
/// of the scheme in the text, and a flag that names another kind has to
/// take the default of that kind instead.
const Parts = struct { spec: Spec, explicit_port: bool };

fn parseParts(text: []const u8) ParseError!Parts {
    if (text.len == 0 or text.len > url_len_max) return error.InvalidProxy;
    // A proxy url reaches a request line, a `CONNECT` line, and a SOCKS
    // handshake. A control byte in any of the three writes bytes the user
    // never asked for.
    if (url.hasControlByte(text)) return error.InvalidProxy;

    var rest = text;
    var kind: Kind = .http;
    if (std.mem.indexOf(u8, rest, "://")) |at| {
        kind = try parseScheme(rest[0..at]);
        rest = rest[at + 3 ..];
    }

    // The authority ends at the first `/`, `?`, or `#`. Everything after it
    // is a path a proxy has no use for.
    const authority_end = std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len;
    var authority = rest[0..authority_end];
    if (authority.len == 0) return error.InvalidProxy;

    var user: []const u8 = "";
    var password: []const u8 = "";
    // The LAST `@` divides the userinfo from the host, because a password
    // may hold an `@` and a host may not. This is the rule RFC 3986 gives
    // and the rule `zurl_core.url.parse` follows for an origin url.
    if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| {
        const userinfo = authority[0..at];
        authority = authority[at + 1 ..];
        // The FIRST `:` divides the user name from the password, because a
        // password may hold one and a user name may not. This is the same
        // split `-u` uses.
        if (std.mem.indexOfScalar(u8, userinfo, ':')) |colon| {
            user = userinfo[0..colon];
            password = userinfo[colon + 1 ..];
        } else {
            user = userinfo;
        }
    }

    const host_port = try splitHostPort(authority);
    const port = host_port.port orelse kind.defaultPort();
    if (host_port.host.len == 0) return error.InvalidProxy;
    if (host_port.host.len > std.Io.net.HostName.max_len) return error.InvalidProxy;

    return .{
        .spec = .{
            .kind = kind,
            .host = host_port.host,
            .port = port,
            .user = user,
            .password = password,
        },
        .explicit_port = host_port.port != null,
    };
}

/// Reads one proxy url and forces the kind, whatever scheme the text names.
///
/// This is `--socks4`, `--socks4a`, `--socks5`, and `--socks5-hostname`.
/// Each of those names both the proxy and the protocol, so the text after
/// the flag is an authority and not a url with a scheme of its own.
/// Measured against curl 8.21.0: `--socks5 127.0.0.1:1080` speaks SOCKS5 to
/// that address.
///
/// A scheme in the text is still read, so a `socks5://` prefix is accepted
/// and dropped. The flag wins, because the flag is the more specific
/// statement.
pub fn parseAs(text: []const u8, kind: Kind) ParseError!Spec {
    const parts = try parseParts(text);
    var spec = parts.spec;
    // The port came from the scheme's own default when the text named none,
    // so it has to be taken again from the kind the flag chose.
    if (!parts.explicit_port) spec.port = kind.defaultPort();
    spec.kind = kind;
    return spec;
}

fn parseScheme(scheme: []const u8) ParseError!Kind {
    if (std.ascii.eqlIgnoreCase(scheme, "http")) return .http;
    if (std.ascii.eqlIgnoreCase(scheme, "https")) return .https;
    if (std.ascii.eqlIgnoreCase(scheme, "socks4")) return .socks4;
    if (std.ascii.eqlIgnoreCase(scheme, "socks4a")) return .socks4a;
    if (std.ascii.eqlIgnoreCase(scheme, "socks5")) return .socks5;
    if (std.ascii.eqlIgnoreCase(scheme, "socks5h")) return .socks5h;
    return error.UnsupportedProxyScheme;
}

const HostPort = struct { host: []const u8, port: ?u16 };

/// Divides an authority into a host and an optional port.
///
/// A bracketed IPv6 literal keeps everything inside the brackets and drops
/// the brackets. Anything after the closing bracket must be a `:port` and
/// nothing else.
fn splitHostPort(authority: []const u8) ParseError!HostPort {
    if (authority[0] == '[') {
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse return error.InvalidProxy;
        const host = authority[1..close];
        const tail = authority[close + 1 ..];
        if (tail.len == 0) return .{ .host = host, .port = null };
        if (tail[0] != ':') return error.InvalidProxy;
        return .{ .host = host, .port = try parsePort(tail[1..]) };
    }
    // A bare authority holds at most one colon. Two would be an IPv6
    // literal with no brackets, which cannot be told from a host and a
    // port, so it is refused rather than guessed at.
    if (std.mem.indexOfScalar(u8, authority, ':')) |colon| {
        const host = authority[0..colon];
        const tail = authority[colon + 1 ..];
        if (std.mem.indexOfScalar(u8, tail, ':') != null) return error.InvalidProxy;
        return .{ .host = host, .port = try parsePort(tail) };
    }
    return .{ .host = authority, .port = null };
}

fn parsePort(text: []const u8) ParseError!u16 {
    if (text.len == 0) return error.InvalidProxy;
    const port = std.fmt.parseInt(u16, text, 10) catch return error.InvalidProxy;
    // Port zero names no listener. A dial to it is a fault, not a default.
    if (port == 0) return error.InvalidProxy;
    return port;
}

/// Whether `host` reaches no proxy, given a `no_proxy` list.
///
/// **Every rule below is measured against curl 8.21.0.** The test was one
/// invocation for each row, with `http_proxy` pointing at a port that
/// refuses, and the answer read off the address curl dialed: the proxy port
/// means the entry did not match, and the origin address means it did.
///
/// - The list is divided on commas. Spaces around an entry are dropped, so
///   `foo.com, example.com` matches `example.com`.
/// - An empty entry matches nothing. A list of one comma excludes no host.
/// - A single `*` matches every host.
/// - A leading dot is dropped, and `.example.com` then matches
///   `example.com` itself as well as `a.example.com`.
/// - An entry matches a host that is equal to it, and a host that ends with
///   a dot and then the entry. So `example.com` matches `a.b.example.com`,
///   and it does not match `notexample.com` or `ample.com`.
/// - Case is not read on either side. `EXAMPLE.COM` matches `example.com`.
/// - **A port in an entry never matches.** `example.com:80` reaches the
///   proxy for `http://example.com/` and for `http://example.com:8080/`
///   alike. curl compares an entry against the host alone, so the colon and
///   the digits are part of a name no host carries. This is the rule that
///   is easiest to get wrong in the generous direction, and a generous
///   answer here sends traffic to a proxy the user excluded.
/// - An entry that reads as `address/bits` is a CIDR block, and it matches
///   a host that is a literal address inside that block. `127.0.0.0/8`
///   matches `127.0.0.1`, and `10.0.0.0/8` does not. A block matches only
///   an address of the same family.
/// - A bare address entry matches that address by the ordinary text rule,
///   so `127.0.0.1` matches `127.0.0.1` and `::1` matches `::1`. The host
///   here carries no brackets, the same way `zurl_core.url.parse` reports
///   it.
/// - **One trailing root dot comes off the host before any rule reads it.**
///   A name that ends with a dot names the root of the DNS tree, so
///   `example.com.` and `example.com` are the same host. See `rootDotOff`.
///
/// This reads no environment variable of its own. The caller decides which
/// text to pass: `--noproxy` when the user wrote one, and the `no_proxy` or
/// `NO_PROXY` value otherwise.
pub fn bypasses(list: []const u8, host: []const u8) bool {
    var it = std.mem.splitScalar(u8, list, ',');
    while (it.next()) |raw| {
        const entry = std.mem.trim(u8, raw, " \t\r\n");
        if (entry.len == 0) continue;
        if (std.mem.eql(u8, entry, "*")) return true;
        if (matchesEntry(entry, host)) return true;
    }
    return false;
}

/// Reads one trailing root label off a DNS name.
///
/// A name that ends with a dot names the root of the DNS tree, so
/// `example.com.` and `example.com` are one host for every purpose here.
/// A `no_proxy` rule that did not read the dot off would send a host the
/// user named in the list to the proxy the user excluded, which is a
/// privacy control failing without a word. Measured against curl 8.21.0:
/// `no_proxy=example.test` with `http://example.test./` went direct.
///
/// **Only one label comes off.** Two dots are not a name DNS reads, so
/// `example.com..` keeps no match, and curl refuses such a url outright
/// with exit 3. A name that is a single dot is left as it is, because the
/// empty text matches nothing that the whole text does not already.
fn rootDotOff(name: []const u8) []const u8 {
    if (name.len > 1 and name[name.len - 1] == '.') return name[0 .. name.len - 1];
    return name;
}

/// Whether one `no_proxy` entry answers for `host`.
///
/// **A host that is a literal address is compared as an address and never
/// as a name.** That is curl's own division, and it matters: the name rule
/// matches a suffix on a label boundary, and `127.0.0.1` ends with `.0.1`,
/// so a name rule over an address host would read `no_proxy=0.1` as an
/// exclusion for every `127.0.0.1`. Measured against curl 8.21.0:
/// `no_proxy=0.1` sent `http://127.0.0.1/` to the proxy.
fn matchesEntry(entry_text: []const u8, host_text: []const u8) bool {
    if (host_text.len == 0) return false;
    // The root dot comes off the host before the address rule as well as
    // before the name rule. Measured against curl 8.21.0,
    // `http://127.0.0.1./` went direct for `no_proxy=127.0.0.1` and for
    // `no_proxy=127.0.0.0/8` alike, so curl reads the dot off first and
    // then decides which of the two rules answers.
    const host = rootDotOff(host_text);
    if (parseAddress(host)) |address| return matchesAddress(entry_text, address);
    // A CIDR block names addresses, and this host is a name. A name is
    // never inside a block, because nothing here resolves one.
    if (std.mem.indexOfScalar(u8, entry_text, '/') != null) return false;

    // Both sides of a name comparison are DNS names, so the entry loses a
    // root dot of its own. The address rule above does not, and that is
    // curl: `no_proxy=127.0.0.1.` sent `http://127.0.0.1/` to the proxy,
    // because an address carries no such dot and the text is then no
    // address at all. Measured.
    const entry = rootDotOff(entry_text);
    // A leading dot is dropped, and the entry then matches the domain
    // itself as well as everything under it.
    const name = if (entry[0] == '.') entry[1..] else entry;
    if (name.len == 0) return false;
    if (std.ascii.eqlIgnoreCase(name, host)) return true;
    // A suffix match must land on a label boundary. Without the dot,
    // `ample.com` would take `example.com`.
    if (host.len <= name.len) return false;
    const at = host.len - name.len;
    if (host[at - 1] != '.') return false;
    return std.ascii.eqlIgnoreCase(name, host[at..]);
}

/// Whether one entry answers for a host that is a literal address.
///
/// An entry with a `/` is a CIDR block, and it holds the address when the
/// two are the same family and the named bits agree. An entry with no `/`
/// must read as an address of the same family and be equal to it.
fn matchesAddress(entry: []const u8, address: std.Io.net.IpAddress) bool {
    const slash = std.mem.indexOfScalar(u8, entry, '/');
    const network_text = if (slash) |at| entry[0..at] else entry;
    const network = parseAddress(network_text) orelse return false;
    const bits: u8 = if (slash) |at| blk: {
        break :blk std.fmt.parseInt(u8, entry[at + 1 ..], 10) catch return false;
    } else switch (network) {
        // No block was named, so every bit of the address must agree.
        .ip4 => 32,
        .ip6 => 128,
    };

    return switch (network) {
        .ip4 => |net4| switch (address) {
            .ip4 => |addr4| bits <= 32 and prefixEqual(&net4.bytes, &addr4.bytes, bits),
            .ip6 => false,
        },
        .ip6 => |net6| switch (address) {
            .ip6 => |addr6| bits <= 128 and prefixEqual(&net6.bytes, &addr6.bytes, bits),
            .ip4 => false,
        },
    };
}

/// Reads `text` as a literal address, or answers null for a name.
///
/// `std.Io.net.IpAddress.parse` and not `parseLiteral`: a `no_proxy` entry
/// and a url host each write an IPv6 address bare, with no brackets, and
/// `parseLiteral` asks for brackets. Neither side carries a port here.
fn parseAddress(text: []const u8) ?std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parse(text, 0) catch null;
}

/// Whether the first `bits` bits of `a` and `b` are the same.
///
/// A prefix of zero bits matches everything, which is what `0.0.0.0/0`
/// means. Asserts nothing about `bits`: the caller has already bounded it
/// against the length of the two addresses, and a bound checked twice is
/// still a bound.
fn prefixEqual(a: []const u8, b: []const u8, bits: u8) bool {
    std.debug.assert(a.len == b.len);
    const whole = bits / 8;
    const spare = bits % 8;
    if (whole > a.len) return false;
    if (!std.mem.eql(u8, a[0..whole], b[0..whole])) return false;
    if (spare == 0) return true;
    if (whole == a.len) return true;
    const mask: u8 = @truncate(@as(u16, 0xff) << @intCast(8 - spare));
    return (a[whole] & mask) == (b[whole] & mask);
}

/// The environment variable names a proxy comes from, in the order they are
/// read.
///
/// **`HTTP_PROXY` is not read, and that is deliberate.** curl reads the
/// lower case name for every variable and the upper case name for every one
/// but this. A CGI program takes the client's `Proxy:` request header as
/// `HTTP_PROXY` in its own environment, so an upper case `HTTP_PROXY` can
/// be set by whoever sent the request. Reading it would let a remote caller
/// choose the proxy of every cleartext transfer the program makes.
///
/// Measured against curl 8.21.0, one invocation for each name, reading the
/// address curl dialed: `http_proxy` took effect and `HTTP_PROXY` did not,
/// while `https_proxy`, `HTTPS_PROXY`, `all_proxy`, and `ALL_PROXY` each
/// took effect. Where both cases of one name are set, the lower case one
/// wins.
pub const Env = struct {
    /// The variable naming the proxy for a cleartext target.
    ///
    /// **One entry, and that is a security rule and not an oversight.** A
    /// CGI program takes the client's `Proxy:` request header as
    /// `HTTP_PROXY` in its own environment, so an entry for the upper case
    /// spelling lets whoever sent the request choose the proxy. Do not add
    /// one. The full history is above.
    pub const http = [_][]const u8{"http_proxy"};
    /// The variable naming the proxy for a TLS target.
    pub const https = [_][]const u8{ "https_proxy", "HTTPS_PROXY" };
    /// The variable naming the proxy for any target that has no more
    /// specific one.
    pub const all = [_][]const u8{ "all_proxy", "ALL_PROXY" };
    /// The variable naming the hosts that reach no proxy.
    pub const no = [_][]const u8{ "no_proxy", "NO_PROXY" };
};

/// What the proxy environment variables say, after every one of them is
/// read.
///
/// Each field answers for one field of a transfer's options, and a field
/// the environment did not name keeps the value here that the options give
/// it. `zurl.proxyFromEnv` does that copy for a caller of the front
/// package.
pub const FromEnv = struct {
    /// The proxy a cleartext target goes through. This comes from
    /// `http_proxy`, and from `all_proxy` when `http_proxy` names none.
    http: ?Spec = null,
    /// The proxy a TLS target goes through. This comes from `https_proxy`
    /// or `HTTPS_PROXY`, and from `all_proxy` when neither names one.
    https: ?Spec = null,
    /// The hosts that reach no proxy. This comes from `no_proxy` or
    /// `NO_PROXY`, and it is empty when neither names one. An empty list
    /// excludes no host, which is what `bypasses` answers for it.
    no_proxy: []const u8 = "",
    /// Whether `all_proxy` named the proxy.
    ///
    /// `all_proxy` covers every protocol the way `-x` does, so a protocol
    /// that carries no proxy must refuse rather than dial direct.
    /// `http_proxy` and `https_proxy` each answer for one HTTP target
    /// alone, so neither of them sets this.
    every_protocol: bool = false,
};

/// Reads the proxy environment variables into one answer.
///
/// **This is the environment half of the rule and nothing more.** A flag
/// that outranks the environment is the caller's business. The CLI puts
/// `-x`, the `--socks` family, and `--noproxy` over what this answers, and
/// a library caller does the same with whatever its own user wrote.
///
/// The order, every part of it measured against curl 8.21.0 by reading the
/// address curl dialed:
///
/// - **A variable set to the empty text counts as unset.** An empty value
///   names no proxy, so the next name in the list answers, and the next
///   variable after that.
/// - **Where both cases of one name are set, the lower case one wins.**
///   Measured with the two cases pointing at two different ports.
/// - `all_proxy` sits behind `http_proxy` and behind `https_proxy`, one
///   scheme at a time. A shell that sets one and not the other still
///   reaches the origin directly for the other scheme.
/// - `HTTP_PROXY` is not read at all. `Env` holds the reason, and it is a
///   security rule and not an oversight.
///
/// **A proxy url that does not read is a fault the caller sees, and never a
/// quiet fall back to a direct connection.** A stale shell profile must not
/// become an unreported direct connection to the origin.
///
/// Only a value that answers is read. `all_proxy` beside an `http_proxy`
/// and an `https_proxy` reaches no `parse` call, so a bad `all_proxy` that
/// nothing uses stops nothing. It still sets `every_protocol`, because the
/// user did name a proxy for every protocol.
pub fn fromEnv(env: *const std.process.Environ.Map) ParseError!FromEnv {
    var out: FromEnv = .{ .no_proxy = noProxyFromEnv(env) };

    const fallback = firstSet(env, &Env.all);
    out.every_protocol = fallback != null;
    if (firstSet(env, &Env.http) orelse fallback) |text| out.http = try parse(text);
    if (firstSet(env, &Env.https) orelse fallback) |text| out.https = try parse(text);
    return out;
}

/// The hosts that reach no proxy, from the environment alone.
///
/// `fromEnv` answers this too, in `FromEnv.no_proxy`. It is a function of
/// its own because it is the one part of the rule a caller can want by
/// itself: `--noproxy` and `-x` are two different flags, so a command line
/// that names a proxy still takes its bypass list from the environment.
pub fn noProxyFromEnv(env: *const std.process.Environ.Map) []const u8 {
    return firstSet(env, &Env.no) orelse "";
}

/// The value of the first name in `names` that is set to a non-empty text,
/// or null when no name is.
///
/// **An empty value counts as unset, and that is curl's own rule.** A
/// variable set to the empty text names no proxy and no bypass list, so
/// reading it as the text `""` would send an empty host to a dial. The
/// lists in `Env` put the lower case spelling first, because the first name
/// that answers wins and curl prefers the lower case one.
fn firstSet(env: *const std.process.Environ.Map, names: []const []const u8) ?[]const u8 {
    for (names) |name| {
        const value = env.get(name) orelse continue;
        if (value.len != 0) return value;
    }
    return null;
}

const testing = std.testing;

/// An environment map holding the names one test lists, and nothing else.
///
/// The caller must `deinit` it. A test that read the real environment would
/// answer one way on a developer's machine and another way in a build, so
/// no test here reads one.
fn testEnv(pairs: []const [2][]const u8) !std.process.Environ.Map {
    var map: std.process.Environ.Map = .init(testing.allocator);
    errdefer map.deinit();
    for (pairs) |pair| try map.put(pair[0], pair[1]);
    return map;
}

test "a proxy url with no scheme is an http proxy" {
    // Measured against curl 8.21.0: `-x 127.0.0.1:PORT` and `-x
    // http://127.0.0.1:PORT` each sent the same absolute-form request to
    // the same listener.
    const spec = try parse("127.0.0.1:3128");
    try testing.expectEqual(Kind.http, spec.kind);
    try testing.expectEqualStrings("127.0.0.1", spec.host);
    try testing.expectEqual(@as(u16, 3128), spec.port);
    try testing.expect(!spec.hasCredential());
}

test "each scheme selects its kind and its own default port" {
    // Measured against curl 8.21.0 by reading the address it dialed for a
    // proxy url that named no port.
    const rows = [_]struct { text: []const u8, kind: Kind, port: u16 }{
        .{ .text = "http://127.0.0.1", .kind = .http, .port = 80 },
        .{ .text = "https://127.0.0.1", .kind = .https, .port = 443 },
        .{ .text = "socks4://127.0.0.1", .kind = .socks4, .port = 1080 },
        .{ .text = "socks4a://127.0.0.1", .kind = .socks4a, .port = 1080 },
        .{ .text = "socks5://127.0.0.1", .kind = .socks5, .port = 1080 },
        .{ .text = "socks5h://127.0.0.1", .kind = .socks5h, .port = 1080 },
    };
    for (rows) |row| {
        const spec = try parse(row.text);
        try testing.expectEqual(row.kind, spec.kind);
        try testing.expectEqual(row.port, spec.port);
        try testing.expectEqualStrings("127.0.0.1", spec.host);
    }
}

test "a scheme this build does not speak is named, not guessed at" {
    // curl 8.21.0 answers `-x ftp://127.0.0.1` with `Unsupported proxy
    // scheme`. Falling back to an HTTP proxy would send the request to a
    // peer that speaks something else.
    try testing.expectError(error.UnsupportedProxyScheme, parse("ftp://127.0.0.1"));
    try testing.expectError(error.UnsupportedProxyScheme, parse("socks://127.0.0.1"));
}

test "the scheme is read without regard to case" {
    try testing.expectEqual(Kind.socks5h, (try parse("SOCKS5H://127.0.0.1")).kind);
    try testing.expectEqual(Kind.https, (try parse("HTTPS://127.0.0.1")).kind);
}

test "a proxy url carries a credential for the proxy alone" {
    // Measured against curl 8.21.0: `-x http://bob:proxypw@127.0.0.1:PORT`
    // sent `Proxy-Authorization: Basic Ym9iOnByb3h5cHc=`, which is
    // base64("bob:proxypw").
    const spec = try parse("http://bob:proxypw@127.0.0.1:3128");
    try testing.expectEqualStrings("bob", spec.user);
    try testing.expectEqualStrings("proxypw", spec.password);
    try testing.expectEqualStrings("127.0.0.1", spec.host);
    try testing.expectEqual(@as(u16, 3128), spec.port);
    try testing.expect(spec.hasCredential());
}

test "the userinfo splits on the last at and the first colon" {
    // A password may hold an `@` and a `:`, and a user name may hold
    // neither. Splitting the other way around reads part of the password as
    // the host.
    const spec = try parse("http://bob:pw:with@signs@proxy.test:8080");
    try testing.expectEqualStrings("bob", spec.user);
    try testing.expectEqualStrings("pw:with@signs", spec.password);
    try testing.expectEqualStrings("proxy.test", spec.host);
}

test "a user name with no password is read as a user name" {
    const spec = try parse("http://bob@proxy.test");
    try testing.expectEqualStrings("bob", spec.user);
    try testing.expectEqualStrings("", spec.password);
    try testing.expect(spec.hasCredential());
}

test "an IPv6 proxy keeps its address and loses its brackets" {
    const spec = try parse("http://[::1]:3128");
    try testing.expectEqualStrings("::1", spec.host);
    try testing.expectEqual(@as(u16, 3128), spec.port);

    const bare = try parse("http://[fe80::1]");
    try testing.expectEqualStrings("fe80::1", bare.host);
    try testing.expectEqual(@as(u16, 80), bare.port);
}

test "a bare IPv6 literal with no brackets is refused, not guessed at" {
    // `::1:3128` could be an address or an address and a port, and no
    // reading of it is more right than the other.
    try testing.expectError(error.InvalidProxy, parse("http://::1:3128"));
}

test "a path after the authority is dropped" {
    // curl accepts one and ignores it. A proxy has no path.
    const spec = try parse("http://127.0.0.1:3128/ignored?x=1");
    try testing.expectEqualStrings("127.0.0.1", spec.host);
    try testing.expectEqual(@as(u16, 3128), spec.port);
}

test "a port that is not a port is a fault, and never a default" {
    try testing.expectError(error.InvalidProxy, parse("http://127.0.0.1:notaport"));
    try testing.expectError(error.InvalidProxy, parse("http://127.0.0.1:0"));
    try testing.expectError(error.InvalidProxy, parse("http://127.0.0.1:99999"));
    try testing.expectError(error.InvalidProxy, parse("http://127.0.0.1:"));
}

test "an empty proxy url, and one with no host, are faults" {
    try testing.expectError(error.InvalidProxy, parse(""));
    try testing.expectError(error.InvalidProxy, parse("http://"));
    try testing.expectError(error.InvalidProxy, parse("http:///path"));
}

test "a control byte in a proxy url is refused before it reaches a request line" {
    // A proxy url reaches a `CONNECT` line and a SOCKS handshake. A CR or
    // an LF in it would write bytes the user never asked for.
    try testing.expectError(error.InvalidProxy, parse("http://proxy\r\nX: 1"));
    try testing.expectError(error.InvalidProxy, parse("http://proxy\x00.test"));
}

test "a flag that names the protocol wins over the scheme in the text" {
    // `--socks5 127.0.0.1` names both the proxy and the protocol.
    const spec = try parseAs("127.0.0.1", .socks5);
    try testing.expectEqual(Kind.socks5, spec.kind);
    try testing.expectEqual(@as(u16, 1080), spec.port);

    // A port the text names is kept.
    const ported = try parseAs("127.0.0.1:9050", .socks5h);
    try testing.expectEqual(Kind.socks5h, ported.kind);
    try testing.expectEqual(@as(u16, 9050), ported.port);

    // And a scheme in the text loses to the flag, port included.
    const schemed = try parseAs("http://127.0.0.1", .socks4);
    try testing.expectEqual(Kind.socks4, schemed.kind);
    try testing.expectEqual(@as(u16, 1080), schemed.port);
}

test "socks5 resolves on this machine and socks5h leaves it to the proxy" {
    // This is the whole difference between the two, and it decides whether
    // a local resolver ever sees the host the user asked for.
    try testing.expect(Kind.socks4.resolvesLocally());
    try testing.expect(Kind.socks5.resolvesLocally());
    try testing.expect(!Kind.socks4a.resolvesLocally());
    try testing.expect(!Kind.socks5h.resolvesLocally());
    try testing.expect(!Kind.http.resolvesLocally());
    try testing.expect(!Kind.https.resolvesLocally());
}

test "only an https proxy puts TLS on the hop to the proxy" {
    // `--proxy-insecure`, `--proxy-cacert`, and `--proxy-capath` control
    // this handshake and no other. A `CONNECT` tunnel through a cleartext
    // proxy still verifies the origin against the origin's own roots.
    try testing.expect(Kind.https.isSecure());
    try testing.expect(!Kind.http.isSecure());
    for ([_]Kind{ .socks4, .socks4a, .socks5, .socks5h }) |k| {
        try testing.expect(!k.isSecure());
        try testing.expect(k.isSocks());
    }
    try testing.expect(!Kind.http.isSocks());
    try testing.expect(!Kind.https.isSocks());
}

test "no_proxy takes a bare domain and everything under it" {
    // Measured against curl 8.21.0, one invocation for each row.
    try testing.expect(bypasses("example.com", "example.com"));
    try testing.expect(bypasses("example.com", "sub.example.com"));
    try testing.expect(bypasses("example.com", "a.b.example.com"));
    try testing.expect(bypasses("b.example.com", "a.b.example.com"));

    // And it takes nothing that only looks like it.
    try testing.expect(!bypasses("example.com", "notexample.com"));
    try testing.expect(!bypasses("ample.com", "example.com"));
    try testing.expect(!bypasses("example.com", "example.com.evil.test"));
}

test "a trailing root dot on the host does not defeat no_proxy" {
    // Measured against curl 8.21.0 with `http_proxy` pointing at a port
    // that refuses, so exit 6 says curl went direct and exit 7 says it
    // went to the proxy. `http://example.test./` with
    // `no_proxy=example.test` gave exit 6, which is the entry matching.
    // zurl sent the same request to the proxy the user had excluded.
    try testing.expect(bypasses("example.test", "example.test."));
    try testing.expect(bypasses("example.test.", "example.test"));
    try testing.expect(bypasses("example.test.", "example.test."));
    try testing.expect(bypasses(".example.test", "sub.example.test."));
    try testing.expect(bypasses("example.test", "sub.example.test."));

    // Two dots are not a host, so no match is invented for one. Measured:
    // `no_proxy=example.test..` sent `http://example.test/` to the proxy.
    try testing.expect(!bypasses("example.test..", "example.test"));
    try testing.expect(!bypasses("example.test", "example.test.."));

    // The dot widens nothing. A host the list does not name still goes
    // through the proxy.
    try testing.expect(!bypasses("example.test", "notexample.test."));
    try testing.expect(!bypasses("ample.test", "example.test."));
}

test "a trailing root dot on an address host still reads as an address" {
    // Measured: `http://127.0.0.1./` went direct for `no_proxy=127.0.0.1`
    // and for `no_proxy=127.0.0.0/8`, so the dot comes off before the
    // address rule and the name rule divide.
    try testing.expect(bypasses("127.0.0.1", "127.0.0.1."));
    try testing.expect(bypasses("127.0.0.0/8", "127.0.0.1."));

    // And the entry keeps no dot of its own on this path. Measured:
    // `no_proxy=127.0.0.1.` sent `http://127.0.0.1/` to the proxy,
    // because the entry text is then no address at all.
    try testing.expect(!bypasses("127.0.0.1.", "127.0.0.1"));

    // The address rule stays narrow. `0.1` is still no exclusion for
    // `127.0.0.1`, with or without the dot.
    try testing.expect(!bypasses("0.1", "127.0.0.1."));
}

test "a leading dot in a no_proxy entry also takes the domain itself" {
    // Measured: `.example.com` excluded `example.com` as well as
    // `sub.example.com`.
    try testing.expect(bypasses(".example.com", "example.com"));
    try testing.expect(bypasses(".example.com", "sub.example.com"));
    try testing.expect(!bypasses(".example.com", "notexample.com"));
}

test "a no_proxy list divides on commas and drops the spaces" {
    try testing.expect(bypasses("foo.com,example.com", "example.com"));
    try testing.expect(bypasses("foo.com, example.com", "example.com"));
    try testing.expect(bypasses(" example.com ", "example.com"));
    try testing.expect(!bypasses("foo.com,bar.com", "example.com"));
}

test "a no_proxy star excludes every host" {
    try testing.expect(bypasses("*", "example.com"));
    try testing.expect(bypasses("*", "127.0.0.1"));
    try testing.expect(bypasses("a.com,*", "anything.test"));
}

test "an empty no_proxy list excludes nothing" {
    // Measured: an empty value and a lone comma each sent the request to
    // the proxy. An empty list that excluded everything would be the
    // failure mode with the largest blast radius.
    try testing.expect(!bypasses("", "example.com"));
    try testing.expect(!bypasses(",", "example.com"));
    try testing.expect(!bypasses("  ", "example.com"));
    try testing.expect(!bypasses("", "localhost"));
}

test "no_proxy reads no case on either side" {
    try testing.expect(bypasses("EXAMPLE.COM", "example.com"));
    try testing.expect(bypasses("example.com", "EXAMPLE.COM"));
    try testing.expect(bypasses("Example.Com", "sub.EXAMPLE.com"));
}

test "a port in a no_proxy entry never matches" {
    // **Measured, and it is the rule most likely to be written the other
    // way.** curl 8.21.0 sent `http://example.com/` to the proxy with
    // `no_proxy=example.com:80`, and sent `http://example.com:8080/` to the
    // proxy with `no_proxy=example.com:8080` as well. An entry with a port
    // names a host no url carries.
    try testing.expect(!bypasses("example.com:80", "example.com"));
    try testing.expect(!bypasses("example.com:8080", "example.com"));
    try testing.expect(!bypasses("example.com:80", "sub.example.com"));
}

test "a no_proxy address entry matches that address" {
    try testing.expect(bypasses("127.0.0.1", "127.0.0.1"));
    try testing.expect(!bypasses("127.0.0.2", "127.0.0.1"));
    try testing.expect(bypasses("::1", "::1"));

    // **A host that is a literal address is never matched by the name
    // rule.** That rule matches a suffix on a label boundary, and
    // `127.0.0.1` ends with `.0.1`, so a name rule over an address host
    // would read `no_proxy=0.1` as an exclusion for every `127.0.0.1`.
    // Measured against curl 8.21.0, three rows: `no_proxy=0.1` and
    // `no_proxy=0.0.1` and `no_proxy=.9` each sent the request to the
    // proxy, and `no_proxy=127.0.0.9` did not.
    try testing.expect(!bypasses("0.1", "127.0.0.1"));
    try testing.expect(!bypasses("0.0.1", "127.0.0.9"));
    try testing.expect(!bypasses(".9", "127.0.0.9"));
    try testing.expect(bypasses("127.0.0.9", "127.0.0.9"));
    // And a name entry never takes an address host, measured with
    // `no_proxy=localhost` against `http://127.0.0.9/`.
    try testing.expect(!bypasses("localhost", "127.0.0.9"));
    // A `*` still takes it, because `*` is read before either rule.
    try testing.expect(bypasses("*", "127.0.0.9"));
}

test "a no_proxy CIDR block matches an address inside it" {
    // Measured against curl 8.21.0: `127.0.0.0/8` excluded `127.0.0.1` and
    // `10.0.0.0/8` did not.
    try testing.expect(bypasses("127.0.0.0/8", "127.0.0.1"));
    try testing.expect(!bypasses("10.0.0.0/8", "127.0.0.1"));
    try testing.expect(bypasses("127.0.0.1/32", "127.0.0.1"));
    try testing.expect(bypasses("127.0.0.1/24", "127.0.0.2"));
    // Measured: a /31 over 127.0.0.0 holds 127.0.0.0 and 127.0.0.1, and
    // not 127.0.0.2.
    try testing.expect(!bypasses("127.0.0.0/31", "127.0.0.2"));
    try testing.expect(bypasses("127.0.0.0/31", "127.0.0.1"));
}

test "a CIDR block matches no host name and no other family" {
    // A name is not an address, and this file resolves nothing.
    try testing.expect(!bypasses("127.0.0.0/8", "example.com"));
    try testing.expect(!bypasses("::/0", "127.0.0.1"));
    try testing.expect(!bypasses("0.0.0.0/0", "::1"));
    // And a block of no bits holds every address of its own family.
    try testing.expect(bypasses("0.0.0.0/0", "203.0.113.9"));
    try testing.expect(bypasses("::/0", "2001:db8::1"));
}

test "a malformed CIDR entry matches nothing rather than everything" {
    // A bad entry that matched everything would silently turn the proxy
    // off. Recovery is never silent, and the safe answer here is the
    // narrow one.
    try testing.expect(!bypasses("127.0.0.0/notanumber", "127.0.0.1"));
    try testing.expect(!bypasses("nothing/8", "127.0.0.1"));
    try testing.expect(!bypasses("127.0.0.0/999", "127.0.0.1"));
}

test "the environment names read the lower case always and the upper case nearly always" {
    // **`HTTP_PROXY` is absent on purpose.** A CGI program takes the
    // client's `Proxy:` request header as `HTTP_PROXY`, so reading it would
    // let a remote caller choose the proxy. Measured against curl 8.21.0:
    // `HTTP_PROXY` alone left the transfer direct, and every other upper
    // case name took effect.
    try testing.expectEqual(@as(usize, 1), Env.http.len);
    try testing.expectEqualStrings("http_proxy", Env.http[0]);
    for (Env.http) |name| try testing.expect(!std.mem.eql(u8, name, "HTTP_PROXY"));

    try testing.expectEqualStrings("https_proxy", Env.https[0]);
    try testing.expectEqualStrings("HTTPS_PROXY", Env.https[1]);
    try testing.expectEqualStrings("all_proxy", Env.all[0]);
    try testing.expectEqualStrings("ALL_PROXY", Env.all[1]);
    try testing.expectEqualStrings("no_proxy", Env.no[0]);
    try testing.expectEqualStrings("NO_PROXY", Env.no[1]);

    // The lower case spelling comes first in every list, because the first
    // name that is set wins and curl prefers the lower case one. Measured
    // with both cases set to different ports.
    for ([_][]const u8{ Env.https[0], Env.all[0], Env.no[0] }) |name| {
        try testing.expect(std.ascii.isLower(name[0]));
    }
}

test "a proxy url at the length bound reads, and one past it does not" {
    var buffer: [url_len_max + 64]u8 = undefined;
    const prefix = "http://";
    @memcpy(buffer[0..prefix.len], prefix);
    @memset(buffer[prefix.len..], 'a');

    const at_bound = buffer[0..url_len_max];
    // The host is still bounded on its own, so a url of this length is a
    // fault for the host and not for the url. Both are bounds and neither
    // is a panic.
    try testing.expectError(error.InvalidProxy, parse(at_bound));
    try testing.expectError(error.InvalidProxy, parse(buffer[0 .. url_len_max + 1]));
}

test "a host at the host name bound reads" {
    var buffer: [std.Io.net.HostName.max_len + 8]u8 = undefined;
    const prefix = "http://";
    @memcpy(buffer[0..prefix.len], prefix);
    @memset(buffer[prefix.len..], 'a');
    const text = buffer[0 .. prefix.len + std.Io.net.HostName.max_len];
    const spec = try parse(text);
    try testing.expectEqual(std.Io.net.HostName.max_len, spec.host.len);

    // One byte more is refused, and it is refused rather than truncated: a
    // truncated host is a different host.
    try testing.expectError(
        error.InvalidProxy,
        parse(buffer[0 .. prefix.len + std.Io.net.HostName.max_len + 1]),
    );
}

test "an empty environment names no proxy and excludes no host" {
    var env = try testEnv(&.{});
    defer env.deinit();

    const from_env = try fromEnv(&env);
    try testing.expectEqual(@as(?Spec, null), from_env.http);
    try testing.expectEqual(@as(?Spec, null), from_env.https);
    try testing.expectEqualStrings("", from_env.no_proxy);
    try testing.expect(!from_env.every_protocol);
    try testing.expectEqualStrings("", noProxyFromEnv(&env));
}

test "each scheme takes the variable of its own" {
    // curl reads `http_proxy` for a cleartext target and `https_proxy` for
    // a TLS one, so a shell that sets one and not the other still reaches
    // the origin directly for the other scheme.
    var env = try testEnv(&.{
        .{ "http_proxy", "http://127.0.0.1:3128" },
        .{ "https_proxy", "http://127.0.0.2:3129" },
    });
    defer env.deinit();

    const from_env = try fromEnv(&env);
    try testing.expectEqualStrings("127.0.0.1", from_env.http.?.host);
    try testing.expectEqualStrings("127.0.0.2", from_env.https.?.host);
    // Neither of the two covers a protocol that is not HTTP.
    try testing.expect(!from_env.every_protocol);

    // And one variable alone leaves the other scheme direct.
    var one = try testEnv(&.{.{ "http_proxy", "http://127.0.0.1:3128" }});
    defer one.deinit();
    const only_cleartext = try fromEnv(&one);
    try testing.expectEqualStrings("127.0.0.1", only_cleartext.http.?.host);
    try testing.expectEqual(@as(?Spec, null), only_cleartext.https);
}

test "a variable set to the empty text counts as unset" {
    // **Measured against curl 8.21.0: an empty `http_proxy` left the
    // transfer direct.** An empty value names no host, so reading it as the
    // text `""` would send an empty host to a dial.
    var env = try testEnv(&.{
        .{ "http_proxy", "" },
        .{ "https_proxy", "" },
        .{ "all_proxy", "" },
        .{ "no_proxy", "" },
    });
    defer env.deinit();

    const from_env = try fromEnv(&env);
    try testing.expectEqual(@as(?Spec, null), from_env.http);
    try testing.expectEqual(@as(?Spec, null), from_env.https);
    try testing.expectEqualStrings("", from_env.no_proxy);
    try testing.expect(!from_env.every_protocol);

    // An empty value does not stop the next name in the list either.
    var mixed = try testEnv(&.{
        .{ "https_proxy", "" },
        .{ "HTTPS_PROXY", "http://127.0.0.2:3129" },
        .{ "no_proxy", "" },
        .{ "NO_PROXY", "example.com" },
    });
    defer mixed.deinit();
    const answered = try fromEnv(&mixed);
    try testing.expectEqualStrings("127.0.0.2", answered.https.?.host);
    try testing.expectEqualStrings("example.com", answered.no_proxy);
}

test "the lower case spelling wins where both cases are set" {
    // Measured against curl 8.21.0 with the two cases pointing at two
    // different ports: the lower case one decided.
    var env = try testEnv(&.{
        .{ "https_proxy", "http://127.0.0.1:3128" },
        .{ "HTTPS_PROXY", "http://127.0.0.2:3129" },
        .{ "all_proxy", "http://127.0.0.3:3130" },
        .{ "ALL_PROXY", "http://127.0.0.4:3131" },
        .{ "no_proxy", "lower.test" },
        .{ "NO_PROXY", "upper.test" },
    });
    defer env.deinit();

    const from_env = try fromEnv(&env);
    try testing.expectEqualStrings("127.0.0.1", from_env.https.?.host);
    // `all_proxy` answers for the cleartext scheme here, and the lower case
    // spelling of it wins the same way.
    try testing.expectEqualStrings("127.0.0.3", from_env.http.?.host);
    try testing.expectEqualStrings("lower.test", from_env.no_proxy);
}

test "HTTP_PROXY is not read, and every other upper case name is" {
    // **This is a security rule and not an oversight.** A CGI program takes
    // the client's `Proxy:` request header as `HTTP_PROXY` in its own
    // environment, so reading it would let whoever sent the request choose
    // the proxy of every cleartext transfer. Measured against curl 8.21.0,
    // one invocation for each name.
    var upper = try testEnv(&.{.{ "HTTP_PROXY", "http://127.0.0.1:3128" }});
    defer upper.deinit();
    const ignored = try fromEnv(&upper);
    try testing.expectEqual(@as(?Spec, null), ignored.http);
    try testing.expectEqual(@as(?Spec, null), ignored.https);

    var lower = try testEnv(&.{.{ "http_proxy", "http://127.0.0.1:3128" }});
    defer lower.deinit();
    try testing.expectEqualStrings("127.0.0.1", (try fromEnv(&lower)).http.?.host);

    // A bad value in `HTTP_PROXY` stops nothing either, because nothing
    // reads it.
    var bad = try testEnv(&.{.{ "HTTP_PROXY", "ftp://127.0.0.1" }});
    defer bad.deinit();
    try testing.expectEqual(@as(?Spec, null), (try fromEnv(&bad)).http);
}

test "all_proxy sits behind each scheme and covers every protocol" {
    // Measured against curl 8.21.0 with both set: the scheme's own variable
    // won, and the scheme with no variable of its own took `all_proxy`.
    var env = try testEnv(&.{
        .{ "all_proxy", "http://127.0.0.3:3130" },
        .{ "http_proxy", "http://127.0.0.1:3128" },
    });
    defer env.deinit();

    const from_env = try fromEnv(&env);
    try testing.expectEqualStrings("127.0.0.1", from_env.http.?.host);
    try testing.expectEqualStrings("127.0.0.3", from_env.https.?.host);
    // `all_proxy` covers every protocol the way `-x` does, and it does so
    // even where a scheme's own variable outranks it for HTTP.
    try testing.expect(from_env.every_protocol);

    // Alone, it answers for both schemes.
    var only = try testEnv(&.{.{ "ALL_PROXY", "socks5h://127.0.0.3:1080" }});
    defer only.deinit();
    const both = try fromEnv(&only);
    try testing.expectEqual(Kind.socks5h, both.http.?.kind);
    try testing.expectEqual(Kind.socks5h, both.https.?.kind);
    try testing.expect(both.every_protocol);
}

test "a proxy url in the environment that does not read is a fault" {
    // **A stale shell profile must not become a direct connection that
    // nobody reports.** The caller sees the fault and stops, the way the
    // CLI does with exit 5 and exit 7.
    var scheme = try testEnv(&.{.{ "http_proxy", "ftp://127.0.0.1" }});
    defer scheme.deinit();
    try testing.expectError(error.UnsupportedProxyScheme, fromEnv(&scheme));

    var port = try testEnv(&.{.{ "https_proxy", "http://127.0.0.1:notaport" }});
    defer port.deinit();
    try testing.expectError(error.InvalidProxy, fromEnv(&port));

    var fallback = try testEnv(&.{.{ "all_proxy", "http://127.0.0.1:0" }});
    defer fallback.deinit();
    try testing.expectError(error.InvalidProxy, fromEnv(&fallback));

    // A value that answers for no scheme reaches no `parse` call, so it
    // stops nothing. This is what the CLI did before this function held the
    // rule, and the behaviour is kept.
    var unused = try testEnv(&.{
        .{ "all_proxy", "ftp://127.0.0.1" },
        .{ "http_proxy", "http://127.0.0.1:3128" },
        .{ "https_proxy", "http://127.0.0.2:3129" },
    });
    defer unused.deinit();
    const read = try fromEnv(&unused);
    try testing.expectEqualStrings("127.0.0.1", read.http.?.host);
    try testing.expect(read.every_protocol);
}

test "the bypass list reads from either case and is answered on its own" {
    var env = try testEnv(&.{.{ "NO_PROXY", "example.com, .test" }});
    defer env.deinit();

    try testing.expectEqualStrings("example.com, .test", noProxyFromEnv(&env));
    try testing.expectEqualStrings("example.com, .test", (try fromEnv(&env)).no_proxy);
    // And the list it names is the one `bypasses` reads.
    try testing.expect(bypasses(noProxyFromEnv(&env), "sub.example.com"));
    try testing.expect(!bypasses(noProxyFromEnv(&env), "other.invalid"));
}

test "the bypass list answers even where a proxy url does not read" {
    // `--noproxy` and `-x` are two different flags, so a caller that puts
    // its own proxy over the environment still wants this list. It must not
    // need `fromEnv`, which faults on a proxy url the caller was going to
    // replace.
    var env = try testEnv(&.{
        .{ "no_proxy", "example.com" },
        .{ "http_proxy", "ftp://127.0.0.1" },
    });
    defer env.deinit();

    try testing.expectEqualStrings("example.com", noProxyFromEnv(&env));
    try testing.expectError(error.UnsupportedProxyScheme, fromEnv(&env));
}
