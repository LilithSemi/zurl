//! URL parsing with curl semantics.
//!
//! `std.Uri` parses a URI as RFC 3986 writes it. curl accepts more than that,
//! because people type less than that. This module adds the differences: a
//! missing scheme, a default port for each scheme, and a user and password in
//! the authority.
//!
//! `parse` allocates nothing. Every slice in the result borrows from the input
//! text, so the text must outlive the `Url`.
//!
//! **A caller can teach this module a scheme.** `defaultPort` holds the
//! schemes zurl ships with. A protocol package outside that table gives its
//! scheme and its port to a `Schemes` value, and `parseWith` then reads a url
//! of that scheme exactly as it reads a built-in one. `parse` is `parseWith`
//! with an empty registry, so the built-in table is unchanged for every
//! caller that registers nothing.

const std = @import("std");

/// A parsed URL. Every slice borrows from the text that `parse` read.
pub const Url = struct {
    scheme: []const u8,
    /// Still escaped, exactly as the url wrote it, and under no rule of its
    /// own.
    ///
    /// This is safe only because every credential builder encodes or
    /// escapes it: `zurl.authorize` percent-decodes it and then base64s it
    /// for `Basic`, and `zurl_core.auth` writes it through `writeQuoted`
    /// for `Digest`, which refuses a byte that no quoted string may carry.
    /// A future caller that writes this text straight into a header needs
    /// its own check first.
    user: ?[]const u8,
    /// Still escaped, and under no rule of its own. See `user`.
    password: ?[]const u8,
    /// An IPv6 host has no brackets here. `http://[::1]:8080/` gives the
    /// host `::1` and the port 8080.
    ///
    /// Empty only for a scheme a caller registered with no port. See
    /// `Scheme.default_port`: such a scheme dials nothing, so `file:///a`
    /// gives the host "". Every other scheme gets `error.InvalidUrl` for
    /// an empty host, because a url that dials must say what it dials.
    ///
    /// **A reader that writes this text into an authority must put the
    /// brackets back and take the zone id off.** The brackets are what
    /// tell the colons inside the address apart from the colon before a
    /// port, so `::1` on port 8080 reaches the wire as `[::1]:8080`. The
    /// zone id of `fe80::1%25eth0` names an interface of this machine and
    /// means nothing to a peer, so RFC 6874 section 3 keeps it off the
    /// wire. `zurl-http` does both in one place, its `writeHost`, which
    /// calls `hostWithoutZone`.
    ///
    /// The zone id stays in this field so that a dial sees it.
    /// `zurl_net.tcp.Host.init` refuses a scope, because it cannot look up
    /// an interface name, and dropping the zone here would hide that
    /// refusal and dial the address with no scope at all.
    ///
    /// A reader that dials this text must read it as an address and not
    /// as a name. `zurl_net.tcp.Host.init` does that, and it is the only
    /// path from this field to a socket.
    ///
    /// Holds no C0 control byte, no DEL, and no raw space. See `path`: a
    /// `Host:` header carries this text as plainly as a request line
    /// carries the path.
    host: []const u8,
    /// The port the transfer connects to.
    ///
    /// Null only for a scheme a caller registered with no port at all. See
    /// `Scheme.default_port`: such a scheme names no peer, so there is no
    /// number to fill in and none to invent. `file` is such a scheme.
    ///
    /// Never null for a scheme in `defaultPort`'s own table. A url that
    /// names no port gets the default of its scheme, so a reader cannot
    /// tell a port a person typed from a port `parse` supplied. See
    /// `zurl_http.h1.authorityPort` for why the engine writes neither on
    /// the wire.
    port: ?u16,
    /// Never empty. A URL with no path gets "/".
    ///
    /// Holds no C0 control byte, no DEL, and no raw space. `parse` rejects
    /// one, because a protocol package writes this text on the wire as it
    /// reads here: a raw CR or LF would end the request line and start a
    /// header of the url's choosing, and a raw space would split the
    /// request line into a target and a version of the url's choosing.
    path: []const u8,
    /// Holds no C0 control byte, no DEL, and no raw space. See `path`.
    query: ?[]const u8,
    /// Holds no C0 control byte, no DEL, and no raw space. See `path`.
    fragment: ?[]const u8,
};

/// What `parse` and its relatives report.
///
/// **The two members answer two different questions, and a script reads
/// them apart.** `InvalidUrl` says the text is not a url: it is curl's
/// `CURLE_URL_MALFORMAT`, exit 3, and a user who reads it looks at what
/// they typed. `UnsupportedProtocol` says the text is a good url for a
/// scheme this build does not speak: it is curl's
/// `CURLE_UNSUPPORTED_PROTOCOL`, exit 1, and a user who reads it looks at
/// how zurl was built.
///
/// Both names are members of `zurl_core.Error`, so a caller that returns
/// that set propagates either one with no map of its own.
///
/// Measured against curl 8.21.0, and this is the order the checks run in:
///
/// ```
/// curl rtmp://host.invalid/            exit 1, Protocol "rtmp" not supported
/// curl nosuchscheme://host.invalid/    exit 1, Protocol "nosuchscheme" not supported
/// curl nosuch://host.invalid:99999/    exit 3, Port number was not a decimal number
/// curl nosuch://exa mple.com/          exit 3, Malformed input to a URL function
/// curl nosuch://                       exit 3, No host part in the URL
/// curl nosuch_x://host.invalid/        exit 3, an underscore is no scheme byte
/// ```
///
/// So every syntax rule answers before the scheme is looked up. A url that
/// is malformed *and* names a scheme nobody speaks reports the malformed
/// half, because that is the half the user can fix.
pub const ParseError = error{ InvalidUrl, UnsupportedProtocol };

/// A scheme a caller taught this module, and the port a url of that scheme
/// gets when it names none.
///
/// A registered scheme wins over the fixed table in `defaultPort`, the same
/// way `zurl.protocol.find` reads the run-time table before the built-in
/// one. So a caller can change the port of a built-in scheme, and a reader
/// of either table sees one rule and not two.
pub const Scheme = struct {
    /// The scheme text, with no "://". Compared without regard to case,
    /// matching RFC 3986.
    name: []const u8,
    /// The port a url of this scheme gets when it names none.
    ///
    /// **Null says the scheme names no peer at all.** `file` is such a
    /// scheme: it reads the local filesystem and dials nothing. Two things
    /// follow, and both are what RFC 8089 writes for `file`:
    ///
    /// - A url of this scheme parses with `Url.port` null. A reader that
    ///   needs a number must say what it does with none.
    /// - A url of this scheme may leave the host empty, so `file:///a/b`
    ///   parses and gives the host "" and the path "/a/b".
    ///
    /// A scheme that is not registered at all and that `defaultPort` does
    /// not name is a different answer: a url of it with no explicit port is
    /// `error.UnsupportedProtocol`, and one with an empty host is
    /// `error.InvalidUrl` whatever port it names. So "this scheme has no
    /// port" and "nobody knows this scheme" never reach a caller as the
    /// same result, and neither of those two is the answer a url nobody
    /// can read gets.
    default_port: ?u16,
};

/// The schemes a caller has taught `parseWith`, beyond `defaultPort`'s own
/// table.
///
/// Bounded, and by a fixed array rather than by an allocation: this table is
/// read on the parse of every url and of every redirect target, it holds one
/// row for each protocol package a program links, and no program links more
/// protocols than a person can name. `add` refuses a row past `max` with
/// `error.TooManySchemes` and changes nothing, so a caller that registers
/// too many learns it at the call and never at the url.
pub const Schemes = struct {
    /// How many schemes one registry holds. Past curl's own protocol
    /// count, which is 26, so a program that registers one package for
    /// each protocol curl speaks still fits.
    pub const max = 32;

    pub const AddError = error{TooManySchemes};

    /// Read through `find`. Only the first `len` rows hold anything.
    entries: [max]Scheme,
    len: usize,

    /// A registry that names no scheme. `parse` uses this one, so the
    /// built-in table alone answers for a caller that registers nothing.
    pub const empty: Schemes = .{ .entries = undefined, .len = 0 };

    /// Adds `scheme` to the registry.
    ///
    /// A name already in the registry is not replaced. Both rows stay and
    /// `find` answers with the one added first, which is the rule
    /// `zurl.protocol.find` follows for the dispatch table beside this one.
    pub fn add(s: *Schemes, scheme: Scheme) AddError!void {
        if (s.len == max) return error.TooManySchemes;
        s.entries[s.len] = scheme;
        s.len += 1;
    }

    /// The registered scheme called `name`, or null when the registry
    /// names none. Compared without regard to case, per RFC 3986.
    pub fn find(s: *const Schemes, name: []const u8) ?Scheme {
        for (s.entries[0..s.len]) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.name, name)) return entry;
        }
        return null;
    }
};

/// The default port for each scheme that zurl knows.
///
/// Returns null for a scheme with no default. The caller then needs an
/// explicit port.
pub fn defaultPort(scheme: []const u8) ?u16 {
    const table = [_]struct { name: []const u8, port: u16 }{
        .{ .name = "http", .port = 80 },
        .{ .name = "https", .port = 443 },
        .{ .name = "ftp", .port = 21 },
        .{ .name = "ftps", .port = 990 },
        .{ .name = "tftp", .port = 69 },
        .{ .name = "smtp", .port = 25 },
        .{ .name = "smtps", .port = 465 },
        .{ .name = "imap", .port = 143 },
        .{ .name = "imaps", .port = 993 },
        .{ .name = "pop3", .port = 110 },
        .{ .name = "pop3s", .port = 995 },
    };
    for (table) |row| {
        if (std.ascii.eqlIgnoreCase(row.name, scheme)) return row.port;
    }
    return null;
}

/// Parses `text` into a `Url`, reading only the built-in scheme table.
///
/// `text` comes from a user or from a server redirect, so bad input is a
/// runtime fault and not an assertion.
pub fn parse(text: []const u8) ParseError!Url {
    return parseWith(text, &Schemes.empty);
}

/// Parses `text` into a `Url`, reading `schemes` before the built-in
/// table.
///
/// This is the hook a protocol package outside zurl needs. `parse` refuses
/// a url whose scheme nothing knows and that names no port, and it refuses
/// one whose host is empty. A caller that registers the scheme first gets
/// neither refusal, so a url for a registered protocol reads exactly like a
/// url for a built-in one.
///
/// `zurl.Client.registerProtocol` calls `Schemes.add` for the caller, so a
/// caller of that function never has to do this half.
pub fn parseWith(text: []const u8, schemes: *const Schemes) ParseError!Url {
    return parseWithDefault(text, schemes, null);
}

/// `parseWith`, with the scheme a url that carries none is read with.
///
/// This is curl's `--proto-default`. A null `default_scheme` keeps the
/// guess below: `ftp` for a host that starts `ftp.`, and `http` for every
/// other. A named one **replaces** that guess and is used for every
/// schemeless url. Measured against curl 8.21.0:
///
/// ```
/// curl ftp.gnu.org/                          reaches ftp://ftp.gnu.org/
/// curl --proto-default http ftp.gnu.org/     reaches http://ftp.gnu.org/
/// ```
///
/// curl reaches the same place by writing `scheme://` in front of the url
/// text, so its own guess never runs either.
///
/// `default_scheme` is borrowed and is not copied. It reaches `Url.scheme`
/// of a schemeless url, so it must outlive the returned `Url`.
///
/// A scheme nothing knows is `error.UnsupportedProtocol` and never
/// `error.InvalidUrl`. See `ParseError`: the two answers send a user to
/// two different places, and curl gives them two different exit codes. The
/// url still parses when it names a port or when the scheme is registered,
/// and the dispatch table then reports the same name for a scheme it has
/// no handler for.
pub fn parseWithDefault(
    text: []const u8,
    schemes: *const Schemes,
    default_scheme: ?[]const u8,
) ParseError!Url {
    if (text.len == 0) return error.InvalidUrl;

    var rest = text;
    var scheme: []const u8 = undefined;

    // **A scheme ends at a colon that at least one slash follows.** curl
    // does not need the second slash: `http:/target.test/` reaches
    // `target.test` there, measured, and so does `http:///target.test/`.
    // Reading only `://` made zurl take the authority of the first as
    // `http:`, which named the host `http` and put the real host in the
    // path. One url that names two hosts is the shape this whole module
    // guards against, so the slash count is read here and not assumed.
    //
    // The colon alone is not enough either. `target.test:8080/x` has a
    // colon with no slash after it, and that colon opens a port and not a
    // scheme. curl reads it as a port too, measured. So a colon with no
    // slash leaves the text with no scheme, and the guess below answers.
    //
    // **The colon of a scheme comes before the path, the query and the
    // fragment.** RFC 3986 section 3.1 gives a scheme letters, digits,
    // `+`, `-` and `.` only, so a `/`, a `?` or a `#` ends the search for
    // it. Reading the first colon anywhere in the text made a schemeless
    // url refuse itself, because the text in front of a colon that belongs
    // to a path or a query is not scheme syntax. Measured against curl
    // 8.21.0, which accepts both:
    //
    // ```
    // curl example.invalid/a:/b
    //     reaches http://example.invalid/a:/b
    // curl 'example.invalid/go?to=https://other.example/'
    //     reaches http://example.invalid/go?to=https://other.example/
    // ```
    //
    // The three refusals below keep their answer, measured at exit 3 in
    // the same curl: `://host/`, `ht_tp:/host/` and `nosuch_x://host/`
    // each put their colon in front of the first `/`, so the scheme syntax
    // check still reads them.
    var scheme_limit = rest.len;
    for ([_]u8{ '/', '?', '#' }) |sep| {
        if (std.mem.indexOfScalar(u8, rest, sep)) |i| scheme_limit = @min(scheme_limit, i);
    }

    var slashes: usize = 0;
    var after_scheme: []const u8 = "";
    var named_scheme = false;
    if (std.mem.indexOfScalar(u8, rest[0..scheme_limit], ':')) |i| {
        const after = rest[i + 1 ..];
        while (slashes < after.len and after[slashes] == '/') slashes += 1;
        if (slashes > 0) {
            // **Syntax before support.** A text that is not a scheme at
            // all is a malformed url, exit 3, and never "this build has no
            // such protocol", exit 1. An empty scheme and a scheme
            // carrying a byte RFC 3986 gives it are both this fault. curl
            // 8.21.0 answers both with exit 3, measured: `://host/`,
            // `nosuch_x://host/`, and `ht_tp:/host/`.
            if (!isSchemeSyntax(rest[0..i])) return error.InvalidUrl;
            scheme = rest[0..i];
            after_scheme = after;
            named_scheme = true;
        }
    }
    if (!named_scheme) {
        // `--proto-default` replaces the guess and never joins it.
        scheme = default_scheme orelse
            (if (std.ascii.startsWithIgnoreCase(rest, "ftp.")) "ftp" else "http");
    }

    // A registered scheme answers before the built-in table, the same
    // order `zurl.protocol.find` reads its two tables in.
    const registered = schemes.find(scheme);
    // A scheme that names no peer needs no host. That is the ordinary
    // spelling of a `file` url, `file:///a/b`, and RFC 8089 says the
    // empty authority means this machine. Every other scheme dials
    // something, so an empty authority there is a url with no
    // destination.
    const names_no_peer = if (registered) |entry| entry.default_port == null else false;

    if (named_scheme) {
        // **How many of those slashes the authority eats.**
        //
        // A scheme that dials a peer eats one or two. `http:/x/` and
        // `http://x/` each reach the host `x`, which is what curl does.
        //
        // **A third slash is left alone, and that is stricter than curl.**
        // curl reads `http:///x/` as the host `x` as well. Eating the
        // third slash would make an authority out of the first path
        // segment of a url that names no authority at all, and that is one
        // more way to reach a host the url never named. zurl answers
        // `error.InvalidUrl` instead, which is what it answers for
        // `http:////x/`, and curl answers that for the four-slash form
        // too. Measured.
        //
        // A scheme that names no peer eats two or none. The `/` of
        // `file:/tmp/a` opens the path, because RFC 8089 gives a file url
        // an authority only after `//`, and curl reads that url as the
        // file `/tmp/a`. Eating one slash there named the host `tmp` and
        // read the file `/a`.
        const skip: usize = if (names_no_peer)
            (if (slashes >= 2) 2 else 0)
        else
            @min(slashes, 2);
        rest = after_scheme[skip..];
    }

    // The fragment is last, so cut it first.
    var fragment: ?[]const u8 = null;
    if (std.mem.indexOfScalar(u8, rest, '#')) |i| {
        fragment = rest[i + 1 ..];
        rest = rest[0..i];
    }

    var query: ?[]const u8 = null;
    if (std.mem.indexOfScalar(u8, rest, '?')) |i| {
        query = rest[i + 1 ..];
        rest = rest[0..i];
    }

    // The authority ends at the first "/". What follows is the path.
    var path: []const u8 = "/";
    var authority = rest;
    if (std.mem.indexOfScalar(u8, rest, '/')) |i| {
        authority = rest[0..i];
        path = rest[i..];
    }

    if (authority.len == 0 and !names_no_peer) return error.InvalidUrl;

    // Userinfo ends at the last "@", because a password may contain one.
    //
    // **The userinfo must then hold no "@" of its own.** See
    // `hasUnsafeUserinfoByte`: the last-"@" rule alone lets the text
    // before an inner "@" name one host while the text after it names
    // another, and only the second is dialed.
    var user: ?[]const u8 = null;
    var password: ?[]const u8 = null;
    var host: []const u8 = "";
    var named_port: ?u16 = null;
    if (authority.len > 0) {
        var hostport = authority;
        if (std.mem.lastIndexOfScalar(u8, authority, '@')) |i| {
            const userinfo = authority[0..i];
            if (hasUnsafeUserinfoByte(userinfo)) return error.InvalidUrl;
            hostport = authority[i + 1 ..];
            if (std.mem.indexOfScalar(u8, userinfo, ':')) |j| {
                user = userinfo[0..j];
                password = userinfo[j + 1 ..];
            } else {
                user = userinfo;
            }
        }
        const host_and_port = try splitHostPort(hostport);
        host = host_and_port.host;
        named_port = host_and_port.port;
    }

    // The path, the query, and the fragment keep their escapes, so a
    // protocol package writes them on the wire exactly as they read here.
    // A raw CR or LF in any of them therefore ends the request line and
    // starts a header of the url's choosing. A url comes from a person, a
    // lockfile, or a manifest, so that is a runtime fault and not an
    // assertion.
    //
    // The check lives here, not in one engine, because every protocol
    // package reads these fields and each would otherwise need the same
    // guard.
    //
    // The host gets the same rule, and it gets it here. `zurl-http` reads
    // an address through `std.Io.net.IpAddress.parse` and a name through
    // `std.Io.net.HostName.init`, and neither call is a guard this module
    // can lean on: the address parser accepts what an address holds and
    // says nothing about a control byte in a name. A `Host:` header
    // carries this text as plainly as a request line carries the path.
    if (hasUnsafeByte(host)) return error.InvalidUrl;
    if (hasUnsafeByte(path)) return error.InvalidUrl;
    if (query) |q| if (hasUnsafeByte(q)) return error.InvalidUrl;
    if (fragment) |f| if (hasUnsafeByte(f)) return error.InvalidUrl;

    // **Last, after every syntax rule above.** The url's own port wins.
    // Then the registry, where a null is an answer and not a gap: the
    // scheme names no peer, so the url gets no port. Then the built-in
    // table. A scheme no table names, with no port in the url, names a
    // protocol this build does not speak, and that is a different answer
    // from a url nobody can read: see `ParseError`.
    //
    // The order is curl's. `nosuch://host:99999/` and
    // `nosuch://exa mple.com/` each exit 3 there, and only
    // `nosuch://host/`, which breaks no syntax rule at all, exits 1.
    // Measured against curl 8.21.0.
    const port: ?u16 = if (named_port) |named|
        named
    else if (registered) |entry|
        entry.default_port
    else
        defaultPort(scheme) orelse return error.UnsupportedProtocol;

    return .{
        .scheme = scheme,
        .user = user,
        .password = password,
        .host = host,
        .port = port,
        .path = path,
        .query = query,
        .fragment = fragment,
    };
}

/// Whether `text` is a scheme, by the grammar RFC 3986 section 3.1 gives
/// one: a letter, and then any number of letters, digits, `+`, `-`, and
/// `.`.
///
/// **This decides which of the two `ParseError` members a bad url gets.**
/// A text that passes here names a protocol, so a build with no handler
/// for it reports `error.UnsupportedProtocol`, exit 1. A text that fails
/// here names nothing, so the url is malformed and reports
/// `error.InvalidUrl`, exit 3.
///
/// curl draws the line in the same place. `nosuch+x-1.y://host/` exits 1
/// and `nosuch_x://host/` exits 3, because an underscore is no scheme
/// byte and curl then reads the whole text as a host. Measured against
/// curl 8.21.0.
///
/// An empty text is not a scheme, so `://host/` is malformed.
pub fn isSchemeSyntax(text: []const u8) bool {
    if (text.len == 0) return false;
    if (!std.ascii.isAlphabetic(text[0])) return false;
    for (text[1..]) |byte| switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '+', '-', '.' => {},
        else => return false,
    };
    return true;
}

/// Whether `text` holds a byte that no part of a url may carry: a C0
/// control byte, a DEL, or a raw space.
///
/// RFC 3986 gives a URI no space at all, and a raw one splits the request
/// line the same way a CR does: `GET /a b HTTP/1.1 HTTP/1.1` reached a
/// peer from the url text `/a b HTTP/1.1`. curl percent-encodes a space
/// rather than send it, and `%20` still parses here, so a url that names a
/// resource with a space in its name still works.
///
/// This is the rule `parse` applies to the path, the query, and the
/// fragment. It is public because a redirect target does not reach `parse`
/// until it is resolved: `zurl-http` reads a `Location` header the server
/// wrote and must hold it to the same rule before the target goes on the
/// wire.
///
/// A percent escape is not a control byte here. `%0d` stays three
/// printable characters until something decodes it, and a request line
/// carries the escaped form.
pub fn hasUnsafeByte(text: []const u8) bool {
    for (text) |byte| switch (byte) {
        0x00...0x20, 0x7f => return true,
        else => {},
    };
    return false;
}

/// Whether `text` holds a byte that no userinfo may carry: a C0 control
/// byte, a raw space, a DEL, or an `@`.
///
/// **The `@` is the one that matters, and it is a safety rule.** RFC 3986
/// section 3.2.1 gives the userinfo `*( unreserved / pct-encoded /
/// sub-delims / ":" )`, and `@` is in none of those sets. The authority
/// splits at the **last** `@`, because a password may hold a `:` and the
/// grammar must still find the host. A raw `@` inside the userinfo
/// therefore makes one url name two hosts: `http://a@b:c@evil.test/` reads
/// to a person as a url for `b`, and the dial goes to `evil.test`. A
/// filter that reads the first name and a client that dials the second is
/// the whole shape of the attack.
///
/// The control bytes and the space get the same answer for the reason
/// `hasUnsafeByte` gives, plus one of their own: the userinfo sits before
/// the host in the text, so a raw LF there hides the host that follows it
/// from anything that reads a url a line at a time.
/// `http://target.test<LF>@evil.test/` dialed `evil.test`.
///
/// A percent escape is not a control byte here, and `%40` is not an `@`.
/// The text keeps its escapes, so `http://a%40b:c@host/` names the user
/// `a%40b` and the host `host`, which is what RFC 3986 asks for.
///
/// Measured against curl 8.21.0, which refuses the same set. A raw byte
/// sweep of `http://u<byte>v@target.test/` gives curl exit 3 for
/// 0x00 to 0x20, for 0x40, and for 0x7F, and exit 0 for every other byte.
pub fn hasUnsafeUserinfoByte(text: []const u8) bool {
    for (text) |byte| switch (byte) {
        0x00...0x20, '@', 0x7f => return true,
        else => {},
    };
    return false;
}

/// `host` with any IPv6 zone id taken off.
///
/// **A zone id never goes on the wire.** RFC 6874 section 3 says a zone id
/// names an interface of the local host and has no meaning to anybody
/// else, so it must not reach a `Host:` header. `Url.host` keeps it,
/// because the dial needs to see it and refuse a scope that zurl cannot
/// look up. Every writer of an authority calls this first.
///
/// A host with no `%` comes back unchanged, so a name pays one scan and
/// nothing else. `isIp6Authority` has already refused a `%` in a host that
/// is not an IPv6 literal, and `isRegisteredName` has refused one in a
/// name, so a `%` that reaches here opens a zone id and nothing else.
///
/// Measured against curl 8.21.0: `http://[fe80::1%25eth0]/` and
/// `http://[fe80::1%eth0]/` each send `Host: [fe80::1]`.
pub fn hostWithoutZone(host: []const u8) []const u8 {
    const i = std.mem.indexOfScalar(u8, host, '%') orelse return host;
    return host[0..i];
}

/// Whether `text` is a host name by the byte set curl 8.21.0 accepts.
///
/// The set is `-`, `.`, the digits, the letters, `_`, and `~`. Every other
/// byte is refused, and that includes the high bytes: curl hands a name
/// with one to its IDN library, and zurl has none, so a name zurl cannot
/// convert is refused rather than sent to a resolver as raw bytes.
///
/// **A `%` is refused, and that is stricter than curl.** curl
/// percent-decodes the host and then applies this same byte set, so
/// `http://tar%67et.test/` reaches `target.test` and
/// `http://target%2Etest/` reaches `target.test` too. `Url.host` borrows
/// from the url text and allocates nothing, so zurl has nowhere to put a
/// decoded host and cannot follow. Refusing is the safe half of that
/// choice: a url whose host reads as one name and dials another is exactly
/// what a filter cannot see, and `%2E` turns one label into two. A url
/// that needs no decoding is unaffected, and no host that zurl could reach
/// before becomes unreachable, because the undecoded text never named a
/// peer that answered.
///
/// Measured against curl 8.21.0 by a byte sweep of
/// `http://a%<hex>b.test/`, which gives exit 0 for 2D-2E, 30-39, 41-5A,
/// 5F, 61-7A, and 7E, and exit 3 for every other byte. curl also accepts a
/// decoded DEL, 0x7F; `hasUnsafeByte` refuses that one already and a DEL
/// in a name reaches no peer, so this set leaves it out.
fn isRegisteredName(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |byte| switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '-', '.', '_', '~' => {},
        else => return false,
    };
    // **One trailing dot is a root label, and two are nothing.**
    // `http://target.test./` names the same peer as `http://target.test/`,
    // and curl accepts it. `http://target.test../` holds an empty label at
    // the end, which no resolver can look up, and curl refuses it. So
    // drop one trailing dot and refuse what is left if it is empty or
    // still ends in a dot.
    //
    // Measured against curl 8.21.0: `a.` and `a.b.` and `..a` and `a...b`
    // exit 0, and `a..` and `.` and `...` and `a.b..` exit 3.
    var trimmed = text;
    if (trimmed[trimmed.len - 1] == '.') trimmed = trimmed[0 .. trimmed.len - 1];
    if (trimmed.len == 0) return false;
    if (trimmed[trimmed.len - 1] == '.') return false;
    return true;
}

/// Whether `text` is the inside of a bracketed authority: an IPv6 address,
/// and after it an optional zone id.
///
/// **The brackets are a promise, and this is the check that keeps it.** An
/// authority writes brackets only around an IPv6 literal, because the
/// brackets are what tell the colons inside the address apart from the
/// colon before a port. zurl read anything at all between them, so
/// `http://[127.0.0.1]/` and `http://[zzz]/` each dialed a peer that the
/// url never named as a name. curl refuses both.
///
/// The address half goes through `std.Io.net.IpAddress.parseIp6`, so the
/// grammar is the one a dial uses and not a second reading of RFC 4291.
/// A dotted IPv4 tail is part of that grammar, so `[::ffff:1.2.3.4]`
/// passes.
///
/// The zone half is RFC 6874. curl takes both spellings, the escaped
/// `%25eth0` and the raw `%eth0`, and refuses an empty one. A reader that
/// writes this host into a `Host:` header must drop the zone: RFC 6874
/// section 3 says a zone id is for the local host alone and never goes on
/// the wire. `zurl_http.h1.writeHost` does that.
///
/// Measured against curl 8.21.0: `[::1]`, `[fe80::1%25eth0]`,
/// `[fe80::1%eth0]`, and `[::ffff:1.2.3.4]` exit 0, and `[1:2]`,
/// `[1.2.3.4]`, `[zzz]`, `[gggg::1]`, `[:::]`, `[1:2:3:4:5:6:7:8:9]`,
/// `[]`, and `[fe80::1%25]` exit 3.
fn isIp6Authority(text: []const u8) bool {
    var address = text;
    if (std.mem.indexOfScalar(u8, text, '%')) |i| {
        address = text[0..i];
        var zone = text[i + 1 ..];
        // The escaped spelling carries the `%` of the zone as `%25`, so
        // what follows the first `%` starts with `25`.
        if (std.mem.startsWith(u8, zone, "25")) zone = zone[2..];
        if (zone.len == 0) return false;
        if (!isRegisteredName(zone)) return false;
    }
    if (address.len == 0) return false;
    _ = std.Io.net.IpAddress.parseIp6(address, 0) catch return false;
    return true;
}

/// Whether `text` holds a C0 control byte, which is any byte below 0x20.
///
/// **This is the rule for text a protocol package has already decoded.**
/// `hasUnsafeByte` reads a url as the url writes it, where `%0d` is three
/// printable characters. A package that percent-decodes a part of the url
/// and then writes the result on the wire holds the bytes the escapes
/// stood for, and the check has to run again on those bytes. `zurl-dict`
/// is such a package: it decodes the path and then writes the word into an
/// RFC 2229 command line.
///
/// A space and a DEL pass here, and `hasUnsafeByte` refuses both. A
/// decoded word may hold either one: RFC 2229 gives a client a backslash
/// escape for each, and curl 8.21.0 sends `dict://h/d:a%20b` as
/// `DEFINE ! a\ b` and `dict://h/d:a%7fb` as `DEFINE ! a\<DEL>`. Measured.
/// A byte below 0x20 has no such escape that a line-oriented protocol can
/// trust, so it is refused rather than escaped.
///
/// curl refuses the same set for the same protocol: `dict://h/d:a%09b` and
/// `dict://h/d:a%0d%0aQUIT` both exit 3, `URL using bad/illegal format`.
/// Measured.
pub fn hasControlByte(text: []const u8) bool {
    for (text) |byte| {
        if (byte < 0x20) return true;
    }
    return false;
}

/// Whether `text` holds a byte that can forge structure in a request: a
/// NUL, a CR, or an LF.
///
/// **This is the narrow rule, for a package that must pass a byte
/// `hasControlByte` refuses.** A gopher request is one line, and a type 7
/// search sends the selector, a TAB, and the search words, so a TAB is
/// data there and must go through. Only the three bytes here can end a
/// line early or end a NUL-terminated field early, so only those three are
/// refused.
///
/// `zurl-gopher` and `zurl-tftp` both read this. A gopher selector ends at
/// a CR or an LF, and a TFTP filename ends at a NUL, so each of the three
/// bytes forges a boundary in at least one of the two.
///
/// This is stricter than curl. curl 8.21.0 sends `gopher://h/1a%0d%0ab`
/// as `<CR><LF>b<CR><LF>`, and `tftp://h/a%0d%0ab` as a filename holding a
/// CR and an LF. Measured. curl does refuse a NUL in either:
/// `tftp://h/a%00b` exits 3.
pub fn hasFramingByte(text: []const u8) bool {
    for (text) |byte| switch (byte) {
        0x00, '\r', '\n' => return true,
        else => {},
    };
    return false;
}

/// Splits "host", "host:port", "[v6]", or "[v6]:port".
///
/// Both halves are checked here and not by the caller. A host goes through
/// `isIp6Authority` when the text carries brackets and through
/// `isRegisteredName` when it does not, so a text that is neither an
/// address nor a name never reaches a dial.
fn splitHostPort(text: []const u8) ParseError!struct { host: []const u8, port: ?u16 } {
    if (text.len == 0) return error.InvalidUrl;

    if (text[0] == '[') {
        const close = std.mem.indexOfScalar(u8, text, ']') orelse return error.InvalidUrl;
        const host = text[1..close];
        if (!isIp6Authority(host)) return error.InvalidUrl;
        const after = text[close + 1 ..];
        if (after.len == 0) return .{ .host = host, .port = null };
        if (after[0] != ':') return error.InvalidUrl;
        return .{ .host = host, .port = try parsePort(after[1..]) };
    }

    if (std.mem.indexOfScalar(u8, text, ':')) |i| {
        const host = text[0..i];
        if (!isRegisteredName(host)) return error.InvalidUrl;
        return .{ .host = host, .port = try parsePort(text[i + 1 ..]) };
    }

    if (!isRegisteredName(text)) return error.InvalidUrl;
    return .{ .host = text, .port = null };
}

/// The port an authority names, or null when it names none.
///
/// **Decimal digits and nothing else.** `std.fmt.parseInt` is not the
/// check this needs: it takes a leading `+` and it takes `_` between
/// digits, so `http://host:+80/` and `http://host:8_0/` both dialed port
/// 80 and curl refuses both. A port on the wire is what a peer answers on,
/// so a text a person cannot read as a number must not become one.
///
/// An empty port is the default port of the scheme, not a fault. curl
/// reads `http://target.test:/` as port 80, measured, and the caller
/// supplies the default when this returns null. `http://http://host/`
/// reaches the same path: its authority is `http:`, so the host is `http`
/// and the port is the default, which is what curl does with it too.
///
/// Leading zeros are kept and the value must still fit: curl takes
/// `:0000065535` as 65535 and refuses `:099999`. That is what a `u16`
/// parse of the digits gives, so the bound needs no line of its own.
fn parsePort(text: []const u8) ParseError!?u16 {
    if (text.len == 0) return null;
    for (text) |byte| {
        if (!std.ascii.isDigit(byte)) return error.InvalidUrl;
    }
    return std.fmt.parseInt(u16, text, 10) catch error.InvalidUrl;
}

pub const DecodeError = error{ InvalidEscape, NoSpaceLeft };

/// Writes the percent-decoded form of `text` into `out` and returns the part
/// of `out` that holds it.
///
/// The decoded form is never longer than `text`, so an `out` as long as `text`
/// is always enough.
pub fn percentDecode(out: []u8, text: []const u8) DecodeError![]u8 {
    var written: usize = 0;
    var i: usize = 0;
    while (i < text.len) {
        const byte = text[i];
        if (byte != '%') {
            if (written == out.len) return error.NoSpaceLeft;
            out[written] = byte;
            written += 1;
            i += 1;
            continue;
        }
        if (i + 2 >= text.len) return error.InvalidEscape;
        const high = std.fmt.charToDigit(text[i + 1], 16) catch return error.InvalidEscape;
        const low = std.fmt.charToDigit(text[i + 2], 16) catch return error.InvalidEscape;
        if (written == out.len) return error.NoSpaceLeft;
        out[written] = @as(u8, high) * 16 + low;
        written += 1;
        i += 3;
    }
    return out[0..written];
}

test "parse reads every part of a full URL" {
    const u = try parse("https://bob:secret@example.com:8443/a/b?q=1#top");
    try std.testing.expectEqualStrings("https", u.scheme);
    try std.testing.expectEqualStrings("bob", u.user.?);
    try std.testing.expectEqualStrings("secret", u.password.?);
    try std.testing.expectEqualStrings("example.com", u.host);
    try std.testing.expectEqual(@as(?u16, 8443), u.port);
    try std.testing.expectEqualStrings("/a/b", u.path);
    try std.testing.expectEqualStrings("q=1", u.query.?);
    try std.testing.expectEqualStrings("top", u.fragment.?);
}

test "a URL with no scheme becomes http, as curl does" {
    const u = try parse("example.com/a");
    try std.testing.expectEqualStrings("http", u.scheme);
    try std.testing.expectEqual(@as(?u16, 80), u.port);
    try std.testing.expectEqualStrings("example.com", u.host);
    try std.testing.expectEqualStrings("/a", u.path);
}

test "a host that starts with ftp. becomes ftp, as curl does" {
    const u = try parse("ftp.example.com/a");
    try std.testing.expectEqualStrings("ftp", u.scheme);
    try std.testing.expectEqual(@as(?u16, 21), u.port);
}

test "--proto-default replaces the guess for a url with no scheme" {
    // Measured against curl 8.21.0, which prepends `scheme://` to the url
    // text and so never runs its own guess either:
    //
    //   curl ftp.gnu.org/                        reaches ftp://ftp.gnu.org/
    //   curl --proto-default http ftp.gnu.org/   reaches http://ftp.gnu.org/
    const guessed = try parseWithDefault("ftp.example.com/a", &Schemes.empty, null);
    try std.testing.expectEqualStrings("ftp", guessed.scheme);

    const named = try parseWithDefault("ftp.example.com/a", &Schemes.empty, "http");
    try std.testing.expectEqualStrings("http", named.scheme);
    try std.testing.expectEqual(@as(?u16, 80), named.port);

    const secure = try parseWithDefault("example.com/a", &Schemes.empty, "https");
    try std.testing.expectEqualStrings("https", secure.scheme);
    try std.testing.expectEqual(@as(?u16, 443), secure.port);
}

test "a url that spells its own scheme ignores --proto-default" {
    const u = try parseWithDefault("http://example.com/a", &Schemes.empty, "https");
    try std.testing.expectEqualStrings("http", u.scheme);
    try std.testing.expectEqual(@as(?u16, 80), u.port);
}

test "--proto-default file reads an absolute path as a file url" {
    // curl does the same: `curl --proto-default file /etc/hostname`
    // prints the file, measured. The scheme has to be registered for the
    // empty authority to be legal, which is `file`'s own shape.
    var schemes: Schemes = .empty;
    try schemes.add(.{ .name = "file", .default_port = null });

    const u = try parseWithDefault("/tmp/secret.txt", &schemes, "file");
    try std.testing.expectEqualStrings("file", u.scheme);
    try std.testing.expectEqualStrings("", u.host);
    try std.testing.expectEqual(@as(?u16, null), u.port);
    try std.testing.expectEqualStrings("/tmp/secret.txt", u.path);

    // And with no flag the same text has no host and no scheme that
    // permits one, so it is refused. curl refuses it too, with
    // `No host part in the URL`.
    try std.testing.expectError(
        error.InvalidUrl,
        parseWithDefault("/tmp/secret.txt", &schemes, null),
    );
}

test "a URL with no path gets a root path" {
    const u = try parse("https://example.com");
    try std.testing.expectEqualStrings("/", u.path);
    try std.testing.expectEqual(@as(?u16, 443), u.port);
}

test "a user with no password parses" {
    const u = try parse("https://bob@example.com/");
    try std.testing.expectEqualStrings("bob", u.user.?);
    try std.testing.expectEqual(@as(?[]const u8, null), u.password);
}

test "an IPv6 host keeps its brackets out of the host field" {
    const u = try parse("http://[::1]:8080/x");
    try std.testing.expectEqualStrings("::1", u.host);
    try std.testing.expectEqual(@as(?u16, 8080), u.port);

    // The brackets are the port marker and nothing else, so a literal
    // with no port keeps the default of its scheme.
    const bare = try parse("https://[2606:4700:4700::1111]/");
    try std.testing.expectEqualStrings("2606:4700:4700::1111", bare.host);
    try std.testing.expectEqual(@as(?u16, 443), bare.port);
    try std.testing.expectEqualStrings("/", bare.path);
}

test "an empty URL is a runtime fault, not an assertion" {
    try std.testing.expectError(error.InvalidUrl, parse(""));
}

test "a port that is not a number is a runtime fault" {
    try std.testing.expectError(error.InvalidUrl, parse("http://example.com:hello/"));
}

test "a port over 65535 is a runtime fault" {
    try std.testing.expectError(error.InvalidUrl, parse("http://example.com:70000/"));
}

test "defaultPort knows the schemes that P0 and later phases use" {
    try std.testing.expectEqual(@as(?u16, 80), defaultPort("http"));
    try std.testing.expectEqual(@as(?u16, 443), defaultPort("https"));
    try std.testing.expectEqual(@as(?u16, 21), defaultPort("ftp"));
    try std.testing.expectEqual(@as(?u16, null), defaultPort("gopher"));
}

test "an unregistered scheme with no port names an unsupported protocol" {
    // **The defect this closes.** The answer used to be
    // `error.InvalidUrl`, exit 3, so a script could not tell "zurl was
    // not built with that protocol" from "you typed a bad url". curl
    // 8.21.0 answers `rtmp://host.invalid/` with exit 1 and
    // `nosuchscheme://host.invalid/` with exit 1, measured.
    try std.testing.expectError(
        error.UnsupportedProtocol,
        parse("gopher://example.com/a"),
    );
    try std.testing.expectError(
        error.UnsupportedProtocol,
        parse("rtmp://host.invalid/"),
    );
    try std.testing.expectError(
        error.UnsupportedProtocol,
        parse("nosuchscheme://host.invalid/"),
    );
    // An explicit port is still enough, and always was.
    const with_port = try parse("gopher://example.com:70/a");
    try std.testing.expectEqual(@as(?u16, 70), with_port.port);
}

test "a malformed url is still malformed whatever its scheme is" {
    // The boundary the fix must not cross. Each of these breaks a syntax
    // rule, so each is exit 3 and never exit 1, whether or not this build
    // speaks the scheme. curl 8.21.0 answers every row with exit 3,
    // measured.
    const malformed = [_][]const u8{
        // An empty scheme names nothing.
        "://example.com/",
        // A scheme carrying a byte RFC 3986 does not give it.
        "nosuch_x://example.com/",
        "no such://example.com/",
        "1abc://example.com/",
        // A known scheme with an authority nobody can read.
        "http:///a",
        "http://example.com:hello/",
        "http://example.com:70000/",
        "http://exa mple.com/",
        // And the same three faults under a scheme nothing knows: the
        // syntax answers first, because that is the half a user can fix.
        "nosuch://",
        "nosuch://example.com:70000/",
        "nosuch://exa mple.com/",
        "nosuch://example.com/a b",
        "nosuch://example.com/a\r\nX: y",
    };
    for (malformed) |text| {
        try std.testing.expectError(error.InvalidUrl, parse(text));
    }
}

test "isSchemeSyntax draws RFC 3986's own line" {
    try std.testing.expect(isSchemeSyntax("http"));
    try std.testing.expect(isSchemeSyntax("HTTP"));
    try std.testing.expect(isSchemeSyntax("nosuch+x-1.y"));
    try std.testing.expect(isSchemeSyntax("a"));

    try std.testing.expect(!isSchemeSyntax(""));
    try std.testing.expect(!isSchemeSyntax("1abc"));
    try std.testing.expect(!isSchemeSyntax("no_such"));
    try std.testing.expect(!isSchemeSyntax("no such"));
    try std.testing.expect(!isSchemeSyntax("no/such"));
    try std.testing.expect(!isSchemeSyntax("+http"));
}

test "an unsupported scheme and a malformed url carry curl's two codes" {
    // The whole point of keeping them apart: a script branches on the
    // number, and 1 and 3 send a reader to two different places.
    const errors = @import("errors.zig");
    try std.testing.expectEqual(
        @as(u32, 1),
        errors.curlCode(error.UnsupportedProtocol),
    );
    try std.testing.expectEqual(@as(u32, 3), errors.curlCode(error.InvalidUrl));
}

test "a registered scheme parses like a built-in one" {
    var schemes: Schemes = .empty;
    try schemes.add(.{ .name = "gopher", .default_port = 70 });

    const u = try parseWith("gopher://example.com/a", &schemes);
    try std.testing.expectEqualStrings("gopher", u.scheme);
    try std.testing.expectEqualStrings("example.com", u.host);
    try std.testing.expectEqual(@as(?u16, 70), u.port);
    try std.testing.expectEqualStrings("/a", u.path);

    // A port the url names still wins over the registered default.
    const named = try parseWith("gopher://example.com:71/a", &schemes);
    try std.testing.expectEqual(@as(?u16, 71), named.port);
}

test "a scheme with no port is not the same answer as a scheme nobody knows" {
    // Both used to be `error.InvalidUrl`, which is why no third party
    // could register a protocol without writing a port into every url.
    var schemes: Schemes = .empty;
    try schemes.add(.{ .name = "file", .default_port = null });

    // No port at all: the url parses, and the port reads null.
    const u = try parseWith("file:///etc/hosts", &schemes);
    try std.testing.expectEqualStrings("file", u.scheme);
    try std.testing.expectEqualStrings("", u.host);
    try std.testing.expectEqual(@as(?u16, null), u.port);
    try std.testing.expectEqualStrings("/etc/hosts", u.path);

    // A host is still allowed, and so is a port the url names.
    const named_host = try parseWith("file://localhost/etc/hosts", &schemes);
    try std.testing.expectEqualStrings("localhost", named_host.host);
    try std.testing.expectEqual(@as(?u16, null), named_host.port);

    // Nobody knows this scheme: still a runtime fault, and still with an
    // empty host.
    try std.testing.expectError(error.InvalidUrl, parseWith("nosuch:///etc/hosts", &schemes));
    // The same url without the registry is the unknown-scheme answer too.
    try std.testing.expectError(error.InvalidUrl, parse("file:///etc/hosts"));
}

test "an empty host stays a runtime fault for a scheme that dials" {
    // A registered scheme with a port names a peer, so a url of it must
    // say which peer. Only a portless scheme may leave the host out.
    var schemes: Schemes = .empty;
    try schemes.add(.{ .name = "gopher", .default_port = 70 });
    try std.testing.expectError(error.InvalidUrl, parseWith("gopher:///a", &schemes));
    try std.testing.expectError(error.InvalidUrl, parse("http:///a"));
}

test "a registered scheme is read before the built-in table" {
    var schemes: Schemes = .empty;
    try schemes.add(.{ .name = "http", .default_port = 8080 });
    const u = try parseWith("http://example.com/a", &schemes);
    try std.testing.expectEqual(@as(?u16, 8080), u.port);
    // The built-in table itself is unchanged for every other caller.
    try std.testing.expectEqual(@as(?u16, 80), defaultPort("http"));
    try std.testing.expectEqual(@as(?u16, 80), (try parse("http://example.com/a")).port);
}

test "a registered scheme matches without regard to case, per RFC 3986" {
    var schemes: Schemes = .empty;
    try schemes.add(.{ .name = "file", .default_port = null });
    const u = try parseWith("FILE:///etc/hosts", &schemes);
    try std.testing.expectEqual(@as(?u16, null), u.port);
    try std.testing.expectEqualStrings("/etc/hosts", u.path);
}

test "a registry that is full refuses the next scheme and keeps what it holds" {
    // The bound is the whole point of a fixed array. A caller learns at
    // the call that its protocol is not registered, rather than at the
    // first url that will not parse.
    var schemes: Schemes = .empty;
    var i: usize = 0;
    var name_storage: [Schemes.max][8]u8 = undefined;
    while (i < Schemes.max) : (i += 1) {
        const name = try std.fmt.bufPrint(&name_storage[i], "s{d}", .{i});
        try schemes.add(.{ .name = name, .default_port = null });
    }
    try std.testing.expectError(error.TooManySchemes, schemes.add(.{
        .name = "one-too-many",
        .default_port = null,
    }));
    try std.testing.expectEqual(Schemes.max, schemes.len);
    // Every row added before the refusal still answers.
    try std.testing.expectEqualStrings("s0", schemes.find("s0").?.name);
    try std.testing.expectEqual(@as(?Scheme, null), schemes.find("one-too-many"));
}

test "a url of a registered scheme keeps the control-byte rules" {
    // The hook adds a scheme. It adds no exception to the rules every
    // other url is held to.
    var schemes: Schemes = .empty;
    try schemes.add(.{ .name = "file", .default_port = null });
    try std.testing.expectError(error.InvalidUrl, parseWith("file:///a\r\nX: y", &schemes));
    try std.testing.expectError(error.InvalidUrl, parseWith("file:///a b", &schemes));
    try std.testing.expectError(error.InvalidUrl, parseWith("file://ho st/a", &schemes));
}

test "percentDecode turns escapes back into bytes" {
    var buf: [32]u8 = undefined;
    const out = try percentDecode(&buf, "a%20b%2Fc");
    try std.testing.expectEqualStrings("a b/c", out);
}

test "percentDecode rejects a truncated escape" {
    var buf: [32]u8 = undefined;
    try std.testing.expectError(error.InvalidEscape, percentDecode(&buf, "a%2"));
}

test "percentDecode rejects a non-hex escape" {
    var buf: [32]u8 = undefined;
    try std.testing.expectError(error.InvalidEscape, percentDecode(&buf, "a%zz"));
}

test "a control byte in the path, the query, or the fragment is a runtime fault" {
    // A protocol package writes these three exactly as they read here, so
    // a raw CR or LF used to end the request line and start a header of
    // the url's choosing: "GET /a\r\nX-Path-Injected: yes HTTP/1.1" went
    // out as a request line plus an injected header.
    const controls = [_][]const u8{ "\r", "\n", "\r\n", "\x00" };
    var buf: [128]u8 = undefined;

    for (controls) |control| {
        const with_path = try std.fmt.bufPrint(
            &buf,
            "http://example.com/a{s}X-Path-Injected: yes",
            .{control},
        );
        try std.testing.expectError(error.InvalidUrl, parse(with_path));
    }
    for (controls) |control| {
        const with_query = try std.fmt.bufPrint(
            &buf,
            "http://example.com/a?q=1{s}X-Query-Injected: yes",
            .{control},
        );
        try std.testing.expectError(error.InvalidUrl, parse(with_query));
    }
    for (controls) |control| {
        const with_fragment = try std.fmt.bufPrint(
            &buf,
            "http://example.com/a#top{s}X-Fragment-Injected: yes",
            .{control},
        );
        try std.testing.expectError(error.InvalidUrl, parse(with_fragment));
    }
}

test "a raw space in the path, the query, or the fragment is a runtime fault" {
    // RFC 3986 gives a URI no space, and curl percent-encodes one rather
    // than send it. A raw space split the request line instead: the url
    // `http://127.0.0.1:33029/a b HTTP/1.1` reached the wire as
    // `GET /a b HTTP/1.1 HTTP/1.1`, so the url chose the version token.
    try std.testing.expectError(error.InvalidUrl, parse("http://example.com/a b HTTP/1.1"));
    try std.testing.expectError(error.InvalidUrl, parse("http://example.com/a?q=1 2"));
    try std.testing.expectError(error.InvalidUrl, parse("http://example.com/a#top 2"));
}

test "a raw at in the userinfo is a runtime fault, so one url names one host" {
    // **The divergence this rule closes.** The authority splits at the
    // last `@`, so the text before an inner `@` reads as a host and the
    // text after it is the host that gets dialed. Measured against curl
    // 8.21.0 through a loopback listener, reading the `Host:` line off
    // the wire:
    //
    // ```
    // http://a@b:c@evil.test/            curl exit 3, zurl reached evil.test
    // http://a@b@target.test/            curl exit 3, zurl reached target.test
    // http://a@b@target.test:80/         curl exit 3, zurl reached target.test
    // http://a@b@[::1]/                  curl exit 3, zurl reached ::1
    // http://target.test<LF>@evil.test/  curl exit 3, zurl reached evil.test
    // ```
    //
    // The last row is the worst of them: a reader that takes a url a line
    // at a time sees `http://target.test`, and the dial went to
    // `evil.test`.
    const rejected = [_][]const u8{
        "http://a@b:c@evil.test/",
        "http://a@b@target.test/",
        "http://a@b@target.test:80/",
        "http://a@b@[::1]/",
        "http://target.test\n@evil.test/",
        "http://a b@target.test/",
        "http://a\tb@target.test/",
        "http://a\x7fb@target.test/",
    };
    for (rejected) |text| {
        try std.testing.expectError(error.InvalidUrl, parse(text));
    }

    // The escaped form is not the raw byte, and it still parses. RFC 3986
    // gives the userinfo `pct-encoded`, so `%40` is a user named `@` and
    // never a separator.
    const escaped = try parse("http://a%40b:c@target.test/");
    try std.testing.expectEqualStrings("a%40b", escaped.user.?);
    try std.testing.expectEqualStrings("c", escaped.password.?);
    try std.testing.expectEqualStrings("target.test", escaped.host);
}

test "a host outside curl's byte set is a runtime fault" {
    // Measured against curl 8.21.0 by a byte sweep of
    // `http://a%<hex>b.test/`: exit 0 for `-`, `.`, the digits, the
    // letters, `_`, and `~`, and exit 3 for every other byte. Before this,
    // zurl accepted every one of these and put the text in a `Host:` line.
    const rejected = [_][]const u8{
        // A backslash is what a reader of a url may take for a separator.
        "http://target.test\\evil.test/",
        // A percent escape that decodes to a separator. curl decodes the
        // host and then refuses this one too.
        "http://target.test%2Fevil.test/",
        // Two trailing dots leave an empty label that no resolver reads.
        "http://target.test../",
        "http://.../",
        "http://./",
        "http://a.b../",
        // A high byte needs an IDN conversion that this build has not.
        "http://targ\xc3\xa9t.test/",
    };
    for (rejected) |text| {
        try std.testing.expectError(error.InvalidUrl, parse(text));
    }

    // One trailing dot is the root label and names the same peer. curl
    // accepts it, measured, and so do `..a` and `a...b`.
    const rooted = try parse("http://target.test./");
    try std.testing.expectEqualStrings("target.test.", rooted.host);
    _ = try parse("http://..target.test/");
    _ = try parse("http://a...b/");
    // An underscore is no resolver's friend, and curl takes it, so a url
    // that names such a host still parses here.
    _ = try parse("http://tar_get.test/");
}

test "a bracketed host must be an IPv6 address" {
    // **Brackets are a promise about what is inside them.** zurl read
    // anything at all, so `http://[127.0.0.1]/` dialed 127.0.0.1 and
    // `http://[zzz]/` dialed the name `zzz`, neither of which the url
    // named the way an authority names a host. curl 8.21.0 gives exit 3
    // for every row below, measured.
    const rejected = [_][]const u8{
        "http://[127.0.0.1]/",
        "http://[zzz]/",
        "http://[1:2]/",
        "http://[gggg::1]/",
        "http://[:::]/",
        "http://[1:2:3:4:5:6:7:8:9]/",
        "http://[]/",
        // An empty zone id names no interface.
        "http://[fe80::1%25]/",
    };
    for (rejected) |text| {
        try std.testing.expectError(error.InvalidUrl, parse(text));
    }

    // The addresses curl accepts still parse, brackets off, zone kept.
    const plain = try parse("http://[::1]:8080/");
    try std.testing.expectEqualStrings("::1", plain.host);
    try std.testing.expectEqual(@as(?u16, 8080), plain.port);

    const mapped = try parse("http://[::ffff:1.2.3.4]/");
    try std.testing.expectEqualStrings("::ffff:1.2.3.4", mapped.host);

    // Both spellings of a zone id, RFC 6874's `%25` and the raw `%`.
    const escaped_zone = try parse("http://[fe80::1%25eth0]/");
    try std.testing.expectEqualStrings("fe80::1%25eth0", escaped_zone.host);
    const raw_zone = try parse("http://[fe80::1%eth0]/");
    try std.testing.expectEqualStrings("fe80::1%eth0", raw_zone.host);
}

test "hostWithoutZone keeps a zone id off the wire" {
    // RFC 6874 section 3: a zone id names an interface of the local host
    // and means nothing to a peer. curl 8.21.0 sends `Host: [fe80::1]`
    // for both spellings, measured off a loopback listener, and zurl sent
    // the zone with it.
    try std.testing.expectEqualStrings("fe80::1", hostWithoutZone("fe80::1%25eth0"));
    try std.testing.expectEqualStrings("fe80::1", hostWithoutZone("fe80::1%eth0"));
    // A host with no zone pays one scan and comes back as it went in.
    try std.testing.expectEqualStrings("::1", hostWithoutZone("::1"));
    try std.testing.expectEqualStrings("example.com", hostWithoutZone("example.com"));
}

test "a port is decimal digits, and an empty one is the scheme's default" {
    // `std.fmt.parseInt` was the whole check, and it reads a leading `+`
    // and a `_` between digits. So `http://target.test:+80/` and
    // `http://target.test:8_0/` each dialed port 80, and curl 8.21.0
    // gives exit 3 for both. Measured by a byte sweep of
    // `http://target.test:8<byte>0/`, where curl takes a digit and the
    // four bytes that end an authority and nothing else.
    const rejected = [_][]const u8{
        "http://target.test:+80/",
        "http://target.test:8_0/",
        "http://target.test:-80/",
        "http://target.test:0x50/",
        "http://target.test:80a/",
        "http://target.test:65536/",
        "http://target.test:099999/",
    };
    for (rejected) |text| {
        try std.testing.expectError(error.InvalidUrl, parse(text));
    }

    // An empty port is the default port, which is what curl reads.
    // `http://target.test:/` reached port 80 there, measured.
    const empty = try parse("http://target.test:/");
    try std.testing.expectEqualStrings("target.test", empty.host);
    try std.testing.expectEqual(@as(?u16, 80), empty.port);

    // Leading zeros are digits, and the value must still fit a `u16`.
    // curl takes `:0000065535` as 65535, measured.
    const padded = try parse("http://target.test:0000065535/");
    try std.testing.expectEqual(@as(?u16, 65535), padded.port);
}

test "a scheme ends at a colon that a slash follows, and one slash is enough" {
    // **Reading only `://` put the host in the path.** Measured against
    // curl 8.21.0 off a loopback listener:
    //
    // ```
    // http:/target.test/   curl reached target.test, zurl reached `http`
    // http:/a/b/c          curl reached a, path /b/c
    // ```
    const one_slash = try parse("http:/target.test/");
    try std.testing.expectEqualStrings("http", one_slash.scheme);
    try std.testing.expectEqualStrings("target.test", one_slash.host);
    try std.testing.expectEqualStrings("/", one_slash.path);

    const split = try parse("http:/a/b/c");
    try std.testing.expectEqualStrings("a", split.host);
    try std.testing.expectEqualStrings("/b/c", split.path);

    // A colon with no slash after it opens a port and not a scheme, which
    // is how `target.test:8080/x` keeps its meaning. curl reads it the
    // same way, measured.
    const ported = try parse("target.test:8080/x");
    try std.testing.expectEqualStrings("http", ported.scheme);
    try std.testing.expectEqualStrings("target.test", ported.host);
    try std.testing.expectEqual(@as(?u16, 8080), ported.port);

    // A bad scheme byte before a slash is malformed and not unsupported,
    // the same answer `nosuch_x://host/` gets. curl gives exit 3 for
    // `ht_tp:/host/`, measured.
    try std.testing.expectError(error.InvalidUrl, parse("ht_tp:/target.test/"));
    // And a good scheme nobody speaks is exit 1 either way.
    try std.testing.expectError(error.UnsupportedProtocol, parse("nosuch:/target.test/"));
    // A scheme with a slash and nothing after it names no host.
    try std.testing.expectError(error.InvalidUrl, parse("http:/"));
    try std.testing.expectError(error.InvalidUrl, parse("http:x/"));
}

test "a colon in the path or the query is not the colon of a scheme" {
    // **The defect this rule exists for.** The scheme scan took the first
    // colon anywhere in the text, so a colon that belonged to the path or
    // to the query asked the scheme syntax check about the text in front
    // of it, and that text is a host and a path and never a scheme. Both
    // of these were `error.InvalidUrl`. curl 8.21.0 accepts both,
    // measured:
    //
    // ```
    // curl example.invalid/a:/b
    //     http://example.invalid/a:/b
    // curl 'example.invalid/go?to=https://other.example/'
    //     http://example.invalid/go?to=https://other.example/
    // ```
    const in_path = try parse("example.com/a:/b");
    try std.testing.expectEqualStrings("http", in_path.scheme);
    try std.testing.expectEqualStrings("example.com", in_path.host);
    try std.testing.expectEqualStrings("/a:/b", in_path.path);

    const in_query = try parse("example.com/go?to=https://other.example/");
    try std.testing.expectEqualStrings("http", in_query.scheme);
    try std.testing.expectEqualStrings("example.com", in_query.host);
    try std.testing.expectEqualStrings("/go", in_query.path);
    try std.testing.expectEqualStrings("to=https://other.example/", in_query.query.?);

    // A colon in the fragment reads the same way.
    const in_fragment = try parse("example.com/a#x://y");
    try std.testing.expectEqualStrings("http", in_fragment.scheme);
    try std.testing.expectEqualStrings("example.com", in_fragment.host);
    try std.testing.expectEqualStrings("x://y", in_fragment.fragment.?);

    // A url that spells a scheme still spells one, because that colon
    // comes in front of the first `/`. The path colon behind it changes
    // nothing.
    const spelled = try parse("https://example.com/a:/b");
    try std.testing.expectEqualStrings("https", spelled.scheme);
    try std.testing.expectEqualStrings("example.com", spelled.host);
    try std.testing.expectEqualStrings("/a:/b", spelled.path);

    // And a port still opens at a colon in front of the first `/`.
    const ported = try parse("example.com:8080/a:/b");
    try std.testing.expectEqualStrings("example.com", ported.host);
    try std.testing.expectEqual(@as(?u16, 8080), ported.port);
    try std.testing.expectEqualStrings("/a:/b", ported.path);
}

test "a file url takes its path from one slash and its authority from two" {
    // RFC 8089 gives a file url an authority only after `//`, so the `/`
    // of `file:/tmp/a` opens the path. curl 8.21.0 reads that url as the
    // file `/tmp/a`, measured, and zurl read the host `tmp` and the file
    // `/a`.
    //
    // `file` reaches the parser as a registered scheme with no port, the
    // way `zurl.Client.registerProtocol` adds it.
    var schemes: Schemes = .empty;
    try schemes.add(.{ .name = "file", .default_port = null });

    const one_slash = try parseWith("file:/tmp/a", &schemes);
    try std.testing.expectEqualStrings("file", one_slash.scheme);
    try std.testing.expectEqualStrings("", one_slash.host);
    try std.testing.expectEqualStrings("/tmp/a", one_slash.path);

    const three_slash = try parseWith("file:///tmp/a", &schemes);
    try std.testing.expectEqualStrings("", three_slash.host);
    try std.testing.expectEqualStrings("/tmp/a", three_slash.path);

    // Two slashes still name an authority, which is how
    // `file://localhost/tmp/a` keeps working.
    const named = try parseWith("file://localhost/tmp/a", &schemes);
    try std.testing.expectEqualStrings("localhost", named.host);
    try std.testing.expectEqualStrings("/tmp/a", named.path);
}

test "a raw space or a control byte in the host is a runtime fault" {
    // This module owns the rule. The HTTP engine reads an address before
    // it reads a name, so a name check is no longer the guard that stops
    // these, and a `Host:` header carries this text as plainly as a
    // request line carries the path.
    const rejected = [_][]const u8{
        "http://exa mple.com/",
        "http://exa\r\nmple.com/",
        "http://exa\nmple.com/",
        "http://exa\x00mple.com/",
        "http://exa mple.com:8080/",
    };
    for (rejected) |text| {
        try std.testing.expectError(error.InvalidUrl, parse(text));
    }
}

test "a percent escape of a space still parses and stays escaped" {
    // curl encodes a space rather than refuse the url. `%20` is three
    // printable characters on the wire, and the request line carries them
    // as they read here.
    const u = try parse("http://example.com/a%20b?q=x%20y#f%20g");
    try std.testing.expectEqualStrings("/a%20b", u.path);
    try std.testing.expectEqualStrings("q=x%20y", u.query.?);
    try std.testing.expectEqualStrings("f%20g", u.fragment.?);
}

test "a percent escape of a control byte still parses" {
    // `%0d` is three printable characters on the wire. Rejecting it would
    // refuse a url that names a real resource, and the escaped form never
    // ends a request line.
    const u = try parse("http://example.com/a%0db?q=%0a#f%00");
    try std.testing.expectEqualStrings("/a%0db", u.path);
    try std.testing.expectEqualStrings("q=%0a", u.query.?);
    try std.testing.expectEqualStrings("f%00", u.fragment.?);
}

test "hasControlByte reads the bytes a decode produced, not the escapes" {
    // The escaped form passes, because it is printable text.
    try std.testing.expect(!hasControlByte("a%0db"));
    // The decoded form does not. This is the pair that matters: a package
    // that decodes and then writes must ask again after the decode.
    try std.testing.expect(hasControlByte("a\rb"));
    try std.testing.expect(hasControlByte("a\nb"));
    try std.testing.expect(hasControlByte("a\tb"));
    try std.testing.expect(hasControlByte("a\x00b"));
    try std.testing.expect(hasControlByte("\x1f"));

    // A space and a DEL pass. RFC 2229 gives a backslash escape for each,
    // and curl 8.21.0 sends both. See the doc comment.
    try std.testing.expect(!hasControlByte("a b"));
    try std.testing.expect(!hasControlByte("a\x7fb"));
    try std.testing.expect(!hasControlByte(""));
    try std.testing.expect(!hasControlByte("hello"));
}

test "hasFramingByte refuses only the three bytes that forge a boundary" {
    try std.testing.expect(hasFramingByte("a\rb"));
    try std.testing.expect(hasFramingByte("a\nb"));
    try std.testing.expect(hasFramingByte("a\x00b"));

    // A TAB passes, and it must: a gopher type 7 request is the selector,
    // a TAB, and the search words, so refusing a TAB would refuse every
    // search.
    try std.testing.expect(!hasFramingByte("selector\tterm"));
    try std.testing.expect(!hasFramingByte("a b"));
    try std.testing.expect(!hasFramingByte("a\x1fb"));
    try std.testing.expect(!hasFramingByte(""));
}

test "the framing rule is narrower than the control rule" {
    // Every framing byte is a control byte, and not every control byte
    // is a framing byte. A package that reads the wrong one of the two
    // either refuses a legal request or lets a forged one through, so
    // the relation is written down here.
    for (0..0x20) |byte| {
        const one = [_]u8{@intCast(byte)};
        try std.testing.expect(hasControlByte(&one));
        if (hasFramingByte(&one)) {
            try std.testing.expect(byte == 0x00 or byte == '\r' or byte == '\n');
        }
    }
}
