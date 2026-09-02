//! The cookie jar: what a transfer sends, what a response adds to it, and
//! the Netscape file it is read from and written to.
//!
//! **This is a credential store.** A cookie is a bearer token: whoever
//! holds one is the session it names. So this file never writes a cookie
//! value to a log, to a diagnostic, or to any stream but the jar file the
//! user named, and `deinit` wipes every buffer before it frees it.
//!
//! **The jar lives in the library and not in the CLI.** A library caller
//! needs cookies for the same reason the command line does: two requests
//! in one program, the first setting a session and the second using it.
//! `src/cli` fills a `Jar` from `-b`, `-c`, and `-j`, and does nothing
//! else with it.
//!
//! **Every rule lives in `zurl_core.cookie`.** This file holds memory, a
//! file, and a lock. It decides nothing about which host may set which
//! domain or which request carries which cookie, so those rules have one
//! home and one set of tests.
//!
//! **The engine asks once for each hop.** `interface` builds the
//! `zurl_http.engine.CookieJar` that `zurl-http` calls, and the engine
//! calls `send` again for every hop of a redirect chain with that hop's
//! own url. That is what keeps a cookie of the first host off the second
//! host, and what lets a cookie survive a redirect that stays on one host.
//! See `zurl_http.engine.CookieJar` for the whole of that seam.
//!
//! **A jar file is untrusted input.** It may come from another program,
//! from a shared directory, or from whoever could write one file. So the
//! reader bounds the file size, the line count, the cookie count, and
//! every field, and a line it cannot read is dropped and counted rather
//! than guessed at. `Report` carries those counts out, because recovery is
//! never silent.

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_http = @import("zurl-http");

const cookie = zurl_core.cookie;
const Url = zurl_core.Url;
const Io = std.Io;
const Allocator = std.mem.Allocator;

const Jar = @This();

/// How many cookies one jar keeps.
///
/// curl 8.21.0 keeps 300, in its own `MAX_COOKIES`, and zurl keeps the
/// same number so a jar that moves between the two programs does not lose
/// cookies at one end alone. A cookie past this bound is refused and
/// counted: the jar never drops one it already holds to make room, because
/// the cookie it dropped could be the session and the one it took could be
/// a server filling the store on purpose.
pub const cookies_max: usize = 300;

/// The largest jar file this build reads, in bytes.
///
/// 300 cookies of the largest shape `zurl_core.cookie` allows come to
/// about 1.7 MiB, so this bound cannot refuse a jar that zurl itself
/// wrote. A file past it is refused whole: a jar read in part could drop
/// the very cookie the transfer needs and say nothing.
pub const file_len_max: usize = 2 * 1024 * 1024;

/// How many lines of a jar file this build reads.
///
/// A file of `cookies_max` cookies has `cookies_max` lines and four of
/// header, so this is generous by a factor of thirty. It bounds the scan
/// of a file made of nothing but empty lines, which `file_len_max` alone
/// would leave at a million rounds.
pub const lines_max: usize = 10_000;

/// What one load, or one run of stores, dropped and why.
///
/// **Recovery is never silent.** A transfer that sent half its cookies
/// must not look like one that sent them all, so every refusal is counted
/// here and `src/cli` writes one line when any count is not zero.
///
/// No field of this names a cookie. A count says a cookie was dropped. The
/// value stays in the jar and out of every message.
pub const Report = struct {
    /// Lines of a jar file, or `Set-Cookie` headers, that did not read as
    /// a cookie at all.
    malformed: usize = 0,
    /// Cookies refused because a response does not control the domain it
    /// named. This is the count that matters: it is one host trying to set
    /// a cookie for another.
    domain_refused: usize = 0,
    /// Cookies refused because the jar already holds `cookies_max`.
    overflow: usize = 0,
    /// Session cookies dropped because `-j` asked for it.
    junked: usize = 0,
    /// Cookies dropped because they had already expired.
    expired: usize = 0,
    /// Cookies left out of a `Cookie` header because the header reached
    /// `zurl_core.cookie.header_len_max`.
    header_full: usize = 0,
    /// Cookies a cleartext hop tried to write over a `Secure` cookie, and
    /// `Secure` cookies a cleartext hop tried to delete.
    ///
    /// RFC 6265bis section 8.6 calls this cookie forcing. It is the count
    /// that says an attacker tried to reach an `https` session from an
    /// `http` one.
    secure_refused: usize = 0,
    /// Whether a jar file stopped at `file_len_max` or at `lines_max`.
    file_truncated: bool = false,

    /// Whether anything at all was dropped.
    pub fn lostAnything(r: Report) bool {
        return r.malformed != 0 or r.domain_refused != 0 or r.overflow != 0 or
            r.expired != 0 or r.header_full != 0 or r.secure_refused != 0 or
            r.file_truncated;
    }
};

/// One cookie, with every field owned by this jar.
const Cookie = struct {
    name: []u8,
    value: []u8,
    /// Lower case, with no leading dot. `zurl_core.cookie` compares
    /// domains without regard to case anyway. Storing one case keeps the
    /// jar file stable from one run to the next.
    domain: []u8,
    path: []u8,
    host_only: bool,
    secure: bool,
    http_only: bool,
    /// Null for a session cookie, which lasts as long as this jar does.
    expires: ?i64,
    /// Which cookie this is in the order they arrived. RFC 6265 section
    /// 5.4 orders a `Cookie` header by this after it orders by path, and
    /// a replaced cookie keeps the number it had.
    created: u64,

    fn free(c: *Cookie, allocator: Allocator) void {
        // Wiped before it goes back to the allocator. A freed buffer keeps
        // its bytes until something else takes the block, and a session
        // token left there is a token a later allocation can read.
        @memset(c.name, 0);
        @memset(c.value, 0);
        @memset(c.domain, 0);
        @memset(c.path, 0);
        allocator.free(c.name);
        allocator.free(c.value);
        allocator.free(c.domain);
        allocator.free(c.path);
    }
};

allocator: Allocator,
io: Io,
cookies: std.ArrayList(Cookie),
/// The next value for `Cookie.created`.
sequence: u64,
/// `-j`: drop every session cookie a jar file holds, rather than load it.
///
/// Measured against curl 8.21.0: `-b jar -j` sent only the cookies of the
/// file that carried an expiry, and `-c` after it wrote only those. So the
/// flag acts on the load and not on the send: a session cookie a **server**
/// sets during the run is kept and sent.
junk_session_cookies: bool,
report: Report,
/// Guards every field above while `-Z` runs several transfers at once.
///
/// Each transfer has a `Client` of its own, and they share one jar,
/// because a cookie a server sets on one url belongs to the run and not to
/// the worker that happened to fetch it. The two hooks are the only
/// callers, and each holds this for one short critical section, so nothing
/// here can deadlock against the lock that guards the two output streams.
lock: Io.Mutex,

/// A new jar with no cookie in it.
///
/// `io` is kept for the clock and for the lock. Nothing here opens a file
/// until `load` or `save` is called.
pub fn init(allocator: Allocator, io: Io) Jar {
    return .{
        .allocator = allocator,
        .io = io,
        .cookies = .empty,
        .sequence = 0,
        .junk_session_cookies = false,
        .report = .{},
        .lock = .init,
    };
}

/// Frees every cookie, after wiping the bytes of each one.
pub fn deinit(jar: *Jar) void {
    for (jar.cookies.items) |*c| c.free(jar.allocator);
    jar.cookies.deinit(jar.allocator);
    jar.* = undefined;
}

/// The time now, in seconds since the epoch.
///
/// Read from `Io` on every call rather than kept from `init`, because a
/// long run would otherwise resolve a `Max-Age` against a clock reading
/// from the start of it. The call blocks on nothing and cannot be
/// canceled.
pub fn nowSeconds(jar: *const Jar) i64 {
    const timestamp = Io.Timestamp.now(jar.io, .real);
    return @intCast(@divFloor(timestamp.nanoseconds, std.time.ns_per_s));
}

/// The `zurl_http.engine.CookieJar` the engine calls.
///
/// The engine calls `send` once for each hop and `receive` once for each
/// `Set-Cookie` of each hop. `jar` must outlive every transfer that
/// carries this interface.
pub fn interface(jar: *Jar) zurl_http.engine.CookieJar {
    return .{ .ptr = jar, .send = sendImpl, .receive = receiveImpl };
}

fn sendImpl(ptr: *anyopaque, url: Url, out: []u8) ?[]const u8 {
    const jar: *Jar = @ptrCast(@alignCast(ptr));
    jar.lock.lockUncancelable(jar.io);
    defer jar.lock.unlock(jar.io);
    return jar.headerFor(url, jar.nowSeconds(), out);
}

fn receiveImpl(ptr: *anyopaque, url: Url, set_cookie: []const u8) void {
    const jar: *Jar = @ptrCast(@alignCast(ptr));
    jar.lock.lockUncancelable(jar.io);
    defer jar.lock.unlock(jar.io);
    jar.store(url, set_cookie, jar.nowSeconds());
}

/// Whether `c` has stopped being valid at `now`.
fn expired(c: Cookie, now: i64) bool {
    const when = c.expires orelse return false;
    return when <= now;
}

/// Whether a request for `url` carries `c`.
///
/// The four rules, and every one of them from `zurl_core.cookie`: the
/// domain, the path, the expiry, and `Secure`. A cookie has to pass all
/// four.
fn matches(c: Cookie, url: Url, now: i64) bool {
    if (expired(c, now)) return false;
    if (!cookie.domainMatches(url.host, c.domain, c.host_only)) return false;
    if (!cookie.pathMatches(url.path, c.path)) return false;
    // **A `Secure` cookie never crosses a cleartext hop.** The server said
    // this cookie is only for a connection nobody else can read, and a
    // plain `http` hop is not one. See `zurl_core.cookie.secureContext`
    // for the loopback exception curl also makes.
    if (c.secure and !cookie.secureContext(url.scheme, url.host)) return false;
    return true;
}

/// Orders two cookies for a `Cookie` header.
///
/// RFC 6265 section 5.4: the longer path comes first, and cookies of one
/// path length go in the order they arrived. A server that reads only the
/// first cookie of a name then reads the more specific one, which is the
/// whole reason for the rule.
fn beforeInHeader(jar: *const Jar, left: usize, right: usize) bool {
    const a = jar.cookies.items[left];
    const b = jar.cookies.items[right];
    if (a.path.len != b.path.len) return a.path.len > b.path.len;
    return a.created < b.created;
}

/// Writes the `Cookie` header value for `url` into `out`, and returns what
/// it wrote. Null when no cookie in this jar goes to `url`.
///
/// `out` must be at least `zurl_core.cookie.header_len_max` bytes, which is
/// the bound the engine sizes its buffer to.
///
/// A jar that matches more cookies than fit stops at the bound and counts
/// the rest in `report.header_full`. Nothing is cut in half: a `name=value`
/// either goes out whole or does not go out.
///
/// **A write that fails all the same rewinds and counts.** `Io.Writer`
/// over a fixed buffer copies what fits before it answers
/// `error.WriteFailed`, so a bound that was measured wrongly would leave
/// half a cookie in the header and hand it to a server. The write used to
/// answer that with `catch unreachable`, which is a panic in a test build
/// and undefined behaviour in the `ReleaseFast` and `ReleaseSmall` builds
/// that ship. A short write is not programmer error in the sense
/// IronStyle asserts on, so it is recovered from: the header goes back to
/// the length it had, `report.header_full` counts the cookie, and the
/// transfer carries on.
pub fn headerFor(jar: *Jar, url: Url, now: i64, out: []u8) ?[]const u8 {
    const bound = @min(out.len, cookie.header_len_max);

    // Bounded by `cookies_max`, so this list never grows and the sort
    // below never allocates.
    var order: [cookies_max]u16 = undefined;
    var matched: usize = 0;
    for (jar.cookies.items, 0..) |c, index| {
        if (matched == order.len) break;
        if (!matches(c, url, now)) continue;
        order[matched] = @intCast(index);
        matched += 1;
    }
    if (matched == 0) return null;

    std.mem.sort(u16, order[0..matched], jar, struct {
        fn lessThan(context: *Jar, a: u16, b: u16) bool {
            return beforeInHeader(context, a, b);
        }
    }.lessThan);

    var writer: Io.Writer = .fixed(out[0..bound]);
    var written: usize = 0;
    for (order[0..matched]) |index| {
        const c = jar.cookies.items[index];
        // Measured on the wire against curl 8.21.0: `Cookie: a=1; b=2`,
        // one separator of a semicolon and a space.
        const separator: []const u8 = if (written == 0) "" else "; ";
        const need = separator.len + c.name.len + 1 + c.value.len;
        if (writer.end + need > bound) {
            jar.report.header_full += 1;
            continue;
        }
        // Where the header ends before this cookie, so a write that runs
        // out of room can put it back. See the doc comment: a fixed
        // writer copies what fits before it answers, so the rewind is
        // what keeps the promise that no `name=value` goes out in half.
        const before = writer.end;
        appendPair(&writer, separator, c.name, c.value) catch {
            writer.end = before;
            jar.report.header_full += 1;
            continue;
        };
        written += 1;
    }
    if (written == 0) return null;
    return writer.buffered();
}

/// Writes one `separator`, `name`, `=`, `value` group into `out`.
///
/// One function for the four writes, so a caller that must undo a short
/// write has one place to catch it. `error.WriteFailed` is the only fault
/// a fixed writer answers, and it means the buffer ran out.
fn appendPair(
    out: *Io.Writer,
    separator: []const u8,
    name: []const u8,
    value: []const u8,
) Io.Writer.Error!void {
    try out.writeAll(separator);
    try out.writeAll(name);
    try out.writeByte('=');
    try out.writeAll(value);
}

/// Takes one `Set-Cookie` header value that arrived on `url`.
///
/// Every rule comes from `zurl_core.cookie`, and this counts what each one
/// refused. A header that does not become a cookie is not a failed
/// transfer: curl answers such a response with exit 0 and stores nothing,
/// and so does this.
///
/// **A cookie that has already expired deletes the one it names.** That is
/// how a server logs a session out: it sends the same name with
/// `Max-Age=0`. RFC 6265 section 5.3 step 11 says to remove the match, and
/// a store that merely refused the header would keep the session alive
/// after the server ended it.
///
/// **A cleartext hop may not touch a `Secure` cookie.** RFC 6265bis section
/// 8.6 calls this cookie forcing. The rule used to live on the send side
/// alone (`matches`), so a response over plain `http` for `a.test` replaced
/// the cookie that a response over `https` for `a.test` had stored, and the
/// jar then sent the replacement back to the `https` site. An on-path
/// attacker who can answer one `http://bank.test/` request could choose the
/// session that the next `https://bank.test/` request carries. The scheme
/// of the hop now reaches both sides of the jar.
pub fn store(jar: *Jar, url: Url, set_cookie: []const u8, now: i64) void {
    const attrs = cookie.parseSetCookie(set_cookie) catch |err| return jar.countRefusal(err);

    // The same question `matches` asks on the send side, asked once here
    // and answered for the store side and the delete side together. See
    // `zurl_core.cookie.secureContext` for the loopback exception curl
    // also makes.
    const secure_context = cookie.secureContext(url.scheme, url.host);

    const resolved = cookie.resolve(attrs, url, now) catch |err| switch (err) {
        error.CookieExpired => {
            jar.deleteNamed(attrs, url, secure_context);
            jar.report.expired += 1;
            return;
        },
        else => return jar.countRefusal(err),
    };

    jar.put(resolved, secure_context);
}

/// Counts one refusal by the rule that made it.
fn countRefusal(jar: *Jar, err: cookie.Refusal) void {
    switch (err) {
        error.CookieMalformed, error.CookieTooLarge => jar.report.malformed += 1,
        error.CookieDomainNotOwned, error.CookiePublicSuffix => jar.report.domain_refused += 1,
        error.CookieExpired => jar.report.expired += 1,
    }
}

/// Removes the cookie that an expired `Set-Cookie` names.
///
/// The domain and the path are worked out the same way `resolve` works
/// them out, because the cookie to remove is the one that header would
/// have stored. `resolve` already got past the domain rule to report the
/// expiry, so `resolveDomain` cannot fail here. A fault is still a
/// removal that does not happen, and never a wrong removal.
fn deleteNamed(
    jar: *Jar,
    attrs: cookie.Attributes,
    url: Url,
    secure_context: bool,
) void {
    const domain = cookie.resolveDomain(url.host, attrs.domain) catch return;
    const path = attrs.path orelse cookie.defaultPath(url.path);
    jar.remove(attrs.name, domain.domain, path, secure_context);
}

/// Removes the cookie with this name, domain, and path, if the jar holds
/// one. RFC 6265 section 5.3 calls these three the identity of a cookie.
///
/// A `Secure` cookie stays where `secure_context` is false. Logging a
/// session out is a change to that session, and a cleartext hop may not
/// make one. RFC 6265bis section 8.6.
fn remove(
    jar: *Jar,
    name: []const u8,
    domain: []const u8,
    path: []const u8,
    secure_context: bool,
) void {
    for (jar.cookies.items, 0..) |*c, index| {
        if (!sameIdentity(c.*, name, domain, path)) continue;
        if (c.secure and !secure_context) {
            jar.report.secure_refused += 1;
            return;
        }
        c.free(jar.allocator);
        _ = jar.cookies.orderedRemove(index);
        return;
    }
}

fn sameIdentity(c: Cookie, name: []const u8, domain: []const u8, path: []const u8) bool {
    if (!std.mem.eql(u8, c.name, name)) return false;
    if (!std.ascii.eqlIgnoreCase(c.domain, domain)) return false;
    return std.mem.eql(u8, c.path, path);
}

/// Puts `resolved` in the jar, replacing whatever cookie of the same name,
/// domain, and path was there.
///
/// A replaced cookie keeps its `created` number, which RFC 6265 section
/// 5.3 step 11 asks for: a server that sets the same cookie again has not
/// made a newer cookie, it has changed the one that was already there, and
/// the send order must not move under it.
fn put(jar: *Jar, resolved: cookie.Resolved, secure_context: bool) void {
    // **Checked here, on the way in, and on every path.** A cookie reaches
    // a request header and a jar line, so a CR, an LF, a NUL, a semicolon,
    // or a tab in one would write a header, or a column, that nobody sent.
    if (!cookie.wireSafe(resolved.name) or !cookie.wireSafe(resolved.value) or
        !cookie.fieldSafe(resolved.domain) or !cookie.fieldSafe(resolved.path))
    {
        jar.report.malformed += 1;
        return;
    }

    var replacing: ?*Cookie = null;
    for (jar.cookies.items) |*c| {
        if (sameIdentity(c.*, resolved.name, resolved.domain, resolved.path)) {
            replacing = c;
            break;
        }
    }

    // **A cleartext hop may not write over a `Secure` cookie.** RFC
    // 6265bis section 8.6. The cookie that is there was stored over a
    // connection nobody else could read, and a hop that anybody can answer
    // must not change it. A new cookie of a name the jar does not hold is
    // not affected: the `Secure` attribute belongs to the cookie that
    // exists, and nothing is being replaced.
    if (replacing) |old| {
        if (old.secure and !secure_context) {
            jar.report.secure_refused += 1;
            return;
        }
    }

    if (replacing == null and jar.cookies.items.len >= cookies_max) {
        // The jar is full. The cookie it already holds may be the session,
        // and the one arriving may be a server filling the store on
        // purpose, so nothing is evicted to make room.
        jar.report.overflow += 1;
        return;
    }

    const fresh = jar.build(resolved) catch {
        // An allocation that did not succeed costs one cookie and not the
        // transfer. It is counted like every other loss.
        jar.report.malformed += 1;
        return;
    };

    if (replacing) |old| {
        const created = old.created;
        old.free(jar.allocator);
        old.* = fresh;
        old.created = created;
        return;
    }

    jar.cookies.append(jar.allocator, fresh) catch {
        var owned = fresh;
        owned.free(jar.allocator);
        jar.report.overflow += 1;
        return;
    };
    jar.sequence += 1;
}

/// How many cookies the jar holds.
pub fn count(jar: *const Jar) usize {
    return jar.cookies.items.len;
}

/// Copies `resolved` into buffers this jar owns.
fn build(jar: *Jar, resolved: cookie.Resolved) Allocator.Error!Cookie {
    const name = try jar.allocator.dupe(u8, resolved.name);
    errdefer jar.allocator.free(name);
    const value = try jar.allocator.dupe(u8, resolved.value);
    errdefer jar.allocator.free(value);
    const domain = try jar.allocator.dupe(u8, resolved.domain);
    errdefer jar.allocator.free(domain);
    // One case in the store, so a jar file zurl writes reads the same from
    // one run to the next whatever case the server used.
    for (domain) |*byte| byte.* = std.ascii.toLower(byte.*);
    const path = try jar.allocator.dupe(u8, resolved.path);

    return .{
        .name = name,
        .value = value,
        .domain = domain,
        .path = path,
        .host_only = resolved.host_only,
        .secure = resolved.secure,
        .http_only = resolved.http_only,
        .expires = resolved.expires,
        .created = jar.sequence,
    };
}

/// Reads a Netscape cookie file's text into the jar.
///
/// **`text` is untrusted.** A line this reader cannot read is dropped and
/// counted, never guessed at, and the scan stops at `lines_max`. A jar
/// file cannot make zurl send a cookie to a host that cookie does not
/// belong to: every line goes through `put`, and the domain a line names
/// is the domain the send rule reads.
///
/// A cookie that has already expired is dropped, which is what curl does
/// with the same file. `-j` drops every session cookie as well. See
/// `junk_session_cookies` for the measurement.
pub fn loadText(jar: *Jar, text: []const u8, now: i64) void {
    var lines: usize = 0;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |raw| {
        if (lines == lines_max) {
            jar.report.file_truncated = true;
            return;
        }
        lines += 1;

        // A file written on another system ends its lines with CRLF.
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0) continue;

        const parsed = cookie.parseJarLine(line) orelse {
            // A comment line is not a fault, and neither is the header
            // curl writes. Only a line that starts like a cookie and is
            // not one gets counted.
            if (line[0] != '#' or std.mem.startsWith(u8, line, cookie.http_only_prefix)) {
                jar.report.malformed += 1;
            }
            continue;
        };

        // **The public-suffix rule, on the way in from a file.** A line
        // naming `com`, or `co.uk`, with the subdomain column TRUE would
        // put a cookie on every host under that domain. A jar file is
        // untrusted input, so the rule `zurl_core.cookie.resolveDomain`
        // holds for a `Set-Cookie` has to hold here too: that function
        // takes the request host, and a load has none, so the check is
        // written out against the list alone.
        //
        // Measured against curl 8.21.0: a jar naming `com` and `test`
        // with TRUE reached no host, and a line naming `co.uk` with TRUE
        // was sent to `www.example.co.uk`. zurl refuses that third line,
        // so it is stricter than curl here. A jar file is the one input a
        // user can fix by hand, and a wide cookie in one reaches every
        // site under the suffix.
        //
        // A host-only line is left alone whatever it names. It reaches a
        // host called exactly `com` and nothing else.
        if (parsed.include_subdomains and zurl_core.psl.isPublicSuffix(parsed.domain)) {
            jar.report.domain_refused += 1;
            continue;
        }

        // Column five is zero for a session cookie, which is what curl
        // writes for one.
        const expires: ?i64 = if (parsed.expires == 0) null else parsed.expires;
        if (expires) |when| {
            if (when <= now) {
                jar.report.expired += 1;
                continue;
            }
        } else if (jar.junk_session_cookies) {
            jar.report.junked += 1;
            continue;
        }

        jar.put(.{
            .name = parsed.name,
            .value = parsed.value,
            .domain = parsed.domain,
            .path = parsed.path,
            // The column decides, and the leading dot does not. See
            // `zurl_core.cookie.JarLine.include_subdomains`.
            .host_only = !parsed.include_subdomains,
            .secure = parsed.secure,
            .http_only = parsed.http_only,
            .expires = expires,
            // A jar file belongs to the user, and no network hop wrote it, so
            // it counts as a secure context. The rule in `put` answers a
            // cleartext peer, and `-b jar.txt` is not one.
        }, true);
    }
}

/// Every fault reading a jar file can report.
pub const LoadError = error{
    /// The file could not be opened or read.
    JarUnreadable,
    /// The file is larger than `file_len_max`.
    JarTooLarge,
} || Allocator.Error;

/// Reads the Netscape cookie file at `path` into the jar.
///
/// The whole file is read into memory first, under `file_len_max`, and
/// then parsed. A file past the bound is `error.JarTooLarge` and no line
/// of it is read: half a jar is a jar that quietly lost the session.
pub fn load(jar: *Jar, path: []const u8, now: i64) LoadError!void {
    const text = Io.Dir.cwd().readFileAlloc(
        jar.io,
        path,
        jar.allocator,
        .limited(file_len_max),
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => return error.JarTooLarge,
        else => return error.JarUnreadable,
    };
    defer {
        // The text holds every cookie value the file carried, so it is
        // wiped before it goes back to the allocator, the same way a
        // cookie is.
        @memset(text, 0);
        jar.allocator.free(text);
    }
    jar.loadText(text, now);
}

/// Orders two cookies for the jar file.
///
/// Newest first. Measured against curl 8.21.0 with eight `Set-Cookie`
/// headers on one response: the file listed them in exactly the reverse of
/// the order the server sent them, because curl keeps its jar as a list it
/// adds to the front of. Writing the same order means a jar zurl wrote and
/// a jar curl wrote for the same response differ in no line.
fn beforeInFile(jar: *const Jar, left: usize, right: usize) bool {
    return jar.cookies.items[left].created > jar.cookies.items[right].created;
}

/// Writes the jar as a Netscape cookie file.
///
/// The four header lines go out even when the jar holds no cookie, which
/// is what curl writes for a `-c` on a response that set none, measured.
///
/// A session cookie takes a zero in the expiry column, which is curl's own
/// convention for one. A cookie that has expired by `now` is left out: it
/// would be dropped by the next reader anyway, and writing it back would
/// keep a dead credential on the disk.
pub fn writeTo(jar: *const Jar, w: *Io.Writer, now: i64) Io.Writer.Error!void {
    try w.writeAll(cookie.jar_header);

    var order: [cookies_max]u16 = undefined;
    var count_kept: usize = 0;
    for (jar.cookies.items, 0..) |c, index| {
        if (count_kept == order.len) break;
        if (expired(c, now)) continue;
        order[count_kept] = @intCast(index);
        count_kept += 1;
    }

    std.mem.sort(u16, order[0..count_kept], jar, struct {
        fn lessThan(context: *const Jar, a: u16, b: u16) bool {
            return beforeInFile(context, a, b);
        }
    }.lessThan);

    for (order[0..count_kept]) |index| {
        const c = jar.cookies.items[index];
        try cookie.writeJarLine(w, .{
            .domain = c.domain,
            .include_subdomains = !c.host_only,
            .path = c.path,
            .secure = c.secure,
            .expires = c.expires orelse 0,
            .name = c.name,
            .value = c.value,
            .http_only = c.http_only,
        });
    }
}

/// Every fault writing a jar file can report.
pub const SaveError = error{
    /// The file could not be created or written.
    JarUnwritable,
} || Allocator.Error;

/// The permissions a new jar file takes.
///
/// **The file holds credentials.** A session token that anybody on the
/// machine can read is a session anybody on the machine can take, so this
/// asks for owner read and owner write and nothing else. curl creates its
/// jar with the default `0o666` and leaves the rest to the process umask,
/// which is looser whenever that umask is.
///
/// The mode is written only on a target whose permissions are a POSIX
/// mode. `Io.File.Permissions` is a different type on Windows and an empty
/// one where a target has no permissions at all, and `toMode` is the
/// member the POSIX shape has. Those targets take the default.
const jar_permissions: Io.File.Permissions = if (@hasDecl(Io.File.Permissions, "toMode"))
    @enumFromInt(0o600)
else
    .default_file;

/// Writes the jar to the file at `path`, replacing whatever was there.
///
/// See `jar_permissions` for what a new file is created with.
pub fn save(jar: *const Jar, path: []const u8, now: i64) SaveError!void {
    var file = Io.Dir.cwd().createFile(jar.io, path, .{ .permissions = jar_permissions }) catch
        return error.JarUnwritable;
    defer file.close(jar.io);

    var buffer: [4096]u8 = undefined;
    var file_writer = file.writer(jar.io, &buffer);
    jar.writeTo(&file_writer.interface, now) catch return error.JarUnwritable;
    file_writer.interface.flush() catch return error.JarUnwritable;
}

const testing = std.testing;

fn testJar() Jar {
    return .init(testing.allocator, testing.io);
}

/// A url for a test, parsed from a literal this file writes.
///
/// The assert stays: `text` is never input, so a parse that refuses it is
/// a mistake in the test above and nowhere else, and that is the one thing
/// IronStyle asserts on. No shipped build reaches this, because a test
/// helper is compiled into the test binary alone.
fn testUrl(text: []const u8) Url {
    return zurl_core.url.parse(text) catch unreachable;
}

/// The `Cookie` header this jar builds for `url`, or null.
fn headerText(jar: *Jar, url_text: []const u8, now: i64, out: []u8) ?[]const u8 {
    return jar.headerFor(testUrl(url_text), now, out);
}

test "a cookie a response set comes back on the next request to that host" {
    var jar = testJar();
    defer jar.deinit();

    jar.store(testUrl("http://a.example.test/one"), "sid=zz9; Path=/", 1000);

    var out: [cookie.header_len_max]u8 = undefined;
    try testing.expectEqualStrings("sid=zz9", headerText(&jar, "http://a.example.test/two", 1000, &out).?);
}

test "a cookie of one host never reaches another host" {
    var jar = testJar();
    defer jar.deinit();

    jar.store(testUrl("http://a.example.test/"), "sid=secret", 1000);

    var out: [cookie.header_len_max]u8 = undefined;
    try testing.expectEqual(
        @as(?[]const u8, null),
        headerText(&jar, "http://b.example.test/", 1000, &out),
    );
    // And the value never appeared anywhere but the jar.
    try testing.expectEqualStrings("sid=secret", headerText(&jar, "http://a.example.test/", 1000, &out).?);
}

test "a response cannot set a cookie for a domain it does not control" {
    var jar = testJar();
    defer jar.deinit();

    jar.store(testUrl("http://evil.test/"), "steal=1; Domain=bank.test", 1000);
    try testing.expectEqual(@as(usize, 0), jar.cookies.items.len);
    try testing.expectEqual(@as(usize, 1), jar.report.domain_refused);

    var out: [cookie.header_len_max]u8 = undefined;
    try testing.expectEqual(@as(?[]const u8, null), headerText(&jar, "http://bank.test/", 1000, &out));
}

test "nothing may set a cookie on a single-label domain" {
    var jar = testJar();
    defer jar.deinit();

    jar.store(testUrl("http://a.com/"), "wide=1; Domain=com", 1000);
    jar.store(testUrl("http://host.localhost/"), "wide=2; Domain=localhost", 1000);
    try testing.expectEqual(@as(usize, 0), jar.cookies.items.len);
    try testing.expectEqual(@as(usize, 2), jar.report.domain_refused);
}

test "a response cannot widen a cookie onto the public suffix it sits under" {
    var jar = testJar();
    defer jar.deinit();

    // The gap the list closes. Without it, `sid` would go to every other
    // site under `co.uk`. Measured against curl 8.21.0, which refuses the
    // same three headers through libpsl.
    jar.store(testUrl("http://www.example.co.uk/"), "sid=1; Domain=co.uk", 1000);
    jar.store(testUrl("http://a.b.github.io/"), "sid=2; Domain=github.io", 1000);
    jar.store(testUrl("http://www.foo.ck/"), "sid=3; Domain=foo.ck", 1000);
    try testing.expectEqual(@as(usize, 0), jar.cookies.items.len);
    try testing.expectEqual(@as(usize, 3), jar.report.domain_refused);

    var out: [cookie.header_len_max]u8 = undefined;
    try testing.expectEqual(
        @as(?[]const u8, null),
        headerText(&jar, "http://other.co.uk/", 1000, &out),
    );

    // And the ordinary domain under the same suffix still works, which is
    // the half that would break real sites if the list over-refused.
    jar.store(testUrl("http://www.example.co.uk/"), "ok=4; Domain=example.co.uk", 1000);
    try testing.expectEqual(@as(usize, 1), jar.cookies.items.len);
    try testing.expectEqualStrings(
        "ok=4",
        headerText(&jar, "http://shop.example.co.uk/", 1000, &out).?,
    );
}

test "a domain cookie reaches a subdomain and a host-only cookie does not" {
    var jar = testJar();
    defer jar.deinit();

    jar.store(testUrl("http://www.example.test/"), "shared=1; Domain=example.test", 1000);
    jar.store(testUrl("http://www.example.test/"), "own=2", 1000);

    var out: [cookie.header_len_max]u8 = undefined;
    const other = headerText(&jar, "http://other.example.test/", 1000, &out).?;
    try testing.expectEqualStrings("shared=1", other);

    var out2: [cookie.header_len_max]u8 = undefined;
    const same = headerText(&jar, "http://www.example.test/", 1000, &out2).?;
    try testing.expect(std.mem.indexOf(u8, same, "own=2") != null);
    try testing.expect(std.mem.indexOf(u8, same, "shared=1") != null);
}

test "a path cookie reaches what sits under it and nothing beside it" {
    var jar = testJar();
    defer jar.deinit();

    jar.store(testUrl("http://a.test/"), "deep=1; Path=/dir", 1000);

    var out: [cookie.header_len_max]u8 = undefined;
    try testing.expectEqualStrings("deep=1", headerText(&jar, "http://a.test/dir/page", 1000, &out).?);
    try testing.expectEqual(@as(?[]const u8, null), headerText(&jar, "http://a.test/", 1000, &out));
    try testing.expectEqual(@as(?[]const u8, null), headerText(&jar, "http://a.test/directory", 1000, &out));
}

test "a Secure cookie is withheld over plain http and sent over https" {
    var jar = testJar();
    defer jar.deinit();

    jar.store(testUrl("https://www.example.test/"), "sec=s1; Secure", 1000);
    jar.store(testUrl("https://www.example.test/"), "plain=p1", 1000);

    var out: [cookie.header_len_max]u8 = undefined;
    // Plain http to a host off the loopback carries the ordinary cookie
    // and never the Secure one.
    try testing.expectEqualStrings(
        "plain=p1",
        headerText(&jar, "http://www.example.test/", 1000, &out).?,
    );

    var out2: [cookie.header_len_max]u8 = undefined;
    const secure = headerText(&jar, "https://www.example.test/", 1000, &out2).?;
    try testing.expect(std.mem.indexOf(u8, secure, "sec=s1") != null);
}

test "a cleartext hop cannot write over a Secure cookie" {
    // RFC 6265bis section 8.6, cookie forcing. The rule used to live on
    // the send side alone, so a response over plain `http` replaced the
    // cookie that a response over `https` had stored, and the jar sent the
    // replacement back to the `https` site. A user who ran
    // `zurl -c jar.txt https://bank.test/login` and later made any
    // `http://bank.test/` request handed an on-path attacker the session.
    var jar = testJar();
    defer jar.deinit();

    jar.store(testUrl("https://bank.test/"), "session=real; Secure; Path=/", 1000);
    try testing.expectEqual(@as(usize, 1), jar.cookies.items.len);

    // The attacker's answer over plain http, of the same name, domain, and
    // path. It changes nothing.
    jar.store(testUrl("http://bank.test/"), "session=attacker; Secure; Path=/", 1000);
    try testing.expectEqual(@as(usize, 1), jar.cookies.items.len);
    try testing.expectEqualStrings("real", jar.cookies.items[0].value);
    try testing.expectEqual(@as(usize, 1), jar.report.secure_refused);

    // Without the `Secure` attribute on the new header either. The
    // attribute of the cookie that is there is what decides.
    jar.store(testUrl("http://bank.test/"), "session=attacker; Path=/", 1000);
    try testing.expectEqualStrings("real", jar.cookies.items[0].value);
    try testing.expectEqual(@as(usize, 2), jar.report.secure_refused);

    // The https site still reads its own value.
    var out: [cookie.header_len_max]u8 = undefined;
    try testing.expectEqualStrings(
        "session=real",
        headerText(&jar, "https://bank.test/", 1000, &out).?,
    );

    // And the same origin over https replaces it, which is the ordinary
    // case this rule must not break.
    jar.store(testUrl("https://bank.test/"), "session=rotated; Secure; Path=/", 1000);
    try testing.expectEqualStrings("rotated", jar.cookies.items[0].value);
    try testing.expectEqual(@as(usize, 2), jar.report.secure_refused);
}

test "a cleartext hop cannot delete a Secure cookie" {
    // The same rule on the delete side. `Max-Age=0` is how a server logs a
    // session out, and logging a session out is a change to that session.
    var jar = testJar();
    defer jar.deinit();

    jar.store(testUrl("https://bank.test/"), "session=real; Secure; Path=/", 1000);
    jar.store(testUrl("http://bank.test/"), "session=; Secure; Path=/; Max-Age=0", 1000);

    try testing.expectEqual(@as(usize, 1), jar.cookies.items.len);
    try testing.expectEqualStrings("real", jar.cookies.items[0].value);
    try testing.expectEqual(@as(usize, 1), jar.report.secure_refused);

    // Over https the same header ends the session.
    jar.store(testUrl("https://bank.test/"), "session=; Secure; Path=/; Max-Age=0", 1000);
    try testing.expectEqual(@as(usize, 0), jar.cookies.items.len);
}

test "a cookie with no Secure attribute is replaced over plain http as before" {
    // The rule reads the cookie that is there and never the hop alone, so
    // an ordinary cookie keeps the ordinary behaviour.
    var jar = testJar();
    defer jar.deinit();

    jar.store(testUrl("http://a.test/"), "plain=first", 1000);
    jar.store(testUrl("http://a.test/"), "plain=second", 1000);

    try testing.expectEqual(@as(usize, 1), jar.cookies.items.len);
    try testing.expectEqualStrings("second", jar.cookies.items[0].value);
    try testing.expectEqual(@as(usize, 0), jar.report.secure_refused);
}

test "loopback counts as a secure context on the store side too" {
    // `zurl_core.cookie.secureContext` makes plain http to a loopback host
    // a secure context, which is what curl 8.21.0 does. The store side asks
    // the same function as the send side, so a local test server can still
    // rotate its own `Secure` cookie.
    var jar = testJar();
    defer jar.deinit();

    jar.store(testUrl("http://127.0.0.1:8080/"), "session=first; Secure; Path=/", 1000);
    jar.store(testUrl("http://127.0.0.1:8080/"), "session=second; Secure; Path=/", 1000);

    try testing.expectEqual(@as(usize, 1), jar.cookies.items.len);
    try testing.expectEqualStrings("second", jar.cookies.items[0].value);
    try testing.expectEqual(@as(usize, 0), jar.report.secure_refused);
}

test "an expired cookie is neither stored nor sent" {
    var jar = testJar();
    defer jar.deinit();

    jar.store(testUrl("http://a.test/"), "gone=1; Max-Age=10", 1000);
    var out: [cookie.header_len_max]u8 = undefined;
    try testing.expectEqualStrings("gone=1", headerText(&jar, "http://a.test/", 1005, &out).?);
    // Ten seconds later the same jar sends nothing.
    try testing.expectEqual(@as(?[]const u8, null), headerText(&jar, "http://a.test/", 1011, &out));
}

test "a Max-Age of zero deletes the cookie it names, which is how a server logs out" {
    var jar = testJar();
    defer jar.deinit();

    jar.store(testUrl("http://a.test/"), "sid=live", 1000);
    try testing.expectEqual(@as(usize, 1), jar.cookies.items.len);

    jar.store(testUrl("http://a.test/"), "sid=; Max-Age=0", 1000);
    try testing.expectEqual(@as(usize, 0), jar.cookies.items.len);
}

test "setting the same cookie again replaces the value and keeps the order" {
    var jar = testJar();
    defer jar.deinit();

    jar.store(testUrl("http://a.test/"), "first=1", 1000);
    jar.store(testUrl("http://a.test/"), "second=2", 1000);
    jar.store(testUrl("http://a.test/"), "first=updated", 1000);

    try testing.expectEqual(@as(usize, 2), jar.cookies.items.len);
    var out: [cookie.header_len_max]u8 = undefined;
    try testing.expectEqualStrings(
        "first=updated; second=2",
        headerText(&jar, "http://a.test/", 1000, &out).?,
    );
}

test "a Cookie header orders the longer path first, which RFC 6265 asks for" {
    var jar = testJar();
    defer jar.deinit();

    jar.store(testUrl("http://a.test/"), "root=1; Path=/", 1000);
    jar.store(testUrl("http://a.test/"), "deep=2; Path=/dir/sub", 1000);
    jar.store(testUrl("http://a.test/"), "mid=3; Path=/dir", 1000);

    var out: [cookie.header_len_max]u8 = undefined;
    try testing.expectEqualStrings(
        "deep=2; mid=3; root=1",
        headerText(&jar, "http://a.test/dir/sub/page", 1000, &out).?,
    );
}

test "a Set-Cookie that is not a cookie is counted and never stored" {
    var jar = testJar();
    defer jar.deinit();

    jar.store(testUrl("http://a.test/"), "novalue", 1000);
    jar.store(testUrl("http://a.test/"), "", 1000);
    try testing.expectEqual(@as(usize, 0), jar.cookies.items.len);
    try testing.expectEqual(@as(usize, 2), jar.report.malformed);
    try testing.expect(jar.report.lostAnything());
}

test "a CR or an LF in a cookie value never reaches the jar" {
    var jar = testJar();
    defer jar.deinit();

    // The parse takes the value up to the first `;`, so an injected header
    // arrives as part of the value itself.
    jar.store(testUrl("http://a.test/"), "id=v\r\nX-Injected: yes", 1000);
    try testing.expectEqual(@as(usize, 0), jar.cookies.items.len);
    try testing.expectEqual(@as(usize, 1), jar.report.malformed);
}

test "the jar stops at its cookie bound and counts what it refused" {
    var jar = testJar();
    defer jar.deinit();

    var name_buffer: [32]u8 = undefined;
    var index: usize = 0;
    while (index < cookies_max + 5) : (index += 1) {
        const text = try std.fmt.bufPrint(&name_buffer, "n{d}=v", .{index});
        jar.store(testUrl("http://a.test/"), text, 1000);
    }
    try testing.expectEqual(cookies_max, jar.count());
    try testing.expectEqual(@as(usize, 5), jar.report.overflow);
}

test "a Cookie header stops at its byte bound and counts the cookies left out" {
    var jar = testJar();
    defer jar.deinit();

    // Each cookie is about 1100 bytes, so the 8 KiB header cannot hold ten.
    var value: [1024]u8 = undefined;
    @memset(&value, 'v');
    var text_buffer: [1200]u8 = undefined;
    var index: usize = 0;
    while (index < 10) : (index += 1) {
        const text = try std.fmt.bufPrint(&text_buffer, "n{d}={s}", .{ index, value });
        jar.store(testUrl("http://a.test/"), text, 1000);
    }

    var out: [cookie.header_len_max]u8 = undefined;
    const header = headerText(&jar, "http://a.test/", 1000, &out).?;
    try testing.expect(header.len <= cookie.header_len_max);
    try testing.expect(jar.report.header_full != 0);
}

test "a cookie pair that runs out of room leaves no half of itself behind" {
    // This is the fact `headerFor` rests on, and the reason its writes
    // are recovered from rather than asserted: `std.Io.Writer.fixed`
    // copies every byte that fits and answers `error.WriteFailed` only
    // after that. Without the rewind, a bound that was measured wrongly
    // would put `; sessio` on the wire as if it were a whole cookie.
    var buffer: [8]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    try appendPair(&writer, "", "a", "1");
    const before = writer.end;

    try testing.expectError(error.WriteFailed, appendPair(&writer, "; ", "session", "v"));
    try testing.expect(writer.end > before);

    writer.end = before;
    try testing.expectEqualStrings("a=1", writer.buffered());
}

test "a Cookie header that runs short writes whole pairs and counts the rest" {
    var jar = testJar();
    defer jar.deinit();

    jar.store(testUrl("http://a.test/"), "aa=1", 1000);
    jar.store(testUrl("http://a.test/"), "bb=2", 1000);

    // Room for `aa=1` and for nothing more, so the second cookie has to
    // be counted rather than cut in half.
    var out: [5]u8 = undefined;
    const header = headerText(&jar, "http://a.test/", 1000, &out).?;
    try testing.expectEqualStrings("aa=1", header);
    try testing.expectEqual(@as(usize, 1), jar.report.header_full);
}

test "a jar file reads back every cookie zurl wrote to it" {
    var jar = testJar();
    defer jar.deinit();

    jar.store(testUrl("http://127.0.0.1:18080/dir/page"), "sess=abc123", 1000);
    jar.store(testUrl("http://www.example.test/"), "dom=d; Domain=example.test", 1000);
    jar.store(testUrl("https://www.example.test/"), "ho=h; HttpOnly; Secure; Max-Age=100000", 1000);

    var buffer: [4096]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    try jar.writeTo(&writer, 1000);

    var second = testJar();
    defer second.deinit();
    second.loadText(writer.buffered(), 1000);
    try testing.expectEqual(@as(usize, 3), second.cookies.items.len);

    var out: [cookie.header_len_max]u8 = undefined;
    try testing.expectEqualStrings(
        "sess=abc123",
        headerText(&second, "http://127.0.0.1:18080/dir/page", 1000, &out).?,
    );
}

test "the jar file starts with the four lines curl writes, even with no cookie" {
    var jar = testJar();
    defer jar.deinit();

    var buffer: [512]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    try jar.writeTo(&writer, 1000);
    try testing.expectEqualStrings(cookie.jar_header, writer.buffered());
}

test "one Set-Cookie writes the exact line curl 8.21.0 writes for it" {
    var jar = testJar();
    defer jar.deinit();

    jar.store(testUrl("http://127.0.0.1:18080/dir/page"), "sess=abc123", 1000);

    var buffer: [512]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    try jar.writeTo(&writer, 1000);
    try testing.expectEqualStrings(
        cookie.jar_header ++ "127.0.0.1\tFALSE\t/dir\tFALSE\t0\tsess\tabc123\n",
        writer.buffered(),
    );
}

test "a HttpOnly cookie keeps its prefix through a save and a load" {
    var jar = testJar();
    defer jar.deinit();

    jar.store(testUrl("http://a.test/"), "ho=h; HttpOnly", 1000);

    var buffer: [512]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    try jar.writeTo(&writer, 1000);
    try testing.expect(std.mem.indexOf(u8, writer.buffered(), cookie.http_only_prefix) != null);

    var second = testJar();
    defer second.deinit();
    second.loadText(writer.buffered(), 1000);
    try testing.expect(second.cookies.items[0].http_only);
}

test "a jar file line that is not a cookie is dropped and counted" {
    var jar = testJar();
    defer jar.deinit();

    jar.loadText(
        "# Netscape HTTP Cookie File\n" ++
            "\n" ++
            "a.test\tFALSE\t/\tFALSE\t0\tgood\tgv\n" ++
            "this line has no columns at all\n" ++
            "a.test\tFALSE\t/\tFALSE\tnotanumber\tbad\tbv\n",
        1000,
    );
    try testing.expectEqual(@as(usize, 1), jar.cookies.items.len);
    try testing.expectEqual(@as(usize, 2), jar.report.malformed);
}

test "a jar file cannot make zurl send a cookie to a host it does not name" {
    var jar = testJar();
    defer jar.deinit();

    jar.loadText("evil.test\tTRUE\t/\tFALSE\t0\tsteal\tsv\n", 1000);

    var out: [cookie.header_len_max]u8 = undefined;
    try testing.expectEqual(@as(?[]const u8, null), headerText(&jar, "http://bank.test/", 1000, &out));
    try testing.expectEqual(
        @as(?[]const u8, null),
        headerText(&jar, "http://notevil.test/", 1000, &out),
    );
    try testing.expectEqualStrings("steal=sv", headerText(&jar, "http://a.evil.test/", 1000, &out).?);
}

test "a jar file cannot put a cookie on a single-label domain" {
    // Measured against curl 8.21.0, which refuses the same two lines from
    // a jar file and sends neither to `www.example.com`.
    var jar = testJar();
    defer jar.deinit();

    jar.loadText(
        "com\tTRUE\t/\tFALSE\t0\twide\twv\n" ++
            "test\tTRUE\t/\tFALSE\t0\ttld\ttv\n",
        1000,
    );
    try testing.expectEqual(@as(usize, 0), jar.cookies.items.len);
    try testing.expectEqual(@as(usize, 2), jar.report.domain_refused);

    var out: [cookie.header_len_max]u8 = undefined;
    try testing.expectEqual(
        @as(?[]const u8, null),
        headerText(&jar, "http://www.example.com/", 1000, &out),
    );

    // A host-only line naming one label is not the same thing. It reaches
    // a host called exactly that and nothing under it.
    var host_only = testJar();
    defer host_only.deinit();
    host_only.loadText("com\tFALSE\t/\tFALSE\t0\tone\tov\n", 1000);
    try testing.expectEqual(@as(usize, 1), host_only.cookies.items.len);
    try testing.expectEqual(
        @as(?[]const u8, null),
        headerText(&host_only, "http://www.example.com/", 1000, &out),
    );
    try testing.expectEqualStrings("one=ov", headerText(&host_only, "http://com/", 1000, &out).?);
}

test "a jar file cannot put a cookie on a public suffix of more than one label" {
    var jar = testJar();
    defer jar.deinit();

    // **zurl is stricter than curl here, measured.** curl 8.21.0 reads
    // both of these lines and sends `psl` to `www.example.co.uk` and
    // `priv` to `a.b.github.io`. zurl drops them: a jar file is untrusted
    // input, and a wide line in one reaches every site under the suffix.
    jar.loadText(
        "co.uk\tTRUE\t/\tFALSE\t0\tpsl\tpv\n" ++
            "github.io\tTRUE\t/\tFALSE\t0\tpriv\tqv\n" ++
            "example.co.uk\tTRUE\t/\tFALSE\t0\tok\tov\n",
        1000,
    );
    try testing.expectEqual(@as(usize, 1), jar.cookies.items.len);
    try testing.expectEqual(@as(usize, 2), jar.report.domain_refused);

    // The ordinary line is read and sent, and the two wide ones are gone.
    var out: [cookie.header_len_max]u8 = undefined;
    try testing.expectEqualStrings(
        "ok=ov",
        headerText(&jar, "http://www.example.co.uk/", 1000, &out).?,
    );
    try testing.expectEqual(
        @as(?[]const u8, null),
        headerText(&jar, "http://a.b.github.io/", 1000, &out),
    );
}

test "junk_session_cookies drops the session cookies a file holds and keeps the rest" {
    var jar = testJar();
    defer jar.deinit();
    jar.junk_session_cookies = true;

    jar.loadText(
        "a.test\tFALSE\t/\tFALSE\t0\tsess\tsv\n" ++
            "a.test\tFALSE\t/\tFALSE\t2000000000\tperm\tpv\n",
        1000,
    );
    try testing.expectEqual(@as(usize, 1), jar.cookies.items.len);
    try testing.expectEqual(@as(usize, 1), jar.report.junked);

    var out: [cookie.header_len_max]u8 = undefined;
    try testing.expectEqualStrings("perm=pv", headerText(&jar, "http://a.test/", 1000, &out).?);
}

test "junk_session_cookies leaves a session cookie a server sets during the run" {
    var jar = testJar();
    defer jar.deinit();
    jar.junk_session_cookies = true;

    jar.store(testUrl("http://a.test/"), "fresh=f", 1000);
    var out: [cookie.header_len_max]u8 = undefined;
    try testing.expectEqualStrings("fresh=f", headerText(&jar, "http://a.test/", 1000, &out).?);
}

test "a jar file scan stops at the line bound and says it stopped" {
    var jar = testJar();
    defer jar.deinit();

    const blank = try testing.allocator.alloc(u8, lines_max + 10);
    defer testing.allocator.free(blank);
    @memset(blank, '\n');
    jar.loadText(blank, 1000);
    try testing.expect(jar.report.file_truncated);
    try testing.expect(jar.report.lostAnything());
}

test "an expired line of a jar file is dropped on the way in" {
    var jar = testJar();
    defer jar.deinit();

    jar.loadText("a.test\tFALSE\t/\tFALSE\t1000000000\told\tov\n", 1788586466);
    try testing.expectEqual(@as(usize, 0), jar.cookies.items.len);
    try testing.expectEqual(@as(usize, 1), jar.report.expired);
}

test "the file written back drops a cookie that expired during the run" {
    var jar = testJar();
    defer jar.deinit();

    jar.store(testUrl("http://a.test/"), "brief=b; Max-Age=10", 1000);
    var buffer: [512]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    try jar.writeTo(&writer, 2000);
    try testing.expectEqualStrings(cookie.jar_header, writer.buffered());
}

test "the interface the engine calls sends and stores through the same jar" {
    var jar = testJar();
    defer jar.deinit();

    const iface = jar.interface();
    iface.receive(iface.ptr, testUrl("http://a.test/"), "sid=through");

    var out: [cookie.header_len_max]u8 = undefined;
    const sent = iface.send(iface.ptr, testUrl("http://a.test/"), &out).?;
    try testing.expectEqualStrings("sid=through", sent);
    try testing.expectEqual(
        @as(?[]const u8, null),
        iface.send(iface.ptr, testUrl("http://other.test/"), &out),
    );
}

test "a jar saved to a file and loaded back holds the same cookies" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // `save` writes relative to the working directory, so the test names a
    // path inside the temporary directory rather than changing it.
    const file_path = try std.fmt.allocPrint(
        testing.allocator,
        ".zig-cache/tmp/{s}/jar.txt",
        .{tmp.sub_path},
    );
    defer testing.allocator.free(file_path);

    var jar = testJar();
    defer jar.deinit();
    jar.store(testUrl("http://a.test/"), "sid=saved", 1000);
    try jar.save(file_path, 1000);

    var second = testJar();
    defer second.deinit();
    try second.load(file_path, 1000);

    var out: [cookie.header_len_max]u8 = undefined;
    try testing.expectEqualStrings("sid=saved", headerText(&second, "http://a.test/", 1000, &out).?);
}

test "a jar file that is not there reports a named fault and leaves the jar empty" {
    var jar = testJar();
    defer jar.deinit();
    try testing.expectError(error.JarUnreadable, jar.load("/nope/no-such-jar.txt", 1000));
    try testing.expectEqual(@as(usize, 0), jar.cookies.items.len);
}
