//! Turns a transfer's proxy options into what the engine sends.
//!
//! `Transfer.Options` holds proxy urls, a `-U` credential, and a bypass
//! list, all as text the caller wrote. The engine wants a
//! `zurl_http.engine.ProxySet`: a host, a port, a kind, and a credential
//! that is ready for the wire. This file is the one step between them.
//!
//! **The proxy credential is built here and nowhere else.** `authorize.zig`
//! builds the origin's credential and reads no proxy field at all, and this
//! file reads no origin field. Two builders, because the two values go to
//! two different peers and a single one would need a flag to say which, and
//! a flag can be wrong.
//!
//! The storage is wiped before it is freed, the way `authorize.Value` wipes
//! its own: the buffer held a cleartext password while the `Basic` value was
//! built from it, and a freed page goes back to the allocator for the next
//! caller to read.

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_http = @import("zurl-http");
const Transfer = @import("Transfer.zig");

const Allocator = std.mem.Allocator;
const auth = zurl_core.auth;

/// Every fault building a proxy credential can report.
///
/// `InvalidEscape` comes from `zurl_core.url.percentDecode`: the proxy url's
/// userinfo holds an escape that is not an escape. A proxy url comes from a
/// command line or from a shell profile, so it is untrusted input and every
/// one of these is a runtime fault, never an assertion.
pub const Error = Allocator.Error || zurl_core.url.DecodeError;

/// One built proxy credential and the storage behind it.
///
/// **Every field here goes to the proxy.** `authorization` is the whole
/// `Proxy-Authorization` header value, which an HTTP or HTTPS proxy reads.
/// `user` and `password` are the decoded halves, which a SOCKS5 exchange
/// reads. A proxy that asked for nothing leaves all three empty and owns no
/// storage.
///
/// The owner must call `deinit`.
pub const Credential = struct {
    authorization: []const u8 = "",
    user: []const u8 = "",
    password: []const u8 = "",
    /// The allocation the three fields point into, or empty when there is
    /// no credential. Read the fields, never this.
    storage: []u8 = &.{},

    /// Wipes and frees the storage.
    ///
    /// The wipe is not housekeeping. The buffer held the decoded user name
    /// and password in cleartext, which is what a SOCKS5 exchange needs and
    /// what the `Basic` value was built from.
    ///
    /// Safe to call on an empty credential, and safe to call twice.
    pub fn deinit(v: *Credential, gpa: Allocator) void {
        if (v.storage.len != 0) {
            std.crypto.secureZero(u8, v.storage);
            gpa.free(v.storage);
        }
        v.* = .{};
    }

    /// Whether this credential has anything to send.
    pub fn isEmpty(v: Credential) bool {
        return v.authorization.len == 0 and v.user.len == 0 and v.password.len == 0;
    }
};

/// The proxy set for one transfer, and the credentials behind it.
///
/// `set` is what the engine reads. The two credentials own the storage the
/// set's `authorization`, `user`, and `password` fields point into, so this
/// value must outlive the `Engine.open` that reads it.
pub const Resolved = struct {
    set: zurl_http.engine.ProxySet = .{},
    http_credential: Credential = .{},
    https_credential: Credential = .{},

    pub fn deinit(r: *Resolved, gpa: Allocator) void {
        r.http_credential.deinit(gpa);
        r.https_credential.deinit(gpa);
        r.set = .{};
    }
};

/// Builds the proxy set one transfer sends with.
///
/// The caller owns the result and must `deinit` it.
///
/// **A `-U` credential outranks the userinfo in a proxy url.** That is
/// curl's order for the origin credential too, where `-u` outranks nothing
/// and the url wins. The proxy side is the other way around because `-U` is
/// the only flag that names a proxy credential at all, so a user who wrote
/// one meant it. curl 8.21.0 behaves this way: `-x http://a:b@host -U c:d`
/// sends the `-U` pair.
///
/// A transfer that named no proxy gets an empty set and allocates nothing,
/// which is what every transfer that predates this file gets.
pub fn resolve(gpa: Allocator, options: Transfer.Options) Error!Resolved {
    var out: Resolved = .{};
    errdefer out.deinit(gpa);

    out.set.no_proxy = options.no_proxy;

    if (options.proxy) |spec| {
        out.http_credential = try credentialFor(gpa, spec, options.proxy_credentials);
        out.set.http = engineProxy(spec, out.http_credential, options.proxy_insecure);
    }
    if (options.proxy_tls) |spec| {
        out.https_credential = try credentialFor(gpa, spec, options.proxy_credentials);
        out.set.https = engineProxy(spec, out.https_credential, options.proxy_insecure);
    }
    return out;
}

/// The engine's view of one proxy, with the credential already built.
fn engineProxy(
    spec: zurl_core.proxy.Spec,
    credential: Credential,
    insecure: bool,
) zurl_http.engine.Proxy {
    return .{
        .kind = spec.kind,
        .host = spec.host,
        .port = spec.port,
        // The header value goes only to an HTTP or an HTTPS proxy. A SOCKS
        // proxy reads no HTTP at all, so it is left empty there rather than
        // carried to a place nothing reads it.
        .authorization = if (spec.kind.isSocks()) "" else credential.authorization,
        // And the two halves go only to a SOCKS5 exchange, for the mirror
        // reason.
        .user = if (spec.kind.isSocks()) credential.user else "",
        .password = if (spec.kind.isSocks()) credential.password else "",
        .insecure = insecure,
    };
}

/// Builds the credential for one proxy.
///
/// The source is `flag` when the caller named one, and the proxy url's own
/// userinfo otherwise. A proxy that has neither gets an empty credential and
/// no allocation.
fn credentialFor(
    gpa: Allocator,
    spec: zurl_core.proxy.Spec,
    flag: ?auth.Credentials,
) Error!Credential {
    if (flag) |c| return build(gpa, c.user, c.password, false);
    if (!spec.hasCredential()) return .{};
    // The url's own userinfo is still percent-encoded, exactly as
    // `zurl_core.url.parse` leaves an origin userinfo. A password holding
    // `%40` is not the password holding `@` until this decodes it.
    return build(gpa, spec.user, spec.password, true);
}

/// Builds one credential into a single allocation.
///
/// The layout is the decoded user name, the decoded password, and then the
/// `Basic` value. One allocation, so one wipe covers every cleartext byte.
///
/// `encoded` says whether the two halves still carry percent escapes.
/// Decoding never grows a value, so the encoded lengths bound the decoded
/// ones and the buffer is measured from them.
fn build(
    gpa: Allocator,
    user_text: []const u8,
    password_text: []const u8,
    encoded: bool,
) Error!Credential {
    // Measured from the credential and never from a constant, the way
    // `authorize.apply` measures its own. A proxy token can be as long as
    // any other token.
    const upper: auth.Credentials = .{ .user = user_text, .password = password_text };
    const total = user_text.len + password_text.len + auth.basicValueSize(upper);
    const storage = try gpa.alloc(u8, total);
    errdefer {
        std.crypto.secureZero(u8, storage);
        gpa.free(storage);
    }

    const user = if (encoded)
        try zurl_core.url.percentDecode(storage[0..user_text.len], user_text)
    else copied: {
        @memcpy(storage[0..user_text.len], user_text);
        break :copied storage[0..user_text.len];
    };
    const password_room = storage[user_text.len..][0..password_text.len];
    const password = if (encoded)
        try zurl_core.url.percentDecode(password_room, password_text)
    else copied: {
        @memcpy(password_room, password_text);
        break :copied password_room;
    };

    const value_room = storage[user_text.len + password_text.len ..];
    const credentials: auth.Credentials = .{ .user = user, .password = password };
    // The room was measured from the encoded lengths, which bound the
    // decoded ones, so this cannot run out. It is still a `try`: a size
    // computed one way and a write done another way must agree at run time
    // and not only in a comment.
    const value = auth.basicValue(value_room, credentials) catch return error.OutOfMemory;

    return .{
        .authorization = value,
        .user = user,
        .password = password,
        .storage = storage,
    };
}

const testing = std.testing;

test "a transfer that named no proxy allocates nothing and sends nothing" {
    var resolved = try resolve(testing.allocator, .{});
    defer resolved.deinit(testing.allocator);
    try testing.expect(resolved.set.isEmpty());
    try testing.expect(resolved.http_credential.isEmpty());
    try testing.expect(resolved.https_credential.isEmpty());
    try testing.expectEqual(@as(usize, 0), resolved.http_credential.storage.len);
}

test "a proxy url with no credential sends no proxy authorization" {
    const spec = try zurl_core.proxy.parse("http://127.0.0.1:3128");
    var resolved = try resolve(testing.allocator, .{ .proxy = spec, .proxy_tls = spec });
    defer resolved.deinit(testing.allocator);

    try testing.expectEqualStrings("127.0.0.1", resolved.set.http.?.host);
    try testing.expectEqual(@as(u16, 3128), resolved.set.http.?.port);
    try testing.expectEqualStrings("", resolved.set.http.?.authorization);
    try testing.expectEqualStrings("", resolved.set.https.?.authorization);
}

test "a credential in the proxy url becomes a Proxy-Authorization value" {
    // Measured against curl 8.21.0 on a loopback listener: `-x
    // http://bob:proxypw@127.0.0.1:PORT` sent `Proxy-Authorization: Basic
    // Ym9iOnByb3h5cHc=`, which is base64("bob:proxypw").
    const spec = try zurl_core.proxy.parse("http://bob:proxypw@127.0.0.1:3128");
    var resolved = try resolve(testing.allocator, .{ .proxy = spec });
    defer resolved.deinit(testing.allocator);
    try testing.expectEqualStrings("Basic Ym9iOnByb3h5cHc=", resolved.set.http.?.authorization);
}

test "a percent escape in the proxy userinfo is decoded before it is encoded" {
    // `%40` is `@`. A password compared byte for byte against the encoded
    // form would never match what the proxy expects.
    const spec = try zurl_core.proxy.parse("http://bob:pw%40x@127.0.0.1:3128");
    var resolved = try resolve(testing.allocator, .{ .proxy = spec });
    defer resolved.deinit(testing.allocator);

    var expected: [64]u8 = undefined;
    const want = try auth.basicValue(&expected, .{ .user = "bob", .password = "pw@x" });
    try testing.expectEqualStrings(want, resolved.set.http.?.authorization);
}

test "a -U credential outranks the userinfo in the proxy url" {
    // Measured against curl 8.21.0: `-x http://a:b@host -U c:d` sent the
    // `-U` pair. `-U` is the only flag that names a proxy credential, so a
    // user who wrote one meant it.
    const spec = try zurl_core.proxy.parse("http://url:urlpw@127.0.0.1:3128");
    var resolved = try resolve(testing.allocator, .{
        .proxy = spec,
        .proxy_credentials = .{ .user = "flag", .password = "flagpw" },
    });
    defer resolved.deinit(testing.allocator);

    var expected: [64]u8 = undefined;
    const want = try auth.basicValue(&expected, .{ .user = "flag", .password = "flagpw" });
    try testing.expectEqualStrings(want, resolved.set.http.?.authorization);
}

test "a socks proxy carries the two halves and no header value" {
    // A SOCKS proxy reads no HTTP, so a `Proxy-Authorization` value would
    // reach nothing at all. The halves go into the RFC 1929 exchange
    // instead.
    const spec = try zurl_core.proxy.parse("socks5h://bob:proxypw@127.0.0.1:1080");
    var resolved = try resolve(testing.allocator, .{ .proxy = spec });
    defer resolved.deinit(testing.allocator);

    try testing.expectEqualStrings("", resolved.set.http.?.authorization);
    try testing.expectEqualStrings("bob", resolved.set.http.?.user);
    try testing.expectEqualStrings("proxypw", resolved.set.http.?.password);
    try testing.expectEqual(zurl_core.proxy.Kind.socks5h, resolved.set.http.?.kind);
}

test "an http proxy carries the header value and neither half" {
    // The mirror of the test above. A `user` and a `password` on an HTTP
    // proxy would reach no field the engine writes, and leaving them set
    // would put a decoded password in the pool key's digest for no reason.
    const spec = try zurl_core.proxy.parse("http://bob:proxypw@127.0.0.1:3128");
    var resolved = try resolve(testing.allocator, .{ .proxy = spec });
    defer resolved.deinit(testing.allocator);

    try testing.expectEqualStrings("", resolved.set.http.?.user);
    try testing.expectEqualStrings("", resolved.set.http.?.password);
    try testing.expect(resolved.set.http.?.authorization.len != 0);
}

test "the two schemes take their own proxy and their own credential" {
    const cleartext = try zurl_core.proxy.parse("http://a:apw@127.0.0.1:3128");
    const secure = try zurl_core.proxy.parse("http://b:bpw@127.0.0.2:3129");
    var resolved = try resolve(testing.allocator, .{ .proxy = cleartext, .proxy_tls = secure });
    defer resolved.deinit(testing.allocator);

    try testing.expectEqualStrings("127.0.0.1", resolved.set.http.?.host);
    try testing.expectEqualStrings("127.0.0.2", resolved.set.https.?.host);
    try testing.expect(!std.mem.eql(
        u8,
        resolved.set.http.?.authorization,
        resolved.set.https.?.authorization,
    ));
}

test "the bypass list reaches the engine set" {
    const spec = try zurl_core.proxy.parse("http://127.0.0.1:3128");
    var resolved = try resolve(testing.allocator, .{ .proxy = spec, .no_proxy = "example.com" });
    defer resolved.deinit(testing.allocator);

    try testing.expectEqualStrings("example.com", resolved.set.no_proxy);
    try testing.expectEqual(
        @as(?zurl_http.engine.Proxy, null),
        resolved.set.forHop(false, "example.com"),
    );
    try testing.expect(resolved.set.forHop(false, "other.test") != null);
}

test "--proxy-insecure answers for the proxy and reaches no origin field" {
    const spec = try zurl_core.proxy.parse("https://127.0.0.1:3128");
    var resolved = try resolve(testing.allocator, .{ .proxy = spec, .proxy_insecure = true });
    defer resolved.deinit(testing.allocator);
    try testing.expect(resolved.set.http.?.insecure);

    // And the default is false, which no fault path changes.
    var verified = try resolve(testing.allocator, .{ .proxy = spec });
    defer verified.deinit(testing.allocator);
    try testing.expect(!verified.set.http.?.insecure);
}

test "a proxy credential of a thousand characters builds" {
    // The defect this shape exists to avoid is the one `authorize.zig`
    // records: a fixed buffer refused every modern token. The buffer here
    // is measured from the credential.
    const long = "t" ** 1200;
    var resolved = try resolve(testing.allocator, .{
        .proxy = try zurl_core.proxy.parse("http://127.0.0.1:3128"),
        .proxy_credentials = .{ .user = "cache", .password = long },
    });
    defer resolved.deinit(testing.allocator);

    const value = resolved.set.http.?.authorization;
    try testing.expect(std.mem.startsWith(u8, value, "Basic "));
    const decoder = std.base64.standard.Decoder;
    const encoded = value["Basic ".len..];
    const raw = try testing.allocator.alloc(u8, try decoder.calcSizeForSlice(encoded));
    defer testing.allocator.free(raw);
    try decoder.decode(raw, encoded);
    try testing.expectEqualStrings("cache:" ++ long, raw);
}

test "a bad escape in the proxy userinfo is a fault, not a guess" {
    const spec = try zurl_core.proxy.parse("http://bob:pw%zz@127.0.0.1:3128");
    try testing.expectError(error.InvalidEscape, resolve(testing.allocator, .{ .proxy = spec }));
}

test "deinit is safe twice and leaves nothing behind" {
    const spec = try zurl_core.proxy.parse("http://bob:proxypw@127.0.0.1:3128");
    var resolved = try resolve(testing.allocator, .{ .proxy = spec });
    resolved.deinit(testing.allocator);
    resolved.deinit(testing.allocator);
    try testing.expect(resolved.set.isEmpty());
}
