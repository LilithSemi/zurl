//! Chooses and builds one `Authorization` header value for a transfer.
//!
//! An `Authorization` header in `Transfer.Options.headers` outranks every
//! other source: the caller wrote that header, so zurl builds none of its
//! own and sends the caller's value unchanged. curl behaves this way.
//!
//! Past that, credentials come from three places, in curl's order: the
//! url's userinfo, then `Transfer.Options.credentials`, then a `netrc`
//! entry for the url's host. Whichever source wins, a challenge from a
//! prior `401` decides the scheme: no challenge builds `Basic`, and a
//! `digest` challenge builds `Digest`.
//!
//! This module does no I/O and sends nothing. `Client.performHttp` calls
//! `apply`, sends the header it returns, and retries after a `401` with a
//! fresh call that carries the server's challenge.
//!
//! `apply` allocates. It measures the value the credential produces and
//! then allocates exactly that, so no constant here decides how long a
//! credential may be. The one real limit is the length of an
//! `Authorization` header line, and `Client.performHttp` checks the built
//! value against it.

const std = @import("std");
const zurl_core = @import("zurl-core");
const Transfer = @import("Transfer.zig");

const Allocator = std.mem.Allocator;
const Url = zurl_core.Url;
const auth = zurl_core.auth;

/// Every runtime fault that building an `Authorization` value can hit.
///
/// `OutOfMemory` comes from the allocator `apply` sizes the value with.
/// `InvalidEscape` comes from `zurl_core.url.percentDecode`: the url's
/// userinfo holds an escape that is not an escape. The rest come from
/// `auth.digestValueSize` and `auth.digestValue`: the server's challenge
/// asked for something zurl cannot answer. A `WWW-Authenticate` header is
/// untrusted input, so every one of these is a runtime fault a caller can
/// recover from, never an assertion and never a panic.
///
/// `NoSpaceLeft` is in the set because `auth.DigestError` carries it, and
/// no path here reaches it: every buffer this module builds into is
/// measured from the value that goes in it. A caller still has to map it,
/// because an error set is a promise the compiler checks and not a claim
/// in a comment.
pub const ApplyError = Allocator.Error || zurl_core.url.DecodeError || auth.DigestError;

/// How many bytes `auth.bearerValue` writes in front of the token.
///
/// The storage for a bearer value is measured from this and the token
/// length, so `bearerValue` can never run out of room. A change to the
/// prefix there without a change here is caught by the test below, which
/// builds a value and compares its length.
const bearer_prefix_len: usize = "Bearer ".len;

/// Where the credential that a transfer sends came from.
///
/// A credential fault has to name one of these. The three sources are set
/// in three different places, and a message that says only "the
/// credential" leaves a user with three candidates and no way to tell
/// which one is wrong.
pub const Source = enum {
    /// An `Authorization` header the caller wrote, which `-H` fills.
    caller_header,
    /// `Transfer.Options.bearer_token`, which `--oauth2-bearer` fills.
    bearer,
    /// The user name and password in the url itself.
    userinfo,
    /// `Transfer.Options.credentials`, which `-u` fills.
    options,
    /// A `machine` or a `default` entry of the netrc text, which
    /// `--netrc-file` fills.
    netrc,

    /// Names this source for a message to a user.
    ///
    /// Names the source and never the credential. A credential is a
    /// secret, and a diagnostic is printed, logged, and pasted into bug
    /// reports.
    pub fn describe(s: Source) []const u8 {
        return switch (s) {
            .caller_header => "the Authorization header you wrote",
            .bearer => "the --oauth2-bearer token",
            .userinfo => "the user name and password in the url",
            .options => "the -u option",
            .netrc => "the netrc file",
        };
    }
};

/// One built `Authorization` header value, and the storage behind it.
///
/// `text` is the value to send. `storage` is the allocation it points
/// into, or an empty slice when `text` borrows the caller's own header
/// and this owns nothing.
///
/// The owner must call `deinit`. Nothing else frees the allocation.
pub const Value = struct {
    /// The header value to send. Valid until `deinit`.
    text: []const u8,
    /// Which credential source produced `text`.
    source: Source,
    /// The allocation `text` points into, or empty for a borrowed `text`.
    /// Read `text`, never this.
    storage: []u8 = &.{},

    /// Wipes and frees the storage.
    ///
    /// The wipe is not housekeeping. The buffer held the raw
    /// "user:password" form in cleartext while `auth.basicValue` encoded
    /// it, and a freed page goes back to the allocator for the next
    /// caller to read. `auth.basicValue` already wipes the part it used;
    /// this wipes the whole allocation, so nothing here depends on how
    /// much of the buffer the builder touched.
    ///
    /// Safe to call on a borrowed value, and safe to call twice.
    pub fn deinit(v: *Value, gpa: Allocator) void {
        if (v.storage.len != 0) {
            std.crypto.secureZero(u8, v.storage);
            gpa.free(v.storage);
        }
        v.* = .{ .text = "", .source = v.source };
    }
};

/// Detail a digest response needs beyond the challenge.
///
/// Only read when `challenge` names the `digest` scheme. A caller building
/// a `Basic` value, or one with no credentials at all, may pass zero
/// values.
pub const Detail = struct {
    /// The request method, in upper case.
    method: []const u8,
    /// The request target, exactly as the request line writes it.
    uri: []const u8,
    /// The client nonce. A real caller takes it from `std.Io.random`; a
    /// test supplies a fixed value so the digest response is repeatable.
    cnonce: []const u8,
    /// The nonce count. It starts at 1 for each new server nonce, and
    /// increments each time a request reuses that nonce.
    nc: u32,
};

/// The `Authorization` header value the caller put in `headers`, or null
/// when the caller put none there.
///
/// The name is matched without regard to case, because HTTP field names
/// are case-insensitive and a caller writes `-H authorization: ...` as
/// readily as `-H Authorization: ...`.
///
/// A caller that writes the header twice gets the first value. A server
/// reads the first `Authorization` header and RFC 7235 allows only one, so
/// the first is the value that would decide the request anyway.
pub fn callerAuthorization(headers: []const std.http.Header) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "Authorization")) return header.value;
    }
    return null;
}

/// Builds the `Authorization` header value for one request.
///
/// The returned `Value` owns its storage. The caller must `deinit` it.
///
/// **Nothing here caps the credential length.** The buffer is measured
/// from the credential that goes in it, and then allocated at that size:
/// `auth.basicValueSize` for a `Basic` value, `auth.digestValueSize` for
/// a `Digest` one. An earlier version kept a 256-byte buffer for a
/// decoded user name and password, which refused every modern token. A
/// token of 1200 characters is an ordinary credential for a binary cache
/// or a forge, and a number written here can only be a guess about what a
/// user does. The real limit is what one `Authorization` header line can
/// carry, and the caller checks the built value against it.
///
/// Returns `options.headers`' own `Authorization` value when the caller
/// set one, with no storage of its own. The caller's header wins: a
/// credential zurl builds beside the caller's would go out as a second
/// `Authorization` header, and a server that reads the first would honour
/// a url password instead of the token the caller asked for.
///
/// Returns null when no credential source has anything to send: no caller
/// header, no userinfo in `url`, no `options.credentials`, and no matching
/// `netrc` entry. A caller sends no `Authorization` header in that case.
pub fn apply(
    gpa: Allocator,
    url: Url,
    options: Transfer.Options,
    challenge: ?auth.Challenge,
    detail: Detail,
) ApplyError!?Value {
    if (callerAuthorization(options.headers)) |text| {
        return .{ .text = text, .source = .caller_header };
    }

    // **A bearer token outranks every credential below it, and it answers
    // no challenge.** `--oauth2-bearer` names the one credential to send,
    // so a `401` that asks for Basic or Digest is reported to the user
    // rather than answered with a password from the url or from `-u`. curl
    // does the same: measured, `--oauth2-bearer t -u a:b` sent
    // `Authorization: Bearer t` and sent no Basic value at any point.
    //
    // The token goes out on the first request, which is what a bearer
    // token is for: there is no bearer challenge to wait for.
    if (options.bearer_token) |token| {
        const storage = try gpa.alloc(u8, bearer_prefix_len + token.len);
        errdefer {
            std.crypto.secureZero(u8, storage);
            gpa.free(storage);
        }
        const text = try auth.bearerValue(storage, token);
        return .{ .text = text, .source = .bearer, .storage = storage };
    }

    // Percent-decoding only ever shortens: it turns three bytes into one
    // and leaves every other byte alone. So the encoded userinfo is its
    // own exact bound, and this scratch needs no constant either.
    const user_len = if (url.user) |v| v.len else 0;
    const password_len = if (url.password) |v| v.len else 0;
    const scratch = try gpa.alloc(u8, user_len + password_len);
    // The scratch holds a cleartext password whenever the url carried
    // one, so it is wiped and not merely freed.
    defer {
        std.crypto.secureZero(u8, scratch);
        gpa.free(scratch);
    }

    const resolved = try resolveCredentials(scratch, url, options) orelse return null;

    const digest = if (challenge) |c| c.scheme == .digest else false;
    if (digest) {
        const input: auth.DigestInput = .{
            .credentials = resolved.credentials,
            .challenge = challenge.?,
            .method = detail.method,
            .uri = detail.uri,
            .cnonce = detail.cnonce,
            .nc = detail.nc,
        };
        // Measured first, so an unanswerable challenge is reported before
        // anything is allocated for it.
        const size = try auth.digestValueSize(input);
        const storage = try gpa.alloc(u8, size);
        errdefer {
            std.crypto.secureZero(u8, storage);
            gpa.free(storage);
        }
        const text = try auth.digestValue(storage, input);
        return .{ .text = text, .source = resolved.source, .storage = storage };
    }

    const storage = try gpa.alloc(u8, auth.basicValueSize(resolved.credentials));
    errdefer {
        std.crypto.secureZero(u8, storage);
        gpa.free(storage);
    }
    const text = try auth.basicValue(storage, resolved.credentials);
    return .{ .text = text, .source = resolved.source, .storage = storage };
}

/// One credential and the source it came from.
const Resolved = struct {
    credentials: auth.Credentials,
    source: Source,
};

/// Finds the credentials to send, in curl's order: `url`'s userinfo, then
/// `options.credentials`, then a `netrc` entry for `url.host`.
///
/// `scratch` holds the percent-decoded form of a userinfo credential, the
/// user name first and the password after it. `zurl_core.url.parse`
/// leaves userinfo percent-encoded, by design, so a password holding
/// `%40` is not the same password as one holding `@` until this decodes
/// it. A `scratch` as long as the encoded userinfo is always enough,
/// because decoding never grows a value.
///
/// The result borrows: from `scratch` for a userinfo credential, and from
/// `options` for the other two. Both must outlive the credential.
fn resolveCredentials(
    scratch: []u8,
    url: Url,
    options: Transfer.Options,
) ApplyError!?Resolved {
    if (url.user) |raw_user| {
        const user = try zurl_core.url.percentDecode(scratch[0..raw_user.len], raw_user);
        const password = if (url.password) |raw_password|
            try zurl_core.url.percentDecode(scratch[raw_user.len..], raw_password)
        else
            "";
        return .{ .credentials = .{ .user = user, .password = password }, .source = .userinfo };
    }

    if (options.credentials) |c| return .{ .credentials = c, .source = .options };

    if (options.netrc_text) |text| {
        if (zurl_core.netrc.lookup(text, url.host)) |entry| {
            return .{
                .credentials = .{
                    .user = entry.login orelse "",
                    .password = entry.password orelse "",
                },
                .source = .netrc,
            };
        }
    }

    return null;
}

const testing = std.testing;

fn parseUrl(text: []const u8) Url {
    return zurl_core.url.parse(text) catch unreachable;
}

/// A `Detail` for tests that never reach the digest path, where its
/// fields go unread.
const no_detail: Detail = .{ .method = "GET", .uri = "/", .cnonce = "", .nc = 0 };

/// Runs `apply` on the test allocator. The caller must `deinit` what it
/// gets back.
fn applied(
    url: Url,
    options: Transfer.Options,
    challenge: ?auth.Challenge,
    detail: Detail,
) ApplyError!?Value {
    return apply(testing.allocator, url, options, challenge, detail);
}

test "--oauth2-bearer sends a Bearer value and outranks every password" {
    // **The guard on the order.** A bearer token is the credential the
    // user named, so a url password, a `-u` password, and a netrc entry
    // must all stay off the wire. Each of the three is set here, and a
    // build that read any of them writes a `Basic` value instead.
    const url = parseUrl("http://alice:s3cret@example.com/");
    var v = (try applied(url, .{
        .bearer_token = "tok-123",
        .credentials = .{ .user = "bob", .password = "wrong" },
        .netrc_text = "machine example.com login netrcuser password netrcpass",
    }, null, no_detail)).?;
    defer v.deinit(testing.allocator);

    try testing.expectEqualStrings("Bearer tok-123", v.text);
    try testing.expectEqual(Source.bearer, v.source);
}

test "an Authorization header the caller wrote still outranks a bearer token" {
    // `-H Authorization` is the one credential above every other, and a
    // bearer token does not change that. Two `Authorization` headers on
    // one request let the server pick, so exactly one value may be built.
    const url = parseUrl("http://example.com/");
    var v = (try applied(url, .{
        .bearer_token = "tok-123",
        .headers = &.{.{ .name = "Authorization", .value = "Token other" }},
    }, null, no_detail)).?;
    defer v.deinit(testing.allocator);

    try testing.expectEqualStrings("Token other", v.text);
    try testing.expectEqual(Source.caller_header, v.source);
}

test "a bearer token answers no Digest challenge" {
    // A `401` that names Digest is answered with a password, and a run
    // that named a bearer token has none to answer with. The token goes
    // out again rather than a Digest value built from a password the user
    // did not choose for this server.
    const url = parseUrl("http://alice:s3cret@example.com/");
    var v = (try applied(url, .{ .bearer_token = "tok-123" }, .{
        .scheme = .digest,
        .realm = "r",
        .nonce = "n",
    }, .{ .method = "GET", .uri = "/", .cnonce = "abcdef", .nc = 1 })).?;
    defer v.deinit(testing.allocator);

    try testing.expectEqualStrings("Bearer tok-123", v.text);
    try testing.expectEqual(Source.bearer, v.source);
}

test "the bearer storage is measured exactly, so bearerValue never runs short" {
    // `bearer_prefix_len` is written here and the prefix is written in
    // `zurl_core.auth`. This pins the two together: a longer prefix there
    // with no change here would be `error.NoSpaceLeft` at run time, on
    // the one path that carries a credential.
    var buffer: [64]u8 = undefined;
    const value = try auth.bearerValue(&buffer, "t");
    try testing.expectEqual(bearer_prefix_len + 1, value.len);
}

test "userinfo in the url wins over the options credentials" {
    const url = parseUrl("http://alice:s3cret@example.com/");
    var v = (try applied(url, .{
        .credentials = .{ .user = "bob", .password = "wrong" },
    }, null, no_detail)).?;
    defer v.deinit(testing.allocator);

    var expected_buf: [256]u8 = undefined;
    const expected = try auth.basicValue(&expected_buf, .{ .user = "alice", .password = "s3cret" });
    try testing.expectEqualStrings(expected, v.text);
    try testing.expectEqual(Source.userinfo, v.source);
}

test "a percent-encoded password in the url is decoded before use" {
    // "%40" decodes to "@". A password compared byte for byte against the
    // still-encoded form would never match what the server expects.
    const url = parseUrl("http://alice:s3%40cret@example.com/");
    var v = (try applied(url, .{}, null, no_detail)).?;
    defer v.deinit(testing.allocator);

    var expected_buf: [256]u8 = undefined;
    const expected = try auth.basicValue(&expected_buf, .{ .user = "alice", .password = "s3@cret" });
    try testing.expectEqualStrings(expected, v.text);
}

test "options credentials win over a netrc entry" {
    const url = parseUrl("http://example.com/");
    var v = (try applied(url, .{
        .credentials = .{ .user = "opt", .password = "optpass" },
        .netrc_text = "machine example.com login netrcuser password netrcpass",
    }, null, no_detail)).?;
    defer v.deinit(testing.allocator);

    var expected_buf: [256]u8 = undefined;
    const expected = try auth.basicValue(&expected_buf, .{ .user = "opt", .password = "optpass" });
    try testing.expectEqualStrings(expected, v.text);
    try testing.expectEqual(Source.options, v.source);
}

test "a netrc entry is used when nothing else is set" {
    const url = parseUrl("http://example.com/");
    var v = (try applied(url, .{
        .netrc_text = "machine example.com login netrcuser password netrcpass",
    }, null, no_detail)).?;
    defer v.deinit(testing.allocator);

    var expected_buf: [256]u8 = undefined;
    const expected = try auth.basicValue(&expected_buf, .{ .user = "netrcuser", .password = "netrcpass" });
    try testing.expectEqualStrings(expected, v.text);
    try testing.expectEqual(Source.netrc, v.source);
}

test "no credentials anywhere produces no authorization header" {
    const url = parseUrl("http://example.com/");
    const v = try applied(url, .{}, null, no_detail);
    try testing.expect(v == null);
}

test "a netrc entry with no match and no default also produces no header" {
    const url = parseUrl("http://other.example.com/");
    const v = try applied(url, .{
        .netrc_text = "machine example.com login alice password secret",
    }, null, no_detail);
    try testing.expect(v == null);
}

test "a digest challenge produces a digest header, not basic" {
    var scratch: [512]u8 = undefined;
    const url = parseUrl("http://bob:secret@example.com/x");
    const challenge = auth.parseChallenge(&scratch, "Digest realm=\"r\", nonce=\"n\"").?;
    var v = (try applied(url, .{}, challenge, .{
        .method = "GET",
        .uri = "/x",
        .cnonce = "abc",
        .nc = 1,
    })).?;
    defer v.deinit(testing.allocator);
    try testing.expect(std.mem.startsWith(u8, v.text, "Digest "));
    try testing.expect(!std.mem.startsWith(u8, v.text, "Basic "));
}

test "no challenge builds basic when credentials exist" {
    const url = parseUrl("http://bob:secret@example.com/x");
    var v = (try applied(url, .{}, null, no_detail)).?;
    defer v.deinit(testing.allocator);
    try testing.expect(std.mem.startsWith(u8, v.text, "Basic "));
}

test "a digest response over a request target with a query matches an independent md5" {
    // The value below was computed outside this program, with md5sum, from
    // the RFC 7616 section 3.4.1 construction:
    //   A1       = md5("bob:test:hunter2")       = 9d6e750c...
    //   A2       = md5("GET:/dir/index.html?q=1") = 0b94ddca...
    //   response = md5(A1 ++ ":abc123:00000001:cafebabe:auth:" ++ A2)
    // Signing the path alone gives 638a1be1a09cbb0b90198c614c200f86
    // instead, which is what a server would reject.
    var scratch: [512]u8 = undefined;
    const url = parseUrl("http://bob:hunter2@example.com/dir/index.html?q=1");
    const challenge = auth.parseChallenge(&scratch, "Digest realm=\"test\", nonce=\"abc123\", qop=\"auth\"").?;
    var v = (try applied(url, .{}, challenge, .{
        .method = "GET",
        .uri = "/dir/index.html?q=1",
        .cnonce = "cafebabe",
        .nc = 1,
    })).?;
    defer v.deinit(testing.allocator);
    try testing.expectEqualStrings(
        "Digest username=\"bob\", realm=\"test\", nonce=\"abc123\", uri=\"/dir/index.html?q=1\", " ++
            "algorithm=MD5, response=\"5119fd64cf27560fe5a40f44877ce06b\", " ++
            "qop=auth, nc=00000001, cnonce=\"cafebabe\"",
        v.text,
    );
}

test "a digest response over an escaped request target matches an independent md5" {
    // The value below was computed outside this program, with md5sum:
    //   A1       = md5("bob:test:hunter2")        = 9d6e750c...
    //   A2       = md5("GET:/a%20b/c?x=%26y")     = 3e736d4a...
    //   response = md5(A1 ++ ":abc123:00000001:cafebabe:auth:" ++ A2)
    // The escape is signed once, exactly as the request line writes it.
    // Signing the double-escaped form "/a%2520b/c?x=%2526y" gives
    // 3635917e207561873d3bdf4ca50c0054, which is what a request line that
    // escaped the `%` again would have needed.
    var scratch: [512]u8 = undefined;
    const url = parseUrl("http://bob:hunter2@example.com/a%20b/c?x=%26y");
    const challenge = auth.parseChallenge(&scratch, "Digest realm=\"test\", nonce=\"abc123\", qop=\"auth\"").?;
    var v = (try applied(url, .{}, challenge, .{
        .method = "GET",
        .uri = "/a%20b/c?x=%26y",
        .cnonce = "cafebabe",
        .nc = 1,
    })).?;
    defer v.deinit(testing.allocator);
    try testing.expectEqualStrings(
        "Digest username=\"bob\", realm=\"test\", nonce=\"abc123\", uri=\"/a%20b/c?x=%26y\", " ++
            "algorithm=MD5, response=\"fd8883a22068dec62101f261b21b7bf1\", " ++
            "qop=auth, nc=00000001, cnonce=\"cafebabe\"",
        v.text,
    );
}

test "a caller's authorization header wins over every credential source" {
    // curl sends the header the caller wrote. zurl used to build its own
    // beside it, and put it first, so a server honoured the url password
    // and discarded the caller's token.
    const url = parseUrl("http://bob:hunter2@example.com/");
    const headers = [_]std.http.Header{.{ .name = "Authorization", .value = "Bearer caller-token" }};
    var v = (try applied(url, .{
        .headers = &headers,
        .credentials = .{ .user = "opt", .password = "optpass" },
        .netrc_text = "machine example.com login netrcuser password netrcpass",
    }, null, no_detail)).?;
    defer v.deinit(testing.allocator);
    try testing.expectEqualStrings("Bearer caller-token", v.text);
    try testing.expectEqual(Source.caller_header, v.source);
    // Borrowed, not built. Nothing was allocated for it.
    try testing.expectEqual(@as(usize, 0), v.storage.len);
}

test "a caller's authorization header wins whatever case it is written in" {
    const url = parseUrl("http://bob:hunter2@example.com/");
    const headers = [_]std.http.Header{.{ .name = "aUtHoRiZaTiOn", .value = "Bearer caller-token" }};
    var v = (try applied(url, .{ .headers = &headers }, null, no_detail)).?;
    defer v.deinit(testing.allocator);
    try testing.expectEqualStrings("Bearer caller-token", v.text);
}

test "a caller's authorization header answers a digest challenge with itself" {
    // A challenge does not let zurl replace what the caller wrote. The
    // caller owns the credential, challenge or none.
    var scratch: [512]u8 = undefined;
    const url = parseUrl("http://bob:hunter2@example.com/x");
    const challenge = auth.parseChallenge(&scratch, "Digest realm=\"r\", nonce=\"n\"").?;
    const headers = [_]std.http.Header{.{ .name = "Authorization", .value = "Bearer caller-token" }};
    var v = (try applied(url, .{ .headers = &headers }, challenge, .{
        .method = "GET",
        .uri = "/x",
        .cnonce = "abc",
        .nc = 1,
    })).?;
    defer v.deinit(testing.allocator);
    try testing.expectEqualStrings("Bearer caller-token", v.text);
}

test "a header that is not authorization leaves the credential alone" {
    // `Proxy-Authorization` is a different header. This module ignores it,
    // and `Client.splitHeaders` refuses it before a transfer sends
    // anything, so it never reaches a server either way.
    const url = parseUrl("http://bob:hunter2@example.com/");
    const headers = [_]std.http.Header{
        .{ .name = "X-Authorization-Note", .value = "not a credential" },
        .{ .name = "Proxy-Authorization", .value = "Basic other" },
    };
    var v = (try applied(url, .{ .headers = &headers }, null, no_detail)).?;
    defer v.deinit(testing.allocator);

    var expected_buf: [256]u8 = undefined;
    const expected = try auth.basicValue(&expected_buf, .{ .user = "bob", .password = "hunter2" });
    try testing.expectEqualStrings(expected, v.text);
}

test "callerAuthorization reports the first of two headers" {
    const headers = [_]std.http.Header{
        .{ .name = "Authorization", .value = "Bearer first" },
        .{ .name = "authorization", .value = "Bearer second" },
    };
    try testing.expectEqualStrings("Bearer first", callerAuthorization(&headers).?);
    try testing.expectEqual(@as(?[]const u8, null), callerAuthorization(&.{}));
}

test "an incomplete digest challenge reports the error, not a header" {
    var scratch: [512]u8 = undefined;
    const url = parseUrl("http://bob:secret@example.com/x");
    const challenge = auth.parseChallenge(&scratch, "Digest realm=\"r\"").?;
    try testing.expectError(error.IncompleteChallenge, applied(url, .{}, challenge, .{
        .method = "GET",
        .uri = "/x",
        .cnonce = "abc",
        .nc = 1,
    }));
}

/// A token the length of the ones a binary cache and a forge hand out.
/// The netrc that broke zurl held four of about this size.
const long_token_len = 1200;

test "a netrc token of 1200 characters builds a basic value" {
    // The defect this test pins: a 256-byte buffer for a decoded
    // credential answered `error.NoSpaceLeft`, which the client reported
    // as a malformed url. Nothing about the credential was malformed, and
    // curl sends the same one without complaint.
    var token: [long_token_len]u8 = @splat('t');
    var netrc_buf: [long_token_len + 64]u8 = undefined;
    const netrc_text = try std.fmt.bufPrint(
        &netrc_buf,
        "machine example.com login cache password {s}",
        .{&token},
    );

    const url = parseUrl("http://example.com/nix-cache-info");
    var v = (try applied(url, .{ .netrc_text = netrc_text }, null, no_detail)).?;
    defer v.deinit(testing.allocator);

    try testing.expectEqual(Source.netrc, v.source);
    try testing.expect(std.mem.startsWith(u8, v.text, "Basic "));

    // The value decodes back to the credential that went in, so nothing
    // was truncated on the way through.
    const decoder = std.base64.standard.Decoder;
    const encoded = v.text["Basic ".len..];
    const raw = try testing.allocator.alloc(u8, try decoder.calcSizeForSlice(encoded));
    defer testing.allocator.free(raw);
    try decoder.decode(raw, encoded);
    try testing.expectEqual(@as(usize, "cache:".len + long_token_len), raw.len);
    try testing.expectEqualStrings("cache:", raw[0.."cache:".len]);
    try testing.expectEqualStrings(&token, raw["cache:".len..]);
}

test "a 1200 character password in the url survives the decode" {
    var token: [long_token_len]u8 = @splat('p');
    var url_buf: [long_token_len + 64]u8 = undefined;
    const url_text = try std.fmt.bufPrint(&url_buf, "http://alice:{s}@example.com/", .{&token});

    const url = parseUrl(url_text);
    var v = (try applied(url, .{}, null, no_detail)).?;
    defer v.deinit(testing.allocator);

    var expected_buf: [long_token_len * 3]u8 = undefined;
    const expected = try auth.basicValue(&expected_buf, .{ .user = "alice", .password = &token });
    try testing.expectEqualStrings(expected, v.text);
    try testing.expectEqual(Source.userinfo, v.source);
}

test "a 1200 character token answers a digest challenge too" {
    // The digest path allocates from `auth.digestValueSize` and not from
    // the basic arithmetic, so it needs its own proof at this size.
    var token: [long_token_len]u8 = @splat('d');
    var netrc_buf: [long_token_len + 64]u8 = undefined;
    const netrc_text = try std.fmt.bufPrint(
        &netrc_buf,
        "machine example.com login cache password {s}",
        .{&token},
    );

    var scratch: [512]u8 = undefined;
    const challenge = auth.parseChallenge(&scratch, "Digest realm=\"r\", nonce=\"n\", qop=\"auth\"").?;
    const url = parseUrl("http://example.com/x");
    var v = (try applied(url, .{ .netrc_text = netrc_text }, challenge, .{
        .method = "GET",
        .uri = "/x",
        .cnonce = "abc",
        .nc = 1,
    })).?;
    defer v.deinit(testing.allocator);
    try testing.expect(std.mem.startsWith(u8, v.text, "Digest username=\"cache\""));
    // The password hashes into the response and never travels, so a long
    // one leaves the value short.
    try testing.expect(v.text.len < long_token_len);
}

test "the allocation fits the value with nothing left over" {
    // A buffer measured from the credential, and not from a constant, is
    // the whole point of this module's sizing. `basicValueSize` reports
    // the buffer, which holds the value and the raw form beside it.
    const c: auth.Credentials = .{ .user = "cache", .password = "a" ** long_token_len };
    var v = (try applied(parseUrl("http://cache:" ++ "a" ** long_token_len ++ "@example.com/"), .{}, null, no_detail)).?;
    defer v.deinit(testing.allocator);
    try testing.expectEqual(auth.basicValueSize(c), v.storage.len);
    try testing.expectEqual(auth.basicValueLen(c), v.text.len);
}

test "deinit on a borrowed value frees nothing and is safe twice" {
    const headers = [_]std.http.Header{.{ .name = "Authorization", .value = "Bearer caller-token" }};
    var v = (try applied(parseUrl("http://example.com/"), .{ .headers = &headers }, null, no_detail)).?;
    v.deinit(testing.allocator);
    v.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), v.text.len);
}
