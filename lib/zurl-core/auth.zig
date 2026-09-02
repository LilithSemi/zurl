//! HTTP authorization headers and the challenges that ask for them.
//!
//! This module builds header values into a caller-supplied buffer and parses a
//! `WWW-Authenticate` value. It does no I/O and it keeps no state between
//! calls.

const std = @import("std");

/// A user name and a password. Both borrow from the caller.
pub const Credentials = struct {
    user: []const u8,
    password: []const u8,
};

/// The authorization schemes that zurl builds.
pub const Scheme = enum { basic, bearer, digest };

/// A parsed `WWW-Authenticate` value.
///
/// Every slice borrows: from the header value, or from the `scratch` that
/// `parseChallenge` read into when a value carried a quoted-pair. Both must
/// outlive the `Challenge`.
///
/// A value holds what the server meant, not what it wrote: the quotes are
/// off and a quoted-pair is unescaped, so `realm="a\"b"` reads here as
/// `a"b`. That is the text a digest response hashes, and `writeQuoted` puts
/// the escapes back when the value goes out again.
pub const Challenge = struct {
    scheme: Scheme,
    realm: ?[]const u8 = null,
    nonce: ?[]const u8 = null,
    qop: ?[]const u8 = null,
    algorithm: ?[]const u8 = null,
    /// The `opaque` parameter. `opaque` is a Zig keyword, so the field has a
    /// different name.
    opaque_token: ?[]const u8 = null,
    stale: bool = false,
};

/// The scheme name and the space that start every `Basic` value.
const basic_prefix = "Basic ";

/// How large an `out` `basicValue` needs for `c`, in bytes.
///
/// This is the buffer size and not the value length. `basicValue` builds
/// the raw "user:password" form inside the same buffer, past the value it
/// returns, so the buffer is longer than the value by that raw length.
/// Use `basicValueLen` for the length of the value itself.
///
/// A caller sizes an allocation from the credential it holds, so no
/// constant anywhere has to guess how long a credential is.
pub fn basicValueSize(c: Credentials) usize {
    const raw_len = c.user.len + 1 + c.password.len;
    return basicValueLen(c) + raw_len;
}

/// How long the `Basic` value for `c` is, in bytes.
///
/// The value is the prefix and the base64 of "user:password", so its
/// length follows from the credential length alone.
pub fn basicValueLen(c: Credentials) usize {
    const raw_len = c.user.len + 1 + c.password.len;
    return basic_prefix.len + std.base64.standard.Encoder.calcSize(raw_len);
}

/// Writes a `Basic` authorization value into `out`.
///
/// RFC 7617 says the value is the base64 of "user:password". `out` must
/// hold the prefix, the encoded form, and the raw "user:password" form all
/// at once. Returns `error.NoSpaceLeft` when it does not. RFC 7617 sets no
/// limit on credential length, so a large enough `out` always works.
/// `basicValueSize` reports how large that is for one credential.
///
/// This function leaves no plaintext behind. It wipes the scratch region
/// that held the raw "user:password" form before it returns, so `out` holds
/// only the encoded value past the returned slice.
pub fn basicValue(out: []u8, c: Credentials) error{NoSpaceLeft}![]u8 {
    const prefix = basic_prefix;
    const raw_len = c.user.len + 1 + c.password.len;
    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(raw_len);
    const total = prefix.len + encoded_len + raw_len;
    if (total > out.len) return error.NoSpaceLeft;

    // Build "user:password" at the tail of `out`, then encode it forward
    // into the front of the same buffer. The size check above guarantees
    // `prefix.len + encoded_len <= out.len - raw_len`, so the encoded range
    // and the raw range never overlap. Safety comes from that arithmetic,
    // not from any assumption about how the encoder orders its reads and
    // writes.
    const raw_start = out.len - raw_len;
    @memcpy(out[raw_start..][0..c.user.len], c.user);
    out[raw_start + c.user.len] = ':';
    @memcpy(out[raw_start + c.user.len + 1 ..][0..c.password.len], c.password);

    @memcpy(out[0..prefix.len], prefix);
    const encoded = encoder.encode(out[prefix.len .. prefix.len + encoded_len], out[raw_start..]);
    const result = out[0 .. prefix.len + encoded.len];

    // The raw range sits past `result`, since `prefix.len + encoded_len <=
    // raw_start`. Wiping it here cannot touch the value this function
    // returns.
    std.crypto.secureZero(u8, out[raw_start..]);
    return result;
}

/// Writes a `Bearer` authorization value into `out`.
pub fn bearerValue(out: []u8, token: []const u8) error{NoSpaceLeft}![]u8 {
    const prefix = "Bearer ";
    const total = prefix.len + token.len;
    if (total > out.len) return error.NoSpaceLeft;
    @memcpy(out[0..prefix.len], prefix);
    @memcpy(out[prefix.len..total], token);
    return out[0..total];
}

/// Parses one `WWW-Authenticate` value.
///
/// `scratch` holds every parameter value that carried a quoted-pair, with
/// the escapes taken off. RFC 9110 section 5.6.4 writes a backslash in
/// front of a `"` or a `\` inside a quoted string, so `realm="a\"b"` names
/// the realm `a"b`. A reader that keeps the backslash hashes it into A1,
/// and the response then does not match what the server computed. A
/// `scratch` as long as `header_value` is always enough: taking an escape
/// off only ever shortens a value, and a value with no escape keeps
/// borrowing from `header_value`.
///
/// Returns null when the scheme is not one that zurl builds, and when
/// `scratch` is too small. The header comes from a server, so unknown
/// input is a runtime fault and not an assertion.
pub fn parseChallenge(scratch: []u8, header_value: []const u8) ?Challenge {
    const trimmed = std.mem.trim(u8, header_value, " \t");
    if (trimmed.len == 0) return null;

    const space = std.mem.indexOfScalar(u8, trimmed, ' ') orelse trimmed.len;
    const scheme_name = trimmed[0..space];
    const scheme: Scheme =
        if (std.ascii.eqlIgnoreCase(scheme_name, "basic"))
            .basic
        else if (std.ascii.eqlIgnoreCase(scheme_name, "bearer"))
            .bearer
        else if (std.ascii.eqlIgnoreCase(scheme_name, "digest"))
            .digest
        else
            return null;

    var challenge: Challenge = .{ .scheme = scheme };
    if (space == trimmed.len) return challenge;

    var used: usize = 0;
    var params: ParamSplitter = .{ .rest = trimmed[space + 1 ..] };
    while (params.next()) |raw_param| {
        const param = std.mem.trim(u8, raw_param, " \t");
        const eq = std.mem.indexOfScalar(u8, param, '=') orelse continue;
        const name = std.mem.trim(u8, param[0..eq], " \t");
        const value = unquoteOnce(scratch, &used, std.mem.trim(u8, param[eq + 1 ..], " \t")) orelse return null;

        if (std.ascii.eqlIgnoreCase(name, "realm")) {
            challenge.realm = value;
        } else if (std.ascii.eqlIgnoreCase(name, "nonce")) {
            challenge.nonce = value;
        } else if (std.ascii.eqlIgnoreCase(name, "qop")) {
            challenge.qop = value;
        } else if (std.ascii.eqlIgnoreCase(name, "algorithm")) {
            challenge.algorithm = value;
        } else if (std.ascii.eqlIgnoreCase(name, "opaque")) {
            challenge.opaque_token = value;
        } else if (std.ascii.eqlIgnoreCase(name, "stale")) {
            challenge.stale = std.ascii.eqlIgnoreCase(value, "true");
        }
    }
    return challenge;
}

/// Parses the challenge that zurl should answer out of one
/// `WWW-Authenticate` value.
///
/// RFC 9110 lets one value carry more than one challenge, separated by
/// commas, and a server is free to write `Basic` first. `parseChallenge`
/// reads only the challenge at the front, so a value of
/// `Basic realm="r", Digest realm="r", nonce="n"` made zurl answer with
/// `Basic`, which sends the password in reversible base64 to a server that
/// offered a scheme where the password never travels. This picks the
/// `Digest` challenge whenever the value holds one, and falls back to the
/// front challenge when it does not.
///
/// `scratch` works the same way it works in `parseChallenge`, and must
/// outlive the returned `Challenge`.
pub fn selectChallenge(scratch: []u8, header_value: []const u8) ?Challenge {
    if (digestChallengeStart(header_value)) |i| return parseChallenge(scratch, header_value[i..]);
    return parseChallenge(scratch, header_value);
}

/// Whether `header_value` offers a `Digest` challenge anywhere in it.
pub fn hasDigestChallenge(header_value: []const u8) bool {
    return digestChallengeStart(header_value) != null;
}

/// Where a `Digest` challenge starts inside `header_value`, if one is
/// there.
///
/// Walks the same comma-separated elements `ParamSplitter` walks, and
/// keeps its own index so the caller gets an offset rather than a slice.
/// An element counts as the start of a challenge only when the scheme name
/// stands alone, so a parameter named `digest=1` is not mistaken for one.
fn digestChallengeStart(header_value: []const u8) ?usize {
    var element_start: usize = 0;
    var in_quotes = false;
    var i: usize = 0;
    while (i <= header_value.len) : (i += 1) {
        if (i < header_value.len) {
            const ch = header_value[i];
            if (ch == '\\' and in_quotes and i + 1 < header_value.len) {
                i += 1;
                continue;
            }
            if (ch == '"') {
                in_quotes = !in_quotes;
                continue;
            }
            if (ch != ',' or in_quotes) continue;
        }

        var lead = element_start;
        while (lead < i and (header_value[lead] == ' ' or header_value[lead] == '\t')) lead += 1;
        if (startsWithScheme(header_value[lead..i], "digest")) return lead;

        if (i == header_value.len) break;
        element_start = i + 1;
    }
    return null;
}

/// Whether `element` starts with the scheme name `name`, followed by a
/// space or by nothing. A scheme name is separated from its parameters by
/// a space, so `digest realm="r"` starts a challenge and `digest=1` does
/// not.
fn startsWithScheme(element: []const u8, name: []const u8) bool {
    if (!std.ascii.startsWithIgnoreCase(element, name)) return false;
    if (element.len == name.len) return true;
    return element[name.len] == ' ' or element[name.len] == '\t';
}

/// Splits a challenge's parameter list on commas, without splitting a comma
/// that sits inside a quoted value.
///
/// RFC 7616 lets `qop` hold a quoted, comma-separated list, such as
/// `qop="auth-int,auth"`. A quoted `realm` may also hold a comma. A plain
/// `splitScalar` on `,` breaks both cases, so this splitter tracks whether it
/// is inside a quoted string and only treats a comma outside one as a
/// separator.
///
/// It also honours RFC 7230's quoted-pair rule: a backslash inside a quoted
/// string escapes the next character, so `\"` does not end the string.
const ParamSplitter = struct {
    rest: []const u8,
    done: bool = false,

    fn next(self: *ParamSplitter) ?[]const u8 {
        if (self.done) return null;

        var in_quotes = false;
        var i: usize = 0;
        while (i < self.rest.len) : (i += 1) {
            const ch = self.rest[i];
            if (ch == '\\' and in_quotes and i + 1 < self.rest.len) {
                i += 1;
                continue;
            }
            if (ch == '"') {
                in_quotes = !in_quotes;
                continue;
            }
            if (ch == ',' and !in_quotes) {
                const part = self.rest[0..i];
                self.rest = self.rest[i + 1 ..];
                return part;
            }
        }
        self.done = true;
        return self.rest;
    }
};

/// Strips exactly one leading and one trailing double quote from `v`, and
/// only when both are present.
///
/// `std.mem.trim` strips a whole run of quote characters from each end,
/// which corrupts a value such as `""` or a value next to an escaped quote.
/// A quoted-string delimiter is exactly one quote on each side, so this
/// strips exactly one pair.
fn unquoteOnce(scratch: []u8, used: *usize, v: []const u8) ?[]const u8 {
    if (!(v.len >= 2 and v[0] == '"' and v[v.len - 1] == '"')) return v;
    const inner = v[1 .. v.len - 1];
    // A value with no backslash is the same bytes either way, so it keeps
    // borrowing from the header and costs no scratch.
    if (std.mem.indexOfScalar(u8, inner, '\\') == null) return inner;

    const out = scratch[used.*..];
    var written: usize = 0;
    var i: usize = 0;
    while (i < inner.len) {
        // RFC 9110 section 5.6.4: a quoted-pair is a backslash and the one
        // character after it. A backslash at the very end escapes nothing,
        // so it stays as it is.
        var byte = inner[i];
        if (byte == '\\' and i + 1 < inner.len) {
            i += 1;
            byte = inner[i];
        }
        if (written == out.len) return null;
        out[written] = byte;
        written += 1;
        i += 1;
    }
    used.* += written;
    return out[0..written];
}

/// Everything that a digest response needs beyond the challenge.
pub const DigestInput = struct {
    credentials: Credentials,
    challenge: Challenge,
    /// The request method, in upper case.
    method: []const u8,
    /// The request target, exactly as the request line writes it.
    uri: []const u8,
    /// The client nonce. The caller supplies it so that a test is repeatable.
    /// Real callers take it from `std.Io.random`, seeded outside this
    /// module: Zig 0.16 has no free-standing `std.crypto.random` value, so
    /// generating one needs an `Io`, which this module does not carry.
    cnonce: []const u8,
    /// The nonce count. It starts at 1 for each new server nonce.
    nc: u32,
};

pub const DigestError = error{
    /// The challenge has no nonce, so no response can be built.
    IncompleteChallenge,
    /// The challenge names an algorithm that zurl does not build.
    UnsupportedAlgorithm,
    /// The challenge asks for auth-int, which zurl does not build.
    UnsupportedQop,
    /// A value that belongs in a quoted string holds a C0 control byte or
    /// a DEL. RFC 9110 keeps those out of `qdtext`, and a quoted-pair
    /// escapes only a tab, a space, and a visible character, so no header
    /// value can carry one. See `writeQuoted`.
    InvalidQuotedValue,
    NoSpaceLeft,
};

/// Writes a `Digest` authorization value into `out`.
///
/// RFC 7616. zurl builds MD5 and SHA-256, with `qop=auth` and without `qop`.
/// It does not build `auth-int`, because that needs the whole body in memory.
///
/// Every value that goes in a quoted string is escaped. See `writeQuoted`
/// for what a value that is not escaped does to the header.
///
/// `digestValueSize` reports how large an `out` this needs for one input.
pub fn digestValue(out: []u8, in: DigestInput) DigestError![]u8 {
    var writer: std.Io.Writer = .fixed(out);
    try writeDigestValue(&writer, in);
    return writer.buffered();
}

/// How large an `out` `digestValue` needs for `in`, in bytes.
///
/// Measured and not guessed. This runs the same builder that
/// `digestValue` runs, over a writer that counts its bytes and keeps
/// none, so the answer is the exact length of the value `digestValue`
/// writes. A caller allocates that many bytes and the build then fits
/// with nothing left over.
///
/// Arithmetic on the input lengths cannot replace this. `writeQuoted`
/// escapes a `"` and a `\`, so a quoted parameter grows by an amount that
/// only its own bytes decide.
///
/// Reports the same faults `digestValue` reports for the same input, and
/// reports them before any allocation. `NoSpaceLeft` is not one of them:
/// a writer that keeps no bytes never runs out of room.
pub fn digestValueSize(in: DigestInput) DigestError!usize {
    var counter: std.Io.Writer.Discarding = .init(&.{});
    try writeDigestValue(&counter.writer, in);
    return @intCast(counter.fullCount());
}

/// Writes the `Digest` value for `in` on `w`.
///
/// The one builder behind both `digestValue` and `digestValueSize`. Two
/// builders, one to write and one to measure, would drift apart on the
/// first change to the value's shape.
fn writeDigestValue(w: *std.Io.Writer, in: DigestInput) DigestError!void {
    const nonce = in.challenge.nonce orelse return error.IncompleteChallenge;
    const realm = in.challenge.realm orelse "";

    const algorithm = in.challenge.algorithm orelse "MD5";
    if (std.ascii.eqlIgnoreCase(algorithm, "MD5")) {
        return build(std.crypto.hash.Md5, w, in, nonce, realm, "MD5");
    }
    if (std.ascii.eqlIgnoreCase(algorithm, "SHA-256")) {
        return build(std.crypto.hash.sha2.Sha256, w, in, nonce, realm, "SHA-256");
    }
    return error.UnsupportedAlgorithm;
}

/// Builds the response for one hash type.
fn build(
    comptime Hash: type,
    writer: *std.Io.Writer,
    in: DigestInput,
    nonce: []const u8,
    realm: []const u8,
    algorithm_name: []const u8,
) DigestError!void {
    const hex_len = Hash.digest_length * 2;

    // A1 is "user:realm:password". A2 is "method:uri".
    var a1: [hex_len]u8 = undefined;
    hashHex(Hash, &a1, &.{ in.credentials.user, ":", realm, ":", in.credentials.password });
    var a2: [hex_len]u8 = undefined;
    hashHex(Hash, &a2, &.{ in.method, ":", in.uri });

    var nc_text: [8]u8 = undefined;
    _ = std.fmt.printInt(&nc_text, in.nc, 16, .lower, .{ .width = 8, .fill = '0' });

    var response: [hex_len]u8 = undefined;
    const use_qop = if (in.challenge.qop) |qop| blk: {
        if (!qopHasAuth(qop)) return error.UnsupportedQop;
        break :blk true;
    } else false;

    if (use_qop) {
        hashHex(Hash, &response, &.{
            &a1, ":", nonce, ":", &nc_text, ":", in.cnonce, ":auth:", &a2,
        });
    } else {
        hashHex(Hash, &response, &.{ &a1, ":", nonce, ":", &a2 });
    }

    // `algorithm_name` is one of two literals in this file, and `response`
    // and `nc_text` are hex that this function computed, so those three
    // need no escaping. Every other value came from a caller or from a
    // server and goes through `writeQuoted`.
    writer.writeAll("Digest username=") catch return error.NoSpaceLeft;
    try writeQuoted(writer, in.credentials.user);
    writer.writeAll(", realm=") catch return error.NoSpaceLeft;
    try writeQuoted(writer, realm);
    writer.writeAll(", nonce=") catch return error.NoSpaceLeft;
    try writeQuoted(writer, nonce);
    writer.writeAll(", uri=") catch return error.NoSpaceLeft;
    try writeQuoted(writer, in.uri);
    writer.print(", algorithm={s}, response=\"{s}\"", .{ algorithm_name, &response }) catch
        return error.NoSpaceLeft;
    if (use_qop) {
        writer.print(", qop=auth, nc={s}, cnonce=", .{&nc_text}) catch return error.NoSpaceLeft;
        try writeQuoted(writer, in.cnonce);
    }
    if (in.challenge.opaque_token) |token| {
        writer.writeAll(", opaque=") catch return error.NoSpaceLeft;
        try writeQuoted(writer, token);
    }
}

/// Writes `value` into `writer` as an RFC 9110 quoted string.
///
/// A `"` or a `\` in the value gets a backslash in front of it. Without
/// that escape, a user name of `a", uri="/evil", x="` closed the quoted
/// string and wrote a second `uri` parameter of its own, ahead of the real
/// one. A user name reaches here from a url's userinfo or from a netrc
/// file, and both are third-party text to a package manager.
///
/// The challenge-derived values, which are `realm`, `nonce`, and `opaque`,
/// go through this too. They only travel back to the server that sent
/// them, so the risk is lower, but the rule is the same one and costs
/// nothing extra.
///
/// A C0 control byte and a DEL cannot travel in a quoted string at all:
/// RFC 9110 keeps them out of `qdtext`, and a quoted-pair escapes only a
/// tab, a space, and a visible character. So this refuses one by name
/// rather than build a header value no peer can read.
fn writeQuoted(writer: *std.Io.Writer, value: []const u8) DigestError!void {
    writer.writeByte('"') catch return error.NoSpaceLeft;
    for (value) |byte| switch (byte) {
        0x00...0x08, 0x0a...0x1f, 0x7f => return error.InvalidQuotedValue,
        '"', '\\' => {
            writer.writeByte('\\') catch return error.NoSpaceLeft;
            writer.writeByte(byte) catch return error.NoSpaceLeft;
        },
        else => writer.writeByte(byte) catch return error.NoSpaceLeft,
    };
    writer.writeByte('"') catch return error.NoSpaceLeft;
}

/// Hashes the parts in order and writes the lower-case hex form into `out`.
fn hashHex(comptime Hash: type, out: []u8, parts: []const []const u8) void {
    std.debug.assert(out.len == Hash.digest_length * 2);
    var hash: Hash = .init(.{});
    for (parts) |part| hash.update(part);
    var digest: [Hash.digest_length]u8 = undefined;
    hash.final(&digest);
    _ = std.fmt.bufPrint(out, "{x}", .{&digest}) catch unreachable;
}

/// Returns true when the qop list offers "auth".
///
/// A server may offer more than one, as in `qop="auth,auth-int"`.
fn qopHasAuth(qop: []const u8) bool {
    var it = std.mem.splitScalar(u8, qop, ',');
    while (it.next()) |raw| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, raw, " \t"), "auth")) return true;
    }
    return false;
}

test "basicValueSize is exactly the buffer basicValue needs" {
    // A caller allocates this number and no other. One byte less has to
    // fail, or the number is a guess with a margin hidden in it.
    const cases = [_]Credentials{
        .{ .user = "", .password = "" },
        .{ .user = "a", .password = "b" },
        .{ .user = "alice", .password = "s3cret" },
        // The length that broke zurl: a cache token of 1200 characters.
        .{ .user = "cache", .password = "t" ** 1200 },
        // Every base64 padding case, so no rounding is missed.
        .{ .user = "u", .password = "1" },
        .{ .user = "u", .password = "12" },
        .{ .user = "u", .password = "123" },
    };
    for (cases) |c| {
        const size = basicValueSize(c);
        const buf = try std.testing.allocator.alloc(u8, size);
        defer std.testing.allocator.free(buf);
        const v = try basicValue(buf, c);
        try std.testing.expectEqual(basicValueLen(c), v.len);

        const small = try std.testing.allocator.alloc(u8, size - 1);
        defer std.testing.allocator.free(small);
        try std.testing.expectError(error.NoSpaceLeft, basicValue(small, c));
    }
}

test "digestValueSize is exactly the length digestValue writes" {
    // The digest value is not the basic arithmetic: `writeQuoted` escapes
    // a quote and a backslash, so a parameter grows by an amount only its
    // own bytes decide. The size therefore comes from the same builder,
    // run over a writer that counts.
    var scratch: [512]u8 = undefined;
    const plain = parseChallenge(&scratch, "Digest realm=\"r\", nonce=\"n\"").?;
    var scratch_qop: [512]u8 = undefined;
    const with_qop = parseChallenge(
        &scratch_qop,
        "Digest realm=\"r\", nonce=\"n\", qop=\"auth\", opaque=\"op\"",
    ).?;
    var scratch_escapes: [512]u8 = undefined;
    const with_escapes = parseChallenge(
        &scratch_escapes,
        "Digest realm=\"a\\\"b\", nonce=\"n\", qop=\"auth\"",
    ).?;

    const inputs = [_]DigestInput{
        .{
            .credentials = .{ .user = "bob", .password = "hunter2" },
            .challenge = plain,
            .method = "GET",
            .uri = "/x",
            .cnonce = "",
            .nc = 0,
        },
        .{
            .credentials = .{ .user = "bob", .password = "hunter2" },
            .challenge = with_qop,
            .method = "GET",
            .uri = "/dir/index.html?q=1",
            .cnonce = "cafebabe",
            .nc = 1,
        },
        // A user name that needs escaping, so the escape shows up in the
        // measured length.
        .{
            .credentials = .{ .user = "a\"b\\c", .password = "p" },
            .challenge = with_escapes,
            .method = "POST",
            .uri = "/x",
            .cnonce = "abc",
            .nc = 7,
        },
        // A password of 1200 characters, which never travels in a digest
        // value but must not break the measurement either.
        .{
            .credentials = .{ .user = "cache", .password = "t" ** 1200 },
            .challenge = with_qop,
            .method = "GET",
            .uri = "/nix-cache-info",
            .cnonce = "abc",
            .nc = 1,
        },
    };

    for (inputs) |in| {
        const size = try digestValueSize(in);
        const buf = try std.testing.allocator.alloc(u8, size);
        defer std.testing.allocator.free(buf);
        const v = try digestValue(buf, in);
        try std.testing.expectEqual(size, v.len);

        const small = try std.testing.allocator.alloc(u8, size - 1);
        defer std.testing.allocator.free(small);
        try std.testing.expectError(error.NoSpaceLeft, digestValue(small, in));
    }
}

test "digestValueSize reports an unanswerable challenge before anything is allocated" {
    var scratch: [512]u8 = undefined;
    const no_nonce = parseChallenge(&scratch, "Digest realm=\"r\"").?;
    try std.testing.expectError(error.IncompleteChallenge, digestValueSize(.{
        .credentials = .{ .user = "b", .password = "p" },
        .challenge = no_nonce,
        .method = "GET",
        .uri = "/",
        .cnonce = "",
        .nc = 0,
    }));

    var scratch_alg: [512]u8 = undefined;
    const bad_algorithm = parseChallenge(&scratch_alg, "Digest realm=\"r\", nonce=\"n\", algorithm=SHA-512").?;
    try std.testing.expectError(error.UnsupportedAlgorithm, digestValueSize(.{
        .credentials = .{ .user = "b", .password = "p" },
        .challenge = bad_algorithm,
        .method = "GET",
        .uri = "/",
        .cnonce = "",
        .nc = 0,
    }));
}

test "digestValue matches the MD5 example in RFC 7616 section 3.9.1" {
    var scratch: [512]u8 = undefined;
    const challenge = parseChallenge(&scratch,
        \\Digest realm="http-auth@example.org", qop="auth", algorithm=MD5, nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"
    ).?;
    var buf: [512]u8 = undefined;
    const v = try digestValue(&buf, .{
        .credentials = .{ .user = "Mufasa", .password = "Circle of Life" },
        .challenge = challenge,
        .method = "GET",
        .uri = "/dir/index.html",
        .cnonce = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
        .nc = 1,
    });
    try std.testing.expect(std.mem.indexOf(u8, v, "response=\"8ca523f5e9506fed4657c9700eebdbec\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, v, "username=\"Mufasa\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, v, "nc=00000001") != null);
    try std.testing.expect(std.mem.indexOf(u8, v, "qop=auth") != null);
    try std.testing.expect(std.mem.startsWith(u8, v, "Digest "));
}

test "digestValue builds a SHA-256 response" {
    var scratch: [512]u8 = undefined;
    const challenge = parseChallenge(&scratch,
        \\Digest realm="r", qop="auth", algorithm=SHA-256, nonce="n"
    ).?;
    var buf: [512]u8 = undefined;
    const v = try digestValue(&buf, .{
        .credentials = .{ .user = "bob", .password = "secret" },
        .challenge = challenge,
        .method = "GET",
        .uri = "/x",
        .cnonce = "abc",
        .nc = 1,
    });
    // The response is pinned to a value computed independently with
    // sha256sum, from the RFC 7616 section 3.4.1 construction:
    //   A1 = sha256("bob:r:secret")
    //   A2 = sha256("GET:/x")
    //   response = sha256(A1 ++ ":n:00000001:abc:auth:" ++ A2)
    try std.testing.expectEqualStrings(
        "Digest username=\"bob\", realm=\"r\", nonce=\"n\", uri=\"/x\", algorithm=SHA-256, " ++
            "response=\"4c2b15f98a7f86ba7d84ef04a10ac923b02b06dfef210bf93fd0a80136cfd040\", " ++
            "qop=auth, nc=00000001, cnonce=\"abc\"",
        v,
    );
}

test "digestValue omits qop when the challenge has none" {
    var scratch: [512]u8 = undefined;
    const challenge = parseChallenge(&scratch, "Digest realm=\"r\", nonce=\"n\"").?;
    var buf: [512]u8 = undefined;
    const v = try digestValue(&buf, .{
        .credentials = .{ .user = "bob", .password = "secret" },
        .challenge = challenge,
        .method = "GET",
        .uri = "/x",
        .cnonce = "abc",
        .nc = 1,
    });
    // The response is pinned to a value computed independently with
    // md5sum, from the RFC 7616 section 3.4.1 construction with no qop:
    //   A1 = md5("bob:r:secret")
    //   A2 = md5("GET:/x")
    //   response = md5(A1 ++ ":n:" ++ A2)
    try std.testing.expectEqualStrings(
        "Digest username=\"bob\", realm=\"r\", nonce=\"n\", uri=\"/x\", algorithm=MD5, " ++
            "response=\"73f61c4f9f09e294128988c58316208f\"",
        v,
    );
    try std.testing.expect(std.mem.indexOf(u8, v, "qop=") == null);
    try std.testing.expect(std.mem.indexOf(u8, v, "cnonce=") == null);
}

test "digestValue rejects a challenge with no nonce" {
    var scratch: [512]u8 = undefined;
    const challenge = parseChallenge(&scratch, "Digest realm=\"r\"").?;
    var buf: [512]u8 = undefined;
    try std.testing.expectError(error.IncompleteChallenge, digestValue(&buf, .{
        .credentials = .{ .user = "bob", .password = "secret" },
        .challenge = challenge,
        .method = "GET",
        .uri = "/x",
        .cnonce = "abc",
        .nc = 1,
    }));
}

test "digestValue rejects an algorithm that zurl does not build" {
    var scratch: [512]u8 = undefined;
    const challenge = parseChallenge(&scratch, "Digest realm=\"r\", nonce=\"n\", algorithm=SHA-512-256").?;
    var buf: [512]u8 = undefined;
    try std.testing.expectError(error.UnsupportedAlgorithm, digestValue(&buf, .{
        .credentials = .{ .user = "bob", .password = "secret" },
        .challenge = challenge,
        .method = "GET",
        .uri = "/x",
        .cnonce = "abc",
        .nc = 1,
    }));
}

test "digestValue rejects auth-int, which zurl does not build" {
    var scratch: [512]u8 = undefined;
    const challenge = parseChallenge(&scratch, "Digest realm=\"r\", nonce=\"n\", qop=\"auth-int\"").?;
    var buf: [512]u8 = undefined;
    try std.testing.expectError(error.UnsupportedQop, digestValue(&buf, .{
        .credentials = .{ .user = "bob", .password = "secret" },
        .challenge = challenge,
        .method = "GET",
        .uri = "/x",
        .cnonce = "abc",
        .nc = 1,
    }));
}

test "basicValue builds the header value that RFC 7617 specifies" {
    var buf: [64]u8 = undefined;
    const v = try basicValue(&buf, .{ .user = "Aladdin", .password = "open sesame" });
    try std.testing.expectEqualStrings("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", v);
}

test "basicValue leaves no plaintext credential behind in the whole buffer" {
    var buf: [64]u8 = undefined;
    const v = try basicValue(&buf, .{ .user = "Aladdin", .password = "open sesame" });
    try std.testing.expectEqualStrings("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", v);

    // Inspect the whole buffer, not just the returned slice. The plaintext
    // "user:password" form was built at the tail of `buf` before it was
    // encoded forward, so a leak would show up past the end of `v`.
    try std.testing.expect(std.mem.indexOf(u8, &buf, "Aladdin:open sesame") == null);
    try std.testing.expect(std.mem.indexOf(u8, &buf, "open sesame") == null);
}

test "basicValue accepts an empty password" {
    var buf: [64]u8 = undefined;
    const v = try basicValue(&buf, .{ .user = "bob", .password = "" });
    try std.testing.expectEqualStrings("Basic Ym9iOg==", v);
}

test "basicValue reports a buffer that is too small" {
    var buf: [4]u8 = undefined;
    try std.testing.expectError(
        error.NoSpaceLeft,
        basicValue(&buf, .{ .user = "Aladdin", .password = "open sesame" }),
    );
}

test "bearerValue builds the header value that RFC 6750 specifies" {
    var buf: [32]u8 = undefined;
    const v = try bearerValue(&buf, "abc123");
    try std.testing.expectEqualStrings("Bearer abc123", v);
}

test "parseChallenge reads a digest challenge" {
    var scratch: [512]u8 = undefined;
    const c = parseChallenge(&scratch,
        \\Digest realm="test", qop="auth", nonce="dcd98b7102dd2f0e", opaque="5ccc069c", algorithm=SHA-256
    ).?;
    try std.testing.expectEqual(Scheme.digest, c.scheme);
    try std.testing.expectEqualStrings("test", c.realm.?);
    try std.testing.expectEqualStrings("auth", c.qop.?);
    try std.testing.expectEqualStrings("dcd98b7102dd2f0e", c.nonce.?);
    try std.testing.expectEqualStrings("5ccc069c", c.opaque_token.?);
    try std.testing.expectEqualStrings("SHA-256", c.algorithm.?);
    try std.testing.expectEqual(false, c.stale);
}

test "parseChallenge reads a basic challenge" {
    var scratch: [512]u8 = undefined;
    const c = parseChallenge(&scratch, "Basic realm=\"here\"").?;
    try std.testing.expectEqual(Scheme.basic, c.scheme);
    try std.testing.expectEqualStrings("here", c.realm.?);
    try std.testing.expectEqual(@as(?[]const u8, null), c.nonce);
}

test "parseChallenge reads stale as a boolean" {
    var scratch: [512]u8 = undefined;
    const c = parseChallenge(&scratch, "Digest realm=\"r\", nonce=\"n\", stale=TRUE").?;
    try std.testing.expectEqual(true, c.stale);
}

test "parseChallenge returns null for a scheme that zurl does not know" {
    var scratch: [512]u8 = undefined;
    try std.testing.expectEqual(@as(?Challenge, null), parseChallenge(&scratch, "Negotiate"));
}

test "selectChallenge answers the digest challenge a server offered after basic" {
    // A server that lists `Basic` first used to get a `Basic` answer, so
    // the password went out in reversible base64 to a server that had
    // offered a scheme where it never travels.
    var scratch: [512]u8 = undefined;
    const value =
        \\Basic realm="r", Digest realm="d", nonce="n", qop="auth"
    ;
    try std.testing.expectEqual(Scheme.basic, parseChallenge(&scratch, value).?.scheme);

    const c = selectChallenge(&scratch, value).?;
    try std.testing.expectEqual(Scheme.digest, c.scheme);
    try std.testing.expectEqualStrings("d", c.realm.?);
    try std.testing.expectEqualStrings("n", c.nonce.?);
    try std.testing.expectEqualStrings("auth", c.qop.?);
    try std.testing.expect(hasDigestChallenge(value));
}

test "selectChallenge keeps the basic challenge when no digest is offered" {
    var scratch: [512]u8 = undefined;
    const c = selectChallenge(&scratch, "Basic realm=\"here\"").?;
    try std.testing.expectEqual(Scheme.basic, c.scheme);
    try std.testing.expectEqualStrings("here", c.realm.?);
    try std.testing.expect(!hasDigestChallenge("Basic realm=\"here\""));
}

test "selectChallenge does not read a parameter named digest as a challenge" {
    var scratch: [512]u8 = undefined;
    const value =
        \\Basic realm="r", digest=1
    ;
    try std.testing.expect(!hasDigestChallenge(value));
    try std.testing.expectEqual(Scheme.basic, selectChallenge(&scratch, value).?.scheme);
}

test "selectChallenge ignores the word digest inside a quoted realm" {
    var scratch: [512]u8 = undefined;
    const value =
        \\Basic realm="Digest zone, please"
    ;
    try std.testing.expect(!hasDigestChallenge(value));
    try std.testing.expectEqual(Scheme.basic, selectChallenge(&scratch, value).?.scheme);
}

test "selectChallenge reads a digest challenge that stands alone" {
    var scratch: [512]u8 = undefined;
    const c = selectChallenge(&scratch, "Digest realm=\"r\", nonce=\"n\"").?;
    try std.testing.expectEqual(Scheme.digest, c.scheme);
    try std.testing.expectEqualStrings("n", c.nonce.?);
}

test "selectChallenge returns null for a value with no scheme zurl builds" {
    var scratch: [512]u8 = undefined;
    try std.testing.expectEqual(@as(?Challenge, null), selectChallenge(&scratch, "Negotiate"));
    try std.testing.expectEqual(@as(?Challenge, null), selectChallenge(&scratch, ""));
}

test "parseChallenge returns null for an empty value" {
    var scratch: [512]u8 = undefined;
    try std.testing.expectEqual(@as(?Challenge, null), parseChallenge(&scratch, ""));
}

test "parseChallenge keeps a quoted qop list intact, and digestValue picks auth from it" {
    // A naive split on every comma would cut this to just "auth-int", which
    // has no "auth" member, so digestValue would wrongly reject a server
    // that does offer "auth".
    var scratch: [512]u8 = undefined;
    const challenge = parseChallenge(&scratch,
        \\Digest realm="r", nonce="n", qop="auth-int,auth"
    ).?;
    try std.testing.expectEqualStrings("auth-int,auth", challenge.qop.?);

    var buf: [512]u8 = undefined;
    const v = try digestValue(&buf, .{
        .credentials = .{ .user = "bob", .password = "secret" },
        .challenge = challenge,
        .method = "GET",
        .uri = "/x",
        .cnonce = "abc",
        .nc = 1,
    });
    try std.testing.expect(std.mem.indexOf(u8, v, "qop=auth") != null);
}

test "parseChallenge keeps a quoted qop list intact no matter the member order" {
    var scratch: [512]u8 = undefined;
    const c = parseChallenge(&scratch,
        \\Digest realm="r", nonce="n", qop="auth,auth-int"
    ).?;
    try std.testing.expectEqualStrings("auth,auth-int", c.qop.?);
}

test "parseChallenge keeps a comma inside a quoted realm intact" {
    var scratch: [512]u8 = undefined;
    const c = parseChallenge(&scratch,
        \\Digest realm="my, realm", nonce="n"
    ).?;
    try std.testing.expectEqualStrings("my, realm", c.realm.?);
}

test "parseChallenge strips exactly one pair of quotes, not a run" {
    // The outer quotes come off once. The inner ones are a quoted-pair, so
    // they are part of the realm and the backslashes in front of them are
    // not: this used to read `say \"hi\"`, and A1 then hashed two
    // backslashes the server never had.
    var scratch: [512]u8 = undefined;
    const c = parseChallenge(&scratch,
        \\Digest realm="say \"hi\"", nonce="n"
    ).?;
    try std.testing.expectEqualStrings("say \"hi\"", c.realm.?);
}

// The two tests below guard the buffer arithmetic in basicValue at its
// tightest sizes. `out` must hold the prefix, the encoded form, and the raw
// "user:password" form all at once, because basicValue builds the raw form
// at the tail of `out` before it encodes forward into the front.

test "basicValue writes the header value into a buffer sized to the exact minimum" {
    // "ab:" is 3 raw bytes, so it needs no base64 padding.
    var buf: [13]u8 = undefined; // "Basic ".len (6) + calcSize(3) (4) + 3
    const v = try basicValue(&buf, .{ .user = "ab", .password = "" });
    try std.testing.expectEqualStrings("Basic YWI6", v);
}

test "basicValue handles a raw length that is a multiple of three, at the exact minimum size" {
    // "user:pass" is 9 raw bytes: three whole base64 groups.
    var buf: [27]u8 = undefined; // "Basic ".len (6) + calcSize(9) (12) + 9
    const v = try basicValue(&buf, .{ .user = "user", .password = "pass" });
    try std.testing.expectEqualStrings("Basic dXNlcjpwYXNz", v);
}

test "basicValue accepts credentials well over the old 512-byte cap" {
    const user = "svc-account";
    var password: [601]u8 = undefined;
    @memset(&password, 'p');
    const raw_len = user.len + 1 + password.len; // 613, over the old cap.

    var buf: [2048]u8 = undefined;
    const v = try basicValue(&buf, .{ .user = user, .password = &password });

    try std.testing.expect(std.mem.startsWith(u8, v, "Basic "));
    const encoded = v["Basic ".len..];
    var decoded: [raw_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&decoded, encoded);

    try std.testing.expectEqualStrings(user, decoded[0..user.len]);
    try std.testing.expectEqual(@as(u8, ':'), decoded[user.len]);
    try std.testing.expectEqualStrings(&password, decoded[user.len + 1 ..]);
}

test "basicValue requires the buffer to hold the prefix, the encoded form, and the raw form" {
    const c = Credentials{ .user = "ab", .password = "cd" };
    // raw_len = 5, calcSize(5) = 8, prefix = 6, so the minimum is 19.
    var too_small: [18]u8 = undefined;
    try std.testing.expectError(error.NoSpaceLeft, basicValue(&too_small, c));

    var exact: [19]u8 = undefined;
    const v = try basicValue(&exact, c);
    try std.testing.expectEqualStrings("Basic YWI6Y2Q=", v);
}

test "a username that closes its quoted string is escaped, not obeyed" {
    // `username="{s}"` with no escaping let a user name of
    // `a", uri="/evil", x="` write a second `uri` parameter of its own,
    // ahead of the real one. The user name comes from a url's userinfo or
    // from a netrc file, so it is third-party text.
    var scratch: [512]u8 = undefined;
    const challenge = parseChallenge(&scratch, "Digest realm=\"r\", nonce=\"n\"").?;
    var buf: [512]u8 = undefined;
    const v = try digestValue(&buf, .{
        .credentials = .{ .user = "a\", uri=\"/evil\", x=\"", .password = "p" },
        .challenge = challenge,
        .method = "GET",
        .uri = "/",
        .cnonce = "abc",
        .nc = 1,
    });

    try std.testing.expect(std.mem.startsWith(
        u8,
        v,
        "Digest username=\"a\\\", uri=\\\"/evil\\\", x=\\\"\", realm=\"r\", nonce=\"n\", uri=\"/\", ",
    ));

    // One `uri` parameter, and it is the real one.
    var count: usize = 0;
    var rest: []const u8 = v;
    while (std.mem.indexOf(u8, rest, " uri=\"")) |i| {
        count += 1;
        rest = rest[i + 6 ..];
    }
    try std.testing.expectEqual(@as(usize, 1), count);
}

test "a backslash in a username is escaped too" {
    // A lone `\` would escape the closing quote and swallow the rest of
    // the header into the user name.
    var scratch: [512]u8 = undefined;
    const challenge = parseChallenge(&scratch, "Digest realm=\"r\", nonce=\"n\"").?;
    var buf: [512]u8 = undefined;
    const v = try digestValue(&buf, .{
        .credentials = .{ .user = "a\\", .password = "p" },
        .challenge = challenge,
        .method = "GET",
        .uri = "/",
        .cnonce = "abc",
        .nc = 1,
    });
    try std.testing.expect(std.mem.startsWith(u8, v, "Digest username=\"a\\\\\", realm=\"r\", "));
}

test "a challenge parameter that closes its quoted string is escaped too" {
    // `realm`, `nonce`, and `opaque` are echoed back to the server that
    // sent them, so they are lower risk than the user name. The rule is
    // the same one, and it costs nothing extra.
    const challenge: Challenge = .{
        .scheme = .digest,
        .realm = "r\", uri=\"/evil",
        .nonce = "n\\",
        .opaque_token = "o\"",
    };
    var buf: [512]u8 = undefined;
    const v = try digestValue(&buf, .{
        .credentials = .{ .user = "bob", .password = "p" },
        .challenge = challenge,
        .method = "GET",
        .uri = "/",
        .cnonce = "abc",
        .nc = 1,
    });
    try std.testing.expect(std.mem.indexOf(u8, v, "realm=\"r\\\", uri=\\\"/evil\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, v, "nonce=\"n\\\\\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, v, "opaque=\"o\\\"\"") != null);
}

test "a control byte in a quoted value is a named error, not a broken header" {
    // No quoted string can carry a CR, an LF, or a NUL, escaped or not, so
    // there is nothing to write. Report it instead of building a header
    // value that a peer must reject.
    var scratch: [512]u8 = undefined;
    const challenge = parseChallenge(&scratch, "Digest realm=\"r\", nonce=\"n\"").?;
    var buf: [512]u8 = undefined;
    const users = [_][]const u8{ "a\r\nX-Injected: yes", "a\rb", "a\nb", "a\x00b" };
    for (users) |user| {
        try std.testing.expectError(error.InvalidQuotedValue, digestValue(&buf, .{
            .credentials = .{ .user = user, .password = "p" },
            .challenge = challenge,
            .method = "GET",
            .uri = "/",
            .cnonce = "abc",
            .nc = 1,
        }));
    }
}

test "an escaped quote in the realm produces the response the server computed" {
    // `unquoteOnce` used to leave `\"` as two bytes, so A1 hashed the
    // backslash and the response never matched. The realm here is the
    // three characters `a"b`, and the numbers below come from `md5sum`:
    //
    //   printf 'bob:a"b:hunter2' | md5sum
    //     -> 251a4cb4ff9f638d5386b3232c75bc1d
    //   printf 'GET:/' | md5sum
    //     -> 71998c64aea37ae77020c49c00f73fa8
    //   printf '251a...bc1d:n:7199...3fa8' | md5sum
    //     -> cd414a79668ed1895c55d53864140c3f
    //
    // A reader that keeps the backslash computes
    // e2fdfab0103e95da79a6bbe9ce3708b0 instead, which the server refuses.
    var scratch: [512]u8 = undefined;
    const challenge = parseChallenge(&scratch,
        \\Digest realm="a\"b", nonce="n"
    ).?;
    try std.testing.expectEqualStrings("a\"b", challenge.realm.?);

    var buf: [512]u8 = undefined;
    const value = try digestValue(&buf, .{
        .credentials = .{ .user = "bob", .password = "hunter2" },
        .challenge = challenge,
        .method = "GET",
        .uri = "/",
        .cnonce = "",
        .nc = 0,
    });

    try std.testing.expect(std.mem.indexOf(u8, value, "response=\"cd414a79668ed1895c55d53864140c3f\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, value, "e2fdfab0103e95da79a6bbe9ce3708b0") == null);

    // The realm goes back out with its escapes on, so the server reads the
    // same realm it sent.
    try std.testing.expect(std.mem.indexOf(u8, value, "realm=\"a\\\"b\"") != null);
}

test "a backslash in a challenge value is unescaped once, not twice" {
    // `\\` names one backslash. A reader that took both off would hash a
    // realm shorter than the one the server named.
    var scratch: [512]u8 = undefined;
    const c = parseChallenge(&scratch,
        \\Digest realm="a\\b", nonce="n\"x"
    ).?;
    try std.testing.expectEqualStrings("a\\b", c.realm.?);
    try std.testing.expectEqualStrings("n\"x", c.nonce.?);
}

test "a challenge value with no escape still borrows from the header" {
    // The common case costs no scratch at all, so a scratch of length zero
    // still reads an ordinary challenge.
    var scratch: [0]u8 = undefined;
    const c = parseChallenge(&scratch, "Digest realm=\"r\", nonce=\"n\"").?;
    try std.testing.expectEqualStrings("r", c.realm.?);
    try std.testing.expectEqualStrings("n", c.nonce.?);
}

test "a challenge that needs more scratch than it has is unreadable, not wrong" {
    // Reporting no challenge is what `Client.performHttp` turns into a
    // message. Half-unescaping one would build a response the server
    // refuses, with nothing to say why.
    var scratch: [1]u8 = undefined;
    try std.testing.expectEqual(@as(?Challenge, null), parseChallenge(&scratch,
        \\Digest realm="a\"bcd", nonce="n"
    ));
}
