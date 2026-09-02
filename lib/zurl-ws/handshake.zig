//! The WebSocket opening handshake, RFC 6455 section 4.1 and section 4.2.
//!
//! A WebSocket transfer starts as one HTTP/1.1 request. This module writes
//! that request, reads the answer, and **decides whether the answer proves
//! the peer is a WebSocket server**.
//!
//! **The proof is `Sec-WebSocket-Accept`, and a wrong one must fail.**
//! RFC 6455 section 4.2.2 makes the server take the exact
//! `Sec-WebSocket-Key` the client sent, append the fixed GUID in `guid`,
//! take SHA-1 of the two together, and base64 the digest. A client that
//! did not check that value would upgrade to anything that answered `101`,
//! and the handshake would prove nothing at all: a plain HTTP server, a
//! cache, or a peer replaying an old answer would each pass. The key is
//! fresh for every handshake, so a value computed for another key cannot
//! be replayed onto this one.
//!
//! **The key is 16 octets from `io.randomSecure`.** RFC 6455 section 4.1
//! says the value must be "selected randomly" and, in section 10.3, that a
//! client must pick it from a source a peer cannot predict. `io.random` is
//! documented to fall back to a weaker source without saying so, and this
//! project rejected it for the TLS client random for that reason. The same
//! rule holds here and in `drawMask`.
//!
//! The key is not a secret: it travels in a header in the clear. It has to
//! be unpredictable so that no answer can be prepared before the request
//! goes out.
//!
//! This module opens nothing and dials nothing. It writes into a caller's
//! buffer and reads from a caller's reader.

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_net = @import("zurl-net");

const Io = std.Io;

/// The fixed string RFC 6455 section 1.3 appends to the key before the
/// digest.
///
/// It is a constant of the protocol and never a secret. Its whole job is
/// to make the digest name this protocol, so a peer that hashes the key
/// for some other reason does not produce the same value by accident.
pub const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// How many octets of entropy the key holds, RFC 6455 section 4.1.
pub const key_bytes: usize = 16;

/// How many characters the base64 of `key_bytes` octets writes.
pub const key_text_len: usize = 24;

/// How many characters the base64 of a SHA-1 digest writes. This is the
/// length of a `Sec-WebSocket-Accept` value.
pub const accept_text_len: usize = 28;

/// The version this client speaks, RFC 6455 section 4.1.
pub const version = "13";

/// Fills `out` with a fresh `Sec-WebSocket-Key` value.
///
/// The entropy is 16 octets from `io.randomSecure`, base64 encoded. See
/// the module comment for why the source has no fallback.
pub fn drawKey(io: Io, out: *[key_text_len]u8) Io.RandomSecureError!void {
    var raw: [key_bytes]u8 = undefined;
    try io.randomSecure(&raw);
    const written = std.base64.standard.Encoder.encode(out, &raw);
    std.debug.assert(written.len == key_text_len);
}

/// Fills `out` with a fresh 32-bit mask key, RFC 6455 section 5.3.
///
/// **A fresh key for every frame, and never a reused one.** Section 5.3
/// says the key must be unpredictable and must be drawn afresh for each
/// frame. Two frames under one key give an attacker the exclusive-or of
/// the two payloads, which is the whole point of not reusing a keystream.
///
/// The source is `io.randomSecure`, for the reason `drawKey` gives.
pub fn drawMask(io: Io, out: *[4]u8) Io.RandomSecureError!void {
    try io.randomSecure(out);
}

/// Writes the `Sec-WebSocket-Accept` value that `key` must produce.
///
/// This is RFC 6455 section 4.2.2 step 5: SHA-1 over the key text and
/// `guid` joined, then base64.
pub fn accept(key: []const u8, out: *[accept_text_len]u8) void {
    var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    var hash: std.crypto.hash.Sha1 = .init(.{});
    hash.update(key);
    hash.update(guid);
    hash.final(&digest);
    const written = std.base64.standard.Encoder.encode(out, &digest);
    std.debug.assert(written.len == accept_text_len);
}

/// Whether `offered` is the value `key` must produce.
///
/// The comparison is over the whole text and it is case-sensitive: base64
/// is case-significant, so a value that differs only in case is a
/// different digest and not the same one written differently.
pub fn acceptMatches(key: []const u8, offered: []const u8) bool {
    if (offered.len != accept_text_len) return false;
    var expected: [accept_text_len]u8 = undefined;
    accept(key, &expected);
    return std.mem.eql(u8, &expected, offered);
}

/// How many octets of one request head this module writes.
///
/// A url path and a query can be long, and the fixed part of the head is
/// under 200 octets. Passing this is `error.RequestTooLong`, which is a
/// bound this keeps and not a fault on the wire.
pub const max_request_bytes: usize = 8192;

/// What `writeRequest` needs to build one head.
pub const Request = struct {
    /// The url the transfer opens. Its path and query go on the request
    /// line, and its host and port go in the `Host:` line.
    url: zurl_core.Url,
    /// The `Sec-WebSocket-Key` value for this handshake, from `drawKey`.
    key: []const u8,
    /// What goes in the `User-Agent:` line.
    user_agent: []const u8,
    /// The whole `Authorization:` value, or null for a transfer with no
    /// credential. Built by the caller, because building one is
    /// `zurl_core.auth`'s job and not this module's.
    authorization: ?[]const u8 = null,
};

/// Why a request head was not written.
pub const RequestError = error{
    /// The head does not fit `out`. See `max_request_bytes`.
    RequestTooLong,
    /// A part of the head holds a byte that would end a line and start a
    /// header of its own choosing.
    HeaderHasFramingByte,
};

/// Writes the opening handshake request into `out`, and returns the part
/// of `out` that holds it.
///
/// **Every value that comes from outside this module is checked for a
/// framing byte first, and nothing is written before every check has
/// passed.** A CR or an LF in a user agent, in a credential, or in a host
/// would end the header line and put a header of that text's own choosing
/// on the wire, which is the same fault `zurl_net.line.write` exists to
/// stop for the command protocols. `zurl_core.url.parse` already refuses
/// such a byte in a path, a query, and a host, so the check here is the
/// second of two for those and the only one for the rest.
///
/// The request line target is the path and the query, exactly as the url
/// wrote them. This module percent-encodes nothing and decodes nothing,
/// which is what `zurl-http` does for the same text.
///
/// The `Host:` line leaves the port out when it is the default for the
/// scheme, which is what curl writes and what RFC 9110 section 7.2 asks
/// for.
pub fn writeRequest(out: []u8, request: Request) RequestError![]u8 {
    const target_query = request.url.query orelse "";
    for ([_][]const u8{
        request.url.path,
        target_query,
        request.url.host,
        request.key,
        request.user_agent,
        request.authorization orelse "",
    }) |part| {
        if (zurl_net.line.hasFramingByte(part)) return error.HeaderHasFramingByte;
    }

    var writer: Io.Writer = .fixed(out);
    writer.writeAll("GET ") catch return error.RequestTooLong;
    writer.writeAll(request.url.path) catch return error.RequestTooLong;
    if (request.url.query) |query| {
        writer.writeAll("?") catch return error.RequestTooLong;
        writer.writeAll(query) catch return error.RequestTooLong;
    }
    writer.writeAll(" HTTP/1.1\r\nHost: ") catch return error.RequestTooLong;
    writeHost(&writer, request.url) catch return error.RequestTooLong;
    writer.writeAll("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ") catch
        return error.RequestTooLong;
    writer.writeAll(request.key) catch return error.RequestTooLong;
    writer.writeAll("\r\nSec-WebSocket-Version: ") catch return error.RequestTooLong;
    writer.writeAll(version) catch return error.RequestTooLong;
    writer.writeAll("\r\nUser-Agent: ") catch return error.RequestTooLong;
    writer.writeAll(request.user_agent) catch return error.RequestTooLong;
    writer.writeAll("\r\nAccept: */*\r\n") catch return error.RequestTooLong;
    if (request.authorization) |value| {
        writer.writeAll("Authorization: ") catch return error.RequestTooLong;
        writer.writeAll(value) catch return error.RequestTooLong;
        writer.writeAll("\r\n") catch return error.RequestTooLong;
    }
    writer.writeAll("\r\n") catch return error.RequestTooLong;
    return writer.buffered();
}

/// Whether `port` is the port a url of `scheme` gets when it names none.
fn isDefaultPort(scheme: []const u8, port: u16) bool {
    if (std.ascii.eqlIgnoreCase(scheme, "wss")) return port == 443;
    return port == 80;
}

/// Writes the authority of `url` the way a `Host:` line writes it.
///
/// **The brackets of an IPv6 address go back on.** `zurl_core.Url.host`
/// holds a bare address, so `ws://[::1]:8080/` reaches here as the host
/// `::1`. Written plainly that reads `::1:8080`, which names no host and
/// no port. A colon in the host is the whole test, because
/// `zurl_net.tcp.Host.init` accepts a name of letters, digits, `-`, and
/// `.` and an address of hex digits, `.`, and `:`.
///
/// **And the zone id comes off.** `zurl_core.url.hostWithoutZone` says
/// why: RFC 6874 gives a zone id meaning on the local host alone, so it
/// must not reach a peer.
fn writeHost(writer: *Io.Writer, url: zurl_core.Url) Io.Writer.Error!void {
    const host = zurl_core.url.hostWithoutZone(url.host);
    const bracketed = std.mem.indexOfScalar(u8, host, ':') != null;
    if (bracketed) try writer.writeAll("[");
    try writer.writeAll(host);
    if (bracketed) try writer.writeAll("]");
    if (url.port) |port| {
        if (!isDefaultPort(url.scheme, port)) try writer.print(":{d}", .{port});
    }
}

/// How many octets one response head line may hold.
///
/// The same shape of bound `zurl-http` keeps on a response head line, and
/// it exists for the same reason: a peer that writes one line forever
/// would otherwise need a buffer this process cannot bound.
pub const max_head_line_bytes: usize = 4096;

/// How many octets a whole response head may hold.
///
/// A head of many short lines passes `max_head_line_bytes` and can still
/// run forever, so the two bounds are both needed and neither replaces the
/// other.
pub const max_head_bytes: usize = 32 * 1024;

/// How many header lines one response head may hold.
pub const max_head_lines: usize = 128;

/// How many octets of a `Location:` value this module keeps.
pub const max_location_bytes: usize = 2048;

/// What the server answered.
pub const Response = struct {
    /// The status the peer wrote.
    status: u16,
    /// Whether the `Upgrade:` line named the `websocket` token.
    upgrade_ok: bool,
    /// Whether the `Connection:` line named the `Upgrade` token.
    connection_ok: bool,
    /// The `Sec-WebSocket-Accept` value, or null when the peer wrote none.
    /// Points into the caller's own storage.
    accept: ?[]const u8,
    /// Whether the peer named an extension. This client offers none, so
    /// any answer here is one the transfer never asked for.
    named_extension: bool,
    /// Whether the peer named a subprotocol. Same rule as
    /// `named_extension`.
    named_subprotocol: bool,
    /// The `Location:` value of a redirect, or null when the peer wrote
    /// none. Points into the caller's own storage.
    location: ?[]const u8,
};

/// Storage for one response head. A field of the caller, so the slices in
/// a `Response` live as long as the caller keeps it.
///
/// **This must not move while a `Response` that came out of it is in
/// use.** `accept` and `location` point inside it.
pub const ResponseStorage = struct {
    line: [max_head_line_bytes]u8 = undefined,
    accept: [accept_text_len]u8 = undefined,
    accept_len: usize = 0,
    location: [max_location_bytes]u8 = undefined,
    location_len: usize = 0,
};

/// Why a response head could not be read.
pub const ReadError = zurl_net.bounded.LineError || error{
    /// The first line is not an HTTP status line, or a header line has no
    /// colon in it.
    MalformedHead,
    /// The head passed `max_head_bytes` or `max_head_lines`.
    HeadTooLarge,
};

/// Reads one HTTP response head from `reader` into `storage`.
///
/// Reads exactly as far as the empty line that ends the head, so whatever
/// follows in the stream is the first octet of the first frame. A
/// WebSocket has no message boundary of its own before the frames start,
/// so a reader that read one octet past the head would lose it.
///
/// Every bound this keeps is named in `ReadError`. A header this module
/// does not read is skipped, and a `Sec-WebSocket-Accept` or a `Location:`
/// longer than its storage is dropped rather than truncated: a truncated
/// accept value would not match, and a truncated location is a different
/// url.
pub fn readResponse(
    reader: *Io.Reader,
    io: Io,
    storage: *ResponseStorage,
    stall: Io.Timeout,
) ReadError!Response {
    storage.accept_len = 0;
    storage.location_len = 0;

    const status_line = try zurl_net.bounded.readLine(reader, io, &storage.line, stall);
    const status = try parseStatusLine(status_line);

    var response: Response = .{
        .status = status,
        .upgrade_ok = false,
        .connection_ok = false,
        .accept = null,
        .named_extension = false,
        .named_subprotocol = false,
        .location = null,
    };

    var head_bytes: usize = status_line.len;
    var lines: usize = 0;
    while (true) {
        const line = try zurl_net.bounded.readLine(reader, io, &storage.line, stall);
        if (line.len == 0) break;

        lines += 1;
        if (lines > max_head_lines) return error.HeadTooLarge;
        head_bytes += line.len;
        if (head_bytes > max_head_bytes) return error.HeadTooLarge;

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedHead;
        const name = line[0..colon];
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");

        if (std.ascii.eqlIgnoreCase(name, "upgrade")) {
            response.upgrade_ok = namesToken(value, "websocket");
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            response.connection_ok = namesToken(value, "upgrade");
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-accept")) {
            if (value.len <= storage.accept.len) {
                @memcpy(storage.accept[0..value.len], value);
                storage.accept_len = value.len;
                response.accept = storage.accept[0..value.len];
            }
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-extensions")) {
            if (value.len != 0) response.named_extension = true;
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-protocol")) {
            if (value.len != 0) response.named_subprotocol = true;
        } else if (std.ascii.eqlIgnoreCase(name, "location")) {
            if (value.len != 0 and value.len <= storage.location.len) {
                @memcpy(storage.location[0..value.len], value);
                storage.location_len = value.len;
                response.location = storage.location[0..value.len];
            }
        }
    }

    return response;
}

/// Reads the status out of an HTTP status line.
///
/// `HTTP/1.1 101 Switching Protocols`. The version must be `HTTP/1.` and
/// the status must be three digits: RFC 6455 section 4.1 upgrades an
/// HTTP/1.1 connection, and nothing else can carry the upgrade.
fn parseStatusLine(line: []const u8) ReadError!u16 {
    if (!std.mem.startsWith(u8, line, "HTTP/1.")) return error.MalformedHead;
    const space = std.mem.indexOfScalar(u8, line, ' ') orelse return error.MalformedHead;
    const rest = line[space + 1 ..];
    if (rest.len < 3) return error.MalformedHead;
    const digits = rest[0..3];
    for (digits) |byte| {
        if (!std.ascii.isDigit(byte)) return error.MalformedHead;
    }
    // A fourth character must end the number, so `1011` is not read as
    // `101` with a tail.
    if (rest.len > 3 and rest[3] != ' ' and rest[3] != '\t') return error.MalformedHead;
    return std.fmt.parseInt(u16, digits, 10) catch error.MalformedHead;
}

/// Whether `value` is a comma separated list that names `token`.
///
/// RFC 9110 section 5.6.1 writes such a list with commas and optional
/// white space, and RFC 6455 section 4.2.2 compares the tokens without
/// regard to case. A `Connection: keep-alive, Upgrade` therefore names the
/// `Upgrade` token, and a reader that compared the whole value would have
/// missed it.
fn namesToken(value: []const u8, token: []const u8) bool {
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |part| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, part, " \t"), token)) return true;
    }
    return false;
}

const testing = std.testing;

test "the accept value is the one RFC 6455 section 1.3 prints" {
    // The worked example of RFC 6455: the key `dGhlIHNhbXBsZSBub25jZQ==`
    // gives the accept value `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`.
    var out: [accept_text_len]u8 = undefined;
    accept("dGhlIHNhbXBsZSBub25jZQ==", &out);
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &out);
    try testing.expect(acceptMatches("dGhlIHNhbXBsZSBub25jZQ==", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
}

test "an accept value that is not the digest of the key does not match" {
    // **This is the check that makes the handshake prove anything.** A
    // client that skipped it would upgrade to any peer that answered
    // `101`.
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    // One character changed.
    try testing.expect(!acceptMatches(key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOa="));
    // The digest of another key.
    try testing.expect(!acceptMatches(key, "HSmrc0sMlYUkAGmm5OPpG2HaGWk="));
    // Empty, short, and long.
    try testing.expect(!acceptMatches(key, ""));
    try testing.expect(!acceptMatches(key, "s3pPLMBiTxaQ9kYGzzhZRbK+xO"));
    try testing.expect(!acceptMatches(key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=="));
    // Base64 is case-significant, so a value that differs only in case is
    // another digest and not this one written differently.
    try testing.expect(!acceptMatches(key, "S3PplmbitxaQ9kYGzzhZRbK+xOo="));
}

test "a drawn key is 24 characters of base64 and differs between draws" {
    var first: [key_text_len]u8 = undefined;
    var second: [key_text_len]u8 = undefined;
    try drawKey(testing.io, &first);
    try drawKey(testing.io, &second);
    try testing.expectEqual(key_text_len, first.len);
    // The chance of a repeat is 2^-128. A repeat here says the entropy
    // source is not one.
    try testing.expect(!std.mem.eql(u8, &first, &second));

    var decoded: [key_bytes]u8 = undefined;
    try std.base64.standard.Decoder.decode(&decoded, &first);
}

test "a drawn mask differs between draws" {
    // **This test used to assert `x or true`, which is true.** A `drawMask`
    // stubbed to `@memset(out, 0)` passed it. The flake it was written
    // around is real: two 32 bit draws repeat about once in four billion,
    // which is too often for a suite that runs on every build.
    //
    // Eight draws close both. All eight repeat about once in 2^224 runs,
    // and a mask of a fixed value fails every run. `Session` still proves
    // the rule that each frame draws its own mask, off the wire.
    const draws = 8;
    var masks: [draws][4]u8 = undefined;
    for (&masks) |*mask| try drawMask(testing.io, mask);

    var differs = false;
    for (masks[1..]) |mask| {
        if (!std.mem.eql(u8, &masks[0], &mask)) differs = true;
    }
    try testing.expect(differs);
}

fn parseWsUrl(text: []const u8) !zurl_core.Url {
    var schemes: zurl_core.url.Schemes = .empty;
    try schemes.add(.{ .name = "ws", .default_port = 80 });
    try schemes.add(.{ .name = "wss", .default_port = 443 });
    return zurl_core.url.parseWith(text, &schemes);
}

test "the request head carries the four lines RFC 6455 section 4.1 asks for" {
    var out: [max_request_bytes]u8 = undefined;
    const head = try writeRequest(&out, .{
        .url = try parseWsUrl("ws://example.com/chat?room=1"),
        .key = "dGhlIHNhbXBsZSBub25jZQ==",
        .user_agent = "zurl/0.1",
    });
    try testing.expectEqualStrings(
        "GET /chat?room=1 HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "User-Agent: zurl/0.1\r\n" ++
            "Accept: */*\r\n\r\n",
        head,
    );
}

test "the Host line writes a port only when it is not the default" {
    var out: [max_request_bytes]u8 = undefined;
    const key = "dGhlIHNhbXBsZSBub25jZQ==";

    const plain = try writeRequest(&out, .{
        .url = try parseWsUrl("ws://example.com/"),
        .key = key,
        .user_agent = "z",
    });
    try testing.expect(std.mem.indexOf(u8, plain, "Host: example.com\r\n") != null);

    var second: [max_request_bytes]u8 = undefined;
    const secure = try writeRequest(&second, .{
        .url = try parseWsUrl("wss://example.com/"),
        .key = key,
        .user_agent = "z",
    });
    try testing.expect(std.mem.indexOf(u8, secure, "Host: example.com\r\n") != null);

    var third: [max_request_bytes]u8 = undefined;
    const odd = try writeRequest(&third, .{
        .url = try parseWsUrl("ws://example.com:8080/"),
        .key = key,
        .user_agent = "z",
    });
    try testing.expect(std.mem.indexOf(u8, odd, "Host: example.com:8080\r\n") != null);
}

test "an IPv6 host reaches the Host line with its brackets back on" {
    var out: [max_request_bytes]u8 = undefined;
    const head = try writeRequest(&out, .{
        .url = try parseWsUrl("ws://[::1]:8080/x"),
        .key = "dGhlIHNhbXBsZSBub25jZQ==",
        .user_agent = "z",
    });
    try testing.expect(std.mem.indexOf(u8, head, "Host: [::1]:8080\r\n") != null);
}

test "a framing byte in a header value is refused before anything is written" {
    var out: [max_request_bytes]u8 = undefined;
    @memset(&out, 0xaa);
    try testing.expectError(error.HeaderHasFramingByte, writeRequest(&out, .{
        .url = try parseWsUrl("ws://example.com/"),
        .key = "dGhlIHNhbXBsZSBub25jZQ==",
        .user_agent = "zurl\r\nX-Injected: yes",
    }));
    // Nothing was written.
    try testing.expectEqual(@as(u8, 0xaa), out[0]);

    try testing.expectError(error.HeaderHasFramingByte, writeRequest(&out, .{
        .url = try parseWsUrl("ws://example.com/"),
        .key = "key\r\nX-Injected: yes",
        .user_agent = "z",
    }));
    try testing.expectError(error.HeaderHasFramingByte, writeRequest(&out, .{
        .url = try parseWsUrl("ws://example.com/"),
        .key = "dGhlIHNhbXBsZSBub25jZQ==",
        .user_agent = "z",
        .authorization = "Basic abc\r\nX-Injected: yes",
    }));
}

test "a head longer than the buffer is refused and not cut" {
    var out: [64]u8 = undefined;
    try testing.expectError(error.RequestTooLong, writeRequest(&out, .{
        .url = try parseWsUrl("ws://example.com/a-path-that-does-not-fit-at-all"),
        .key = "dGhlIHNhbXBsZSBub25jZQ==",
        .user_agent = "zurl/0.1",
    }));
}

fn readHead(text: []const u8, storage: *ResponseStorage) !Response {
    var reader: Io.Reader = .fixed(text);
    return readResponse(&reader, testing.io, storage, .none);
}

test "the switching protocols answer reads back whole" {
    var storage: ResponseStorage = .{};
    const response = try readHead(
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        &storage,
    );
    try testing.expectEqual(@as(u16, 101), response.status);
    try testing.expect(response.upgrade_ok);
    try testing.expect(response.connection_ok);
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", response.accept.?);
    try testing.expect(!response.named_extension);
    try testing.expect(!response.named_subprotocol);
}

test "the reader stops at the empty line, so the first frame octet stays" {
    var reader: Io.Reader = .fixed(
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n\r\n" ++
            "\x81\x05Hello",
    );
    var storage: ResponseStorage = .{};
    _ = try readResponse(&reader, testing.io, &storage, .none);
    const rest = try reader.allocRemaining(testing.allocator, .limited(64));
    defer testing.allocator.free(rest);
    try testing.expectEqualStrings("\x81\x05Hello", rest);
}

test "a Connection line that names Upgrade among others still counts" {
    var storage: ResponseStorage = .{};
    const response = try readHead(
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Connection: keep-alive, Upgrade\r\n\r\n",
        &storage,
    );
    try testing.expect(response.connection_ok);

    var second: ResponseStorage = .{};
    const missing = try readHead(
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Connection: keep-alive\r\n\r\n",
        &second,
    );
    try testing.expect(!missing.connection_ok);
}

test "an extension or a subprotocol the transfer never offered is seen" {
    var storage: ResponseStorage = .{};
    const response = try readHead(
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Sec-WebSocket-Extensions: permessage-deflate\r\n" ++
            "Sec-WebSocket-Protocol: chat\r\n\r\n",
        &storage,
    );
    try testing.expect(response.named_extension);
    try testing.expect(response.named_subprotocol);
}

test "a redirect answer gives its status and its location" {
    var storage: ResponseStorage = .{};
    const response = try readHead(
        "HTTP/1.1 302 Found\r\n" ++
            "Location: ws://elsewhere.example/chat\r\n\r\n",
        &storage,
    );
    try testing.expectEqual(@as(u16, 302), response.status);
    try testing.expectEqualStrings("ws://elsewhere.example/chat", response.location.?);
    try testing.expectEqual(@as(?[]const u8, null), response.accept);
}

test "a head this module cannot read is refused" {
    var storage: ResponseStorage = .{};
    try testing.expectError(error.MalformedHead, readHead("NOT-HTTP\r\n\r\n", &storage));
    try testing.expectError(error.MalformedHead, readHead("HTTP/1.1 abc x\r\n\r\n", &storage));
    try testing.expectError(error.MalformedHead, readHead("HTTP/1.1 1011 x\r\n\r\n", &storage));
    try testing.expectError(
        error.MalformedHead,
        readHead("HTTP/1.1 101 x\r\nnocolon\r\n\r\n", &storage),
    );
    // A head with no empty line at the end never ends.
    try testing.expectError(error.EndOfStream, readHead("HTTP/1.1 101 x\r\nA: b\r\n", &storage));
}

test "a head of many short lines is refused by the line count" {
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(testing.allocator);
    try text.appendSlice(testing.allocator, "HTTP/1.1 101 x\r\n");
    for (0..max_head_lines + 1) |_| try text.appendSlice(testing.allocator, "A: b\r\n");
    try text.appendSlice(testing.allocator, "\r\n");

    var storage: ResponseStorage = .{};
    try testing.expectError(error.HeadTooLarge, readHead(text.items, &storage));
}

test "an accept value longer than its storage is dropped and never cut" {
    // A cut accept value would not match, so dropping it and refusing the
    // handshake is the same answer with no chance of a partial compare.
    var storage: ResponseStorage = .{};
    const response = try readHead(
        "HTTP/1.1 101 x\r\nSec-WebSocket-Accept: " ++ ("Q" ** 200) ++ "\r\n\r\n",
        &storage,
    );
    try testing.expectEqual(@as(?[]const u8, null), response.accept);
}
