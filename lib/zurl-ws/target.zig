//! Where a redirect on the opening handshake points.
//!
//! **A `Location:` value is the server's text, not the user's.** RFC 6455
//! section 4.1 lets a client follow a redirect on the opening handshake,
//! so the answer to a `ws://` url can name another url. Every rule a url a
//! person typed passes must hold for this one too, and two of them hold
//! here:
//!
//! - **The bytes are checked before anything reads them.** A raw CR or LF
//!   in the value would end the request line of the next hop and start a
//!   header of the server's own choosing. The rule is
//!   `zurl_core.url.hasUnsafeByte`, the one `zurl_core.url.parse` applies,
//!   so a redirect target and a typed url are held to one rule and not
//!   two.
//! - **The result goes back through `zurl_core.url.parseWith`.** This
//!   module writes text and never a `Url`, so the host, the path, the
//!   query, and the fragment of the next hop are checked by the same
//!   parser that read the first one.
//!
//! **The scheme rule is not here.** `zurl_core.redirect.Set` says which
//! protocols a redirect may move a transfer to, and `Fetcher` asks it,
//! because only `Fetcher` holds the transfer's own set.
//!
//! **What this does not resolve.** A target that is neither absolute, nor
//! authority-relative, nor path-absolute is refused. RFC 3986 section 5.3
//! merges a bare relative path against the base's path, and zurl's
//! WebSocket package does not do that merge: a server that wants zurl to
//! follow writes `/chat` or a whole url, which is what a WebSocket server
//! writes in practice. The refusal is `error.RelativeTarget`, and it says
//! so, rather than guess at a path.

const std = @import("std");
const zurl_core = @import("zurl-core");

/// How many octets of resolved target text this writes.
///
/// A url a `Location:` names, plus the scheme and the authority of the
/// base that a path-absolute target takes. Generous past any url a server
/// would write.
pub const max_target_bytes: usize = 4096;

/// Why a redirect target could not be resolved.
pub const ResolveError = error{
    /// The value holds a byte no url may carry: a C0 control byte, a DEL,
    /// or a raw space. See the module comment.
    UnsafeLocation,
    /// The value is empty, so it names nothing.
    EmptyLocation,
    /// The value is a relative reference this module does not merge. See
    /// the module comment.
    RelativeTarget,
    /// The resolved text does not fit `out`.
    TargetTooLong,
};

/// Writes the url that `location` names, relative to `base`, into `out`.
///
/// Three shapes resolve:
///
/// - an absolute url, which names its own scheme: taken as it is.
/// - `//host/path`, which takes the scheme of `base`.
/// - `/path`, which takes the scheme and the authority of `base`.
///
/// Anything else is `error.RelativeTarget`.
///
/// The result points into `out`. It is text and not a `Url`, so the caller
/// reads it back through `zurl_core.url.parseWith` and every url rule
/// applies to it.
pub fn resolve(out: []u8, base: zurl_core.Url, location: []const u8) ResolveError![]u8 {
    // **The base must not live inside `out`.** `zurl_core.url.parse`
    // returns slices that borrow their input, so a caller that parsed the
    // last hop out of this same buffer would hand this function a base and
    // a destination in the same memory. The copy below is a `@memcpy`, and
    // `@memcpy` refuses arguments that alias. Which buffer a caller passes
    // is the caller's own choice and no peer's, so this is an assertion.
    // See `Fetcher.open` for the two buffer shape that keeps it true.
    std.debug.assert(!overlaps(out, base.scheme));
    std.debug.assert(!overlaps(out, base.host));

    // **First, before anything reads a byte of it.**
    if (zurl_core.url.hasUnsafeByte(location)) return error.UnsafeLocation;
    if (location.len == 0) return error.EmptyLocation;

    var writer: std.Io.Writer = .fixed(out);

    if (hasScheme(location)) {
        writer.writeAll(location) catch return error.TargetTooLong;
        return writer.buffered();
    }

    if (std.mem.startsWith(u8, location, "//")) {
        writer.writeAll(base.scheme) catch return error.TargetTooLong;
        writer.writeAll(":") catch return error.TargetTooLong;
        writer.writeAll(location) catch return error.TargetTooLong;
        return writer.buffered();
    }

    if (location[0] == '/') {
        writer.writeAll(base.scheme) catch return error.TargetTooLong;
        writer.writeAll("://") catch return error.TargetTooLong;
        writeAuthority(&writer, base) catch return error.TargetTooLong;
        writer.writeAll(location) catch return error.TargetTooLong;
        return writer.buffered();
    }

    return error.RelativeTarget;
}

/// Whether `slice` shares one octet or more with `out`.
///
/// Compares addresses, because that is what aliasing is. An empty slice
/// shares nothing whatever its address is.
fn overlaps(out: []const u8, slice: []const u8) bool {
    if (out.len == 0 or slice.len == 0) return false;
    const out_start = @intFromPtr(out.ptr);
    const slice_start = @intFromPtr(slice.ptr);
    return slice_start < out_start + out.len and out_start < slice_start + slice.len;
}

/// Whether `text` starts with a scheme and a colon, RFC 3986 section 3.1.
///
/// A letter, then any number of letters, digits, `+`, `-`, and `.`, then a
/// colon. `zurl_core.url.isSchemeSyntax` holds that grammar, so the rule
/// is read from one place and not written twice.
///
/// The colon must come before any `/`, `?`, or `#`. Without that, a
/// path-absolute target holding a colon, such as `/a:b`, would read as a
/// scheme.
fn hasScheme(text: []const u8) bool {
    const colon = std.mem.indexOfScalar(u8, text, ':') orelse return false;
    for (text[0..colon]) |byte| {
        if (byte == '/' or byte == '?' or byte == '#') return false;
    }
    return zurl_core.url.isSchemeSyntax(text[0..colon]);
}

/// Writes the authority of `base`, with the brackets an IPv6 address
/// needs.
///
/// `zurl_core.Url.host` holds a bare address, so `ws://[::1]:8080/` reads
/// back here as `::1`. Written plainly that names no host and no port. A
/// colon in the host is the whole test, because `zurl_net.tcp.Host.init`
/// accepts a name of letters, digits, `-`, and `.` and an address of hex
/// digits, `.`, and `:`.
///
/// **The userinfo is dropped.** A credential must not follow a redirect,
/// and the transfer's own credential is a separate input that
/// `Fetcher` withholds across a hop of its own.
fn writeAuthority(writer: *std.Io.Writer, base: zurl_core.Url) std.Io.Writer.Error!void {
    const bracketed = std.mem.indexOfScalar(u8, base.host, ':') != null;
    if (bracketed) try writer.writeAll("[");
    try writer.writeAll(base.host);
    if (bracketed) try writer.writeAll("]");
    if (base.port) |port| try writer.print(":{d}", .{port});
}

const testing = std.testing;

fn parseWsUrl(text: []const u8) !zurl_core.Url {
    var schemes: zurl_core.url.Schemes = .empty;
    try schemes.add(.{ .name = "ws", .default_port = 80 });
    try schemes.add(.{ .name = "wss", .default_port = 443 });
    return zurl_core.url.parseWith(text, &schemes);
}

test "an absolute target is taken as it is" {
    var out: [max_target_bytes]u8 = undefined;
    const base = try parseWsUrl("ws://a.example:9001/chat");
    try testing.expectEqualStrings(
        "wss://b.example/other",
        try resolve(&out, base, "wss://b.example/other"),
    );
    // A scheme this package cannot open still resolves here. The refusal
    // is the caller's, which reads `zurl_core.redirect.Set`.
    try testing.expectEqualStrings(
        "file:///etc/passwd",
        try resolve(&out, base, "file:///etc/passwd"),
    );
}

test "an authority-relative target takes the base scheme" {
    var out: [max_target_bytes]u8 = undefined;
    const base = try parseWsUrl("wss://a.example/chat");
    try testing.expectEqualStrings(
        "wss://b.example/other",
        try resolve(&out, base, "//b.example/other"),
    );
}

test "a path-absolute target takes the base scheme and authority" {
    var out: [max_target_bytes]u8 = undefined;
    const base = try parseWsUrl("ws://a.example:9001/chat");
    try testing.expectEqualStrings(
        "ws://a.example:9001/other?x=1",
        try resolve(&out, base, "/other?x=1"),
    );
}

test "the credential of the base does not travel to the next hop" {
    var out: [max_target_bytes]u8 = undefined;
    const base = try parseWsUrl("ws://alice:secret@a.example:9001/chat");
    const resolved = try resolve(&out, base, "/other");
    try testing.expectEqualStrings("ws://a.example:9001/other", resolved);
    try testing.expect(std.mem.indexOf(u8, resolved, "secret") == null);
}

test "an IPv6 base gets its brackets back" {
    var out: [max_target_bytes]u8 = undefined;
    const base = try parseWsUrl("ws://[::1]:9001/chat");
    try testing.expectEqualStrings(
        "ws://[::1]:9001/other",
        try resolve(&out, base, "/other"),
    );
}

test "a byte that would end a request line is refused" {
    // A `Location: /a\r\nX-Injected: yes` reached the next hop as a
    // request line plus a header nobody asked for.
    var out: [max_target_bytes]u8 = undefined;
    const base = try parseWsUrl("ws://a.example/chat");
    try testing.expectError(
        error.UnsafeLocation,
        resolve(&out, base, "/a\r\nX-Injected: yes"),
    );
    try testing.expectError(error.UnsafeLocation, resolve(&out, base, "/a\nb"));
    try testing.expectError(error.UnsafeLocation, resolve(&out, base, "/a b"));
    try testing.expectError(error.UnsafeLocation, resolve(&out, base, "/a\x00b"));
}

test "a relative target this module does not merge is refused and not guessed" {
    var out: [max_target_bytes]u8 = undefined;
    const base = try parseWsUrl("ws://a.example/chat/room");
    try testing.expectError(error.RelativeTarget, resolve(&out, base, "other"));
    try testing.expectError(error.RelativeTarget, resolve(&out, base, "../other"));
    try testing.expectError(error.EmptyLocation, resolve(&out, base, ""));
}

test "a colon inside a path does not read as a scheme" {
    var out: [max_target_bytes]u8 = undefined;
    const base = try parseWsUrl("ws://a.example/chat");
    try testing.expectEqualStrings(
        "ws://a.example:80/a:b",
        try resolve(&out, base, "/a:b"),
    );
}

test "two relative hops in a row resolve, with the base in the other buffer" {
    // **The abort this shape exists to stop.** The first hop wrote its
    // answer into `out`, and the caller then parsed the next base out of
    // `out`. The second hop passed that base back to `resolve` with the
    // same `out`, so `base.scheme` and the destination were the same
    // octets. `std.Io.Writer.write` is a `@memcpy`, and `@memcpy` aborts
    // on arguments that alias, in Debug and in ReleaseSafe alike.
    //
    // Two buffers close it: the resolved text is copied into `kept` and
    // the base of the next hop is parsed out of the copy, so `resolve`
    // reads one buffer and writes the other. `Fetcher.open` keeps the same
    // shape with `effective_storage` and `target_storage`.
    var out: [max_target_bytes]u8 = undefined;
    var kept: [max_target_bytes]u8 = undefined;

    const first = try parseWsUrl("ws://a.example:9001/chat");
    const hop1 = try resolve(&out, first, "ws://b.example:9002/one");
    try testing.expectEqualStrings("ws://b.example:9002/one", hop1);

    @memcpy(kept[0..hop1.len], hop1);
    const second = try parseWsUrl(kept[0..hop1.len]);
    const hop2 = try resolve(&out, second, "/two");
    try testing.expectEqualStrings("ws://b.example:9002/two", hop2);

    // And a third, because the fault needed two hops to appear at all.
    @memcpy(kept[0..hop2.len], hop2);
    const third = try parseWsUrl(kept[0..hop2.len]);
    const hop3 = try resolve(&out, third, "/three");
    try testing.expectEqualStrings("ws://b.example:9002/three", hop3);
}

test "a target longer than the buffer is refused and not cut" {
    var out: [32]u8 = undefined;
    const base = try parseWsUrl("ws://a.example/chat");
    try testing.expectError(
        error.TargetTooLong,
        resolve(&out, base, "ws://a-very-long-host.example/a/long/path"),
    );
}
