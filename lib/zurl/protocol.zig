//! The scheme dispatch table.
//!
//! `Client.perform` resolves a URL's scheme to a `Protocol` and calls it.
//! A built-in scheme comes from the comptime `builtins` table below. A
//! caller adds another scheme with `Client.registerProtocol`. Both kinds
//! are the same `Protocol` shape, so `find` has one dispatch path for
//! either kind: it is a table lookup either way, not a special case for
//! "built in" versus "registered".
//!
//! Registration reaches the url parser too. `Client.registerProtocol`
//! puts the scheme and its `default_port` into the client's own
//! `zurl_core.url.Schemes`, and `Client.perform` parses with that
//! registry. So a URL for a registered scheme parses like a URL for a
//! built-in one, and a protocol package outside this repository needs
//! nothing else to be usable.

const std = @import("std");
const zurl_core = @import("zurl-core");
const Transfer = @import("Transfer.zig");
const Response = @import("Response.zig");
const Client = @import("Client.zig");

/// The `Transfer.Options` fields a protocol reads nothing of.
///
/// **An option a protocol drops has to be loud.** A protocol package is
/// handed the whole of `Transfer.Options` and reads the fields it knows.
/// Every other field is dropped with no sign at all, so a user who asked
/// for a proxy or for authentication got neither and no diagnostic. Both
/// are controls that fail **open**: the user asked for indirection or for
/// a credential and the transfer ran without one.
///
/// A protocol names its gaps here, and `Client.perform` refuses the
/// combination by name before the dispatch runs. The refusal is
/// `error.NotBuiltIn`, exit 4, with a sentence that says which option and
/// which protocol. That is worse than carrying the option and better than
/// dropping it.
///
/// Every field defaults to false, so a protocol that reads an option says
/// nothing here.
pub const Unread = struct {
    /// This protocol cannot go through a proxy.
    ///
    /// Read against `Transfer.Options.proxy_every_protocol`, which is the
    /// `-x` family and `all_proxy`, and against
    /// `Transfer.Options.no_proxy`, so a host the user excluded is not
    /// refused. `proxy` and `proxy_tls` are not read here: those two are
    /// the answers for a cleartext HTTP target and a TLS HTTP one, so
    /// neither applies to a url of another scheme, which is curl's own
    /// division of `http_proxy` and `https_proxy`.
    proxy: bool = false,
    /// This protocol sends no credential.
    ///
    /// Read against `Transfer.Options.credentials` and against the url's
    /// own userinfo. A netrc file is not read here: `--netrc` names a file
    /// that may hold no entry for this host at all, and only the lookup
    /// this protocol does not do would say.
    credentials: bool = false,
};

/// One scheme a `Client` knows how to fetch.
pub const Protocol = struct {
    /// The URL scheme this protocol handles. Compared case-insensitively,
    /// matching RFC 3986.
    scheme: []const u8,
    /// The port a URL for this scheme uses when it names none.
    ///
    /// `Client.registerProtocol` hands this number to
    /// `zurl_core.url.Schemes`, so a URL for a registered scheme parses
    /// exactly as a built-in one does and needs no explicit port. That
    /// makes this field the protocol's answer and not a note about one:
    /// the parser reads it.
    ///
    /// **Null says the protocol names no peer.** It reads no socket, so a
    /// URL of its scheme carries no port and may leave the host out
    /// altogether: `file:///a/b` parses, with the host "" and
    /// `Url.port` null. A protocol that dials must name a number here, or
    /// every URL of its scheme has to write one.
    ///
    /// This field once documented the opposite. `zurl_core.url.parse`
    /// carried a fixed table and no hook, so a URL for a scheme it did not
    /// know was `error.InvalidUrl` before dispatch ever saw it, and a
    /// third-party protocol package could not be used without writing a
    /// port into every URL. `zurl_core.url.parseWith` is that hook, and
    /// `Client.perform` reads it.
    ///
    /// A scheme that reaches neither table is `error.UnsupportedProtocol`
    /// now, and no longer `error.InvalidUrl`. The parser reports it for a
    /// URL with no port, and `find` reports it for a URL that named one,
    /// so the two paths give one answer and one exit code. See
    /// `zurl_core.url.ParseError`.
    default_port: ?u16,
    /// Opaque state for `vtable.perform`. The built-in HTTP protocol does
    /// not use this, and leaves it `null`.
    ptr: ?*anyopaque,
    vtable: *const VTable,
    /// The transfer options this protocol reads nothing of. See `Unread`.
    ///
    /// The default is "reads everything", so a protocol that forgets this
    /// field keeps the old silent behaviour. That is why every built-in
    /// package names it, and why `Client.perform` reports the refusal with
    /// a sentence naming the flag: a reader of the sentence can find this
    /// field.
    unread: Unread = .{},

    pub const VTable = struct {
        perform: *const fn (
            ptr: ?*anyopaque,
            c: *Client,
            url: zurl_core.Url,
            options: Transfer.Options,
            d: ?*zurl_core.Diagnostics,
        ) zurl_core.Error!Response,
    };

    /// Runs this protocol's transfer.
    pub fn perform(
        p: Protocol,
        c: *Client,
        url: zurl_core.Url,
        options: Transfer.Options,
        d: ?*zurl_core.Diagnostics,
    ) zurl_core.Error!Response {
        return p.vtable.perform(p.ptr, c, url, options, d);
    }
};

const http_vtable: Protocol.VTable = .{ .perform = performHttp };

/// The schemes a `Client` handles with no run-time registration.
pub const builtins = [_]Protocol{
    .{ .scheme = "http", .default_port = 80, .ptr = null, .vtable = &http_vtable },
    .{ .scheme = "https", .default_port = 443, .ptr = null, .vtable = &http_vtable },
};

fn performHttp(
    ptr: ?*anyopaque,
    c: *Client,
    url: zurl_core.Url,
    options: Transfer.Options,
    d: ?*zurl_core.Diagnostics,
) zurl_core.Error!Response {
    _ = ptr;
    return c.performHttp(url, options, d);
}

/// Finds the protocol that handles `scheme`.
///
/// Checks `runtime` before `builtins`, so a caller can shadow a built-in
/// scheme by registering one of its own. Returns `null` when neither
/// table names `scheme`; the caller reports that as
/// `error.UnsupportedProtocol`, not here, because only the caller has a
/// `Diagnostics` to record it in.
pub fn find(runtime: []const Protocol, scheme: []const u8) ?Protocol {
    for (runtime) |p| {
        if (std.ascii.eqlIgnoreCase(p.scheme, scheme)) return p;
    }
    for (builtins) |p| {
        if (std.ascii.eqlIgnoreCase(p.scheme, scheme)) return p;
    }
    return null;
}

const testing = std.testing;

test "find resolves a scheme case-insensitively, per RFC 3986" {
    const found = find(&.{}, "HTTP") orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("http", found.scheme);
    try testing.expectEqual(&http_vtable, found.vtable);
}

fn shadowPerform(
    ptr: ?*anyopaque,
    c: *Client,
    url: zurl_core.Url,
    options: Transfer.Options,
    d: ?*zurl_core.Diagnostics,
) zurl_core.Error!Response {
    _ = c;
    _ = url;
    _ = options;
    _ = d;
    const reader: *std.Io.Reader = @ptrCast(@alignCast(ptr.?));
    return .{ .status = 200, .content_length = 9, .transfer_encoding = .none, .body = reader };
}

test "registering a protocol teaches the url parser its scheme" {
    // The defect this closes: registration filled the dispatch table
    // alone, so `Client.perform` refused the url at
    // `zurl_core.url.parse` and the registered handler never ran. A
    // scheme no table named, with no port and an empty host, is the
    // shape a `file` url has.
    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    // Before registration the url does not parse at all.
    try testing.expectError(error.InvalidUrl, client.perform("zurltest:///a/b", .{}, null));

    var body_reader: std.Io.Reader = .fixed("shadowed!");
    const vtable: Protocol.VTable = .{ .perform = shadowPerform };
    try client.registerProtocol(.{
        .scheme = "zurltest",
        .default_port = null,
        .ptr = &body_reader,
        .vtable = &vtable,
    });

    const response = try client.perform("zurltest:///a/b", .{}, null);
    try testing.expectEqual(@as(u16, 200), response.status);
}

test "a registration that the parser cannot take registers no dispatch either" {
    // Both tables or neither. A client that dispatched a scheme its own
    // parser refuses would answer `error.InvalidUrl` for every url of
    // that scheme, which is the half-registered state this rule exists
    // to make unreachable.
    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var body_reader: std.Io.Reader = .fixed("shadowed!");
    const vtable: Protocol.VTable = .{ .perform = shadowPerform };

    var name_storage: [zurl_core.url.Schemes.max][8]u8 = undefined;
    for (&name_storage, 0..) |*storage, i| {
        const name = try std.fmt.bufPrint(storage, "s{d}", .{i});
        try client.registerProtocol(.{
            .scheme = name,
            .default_port = null,
            .ptr = &body_reader,
            .vtable = &vtable,
        });
    }

    try testing.expectError(error.TooManySchemes, client.registerProtocol(.{
        .scheme = "one-too-many",
        .default_port = null,
        .ptr = &body_reader,
        .vtable = &vtable,
    }));
    try testing.expectEqual(zurl_core.url.Schemes.max, client.protocols.items.len);
    try testing.expectEqual(@as(?Protocol, null), find(client.protocols.items, "one-too-many"));
}

test "an option a protocol reads nothing of is refused by name" {
    // **The shape this closes.** A protocol package is handed the whole of
    // `Transfer.Options` and drops every field it does not read, with no
    // sign. So `-x socks5h://127.0.0.1:9050 ftp://host/f` connected
    // straight to the origin, and a user routing through Tor or through
    // the one permitted egress got a direct connection and no diagnostic.
    // A privacy control that fails open is worse than one that refuses.
    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var body_reader: std.Io.Reader = .fixed("shadowed!");
    const vtable: Protocol.VTable = .{ .perform = shadowPerform };
    try client.registerProtocol(.{
        .scheme = "noproxy-test",
        .default_port = 9,
        .ptr = &body_reader,
        .vtable = &vtable,
        .unread = .{ .proxy = true },
    });

    // With no proxy named, the transfer runs as it always did.
    const plain = try client.perform("noproxy-test://example.invalid:9/", .{}, null);
    try testing.expectEqual(@as(u16, 200), plain.status);

    // With one named, it is refused before the dispatch runs.
    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(error.NotBuiltIn, client.perform(
        "noproxy-test://example.invalid:9/",
        .{ .proxy_every_protocol = true },
        &d,
    ));
    // curl's `CURLE_NOT_BUILT_IN`, so a script that branches on curl codes
    // gets the number curl gives for a feature this build lacks.
    try testing.expectEqual(@as(?u32, 4), d.curl_code);
    try testing.expect(d.message != null);

    // A host the user excluded from proxying reaches the origin direct
    // under every protocol, so there is nothing to refuse for it.
    const excluded = try client.perform("noproxy-test://example.invalid:9/", .{
        .proxy_every_protocol = true,
        .no_proxy = "example.invalid",
    }, null);
    try testing.expectEqual(@as(u16, 200), excluded.status);

    // And a trailing root dot names the same host. This used to refuse
    // the transfer, because `zurl_core.proxy.bypasses` read the dot as
    // part of the name and found no match. The rule now reads it off, so
    // both spellings of the host answer the same way.
    const dotted = try client.perform("noproxy-test://example.invalid.:9/", .{
        .proxy_every_protocol = true,
        .no_proxy = "example.invalid",
    }, null);
    try testing.expectEqual(@as(u16, 200), dotted.status);
}

test "a credential a protocol sends nowhere is refused by name" {
    // The sibling of the rule above, and the same failure open: SMTP has
    // no `AUTH` command in this build, so `-u user:pass` used to send the
    // message unauthenticated, with no warning and exit 0.
    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var body_reader: std.Io.Reader = .fixed("shadowed!");
    const vtable: Protocol.VTable = .{ .perform = shadowPerform };
    try client.registerProtocol(.{
        .scheme = "nocred-test",
        .default_port = 9,
        .ptr = &body_reader,
        .vtable = &vtable,
        .unread = .{ .credentials = true },
    });

    const plain = try client.perform("nocred-test://example.invalid:9/", .{}, null);
    try testing.expectEqual(@as(u16, 200), plain.status);

    // `-u`, and then the userinfo of the url, which is the same credential
    // by another route.
    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(error.NotBuiltIn, client.perform(
        "nocred-test://example.invalid:9/",
        .{ .credentials = .{ .user = "alice", .password = "s3cret" } },
        &d,
    ));
    try testing.expectEqual(@as(?u32, 4), d.curl_code);

    try testing.expectError(error.NotBuiltIn, client.perform(
        "nocred-test://alice:s3cret@example.invalid:9/",
        .{},
        null,
    ));

    // And the message never quotes the credential.
    try testing.expect(std.mem.indexOf(u8, d.message.?, "s3cret") == null);
}

test "a runtime registration shadows a built-in scheme" {
    // `Client.perform` needs no live server for this: `shadowPerform`
    // never touches `c.http`, so this runs in every build configuration.
    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var body_reader: std.Io.Reader = .fixed("shadowed!");
    const vtable: Protocol.VTable = .{ .perform = shadowPerform };
    try client.registerProtocol(.{
        .scheme = "http",
        .default_port = 80,
        .ptr = &body_reader,
        .vtable = &vtable,
    });

    // A URL syntactically valid for `http` is enough: the registered
    // handler answers before `Client.performHttp` would ever connect.
    const response = try client.perform("http://127.0.0.1:1/", .{}, null);
    try testing.expectEqual(@as(u16, 200), response.status);

    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("shadowed!", contents);
}
