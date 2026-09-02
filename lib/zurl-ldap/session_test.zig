//! The end to end tests of this package, over the loopback RFC 4511
//! fixture.
//!
//! These are the tests that prove a rule **on the wire** and not in a
//! builder alone. The unit tests in `ber.zig`, `filter.zig`, `ldif.zig`,
//! and `message.zig` prove the pieces. These prove that a url reaches a
//! peer as the request it should, that the peer's answer reaches the
//! caller as the text it should, and that a hostile message is refused
//! before it costs anything.
//!
//! No test here reaches the network. Every one starts a fixture on
//! 127.0.0.1 with a port the operating system assigns.

const std = @import("std");

const ber = @import("ber.zig");
const filter = @import("filter.zig");
const message = @import("message.zig");
const target = @import("target.zig");
const test_server = @import("test_server.zig");
const Fetcher = @import("Fetcher.zig");

const testing = std.testing;
const Diagnostics = @import("zurl-core").Diagnostics;

/// One fixture, one fetcher, and the url that reaches them.
const Fixture = struct {
    server: test_server,
    fetcher: Fetcher,
    url_text: [256]u8,
    /// An empty trust store, so a StartTLS test reaches the dial.
    ///
    /// **The fixture speaks no TLS**, so no handshake ever runs against
    /// it. This exists only so `tlsOptions` does not refuse before the
    /// dial: a build with no trust store cannot open an encrypted session
    /// at all, which is a rule `Fetcher.zig` tests on its own.
    lock: std.Io.RwLock,
    bundle: std.crypto.Certificate.Bundle,

    fn start(fx: *Fixture, script: test_server.Script) !void {
        try fx.server.start(script);
        fx.fetcher = .init(testing.allocator, testing.io);
        fx.lock = .init;
        fx.bundle = .empty;
    }

    fn trust(fx: *Fixture) Fetcher.Trust {
        return .{
            .lock = &fx.lock,
            .bundle = &fx.bundle,
            .ptr = fx,
            .load = noLoad,
        };
    }

    fn noLoad(ptr: *anyopaque) @import("zurl-core").Error!void {
        _ = ptr;
    }

    fn stop(fx: *Fixture) void {
        fx.fetcher.deinit();
        fx.server.stop();
    }

    /// The url `path` names on the fixture's own port.
    fn url(fx: *Fixture, path: []const u8) !@import("zurl-core").Url {
        const text = try std.fmt.bufPrint(&fx.url_text, "ldap://127.0.0.1:{d}/{s}", .{
            fx.server.port(),
            path,
        });
        return Fetcher.parseLdapUrl(text);
    }

    /// Runs one transfer and returns its text.
    fn fetch(fx: *Fixture, path: []const u8, options: Fetcher.Options) ![]const u8 {
        const body = try fx.fetcher.open(try fx.url(path), options, null);
        return body.reader.buffered();
    }
};

/// The entry slapd holds for `dc=zurl,dc=test`, as the fixture returns it.
const root_entry: test_server.Entry = .{
    .dn = "dc=zurl,dc=test",
    .attributes = &.{
        .{ .description = "objectClass", .values = &.{ "dcObject", "organization" } },
        .{ .description = "dc", .values = &.{"zurl"} },
        .{ .description = "o", .values = &.{"zurl test directory"} },
    },
};

test "a whole search reaches the wire and its answer matches what curl printed" {
    // **The measurement this test pins.** curl 8.21.0 against a real slapd
    // 2.6.13, with `od -c`, printed exactly these bytes for the same entry:
    //
    //     DN: dc=zurl,dc=test\n
    //     \tobjectClass: dcObject\n\tobjectClass: organization\n\n
    //     \tdc: zurl\n\n
    //     \to: zurl test directory\n\n
    //     \n
    var fx: Fixture = undefined;
    try fx.start(.{ .entries = &.{root_entry} });
    defer fx.stop();

    const text = try fx.fetch("dc=zurl,dc=test", .{});
    try testing.expectEqualStrings(
        "DN: dc=zurl,dc=test\n" ++
            "\tobjectClass: dcObject\n\tobjectClass: organization\n\n" ++
            "\tdc: zurl\n\n" ++
            "\to: zurl test directory\n\n" ++
            "\n",
        text,
    );
}

test "the bind, the search, and the unbind go out in curl's order" {
    var fx: Fixture = undefined;
    try fx.start(.{ .entries = &.{root_entry} });
    defer fx.stop();

    _ = try fx.fetch("dc=zurl,dc=test", .{});
    fx.server.wait();

    try testing.expectEqual(@as(usize, 3), fx.server.requestCount());
    // The anonymous bind curl sends, byte for byte.
    try testing.expectEqualSlices(u8, &.{
        0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07,
        0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
    }, fx.server.request(0));
    // The unbind curl sends, with the third message id.
    try testing.expectEqualSlices(
        u8,
        &.{ 0x30, 0x05, 0x02, 0x01, 0x03, 0x42, 0x00 },
        fx.server.request(2),
    );
}

test "a bind always goes out, even with no credential" {
    // RFC 4511 section 5.1.1 makes the anonymous bind a real operation.
    // curl sends it for a url with no `-u` at all, measured.
    var fx: Fixture = undefined;
    try fx.start(.{ .entries = &.{} });
    defer fx.stop();

    _ = try fx.fetch("dc=zurl,dc=test", .{});
    fx.server.wait();

    try testing.expectEqual(@as(i32, 1), try requestId(fx.server.request(0)));
    var fields = try requestFields(fx.server.request(0), message.app_bind_request);
    try testing.expectEqual(@as(i64, 3), try ber.integerValue(i64, try fields.expect(ber.integer)));
    try testing.expectEqualStrings("", (try fields.expect(ber.octet_string)).content);
    try testing.expectEqualStrings(
        "",
        (try fields.expect(.context(message.auth_simple, false))).content,
    );
}

test "-u reaches the bind as the name and the password, and nothing else does" {
    var fx: Fixture = undefined;
    try fx.start(.{ .entries = &.{} });
    defer fx.stop();

    _ = try fx.fetch("dc=zurl,dc=test", .{
        .credentials = .{ .dn = "cn=admin,dc=zurl,dc=test", .password = "secret" },
    });
    fx.server.wait();

    // The bytes curl sent for the same `-u`, measured on the wire.
    const want = [_]u8{ 0x30, 0x2a, 0x02, 0x01, 0x01, 0x60, 0x25, 0x02, 0x01, 0x03, 0x04, 0x18 } ++
        "cn=admin,dc=zurl,dc=test".* ++ [_]u8{ 0x80, 0x06 } ++ "secret".*;
    try testing.expectEqualSlices(u8, &want, fx.server.request(0));
}

test "the userinfo of a url beats -u, and it is percent-decoded" {
    var fx: Fixture = undefined;
    try fx.start(.{ .entries = &.{} });
    defer fx.stop();

    const text = try std.fmt.bufPrint(
        &fx.url_text,
        "ldap://cn%3Dbob%2Cdc%3Da:pw@127.0.0.1:{d}/dc=a",
        .{fx.server.port()},
    );
    _ = try fx.fetcher.open(try Fetcher.parseLdapUrl(text), .{
        .credentials = .{ .dn = "cn=ignored", .password = "ignored" },
    }, null);
    fx.server.wait();

    var fields = try requestFields(fx.server.request(0), message.app_bind_request);
    _ = try fields.expect(ber.integer);
    try testing.expectEqualStrings("cn=bob,dc=a", (try fields.expect(ber.octet_string)).content);
    try testing.expectEqualStrings(
        "pw",
        (try fields.expect(.context(message.auth_simple, false))).content,
    );
}

test "a password of any bytes at all reaches the peer whole" {
    // **The proof that this protocol needs no credential gate.** Every
    // line protocol in this repository refuses a NUL, a CR, and an LF in a
    // credential, because each would end a command line. BER counts the
    // octets in front of a value, so none of the three can end anything
    // here, and refusing them would refuse a password a directory holds.
    var fx: Fixture = undefined;
    try fx.start(.{ .entries = &.{} });
    defer fx.stop();

    var password: [256]u8 = undefined;
    for (&password, 0..) |*b, i| b.* = @truncate(i);

    _ = try fx.fetch("dc=a", .{
        .credentials = .{ .dn = "cn=a", .password = &password },
    });
    fx.server.wait();

    var fields = try requestFields(fx.server.request(0), message.app_bind_request);
    _ = try fields.expect(ber.integer);
    _ = try fields.expect(ber.octet_string);
    const simple = try fields.expect(.context(message.auth_simple, false));
    try testing.expectEqualSlices(u8, &password, simple.content);
}

test "the scope, the attributes, and the filter of a url reach the wire" {
    var fx: Fixture = undefined;
    try fx.start(.{ .entries = &.{} });
    defer fx.stop();

    _ = try fx.fetch("ou=people,dc=zurl,dc=test?cn,mail?one?(cn=Ross*)", .{});
    fx.server.wait();

    try testing.expectEqual(@as(i32, 2), try requestId(fx.server.request(1)));
    var fields = try requestFields(fx.server.request(1), message.app_search_request);
    try testing.expectEqualStrings(
        "ou=people,dc=zurl,dc=test",
        (try fields.expect(ber.octet_string)).content,
    );
    try testing.expectEqual(@as(i64, 1), try ber.integerValue(i64, try fields.expect(ber.enumerated)));
    // derefAliases is always neverDerefAliases, which is what curl sends.
    try testing.expectEqual(@as(i64, 0), try ber.integerValue(i64, try fields.expect(ber.enumerated)));
    try testing.expectEqual(@as(i64, 0), try ber.integerValue(i64, try fields.expect(ber.integer)));
    try testing.expectEqual(@as(i64, 0), try ber.integerValue(i64, try fields.expect(ber.integer)));
    try testing.expectEqual(false, try ber.booleanValue(try fields.expect(ber.boolean)));

    // The filter is a `[4]` substring match on `cn` with one `initial`.
    const f = try fields.expect(.context(filter.tag_substrings, true));
    var parts = try fields.enter(f);
    try testing.expectEqualStrings("cn", (try parts.expect(ber.octet_string)).content);
    const pieces = try parts.expect(ber.sequence);
    var piece = try parts.enter(pieces);
    try testing.expectEqualStrings(
        "Ross",
        (try piece.expect(.context(filter.tag_initial, false))).content,
    );

    const attributes = try fields.expect(ber.sequence);
    var names = try fields.enter(attributes);
    try testing.expectEqualStrings("cn", (try names.expect(ber.octet_string)).content);
    try testing.expectEqualStrings("mail", (try names.expect(ber.octet_string)).content);
    try testing.expect(names.atEnd());
}

test "a url with only a dn sends the three defaults curl sends" {
    var fx: Fixture = undefined;
    try fx.start(.{ .entries = &.{} });
    defer fx.stop();

    _ = try fx.fetch("dc=zurl,dc=test", .{});
    fx.server.wait();

    // The whole SearchRequest curl sent for the same url, measured, with
    // the empty attribute SEQUENCE on the end.
    const want = [_]u8{ 0x30, 0x34, 0x02, 0x01, 0x02, 0x63, 0x2f, 0x04, 0x0f } ++
        "dc=zurl,dc=test".* ++
        [_]u8{ 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00 } ++
        [_]u8{ 0x87, 0x0b } ++ "objectclass".* ++ [_]u8{ 0x30, 0x00 };
    try testing.expectEqualSlices(u8, &want, fx.server.request(1));
}

test "every escaped byte of a filter reaches the peer as itself" {
    // **The escaping rule, proved on the wire.** `filter.zig` proves it in
    // the builder. This proves the byte reaches a peer, is read back off
    // the socket by a second decoder, and is still that byte.
    var value: usize = 0;
    while (value < 256) : (value += 1) {
        const byte: u8 = @intCast(value);
        var fx: Fixture = undefined;
        try fx.start(.{ .entries = &.{} });
        defer fx.stop();

        var path: [64]u8 = undefined;
        const text = try std.fmt.bufPrint(&path, "dc=a?1.1?base?(cn=A\\{x:0>2}B)", .{byte});
        _ = try fx.fetch(text, .{});
        fx.server.wait();

        var fields = try requestFields(fx.server.request(1), message.app_search_request);
        _ = try fields.expect(ber.octet_string);
        _ = try fields.expect(ber.enumerated);
        _ = try fields.expect(ber.enumerated);
        _ = try fields.expect(ber.integer);
        _ = try fields.expect(ber.integer);
        _ = try fields.expect(ber.boolean);

        // **Exactly one filter node**, whatever the byte is. A byte that
        // could change the tree would show up here as a second node.
        const f = try fields.expect(.context(filter.tag_equality, true));
        var item = try fields.enter(f);
        try testing.expectEqualStrings("cn", (try item.expect(ber.octet_string)).content);
        const assertion = try item.expect(ber.octet_string);
        try testing.expect(item.atEnd());
        try testing.expectEqualSlices(u8, &.{ 'A', byte, 'B' }, assertion.content);
    }
}

test "a filter that would forge a second item is refused before a socket opens" {
    // A bare `(` or `)` inside a value would close the item the parser is
    // reading and open one the url chose. Both are refused, and no dial
    // happens at all, so a mistyped filter sends no credential anywhere.
    const bad = [_][]const u8{
        "dc=a?cn?base?(cn=x(y)",
        "dc=a?cn?base?(cn=x",
        "dc=a?cn?base?(cn=x)(sn=y)",
        "dc=a?cn?base?(cn=\\zz)",
        "dc=a?cn?base?(cn=\\)",
        "dc=a?cn?base?(&(cn=x)",
        "dc=a?cn?base?(!)",
    };
    for (bad) |path| {
        var fx: Fixture = undefined;
        try fx.start(.{ .entries = &.{} });
        defer fx.stop();

        var d: Diagnostics = .{};
        try testing.expectError(
            error.InvalidUrl,
            fx.fetcher.open(try fx.url(path), .{}, &d),
        );
        // **No socket opened.** curl refuses the same filter only after it
        // has dialed and bound, measured: it exits 39 and its bind is
        // already on the wire.
        try testing.expectEqual(@as(usize, 0), fx.server.connections());
        try testing.expect(d.message != null);
    }
}

test "a url this build will not send opens no socket at all" {
    const bad = [_][]const u8{
        "dc=a?cn?children",
        "dc=a?cn?base?(cn=x)?!bindname=cn=admin",
        "dc%zz",
        "cn=a%0ADN:%20forged",
        "dc=a?c%20n",
    };
    for (bad) |path| {
        var fx: Fixture = undefined;
        try fx.start(.{ .entries = &.{} });
        defer fx.stop();

        try testing.expectError(error.InvalidUrl, fx.fetcher.open(try fx.url(path), .{}, null));
        try testing.expectEqual(@as(usize, 0), fx.server.connections());
    }
}

test "a bind the server refuses stops the transfer and sends no search" {
    var fx: Fixture = undefined;
    // 49 is `invalidCredentials`, which curl maps to exit 67, measured.
    try fx.start(.{ .bind_code = 49, .bind_diagnostic = "no such user" });
    defer fx.stop();

    var d: Diagnostics = .{};
    try testing.expectError(error.LoginDenied, fx.fetcher.open(
        try fx.url("dc=a"),
        .{ .credentials = .{ .dn = "cn=a", .password = "b" } },
        &d,
    ));
    fx.server.wait();

    // Only the bind went out. A search after a refused bind would run as
    // whoever the server thinks an unbound connection is.
    try testing.expectEqual(@as(usize, 1), fx.server.requestCount());
    try testing.expect(std.mem.indexOf(u8, d.message.?, "the -u option") != null);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "invalid credentials") != null);
    // The server's own words reach the message too.
    try testing.expect(std.mem.indexOf(u8, d.message.?, "no such user") != null);
}

test "each bind result code takes the exit code curl gives it" {
    const Case = struct { code: i32, err: anyerror };
    const cases = [_]Case{
        // Measured against curl 8.21.0 on a real slapd 2.6.13.
        .{ .code = 49, .err = error.LoginDenied },
        .{ .code = 34, .err = error.LdapCannotBind },
        // From curl's own `oldap_map_error`.
        .{ .code = 2, .err = error.UnsupportedProtocol },
        .{ .code = 50, .err = error.FtpAccessDenied },
        .{ .code = 53, .err = error.LdapCannotBind },
        // A server asking for SASL is reported and nothing weaker is
        // tried.
        .{ .code = 7, .err = error.LdapCannotBind },
        .{ .code = 8, .err = error.LdapCannotBind },
    };
    for (cases) |case| {
        var fx: Fixture = undefined;
        try fx.start(.{ .bind_code = case.code });
        defer fx.stop();
        try testing.expectError(case.err, fx.fetcher.open(try fx.url("dc=a"), .{}, null));
    }
}

test "a search the server refuses is exit 39, which is curl's own code" {
    var fx: Fixture = undefined;
    // 32 is `noSuchObject`. Measured: curl exits 39 and prints
    // `search failed No such object`.
    try fx.start(.{ .search_code = 32, .search_diagnostic = "" });
    defer fx.stop();

    var d: Diagnostics = .{};
    try testing.expectError(
        error.LdapSearchFailed,
        fx.fetcher.open(try fx.url("cn=nope,dc=a"), .{}, &d),
    );
    try testing.expect(std.mem.indexOf(u8, d.message.?, "no such object") != null);
}

test "sizeLimitExceeded ends the search and is not a failure" {
    // curl reads it as a completed search and prints the entries that did
    // arrive, so this does too.
    var fx: Fixture = undefined;
    try fx.start(.{ .search_code = 4, .entries = &.{root_entry} });
    defer fx.stop();

    const body = try fx.fetcher.open(try fx.url("dc=zurl,dc=test?dc?sub"), .{}, null);
    try testing.expectEqual(message.ResultCode.size_limit_exceeded, body.status);
    try testing.expectEqual(@as(usize, 1), body.entries);
    try testing.expect(body.length != 0);
}

test "a search that worked reports the result code curl prints as http_code" {
    // Measured: curl printed `000` for `%{http_code}` on a search that
    // worked and `032` on one whose base object was not there.
    var fx: Fixture = undefined;
    try fx.start(.{ .entries = &.{root_entry} });
    defer fx.stop();

    const body = try fx.fetcher.open(try fx.url("dc=zurl,dc=test"), .{}, null);
    try testing.expectEqual(message.ResultCode.success, body.status);
    try testing.expectEqual(@as(i32, 0), @intFromEnum(body.status));
}

test "a referral is counted, written nowhere, and never followed" {
    // **curl loses entries here and this build does not.** Measured
    // against slapd: curl stopped the whole search at the first
    // `SearchResultReference` and printed no entry after it. This build
    // reads past the reference and carries on to the `SearchResultDone`.
    var fx: Fixture = undefined;
    try fx.start(.{
        .entries = &.{
            .{ .dn = "ou=first,dc=a", .attributes = &.{
                .{ .description = "ou", .values = &.{"first"} },
            } },
            .{ .dn = "ou=second,dc=a", .attributes = &.{
                .{ .description = "ou", .values = &.{"second"} },
            } },
        },
        .references = &.{"ldap://other.example.com/ou=elsewhere,dc=a??sub"},
        .reference_after = 1,
    });
    defer fx.stop();

    const body = try fx.fetcher.open(try fx.url("dc=a?ou?sub"), .{}, null);
    try testing.expectEqual(@as(usize, 2), body.entries);
    try testing.expectEqual(@as(usize, 1), body.references);

    const text = body.reader.buffered();
    // Both entries are there, and the second is the one curl drops.
    try testing.expect(std.mem.indexOf(u8, text, "DN: ou=first,dc=a") != null);
    try testing.expect(std.mem.indexOf(u8, text, "DN: ou=second,dc=a") != null);
    // **The referral host is nowhere in the answer.** Writing it would put
    // a name the server chose into the output, and following it would send
    // the bind credential there.
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, text, "other.example.com"),
    );
    // Only the bind, the search, and the unbind went out. Nothing was
    // dialed at the referral host.
    fx.server.wait();
    try testing.expectEqual(@as(usize, 3), fx.server.requestCount());
}

test "an entry whose value would draw a line comes out in base64" {
    // The one place this build differs from curl, proved end to end.
    // Measured: curl printed `embedded\nLF and DN: cn=forged` raw.
    var fx: Fixture = undefined;
    try fx.start(.{ .entries = &.{
        .{ .dn = "cn=Edge,dc=a", .attributes = &.{
            .{ .description = "description", .values = &.{"embedded\nLF and DN: cn=forged"} },
        } },
    } });
    defer fx.stop();

    const text = try fx.fetch("cn=Edge,dc=a?description", .{});
    // Exactly three line endings: the DN line, the value line, and the
    // blank that ends the attribute, plus the blank that ends the entry.
    try testing.expectEqual(@as(usize, 4), std.mem.count(u8, text, "\n"));
    try testing.expect(std.mem.indexOf(u8, text, "description:: ") != null);
    // The forged DN never appears at the start of a line.
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, text, "\nDN: cn=forged"),
    );
}

test "a server that names an attribute to forge an entry gets no output at all" {
    // **The regression test for the defect a review found, on the wire.**
    // The DN arm and the value arm were hardened and tested and this one
    // was not, so a server that answered with an attribute named
    // `cn: real\nDN: cn=forged` drew an entry the directory does not hold.
    var fx: Fixture = undefined;
    try fx.start(.{ .entries = &.{
        .{ .dn = "cn=real,dc=a", .attributes = &.{
            .{
                .description = "cn: real\nDN: cn=forged,dc=a\n\tuserPassword",
                .values = &.{"hunter2"},
            },
        } },
    } });
    defer fx.stop();

    var d: Diagnostics = .{};
    try testing.expectError(
        error.WeirdServerReply,
        fx.fetcher.open(try fx.url("cn=real,dc=a"), .{}, &d),
    );
    // No answer is held, so no byte of the forged entry can reach a
    // caller.
    try testing.expectEqual(@as(?[]u8, null), fx.fetcher.answer);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "attribute description") != null);
}

test "an escape byte in an attribute description never reaches a terminal" {
    // The same hole let a server move a cursor or set a colour. The set
    // this build accepts is narrower than printable, so it is closed by
    // the same check.
    var fx: Fixture = undefined;
    try fx.start(.{ .entries = &.{
        .{ .dn = "cn=a", .attributes = &.{
            .{ .description = "cn\x1b[31m", .values = &.{"x"} },
        } },
    } });
    defer fx.stop();

    try testing.expectError(
        error.WeirdServerReply,
        fx.fetcher.open(try fx.url("cn=a"), .{}, null),
    );
    try testing.expectEqual(@as(?[]u8, null), fx.fetcher.answer);
}

test "a DN a server could forge a line with comes out in base64" {
    // curl has no base64 arm for a DN at all.
    var fx: Fixture = undefined;
    try fx.start(.{ .entries = &.{
        .{ .dn = "cn=a\nDN: cn=forged", .attributes = &.{} },
    } });
    defer fx.stop();

    const text = try fx.fetch("dc=a?1.1", .{});
    try testing.expect(std.mem.startsWith(u8, text, "DN:: "));
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, text, "\n"));
}

test "an attribute the server sent with no values writes one line and no blank" {
    var fx: Fixture = undefined;
    try fx.start(.{ .entries = &.{
        .{ .dn = "cn=a", .attributes = &.{
            .{ .description = "cn", .values = &.{} },
            .{ .description = "sn", .values = &.{"b"} },
        } },
    } });
    defer fx.stop();

    const text = try fx.fetch("cn=a", .{});
    try testing.expectEqualStrings("DN: cn=a\n\tcn:\n\tsn: b\n\n\n", text);
}

test "a length that claims four gigabytes costs six bytes and no memory" {
    // **The bound this package exists to keep.** The fixture writes the
    // header and nothing else, so the client must refuse on the number and
    // never wait for the bytes.
    var fx: Fixture = undefined;
    try fx.start(.{ .raw = &.{ 0x30, 0x84, 0xff, 0xff, 0xff, 0xff } });
    defer fx.stop();

    var d: Diagnostics = .{};
    try testing.expectError(
        error.FileSizeExceeded,
        fx.fetcher.open(try fx.url("dc=a"), .{}, &d),
    );
    try testing.expect(std.mem.indexOf(u8, d.message.?, "MessageTooLarge") != null);
}

test "the indefinite length form is refused on the wire" {
    var fx: Fixture = undefined;
    try fx.start(.{ .raw = &.{ 0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00 } });
    defer fx.stop();

    var d: Diagnostics = .{};
    try testing.expectError(
        error.WeirdServerReply,
        fx.fetcher.open(try fx.url("dc=a"), .{}, &d),
    );
    try testing.expect(std.mem.indexOf(u8, d.message.?, "IndefiniteLength") != null);
}

test "a message that nests past the bound is refused on the wire" {
    // `ber.max_depth + 4` opening SEQUENCE headers inside the envelope.
    const levels = ber.max_depth + 4;
    var bytes: [(ber.max_depth + 4) * 2]u8 = undefined;
    for (0..levels) |i| {
        bytes[i * 2] = 0x30;
        bytes[i * 2 + 1] = @intCast((levels - i - 1) * 2);
    }

    var fx: Fixture = undefined;
    try fx.start(.{ .raw = &bytes });
    defer fx.stop();

    var d: Diagnostics = .{};
    try testing.expectError(
        error.WeirdServerReply,
        fx.fetcher.open(try fx.url("dc=a"), .{}, &d),
    );
    // The message reads as a SEQUENCE holding a SEQUENCE where the message
    // id belongs, so it stops at the shape before it reaches the depth.
    try testing.expect(d.message != null);
}

test "a message this build cannot read is a runtime fault and never an assertion" {
    const hostile = [_][]const u8{
        // A length octet count over four.
        &.{ 0x30, 0x85, 1, 2, 3, 4, 5 },
        // A message that is not a SEQUENCE.
        &.{ 0x04, 0x02, 'a', 'b' },
        // A SEQUENCE holding nothing.
        &.{ 0x30, 0x00 },
        // An operation this build does not know.
        &.{ 0x30, 0x05, 0x02, 0x01, 0x01, 0x67, 0x00 },
        // A result code RFC 4511 does not name.
        &.{ 0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x5b, 0x04, 0x00, 0x04, 0x00 },
        // The multi-byte tag number form.
        &.{ 0x1f, 0x81, 0x00, 0x00 },
        // A message id that does not fit an i32.
        &.{ 0x30, 0x0d, 0x02, 0x09, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x42, 0x00 },
    };
    for (hostile) |bytes| {
        var fx: Fixture = undefined;
        try fx.start(.{ .raw = bytes });
        defer fx.stop();

        var d: Diagnostics = .{};
        const result = fx.fetcher.open(try fx.url("dc=a"), .{}, &d);
        try testing.expectError(error.WeirdServerReply, result);
        try testing.expect(d.message != null);
    }
}

test "a reply carrying another request's message id is refused" {
    var fx: Fixture = undefined;
    try fx.start(.{ .wrong_message_id = true });
    defer fx.stop();

    var d: Diagnostics = .{};
    try testing.expectError(
        error.WeirdServerReply,
        fx.fetcher.open(try fx.url("dc=a"), .{}, &d),
    );
    try testing.expect(std.mem.indexOf(u8, d.message.?, "MessageIdMismatch") != null);
}

test "the unsolicited notification of RFC 4511 reads as a disconnection" {
    // Message id zero and an `ExtendedResponse` holding `unavailable`.
    var fx: Fixture = undefined;
    try fx.start(.{ .raw = &.{
        0x30, 0x0c, 0x02, 0x01, 0x00, 0x78, 0x07,
        0x0a, 0x01, 0x34, 0x04, 0x00, 0x04, 0x00,
    } });
    defer fx.stop();

    var d: Diagnostics = .{};
    try testing.expectError(
        error.WeirdServerReply,
        fx.fetcher.open(try fx.url("dc=a"), .{}, &d),
    );
    try testing.expect(std.mem.indexOf(u8, d.message.?, "ServerDisconnecting") != null);
}

test "a peer that closes in the middle of a message is a fault" {
    var fx: Fixture = undefined;
    try fx.start(.{ .raw = null });
    defer fx.stop();
    // The default script answers the bind, so a truncated one needs a raw
    // prefix.
    fx.server.script.raw = &.{ 0x30, 0x0c, 0x02, 0x01 };
    // The fixture holds the socket after a raw write, so the client waits
    // on the rest of the message and the stall bound is what stops it.
    var d: Diagnostics = .{};
    const short: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(200), .clock = .awake } };
    try testing.expectError(error.OperationTimedOut, fx.fetcher.open(
        try fx.url("dc=a"),
        .{ .read_timeout = short },
        &d,
    ));
}

test "a server that sends more messages than the bound allows is stopped by name" {
    // **A bound on round trips and not on bytes.** An entry with no
    // attributes writes ten bytes of output, so the size bound alone would
    // let such a server hold this transfer for a very long time.
    var fx: Fixture = undefined;
    try fx.start(.{ .flood_entries = Fetcher.max_messages + 1, .entries = &.{} });
    defer fx.stop();

    var d: Diagnostics = .{};
    try testing.expectError(
        error.FileSizeExceeded,
        fx.fetcher.open(try fx.url("dc=a?1.1?sub"), .{}, &d),
    );
    try testing.expect(std.mem.indexOf(u8, d.message.?, "messages zurl reads") != null);
}

test "an answer past the size bound is refused and no byte of it comes back" {
    var fx: Fixture = undefined;
    try fx.start(.{ .entries = &.{ root_entry, root_entry, root_entry } });
    defer fx.stop();

    var d: Diagnostics = .{};
    try testing.expectError(error.FileSizeExceeded, fx.fetcher.open(
        try fx.url("dc=zurl,dc=test?dc?sub"),
        .{ .max_response_bytes = 16 },
        &d,
    ));
    try testing.expectEqual(@as(?[]u8, null), fx.fetcher.answer);
}

test "a search that never ends is stopped by the stall bound" {
    var fx: Fixture = undefined;
    try fx.start(.{ .entries = &.{root_entry}, .omit_done = true });
    defer fx.stop();

    const short: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(200), .clock = .awake } };
    try testing.expectError(error.OperationTimedOut, fx.fetcher.open(
        try fx.url("dc=zurl,dc=test?dc?sub"),
        .{ .read_timeout = short },
        null,
    ));
}

test "a peer that says nothing at all is stopped by the stall bound" {
    var server: test_server = undefined;
    try server.startSilent();
    defer server.stop();

    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();

    var text: [64]u8 = undefined;
    const url_text = try std.fmt.bufPrint(&text, "ldap://127.0.0.1:{d}/dc=a", .{server.port()});
    const short: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(200), .clock = .awake } };
    try testing.expectError(error.OperationTimedOut, f.open(
        try Fetcher.parseLdapUrl(url_text),
        .{ .read_timeout = short },
        null,
    ));
}

test "a refused StartTLS sends no credential and is exit 64" {
    // The fixture refuses StartTLS by default, because it speaks no TLS.
    var fx: Fixture = undefined;
    try fx.start(.{});
    defer fx.stop();

    var d: Diagnostics = .{};
    try testing.expectError(error.UseSslFailed, fx.fetcher.open(
        try fx.url("dc=a"),
        .{
            .tls = .explicit,
            .trust = fx.trust(),
            .credentials = .{ .dn = "cn=admin", .password = "hunter2" },
        },
        &d,
    ));
    fx.server.wait();

    // **Only the StartTLS went out.** No bind, so the password never left
    // this process.
    try testing.expectEqual(@as(usize, 1), fx.server.requestCount());
    const sent = fx.server.request(0);
    try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, sent, "hunter2"));
    try testing.expect(std.mem.indexOf(u8, sent, message.start_tls_oid) != null);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "refused StartTLS") != null);
}

test "the StartTLS request names the OID RFC 4511 gives it" {
    var fx: Fixture = undefined;
    try fx.start(.{});
    defer fx.stop();

    _ = fx.fetcher.open(
        try fx.url("dc=a"),
        .{ .tls = .explicit, .trust = fx.trust() },
        null,
    ) catch {};
    fx.server.wait();

    const want = [_]u8{ 0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16 } ++
        "1.3.6.1.4.1.1466.20037".*;
    try testing.expectEqualSlices(u8, &want, fx.server.request(0));
}

test "a server that writes behind its StartTLS answer is refused" {
    // **Those bytes crossed in the clear.** Carrying them into the session
    // would hand a caller text a listener on the path could have chosen.
    var fx: Fixture = undefined;
    try fx.start(.{ .start_tls_code = 0, .start_tls_trailer = "leftover" });
    defer fx.stop();

    var d: Diagnostics = .{};
    try testing.expectError(error.UseSslFailed, fx.fetcher.open(
        try fx.url("dc=a"),
        .{
            .tls = .explicit,
            .trust = fx.trust(),
            .credentials = .{ .dn = "cn=a", .password = "s3cret" },
        },
        &d,
    ));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "behind its StartTLS answer") != null);
}

test "a bind name naming a SASL mechanism is refused by name" {
    // This build sends only the simple bind of RFC 4511 section 4.2, and
    // `;AUTH=` is curl's spelling for a mechanism.
    var fx: Fixture = undefined;
    try fx.start(.{});
    defer fx.stop();

    var d: Diagnostics = .{};
    try testing.expectError(error.NotBuiltIn, fx.fetcher.open(
        try fx.url("dc=a"),
        .{ .credentials = .{ .dn = "cn=admin;AUTH=DIGEST-MD5", .password = "x" } },
        &d,
    ));
    try testing.expectEqual(@as(usize, 0), fx.server.connections());
    try testing.expect(std.mem.indexOf(u8, d.message.?, "simple bind") != null);
}

test "a bind name holding a control byte is refused before a socket opens" {
    var fx: Fixture = undefined;
    try fx.start(.{});
    defer fx.stop();

    try testing.expectError(error.InvalidUrl, fx.fetcher.open(
        try fx.url("dc=a"),
        .{ .credentials = .{ .dn = "cn=a\nb", .password = "x" } },
        null,
    ));
    try testing.expectEqual(@as(usize, 0), fx.server.connections());
}

test "a credential longer than this package sends is refused by name" {
    var fx: Fixture = undefined;
    try fx.start(.{});
    defer fx.stop();

    const long = "a" ** (Fetcher.max_bind_dn_bytes + 1);
    try testing.expectError(error.CredentialTooLarge, fx.fetcher.open(
        try fx.url("dc=a"),
        .{ .credentials = .{ .dn = long, .password = "x" } },
        null,
    ));
    try testing.expectEqual(@as(usize, 0), fx.server.connections());
}

test "a netrc entry reaches the bind when the url and -u name nothing" {
    var fx: Fixture = undefined;
    try fx.start(.{ .entries = &.{} });
    defer fx.stop();

    _ = try fx.fetch("dc=a", .{
        .netrc_text = "machine 127.0.0.1 login cn=netrc,dc=a password np",
    });
    fx.server.wait();

    var fields = try requestFields(fx.server.request(0), message.app_bind_request);
    _ = try fields.expect(ber.integer);
    try testing.expectEqualStrings("cn=netrc,dc=a", (try fields.expect(ber.octet_string)).content);
}

test "one fetcher runs two transfers and holds nothing of the first" {
    var fx: Fixture = undefined;
    try fx.start(.{ .entries = &.{root_entry} });
    defer fx.stop();

    const first = try fx.fetch("dc=zurl,dc=test?dc", .{});
    const first_len = first.len;
    try testing.expect(first_len != 0);

    var second: Fixture = undefined;
    try second.start(.{ .entries = &.{
        .{ .dn = "cn=b", .attributes = &.{.{ .description = "cn", .values = &.{"b"} }} },
    } });
    defer second.server.stop();

    const text = try std.fmt.bufPrint(&fx.url_text, "ldap://127.0.0.1:{d}/cn=b", .{
        second.server.port(),
    });
    const body = try fx.fetcher.open(try Fetcher.parseLdapUrl(text), .{}, null);
    try testing.expectEqualStrings("DN: cn=b\n\tcn: b\n\n\n", body.reader.buffered());
    second.fetcher.deinit();
}

test "the answer and the credential are wiped, so nothing outlives the transfer" {
    // A directory entry may hold a `userPassword`, and the buffers here
    // outlive the transfer that read them.
    var fx: Fixture = undefined;
    try fx.start(.{ .entries = &.{
        .{ .dn = "cn=a", .attributes = &.{
            .{ .description = "userPassword", .values = &.{"hunter2!"} },
        } },
    } });
    defer fx.stop();

    _ = try fx.fetch("cn=a", .{ .credentials = .{ .dn = "cn=admin", .password = "s3cretpw" } });

    // The credential is already gone: `open` wipes it on every path out.
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, &fx.fetcher.credential_storage, "s3cretpw"),
    );
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, &fx.fetcher.request.bytes, "s3cretpw"),
    );
    // The session buffer is wiped when `open` returns, so the last entry
    // is not in it either.
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, fx.fetcher.session.buffer.?, "hunter2!"),
    );
}

test "a url whose host does not accept a connection is exit 7" {
    var f: Fetcher = .init(testing.allocator, testing.io);
    defer f.deinit();
    try testing.expectError(error.CouldNotConnect, f.open(
        try Fetcher.parseLdapUrl("ldap://127.0.0.1:1/dc=a"),
        .{},
        null,
    ));
}

/// A cursor over the fields of one request the fixture kept.
///
/// **`message.read` reads replies and not requests**, on purpose: a client
/// that answered its own `BindRequest` tag would be reading a message it
/// should never see. So a test that walks what went out uses the BER
/// cursor itself, which is the same thing a server does.
///
/// `app` is the `[APPLICATION n]` tag the operation must carry, so a test
/// that expects a bind and finds a search says so.
fn requestFields(bytes: []const u8, app: u5) !ber.Cursor {
    var outer: ber.Cursor = .init(bytes);
    const envelope = try outer.expect(ber.sequence);
    var top = try outer.enter(envelope);
    _ = try top.expect(ber.integer);
    const op = try top.expect(.application(app, true));
    return top.enter(op);
}

/// The message id of one request the fixture kept.
fn requestId(bytes: []const u8) !i32 {
    var outer: ber.Cursor = .init(bytes);
    const envelope = try outer.expect(ber.sequence);
    var top = try outer.enter(envelope);
    return ber.integerValue(i32, try top.expect(ber.integer));
}

test "--connect-to moves an ldap dial and --resolve reaches this package too" {
    // The defect this closes: this package read no `connect_to`, so a
    // user who named either flag got a dial to the url's own host and no
    // diagnostic.
    //
    // **No test here touches a resolver.** The url names `127.0.0.2:1`,
    // which refuses at once, so the flag is the only thing that can reach
    // the fixture.
    var fx: Fixture = undefined;
    try fx.start(.{ .entries = &.{root_entry} });
    defer fx.stop();

    const url = try Fetcher.parseLdapUrl("ldap://127.0.0.2:1/dc=zurl,dc=test");

    var bare: Diagnostics = .{};
    try testing.expectError(error.CouldNotConnect, fx.fetcher.open(url, .{}, &bare));
    try testing.expectEqual(@as(usize, 0), fx.server.connections());

    const body = try fx.fetcher.open(url, .{ .connect_to = &.{.{
        .from_host = "127.0.0.2",
        .from_port = 1,
        .to_host = "127.0.0.1",
        .to_port = fx.server.port(),
    }} }, null);
    try testing.expectEqualStrings(
        "DN: dc=zurl,dc=test\n" ++
            "\tobjectClass: dcObject\n\tobjectClass: organization\n\n" ++
            "\tdc: zurl\n\n" ++
            "\to: zurl test directory\n\n" ++
            "\n",
        body.reader.buffered(),
    );
    try testing.expectEqual(@as(usize, 1), fx.server.connections());
}
