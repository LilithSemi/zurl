//! End to end tests of `zurl_ssh.Authenticator` against the loopback
//! fixture.
//!
//! These live in their own file for the reason `handshake_test.zig` gives:
//! the client and the fixture would otherwise import each other's module.
//!
//! **No test in this file reaches the real network.** Every one starts a
//! `test_server` on 127.0.0.1 with a port the operating system assigns.
//!
//! What these prove: that a `publickey` signature the client makes
//! verifies against a blob a second piece of code built from the RFC's
//! list, that a password crosses the wire and comes back accepted, that a
//! banner is filtered, and that every refusal happens where it should.
//! What they cannot prove is that the blob is the one the rest of the
//! world signs, because both sides are this repository. Only a real
//! `sshd` shows that, and the report records one.

const std = @import("std");

const Authenticator = @import("Authenticator.zig");
const Transport = @import("Transport.zig");
const privatekey = @import("privatekey.zig");
const test_server = @import("test_server.zig");
const userauth = @import("userauth.zig");
const wire = @import("wire.zig");

const testing = std.testing;

/// One fixture, one transport, one authenticator, and one key.
///
/// Every one of the four is on the heap, because each holds pointers into
/// the last and none of them may move.
const Fixture = struct {
    server: *test_server,
    endpoint: *test_server.Endpoint,
    transport: *Transport,
    authenticator: *Authenticator,
    key: *privatekey.PrivateKey,

    fn start(auth: test_server.AuthScript, options: Authenticator.Options) !Fixture {
        const key = try testing.allocator.create(privatekey.PrivateKey);
        errdefer testing.allocator.destroy(key);
        try privatekey.parse(key, testing.allocator, privatekey.test_plain_key, null);
        errdefer key.deinit();

        // The fixture takes the same key the client signs with, unless the
        // caller named another.
        var script = auth;
        if (script.public_key) |blob| {
            if (blob.len == 0) script.public_key = key.publicBlob();
        }

        const server = try testing.allocator.create(test_server);
        errdefer testing.allocator.destroy(server);
        try server.start(.{ .auth = script });
        errdefer server.stop();

        const endpoint = try testing.allocator.create(test_server.Endpoint);
        errdefer testing.allocator.destroy(endpoint);
        try endpoint.connect(server.port());
        errdefer endpoint.close();

        const transport = try testing.allocator.create(Transport);
        errdefer testing.allocator.destroy(transport);
        try transport.init(testing.allocator, testing.io, endpoint.channel(), .{
            .peer = .{ .host = "fixture.test", .port = 22 },
            .verifier = server.verifier(),
        });
        errdefer transport.deinit();

        const authenticator = try testing.allocator.create(Authenticator);
        errdefer testing.allocator.destroy(authenticator);

        var wired = options;
        if (wired.key != null) wired.key = key;
        authenticator.init(transport, wired);

        return .{
            .server = server,
            .endpoint = endpoint,
            .transport = transport,
            .authenticator = authenticator,
            .key = key,
        };
    }

    fn stop(f: Fixture) void {
        f.authenticator.deinit();
        testing.allocator.destroy(f.authenticator);
        f.transport.deinit();
        testing.allocator.destroy(f.transport);
        f.endpoint.close();
        testing.allocator.destroy(f.endpoint);
        f.server.stop();
        testing.allocator.destroy(f.server);
        f.key.deinit();
        testing.allocator.destroy(f.key);
    }

    /// Runs the handshake and then the authentication.
    fn run(f: Fixture) !void {
        try f.transport.handshake();
        return f.authenticator.authenticate();
    }
};

/// Put in `AuthScript.public_key` to mean "the key the client holds".
/// `Fixture.start` swaps it for the real blob, because the key does not
/// exist until `start` has parsed it.
const own_key: []const u8 = "";

/// Put in `Authenticator.Options.key` to mean "the key the fixture
/// parsed". `Fixture.start` swaps it for the real pointer, so **this value
/// is never read**. It exists only to say that a key is wanted.
var own_key_marker: privatekey.PrivateKey = undefined;

test "a publickey attempt signs the session identifier and the server accepts" {
    // **This is the test that proves the signature blob against a second
    // build of it.** The fixture writes the eight fields of RFC 4252
    // section 7 by hand and verifies the client's signature over them. A
    // client that left the session identifier out, or that wrote the
    // fields in another order, fails here.
    var f = try Fixture.start(
        .{ .public_key = own_key, .methods = "publickey" },
        .{ .user = "alice", .key = &own_key_marker },
    );
    defer f.stop();

    try f.run();
    try testing.expect(f.authenticator.authenticated());
    // Two publickey requests went out, the query and the signed attempt,
    // and the `none` request before them.
    try testing.expectEqual(@as(u64, 3), f.authenticator.counters.attempts);
    try testing.expectEqual(@as(u64, 1), f.authenticator.counters.failures);
    try testing.expectEqual(@as(u64, 0), f.authenticator.counters.public_key_queries_refused);
}

test "a signature made for another session does not verify" {
    // **The session identifier is what makes a captured signature
    // useless.** The client cannot be made to sign the wrong one, so this
    // drives the same check from the other side: the fixture verifies
    // against its own session identifier, and a client that signed
    // anything else is refused. The proof that the two are the same value
    // is that the test above passes.
    //
    // Here the fixture holds a key the client does not have, so no
    // signature the client could make would verify at all.
    const other_seed: [32]u8 = @splat(0x91);
    const other = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(other_seed);
    var blob_storage: [64]u8 = undefined;
    var blob: wire.Writer = .init(&blob_storage);
    try blob.string("ssh-ed25519");
    try blob.string(&other.public_key.toBytes());

    var f = try Fixture.start(
        .{ .public_key = blob.written(), .methods = "publickey" },
        .{ .user = "alice", .key = &own_key_marker },
    );
    defer f.stop();

    try testing.expectError(error.AuthenticationFailed, f.run());
    try testing.expect(!f.authenticator.authenticated());
}

test "a publickey query the server refuses costs no signature" {
    // RFC 4252 section 7 lets a client ask first. A server with a long
    // list of keys answers the query with a failure, and no signing work
    // is done at all.
    var f = try Fixture.start(
        .{ .public_key = own_key, .refuse_public_key_query = true, .methods = "publickey" },
        .{ .user = "alice", .key = &own_key_marker },
    );
    defer f.stop();

    try testing.expectError(error.AuthenticationFailed, f.run());
    try testing.expectEqual(@as(u64, 1), f.authenticator.counters.public_key_queries_refused);
    // The `none` request and the query, and nothing more.
    try testing.expectEqual(@as(u64, 2), f.authenticator.counters.attempts);
}

test "a publickey query answered with a success is refused, because nothing was proved" {
    // **A query is a question, and this is a yes to a question nobody
    // proved the answer to.** RFC 4252 section 7 gives a server two
    // answers to a query: a failure, or `SSH_MSG_USERAUTH_PK_OK`. A
    // success is neither, and taking it would leave this build with a
    // path where the login worked and no signature was ever made.
    //
    // The server is the party that loses by accepting an unproven key,
    // and it has already decided, so this costs the client nothing it can
    // measure. The reason to refuse is the path, not the loss: a rule
    // that says yes to something it never proved is how the next defect
    // gets in, and a broken or hostile server is caught here rather than
    // three messages later.
    var f = try Fixture.start(
        .{
            .public_key = own_key,
            .answer_public_key_query_with_success = true,
            .methods = "publickey",
        },
        .{ .user = "alice", .key = &own_key_marker },
    );
    defer f.stop();

    try testing.expectError(error.PublicKeyAcceptedUnproven, f.run());
    try testing.expect(!f.authenticator.authenticated());
    try testing.expectEqual(@as(u64, 1), f.authenticator.counters.public_key_unproven);
}

test "a PK_OK that names another key is refused before anything is signed" {
    // **A server that echoes a key the client did not send is answering a
    // question nobody asked.** Signing after that would prove nothing
    // about this exchange.
    var f = try Fixture.start(
        .{ .public_key = own_key, .forge_public_key_ok = true, .methods = "publickey" },
        .{ .user = "alice", .key = &own_key_marker },
    );
    defer f.stop();

    try testing.expectError(error.PublicKeyOkMismatch, f.run());
}

test "a password attempt crosses the wire and the server accepts" {
    var f = try Fixture.start(
        .{ .password = "hunter2", .methods = "password" },
        .{ .user = "alice", .password = "hunter2" },
    );
    defer f.stop();

    try f.run();
    try testing.expect(f.authenticator.authenticated());
}

test "a wrong password fails and the failure names no reason of its own" {
    // **The server decides what a failure says.** The client reports
    // `AuthenticationFailed` and nothing more, so it cannot tell a user
    // that the account exists or that the password was close.
    var f = try Fixture.start(
        .{ .password = "hunter2", .methods = "password" },
        .{ .user = "alice", .password = "wrong" },
    );
    defer f.stop();

    try testing.expectError(error.AuthenticationFailed, f.run());
    try testing.expectEqualStrings("password", f.authenticator.acceptedMethods());
}

test "a password change request is refused by name" {
    var f = try Fixture.start(
        .{ .password = "hunter2", .password_change = true, .methods = "password" },
        .{ .user = "alice", .password = "hunter2" },
    );
    defer f.stop();

    try testing.expectError(error.PasswordChangeRequired, f.run());
}

test "keyboard-interactive answers one hidden question with the password" {
    var f = try Fixture.start(
        .{
            .password = "hunter2",
            .methods = "keyboard-interactive",
            .interactive_prompts = 1,
        },
        .{ .user = "alice", .password = "hunter2" },
    );
    defer f.stop();

    try f.run();
    try testing.expect(f.authenticator.authenticated());
    try testing.expectEqual(@as(u64, 1), f.authenticator.counters.info_requests);
}

test "an informational round with no prompt is answered with no answers" {
    // RFC 4256 section 3.3. The first round carries no question at all,
    // and the second carries the password prompt.
    var f = try Fixture.start(
        .{
            .password = "hunter2",
            .methods = "keyboard-interactive",
            .interactive_rounds = 2,
            .interactive_prompts = 1,
        },
        .{ .user = "alice", .password = "hunter2" },
    );
    defer f.stop();

    try f.run();
    try testing.expect(f.authenticator.authenticated());
    try testing.expectEqual(@as(u64, 2), f.authenticator.counters.info_requests);
}

test "a keyboard-interactive question this build cannot answer is refused by name" {
    // **Two questions want two different answers.** Sending the password
    // twice would put it where the server asked for something else.
    var f = try Fixture.start(
        .{
            .password = "hunter2",
            .methods = "keyboard-interactive",
            .interactive_prompts = 2,
        },
        .{ .user = "alice", .password = "hunter2" },
    );
    defer f.stop();
    try testing.expectError(error.KeyboardInteractivePromptUnsupported, f.run());

    // And a question the server wants echoed is not a password.
    var echoed = try Fixture.start(
        .{
            .password = "hunter2",
            .methods = "keyboard-interactive",
            .interactive_prompts = 1,
            .interactive_echo = true,
        },
        .{ .user = "alice", .password = "hunter2" },
    );
    defer echoed.stop();
    try testing.expectError(error.KeyboardInteractivePromptUnsupported, echoed.run());
}

test "keyboard-interactive is skipped when the caller turns it off" {
    var f = try Fixture.start(
        .{ .password = "hunter2", .methods = "keyboard-interactive" },
        .{
            .user = "alice",
            .password = "hunter2",
            .allow_keyboard_interactive = false,
        },
    );
    defer f.stop();

    // The server names one method and the caller will not run it, so
    // nothing was ever offered.
    try testing.expectError(error.NoUsableAuthMethod, f.run());
}

test "a partial success runs the second method" {
    // RFC 4252 section 5.1. The key works and the server wants the
    // password as well.
    var f = try Fixture.start(
        .{
            .public_key = own_key,
            .password = "hunter2",
            .partial_success = true,
            .methods = "publickey,password",
        },
        .{ .user = "alice", .key = &own_key_marker, .password = "hunter2" },
    );
    defer f.stop();

    try f.run();
    try testing.expect(f.authenticator.authenticated());
    try testing.expectEqual(@as(u64, 1), f.authenticator.counters.partial_successes);
    // **A partial success is never a success.** The flag came back true
    // and the run went on to the second method.
    try testing.expect(f.authenticator.partialSuccess());
}

test "the none method learns the list, and a server may accept it" {
    var accepted = try Fixture.start(
        .{ .accept_none = true },
        .{ .user = "alice" },
    );
    defer accepted.stop();
    try accepted.run();
    try testing.expect(accepted.authenticator.authenticated());
    try testing.expectEqual(@as(u64, 1), accepted.authenticator.counters.attempts);

    var refused = try Fixture.start(
        .{ .methods = "publickey,password" },
        .{ .user = "alice" },
    );
    defer refused.stop();
    // The caller gave no credential, so nothing on the server's list can
    // be offered.
    try testing.expectError(error.NoUsableAuthMethod, refused.run());
    try testing.expectEqualStrings("publickey,password", refused.authenticator.acceptedMethods());
}

test "a method the server did not name is never tried" {
    // The caller has a password and the server names only `publickey`, so
    // the password never goes out.
    var f = try Fixture.start(
        .{ .password = "hunter2", .methods = "publickey" },
        .{ .user = "alice", .password = "hunter2" },
    );
    defer f.stop();

    try testing.expectError(error.NoUsableAuthMethod, f.run());
    // The `none` request, and nothing else.
    try testing.expectEqual(@as(u64, 1), f.authenticator.counters.attempts);
}

test "a run that offered everything it had is a failure and not a bound" {
    // **The two must not be confused.** A caller that is out of
    // credentials has a different thing to fix from a caller that hit a
    // bound it set itself. Here `max_rounds` is exactly the number of
    // methods there are to offer, so a bound checked one step late would
    // report the wrong one.
    var f = try Fixture.start(
        .{ .password = "hunter2", .methods = "password" },
        .{ .user = "alice", .password = "wrong", .max_rounds = 1 },
    );
    defer f.stop();
    try testing.expectError(error.AuthenticationFailed, f.run());

    // And a bound of zero stops before anything is offered.
    var none = try Fixture.start(
        .{ .password = "hunter2", .methods = "password" },
        .{ .user = "alice", .password = "hunter2", .max_rounds = 0 },
    );
    defer none.stop();
    try testing.expectError(error.TooManyAuthRounds, none.run());
}

/// Keeps the banners a test's sink was given.
const BannerRecord = struct {
    storage: [1024]u8 = undefined,
    len: usize = 0,
    count: usize = 0,

    fn show(ctx: ?*anyopaque, given: []const u8) void {
        const self: *BannerRecord = @ptrCast(@alignCast(ctx.?));
        self.count += 1;
        const take = @min(given.len, self.storage.len);
        @memcpy(self.storage[0..take], given[0..take]);
        self.len = take;
    }

    fn text(self: *const BannerRecord) []const u8 {
        return self.storage[0..self.len];
    }
};

test "a banner reaches the caller with everything a terminal acts on taken out" {
    var record: BannerRecord = .{};
    var f = try Fixture.start(
        .{
            .password = "hunter2",
            .methods = "password",
            .banner = "welcome\n\x1b[2Jto the fixture\r\n",
        },
        .{
            .user = "alice",
            .password = "hunter2",
            .banner = .{ .ctx = &record, .show = BannerRecord.show },
        },
    );
    defer f.stop();

    try f.run();
    try testing.expect(f.authenticator.authenticated());
    try testing.expectEqual(@as(usize, 1), record.count);
    // The escape and the carriage return are gone and the line feeds
    // stayed, because a banner is many lines of text.
    try testing.expectEqualStrings("welcome\n?[2Jto the fixture?\n", record.text());
    try testing.expectEqualStrings("welcome\n?[2Jto the fixture?\n", f.authenticator.banner());
    try testing.expectEqual(@as(u64, 1), f.authenticator.counters.banners);
}

test "a banner with no sink is still counted and never dropped in silence" {
    var f = try Fixture.start(
        .{ .password = "hunter2", .methods = "password", .banner = "hello" },
        .{ .user = "alice", .password = "hunter2" },
    );
    defer f.stop();

    try f.run();
    try testing.expectEqual(@as(u64, 1), f.authenticator.counters.banners);
    try testing.expectEqual(@as(u64, 5), f.authenticator.counters.banner_bytes);
    try testing.expectEqualStrings("hello", f.authenticator.banner());
}

test "a server that writes banners without end is stopped by a bound" {
    // **A banner arrives before authentication, so any host that answers
    // a connection can choose these bytes.** A peer that writes them
    // forever is closed by the run bound.
    var f = try Fixture.start(
        .{
            .password = "hunter2",
            .methods = "password",
            .banner = "spam",
            .banner_count = Authenticator.max_banner_run + 1,
        },
        .{ .user = "alice", .password = "hunter2" },
    );
    defer f.stop();

    try testing.expectError(error.TooManyBanners, f.run());
}

test "a server that will not start ssh-userauth is a named refusal" {
    var f = try Fixture.start(
        .{ .refuse_service = true },
        .{ .user = "alice", .password = "hunter2" },
    );
    defer f.stop();

    // The fixture says goodbye rather than accepting the service, and the
    // transport reports that first.
    try testing.expectError(error.PeerDisconnected, f.run());
}

test "a service accept that names another service is refused" {
    var f = try Fixture.start(
        .{ .service_name = "ssh-connection", .password = "hunter2" },
        .{ .user = "alice", .password = "hunter2" },
    );
    defer f.stop();

    try testing.expectError(error.ServiceMismatch, f.run());
}

test "a service accept with no name at all is accepted, because some servers write none" {
    var f = try Fixture.start(
        .{ .service_name = "", .password = "hunter2", .methods = "password" },
        .{ .user = "alice", .password = "hunter2" },
    );
    defer f.stop();

    try f.run();
    try testing.expect(f.authenticator.authenticated());
}

test "authentication before the handshake is a named fault and writes nothing" {
    var f = try Fixture.start(
        .{ .password = "hunter2" },
        .{ .user = "alice", .password = "hunter2" },
    );
    defer f.stop();

    // No handshake, so there is no session identifier to sign against and
    // no cipher to send a password under.
    try testing.expectError(error.SessionNotEstablished, f.authenticator.authenticate());
}

test "an empty user name and one that is too long are both refused before any write" {
    var empty = try Fixture.start(.{}, .{ .user = "" });
    defer empty.stop();
    try testing.expectError(error.UserNameEmpty, empty.authenticator.authenticate());

    const long: [userauth.max_user_bytes + 1]u8 = @splat('a');
    var big = try Fixture.start(.{}, .{ .user = &long });
    defer big.stop();
    try testing.expectError(error.UserNameTooLong, big.authenticator.authenticate());
}

test "the wrong user is refused, whatever the credential" {
    var f = try Fixture.start(
        .{ .password = "hunter2", .methods = "password", .user = "alice" },
        .{ .user = "mallory", .password = "hunter2" },
    );
    defer f.stop();

    try testing.expectError(error.AuthenticationFailed, f.run());
}

test "a key and a password together try the key first" {
    // The key is the one the fixture holds and the password is wrong, so
    // a run that tried the password first would fail.
    var f = try Fixture.start(
        .{
            .public_key = own_key,
            .password = "hunter2",
            .methods = "publickey,password",
        },
        .{ .user = "alice", .key = &own_key_marker, .password = "wrong" },
    );
    defer f.stop();

    try f.run();
    try testing.expect(f.authenticator.authenticated());
}

test "the request buffer holds no password once an attempt is over" {
    // **A password lives in the request buffer until it is encrypted.**
    // This reads the buffer back afterwards, which is the only way to
    // show the wipe happened.
    var f = try Fixture.start(
        .{ .password = "hunter2", .methods = "password" },
        .{ .user = "alice", .password = "hunter2" },
    );
    defer f.stop();

    try f.run();
    try testing.expect(f.authenticator.authenticated());
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, &f.authenticator.request_storage, "hunter2"),
    );
}

test "the encrypted key file signs the same way the plain one does" {
    // The key here comes out of an `aes256-ctr` file with a `bcrypt`
    // derivation, so this is the whole path from a passphrase to a
    // signature a server accepts.
    var key: privatekey.PrivateKey = undefined;
    try privatekey.parse(
        &key,
        testing.allocator,
        privatekey.test_encrypted_key,
        privatekey.test_encrypted_passphrase,
    );
    defer key.deinit();

    const server = try testing.allocator.create(test_server);
    defer testing.allocator.destroy(server);
    try server.start(.{ .auth = .{
        .public_key = key.publicBlob(),
        .methods = "publickey",
    } });
    defer server.stop();

    const endpoint = try testing.allocator.create(test_server.Endpoint);
    defer testing.allocator.destroy(endpoint);
    try endpoint.connect(server.port());
    defer endpoint.close();

    const transport = try testing.allocator.create(Transport);
    defer testing.allocator.destroy(transport);
    try transport.init(testing.allocator, testing.io, endpoint.channel(), .{
        .peer = .{ .host = "fixture.test", .port = 22 },
        .verifier = server.verifier(),
    });
    defer transport.deinit();

    const authenticator = try testing.allocator.create(Authenticator);
    defer testing.allocator.destroy(authenticator);
    authenticator.init(transport, .{ .user = "alice", .key = &key });
    defer authenticator.deinit();

    try transport.handshake();
    try authenticator.authenticate();
    try testing.expect(authenticator.authenticated());
}
