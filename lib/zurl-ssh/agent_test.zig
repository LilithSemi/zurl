//! End to end tests of `zurl_ssh.AgentClient` against a loopback agent,
//! and of a `publickey` login that the agent signs.
//!
//! These live in their own file for the reason `channel_test.zig` gives:
//! the client and the fixtures would otherwise import each other's module.
//! The login test needs both fixtures at once, the SSH server and the
//! agent, and this is the one file that holds them together.
//!
//! **No test in this file reaches the real network, and none of them
//! reaches a real agent.** The agent fixture listens on a unix domain
//! socket inside the test's own temporary directory, and the SSH fixture
//! listens on 127.0.0.1 with a port the operating system assigns.
//!
//! **The login test is the one that matters.** The SSH fixture accepts one
//! public key blob and checks the signature against it, and the key the
//! agent signs with never reaches the client: the client learns the blob
//! from the agent's identities answer and gets the signature from the
//! agent's sign response. A build where the agent path is wired to a key
//! this process holds would still pass every other test in this file and
//! would fail this one.

const std = @import("std");

const AgentClient = @import("AgentClient.zig");
const Authenticator = @import("Authenticator.zig");
const Transport = @import("Transport.zig");
const agent = @import("agent.zig");
const privatekey = @import("privatekey.zig");
const test_server = @import("test_server.zig");
const wire = @import("wire.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const testing = std.testing;

/// The seed of the key the agent fixture signs with. A constant, so every
/// run offers the same public key and a test can pin its blob.
const agent_key_seed: [Ed25519.KeyPair.seed_length]u8 = @splat(0x71);

/// How long a test waits for the agent fixture to answer.
const test_stall: std.Io.Timeout = .{
    .duration = .{ .raw = .fromSeconds(10), .clock = .awake },
};

/// What one run of the agent fixture answers with.
const Script = struct {
    /// Whether to list an RSA key in front of the `ssh-ed25519` one.
    ///
    /// **True is the case that matters.** A person whose agent holds an
    /// RSA key beside an `ssh-ed25519` one must still log in.
    list_rsa_first: bool = true,
    /// Whether to list the `ssh-ed25519` key at all.
    list_ed25519: bool = true,
    /// Answer `SSH_AGENT_FAILURE` to the identities request.
    refuse_identities: bool = false,
    /// Answer `SSH_AGENT_FAILURE` to the sign request.
    refuse_sign: bool = false,
    /// Write a length field that claims more than the body holds, then
    /// close. A client that trusted the length would read past its own
    /// buffer or hang.
    lie_about_length: bool = false,
    /// Close the socket without answering anything at all.
    close_at_once: bool = false,
};

/// A loopback SSH agent, for the tests of this package.
///
/// **This is a test fixture and not a product.** It answers
/// `SSH_AGENTC_REQUEST_IDENTITIES` and `SSH_AGENTC_SIGN_REQUEST` and
/// nothing else, and it holds one key with no passphrase and no
/// constraint.
///
/// **Must not move once `start` has run.** The task holds a pointer to it.
const FakeAgent = struct {
    server: std.Io.net.Server,
    task: std.Io.Future(void),
    script: Script,
    key: Ed25519.KeyPair,
    key_blob_storage: [128]u8,
    key_blob_len: usize,
    path_storage: [128]u8,
    path_len: usize,
    signed_storage: [4096]u8,
    signed_len: usize,
    failure: ?[]const u8,
    finished: std.atomic.Value(bool),

    /// Listens on a socket inside `dir_sub_path` and answers one
    /// connection.
    ///
    /// Returns `error.SkipZigTest` in a build with no concurrency. The
    /// agent and its client cannot both make progress on one task.
    fn start(a: *FakeAgent, dir_sub_path: []const u8, script: Script) !void {
        const socket_path = try std.fmt.bufPrint(
            &a.path_storage,
            ".zig-cache/tmp/{s}/agent.sock",
            .{dir_sub_path},
        );
        a.path_len = socket_path.len;

        const address = try std.Io.net.UnixAddress.init(socket_path);
        a.server = try address.listen(testing.io, .{});
        errdefer a.server.deinit(testing.io);

        a.script = script;
        a.key = try Ed25519.KeyPair.generateDeterministic(agent_key_seed);
        var blob: wire.Writer = .init(&a.key_blob_storage);
        try blob.string("ssh-ed25519");
        try blob.string(&a.key.public_key.toBytes());
        a.key_blob_len = blob.written().len;
        a.signed_len = 0;
        a.failure = null;
        a.finished = .init(false);

        a.task = testing.io.concurrent(run, .{a}) catch |err| switch (err) {
            error.ConcurrencyUnavailable => {
                if (@import("builtin").single_threaded) return error.SkipZigTest;
                return err;
            },
        };
    }

    fn stop(a: *FakeAgent) void {
        a.task.cancel(testing.io);
        a.server.deinit(testing.io);
    }

    fn path(a: *const FakeAgent) []const u8 {
        return a.path_storage[0..a.path_len];
    }

    fn keyBlob(a: *const FakeAgent) []const u8 {
        return a.key_blob_storage[0..a.key_blob_len];
    }

    /// The bytes the client asked to have signed, byte for byte.
    ///
    /// **Not thread safe while the task runs.** A test reads it after the
    /// exchange is over, the way `test_server.failure` is read.
    fn signedData(a: *const FakeAgent) []const u8 {
        return a.signed_storage[0..a.signed_len];
    }

    fn run(a: *FakeAgent) void {
        a.runFallible() catch |err| {
            a.failure = @errorName(err);
        };
        a.finished.store(true, .release);
    }

    fn runFallible(a: *FakeAgent) !void {
        const stream = try a.server.accept(testing.io);
        defer stream.close(testing.io);

        if (a.script.close_at_once) return;

        var read_storage: [8192]u8 = undefined;
        var write_storage: [8192]u8 = undefined;
        var reader: std.Io.net.Stream.Reader = .init(stream, testing.io, &read_storage);
        var writer: std.Io.net.Stream.Writer = .init(stream, testing.io, &write_storage);

        var body_storage: [8192]u8 = undefined;
        // The agent answers until the client closes, the way a real one
        // does. A test that ran a fixed number of rounds would have the
        // fixture close first, and a client that then read nothing would
        // look broken when it is not.
        while (true) {
            var header: [4]u8 = undefined;
            reader.interface.readSliceAll(&header) catch return;
            const declared = std.mem.readInt(u32, &header, .big);
            if (declared == 0 or declared > body_storage.len) return error.BadRequestLength;
            const body = body_storage[0..declared];
            try reader.interface.readSliceAll(body);

            var r: wire.Reader = .init(body);
            switch (@as(agent.Id, @enumFromInt(try r.byte()))) {
                .request_identities => try a.answerIdentities(&writer),
                .sign_request => {
                    const asked_blob = try r.string();
                    if (!std.mem.eql(u8, asked_blob, a.keyBlob())) return error.WrongKeyAsked;
                    const data = try r.string();
                    if (data.len > a.signed_storage.len) return error.SignDataTooLong;
                    @memcpy(a.signed_storage[0..data.len], data);
                    a.signed_len = data.len;
                    try a.answerSignature(&writer, data);
                },
                else => return error.UnknownRequest,
            }
            // A lying length is followed by a close, so the client waits
            // for bytes that will never come and must say so. Leaving the
            // socket open would test the stall bound instead.
            if (a.script.lie_about_length) return;
        }
    }

    fn answerIdentities(a: *FakeAgent, writer: *std.Io.net.Stream.Writer) !void {
        if (a.script.refuse_identities) return a.sendFailure(writer);

        var storage: [1024]u8 = undefined;
        var w: wire.Writer = .init(&storage);
        try w.uint32(0);
        const body_at = w.at;
        try w.byte(@intFromEnum(agent.Id.identities_answer));

        var count: u32 = 0;
        if (a.script.list_rsa_first) count += 1;
        if (a.script.list_ed25519) count += 1;
        try w.uint32(count);

        if (a.script.list_rsa_first) {
            var rsa_storage: [256]u8 = undefined;
            var rsa: wire.Writer = .init(&rsa_storage);
            try rsa.string("ssh-rsa");
            try rsa.mpint(&.{ 0x01, 0x00, 0x01 });
            try rsa.mpint(&.{ 0xde, 0xad, 0xbe, 0xef });
            try w.string(rsa.written());
            try w.string("an RSA key the client must walk past");
        }
        if (a.script.list_ed25519) {
            try w.string(a.keyBlob());
            try w.string("the key the agent signs with");
        }

        return a.frameAndSend(writer, w.written(), body_at);
    }

    fn answerSignature(
        a: *FakeAgent,
        writer: *std.Io.net.Stream.Writer,
        data: []const u8,
    ) !void {
        if (a.script.refuse_sign) return a.sendFailure(writer);

        var storage: [256]u8 = undefined;
        var w: wire.Writer = .init(&storage);
        try w.uint32(0);
        const body_at = w.at;
        try w.byte(@intFromEnum(agent.Id.sign_response));

        var blob_storage: [128]u8 = undefined;
        var blob: wire.Writer = .init(&blob_storage);
        try blob.string("ssh-ed25519");
        const signature = try a.key.sign(data, null);
        try blob.string(&signature.toBytes());
        try w.string(blob.written());

        return a.frameAndSend(writer, w.written(), body_at);
    }

    fn sendFailure(a: *FakeAgent, writer: *std.Io.net.Stream.Writer) !void {
        var storage: [8]u8 = undefined;
        var w: wire.Writer = .init(&storage);
        try w.uint32(0);
        const body_at = w.at;
        try w.byte(@intFromEnum(agent.Id.failure));
        return a.frameAndSend(writer, w.written(), body_at);
    }

    /// Writes the length of the body over the four bytes left for it, then
    /// pushes the message out.
    ///
    /// With `lie_about_length` set, the length claims one more byte than
    /// the body holds and the socket then closes. That is the answer a
    /// client must refuse rather than wait on or read past.
    fn frameAndSend(
        a: *FakeAgent,
        writer: *std.Io.net.Stream.Writer,
        message: []u8,
        body_at: usize,
    ) !void {
        const body_len = message.len - body_at;
        const declared: u32 = @intCast(if (a.script.lie_about_length) body_len + 64 else body_len);
        std.mem.writeInt(u32, message[0..4], declared, .big);
        try writer.interface.writeAll(message);
        try writer.interface.flush();
    }
};

/// A temporary directory, its agent, and the client connected to it.
const Fixture = struct {
    tmp: testing.TmpDir,
    fake: *FakeAgent,
    client: *AgentClient,

    fn start(script: Script) !Fixture {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();

        const fake = try testing.allocator.create(FakeAgent);
        errdefer testing.allocator.destroy(fake);
        try fake.start(&tmp.sub_path, script);
        errdefer fake.stop();

        const client = try testing.allocator.create(AgentClient);
        errdefer testing.allocator.destroy(client);
        try client.connect(testing.io, fake.path(), .{ .stall = test_stall });

        return .{ .tmp = tmp, .fake = fake, .client = client };
    }

    fn stop(f: *Fixture) void {
        f.client.close();
        testing.allocator.destroy(f.client);
        f.fake.stop();
        testing.allocator.destroy(f.fake);
        f.tmp.cleanup();
    }
};

test "an agent holding an RSA key and an ed25519 key gives back the ed25519 one" {
    var f = try Fixture.start(.{});
    defer f.stop();

    const chosen = try f.client.selectIdentity();
    try testing.expectEqualSlices(u8, f.fake.keyBlob(), chosen.key_blob);
    try testing.expectEqualStrings("the key the agent signs with", chosen.comment);

    // **The recovery is counted and not silent.** One key was walked past,
    // and a caller that wonders why a login failed can read that.
    try testing.expectEqual(@as(u64, 2), f.client.counters.identities_seen);
    try testing.expectEqual(@as(u64, 1), f.client.counters.identities_skipped);

    const signer = f.client.signer().?;
    try testing.expectEqualStrings("ssh-ed25519", signer.algorithm);
    try testing.expectEqualSlices(u8, f.fake.keyBlob(), signer.public_blob);
}

test "an agent holding no key this build can use is a named refusal" {
    var f = try Fixture.start(.{ .list_ed25519 = false });
    defer f.stop();

    try testing.expectError(error.NoUsableIdentity, f.client.selectIdentity());
    // Null and not a signer with no key behind it, so no `publickey`
    // attempt is ever offered.
    try testing.expectEqual(@as(?@TypeOf(f.client.signer().?), null), f.client.signer());
    try testing.expectEqual(@as(?AgentClient.Error, error.NoUsableIdentity), f.client.fault);
}

test "an agent that refuses the identities request is a named refusal" {
    var f = try Fixture.start(.{ .refuse_identities = true });
    defer f.stop();

    try testing.expectError(error.AgentRefused, f.client.selectIdentity());
}

test "a signature the agent refuses reaches the caller by name" {
    var f = try Fixture.start(.{ .refuse_sign = true });
    defer f.stop();

    _ = try f.client.selectIdentity();
    var out: [privatekey.max_signature_bytes]u8 = undefined;
    try testing.expectError(error.AgentRefused, f.client.sign("a message", &out));
    try testing.expectEqual(@as(u64, 1), f.client.counters.sign_refusals);

    // Through the signer seam the same refusal is `SignerRefused`, and
    // the name of what happened stays readable in `fault`.
    const signer = f.client.signer().?;
    try testing.expectError(
        error.SignerRefused,
        signer.sign(signer.ctx, "a message", &out),
    );
    try testing.expectEqual(@as(?AgentClient.Error, error.AgentRefused), f.client.fault);
}

test "an answer whose length runs past what arrives is refused and never read past" {
    // The agent claims 64 bytes more than it wrote and then closes.
    // **A client that trusted the length would read past its buffer or
    // wait for bytes that are never coming.**
    var f = try Fixture.start(.{ .lie_about_length = true });
    defer f.stop();

    const answered = f.client.selectIdentity();
    try testing.expectError(error.EndOfStream, answered);
}

test "an agent that closes without answering is refused and does not hang" {
    var f = try Fixture.start(.{ .close_at_once = true });
    defer f.stop();

    // **The name depends on the race and the refusal does not.** A peer
    // that closes while a request is still in flight gives a reset on one
    // run and a clean end on another, so the test names the set and not
    // one member of it. What it proves is that the client stops with an
    // error rather than waiting out its stall bound.
    if (f.client.selectIdentity()) |_| {
        return error.TestExpectedRefusal;
    } else |err| switch (err) {
        error.EndOfStream, error.ReadFailed, error.WriteFailed => {},
        else => {
            std.debug.print("\nexpected a closed socket, got {s}\n", .{@errorName(err)});
            return error.TestUnexpectedError;
        },
    }
}

test "a request before connect, and one after close, are refused by name" {
    var client: AgentClient = undefined;
    // `connect` is what sets this, so a value that never connected is
    // set by hand here and nowhere else.
    client.connected = false;
    client.key_blob_len = 0;
    client.fault = null;
    client.counters = .{};
    try testing.expectError(error.AgentNotConnected, client.selectIdentity());

    var f = try Fixture.start(.{});
    defer f.stop();
    _ = try f.client.selectIdentity();
    f.client.close();
    var out: [privatekey.max_signature_bytes]u8 = undefined;
    try testing.expectError(error.AgentNotConnected, f.client.sign("a message", &out));
}

test "a publickey login completes with the signature the agent returned" {
    // **The test the whole file is for.** The client holds no private
    // key. It learns the public key from the agent's identities answer,
    // asks the agent for a signature over the blob of RFC 4252 section 7,
    // and the SSH fixture checks that signature against the blob the
    // request offered.
    var f = try Fixture.start(.{});
    defer f.stop();

    const chosen = try f.client.selectIdentity();

    const server = try testing.allocator.create(test_server);
    defer testing.allocator.destroy(server);
    try server.start(.{ .auth = .{
        .user = "alice",
        .public_key = chosen.key_blob,
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
    authenticator.init(transport, .{
        .user = "alice",
        .signer = f.client.signer(),
    });
    defer authenticator.deinit();

    try transport.handshake();
    errdefer if (server.failure) |name| {
        std.debug.print("\nthe fixture failed first: {s}\n", .{name});
    };
    try authenticator.authenticate();
    try testing.expect(authenticator.authenticated());

    // One signature, and it covered the session identifier. RFC 4252
    // section 7 puts that first, and without it a signature from one
    // session would prove the same thing in every other one.
    try testing.expectEqual(@as(u64, 1), f.client.counters.sign_requests);
    const signed = f.fake.signedData();
    var r: wire.Reader = .init(signed);
    const session_id = try r.string();
    try testing.expectEqualSlices(u8, transport.sessionId().?, session_id);
}

test "a caller that names a key and a signer at once is refused" {
    // **Two answers to one question, and picking one silently is what
    // this refuses to do.** The two can name two different keys.
    const server = try testing.allocator.create(test_server);
    defer testing.allocator.destroy(server);
    try server.start(.{ .auth = .{ .accept_none = false, .methods = "publickey" } });
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
    try transport.handshake();

    const key = try testing.allocator.create(privatekey.PrivateKey);
    defer testing.allocator.destroy(key);
    try privatekey.parse(key, testing.allocator, privatekey.test_plain_key, null);
    defer key.deinit();

    const authenticator = try testing.allocator.create(Authenticator);
    defer testing.allocator.destroy(authenticator);
    authenticator.init(transport, .{
        .user = "alice",
        .key = key,
        .signer = key.signer(),
    });
    defer authenticator.deinit();

    try testing.expectError(error.TwoPublicKeySigners, authenticator.authenticate());
}

const Client = @import("Client.zig");
const hostkey = @import("hostkey.zig");

test "a signer reaches the authenticator through Client, and no key file is read" {
    // **`Client` is the door a caller comes through, so a signer that only
    // `Authenticator` took was a seam nobody could reach.** The agent held
    // the key, `Authenticator.Options` had a place to put it, and
    // `Client.Options` did not. A consumer driving `Client` then had to
    // rebuild the dial, the key exchange and the login to use an agent,
    // and a second copy of that sequence is a second copy of the host key
    // check, which is the last thing that may have two.
    //
    // This opens a whole connection with a signer and no key at all.
    var f = try Fixture.start(.{});
    defer f.stop();

    const chosen = try f.client.selectIdentity();

    var server: test_server = undefined;
    try server.start(.{
        .auth = .{
            .user = "alice",
            .public_key = chosen.key_blob,
            .methods = "publickey",
        },
        .connection = .{ .service = .idle, .accept_request = "subsystem" },
    });
    defer server.stop();

    var client: Client = undefined;
    try client.open(testing.allocator, testing.io, .{
        .peer = .{ .host = "127.0.0.1", .port = server.port() },
        .verifier = server.verifier(),
        .user = "alice",
        .signer = f.client.signer(),
    });
    defer client.close();

    // The agent signed once, and nothing came off the disk.
    try testing.expectEqual(@as(u64, 1), f.client.counters.sign_requests);
    try testing.expectEqualStrings("", client.keyPath());

    // And the signature covered the session identifier, so it proves this
    // session and not another. RFC 4252 section 7.
    var r: wire.Reader = .init(f.fake.signedData());
    const session_id = try r.string();
    try testing.expect(session_id.len != 0);
}

test "a signer and a key the caller named are refused rather than one picked" {
    // The same rule `Authenticator.authenticate` keeps, said at the door.
    // The two can name two different keys, and picking one quietly logs in
    // as somebody the caller did not name.
    var f = try Fixture.start(.{});
    defer f.stop();

    // **`signer()` answers null until an identity is chosen**, so the
    // choice comes first or the option below is null and the refusal has
    // nothing to refuse. See `AgentClient.signer`.
    _ = try f.client.selectIdentity();

    var recorder: AcceptingVerifier = .{};
    var client: Client = undefined;
    try testing.expectError(error.TwoPublicKeySigners, client.open(
        testing.allocator,
        testing.io,
        .{
            .peer = .{ .host = "127.0.0.1", .port = 1 },
            .verifier = recorder.verifier(),
            .user = "alice",
            .signer = f.client.signer(),
            .key_location = .{ .path = "/nonexistent/id_ed25519" },
        },
    ));

    // A passphrase says the same thing: the caller meant to open a file
    // that this connection never opens.
    var second: Client = undefined;
    try testing.expectError(error.TwoPublicKeySigners, second.open(
        testing.allocator,
        testing.io,
        .{
            .peer = .{ .host = "127.0.0.1", .port = 1 },
            .verifier = recorder.verifier(),
            .user = "alice",
            .signer = f.client.signer(),
            .key_passphrase = "hunter2",
        },
    ));
}

/// A verifier that takes every key. The two tests above refuse before they
/// dial, so nothing here is ever asked.
const AcceptingVerifier = struct {
    fn verifier(a: *AcceptingVerifier) hostkey.Verifier {
        return .{ .ctx = a, .decide = decide };
    }

    fn decide(
        _: ?*anyopaque,
        _: hostkey.Peer,
        _: hostkey.PublicKey,
        _: []const u8,
    ) hostkey.TrustError!void {}
};
