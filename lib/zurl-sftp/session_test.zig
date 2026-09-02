//! End to end tests of `zurl_sftp.Session` against the loopback fixture
//! that `zurl-ssh` carries.
//!
//! **No test in this file reaches the real network.** Every one starts a
//! `zurl_ssh.test_server` on 127.0.0.1 with a port the operating system
//! assigns, logs in, opens a channel, and asks for the `sftp` subsystem.
//!
//! **The fixture builds its packets with `zurl_ssh.wire` and not with
//! `protocol.zig`.** `zurl-ssh` cannot import `zurl-sftp`, which imports
//! it, and that is a gain: a fixture built out of the client's own writers
//! would agree with a client that framed every packet the same wrong way.
//! What no test here can prove is that version 3 is the version the rest
//! of the world speaks. Only a real `sftp-server` shows that, and the
//! report records one.

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_ssh = @import("zurl-ssh");

const Fetcher = @import("Fetcher.zig");
const Session = @import("Session.zig");
const protocol = @import("protocol.zig");

const testing = std.testing;
const test_server = zurl_ssh.test_server;

/// One fixture, one transport, one login, one channel, and one session.
///
/// Every one is on the heap, because each holds pointers into the last and
/// none of them may move.
const Fixture = struct {
    server: *test_server,
    endpoint: *test_server.Endpoint,
    transport: *zurl_ssh.Transport,
    authenticator: *zurl_ssh.Authenticator,
    channel: *zurl_ssh.Channel,
    session: *Session,

    fn start(script: test_server.ConnectionScript) !Fixture {
        var wired = script;
        wired.service = .sftp;
        wired.accept_request = "subsystem";

        const server = try testing.allocator.create(test_server);
        errdefer testing.allocator.destroy(server);
        try server.start(.{
            .auth = .{ .accept_none = true, .methods = "none" },
            .connection = wired,
        });
        errdefer server.stop();

        const endpoint = try testing.allocator.create(test_server.Endpoint);
        errdefer testing.allocator.destroy(endpoint);
        try endpoint.connect(server.port());
        errdefer endpoint.close();

        const transport = try testing.allocator.create(zurl_ssh.Transport);
        errdefer testing.allocator.destroy(transport);
        try transport.init(testing.allocator, testing.io, endpoint.channel(), .{
            .peer = .{ .host = "fixture.test", .port = 22 },
            .verifier = server.verifier(),
        });
        errdefer transport.deinit();

        const authenticator = try testing.allocator.create(zurl_ssh.Authenticator);
        errdefer testing.allocator.destroy(authenticator);
        authenticator.init(transport, .{ .user = "alice" });
        errdefer authenticator.deinit();

        const channel = try testing.allocator.create(zurl_ssh.Channel);
        errdefer testing.allocator.destroy(channel);
        try channel.init(testing.allocator, transport, .{
            .window_bytes = script.window_bytes,
            .max_packet_bytes = script.max_packet_bytes,
        });
        errdefer channel.deinit(testing.allocator);

        const session = try testing.allocator.create(Session);
        errdefer testing.allocator.destroy(session);
        try session.init(testing.allocator, channel, .{});

        return .{
            .server = server,
            .endpoint = endpoint,
            .transport = transport,
            .authenticator = authenticator,
            .channel = channel,
            .session = session,
        };
    }

    fn stop(f: Fixture) void {
        f.session.deinit();
        testing.allocator.destroy(f.session);
        f.channel.deinit(testing.allocator);
        testing.allocator.destroy(f.channel);
        f.authenticator.deinit();
        testing.allocator.destroy(f.authenticator);
        f.transport.deinit();
        testing.allocator.destroy(f.transport);
        f.endpoint.close();
        testing.allocator.destroy(f.endpoint);
        f.server.stop();
        testing.allocator.destroy(f.server);
    }

    /// Runs the handshake, the login, the channel, the subsystem request,
    /// and `SSH_FXP_INIT`.
    fn run(f: Fixture) !void {
        try f.transport.handshake();
        try f.authenticator.authenticate();
        try f.channel.open();
        try f.channel.requestSubsystem(protocol.subsystem_name);
        return f.session.start();
    }

    /// Downloads `path` whole.
    fn download(f: Fixture, path: []const u8) ![]u8 {
        const handle = try f.session.open(path, protocol.open_read);
        defer f.session.close(handle) catch {};

        var collected: std.ArrayList(u8) = .empty;
        errdefer collected.deinit(testing.allocator);
        var chunk: [8192]u8 = undefined;
        var offset: u64 = 0;
        while (true) {
            const taken = try f.session.read(handle, offset, &chunk);
            if (taken == 0) break;
            try collected.appendSlice(testing.allocator, chunk[0..taken]);
            offset += taken;
        }
        return collected.toOwnedSlice(testing.allocator);
    }
};

test "an init is answered with a version, and version 3 is what this build takes" {
    var f = try Fixture.start(.{ .sftp = .{ .contents = "x" } });
    defer f.stop();

    try f.run();
    try testing.expectEqual(@as(u32, 3), f.session.version());
}

test "a server that answers with another version stops the session" {
    // A server that answers 2 speaks a protocol this build does not, and
    // one that answers 4 answered something it was never offered.
    var f = try Fixture.start(.{ .sftp = .{ .version = 4 } });
    defer f.stop();

    try f.transport.handshake();
    try f.authenticator.authenticate();
    try f.channel.open();
    try f.channel.requestSubsystem(protocol.subsystem_name);
    try testing.expectError(error.VersionUnsupported, f.session.start());
}

test "a file is opened, read whole, and closed" {
    const contents = "the whole file, byte for byte\n";
    var f = try Fixture.start(.{ .sftp = .{ .contents = contents } });
    defer f.stop();

    try f.run();
    const got = try f.download("/f.txt");
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(contents, got);
}

test "a short read is not the end of the file" {
    // **Section 6.4 of the draft lets a server answer with fewer bytes
    // than were asked for.** A client that took one for the end would
    // truncate every download from such a server and report success.
    var contents: [40 * 1024]u8 = undefined;
    for (&contents, 0..) |*byte, i| byte.* = @truncate(i *% 13);

    var f = try Fixture.start(.{
        .sftp = .{ .contents = &contents, .read_chunk_bytes = 91 },
    });
    defer f.stop();

    try f.run();
    const got = try f.download("/f.txt");
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, &contents, got);
    try testing.expect(f.session.counters.short_reads > 0);
}

test "a data reply of no bytes is a fault and never the end of the file" {
    // **The server decides the length of every read, and zero is not an
    // end.** Only `SSH_FX_EOF` ends a file. A build that stopped on an
    // empty data reply would write the bytes it had, print an ordinary
    // transfer summary, and exit 0, so any download could be cut to any
    // prefix the server chose with no error and no diagnostic. For a tool
    // that fetches scripts and archives, a prefix returned as a whole file
    // is worse than a failure.
    var contents: [4096]u8 = undefined;
    for (&contents, 0..) |*byte, i| byte.* = @truncate(i *% 11);

    var f = try Fixture.start(.{
        .sftp = .{ .contents = &contents, .read_chunk_bytes = 0 },
    });
    defer f.stop();

    try f.run();
    const handle = try f.session.open("/f.txt", protocol.open_read);
    defer f.session.close(handle) catch {};

    var chunk: [1024]u8 = undefined;
    try testing.expectError(error.ReadEmpty, f.session.read(handle, 0, &chunk));

    // And the whole download stops rather than handing back what arrived.
    try testing.expectError(error.ReadEmpty, f.download("/f.txt"));
}

test "a download larger than the channel window goes through whole" {
    // The SFTP layer is above the flow control, so this proves the two
    // together: the packets are reassembled across channel messages and
    // the window is credited while the reads run.
    var contents: [200 * 1024]u8 = undefined;
    for (&contents, 0..) |*byte, i| byte.* = @truncate(i *% 7);

    var f = try Fixture.start(.{
        .window_bytes = 16 * 1024,
        .max_packet_bytes = 4096,
        .sftp = .{ .contents = &contents },
    });
    defer f.stop();

    try f.run();
    const got = try f.download("/f.txt");
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, &contents, got);
    try testing.expect(f.channel.counters.window_credits > 0);
}

test "an sftp packet split across channel messages is put back together" {
    // One `SSH_MSG_CHANNEL_DATA` is not one SFTP packet. With a 300 byte
    // channel message and a longer file, every reply crosses at least one
    // boundary, so a client that framed on the channel message would fail
    // on the first read.
    var contents: [8 * 1024]u8 = undefined;
    for (&contents, 0..) |*byte, i| byte.* = @truncate(i *% 3);

    var f = try Fixture.start(.{
        .window_bytes = 4096,
        .max_packet_bytes = 300,
        .sftp = .{ .contents = &contents },
    });
    defer f.stop();

    try f.run();
    const got = try f.download("/f.txt");
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, &contents, got);
}

test "a file the server has not got is its own status and not an empty file" {
    var f = try Fixture.start(.{ .sftp = .{ .contents = "x" } });
    defer f.stop();

    try f.run();
    try testing.expectError(
        error.ServerFault,
        f.session.open("/not-here.txt", protocol.open_read),
    );
    const held = f.session.lastStatus() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(protocol.Status.no_such_file, held.status);
    try testing.expectEqualStrings("no such file", held.message);
}

test "a stat reads the size and the mode the server sent" {
    var f = try Fixture.start(.{ .sftp = .{ .contents = "12345" } });
    defer f.stop();

    try f.run();
    const attributes = try f.session.stat("/f.txt");
    try testing.expectEqual(@as(?u64, 5), attributes.size);
    try testing.expect(attributes.isRegular());
    try testing.expect(!attributes.isDirectory());
}

test "a directory listing walks the names the server sent" {
    var f = try Fixture.start(.{ .sftp = .{
        .path = "/dir/",
        .entries = &.{
            .{ "a.txt", "-rw-r--r-- 1 u g 3 Jan 1 00:00 a.txt" },
            .{ "b.txt", "-rw-r--r-- 1 u g 4 Jan 1 00:00 b.txt" },
        },
    } });
    defer f.stop();

    try f.run();
    const handle = try f.session.openDirectory("/dir/");
    defer f.session.close(handle) catch {};

    var batch = (try f.session.readDirectory(handle)) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u32, 2), batch.count);
    const first = (try batch.iterator.next()).?;
    try testing.expectEqualStrings("a.txt", first.filename);
    try testing.expectEqualStrings("-rw-r--r-- 1 u g 3 Jan 1 00:00 a.txt", first.longname);
    const second = (try batch.iterator.next()).?;
    try testing.expectEqualStrings("b.txt", second.filename);

    // The end of a listing is a status and not an empty name reply.
    try testing.expectEqual(@as(?protocol.NameReply, null), try f.session.readDirectory(handle));
}

test "an upload writes the bytes the caller gave and the close is answered" {
    const payload = "uploaded through the subsystem\n";
    var f = try Fixture.start(.{
        .sftp = .{ .path = "/up.txt", .accept_write = true },
    });
    defer f.stop();

    try f.run();
    const handle = try f.session.open(
        "/up.txt",
        protocol.open_write | protocol.open_create | protocol.open_truncate,
    );
    try f.session.write(handle, 0, payload);
    // **The close is not a formality.** The draft lets a server report a
    // write it deferred here.
    try f.session.close(handle);

    try testing.expectEqualStrings(payload, f.server.uploaded());
}

test "an upload the server will not take is a fault and never a quiet success" {
    var f = try Fixture.start(.{ .sftp = .{ .path = "/up.txt" } });
    defer f.stop();

    try f.run();
    const handle = try f.session.open(
        "/up.txt",
        protocol.open_write | protocol.open_create | protocol.open_truncate,
    );
    try testing.expectError(error.ServerFault, f.session.write(handle, 0, "no"));
}

test "an open the server refuses carries the server's own status" {
    var f = try Fixture.start(.{
        .sftp = .{ .open_status = 3, .contents = "x" },
    });
    defer f.stop();

    try f.run();
    try testing.expectError(error.ServerFault, f.session.open("/f.txt", protocol.open_read));
    const held = f.session.lastStatus() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(protocol.Status.permission_denied, held.status);
}

test "a realpath answers with one name" {
    var f = try Fixture.start(.{ .sftp = .{ .contents = "x" } });
    defer f.stop();

    try f.run();
    try testing.expectEqualStrings(".", try f.session.realPath("."));
}

/// One fixture and one `Fetcher`, dialled over the loopback.
///
/// **This one drives the whole package**, from the url to the answer,
/// where the `Fixture` above drives the session alone. It reaches no
/// further than 127.0.0.1 with a port the operating system assigned.
const TransferFixture = struct {
    server: *test_server,
    fetcher: *Fetcher,

    fn start(script: test_server.ConnectionScript) !TransferFixture {
        var wired = script;
        wired.service = .sftp;
        wired.accept_request = "subsystem";

        const server = try testing.allocator.create(test_server);
        errdefer testing.allocator.destroy(server);
        try server.start(.{
            .auth = .{ .accept_none = true, .methods = "none" },
            .connection = wired,
        });
        errdefer server.stop();

        const fetcher = try testing.allocator.create(Fetcher);
        fetcher.* = .init(testing.allocator, testing.io);
        return .{ .server = server, .fetcher = fetcher };
    }

    fn stop(f: TransferFixture) void {
        f.fetcher.deinit();
        testing.allocator.destroy(f.fetcher);
        f.server.stop();
        testing.allocator.destroy(f.server);
    }

    fn url(f: TransferFixture, path: []const u8) zurl_core.Url {
        return .{
            .scheme = "sftp",
            .user = "alice",
            .password = null,
            .host = "127.0.0.1",
            .port = f.server.port(),
            .path = path,
            .query = null,
            .fragment = null,
        };
    }

    /// The options every test here uses.
    ///
    /// **`insecure` is set on purpose.** The fixture's host key is in no
    /// `known_hosts` file, and this file tests the transfer and not the
    /// trust decision, which `zurl_ssh.knownhosts` tests on its own.
    fn options(f: TransferFixture) Fetcher.Options {
        _ = f;
        return .{ .insecure = true };
    }
};

test "a transfer whose file arrives whole reports the bytes the server stated" {
    const contents = "the whole file, over the whole stack\n";
    var f = try TransferFixture.start(.{ .sftp = .{ .contents = contents } });
    defer f.stop();

    const body = try f.fetcher.open(f.url("/f.txt"), f.options(), null);
    try testing.expectEqual(@as(u64, contents.len), body.length);
    var seen: [64]u8 = undefined;
    try testing.expectEqualStrings(contents, seen[0..try body.reader.readSliceShort(&seen)]);
}

test "a transfer the server cut short is a fault and never a short file" {
    // **The whole of finding C1, from the url down.** The fixture answers
    // the read with a `SSH_FXP_DATA` of no bytes, which is what a hostile
    // or broken server sends to cut a download at a length it chooses. A
    // build that read that as the end wrote the bytes it had, printed an
    // ordinary summary, and exited 0.
    var contents: [2048]u8 = undefined;
    for (&contents, 0..) |*byte, i| byte.* = @truncate(i *% 5);

    var f = try TransferFixture.start(.{
        .sftp = .{ .contents = &contents, .read_chunk_bytes = 0 },
    });
    defer f.stop();

    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(
        error.WeirdServerReply,
        f.fetcher.open(f.url("/f.txt"), f.options(), &d),
    );
    // Nothing was handed back, so nothing could be written as the file.
    try testing.expectEqual(@as(?[]u8, null), f.fetcher.answer);
}

test "--connect-to moves an sftp dial and the host key check keeps the url's name" {
    // The defect this closes: this package read no `connect_to`, so a
    // user who named either flag got a dial to the url's own host and no
    // diagnostic. curl 8.21.0 applies both to `sftp`, measured.
    //
    // **The dial moves and the host key check does not.**
    // `zurl_ssh.Client.Options.dial` takes the moved address and
    // `Options.peer` keeps the url's name, which is the name a
    // `known_hosts` record is looked up under.
    // `zurl_ssh.Client` tests that split against a recording verifier.
    //
    // **No test here touches a resolver.** The url names `127.0.0.2:1`,
    // which refuses at once, so the flag is the only thing that can reach
    // the fixture.
    const contents = "moved by --connect-to\n";
    var f = try TransferFixture.start(.{ .sftp = .{ .contents = contents } });
    defer f.stop();

    var away = f.url("/f.txt");
    away.host = "127.0.0.2";
    away.port = 1;

    var bare: zurl_core.Diagnostics = .{};
    try testing.expectError(
        error.CouldNotConnect,
        f.fetcher.open(away, f.options(), &bare),
    );

    var moved = f.options();
    moved.connect_to = &.{.{
        .from_host = "127.0.0.2",
        .from_port = 1,
        .to_host = "127.0.0.1",
        .to_port = f.server.port(),
    }};
    const body = try f.fetcher.open(away, moved, null);
    try testing.expectEqual(@as(u64, contents.len), body.length);
    var seen: [64]u8 = undefined;
    try testing.expectEqualStrings(contents, seen[0..try body.reader.readSliceShort(&seen)]);
}
