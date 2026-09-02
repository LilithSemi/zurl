//! End to end tests of `zurl_scp.Session` and `zurl_scp.command` against
//! the loopback fixture that `zurl-ssh` carries.
//!
//! **No test in this file reaches the real network.** Every one starts a
//! `zurl_ssh.test_server` on 127.0.0.1 with a port the operating system
//! assigns, logs in, opens a channel, and sends an `exec` request.
//!
//! **The fixture writes its rcp bytes by hand.** `zurl-ssh` cannot import
//! `zurl-scp`, which imports it, and that is a gain: a fixture built out of
//! the client's own writers would agree with a client that framed the
//! dialogue the same wrong way. What no test here can prove is that this is
//! the dialogue a real `scp` speaks. Only a real OpenSSH shows that, and the
//! report records one.
//!
//! # The tests that matter most
//!
//! The ones that read `Server.execCommand`. They compare the bytes that
//! reached the far side against what a shell would take them for, so the
//! quoting rule is proved on the wire and not in the builder alone.

const std = @import("std");
const zurl_ssh = @import("zurl-ssh");

const command = @import("command.zig");
const protocol = @import("protocol.zig");
const Session = @import("Session.zig");

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
    request_storage: *[
        command.max_command_bytes +
            zurl_ssh.connection.max_control_bytes
    ]u8,

    fn start(script: test_server.ConnectionScript) !Fixture {
        var wired = script;
        wired.service = .scp;
        wired.accept_request = "exec";

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
        session.init(channel);

        const request_storage = try testing.allocator.create(
            [command.max_command_bytes + zurl_ssh.connection.max_control_bytes]u8,
        );

        return .{
            .server = server,
            .endpoint = endpoint,
            .transport = transport,
            .authenticator = authenticator,
            .channel = channel,
            .session = session,
            .request_storage = request_storage,
        };
    }

    fn stop(f: Fixture) void {
        testing.allocator.destroy(f.request_storage);
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

    /// Runs the handshake, the login, the channel, and the `exec` request
    /// for `path`.
    fn run(f: Fixture, mode: command.Mode, path: []const u8) !void {
        try f.transport.handshake();
        try f.authenticator.authenticate();
        try f.channel.open();
        var storage: [command.max_command_bytes]u8 = undefined;
        const line = try command.build(&storage, mode, path);
        return f.channel.requestExec(f.request_storage, line);
    }

    /// Downloads the one file the fixture holds.
    fn download(f: Fixture) ![]u8 {
        try f.session.beginDownload();
        const file = (try f.session.nextFile()) orelse
            return error.TestUnexpectedResult;

        var collected: std.ArrayList(u8) = .empty;
        errdefer collected.deinit(testing.allocator);
        var chunk: [8192]u8 = undefined;
        while (true) {
            const taken = try f.session.readBody(&chunk);
            if (taken == 0) break;
            try collected.appendSlice(testing.allocator, chunk[0..taken]);
        }
        try f.session.endFile();
        try testing.expectEqual(file.size, collected.items.len);
        return collected.toOwnedSlice(testing.allocator);
    }
};

test "a file is read whole over the rcp dialogue" {
    const contents = "hello from scp\n";
    var f = try Fixture.start(.{ .scp = .{ .contents = contents } });
    defer f.stop();

    try f.run(.download, "/srv/hello.txt");
    const got = try f.download();
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(contents, got);
}

test "the command that reached the far side is the one curl sends" {
    var f = try Fixture.start(.{ .scp = .{ .contents = "x" } });
    defer f.stop();

    try f.run(.download, "/srv/hello.txt");
    const got = try f.download();
    defer testing.allocator.free(got);

    try testing.expectEqualStrings(
        "scp -pf '/srv/hello.txt'",
        f.server.execCommand(),
    );
}

test "a path holding a shell metacharacter reaches the far side as data" {
    // **This is the test the whole package exists for.** Each of these
    // paths is a command on somebody else's machine if the quoting is
    // wrong, and each one must arrive as one shell word holding those exact
    // bytes.
    const hostile = [_][]const u8{
        "/srv/a;id",
        "/srv/a`id`",
        "/srv/a$(id)",
        "/srv/a|id",
        "/srv/a&&id",
        "/srv/a\nid",
        "/srv/a b",
        "/srv/it's.txt",
        "/srv/$HOME",
        "/srv/*",
        "/srv/a>b",
        "/srv/a<b",
        "/srv/a\\b",
        "/srv/a\"b",
        "/srv/--; rm -rf /",
    };

    for (hostile) |path| {
        var f = try Fixture.start(.{ .scp = .{ .contents = "ok" } });
        defer f.stop();

        try f.run(.download, path);
        const got = try f.download();
        defer testing.allocator.free(got);
        try testing.expectEqualStrings("ok", got);

        // The fixture kept the bytes of the request. Walk them the way a
        // POSIX shell would and check that what the shell would run is
        // `scp` with `-pf` and this exact path, and nothing else.
        const line = f.server.execCommand();
        var word_storage: [512]u8 = undefined;
        var words: usize = 0;
        var last: []const u8 = "";
        var walker: ShellWalk = .init(line);
        while (try walker.next(&word_storage)) |word| {
            words += 1;
            last = word;
        }
        try testing.expectEqual(@as(usize, 3), words);
        try testing.expectEqualStrings(path, last);
        // No unquoted metacharacter survived anywhere in the command.
        try testing.expect(!walker.saw_bare_metacharacter);
    }
}

/// Walks a command the way a POSIX shell splits it into words.
///
/// **It is a test's own reader and not a shell.** It knows single quotes,
/// double quotes, and the space, which is every construct the quoting rule
/// uses. Anything else outside a quoted string is a metacharacter that
/// escaped, and `saw_bare_metacharacter` says so.
const ShellWalk = struct {
    line: []const u8,
    at: usize,
    saw_bare_metacharacter: bool,

    fn init(line: []const u8) ShellWalk {
        return .{ .line = line, .at = 0, .saw_bare_metacharacter = false };
    }

    fn next(w: *ShellWalk, out: []u8) !?[]const u8 {
        while (w.at < w.line.len and w.line[w.at] == ' ') w.at += 1;
        if (w.at == w.line.len) return null;

        var written: usize = 0;
        var single = false;
        var double = false;
        while (w.at < w.line.len) : (w.at += 1) {
            const byte = w.line[w.at];
            if (byte == '\'' and !double) {
                single = !single;
                continue;
            }
            if (byte == '"' and !single) {
                double = !double;
                continue;
            }
            if (!single and !double) {
                if (byte == ' ') break;
                // A byte a shell reads as syntax, outside every quote.
                for (";|&$`()<>*?[]{}#~!\n\r\\\"") |bad| {
                    if (byte == bad) w.saw_bare_metacharacter = true;
                }
            }
            if (written == out.len) return error.TestUnexpectedResult;
            out[written] = byte;
            written += 1;
        }
        if (single or double) return error.TestUnexpectedResult;
        return out[0..written];
    }
};

test "a path with a NUL never reaches the far side at all" {
    var storage: [command.max_command_bytes]u8 = undefined;
    // The refusal is in the builder, so the socket never opens. A test that
    // needed a server for this would be testing the wrong layer.
    try testing.expectError(
        error.PathHasNul,
        command.build(&storage, .download, "/srv/a\x00b"),
    );
}

test "a T line is read and answered before the C line" {
    var f = try Fixture.start(.{ .scp = .{ .contents = "x", .send_times = true } });
    defer f.stop();

    try f.run(.download, "/srv/f");
    const got = try f.download();
    defer testing.allocator.free(got);
    try testing.expectEqual(@as(u64, 1), f.session.counters.time_lines);
}

test "a server that sends no T line still transfers" {
    // `-p` asks for the times and a server may still send none.
    var f = try Fixture.start(.{ .scp = .{ .contents = "y", .send_times = false } });
    defer f.stop();

    try f.run(.download, "/srv/f");
    const got = try f.download();
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("y", got);
    try testing.expectEqual(@as(u64, 0), f.session.counters.time_lines);
}

test "the mode and the name on the C line are read and neither picks a file" {
    var f = try Fixture.start(.{ .scp = .{
        .mode = "0755",
        .name = "other.txt",
        .contents = "z",
    } });
    defer f.stop();

    try f.run(.download, "/srv/f");
    try f.session.beginDownload();
    const file = (try f.session.nextFile()) orelse return error.TestUnexpectedResult;
    // The mode is read and it is never applied. The name is read and it
    // never names a file zurl writes: it is the server's word about the
    // file it sent, and the url is what `-O` reads.
    try testing.expectEqual(@as(u16, 0o755), file.mode);
    try testing.expectEqualStrings("other.txt", file.name);
    try testing.expectEqual(@as(u64, 1), file.size);
}

test "a C line whose name is a path stops the transfer" {
    // A server that answered `C0644 1 ../../etc/passwd` would be trying to
    // choose a file on this side. Nothing here writes such a name, and the
    // line is still refused so the attempt is a fault and not a value that
    // travels on.
    var f = try Fixture.start(.{ .scp = .{
        .control_line = "C0644 1 ../../../etc/passwd",
        .contents = "x",
    } });
    defer f.stop();

    try f.run(.download, "/srv/f");
    try f.session.beginDownload();
    try testing.expectError(error.NameInvalid, f.session.nextFile());
}

test "a C line with a size that will not parse stops the transfer" {
    var f = try Fixture.start(.{ .scp = .{
        .size_override = "99999999999999999999999",
        .contents = "x",
    } });
    defer f.stop();

    try f.run(.download, "/srv/f");
    try f.session.beginDownload();
    try testing.expectError(error.SizeInvalid, f.session.nextFile());
}

test "a body never runs past the size the C line named" {
    // The fixture says 2 bytes and writes 8. A client that read until the
    // channel ended would take the status byte and the rest as file
    // content.
    var f = try Fixture.start(.{ .scp = .{
        .size_override = "2",
        .contents = "12345678",
    } });
    defer f.stop();

    try f.run(.download, "/srv/f");
    try f.session.beginDownload();
    const file = (try f.session.nextFile()) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u64, 2), file.size);

    var chunk: [64]u8 = undefined;
    const taken = try f.session.readBody(&chunk);
    try testing.expectEqual(@as(usize, 2), taken);
    try testing.expectEqualStrings("12", chunk[0..2]);
    try testing.expectEqual(@as(usize, 0), try f.session.readBody(&chunk));
}

test "a fatal message from the remote is a fault and never an empty file" {
    var f = try Fixture.start(.{ .scp = .{
        .fatal = "scp: /nope: No such file or directory",
    } });
    defer f.stop();

    try f.run(.download, "/nope");
    try f.session.beginDownload();
    try testing.expectError(error.RemoteFault, f.session.nextFile());
    try testing.expectEqualStrings(
        "scp: /nope: No such file or directory",
        f.session.lastMessage(),
    );
}

test "a warning from the remote is a fault too" {
    var f = try Fixture.start(.{ .scp = .{
        .warning = "scp: /x: Permission denied",
    } });
    defer f.stop();

    try f.run(.download, "/x");
    try f.session.beginDownload();
    try testing.expectError(error.RemoteFault, f.session.nextFile());
    try testing.expectEqual(@as(u64, 1), f.session.counters.warnings);
    try testing.expectEqualStrings(
        "scp: /x: Permission denied",
        f.session.lastMessage(),
    );
}

test "a D line is refused, because this build transfers one file" {
    var f = try Fixture.start(.{ .scp = .{ .control_line = "D0755 0 sub" } });
    defer f.stop();

    try f.run(.download, "/srv/sub");
    try f.session.beginDownload();
    try testing.expectError(error.DirectoryUnsupported, f.session.nextFile());
}

test "a control line this build does not name is refused" {
    var f = try Fixture.start(.{ .scp = .{ .control_line = "Z0644 1 f" } });
    defer f.stop();

    try f.run(.download, "/srv/f");
    try f.session.beginDownload();
    try testing.expectError(error.LineTypeUnknown, f.session.nextFile());
}

test "a channel that ends before the status byte is a partial file" {
    var f = try Fixture.start(.{ .scp = .{
        .contents = "abcd",
        .omit_end_status = true,
    } });
    defer f.stop();

    try f.run(.download, "/srv/f");
    try f.session.beginDownload();
    _ = (try f.session.nextFile()) orelse return error.TestUnexpectedResult;
    var chunk: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, 4), try f.session.readBody(&chunk));
    try testing.expectEqual(@as(usize, 0), try f.session.readBody(&chunk));
    // The file bytes all arrived and the status byte behind them did not, so
    // the remote did not finish. A build that stopped at the last body byte
    // would call this whole.
    try testing.expectError(error.PartialFile, f.session.endFile());
}

test "a file larger than the channel window goes through whole" {
    var contents: [200 * 1024]u8 = undefined;
    for (&contents, 0..) |*byte, i| byte.* = @truncate(i *% 11);

    var f = try Fixture.start(.{
        .window_bytes = 16 * 1024,
        .max_packet_bytes = 4096,
        .scp = .{ .contents = &contents },
    });
    defer f.stop();

    try f.run(.download, "/srv/big.bin");
    const got = try f.download();
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, &contents, got);
    try testing.expect(f.channel.counters.window_credits > 0);
}

test "a control line split across channel messages is put back together" {
    // With a 64 byte channel message, the `T` line, the `C` line, and the
    // body all cross a boundary, so a client that framed on the channel
    // message would fail on the first line.
    const contents = "a body that crosses several channel messages on its way\n";
    var f = try Fixture.start(.{
        .window_bytes = 4096,
        .max_packet_bytes = 64,
        .scp = .{ .contents = contents },
    });
    defer f.stop();

    try f.run(.download, "/srv/f");
    const got = try f.download();
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(contents, got);
}

test "the exit status of the remote command is collected" {
    var f = try Fixture.start(.{
        .exit_status = 0,
        .scp = .{ .contents = "ok" },
    });
    defer f.stop();

    try f.run(.download, "/srv/f");
    const got = try f.download();
    defer testing.allocator.free(got);

    try f.channel.sendEof();
    try f.channel.close();
    try testing.expectEqual(@as(?u32, 0), f.channel.exitStatus());
}

test "a remote command that failed does not look like a good transfer" {
    var f = try Fixture.start(.{
        .exit_status = 1,
        .scp = .{ .fatal = "scp: /nope: No such file or directory" },
    });
    defer f.stop();

    try f.run(.download, "/nope");
    try f.session.beginDownload();
    try testing.expectError(error.RemoteFault, f.session.nextFile());

    try f.channel.close();
    // **A body that arrived is not the whole answer.** The status says the
    // remote command failed, and a build that read only the body would
    // report a transfer that did not happen.
    try testing.expectEqual(@as(?u32, 1), f.channel.exitStatus());
}

test "an upload writes the C line and the bytes the caller gave" {
    const payload = "uploaded over the exec channel\n";
    var f = try Fixture.start(.{ .scp = .{ .receive = true } });
    defer f.stop();

    try f.run(.upload, "/srv/up.txt");
    try f.session.beginUpload();
    try f.session.sendFileLine(0o644, payload.len, "up.txt");
    try f.session.writeBody(payload);
    try f.session.finishFile();

    try testing.expectEqualStrings("scp -t '/srv/up.txt'", f.server.execCommand());
    try testing.expectEqualStrings(payload, f.server.uploaded());
}

test "an upload will not write one byte past the length it named" {
    var f = try Fixture.start(.{ .scp = .{ .receive = true } });
    defer f.stop();

    try f.run(.upload, "/srv/up.txt");
    try f.session.beginUpload();
    try f.session.sendFileLine(0o644, 4, "up.txt");
    // The remote reads exactly four bytes, so a fifth would be read as the
    // status byte and then as the next control line.
    try testing.expectError(
        error.SessionStateInvalid,
        f.session.writeBody("12345"),
    );
}

test "an upload the remote refuses is a fault and never a quiet success" {
    var f = try Fixture.start(.{ .scp = .{
        .receive = true,
        .fatal = "scp: /srv/up.txt: Permission denied",
    } });
    defer f.stop();

    try f.run(.upload, "/srv/up.txt");
    try f.session.beginUpload();
    try testing.expectError(
        error.RemoteFault,
        f.session.sendFileLine(0o644, 4, "up.txt"),
    );
    try testing.expectEqualStrings(
        "scp: /srv/up.txt: Permission denied",
        f.session.lastMessage(),
    );
}

test "an upload command carries the quoted path and the C line the basename" {
    var f = try Fixture.start(.{ .scp = .{ .receive = true } });
    defer f.stop();

    // A path with a quote in it, so both halves of the rule run at once.
    try f.run(.upload, "/srv/it's up.txt");
    try f.session.beginUpload();
    const name = protocol.baseName("/srv/it's up.txt");
    try f.session.sendFileLine(0o644, 2, name);
    try f.session.writeBody("hi");
    try f.session.finishFile();

    try testing.expectEqualStrings(
        "scp -t '/srv/it'\"'\"'s up.txt'",
        f.server.execCommand(),
    );
    try testing.expectEqualStrings("hi", f.server.uploaded());
}

test "control lines that name no file are bounded, not read forever" {
    // **A `T` line moves nothing.** A client that bounded only the file
    // would read these for as long as a server wrote them, and each one
    // costs a round trip. The bound is `Session.max_control_lines`.
    var f = try Fixture.start(.{ .scp = .{
        .contents = "x",
        .extra_time_lines = Session.max_control_lines + 4,
    } });
    defer f.stop();

    try f.run(.download, "/srv/f");
    try f.session.beginDownload();
    try testing.expectError(error.ControlLineFlood, f.session.nextFile());
    try testing.expectEqual(
        @as(u64, Session.max_control_lines),
        f.session.counters.control_lines,
    );
}

test "the staging buffer is wiped when the transfer is over" {
    // **The buffer holds the file in the clear.** A private file that a
    // transfer read stays in that memory until something writes over it,
    // and this value outlives the transfer on a caller's stack.
    const secret = "a password in a file, which is what people put in one\n";
    var f = try Fixture.start(.{ .scp = .{ .contents = secret } });
    defer f.stop();

    try f.run(.download, "/srv/secret.txt");
    try f.session.beginDownload();
    _ = (try f.session.nextFile()) orelse return error.TestUnexpectedResult;
    var chunk: [8192]u8 = undefined;
    try testing.expectEqual(secret.len, try f.session.readBody(&chunk));
    try testing.expectEqualStrings(secret, chunk[0..secret.len]);
    // The bytes stay in the staging buffer after a caller has taken them:
    // `readBody` copies out and writes nothing back.
    try testing.expect(std.mem.indexOf(u8, &f.session.buffer, secret) != null);

    f.session.wipe();
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, &f.session.buffer, secret),
    );
    for (f.session.buffer) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "a request the server refuses is named and never read as a transfer" {
    var f = try Fixture.start(.{ .refuse_request = true, .scp = .{ .contents = "x" } });
    defer f.stop();

    try f.transport.handshake();
    try f.authenticator.authenticate();
    try f.channel.open();
    var storage: [command.max_command_bytes]u8 = undefined;
    const line = try command.build(&storage, .download, "/srv/f");
    try testing.expectError(
        error.ChannelRequestRefused,
        f.channel.requestExec(f.request_storage, line),
    );
}
