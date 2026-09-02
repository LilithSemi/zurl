//! zurl: the fixtures that every end to end test shares.
//!
//! This file owns the way a test reaches the shipped program: it spawns
//! the installed binary, it points that binary at a loopback server, and
//! it gives a test a directory the binary may write into. `src/main.zig`
//! and `src/cli/e2e_test.zig` both take their fixtures from here, so the
//! two suites run the same binary in the same environment. Two spawn
//! helpers would be two environments, and a test in the wrong one would
//! prove the wrong thing.
//!
//! It owns no assertion about zurl itself. Every `test` block that reads a
//! flag, a message, or an exit code lives beside that flag's own code.
//! The one assertion here, `afterMeter`, is about the shape of the meter
//! and not about any one transfer.
//!
//! Nothing outside a test build reaches this file. It names
//! `build_options` and `zurl-http`, and the build gives both to the test
//! module alone, so the shipped binary links neither.

const std = @import("std");
const Io = std.Io;
const testing = std.testing;

const build_options = @import("build_options");
/// The progress meter's own shape. `afterMeter` reads it.
const progress = @import("progress.zig");

/// The loopback HTTP server the library's own tests use. No test here
/// reaches the network.
pub const test_server = @import("zurl-http").test_server;

/// The loopback proxy the library's own tests use: an HTTP proxy, a
/// `CONNECT` tunnel, and a SOCKS server. Exported for the same reason
/// `test_server` is, so no second copy exists here to drift from it.
pub const proxy_test_server = @import("zurl-http").proxy_test_server;

/// The loopback TLS 1.3 server the library's own tests use. It runs a real
/// handshake and presents a certificate chain the test picks, so `-k`,
/// `--cacert`, and the chain rules have an `https` url to aim at that
/// never leaves this machine.
pub const tls_test_server = @import("zurl-tls").test_server;

/// Runs the installed `zurl` binary with `args` and returns its captured
/// output. The caller owns `stdout` and `stderr` in the result.
///
/// The child gets an empty environment, so a `.curlrc` or a
/// `CURL_CA_BUNDLE` on the machine that runs the suite cannot change what
/// a test sees. `Args` reads `CURL_HOME`, `XDG_CONFIG_HOME`, and `HOME` to
/// find a default config file, and finds none with nothing set.
pub fn runZurl(args: []const []const u8) !std.process.RunResult {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(testing.allocator);
    try argv.append(testing.allocator, build_options.exe_path);
    try argv.appendSlice(testing.allocator, args);

    var empty_env: std.process.Environ.Map = .init(testing.allocator);
    defer empty_env.deinit();

    return std.process.run(testing.allocator, testing.io, .{
        .argv = argv.items,
        .environ_map = &empty_env,
    });
}

/// One environment variable a spawned run carries.
pub const EnvPair = struct { name: []const u8, value: []const u8 };

/// The same as `runZurl`, with `env` set in the child's environment.
///
/// **Only the names a test lists are set.** The rest of the environment
/// stays empty, exactly as `runZurl` leaves it, so a `.curlrc` or an
/// `http_proxy` on the machine that runs the suite cannot change what a
/// test sees. That matters most here: a proxy test whose result depended
/// on the developer's shell would prove nothing.
pub fn runZurlWithEnv(env: []const EnvPair, args: []const []const u8) !std.process.RunResult {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(testing.allocator);
    try argv.append(testing.allocator, build_options.exe_path);
    try argv.appendSlice(testing.allocator, args);

    var map: std.process.Environ.Map = .init(testing.allocator);
    defer map.deinit();
    for (env) |pair| try map.put(pair.name, pair.value);

    return std.process.run(testing.allocator, testing.io, .{
        .argv = argv.items,
        .environ_map = &map,
    });
}

/// The same as `runZurl`, with `dir` as the child's working directory.
///
/// Every `-o` and `-O` test needs this. `-O` writes into the working
/// directory, so a test that did not set one would drop files into the
/// directory the suite runs in, which is the repository itself.
pub fn runZurlIn(dir: Io.Dir, args: []const []const u8) !std.process.RunResult {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(testing.allocator);
    try argv.append(testing.allocator, build_options.exe_path);
    try argv.appendSlice(testing.allocator, args);

    var empty_env: std.process.Environ.Map = .init(testing.allocator);
    defer empty_env.deinit();

    return std.process.run(testing.allocator, testing.io, .{
        .argv = argv.items,
        .environ_map = &empty_env,
        .cwd = .{ .dir = dir },
    });
}

/// Runs the binary with `out` as its standard output, and waits.
///
/// Every helper above pipes standard output, so none of them can say
/// where in a **file** the body lands. A shell hands its child a file
/// description whose offset it already moved, and the child must write
/// from there. This helper is the only way a test can set that up.
///
/// The caller owns `out` and reads the file back itself.
pub fn runZurlWithStdout(out: Io.File, args: []const []const u8) !std.process.Child.Term {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(testing.allocator);
    try argv.append(testing.allocator, build_options.exe_path);
    try argv.appendSlice(testing.allocator, args);

    var empty_env: std.process.Environ.Map = .init(testing.allocator);
    defer empty_env.deinit();

    var child = try std.process.spawn(testing.io, .{
        .argv = argv.items,
        .environ_map = &empty_env,
        .stdout = .{ .file = out },
    });
    return child.wait(testing.io);
}

/// One temporary directory, plus a `work` directory inside it.
///
/// A refusal test has to prove that no file appeared **anywhere**, not
/// only that the name it expected is missing. The child runs in `work`, so
/// a name that escaped one level would land in `root`, and both are
/// iterated. `root` holds nothing but `work` when the run is clean.
pub const SandboxDir = struct {
    tmp: testing.TmpDir,
    root: Io.Dir,
    work: Io.Dir,

    pub fn init() !SandboxDir {
        var tmp = testing.tmpDir(.{ .iterate = true });
        errdefer tmp.cleanup();
        const work = try tmp.dir.createDirPathOpen(testing.io, "work", .{
            .open_options = .{ .iterate = true },
        });
        return .{ .tmp = tmp, .root = tmp.dir, .work = work };
    }

    pub fn deinit(self: *SandboxDir) void {
        self.work.close(testing.io);
        self.tmp.cleanup();
    }

    /// Fails unless `work` is empty and `root` holds nothing but `work`.
    pub fn expectNothingWritten(self: *const SandboxDir) !void {
        var work_it = self.work.iterate();
        if (try work_it.next(testing.io)) |entry| {
            std.debug.print("the run wrote '{s}' into its working directory\n", .{entry.name});
            return error.TestUnexpectedResult;
        }

        var root_it = self.root.iterate();
        while (try root_it.next(testing.io)) |entry| {
            if (std.mem.eql(u8, entry.name, "work")) continue;
            std.debug.print("the run wrote '{s}' into the parent directory\n", .{entry.name});
            return error.TestUnexpectedResult;
        }
    }
};

/// The url of `server`'s root, allocated with the testing allocator.
pub fn loopbackUrl(server: *const test_server.TestServer) ![]u8 {
    return loopbackUrlAt(server, "/");
}

/// The url of `path` on `server`, allocated with the testing allocator.
pub fn loopbackUrlAt(server: *const test_server.TestServer, path: []const u8) ![]u8 {
    return std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}{s}", .{ server.port(), path });
}

/// The `https` url of `server`'s root, allocated with the testing
/// allocator.
///
/// The url names the address and not `zurl.test`, because the fixture puts
/// the loopback address in every leaf it mints as an `iPAddress` name. So
/// a run needs no name resolution and reaches nothing but this machine.
pub fn loopbackTlsUrl(server: *const tls_test_server.TlsTestServer) ![]u8 {
    return std.fmt.allocPrint(testing.allocator, "https://127.0.0.1:{d}/", .{server.port()});
}

/// Writes the certificate authority root of `server` into `dir` as
/// `root.pem` and gives its absolute path, allocated with the testing
/// allocator.
///
/// This is what a test names in `--cacert`. No real trust store holds a
/// certificate this process minted a moment ago, so it is the only way a
/// spawned run can trust the fixture.
/// The path carries the sentinel `realPathFileAlloc` allocates. A caller
/// that dropped it would free one octet less than it took.
pub fn writeRootPem(
    server: *const tls_test_server.TlsTestServer,
    dir: Io.Dir,
) ![:0]u8 {
    var pem_buf: [tls_test_server.root_pem_max]u8 = undefined;
    const pem = try server.rootPem(&pem_buf);
    try dir.writeFile(testing.io, .{ .sub_path = "root.pem", .data = pem });
    return dir.realPathFileAlloc(testing.io, "root.pem", testing.allocator);
}

/// Asserts that `stderr` opens with one whole progress meter, and returns
/// what follows it.
///
/// **Every transfer here draws a meter, because every test spawns zurl
/// with pipes.** Measured against curl 8.21.0 under a real pty: `curl URL
/// | cat` draws a meter, and so does `curl -o f URL` on a terminal. A
/// pipe on standard output keeps the body away from the meter's screen,
/// so the meter is drawn.
///
/// The one case that draws nothing is a body on a terminal, and no test
/// here can reach it: `std.process.run` gives the child pipes. The rule
/// itself lives in `progress.draws`, which is pure, and `run.meterVisibility`
/// feeds it. Both are tested with a boolean rather than a terminal.
///
/// `-s` stops the meter too, and `-S` does not bring it back.
///
/// The meter is the two header lines, then rows that a carriage return
/// separates, then one newline. This reads to that newline.
pub fn afterMeter(stderr: []const u8) ![]const u8 {
    try testing.expect(std.mem.startsWith(u8, stderr, progress.header));
    const rows = stderr[progress.header.len..];
    // The rows carry no newline of their own, so the first one ends the
    // meter. A meter with no newline never closed, and the caller's own
    // message would run onto the same line.
    const end = std.mem.indexOfScalar(u8, rows, '\n') orelse return error.MeterNeverClosed;

    // Each row is a return and `row_width` bytes, so the block divides
    // evenly. A row of another width would leave the columns crooked.
    const block = rows[0..end];
    try testing.expectEqual(@as(usize, 0), block.len % (1 + progress.row_width));
    try testing.expect(block.len > 0);

    return rows[end + 1 ..];
}

/// A port on loopback that nothing listens on.
///
/// A connect to the result is refused, which is the fault every "the
/// transfer failed" test needs. Needs no concurrency, so it works even
/// in a build that has none.
///
/// `test_server.closedPort` holds the port for the life of this process.
/// See it for why the socket is never released: a port that is read and
/// then freed can be taken by another test binary of a parallel suite,
/// and the test then reaches a stranger instead of a refusal.
pub fn closedPort() !u16 {
    return test_server.closedPort("127.0.0.1");
}
