//! Opens a stream to a unix domain socket, named by a path on this
//! machine.
//!
//! This file owns the connect and nothing else. It frames no protocol, it
//! sets no socket option, and it reads no environment variable. The stream
//! it hands back is the same `std.Io.net.Stream` that `tcp.dial` gives, so
//! a caller above it holds one shape for a peer on the network and a peer
//! on this machine.
//!
//! **There is no name lookup and no second address to try.** A path names
//! one socket. So this file has none of the machinery `tcp.zig` carries: no
//! resolver check, no happy eyeballs race, and no deadline around the
//! connect. `std.Io.net.UnixAddress.connect` takes no timeout, and a
//! connect to a socket file on this machine either completes or refuses at
//! once, so a bound with nothing to bound is not offered. A caller that
//! wants one puts it around this call.
//!
//! **Nagle's algorithm is not turned off here**, because it is a TCP
//! option and a unix socket has no TCP under it. See `tcp.setNoDelay` for
//! the measurement that made the option necessary on the other path.
//!
//! What dials here today: `zurl_ssh.AgentClient`, which speaks the SSH
//! agent protocol to a socket the user's agent listens on.

const std = @import("std");

/// The longest path a socket may have.
///
/// This is the bound `std.Io.net.UnixAddress.max_len` keeps, which is 108
/// on every platform but Windows. It is a kernel bound and not a taste:
/// the address a connect passes to the operating system holds the path in
/// an array of this size. **A caller must not join a long directory and a
/// file name and hope.** `dial` refuses a longer path by name.
pub const max_path_bytes = std.Io.net.UnixAddress.max_len;

/// Every fault a dial to a unix domain socket can report.
///
/// Each name says what a user must do about it, the way `tcp.DialError`
/// does. A path that is wrong is apart from a socket that is there and
/// takes no connection, because the first is the user's own spelling and
/// the second is a program that is not running.
pub const DialError = error{
    /// The path is longer than `max_path_bytes`.
    SocketPathTooLong,
    /// Nothing is at the path. An agent that is not running, and a path
    /// that names a directory that does not exist, both land here.
    SocketNotFound,
    /// A part of the path is not a directory, the path runs through a
    /// loop of symbolic links, or the file system refused the write a
    /// connect needs.
    SocketPathUnusable,
    /// The file mode of the socket, or of a directory on the way to it,
    /// keeps this process out.
    ///
    /// **This is the name a user reads when an agent belongs to another
    /// account.** An agent socket is made with mode 0600 on purpose, so
    /// this is what a wrong `SSH_AUTH_SOCK` from another login gives.
    AccessDenied,
    /// The path names a socket and no connection was made. No listener,
    /// a full backlog, and no local file descriptor left all land here,
    /// because the answer to all of them is that nothing accepted.
    CouldNotConnect,
    /// This build, or this operating system, has no unix domain socket to
    /// open.
    ///
    /// **A refusal and never a fall back.** There is no second way to
    /// reach an agent, so a caller finds out here instead of reaching a
    /// different peer.
    SocketUnsupported,
    /// Something outside the dial stopped it.
    Canceled,
    /// The operating system returned something `std.Io` does not name.
    Unexpected,
};

/// Opens a stream to the socket at `path`.
///
/// The caller owns the stream and must close it with `close`.
///
/// **An abstract socket is reached the way `std.Io.net.UnixAddress` reaches
/// one**: a path whose first byte is a NUL names the abstract namespace on
/// Linux and no file on disk. Nothing here treats that path specially, so
/// a caller that wants one passes it and a caller that does not never
/// writes a leading NUL.
pub fn dial(io: std.Io, path: []const u8) DialError!std.Io.net.Stream {
    const address = std.Io.net.UnixAddress.init(path) catch |err| switch (err) {
        error.NameTooLong => return error.SocketPathTooLong,
    };
    return address.connect(io) catch |err| switch (err) {
        error.FileNotFound => error.SocketNotFound,
        error.NotDir, error.SymLinkLoop, error.ReadOnlyFileSystem => error.SocketPathUnusable,
        error.AccessDenied, error.PermissionDenied => error.AccessDenied,
        error.SystemResources,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        error.WouldBlock,
        error.NetworkDown,
        => error.CouldNotConnect,
        error.AddressFamilyUnsupported,
        error.ProtocolUnsupportedBySystem,
        error.SocketModeUnsupported,
        => error.SocketUnsupported,
        error.Canceled => error.Canceled,
        error.Unexpected => error.Unexpected,
    };
}

const testing = std.testing;

test "a path longer than the kernel holds is refused before any syscall" {
    // **The bound is the reason this test exists.** The address a connect
    // builds copies the path into an array of `max_path_bytes`, so a
    // longer path is a write past the end of it. The refusal is named and
    // it happens before anything is opened.
    var long: [max_path_bytes + 1]u8 = undefined;
    @memset(&long, 'a');
    try testing.expectError(error.SocketPathTooLong, dial(testing.io, &long));
}

test "a path that names nothing is not found" {
    const answer = dial(testing.io, ".zig-cache/tmp/zurl-no-such-agent.sock");
    try testing.expectError(error.SocketNotFound, answer);
}

test "a stream opens to a socket that is listening, and carries bytes both ways" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_storage: [max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(
        &path_storage,
        ".zig-cache/tmp/{s}/dial.sock",
        .{&tmp.sub_path},
    );

    const address = try std.Io.net.UnixAddress.init(path);
    var server = try address.listen(testing.io, .{});
    defer server.deinit(testing.io);

    var client = try dial(testing.io, path);
    defer client.close(testing.io);

    var accepted = try server.accept(testing.io);
    defer accepted.close(testing.io);

    var write_storage: [64]u8 = undefined;
    var client_writer: std.Io.net.Stream.Writer = .init(client, testing.io, &write_storage);
    try client_writer.interface.writeAll("ping");
    try client_writer.interface.flush();

    var read_storage: [64]u8 = undefined;
    var server_reader: std.Io.net.Stream.Reader = .init(accepted, testing.io, &read_storage);
    var taken: [4]u8 = undefined;
    try server_reader.interface.readSliceAll(&taken);
    try testing.expectEqualStrings("ping", &taken);
}
