//! zurl's `scp://` protocol: the old rcp protocol over an SSH `exec`
//! channel.
//!
//! One protocol, one module. A build that does not want SCP leaves this
//! module out and loses nothing else, and a program outside this repository
//! takes this module, `zurl-core`, `zurl-net`, and `zurl-ssh` and gets
//! `scp://` with no other part of zurl.
//!
//! **This package does not import `zurl`, and it never will**: the front
//! package imports no protocol package, and a protocol package that
//! imported it back could not be left out. `Fetcher.protocol` takes the
//! front package's namespace as a comptime parameter instead.
//!
//! A caller wires it in three lines:
//!
//!     var fetcher: zurl_scp.Fetcher = .init(gpa, io);
//!     defer fetcher.deinit();
//!     try client.registerProtocol(fetcher.protocol(zurl));
//!
//! # What `scp://` is
//!
//! **It is not a protocol the server speaks. It is a program the server
//! runs.** curl's scp, and this one, open an SSH `exec` channel and run the
//! remote `scp` binary in source mode, `scp -pf <path>`, or in sink mode,
//! `scp -t <path>`. The two then speak the rcp protocol over the channel:
//! a `C` line with a mode, a size, and a name, the bytes, one status byte,
//! and one status byte back for each control line.
//!
//! `sftp://` is the better protocol and the one to reach for. This scheme
//! is here because curl carries it and because an account whose shell will
//! not start an `sftp` subsystem may still run a command.
//!
//! # The one rule this package exists to keep
//!
//! **A path from a url is interpolated into a command that a shell on
//! somebody else's machine reads.** RFC 4254 section 6.5 says so. A path
//! holding a `;`, a backtick, or a `$(` is remote command execution and not
//! a broken file name.
//!
//! `command` is the one place in this repository that builds such a
//! command, and the rule is stated there and enforced there: **the whole
//! path in single quotes, every embedded `'` written as `'"'"'`, a NUL
//! refused, and an empty or over-long path refused.** Inside single quotes
//! a POSIX shell expands nothing, so every other metacharacter reaches the
//! remote as data.
//!
//! # What the server says, and what it may not decide
//!
//! The `C` line carries a mode, a size, and a name, and the server chose
//! all three. The size bounds a read and is checked against
//! `Fetcher.Options.max_response_bytes` first. **The name never chooses a
//! file zurl writes**: `-O` takes its name from the url, and
//! `src/cli/output.zig`'s `checkName` is the one function that judges such
//! a name. **The mode is read and never applied**, so a server cannot hand
//! anybody a setuid file.
//!
//! **The remote command's exit status is read**, RFC 4254 section 6.10. A
//! remote `scp` that failed does not look like a transfer that worked, and
//! a channel that closed with no status at all is a fault too.
//!
//! # What this does not do
//!
//! No recursion, so a `D` line is refused by name. No resume, because the
//! rcp protocol carries no offset. No directory listing, because a remote
//! `scp` lists nothing: use `sftp://` with a url that ends in a slash.

const std = @import("std");

/// Runs one `scp://` transfer, and builds the dispatch entry that
/// registers it.
pub const Fetcher = @import("zurl-scp/Fetcher.zig");

/// **The quoting rule for a path that reaches a remote shell.** The one
/// command builder in this repository.
pub const command = @import("zurl-scp/command.zig");

/// The rcp control lines. Pure bytes.
pub const protocol = @import("zurl-scp/protocol.zig");

/// The rcp dialogue over one SSH `exec` channel.
pub const Session = @import("zurl-scp/Session.zig");

/// The url scheme this package handles.
pub const scheme = Fetcher.scheme;

/// The port a url of this scheme uses when it names none.
pub const default_port = Fetcher.default_port;

test {
    _ = Fetcher;
    _ = command;
    _ = protocol;
    _ = Session;
    _ = @import("zurl-scp/session_test.zig");
}

test "the package names the scheme and the port RFC 4253 assigns" {
    try std.testing.expectEqualStrings("scp", scheme);
    try std.testing.expectEqual(@as(?u16, 22), default_port);
}

test "the package states one quoting rule and carries one builder" {
    // A second builder is how the next injection gets in, so this pins the
    // count: `command.build` is the whole public surface for a command.
    var storage: [command.max_command_bytes]u8 = undefined;
    try std.testing.expectEqualStrings(
        "scp -pf '/a;id'",
        try command.build(&storage, .download, "/a;id"),
    );
    try std.testing.expectEqualStrings(
        "scp -t '/a b'",
        try command.build(&storage, .upload, "/a b"),
    );
}
