//! zurl's `pop3://` and `pop3s://` protocols, RFC 1939 and RFC 2595.
//!
//! One protocol, one module. A build that does not want POP3 leaves this
//! module out and loses nothing else, and a program outside this
//! repository takes this module, `zurl-core`, and `zurl-net` and gets both
//! schemes with no other part of zurl.
//!
//! **One package owns both schemes**, the way `zurl-ftp` owns `ftp` and
//! `ftps`. RFC 1939 names the commands and the answers, and `pop3s`
//! changes neither: it puts the same dialogue inside TLS. The two carry
//! different default ports, 110 and 995, because implicit TLS has a port
//! of its own.
//!
//! **This package does not import `zurl`, and it never will**: the front
//! package imports no protocol package, and a protocol package that
//! imported it back could not be left out. `Fetcher.protocol` takes the
//! front package's namespace as a comptime parameter instead.
//!
//! A caller wires it in four lines:
//!
//!     var fetcher: zurl_pop3.Fetcher = .init(gpa, io);
//!     defer fetcher.deinit();
//!     try client.registerProtocol(fetcher.protocol(zurl));
//!     try client.registerProtocol(fetcher.secureProtocol(zurl));
//!
//! **What a transfer sends.** The command order is curl's own, measured
//! against curl 8.21.0 on a loopback RFC 1939 fixture:
//!
//!     [STLS], then USER and PASS or APOP, then LIST or RETR or the
//!     --request command, then QUIT
//!
//! **The three rules that keep this safe**, each with its own section in
//! the file that holds it:
//!
//! - **No command can carry a forged line ending.** Every command goes out
//!   through `Control.send`, which calls the one gate every line-oriented
//!   package in this repository shares. The url path and the credential
//!   are each refused a second time, earlier, so the message names the url
//!   and not the command. A forged line here would write a `DELE`, and the
//!   `QUIT` at the end of the session makes a `DELE` permanent.
//! - **A multi-line body ends at one period on a line of its own.** A body
//!   line that starts with a period arrives with two, and the receiver
//!   takes one off. A reader that stopped at the first period would cut a
//!   message and read the rest as answers to later commands. See
//!   `response.terminates` and `response.unstuff`.
//! - **An `STLS` session never logs in with `APOP`.** The APOP timestamp
//!   of an explicit session arrives before the handshake, so it is text an
//!   attacker on the path can choose. See `Fetcher.login`.
//!
//! **Every wait is bounded**: the dial, the `STLS` step, and any handshake
//! by `--connect-timeout`, each line by `Control.max_line_bytes`, each
//! wait for a byte by `--speed-time` under a 300 second ceiling, and the
//! body by `--max-filesize` under a 16 MiB ceiling.

const std = @import("std");

/// Runs one POP3 transfer and builds the two dispatch entries that
/// register it.
pub const Fetcher = @import("zurl-pop3/Fetcher.zig");

/// The RFC 1939 command and response dialogue, over one reader and one
/// writer. It holds no socket, so a test can drive a whole session in
/// memory.
pub const Control = @import("zurl-pop3/Control.zig");

/// The RFC 1939 response grammar: `+OK`, `-ERR`, the period that ends a
/// body, and the period that a body line carries twice. Pure text.
pub const response = @import("zurl-pop3/response.zig");

/// The commands, the APOP digest, and the rule that says whether an answer
/// is one line or a body. Pure text.
pub const command = @import("zurl-pop3/command.zig");

/// What a url path names: one message, or the whole mailbox. Pure text.
pub const target = @import("zurl-pop3/target.zig");

/// The loopback RFC 1939 server this package's tests use.
///
/// Exported for the same reason `zurl_ftp.test_server` is: the end to end
/// tests of the command line need a POP3 peer, and a second copy of this
/// fixture would drift from the one the package tests itself with. It is a
/// fixture and not a product, and nothing but a test may use it. It speaks
/// no TLS, so it serves `pop3` and never `pop3s`.
pub const test_server = @import("zurl-pop3/test_server.zig");

/// The plain url scheme this package handles.
pub const scheme = Fetcher.scheme;

/// The encrypted url scheme this package handles.
pub const secure_scheme = Fetcher.secure_scheme;

/// The port a `pop3://` url uses when it names none.
pub const default_port = Fetcher.default_port;

/// The port a `pop3s://` url uses when it names none.
pub const secure_default_port = Fetcher.secure_default_port;

test {
    _ = Fetcher;
    _ = Control;
    _ = response;
    _ = command;
    _ = target;
}

test "the package names both schemes and the two ports they use" {
    try std.testing.expectEqualStrings("pop3", scheme);
    try std.testing.expectEqualStrings("pop3s", secure_scheme);
    try std.testing.expectEqual(@as(?u16, 110), default_port);
    try std.testing.expectEqual(@as(?u16, 995), secure_default_port);
}
