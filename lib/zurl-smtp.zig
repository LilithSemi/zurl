//! zurl's `smtp://` and `smtps://` protocols, RFC 5321 and RFC 3207.
//!
//! One protocol, one module. A build that does not want SMTP leaves this
//! module out and loses nothing else, and a program outside this
//! repository takes this module, `zurl-core`, and `zurl-net` and gets both
//! schemes with no other part of zurl.
//!
//! **This is the one protocol package that sends rather than fetches.**
//! Everything else here asks a server for bytes. This one hands a server a
//! message and reads back whether it took it, so the answer of a transfer
//! is empty and the interesting part is the `DATA` phase.
//!
//! **One package owns both schemes**, the way `zurl-ftp` owns `ftp` and
//! `ftps`. The two carry different default ports, 25 and 465.
//!
//! **This package does not import `zurl`, and it never will**:
//! `Fetcher.protocol` takes the front package's namespace as a comptime
//! parameter instead.
//!
//! A caller wires it in four lines:
//!
//!     var fetcher: zurl_smtp.Fetcher = .init(gpa, io);
//!     defer fetcher.deinit();
//!     try client.registerProtocol(fetcher.protocol(zurl));
//!     try client.registerProtocol(fetcher.secureProtocol(zurl));
//!
//! **What a transfer sends.** The command order is curl's own, measured
//! against curl 8.21.0 on a loopback RFC 5321 fixture:
//!
//!     [EHLO, STARTTLS,] EHLO name, MAIL FROM:<sender>, one RCPT TO for
//!     each recipient, DATA, the message, then QUIT
//!
//! with `HELO name` in place of `EHLO name` when the server does not know
//! the newer command.
//!
//! **The two rules that keep this safe.** Both are places where zurl
//! refuses what curl 8.21.0 sends, and both were measured:
//!
//! - **No command can carry a forged line ending.** A CR or an LF in
//!   `--mail-from` or `--mail-rcpt` would end the command line and write a
//!   second `RCPT TO`, so the message would go to somebody the user never
//!   named. Measured: curl puts that second recipient on the wire, and
//!   zurl exits 3 with no connection at all. See `Fetcher.addressIsSafe`.
//! - **The message is dot-stuffed.** A body line of one period ends the
//!   `DATA` phase, so every byte after it is read as an SMTP command.
//!   Measured: a body written with bare line feeds walks straight through
//!   curl, which stuffs only after a `CRLF`, and the server reads the rest
//!   of the message as commands. See `message`.
//!
//! **Every wait is bounded**: the dial, the `STARTTLS` step, and any
//! handshake by `--connect-timeout`, each reply line by
//! `Control.max_line_bytes`, each reply by `Control.reply_limits`, each
//! wait for a byte by `--speed-time` under a 300 second ceiling, and the
//! message by `--max-filesize` under a 16 MiB ceiling.

const std = @import("std");

/// Runs one SMTP transfer and builds the two dispatch entries that
/// register it.
pub const Fetcher = @import("zurl-smtp/Fetcher.zig");

/// The RFC 5321 command and reply dialogue, over one reader and one
/// writer. It holds no socket, so a test can drive a whole session in
/// memory.
pub const Control = @import("zurl-smtp/Control.zig");

/// Turning a message body into the octets of a `DATA` phase, with the
/// dot-stuffing RFC 5321 section 4.5.2 asks for. Pure text, and the one
/// module in this package that a message's own safety depends on.
pub const message = @import("zurl-smtp/message.zig");

/// The commands, and what an `EHLO` answer says a server can do. Pure
/// text.
pub const command = @import("zurl-smtp/command.zig");

/// The loopback RFC 5321 server this package's tests use.
///
/// Exported for the same reason `zurl_ftp.test_server` is: the end to end
/// tests of the command line need an SMTP peer, and a second copy of this
/// fixture would drift from the one the package tests itself with. It is a
/// fixture and not a product, and nothing but a test may use it. It speaks
/// no TLS, so it serves `smtp` and never `smtps`.
pub const test_server = @import("zurl-smtp/test_server.zig");

/// The plain url scheme this package handles.
pub const scheme = Fetcher.scheme;

/// The encrypted url scheme this package handles.
pub const secure_scheme = Fetcher.secure_scheme;

/// The port an `smtp://` url uses when it names none.
pub const default_port = Fetcher.default_port;

/// The port an `smtps://` url uses when it names none.
pub const secure_default_port = Fetcher.secure_default_port;

test {
    _ = Fetcher;
    _ = Control;
    _ = message;
    _ = command;
}

test "the package names both schemes and the two ports they use" {
    try std.testing.expectEqualStrings("smtp", scheme);
    try std.testing.expectEqualStrings("smtps", secure_scheme);
    try std.testing.expectEqual(@as(?u16, 25), default_port);
    try std.testing.expectEqual(@as(?u16, 465), secure_default_port);
}
