//! zurl's `ftp://` and `ftps://` protocols, RFC 959 and RFC 4217.
//!
//! One protocol, one module. A build that does not want FTP leaves this
//! module out and loses nothing else, and a program outside this
//! repository takes this module, `zurl-core`, and `zurl-net` and gets both
//! schemes with no other part of zurl.
//!
//! **One package owns both schemes**, the way `zurl-gopher` owns `gopher`
//! and `gophers`. RFC 959 names the commands and the replies, and `ftps`
//! changes neither: it puts the same dialogue inside TLS. The two carry
//! different default ports, 21 and 990, because implicit TLS has a port of
//! its own.
//!
//! **This package does not import `zurl`, and it never will**: the front
//! package imports no protocol package, and a protocol package that
//! imported it back could not be left out. `Fetcher.protocol` takes the
//! front package's namespace as a comptime parameter instead.
//!
//! A caller wires it in four lines:
//!
//!     var fetcher: zurl_ftp.Fetcher = .init(gpa, io);
//!     defer fetcher.deinit();
//!     try client.registerProtocol(fetcher.protocol(zurl));
//!     try client.registerProtocol(fetcher.secureProtocol(zurl));
//!
//! **What a transfer sends.** The command order is curl's own, measured
//! against curl 8.21.0 on a loopback RFC 959 server:
//!
//!     USER, PASS, [PBSZ 0, PROT P], CWD for each directory of the path,
//!     EPSV or PASV, TYPE I or TYPE A, [SIZE], [REST], RETR or LIST or
//!     NLST, then QUIT
//!
//! with `AUTH TLS` before `USER` for an explicit TLS transfer.
//!
//! **The three rules that keep this safe**, each with its own section in
//! the file that holds it:
//!
//! - **The address a `PASV` answer names is never dialed.** It is written
//!   by the server, so a hostile one could point this client at any
//!   machine it liked. The data connection goes to the host the url named.
//!   curl has done the same by default since 7.74.0. See
//!   `Fetcher.dataTarget`.
//! - **No command can carry a forged line ending.** Every command goes out
//!   through `command.write`, which refuses a NUL, a CR, or an LF in the
//!   argument. The url path and the credential are each refused a second
//!   time, earlier, so the message names the url and not the command.
//! - **A multi-line reply is read whole.** RFC 959 ends one only at a line
//!   carrying the same code and a space. A reader that stopped at the
//!   first line would read every later answer against the wrong command.
//!   See `reply.Collector`.
//!
//! **Every wait is bounded**: the dial and any TLS handshake by
//! `--connect-timeout`, each reply line by `zurl_net.bounded.readLine`,
//! each reply by a line count and a byte count, and the data connection by
//! a size bound and a stall bound.

const std = @import("std");

/// Runs one FTP transfer and builds the two dispatch entries that register
/// it.
pub const Fetcher = @import("zurl-ftp/Fetcher.zig");

/// The RFC 959 command and reply dialogue, over one reader and one writer.
/// It holds no socket, so a test can drive a whole session in memory.
pub const Control = @import("zurl-ftp/Control.zig");

/// The RFC 959 reply grammar, multi-line replies included, and the two
/// answers that carry an address. Pure text.
pub const reply = @import("zurl-ftp/reply.zig");

/// Writing one command line, and the refusal that keeps a second one out
/// of it. Pure text.
pub const command = @import("zurl-ftp/command.zig");

/// What a url path names: the directories to change into, and the file or
/// the listing. Pure text.
pub const target = @import("zurl-ftp/target.zig");

/// The loopback RFC 959 server this package's tests use.
///
/// Exported for the same reason `zurl_http.test_server` is: the end to end
/// tests of the command line need an FTP peer, and a second copy of this
/// fixture would drift from the one the package tests itself with. It is a
/// fixture and not a product, and nothing but a test may use it. It speaks
/// no TLS, so it serves `ftp` and never `ftps`.
pub const test_server = @import("zurl-ftp/test_server.zig");

/// The plain url scheme this package handles.
pub const scheme = Fetcher.scheme;

/// The encrypted url scheme this package handles.
pub const secure_scheme = Fetcher.secure_scheme;

/// The port an `ftp://` url uses when it names none.
pub const default_port = Fetcher.default_port;

/// The port an `ftps://` url uses when it names none.
pub const secure_default_port = Fetcher.secure_default_port;

test {
    _ = Fetcher;
    _ = Control;
    _ = reply;
    _ = command;
    _ = target;
}

test "the package names both schemes and the two ports they use" {
    try std.testing.expectEqualStrings("ftp", scheme);
    try std.testing.expectEqualStrings("ftps", secure_scheme);
    try std.testing.expectEqual(@as(?u16, 21), default_port);
    try std.testing.expectEqual(@as(?u16, 990), secure_default_port);
}
