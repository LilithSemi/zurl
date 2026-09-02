//! zurl's `telnet://` protocol, RFC 854.
//!
//! One protocol, one module. A build that does not want telnet leaves this
//! module out and loses nothing else, and a program outside this
//! repository takes this module, `zurl-core`, and `zurl-net` and gets
//! `telnet://` with no other part of zurl.
//!
//! **This package does not import `zurl`, and it never will**: the front
//! package imports no protocol package, and a protocol package that
//! imported it back could not be left out. `Fetcher.protocol` takes the
//! front package's namespace as a comptime parameter instead.
//!
//! A caller wires it in three lines:
//!
//!     var fetcher: zurl_telnet.Fetcher = .init(gpa, io);
//!     defer fetcher.deinit();
//!     try client.registerProtocol(fetcher.protocol(zurl));
//!
//! **What a transfer writes.** Whatever the caller gave it, with **every
//! 255 doubled**. That doubling is the whole safety of this protocol: 255
//! is `IAC`, and an undoubled one lets the octets after it reach the peer
//! as a command. A body holding `FF FD 18` would otherwise arrive as
//! `IAC DO TERMINAL-TYPE`, and one holding `FF F4` as an interrupt. See
//! `iac.escape`, which is the one writer.
//!
//! It also answers option negotiation, and it answers it the way curl
//! 8.21.0 does, measured against a loopback server:
//!
//! ```
//! server  IAC DO TERMINAL-TYPE
//! zurl    IAC WONT TERMINAL-TYPE      the answer, and it refuses
//! zurl    IAC WILL BINARY             then the four offers, once
//! zurl    IAC DO BINARY
//! zurl    IAC WILL SUPPRESS-GO-AHEAD
//! zurl    IAC DO SUPPRESS-GO-AHEAD
//! ```
//!
//! Nothing goes out until the peer negotiates first, which is what curl
//! does too: with a server that opened with plain data, curl wrote only
//! the standard input it was given.
//!
//! **What a transfer reads.** The data octets, with every doubled 255
//! halved and every command taken out, until the peer closes. That is what
//! curl writes to standard output for the same session, measured.
//!
//! What this does not do: no TLS, because curl carries no `telnets` scheme
//! and RFC 854 names none. No `-t`/`--telnet-option`, so `TERMINAL-TYPE`,
//! `XDISPLOC`, and `NEW-ENVIRON` are refused where curl with a `-t` would
//! accept one. **Standard input is not read on its own**: curl relays it
//! to a telnet peer with no flag at all, and zurl sends what `-d` or `-T`
//! names, so `-T -` is the flag that relays standard input.

const std = @import("std");

/// Runs one `telnet://` transfer, and builds the dispatch entry that
/// registers it.
pub const Fetcher = @import("zurl-telnet/Fetcher.zig");

/// The telnet command stream: the escaping, the decoding, and the option
/// negotiation. Pure bytes, and testable with a table.
pub const iac = @import("zurl-telnet/iac.zig");

/// The loopback RFC 854 server this package's tests use.
///
/// Exported for the same reason `zurl_http.test_server` is: the end to end
/// tests of the command line need a telnet peer, and a second copy of this
/// fixture would drift from the one the package tests itself with. It is a
/// fixture and not a product, and nothing but a test may use it.
pub const test_server = @import("zurl-telnet/test_server.zig");

/// The url scheme this package handles.
pub const scheme = Fetcher.scheme;

/// The port a url of this scheme uses when it names none.
pub const default_port = Fetcher.default_port;

test {
    _ = Fetcher;
    _ = iac;
}

test "the package names the scheme and the port RFC 854 assigns" {
    try std.testing.expectEqualStrings("telnet", scheme);
    try std.testing.expectEqual(@as(?u16, 23), default_port);
}
