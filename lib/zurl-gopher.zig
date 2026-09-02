//! zurl's `gopher://` and `gophers://` protocols, RFC 1436.
//!
//! One protocol, one module. A build that does not want gopher leaves this
//! module out and loses nothing else, and a program outside this
//! repository takes this module, `zurl-core`, and `zurl-net` and gets both
//! schemes with no other part of zurl.
//!
//! **One package owns both schemes.** RFC 1436 names the request and the
//! answer, and `gophers` changes neither: it puts the same two on a TLS
//! session, on the same port 70. That is the same reason
//! `zurl.protocol.builtins` gives `http` and `https` one vtable.
//!
//! **This package does not import `zurl`, and it never will**: the front
//! package imports no protocol package, and a protocol package that
//! imported it back could not be left out. `Fetcher.protocol` takes the
//! front package's namespace as a comptime parameter instead, so the
//! dispatch entry is built against the shape and not against an import.
//!
//! A caller wires it in four lines:
//!
//!     var fetcher: zurl_gopher.Fetcher = .init(gpa, io);
//!     defer fetcher.deinit();
//!     try client.registerProtocol(fetcher.protocol(zurl));
//!     try client.registerProtocol(fetcher.secureProtocol(zurl));
//!
//! A caller that wants the plain scheme alone registers the first of the
//! two, and `gophers://` is then `error.UnsupportedProtocol`.
//!
//! **What a transfer writes.** One line: the selector, then CRLF. The
//! selector is the url path with the leading `/` and the item type
//! dropped, then percent-decoded, which is what curl 8.21.0 sends,
//! measured. So `gopher://h/0/foo.txt` writes `/foo.txt\r\n`.
//!
//! **What a transfer reads.** Every byte the server sent, until the peer
//! closes. curl writes a gopher answer through with no transformation,
//! measured, so neither does this.
//!
//! **`gophers` verifies the peer exactly as `https` does**, against the
//! trust store the front package loads, through `zurl_net.Connection`.
//! `-k` is the one input that turns the check off. See
//! `Fetcher.tlsOptions`.

const std = @import("std");

/// Runs one gopher transfer, plain or encrypted, and builds the two
/// dispatch entries that register it.
pub const Fetcher = @import("zurl-gopher/Fetcher.zig");

/// The map from a url to the one line a request carries. Pure text, and
/// testable with a table.
pub const selector = @import("zurl-gopher/selector.zig");

/// The loopback RFC 1436 server this package's tests use.
///
/// Exported for the same reason `zurl_http.test_server` is: the end to end
/// tests of the command line need a gopher peer, and a second copy of this
/// fixture would drift from the one the package tests itself with. It is
/// a fixture and not a product, and nothing but a test may use it. It
/// speaks no TLS, so it serves `gopher` and never `gophers`.
pub const test_server = @import("zurl-gopher/test_server.zig");

/// The plain url scheme this package handles.
pub const scheme = Fetcher.scheme;

/// The encrypted url scheme this package handles.
pub const secure_scheme = Fetcher.secure_scheme;

/// The port a url of either scheme uses when it names none.
pub const default_port = Fetcher.default_port;

test {
    _ = Fetcher;
    _ = selector;
}

test "the package names both schemes and the one port they share" {
    try std.testing.expectEqualStrings("gopher", scheme);
    try std.testing.expectEqualStrings("gophers", secure_scheme);
    try std.testing.expectEqual(@as(?u16, 70), default_port);
}
