//! zurl's `dict://` protocol, RFC 2229.
//!
//! One protocol, one module. A build that does not want dictionary lookups
//! leaves this module out and loses nothing else, and a program outside
//! this repository takes this module, `zurl-core`, and `zurl-net` and gets
//! `dict://` with no other part of zurl.
//!
//! **This package does not import `zurl`, and it never will**: the front
//! package imports no protocol package, and a protocol package that
//! imported it back could not be left out. `Fetcher.protocol` takes the
//! front package's namespace as a comptime parameter instead, so the
//! dispatch entry is built against the shape and not against an import.
//!
//! A caller wires it in three lines:
//!
//!     var fetcher: zurl_dict.Fetcher = .init(gpa, io);
//!     defer fetcher.deinit();
//!     try client.registerProtocol(fetcher.protocol(zurl));
//!
//! `zurl.Client.registerProtocol` teaches `zurl_core.url` the scheme at
//! the same time, so `dict://dict.org/d:hello` parses after that one call.
//!
//! **What a transfer writes.** Three lines, the same three curl 8.21.0
//! writes, measured against a listener that captured them:
//!
//! ```
//! CLIENT zurl/0.1\r\n
//! DEFINE ! hello\r\n
//! QUIT\r\n
//! ```
//!
//! **What a transfer reads.** Every byte the server sent, the RFC 2229
//! status lines included. curl does no parsing of a dict answer, measured
//! against a loopback server, so neither does this.
//!
//! What this does not do: no `AUTH`, because curl sends none for `dict`
//! either. No connection reuse, because the session ends with `QUIT` and
//! the server closes. No TLS: RFC 2229 names no `dicts` scheme and curl
//! carries none.

const std = @import("std");

/// Runs one `dict://` transfer, and builds the dispatch entry that
/// registers it.
pub const Fetcher = @import("zurl-dict/Fetcher.zig");

/// The map from a url path to an RFC 2229 command line. Pure text, and
/// testable with a table.
pub const request = @import("zurl-dict/request.zig");

/// The loopback RFC 2229 server this package's tests use.
///
/// Exported for the same reason `zurl_http.test_server` is: the end to end
/// tests of the command line need a dict peer, and a second copy of this
/// fixture would drift from the one the package tests itself with. It is
/// a fixture and not a product, and nothing but a test may use it.
pub const test_server = @import("zurl-dict/test_server.zig");

/// The url scheme this package handles.
pub const scheme = Fetcher.scheme;

/// The port a url of this scheme uses when it names none.
pub const default_port = Fetcher.default_port;

test {
    _ = Fetcher;
    _ = request;
}

test "the package names the scheme and the port it handles" {
    try std.testing.expectEqualStrings("dict", scheme);
    try std.testing.expectEqual(@as(?u16, 2628), default_port);
}
