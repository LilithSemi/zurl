//! zurl's `file://` protocol.
//!
//! One protocol, one module. A build that does not want local file reads
//! leaves this module out and loses nothing else, and a program outside
//! this repository takes this module and `zurl-core` and gets `file://`
//! with no other part of zurl.
//!
//! **This package imports `zurl-core` and nothing else of ours.** It does
//! not import `zurl`, and it never will: the front package imports no
//! protocol package, and a protocol package that imported it back could
//! not be left out. `Fetcher.protocol` takes the front package's namespace
//! as a comptime parameter instead, so the dispatch entry is built against
//! the shape and not against an import.
//!
//! A caller wires it in three lines:
//!
//!     var fetcher: zurl_file.Fetcher = .init(io);
//!     defer fetcher.deinit();
//!     try client.registerProtocol(fetcher.protocol(zurl));
//!
//! `zurl.Client.registerProtocol` teaches `zurl_core.url` the scheme at
//! the same time, so `file:///a/b` parses after that one call.
//!
//! What this does not do: no `-I`, because zurl has no such flag and a
//! local file has no head to print, and no byte range, because zurl has no
//! `-r` either.

const std = @import("std");

/// Reads one local file for one transfer, and builds the dispatch entry
/// that registers it.
pub const Fetcher = @import("zurl-file/Fetcher.zig");

/// The url scheme this package handles.
pub const scheme = Fetcher.scheme;

/// The port a url of this scheme uses, which is none. See
/// `zurl_core.url.Scheme.default_port` for what a null means to the parser.
pub const default_port = Fetcher.default_port;

test {
    _ = Fetcher;
}

test "the package names the scheme it handles" {
    try std.testing.expectEqualStrings("file", scheme);
    try std.testing.expectEqual(@as(?u16, null), default_port);
}
