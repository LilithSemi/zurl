//! zurl's `tftp://` protocol, RFC 1350.
//!
//! One protocol, one module. A build that does not want TFTP leaves this
//! module out and loses nothing else, and a program outside this
//! repository takes this module, `zurl-core`, and `zurl-net` and gets
//! `tftp://` with no other part of zurl.
//!
//! **This is the one protocol package that reads no stream.** A TFTP
//! transfer is a series of UDP datagrams, each one acknowledged, and the
//! client is what recovers a datagram the network dropped. So this package
//! owns a socket of its own, its own block numbering, and its own
//! retransmission. `zurl-net` gives it the error taxonomy and nothing
//! else: there is no `Connection` here, because there is no connection.
//!
//! **This package does not import `zurl`, and it never will**: the front
//! package imports no protocol package, and a protocol package that
//! imported it back could not be left out. `Fetcher.protocol` takes the
//! front package's namespace as a comptime parameter instead.
//!
//! A caller wires it in three lines:
//!
//!     var fetcher: zurl_tftp.Fetcher = .init(gpa, io);
//!     defer fetcher.deinit();
//!     try client.registerProtocol(fetcher.protocol(zurl));
//!
//! **What a transfer writes.** One read request, then one acknowledgement
//! for each block. The read request is byte for byte what curl 8.21.0
//! sends by default, measured against a `socat` listener on UDP:
//!
//! ```
//! 00 01 'hello.txt' 00 'octet' 00
//! 'tsize' 00 '0' 00 'blksize' 00 '512' 00 'timeout' 00 '6' 00
//! ```
//!
//! **What a transfer reads.** The blocks of the file, in order, until one
//! arrives shorter than the block size. A server that answered `tsize`
//! also gave the size before the first block.
//!
//! What this does not do: no upload, so no `WRQ`. No `netascii`, because
//! this build has no `-B`.
//!
//! `Fetcher.Options.send_options` is `--tftp-no-options`, which writes the
//! file name and the mode alone. `Fetcher.Options.block_size` is
//! `--tftp-blksize`, which writes another number into the `blksize`
//! option. The number lies between `packet.min_block_size` and
//! `packet.max_block_size`, and one outside that range is refused by name
//! before any datagram goes out.

const std = @import("std");

/// Runs one `tftp://` download, and builds the dispatch entry that
/// registers it.
pub const Fetcher = @import("zurl-tftp/Fetcher.zig");

/// The five TFTP packets and the option extension. Pure bytes, and
/// testable with a table.
pub const packet = @import("zurl-tftp/packet.zig");

/// The loopback RFC 1350 server this package's tests use.
///
/// Exported for the same reason `zurl_http.test_server` is: the end to end
/// tests of the command line need a TFTP peer, and a second copy of this
/// fixture would drift from the one the package tests itself with. It is
/// a fixture and not a product, and nothing but a test may use it.
pub const test_server = @import("zurl-tftp/test_server.zig");

/// The url scheme this package handles.
pub const scheme = Fetcher.scheme;

/// The port a url of this scheme uses when it names none.
pub const default_port = Fetcher.default_port;

test {
    _ = Fetcher;
    _ = packet;
}

test "the package names the scheme and the port it handles" {
    try std.testing.expectEqualStrings("tftp", scheme);
    try std.testing.expectEqual(@as(?u16, 69), default_port);
}
