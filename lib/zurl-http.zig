//! An HTTP engine seam, and an HTTP/1.1 engine over `zurl-net`.
//!
//! `engine` defines the seam: a `Request` in, an `Exchange` that reports a
//! `Head` and streams a body out. `h1` is the only engine today, and it
//! owns its connections: it dials and hand shakes through `zurl-net`, so a
//! TLS fault keeps the name and the cause that `zurl-net` gave it, and it
//! keeps the pool of connections a finished exchange handed back. A later
//! phase adds an engine beside it for ALPN and client certificates;
//! nothing outside `h1.zig` should need to change for that swap.

pub const engine = @import("zurl-http/engine.zig");
pub const h1 = @import("zurl-http/h1.zig");

/// The HTTP/2 half of the engine. `h1` owns the dial, so it is what reads
/// the ALPN answer and calls in here for a peer that chose `h2`.
pub const h2 = @import("zurl-http/h2.zig");

/// A loopback HTTP/2 server for tests. It speaks frames, so an HTTP/2 test
/// needs no TLS and no network.
pub const h2_test_server = @import("zurl-http/h2_test_server.zig");

/// One QUIC connection over a UDP socket. **The only file in the HTTP/3
/// path that touches the network.**
pub const quic = @import("zurl-http/quic.zig");

/// The HTTP/3 half of the engine, RFC 9114. `Open` is the shape
/// `h2.Open` is, so the caller that joins a hop's secrets with the
/// caller's headers does it once for both.
pub const h3 = @import("zurl-http/h3.zig");

/// A loopback QUIC and HTTP/3 server for tests. It runs a real TLS 1.3
/// handshake over CRYPTO frames, so an HTTP/3 test needs no network.
pub const h3_test_server = @import("zurl-http/h3_test_server.zig");

/// Maps engine faults onto the zurl error taxonomy, and records
/// diagnostics.
pub const errors = @import("zurl-http/errors.zig");

/// A loopback HTTP server for tests. Exposed so other packages that add
/// HTTP-shaped tests do not need to write their own.
pub const test_server = @import("zurl-http/test_server.zig");

/// A loopback proxy for tests: an HTTP proxy, a `CONNECT` tunnel, and a
/// SOCKS server. Exposed beside `test_server` for the same reason.
pub const proxy_test_server = @import("zurl-http/proxy_test_server.zig");

test {
    _ = engine;
    _ = h1;
    _ = h2;
    _ = errors;
    _ = test_server;
    _ = proxy_test_server;
    _ = h2_test_server;
    _ = quic;
    _ = h3;
    _ = h3_test_server;
}
