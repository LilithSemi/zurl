//! Certificate handling for zurl.
//!
//! This package imports `zurl-core`, for the `ca.Source` type that
//! `ca.resolve` produces. It imports no other zurl package.

pub const bundle = @import("zurl-tls/bundle.zig");

/// A bounded reader for a certificate that a peer sent.
///
/// `std.crypto.Certificate.parse` walks a certificate with no bound check
/// of any kind, so six octets from a server are enough to read past the
/// end of the buffer. `certificate.parse` gives back the same
/// `std.crypto.Certificate.Parsed` and checks every read first. Both
/// certificate chain walks in `Client` use it.
pub const certificate = @import("zurl-tls/certificate.zig");

pub const loader = @import("zurl-tls/loader.zig");

/// A copy of `std.crypto.tls.Client`, with a patch that lets it speak to a
/// server that has an ECDSA certificate and offers only TLS 1.2. The file
/// `zurl-tls/UPSTREAM` says what the patch is and how to re-sync the copy.
///
/// `zig build check-vendor` compares the copy with the same file in the Zig
/// that runs the build. It fails on a changed line that no `ZURL PATCH`
/// comment accounts for.
pub const Client = @import("zurl-tls/Client.zig");

/// A loopback TLS 1.3 server for tests. It runs a real handshake with the
/// client above and it presents a chain the test chooses, a forged one
/// included, so no TLS test needs the network.
///
/// It lives here, and not beside `zurl-http/test_server.zig`, because
/// every package that speaks a TLS twin of a protocol reaches `zurl-tls`
/// through `zurl-net`. A fixture in the HTTP package would be out of
/// reach of `ftps`, `imaps`, `pop3s`, `smtps`, `gophers`, `wss`, `ldaps`
/// and `mqtts`.
pub const test_server = @import("zurl-tls/test_server.zig");

test {
    _ = bundle;
    _ = certificate;
    _ = loader;
    _ = Client;
    _ = test_server;
}
