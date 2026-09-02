//! Sockets for zurl: dialing, and a TLS session over `zurl-tls`.
//!
//! This package is what sits under a protocol engine. It opens a stream to
//! a peer, it can put TLS on that stream, and it hands back a
//! `std.Io.Reader` and a `std.Io.Writer`. An engine above it therefore
//! holds one code path for `http` and `https`, and zurl owns its own
//! connection setup instead of `std.http.Client` owning it.
//!
//! That ownership is the reason the package exists. `std.http.Client`
//! imports std's own TLS, so the ECDSA-over-TLS-1.2 patch in
//! `zurl-tls/Client.zig` cannot be reached through it. It also collapses
//! every TLS fault into one name, so an expired certificate, a wrong host
//! name, and an untrusted root all reach a user as exit 35 where curl
//! gives exit 60. `errors.zig` here keeps those apart.
//!
//! This package imports `zurl-core` and `zurl-tls`. It does not import
//! `zurl-http` or `zurl`, and it never will: the graph runs one way.
//!
//! The line framing for a command and reply protocol is here, and all four
//! of FTP, SMTP, IMAP, and POP3 read it from this one place:
//!
//! - `bounded.readLine` reads one line under two bounds, a length and a
//!   stall.
//! - `line` writes one command line and **refuses a NUL, a CR, or an LF in
//!   any part of it**, which is the injection gate of all four protocols.
//!   `line.Session` is the dialogue over one reader and one writer.
//! - `reply` is the three digit code grammar, which FTP and SMTP share.
//!   POP3 and IMAP each own their own grammar, because neither answers
//!   with a code.
//!
//! What is not here yet: no session cache, no ALPN, and no client
//! certificate.
//!
//! The connection pool is not here either, and it is not missing. A pool
//! has to know when a protocol has finished with a connection, and only
//! the protocol engine knows that. `zurl-http/h1.zig` keeps it, over the
//! `Connection` values this package hands out.

/// Opening a stream to a peer, with a bound on how long that may take.
pub const tcp = @import("zurl-net/tcp.zig");

/// The check over `/etc/resolv.conf` that runs before a name lookup.
/// `tcp.dial` is its only caller. It is here, and not private to `tcp`,
/// so its grammar can be read next to the grammar of `std`.
pub const resolv = @import("zurl-net/resolv.zig");

/// Where a transfer dials when `--resolve` or `--connect-to` moves it.
/// Every protocol package that opens a socket reads this one definition,
/// and `zurl-http/engine.zig` re-exports it.
pub const override = @import("zurl-net/override.zig");

/// One open connection, plain or encrypted, behind one reader and one
/// writer.
pub const Connection = @import("zurl-net/Connection.zig");

/// Reaching an origin through a proxy: the `CONNECT` tunnel and the SOCKS
/// handshakes, each as a `bounded.Upgrade` that runs inside the connect
/// deadline.
pub const proxy = @import("zurl-net/proxy.zig");

/// The map from a dial or handshake fault onto `zurl_core.Error`.
pub const errors = @import("zurl-net/errors.zig");

/// The two waits a protocol package must bound: bringing a connection up,
/// and reading an answer that ends only when the peer closes.
pub const bounded = @import("zurl-net/bounded.zig");

/// Writing one command line, the refusal that keeps a second one out of
/// it, and the dialogue that carries both. Shared by every line-oriented
/// protocol package.
pub const line = @import("zurl-net/line.zig");

/// The reply grammar of a protocol that answers with a three digit code,
/// multi-line replies included. Shared by `zurl-ftp` and `zurl-smtp`.
pub const reply = @import("zurl-net/reply.zig");

/// The SASL mechanisms, the choice between them, and the bytes of each
/// exchange. Shared by `zurl-smtp`, `zurl-imap`, and `zurl-pop3`.
pub const sasl = @import("zurl-net/sasl.zig");

test {
    _ = tcp;
    _ = resolv;
    _ = override;
    _ = Connection;
    _ = proxy;
    _ = errors;
    _ = bounded;
    _ = line;
    _ = reply;
    _ = sasl;
}
