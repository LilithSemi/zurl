//! zurl: the front package.
//!
//! This package imports `zurl-core`, `zurl-stream`, and every enabled
//! protocol package. No protocol package imports this one; that boundary
//! is what lets a protocol move to its own repository later.

const std = @import("std");

pub const Transfer = @import("zurl/Transfer.zig");
pub const Response = @import("zurl/Response.zig");
pub const protocol = @import("zurl/protocol.zig");
pub const body = @import("zurl/body.zig");
pub const request_body = @import("zurl/request_body.zig");
pub const multipart = @import("zurl/multipart.zig");
pub const authorize = @import("zurl/authorize.zig");
/// Turns a transfer's proxy options into what the engine sends. The proxy
/// credential is built here, and the origin's is built in `authorize`.
pub const proxy = @import("zurl/proxy.zig");
pub const Client = @import("zurl/Client.zig");
pub const download = @import("zurl/download.zig");
pub const Multi = @import("zurl/Multi.zig");
pub const Jar = @import("zurl/Jar.zig");

/// Every fault a transfer can report.
///
/// **A consumer needs this name to hold what `Client.perform` and
/// `download.toFile` answer**, because both are written `Error!Result`.
/// Without it a caller outside this repository has to reach into
/// `zurl-core` for a name the front package already promises, which is the
/// one thing the layering rule says it must not do.
///
/// Re-exported for the reason `embedded_ca_bundle_pem` and
/// `ConnectionPool` are: a caller reads the front package alone.
pub const Error = @import("zurl-core").Error;

/// Where a transfer records what went wrong, and the url, status and
/// message that go with it.
///
/// **A consumer needs this name to make one**, because `Client.perform`
/// and `download.toFile` both take `?*Diagnostics` and a caller that
/// cannot write `var d: zurl.Diagnostics = .{}` can only pass null, which
/// throws away every message this package writes.
///
/// `Diagnostics.status` holds the status where the fault carries one. See
/// `Transfer.Options.fail_on_error`, which turns a `4xx` or `5xx` into
/// `Error.HttpReturnedError` and records the status beside it.
pub const Diagnostics = @import("zurl-core").Diagnostics;

/// The trust bundle the build put into this binary, as PEM text.
///
/// This is what `zurl_core.ca.Source.embedded` names, and it is the store
/// a transfer verifies against when no `--cacert`, no `--capath`, and no
/// environment variable names another. `--dump-ca-embed` writes it out, so
/// a user can read the roots this binary trusts without trusting the
/// binary to describe them.
///
/// Re-exported here, and not reached through `zurl-tls`, so the CLI keeps
/// one package to talk to. The layering rule is that the CLI reads the
/// front package alone.
pub const embedded_ca_bundle_pem = @import("zurl-tls").bundle.embedded_pem;

/// A connection pool that more than one `Client` may use.
///
/// One `Client` runs one transfer at a time, so a caller that runs several
/// at once holds several clients. Each of them keeps a pool of its own
/// unless the caller hands them one of these, and a pool of its own means a
/// connection of its own to every host: eight parallel transfers to one
/// HTTP/2 host cost eight TCP connections and eight TLS handshakes where
/// one of each would do.
///
/// Make one with `createConnectionPool`, give it to each client with
/// `Client.shareConnections`, and free it with `destroyConnectionPool`
/// after every one of those clients is deinitialised.
///
/// Re-exported here for the reason `embedded_ca_bundle_pem` is: the CLI
/// reads the front package alone.
pub const ConnectionPool = @import("zurl-http").h1.SharedPool;

/// Makes a `ConnectionPool`. `io` must be the one every client that joins
/// it uses.
pub fn createConnectionPool(
    allocator: std.mem.Allocator,
    io: std.Io,
) std.mem.Allocator.Error!*ConnectionPool {
    return @import("zurl-http").h1.createSharedPool(allocator, io);
}

/// Frees a `ConnectionPool` and closes every connection it still holds.
///
/// Every client that joined the pool must be deinitialised first. Each of
/// them holds the pool, and this gives the caller's own hold back: the last
/// one out is what frees it.
pub fn destroyConnectionPool(pool: *ConnectionPool) void {
    @import("zurl-http").h1.destroySharedPool(pool);
}

test {
    _ = Transfer;
    _ = Response;
    _ = protocol;
    _ = body;
    _ = request_body;
    _ = multipart;
    _ = authorize;
    _ = proxy;
    _ = Client;
    _ = download;
    _ = Multi;
    _ = Jar;
    _ = @import("zurl/compat_test.zig");
}
