//! zurl's `ws://` and `wss://` protocols, RFC 6455.
//!
//! One protocol, one module. A build that does not want WebSockets leaves
//! this module out and loses nothing else, and a program outside this
//! repository takes this module, `zurl-core`, and `zurl-net` and gets both
//! schemes with no other part of zurl.
//!
//! **One package owns both schemes.** RFC 6455 names one handshake and one
//! frame format, and `wss` changes neither: it puts the same two on a TLS
//! session. That is the same reason `zurl.protocol.builtins` gives `http`
//! and `https` one vtable. The two schemes carry different default ports,
//! 80 and 443, because the opening handshake is an HTTP request and RFC
//! 6455 section 3 gives it the HTTP ports.
//!
//! **This package does not import `zurl`, and it never will**: the front
//! package imports no protocol package, and a protocol package that
//! imported it back could not be left out. `Fetcher.protocol` takes the
//! front package's namespace as a comptime parameter instead.
//!
//! **It does not import `zurl-http` either.** A WebSocket transfer opens
//! with an HTTP/1.1 request, so this package carries the small piece of
//! HTTP that the handshake needs, in `handshake`. Importing the HTTP
//! engine would tie this package to it, and a build that wanted WebSockets
//! and not HTTP could not have one.
//!
//! A caller wires it in four lines:
//!
//!     var fetcher: zurl_ws.Fetcher = .init(gpa, io);
//!     defer fetcher.deinit();
//!     try client.registerProtocol(fetcher.protocol(zurl));
//!     try client.registerProtocol(fetcher.secureProtocol(zurl));
//!
//! **What a transfer writes.** One `GET` with `Upgrade: websocket`,
//! `Connection: Upgrade`, a `Sec-WebSocket-Key` of 16 fresh octets in
//! base64, and `Sec-WebSocket-Version: 13`. After that it writes control
//! frames alone: a pong for every ping, and a close for the peer's close.
//! **Every frame it writes is masked with a key drawn afresh for that
//! frame**, which RFC 6455 section 5.3 requires of a client.
//!
//! **What a transfer reads.** The payload of every data frame, joined, up
//! to `Fetcher.Options.max_response_bytes`. The frames stop at the peer's
//! close frame or at the end of the socket.
//!
//! **The handshake is verified, and a wrong answer fails the transfer.**
//! `Sec-WebSocket-Accept` must be the base64 of SHA-1 over the key this
//! transfer sent and the fixed GUID of RFC 6455 section 1.3. A client that
//! did not check it would upgrade to anything that answered `101`, and the
//! handshake would prove nothing at all.
//!
//! **`wss` verifies the peer exactly as `https` does**, against the trust
//! store the front package loads, through `zurl_net.Connection`. `-k` is
//! the one input that turns the check off. See `Fetcher.tlsOptions`.
//!
//! What this does not do: no data frame goes out, so `-d` on a `ws://` url
//! sends nothing. curl's own command line tool receives on a WebSocket and
//! sends nothing either. No subprotocol and no extension are offered, and
//! an answer that names one fails the transfer, because an extension can
//! change what the reserved bits and the payload mean. No UTF-8 check on a
//! text frame, because zurl writes a body through as octets.

const std = @import("std");

/// Runs one WebSocket transfer, plain or encrypted, and builds the two
/// dispatch entries that register it.
pub const Fetcher = @import("zurl-ws/Fetcher.zig");

/// The frame: the opcode, the FIN bit, the three length forms, and the
/// mask. Pure bytes, and testable with a table.
pub const frame = @import("zurl-ws/frame.zig");

/// The opening handshake: the key, the accept value it must produce, the
/// request head, and the answer.
pub const handshake = @import("zurl-ws/handshake.zig");

/// The close frame's payload: the status code rule, and the cleaning that
/// a peer's reason passes before it can reach output.
pub const close = @import("zurl-ws/close.zig");

/// One dialogue over one reader and one writer. The direction rules live
/// here: a masked frame from a server is refused, and every frame that
/// goes out is masked.
pub const Session = @import("zurl-ws/Session.zig");

/// Where a redirect on the opening handshake points.
pub const target = @import("zurl-ws/target.zig");

/// The loopback RFC 6455 server this package's tests use.
///
/// Exported for the same reason `zurl_http.test_server` is: the end to end
/// tests of the command line need a WebSocket peer, and a second copy of
/// this fixture would drift from the one the package tests itself with. It
/// is a fixture and not a product, and nothing but a test may use it. It
/// speaks no TLS, so it serves `ws` and never `wss`.
pub const test_server = @import("zurl-ws/test_server.zig");

/// The plain url scheme this package handles.
pub const scheme = Fetcher.scheme;

/// The encrypted url scheme this package handles.
pub const secure_scheme = Fetcher.secure_scheme;

/// The port a `ws://` url uses when it names none.
pub const default_port = Fetcher.default_port;

/// The port a `wss://` url uses when it names none.
pub const secure_default_port = Fetcher.secure_default_port;

test {
    _ = Fetcher;
    _ = frame;
    _ = handshake;
    _ = close;
    _ = Session;
    _ = target;
}

test "the package names both schemes and the two ports RFC 6455 gives them" {
    try std.testing.expectEqualStrings("ws", scheme);
    try std.testing.expectEqualStrings("wss", secure_scheme);
    try std.testing.expectEqual(@as(?u16, 80), default_port);
    try std.testing.expectEqual(@as(?u16, 443), secure_default_port);
}
