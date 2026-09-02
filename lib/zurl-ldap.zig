//! zurl's `ldap://` and `ldaps://` protocols, RFC 4511 and RFC 4516.
//!
//! One protocol, one module. A build that does not want directory lookups
//! leaves this module out and loses nothing else, and a program outside
//! this repository takes this module, `zurl-core`, and `zurl-net` and gets
//! both schemes with no other part of zurl.
//!
//! **One package owns both schemes.** RFC 4511 names the operations, and
//! `ldaps` changes none of them: it puts the same ones inside TLS, on port
//! 636 against 389 for plain LDAP. That is the same reason
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
//!     var fetcher: zurl_ldap.Fetcher = .init(gpa, io);
//!     defer fetcher.deinit();
//!     try client.registerProtocol(fetcher.protocol(zurl));
//!     try client.registerProtocol(fetcher.secureProtocol(zurl));
//!
//! `zurl.Client.registerProtocol` teaches `zurl_core.url` the scheme at
//! the same time, so `ldap://host/dc=example,dc=com` parses after that
//! call.
//!
//! ## What this package is
//!
//! LDAP is the one protocol zurl speaks whose messages are not text. Every
//! other one writes commands as lines and reads answers as lines. This one
//! writes BER, and a BER length is a number the peer chose that decides how
//! many bytes this process then reads. That is why the package is larger
//! than the ones beside it, and it is why `ber.zig` is its own module with
//! its own bounds.
//!
//! ## The three rules a reader should know
//!
//! **A length is bounded before it is used, never after.** `Session.zig`
//! reads six bytes of header, checks the length in them against
//! `Session.max_message_bytes`, and only then allocates. `ber.zig` refuses
//! the indefinite length form by name and refuses a long form that names
//! more than four length octets. Nesting is bounded by `ber.max_depth`.
//!
//! **A filter from a url reaches the wire, and `filter.zig` holds the
//! escaping rule.** RFC 4515 writes NUL, `(`, `)`, `*`, and `\` only as
//! `\00`, `\28`, `\29`, `\2a`, and `\5c`. A literal one of those five is
//! refused by name. Everything else is a byte, and BER counts the octets
//! in front of a value, so no byte a value holds can end an element early.
//!
//! **The answer is curl's format, and `ldif.zig` holds it.** It was
//! measured off curl 8.21.0 against a real slapd 2.6.13, byte for byte. It
//! differs in exactly two places, and both are about a byte a server chose
//! drawing a line in the output. See that file.
//!
//! ## What this does not do
//!
//! No SASL, no referral following, and no operation that writes to a
//! directory. See `Fetcher`.

const std = @import("std");

/// Runs one LDAP transfer, plain or encrypted, and builds the two dispatch
/// entries that register it.
pub const Fetcher = @import("zurl-ldap/Fetcher.zig");

/// BER, the subset RFC 4511 needs. **The file that bounds a length before
/// it reads the bytes that length describes.** Pure bytes, and it knows no
/// LDAP structure at all.
pub const ber = @import("zurl-ldap/ber.zig");

/// RFC 4515, the string form of a search filter, and the BER it becomes.
/// **The file that holds this package's escaping rule.**
pub const filter = @import("zurl-ldap/filter.zig");

/// RFC 4516, the `ldap://` url, read into the four things a search needs.
pub const target = @import("zurl-ldap/target.zig");

/// The text one search result becomes. curl's own format, measured.
pub const ldif = @import("zurl-ldap/ldif.zig");

/// RFC 4511, the protocol operations this package sends and reads.
pub const message = @import("zurl-ldap/message.zig");

/// One dialogue: the message ids and the envelope off the socket.
pub const Session = @import("zurl-ldap/Session.zig");

/// The loopback RFC 4511 server this package's tests use.
///
/// Exported for the same reason `zurl_http.test_server` is: the end to end
/// tests of the command line need an LDAP peer, and a second copy of this
/// fixture would drift from the one the package tests itself with. It is a
/// fixture and not a product, and nothing but a test may use it. It speaks
/// no TLS, so it serves `ldap` and never `ldaps`.
pub const test_server = @import("zurl-ldap/test_server.zig");

/// The plain url scheme this package handles.
pub const scheme = Fetcher.scheme;

/// The encrypted url scheme this package handles.
pub const secure_scheme = Fetcher.secure_scheme;

/// The port an `ldap://` url uses when it names none.
pub const default_port = Fetcher.default_port;

/// The port an `ldaps://` url uses when it names none.
pub const secure_default_port = Fetcher.secure_default_port;

test {
    _ = Fetcher;
    _ = ber;
    _ = filter;
    _ = target;
    _ = ldif;
    _ = message;
    _ = Session;
    _ = @import("zurl-ldap/session_test.zig");
}

test "the package names both schemes and the two ports curl dials" {
    try std.testing.expectEqualStrings("ldap", scheme);
    try std.testing.expectEqualStrings("ldaps", secure_scheme);
    try std.testing.expectEqual(@as(?u16, 389), default_port);
    try std.testing.expectEqual(@as(?u16, 636), secure_default_port);
}
