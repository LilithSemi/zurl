//! zurl's `mqtt://` and `mqtts://` protocols, MQTT 3.1.1.
//!
//! One protocol, one module. A build that does not want a message broker
//! leaves this module out and loses nothing else, and a program outside
//! this repository takes this module, `zurl-core`, and `zurl-net` and gets
//! both schemes with no other part of zurl.
//!
//! **One package owns both schemes.** MQTT 3.1.1 names the packets and
//! `mqtts` changes none of them: it puts the same ones inside TLS, on port
//! 8883 against 1883. That is the same reason `zurl.protocol.builtins`
//! gives `http` and `https` one vtable.
//!
//! **This package does not import `zurl`, and it never will**: the front
//! package imports no protocol package, and a protocol package that
//! imported it back could not be left out. `Fetcher.protocol` takes the
//! front package's namespace as a comptime parameter instead, so the
//! dispatch entry is built against the shape and not against an import.
//!
//! A caller wires it in four lines:
//!
//!     const fetcher = try zurl_mqtt.Fetcher.create(gpa, io);
//!     defer fetcher.destroy();
//!     try client.registerProtocol(fetcher.protocol(zurl));
//!     try client.registerProtocol(fetcher.secureProtocol(zurl));
//!
//! `zurl.Client.registerProtocol` teaches `zurl_core.url` the scheme at
//! the same time, so `mqtt://broker/sensor/1` parses after that call.
//!
//! ## What this package is
//!
//! MQTT is a binary protocol, and it shares the hazard `zurl-ldap` names:
//! a count in front of a value is a number the **peer** chose that decides
//! how many bytes this process then reads. `zurl-ssh` and `zurl-ldap` have
//! the same shape and each answers it in its own file. Here the answer is
//! `varint.zig`, which is its own module for the reason
//! `zurl-ldap/ber.zig` is: the bound belongs where the number is decoded,
//! not where it is used.
//!
//! ## The three rules a reader should know
//!
//! **A length is bounded before it is used, never after.** MQTT 3.1.1
//! section 2.2.3 writes the remaining length as one to four bytes, and
//! four bytes name 268 435 455 octets. `varint.zig` refuses a fifth
//! continuation byte, refuses a run that ends unfinished, and refuses a
//! length with two spellings. `Session.receive` then checks the decoded
//! number against `Session.max_packet_bytes` **before** it allocates,
//! because a legal four byte length can still ask for a quarter of a
//! gigabyte.
//!
//! **This package needs no line gate, and `topic.zig` says why.** MQTT
//! counts the octets in front of every string, so a CR, an LF, or a space
//! in a topic or a password is data on the wire and can end nothing.
//! `zurl_net.line.write` is the gate every line protocol here calls, and
//! this one calls it nowhere. What `topic.zig` does refuse is the two
//! things that change what a topic **means**: a NUL, which MQTT 3.1.1
//! section 1.5.3 forbids in a string, and a `+` or a `#` in a topic this
//! package publishes to, which section 4.7 makes a wildcard. curl sends
//! all three and exits 0, measured.
//!
//! **The output is curl's own format, measured.** A subscribed message
//! reaches standard output as the whole variable header of its PUBLISH:
//! the two byte topic count, the topic, and then the payload. That is what
//! curl 8.21.0 wrote, byte for byte, and it is the only format an MQTT url
//! has. See `Fetcher.runSubscribe`.
//!
//! ## What this does not do
//!
//! No QoS above zero, no retained message, no will, no MQTT 5, and no
//! proxy. A subscribe reads a named number of messages and ends, where
//! curl's runs until somebody stops it. See `Fetcher` for each one, and
//! for what was measured beside it.

const std = @import("std");

/// Runs one MQTT transfer, plain or encrypted, and builds the two dispatch
/// entries that register it.
pub const Fetcher = @import("zurl-mqtt/Fetcher.zig");

/// MQTT 3.1.1's variable byte integer. **The file that bounds the one
/// number a peer sends that decides how many bytes this process reads.**
/// Pure bytes, and it knows no packet type at all.
pub const varint = @import("zurl-mqtt/varint.zig");

/// The control packets this package builds and reads.
pub const packet = @import("zurl-mqtt/packet.zig");

/// The topic a url names. **The file that holds this package's injection
/// rule**, and the argument for why the rule is what it is.
pub const topic = @import("zurl-mqtt/topic.zig");

/// One dialogue: the packet framing off a socket, and the bound on a
/// remaining length a peer chose.
pub const Session = @import("zurl-mqtt/Session.zig");

/// The loopback MQTT 3.1.1 broker this package's tests use.
///
/// Exported for the same reason `zurl_http.test_server` is: the end to end
/// tests of the command line need a broker, and a second copy of this
/// fixture would drift from the one the package tests itself with. It is a
/// fixture and not a product, and nothing but a test may use it. It speaks
/// no TLS, so it serves `mqtt` and never `mqtts`.
pub const test_server = @import("zurl-mqtt/test_server.zig");

/// The plain url scheme this package handles.
pub const scheme = Fetcher.scheme;

/// The encrypted url scheme this package handles.
pub const secure_scheme = Fetcher.secure_scheme;

/// The port an `mqtt://` url uses when it names none.
pub const default_port = Fetcher.default_port;

/// The port an `mqtts://` url uses when it names none.
pub const secure_default_port = Fetcher.secure_default_port;

/// How many messages a subscribe reads when nobody names a number.
pub const default_message_count = Fetcher.default_message_count;

/// The most messages `--mqtt-messages` may ask for.
pub const max_message_count = Fetcher.max_message_count;

/// How many bytes of client identifier `--mqtt-client-id` may carry.
pub const max_client_id_bytes = Fetcher.max_client_id_bytes;

test {
    _ = Fetcher;
    _ = varint;
    _ = packet;
    _ = topic;
    _ = Session;
    _ = @import("zurl-mqtt/session_test.zig");
}

test "the package names both schemes and the two ports curl dials" {
    try std.testing.expectEqualStrings("mqtt", scheme);
    try std.testing.expectEqualStrings("mqtts", secure_scheme);
    try std.testing.expectEqual(@as(?u16, 1883), default_port);
    try std.testing.expectEqual(@as(?u16, 8883), secure_default_port);
}
