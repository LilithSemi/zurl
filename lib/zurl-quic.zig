//! The packet and frame layer of QUIC, RFC 9000, and the keys RFC 9001
//! fixes in its own text.
//!
//! **This is a codec and nothing else.** It reads and writes the bytes of
//! a QUIC packet: the variable-length integer, the two header forms, the
//! packet number and its truncation, every frame of RFC 9000 section 19,
//! and the transport parameters of section 18. It opens no socket, it
//! allocates nothing, and it keeps no connection state.
//!
//! It imports no other package of ours, for the reason `zurl-hpack` and
//! `zurl-h2` import none: a codec with a published specification and
//! published test vectors needs no url rule, no error taxonomy, and no
//! trust root. The engine that sits over it is what maps a fault here
//! onto `zurl_core.Error`.
//!
//! ## What this package does not do
//!
//! **There is no connection here.** No handshake, no loss recovery, no
//! congestion control, no flow control accounting, no stream state
//! machine, no path validation, and no timer. Those are the layers above,
//! and each is its own piece of work.
//!
//! **There is no TLS here.** QUIC's key schedule comes from the TLS 1.3
//! handshake, and this package has none. What it does have is the part
//! that needs no handshake at all:
//!
//! - `protection.Keys` is the shape a key set has: one AEAD suite, a
//!   packet protection key, an IV, and a header protection key. It seals,
//!   it opens, and it makes a header mask. The TLS task builds one with
//!   `protection.Keys.fromSecret` and a secret TLS produced.
//! - `initial` builds the one key set that needs no handshake. RFC 9001
//!   section 5.2 derives the Initial keys from the client's first
//!   Destination Connection ID with a salt written into the RFC, so a
//!   client can protect its first packet before it has spoken to anyone.
//!   It also holds the fixed Retry integrity key of section 5.8.
//!
//! So the TLS task adds secrets, not machinery. See `protection.zig`.
//!
//! ## The one rule a reader should know
//!
//! **Every length in a QUIC packet is a number the peer chose, and a
//! variable-length integer can name 2^62.** No function here allocates,
//! so no such number can ask this process for memory. Each one is checked
//! against the bytes that really arrived, in `Cursor.takeVarintLength`,
//! before any slice is made. A decoded frame borrows the datagram it came
//! in and copies none of it.
//!
//! ## Test vectors
//!
//! `varint` and `packet` carry the worked examples of RFC 9000 appendix
//! A. `rfc9001_test.zig` carries appendix A of RFC 9001: the Initial
//! keys, the client Initial packet, the server Initial packet, the Retry
//! integrity tag, and the ChaCha20-Poly1305 short header packet, each
//! checked byte for byte.

const std = @import("std");

/// QUIC's variable-length integer, RFC 9000 section 16. **The number
/// format under every other file here.**
pub const varint = @import("zurl-quic/varint.zig");

/// A read position inside one datagram. **The file where a length the
/// peer chose meets the bytes that really arrived.**
pub const Cursor = @import("zurl-quic/Cursor.zig");

/// Packet headers, RFC 9000 section 17. Both forms, the version, the
/// connection ids, and the packet number with its truncation.
pub const packet = @import("zurl-quic/packet.zig");

/// The frames of RFC 9000 section 19, read and written.
pub const frame = @import("zurl-quic/frame.zig");

/// The transport parameters of RFC 9000 section 18.
pub const transport_parameters = @import("zurl-quic/transport_parameters.zig");

/// Packet protection, RFC 9001 section 5. **The shape the TLS task fills
/// in**: a suite, a key, an IV, and a header protection key.
pub const protection = @import("zurl-quic/protection.zig");

/// Header protection, RFC 9001 section 5.4. The sample, the mask, and the
/// two directions it is applied in.
pub const header_protection = @import("zurl-quic/header_protection.zig");

/// The keys QUIC version 1 writes into its own specification: the Initial
/// keys of RFC 9001 section 5.2 and the Retry integrity key of section
/// 5.8. **The one key set that needs no handshake.**
pub const initial = @import("zurl-quic/initial.zig");

/// The units and the constants of RFC 9002, and the three packet number
/// spaces. **Time is a number the caller supplies**, so nothing here
/// reads a clock.
pub const loss = @import("zurl-quic/loss.zig");

/// The round-trip time estimate of RFC 9002 section 5.
pub const Rtt = @import("zurl-quic/Rtt.zig");

/// NewReno congestion control, RFC 9002 section 7.
pub const Congestion = @import("zurl-quic/Congestion.zig");

/// The packet numbers received in one space, and the `ACK` frame that
/// reports them. RFC 9000 section 13.2.
pub const AckRanges = @import("zurl-quic/AckRanges.zig");

/// Loss detection and the sending gate, RFC 9002. **The file that holds
/// the three packet number spaces apart.**
pub const Recovery = @import("zurl-quic/Recovery.zig");

/// The transport error codes of RFC 9000 section 20.1, and the name each
/// one carries.
pub const transport_error = @import("zurl-quic/transport_error.zig");

/// Stream identifiers, the two stream state machines, and the flow
/// control counter. RFC 9000 sections 2, 3, and 4.
pub const stream = @import("zurl-quic/stream.zig");

/// `STREAM` frame reassembly: the bytes of one receiving half put back in
/// order, under a bound for every number the peer chose.
pub const Reassembly = @import("zurl-quic/Reassembly.zig");

/// The bytes of one sending half that are written and not yet
/// acknowledged, and the ranges a loss put back in the queue.
pub const SendBuffer = @import("zurl-quic/SendBuffer.zig");

/// The stream table of one connection: both levels of flow control, the
/// stream limits, and the frames that carry them. **The layer between
/// the frames and HTTP/3.**
pub const Streams = @import("zurl-quic/Streams.zig");

test {
    _ = varint;
    _ = Cursor;
    _ = packet;
    _ = frame;
    _ = transport_parameters;
    _ = protection;
    _ = header_protection;
    _ = initial;
    _ = loss;
    _ = Rtt;
    _ = Congestion;
    _ = AckRanges;
    _ = Recovery;
    _ = transport_error;
    _ = stream;
    _ = Reassembly;
    _ = SendBuffer;
    _ = Streams;
    _ = @import("zurl-quic/rfc9001_test.zig");
}

test "the package names QUIC version 1 and the two bounds under everything" {
    try std.testing.expectEqual(@as(u32, 1), @intFromEnum(packet.Version.v1));
    try std.testing.expectEqual(@as(u64, (1 << 62) - 1), varint.max_value);
    try std.testing.expectEqual(@as(usize, 20), packet.max_connection_id_len);
}
