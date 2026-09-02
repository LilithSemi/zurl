//! HTTP/3, RFC 9114: the frame layer, the settings, the unidirectional
//! stream types, and the connection rules that join them.
//!
//! This package is to HTTP/3 what `zurl-h2` is to HTTP/2. It turns bytes
//! into frames and back, and it says which frame may appear where. It
//! opens no socket, it holds no QUIC connection, it allocates nothing, and
//! it does no field compression: `zurl-qpack` is the codec that turns a
//! field section into fields, and `zurl-http/h3.zig` is the engine that
//! joins the two to a QUIC connection.
//!
//! ## Why this one imports `zurl-quic` when `zurl-h2` imports nothing
//!
//! **Because RFC 9114 does not define a number format, it uses QUIC's.**
//! Section 7.1 says every length and every identifier in an HTTP/3 frame
//! is "a variable-length integer, as described in Section 16 of
//! [QUIC-TRANSPORT]", and the same holds for a setting identifier and for
//! a unidirectional stream type. A second copy of that coder here would be
//! a second place for the 62 bit bound and the minimal-encoding rule to
//! drift from the one the packet layer already passes RFC 9000 appendix A
//! with. So `zurl_quic.varint` is the coder, and there is one of it.
//!
//! `zurl-qpack` made the other choice and restated its integer coder, and
//! that was right there for the opposite reason: RFC 9204's integer is
//! **not** QUIC's. It is HPACK's prefixed integer with a wider ceiling, so
//! sharing would have meant one coder answering to two specifications.
//!
//! Nothing else comes in. No `zurl-core`, no url rule, no error taxonomy,
//! no trust root. The engine above is what maps a fault here onto
//! `zurl_core.Error`.
//!
//! ## What a reader should know
//!
//! **A frame length is a number the peer chose and nothing here is sized
//! from one.** `frame.readHeader` reads the type and the length and stops.
//! A `DATA` frame is a response body and may be gigabytes, so the caller
//! streams it; the small frames have payload readers here, and each of
//! those is given a payload the caller already bounded.
//!
//! **An unknown frame is stepped over and a reserved one is expected.**
//! RFC 9114 sections 7.2.8 and 9 have a peer send `0x1f * N + 0x21` on
//! purpose, so a build that closed the connection over one would refuse a
//! conformant peer. The four HTTP/2 frame types are the exception, and
//! they are refused.
//!
//! ## A request, end to end
//!
//! ```text
//!   client                                             server
//!   ------                                             ------
//!   uni stream 2:  0x00 SETTINGS ...        -->
//!   uni stream 6:  0x02 (QPACK encoder)     -->
//!   uni stream 10: 0x03 (QPACK decoder)     -->
//!   bidi stream 0: HEADERS [DATA...] FIN    -->
//!                                           <--  uni stream 3:  0x00 SETTINGS
//!                                           <--  bidi stream 0: HEADERS DATA... FIN
//! ```

const std = @import("std");

/// The RFC this package implements.
pub const rfc = "RFC 9114";

/// The ALPN protocol name of HTTP/3. RFC 9114 section 3.1.
///
/// **This is the only name that reaches an HTTP/3 server**, and it goes in
/// the TLS client hello of the QUIC handshake. A TLS session over TCP must
/// never offer it: a peer cannot speak HTTP/3 over a stream socket, and a
/// peer that chose it there would leave the connection with no protocol
/// either side can use.
pub const alpn_name = "h3";

/// The frame layer, RFC 9114 section 7.
pub const frame = @import("zurl-h3/frame.zig");

/// The `SETTINGS` frame payload, RFC 9114 section 7.2.4.
pub const settings = @import("zurl-h3/settings.zig");
pub const Settings = settings.Settings;

/// The unidirectional stream types, RFC 9114 section 6.2.
pub const stream_type = @import("zurl-h3/stream_type.zig");

/// The application error codes, RFC 9114 section 8.1 and RFC 9204
/// section 6.
pub const error_code = @import("zurl-h3/error_code.zig");
pub const ErrorCode = error_code.Code;

/// Which stream carries what, which frame may appear where, and the order
/// the first frames must arrive in.
pub const Connection = @import("zurl-h3/Connection.zig");

test {
    _ = frame;
    _ = settings;
    _ = stream_type;
    _ = error_code;
    _ = Connection;
}

test "the package names the RFC it implements and the name it offers in ALPN" {
    try std.testing.expectEqualStrings("RFC 9114", rfc);
    try std.testing.expectEqualStrings("h3", alpn_name);
}

test "one control stream carries SETTINGS first, and a request stream carries a message" {
    // The two rules a peer breaks first, in the two lines it takes to
    // break them.
    var c: Connection = .init(.client, .{});
    try std.testing.expectError(error.MissingSettings, c.onControlFrame(.goaway));

    var m: Connection.Message = .{};
    try std.testing.expectError(error.FrameUnexpected, m.onFrame(.data, false));
}
