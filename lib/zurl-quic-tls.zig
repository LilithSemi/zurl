//! The TLS 1.3 handshake of QUIC, RFC 9001.
//!
//! `zurl-quic` reads and writes QUIC packets, and it holds the key
//! derivation of RFC 9001 section 5 with the appendix A vectors passing
//! byte for byte. What it has no way to produce is a **secret**: a secret
//! comes from a TLS handshake, and that package has none. This one runs
//! the handshake and hands the secrets over.
//!
//! ## The two halves, and the line between them
//!
//! ```text
//!    zurl-tls/Client.zig            this package             zurl-quic
//!    ------------------             ------------             ---------
//!    certificate chain      <--     Handshake.zig    -->      protection.Keys
//!    host and address walk          schedule.zig             transport_parameters
//!    CertificateVerify              CryptoStream.zig         packet, frame
//!    key exchange                   Session.zig
//!    ALPN encode and check
//! ```
//!
//! **Nothing here decides trust.** The certificate chain walk, the host
//! name and address walk, the trust store, and the CertificateVerify
//! signature all run in `zurl_tls.Client.quic`, which is the vendored TLS
//! client's own code in the vendored TLS client's own file. This package
//! holds no certificate code at all: the rules live in one place in the
//! vendored client, and TLS over TCP and TLS over QUIC call the same
//! function to apply them.
//!
//! The Diffie-Hellman is the vendored client's `KeyShare` for the same
//! reason, and the ALPN offer goes out through the vendored client's own
//! encoder and comes back through its own checker.
//!
//! ## Why this is not a patch to the vendored client
//!
//! `zurl_tls.Client.init` reads TLS records and it produces a record
//! cipher. QUIC has neither. RFC 9001 section 4 puts the handshake
//! messages in CRYPTO frames, at three encryption levels, and asks TLS for
//! a secret at each one. Turning `init` into something that does both
//! would replace the loop that reads records, which is most of that
//! function, and the copy has to stay a re-syncable delta of upstream.
//! See `.superpowers/sdd/p4-quic-tls-report.md` for the whole argument.
//!
//! ## What is here
//!
//! | File | Owns |
//! | --- | --- |
//! | `schedule.zig` | The TLS 1.3 key schedule, RFC 8446 section 7.1, and the QUIC key sets under it |
//! | `CryptoStream.zig` | CRYPTO frame reassembly, RFC 9000 section 19.6 |
//! | `Handshake.zig` | The message state machine, RFC 9001 section 4 |
//! | `Session.zig` | The keys of every level, the packet number spaces, and the key update of RFC 9001 section 6 |
//!
//! ## What is not here
//!
//! No socket, no datagram, no loss recovery, no congestion control, no
//! HTTP/3 framing, and no QPACK. Nothing in this package is reachable from
//! the command line.
//!
//! ## The rule a reader should know
//!
//! **A nonce must never repeat under one key.** RFC 9001 section 5.3
//! builds the AEAD nonce from the packet protection IV and the packet
//! number, and the IV is fixed for a key. So two packets under one key
//! with one packet number would share a nonce, and that gives away the
//! authentication key. `Session.nextPacketNumber` is the only place a
//! packet number is produced, and it is where the bound lives.

const std = @import("std");

/// The TLS 1.3 key schedule and the QUIC key sets it feeds.
pub const schedule = @import("zurl-quic-tls/schedule.zig");

/// One encryption level's CRYPTO stream, reassembled from frames that may
/// arrive out of order.
pub const CryptoStream = @import("zurl-quic-tls/CryptoStream.zig");

/// The keys of every level, the packet number spaces, and the key update.
pub const Session = @import("zurl-quic-tls/Session.zig");

/// The TLS 1.3 handshake of a QUIC client.
pub const Handshake = @import("zurl-quic-tls/Handshake.zig");

test {
    _ = schedule;
    _ = CryptoStream;
    _ = Session;
    _ = Handshake;
    _ = @import("zurl-quic-tls/handshake_test.zig");
}

test "the package offers only the three suites RFC 9001 gives header protection" {
    const quic = @import("zurl-quic");
    try std.testing.expectEqual(@as(usize, 3), Handshake.offered_suites.len);
    const secret = [_]u8{0x01} ** 48;
    for (Handshake.offered_suites) |suite| {
        // Each one has a header protection rule in RFC 9001 sections
        // 5.4.3 and 5.4.4, which is what a header mask needs.
        const keys: quic.protection.Keys = .fromSecret(suite, secret[0..suite.hash().secretLen()]);
        try std.testing.expectEqual(suite.headerKeyLen(), keys.headerKeySlice().len);
    }
}
