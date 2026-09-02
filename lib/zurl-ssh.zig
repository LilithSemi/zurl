//! zurl's SSH transport layer, RFC 4253.
//!
//! **This package registers no url scheme, and nothing in it is reachable
//! from the command line.** It is the bottom of an SSH client and only the
//! bottom. There is no authentication here, no channel, and no SFTP. A
//! later task builds each of those on top of `Transport`, and only the
//! last one of them turns a `scp` or `sftp` url into a transfer.
//!
//! One protocol, one module. It imports `zurl-core` and `zurl-net` and
//! nothing else of ours, the way every other protocol package does, and
//! **it does not import `zurl`**: a protocol package that imported the
//! front package could not be left out of a build that does not want it.
//!
//! **What this build speaks, and what it refuses by name:**
//!
//! | category | supported | refused |
//! | --- | --- | --- |
//! | key exchange | `curve25519-sha256`, `curve25519-sha256@libssh.org` | everything else |
//! | host key | `ssh-ed25519` | `ssh-rsa`, `rsa-sha2-256`, `rsa-sha2-512`, `ssh-dss`, the three `ecdsa-sha2-nistp*` |
//! | cipher | `aes256-gcm@openssh.com`, `chacha20-poly1305@openssh.com` | everything else |
//! | MAC | implicit in both ciphers | every named MAC |
//! | compression | `none` | `zlib`, `zlib@openssh.com` |
//!
//! RSA is refused because `std.crypto` carries no RSA signer.
//! `std.crypto.Certificate` verifies RSA for TLS and exposes nothing a
//! host key check could call. A client that accepted an RSA host key and
//! did not verify the signature would be worse than one that refuses, so
//! `zurl_ssh.hostkey.refusalFor` names each refused algorithm and says
//! why.
//!
//! **Host key trust is the caller's decision and there is no way to skip
//! it.** Verifying the server's signature over the exchange hash proves
//! that the peer holds the private key for the key it presented. It proves
//! nothing about whether that key belongs to the host the user asked for.
//! `Transport.Options.verifier` has no default value, so a caller that
//! forgets it does not compile, and this package ships no "accept
//! anything" verifier. `known_hosts` parsing is the later task that fills
//! the shape in.
//!
//! A caller wires a transport over any reader and writer:
//!
//!     var transport: zurl_ssh.Transport = undefined;
//!     try transport.init(gpa, io, channel, .{
//!         .peer = .{ .host = host, .port = port },
//!         .verifier = my_known_hosts_verifier,
//!     });
//!     defer transport.deinit();
//!     try transport.handshake();
//!     try transport.send(payload);

const std = @import("std");

/// One SSH connection: the identification exchange, the key exchange, and
/// the packet stream after it.
pub const Transport = @import("zurl-ssh/Transport.zig");

/// The SSH data types of RFC 4251 section 5, and the first-match
/// negotiation rule.
pub const wire = @import("zurl-ssh/wire.zig");

/// The identification string exchange, RFC 4253 section 4.2.
pub const version = @import("zurl-ssh/version.zig");

/// The binary packet protocol and its padding rules, RFC 4253 section 6.
pub const packet = @import("zurl-ssh/packet.zig");

/// The two AEAD packet ciphers and the framing each one puts around a
/// packet.
pub const cipher = @import("zurl-ssh/cipher.zig");

/// The transport message numbers, and the four messages a transport
/// answers on its own.
pub const messages = @import("zurl-ssh/messages.zig");

/// `SSH_MSG_KEXINIT`, the algorithm lists this build offers, and the
/// negotiation of RFC 4253 section 7.1.
pub const algorithms = @import("zurl-ssh/algorithms.zig");

/// `curve25519-sha256`, the exchange hash, and the key derivation.
pub const kex = @import("zurl-ssh/kex.zig");

/// The host key: what this build verifies, what it refuses by name, and
/// where the trust decision is made.
pub const hostkey = @import("zurl-ssh/hostkey.zig");

/// RFC 4252 over one `Transport`: the service request, the methods, and
/// the banner.
pub const Authenticator = @import("zurl-ssh/Authenticator.zig");

/// The messages of RFC 4252, and the blob a `publickey` attempt signs.
pub const userauth = @import("zurl-ssh/userauth.zig");

/// The `openssh-key-v1` private key format, and the signature a
/// `publickey` attempt sends.
pub const privatekey = @import("zurl-ssh/privatekey.zig");

/// Finds a private key on disk, the way curl and OpenSSH find one.
pub const keyfile = @import("zurl-ssh/keyfile.zig");

/// The connection protocol messages of RFC 4254. Pure bytes.
pub const connection = @import("zurl-ssh/connection.zig");

/// One session channel: the open, the flow control, `exec` and
/// `subsystem`, and the exit status.
pub const Channel = @import("zurl-ssh/Channel.zig");

/// `known_hosts`, and the two ways curl pins a host key on the command
/// line.
pub const knownhosts = @import("zurl-ssh/knownhosts.zig");

/// One SSH connection end to end: the dial, the handshake, the login, and
/// one channel.
pub const Client = @import("zurl-ssh/Client.zig");

/// The loopback RFC 4253 server this package's tests use.
///
/// Exported for the same reason `zurl_http.test_server` is: a later task
/// needs an SSH peer for its own tests, and a second copy of this fixture
/// would drift from the one the transport is tested against. **It is a
/// fixture and not a product, and nothing but a test may use it.** In
/// particular the verifier it carries trusts whatever key it is shown,
/// which is exactly what no real caller may do.
pub const test_server = @import("zurl-ssh/test_server.zig");

test {
    _ = Transport;
    _ = wire;
    _ = version;
    _ = packet;
    _ = cipher;
    _ = messages;
    _ = algorithms;
    _ = kex;
    _ = hostkey;
    _ = Authenticator;
    _ = userauth;
    _ = privatekey;
    _ = keyfile;
    _ = connection;
    _ = Channel;
    _ = knownhosts;
    _ = Client;
    _ = test_server;
    _ = @import("zurl-ssh/handshake_test.zig");
    _ = @import("zurl-ssh/auth_test.zig");
    _ = @import("zurl-ssh/channel_test.zig");
}

test "the package names only the algorithms it can run" {
    try std.testing.expectEqual(@as(usize, 2), algorithms.supported_kex.len);
    try std.testing.expectEqual(@as(usize, 1), algorithms.offered_host_key.len);
    try std.testing.expectEqual(@as(usize, 2), algorithms.offered_cipher.len);
    try std.testing.expectEqual(@as(usize, 0), algorithms.offered_mac.len);
    try std.testing.expectEqual(@as(usize, 1), algorithms.offered_compression.len);
    try std.testing.expectEqualStrings("none", algorithms.offered_compression[0]);
}
