//! `SSH_MSG_KEXINIT` and the negotiation of RFC 4253 section 7.1. Pure
//! bytes, and testable with a table.
//!
//! **What this build offers, and nothing else:**
//!
//! | category | offered |
//! | --- | --- |
//! | key exchange | `curve25519-sha256`, `curve25519-sha256@libssh.org` |
//! | host key | `ssh-ed25519` |
//! | cipher | `aes256-gcm@openssh.com`, `chacha20-poly1305@openssh.com` |
//! | MAC | nothing |
//! | compression | `none` |
//!
//! **The MAC list is empty on purpose.** Both offered ciphers are AEAD, so
//! the MAC is part of the cipher. OpenSSH's `kex_choose_conf` skips MAC
//! negotiation whenever the chosen cipher authenticates, and this client
//! offers no cipher that does not. A MAC name in this list would be a name
//! this build cannot compute.
//!
//! **The compression list is `none` only.** A compressor between the
//! plaintext and the cipher lets the length of a packet leak what is
//! inside it, and zurl has nothing that needs the bytes back.
//!
//! **`kex-strict-c-v00@openssh.com` is offered, and it is not an
//! algorithm.** It is the marker of OpenSSH's strict key exchange, which
//! closes CVE-2023-48795. Without it a peer in the middle can drop packets
//! from the front of the session and the sequence numbers still line up,
//! because nothing checks them until the first key is in place. With it,
//! sequence numbers go back to zero at every `SSH_MSG_NEWKEYS` and no
//! `IGNORE`, `DEBUG`, or `UNIMPLEMENTED` may appear during a key exchange.
//! `zurl_ssh.Transport` applies both rules.
//!
//! **A server that does not name the marker gets AES-GCM.** The marker is
//! the server's to send, and a server that sends none leaves this side
//! with the second half of the answer: the attack works against
//! `chacha20-poly1305@openssh.com` and against CBC with Encrypt-then-MAC,
//! and it does not work against `aes256-gcm@openssh.com`, whose nonce is a
//! counter of this side's own rather than the packet sequence number. A
//! deleted packet puts that counter out of step and the very next tag
//! fails.
//!
//! The choice has to be made in the offer and not after the server's
//! answer. RFC 4253 section 7.1 makes the client's order the one that
//! decides, so a client that put `chacha20-poly1305@openssh.com` first and
//! then picked the second name for itself would pick a cipher the server
//! did not pick, and the connection would fail. Naming AES-GCM first is
//! what makes both sides choose it.
//!
//! **What it costs.** ChaCha20-Poly1305 is faster than AES-GCM on a
//! machine with no AES instructions, so a transfer on such hardware is
//! slower. Nothing is refused: a server that offers
//! `chacha20-poly1305@openssh.com` alone still gets it, and
//! `zurl_ssh.Transport` still closes the injection window for it.
//!
//! **The negotiation walks the client's list.** RFC 4253 section 7.1 makes
//! the chosen algorithm the first one on the client's list that the server
//! also names. A search that walked the server's list would let a server
//! pick the weakest thing the client can do. See `wire.firstMatch`.
//!
//! What this module does not own: no key exchange maths, and no packet.
//! `zurl_ssh.kex` does the maths and `zurl_ssh.packet` frames.

const std = @import("std");

const cipher = @import("cipher.zig");
const hostkey = @import("hostkey.zig");
const messages = @import("messages.zig");
const wire = @import("wire.zig");

/// RFC 8731 section 3.
pub const curve25519_sha256 = "curve25519-sha256";

/// The name the same method had before RFC 8731 gave it one. Servers
/// still offer it, so this build still names it.
pub const curve25519_sha256_libssh = "curve25519-sha256@libssh.org";

/// The marker a client sends to ask for strict key exchange.
pub const strict_kex_client = "kex-strict-c-v00@openssh.com";

/// The marker a server sends to agree to it.
pub const strict_kex_server = "kex-strict-s-v00@openssh.com";

/// The key exchange methods this build can run.
pub const KexAlgorithm = enum {
    /// Both names above run this one. RFC 8731 section 3 says they are
    /// the same method.
    curve25519_sha256,
};

/// The key exchange names this build may select, in preference order.
pub const supported_kex = [_][]const u8{ curve25519_sha256, curve25519_sha256_libssh };

/// The key exchange names this build puts on the wire.
///
/// The strict key exchange marker rides here and is never selectable. A
/// server never offers the client marker back, so `wire.firstMatch` over
/// `supported_kex` can never return it.
pub const offered_kex = [_][]const u8{
    curve25519_sha256,
    curve25519_sha256_libssh,
    strict_kex_client,
};

/// The host key names this build can verify, in preference order.
pub const offered_host_key = [_][]const u8{"ssh-ed25519"};

/// The ciphers this build can run, in preference order.
///
/// **AES-GCM comes first because of CVE-2023-48795.** See the module
/// comment.
pub const offered_cipher = [_][]const u8{
    "aes256-gcm@openssh.com",
    "chacha20-poly1305@openssh.com",
};

/// The MAC names this build offers, which is none. See the module
/// comment.
pub const offered_mac = [_][]const u8{};

/// The compression names this build offers.
pub const offered_compression = [_][]const u8{"none"};

/// How many bytes of cookie a `SSH_MSG_KEXINIT` carries, RFC 4253
/// section 7.1.
pub const cookie_bytes = 16;

/// Why a `SSH_MSG_KEXINIT` was not read.
pub const ParseError = wire.ReadError || error{
    /// The payload is not a `SSH_MSG_KEXINIT`.
    WrongMessage,
};

/// The ten name-lists and the two fields behind them, RFC 4253
/// section 7.1.
///
/// Every list points into the payload it was read from.
pub const Kexinit = struct {
    cookie: [cookie_bytes]u8,
    kex: wire.NameList,
    host_key: wire.NameList,
    cipher_client_to_server: wire.NameList,
    cipher_server_to_client: wire.NameList,
    mac_client_to_server: wire.NameList,
    mac_server_to_client: wire.NameList,
    compression_client_to_server: wire.NameList,
    compression_server_to_client: wire.NameList,
    languages_client_to_server: wire.NameList,
    languages_server_to_client: wire.NameList,
    /// Whether a guessed key exchange packet follows this one.
    first_kex_packet_follows: bool,
};

/// Reads a `SSH_MSG_KEXINIT` payload.
///
/// The reserved `uint32` at the end is read and not checked. RFC 4253
/// section 7.1 sets it to zero and says nothing about a peer that does
/// not, and a client that refused a non-zero value would refuse a server
/// that a later extension made legal.
pub fn parseKexinit(payload: []const u8) ParseError!Kexinit {
    var r: wire.Reader = .init(payload);
    if (try r.byte() != @intFromEnum(messages.Id.kexinit)) return error.WrongMessage;
    const cookie = try r.take(cookie_bytes);

    // Read one field at a time, in wire order. A struct literal would
    // read the same ten lists, and this file must not depend on the order
    // a literal's fields are evaluated in.
    const kex = try r.nameList();
    const host_key = try r.nameList();
    const cipher_client_to_server = try r.nameList();
    const cipher_server_to_client = try r.nameList();
    const mac_client_to_server = try r.nameList();
    const mac_server_to_client = try r.nameList();
    const compression_client_to_server = try r.nameList();
    const compression_server_to_client = try r.nameList();
    const languages_client_to_server = try r.nameList();
    const languages_server_to_client = try r.nameList();
    const first_kex_packet_follows = try r.boolean();
    _ = try r.uint32();

    return .{
        .cookie = cookie[0..cookie_bytes].*,
        .kex = kex,
        .host_key = host_key,
        .cipher_client_to_server = cipher_client_to_server,
        .cipher_server_to_client = cipher_server_to_client,
        .mac_client_to_server = mac_client_to_server,
        .mac_server_to_client = mac_server_to_client,
        .compression_client_to_server = compression_client_to_server,
        .compression_server_to_client = compression_server_to_client,
        .languages_client_to_server = languages_client_to_server,
        .languages_server_to_client = languages_server_to_client,
        .first_kex_packet_follows = first_kex_packet_follows,
    };
}

/// Builds this build's own `SSH_MSG_KEXINIT` into `out`.
///
/// The result points into `out`. It goes into the exchange hash as `I_C`,
/// exactly as it is here, so a caller must keep it until the exchange
/// hash is built.
///
/// **The cookie must be 16 random bytes.** RFC 4253 section 7.1 says so,
/// and the reason is that both cookies go into the exchange hash. A
/// predictable cookie lets a peer fix part of a hash the other side signs.
/// This module draws no entropy, so the caller passes the cookie in.
pub fn writeKexinit(out: []u8, cookie: [cookie_bytes]u8) wire.WriteError![]u8 {
    var w: wire.Writer = .init(out);
    try w.byte(@intFromEnum(messages.Id.kexinit));
    try w.bytes(&cookie);
    try w.nameList(&offered_kex);
    try w.nameList(&offered_host_key);
    try w.nameList(&offered_cipher);
    try w.nameList(&offered_cipher);
    try w.nameList(&offered_mac);
    try w.nameList(&offered_mac);
    try w.nameList(&offered_compression);
    try w.nameList(&offered_compression);
    try w.nameList(&.{});
    try w.nameList(&.{});
    // This client never guesses. A guess that is wrong costs a packet
    // that both sides must then agree to throw away, and it saves one
    // round trip only when the guess is right.
    try w.boolean(false);
    try w.uint32(0);
    return w.written();
}

/// How many bytes this build's own `SSH_MSG_KEXINIT` needs.
///
/// A comptime value, so a caller sizes its buffer with no guess. The
/// lists are all constants of this module.
pub const kexinit_bytes = blk: {
    var counter: [1024]u8 = undefined;
    const built = writeKexinit(&counter, @splat(0)) catch unreachable;
    break :blk built.len;
};

/// What this build refuses, and why.
pub const Refusal = struct {
    algorithm: []const u8,
    reason: []const u8,
};

/// The first name in `list` that this build refuses by name, with its
/// reason.
///
/// **This turns a blank negotiation failure into an answer.** A server
/// that offers `ssh-rsa` alone would otherwise give a user nothing but
/// "no common host key algorithm". See `hostkey.refusalFor`.
pub fn hostKeyRefusal(list: wire.NameList) ?Refusal {
    var it = list.iterator();
    while (it.next()) |candidate| {
        if (hostkey.refusalFor(candidate)) |reason| {
            return .{ .algorithm = candidate, .reason = reason };
        }
    }
    return null;
}

/// Why a negotiation found nothing.
pub const NegotiateError = error{
    /// No key exchange method in common. This build offers
    /// `curve25519-sha256` and its older name.
    NoCommonKexAlgorithm,
    /// No host key algorithm in common. `hostKeyRefusal` names the reason
    /// when the server offered one this build refuses on purpose.
    NoCommonHostKeyAlgorithm,
    /// No cipher in common, in one direction or the other.
    NoCommonCipher,
    /// The server does not offer `none` compression. This build has no
    /// compressor.
    NoCommonCompression,
};

/// What the two sides agreed on.
pub const Choice = struct {
    kex: KexAlgorithm,
    host_key: hostkey.Algorithm,
    /// The name the key exchange was chosen under, which is what a
    /// diagnostic shows.
    kex_name: []const u8,
    cipher_client_to_server: cipher.Algorithm,
    cipher_server_to_client: cipher.Algorithm,
    /// Whether both sides asked for strict key exchange.
    strict_kex: bool,
};

/// Chooses one algorithm in each category, RFC 4253 section 7.1.
///
/// `server` is what the server offered. The client's own lists are the
/// constants above, and each choice is the first client name the server
/// also names.
pub fn negotiate(server: Kexinit) NegotiateError!Choice {
    const kex_name = wire.firstMatch(&supported_kex, server.kex) orelse
        return error.NoCommonKexAlgorithm;
    const host_key_name = wire.firstMatch(&offered_host_key, server.host_key) orelse
        return error.NoCommonHostKeyAlgorithm;
    const to_server = wire.firstMatch(&offered_cipher, server.cipher_client_to_server) orelse
        return error.NoCommonCipher;
    const to_client = wire.firstMatch(&offered_cipher, server.cipher_server_to_client) orelse
        return error.NoCommonCipher;
    if (!server.compression_client_to_server.contains("none") or
        !server.compression_server_to_client.contains("none"))
    {
        return error.NoCommonCompression;
    }

    return .{
        // Both offered names run the one method, so the enum has one
        // value and the name is kept beside it for the diagnostic.
        .kex = .curve25519_sha256,
        .kex_name = kex_name,
        // `offered_host_key` holds only names `hostkey.fromName` knows,
        // so a match is always a name it can read. A null here would mean
        // this module's own list and that function disagree, which is a
        // programmer error.
        .host_key = hostkey.fromName(host_key_name).?,
        .cipher_client_to_server = cipher.fromName(to_server).?,
        .cipher_server_to_client = cipher.fromName(to_client).?,
        .strict_kex = server.kex.contains(strict_kex_server),
    };
}

const testing = std.testing;

/// Builds a server `SSH_MSG_KEXINIT` for a test, from lists given as
/// text.
const ServerLists = struct {
    kex: []const u8 = curve25519_sha256,
    host_key: []const u8 = "ssh-ed25519",
    cipher_c2s: []const u8 = "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
    cipher_s2c: []const u8 = "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
    mac: []const u8 = "hmac-sha2-256",
    compression: []const u8 = "none",
    first_kex_packet_follows: bool = false,
};

fn writeServerKexinit(out: []u8, lists: ServerLists) ![]u8 {
    var w: wire.Writer = .init(out);
    try w.byte(@intFromEnum(messages.Id.kexinit));
    try w.bytes(&[_]u8{0xab} ** cookie_bytes);
    try w.string(lists.kex);
    try w.string(lists.host_key);
    try w.string(lists.cipher_c2s);
    try w.string(lists.cipher_s2c);
    try w.string(lists.mac);
    try w.string(lists.mac);
    try w.string(lists.compression);
    try w.string(lists.compression);
    try w.string("");
    try w.string("");
    try w.boolean(lists.first_kex_packet_follows);
    try w.uint32(0);
    return w.written();
}

test "a KEXINIT this build wrote reads back as the lists it offers" {
    var storage: [kexinit_bytes]u8 = undefined;
    var cookie: [cookie_bytes]u8 = undefined;
    for (&cookie, 0..) |*b, i| b.* = @intCast(i);
    const payload = try writeKexinit(&storage, cookie);

    const parsed = try parseKexinit(payload);
    try testing.expectEqualSlices(u8, &cookie, &parsed.cookie);
    try testing.expect(parsed.kex.contains(curve25519_sha256));
    try testing.expect(parsed.kex.contains(curve25519_sha256_libssh));
    try testing.expect(parsed.kex.contains(strict_kex_client));
    try testing.expect(parsed.host_key.contains("ssh-ed25519"));
    try testing.expect(parsed.cipher_client_to_server.contains("chacha20-poly1305@openssh.com"));
    try testing.expect(parsed.cipher_server_to_client.contains("aes256-gcm@openssh.com"));
    try testing.expectEqual(@as(usize, 0), parsed.mac_client_to_server.count());
    try testing.expectEqual(@as(usize, 0), parsed.mac_server_to_client.count());
    try testing.expectEqualStrings("none", parsed.compression_client_to_server.text);
    try testing.expectEqual(@as(usize, 0), parsed.languages_client_to_server.count());
    try testing.expectEqual(false, parsed.first_kex_packet_follows);
}

test "the client's order decides, not the server's" {
    // **The rule of RFC 4253 section 7.1.** The server lists
    // ChaCha20-Poly1305 first, and AES-GCM still wins, because it is first
    // on the client's list.
    var storage: [512]u8 = undefined;
    const payload = try writeServerKexinit(&storage, .{
        .cipher_c2s = "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
        .cipher_s2c = "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
    });
    const choice = try negotiate(try parseKexinit(payload));
    try testing.expectEqual(
        cipher.Algorithm.aes256_gcm_openssh,
        choice.cipher_client_to_server,
    );
    try testing.expectEqual(
        cipher.Algorithm.aes256_gcm_openssh,
        choice.cipher_server_to_client,
    );
}

test "AES-GCM is preferred over ChaCha20-Poly1305, and CVE-2023-48795 is why" {
    // **The offer is where this is decided.** The client's order is the
    // one both sides follow, so a client that named
    // `chacha20-poly1305@openssh.com` first and then chose the second name
    // for itself would choose a cipher the server did not choose.
    try testing.expectEqualStrings("aes256-gcm@openssh.com", offered_cipher[0]);
    try testing.expectEqualStrings("chacha20-poly1305@openssh.com", offered_cipher[1]);

    // A server that names both gets AES-GCM, whether or not it agreed to
    // strict key exchange. The attack works against the other cipher, and
    // a server with no marker is the case where it is open.
    var storage: [512]u8 = undefined;
    const payload = try writeServerKexinit(&storage, .{ .kex = curve25519_sha256 });
    const choice = try negotiate(try parseKexinit(payload));
    try testing.expect(!choice.strict_kex);
    try testing.expectEqual(cipher.Algorithm.aes256_gcm_openssh, choice.cipher_client_to_server);
    try testing.expectEqual(cipher.Algorithm.aes256_gcm_openssh, choice.cipher_server_to_client);

    // **Nothing is refused for it.** A server that speaks the other cipher
    // and nothing else still gets a connection, and `Transport` closes the
    // injection window for it.
    const only_chacha = try writeServerKexinit(&storage, .{
        .cipher_c2s = "chacha20-poly1305@openssh.com",
        .cipher_s2c = "chacha20-poly1305@openssh.com",
    });
    const second = try negotiate(try parseKexinit(only_chacha));
    try testing.expectEqual(
        cipher.Algorithm.chacha20_poly1305_openssh,
        second.cipher_server_to_client,
    );
}

test "the two directions are negotiated on their own" {
    var storage: [512]u8 = undefined;
    const payload = try writeServerKexinit(&storage, .{
        .cipher_c2s = "aes256-gcm@openssh.com",
        .cipher_s2c = "chacha20-poly1305@openssh.com",
    });
    const choice = try negotiate(try parseKexinit(payload));
    try testing.expectEqual(cipher.Algorithm.aes256_gcm_openssh, choice.cipher_client_to_server);
    try testing.expectEqual(
        cipher.Algorithm.chacha20_poly1305_openssh,
        choice.cipher_server_to_client,
    );
}

test "the older curve25519 name is the same method" {
    var storage: [512]u8 = undefined;
    const payload = try writeServerKexinit(&storage, .{ .kex = curve25519_sha256_libssh });
    const choice = try negotiate(try parseKexinit(payload));
    try testing.expectEqual(KexAlgorithm.curve25519_sha256, choice.kex);
    try testing.expectEqualStrings(curve25519_sha256_libssh, choice.kex_name);
}

test "each category that has nothing in common is refused by its own name" {
    var storage: [512]u8 = undefined;
    {
        const payload = try writeServerKexinit(&storage, .{
            .kex = "diffie-hellman-group14-sha256",
        });
        try testing.expectError(
            error.NoCommonKexAlgorithm,
            negotiate(try parseKexinit(payload)),
        );
    }
    {
        const payload = try writeServerKexinit(&storage, .{ .host_key = "ssh-rsa,rsa-sha2-512" });
        try testing.expectError(
            error.NoCommonHostKeyAlgorithm,
            negotiate(try parseKexinit(payload)),
        );
    }
    {
        const payload = try writeServerKexinit(&storage, .{ .cipher_s2c = "aes128-ctr" });
        try testing.expectError(error.NoCommonCipher, negotiate(try parseKexinit(payload)));
    }
    {
        const payload = try writeServerKexinit(&storage, .{ .compression = "zlib" });
        try testing.expectError(error.NoCommonCompression, negotiate(try parseKexinit(payload)));
    }
}

test "a server that offers RSA host keys gets an answer that names RSA" {
    var storage: [512]u8 = undefined;
    const payload = try writeServerKexinit(&storage, .{
        .host_key = "rsa-sha2-512,rsa-sha2-256,ssh-rsa",
    });
    const parsed = try parseKexinit(payload);
    try testing.expectError(error.NoCommonHostKeyAlgorithm, negotiate(parsed));

    const refusal = hostKeyRefusal(parsed.host_key) orelse return error.TestExpectedRefusal;
    try testing.expectEqualStrings("rsa-sha2-512", refusal.algorithm);
    try testing.expect(std.mem.indexOf(u8, refusal.reason, "RSA") != null);

    // A server that offers an algorithm nobody names gets no reason, and
    // that is right: there is nothing to explain.
    const nothing = try writeServerKexinit(&storage, .{ .host_key = "made-up-v01" });
    const other = try parseKexinit(nothing);
    try testing.expectEqual(@as(?Refusal, null), hostKeyRefusal(other.host_key));
}

test "strict key exchange is on only when the server names its own marker" {
    var storage: [512]u8 = undefined;
    {
        const payload = try writeServerKexinit(&storage, .{
            .kex = curve25519_sha256 ++ "," ++ strict_kex_server,
        });
        const choice = try negotiate(try parseKexinit(payload));
        try testing.expect(choice.strict_kex);
    }
    {
        const payload = try writeServerKexinit(&storage, .{ .kex = curve25519_sha256 });
        const choice = try negotiate(try parseKexinit(payload));
        try testing.expect(!choice.strict_kex);
    }
    {
        // The client's own marker coming back is not the server's, and it
        // must not turn the rule on.
        const payload = try writeServerKexinit(&storage, .{
            .kex = curve25519_sha256 ++ "," ++ strict_kex_client,
        });
        const choice = try negotiate(try parseKexinit(payload));
        try testing.expect(!choice.strict_kex);
    }
}

test "a marker is never chosen as a key exchange method" {
    // A server that offered the client marker back and nothing else has
    // offered no method at all.
    var storage: [512]u8 = undefined;
    const payload = try writeServerKexinit(&storage, .{ .kex = strict_kex_client });
    try testing.expectError(error.NoCommonKexAlgorithm, negotiate(try parseKexinit(payload)));
}

test "a truncated or wrong KEXINIT is refused and never read past" {
    try testing.expectError(error.Truncated, parseKexinit(""));
    try testing.expectError(error.WrongMessage, parseKexinit("\x15"));
    try testing.expectError(error.Truncated, parseKexinit("\x14\x00\x00"));

    var storage: [512]u8 = undefined;
    const payload = try writeServerKexinit(&storage, .{});
    for (1..payload.len) |cut| {
        const result = parseKexinit(payload[0..cut]);
        try testing.expect(std.meta.isError(result));
    }
    // A list whose length runs past the payload is refused on the length.
    try testing.expectError(
        error.LengthOutOfRange,
        parseKexinit("\x14" ++ "\x00" ** 16 ++ "\xff\xff\xff\xff"),
    );
}

test "kexinit_bytes is what writeKexinit needs, and one byte less is not enough" {
    var exact: [kexinit_bytes]u8 = undefined;
    const built = try writeKexinit(&exact, @splat(0));
    try testing.expectEqual(kexinit_bytes, built.len);

    var short: [kexinit_bytes - 1]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, writeKexinit(&short, @splat(0)));
}
