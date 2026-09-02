//! Which TLS versions a transfer will keep.
//!
//! This is one enum and one predicate. It lives in `zurl-core` because
//! three packages have to name the same floor and none of them imports
//! another: `zurl` carries it on `Transfer.Options`, `zurl-http` carries it
//! on a request, and `zurl-net` enforces it on the session. A second copy
//! in any of the three is a floor that can drift.

const std = @import("std");

/// The lowest TLS version a connection will keep.
///
/// **zurl speaks TLS 1.2 and TLS 1.3, and nothing older.** RFC 8996
/// deprecated TLS 1.0 and TLS 1.1 in 2021, and the vendored TLS client
/// offers neither.
///
/// curl 8.21.0 on this machine reaches the same place from the other side.
/// It links OpenSSL 3.6.3, whose default security level refuses both, so
/// the flags parse and the connection still cannot happen. Measured:
///
/// ```
/// curl --tlsv1.0 https://tls-v1-0.badssl.com:1010/   exit 35
/// curl --tlsv1.1 https://tls-v1-1.badssl.com:1011/   exit 35
/// curl --tlsv1.2 https://tls-v1-2.badssl.com:1012/   exit 0
/// ```
///
/// So `--tlsv1.0` and `--tlsv1.1` are accepted and cannot move this floor
/// down. Refusing either flag would fail a script curl runs, which is the
/// opposite of a drop-in replacement.
///
/// Ordered lowest first, so a comparison of the tag values is a comparison
/// of the versions.
pub const MinVersion = enum {
    tls_1_2,
    tls_1_3,

    /// The floor of this build. A flag naming a lower version cannot go
    /// below it.
    pub const floor: MinVersion = .tls_1_2;

    /// Whether `version` meets this floor.
    ///
    /// Anything the TLS client did not negotiate is below every floor.
    /// `zurl_tls.Client` establishes a TLS 1.2 or a TLS 1.3 session and no
    /// other, so no third answer can arrive, and a third answer must not
    /// read as "high enough" if one ever does.
    pub fn met(min: MinVersion, version: std.crypto.tls.ProtocolVersion) bool {
        return switch (version) {
            .tls_1_3 => true,
            .tls_1_2 => min == .tls_1_2,
            else => false,
        };
    }

    /// The higher of two floors. A command line that names more than one
    /// `--tlsv1.x` keeps the highest, the way curl keeps the last word of
    /// a set of bounds that only ever tighten.
    pub fn max(a: MinVersion, b: MinVersion) MinVersion {
        return if (@intFromEnum(a) >= @intFromEnum(b)) a else b;
    }

    /// The name a message prints, the way curl spells it.
    pub fn name(min: MinVersion) []const u8 {
        return switch (min) {
            .tls_1_2 => "TLSv1.2",
            .tls_1_3 => "TLSv1.3",
        };
    }
};

/// A TLS version a curl flag can name.
///
/// `MinVersion` above is the floor **this build can hold**, so it has two
/// members. This enum is the scale the *flags* speak, so it has four: a
/// user writes `--tls-max 1.0` and `--tlsv1.1` whether or not the build
/// offers either version. Two jobs need that wider scale:
///
/// - `--tls-max` sets the ceiling. A ceiling of TLS 1.0 or TLS 1.1 is
///   below the floor, and the transfer must say so rather than run.
/// - The min/max conflict curl reports at parse time compares the version
///   a `--tlsv1.x` flag **named** with the ceiling, and not the floor the
///   build clamped that flag to. Measured against curl 8.21.0:
///   `--tls-max 1.0 --tlsv1.0` runs the transfer and fails at the
///   handshake with 35, and `--tls-max 1.0 --tlsv1.1` never starts and
///   exits 2. Only the named version tells those two apart.
///
/// Ordered lowest first, so a comparison of the tag values is a comparison
/// of the versions.
pub const Version = enum {
    tls_1_0,
    tls_1_1,
    tls_1_2,
    tls_1_3,

    /// The highest version this build offers. This is also the ceiling a
    /// transfer keeps when no `--tls-max` names one, so the flag's default
    /// changes nothing.
    pub const highest: Version = .tls_1_3;

    /// The `--tls-max` value `text` names, or null when it names none.
    ///
    /// curl 8.21.0 takes `default`, `1.0`, `1.1`, `1.2`, and `1.3`, and
    /// answers every other value, the empty one included, with exit 2 and
    /// `option --tls-max: is badly used here`. Measured. `default` means
    /// "whatever the library offers", which for zurl is TLS 1.3.
    pub fn fromMaxText(text: []const u8) ?Version {
        if (std.mem.eql(u8, text, "default")) return highest;
        if (std.mem.eql(u8, text, "1.0")) return .tls_1_0;
        if (std.mem.eql(u8, text, "1.1")) return .tls_1_1;
        if (std.mem.eql(u8, text, "1.2")) return .tls_1_2;
        if (std.mem.eql(u8, text, "1.3")) return .tls_1_3;
        return null;
    }

    /// Whether a ceiling of `max` keeps `version`.
    ///
    /// Written as an allowlist, the way `MinVersion.met` is. A session
    /// reporting a version this build never negotiates is above every
    /// ceiling, so a peer cannot answer a narrowed offer with something
    /// else and have it read as permitted.
    pub fn permits(max: Version, version: std.crypto.tls.ProtocolVersion) bool {
        return switch (version) {
            .tls_1_2 => @intFromEnum(max) >= @intFromEnum(Version.tls_1_2),
            .tls_1_3 => max == .tls_1_3,
            else => false,
        };
    }

    /// Whether a ceiling of `max` leaves any version a floor of `min`
    /// also keeps.
    ///
    /// False is the empty range: the user asked for a ceiling under the
    /// floor of this build, and no version at all is left. The transfer
    /// must fail with that named, and never succeed on a version the user
    /// excluded.
    pub fn permitsFloor(max: Version, min: MinVersion) bool {
        return switch (min) {
            .tls_1_2 => max.permits(.tls_1_2) or max.permits(.tls_1_3),
            .tls_1_3 => max.permits(.tls_1_3),
        };
    }

    /// The highest version the client hello offers under this ceiling.
    ///
    /// Only TLS 1.2 and TLS 1.3 can be offered, so a ceiling below TLS 1.2
    /// has no answer here. The caller checks `permitsFloor` first and
    /// fails the transfer, so this is never asked about such a ceiling.
    pub fn offer(max: Version) std.crypto.tls.ProtocolVersion {
        return switch (max) {
            .tls_1_3 => .tls_1_3,
            else => .tls_1_2,
        };
    }

    /// The name a message prints, the way curl spells it.
    pub fn name(v: Version) []const u8 {
        return switch (v) {
            .tls_1_0 => "TLSv1.0",
            .tls_1_1 => "TLSv1.1",
            .tls_1_2 => "TLSv1.2",
            .tls_1_3 => "TLSv1.3",
        };
    }
};

const testing = std.testing;

test "the floor of this build is TLS 1.2" {
    try testing.expectEqual(MinVersion.tls_1_2, MinVersion.floor);
}

test "a floor of 1.2 keeps both versions and a floor of 1.3 keeps one" {
    try testing.expect(MinVersion.tls_1_2.met(.tls_1_2));
    try testing.expect(MinVersion.tls_1_2.met(.tls_1_3));
    try testing.expect(!MinVersion.tls_1_3.met(.tls_1_2));
    try testing.expect(MinVersion.tls_1_3.met(.tls_1_3));
}

test "a version this build never negotiates is below every floor" {
    // The check is written as an allowlist. A session that somehow
    // reported TLS 1.0 must never read as meeting the floor.
    try testing.expect(!MinVersion.tls_1_2.met(.tls_1_0));
    try testing.expect(!MinVersion.tls_1_2.met(.tls_1_1));
    try testing.expect(!MinVersion.tls_1_3.met(.tls_1_0));
}

test "the higher of two floors wins" {
    try testing.expectEqual(MinVersion.tls_1_3, MinVersion.tls_1_2.max(.tls_1_3));
    try testing.expectEqual(MinVersion.tls_1_3, MinVersion.tls_1_3.max(.tls_1_2));
    try testing.expectEqual(MinVersion.tls_1_2, MinVersion.tls_1_2.max(.tls_1_2));
}

test "each floor names itself the way curl spells it" {
    try testing.expectEqualStrings("TLSv1.2", MinVersion.tls_1_2.name());
    try testing.expectEqualStrings("TLSv1.3", MinVersion.tls_1_3.name());
}

test "--tls-max reads exactly the five values curl reads" {
    try testing.expectEqual(Version.tls_1_0, Version.fromMaxText("1.0").?);
    try testing.expectEqual(Version.tls_1_1, Version.fromMaxText("1.1").?);
    try testing.expectEqual(Version.tls_1_2, Version.fromMaxText("1.2").?);
    try testing.expectEqual(Version.tls_1_3, Version.fromMaxText("1.3").?);
    // `default` is "whatever the library offers", which here is TLS 1.3.
    try testing.expectEqual(Version.tls_1_3, Version.fromMaxText("default").?);
    try testing.expectEqual(Version.highest, Version.fromMaxText("default").?);
}

test "a --tls-max value curl refuses is refused here too" {
    // curl 8.21.0 answers each of these with exit 2 and
    // `option --tls-max: is badly used here`. Measured.
    try testing.expectEqual(@as(?Version, null), Version.fromMaxText(""));
    try testing.expectEqual(@as(?Version, null), Version.fromMaxText("1.4"));
    try testing.expectEqual(@as(?Version, null), Version.fromMaxText("1"));
    try testing.expectEqual(@as(?Version, null), Version.fromMaxText("tlsv1.2"));
    // The value is read byte for byte, the way curl reads it.
    try testing.expectEqual(@as(?Version, null), Version.fromMaxText("DEFAULT"));
    try testing.expectEqual(@as(?Version, null), Version.fromMaxText(" 1.2"));
}

test "a ceiling keeps every version at or below it" {
    try testing.expect(Version.tls_1_3.permits(.tls_1_3));
    try testing.expect(Version.tls_1_3.permits(.tls_1_2));
    try testing.expect(!Version.tls_1_2.permits(.tls_1_3));
    try testing.expect(Version.tls_1_2.permits(.tls_1_2));
    try testing.expect(!Version.tls_1_1.permits(.tls_1_2));
    try testing.expect(!Version.tls_1_0.permits(.tls_1_2));
}

test "a version this build never negotiates is above every ceiling" {
    // The mirror of the floor's own allowlist test. A peer that answered
    // a narrowed offer with TLS 1.0 must not read as permitted.
    try testing.expect(!Version.tls_1_3.permits(.tls_1_0));
    try testing.expect(!Version.tls_1_3.permits(.tls_1_1));
    try testing.expect(!Version.tls_1_0.permits(.tls_1_0));
}

test "a ceiling below the floor leaves no version at all" {
    // This is `--tls-max 1.0` and `--tls-max 1.1`. curl 8.21.0 accepts
    // both flags and then fails the handshake with 35, because its
    // OpenSSL refuses those versions at its default security level.
    try testing.expect(!Version.tls_1_0.permitsFloor(.tls_1_2));
    try testing.expect(!Version.tls_1_1.permitsFloor(.tls_1_2));
    try testing.expect(Version.tls_1_2.permitsFloor(.tls_1_2));
    try testing.expect(Version.tls_1_3.permitsFloor(.tls_1_2));

    // And with `--tlsv1.3` the floor rises, so only the top ceiling is
    // left. curl reports this pair at parse time; see `src/cli/Args.zig`.
    try testing.expect(!Version.tls_1_2.permitsFloor(.tls_1_3));
    try testing.expect(Version.tls_1_3.permitsFloor(.tls_1_3));
}

test "the offer a ceiling makes is the highest version it keeps" {
    try testing.expectEqual(std.crypto.tls.ProtocolVersion.tls_1_3, Version.tls_1_3.offer());
    try testing.expectEqual(std.crypto.tls.ProtocolVersion.tls_1_2, Version.tls_1_2.offer());
}

test "each named version spells itself the way curl spells it" {
    try testing.expectEqualStrings("TLSv1.0", Version.tls_1_0.name());
    try testing.expectEqualStrings("TLSv1.1", Version.tls_1_1.name());
    try testing.expectEqualStrings("TLSv1.2", Version.tls_1_2.name());
    try testing.expectEqualStrings("TLSv1.3", Version.tls_1_3.name());
}
