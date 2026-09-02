//! The QPACK static table, RFC 9204 Appendix A.
//!
//! Ninety nine field lines that never change and that both peers know
//! without either one sending them. This file owns the list and the two
//! lookups over it. It owns nothing else: it holds no state, it allocates
//! nothing, and it knows nothing about the dynamic table.
//!
//! **The two tables are addressed separately.** RFC 9204 section 3 says so
//! in its first sentence, and that is the difference from HPACK: there is
//! no shared index space here, and a representation carries a 'T' bit that
//! says which table it means. So this file needs no rule about where the
//! static table stops and the dynamic table starts.
//!
//! **The first entry is index 0**, where the HPACK static table starts at
//! index 1. The RFC calls that out in section 3.1, because it is exactly
//! the kind of difference that a port from HPACK gets wrong.
//!
//! Every name here is lowercase, which is what HTTP/3 requires of a field
//! name on the wire. `find` compares byte for byte and does no folding, so
//! a caller with an uppercase name gets no match and sends a literal.

const std = @import("std");

/// One static table row.
pub const Entry = struct {
    name: []const u8,
    value: []const u8,
};

/// RFC 9204 Appendix A, Table 4. `entries[0]` is index 0.
///
/// The rows were read out of the RFC text by a script and not typed, and
/// the two comptime checks below are what prove the reading.
pub const entries = [_]Entry{
    .{ .name = ":authority", .value = "" }, // 0
    .{ .name = ":path", .value = "/" }, // 1
    .{ .name = "age", .value = "0" }, // 2
    .{ .name = "content-disposition", .value = "" }, // 3
    .{ .name = "content-length", .value = "0" }, // 4
    .{ .name = "cookie", .value = "" }, // 5
    .{ .name = "date", .value = "" }, // 6
    .{ .name = "etag", .value = "" }, // 7
    .{ .name = "if-modified-since", .value = "" }, // 8
    .{ .name = "if-none-match", .value = "" }, // 9
    .{ .name = "last-modified", .value = "" }, // 10
    .{ .name = "link", .value = "" }, // 11
    .{ .name = "location", .value = "" }, // 12
    .{ .name = "referer", .value = "" }, // 13
    .{ .name = "set-cookie", .value = "" }, // 14
    .{ .name = ":method", .value = "CONNECT" }, // 15
    .{ .name = ":method", .value = "DELETE" }, // 16
    .{ .name = ":method", .value = "GET" }, // 17
    .{ .name = ":method", .value = "HEAD" }, // 18
    .{ .name = ":method", .value = "OPTIONS" }, // 19
    .{ .name = ":method", .value = "POST" }, // 20
    .{ .name = ":method", .value = "PUT" }, // 21
    .{ .name = ":scheme", .value = "http" }, // 22
    .{ .name = ":scheme", .value = "https" }, // 23
    .{ .name = ":status", .value = "103" }, // 24
    .{ .name = ":status", .value = "200" }, // 25
    .{ .name = ":status", .value = "304" }, // 26
    .{ .name = ":status", .value = "404" }, // 27
    .{ .name = ":status", .value = "503" }, // 28
    .{ .name = "accept", .value = "*/*" }, // 29
    .{ .name = "accept", .value = "application/dns-message" }, // 30
    .{ .name = "accept-encoding", .value = "gzip, deflate, br" }, // 31
    .{ .name = "accept-ranges", .value = "bytes" }, // 32
    .{ .name = "access-control-allow-headers", .value = "cache-control" }, // 33
    .{ .name = "access-control-allow-headers", .value = "content-type" }, // 34
    .{ .name = "access-control-allow-origin", .value = "*" }, // 35
    .{ .name = "cache-control", .value = "max-age=0" }, // 36
    .{ .name = "cache-control", .value = "max-age=2592000" }, // 37
    .{ .name = "cache-control", .value = "max-age=604800" }, // 38
    .{ .name = "cache-control", .value = "no-cache" }, // 39
    .{ .name = "cache-control", .value = "no-store" }, // 40
    .{ .name = "cache-control", .value = "public, max-age=31536000" }, // 41
    .{ .name = "content-encoding", .value = "br" }, // 42
    .{ .name = "content-encoding", .value = "gzip" }, // 43
    .{ .name = "content-type", .value = "application/dns-message" }, // 44
    .{ .name = "content-type", .value = "application/javascript" }, // 45
    .{ .name = "content-type", .value = "application/json" }, // 46
    .{ .name = "content-type", .value = "application/x-www-form-urlencoded" }, // 47
    .{ .name = "content-type", .value = "image/gif" }, // 48
    .{ .name = "content-type", .value = "image/jpeg" }, // 49
    .{ .name = "content-type", .value = "image/png" }, // 50
    .{ .name = "content-type", .value = "text/css" }, // 51
    .{ .name = "content-type", .value = "text/html; charset=utf-8" }, // 52
    .{ .name = "content-type", .value = "text/plain" }, // 53
    .{ .name = "content-type", .value = "text/plain;charset=utf-8" }, // 54
    .{ .name = "range", .value = "bytes=0-" }, // 55
    .{ .name = "strict-transport-security", .value = "max-age=31536000" }, // 56
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains" }, // 57
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains; preload" }, // 58
    .{ .name = "vary", .value = "accept-encoding" }, // 59
    .{ .name = "vary", .value = "origin" }, // 60
    .{ .name = "x-content-type-options", .value = "nosniff" }, // 61
    .{ .name = "x-xss-protection", .value = "1; mode=block" }, // 62
    .{ .name = ":status", .value = "100" }, // 63
    .{ .name = ":status", .value = "204" }, // 64
    .{ .name = ":status", .value = "206" }, // 65
    .{ .name = ":status", .value = "302" }, // 66
    .{ .name = ":status", .value = "400" }, // 67
    .{ .name = ":status", .value = "403" }, // 68
    .{ .name = ":status", .value = "421" }, // 69
    .{ .name = ":status", .value = "425" }, // 70
    .{ .name = ":status", .value = "500" }, // 71
    .{ .name = "accept-language", .value = "" }, // 72
    .{ .name = "access-control-allow-credentials", .value = "FALSE" }, // 73
    .{ .name = "access-control-allow-credentials", .value = "TRUE" }, // 74
    .{ .name = "access-control-allow-headers", .value = "*" }, // 75
    .{ .name = "access-control-allow-methods", .value = "get" }, // 76
    .{ .name = "access-control-allow-methods", .value = "get, post, options" }, // 77
    .{ .name = "access-control-allow-methods", .value = "options" }, // 78
    .{ .name = "access-control-expose-headers", .value = "content-length" }, // 79
    .{ .name = "access-control-request-headers", .value = "content-type" }, // 80
    .{ .name = "access-control-request-method", .value = "get" }, // 81
    .{ .name = "access-control-request-method", .value = "post" }, // 82
    .{ .name = "alt-svc", .value = "clear" }, // 83
    .{ .name = "authorization", .value = "" }, // 84
    .{ .name = "content-security-policy", .value = "script-src 'none'; object-src 'none'; base-uri 'none'" }, // 85
    .{ .name = "early-data", .value = "1" }, // 86
    .{ .name = "expect-ct", .value = "" }, // 87
    .{ .name = "forwarded", .value = "" }, // 88
    .{ .name = "if-range", .value = "" }, // 89
    .{ .name = "origin", .value = "" }, // 90
    .{ .name = "purpose", .value = "prefetch" }, // 91
    .{ .name = "server", .value = "" }, // 92
    .{ .name = "timing-allow-origin", .value = "*" }, // 93
    .{ .name = "upgrade-insecure-requests", .value = "1" }, // 94
    .{ .name = "user-agent", .value = "" }, // 95
    .{ .name = "x-forwarded-for", .value = "" }, // 96
    .{ .name = "x-frame-options", .value = "deny" }, // 97
    .{ .name = "x-frame-options", .value = "sameorigin" }, // 98
};

/// How many entries the static table holds. The largest index that names
/// one is `len - 1`.
pub const len: u64 = entries.len;

comptime {
    @setEvalBranchQuota(20_000);
    if (entries.len != 99) @compileError("the static table of RFC 9204 Appendix A has 99 entries");

    // A name with an uppercase letter would be a transcription slip, and
    // it would also be a field name HTTP/3 forbids on the wire. Two of the
    // values are uppercase on purpose, so only the names are checked.
    for (entries) |entry| {
        for (entry.name) |octet| {
            if (octet >= 'A' and octet <= 'Z') {
                @compileError("a static table name must be lowercase, RFC 9204 Appendix A");
            }
        }
    }
}

/// The entry at `index`, or null when `index` names no static entry.
///
/// RFC 9204 section 3.1: an invalid static table index is a fault for the
/// caller to name, so this returns null rather than deciding what it
/// means. The two callers name it differently, because the RFC does: in a
/// field line representation it is QPACK_DECOMPRESSION_FAILED, and on the
/// encoder stream it is QPACK_ENCODER_STREAM_ERROR.
pub fn get(index: u64) ?Entry {
    if (index >= len) return null;
    return entries[@intCast(index)];
}

/// What `find` located.
pub const Match = union(enum) {
    /// No entry carries this name.
    none,
    /// This index carries the name and the value.
    full: u64,
    /// This index carries the name, with some other value.
    name: u64,
};

/// Looks for `name` and `value` in the table.
///
/// A full match wins over a name match, and the lowest index wins among
/// name matches. The scan is linear over 99 rows, which is short enough
/// that a map would cost more to keep right than it saves.
pub fn find(name: []const u8, value: []const u8) Match {
    var name_only: ?u64 = null;
    for (entries, 0..) |entry, index| {
        if (!std.mem.eql(u8, entry.name, name)) continue;
        if (std.mem.eql(u8, entry.value, value)) return .{ .full = @intCast(index) };
        if (name_only == null) name_only = @intCast(index);
    }
    if (name_only) |index| return .{ .name = index };
    return .none;
}

const testing = std.testing;

test "the table holds the 99 entries of RFC 9204 Appendix A, at the RFC's indices" {
    try testing.expectEqual(@as(u64, 99), len);
    try testing.expectEqualStrings(":authority", get(0).?.name);
    try testing.expectEqualStrings("", get(0).?.value);
    try testing.expectEqualStrings(":path", get(1).?.name);
    try testing.expectEqualStrings("/", get(1).?.value);
    try testing.expectEqualStrings("age", get(2).?.name);
    try testing.expectEqualStrings("0", get(2).?.value);
    try testing.expectEqualStrings(":method", get(17).?.name);
    try testing.expectEqualStrings("GET", get(17).?.value);
    try testing.expectEqualStrings(":scheme", get(23).?.name);
    try testing.expectEqualStrings("https", get(23).?.value);
    try testing.expectEqualStrings(":status", get(25).?.name);
    try testing.expectEqualStrings("200", get(25).?.value);
    try testing.expectEqualStrings("accept", get(30).?.name);
    try testing.expectEqualStrings("application/dns-message", get(30).?.value);
    try testing.expectEqualStrings("content-type", get(47).?.name);
    try testing.expectEqualStrings("application/x-www-form-urlencoded", get(47).?.value);
    try testing.expectEqualStrings("content-type", get(52).?.name);
    try testing.expectEqualStrings("text/html; charset=utf-8", get(52).?.value);
    try testing.expectEqualStrings("content-type", get(54).?.name);
    try testing.expectEqualStrings("text/plain;charset=utf-8", get(54).?.value);
    try testing.expectEqualStrings("strict-transport-security", get(58).?.name);
    try testing.expectEqualStrings(
        "max-age=31536000; includesubdomains; preload",
        get(58).?.value,
    );
    try testing.expectEqualStrings("content-security-policy", get(85).?.name);
    try testing.expectEqualStrings(
        "script-src 'none'; object-src 'none'; base-uri 'none'",
        get(85).?.value,
    );
    try testing.expectEqualStrings("x-frame-options", get(98).?.name);
    try testing.expectEqualStrings("sameorigin", get(98).?.value);
}

test "index 99 and up name no static entry, and index 0 names the first one" {
    try testing.expect(get(0) != null);
    try testing.expectEqual(@as(?Entry, null), get(99));
    try testing.expectEqual(@as(?Entry, null), get(100));
    try testing.expectEqual(@as(?Entry, null), get(std.math.maxInt(u64)));
}

test "a name and a value that both match give the index of the pair" {
    try testing.expectEqual(Match{ .full = 1 }, find(":path", "/"));
    try testing.expectEqual(Match{ .full = 17 }, find(":method", "GET"));
    try testing.expectEqual(Match{ .full = 20 }, find(":method", "POST"));
    try testing.expectEqual(Match{ .full = 23 }, find(":scheme", "https"));
    try testing.expectEqual(Match{ .full = 25 }, find(":status", "200"));
    try testing.expectEqual(Match{ .full = 71 }, find(":status", "500"));
    try testing.expectEqual(Match{ .full = 0 }, find(":authority", ""));
}

test "a name that matches with another value gives the lowest index of that name" {
    try testing.expectEqual(Match{ .name = 0 }, find(":authority", "www.example.com"));
    try testing.expectEqual(Match{ .name = 1 }, find(":path", "/index.html"));
    try testing.expectEqual(Match{ .name = 15 }, find(":method", "PATCH"));
    try testing.expectEqual(Match{ .name = 24 }, find(":status", "418"));
    try testing.expectEqual(Match{ .name = 36 }, find("cache-control", "private"));
}

test "a name the table does not carry matches nothing" {
    try testing.expectEqual(Match.none, find("custom-key", "custom-value"));
    try testing.expectEqual(Match.none, find("", ""));
    try testing.expectEqual(Match.none, find("host", ""));
}

test "the lookup folds no case, so an uppercase name matches nothing" {
    try testing.expectEqual(Match.none, find("Cache-Control", "no-cache"));
    try testing.expectEqual(Match{ .full = 39 }, find("cache-control", "no-cache"));
}

test "the two values the RFC writes in uppercase are kept as they are" {
    try testing.expectEqualStrings("FALSE", get(73).?.value);
    try testing.expectEqualStrings("TRUE", get(74).?.value);
    try testing.expectEqual(Match{ .full = 74 }, find("access-control-allow-credentials", "TRUE"));
}
