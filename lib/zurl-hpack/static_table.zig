//! The HPACK static table, RFC 7541 Appendix A.
//!
//! Sixty one header fields that never change and that both peers know
//! without either one sending them. This file owns the list and the two
//! lookups over it. It owns nothing else: it holds no state, it allocates
//! nothing, and it knows nothing about the dynamic table that sits above
//! it in the index space.
//!
//! **The index space is one.** Index 1 through 61 name these entries, and
//! index 62 upward names the dynamic table. `Decoder.zig` owns that split,
//! because only it holds a dynamic table.
//!
//! Every name here is lowercase, which is what HTTP/2 requires of a field
//! name on the wire. `find` compares byte for byte and does no folding, so
//! a caller with an uppercase name gets no match and sends a literal.

const std = @import("std");

/// One static table row.
pub const Entry = struct {
    name: []const u8,
    value: []const u8,
};

/// RFC 7541 Appendix A, Table 1. `entries[0]` is index 1.
pub const entries = [_]Entry{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

/// How many entries the static table holds, and so the largest index that
/// names one.
pub const len: u32 = entries.len;

comptime {
    if (entries.len != 61) @compileError("the static table of RFC 7541 Appendix A has 61 entries");
}

/// The entry at `index`, or null when `index` names no static entry.
///
/// `index` is the HPACK index, so 1 is the first entry and 0 names
/// nothing. RFC 7541 section 6.1 forbids index 0 in an indexed header
/// field, and this returns null for it rather than deciding what that
/// means.
pub fn get(index: u32) ?Entry {
    if (index == 0 or index > len) return null;
    return entries[index - 1];
}

/// What `find` located.
pub const Match = union(enum) {
    /// No entry carries this name.
    none,
    /// This index carries the name and the value.
    full: u32,
    /// This index carries the name, with some other value.
    name: u32,
};

/// Looks for `name` and `value` in the table.
///
/// A full match wins over a name match, and the lowest index wins among
/// name matches. The scan is linear over 61 rows, which is short enough
/// that a map would cost more to keep right than it saves.
pub fn find(name: []const u8, value: []const u8) Match {
    var name_only: ?u32 = null;
    for (entries, 1..) |entry, index| {
        if (!std.mem.eql(u8, entry.name, name)) continue;
        if (std.mem.eql(u8, entry.value, value)) return .{ .full = @intCast(index) };
        if (name_only == null) name_only = @intCast(index);
    }
    if (name_only) |index| return .{ .name = index };
    return .none;
}

const testing = std.testing;

test "the table holds the 61 entries of RFC 7541 Appendix A, at the RFC's indices" {
    try testing.expectEqual(@as(u32, 61), len);
    try testing.expectEqualStrings(":authority", get(1).?.name);
    try testing.expectEqualStrings("", get(1).?.value);
    try testing.expectEqualStrings(":method", get(2).?.name);
    try testing.expectEqualStrings("GET", get(2).?.value);
    try testing.expectEqualStrings(":path", get(4).?.name);
    try testing.expectEqualStrings("/", get(4).?.value);
    try testing.expectEqualStrings(":status", get(8).?.name);
    try testing.expectEqualStrings("200", get(8).?.value);
    try testing.expectEqualStrings("accept-encoding", get(16).?.name);
    try testing.expectEqualStrings("gzip, deflate", get(16).?.value);
    try testing.expectEqualStrings("cache-control", get(24).?.name);
    try testing.expectEqualStrings("date", get(33).?.name);
    try testing.expectEqualStrings("location", get(46).?.name);
    try testing.expectEqualStrings("set-cookie", get(55).?.name);
    try testing.expectEqualStrings("www-authenticate", get(61).?.name);
}

test "index zero and index 62 name no static entry" {
    try testing.expectEqual(@as(?Entry, null), get(0));
    try testing.expectEqual(@as(?Entry, null), get(62));
    try testing.expectEqual(@as(?Entry, null), get(std.math.maxInt(u32)));
}

test "every name in the table is lowercase, the way HTTP/2 requires" {
    for (entries) |entry| {
        for (entry.name) |octet| try testing.expect(octet < 'A' or octet > 'Z');
    }
}

test "a name and a value that both match give the index of the pair" {
    try testing.expectEqual(Match{ .full = 2 }, find(":method", "GET"));
    try testing.expectEqual(Match{ .full = 3 }, find(":method", "POST"));
    try testing.expectEqual(Match{ .full = 7 }, find(":scheme", "https"));
    try testing.expectEqual(Match{ .full = 14 }, find(":status", "500"));
}

test "a name that matches with another value gives the lowest index of that name" {
    try testing.expectEqual(Match{ .name = 2 }, find(":method", "PUT"));
    try testing.expectEqual(Match{ .name = 8 }, find(":status", "418"));
    try testing.expectEqual(Match{ .name = 24 }, find("cache-control", "no-cache"));
}

test "a name the table does not carry matches nothing" {
    try testing.expectEqual(Match.none, find("custom-key", "custom-value"));
    try testing.expectEqual(Match.none, find("", ""));
}

test "the lookup folds no case, so an uppercase name matches nothing" {
    try testing.expectEqual(Match.none, find("Cache-Control", ""));
    try testing.expectEqual(Match{ .full = 24 }, find("cache-control", ""));
}
