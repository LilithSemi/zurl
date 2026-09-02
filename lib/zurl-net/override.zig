//! Where a transfer dials, when `--resolve` or `--connect-to` moves it.
//!
//! **An entry moves the dial and nothing else.** The name a request writes
//! and the name a peer's certificate or host key is checked against stay
//! the ones the url wrote. Any other reading would turn these two flags
//! into a way to send a request for one host to a peer that holds a
//! credential for another, which is the thing verification exists to stop.
//!
//! This file lives in `zurl-net` because every package that dials imports
//! `zurl-net` and because the rule must have one home. `zurl-http/engine.zig`
//! re-exports the three names below, so the HTTP engine and each protocol
//! package read one definition and no copy can drift from it.
//!
//! This file opens no socket and holds no state. It is a match and a
//! choice over text the caller owns.

const std = @import("std");

const tcp = @import("tcp.zig");

/// One `--resolve` or `--connect-to` entry: where to dial for a url that
/// names a given host and port.
///
/// **This moves the dial and nothing else.** The `Host` header, the TLS
/// server name, the name the peer certificate is checked against, and the
/// name an SSH host key is looked up under all stay the ones the url
/// wrote.
///
/// Every field borrows from the caller, so the caller must keep the text
/// alive for the whole transfer.
pub const HostOverride = struct {
    /// The host the url names, or empty for any host. Matched without
    /// regard to case, because a host name has none.
    ///
    /// An IPv6 host carries no brackets here, because
    /// `zurl_core.url.parse` takes them off the url too.
    from_host: []const u8 = "",
    /// The port the url names, or null for any port.
    from_port: ?u16 = null,
    /// The host or address to dial instead, or empty to keep the url's
    /// own. Never becomes the `Host` header and never becomes the name a
    /// certificate or a host key is checked against.
    to_host: []const u8 = "",
    /// The port to dial, or null to keep the url's own.
    to_port: ?u16 = null,

    /// Whether this entry answers for a url naming `host` on `port`.
    pub fn matches(self: HostOverride, host: []const u8, port: u16) bool {
        if (self.from_host.len != 0 and !std.ascii.eqlIgnoreCase(self.from_host, host)) return false;
        if (self.from_port) |wanted| {
            if (wanted != port) return false;
        }
        return true;
    }
};

/// Where one hop dials, after every `HostOverride` has been read.
pub const DialTarget = struct {
    host: []const u8,
    port: u16,
    /// Whether an entry moved the dial away from the url's own host and
    /// port. False for every transfer that named no override, so the
    /// connection pool keys exactly as it did before this field existed.
    overridden: bool,

    /// The start of the sentence that reports a dial host which
    /// `tcp.Host.init` would not read.
    ///
    /// **The two cases send a reader to two different places.** Text the
    /// url wrote is a bad url. Text a flag wrote is a bad flag, and a
    /// message that called it a bad url would send the user to look at
    /// the url they typed correctly.
    ///
    /// `err` says what was wrong with the text, because the two members
    /// are two different faults and one sentence cannot answer for both.
    /// A name over the bound is a good host name that no resolver can
    /// look up, so its sentence says the name is too long and never that
    /// the text is not a name. See `tcp.Host.InitError`.
    ///
    /// The switch has no `else`, so a new member of that set is a compile
    /// error here and never a sentence that does not fit it.
    pub fn faultPrefix(self: DialTarget, err: tcp.Host.InitError) []const u8 {
        return switch (err) {
            error.InvalidHost => if (self.overridden)
                "the --connect-to or --resolve target is neither an address nor a name: "
            else
                "the host is neither an address nor a name: ",
            error.HostNameTooLong => if (self.overridden)
                "the --connect-to or --resolve target is longer than the dns encoding holds, so no resolver can look it up: "
            else
                "the host name is longer than the dns encoding holds, so no resolver can look it up: ",
        };
    }
};

/// Where a url naming `host` on `port` dials, given `list`.
///
/// The first entry that matches wins, which is curl's own order: an
/// earlier `--connect-to` takes a url that a later one would also take.
/// An entry that names no replacement host keeps the url's own, and one
/// that names no replacement port keeps the url's own port.
pub fn dialTarget(list: []const HostOverride, host: []const u8, port: u16) DialTarget {
    for (list) |entry| {
        if (!entry.matches(host, port)) continue;
        const to_host = if (entry.to_host.len == 0) host else entry.to_host;
        const to_port = entry.to_port orelse port;
        return .{
            .host = to_host,
            .port = to_port,
            .overridden = to_port != port or !std.mem.eql(u8, to_host, host),
        };
    }
    return .{ .host = host, .port = port, .overridden = false };
}

const testing = std.testing;

test "dialTarget answers the url's own host and port when no entry matches" {
    // The whole of the old behaviour, and the answer every transfer that
    // named neither flag gets. `overridden` false is what keeps the
    // connection pool keyed exactly as it was before these flags existed.
    const empty = dialTarget(&.{}, "example.com", 443);
    try testing.expectEqualStrings("example.com", empty.host);
    try testing.expectEqual(@as(u16, 443), empty.port);
    try testing.expect(!empty.overridden);

    const other: []const HostOverride = &.{
        .{ .from_host = "elsewhere.test", .from_port = 443, .to_host = "127.0.0.1", .to_port = 443 },
    };
    const missed = dialTarget(other, "example.com", 443);
    try testing.expectEqualStrings("example.com", missed.host);
    try testing.expect(!missed.overridden);

    // A matching host on another port is not a match. `--resolve` names a
    // host and a port together, and curl's own name cache is keyed on
    // both.
    const wrong_port: []const HostOverride = &.{
        .{ .from_host = "example.com", .from_port = 8443, .to_host = "127.0.0.1", .to_port = 8443 },
    };
    try testing.expect(!dialTarget(wrong_port, "example.com", 443).overridden);
}

test "dialTarget moves the dial, and the first matching entry wins" {
    const list: []const HostOverride = &.{
        .{ .from_host = "example.com", .from_port = 443, .to_host = "127.0.0.1", .to_port = 443 },
        // A second entry for the same url. curl takes the first it finds,
        // so this one must never answer.
        .{ .from_host = "example.com", .from_port = 443, .to_host = "127.0.0.2", .to_port = 443 },
    };
    const moved = dialTarget(list, "example.com", 443);
    try testing.expectEqualStrings("127.0.0.1", moved.host);
    try testing.expectEqual(@as(u16, 443), moved.port);
    try testing.expect(moved.overridden);

    // A host name has no case, so a url that spelled it differently still
    // matches. The dial target is used as written.
    const cased = dialTarget(list, "EXAMPLE.com", 443);
    try testing.expectEqualStrings("127.0.0.1", cased.host);
    try testing.expect(cased.overridden);
}

test "an empty field of a --connect-to entry means any on the left and keep on the right" {
    // `::127.0.0.1:8080` is curl's own spelling for "every host and every
    // port goes to this one address".
    const wild: []const HostOverride = &.{
        .{ .from_host = "", .from_port = null, .to_host = "127.0.0.1", .to_port = 8080 },
    };
    const a = dialTarget(wild, "example.com", 443);
    try testing.expectEqualStrings("127.0.0.1", a.host);
    try testing.expectEqual(@as(u16, 8080), a.port);
    try testing.expect(a.overridden);

    // An entry that names no replacement keeps the url's own host and
    // port, and reports that nothing moved. A connection opened for it is
    // the same peer the url named, so it may share the pool with one.
    const keep: []const HostOverride = &.{
        .{ .from_host = "example.com", .from_port = null, .to_host = "", .to_port = null },
    };
    const b = dialTarget(keep, "example.com", 443);
    try testing.expectEqualStrings("example.com", b.host);
    try testing.expectEqual(@as(u16, 443), b.port);
    try testing.expect(!b.overridden);

    // A port alone moves the dial, and the host stays the url's own.
    const port_only: []const HostOverride = &.{
        .{ .from_host = "example.com", .from_port = 80, .to_host = "", .to_port = 8080 },
    };
    const c = dialTarget(port_only, "example.com", 80);
    try testing.expectEqualStrings("example.com", c.host);
    try testing.expectEqual(@as(u16, 8080), c.port);
    try testing.expect(c.overridden);
}

test "an unreadable dial host says which of the url and the flag wrote it" {
    // A user who reads that the url is malformed, when the unreadable
    // name came from `--connect-to`, looks at the wrong thing.
    const plain = dialTarget(&.{}, "example.com", 80);
    try testing.expect(std.mem.indexOf(u8, plain.faultPrefix(error.InvalidHost), "--connect-to") == null);

    const list: []const HostOverride = &.{
        .{ .from_host = "example.com", .to_host = "not a host" },
    };
    const moved = dialTarget(list, "example.com", 80);
    try testing.expect(std.mem.indexOf(u8, moved.faultPrefix(error.InvalidHost), "--connect-to") != null);
}

test "a dial host over the length bound is not reported as text that is not a name" {
    // The sentence is the only place a user learns what to do. A name of
    // 254 characters is a good host name, so a sentence that said it was
    // not one would send the user to look for a typo that is not there.
    const plain = dialTarget(&.{}, "example.com", 80);
    const too_long = plain.faultPrefix(error.HostNameTooLong);
    try testing.expect(std.mem.indexOf(u8, too_long, "longer") != null);
    try testing.expect(std.mem.indexOf(u8, too_long, "neither") == null);

    // The flag keeps the last word about where to look, for both faults.
    const list: []const HostOverride = &.{
        .{ .from_host = "example.com", .to_host = "long" },
    };
    const moved = dialTarget(list, "example.com", 80);
    try testing.expect(std.mem.indexOf(
        u8,
        moved.faultPrefix(error.HostNameTooLong),
        "--connect-to",
    ) != null);
}
