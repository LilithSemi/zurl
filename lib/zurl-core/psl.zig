//! The public suffix list this build carries, and the one question a
//! cookie asks of it.
//!
//! **Why it is here at all.** A `Set-Cookie` may name a `Domain` the
//! response does not own, and the domain rule alone cannot stop every
//! case. A response from `www.example.co.uk` sits under `co.uk`, so
//! `zurl_core.cookie.resolveDomain` rule 4 lets it name `Domain=co.uk`,
//! and every other site under that suffix would then read the cookie back.
//! Only a list of the suffixes names that case. curl links libpsl for it.
//! zurl has no C dependency, so the list is data this build embeds, the
//! way `zurl-tls` embeds the trust roots.
//!
//! **The table is generated, not written.** `tools/psl2bin.zig` reads the
//! upstream list at build time and writes the compact form that
//! `psl/format.zig` describes. The generator refuses a list that is empty
//! or cut short, and it reads its own output back before it writes the
//! file. The declaration below then parses the header at compile time, so
//! a table that is not one stops the build.
//!
//! The table holds the ICANN section and the private section together.
//! Measured against curl 8.21.0, which does the same: a `Set-Cookie`
//! naming `Domain=.github.io` from `a.b.github.io` is refused, and
//! `Domain=.b.github.io` is kept.

const std = @import("std");

/// The layout of the table, and the code that writes and reads it.
pub const format = @import("psl/format.zig");

/// The compact table, written by `tools/psl2bin.zig` at build time.
const table_bytes = @embedFile("psl_data");

/// The fewest rules a shipped table may hold.
///
/// The list holds over ten thousand. The generator holds its own floor,
/// and this one is the second: a table that reached the embed step empty
/// or cut short fails the build here rather than shipping as a check that
/// refuses nothing.
pub const rule_count_min: u32 = 4000;

/// The table, parsed. A table this build cannot read stops the build.
pub const table: format.Table = format.parse(table_bytes) catch |err| {
    @compileError("the public suffix table did not parse: " ++ @errorName(err));
};

comptime {
    if (table.rule_count < rule_count_min) {
        @compileError("the public suffix table holds too few rules to be the list");
    }
}

/// Whether `domain` is itself a public suffix, and so a domain no single
/// site owns.
///
/// See `format.isPublicSuffix` for the matching rules, and for what a name
/// this build cannot represent gets.
pub fn isPublicSuffix(domain: []const u8) bool {
    return format.isPublicSuffix(table, domain);
}

/// How many rules the table holds, exceptions apart.
pub fn ruleCount() u32 {
    return table.rule_count;
}

const testing = std.testing;

test {
    _ = format;
}

test "the embedded table is the list and not a stub" {
    try testing.expect(table.rule_count >= rule_count_min);
    try testing.expect(table.exception_count >= 1);
    try testing.expect(table.max_rule_labels >= 3);
}

/// The vectors of <https://github.com/publicsuffix/list/blob/main/tests/test_psl.txt>,
/// the ones this build can represent.
///
/// The upstream file gives a name and the registrable domain of that name,
/// or null when the name has none. A name has no registrable domain
/// exactly when it is itself a public suffix, which is the question this
/// file answers. The Unicode rows of that file are left out and their
/// punycode twins, which the same file carries, are kept: zurl has no IDN
/// and a url host reaches it as an A-label.
const vectors = [_]struct { name: []const u8, suffix: bool }{
    // Mixed case.
    .{ .name = "COM", .suffix = true },
    .{ .name = "example.COM", .suffix = false },
    .{ .name = "WwW.example.COM", .suffix = false },
    // Leading dot.
    .{ .name = ".com", .suffix = true },
    .{ .name = ".example", .suffix = true },
    .{ .name = ".example.com", .suffix = true },
    // Unlisted TLD.
    .{ .name = "example", .suffix = true },
    .{ .name = "example.example", .suffix = false },
    .{ .name = "b.example.example", .suffix = false },
    .{ .name = "a.b.example.example", .suffix = false },
    // A TLD with one rule.
    .{ .name = "biz", .suffix = true },
    .{ .name = "domain.biz", .suffix = false },
    .{ .name = "b.domain.biz", .suffix = false },
    .{ .name = "a.b.domain.biz", .suffix = false },
    // A TLD with rules of two levels.
    .{ .name = "com", .suffix = true },
    .{ .name = "example.com", .suffix = false },
    .{ .name = "b.example.com", .suffix = false },
    .{ .name = "a.b.example.com", .suffix = false },
    .{ .name = "uk.com", .suffix = true },
    .{ .name = "example.uk.com", .suffix = false },
    .{ .name = "b.example.uk.com", .suffix = false },
    .{ .name = "a.b.example.uk.com", .suffix = false },
    .{ .name = "test.ac", .suffix = false },
    // A TLD with one wildcard rule.
    .{ .name = "mm", .suffix = true },
    .{ .name = "c.mm", .suffix = true },
    .{ .name = "b.c.mm", .suffix = false },
    .{ .name = "a.b.c.mm", .suffix = false },
    // A TLD with more rules.
    .{ .name = "jp", .suffix = true },
    .{ .name = "test.jp", .suffix = false },
    .{ .name = "www.test.jp", .suffix = false },
    .{ .name = "ac.jp", .suffix = true },
    .{ .name = "test.ac.jp", .suffix = false },
    .{ .name = "www.test.ac.jp", .suffix = false },
    .{ .name = "kyoto.jp", .suffix = true },
    .{ .name = "test.kyoto.jp", .suffix = false },
    .{ .name = "ide.kyoto.jp", .suffix = true },
    .{ .name = "b.ide.kyoto.jp", .suffix = false },
    .{ .name = "a.b.ide.kyoto.jp", .suffix = false },
    .{ .name = "c.kobe.jp", .suffix = true },
    .{ .name = "b.c.kobe.jp", .suffix = false },
    .{ .name = "a.b.c.kobe.jp", .suffix = false },
    .{ .name = "city.kobe.jp", .suffix = false },
    .{ .name = "www.city.kobe.jp", .suffix = false },
    // A TLD with a wildcard rule and exceptions.
    .{ .name = "ck", .suffix = true },
    .{ .name = "test.ck", .suffix = true },
    .{ .name = "b.test.ck", .suffix = false },
    .{ .name = "a.b.test.ck", .suffix = false },
    .{ .name = "www.ck", .suffix = false },
    .{ .name = "www.www.ck", .suffix = false },
    // The US K12 rules, which are three labels deep.
    .{ .name = "us", .suffix = true },
    .{ .name = "test.us", .suffix = false },
    .{ .name = "www.test.us", .suffix = false },
    .{ .name = "ak.us", .suffix = true },
    .{ .name = "test.ak.us", .suffix = false },
    .{ .name = "www.test.ak.us", .suffix = false },
    .{ .name = "k12.ak.us", .suffix = true },
    .{ .name = "test.k12.ak.us", .suffix = false },
    .{ .name = "www.test.k12.ak.us", .suffix = false },
    // Internationalised names, as A-labels.
    .{ .name = "xn--85x722f.com.cn", .suffix = false },
    .{ .name = "xn--85x722f.xn--55qx5d.cn", .suffix = false },
    .{ .name = "www.xn--85x722f.xn--55qx5d.cn", .suffix = false },
    .{ .name = "shishi.xn--55qx5d.cn", .suffix = false },
    .{ .name = "xn--55qx5d.cn", .suffix = true },
    .{ .name = "xn--85x722f.xn--fiqs8s", .suffix = false },
    .{ .name = "www.xn--85x722f.xn--fiqs8s", .suffix = false },
    .{ .name = "shishi.xn--fiqs8s", .suffix = false },
    .{ .name = "xn--fiqs8s", .suffix = true },
};

test "every vector of the upstream test file gives the answer it names" {
    for (vectors) |vector| {
        const answer = isPublicSuffix(vector.name);
        testing.expectEqual(vector.suffix, answer) catch |err| {
            std.debug.print("public suffix vector failed: {s}\n", .{vector.name});
            return err;
        };
    }
}

test "the suffixes a cookie must not reach are named, and the names under them are not" {
    // The case the jar could not name before this list.
    try testing.expect(isPublicSuffix("co.uk"));
    try testing.expect(!isPublicSuffix("example.co.uk"));
    try testing.expect(!isPublicSuffix("www.example.co.uk"));

    try testing.expect(isPublicSuffix("com.au"));
    try testing.expect(!isPublicSuffix("example.com.au"));

    try testing.expect(isPublicSuffix("github.io"));
    try testing.expect(!isPublicSuffix("pages.github.io"));

    // The single-label floor the jar already held.
    try testing.expect(isPublicSuffix("com"));
    try testing.expect(isPublicSuffix("net"));
    try testing.expect(isPublicSuffix("localhost"));
}

test "a name this build cannot represent is called a public suffix" {
    // No IDN, so a U-label is refused rather than guessed at. `公司.cn`.
    try testing.expect(isPublicSuffix("\u{516C}\u{53F8}.cn"));
    try testing.expect(isPublicSuffix("example.\u{516C}\u{53F8}.cn"));
}

test "the names the test fixtures of this repository use stay registrable" {
    // `test` and `invalid` are reserved names and are in no list, so a
    // cookie may still be set for a domain under them. Every loopback
    // fixture in this repository depends on that.
    try testing.expect(!isPublicSuffix("example.test"));
    try testing.expect(!isPublicSuffix("a.example.test"));
    try testing.expect(!isPublicSuffix("bank.test"));
    try testing.expect(!isPublicSuffix("example.invalid"));
}
