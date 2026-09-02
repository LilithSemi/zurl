//! The compact form of the public suffix list, and the rules that read it.
//!
//! **One file holds the writer and the reader.** `tools/psl2bin.zig` calls
//! `encode` at build time and `lib/zurl-core/psl.zig` calls `parse` and
//! `isPublicSuffix` at run time. A second copy of either half would be a
//! second place for the layout to drift, and a table that decodes to the
//! wrong suffix sends a cookie to the wrong site.
//!
//! **Why a compact form and not the file.** The list at
//! <https://publicsuffix.org/list/> is about 330 kB of text with comments,
//! blank lines, and internationalised names. zurl targets a board with
//! 256 MB and ships one static binary, so the text does not go in. What
//! goes in is the rules alone, in the order a match reads them.
//!
//! ## The key
//!
//! A rule is matched label by label, from the right. So a rule is stored
//! with its labels reversed and joined by a period: `co.uk` becomes
//! `uk.co`, and `*.kawasaki.jp` becomes `jp.kawasaki.*`. A domain is
//! reversed the same way before a search, which turns "does this rule end
//! this name" into "is this key in the table".
//!
//! Reversed keys that share a parent also share a byte prefix, and the
//! table is sorted, so the prefix is written once. This is front coding.
//!
//! ## The layout
//!
//! Every number is little endian.
//!
//! ```
//! 0  .. 4   "ZPSL"
//! 4         format_version
//! 5         block_log2
//! 6         max_rule_labels
//! 7         0
//! 8  .. 12  rule_count       u32
//! 12 .. 16  block_count      u32
//! 16 .. 20  exception_count  u32
//! 20 .. 24  exceptions_len   u32
//! 24 .. 28  entries_len      u32
//! 28 ..     the exception area, `exceptions_len` bytes
//! then      the block table, `block_count` u32 offsets into the entries
//! then      the entry area, `entries_len` bytes
//! ```
//!
//! The exception area holds one length byte and then the key, for each of
//! the eight exception rules the list carries today. They are kept apart
//! from the other rules because there are so few of them, and because
//! keeping them apart takes the kind flag out of every other entry.
//!
//! One entry of the entry area is a header and then the bytes the key does
//! not share with the key before it:
//!
//! - A header byte other than `0xF0` packs both lengths: the high nibble
//!   is the shared length, 0 to 15, and the low nibble is the rest
//!   length, 1 to 15.
//! - A header byte of `0xF0` is the escape. Two bytes follow it: the
//!   shared length and then the rest length. `0xF0` names a rest length of
//!   zero in the packed form, which no entry has, so the escape is never
//!   ambiguous.
//!
//! The first entry of each block shares nothing, so a search can jump to a
//! block and read forward. The block table gives the offset of each of
//! those entries.
//!
//! ## What is bounded
//!
//! The table is a build artifact and not network input, but every read
//! here still checks its bound. A truncated table must give a wrong answer
//! that is safe, or no answer, and never a read past the end.

const std = @import("std");

/// The four bytes at the front of every table this file writes.
pub const magic = [4]u8{ 'Z', 'P', 'S', 'L' };

/// The layout version. A reader refuses a table that names another one.
pub const format_version: u8 = 1;

/// Entries in one block, as a power of two.
///
/// A block starts with a whole key, so a search jumps to a block and reads
/// forward from there. A larger block saves bytes in the block table and
/// costs time in the scan. 32 keeps the block table near 1.3 kB for the
/// list of today and keeps the scan to 32 keys.
pub const block_log2: u8 = 5;

/// Entries in one block.
pub const block_len: usize = @as(usize, 1) << @intCast(block_log2);

/// The longest key this file writes or reads, in bytes.
///
/// A DNS name is at most 253 bytes, so one length byte covers every key a
/// real rule can have.
pub const key_len_max: usize = 255;

/// The most labels one rule may hold.
///
/// The list of today has seven. 16 leaves room and still bounds the
/// buffers a search keeps on the stack.
pub const rule_labels_max: usize = 16;

/// The most labels a name this file looks up may hold.
///
/// A key is at most 255 bytes and a label is at least one byte with one
/// period behind it, so 128 labels is the ceiling the length already
/// gives. A name past it is refused rather than searched.
pub const domain_labels_max: usize = 128;

/// The most exception rules this file reads.
///
/// The list of today has eight. The bound stops a malformed exception area
/// from making the scan run on.
pub const exception_count_max: usize = 1024;

/// The size of the header, in bytes.
pub const header_len: usize = 28;

/// The header byte that says two length bytes follow.
const escape_byte: u8 = 0xF0;

/// What a table cannot be.
pub const Error = error{
    /// The bytes do not start with `magic`. The build wrote something
    /// else, or wrote nothing.
    PublicSuffixBadMagic,
    /// The table names a layout this file does not read.
    PublicSuffixBadVersion,
    /// The lengths in the header do not agree with the bytes that follow.
    PublicSuffixTruncated,
    /// The table holds no rule. A list that refuses nothing is worse than
    /// no list, because it reads as a check that ran.
    PublicSuffixEmpty,
};

/// A table that `parse` has checked. Every slice borrows from the bytes
/// that were passed in.
pub const Table = struct {
    /// How many rules the entry area holds, exceptions apart.
    rule_count: u32,
    /// The most labels any rule in this table holds. A search tries no
    /// candidate longer than this.
    max_rule_labels: u8,
    /// How many exception rules the exception area holds.
    exception_count: u32,
    /// Length byte and key, once for each exception rule.
    exceptions: []const u8,
    /// One u32 offset into `entries` for each block.
    blocks: []const u8,
    /// The front-coded keys.
    entries: []const u8,
};

/// Reads the header of `bytes` and returns the three areas behind it.
///
/// Fails rather than guesses. A caller that embeds a build artifact may
/// call this at compile time, which turns a truncated or empty table into
/// a build that does not finish.
pub fn parse(bytes: []const u8) Error!Table {
    if (bytes.len < header_len) return error.PublicSuffixTruncated;
    if (!std.mem.eql(u8, bytes[0..4], &magic)) return error.PublicSuffixBadMagic;
    if (bytes[4] != format_version) return error.PublicSuffixBadVersion;
    if (bytes[5] != block_log2) return error.PublicSuffixBadVersion;

    const max_rule_labels = bytes[6];
    if (max_rule_labels == 0 or max_rule_labels > rule_labels_max) return error.PublicSuffixTruncated;

    const rule_count = std.mem.readInt(u32, bytes[8..][0..4], .little);
    const block_count = std.mem.readInt(u32, bytes[12..][0..4], .little);
    const exception_count = std.mem.readInt(u32, bytes[16..][0..4], .little);
    const exceptions_len = std.mem.readInt(u32, bytes[20..][0..4], .little);
    const entries_len = std.mem.readInt(u32, bytes[24..][0..4], .little);

    if (rule_count == 0 or entries_len == 0) return error.PublicSuffixEmpty;
    if (exception_count > exception_count_max) return error.PublicSuffixTruncated;

    // The block table has one entry for each whole or part block, so its
    // length is decided by the rule count. A header that says otherwise is
    // a header that was not written by `encode`.
    const wanted_blocks = (@as(usize, rule_count) + block_len - 1) / block_len;
    if (block_count != wanted_blocks) return error.PublicSuffixTruncated;

    const blocks_len = @as(usize, block_count) * 4;
    const total = header_len + @as(usize, exceptions_len) + blocks_len + @as(usize, entries_len);
    if (bytes.len != total) return error.PublicSuffixTruncated;

    const exceptions_at = header_len;
    const blocks_at = exceptions_at + @as(usize, exceptions_len);
    const entries_at = blocks_at + blocks_len;

    return .{
        .rule_count = rule_count,
        .max_rule_labels = max_rule_labels,
        .exception_count = exception_count,
        .exceptions = bytes[exceptions_at..blocks_at],
        .blocks = bytes[blocks_at..entries_at],
        .entries = bytes[entries_at..],
    };
}

/// Whether `domain` is itself a public suffix.
///
/// **This is the question a cookie asks.** A `Set-Cookie` may not name a
/// domain that every site under it would read back, so `co.uk` gets a
/// refusal and `example.co.uk` does not.
///
/// The algorithm is the one at <https://publicsuffix.org/list/>:
///
/// 1. Find every rule that matches the right end of the name. A `*` label
///    in a rule matches any one label.
/// 2. An exception rule wins over every other rule. Otherwise the rule
///    with the most labels wins.
/// 3. With no matching rule, the rule is `*`, so the public suffix is the
///    rightmost label alone.
/// 4. The public suffix is the labels the winning rule matched. An
///    exception rule loses its leftmost label first.
///
/// The answer is true when the public suffix is the whole name.
///
/// **One rule is libpsl's and not the specification's**: the parent of a
/// wildcard rule is a public suffix too, so `*.0emm.com` makes
/// `0emm.com` one. See the comment on that check below, and the
/// measurement beside curl 8.21.0 it carries.
///
/// **A name zurl cannot represent gets a true.** zurl has no IDN, so a
/// name with a byte over 127 is not a name this build can compare against
/// the table, which holds A-labels alone. It is called a public suffix, so
/// the cookie is refused. A refusal costs one cookie. A guess leaks one.
/// The same answer goes to an empty label, to a name over `key_len_max`,
/// and to a name with more labels than `domain_labels_max`.
pub fn isPublicSuffix(table: Table, domain: []const u8) bool {
    if (domain.len == 0 or domain.len > key_len_max) return true;
    for (domain) |byte| {
        if (byte >= 0x80) return true;
    }

    // The rightmost labels are the only ones a rule can reach, so the ring
    // keeps those and drops the rest as it goes.
    var ring: [rule_labels_max][]const u8 = undefined;
    var total: usize = 0;
    var it = std.mem.splitScalar(u8, domain, '.');
    while (it.next()) |label| {
        if (label.len == 0) return true;
        ring[total % rule_labels_max] = label;
        total += 1;
        if (total > domain_labels_max) return true;
    }

    // One label and no list at all: the rule is `*`, so the label is the
    // whole public suffix. This is the floor a client holds with no list,
    // and the table never makes it looser.
    if (total <= 1) return true;

    const longest = @min(total, @as(usize, table.max_rule_labels));
    var buf: [key_len_max]u8 = undefined;

    // An exception rule wins over every other rule, whatever its length.
    // It takes its leftmost label off, so the public suffix it names is
    // always shorter than the name, and the answer is always false.
    var k = longest;
    while (k >= 2) : (k -= 1) {
        const key = reversedKey(&buf, &ring, total, k, false) orelse continue;
        if (isException(table, key)) return false;
    }

    // **The parent of a wildcard rule.** `*.0emm.com` says every one-label
    // child of `0emm.com` is a registry of its own, so a cookie set for
    // `0emm.com` would cross all of them. The algorithm at
    // publicsuffix.org does not say the parent is a suffix, because a `*`
    // must match one label. libpsl says it is, and curl therefore refuses
    // the cookie. Measured against curl 8.21.0: a `Set-Cookie` naming
    // `Domain=.0emm.com` from `www.x.0emm.com` is refused, and zurl
    // refuses it here for the same reason. The direction is strict, so it
    // can cost a cookie and cannot leak one.
    if (total < @as(usize, table.max_rule_labels)) {
        if (reversedKey(&buf, &ring, total, total, true)) |key| {
            if (contains(table, key)) return true;
        }
    }

    // The longest matching rule wins, so the search runs from the longest
    // candidate down. A rule of one label cannot make the answer true for
    // a name of two or more, so the search stops at two.
    k = longest;
    while (k >= 2) : (k -= 1) {
        if (reversedKey(&buf, &ring, total, k, false)) |key| {
            if (contains(table, key)) return k == total;
        }
        if (reversedKey(&buf, &ring, total, k - 1, true)) |key| {
            if (contains(table, key)) return k == total;
        }
    }

    // No rule matched. The public suffix is the rightmost label, and the
    // name has more than one.
    return false;
}

/// Whether `key` is one of the exception rules.
///
/// `key` is a reversed-label key, lower case, with no leading `!`.
pub fn isException(table: Table, key: []const u8) bool {
    var pos: usize = 0;
    var seen: usize = 0;
    while (pos < table.exceptions.len and seen < exception_count_max) : (seen += 1) {
        const len = table.exceptions[pos];
        pos += 1;
        if (pos + len > table.exceptions.len) return false;
        if (std.mem.eql(u8, table.exceptions[pos..][0..len], key)) return true;
        pos += len;
    }
    return false;
}

/// Whether `key` is one of the normal or wildcard rules.
///
/// `key` is a reversed-label key, lower case. A wildcard rule carries a
/// `*` label, so `*.ck` is looked up as `ck.*`.
pub fn contains(table: Table, key: []const u8) bool {
    if (key.len == 0 or key.len > key_len_max) return false;
    const block_count = table.blocks.len / 4;
    if (block_count == 0) return false;

    // The first key of block zero is the smallest key in the table. A
    // target under it is in no block.
    var buf: [key_len_max]u8 = undefined;
    const first = blockFirstKey(table, 0, &buf) orelse return false;
    if (std.mem.order(u8, first, key) == .gt) return false;

    // Find the last block whose first key is not greater than the target.
    var low: usize = 0;
    var high: usize = block_count;
    while (high - low > 1) {
        const mid = low + (high - low) / 2;
        const mid_key = blockFirstKey(table, mid, &buf) orelse {
            high = mid;
            continue;
        };
        if (std.mem.order(u8, mid_key, key) == .gt) high = mid else low = mid;
    }

    return scanBlock(table, low, key);
}

/// The offset of block `index` in the entry area, or null when the table
/// does not name one.
fn blockOffset(table: Table, index: usize) ?usize {
    const at = index * 4;
    if (at + 4 > table.blocks.len) return null;
    const off = std.mem.readInt(u32, table.blocks[at..][0..4], .little);
    if (off > table.entries.len) return null;
    return off;
}

/// The whole first key of block `index`, written into `buf`.
///
/// The first entry of a block shares nothing, so its key is in the entry
/// itself.
fn blockFirstKey(table: Table, index: usize, buf: []u8) ?[]const u8 {
    const off = blockOffset(table, index) orelse return null;
    const entry = readEntry(table.entries, off) orelse return null;
    if (entry.shared != 0) return null;
    if (entry.rest.len > buf.len) return null;
    @memcpy(buf[0..entry.rest.len], entry.rest);
    return buf[0..entry.rest.len];
}

/// Whether block `index` holds `key`.
///
/// The keys of a block rise, so the scan stops at the first key over the
/// target rather than reading the whole block.
fn scanBlock(table: Table, index: usize, key: []const u8) bool {
    var pos = blockOffset(table, index) orelse return false;
    const end = blockOffset(table, index + 1) orelse table.entries.len;
    if (end > table.entries.len or end < pos) return false;

    var buf: [key_len_max]u8 = undefined;
    var len: usize = 0;
    var seen: usize = 0;
    while (seen < block_len and pos < end) : (seen += 1) {
        const entry = readEntry(table.entries[0..end], pos) orelse return false;
        if (entry.shared > len) return false;
        if (entry.shared + entry.rest.len > buf.len) return false;
        @memcpy(buf[entry.shared..][0..entry.rest.len], entry.rest);
        len = entry.shared + entry.rest.len;
        pos = entry.next;

        switch (std.mem.order(u8, buf[0..len], key)) {
            .eq => return true,
            .gt => return false,
            .lt => {},
        }
    }
    return false;
}

/// One decoded entry, with the offset the next entry starts at.
const Entry = struct {
    shared: usize,
    rest: []const u8,
    next: usize,
};

/// Reads the entry at `pos`, or null when the bytes do not hold a whole
/// one.
fn readEntry(entries: []const u8, pos: usize) ?Entry {
    if (pos >= entries.len) return null;
    const header = entries[pos];
    var at = pos + 1;
    var shared: usize = undefined;
    var rest_len: usize = undefined;
    if (header == escape_byte) {
        if (at + 2 > entries.len) return null;
        shared = entries[at];
        rest_len = entries[at + 1];
        at += 2;
    } else {
        shared = header >> 4;
        rest_len = header & 0x0F;
    }
    if (rest_len == 0) return null;
    if (at + rest_len > entries.len) return null;
    return .{ .shared = shared, .rest = entries[at..][0..rest_len], .next = at + rest_len };
}

/// Writes the reversed-label key of the rightmost `k` labels of a name.
///
/// `ring` holds the labels of the name by their index from the left,
/// modulo its own length, and `total` is how many labels the name has.
/// With `star` set, a `*` label goes on the left end, which is the form a
/// wildcard rule is stored in.
///
/// Returns null when the key does not fit `buf`.
fn reversedKey(
    buf: []u8,
    ring: *const [rule_labels_max][]const u8,
    total: usize,
    k: usize,
    star: bool,
) ?[]const u8 {
    var len: usize = 0;
    var j: usize = 0;
    while (j < k) : (j += 1) {
        const label = ring[(total - 1 - j) % rule_labels_max];
        if (len != 0) {
            if (len + 1 > buf.len) return null;
            buf[len] = '.';
            len += 1;
        }
        if (len + label.len > buf.len) return null;
        for (label, 0..) |byte, offset| buf[len + offset] = std.ascii.toLower(byte);
        len += label.len;
    }
    if (star) {
        if (len + 2 > buf.len) return null;
        buf[len] = '.';
        buf[len + 1] = '*';
        len += 2;
    }
    return buf[0..len];
}

/// What `encode` refuses to write.
pub const EncodeError = error{
    /// The keys were not handed over in rising order, or one was there
    /// twice. The search is a binary search, so an unsorted table would
    /// answer no for a rule that is in it.
    PublicSuffixUnsorted,
    /// A key is empty or longer than `key_len_max`.
    PublicSuffixKeyTooLong,
    /// A rule holds more labels than `rule_labels_max`.
    PublicSuffixTooManyLabels,
    /// There are more exception rules than `exception_count_max`.
    PublicSuffixTooManyExceptions,
    /// There is no rule to write. See `Error.PublicSuffixEmpty`.
    PublicSuffixNothingToWrite,
} || std.mem.Allocator.Error;

/// Writes the compact table for `keys` and `exceptions` to `out`.
///
/// `keys` are the reversed-label keys of the normal and wildcard rules, in
/// rising order, each one once. `exceptions` are the reversed-label keys
/// of the exception rules, with no `!`.
///
/// `allocator` backs the bytes appended to `out`.
pub fn encode(
    allocator: std.mem.Allocator,
    keys: []const []const u8,
    exceptions: []const []const u8,
    out: *std.ArrayList(u8),
) EncodeError!void {
    if (keys.len == 0) return error.PublicSuffixNothingToWrite;
    if (exceptions.len > exception_count_max) return error.PublicSuffixTooManyExceptions;

    var max_rule_labels: usize = 1;

    var exception_area: std.ArrayList(u8) = .empty;
    defer exception_area.deinit(allocator);
    for (exceptions) |key| {
        try checkKey(key);
        max_rule_labels = @max(max_rule_labels, std.mem.count(u8, key, ".") + 1);
        try exception_area.append(allocator, @intCast(key.len));
        try exception_area.appendSlice(allocator, key);
    }

    var entries: std.ArrayList(u8) = .empty;
    defer entries.deinit(allocator);
    var blocks: std.ArrayList(u8) = .empty;
    defer blocks.deinit(allocator);

    var previous: []const u8 = "";
    for (keys, 0..) |key, index| {
        try checkKey(key);
        max_rule_labels = @max(max_rule_labels, std.mem.count(u8, key, ".") + 1);
        if (index != 0 and std.mem.order(u8, previous, key) != .lt) return error.PublicSuffixUnsorted;

        const block_start = index % block_len == 0;
        if (block_start) {
            var offset: [4]u8 = undefined;
            std.mem.writeInt(u32, &offset, @intCast(entries.items.len), .little);
            try blocks.appendSlice(allocator, &offset);
        }

        const shared: usize = if (block_start) 0 else sharedPrefixLen(previous, key);
        const rest = key[shared..];
        if (shared <= 15 and rest.len <= 15) {
            try entries.append(allocator, @intCast((shared << 4) | rest.len));
        } else {
            try entries.append(allocator, escape_byte);
            try entries.append(allocator, @intCast(shared));
            try entries.append(allocator, @intCast(rest.len));
        }
        try entries.appendSlice(allocator, rest);
        previous = key;
    }

    if (max_rule_labels > rule_labels_max) return error.PublicSuffixTooManyLabels;

    var header: [header_len]u8 = @splat(0);
    @memcpy(header[0..4], &magic);
    header[4] = format_version;
    header[5] = block_log2;
    header[6] = @intCast(max_rule_labels);
    std.mem.writeInt(u32, header[8..12], @intCast(keys.len), .little);
    std.mem.writeInt(u32, header[12..16], @intCast(blocks.items.len / 4), .little);
    std.mem.writeInt(u32, header[16..20], @intCast(exceptions.len), .little);
    std.mem.writeInt(u32, header[20..24], @intCast(exception_area.items.len), .little);
    std.mem.writeInt(u32, header[24..28], @intCast(entries.items.len), .little);

    try out.appendSlice(allocator, &header);
    try out.appendSlice(allocator, exception_area.items);
    try out.appendSlice(allocator, blocks.items);
    try out.appendSlice(allocator, entries.items);
}

/// Refuses a key that is empty, too long, or has too many labels.
fn checkKey(key: []const u8) EncodeError!void {
    if (key.len == 0 or key.len > key_len_max) return error.PublicSuffixKeyTooLong;
    if (std.mem.count(u8, key, ".") + 1 > rule_labels_max) return error.PublicSuffixTooManyLabels;
}

/// How many leading bytes `a` and `b` share, capped at 255 so one byte can
/// name the answer.
fn sharedPrefixLen(a: []const u8, b: []const u8) usize {
    const limit = @min(@min(a.len, b.len), @as(usize, 255));
    var i: usize = 0;
    while (i < limit and a[i] == b[i]) : (i += 1) {}
    return i;
}

const testing = std.testing;

/// Builds a table over `keys` and `exceptions` for a test.
///
/// The caller owns the bytes and frees them.
fn buildTable(
    keys: []const []const u8,
    exceptions: []const []const u8,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(testing.allocator);
    try encode(testing.allocator, keys, exceptions, &out);
    return out.toOwnedSlice(testing.allocator);
}

/// A table with the shapes every rule kind needs: a plain suffix, a
/// two-label suffix, a wildcard, and the exception that takes one child
/// back out of the wildcard.
fn sampleTable() ![]u8 {
    return buildTable(&.{
        "ck.*",
        "com",
        "io.github",
        "jp",
        "jp.kawasaki.*",
        "uk",
        "uk.co",
    }, &.{
        "ck.www",
        "jp.kawasaki.city",
    });
}

test "a written table parses back with the counts it was given" {
    const bytes = try sampleTable();
    defer testing.allocator.free(bytes);

    const table = try parse(bytes);
    try testing.expectEqual(@as(u32, 7), table.rule_count);
    try testing.expectEqual(@as(u32, 2), table.exception_count);
    try testing.expectEqual(@as(u8, 3), table.max_rule_labels);
}

test "every key written is found and no other key is" {
    const bytes = try sampleTable();
    defer testing.allocator.free(bytes);
    const table = try parse(bytes);

    for ([_][]const u8{ "ck.*", "com", "io.github", "jp", "jp.kawasaki.*", "uk", "uk.co" }) |key| {
        try testing.expect(contains(table, key));
    }
    for ([_][]const u8{ "", "c", "co", "uk.c", "uk.co.", "uk.con", "zz", "jp.kawasaki" }) |key| {
        try testing.expect(!contains(table, key));
    }
}

test "a public suffix of two labels is one, and a name under it is not" {
    const bytes = try sampleTable();
    defer testing.allocator.free(bytes);
    const table = try parse(bytes);

    try testing.expect(isPublicSuffix(table, "co.uk"));
    try testing.expect(!isPublicSuffix(table, "example.co.uk"));
    try testing.expect(!isPublicSuffix(table, "www.example.co.uk"));
}

test "a single label is a public suffix whether the table names it or not" {
    const bytes = try sampleTable();
    defer testing.allocator.free(bytes);
    const table = try parse(bytes);

    try testing.expect(isPublicSuffix(table, "com"));
    try testing.expect(isPublicSuffix(table, "uk"));
    try testing.expect(isPublicSuffix(table, "nosuchtld"));
}

test "a wildcard rule makes every one-label child a public suffix" {
    const bytes = try sampleTable();
    defer testing.allocator.free(bytes);
    const table = try parse(bytes);

    try testing.expect(isPublicSuffix(table, "foo.ck"));
    try testing.expect(isPublicSuffix(table, "anything.ck"));
    try testing.expect(!isPublicSuffix(table, "deep.foo.ck"));
}

test "the parent of a wildcard rule is a public suffix as well" {
    const bytes = try sampleTable();
    defer testing.allocator.free(bytes);
    const table = try parse(bytes);

    // `*.kawasaki.jp` is a rule and `kawasaki.jp` is not, so the letter of
    // the algorithm would make `kawasaki.jp` registrable. libpsl calls it
    // a suffix and curl refuses a cookie for it, so zurl does too.
    try testing.expect(isPublicSuffix(table, "kawasaki.jp"));
    try testing.expect(isPublicSuffix(table, "other.kawasaki.jp"));
    // A name under the wildcard's children is still registrable.
    try testing.expect(!isPublicSuffix(table, "www.other.kawasaki.jp"));
}

test "an exception rule takes one name back out of a wildcard" {
    const bytes = try sampleTable();
    defer testing.allocator.free(bytes);
    const table = try parse(bytes);

    try testing.expect(!isPublicSuffix(table, "www.ck"));
    try testing.expect(!isPublicSuffix(table, "deep.www.ck"));
    try testing.expect(!isPublicSuffix(table, "city.kawasaki.jp"));
    try testing.expect(isPublicSuffix(table, "other.kawasaki.jp"));
}

test "the longest matching rule wins" {
    const bytes = try sampleTable();
    defer testing.allocator.free(bytes);
    const table = try parse(bytes);

    // `github.io` is a rule and `io` is not, so `github.io` is the suffix
    // and `pages.github.io` is a name under it.
    try testing.expect(isPublicSuffix(table, "github.io"));
    try testing.expect(!isPublicSuffix(table, "pages.github.io"));
}

test "a name is matched without regard to case" {
    const bytes = try sampleTable();
    defer testing.allocator.free(bytes);
    const table = try parse(bytes);

    try testing.expect(isPublicSuffix(table, "CO.UK"));
    try testing.expect(isPublicSuffix(table, "Co.Uk"));
    try testing.expect(!isPublicSuffix(table, "Example.CO.UK"));
}

test "a name zurl cannot represent is called a public suffix" {
    const bytes = try sampleTable();
    defer testing.allocator.free(bytes);
    const table = try parse(bytes);

    // No IDN, so a byte over 127 is a name this build cannot compare.
    try testing.expect(isPublicSuffix(table, "\xd1\x80\xd1\x84"));
    try testing.expect(isPublicSuffix(table, "example.\xd1\x80\xd1\x84"));
    // An empty label, a leading period, and a trailing period.
    try testing.expect(isPublicSuffix(table, ""));
    try testing.expect(isPublicSuffix(table, ".co.uk"));
    try testing.expect(isPublicSuffix(table, "co.uk."));
    try testing.expect(isPublicSuffix(table, "a..co.uk"));
}

test "a name longer than a key is refused rather than searched" {
    const bytes = try sampleTable();
    defer testing.allocator.free(bytes);
    const table = try parse(bytes);

    const long: [key_len_max + 1]u8 = @splat('a');
    try testing.expect(isPublicSuffix(table, &long));
}

test "a table with more keys than one block still finds every key" {
    // Three blocks and a bit, so the binary search has to pick one.
    var names: [block_len * 3 + 7][]const u8 = undefined;
    var storage: [names.len][7]u8 = undefined;
    for (&storage, 0..) |*slot, index| {
        _ = try std.fmt.bufPrint(slot, "k{d:0>6}", .{index});
        names[index] = slot;
    }
    const bytes = try buildTable(&names, &.{});
    defer testing.allocator.free(bytes);
    const table = try parse(bytes);

    try testing.expectEqual(@as(u32, names.len), table.rule_count);
    for (names) |key| try testing.expect(contains(table, key));
    try testing.expect(!contains(table, "k999999"));
    try testing.expect(!contains(table, "a"));
}

test "a key longer than fifteen bytes past its prefix uses the escape" {
    const long_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const long_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const bytes = try buildTable(&.{ long_a, long_b }, &.{});
    defer testing.allocator.free(bytes);
    const table = try parse(bytes);

    try testing.expect(contains(table, long_a));
    try testing.expect(contains(table, long_b));
    try testing.expect(!contains(table, "aaaa"));
}

test "parse refuses a table that is empty, short, or not one of ours" {
    try testing.expectError(error.PublicSuffixTruncated, parse(""));
    try testing.expectError(error.PublicSuffixTruncated, parse("ZPSL"));

    const good = try sampleTable();
    defer testing.allocator.free(good);

    const wrong_magic = try testing.allocator.dupe(u8, good);
    defer testing.allocator.free(wrong_magic);
    wrong_magic[0] = 'X';
    try testing.expectError(error.PublicSuffixBadMagic, parse(wrong_magic));

    const wrong_version = try testing.allocator.dupe(u8, good);
    defer testing.allocator.free(wrong_version);
    wrong_version[4] = format_version + 1;
    try testing.expectError(error.PublicSuffixBadVersion, parse(wrong_version));

    try testing.expectError(error.PublicSuffixTruncated, parse(good[0 .. good.len - 1]));

    const no_rules = try testing.allocator.dupe(u8, good);
    defer testing.allocator.free(no_rules);
    std.mem.writeInt(u32, no_rules[8..][0..4], 0, .little);
    try testing.expectError(error.PublicSuffixEmpty, parse(no_rules));
}

test "encode refuses keys that are unsorted, repeated, or empty" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);

    try testing.expectError(
        error.PublicSuffixUnsorted,
        encode(testing.allocator, &.{ "uk.co", "com" }, &.{}, &out),
    );
    out.clearRetainingCapacity();
    try testing.expectError(
        error.PublicSuffixUnsorted,
        encode(testing.allocator, &.{ "com", "com" }, &.{}, &out),
    );
    out.clearRetainingCapacity();
    try testing.expectError(
        error.PublicSuffixKeyTooLong,
        encode(testing.allocator, &.{""}, &.{}, &out),
    );
    out.clearRetainingCapacity();
    try testing.expectError(
        error.PublicSuffixNothingToWrite,
        encode(testing.allocator, &.{}, &.{}, &out),
    );
}
