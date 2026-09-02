//! Turns the public suffix list into the compact table zurl embeds.
//!
//! The list at <https://publicsuffix.org/list/> is a text file: one rule to
//! a line, `//` for a comment, a `*` label for a wildcard rule, and a `!`
//! in front of an exception rule. This tool reads that file and writes the
//! form `lib/zurl-core/psl/format.zig` describes.
//!
//! **Internationalised rules become A-labels here.** The file names them
//! in Unicode, such as `公司.cn`. zurl has no IDN and a url host reaches it
//! as an A-label, such as `xn--55qx5d.cn`, so this tool does the punycode
//! of RFC 3492 at build time. The table then holds ASCII alone and the
//! match at run time is a byte compare. Measured against curl 8.21.0,
//! which does the same through libidn2: a `Set-Cookie` naming
//! `Domain=.xn--55qx5d.cn` from a host under it is refused.
//!
//! **A short list fails the build.** `generate` takes the least number of
//! rules it will accept. A list that arrives empty or cut in half would
//! otherwise ship as a check that runs and refuses nothing.
//!
//! Usage: `psl2bin <public_suffix_list.dat> <out.bin>`

const std = @import("std");
const format = @import("psl-format");
const Io = std.Io;

/// The largest list file this tool reads.
///
/// The list is about 330 kB today. 16 MiB leaves fifty times that room and
/// still refuses a build dependency that names something else.
const max_input_bytes: usize = 16 * 1024 * 1024;

/// The least number of rules the shipped table may hold.
///
/// The list holds over ten thousand. A table under this is a list that did
/// not arrive whole, and a build that ships it would refuse almost
/// nothing.
const rules_min: usize = 4000;

/// The longest one DNS label may be, in bytes. RFC 1035 section 2.3.4.
const label_len_max: usize = 63;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;

    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 3) {
        printLine(io, "usage: {s} <public_suffix_list.dat> <out.bin>\n", .{if (args.len > 0) args[0] else "psl2bin"});
        return error.MissingArguments;
    }
    const in_path = args[1];
    const out_path = args[2];
    const cwd: Io.Dir = .cwd();

    const text = try cwd.readFileAlloc(io, in_path, arena, .limited(max_input_bytes));

    var out: std.ArrayList(u8) = .empty;
    const stats = try generate(arena, text, &out, rules_min);

    const out_file = try cwd.createFile(io, out_path, .{});
    defer out_file.close(io);
    try out_file.writeStreamingAll(io, out.items);

    printLine(io, "psl2bin: {d} rules and {d} exceptions in {d} bytes\n", .{
        stats.rules,
        stats.exceptions,
        out.items.len,
    });
}

/// Prints one line to stdout, never to stderr.
///
/// The build runner surfaces anything a run step writes to stderr as
/// "failed command:" noise, even on success. Stdout stays quiet unless this
/// tool is run directly.
fn printLine(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
    Io.File.stdout().writeStreamingAll(io, msg) catch {};
}

/// What one run of this tool produced.
pub const Stats = struct {
    /// Normal and wildcard rules, after duplicates were dropped.
    rules: usize,
    /// Exception rules.
    exceptions: usize,
};

/// What this tool refuses to read or write.
pub const GenerateError = error{
    /// A rule holds a label with no bytes, such as `a..b`.
    PslEmptyLabel,
    /// A rule holds a `*` that is not a whole label.
    PslBadWildcard,
    /// A label is longer than DNS allows.
    PslLabelTooLong,
    /// A `!` with no rule behind it.
    PslEmptyRule,
    /// The rule holds a byte sequence that is not UTF-8.
    PslBadUtf8,
    /// The punycode of a label overflowed. RFC 3492 section 6.4.
    PslPunycodeOverflow,
    /// The list held fewer rules than the caller would accept.
    PslListTooShort,
    /// The table was written and then did not read back. See `verify`.
    PslVerifyFailed,
} || format.EncodeError || std.mem.Allocator.Error;

/// Reads `text` as the public suffix list and writes the compact table to
/// `out`.
///
/// `minimum` is the least number of normal and wildcard rules this
/// function will accept. `main` passes `rules_min`, so a truncated list
/// fails the build. A test passes a small number, so a fixture of four
/// rules still runs.
///
/// `allocator` backs the parse and every byte appended to `out`. Pass an
/// arena, or another allocator whose memory the caller reclaims in one
/// step: this function frees nothing on its own.
pub fn generate(
    allocator: std.mem.Allocator,
    text: []const u8,
    out: *std.ArrayList(u8),
    minimum: usize,
) GenerateError!Stats {
    var keys: std.ArrayList([]const u8) = .empty;
    var exceptions: std.ArrayList([]const u8) = .empty;

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw_line| {
        const rule = (try parseLine(allocator, raw_line)) orelse continue;
        if (rule.exception) {
            try exceptions.append(allocator, rule.key);
        } else {
            try keys.append(allocator, rule.key);
        }
    }

    std.mem.sort([]const u8, keys.items, {}, lessThan);
    std.mem.sort([]const u8, exceptions.items, {}, lessThan);
    const unique_keys = dedupe(keys.items);
    const unique_exceptions = dedupe(exceptions.items);

    if (unique_keys.len < minimum) return error.PslListTooShort;

    try format.encode(allocator, unique_keys, unique_exceptions, out);
    try verify(out.items, unique_keys, unique_exceptions);

    return .{ .rules = unique_keys.len, .exceptions = unique_exceptions.len };
}

/// Reads the table back and checks that every rule that went in comes out.
///
/// **This is the guard that a silently wrong table cannot pass.** The
/// encoder and the decoder are one file, so a fault in either shows up
/// here, at build time, and not as a cookie sent to the wrong site.
fn verify(bytes: []const u8, keys: []const []const u8, exceptions: []const []const u8) GenerateError!void {
    const table = format.parse(bytes) catch return error.PslVerifyFailed;
    if (table.rule_count != keys.len) return error.PslVerifyFailed;
    if (table.exception_count != exceptions.len) return error.PslVerifyFailed;
    for (keys) |key| {
        if (!format.contains(table, key)) return error.PslVerifyFailed;
    }
    for (exceptions) |key| {
        if (!format.isException(table, key)) return error.PslVerifyFailed;
    }
}

/// Orders two keys by their bytes, which is the order the table is
/// searched in.
fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

/// Drops the repeats from a sorted list, in place, and returns the part
/// that is left.
fn dedupe(items: [][]const u8) [][]const u8 {
    if (items.len == 0) return items;
    var kept: usize = 1;
    var index: usize = 1;
    while (index < items.len) : (index += 1) {
        if (std.mem.eql(u8, items[index], items[kept - 1])) continue;
        items[kept] = items[index];
        kept += 1;
    }
    return items[0..kept];
}

/// One rule, with its labels already reversed and lower case.
const Rule = struct {
    key: []const u8,
    exception: bool,
};

/// Reads one line of the list, or returns null for a comment or a blank
/// line.
fn parseLine(allocator: std.mem.Allocator, raw_line: []const u8) GenerateError!?Rule {
    const line = std.mem.trim(u8, raw_line, " \t\r\n");
    if (line.len == 0) return null;
    if (std.mem.startsWith(u8, line, "//")) return null;

    var body = line;
    var exception = false;
    if (body[0] == '!') {
        exception = true;
        body = body[1..];
    }
    if (body.len == 0) return error.PslEmptyRule;

    var labels: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, body, '.');
    while (it.next()) |label| {
        if (label.len == 0) return error.PslEmptyLabel;
        try labels.append(allocator, label);
    }
    if (labels.items.len > format.rule_labels_max) return error.PublicSuffixTooManyLabels;

    var key: std.ArrayList(u8) = .empty;
    var index = labels.items.len;
    while (index > 0) {
        index -= 1;
        if (key.items.len != 0) try key.append(allocator, '.');
        try encodeLabel(allocator, labels.items[index], &key);
    }
    if (key.items.len > format.key_len_max) return error.PublicSuffixKeyTooLong;

    return .{ .key = try key.toOwnedSlice(allocator), .exception = exception };
}

/// Appends one label to `out`, in the form a url host carries it.
///
/// An ASCII label goes in lower case. A label with any byte over 127 goes
/// through punycode first, so `公司` becomes `xn--55qx5d`.
fn encodeLabel(allocator: std.mem.Allocator, label: []const u8, out: *std.ArrayList(u8)) GenerateError!void {
    var ascii = true;
    for (label) |byte| {
        if (byte >= 0x80) ascii = false;
    }

    if (ascii) {
        // The list uses `*` as a whole label and nowhere else. A `*` inside
        // a label would name a rule this build cannot match.
        if (std.mem.indexOfScalar(u8, label, '*') != null and label.len != 1) return error.PslBadWildcard;
        if (label.len > label_len_max) return error.PslLabelTooLong;
        for (label) |byte| try out.append(allocator, std.ascii.toLower(byte));
        return;
    }

    const start = out.items.len;
    try out.appendSlice(allocator, "xn--");
    try punycode(allocator, label, out);
    if (out.items.len - start > label_len_max) return error.PslLabelTooLong;
}

// RFC 3492 section 5, the parameters of the punycode of IDNA.
const base: u32 = 36;
const tmin: u32 = 1;
const tmax: u32 = 26;
const skew: u32 = 38;
const damp: u32 = 700;
const initial_bias: u32 = 72;
const initial_n: u32 = 128;

/// Appends the punycode of `label` to `out`, with no `xn--` in front.
///
/// RFC 3492 section 6.3. Every add and multiply is checked, which is what
/// section 6.4 asks for: an unchecked one would wrap and write a label
/// that decodes to another name.
fn punycode(allocator: std.mem.Allocator, label: []const u8, out: *std.ArrayList(u8)) GenerateError!void {
    var points: std.ArrayList(u32) = .empty;
    defer points.deinit(allocator);

    const view = std.unicode.Utf8View.init(label) catch return error.PslBadUtf8;
    var it = view.iterator();
    while (it.nextCodepoint()) |point| try points.append(allocator, point);

    var basic: u32 = 0;
    for (points.items) |point| {
        if (point < 0x80) {
            try out.append(allocator, std.ascii.toLower(@intCast(point)));
            basic += 1;
        }
    }
    if (basic > 0) try out.append(allocator, '-');

    var handled = basic;
    var n: u32 = initial_n;
    var delta: u32 = 0;
    var bias: u32 = initial_bias;

    while (handled < points.items.len) {
        // The smallest code point that is not yet handled.
        var m: u32 = std.math.maxInt(u32);
        for (points.items) |point| {
            if (point >= n and point < m) m = point;
        }
        if (m == std.math.maxInt(u32)) return error.PslPunycodeOverflow;

        const step = std.math.mul(u32, m - n, handled + 1) catch return error.PslPunycodeOverflow;
        delta = std.math.add(u32, delta, step) catch return error.PslPunycodeOverflow;
        n = m;

        for (points.items) |point| {
            if (point < n) delta = std.math.add(u32, delta, 1) catch return error.PslPunycodeOverflow;
            if (point != n) continue;

            var q = delta;
            var k: u32 = base;
            while (true) : (k += base) {
                const t: u32 = if (k <= bias) tmin else if (k >= bias + tmax) tmax else k - bias;
                if (q < t) break;
                try out.append(allocator, digitChar(t + (q - t) % (base - t)));
                q = (q - t) / (base - t);
            }
            try out.append(allocator, digitChar(q));
            bias = adapt(delta, handled + 1, handled == basic);
            delta = 0;
            handled += 1;
        }

        delta = std.math.add(u32, delta, 1) catch return error.PslPunycodeOverflow;
        n = std.math.add(u32, n, 1) catch return error.PslPunycodeOverflow;
    }
}

/// RFC 3492 section 6.1, the bias adaptation.
fn adapt(delta_in: u32, points: u32, first: bool) u32 {
    var delta = if (first) delta_in / damp else delta_in / 2;
    delta += delta / points;
    var k: u32 = 0;
    while (delta > ((base - tmin) * tmax) / 2) {
        delta /= base - tmin;
        k += base;
    }
    return k + (((base - tmin + 1) * delta) / (delta + skew));
}

/// RFC 3492 section 5, the digit alphabet: `a` to `z` then `0` to `9`.
fn digitChar(digit: u32) u8 {
    return if (digit < 26) @intCast('a' + digit) else @intCast('0' + (digit - 26));
}

const testing = std.testing;

/// A fixture with one of each rule kind, the comment lines the real file
/// carries, and an internationalised rule.
const test_list =
    \\// ===BEGIN ICANN DOMAINS===
    \\
    \\com
    \\uk
    \\co.uk
    \\ck
    \\*.ck
    \\!www.ck
    \\公司.cn
    \\cn
    \\// a comment in the middle
    \\
    \\// ===BEGIN PRIVATE DOMAINS===
    \\github.io
    \\
;

/// Builds the table for `text` and returns both the bytes and the counts.
fn buildFixture(allocator: std.mem.Allocator, text: []const u8) !struct { bytes: []u8, stats: Stats } {
    var out: std.ArrayList(u8) = .empty;
    const stats = try generate(allocator, text, &out, 1);
    return .{ .bytes = try out.toOwnedSlice(allocator), .stats = stats };
}

test "every rule kind is read, and comments and blank lines are not" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const built = try buildFixture(arena_state.allocator(), test_list);

    // com, uk, co.uk, ck, *.ck, 公司.cn, cn, github.io
    try testing.expectEqual(@as(usize, 8), built.stats.rules);
    try testing.expectEqual(@as(usize, 1), built.stats.exceptions);
}

test "the table answers the four rule kinds the way the specification says" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const built = try buildFixture(arena_state.allocator(), test_list);
    const table = try format.parse(built.bytes);

    // A normal rule of two labels.
    try testing.expect(format.isPublicSuffix(table, "co.uk"));
    try testing.expect(!format.isPublicSuffix(table, "example.co.uk"));
    // A wildcard rule.
    try testing.expect(format.isPublicSuffix(table, "foo.ck"));
    // An exception rule.
    try testing.expect(!format.isPublicSuffix(table, "www.ck"));
    // The private section counts like the rest.
    try testing.expect(format.isPublicSuffix(table, "github.io"));
    try testing.expect(!format.isPublicSuffix(table, "pages.github.io"));
}

test "an internationalised rule reaches the table as an A-label" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const built = try buildFixture(arena_state.allocator(), test_list);
    const table = try format.parse(built.bytes);

    // `公司.cn` is `xn--55qx5d.cn`, which is the form a url host carries.
    try testing.expect(format.contains(table, "cn.xn--55qx5d"));
    try testing.expect(format.isPublicSuffix(table, "xn--55qx5d.cn"));
    try testing.expect(!format.isPublicSuffix(table, "example.xn--55qx5d.cn"));
}

test "an empty or truncated list fails rather than writing a table" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.ArrayList(u8) = .empty;
    try testing.expectError(error.PslListTooShort, generate(arena, "", &out, 1));
    out.clearRetainingCapacity();
    try testing.expectError(error.PslListTooShort, generate(arena, "// only a comment\n", &out, 1));
    out.clearRetainingCapacity();
    try testing.expectError(error.PslListTooShort, generate(arena, test_list, &out, 4000));
    out.clearRetainingCapacity();
    // With no floor at all the encoder still refuses to write a table of
    // nothing, so neither half can ship an empty list on its own.
    try testing.expectError(error.PublicSuffixNothingToWrite, generate(arena, "", &out, 0));
    try testing.expectEqual(@as(usize, 0), out.items.len);
}

test "a rule this build cannot match fails the build" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.ArrayList(u8) = .empty;
    try testing.expectError(error.PslEmptyLabel, generate(arena, "a..b\n", &out, 1));
    out.clearRetainingCapacity();
    try testing.expectError(error.PslBadWildcard, generate(arena, "a*b.ck\n", &out, 1));
    out.clearRetainingCapacity();
    try testing.expectError(error.PslEmptyRule, generate(arena, "!\n", &out, 1));
    out.clearRetainingCapacity();
    try testing.expectError(error.PslBadUtf8, generate(arena, "\xff\xfe.cn\n", &out, 1));
}

test "a repeated rule is written once" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const built = try buildFixture(arena_state.allocator(), "com\ncom\nCOM\nnet\n");

    try testing.expectEqual(@as(usize, 2), built.stats.rules);
}

test "punycode matches the vectors of RFC 3492 and of the list" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const cases = [_]struct { unicode: []const u8, ascii: []const u8 }{
        // RFC 3492 section 7.1, the Arabic, Chinese, Czech and Japanese
        // samples. The list itself carries none of these, so they test the
        // coder and not the list.
        .{ .unicode = "\u{0644}\u{064A}\u{0647}\u{0645}\u{0627}\u{0628}\u{062A}\u{0643}\u{0644}\u{0645}\u{0648}\u{0634}\u{0639}\u{0631}\u{0628}\u{064A}\u{061F}", .ascii = "xn--egbpdaj6bu4bxfgehfvwxn" },
        .{ .unicode = "\u{4ED6}\u{4EEC}\u{4E3A}\u{4EC0}\u{4E48}\u{4E0D}\u{8BF4}\u{4E2D}\u{6587}", .ascii = "xn--ihqwcrb4cv8a8dqg056pqjye" },
        .{ .unicode = "\u{0050}\u{0072}\u{006F}\u{010D}\u{0070}\u{0072}\u{006F}\u{0073}\u{0074}\u{011B}\u{006E}\u{0065}\u{006D}\u{006C}\u{0075}\u{0076}\u{00ED}\u{010D}\u{0065}\u{0073}\u{006B}\u{0079}", .ascii = "xn--Proprostnemluvesky-uyb24dma41a" },
        // Entries of the list itself, checked against curl 8.21.0, which
        // reaches the same A-labels through libidn2.
        .{ .unicode = "\u{0440}\u{0444}", .ascii = "xn--p1ai" },
        .{ .unicode = "\u{516C}\u{53F8}", .ascii = "xn--55qx5d" },
        .{ .unicode = "\u{4E2D}\u{56FD}", .ascii = "xn--fiqs8s" },
        .{ .unicode = "\u{9999}\u{6E2F}", .ascii = "xn--j6w193g" },
    };

    for (cases) |case| {
        var out: std.ArrayList(u8) = .empty;
        try encodeLabel(arena, case.unicode, &out);
        // The coder writes lower case, and one RFC vector is mixed case.
        var lower: [label_len_max]u8 = undefined;
        const wanted = std.ascii.lowerString(lower[0..case.ascii.len], case.ascii);
        try testing.expectEqualStrings(wanted, out.items);
    }
}
