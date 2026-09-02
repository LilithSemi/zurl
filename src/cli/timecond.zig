//! zurl: what `-z`, `--time-cond` asks for.
//!
//! The flag names a moment, and the request then carries one header that
//! asks the server to answer only if the body changed on the right side of
//! it. This file reads the argument and writes the header value. It opens
//! nothing: an argument that names a file is resolved by `src/main.zig`,
//! the one place in the CLI that reads the file system.
//!
//! **The argument has a prefix and then a moment.** Measured against curl
//! 8.21.0 with a loopback server:
//!
//! ```
//! -z '21 Oct 2015 07:28:00 GMT'    If-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT
//! -z '+21 Oct 2015 07:28:00 GMT'   If-Modified-Since, the same line
//! -z '-21 Oct 2015 07:28:00 GMT'   If-Unmodified-Since: Wed, 21 Oct 2015 07:28:00 GMT
//! -z '=21 Oct 2015 07:28:00 GMT'   no header at all on http
//! -z tcfile                        If-Modified-Since, from the file's own time
//! -z -tcfile                       If-Unmodified-Since, from the file's own time
//! ```
//!
//! **A moment that reads as neither a date nor a file is dropped, with a
//! warning, and the transfer still runs.** That is curl's own answer,
//! measured: `-z 2015-10-21` prints `Illegal date format for -z,
//! --time-cond (and not a filename). Disabling time condition.` and sends
//! the request with no condition header. The exit code stays 0. zurl says
//! the same thing in its own words, so nothing is dropped in silence, and
//! nothing is guessed at either: a date this file cannot read is refused
//! by name rather than misread into a moment the user did not mean.
//!
//! `readDate` reads what curl's own `curl_getdate` reads, checked shape by
//! shape against the real program. See it for the measured table.

const std = @import("std");

/// The header a `-z` argument asks for.
pub const Condition = enum {
    /// The default, and what `+` spells outright. The server answers with
    /// the body when it changed after the moment, and with `304` when it
    /// did not.
    modified_since,
    /// What `-` spells. The server answers with the body when it did
    /// *not* change after the moment.
    unmodified_since,
    /// What `=` spells. curl uses it to ask an ftp server about a file's
    /// own `Last-Modified`, and it puts no header on an http request at
    /// all: measured, `-z '=21 Oct 2015 07:28:00 GMT'` sent neither
    /// condition header. This build sends none either.
    last_modified,

    /// The header name this condition writes, or null when it writes none.
    pub fn headerName(c: Condition) ?[]const u8 {
        return switch (c) {
            .modified_since => "If-Modified-Since",
            .unmodified_since => "If-Unmodified-Since",
            .last_modified => null,
        };
    }
};

/// One `-z` argument, split into the header it asks for and the text that
/// names the moment.
pub const Request = struct {
    condition: Condition,
    /// What is left after the prefix. Borrows from the argument.
    text: []const u8,
};

/// Splits a `-z` argument into its prefix and the rest.
///
/// An argument with no prefix byte asks for `If-Modified-Since`, which is
/// the default curl documents and the one measured above. An empty
/// argument keeps that default and carries empty text, which `readDate`
/// then refuses.
pub fn split(argument: []const u8) Request {
    if (argument.len == 0) return .{ .condition = .modified_since, .text = argument };
    return switch (argument[0]) {
        '+' => .{ .condition = .modified_since, .text = argument[1..] },
        '-' => .{ .condition = .unmodified_since, .text = argument[1..] },
        '=' => .{ .condition = .last_modified, .text = argument[1..] },
        else => .{ .condition = .modified_since, .text = argument },
    };
}

/// The longest `-z` argument `readDate` reads.
///
/// Every date curl accepts fits in far less. The bound stops a config file
/// handing an unbounded string to the token walk below.
pub const max_date_len: usize = 128;

/// The months, in the order `readDate` numbers them.
const month_names = [_][]const u8{
    "jan", "feb", "mar", "apr", "may", "jun",
    "jul", "aug", "sep", "oct", "nov", "dec",
};

/// The weekday names `readDate` steps over. A weekday adds nothing a date
/// needs, and curl ignores it too.
const weekday_names = [_][]const u8{
    "sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday",
};

/// The named time zones `readDate` reads, and the minutes each one sits
/// east of UTC.
///
/// curl reads a longer list, the military single letters among them. This
/// holds the four that a real server or a real command line writes. A name
/// outside it makes the whole date unreadable, which sends the argument on
/// to the file check and then to the warning, so nothing is guessed.
const zone_names = [_]struct { name: []const u8, minutes: i32 }{
    .{ .name = "gmt", .minutes = 0 },
    .{ .name = "utc", .minutes = 0 },
    .{ .name = "ut", .minutes = 0 },
    .{ .name = "z", .minutes = 0 },
};

/// Reads a `-z` date and returns it as seconds since the epoch, or null
/// when the text is not a date this build reads.
///
/// **This is curl's own algorithm, and it is a token walk and not a list
/// of formats.** curl's `curl_getdate` cuts the text into pieces and asks
/// what each piece is: a weekday name, a month name, a time, a zone, or a
/// number. The order does not matter, which is why one walk reads every
/// format curl's manual lists. Checked shape by shape against curl 8.21.0
/// with a loopback server, each one sending the same instant:
///
/// ```
/// Sun, 06 Nov 1994 08:49:37 GMT    RFC 1123
/// Sunday, 06-Nov-94 08:49:37 GMT   RFC 850
/// Sun Nov  6 08:49:37 1994         asctime
/// 06 Nov 1994 08:49:37 GMT         RFC 822
/// 06-Nov-94 08:49:37 GMT           RFC 850, no weekday
/// Nov 6 1994 08:49:37              no zone
/// 08:49:37 06 Nov 1994             the time first
/// 6 Nov 1994 08:49:37 +0100        a numeric zone, one hour east
/// 1994 Nov 6                       no time at all: midnight
/// 19941106 08:49:37                a packed date
/// 19941106                         a packed date, midnight
/// ```
///
/// And the shapes curl refuses, measured the same way. Each one made curl
/// print `Illegal date format for -z` and send no condition header, so
/// zurl refuses each of them too rather than read a moment curl would not:
///
/// ```
/// 1994-11-06 08:49:37   no month name, and the digits are not packed
/// 1994-11-06            the same
/// 2015-10-21T07:28:00Z  the same
/// 10/21/2015            the same
/// now                   curl reads no relative word
/// yesterday             the same
/// 1445412480            a bare epoch second is not a date
/// ```
///
/// A date with no time is midnight, which is what curl answers for
/// `1994 Nov 6`. A date with no zone is UTC, which is what curl answers
/// for `Nov 6 1994 08:49:37`.
///
/// Returns null rather than an error. A `-z` argument that is not a date
/// may still be a file name, so the caller has one more thing to try
/// before it warns.
pub fn readDate(text: []const u8) ?i64 {
    if (text.len == 0 or text.len > max_date_len) return null;

    var hour: ?u32 = null;
    var minute: u32 = 0;
    var second: u32 = 0;
    var day: ?u32 = null;
    var month: ?u32 = null;
    var year: ?u32 = null;
    var zone_minutes: i32 = 0;

    // Every round consumes at least one byte, so `max_date_len` bounds
    // this walk.
    var rest = text;
    while (rest.len != 0) {
        while (rest.len != 0 and isDelimiter(rest[0])) rest = rest[1..];
        var end: usize = 0;
        while (end < rest.len and !isDelimiter(rest[end])) end += 1;
        const piece = rest[0..end];
        rest = rest[end..];
        if (piece.len == 0) continue;

        // A weekday says nothing a date needs. curl steps over it too.
        if (isWeekday(piece)) continue;

        if (hour == null) {
            if (readTime(piece)) |time| {
                hour = time.hour;
                minute = time.minute;
                second = time.second;
                continue;
            }
        }
        if (month == null) {
            if (readMonth(piece)) |number| {
                month = number;
                continue;
            }
        }
        if (readZone(piece)) |offset| {
            zone_minutes = offset;
            continue;
        }
        // **A packed date fills three fields at once.** curl reads
        // `19941106` as a whole date, measured, and no other eight digit
        // number is a date at all.
        if (piece.len == 8 and allDigits(piece) and year == null and month == null and day == null) {
            year = std.fmt.parseInt(u32, piece[0..4], 10) catch return null;
            month = std.fmt.parseInt(u32, piece[4..6], 10) catch return null;
            day = std.fmt.parseInt(u32, piece[6..8], 10) catch return null;
            continue;
        }
        if (piece.len == 4 and allDigits(piece) and year == null) {
            year = std.fmt.parseInt(u32, piece, 10) catch return null;
            continue;
        }
        if (day == null and piece.len <= 2 and allDigits(piece)) {
            day = std.fmt.parseInt(u32, piece, 10) catch return null;
            continue;
        }
        if (year == null and piece.len == 2 and allDigits(piece)) {
            year = std.fmt.parseInt(u32, piece, 10) catch return null;
            continue;
        }
        // A piece that is none of the above makes the whole text
        // unreadable. curl stops on an unknown token too, which is why
        // `2015-10-21T07:28:00Z` and `10/21/2015` reach no header.
        return null;
    }

    var y = year orelse return null;
    const m = month orelse return null;
    const d = day orelse return null;
    // A two digit year reads the way RFC 6265 reads one: 70 through 99 is
    // the 1900s and 0 through 69 is the 2000s. curl reads `06-Nov-94` as
    // 1994, measured.
    if (y >= 70 and y <= 99) y += 1900;
    if (y <= 69) y += 2000;

    if (m < 1 or m > 12) return null;
    if (d < 1 or d > 31) return null;
    const h = hour orelse 0;
    if (h > 23 or minute > 59 or second > 59) return null;
    if (y < 1601 or y > 9999) return null;

    const days = daysFromCivil(y, m, d);
    const seconds = @as(i64, days) * 86400 +
        @as(i64, h) * 3600 + @as(i64, minute) * 60 + @as(i64, second);
    // A zone east of UTC names an earlier instant, so its offset comes
    // off. Measured: `6 Nov 1994 08:49:37 +0100` sent `07:49:37 GMT`.
    return seconds - @as(i64, zone_minutes) * 60;
}

/// The longest text `writeHeaderValue` writes, so a caller can size one
/// buffer for it. An IMF-fixdate is always 29 bytes.
pub const header_value_len: usize = 29;

/// The first instant `writeHeaderValue` spells: 1601-01-01, the year
/// `readDate` floors at.
const min_header_seconds: i64 = -11644473600;

/// The last instant `writeHeaderValue` spells: the last second of 9999,
/// which is the last year four digits hold.
const max_header_seconds: i64 = 253402300799;

/// Writes `seconds` into `buffer` as the IMF-fixdate a condition header
/// carries, and returns what it wrote.
///
/// RFC 9110 gives `If-Modified-Since` and `If-Unmodified-Since` the one
/// fixed format, `Sun, 06 Nov 1994 08:49:37 GMT`, and curl writes exactly
/// that: measured, every accepted `-z` argument above reached the wire in
/// this shape whatever shape the user typed.
///
/// **A moment outside the years the format can spell answers null.** A
/// caller's value may come from a file's own timestamp, and a file system
/// puts no bound on that: a stamp far in the future would need a year of
/// more than four digits, and the line would then be the wrong length and
/// carry a year no server reads. The caller drops the condition and says
/// so, rather than send a header that is not an IMF-fixdate.
pub fn writeHeaderValue(buffer: *[header_value_len]u8, seconds: i64) ?[]const u8 {
    const day_names = [_][]const u8{ "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun" };
    const month_titles = [_][]const u8{
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    };

    // Floor division, so a moment before the epoch still lands on the day
    // that holds it rather than on the day after.
    // The bound the format itself carries: four digits of year, and no
    // year before the one the civil calendar this file implements starts
    // at. Checked before the arithmetic, so nothing below can overflow
    // the 29 bytes.
    if (seconds < min_header_seconds or seconds > max_header_seconds) return null;

    const days = @divFloor(seconds, 86400);
    const in_day: u32 = @intCast(seconds - days * 86400);
    const civil = civilFromDays(days);

    // 1970-01-01 was a Thursday, which is index 3 of `day_names`.
    const weekday: usize = @intCast(@mod(days + 3, 7));

    return std.fmt.bufPrint(buffer, "{s}, {d:0>2} {s} {d:0>4} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
        day_names[weekday],
        civil.day,
        month_titles[civil.month - 1],
        civil.year,
        in_day / 3600,
        (in_day / 60) % 60,
        in_day % 60,
    }) catch unreachable;
}

/// The delimiters that cut one piece of a date from the next.
///
/// Space, tab, comma, and dash. The dash is what makes `06-Nov-94` read
/// as three pieces, which curl reads too. A `+` is not a delimiter: it
/// starts a numeric zone, and `readZone` needs it.
fn isDelimiter(byte: u8) bool {
    return byte == ' ' or byte == '\t' or byte == ',' or byte == '-';
}

fn allDigits(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |byte| {
        if (!std.ascii.isDigit(byte)) return false;
    }
    return true;
}

fn isWeekday(piece: []const u8) bool {
    if (piece.len < 3) return false;
    for (weekday_names) |name| {
        // The three letter form and the whole word both count, which is
        // what `Sun` and `Sunday` need.
        if (std.ascii.eqlIgnoreCase(piece[0..3], name[0..3])) {
            return piece.len == 3 or std.ascii.eqlIgnoreCase(piece, name);
        }
    }
    return false;
}

fn readMonth(piece: []const u8) ?u32 {
    if (piece.len < 3) return null;
    for (month_names, 0..) |name, index| {
        if (std.ascii.eqlIgnoreCase(piece[0..3], name)) return @intCast(index + 1);
    }
    return null;
}

/// Reads `hh:mm` or `hh:mm:ss`. A piece with no colon is not a time.
fn readTime(piece: []const u8) ?struct { hour: u32, minute: u32, second: u32 } {
    var it = std.mem.splitScalar(u8, piece, ':');
    const h = it.next() orelse return null;
    const m = it.next() orelse return null;
    const s = it.next() orelse "0";
    if (it.next() != null) return null;
    if (h.len < 1 or h.len > 2 or m.len < 1 or m.len > 2 or s.len < 1 or s.len > 2) return null;
    if (!allDigits(h) or !allDigits(m) or !allDigits(s)) return null;
    return .{
        .hour = std.fmt.parseInt(u32, h, 10) catch return null,
        .minute = std.fmt.parseInt(u32, m, 10) catch return null,
        .second = std.fmt.parseInt(u32, s, 10) catch return null,
    };
}

/// Reads a zone, either a name from `zone_names` or a numeric `+hhmm`.
///
/// A bare `-hhmm` never reaches here: the dash is a delimiter, so a west
/// zone arrives as the digits alone and reads as a year or a day instead.
/// curl has the same gap in the same place, and a date whose zone was
/// dropped is still refused rather than misread whenever the digits fit
/// no other field.
fn readZone(piece: []const u8) ?i32 {
    for (zone_names) |zone| {
        if (std.ascii.eqlIgnoreCase(piece, zone.name)) return zone.minutes;
    }
    if (piece.len == 5 and piece[0] == '+' and allDigits(piece[1..])) {
        const hours = std.fmt.parseInt(i32, piece[1..3], 10) catch return null;
        const minutes = std.fmt.parseInt(i32, piece[3..5], 10) catch return null;
        if (hours > 23 or minutes > 59) return null;
        return hours * 60 + minutes;
    }
    return null;
}

/// Days from 1970-01-01 to `year`-`month`-`day`, by Howard Hinnant's
/// `days_from_civil`. The same algorithm `zurl_core.cookie` uses, and the
/// two agree on every date because both are that one published formula.
fn daysFromCivil(year: u32, month: u32, day: u32) i64 {
    const y: i64 = @as(i64, year) - @intFromBool(month <= 2);
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const m: i64 = @intCast(month);
    const d: i64 = @intCast(day);
    const doy = @divTrunc(153 * (m + (if (m > 2) @as(i64, -3) else 9)) + 2, 5) + d - 1;
    const doe = yoe * 365 + @divTrunc(yoe, 4) - @divTrunc(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

/// The inverse of `daysFromCivil`, by the same author's
/// `civil_from_days`. `writeHeaderValue` needs it to name the day.
fn civilFromDays(days: i64) struct { year: u32, month: u32, day: u32 } {
    const z = days + 719468;
    const era = @divFloor(z, 146097);
    const doe = z - era * 146097;
    const yoe = @divTrunc(doe - @divTrunc(doe, 1460) + @divTrunc(doe, 36524) - @divTrunc(doe, 146096), 365);
    const y = yoe + era * 400;
    const doy = doe - (365 * yoe + @divTrunc(yoe, 4) - @divTrunc(yoe, 100));
    const mp = @divTrunc(5 * doy + 2, 153);
    const d = doy - @divTrunc(153 * mp + 2, 5) + 1;
    const m = mp + (if (mp < 10) @as(i64, 3) else -9);
    return .{
        .year = @intCast(y + @intFromBool(m <= 2)),
        .month = @intCast(m),
        .day = @intCast(d),
    };
}

const testing = std.testing;

test "split reads the prefix curl reads" {
    try testing.expectEqual(Condition.modified_since, split("21 Oct 2015").condition);
    try testing.expectEqualStrings("21 Oct 2015", split("21 Oct 2015").text);

    try testing.expectEqual(Condition.modified_since, split("+21 Oct 2015").condition);
    try testing.expectEqualStrings("21 Oct 2015", split("+21 Oct 2015").text);

    try testing.expectEqual(Condition.unmodified_since, split("-21 Oct 2015").condition);
    try testing.expectEqualStrings("21 Oct 2015", split("-21 Oct 2015").text);

    try testing.expectEqual(Condition.last_modified, split("=21 Oct 2015").condition);
    try testing.expectEqualStrings("21 Oct 2015", split("=21 Oct 2015").text);

    // A prefix with nothing after it leaves empty text, which `readDate`
    // refuses, and an empty argument keeps the default condition.
    try testing.expectEqualStrings("", split("-").text);
    try testing.expectEqual(Condition.modified_since, split("").condition);
}

test "a condition names the header curl sends, and = names none" {
    try testing.expectEqualStrings("If-Modified-Since", Condition.modified_since.headerName().?);
    try testing.expectEqualStrings("If-Unmodified-Since", Condition.unmodified_since.headerName().?);
    // Measured: `-z '=<a date>'` put neither condition header on an http
    // request.
    try testing.expectEqual(@as(?[]const u8, null), Condition.last_modified.headerName());
}

test "readDate reads every shape curl 8.21.0 reads" {
    // Every line below reached curl and produced the same instant on the
    // wire: `Sun, 06 Nov 1994 08:49:37 GMT`.
    const wanted: i64 = 784111777;
    const accepted = [_][]const u8{
        "Sun, 06 Nov 1994 08:49:37 GMT",
        "Sunday, 06-Nov-94 08:49:37 GMT",
        "Sun Nov  6 08:49:37 1994",
        "06 Nov 1994 08:49:37 GMT",
        "06-Nov-94 08:49:37 GMT",
        "Nov 6 1994 08:49:37",
        "08:49:37 06 Nov 1994",
        "6 Nov 1994 08:49:37 UTC",
        "19941106 08:49:37",
    };
    for (accepted) |text| {
        const read = readDate(text) orelse {
            std.debug.print("'{s}' did not read as a date\n", .{text});
            return error.TestUnexpectedResult;
        };
        if (read != wanted) {
            std.debug.print("'{s}' read as {d}, wanted {d}\n", .{ text, read, wanted });
            return error.TestUnexpectedResult;
        }
    }

    // A numeric zone east of UTC names an earlier instant. Measured:
    // curl sent `07:49:37 GMT` for this one.
    try testing.expectEqual(@as(?i64, wanted - 3600), readDate("6 Nov 1994 08:49:37 +0100"));

    // No time at all is midnight, which is what curl answered for both.
    const midnight: i64 = 784080000;
    try testing.expectEqual(@as(?i64, midnight), readDate("1994 Nov 6"));
    try testing.expectEqual(@as(?i64, midnight), readDate("19941106"));
}

test "readDate refuses every shape curl 8.21.0 refuses" {
    // Each of these made curl print `Illegal date format for -z` and send
    // no condition header. A zurl that read one of them would put a
    // moment on the wire that curl never would.
    const refused = [_][]const u8{
        "1994-11-06 08:49:37",
        "1994-11-06",
        "2015-10-21T07:28:00Z",
        "10/21/2015",
        "now",
        "yesterday",
        "1445412480",
        "gibberish-not-a-date",
        "",
        // A month with no day, and a day with no month. Neither names a
        // moment.
        "Nov 1994",
        "06 1994",
    };
    for (refused) |text| {
        if (readDate(text)) |read| {
            std.debug.print("'{s}' read as {d}, and curl refuses it\n", .{ text, read });
            return error.TestUnexpectedResult;
        }
    }

    // Past the bound, whatever it holds.
    const long = "Sun, 06 Nov 1994 08:49:37 GMT" ** 8;
    try testing.expect(long.len > max_date_len);
    try testing.expectEqual(@as(?i64, null), readDate(long));
}

test "readDate refuses a field outside its own range" {
    // The walk reads the pieces, and these checks are what stop a piece
    // that read cleanly from naming a moment that does not exist.
    try testing.expectEqual(@as(?i64, null), readDate("32 Nov 1994"));
    try testing.expectEqual(@as(?i64, null), readDate("06 Nov 1994 24:00:00"));
    try testing.expectEqual(@as(?i64, null), readDate("06 Nov 1994 08:60:00"));
    try testing.expectEqual(@as(?i64, null), readDate("19941332"));
}

test "writeHeaderValue writes the one format RFC 9110 names" {
    var buffer: [header_value_len]u8 = undefined;
    try testing.expectEqualStrings(
        "Sun, 06 Nov 1994 08:49:37 GMT",
        writeHeaderValue(&buffer, 784111777).?,
    );
    try testing.expectEqualStrings(
        "Thu, 01 Jan 1970 00:00:00 GMT",
        writeHeaderValue(&buffer, 0).?,
    );
    // The `Last-Modified` of the measurement fixture, and the exact line
    // curl put on the wire for `-z tcfile` against a file stamped there.
    try testing.expectEqualStrings(
        "Wed, 21 Oct 2015 07:28:00 GMT",
        writeHeaderValue(&buffer, 1445412480).?,
    );
    // Every line is exactly the one length RFC 9110 gives it.
    try testing.expectEqual(header_value_len, writeHeaderValue(&buffer, 0).?.len);
}

test "writeHeaderValue refuses a moment no four digit year holds" {
    // A file timestamp has no bound of its own, so this is the guard that
    // keeps a stamp far outside the calendar from writing a line that is
    // not an IMF-fixdate. The caller drops the condition instead.
    var buffer: [header_value_len]u8 = undefined;
    try testing.expectEqual(@as(?[]const u8, null), writeHeaderValue(&buffer, 253402300800));
    try testing.expectEqual(@as(?[]const u8, null), writeHeaderValue(&buffer, -11644473601));
    try testing.expectEqual(@as(?[]const u8, null), writeHeaderValue(&buffer, std.math.maxInt(i64)));
    try testing.expectEqual(@as(?[]const u8, null), writeHeaderValue(&buffer, std.math.minInt(i64)));

    // And the two moments just inside the bound still write.
    try testing.expectEqualStrings(
        "Fri, 31 Dec 9999 23:59:59 GMT",
        writeHeaderValue(&buffer, 253402300799).?,
    );
    try testing.expectEqualStrings(
        "Mon, 01 Jan 1601 00:00:00 GMT",
        writeHeaderValue(&buffer, -11644473600).?,
    );
}

test "readDate and writeHeaderValue round trip every accepted shape" {
    // The property that matters on the wire: whatever shape the user
    // typed, the header carries the one format, and reading that header
    // back gives the same instant.
    var buffer: [header_value_len]u8 = undefined;
    const shapes = [_][]const u8{
        "Sun, 06 Nov 1994 08:49:37 GMT",
        "Sunday, 06-Nov-94 08:49:37 GMT",
        "Sun Nov  6 08:49:37 1994",
        "19941106 08:49:37",
        "1994 Nov 6",
    };
    for (shapes) |text| {
        const first = readDate(text).?;
        const line = writeHeaderValue(&buffer, first).?;
        try testing.expectEqual(@as(?i64, first), readDate(line));
    }
}
