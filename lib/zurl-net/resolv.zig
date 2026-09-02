//! The guard over `/etc/resolv.conf`, read before a name lookup starts.
//!
//! zurl does not resolve a name itself. `std.Io.net.HostName.connect`
//! does, through the resolver in `std.Io.Threaded`, and that resolver
//! reads `/etc/resolv.conf` at every lookup. Two values in that file make
//! the resolver leave its own buffers:
//!
//! - A `search` line longer than 255 octets.
//!   `std.Io.net.HostName.ResolvConf.parse` copies the rest of the line
//!   into a 255 octet array with no length check, and then records the
//!   length it copied. The copy writes past the array, and the slice the
//!   resolver makes from the recorded length is longer than the array it
//!   points into.
//! - `options attempts:0`. The resolver divides by that value to get the
//!   wait of one attempt.
//!
//! A third pair of values is unsafe together. The resolver joins the host
//! name, a dot, and one search domain in a 255 octet array, again with no
//! length check, so a long name and a search list overflow that array
//! together while each one alone fits.
//!
//! **The file is local, so none of this is a remote fault, and the
//! severity is bounded by that.** It is guarded anyway for two reasons. A
//! write past an array and a division by zero are the same defect whoever
//! wrote the file, and nobody types this file: a container image and a
//! DHCP lease both write it, and the user reads neither. The build a user
//! runs carries no safety checks, so the write happens there instead of a
//! panic.
//!
//! So this file reads the same file with the same grammar and answers one
//! question: can the resolver look this name up without leaving a buffer?
//! `tcp.dial` asks it before every lookup and refuses the dial when the
//! answer is no. A file the resolver can use is never changed by this
//! guard, and a file this guard cannot read is never a refusal: the
//! resolver falls back to `127.0.0.1` with no search list, which is safe.
//!
//! **The grammar here must stay the same as the grammar in `std`.** Every
//! reading below is the reading `std.Io.net.HostName.ResolvConf.parse`
//! makes of the same bytes, down to where a comment starts and which
//! `search` line wins. A guard that read the file differently would
//! either refuse a file the resolver handles or pass a file it does not.

const std = @import("std");

/// Every fault this guard can report. Each one says which value of
/// `/etc/resolv.conf` the resolver cannot use, so the sentence a user
/// reads names the file and the line.
pub const GuardError = error{
    /// The `search` or `domain` line is longer than the array the
    /// resolver copies it into.
    ResolverSearchListTooLong,
    /// The file holds `options attempts:0`, and the resolver divides by
    /// that value.
    ResolverAttemptsZero,
    /// The host name and one search domain do not fit together in the
    /// array the resolver joins them in.
    ResolverSearchNameTooLong,
};

/// Where the resolver reads its configuration.
pub const path = "/etc/resolv.conf";

/// The line buffer `std.Io.net.HostName.ResolvConf.init` gives its
/// reader.
///
/// This guard uses the same size on purpose. A line that does not fit
/// makes the reader of `std` report `error.StreamTooLong`, and the
/// resolver then refuses the whole file with `ResolvConfParseFailed`
/// before it copies anything. So a guard that stops at the same line
/// stops where the resolver stops, and no unsafe value can hide behind a
/// line that neither of them reads.
const line_buffer_len = 512;

/// The array the resolver copies the search list into, and the array it
/// joins a name and a search domain in. Both are
/// `std.Io.net.HostName.max_len`.
const buffer_len = std.Io.net.HostName.max_len;

/// The values of `/etc/resolv.conf` that decide whether a lookup is safe.
///
/// The defaults are the defaults of `std.Io.net.HostName.ResolvConf`, so
/// a file with none of these directives reads the same here as it does
/// there. `timeout` and `nameserver` are not here, because neither one
/// can drive the resolver out of a buffer.
pub const Config = struct {
    /// The length the resolver records in `search_len`, which is the
    /// length of the rest of the last `search` or `domain` line.
    search_len: usize = 0,
    /// The longest single domain of that search list.
    longest_domain: usize = 0,
    /// How many dots a name must hold before the search list is skipped.
    ndots: u8 = 1,
    /// How many times the resolver asks before it gives up.
    attempts: u8 = 2,
};

/// The directives this guard reads. The names are the names `std` reads.
const Directive = enum { options, nameserver, domain, search };

/// The options this guard reads. `timeout` is left out because the
/// resolver only multiplies by it.
const Option = enum { ndots, attempts };

/// Reads `/etc/resolv.conf` and reports whether the resolver can look
/// `name` up without leaving a buffer.
///
/// A file that cannot be opened is not a refusal. The resolver answers a
/// missing file with `127.0.0.1` and no search list, and both of those
/// are safe, so the dial carries on.
///
/// `name` is the written host name, with no brackets and with any
/// trailing dot still on it, which is what `tcp.Host` holds.
pub fn guard(io: std.Io, name: []const u8) GuardError!void {
    const file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch return;
    defer file.close(io);

    var line_buffer: [line_buffer_len]u8 = undefined;
    var file_reader = file.reader(io, &line_buffer);
    return check(read(&file_reader.interface), name);
}

/// Reads the configuration out of `reader`.
///
/// A read that fails ends the walk and keeps what was read so far. That
/// is not a silent recovery: the reader of `std` fails at the same byte
/// with the same buffer, and the resolver turns any such fault into
/// `ResolvConfParseFailed` and looks nothing up. So this guard only has
/// to be right about the files the resolver accepts.
pub fn read(reader: *std.Io.Reader) Config {
    var config: Config = .{};

    while (reader.takeSentinel('\n')) |line_with_comment| {
        const line = line: {
            var split = std.mem.splitScalar(u8, line_with_comment, '#');
            break :line split.first();
        };
        var line_it = std.mem.tokenizeAny(u8, line, " \t");

        const token = line_it.next() orelse continue;
        switch (std.meta.stringToEnum(Directive, token) orelse continue) {
            .options => while (line_it.next()) |sub_token| {
                var colon_it = std.mem.splitScalar(u8, sub_token, ':');
                const option_name = colon_it.first();
                const value_text = colon_it.next() orelse continue;
                // The two recoveries are the recoveries of `std`: a value
                // above 255 reads as 255, and a value that is not a
                // number leaves the option alone.
                const value = std.fmt.parseInt(u8, value_text, 10) catch |err| switch (err) {
                    error.Overflow => 255,
                    error.InvalidCharacter => continue,
                };
                switch (std.meta.stringToEnum(Option, option_name) orelse continue) {
                    .ndots => config.ndots = @min(value, 15),
                    .attempts => config.attempts = @min(value, 10),
                }
            },
            // A nameserver address cannot drive the resolver out of a
            // buffer. The resolver holds three of them in an array it
            // bounds itself.
            .nameserver => continue,
            // The last such line wins, because the resolver overwrites
            // its one search array at every line.
            .domain, .search => {
                const rest = line_it.rest();
                config.search_len = rest.len;
                config.longest_domain = longestDomain(rest);
            },
        }
    } else |_| {}

    return config;
}

/// The longest whitespace separated domain of `search`.
///
/// The resolver appends one domain at a time, so the longest one is what
/// decides whether the join fits.
fn longestDomain(search: []const u8) usize {
    var longest: usize = 0;
    var it = std.mem.tokenizeAny(u8, search, " \t");
    while (it.next()) |domain| longest = @max(longest, domain.len);
    return longest;
}

/// Reports whether the resolver can look `name` up under `config`.
///
/// The three checks are in the order the resolver reaches them: it copies
/// the search list first, then works out the wait of one attempt, then
/// joins the name with a search domain.
pub fn check(config: Config, name: []const u8) GuardError!void {
    if (config.search_len > buffer_len) return error.ResolverSearchListTooLong;
    if (config.attempts == 0) return error.ResolverAttemptsZero;

    // The resolver skips the search list for a name that already holds
    // `ndots` dots, and for a name that ends in a dot, which asks for the
    // root. Neither of those can reach the join at all.
    if (config.longest_domain == 0) return;
    if (std.mem.endsWith(u8, name, ".")) return;
    if (std.mem.countScalar(u8, name, '.') >= config.ndots) return;

    // The join is the name, one dot, and one search domain.
    if (name.len + 1 + config.longest_domain > buffer_len) {
        return error.ResolverSearchNameTooLong;
    }
}

const testing = std.testing;

/// Reads `text` the way `guard` reads the file.
fn readText(text: []const u8) Config {
    var reader: std.Io.Reader = .fixed(text);
    return read(&reader);
}

test "an ordinary file leaves every dial alone" {
    const config = readText(
        \\# Generated by resolvconf
        \\nameserver 1.1.1.1
        \\nameserver 1.0.0.1
        \\search example.com corp.example.com
        \\options edns0 trust-ad ndots:1
        \\
    );

    try testing.expectEqual(@as(u8, 1), config.ndots);
    try testing.expectEqual(@as(u8, 2), config.attempts);
    try check(config, "www.example.com");
    // A single label holds no dot, so it does reach the join. The longest
    // domain here is 19 characters, so the join is far inside the array.
    try check(config, "host");
}

test "a search line longer than the resolver copies it is refused" {
    // **This is the write.** The resolver copies the rest of the line
    // into a 255 octet array with no length check, so a 400 octet line
    // writes 145 octets past the end of it, and then records 400 as the
    // length. The build a user runs makes that write instead of a panic.
    var text: [16 + 400]u8 = undefined;
    @memcpy(text[0..7], "search ");
    @memset(text[7..407], 'a');
    text[407] = '\n';

    try testing.expectError(
        error.ResolverSearchListTooLong,
        check(readText(text[0..408]), "example.com"),
    );
}

test "a search line the array holds exactly is not refused" {
    // The bound is the length of the array and not one less than it. A
    // guard that refused 255 octets would refuse a file the resolver
    // handles correctly, which is a working machine zurl would not dial
    // from.
    var text: [8 + 256]u8 = undefined;
    @memcpy(text[0..7], "search ");
    @memset(text[7..262], 'a');
    text[262] = '\n';

    const fits = readText(text[0..263]);
    try testing.expectEqual(@as(usize, 255), fits.search_len);
    // The name holds a dot and `ndots` is 1, so the search list is
    // skipped and only the length of the line is under test here.
    try check(fits, "a.example.com");

    // One octet more is the first length that writes past the array.
    text[262] = 'a';
    text[263] = '\n';
    try testing.expectError(
        error.ResolverSearchListTooLong,
        check(readText(text[0..264]), "a.example.com"),
    );
}

test "attempts of zero is refused before the resolver divides by it" {
    // The resolver works the wait of one attempt out as
    // `(ns_per_s / attempts) * timeout_seconds`. A zero there is
    // undefined behaviour in the build a user runs and a panic in a build
    // with the checks on.
    const config = readText(
        \\nameserver 1.1.1.1
        \\options attempts:0
        \\
    );

    try testing.expectEqual(@as(u8, 0), config.attempts);
    try testing.expectError(error.ResolverAttemptsZero, check(config, "example.com"));
}

test "an attempts value the resolver can divide by is left alone" {
    try check(readText("options attempts:1\n"), "example.com");
    try check(readText("options attempts:5\n"), "example.com");
    // The resolver holds the value to 10, and a value above 255 reads as
    // 255 first. Neither one is zero, so neither one is refused.
    try testing.expectEqual(@as(u8, 10), readText("options attempts:99\n").attempts);
    try testing.expectEqual(@as(u8, 10), readText("options attempts:1000\n").attempts);
    try check(readText("options attempts:1000\n"), "example.com");
}

test "an attempts value that is not a number leaves the default in place" {
    // The resolver skips a value it cannot read, so the default of two
    // stands and nothing is refused. A guard that read it as zero would
    // refuse every dial on such a machine.
    const config = readText("options attempts:x\n");
    try testing.expectEqual(@as(u8, 2), config.attempts);
    try check(config, "example.com");
}

test "a name and a search domain that do not fit together are refused" {
    // Each one alone fits in the array. The resolver joins them with a
    // dot between and writes the result into 255 octets with no length
    // check, so the two together are what overflows.
    const config = readText(
        \\search default.svc.cluster.local svc.cluster.local
        \\options ndots:5
        \\
    );

    var name: [251]u8 = undefined;
    for (&name, 0..) |*byte, i| byte.* = if ((i + 1) % 64 == 0) '.' else 'a';

    // 251 + 1 + 25 is 277, which is 22 octets past the array.
    try testing.expectError(
        error.ResolverSearchNameTooLong,
        check(config, &name),
    );
    // A short name under the same file is far inside the array.
    try check(config, "web");
}

test "a name with enough dots never reaches the join" {
    // The resolver skips the search list once a name holds `ndots` dots,
    // so such a name cannot overflow the join however long the search
    // list is. A guard that refused it would refuse a name that resolves.
    const config = readText(
        \\search default.svc.cluster.local
        \\options ndots:2
        \\
    );

    var name: [251]u8 = undefined;
    for (&name, 0..) |*byte, i| byte.* = if ((i + 1) % 64 == 0) '.' else 'a';

    // Three dots, which is `ndots` or more, so the search list is
    // skipped.
    try check(config, &name);
}

test "a trailing dot asks for the root and skips the search list" {
    // A name that ends in a dot is a request for global scope. The
    // resolver skips the search list for it, so the join cannot overflow.
    const config = readText(
        \\search default.svc.cluster.local
        \\options ndots:15
        \\
    );

    var name: [252]u8 = undefined;
    @memset(name[0..251], 'a');
    name[251] = '.';

    try check(config, &name);
    // The same name without the dot does reach the join, so the dot is
    // what this test is about and not the length.
    try testing.expectError(error.ResolverSearchNameTooLong, check(config, name[0..251]));
}

test "a file with no search list refuses nothing" {
    const config = readText(
        \\nameserver 127.0.0.53
        \\options edns0 trust-ad
        \\
    );

    try testing.expectEqual(@as(usize, 0), config.search_len);
    try testing.expectEqual(@as(usize, 0), config.longest_domain);

    var name: [253]u8 = undefined;
    for (&name, 0..) |*byte, i| byte.* = if ((i + 1) % 64 == 0) '.' else 'a';
    try check(config, &name);
}

test "the last search line wins, the way the resolver reads it" {
    // The resolver overwrites its one search array at every `search` or
    // `domain` line, so an earlier line cannot decide anything. A guard
    // that kept the first line would refuse on a value the resolver threw
    // away.
    const config = readText(
        \\search averylongdomainname.example.com
        \\domain a.io
        \\
    );

    try testing.expectEqual(@as(usize, 4), config.longest_domain);
    try testing.expectEqual(@as(usize, 4), config.search_len);
}

test "a comment is not part of the search list" {
    // The resolver cuts the line at the first `#`. A guard that counted
    // the comment would refuse a file over a length nothing copies.
    var text: [8 + 400]u8 = undefined;
    @memcpy(text[0..9], "search a#");
    @memset(text[9..399], 'b');
    text[399] = '\n';

    const config = readText(text[0..400]);
    try testing.expectEqual(@as(usize, 1), config.search_len);
    try check(config, "example");
}

test "a guard fault names which value the resolver cannot use" {
    // Three faults and three sentences. One name for all of them would
    // send a user to read a file without saying which line to look at.
    try testing.expect(GuardError.ResolverSearchListTooLong != GuardError.ResolverAttemptsZero);
    try testing.expect(GuardError.ResolverAttemptsZero != GuardError.ResolverSearchNameTooLong);
}

test "the guard reads the machine's own file without refusing an ordinary name" {
    // The one test that opens the real file. Every machine a build runs
    // on is expected to hold a file the resolver can use, so a refusal
    // here is a machine that would drive the resolver out of a buffer.
    //
    // A machine with no such file is not a failure. The resolver falls
    // back to `127.0.0.1` with no search list, and the guard allows it.
    try guard(testing.io, "example.com");
}
