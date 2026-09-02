//! curl's `-w` / `--write-out` format string.
//!
//! `Args` captures the string unparsed in `Plan.write_out`. This file
//! renders it, once for each url, after that url's transfer ends.
//!
//! `render` takes a `Values`, not a `Response`. The values it needs come
//! from three places: the response head, the url the transfer finished on,
//! and a `zurl-stream.Speedometer` that counted the body bytes and the
//! time. A struct of finished numbers keeps this file free of the
//! transfer, so every rule below has a test that starts no server.
//!
//! **Every rendering here was measured against curl 8.21.0.** A `-w`
//! string goes into a script, and a script reads the bytes. The measured
//! forms are:
//!
//! - `%{http_code}` prints three digits, zero-padded on the left. A
//!   transfer that got no response at all prints `000`.
//! - `%{size_download}` prints a plain integer with no separator and no
//!   unit.
//! - `%{speed_download}` prints a plain integer, in bytes per second,
//!   truncated and not rounded. curl 8.21.0 prints no decimal point here.
//! - `%{time_total}` prints seconds with exactly six decimal places, such
//!   as `0.007275`. The separator is always `.`, measured under
//!   `LC_ALL=de_DE.UTF-8` as well as `LC_ALL=C`.
//! - `%{url_effective}` prints the url the transfer finished on. With no
//!   redirect that is the url the command line gave. With `-L` it is the
//!   final hop.
//! - `%{content_type}` prints the final response's `Content-Type` value
//!   whole, including any `charset` parameter, such as
//!   `text/plain; charset=utf-8`. A response that carried no
//!   `Content-Type` prints nothing at all, not a word such as `none`.
//!
//! **An unknown variable does not print, and it does not fail the run.**
//! The plan for this task said curl writes an unknown `%{...}` through
//! literally. curl 8.21.0 does not. Measured directly against the real
//! program, `curl -w 'A%{bogus}B'` prints `AB` on standard output and
//! writes one line to standard error:
//!
//! ```
//! curl: unknown --write-out variable: 'bogus'
//! ```
//!
//! The exit code stays 0, and `-s` does not hide the line. zurl copies
//! that: the variable prints nothing, a line goes to standard error, and
//! the transfer's own exit code is untouched. IronStyle asks that
//! recovery is never silent, and the line is that recovery. Variable
//! names are matched with regard to case, so `%{HTTP_CODE}` is unknown,
//! which curl 8.21.0 agrees with.
//!
//! **An unterminated `%{` prints as itself, with no line on standard
//! error.** Measured: `curl -w 'A%{http_code'` prints `A%{http_code`.
//!
//! **The `%{...}` scan stops at the first `}`.** Measured:
//! `curl -w '%{a%{http_code}}'` reads the name `a%{http_code`, calls it
//! unknown, and prints the last `}` as a literal.
//!
//! **A `%` that starts nothing prints as itself.** Measured: `A%` prints
//! `A%`, and `A%zB` prints `A%zB`. `%%` prints one `%`.
//!
//! **`\n`, `\t`, and `\r` become their control characters. `\\` does
//! not.** The plan for this task named `\\` as a fourth escape. curl
//! 8.21.0 has no such escape, and neither does curl's own manual, which
//! lists three. Measured at the byte level: `-w` given the two bytes `\`
//! `\` prints those two bytes back, and given `\` `\` `n` prints `\` `\`
//! `n`. Any other backslash pair prints both bytes too, measured: `\q`
//! prints `\q`, and a format string that ends in `\` prints that `\`.
//!
//! **Two of those values come from a server, and a control code point in
//! one of them never reaches the terminal raw.** `%{content_type}` is a
//! response header and `%{url_effective}` can be a redirect target, so a
//! peer chooses the bytes. Measured against curl 8.21.0 with a loopback
//! server answering `Content-Type: text/plain<ESC>[2J<ESC>[31mHACKED`:
//!
//! ```
//! curl -w '%{content_type}'   text/plain^[[2J^[[31mHACKED
//! zurl -w '%{content_type}'   text/plain?[2J?[31mHACKED
//! ```
//!
//! curl hands the escape sequence to the terminal, which clears the screen
//! and changes the colour. zurl writes one `?` for each control code
//! point, through `safe.writeWithoutControls`. The same rule refuses a
//! control in a `-J` file name, in `src/cli/output.zig`, so there is one
//! rule and not two: the two used to disagree, and the disagreement is
//! what let a UTF-8 encoded C1 control into a file name.
//!
//! **Everything else about the value is left alone.** UTF-8 stays whole,
//! and the text is not truncated, because a script reads these bytes: half
//! a url that still reads like a whole url is a worse answer than a long
//! one. `safe.Text` is the stricter rule and belongs on a message, which
//! is where this file still uses it, on the name inside an unknown
//! `%{...}`.
//!
//! **A format string is untrusted input.** It comes from the command
//! line, so this file bounds it in three places. `max_format_bytes`
//! bounds the whole string, and `src/main.zig` refuses a longer one
//! before any transfer runs. `max_variable_name_len` bounds the name
//! this file reads out of a `%{...}`, so no name reaches the lookup or
//! the standard error line unbounded. `src/cli/safe.zig` bounds what a
//! name may spell on standard error: a name carries any byte the command
//! line carried, and a raw control byte would let a name draw a line of
//! its own in a log. That printer is shared with every other message that
//! echoes untrusted text, so one rule covers them all.
//!
//! The number of variables in a string needs no bound of its own. Each
//! `%{...}` costs at least four bytes of the format string, and each one
//! prints a bounded number of bytes, so `max_format_bytes` already bounds
//! the work and the output together.

const std = @import("std");

/// For `Transfer.WireVersion` alone. The engine owns the set of versions a
/// response can have arrived in, and `zurl` re-exports it, so this file
/// names no version of its own.
const zurl = @import("zurl");
const safe = @import("safe.zig");

const Writer = std.Io.Writer;

/// The longest `-w` format string zurl renders, in bytes.
///
/// curl 8.21.0 has no limit here: a 1 MiB format string renders. zurl
/// names its own, because a format string is a display template and 64
/// KiB is already far past any real one. `src/main.zig` refuses a longer
/// string with `too_long_message`, before the transfer runs, rather than
/// render a part of it. A user who wanted the whole string and got half
/// of it would read a truncated line as a real answer.
pub const max_format_bytes: usize = 64 * 1024;

/// The longest name this file reads out of a `%{...}`.
///
/// No variable curl names comes near this. A longer name is therefore
/// unknown, and it takes the unknown path: nothing on standard output,
/// one line on standard error. The bound exists so the name that reaches
/// the lookup and the line is bounded, whatever the command line held.
pub const max_variable_name_len: usize = 64;

/// The sentence that refuses a format string longer than
/// `max_format_bytes`. Names the flag, then names the limit, the way
/// every other zurl usage fault does.
pub const too_long_message = std.fmt.comptimePrint(
    "zurl: -w takes a format string of at most {d} bytes",
    .{max_format_bytes},
);

/// What one finished transfer knows, in the form `render` prints.
///
/// Every default is what a transfer that reached no server reports, so a
/// caller fills in only what it learned. `http_code` of 0 prints `000`,
/// which is what curl 8.21.0 prints after a failed connection.
///
/// **Lifetime.** `url_effective` and `content_type` borrow from the
/// `zurl.Response` they were read from, so they stay valid only as long
/// as that response does. Render before the next `perform`.
pub const Values = struct {
    /// The final response's status. 0 when no response arrived.
    http_code: u16 = 0,
    /// How many body bytes the transfer read, after any content decoding.
    ///
    /// **The two tools agree on every transfer that carries no content
    /// coding, which is every transfer without `--compressed`.** With no
    /// offer the request sends no `Accept-Encoding`, so nothing arrives
    /// coded and this number is the wire count as well.
    ///
    /// **They disagree under `--compressed`, and this is measured.** A
    /// gzip answer whose 64 wire octets decode to 80: `curl --compressed
    /// -o file -w '%{size_download}'` wrote 80 octets to the file and
    /// printed 64, so curl counts the wire. zurl prints 80, the octets it
    /// wrote. The whole of zurl's accounting measures the decoded body:
    /// `--max-filesize` bounds it, `download.Result.digest` covers it, and
    /// `zurl_stream.Progress` reports no total at all rather than a wire
    /// length the count can never reach. One number here from the wire
    /// would be the only one of the five that described different octets.
    size_download: u64 = 0,
    /// The transfer's average rate, in bytes per second. Over the same
    /// octets `size_download` counts.
    speed_download: u64 = 0,
    /// How long the whole transfer took, in nanoseconds. Counted from
    /// before the connection, the way curl counts `time_total`.
    time_total_ns: u64 = 0,
    /// The url the transfer finished on.
    url_effective: []const u8 = "",
    /// The final response's `Content-Type`, whole. `null` when the
    /// response carried none.
    content_type: ?[]const u8 = null,
    /// Which version of HTTP framed the final response. `null` when no
    /// response arrived, and for a protocol that speaks no HTTP.
    http_version: ?zurl.Transfer.WireVersion = null,
};

/// Every `%{...}` name zurl knows. The name of each member is the name a
/// format string spells, so `std.meta.stringToEnum` is the whole lookup
/// and no second table can fall out of step with this one.
const Variable = enum {
    http_code,
    http_version,
    size_download,
    speed_download,
    time_total,
    url_effective,
    content_type,
};

/// Renders `format` to `out`, and writes a line to `warnings` for each
/// unknown variable it holds.
///
/// `warnings` is standard error. A line goes there even when `-s` asked
/// for silence, because curl 8.21.0 writes it under `-s` too, and because
/// a variable that prints nothing with no word to the user is a silent
/// failure.
///
/// Never reports a fault of its own for anything `format` spells. A
/// format string is read after the transfer already ran, so a bad one
/// must not change what the transfer reported. Only a write that fails
/// returns an error, and that is the caller's own stream breaking.
///
/// Asserts that `format` fits `max_format_bytes`. The caller refuses a
/// longer string before the transfer, so a longer one here is a missed
/// check in the caller and not a fault of the command line.
pub fn render(
    out: *Writer,
    warnings: *Writer,
    format: []const u8,
    values: Values,
) Writer.Error!void {
    std.debug.assert(format.len <= max_format_bytes);

    var i: usize = 0;
    while (i < format.len) {
        switch (format[i]) {
            '\\' => i += try writeEscape(out, format[i..]),
            '%' => i += try writeVariable(out, warnings, format[i..], values),
            else => {
                try out.writeByte(format[i]);
                i += 1;
            },
        }
    }
}

/// Writes the escape that starts `rest`, and returns how many bytes of
/// `rest` it consumed.
///
/// `rest` starts with a backslash. A backslash pair that names no escape
/// prints both of its bytes, and a backslash at the end of the string
/// prints alone.
///
/// **There are three escapes, and `\\` is not one of them.** curl's own
/// manual lists `\n`, `\r`, and `\t` and no more. Measured against curl
/// 8.21.0 at the byte level: `-w` given the two bytes `\` `\` prints the
/// two bytes `\` `\`, and given `\` `\` `n` prints `\` `\` `n` rather
/// than a backslash and a newline. The pair is read as one unknown
/// escape, and an unknown escape prints both of its bytes.
///
/// The pair is consumed whole, and the second byte is never read again.
/// Measured: `-w '\%{http_code}'` prints `\%{http_code}`, so the `%`
/// after an unknown escape starts no variable.
fn writeEscape(out: *Writer, rest: []const u8) Writer.Error!usize {
    std.debug.assert(rest[0] == '\\');

    if (rest.len == 1) {
        try out.writeByte('\\');
        return 1;
    }

    const control: ?u8 = switch (rest[1]) {
        'n' => '\n',
        't' => '\t',
        'r' => '\r',
        else => null,
    };

    if (control) |byte| {
        try out.writeByte(byte);
    } else {
        try out.writeAll(rest[0..2]);
    }
    return 2;
}

/// Writes whatever the `%` that starts `rest` introduces, and returns how
/// many bytes of `rest` it consumed.
///
/// Returns `rest.len` for an unterminated `%{`, because that whole tail
/// prints as itself and nothing after it can start anything else.
fn writeVariable(
    out: *Writer,
    warnings: *Writer,
    rest: []const u8,
    values: Values,
) Writer.Error!usize {
    std.debug.assert(rest[0] == '%');

    // A `%` at the end of the string, and a `%` before any byte other
    // than `%` or `{`, both print as themselves.
    if (rest.len == 1 or (rest[1] != '%' and rest[1] != '{')) {
        try out.writeByte('%');
        return 1;
    }

    if (rest[1] == '%') {
        try out.writeByte('%');
        return 2;
    }

    const body = rest[2..];
    const close = std.mem.indexOfScalar(u8, body, '}') orelse {
        // Unterminated. The whole tail is literal text.
        try out.writeAll(rest);
        return rest.len;
    };

    const name = body[0..close];
    const consumed = 2 + close + 1;

    // A name past the bound cannot be a variable, so it takes the same
    // path a misspelled one takes.
    const known: ?Variable = if (name.len > max_variable_name_len)
        null
    else
        std.meta.stringToEnum(Variable, name);

    const variable = known orelse {
        try warnings.print("zurl: unknown --write-out variable: '{f}'\n", .{safe.Text{
            .bytes = name,
            .max_len = max_variable_name_len,
        }});
        return consumed;
    };

    try writeValue(out, variable, values);
    return consumed;
}

/// Writes one variable's value, in curl 8.21.0's own text for it.
fn writeValue(out: *Writer, variable: Variable, values: Values) Writer.Error!void {
    switch (variable) {
        // Three digits, zero-padded. curl prints `000` when no response
        // arrived, so the padding is part of the contract and not a
        // coincidence of every status being three digits.
        .http_code => try out.print("{d:0>3}", .{values.http_code}),
        // **The version the peer answered in, not the version a flag asked
        // for.** This is how a script tells an HTTP/3 transfer from one
        // that fell back, so a value read off the command line would be
        // worse than useless. Measured against curl 8.21.0: `1.1` over
        // HTTP/1.1, `2` over HTTP/2, `3` over HTTP/3, and `0` for a
        // transfer that reached no server.
        .http_version => try out.writeAll(if (values.http_version) |v| v.text() else "0"),
        .size_download => try out.print("{d}", .{values.size_download}),
        .speed_download => try out.print("{d}", .{values.speed_download}),
        .time_total => try writeSeconds(out, values.time_total_ns),
        // **The two values a server chooses, and the only two that reach
        // standard output through a rule.** See this file's own doc
        // comment for the measurement and for why a `?` and not a raw
        // byte.
        .url_effective => try safe.writeWithoutControls(out, values.url_effective),
        // curl prints nothing for a response that carried no
        // `Content-Type`, so an absent one and an empty one read alike.
        .content_type => try safe.writeWithoutControls(out, values.content_type orelse ""),
    }
}

/// Writes `ns` as seconds with exactly six decimal places.
///
/// curl prints a `double` through `%.6f`, which rounds to the nearest
/// microsecond. This rounds the same way in integers, so no float is
/// needed and the digits do not move with the target's floating-point
/// behaviour. The saturating add keeps a nanosecond count near the top of
/// the range from wrapping.
fn writeSeconds(out: *Writer, ns: u64) Writer.Error!void {
    const us = (ns +| (std.time.ns_per_us / 2)) / std.time.ns_per_us;
    try out.print("{d}.{d:0>6}", .{ us / std.time.us_per_s, us % std.time.us_per_s });
}

const testing = std.testing;

/// Renders `format` and returns the two streams it wrote, so a test reads
/// standard output and standard error apart.
///
/// The buffers are fixed and generous. A test that overruns one is a test
/// that meant to check a bound, and it should say so with its own writer.
const Rendered = struct {
    out: []const u8,
    warnings: []const u8,

    var out_buffer: [4096]u8 = undefined;
    var warn_buffer: [4096]u8 = undefined;

    fn of(format: []const u8, values: Values) !Rendered {
        var out: Writer = .fixed(&out_buffer);
        var warnings: Writer = .fixed(&warn_buffer);
        try render(&out, &warnings, format, values);
        return .{ .out = out.buffered(), .warnings = warnings.buffered() };
    }
};

/// One transfer's worth of values, so a test names only what it checks.
const sample: Values = .{
    .http_code = 200,
    .size_download = 12,
    .speed_download = 2028,
    .time_total_ns = 7_275_000,
    .url_effective = "http://127.0.0.1:18932/hello",
    .content_type = "text/plain; charset=utf-8",
    .http_version = .http_1_1,
};

test "%{http_version} prints the version the peer answered in" {
    // Every text below is curl 8.21.0's own for the same transfer,
    // measured: `--http1.1` against `https://example.com/` printed `1.1`,
    // `--http2` printed `2`, `--http3` against
    // `https://www.cloudflare.com/robots.txt` printed `3`, and a transfer
    // that reached no server printed `0`.
    var values = sample;

    values.http_version = .http_1_0;
    try testing.expectEqualStrings("1.0", (try Rendered.of("%{http_version}", values)).out);
    values.http_version = .http_1_1;
    try testing.expectEqualStrings("1.1", (try Rendered.of("%{http_version}", values)).out);
    values.http_version = .http_2;
    try testing.expectEqualStrings("2", (try Rendered.of("%{http_version}", values)).out);
    values.http_version = .http_3;
    try testing.expectEqualStrings("3", (try Rendered.of("%{http_version}", values)).out);

    // **A transfer with no response prints `0`, and never an empty
    // string.** A script that reads this field compares it against a
    // number, and an empty field would read as a missing variable.
    values.http_version = null;
    const none = try Rendered.of("%{http_version}", values);
    try testing.expectEqualStrings("0", none.out);
    try testing.expectEqualStrings("", none.warnings);
}

test "a literal format string is written unchanged" {
    const r = try Rendered.of("plain text, no variables 123", sample);
    try testing.expectEqualStrings("plain text, no variables 123", r.out);
    try testing.expectEqualStrings("", r.warnings);
}

test "an empty format string writes nothing" {
    const r = try Rendered.of("", sample);
    try testing.expectEqualStrings("", r.out);
    try testing.expectEqualStrings("", r.warnings);
}

test "%{http_code} becomes the status" {
    const r = try Rendered.of("%{http_code}", sample);
    try testing.expectEqualStrings("200", r.out);
    try testing.expectEqualStrings("", r.warnings);
}

test "%{http_code} pads to three digits, so a transfer that got no response reads 000" {
    // Measured against curl 8.21.0: a refused connection prints `000`,
    // not `0`. A script that reads a fixed three bytes depends on it.
    const r = try Rendered.of("%{http_code}", .{});
    try testing.expectEqualStrings("000", r.out);
}

test "%{size_download} becomes the byte count" {
    const r = try Rendered.of("%{size_download}", sample);
    try testing.expectEqualStrings("12", r.out);

    // A plain integer with no separator and no unit, at any size.
    const big = try Rendered.of("%{size_download}", .{ .size_download = 1234567890 });
    try testing.expectEqualStrings("1234567890", big.out);
}

test "%{speed_download} is a plain integer of bytes per second" {
    // curl 8.21.0 prints no decimal point here. Measured: 10 bytes over
    // 2.014622 seconds printed `4`, so the value truncates.
    const r = try Rendered.of("%{speed_download}", sample);
    try testing.expectEqualStrings("2028", r.out);

    const none = try Rendered.of("%{speed_download}", .{});
    try testing.expectEqualStrings("0", none.out);
}

test "%{time_total} is seconds with six decimal places and a dot" {
    const r = try Rendered.of("%{time_total}", sample);
    try testing.expectEqualStrings("0.007275", r.out);

    // The whole-second part carries no padding of its own, and a time
    // past one second keeps all six places.
    const long = try Rendered.of("%{time_total}", .{ .time_total_ns = 2_014_622_000 });
    try testing.expectEqualStrings("2.014622", long.out);

    // A very small time still prints six places, and zero prints them
    // too. Measured: curl printed `0.000028` for a name lookup.
    const small = try Rendered.of("%{time_total}", .{ .time_total_ns = 28_000 });
    try testing.expectEqualStrings("0.000028", small.out);

    const zero = try Rendered.of("%{time_total}", .{ .time_total_ns = 0 });
    try testing.expectEqualStrings("0.000000", zero.out);
}

test "%{time_total} rounds to the nearest microsecond and does not wrap at the top" {
    // 1500 ns is one and a half microseconds, which rounds up.
    const up = try Rendered.of("%{time_total}", .{ .time_total_ns = 1_500 });
    try testing.expectEqualStrings("0.000002", up.out);

    const down = try Rendered.of("%{time_total}", .{ .time_total_ns = 1_499 });
    try testing.expectEqualStrings("0.000001", down.out);

    // The saturating add must not wrap a count near the top of the range.
    const r = try Rendered.of("%{time_total}", .{ .time_total_ns = std.math.maxInt(u64) });
    try testing.expect(r.out.len > 6);
}

test "%{url_effective} becomes the url the transfer finished on" {
    const r = try Rendered.of("%{url_effective}", sample);
    try testing.expectEqualStrings("http://127.0.0.1:18932/hello", r.out);
}

test "%{content_type} keeps the whole value, charset and all" {
    const r = try Rendered.of("%{content_type}", sample);
    try testing.expectEqualStrings("text/plain; charset=utf-8", r.out);
}

test "a control a server chose never reaches the terminal through -w" {
    // Measured against curl 8.21.0 with a loopback server answering this
    // exact `Content-Type`: curl prints the escape sequence raw, so the
    // terminal clears its screen and turns red. zurl writes one `?` for
    // each control code point instead.
    const r = try Rendered.of("%{content_type}", .{
        .content_type = "text/plain\x1b[2J\x1b[31mHACKED",
    });
    try testing.expectEqualStrings("text/plain?[2J?[31mHACKED", r.out);

    // The same rule covers the url, which a redirect target chooses.
    const u = try Rendered.of("%{url_effective}", .{
        .url_effective = "http://h/a\x1b]0;forged title\x07b",
    });
    try testing.expectEqualStrings("http://h/a?]0;forged title?b", u.out);

    // And the C1 controls, which are the half a per-call-site rule missed
    // in `src/cli/output.zig`. `\xc2\x9b` is U+009B, the CSI.
    const c1 = try Rendered.of("%{content_type}", .{
        .content_type = "text/plain\xc2\x9b31m",
    });
    try testing.expectEqualStrings("text/plain?31m", c1.out);
}

test "-w leaves a UTF-8 value whole, because a script reads these bytes" {
    // A media type or a url that carries a name must reach standard output
    // as the peer wrote it. `safe.Text`, the rule for a message, would
    // answer one `?` for each of these bytes, which is right for a message
    // and wrong here.
    const r = try Rendered.of("%{content_type}", .{
        .content_type = "text/plain; name=\xe6\x97\xa5\xe6\x9c\xac",
    });
    try testing.expectEqualStrings("text/plain; name=\xe6\x97\xa5\xe6\x9c\xac", r.out);
}

test "%{content_type} writes nothing when the response carried none" {
    // Measured against curl 8.21.0 with a 204: the variable prints an
    // empty string, never a word such as `none`.
    const r = try Rendered.of("[%{content_type}]", .{ .content_type = null });
    try testing.expectEqualStrings("[]", r.out);
    try testing.expectEqualStrings("", r.warnings);
}

test "an unknown variable prints nothing and names itself on standard error" {
    // The plan for this task said curl writes an unknown variable through
    // literally. curl 8.21.0 does not: measured, `-w 'A%{bogus_thing}B'`
    // prints `AB` and writes one line to standard error, and the exit
    // code stays 0.
    const r = try Rendered.of("A%{bogus_thing}B", sample);
    try testing.expectEqualStrings("AB", r.out);
    try testing.expectEqualStrings(
        "zurl: unknown --write-out variable: 'bogus_thing'\n",
        r.warnings,
    );
}

test "an unknown variable does not stop the variables around it" {
    const r = try Rendered.of("%{http_code}-%{nope}-%{size_download}", sample);
    try testing.expectEqualStrings("200--12", r.out);
    try testing.expectEqualStrings(
        "zurl: unknown --write-out variable: 'nope'\n",
        r.warnings,
    );
}

test "a variable name is matched with regard to case, matching curl" {
    // Measured: curl 8.21.0 calls `%{HTTP_CODE}` unknown.
    const r = try Rendered.of("%{HTTP_CODE}", sample);
    try testing.expectEqualStrings("", r.out);
    try testing.expect(std.mem.indexOf(u8, r.warnings, "'HTTP_CODE'") != null);
}

test "an empty variable name is unknown, matching curl" {
    const r = try Rendered.of("a%{}b", sample);
    try testing.expectEqualStrings("ab", r.out);
    try testing.expectEqualStrings("zurl: unknown --write-out variable: ''\n", r.warnings);
}

test "an unterminated %{ is written through literally" {
    // Measured: curl 8.21.0 prints `A%{http_code` and writes no line to
    // standard error.
    const r = try Rendered.of("A%{http_code", sample);
    try testing.expectEqualStrings("A%{http_code", r.out);
    try testing.expectEqualStrings("", r.warnings);

    const bare = try Rendered.of("X%{", sample);
    try testing.expectEqualStrings("X%{", bare.out);
    try testing.expectEqualStrings("", bare.warnings);
}

test "the name scan stops at the first closing brace" {
    // Measured: curl 8.21.0 reads the name `a%{http_code` out of
    // `%{a%{http_code}}` and prints the trailing `}` as a literal.
    const r = try Rendered.of("%{a%{http_code}}", sample);
    try testing.expectEqualStrings("}", r.out);
    try testing.expect(std.mem.indexOf(u8, r.warnings, "'a%{http_code'") != null);
}

test "%% is one percent sign" {
    const r = try Rendered.of("A%%B", sample);
    try testing.expectEqualStrings("A%B", r.out);
    try testing.expectEqualStrings("", r.warnings);

    // `%%{http_code}` is a literal percent and then literal text, never a
    // variable.
    const escaped = try Rendered.of("%%{http_code}", sample);
    try testing.expectEqualStrings("%{http_code}", escaped.out);
}

test "a percent that starts nothing is written through literally" {
    // Measured: curl 8.21.0 prints `A%` for `A%`, and `A%zB` for `A%zB`.
    const trailing = try Rendered.of("A%", sample);
    try testing.expectEqualStrings("A%", trailing.out);

    const other = try Rendered.of("A%zB", sample);
    try testing.expectEqualStrings("A%zB", other.out);
    try testing.expectEqualStrings("", other.warnings);
}

test "backslash escapes become their control characters" {
    // The Zig literal doubles each backslash, so the format string holds
    // one backslash before each of n, t, and r.
    const r = try Rendered.of("a\\nb\\tc\\rd", sample);
    try testing.expectEqualStrings("a\nb\tc\rd", r.out);
    try testing.expectEqualStrings("", r.warnings);
}

test "a doubled backslash prints two backslashes, because curl has no such escape" {
    // The plan for this task named `\\` as a fourth escape. curl's manual
    // lists three, and curl 8.21.0 agrees at the byte level: a format
    // string of the two bytes `\` `\` prints those two bytes.
    const pair = try Rendered.of("\\\\", sample);
    try testing.expectEqualStrings("\\\\", pair.out);
    try testing.expectEqualStrings("", pair.warnings);

    // And the pair is read whole, so the `n` after it stays a letter
    // rather than joining the second backslash into a newline.
    const before_n = try Rendered.of("a\\\\nb", sample);
    try testing.expectEqualStrings("a\\\\nb", before_n.out);
}

test "a backslash that names no escape is written through literally" {
    // Measured: curl 8.21.0 prints `a\qb` for `a\qb`, and a format string
    // that ends in a backslash prints that backslash.
    const unknown = try Rendered.of("a\\qb", sample);
    try testing.expectEqualStrings("a\\qb", unknown.out);

    const trailing = try Rendered.of("ab\\", sample);
    try testing.expectEqualStrings("ab\\", trailing.out);
    try testing.expectEqualStrings("", trailing.warnings);
}

test "an unknown escape consumes both bytes, so a percent after it starts nothing" {
    // Measured: `-w '\%{http_code}'` prints `\%{http_code}`. The `%` is
    // part of the escape pair and is never read again.
    const after = try Rendered.of("\\%{http_code}", sample);
    try testing.expectEqualStrings("\\%{http_code}", after.out);
    try testing.expectEqualStrings("", after.warnings);

    // With a backslash pair in front, the `%` is free again and the
    // variable renders. Measured: `\\%{http_code}` prints `\\200`.
    const freed = try Rendered.of("\\\\%{http_code}", sample);
    try testing.expectEqualStrings("\\\\200", freed.out);
}

test "every variable renders together in one format string" {
    const r = try Rendered.of(
        "%{http_code} %{size_download} %{speed_download} %{time_total} " ++
            "%{url_effective} %{content_type}\\n",
        sample,
    );
    try testing.expectEqualStrings(
        "200 12 2028 0.007275 http://127.0.0.1:18932/hello text/plain; charset=utf-8\n",
        r.out,
    );
    try testing.expectEqualStrings("", r.warnings);
}

test "a name past the bound is unknown, and the line that names it stays bounded" {
    const long_name = "z" ** (max_variable_name_len + 40);
    var out_buffer: [256]u8 = undefined;
    var warn_buffer: [256]u8 = undefined;
    var out: Writer = .fixed(&out_buffer);
    var warnings: Writer = .fixed(&warn_buffer);
    try render(&out, &warnings, "%{" ++ long_name ++ "}", sample);

    try testing.expectEqualStrings("", out.buffered());
    // The echoed name is cut at the bound and marked as cut.
    const line = warnings.buffered();
    try testing.expect(std.mem.endsWith(u8, line, "...'\n"));
    try testing.expect(line.len < max_variable_name_len + 64);
}

test "a name that carries a control byte cannot draw a second line on standard error" {
    // A format string is command-line input. A newline inside a name
    // would otherwise print a line that reads like one of zurl's own.
    const r = try Rendered.of("%{bad\nname\x1b[2J}", sample);
    try testing.expectEqualStrings("", r.out);
    try testing.expectEqualStrings(
        "zurl: unknown --write-out variable: 'bad?name?[2J'\n",
        r.warnings,
    );
    // One line, and only one.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, r.warnings, "\n"));
}

test "a format string of thousands of variables renders every one" {
    // Each `%{...}` costs at least four bytes of the format string, so
    // `max_format_bytes` bounds the count. This checks the loop keeps up
    // with a string near that shape rather than stopping early.
    const repeats = 4000;
    const format = "%{http_code}" ** repeats;
    try testing.expect(format.len <= max_format_bytes);

    var buffer: [3 * repeats]u8 = undefined;
    var out: Writer = .fixed(&buffer);
    var warnings: Writer = .fixed(&.{});
    try render(&out, &warnings, format, sample);

    try testing.expectEqual(@as(usize, 3 * repeats), out.buffered().len);
    try testing.expectEqualStrings("200200200", out.buffered()[0..9]);
}

test "the refusal sentence names the flag and the limit" {
    try testing.expect(std.mem.indexOf(u8, too_long_message, "-w") != null);
    try testing.expect(std.mem.indexOf(u8, too_long_message, "65536") != null);
}
