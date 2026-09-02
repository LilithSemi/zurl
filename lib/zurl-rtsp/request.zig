//! One RTSP 1.0 request head, and **this package's injection gate.**
//!
//! RTSP is a line protocol. A request is
//! `METHOD uri RTSP/1.0<CRLF>` then a header for each line and an empty
//! line, so a CR or an LF anywhere in the uri, in a header name, or in a
//! header value ends a line early and starts a line of the sender's
//! choosing. `Session: a<CRLF>Transport: b` from a flag is two headers
//! where the user wrote one, and a stream uri holding a CRLF can write a
//! whole second request behind the first.
//!
//! **So every part goes through `zurl_net.line.write`**, which is the one
//! gate this repository keeps for a line protocol. It refuses a NUL, a CR,
//! and an LF in any part, and it refuses them **before** it writes a byte,
//! so a refused request leaves nothing half written. Nothing in this file
//! reaches a writer any other way.
//!
//! The parts that come from outside and reach a line here are:
//!
//! - the request uri, from the url or from `--rtsp-stream-uri`,
//! - `--rtsp-session-id`, `--rtsp-transport`, and `--rtsp-request`,
//! - every `-H` name and value,
//! - the `Authorization` value that `-u` builds.
//!
//! The url's own path and query need no check of their own:
//! `zurl_core.url.parse` already refuses a C0 control byte, a DEL, and a
//! raw space in either. The flags and the headers have no such rule behind
//! them, and they are why this gate is here.
//!
//! **A space is refused in a header name and nowhere else.** RFC 2326
//! borrows RFC 2616's header grammar, where a name is a token and a token
//! holds no space, so `X Y: v` would be read by a server as a line it
//! cannot parse or, worse, as a continuation of the line above.
//!
//! This file writes into a buffer the caller owns and opens nothing.

const std = @import("std");

const zurl_net = @import("zurl-net");

const method = @import("method.zig");

/// The version this build writes and reads. RFC 2326 section 3.1.
pub const version = "RTSP/1.0";

/// How many bytes one request head may take, the empty line counted.
///
/// A head is a handful of short lines: a request line, a `CSeq`, a
/// `User-Agent`, and whatever `-H` adds. 8 KiB is generous for that and it
/// is the buffer this package keeps for the job.
pub const max_head_bytes: usize = 8192;

/// How many bytes one line of a request head may take, the `CRLF`
/// counted.
///
/// `zurl_net.line.max_command_bytes`, which is the number every line
/// protocol here uses for the same question.
pub const max_line_bytes: usize = zurl_net.line.max_command_bytes;

/// Why a request head could not be built.
pub const Error = error{
    /// A part holds a NUL, a CR, or an LF. **This is the injection
    /// refusal.** See the module comment for what each of the three would
    /// do to the head.
    PartHasFramingByte,
    /// A header name holds a space, which no RFC 2616 token may.
    HeaderNameHasSpace,
    /// A header name is empty.
    HeaderNameEmpty,
    /// One line does not fit `max_line_bytes`.
    LineTooLong,
    /// The head together does not fit `max_head_bytes`.
    HeadTooLong,
};

/// One header this build writes.
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// Builds one request head into storage the caller owns.
///
/// **Every line goes out through `line`, and `line` is the only writer.**
/// A part that reaches a head any other way is a part that skipped the
/// gate, so there is no second path here at all.
pub const Writer = struct {
    bytes: [max_head_bytes]u8 = undefined,
    len: usize = 0,
    /// Where one line is built before it is copied into `bytes`.
    line_storage: [max_line_bytes]u8 = undefined,

    /// Throws away whatever head is in the buffer.
    pub fn reset(w: *Writer) void {
        w.len = 0;
    }

    /// The head built so far.
    pub fn written(w: *const Writer) []const u8 {
        return w.bytes[0..w.len];
    }

    /// Writes one line, made of `parts` joined and a `CRLF`.
    ///
    /// **The gate.** `zurl_net.line.write` checks every part for a NUL, a
    /// CR, and an LF, and it writes nothing at all when one holds any of
    /// the three.
    pub fn line(w: *Writer, parts: []const []const u8) Error!void {
        const built = zurl_net.line.write(&w.line_storage, parts) catch |err| switch (err) {
            error.ArgumentHasFramingByte => return error.PartHasFramingByte,
            error.CommandTooLong => return error.LineTooLong,
        };
        if (built.len > w.bytes.len - w.len) return error.HeadTooLong;
        @memcpy(w.bytes[w.len..][0..built.len], built);
        w.len += built.len;
    }

    /// Writes the request line.
    ///
    /// `target` is the uri the request acts on, or `*` for an `OPTIONS`
    /// that names the server. RFC 2326 section 6.1 makes the target an
    /// absolute url, which is where RTSP differs from HTTP most visibly:
    /// an HTTP request line carries a path and this one carries a whole
    /// url.
    pub fn requestLine(w: *Writer, verb: method.Method, target: []const u8) Error!void {
        try w.line(&.{ verb.text(), " ", target, " ", version });
    }

    /// Writes one header.
    ///
    /// **The framing check comes first and the token check second.** A
    /// name holding a CR is a name that would write a header line of its
    /// own, and that is the graver of the two faults: reporting it as a
    /// space in a token would send a reader looking at the wrong thing.
    /// `line` runs the framing check over the whole line, and
    /// `zurl_net.line.hasFramingByte` runs it over the name alone here so
    /// the order holds.
    pub fn header(w: *Writer, name: []const u8, value: []const u8) Error!void {
        if (zurl_net.line.hasFramingByte(name)) return error.PartHasFramingByte;
        if (name.len == 0) return error.HeaderNameEmpty;
        if (std.mem.indexOfScalar(u8, name, ' ') != null) return error.HeaderNameHasSpace;
        if (std.mem.indexOfScalar(u8, name, '\t') != null) return error.HeaderNameHasSpace;
        try w.line(&.{ name, ": ", value });
    }

    /// Writes a header whose value is a number.
    pub fn headerNumber(w: *Writer, name: []const u8, value: u64) Error!void {
        var digits: [20]u8 = undefined;
        const text = std.fmt.bufPrint(&digits, "{d}", .{value}) catch return error.LineTooLong;
        try w.header(name, text);
    }

    /// Writes the empty line that ends the head.
    pub fn end(w: *Writer) Error!void {
        try w.line(&.{});
    }
};

/// Names the fault, for a message to a user.
///
/// A switch with no else arm, so a member added later has no other
/// member's words to fall into.
pub fn describe(err: Error) []const u8 {
    return switch (err) {
        error.PartHasFramingByte => "a part of this rtsp request holds a NUL, a CR, or an LF, and any of the three would end the line early and write a header this request does not carry",
        error.HeaderNameHasSpace => "a header name holds a space or a tab, and RFC 2616 makes a header name a token, which holds neither",
        error.HeaderNameEmpty => "a header was given with no name at all",
        error.LineTooLong => "one line of this rtsp request is longer than zurl writes",
        error.HeadTooLong => "this rtsp request head is longer than zurl writes",
    };
}

const testing = std.testing;

test "a request head is the request line, the headers, and an empty line" {
    // The shape curl wrote, measured through a relay to a real mediamtx
    // 1.18.2: `OPTIONS * RTSP/1.0`, `CSeq: 1`, `User-Agent: curl/8.21.0`,
    // and then the empty line.
    var w: Writer = .{};
    try w.requestLine(.options, "*");
    try w.headerNumber("CSeq", 1);
    try w.header("User-Agent", "zurl/0.1");
    try w.end();

    try testing.expectEqualStrings(
        "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: zurl/0.1\r\n\r\n",
        w.written(),
    );
}

test "the request line carries a whole url, which is where rtsp differs from http" {
    // RFC 2326 section 6.1. An HTTP request line writes a path.
    var w: Writer = .{};
    try w.requestLine(.describe, "rtsp://example.test:554/stream");
    try testing.expectEqualStrings(
        "DESCRIBE rtsp://example.test:554/stream RTSP/1.0\r\n",
        w.written(),
    );
}

test "a CR, an LF, or a NUL in any part is refused and nothing is written" {
    // **The injection proof of this package.** Each of these would end the
    // request line or a header line early and put a header of its own
    // behind it. The sources are `--rtsp-session-id`,
    // `--rtsp-stream-uri`, `--rtsp-transport`, and every `-H`.
    const forged = [_][]const u8{
        "a\r\nSession: stolen",
        "a\nTransport: stolen",
        "a\rSession: stolen",
        "a\x00b",
        "\r\n",
        "\n",
        "\r",
        "\x00",
        "rtsp://h/s\r\nTEARDOWN rtsp://h/s RTSP/1.0",
        "12345678\r\nRequire: nothing",
    };

    for (forged) |part| {
        var w: Writer = .{};
        try testing.expectError(error.PartHasFramingByte, w.requestLine(.setup, part));
        try testing.expectEqual(@as(usize, 0), w.len);

        var v: Writer = .{};
        try testing.expectError(error.PartHasFramingByte, v.header("Session", part));
        try testing.expectEqual(@as(usize, 0), v.len);

        var n: Writer = .{};
        try testing.expectError(error.PartHasFramingByte, n.header(part, "x"));
        try testing.expectEqual(@as(usize, 0), n.len);
    }
}

test "a refused part leaves the lines already written untouched" {
    // A head that got as far as two good lines and then met a bad part
    // keeps the two and grows no further. The caller throws the whole head
    // away, and this proves the refusal never wrote a partial line into
    // the middle of it.
    var w: Writer = .{};
    try w.requestLine(.play, "rtsp://h/s");
    try w.headerNumber("CSeq", 3);
    const before = w.len;

    try testing.expectError(
        error.PartHasFramingByte,
        w.header("Session", "12345\r\nRange: npt=0-"),
    );
    try testing.expectEqual(before, w.len);
    try testing.expectEqualStrings(
        "PLAY rtsp://h/s RTSP/1.0\r\nCSeq: 3\r\n",
        w.written(),
    );
}

test "a space in a header name is refused, because no token holds one" {
    var w: Writer = .{};
    try testing.expectError(error.HeaderNameHasSpace, w.header("X Y", "v"));
    try testing.expectError(error.HeaderNameHasSpace, w.header("X\tY", "v"));
    try testing.expectError(error.HeaderNameEmpty, w.header("", "v"));
    try testing.expectEqual(@as(usize, 0), w.len);

    // A space in a value is ordinary and stays.
    try w.header("Transport", "RTP/AVP;unicast;client_port=4588-4589");
    try w.header("Range", "npt=0.000-");
    try testing.expectEqualStrings(
        "Transport: RTP/AVP;unicast;client_port=4588-4589\r\nRange: npt=0.000-\r\n",
        w.written(),
    );
}

test "a byte that is not framing still reaches the head" {
    // The rule refuses three bytes and never a fourth. A semicolon, an
    // equals, a DEL, and a high byte are all ordinary in a transport
    // specification or a session identifier.
    var w: Writer = .{};
    try w.header("Transport", "RTP/AVP;unicast;client_port=4588-4589;mode=\"PLAY\"");
    try w.header("Session", "12345678\x7f");
    try w.header("X-Note", "caf\xc3\xa9");
    try testing.expect(std.mem.indexOf(u8, w.written(), "mode=\"PLAY\"") != null);
    try testing.expect(std.mem.indexOf(u8, w.written(), "caf\xc3\xa9") != null);
}

test "a line longer than the bound is refused rather than cut" {
    var w: Writer = .{};
    var long: [max_line_bytes]u8 = undefined;
    @memset(&long, 'v');
    try testing.expectError(error.LineTooLong, w.header("X", &long));
    try testing.expectEqual(@as(usize, 0), w.len);
}

test "a head longer than the bound is refused rather than cut" {
    var w: Writer = .{};
    var value: [1000]u8 = undefined;
    @memset(&value, 'v');

    var wrote: usize = 0;
    while (true) : (wrote += 1) {
        w.header("X", &value) catch |err| {
            try testing.expectEqual(Error.HeadTooLong, err);
            break;
        };
        // A head of 8 KiB takes nine of these at most, so a loop that ran
        // past twenty is a bound that is not there.
        try testing.expect(wrote < 20);
    }
    try testing.expect(w.len <= max_head_bytes);
}

test "reset starts the next request over" {
    var w: Writer = .{};
    try w.requestLine(.options, "*");
    try testing.expect(w.len != 0);
    w.reset();
    try testing.expectEqual(@as(usize, 0), w.len);

    try w.requestLine(.teardown, "rtsp://h/s");
    try testing.expectEqualStrings("TEARDOWN rtsp://h/s RTSP/1.0\r\n", w.written());
}

test "every fault has a sentence of its own" {
    const every = [_]Error{
        error.PartHasFramingByte,
        error.HeaderNameHasSpace,
        error.HeaderNameEmpty,
        error.LineTooLong,
        error.HeadTooLong,
    };
    for (every) |err| {
        try testing.expect(describe(err).len != 0);
        for (every) |other| {
            if (err == other) continue;
            try testing.expect(!std.mem.eql(u8, describe(err), describe(other)));
        }
    }
}
