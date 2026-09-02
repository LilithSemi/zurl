//! One RTSP 1.0 reply head, and **the bounds on what a server announces.**
//!
//! A reply is `RTSP/1.0 code reason<CRLF>`, then a header for each line,
//! then an empty line, then a body of exactly `Content-Length` octets. RFC
//! 2326 section 7.
//!
//! Three numbers come off a server here and each one is bounded before it
//! is used:
//!
//! - **A head line** is bounded by `max_line_bytes`, so a server that
//!   writes a line and never ends it cannot fill this process.
//!   `zurl_net.bounded.readLine` keeps that bound.
//! - **A head block** is bounded by `max_head_bytes` across every line
//!   together. A head of many short lines is legal and can still be
//!   endless, which one line bound cannot catch. `zurl-http` keeps the
//!   same pair of bounds for the same reason.
//! - **`Content-Length` is bounded before a byte of the body is read.**
//!   It is a number a server chose that decides how many bytes this
//!   process then reads and how much memory it takes. A reader that
//!   allocated on it first would let a one line header ask for as much as
//!   the number can hold. `zurl_rtsp.Fetcher` passes its own ceiling in,
//!   and a length past it is `error.BodyTooLarge`.
//!
//! **A reply with no `Content-Length` has no body.** RFC 2326 section 4.4
//! says so: RTSP has no chunked transfer coding and no read-until-close,
//! so a reply that names no length carries nothing, and this file returns
//! zero rather than read on. That is what makes a session reusable at all,
//! because the next reply starts at the next byte.
//!
//! This file parses text. It opens nothing and it never reads a body: a
//! caller that has the length reads the octets itself.

const std = @import("std");

/// How many bytes of one head line this reads, the `CRLF` counted.
pub const max_line_bytes: usize = 8192;

/// How many bytes of one head block this reads, every line together.
pub const max_head_bytes: usize = 65_536;

/// The version a reply must name. RFC 2326 section 3.1.
pub const version = "RTSP/1.0";

/// The header a reply carries its request's sequence number in.
pub const cseq_header = "CSeq";

/// The header a reply carries its body length in.
pub const content_length_header = "Content-Length";

/// The header a `SETUP` reply carries the session identifier in.
pub const session_header = "Session";

/// Why a reply could not be read.
pub const Error = error{
    /// The first line is not `RTSP/1.0 <code> <reason>`.
    BadStatusLine,
    /// The status code is not three digits.
    BadStatusCode,
    /// The reply names a version this build does not speak.
    BadVersion,
    /// A header line holds no colon at all.
    BadHeaderLine,
    /// The reply carries no `CSeq`, which RFC 2326 section 12.17 makes
    /// required in every reply.
    NoSequenceNumber,
    /// The `CSeq` is not a number.
    BadSequenceNumber,
    /// The `Content-Length` is not a number.
    BadContentLength,
    /// The `Content-Length` is past the caller's ceiling. See the module
    /// comment.
    BodyTooLarge,
    /// The head block is past `max_head_bytes`.
    HeadTooLarge,
};

/// The status line of a reply.
pub const Status = struct {
    code: u16,
    /// The reason phrase, which a server writes for a person to read. May
    /// be empty: RFC 2326 lets it be.
    reason: []const u8,

    /// Whether this code says the request worked. RFC 2326 section 7.1.1
    /// numbers a success in the 200 range.
    pub fn ok(s: Status) bool {
        return s.code >= 200 and s.code < 300;
    }
};

/// Reads the status line of a reply.
///
/// `line` has its ending already taken off, which is what
/// `zurl_net.bounded.readLine` returns.
pub fn status(line: []const u8) Error!Status {
    var it = std.mem.splitScalar(u8, line, ' ');
    const named_version = it.next() orelse return error.BadStatusLine;
    // Case-insensitive on the version, because RFC 2326 writes it in
    // upper case and a server that wrote it otherwise still means it.
    if (!std.ascii.eqlIgnoreCase(named_version, version)) return error.BadVersion;

    const code_text = it.next() orelse return error.BadStatusLine;
    if (code_text.len != 3) return error.BadStatusCode;
    const code = std.fmt.parseInt(u16, code_text, 10) catch return error.BadStatusCode;

    return .{ .code = code, .reason = it.rest() };
}

/// What one head block said.
pub const Head = struct {
    /// The `CSeq` the reply names. **A reply must carry one**, RFC 2326
    /// section 12.17, and a reply that does not is `error.NoSequenceNumber`
    /// rather than a reply this session guesses about.
    cseq: u64,
    /// How many octets of body follow the empty line. Zero for a reply
    /// with no `Content-Length`, which RFC 2326 section 4.4 makes a reply
    /// with no body.
    content_length: u64,
    /// The `Session` value the reply carries, with any parameters after
    /// the first `;` taken off, or null when it carries none. Points into
    /// the caller's own head storage.
    session: ?[]const u8,
};

/// Reads the header lines of a reply out of `block`.
///
/// `block` is every head line joined, each one ending with a `CRLF`, and
/// it is what `Reader` collects. `max_body_bytes` is the caller's ceiling
/// on `Content-Length`.
///
/// **The ceiling runs here, not at the caller.** A caller that read the
/// length and then checked it would have written the number into its own
/// state first, and this way the number a caller sees is already bounded.
pub fn head(block: []const u8, max_body_bytes: u64) Error!Head {
    var cseq: ?u64 = null;
    var content_length: u64 = 0;
    var session: ?[]const u8 = null;

    var lines = std.mem.splitSequence(u8, block, "\r\n");
    while (lines.next()) |raw| {
        if (raw.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, raw, ':') orelse return error.BadHeaderLine;
        const name = std.mem.trim(u8, raw[0..colon], " \t");
        const value = std.mem.trim(u8, raw[colon + 1 ..], " \t");

        if (std.ascii.eqlIgnoreCase(name, cseq_header)) {
            // **The first `CSeq` wins.** A reply with two of them is a
            // reply a middle box could have added a line to, and reading
            // the second would let it decide which request this answers.
            if (cseq == null) {
                cseq = std.fmt.parseInt(u64, value, 10) catch return error.BadSequenceNumber;
            }
        } else if (std.ascii.eqlIgnoreCase(name, content_length_header)) {
            const named = std.fmt.parseInt(u64, value, 10) catch return error.BadContentLength;
            // **The bound, and it runs before the caller ever sees the
            // number.**
            if (named > max_body_bytes) return error.BodyTooLarge;
            content_length = named;
        } else if (std.ascii.eqlIgnoreCase(name, session_header)) {
            if (session == null) session = sessionId(value);
        }
    }

    return .{
        .cseq = cseq orelse return error.NoSequenceNumber,
        .content_length = content_length,
        .session = session,
    };
}

/// The identifier part of a `Session` value.
///
/// RFC 2326 section 12.37 writes `Session: 12345678;timeout=60`, so the
/// identifier ends at the first `;`. A caller that kept the whole value
/// and sent it back would send the timeout as part of the identifier.
pub fn sessionId(value: []const u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, value, ';') orelse value.len;
    return std.mem.trim(u8, value[0..end], " \t");
}

/// Names the fault, for a message to a user.
pub fn describe(err: Error) []const u8 {
    return switch (err) {
        error.BadStatusLine => "the rtsp server sent a first line that is not a status line",
        error.BadStatusCode => "the rtsp server sent a status line whose code is not three digits",
        error.BadVersion => "the rtsp server answered with a version that is not RTSP/1.0",
        error.BadHeaderLine => "the rtsp server sent a header line with no colon in it",
        error.NoSequenceNumber => "the rtsp server sent a reply with no CSeq, which RFC 2326 section 12.17 makes required, so there is no way to tell which request it answers",
        error.BadSequenceNumber => "the rtsp server sent a CSeq that is not a number",
        error.BadContentLength => "the rtsp server sent a Content-Length that is not a number",
        error.BodyTooLarge => "the rtsp server announced a body larger than zurl reads",
        error.HeadTooLarge => "the rtsp server sent a reply head larger than zurl reads",
    };
}

const testing = std.testing;

test "the status line curl read off a real server reads back here" {
    // Measured through a relay to mediamtx 1.18.2: the reply to `OPTIONS *`
    // was `RTSP/1.0 200 OK`.
    const ok = try status("RTSP/1.0 200 OK");
    try testing.expectEqual(@as(u16, 200), ok.code);
    try testing.expectEqualStrings("OK", ok.reason);
    try testing.expect(ok.ok());

    const missing = try status("RTSP/1.0 404 Not Found");
    try testing.expectEqual(@as(u16, 404), missing.code);
    try testing.expectEqualStrings("Not Found", missing.reason);
    try testing.expect(!missing.ok());

    // A reason phrase may be empty. RFC 2326 lets it be.
    const bare = try status("RTSP/1.0 200 ");
    try testing.expectEqual(@as(u16, 200), bare.code);
    try testing.expectEqualStrings("", bare.reason);
}

test "a first line that is not a status line is refused" {
    try testing.expectError(error.BadStatusLine, status("RTSP/1.0"));
    try testing.expectError(error.BadVersion, status("HTTP/1.1 200 OK"));
    try testing.expectError(error.BadVersion, status("RTSP/2.0 200 OK"));
    try testing.expectError(error.BadVersion, status(""));
    try testing.expectError(error.BadStatusCode, status("RTSP/1.0 20 OK"));
    try testing.expectError(error.BadStatusCode, status("RTSP/1.0 2000 OK"));
    try testing.expectError(error.BadStatusCode, status("RTSP/1.0 abc OK"));

    // The version is read without regard to case.
    try testing.expectEqual(@as(u16, 200), (try status("rtsp/1.0 200 OK")).code);
}

test "a head reads its CSeq, its length, and its session" {
    // The head mediamtx sent, measured, with a Content-Length added.
    const block =
        "CSeq: 1\r\n" ++
        "Public: DESCRIBE, ANNOUNCE, SETUP, PLAY, RECORD, PAUSE, GET_PARAMETER, TEARDOWN\r\n" ++
        "Server: gortsplib\r\n" ++
        "Content-Length: 42\r\n" ++
        "Session: 12345678;timeout=60\r\n";

    const read = try head(block, 1024);
    try testing.expectEqual(@as(u64, 1), read.cseq);
    try testing.expectEqual(@as(u64, 42), read.content_length);
    try testing.expectEqualStrings("12345678", read.session.?);
}

test "a reply with no Content-Length carries no body" {
    // RFC 2326 section 4.4. There is no chunked coding and no
    // read-until-close, so a reply that names no length has nothing after
    // the empty line, and the next reply starts at the next byte.
    const read = try head("CSeq: 7\r\nServer: gortsplib\r\n", 1024);
    try testing.expectEqual(@as(u64, 7), read.cseq);
    try testing.expectEqual(@as(u64, 0), read.content_length);
    try testing.expectEqual(@as(?[]const u8, null), read.session);
}

test "a Content-Length past the ceiling is refused before the caller sees it" {
    // **The bound on a number a server chose.** A reader that took this
    // and allocated would let one header line ask for as much as the
    // number can hold.
    try testing.expectError(
        error.BodyTooLarge,
        head("CSeq: 1\r\nContent-Length: 4294967295\r\n", 1024),
    );
    try testing.expectError(
        error.BodyTooLarge,
        head("CSeq: 1\r\nContent-Length: 1025\r\n", 1024),
    );
    // Exactly the ceiling reads, so the bound is the number and not an
    // order of magnitude near it.
    const exact = try head("CSeq: 1\r\nContent-Length: 1024\r\n", 1024);
    try testing.expectEqual(@as(u64, 1024), exact.content_length);

    // A length that is not a number is its own fault, so a user knows to
    // look at the server and not at a size.
    try testing.expectError(
        error.BadContentLength,
        head("CSeq: 1\r\nContent-Length: lots\r\n", 1024),
    );
    try testing.expectError(
        error.BadContentLength,
        head("CSeq: 1\r\nContent-Length: -1\r\n", 1024),
    );
}

test "a reply with no CSeq is a protocol error and not a reply this session guesses about" {
    // RFC 2326 section 12.17 makes `CSeq` required in every reply. Without
    // one there is no way to say which request the reply answers, and a
    // session that guessed would read the answer to one request as the
    // answer to another.
    try testing.expectError(error.NoSequenceNumber, head("Server: gortsplib\r\n", 1024));
    try testing.expectError(error.NoSequenceNumber, head("", 1024));
    try testing.expectError(error.BadSequenceNumber, head("CSeq: one\r\n", 1024));
}

test "the first CSeq wins, so a second line cannot change which request this answers" {
    const read = try head("CSeq: 3\r\nCSeq: 9\r\n", 1024);
    try testing.expectEqual(@as(u64, 3), read.cseq);
}

test "a header line with no colon is refused rather than skipped" {
    // A line nobody can parse is a line this build does not know the
    // meaning of, and skipping it is how a header a server sent goes
    // unread.
    try testing.expectError(error.BadHeaderLine, head("CSeq: 1\r\nnonsense\r\n", 1024));
}

test "a header name and value read without regard to case or spacing" {
    const read = try head("cseq:  4\r\ncontent-length:\t8\r\nsession:  abc ;timeout=60\r\n", 1024);
    try testing.expectEqual(@as(u64, 4), read.cseq);
    try testing.expectEqual(@as(u64, 8), read.content_length);
    try testing.expectEqualStrings("abc", read.session.?);
}

test "a session value keeps its identifier and drops its parameters" {
    // RFC 2326 section 12.37. A caller that sent the whole value back
    // would send the timeout as part of the identifier.
    try testing.expectEqualStrings("12345678", sessionId("12345678;timeout=60"));
    try testing.expectEqualStrings("12345678", sessionId("12345678"));
    try testing.expectEqualStrings("12345678", sessionId(" 12345678 ; timeout=60"));
    try testing.expectEqualStrings("", sessionId(";timeout=60"));
}

test "every fault has a sentence of its own" {
    const every = [_]Error{
        error.BadStatusLine,
        error.BadStatusCode,
        error.BadVersion,
        error.BadHeaderLine,
        error.NoSequenceNumber,
        error.BadSequenceNumber,
        error.BadContentLength,
        error.BodyTooLarge,
        error.HeadTooLarge,
    };
    for (every) |err| {
        try testing.expect(describe(err).len != 0);
        for (every) |other| {
            if (err == other) continue;
            try testing.expect(!std.mem.eql(u8, describe(err), describe(other)));
        }
    }
}
