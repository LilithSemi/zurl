//! The RTSP 1.0 request methods, RFC 2326 section 10.
//!
//! **RTSP looks like HTTP and is not HTTP.** It borrows the request line,
//! the header block, and the status line, and then it changes what those
//! carry: the target of a request is an absolute url and not a path, every
//! request and reply carries a `CSeq`, and a server may send a request to
//! a client. So the methods are their own list here and not
//! `std.http.Method`, which names none of them.
//!
//! This file names which methods this build sends and which it refuses,
//! and it says why for each refusal. It knows no socket and no header.

const std = @import("std");

/// One RTSP request method this build sends.
///
/// The eight below are the eight a reader of a stream needs. RFC 2326
/// section 10 also names `ANNOUNCE` and `RECORD`; see `refusal` for why
/// neither is here.
pub const Method = enum {
    options,
    describe,
    setup,
    play,
    pause,
    teardown,
    get_parameter,
    set_parameter,

    /// The text this method takes on the request line.
    pub fn text(m: Method) []const u8 {
        return switch (m) {
            .options => "OPTIONS",
            .describe => "DESCRIBE",
            .setup => "SETUP",
            .play => "PLAY",
            .pause => "PAUSE",
            .teardown => "TEARDOWN",
            .get_parameter => "GET_PARAMETER",
            .set_parameter => "SET_PARAMETER",
        };
    }

    /// Whether a request of this method normally carries a body.
    ///
    /// RFC 2326 section 10.8 and 10.9 give `GET_PARAMETER` and
    /// `SET_PARAMETER` a body of parameter names or of parameter
    /// assignments. No other method here carries one, and a `-d` beside
    /// one of the others is refused rather than sent: a server that read a
    /// body after a `PLAY` would be reading the next request.
    pub fn takesBody(m: Method) bool {
        return switch (m) {
            .get_parameter, .set_parameter => true,
            .options, .describe, .setup, .play, .pause, .teardown => false,
        };
    }

    /// Whether this method's request line may name `*` in place of a url.
    ///
    /// RFC 2326 section 10.1 lets `OPTIONS` name the server rather than a
    /// stream, and curl writes exactly that: measured, `curl
    /// rtsp://127.0.0.1:8554/stream` put `OPTIONS * RTSP/1.0` on the wire,
    /// with the path of the url nowhere in the request.
    pub fn allowsAsterisk(m: Method) bool {
        return m == .options;
    }
};

/// Reads a method name, however it is written.
///
/// Case-insensitive, because a user types `-X describe` as often as
/// `-X DESCRIBE`. The underscore of `GET_PARAMETER` is part of the name
/// and a hyphen in its place is not the same method.
pub fn parse(name: []const u8) ?Method {
    const table = [_]struct { text: []const u8, method: Method }{
        .{ .text = "OPTIONS", .method = .options },
        .{ .text = "DESCRIBE", .method = .describe },
        .{ .text = "SETUP", .method = .setup },
        .{ .text = "PLAY", .method = .play },
        .{ .text = "PAUSE", .method = .pause },
        .{ .text = "TEARDOWN", .method = .teardown },
        .{ .text = "GET_PARAMETER", .method = .get_parameter },
        .{ .text = "SET_PARAMETER", .method = .set_parameter },
    };
    for (table) |row| {
        if (std.ascii.eqlIgnoreCase(row.text, name)) return row.method;
    }
    return null;
}

/// The sentence that refuses `name`, or null when this build sends it.
///
/// **A method this build will not send is refused by name and never sent
/// as another one.** `zurl_rtsp.Fetcher` reports the sentence with
/// `error.NotBuiltIn`, exit 4, which is curl's code for a feature a build
/// does not carry.
pub fn refusal(name: []const u8) ?[]const u8 {
    if (parse(name) != null) return null;

    // The two RFC 2326 names this build knows and does not send. Both
    // write to a server: `ANNOUNCE` replaces the description of a stream
    // and `RECORD` starts a recording on it. A request that changed what a
    // server holds should not be one letter away from one that reads it,
    // which is the rule `zurl-ldap` keeps for a directory.
    if (std.ascii.eqlIgnoreCase(name, "ANNOUNCE")) {
        return "ANNOUNCE writes a stream description to the server, and this build of zurl sends no rtsp request that changes what a server holds";
    }
    if (std.ascii.eqlIgnoreCase(name, "RECORD")) {
        return "RECORD starts a recording on the server, and this build of zurl sends no rtsp request that changes what a server holds";
    }
    if (std.ascii.eqlIgnoreCase(name, "REDIRECT")) {
        return "REDIRECT is a request a server sends to a client, RFC 2326 section 10.10, and a client does not send one";
    }
    return "this is not an rtsp method RFC 2326 section 10 names";
}

const testing = std.testing;

test "every method writes the text RFC 2326 section 10 names" {
    const cases = [_]struct { method: Method, text: []const u8 }{
        .{ .method = .options, .text = "OPTIONS" },
        .{ .method = .describe, .text = "DESCRIBE" },
        .{ .method = .setup, .text = "SETUP" },
        .{ .method = .play, .text = "PLAY" },
        .{ .method = .pause, .text = "PAUSE" },
        .{ .method = .teardown, .text = "TEARDOWN" },
        .{ .method = .get_parameter, .text = "GET_PARAMETER" },
        .{ .method = .set_parameter, .text = "SET_PARAMETER" },
    };
    for (cases) |case| {
        try testing.expectEqualStrings(case.text, case.method.text());
        try testing.expectEqual(case.method, parse(case.text).?);
        // However it is typed.
        try testing.expectEqual(case.method, parse(
            case.method.text(),
        ).?);
    }
    try testing.expectEqual(Method.describe, parse("describe").?);
    try testing.expectEqual(Method.get_parameter, parse("Get_Parameter").?);
}

test "a name that is not a method reads as none" {
    try testing.expectEqual(@as(?Method, null), parse("GET"));
    try testing.expectEqual(@as(?Method, null), parse("GET-PARAMETER"));
    try testing.expectEqual(@as(?Method, null), parse(""));
    try testing.expectEqual(@as(?Method, null), parse("OPTIONS "));
}

test "the two methods that write to a server are refused with their own words" {
    // **Not refused as an unknown name.** A user who typed `ANNOUNCE` gets
    // told what it does and why this build will not send it, rather than
    // told it is not a method.
    const announce = refusal("ANNOUNCE").?;
    try testing.expect(std.mem.indexOf(u8, announce, "changes what a server holds") != null);
    const record = refusal("record").?;
    try testing.expect(std.mem.indexOf(u8, record, "recording") != null);
    const redirect = refusal("REDIRECT").?;
    try testing.expect(std.mem.indexOf(u8, redirect, "a server sends to a client") != null);

    try testing.expect(refusal("NOSUCH") != null);
    try testing.expectEqual(@as(?[]const u8, null), refusal("PLAY"));
    try testing.expectEqual(@as(?[]const u8, null), refusal("play"));
}

test "only the two parameter methods carry a body" {
    // RFC 2326 sections 10.8 and 10.9. A `-d` beside any other method is
    // refused rather than sent, so a server never reads a body where the
    // next request should be.
    try testing.expect(Method.get_parameter.takesBody());
    try testing.expect(Method.set_parameter.takesBody());
    try testing.expect(!Method.options.takesBody());
    try testing.expect(!Method.describe.takesBody());
    try testing.expect(!Method.setup.takesBody());
    try testing.expect(!Method.play.takesBody());
    try testing.expect(!Method.pause.takesBody());
    try testing.expect(!Method.teardown.takesBody());
}

test "only OPTIONS may name the server rather than a stream" {
    // Measured: curl put `OPTIONS * RTSP/1.0` on the wire for every rtsp
    // url it was given, `/stream` and `/nosuch` alike.
    try testing.expect(Method.options.allowsAsterisk());
    try testing.expect(!Method.describe.allowsAsterisk());
    try testing.expect(!Method.setup.allowsAsterisk());
    try testing.expect(!Method.teardown.allowsAsterisk());
}
