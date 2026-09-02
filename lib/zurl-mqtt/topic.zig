//! The topic a `mqtt://` url names, and **this package's injection rule.**
//!
//! curl reads the path of an MQTT url as the topic, and nothing else of
//! the url: measured against curl 8.21.0 through a byte logging relay,
//! `mqtt://host/a/b/c/d` published to `a/b/c/d`, `mqtt://host/t/g?x=1`
//! published to `t/g` with the query dropped, and `mqtt://host/t/%2Fesc`
//! published to `t//esc` with the escape decoded. A url with an empty path
//! or no path at all is exit 3 and no socket opens. This file reads a url
//! the same way.
//!
//! ## The rule, in two halves
//!
//! **The framing half: no byte a topic holds can end a field or start a
//! packet.** MQTT 3.1.1 section 1.5.3 puts a two byte octet count in front
//! of every string, and `packet.zig` computes that count from the bytes it
//! is given. So a CR, an LF, a space, or any other byte is data inside the
//! count and can end nothing. That is the opposite of every line protocol
//! in this repository, where `zurl_net.line.write` has to refuse the three
//! framing bytes, and it is why this package does not call that gate at
//! all. The test "a topic of any byte at all reaches the wire whole"
//! proves it.
//!
//! **The meaning half: the bytes that change what a topic names are
//! refused by name.** Framing is not the only way a url can send a message
//! somewhere the user did not write:
//!
//! - **A NUL is refused.** MQTT 3.1.1 section 1.5.3 forbids U+0000 in any
//!   UTF-8 encoded string, and a server must answer one by closing the
//!   connection. It is also the byte an operating system reads a name up
//!   to, so a topic logged to a file names one thing to MQTT and another
//!   to everything downstream.
//! - **A `+` or a `#` in a topic this package publishes to is refused.**
//!   Section 3.3.2.1 says a PUBLISH topic name must hold neither. They are
//!   the wildcards of section 4.7, so `mqtt://host/t/%23` is not one topic
//!   but every topic under `t/`, and a publish that reached the wire would
//!   hand the payload to every subscriber of the subtree. The url named
//!   one topic and the wire would carry a pattern.
//! - **A topic filter, which is what a subscribe sends, keeps both.**
//!   Section 4.7 makes a wildcard legal there and curl sends one, measured:
//!   `mqtt://host/t/%23` subscribed with the filter `t/#`. A subscribe
//!   reads and a publish writes, so the same byte is a question in one and
//!   a broadcast in the other.
//!
//! **curl refuses none of the three.** Measured: `mqtt://host/t/%23` with
//! `-d` published to `t/#`, `mqtt://host/t/%00x` published to a topic
//! holding a NUL, and `mqtt://host/t/%0d%0ax` published to a topic holding
//! a CRLF. curl exited 0 for each, even where the broker must throw the
//! packet away and close, so a user reading the exit code was told the
//! message was sent.
//!
//! This file opens nothing and allocates nothing. It writes into a buffer
//! the caller owns.

const std = @import("std");

const zurl_core = @import("zurl-core");

/// How many bytes of topic this package sends.
///
/// MQTT 3.1.1 section 1.5.3 puts the hard ceiling at 65 535, which is what
/// the two byte count holds. This is far below it, because the topic comes
/// out of a url path and no topic a person writes is longer. The buffer
/// that holds it is a field of the `Fetcher`, so this number is what that
/// value costs.
///
/// A url past it is `error.TopicTooLong`, and no socket opens.
pub const max_topic_bytes: usize = 4096;

/// What a topic is for.
///
/// **The two arms differ on one rule and only one**: a wildcard. See the
/// module comment.
pub const Use = enum {
    /// The topic name of a PUBLISH. MQTT 3.1.1 section 3.3.2.1.
    publish,
    /// The topic filter of a SUBSCRIBE. MQTT 3.1.1 section 3.8.3.
    subscribe,
};

/// Why a url names no topic this package will send.
pub const Error = error{
    /// The url named no path, or named only "/". curl answers the same url
    /// with exit 3 and opens no socket, measured.
    TopicEmpty,
    /// The decoded topic is longer than `max_topic_bytes`.
    TopicTooLong,
    /// The path holds a `%` that is not the start of an escape.
    TopicBadEscape,
    /// The decoded topic holds a NUL. See the module comment.
    TopicHasNul,
    /// A publish topic holds a `+` or a `#`. See the module comment.
    TopicHasWildcard,
};

/// Where a decoded topic lives while a transfer runs.
///
/// A named type and not a bare array, so a `Fetcher` field says what it
/// costs and a test can make one without knowing the number.
pub const Storage = [max_topic_bytes]u8;

/// Reads the topic out of `url` into `out`, and applies the rule above.
///
/// The result points into `out`.
///
/// **The query and the fragment are dropped, and the leading slash goes.**
/// That is what curl does, measured. A topic is a path through a broker's
/// name space and it has no leading separator: `mqtt://host/a/b` publishes
/// to `a/b` and not to `/a/b`.
pub fn parse(out: *Storage, url: zurl_core.Url, use: Use) Error![]const u8 {
    // `zurl_core.url.parse` gives an empty path as "/", so both spellings
    // of "this url names no topic" arrive here as one.
    const raw = std.mem.trimStart(u8, url.path, "/");
    if (raw.len == 0) return error.TopicEmpty;
    // The decoded form is never longer than the escaped one, so a check
    // here bounds the decode as well.
    if (raw.len > out.len) return error.TopicTooLong;

    const decoded = zurl_core.url.percentDecode(out[0..raw.len], raw) catch |err| switch (err) {
        error.InvalidEscape => return error.TopicBadEscape,
        // The buffer is exactly the escaped length and a decode never
        // grows, so this arm cannot be reached from the call above.
        error.NoSpaceLeft => return error.TopicTooLong,
    };
    if (decoded.len == 0) return error.TopicEmpty;

    // **The meaning half of the rule, and it runs before the caller sees
    // the topic at all.** See the module comment.
    for (decoded) |byte| {
        if (byte == 0) return error.TopicHasNul;
        if (use == .publish and (byte == '+' or byte == '#')) return error.TopicHasWildcard;
    }
    return decoded;
}

/// Names the fault `parse` reported, for a message to a user.
///
/// One sentence for each member, so a `Fetcher` reports every one of them
/// and a member added later has no default to fall into.
pub fn describe(err: Error) []const u8 {
    return switch (err) {
        error.TopicEmpty => "an mqtt url names its topic in the path, and this url has none",
        error.TopicTooLong => "the topic this url names is longer than zurl sends",
        error.TopicBadEscape => "the topic in this url holds a percent escape that is not an escape",
        error.TopicHasNul => "the topic holds a NUL, which MQTT 3.1.1 section 1.5.3 does not allow in a string, and a broker answers one by closing the connection",
        error.TopicHasWildcard => "the topic holds a + or a #, which MQTT 3.1.1 section 4.7 makes a wildcard, so publishing to it would send the payload to every topic under the pattern and not to the one this url names",
    };
}

const testing = std.testing;

/// Parses `text` the way a `Client` with this package registered does.
fn parseUrl(text: []const u8) !zurl_core.Url {
    var schemes: zurl_core.url.Schemes = .empty;
    try schemes.add(.{ .name = "mqtt", .default_port = 1883 });
    try schemes.add(.{ .name = "mqtts", .default_port = 8883 });
    return zurl_core.url.parseWith(text, &schemes);
}

/// Reads the topic of `text` under `use`.
fn topicOf(out: *Storage, text: []const u8, use: Use) ![]const u8 {
    return parse(out, try parseUrl(text), use);
}

test "the topic is the path, with the leading slash off, as curl sends it" {
    // Every row was measured off curl 8.21.0 through a relay to a real
    // mosquitto 2.1.2. The bytes after `30 <len> 00 <n>` in each capture
    // are the topic printed here.
    var out: Storage = undefined;
    try testing.expectEqualStrings("t/a", try topicOf(&out, "mqtt://h/t/a", .publish));
    try testing.expectEqualStrings("a/b/c/d", try topicOf(&out, "mqtt://h/a/b/c/d", .publish));
    try testing.expectEqualStrings("zurl/test", try topicOf(&out, "mqtt://h/zurl/test", .publish));
}

test "the query and the fragment are not part of the topic" {
    // Measured: `curl -d body-G mqtt://127.0.0.1/t/g?x=1` put `00 03 74 2f
    // 67` on the wire, which is the topic `t/g` with no query at all.
    var out: Storage = undefined;
    try testing.expectEqualStrings("t/g", try topicOf(&out, "mqtt://h/t/g?x=1", .publish));
    try testing.expectEqualStrings("t/g", try topicOf(&out, "mqtt://h/t/g#frag", .publish));
    try testing.expectEqualStrings("t/g", try topicOf(&out, "mqtt://h/t/g?x=1#frag", .publish));
}

test "an escape in the path is decoded, the way curl decodes it" {
    // Measured: `mqtt://127.0.0.1/t/%2Fesc` reached the wire as the five
    // byte topic `t//esc`.
    var out: Storage = undefined;
    try testing.expectEqualStrings("t//esc", try topicOf(&out, "mqtt://h/t/%2Fesc", .publish));
    try testing.expectEqualStrings("a b", try topicOf(&out, "mqtt://h/a%20b", .publish));
    try testing.expectError(error.TopicBadEscape, topicOf(&out, "mqtt://h/a%zz", .publish));
    try testing.expectError(error.TopicBadEscape, topicOf(&out, "mqtt://h/a%2", .publish));
}

test "a url that names no topic opens no socket, which is curl's answer too" {
    // Measured: `curl -d body-D mqtt://127.0.0.1:21883/` and
    // `curl -d body-E mqtt://127.0.0.1:21883` both exited 3, and the relay
    // logged no connection for either.
    var out: Storage = undefined;
    try testing.expectError(error.TopicEmpty, topicOf(&out, "mqtt://h/", .publish));
    try testing.expectError(error.TopicEmpty, topicOf(&out, "mqtt://h", .publish));
    try testing.expectError(error.TopicEmpty, topicOf(&out, "mqtt://h///", .publish));
    try testing.expectError(error.TopicEmpty, topicOf(&out, "mqtt://h/?q=1", .publish));
}

test "a topic of any byte at all reaches the wire whole" {
    // **The framing half of this package's rule, proved.** MQTT counts the
    // octets of a string in front of it, so a CR, an LF, a space, a tab, a
    // DEL, or a high byte is data and can end no field. Every one of these
    // would be refused by `zurl_net.line.write` in a line protocol, and
    // none of them needs refusing here.
    var out: Storage = undefined;
    try testing.expectEqualStrings("a\r\nb", try topicOf(&out, "mqtt://h/a%0d%0ab", .publish));
    try testing.expectEqualStrings("a\rb", try topicOf(&out, "mqtt://h/a%0db", .publish));
    try testing.expectEqualStrings("a\nb", try topicOf(&out, "mqtt://h/a%0ab", .publish));
    try testing.expectEqualStrings("a\tb", try topicOf(&out, "mqtt://h/a%09b", .publish));
    try testing.expectEqualStrings("a b", try topicOf(&out, "mqtt://h/a%20b", .publish));
    try testing.expectEqualStrings("a\x7fb", try topicOf(&out, "mqtt://h/a%7fb", .publish));
    try testing.expectEqualStrings("a\xc3\xa9b", try topicOf(&out, "mqtt://h/a%c3%a9b", .publish));

    // The same is true of a filter.
    try testing.expectEqualStrings("a\r\nb", try topicOf(&out, "mqtt://h/a%0d%0ab", .subscribe));
}

test "a NUL in the topic is refused, and curl sends one" {
    // Measured: `curl -d N mqtt://127.0.0.1:21883/t/%00x` put
    // `30 07 00 04 74 2f 00 78 4e` on the wire, a topic holding a NUL, and
    // exited 0. MQTT 3.1.1 section 1.5.3 forbids it and a broker must
    // close the connection, so curl's exit 0 says a message was sent that
    // the broker threw away.
    var out: Storage = undefined;
    try testing.expectError(error.TopicHasNul, topicOf(&out, "mqtt://h/t/%00x", .publish));
    try testing.expectError(error.TopicHasNul, topicOf(&out, "mqtt://h/%00", .publish));
    try testing.expectError(error.TopicHasNul, topicOf(&out, "mqtt://h/a%00", .subscribe));
}

test "a wildcard is refused for a publish and kept for a subscribe" {
    // **The one rule the two uses do not share.** Measured: curl published
    // to `t/#` and exited 0, and curl subscribed to `t/#` as well. Only
    // the first of those two sends a payload somewhere the url did not
    // name.
    var out: Storage = undefined;
    try testing.expectError(error.TopicHasWildcard, topicOf(&out, "mqtt://h/t/%23", .publish));
    try testing.expectError(error.TopicHasWildcard, topicOf(&out, "mqtt://h/t/%2b", .publish));
    try testing.expectError(error.TopicHasWildcard, topicOf(&out, "mqtt://h/%23", .publish));
    try testing.expectError(error.TopicHasWildcard, topicOf(&out, "mqtt://h/a/%2b/b", .publish));

    try testing.expectEqualStrings("t/#", try topicOf(&out, "mqtt://h/t/%23", .subscribe));
    try testing.expectEqualStrings("t/+", try topicOf(&out, "mqtt://h/t/%2b", .subscribe));
    try testing.expectEqualStrings("#", try topicOf(&out, "mqtt://h/%23", .subscribe));
}

test "a topic past the bound is refused rather than cut short" {
    // A cut topic would publish to a name the user did not write, which is
    // the same fault as an escape that changed the name.
    var out: Storage = undefined;
    var text: [max_topic_bytes + 64]u8 = undefined;
    const head = "mqtt://h/";
    @memcpy(text[0..head.len], head);
    @memset(text[head.len..][0 .. max_topic_bytes + 1], 'z');
    try testing.expectError(
        error.TopicTooLong,
        topicOf(&out, text[0 .. head.len + max_topic_bytes + 1], .publish),
    );

    // One byte under the bound still reads.
    const fitted = try topicOf(&out, text[0 .. head.len + max_topic_bytes], .publish);
    try testing.expectEqual(max_topic_bytes, fitted.len);
}

test "every fault has a sentence of its own" {
    // A switch with no else arm, so a member added later cannot be
    // reported with another member's words.
    const every = [_]Error{
        error.TopicEmpty,
        error.TopicTooLong,
        error.TopicBadEscape,
        error.TopicHasNul,
        error.TopicHasWildcard,
    };
    for (every) |err| {
        const text = describe(err);
        try testing.expect(text.len != 0);
        for (every) |other| {
            if (err == other) continue;
            try testing.expect(!std.mem.eql(u8, text, describe(other)));
        }
    }
}
