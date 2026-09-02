//! What an `imap://` url names: a mailbox, and the message inside it.
//!
//! Pure text. This module opens nothing and sends nothing, so every rule
//! here is testable with a table.
//!
//! RFC 5092 gives an IMAP url a path and a list of `;name=value` pairs
//! after it. curl reads three of them, and this reads the two that name a
//! message. Measured against curl 8.21.0 on a loopback IMAP fixture:
//!
//!     imap://h/                    LIST "" *
//!     imap://h/INBOX               LIST "INBOX" *
//!     imap://h/INBOX;UID=1         SELECT INBOX, then UID FETCH 1 BODY[]
//!     imap://h/INBOX;MAILINDEX=2   SELECT INBOX, then FETCH 2 BODY[]
//!     imap://h/My%20Box;UID=1      SELECT "My Box", then UID FETCH 1 BODY[]
//!
//! **`UID` and `MAILINDEX` are not the same number.** A UID belongs to the
//! message for as long as the mailbox lives, and a mail index is where the
//! message sits in the mailbox right now, which changes when another
//! message is deleted. So `UID FETCH` and `FETCH` are different commands
//! and this module keeps them apart.
//!
//! **The order is decode, then check, then split off the parameters.** The
//! `;` that starts a parameter is looked for **before** the decode, so a
//! `%3b` inside a mailbox name stays part of the name. curl does the same,
//! and it has to: a mailbox may hold a semicolon.
//!
//! The check between the two is the injection refusal.
//! `zurl_core.url.parse` already refuses a raw control byte in a path, so
//! a percent escape is the only way one can arrive. A CR or an LF in a
//! mailbox name would end the `SELECT` line and write a command of the
//! url's own choosing. `Control.send` refuses the same three bytes again
//! at the socket, and this is the check that names the url instead of the
//! command.

const std = @import("std");
const zurl_core = @import("zurl-core");

const command = @import("command.zig");

/// How many bytes of a decoded mailbox name this holds.
///
/// RFC 3501 sets no limit. A real mailbox name is a few dozen bytes, and
/// this is far past any of them. It is a bound because the name goes into
/// one command line and an unbounded one needs an unbounded buffer.
/// Passing it is `error.PathTooLong`.
///
/// `command.quote` sizes its output buffer from this number, so the two
/// must agree.
pub const max_mailbox_bytes = command.max_quoted_input_bytes;

/// How many bytes of a message number this holds.
pub const max_id_bytes = 64;

/// Why a url path was not read.
pub const ParseError = error{
    /// The decoded path is longer than `max_mailbox_bytes`, or the message
    /// number is longer than `max_id_bytes`.
    PathTooLong,
    /// The path holds a percent escape that is not an escape.
    InvalidEscape,
    /// The decoded path holds a byte below 0x20.
    ///
    /// **This is the injection refusal.** A CR or an LF would end a
    /// command line and start one of the url's own. The other control
    /// bytes go with them because curl refuses the whole class in a url
    /// path, and because RFC 3501 lets no control byte into an atom or a
    /// quoted string.
    PathHasControlByte,
    /// A `;name=value` pair this package does not read, or one with no
    /// value.
    ///
    /// **Refused rather than ignored.** A url that asked for
    /// `;PARTIAL=0.1024` and got the whole message would hand a user
    /// something other than what was asked for, without saying so.
    UnknownParameter,
    /// A message number that is not a run of digits.
    InvalidMessageNumber,
};

/// How the message the url names is addressed.
pub const Addressing = enum {
    /// No message. The url names a mailbox, or nothing at all.
    none,
    /// `;UID=n`, which is `UID FETCH n`.
    uid,
    /// `;MAILINDEX=n`, which is `FETCH n`.
    index,
};

/// One url path, read.
///
/// **A `Target` must not move once `parse` has run.** `mailbox` and `id`
/// point into `bytes`, which is a field of this value.
pub const Target = struct {
    /// The decoded mailbox name. `mailbox` points into this.
    bytes: [max_mailbox_bytes]u8,
    /// The decoded message number. `id` points into this.
    id_bytes: [max_id_bytes]u8,
    /// The mailbox the url names, or an empty slice for a url that names
    /// none.
    mailbox: []const u8,
    /// The message the url names, or an empty slice.
    id: []const u8,
    /// How `id` addresses the message.
    addressing: Addressing,

    /// A `Target` that names nothing yet.
    pub const empty: Target = .{
        .bytes = undefined,
        .id_bytes = undefined,
        .mailbox = "",
        .id = "",
        .addressing = .none,
    };

    /// Whether the url names one message rather than a set of mailboxes.
    pub fn fetches(t: *const Target) bool {
        return t.addressing != .none;
    }

    /// Reads `path` into `t`.
    ///
    /// `path` is the url path as `zurl_core.url.parse` left it, still
    /// escaped and always starting with a `/`. The query and the fragment
    /// are not part of it.
    pub fn parse(t: *Target, path: []const u8) ParseError!void {
        t.mailbox = "";
        t.id = "";
        t.addressing = .none;

        const body = if (std.mem.startsWith(u8, path, "/")) path[1..] else path;

        // **The `;` is found before the decode**, so a `%3b` inside a
        // mailbox name stays part of the name.
        const semicolon = std.mem.indexOfScalar(u8, body, ';');
        const raw_mailbox = if (semicolon) |at| body[0..at] else body;
        const raw_parameters = if (semicolon) |at| body[at + 1 ..] else "";

        if (raw_mailbox.len > t.bytes.len) return error.PathTooLong;
        const mailbox = zurl_core.url.percentDecode(&t.bytes, raw_mailbox) catch
            return error.InvalidEscape;
        if (zurl_core.url.hasControlByte(mailbox)) return error.PathHasControlByte;
        t.mailbox = mailbox;

        if (raw_parameters.len == 0) return;
        try t.parseParameters(raw_parameters);
    }

    /// Reads the `;name=value` pairs after the mailbox.
    ///
    /// The last pair of the two this reads wins, which is what a caller
    /// that wrote both asked for last. curl reads `;UID=` and
    /// `;MAILINDEX=` too, and it reads a third, `;SECTION=`, which this
    /// package does not: see `ParseError.UnknownParameter`.
    fn parseParameters(t: *Target, text: []const u8) ParseError!void {
        var it = std.mem.splitScalar(u8, text, ';');
        while (it.next()) |pair| {
            if (pair.len == 0) continue;
            const equals = std.mem.indexOfScalar(u8, pair, '=') orelse
                return error.UnknownParameter;
            const name = pair[0..equals];
            const raw_value = pair[equals + 1 ..];

            const addressing: Addressing = if (std.ascii.eqlIgnoreCase(name, "UID"))
                .uid
            else if (std.ascii.eqlIgnoreCase(name, "MAILINDEX"))
                .index
            else
                return error.UnknownParameter;

            if (raw_value.len > t.id_bytes.len) return error.PathTooLong;
            const value = zurl_core.url.percentDecode(&t.id_bytes, raw_value) catch
                return error.InvalidEscape;
            // **The injection refusal runs before the shape check**, so a
            // `%0d%0a` in the number is named for what it is rather than
            // for not being a digit.
            if (zurl_core.url.hasControlByte(value)) return error.PathHasControlByte;
            if (value.len == 0) return error.InvalidMessageNumber;
            // **A message number is digits and nothing else.** RFC 3501
            // makes both a `nz-number`, so refusing anything else costs a
            // user nothing and takes one more source of text out of the
            // command line.
            for (value) |byte| {
                if (!std.ascii.isDigit(byte)) return error.InvalidMessageNumber;
            }

            t.id = value;
            t.addressing = addressing;
        }
    }
};

const testing = std.testing;

test "a url with no path names no mailbox and no message" {
    var t: Target = .empty;
    for ([_][]const u8{ "", "/" }) |path| {
        try t.parse(path);
        try testing.expectEqualStrings("", t.mailbox);
        try testing.expectEqual(Addressing.none, t.addressing);
        try testing.expect(!t.fetches());
    }
}

test "a url with a path names a mailbox and no message" {
    var t: Target = .empty;
    try t.parse("/INBOX");
    try testing.expectEqualStrings("INBOX", t.mailbox);
    try testing.expectEqual(Addressing.none, t.addressing);
    try testing.expect(!t.fetches());
}

test "a UID and a mail index are different numbers and different commands" {
    var t: Target = .empty;
    try t.parse("/INBOX;UID=1");
    try testing.expectEqualStrings("INBOX", t.mailbox);
    try testing.expectEqualStrings("1", t.id);
    try testing.expectEqual(Addressing.uid, t.addressing);
    try testing.expect(t.fetches());

    try t.parse("/INBOX;MAILINDEX=2");
    try testing.expectEqualStrings("2", t.id);
    try testing.expectEqual(Addressing.index, t.addressing);

    // Read without regard to case, the way curl reads them.
    try t.parse("/INBOX;uid=7");
    try testing.expectEqual(Addressing.uid, t.addressing);
    try testing.expectEqualStrings("7", t.id);
}

test "the last of two message parameters wins" {
    var t: Target = .empty;
    try t.parse("/INBOX;UID=1;MAILINDEX=2");
    try testing.expectEqual(Addressing.index, t.addressing);
    try testing.expectEqualStrings("2", t.id);

    try t.parse("/INBOX;MAILINDEX=2;UID=1");
    try testing.expectEqual(Addressing.uid, t.addressing);
    try testing.expectEqualStrings("1", t.id);
}

test "a mailbox name is decoded and the semicolon is found before the decode" {
    var t: Target = .empty;
    try t.parse("/My%20Box;UID=1");
    try testing.expectEqualStrings("My Box", t.mailbox);
    try testing.expectEqualStrings("1", t.id);

    // **A `%3b` stays part of the name.** A mailbox may hold a semicolon,
    // and a reader that decoded first would split the name in two.
    try t.parse("/a%3bb");
    try testing.expectEqualStrings("a;b", t.mailbox);
    try testing.expectEqual(Addressing.none, t.addressing);

    // A quote in a name survives the decode. `command.quote` is what makes
    // it safe on the wire.
    try t.parse("/My%22Box;UID=1");
    try testing.expectEqualStrings("My\"Box", t.mailbox);
}

test "a mailbox name that could forge a command is refused" {
    // **The injection proof at the url.** A `%0d%0a` in the name would
    // otherwise end the `SELECT` line and put a command of the url's own
    // behind it.
    var t: Target = .empty;
    const forged = [_][]const u8{
        "/IN%0d%0aA001%20LOGOUT",
        "/IN%0aA001%20LOGOUT",
        "/IN%0dA001%20LOGOUT",
        "/IN%00BOX",
        "/%0d%0a",
        "/%0a;UID=1",
        "/IN%09BOX",
        "/IN%1fBOX",
    };
    for (forged) |path| {
        try testing.expectError(error.PathHasControlByte, t.parse(path));
    }
}

test "a message number that is not digits is refused" {
    // A number is the one thing that goes into a `FETCH` beside the verb,
    // so refusing anything else takes a source of text out of the command
    // line altogether.
    var t: Target = .empty;
    const bad = [_][]const u8{
        "/INBOX;UID=",
        "/INBOX;UID=abc",
        "/INBOX;UID=1a",
        "/INBOX;UID=-1",
        "/INBOX;UID= 1",
        "/INBOX;UID=1%20LOGOUT",
        "/INBOX;MAILINDEX=x",
        "/INBOX;UID=1:2",
        "/INBOX;UID=*",
    };
    for (bad) |path| {
        try testing.expectError(error.InvalidMessageNumber, t.parse(path));
    }
    // A `%0d%0a` in the number is refused for holding a control byte,
    // which is the earlier of the two rules.
    try testing.expectError(error.PathHasControlByte, t.parse("/INBOX;UID=1%0d%0aA001%20LOGOUT"));
}

test "a parameter this package does not read is refused and never ignored" {
    // **Ignoring one would hand a user something other than what was
    // asked for.** `;PARTIAL=0.1024` asks for part of a message, and a
    // transfer that answered it with the whole message would say nothing
    // about the difference.
    var t: Target = .empty;
    const unknown = [_][]const u8{
        "/INBOX;SECTION=1.2",
        "/INBOX;PARTIAL=0.1024",
        "/INBOX;UIDVALIDITY=1",
        "/INBOX;UID=1;SECTION=TEXT",
        "/INBOX;novalue",
    };
    for (unknown) |path| {
        try testing.expectError(error.UnknownParameter, t.parse(path));
    }
}

test "a name longer than the bound is refused" {
    var t: Target = .empty;
    var path: [max_mailbox_bytes + 4]u8 = undefined;
    @memset(&path, 'x');
    path[0] = '/';
    try testing.expectError(error.PathTooLong, t.parse(&path));

    var number: [max_id_bytes + 16]u8 = undefined;
    @memset(&number, '1');
    var buffer: [max_id_bytes + 32]u8 = undefined;
    const long = try std.fmt.bufPrint(&buffer, "/INBOX;UID={s}", .{number});
    try testing.expectError(error.PathTooLong, t.parse(long));
}

test "a percent escape that is not an escape is refused" {
    var t: Target = .empty;
    for ([_][]const u8{ "/%", "/%z1", "/IN%GGOX", "/INBOX;UID=%" }) |path| {
        try testing.expectError(error.InvalidEscape, t.parse(path));
    }
}
