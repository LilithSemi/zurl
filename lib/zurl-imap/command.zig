//! The RFC 3501 commands, the tag each one carries, and the quoting a
//! mailbox name needs.
//!
//! **The injection gate is not here, and that is on purpose.** Every
//! command this package sends goes out through `Control.send`, which calls
//! `zurl_net.line.Session.send`, which refuses a NUL, a CR, or an LF in
//! any part of the line before a byte reaches the writer. That gate is one
//! function, shared with every other line-oriented protocol package.
//!
//! **IMAP needs a second gate, and it is here.** A mailbox name goes into
//! a command as an astring, RFC 3501 section 4.3, and a name that is not
//! an atom is written inside double quotes. A name that holds a `"` would
//! close that string early and put the rest of the name outside it, where
//! the server reads it as more arguments:
//!
//!     SELECT "My" INBOX"          from the name `My" INBOX`
//!
//! `quote` writes a `\` before every `"` and every `\`, which is what RFC
//! 3501 asks and what curl does: measured against curl 8.21.0, the url
//! `imap://h/My%22Box;UID=1` reaches the wire as `SELECT "My\"Box"`.
//!
//! This module does no I/O. It writes into a buffer the caller owns.

const std = @import("std");
const zurl_net = @import("zurl-net");

/// How many bytes of one command line this package writes, the `CRLF`
/// counted.
///
/// RFC 3501 sets no limit a client has to keep. A mailbox name can be long
/// and a `--request` command longer, so this is generous, and it is a
/// bound because an unbounded command needs an unbounded buffer. Passing
/// it is `error.CommandTooLong`.
pub const max_command_bytes = zurl_net.line.max_command_bytes;

/// Why a command was not written.
///
/// Both names come from `zurl_net.line`.
pub const WriteError = zurl_net.line.WriteError;

/// How many bytes of text `quote` writes a quoted form for.
///
/// `target.max_mailbox_bytes` and `Fetcher.max_credential_bytes` are both
/// this number, and both are checked before `quote` runs.
pub const max_quoted_input_bytes = 512;

/// How many bytes a quoted text may take, the quotes and every escape
/// counted.
///
/// Every byte may need an escape, so this is twice
/// `max_quoted_input_bytes` and two more for the quotes. Passing it is
/// `error.MailboxTooLong`.
///
/// It was 1024 while the sentence above said 1026, so a legal 512 octet
/// mailbox of nothing but `"` was refused as too long. The number is
/// derived now, so the sentence and the value cannot part again.
pub const max_quoted_bytes = max_quoted_input_bytes * 2 + 2;

/// Why a mailbox name could not be written.
pub const QuoteError = error{
    /// The quoted form does not fit `out`.
    MailboxTooLong,
};

/// How many digits a tag carries after its letter.
///
/// Three, which is what curl writes: measured, curl's first command is
/// `A001` and its fifth is `A005`. A session that sent more than 999
/// commands would wrap, and this package sends at most six.
pub const tag_digits = 3;

/// How many bytes one tag takes.
pub const tag_bytes = 1 + tag_digits;

/// Writes the tag of command number `n`, counting from one.
///
/// `A001`, `A002`, and so on, which is curl's own spelling. The result
/// points into `out` and holds only a letter and digits, so it can carry
/// no framing byte and needs no quoting.
pub fn writeTag(out: *[tag_bytes]u8, n: u16) []const u8 {
    out[0] = 'A';
    var value = n % 1000;
    var i: usize = tag_digits;
    while (i > 0) : (i -= 1) {
        out[i] = '0' + @as(u8, @intCast(value % 10));
        value /= 10;
    }
    return out;
}

/// Whether `name` is an RFC 3501 atom, which needs no quotes.
///
/// The atom-specials of section 9 are `(`, `)`, `{`, space, a control
/// byte, `%`, `*`, `"`, `\`, and `]`. A name holding any of them is
/// written as a quoted string instead. An empty name is not an atom
/// either: the empty mailbox is written `""`, which is what a `LIST` with
/// no reference name sends.
///
/// This is curl's own rule, measured: `INBOX` reaches the wire unquoted
/// and `My Box` reaches it as `"My Box"`.
pub fn isAtom(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |byte| {
        switch (byte) {
            '(', ')', '{', ' ', '%', '*', '"', '\\', ']' => return false,
            0...0x1f, 0x7f => return false,
            else => {},
        }
    }
    return true;
}

/// Writes `name` as an RFC 3501 astring into `out`, and returns it.
///
/// An atom is written as it stands. Anything else is written inside double
/// quotes, with a `\` before every `"` and every `\`.
///
/// **The escape is what keeps a mailbox name inside its own argument.**
/// See the module comment.
///
/// A name holding a byte a quoted string cannot carry, which is a CR, an
/// LF, or a NUL, is not refused here: `Control.send` refuses it, and
/// `target.Target.parse` refuses it earlier still, so the message names
/// the url. This function is about the shape of the argument and not about
/// the bytes in it.
pub fn quote(out: []u8, name: []const u8) QuoteError![]const u8 {
    if (isAtom(name)) {
        if (name.len > out.len) return error.MailboxTooLong;
        @memcpy(out[0..name.len], name);
        return out[0..name.len];
    }

    var at: usize = 0;
    if (out.len < 2) return error.MailboxTooLong;
    out[at] = '"';
    at += 1;
    for (name) |byte| {
        const escaped = byte == '"' or byte == '\\';
        const need: usize = if (escaped) 2 else 1;
        // One byte is kept back for the closing quote.
        if (at + need + 1 > out.len) return error.MailboxTooLong;
        if (escaped) {
            out[at] = '\\';
            at += 1;
        }
        out[at] = byte;
        at += 1;
    }
    out[at] = '"';
    return out[0 .. at + 1];
}

// The commands this package sends. Named here so a typo is a compile error
// and so one file lists every command that can reach a server.

/// RFC 3501: what the server can do.
pub const capability = "CAPABILITY";
/// RFC 3501: logs in with a user name and a password, both in the clear.
pub const login = "LOGIN";
/// RFC 3501: opens a mailbox for reading and writing.
pub const select = "SELECT";
/// RFC 3501: opens a mailbox for reading alone.
pub const examine = "EXAMINE";
/// RFC 3501: names the mailboxes under a reference name.
pub const list = "LIST";
/// RFC 3501: reads parts of a message, by sequence number.
pub const fetch = "FETCH";
/// RFC 3501: makes the next command read a unique identifier instead of a
/// sequence number.
pub const uid = "UID";
/// RFC 3501 section 6.2.2: opens a SASL exchange.
pub const authenticate = "AUTHENTICATE";
/// RFC 3501 section 6.2.2: the one line a client writes to end a SASL
/// exchange it cannot finish.
///
/// **A client that walked away from a challenge without this would leave
/// the server waiting for a response**, and the next command would be read
/// as that response. One asterisk on a line of its own is what says the
/// exchange is over.
pub const auth_cancel = "*";
/// RFC 2595: asks to put TLS on the connection.
pub const starttls = "STARTTLS";
/// RFC 3501: ends the session.
pub const logout = "LOGOUT";

/// The part of a `FETCH` that names the whole message.
///
/// curl asks for exactly this, measured: `UID FETCH 1 BODY[]`. `BODY[]`
/// and not `RFC822`, because `BODY[]` does not set the `\Seen` flag on
/// some servers and `RFC822` always does.
pub const whole_message = "BODY[]";

/// The reference name and the pattern a `LIST` of every mailbox carries.
///
/// curl sends `LIST "" *` for a url with no mailbox, measured.
pub const list_all_pattern = "*";

const testing = std.testing;

test "a tag is a letter and three digits, the way curl writes one" {
    var storage: [tag_bytes]u8 = undefined;
    try testing.expectEqualStrings("A001", writeTag(&storage, 1));
    try testing.expectEqualStrings("A002", writeTag(&storage, 2));
    try testing.expectEqualStrings("A010", writeTag(&storage, 10));
    try testing.expectEqualStrings("A999", writeTag(&storage, 999));
    // A session past 999 wraps rather than grow the tag. This package
    // sends at most six commands, so no session reaches it.
    try testing.expectEqualStrings("A000", writeTag(&storage, 1000));
    try testing.expectEqualStrings("A001", writeTag(&storage, 1001));
}

test "a tag can carry no framing byte and needs no quoting" {
    var storage: [tag_bytes]u8 = undefined;
    var n: u16 = 0;
    while (n < 1000) : (n += 1) {
        const tag = writeTag(&storage, n);
        try testing.expect(!zurl_net.line.hasFramingByte(tag));
        try testing.expect(isAtom(tag));
        try testing.expectEqual(@as(usize, tag_bytes), tag.len);
    }
}

test "an atom needs no quotes and anything else does" {
    try testing.expect(isAtom("INBOX"));
    try testing.expect(isAtom("Sent-Mail"));
    try testing.expect(isAtom("a.b/c"));
    try testing.expect(isAtom("#news.comp"));

    try testing.expect(!isAtom(""));
    try testing.expect(!isAtom("My Box"));
    try testing.expect(!isAtom("My\"Box"));
    try testing.expect(!isAtom("My\\Box"));
    try testing.expect(!isAtom("a(b"));
    try testing.expect(!isAtom("a)b"));
    try testing.expect(!isAtom("a{b"));
    try testing.expect(!isAtom("a]b"));
    try testing.expect(!isAtom("a%b"));
    try testing.expect(!isAtom("a*b"));
    try testing.expect(!isAtom("a\rb"));
    try testing.expect(!isAtom("a\x00b"));
    try testing.expect(!isAtom("a\x7fb"));
}

test "a mailbox name reaches the wire the way curl writes it" {
    // Measured against curl 8.21.0 on a loopback IMAP fixture.
    var out: [max_quoted_bytes]u8 = undefined;
    try testing.expectEqualStrings("INBOX", try quote(&out, "INBOX"));
    try testing.expectEqualStrings("\"My Box\"", try quote(&out, "My Box"));
    try testing.expectEqualStrings("\"My\\\"Box\"", try quote(&out, "My\"Box"));
    try testing.expectEqualStrings("\"\"", try quote(&out, ""));
}

test "a quote in a mailbox name cannot close the argument early" {
    // **The injection proof of the second gate.** Without the escape,
    // `SELECT "My" INBOX"` would reach the server, which reads `INBOX` as
    // a second argument that the url never named.
    var out: [max_quoted_bytes]u8 = undefined;
    try testing.expectEqualStrings(
        "\"My\\\" INBOX\"",
        try quote(&out, "My\" INBOX"),
    );
    try testing.expectEqualStrings(
        "\"a\\\\\\\"b\"",
        try quote(&out, "a\\\"b"),
    );
    // Every quote and every backslash is escaped, and nothing else is.
    const written = try quote(&out, "\"\"\\\\");
    try testing.expectEqualStrings("\"\\\"\\\"\\\\\\\\\"", written);
}

test "a name too long for the buffer is refused rather than cut" {
    var small: [8]u8 = undefined;
    try testing.expectError(error.MailboxTooLong, quote(&small, "a-long-atom-name"));
    try testing.expectError(error.MailboxTooLong, quote(&small, "a long name"));
    // A name of all quotes takes two bytes for each one.
    try testing.expectError(error.MailboxTooLong, quote(&small, "\"\"\"\""));
    // One that fits is written.
    try testing.expectEqualStrings("\"a b\"", try quote(&small, "a b"));
}

test "every command this package sends is one word with no framing byte" {
    const verbs = [_][]const u8{
        capability, login, select, examine, list, fetch, uid, starttls, logout,
    };
    for (verbs) |verb| {
        try testing.expect(verb.len > 0);
        try testing.expect(!zurl_net.line.hasFramingByte(verb));
        try testing.expect(isAtom(verb));
        for (verb) |byte| try testing.expect(std.ascii.isUpper(byte));
    }
}
