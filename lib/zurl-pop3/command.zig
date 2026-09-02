//! The RFC 1939 commands, and the two rules that go with them.
//!
//! **The injection gate is not here, and that is on purpose.** Every
//! command this package sends goes out through `Control.send`, which calls
//! `zurl_net.line.Session.send`, which refuses a NUL, a CR, or an LF in
//! any part of the line before a byte reaches the writer. That gate is one
//! function, shared with every other line-oriented protocol package, so
//! there is one rule and not four. See `Control.send`.
//!
//! **Why the gate matters here.** A command is `VERB<SP>argument<CRLF>`,
//! so a CR or an LF inside the argument ends the line early and starts a
//! command of the argument's choosing. `USER a<CRLF>PASS x<CRLF>` from a
//! url is two commands where the url named one, and
//! `RETR 1<CRLF>DELE 2<CRLF>` marks a message for deletion that the user
//! never named, which the `QUIT` at the end of the session then makes
//! permanent.
//!
//! What is here: the list of verbs, so one file names every command that
//! can reach a server; the digest an `APOP` login carries; and the rule
//! that says whether an answer is one line or a body.
//!
//! This module does no I/O.

const std = @import("std");
const zurl_net = @import("zurl-net");

/// How many bytes of one command line this package writes, the `CRLF`
/// counted.
///
/// RFC 1939 sets no limit on a command. A user name can be long and a
/// password longer, so this is generous, and it is a bound because an
/// unbounded command needs an unbounded buffer. Passing it is
/// `error.CommandTooLong`.
pub const max_command_bytes = zurl_net.line.max_command_bytes;

/// Why a command was not written.
///
/// `ArgumentHasFramingByte` says a part holds a NUL, a CR, or an LF, and
/// `CommandTooLong` says the parts do not fit. Both come from
/// `zurl_net.line`.
pub const WriteError = zurl_net.line.WriteError;

/// The MD5 digest an `APOP` command carries, as lowercase hexadecimal.
///
/// RFC 1939 section 7: the digest is MD5 over the server's greeting
/// timestamp followed by the password. **The password itself never crosses
/// the network**, which is the whole reason this command exists.
///
/// The result is 32 characters and holds only `0` to `9` and `a` to `f`,
/// so it can carry no framing byte whatever the password held.
pub fn apopDigest(timestamp: []const u8, password: []const u8) [32]u8 {
    var md5: std.crypto.hash.Md5 = .init(.{});
    md5.update(timestamp);
    md5.update(password);
    var sum: [std.crypto.hash.Md5.digest_length]u8 = undefined;
    md5.final(&sum);

    var out: [32]u8 = undefined;
    const digits = "0123456789abcdef";
    for (sum, 0..) |byte, i| {
        out[i * 2] = digits[byte >> 4];
        out[i * 2 + 1] = digits[byte & 0x0f];
    }
    return out;
}

// The verbs this package sends. Named here so a typo is a compile error
// and so one file lists every command that can reach a server.

/// RFC 1939: names the user to log in as.
pub const user = "USER";
/// RFC 1939: the password for `user`, in the clear.
pub const pass = "PASS";
/// RFC 1939 section 7: logs in with a digest, so the password stays off
/// the network.
pub const apop = "APOP";
/// RFC 1939: how many messages there are and how many bytes they hold.
pub const stat = "STAT";
/// RFC 1939: the number and the size of each message. Multi-line with no
/// argument, one line with one.
pub const list = "LIST";
/// RFC 1939: sends one whole message. Always multi-line.
pub const retr = "RETR";
/// RFC 1939: marks one message for deletion. The server acts on it at
/// `QUIT`.
pub const dele = "DELE";
/// RFC 2449: what the server can do. Multi-line.
pub const capa = "CAPA";
/// RFC 1939 section 7: the unique identifier of each message. Multi-line
/// with no argument, one line with one.
pub const uidl = "UIDL";
/// RFC 1939 section 7: the header and the first lines of a message.
/// Always multi-line.
pub const top = "TOP";
/// RFC 1734 and RFC 5034: opens a SASL exchange.
pub const auth = "AUTH";
/// RFC 5034: the one line a client writes to end a SASL exchange it cannot
/// finish.
///
/// **A client that walked away from a challenge without this would leave
/// the server waiting for a response**, and the next command would be read
/// as that response. One asterisk on a line of its own is what says the
/// exchange is over.
pub const auth_cancel = "*";
/// The `CAPA` line that names the SASL mechanisms a server takes.
///
/// RFC 5034 section 6 writes it `SASL PLAIN LOGIN CRAM-MD5`. Measured from
/// curl 8.21.0: this is the only line curl reads for a mechanism list, and
/// a `CAPA` answer with no `SASL` line drew no `AUTH` from it.
pub const sasl_capability = "SASL";
/// RFC 2595: asks to put TLS on the connection.
pub const stls = "STLS";
/// RFC 1939: ends the session, and is what makes a `DELE` take effect.
pub const quit = "QUIT";

/// The mechanisms the `SASL` line of a `CAPA` answer names, or null when
/// no line names one.
///
/// `body` is the whole answer, one line for each capability, each with a
/// `CRLF` after it, which is what `Control.readBody` gives.
///
/// **The keyword must be the whole first word of a line.** RFC 2449 makes
/// a capability a keyword and its parameters, so a test that matched
/// anywhere would read a server's own text as a mechanism list.
///
/// A `SASL` line with no mechanism after it gives an empty slice, which is
/// not null: a server that named the capability and no mechanism has said
/// something different from a server that named neither.
///
/// The result points into `body`.
pub fn saslMechanisms(body: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, body, "\r\n");
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t");
        const space = std.mem.indexOfAny(u8, line, " \t") orelse line.len;
        if (!eq(line[0..space], sasl_capability)) continue;
        return std.mem.trim(u8, line[space..], " \t");
    }
    return null;
}

/// Whether the answer to `verb` with `argument` is a multi-line response.
///
/// **This decides how the session reads the next answer**, so getting it
/// wrong leaves the session out of step: a reader that expected one line
/// and got a body would read the body as answers to later commands, and a
/// reader that expected a body and got one line would wait for a period
/// that never arrives.
///
/// The rule is curl's own, measured against curl 8.21.0 on a loopback POP3
/// fixture: `-X LIST` reads a body and `-X LIST 1` reads one line, so the
/// argument decides for `LIST` and for `UIDL`. `RETR`, `TOP`, and `CAPA`
/// are always a body.
pub fn isMultiline(verb: []const u8, argument: ?[]const u8) bool {
    if (eq(verb, retr) or eq(verb, top) or eq(verb, capa)) return true;
    // **`AUTH` with no argument lists the mechanisms and is multi-line;
    // `AUTH <mechanism>` opens an exchange and is not.** RFC 1734 gives
    // the two the same verb, and a reader that treated them alike would
    // wait for a period that never arrives.
    if (eq(verb, auth)) {
        const text = argument orelse return true;
        return std.mem.trim(u8, text, " ").len == 0;
    }
    if (eq(verb, list) or eq(verb, uidl)) {
        const text = argument orelse return true;
        return std.mem.trim(u8, text, " ").len == 0;
    }
    return false;
}

fn eq(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

const testing = std.testing;

test "every verb this package sends is one word with no framing byte" {
    // A verb reaches `zurl_net.line.write` as a part of the command line,
    // so a verb constant holding a space or a CR would be a second
    // command. Every one of them is checked here, at compile time and at
    // run time both.
    const verbs = [_][]const u8{
        user, pass, apop, stat, list, retr, dele, capa, uidl, top, stls, quit,
    };
    for (verbs) |verb| {
        try testing.expect(verb.len > 0);
        try testing.expect(!zurl_net.line.hasFramingByte(verb));
        try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, verb, ' '));
        for (verb) |byte| try testing.expect(std.ascii.isUpper(byte) or std.ascii.isDigit(byte));
    }
}

test "the APOP digest is the MD5 of the timestamp and the password" {
    // The example of RFC 1939 section 7, worked through: the timestamp
    // `<1896.697170952@dbc.mtview.ca.us>` and the password `tanstaaf`
    // give the digest the standard prints.
    const digest = apopDigest("<1896.697170952@dbc.mtview.ca.us>", "tanstaaf");
    try testing.expectEqualStrings("c4c9334bac560ecc979e58001b3e22fb", &digest);
}

test "the APOP digest can carry no framing byte, whatever the password held" {
    // The digest is hexadecimal, so a password holding a CR cannot put one
    // on the command line through this route. The credential check refuses
    // such a password earlier anyway, and this is the second reason it can
    // never reach a command.
    const digest = apopDigest("<a@b>", "pw\r\nDELE 1\x00");
    for (digest) |byte| {
        try testing.expect(std.ascii.isHex(byte));
        try testing.expect(!std.ascii.isUpper(byte));
    }
}

test "the multi-line rule is the one curl uses" {
    // Measured against curl 8.21.0 on a loopback POP3 fixture: `-X LIST`
    // reads a body and `-X LIST 1` reads one line.
    try testing.expect(isMultiline(retr, "1"));
    try testing.expect(isMultiline(top, "1 0"));
    try testing.expect(isMultiline(capa, null));
    try testing.expect(isMultiline(list, null));
    try testing.expect(isMultiline(list, ""));
    try testing.expect(isMultiline(list, "  "));
    try testing.expect(isMultiline(uidl, null));

    try testing.expect(!isMultiline(list, "1"));
    try testing.expect(!isMultiline(uidl, "1"));
    try testing.expect(!isMultiline(stat, null));
    try testing.expect(!isMultiline(dele, "1"));
    try testing.expect(!isMultiline(user, "bob"));
    try testing.expect(!isMultiline(quit, null));
    // The verb is read without regard to case, because `--request` is
    // whatever a user typed.
    try testing.expect(isMultiline("retr", "1"));
    try testing.expect(!isMultiline("Stat", null));
}
