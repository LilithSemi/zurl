//! The RFC 5321 commands, and what an `EHLO` answer says a server can do.
//!
//! **The injection gate is not here, and that is on purpose.** Every
//! command this package sends goes out through `Control.send`, which calls
//! `zurl_net.line.Session.send`, which refuses a NUL, a CR, or an LF in
//! any part of the line before a byte reaches the writer. That gate is one
//! function, shared with every other line-oriented protocol package.
//!
//! **Why the gate matters here more than anywhere else.** An SMTP command
//! line carries an address a user wrote, and the command it could forge is
//! `RCPT TO:`. A forged one sends the message to somebody the user never
//! named. Measured against curl 8.21.0 on a loopback fixture:
//!
//!     curl --mail-rcpt $'c@d>\r\nRCPT TO:<evil@x'
//!         wire: RCPT TO:<c@d>, then RCPT TO:<evil@x>
//!     zurl --mail-rcpt $'c@d>\r\nRCPT TO:<evil@x'
//!         exit 3, and no connection at all
//!
//! curl 8.21.0 puts the second recipient on the wire. So does the same
//! text in `--mail-from`. zurl refuses both.
//!
//! This module does no I/O.

const std = @import("std");
const zurl_net = @import("zurl-net");

/// How many bytes of one command line this package writes, the `CRLF`
/// counted.
///
/// RFC 5321 section 4.5.3.1.4 sets the command line at 512 octets and
/// section 4.5.3.1.3 sets the reverse path at 256. This is larger than
/// both, because a server may take more and a client that refused a longer
/// address would refuse mail a server would have taken. It is still a
/// bound, because an unbounded command needs an unbounded buffer. Passing
/// it is `error.CommandTooLong`.
pub const max_command_bytes = zurl_net.line.max_command_bytes;

/// Why a command was not written.
///
/// Both names come from `zurl_net.line`.
pub const WriteError = zurl_net.line.WriteError;

// The commands this package sends. Named here so a typo is a compile error
// and so one file lists every command that can reach a server.

/// RFC 5321: opens the session and asks what the server can do.
pub const ehlo = "EHLO";
/// RFC 821: opens the session on a server that does not know `EHLO`.
pub const helo = "HELO";
/// RFC 5321: names the envelope sender.
pub const mail = "MAIL FROM:<";
/// RFC 5321: names one envelope recipient.
pub const rcpt = "RCPT TO:<";
/// The bracket that closes a `MAIL FROM` or a `RCPT TO` address.
pub const path_close = ">";
/// RFC 5321: says the message follows.
pub const data = "DATA";
/// RFC 3207: asks to put TLS on the connection.
pub const starttls = "STARTTLS";
/// RFC 4954: opens a SASL exchange.
pub const auth = "AUTH";
/// RFC 4954 section 4: the one line a client writes to cancel an exchange
/// it cannot finish.
///
/// **A client that walked away from a challenge without this would leave
/// the server waiting for a response**, and the next command would be read
/// as that response. One asterisk on a line of its own is what says the
/// exchange is over.
pub const auth_cancel = "*";
/// RFC 5321: ends the session.
pub const quit = "QUIT";

/// The `SIZE` parameter of a `MAIL FROM`, RFC 1870.
///
/// curl sends it whenever the `EHLO` answer named `SIZE`, measured:
/// `MAIL FROM:<a@b> SIZE=38`. A server that did not name the extension is
/// sent a plain `MAIL FROM`, because an unknown parameter is a `501` on a
/// server that does not have it.
pub const size_parameter = " SIZE=";

/// The `EHLO` keyword that says a server takes a message size.
pub const size_keyword = "SIZE";

/// The `EHLO` keyword that says a server takes `STARTTLS`.
pub const starttls_keyword = "STARTTLS";

/// The `EHLO` keyword that names the SASL mechanisms a server takes.
///
/// RFC 4954 section 4 writes the line as `AUTH PLAIN LOGIN CRAM-MD5`, one
/// mechanism for each name after the keyword. Measured from a loopback
/// fixture, curl 8.21.0 reads the same line and picks one name off it.
pub const auth_keyword = "AUTH";

/// Whether the text of an `EHLO` answer names `keyword`.
///
/// An `EHLO` answer is one line for each thing the server can do, and this
/// package reads them joined with `\n`, which is what
/// `zurl_net.reply.Collector` builds. The first line is the server's own
/// name and never a keyword, so it is skipped.
///
/// **A middle line still carries its own `250-` prefix.** The collector
/// takes the code off the first line and the last line and keeps every
/// middle line exactly as it arrived, because the standards give a middle
/// line no structure. So this takes the prefix off again, and a reader
/// that did not would find `250-SIZE` where it looked for `SIZE` and
/// would report that no server takes a message size.
///
/// **The keyword must be the whole first word of a line.** RFC 5321
/// section 4.1.1.1 makes it an `ehlo-keyword`, and the rest of the line is
/// its parameters. A test that matched anywhere in the answer would read
/// the server's greeting text as a capability: a banner reading `no
/// STARTTLS here` would otherwise say the opposite of what it says.
pub fn announces(answer: []const u8, keyword: []const u8) bool {
    return parameters(answer, keyword) != null;
}

/// The parameters of the line of `answer` that names `keyword`, or null
/// when no line does.
///
/// **This is `announces`, with the rest of the line kept.** A `SIZE` line
/// is read for its keyword alone, and an `AUTH` line is read for the
/// mechanism names after it. Both rules are the same rule, so both read
/// the same lines the same way: the first line names the server and never
/// a capability, and a middle line still carries its own `250-` prefix.
///
/// A keyword with no parameters gives an empty slice, which is not null. A
/// server that writes a bare `AUTH` line has named the extension and no
/// mechanism, and a caller has to tell that from a server that named no
/// extension at all.
///
/// The result points into `answer`.
pub fn parameters(answer: []const u8, keyword: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, answer, '\n');
    // The first line names the server, not a capability.
    _ = it.next();
    while (it.next()) |line| {
        const bare = std.mem.trim(u8, stripCode(line), " \t");
        const space = std.mem.indexOfAny(u8, bare, " \t") orelse bare.len;
        if (!std.ascii.eqlIgnoreCase(bare[0..space], keyword)) continue;
        return std.mem.trim(u8, bare[space..], " \t");
    }
    return null;
}

/// Takes a `nnn-` or a `nnn ` prefix off `line`, when it carries one.
fn stripCode(line: []const u8) []const u8 {
    if (line.len < 4) return line;
    for (line[0..3]) |c| {
        if (!std.ascii.isDigit(c)) return line;
    }
    return switch (line[3]) {
        ' ', '-' => line[4..],
        else => line,
    };
}

const testing = std.testing;

test "every command this package sends carries no framing byte" {
    const parts = [_][]const u8{
        ehlo,             helo,         data,       starttls,       quit,
        mail,             rcpt,         path_close, size_parameter, size_keyword,
        starttls_keyword, auth_keyword, auth,       auth_cancel,
    };
    for (parts) |part| {
        try testing.expect(part.len > 0);
        try testing.expect(!zurl_net.line.hasFramingByte(part));
    }
}

test "a middle line still carries its own code, and the keyword is behind it" {
    // **This is the shape `zurl_net.reply.Collector` really builds.** It
    // takes the code off the first line and the last line and keeps every
    // middle line whole, so a reader that did not take the prefix off here
    // would find `250-SIZE` where it looked for `SIZE`.
    const answer = "fixture\n250-SIZE 1000000\n250-PIPELINING\nSTARTTLS";
    try testing.expect(announces(answer, size_keyword));
    try testing.expect(announces(answer, "PIPELINING"));
    try testing.expect(announces(answer, starttls_keyword));
    try testing.expect(!announces(answer, "250"));
    try testing.expect(!announces(answer, "AUTH"));
}

test "an EHLO answer names a keyword only as the first word of a line" {
    const answer = "mail.example.com Hello\nSIZE 1000000\nPIPELINING\nSTARTTLS\n8BITMIME";
    try testing.expect(announces(answer, size_keyword));
    try testing.expect(announces(answer, starttls_keyword));
    try testing.expect(announces(answer, "PIPELINING"));
    try testing.expect(announces(answer, "8BITMIME"));
    try testing.expect(!announces(answer, "AUTH"));
    try testing.expect(!announces(answer, "1000000"));
}

test "the server's own name is not a keyword" {
    // **The defect this rule exists for.** A banner reading `no STARTTLS
    // here` would otherwise say the server takes the command.
    try testing.expect(!announces("STARTTLS.example.com Hello", starttls_keyword));
    try testing.expect(!announces("SIZE.example.com Hello", size_keyword));
    try testing.expect(!announces("mail.example.com no STARTTLS here", starttls_keyword));
    try testing.expect(!announces("mail.example.com Hello\nno STARTTLS here", starttls_keyword));
}

test "a keyword is read without regard to case, and its parameters do not count" {
    try testing.expect(announces("host\nsize 100", size_keyword));
    try testing.expect(announces("host\nSize 100", size_keyword));
    try testing.expect(announces("host\n  SIZE  100  ", size_keyword));
    // A longer word that starts with the keyword is another keyword.
    try testing.expect(!announces("host\nSIZEX 100", size_keyword));
    try testing.expect(!announces("host\nXSIZE", size_keyword));
}

test "an answer of one line names no keyword at all" {
    try testing.expect(!announces("mail.example.com Hello", size_keyword));
    try testing.expect(!announces("", size_keyword));
}

test "the AUTH line hands back the mechanisms after the keyword" {
    // This is the shape `zurl_net.reply.Collector` builds: the code is
    // off the first line and the last line and every middle line keeps
    // its own.
    const answer = "fixture\n250-SIZE 1000000\n250-AUTH PLAIN LOGIN CRAM-MD5\nSTARTTLS";
    try testing.expectEqualStrings(
        "PLAIN LOGIN CRAM-MD5",
        parameters(answer, auth_keyword).?,
    );
    try testing.expectEqualStrings("1000000", parameters(answer, size_keyword).?);
    // A keyword with no parameters gives an empty slice and never null.
    try testing.expectEqualStrings("", parameters(answer, starttls_keyword).?);
    // A keyword no line names gives null, which is what tells a caller
    // the server offers no SASL at all.
    try testing.expectEqual(@as(?[]const u8, null), parameters(answer, "GSSAPI"));
}

test "an AUTH line the server did not write is null and never an empty list" {
    // **A server that named no AUTH is not a server that named an empty
    // AUTH.** The first may take a login another way and the second
    // cannot, so the two must not read the same.
    try testing.expectEqual(
        @as(?[]const u8, null),
        parameters("fixture\n250 SIZE 100", auth_keyword),
    );
    try testing.expectEqualStrings(
        "",
        parameters("fixture\n250 AUTH", auth_keyword).?,
    );
    // The server's own name is not a keyword here either.
    try testing.expectEqual(
        @as(?[]const u8, null),
        parameters("AUTH.example.com Hello", auth_keyword),
    );
}

test "the AUTH line is read without regard to case, the way SIZE is" {
    try testing.expectEqualStrings(
        "PLAIN LOGIN",
        parameters("host\n250-auth PLAIN LOGIN\n250 SIZE 1", auth_keyword).?,
    );
    try testing.expectEqualStrings(
        "PLAIN",
        parameters("host\n  AUTH  PLAIN  ", auth_keyword).?,
    );
    // A longer word that opens with the keyword is another keyword.
    try testing.expectEqual(
        @as(?[]const u8, null),
        parameters("host\nAUTHX PLAIN", auth_keyword),
    );
}
