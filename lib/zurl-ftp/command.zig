//! Writes one RFC 959 command line, and refuses every byte that could
//! forge a second one.
//!
//! **This is the one function that turns text into a command.** Every
//! command an FTP session sends goes through `write`: the verb this file
//! names, and the argument, which comes from a url path, a user name, a
//! password, or a number this package computed. Nothing else in the
//! package writes to the control connection, so the refusal below covers
//! every command and not the ones somebody remembered.
//!
//! **The rule.** A command is `VERB<SP>argument<CRLF>`, so a CR or an LF
//! inside the argument ends the line early and starts a command of the
//! argument's choosing. `USER a<CRLF>PASS x<CRLF>` from a url is two
//! commands where the url named one. A NUL is refused with them: RFC 959
//! puts no NUL in a command, an operating system reads a path up to the
//! first one, and one rule over the three bytes is the rule this project
//! already keeps for `gopher` and `tftp`.
//!
//! **The refusal comes before any byte reaches the socket.** `write`
//! builds the whole line into the caller's buffer and checks the argument
//! first, so a refused command leaves nothing half written on the wire.
//!
//! This module does no I/O. It writes into a buffer the caller owns.
//!
//! **The refusal itself is `zurl_net.line.write`**, which every
//! line-oriented protocol package shares. SMTP, IMAP, and POP3 each frame
//! a command their own way and each needs the same gate, so the gate is
//! one function in `zurl-net` and this module is the FTP shape over it.

const std = @import("std");
const zurl_net = @import("zurl-net");

/// How many bytes of one command line this writes, the `CRLF` counted.
///
/// RFC 959 sets no limit. A path can be long and a password longer, so
/// this is generous, and it is a bound because an unbounded command needs
/// an unbounded buffer. Passing it is `error.CommandTooLong`.
pub const max_command_bytes = zurl_net.line.max_command_bytes;

/// Why a command was not written.
///
/// `ArgumentHasFramingByte` says the argument holds a NUL, a CR, or an LF,
/// and `CommandTooLong` says the verb and the argument do not fit. Both
/// come from `zurl_net.line`.
pub const WriteError = zurl_net.line.WriteError;

/// Writes `VERB<SP>argument<CRLF>` into `out`, or `VERB<CRLF>` for a null
/// argument, and returns the bytes written.
///
/// **The argument is checked before anything is written.** A NUL, a CR, or
/// an LF anywhere in it is `error.ArgumentHasFramingByte` and `out` is not
/// touched.
///
/// `verb` is never checked, and it does not need to be: every call site in
/// this package passes a string constant this file names below. It is a
/// parameter and not an enum so a caller reads `RETR` at the call, and the
/// constants are here so a typo is a compile error.
pub fn write(out: []u8, verb: []const u8, argument: ?[]const u8) WriteError![]u8 {
    // The package bound stands even when the caller's buffer is larger,
    // so one number answers how long an FTP command may be.
    const argument_len = if (argument) |text| text.len + 1 else 0;
    if (verb.len + argument_len + 2 > max_command_bytes) return error.CommandTooLong;

    // **The refusal is inside this call, and it runs before any byte is
    // written.** See `zurl_net.line.write`.
    if (argument) |text| return zurl_net.line.write(out, &.{ verb, " ", text });
    return zurl_net.line.write(out, &.{verb});
}

/// Writes a command whose argument is a number this package computed.
///
/// The number cannot hold a framing byte, so this cannot be refused for
/// one. It still goes through `write`, because one path to the socket is
/// what makes the rule above hold for every command.
pub fn writeNumber(out: []u8, verb: []const u8, value: u64) WriteError![]u8 {
    var digits: [20]u8 = undefined;
    const text = std.fmt.bufPrint(&digits, "{d}", .{value}) catch return error.CommandTooLong;
    return write(out, verb, text);
}

/// The password an anonymous login sends when the caller named none.
///
/// curl 8.21.0 sends exactly this, measured against a loopback server:
/// `USER anonymous` and then `PASS ftp@example.com`.
pub const anonymous_password = "ftp@example.com";

/// The user name an anonymous login sends when the caller named none.
pub const anonymous_user = "anonymous";

// The verbs this package sends. Named here so a typo is a compile error
// and so one file lists every command that can reach a server.

/// RFC 959: names the user to log in as.
pub const user = "USER";
/// RFC 959: the password for `user`.
pub const pass = "PASS";
/// RFC 959: changes the working directory, one component at a time.
pub const cwd = "CWD";
/// RFC 959: sets the representation type. `I` for a download, `A` for a
/// listing.
pub const type_ = "TYPE";
/// RFC 959: asks the server to listen for the data connection, and to name
/// the address and port in a `227` answer.
pub const pasv = "PASV";
/// RFC 2428: asks the same as `PASV`, and names the port alone.
pub const epsv = "EPSV";
/// RFC 3659: asks for the size of a file, in a `213` answer.
pub const size = "SIZE";
/// RFC 959: says where the next transfer starts. This is `-C`.
pub const rest = "REST";
/// RFC 959: sends a file down the data connection.
pub const retr = "RETR";
/// RFC 959: sends a directory listing down the data connection.
pub const list = "LIST";
/// RFC 959: sends the names alone down the data connection. This is `-l`.
pub const nlst = "NLST";
/// RFC 4217: asks to put TLS on the control connection.
pub const auth = "AUTH";
/// RFC 4217: sets the protection buffer size, which is always 0 for TLS.
pub const pbsz = "PBSZ";
/// RFC 4217: sets the data channel protection level. `P` is private.
pub const prot = "PROT";
/// RFC 959: ends the session.
pub const quit = "QUIT";

const testing = std.testing;

test "a command with an argument, and one without" {
    var out: [64]u8 = undefined;
    try testing.expectEqualStrings("USER anonymous\r\n", try write(&out, user, "anonymous"));
    try testing.expectEqualStrings("PASV\r\n", try write(&out, pasv, null));
    try testing.expectEqualStrings("QUIT\r\n", try write(&out, quit, null));
    try testing.expectEqualStrings("TYPE I\r\n", try write(&out, type_, "I"));
    try testing.expectEqualStrings("REST 20\r\n", try writeNumber(&out, rest, 20));
    try testing.expectEqualStrings("REST 0\r\n", try writeNumber(&out, rest, 0));
}

test "an empty argument still writes the space, because the argument exists" {
    // `RETR <SP><CRLF>` and `RETR<CRLF>` are different commands. A caller
    // that passes an empty slice asked for the first one.
    var out: [64]u8 = undefined;
    try testing.expectEqualStrings("RETR \r\n", try write(&out, retr, ""));
    try testing.expectEqualStrings("RETR\r\n", try write(&out, retr, null));
}

test "a CR, an LF, or a NUL in an argument is refused and nothing is written" {
    // **The injection proof.** Each argument below would end the command
    // line early and put a command of its own behind it.
    var out: [128]u8 = undefined;
    @memset(&out, 0xaa);

    const forged = [_][]const u8{
        "a\r\nQUIT",
        "a\nQUIT",
        "a\rQUIT",
        "a\x00b",
        "\r\n",
        "\n",
        "\r",
        "\x00",
        "anonymous\r\nPASS hunter2",
        "/pub\r\nDELE important",
        "\r\nAUTH TLS",
    };
    for (forged) |argument| {
        for ([_][]const u8{ user, pass, cwd, retr, list, nlst, size, type_, prot, auth }) |verb| {
            try testing.expectError(error.ArgumentHasFramingByte, write(&out, verb, argument));
        }
    }

    // Not one byte of the buffer moved.
    for (out) |byte| try testing.expectEqual(@as(u8, 0xaa), byte);
}

test "a byte that is not framing still reaches the command line" {
    // The rule refuses three bytes and never a fourth. A space, a tab, a
    // DEL, and a high byte are all ordinary in a path a server holds.
    var out: [64]u8 = undefined;
    try testing.expectEqualStrings("RETR a b.txt\r\n", try write(&out, retr, "a b.txt"));
    try testing.expectEqualStrings("RETR a\tb\r\n", try write(&out, retr, "a\tb"));
    try testing.expectEqualStrings("RETR a\x7fb\r\n", try write(&out, retr, "a\x7fb"));
    try testing.expectEqualStrings("RETR \xc3\xa9\r\n", try write(&out, retr, "\xc3\xa9"));
    try testing.expectEqualStrings("RETR a%0db\r\n", try write(&out, retr, "a%0db"));
}

test "a command past the bound is refused, and one at the bound is written" {
    var out: [max_command_bytes]u8 = undefined;
    var argument: [max_command_bytes]u8 = undefined;
    @memset(&argument, 'x');

    // `RETR` is four bytes, the space is one, and `CRLF` is two.
    const fits = max_command_bytes - 7;
    const line = try write(&out, retr, argument[0..fits]);
    try testing.expectEqual(max_command_bytes, line.len);

    try testing.expectError(error.CommandTooLong, write(&out, retr, argument[0 .. fits + 1]));
}

test "a buffer smaller than the command refuses rather than overrun" {
    var out: [8]u8 = undefined;
    try testing.expectError(error.CommandTooLong, write(&out, retr, "a-long-name.txt"));
}

test "the anonymous credential is the one curl sends" {
    // Measured against curl 8.21.0 on a loopback RFC 959 server:
    // `USER anonymous` and `PASS ftp@example.com`.
    try testing.expectEqualStrings("anonymous", anonymous_user);
    try testing.expectEqualStrings("ftp@example.com", anonymous_password);
}
