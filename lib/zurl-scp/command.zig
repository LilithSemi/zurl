//! The remote command an `scp://` transfer runs, and the one quoting rule
//! this repository has for a path that reaches a shell.
//!
//! # The rule
//!
//! **Wrap the whole path in single quotes, and write every embedded `'` as
//! `'"'"'`. Refuse a NUL, refuse an empty path, and refuse a path that
//! does not fit the bound.** Nothing else is changed, and no byte is
//! dropped.
//!
//! That is the whole rule. It is libssh2's `shell_quotearg` in its
//! single-quote form, and it is what curl 8.21.0 sends: the command was
//! read off a real OpenSSH 10.5p1 with a `ForceCommand` that logged
//! `$SSH_ORIGINAL_COMMAND`, and curl wrote `scp -pf '/tmp/.../hello.txt'`
//! and `scp -pf '/tmp/.../it'"'"'s.txt'`.
//!
//! # Why it is safe
//!
//! RFC 4254 section 6.5 says the server runs an `exec` command "as if"
//! a shell had read it, so every quoting rule of that shell applies. Inside
//! a POSIX single-quoted string a shell expands nothing: a space, a `$`, a
//! backtick, a `;`, a `|`, a `&`, a `(`, a newline, and a `<` are all
//! ordinary data. **The single quote is the only byte that can leave the
//! string**, and `'"'"'` closes the string, writes one literal quote inside
//! a double-quoted string, and opens the string again. There is no third
//! case, so there is no byte a shell reads as syntax after this runs.
//!
//! Two bytes are refused rather than escaped:
//!
//! - **A NUL.** The far side hands the command to a shell as a C string
//!   and the shell hands the path to `execve` as a C string, so a NUL cuts
//!   the path there. The remote would then act on a shorter path than zurl
//!   asked for and report success for it. No escaping closes that, so the
//!   path is refused.
//! - **Nothing else.** A newline, a CR, and every control byte survive the
//!   quotes as data, which is what a file name holding one deserves.
//!
//! # What a caller must not do
//!
//! **Do not build a command any other way.** `zurl_ssh.connection.writeExec`
//! writes the bytes and judges none of them, and this file is the one
//! caller of it outside a test. A second builder is how the next injection
//! gets in.
//!
//! **Do not interpolate anything but the path.** The mode, the size, and
//! the file name that come back from the server never reach a command.

const std = @import("std");

/// The longest path this build sends to a remote `scp`.
///
/// 4096, which is `PATH_MAX` on Linux and the bound `zurl_sftp.protocol`
/// keeps for the same reason. A path past it is refused before one byte is
/// quoted, so the quoting never runs on input this build could not send
/// anyway.
pub const max_path_bytes: usize = 4096;

/// How many bytes one path byte can become.
///
/// Five. A `'` becomes `'"'"'`, which is five bytes, and every other byte
/// stays one. The number is here so that `max_command_bytes` is a
/// computation and not a guess.
pub const quote_growth: usize = 5;

/// The longest command this build writes.
///
/// The longest prefix, plus the two quotes the wrapper adds, plus the worst
/// case of `max_path_bytes` bytes that are every one of them a single
/// quote.
pub const max_command_bytes: usize =
    max_prefix_bytes + 2 + max_path_bytes * quote_growth;

/// Which direction a transfer runs, which is the only thing that changes
/// the command.
pub const Mode = enum {
    /// Read a file off the server. The remote command is `scp -pf <path>`.
    ///
    /// The `-f` is "from", which is what puts the remote `scp` in source
    /// mode. The `-p` asks it for the times, which it writes as a `T` line
    /// before the `C` line. curl sends both, measured.
    download,
    /// Write a file onto the server. The remote command is `scp -t <path>`.
    ///
    /// The `-t` is "to", which is sink mode. curl sends no `-p` here,
    /// measured, because this side has no times to give.
    upload,

    /// The bytes in front of the quoted path, with the space.
    pub fn prefix(m: Mode) []const u8 {
        return switch (m) {
            .download => "scp -pf ",
            .upload => "scp -t ",
        };
    }
};

/// The longest `Mode.prefix`.
const max_prefix_bytes: usize = "scp -pf ".len;

/// Why a path will not become a command.
///
/// **Every one of these stops the transfer.** None of them is recovered
/// from by changing the path, because a path this build changed is not the
/// path the user asked for.
pub const Error = error{
    /// The path holds no byte. There is no file to name.
    PathEmpty,
    /// The path holds a NUL, which would cut it short on the far side.
    PathHasNul,
    /// The path is longer than `max_path_bytes`.
    PathTooLong,
    /// The quoted command does not fit the buffer the caller gave.
    CommandTooLong,
};

/// Writes `path` as one POSIX shell word into `out`.
///
/// This is the rule the module comment states, and it is written here once.
/// **A caller that needs a quoted path calls this and does not copy the
/// three lines below.**
pub fn quote(out: []u8, path: []const u8) Error![]u8 {
    if (path.len == 0) return error.PathEmpty;
    if (path.len > max_path_bytes) return error.PathTooLong;
    if (std.mem.indexOfScalar(u8, path, 0) != null) return error.PathHasNul;

    // The room is checked once, against the worst case, before one byte is
    // written. A bound checked while writing would leave a half-built
    // command in `out` for a caller that ignored the error.
    if (out.len < path.len * quote_growth + 2) return error.CommandTooLong;

    var at: usize = 0;
    out[at] = '\'';
    at += 1;
    for (path) |byte| {
        if (byte == '\'') {
            // Close the string, write one literal quote in double quotes,
            // and open the string again. This is the only escape, because
            // it is the only byte that can leave a single-quoted string.
            @memcpy(out[at..][0..5], "'\"'\"'");
            at += 5;
        } else {
            out[at] = byte;
            at += 1;
        }
    }
    out[at] = '\'';
    at += 1;
    return out[0..at];
}

/// Writes the whole remote command for one transfer into `out`.
///
/// **`out` must be at least `max_command_bytes` long** for a caller that
/// wants every path this build accepts to fit. A shorter buffer is not a
/// fault by itself: a command that does not fit is `error.CommandTooLong`
/// and never a command cut short.
pub fn build(out: []u8, mode: Mode, path: []const u8) Error![]u8 {
    const prefix = mode.prefix();
    if (out.len < prefix.len) return error.CommandTooLong;
    @memcpy(out[0..prefix.len], prefix);
    const quoted = try quote(out[prefix.len..], path);
    return out[0 .. prefix.len + quoted.len];
}

const testing = std.testing;

test "a plain path is wrapped in single quotes and changed no other way" {
    var storage: [128]u8 = undefined;
    try testing.expectEqualStrings(
        "'/tmp/hello.txt'",
        try quote(&storage, "/tmp/hello.txt"),
    );
}

test "the command is the one curl sends, measured against a real OpenSSH" {
    var storage: [max_command_bytes]u8 = undefined;
    try testing.expectEqualStrings(
        "scp -pf '/srv/hello.txt'",
        try build(&storage, .download, "/srv/hello.txt"),
    );
    try testing.expectEqualStrings(
        "scp -t '/srv/up.txt'",
        try build(&storage, .upload, "/srv/up.txt"),
    );
}

test "a single quote becomes the five byte sequence and nothing else does" {
    var storage: [128]u8 = undefined;
    // curl 8.21.0 sends exactly this for a file named `it's.txt`,
    // measured off a `ForceCommand` on OpenSSH 10.5p1.
    try testing.expectEqualStrings(
        "'/srv/it'\"'\"'s.txt'",
        try quote(&storage, "/srv/it's.txt"),
    );
    // Two in a row, and one at each end, because the loop has no state and
    // a rule that only works away from the edges is a rule that does not
    // work.
    try testing.expectEqualStrings(
        "''\"'\"''\"'\"''",
        try quote(&storage, "''"),
    );
    try testing.expectEqualStrings(
        "''\"'\"'a'\"'\"''",
        try quote(&storage, "'a'"),
    );
}

test "every shell metacharacter reaches the remote as data" {
    // **This is the test the whole file exists for.** Each of these bytes
    // is syntax to a shell, and each one must come out of `quote` as
    // itself, inside the quotes, with no extra byte beside it.
    const hostile = [_][]const u8{
        ";",         "|",   "&",    "$",     "`",  "(",  ")",  "<",  ">",  "\n",        "\r",         "\t",
        " ",         "*",   "?",    "[",     "]",  "{",  "}",  "#",  "~",  "!",         "\\",         "\"",
        "$(",        "${",  "`id`", "$(id)", "&&", "||", ";;", ">>", "2>", "\n/bin/sh", "; rm -rf /", "$(touch /tmp/pwned)",
        "`touch x`", "a b", "--",   "-rf",
    };
    var storage: [256]u8 = undefined;
    for (hostile) |sample| {
        const got = try quote(&storage, sample);
        // The shape is one quote, the bytes, one quote. No byte grew and
        // none was dropped, because none of these is a single quote.
        try testing.expectEqual(sample.len + 2, got.len);
        try testing.expectEqual(@as(u8, '\''), got[0]);
        try testing.expectEqual(@as(u8, '\''), got[got.len - 1]);
        try testing.expectEqualStrings(sample, got[1 .. got.len - 1]);
    }
}

test "a quoted command holds no unquoted metacharacter anywhere" {
    // A stronger reading of the same property, over the whole command: past
    // the prefix, the only bytes outside the single quotes are the ones the
    // `'"'"'` escape writes. So the count of quote characters is even, and
    // every byte between an opening and a closing quote is data.
    var storage: [max_command_bytes]u8 = undefined;
    const path = "/srv/a';id;'b$(x)`y`|z&w\n";
    const command = try build(&storage, .download, path);

    // Walk the command the way a shell would, tracking whether the walker
    // is inside a single-quoted string, and collect what a shell would take
    // as the one argument.
    var word: [256]u8 = undefined;
    var at: usize = 0;
    var i: usize = "scp -pf ".len;
    var single = false;
    var double = false;
    while (i < command.len) : (i += 1) {
        const byte = command[i];
        if (byte == '\'' and !double) {
            single = !single;
            continue;
        }
        if (byte == '"' and !single) {
            double = !double;
            continue;
        }
        // Nothing outside a quoted string may reach here: every byte of
        // the path is written inside one.
        try testing.expect(single or double);
        word[at] = byte;
        at += 1;
    }
    try testing.expect(!single and !double);
    // What the shell would hand the remote `scp` is the path, byte for
    // byte, and nothing was ever a second word or a second command.
    try testing.expectEqualStrings(path, word[0..at]);
}

test "a NUL is refused, because no escaping closes it" {
    var storage: [128]u8 = undefined;
    try testing.expectError(error.PathHasNul, quote(&storage, "/srv/a\x00b"));
    try testing.expectError(error.PathHasNul, build(&storage, .download, "\x00"));
}

test "an empty path and a path past the bound are refused" {
    var storage: [max_command_bytes]u8 = undefined;
    try testing.expectError(error.PathEmpty, quote(&storage, ""));

    var long: [max_path_bytes + 1]u8 = undefined;
    @memset(&long, 'a');
    try testing.expectError(error.PathTooLong, quote(&storage, &long));
    try testing.expectEqual(
        @as(usize, max_path_bytes + 2),
        (try quote(&storage, long[0..max_path_bytes])).len,
    );
}

test "a buffer too small is a refusal and never a command cut short" {
    var storage: [8]u8 = undefined;
    try testing.expectError(error.CommandTooLong, quote(&storage, "abcdefgh"));
    try testing.expectError(error.CommandTooLong, build(&storage, .download, "a"));
    // Nothing was written into the caller's buffer past the prefix, so a
    // caller that ignored the error has no half-built command to send.
    try testing.expectError(error.CommandTooLong, build(storage[0..4], .download, "a"));
}

test "max_command_bytes holds the worst case this build accepts" {
    // Every byte a single quote is the worst input, and it must still fit.
    const gpa = testing.allocator;
    const path = try gpa.alloc(u8, max_path_bytes);
    defer gpa.free(path);
    @memset(path, '\'');

    const out = try gpa.alloc(u8, max_command_bytes);
    defer gpa.free(out);
    const command = try build(out, .download, path);
    try testing.expectEqual(max_command_bytes, command.len);
}

test "the two modes name the two halves of the rcp protocol" {
    try testing.expectEqualStrings("scp -pf ", Mode.download.prefix());
    try testing.expectEqualStrings("scp -t ", Mode.upload.prefix());
    // The download asks for the times, which is what makes the server
    // write a `T` line before the `C` line.
    try testing.expect(std.mem.indexOf(u8, Mode.download.prefix(), "-p") != null);
    try testing.expect(std.mem.indexOf(u8, Mode.upload.prefix(), "-p") == null);
}
