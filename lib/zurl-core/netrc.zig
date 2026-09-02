//! A parser for the netrc file format.
//!
//! This module does no I/O. The caller reads the file and passes the bytes.
//! The format is a stream of tokens, so a newline and a space mean the same
//! thing.

const std = @import("std");

/// The credentials for one machine. Every slice borrows from the input text.
pub const Entry = struct {
    login: ?[]const u8 = null,
    password: ?[]const u8 = null,
    account: ?[]const u8 = null,
};

/// Returns the entry for `host`, or the `default` entry, or null.
///
/// A named machine wins over `default` even when `default` comes first, which
/// is what curl does.
pub fn lookup(text: []const u8, host: []const u8) ?Entry {
    var it: Tokenizer = .{ .text = text };

    var matched: ?Entry = null;
    var fallback: ?Entry = null;
    // Which entry the following login, password, and account tokens belong to.
    var target: enum { none, matched, fallback } = .none;

    while (it.next()) |token| {
        if (std.mem.eql(u8, token, "machine")) {
            const name = it.next() orelse break;
            if (std.ascii.eqlIgnoreCase(name, host)) {
                matched = .{};
                target = .matched;
            } else {
                target = .none;
            }
            continue;
        }
        if (std.mem.eql(u8, token, "default")) {
            // A later default does not replace an earlier one.
            if (fallback == null) fallback = .{};
            target = .fallback;
            continue;
        }
        if (std.mem.eql(u8, token, "macdef")) {
            it.skipMacdef();
            target = .none;
            continue;
        }

        const field: enum { login, password, account } =
            if (std.mem.eql(u8, token, "login"))
                .login
            else if (std.mem.eql(u8, token, "password"))
                .password
            else if (std.mem.eql(u8, token, "account"))
                .account
            else
                continue;

        const value = it.next() orelse break;
        const entry = switch (target) {
            .none => continue,
            .matched => &matched.?,
            .fallback => &fallback.?,
        };
        switch (field) {
            .login => entry.login = value,
            .password => entry.password = value,
            .account => entry.account = value,
        }
    }

    return matched orelse fallback;
}

/// Splits netrc text into tokens. A comment runs to the end of its line.
const Tokenizer = struct {
    text: []const u8,
    index: usize = 0,

    fn next(t: *Tokenizer) ?[]const u8 {
        t.skipSpaceAndComments();
        if (t.index >= t.text.len) return null;
        const start = t.index;
        while (t.index < t.text.len and !isSpace(t.text[t.index])) t.index += 1;
        return t.text[start..t.index];
    }

    /// Steps over the rest of a macdef, which ends at a blank line.
    fn skipMacdef(t: *Tokenizer) void {
        // Step over the macro name and the rest of its line, then past the
        // newline itself. Without that step, the loop below reads a
        // zero-length line at the current position and returns at once,
        // never skipping the macro body.
        while (t.index < t.text.len and t.text[t.index] != '\n') t.index += 1;
        if (t.index < t.text.len) t.index += 1;
        while (t.index < t.text.len) {
            const line_start = t.index;
            while (t.index < t.text.len and t.text[t.index] != '\n') t.index += 1;
            const line = std.mem.trim(u8, t.text[line_start..t.index], " \t\r");
            if (t.index < t.text.len) t.index += 1;
            if (line.len == 0) return;
        }
    }

    fn skipSpaceAndComments(t: *Tokenizer) void {
        while (t.index < t.text.len) {
            if (isSpace(t.text[t.index])) {
                t.index += 1;
                continue;
            }
            if (t.text[t.index] == '#') {
                while (t.index < t.text.len and t.text[t.index] != '\n') t.index += 1;
                continue;
            }
            return;
        }
    }

    fn isSpace(c: u8) bool {
        return c == ' ' or c == '\t' or c == '\r' or c == '\n';
    }
};

const sample =
    \\# a comment
    \\machine example.com
    \\  login bob
    \\  password secret
    \\
    \\machine other.example.com login alice password hunter2 account acct
    \\
    \\default login anon password anon@example.com
;

test "lookup finds an entry by machine name" {
    const e = lookup(sample, "example.com").?;
    try std.testing.expectEqualStrings("bob", e.login.?);
    try std.testing.expectEqualStrings("secret", e.password.?);
    try std.testing.expectEqual(@as(?[]const u8, null), e.account);
}

test "lookup reads an entry written on one line" {
    const e = lookup(sample, "other.example.com").?;
    try std.testing.expectEqualStrings("alice", e.login.?);
    try std.testing.expectEqualStrings("hunter2", e.password.?);
    try std.testing.expectEqualStrings("acct", e.account.?);
}

test "lookup falls back to the default entry" {
    const e = lookup(sample, "unlisted.example.com").?;
    try std.testing.expectEqualStrings("anon", e.login.?);
    try std.testing.expectEqualStrings("anon@example.com", e.password.?);
}

test "lookup returns null when there is no match and no default" {
    const text = "machine example.com login bob password secret";
    try std.testing.expectEqual(@as(?Entry, null), lookup(text, "other.com"));
}

test "lookup ignores a macdef body" {
    const text =
        \\macdef init
        \\machine trap.example.com login evil password evil
        \\
        \\machine example.com login bob password secret
    ;
    try std.testing.expectEqual(@as(?Entry, null), lookup(text, "trap.example.com"));
    const e = lookup(text, "example.com").?;
    try std.testing.expectEqualStrings("bob", e.login.?);
}

test "a host name match ignores case" {
    const e = lookup(sample, "EXAMPLE.COM").?;
    try std.testing.expectEqualStrings("bob", e.login.?);
}

test "lookup returns null for empty text" {
    try std.testing.expectEqual(@as(?Entry, null), lookup("", "example.com"));
}
