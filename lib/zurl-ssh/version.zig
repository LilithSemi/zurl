//! The identification string exchange, RFC 4253 section 4.2.
//!
//! This is the first thing on the wire and the only part of SSH that is
//! text. Each side writes `SSH-protoversion-softwareversion` and a line
//! ending. Every byte after those two lines is a binary packet.
//!
//! **A server may write other lines first, and RFC 4253 section 4.2 lets
//! it write as many as it likes.** That is where a legal notice goes. So
//! this module reads lines until one starts with `SSH-`, and it bounds
//! that search three ways:
//!
//! - `max_line_bytes` is the bound on one line, which RFC 4253 sets at
//!   255 bytes with the line ending counted.
//! - `max_preamble_lines` is the bound on how many lines may come before
//!   the identification.
//! - `max_preamble_bytes` is the bound on the whole preamble.
//!
//! Without all three, a peer that writes short lines forever holds this
//! process forever. The first bound alone does not stop it.
//!
//! **The identification string is the input to the exchange hash**, as
//! `V_C` and `V_S`, and it goes in with no line ending. See
//! `zurl_ssh.kex`.
//!
//! What this module does not own: it opens no connection and it writes
//! nothing to the peer. `zurl_ssh.Transport` runs the exchange over its
//! own channel.

const std = @import("std");
const zurl_net = @import("zurl-net");

/// The bound on one line, the line ending counted. RFC 4253 section 4.2
/// sets it.
pub const max_line_bytes = 255;

/// The bound on the identification string itself, which is
/// `max_line_bytes` less the `CRLF`.
pub const max_identification_bytes = max_line_bytes - 2;

/// How many lines may come before the identification.
///
/// RFC 4253 section 4.2 puts no number on this, so this build picks one.
/// A legal notice of 64 lines is generous, and a peer that writes a 65th
/// is not writing a notice.
pub const max_preamble_lines = 64;

/// How many bytes of preamble this reads before it gives up.
///
/// The line bound and the line count together already cap this, and this
/// third bound is the one that stays right when either of the other two
/// changes.
pub const max_preamble_bytes = 8192;

/// Why an identification string was not accepted.
pub const ParseError = error{
    /// The line does not start with `SSH-`.
    NotIdentification,
    /// The line holds a byte that RFC 4253 section 4.2 forbids. A NUL, a
    /// CR inside the text, and any other control byte all land here.
    IdentificationHasControlByte,
    /// The line is longer than RFC 4253 section 4.2 allows.
    IdentificationTooLong,
    /// There is no protocol version, or no software version behind it.
    IdentificationMalformed,
    /// The peer speaks a protocol version this build does not. SSH 1 is
    /// the case that matters, and this build speaks SSH 2 only.
    UnsupportedProtocolVersion,
};

/// What a peer said it is.
///
/// The slices point into the buffer the line was read into.
pub const Identification = struct {
    /// The whole line, with no line ending. This is what goes into the
    /// exchange hash.
    text: []const u8,
    /// The `protoversion` field, which is `2.0` or `1.99`.
    protocol: []const u8,
    /// The `softwareversion` field, with the comment left off.
    software: []const u8,
    /// The comment behind the first space, or empty.
    comment: []const u8,
};

/// The protocol versions this build speaks.
///
/// `1.99` means a server that speaks both SSH 1 and SSH 2 and that is
/// willing to speak SSH 2, which RFC 4253 section 5.1 describes. `1.5`
/// and anything else means SSH 1 alone, which this build refuses.
const supported_protocols = [_][]const u8{ "2.0", "1.99" };

/// Reads one identification string out of `line`.
///
/// `line` must have no line ending on it. `zurl_net.bounded.readLine`
/// takes both `CRLF` and a bare `LF` off, and a CR left anywhere inside
/// the text is `error.IdentificationHasControlByte`.
pub fn parse(line: []const u8) ParseError!Identification {
    if (line.len > max_identification_bytes) return error.IdentificationTooLong;
    for (line) |c| {
        // RFC 4253 section 4.2 asks for printable US-ASCII. A space is
        // allowed because the comment field is behind one.
        if (c < 0x20 or c > 0x7e) return error.IdentificationHasControlByte;
    }
    if (!std.mem.startsWith(u8, line, "SSH-")) return error.NotIdentification;

    const after_prefix = line[4..];
    const dash = std.mem.indexOfScalar(u8, after_prefix, '-') orelse
        return error.IdentificationMalformed;
    const protocol = after_prefix[0..dash];
    const tail = after_prefix[dash + 1 ..];
    if (protocol.len == 0 or tail.len == 0) return error.IdentificationMalformed;

    var supported = false;
    for (supported_protocols) |name| {
        if (std.mem.eql(u8, protocol, name)) supported = true;
    }
    if (!supported) return error.UnsupportedProtocolVersion;

    const space = std.mem.indexOfScalar(u8, tail, ' ');
    const software = if (space) |i| tail[0..i] else tail;
    const comment = if (space) |i| tail[i + 1 ..] else "";
    if (software.len == 0) return error.IdentificationMalformed;

    return .{ .text = line, .protocol = protocol, .software = software, .comment = comment };
}

/// Why an identification string was not built.
pub const BuildError = error{
    /// The software name holds a byte RFC 4253 section 4.2 forbids there.
    /// A space and a minus sign are both forbidden, because both are
    /// field separators in this line.
    SoftwareNameInvalid,
    /// The line does not fit `out`, or it passes `max_line_bytes`.
    IdentificationTooLong,
};

/// Builds `SSH-2.0-<software>` and a `CRLF` into `out`.
///
/// **The software name is checked before any byte is written.** RFC 4253
/// section 4.2 forbids whitespace and a minus sign in that field, and a
/// name carrying either would move the field boundaries of the line this
/// build then hashes as `V_C`.
///
/// The result points into `out`.
pub fn build(out: []u8, software: []const u8) BuildError![]u8 {
    if (software.len == 0) return error.SoftwareNameInvalid;
    for (software) |c| {
        if (c < 0x21 or c > 0x7e or c == '-') return error.SoftwareNameInvalid;
    }
    const total = "SSH-2.0-".len + software.len + 2;
    if (total > out.len or total > max_line_bytes) return error.IdentificationTooLong;

    var at: usize = 0;
    for ("SSH-2.0-") |c| {
        out[at] = c;
        at += 1;
    }
    @memcpy(out[at..][0..software.len], software);
    at += software.len;
    out[at] = '\r';
    out[at + 1] = '\n';
    return out[0..total];
}

/// The identification string inside a line this build wrote, with the
/// `CRLF` taken off.
///
/// The exchange hash takes `V_C` with no line ending, and this is what
/// takes it off.
pub fn withoutLineEnding(line: []const u8) []const u8 {
    var end = line.len;
    if (end > 0 and line[end - 1] == '\n') end -= 1;
    if (end > 0 and line[end - 1] == '\r') end -= 1;
    return line[0..end];
}

/// Why reading the peer's identification stopped.
pub const ReadError = zurl_net.bounded.LineError || ParseError || error{
    /// The peer wrote `max_preamble_lines` lines, or `max_preamble_bytes`
    /// bytes, and no identification. See the module comment for why all
    /// three bounds are needed.
    NoIdentification,
};

/// Reads the peer's identification string, skipping the lines it may
/// write first.
///
/// The result points into `storage`, so it is valid until the next read
/// into that buffer.
///
/// Bounded four ways: `storage.len` bounds one line,
/// `max_preamble_lines` bounds how many lines are skipped,
/// `max_preamble_bytes` bounds the whole preamble, and `stall` bounds how
/// long the peer may write nothing.
///
/// **A line that is too long ends the session.** `zurl_net.bounded.readLine`
/// consumes what it read, so nothing after that point can be lined up
/// with a line boundary again.
pub fn read(
    r: *std.Io.Reader,
    io: std.Io,
    storage: *[max_line_bytes]u8,
    stall: std.Io.Timeout,
) ReadError!Identification {
    var lines: usize = 0;
    var preamble: usize = 0;
    while (lines <= max_preamble_lines) : (lines += 1) {
        const line = try zurl_net.bounded.readLine(r, io, storage, stall);
        if (std.mem.startsWith(u8, line, "SSH-")) return parse(line);
        // Not the identification, so it is a notice. It is counted and
        // thrown away.
        preamble = std.math.add(usize, preamble, line.len + 2) catch
            return error.NoIdentification;
        if (preamble > max_preamble_bytes) return error.NoIdentification;
    }
    return error.NoIdentification;
}

const testing = std.testing;

test "an identification string splits into its three fields" {
    const id = try parse("SSH-2.0-OpenSSH_9.6");
    try testing.expectEqualStrings("2.0", id.protocol);
    try testing.expectEqualStrings("OpenSSH_9.6", id.software);
    try testing.expectEqualStrings("", id.comment);
    try testing.expectEqualStrings("SSH-2.0-OpenSSH_9.6", id.text);

    const commented = try parse("SSH-2.0-OpenSSH_9.6 Debian and more");
    try testing.expectEqualStrings("OpenSSH_9.6", commented.software);
    try testing.expectEqualStrings("Debian and more", commented.comment);
}

test "SSH 1.99 is a server willing to speak SSH 2, and SSH 1.5 is not" {
    const both = try parse("SSH-1.99-OpenSSH_3.4");
    try testing.expectEqualStrings("1.99", both.protocol);
    try testing.expectError(error.UnsupportedProtocolVersion, parse("SSH-1.5-1.2.27"));
    try testing.expectError(error.UnsupportedProtocolVersion, parse("SSH-3.0-future"));
}

test "a control byte anywhere in the identification is refused" {
    // **This is the rule that keeps the exchange hash input printable.**
    // A CR inside the text would make `V_S` hold a byte no server put
    // there, and a NUL would end a C string in whatever reads the name.
    try testing.expectError(error.IdentificationHasControlByte, parse("SSH-2.0-a\x00b"));
    try testing.expectError(error.IdentificationHasControlByte, parse("SSH-2.0-a\rb"));
    try testing.expectError(error.IdentificationHasControlByte, parse("SSH-2.0-a\x7fb"));
    try testing.expectError(error.IdentificationHasControlByte, parse("SSH-2.0-a\xffb"));
}

test "a malformed identification is refused by name" {
    try testing.expectError(error.NotIdentification, parse("hello"));
    try testing.expectError(error.NotIdentification, parse(""));
    try testing.expectError(error.IdentificationMalformed, parse("SSH-2.0"));
    try testing.expectError(error.IdentificationMalformed, parse("SSH-2.0-"));
    try testing.expectError(error.IdentificationMalformed, parse("SSH--x"));
}

test "an identification longer than RFC 4253 allows is refused" {
    var storage: [max_line_bytes + 1]u8 = undefined;
    @memset(&storage, 'x');
    @memcpy(storage[0..8], "SSH-2.0-");
    try testing.expectError(
        error.IdentificationTooLong,
        parse(storage[0 .. max_identification_bytes + 1]),
    );
    // One byte under the bound is read.
    const ok = try parse(storage[0..max_identification_bytes]);
    try testing.expectEqualStrings("2.0", ok.protocol);
}

test "build writes the line, and parse reads back what it wrote" {
    var storage: [max_line_bytes]u8 = undefined;
    const line = try build(&storage, "zurl_1.1");
    try testing.expectEqualStrings("SSH-2.0-zurl_1.1\r\n", line);

    const id = try parse(withoutLineEnding(line));
    try testing.expectEqualStrings("SSH-2.0-zurl_1.1", id.text);
    try testing.expectEqualStrings("zurl_1.1", id.software);
}

test "a software name with a space, a minus, or a control byte is refused" {
    // RFC 4253 section 4.2 makes both the space and the minus field
    // separators in this line, so neither may sit inside the name.
    var storage: [max_line_bytes]u8 = undefined;
    try testing.expectError(error.SoftwareNameInvalid, build(&storage, "zurl 1.1"));
    try testing.expectError(error.SoftwareNameInvalid, build(&storage, "zurl-1.1"));
    try testing.expectError(error.SoftwareNameInvalid, build(&storage, "zurl\r\n"));
    try testing.expectError(error.SoftwareNameInvalid, build(&storage, ""));

    var long: [max_line_bytes]u8 = undefined;
    @memset(&long, 'x');
    try testing.expectError(error.IdentificationTooLong, build(&storage, &long));
}

test "read skips the lines a server may write before its identification" {
    var source: std.Io.Reader = .fixed(
        "This system is for authorised users only.\r\n" ++
            "Notices may be many lines.\r\n" ++
            "SSH-2.0-OpenSSH_9.6\r\n" ++
            "\x00\x00\x00\x0c",
    );
    var storage: [max_line_bytes]u8 = undefined;
    const id = try read(&source, testing.io, &storage, .none);
    try testing.expectEqualStrings("SSH-2.0-OpenSSH_9.6", id.text);
    // The bytes behind the identification are the first binary packet,
    // and nothing here consumed them.
    try testing.expectEqualSlices(u8, "\x00\x00\x00\x0c", source.buffered());
}

test "a bare LF ends a line too, because servers exist that write one" {
    var source: std.Io.Reader = .fixed("SSH-2.0-tiny\n");
    var storage: [max_line_bytes]u8 = undefined;
    const id = try read(&source, testing.io, &storage, .none);
    try testing.expectEqualStrings("SSH-2.0-tiny", id.text);
}

test "a peer that writes notices forever is refused, and never read forever" {
    // **The bound that matters most in this file.** Each line is short,
    // so the line bound never fires. The count bound is what stops it.
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(testing.allocator);
    for (0..max_preamble_lines + 2) |_| try text.appendSlice(testing.allocator, "notice\r\n");
    try text.appendSlice(testing.allocator, "SSH-2.0-late\r\n");

    var source: std.Io.Reader = .fixed(text.items);
    var storage: [max_line_bytes]u8 = undefined;
    try testing.expectError(error.NoIdentification, read(&source, testing.io, &storage, .none));
}

test "a preamble of long lines is refused on bytes before it is on lines" {
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(testing.allocator);
    var one: [max_identification_bytes]u8 = undefined;
    @memset(&one, 'n');
    for (0..max_preamble_lines) |_| {
        try text.appendSlice(testing.allocator, &one);
        try text.appendSlice(testing.allocator, "\r\n");
    }

    var source: std.Io.Reader = .fixed(text.items);
    var storage: [max_line_bytes]u8 = undefined;
    try testing.expectError(error.NoIdentification, read(&source, testing.io, &storage, .none));
}

test "a line longer than the bound ends the read, and never grows a buffer" {
    var storage_bytes: [max_line_bytes * 4]u8 = undefined;
    @memset(&storage_bytes, 'x');
    var source: std.Io.Reader = .fixed(&storage_bytes);
    var storage: [max_line_bytes]u8 = undefined;
    try testing.expectError(error.LineTooLong, read(&source, testing.io, &storage, .none));
}

test "a peer that closes before it identifies is a fault" {
    var source: std.Io.Reader = .fixed("SSH-2.0-half");
    var storage: [max_line_bytes]u8 = undefined;
    try testing.expectError(error.EndOfStream, read(&source, testing.io, &storage, .none));
}
