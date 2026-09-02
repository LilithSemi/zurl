//! The rcp dialogue over one SSH `exec` channel.
//!
//! `zurl_ssh.Channel` is a byte stream and this is the protocol that runs
//! inside it. **One control line is not one `SSH_MSG_CHANNEL_DATA`**: a
//! line can be split across two of them, and a line and the file bytes
//! behind it can arrive in one. This value frames on the newline and on the
//! byte count a `C` line named, and never on a channel message boundary. A
//! build that assumed one for the other works against a fixture on a fast
//! loopback socket and fails against the same server over a long link.
//!
//! # One file, and no recursion
//!
//! A remote `scp -pf` can send a `D` line and walk a whole directory. **This
//! build refuses one by name.** curl does the same: `scp://` names one file
//! and there is no `-r`. A refusal that says `D` arrived is better than a
//! transfer that silently read the first file of a tree.
//!
//! # Every bound on the peer
//!
//! | what | bound | where |
//! | --- | --- | --- |
//! | one control line | `protocol.max_line_bytes` | `readLine` |
//! | the mode, the size, and the name on a `C` line | see `protocol` | `nextFile` |
//! | the bytes of one file | the size the `C` line named, and no more | `readBody` |
//! | a warning or a fatal message kept | `max_message_bytes` | `takeMessage` |
//! | control lines before the file | `max_control_lines` | `nextFile` |
//!
//! **The size on the `C` line bounds the read and the caller bounds the
//! size.** `readBody` never returns one byte past it, whatever the server
//! writes, and a caller that has its own ceiling checks the size before it
//! allocates.

const Session = @This();

const std = @import("std");
const zurl_ssh = @import("zurl-ssh");

const command = @import("command.zig");
const protocol = @import("protocol.zig");

/// How many bytes of a warning or a fatal message this keeps.
///
/// 256. It is the peer's own text, it goes into a diagnostic, and a
/// diagnostic has room for one sentence. **Nothing has made it safe for a
/// terminal here**: a caller runs it through
/// `zurl_ssh.userauth.sanitizeBanner` before it reaches one.
pub const max_message_bytes: usize = 256;

/// How many control lines this reads before it gives up on finding a `C`.
///
/// A server may write a `T` line and a warning before the `C` line. Eight
/// is more than any real one writes, and it stops a peer that answers
/// forever with lines that name no file.
pub const max_control_lines: usize = 8;

/// Why the dialogue stopped.
pub const Error = zurl_ssh.Channel.Error || protocol.ParseError || error{
    /// The remote `scp` wrote a `\x01` or a `\x02` message.
    /// `lastMessage` is what it said.
    RemoteFault,
    /// The channel ended before the dialogue did.
    PartialFile,
    /// The peer answered a control line with a byte this build does not
    /// name.
    StatusUnknown,
    /// The server sent a `D` line, which is a directory, and this build
    /// transfers one file.
    DirectoryUnsupported,
    /// The server wrote more control lines than `max_control_lines`
    /// without naming a file.
    ControlLineFlood,
    /// A caller asked for something out of order. A caller's own bug.
    SessionStateInvalid,
};

/// What the dialogue did that no caller asked for.
pub const Counters = struct {
    /// How many `T` lines arrived.
    time_lines: u64 = 0,
    /// How many `\x01` warnings arrived that the transfer carried on past.
    warnings: u64 = 0,
    /// How many control lines arrived in all.
    control_lines: u64 = 0,
};

/// The one file a download reads.
pub const File = struct {
    /// The mode the server named. **Read and never applied.** See
    /// `protocol`.
    mode: u16,
    /// How many bytes the file holds, as the server named it.
    size: u64,
    /// The name the server named. **It never chooses a file zurl writes.**
    /// It points into this value's own line buffer and it is valid until
    /// the next `nextFile`.
    name: []const u8,
};

channel: *zurl_ssh.Channel,

/// Holds channel bytes that have arrived and that no read has taken.
buffer: [buffer_bytes]u8,
len: usize,
at: usize,

/// Holds one control line while it is read.
line_storage: [protocol.max_line_bytes]u8,

/// Holds the last warning or fatal message. **The peer's own text.**
message_storage: [max_message_bytes]u8,
message_len: usize,

/// How many bytes of the file in play are still to come.
remaining: u64,
/// Whether a file is open, so a read out of order is a fault and not a
/// silent zero.
in_file: bool,

counters: Counters,

/// How much of the channel this stages at a time.
///
/// 8 KiB. It is a staging buffer and not a bound on anything: the channel
/// holds its own window and this only decides how many bytes one
/// `Channel.read` may bring back.
const buffer_bytes: usize = 8 * 1024;

/// Starts a dialogue over `channel`.
///
/// Initializes `s` in place, because the name a caller reads points into
/// this value.
///
/// **This writes nothing.** `beginDownload` or `beginUpload` does that.
pub fn init(s: *Session, channel: *zurl_ssh.Channel) void {
    s.* = .{
        .channel = channel,
        .buffer = undefined,
        .len = 0,
        .at = 0,
        .line_storage = undefined,
        .message_storage = undefined,
        .message_len = 0,
        .remaining = 0,
        .in_file = false,
        .counters = .{},
    };
}

/// Writes over every buffer that held file bytes or the peer's words.
///
/// **The staging buffer holds the file in the clear**, and so do the line
/// buffer and the message buffer. A caller runs this when the transfer is
/// over, whichever way it ended.
pub fn wipe(s: *Session) void {
    std.crypto.secureZero(u8, &s.buffer);
    std.crypto.secureZero(u8, &s.line_storage);
    std.crypto.secureZero(u8, &s.message_storage);
    s.len = 0;
    s.at = 0;
    s.message_len = 0;
}

/// The last warning or fatal message the peer wrote, or an empty slice.
///
/// **This is the peer's own text and nothing here made it safe to print.**
pub fn lastMessage(s: *const Session) []const u8 {
    return s.message_storage[0..s.message_len];
}

/// Tells the server this side is ready to read.
///
/// A remote `scp -pf` writes nothing until this byte arrives.
pub fn beginDownload(s: *Session) Error!void {
    return s.sendAck();
}

/// Reads control lines until a `C` line arrives, and answers each one.
///
/// Returns null when the server closed the channel with no file, which is
/// what a remote `scp` that found nothing to send does after its message.
///
/// **Every field of the answer is the server's**, and each one is bounded
/// by `protocol` before it gets here. See this module's own comment.
pub fn nextFile(s: *Session) Error!?File {
    if (s.in_file) return error.SessionStateInvalid;

    var lines: usize = 0;
    while (lines < max_control_lines) : (lines += 1) {
        const raw = (try s.readLine()) orelse return null;
        s.counters.control_lines += 1;

        // A `\x01` or a `\x02` is a message and not a control line, and it
        // is read first because its text would parse as nothing else.
        if (raw.len != 0 and (raw[0] == protocol.warning or raw[0] == protocol.fatal)) {
            s.takeMessage(raw[1..]);
            if (raw[0] == protocol.fatal) return error.RemoteFault;
            // **A warning ends the transfer here too.** A remote `scp`
            // writes `\x01` for a file it could not open, and a build that
            // carried on would report an empty file for it. The counter
            // keeps the two apart for a reader.
            s.counters.warnings += 1;
            return error.RemoteFault;
        }

        const parsed = try protocol.parseLine(raw);
        switch (parsed) {
            .time => {
                s.counters.time_lines += 1;
                try s.sendAck();
            },
            .file => |file| {
                try s.sendAck();
                s.remaining = file.size;
                s.in_file = true;
                return .{ .mode = file.mode, .size = file.size, .name = file.name };
            },
            .directory, .end_directory => return error.DirectoryUnsupported,
        }
    }
    return error.ControlLineFlood;
}

/// Fills `out` with the bytes of the file in play.
///
/// Zero says the file is whole. **It never returns one byte past the size
/// the `C` line named**, whatever the server writes after it: those bytes
/// are the status byte and whatever comes next, and `endFile` reads them.
pub fn readBody(s: *Session, out: []u8) Error!usize {
    if (!s.in_file) return error.SessionStateInvalid;
    if (s.remaining == 0) return 0;

    const want: usize = @intCast(@min(@as(u64, out.len), s.remaining));
    const taken = try s.readSome(out[0..want]);
    if (taken == 0) return error.PartialFile;
    s.remaining -= taken;
    return taken;
}

/// Reads the status byte behind the file and answers it.
///
/// **A remote `scp` reports a read it could not finish here.** A build that
/// stopped at the last body byte would call a truncated file whole.
pub fn endFile(s: *Session) Error!void {
    if (!s.in_file) return error.SessionStateInvalid;
    if (s.remaining != 0) return error.PartialFile;
    s.in_file = false;
    try s.readStatus();
    return s.sendAck();
}

/// Waits for the `\0` a remote `scp -t` writes when it is ready.
pub fn beginUpload(s: *Session) Error!void {
    return s.readStatus();
}

/// Writes the `C` line for one file and waits for the answer.
///
/// `name` is a basename. See `protocol.writeFileLine`.
pub fn sendFileLine(s: *Session, mode: u16, size: u64, name: []const u8) Error!void {
    if (s.in_file) return error.SessionStateInvalid;
    const line = protocol.writeFileLine(&s.line_storage, mode, size, name) catch |err|
        switch (err) {
            // The buffer is `protocol.max_line_bytes` and the name is
            // bounded well under it, so this is unreachable by
            // construction. It is still an error rather than an assert,
            // because a caller outside this package sets the name.
            error.NoSpaceLeft => return error.NameInvalid,
            else => |rest| return rest,
        };
    try s.channel.write(line);
    try s.readStatus();
    s.remaining = size;
    s.in_file = true;
}

/// Writes body bytes for the file in play.
///
/// **It refuses one byte past the size the `C` line named.** A server that
/// was told 14 bytes reads exactly 14, and the fifteenth would be read as
/// the status byte and then as the next control line.
pub fn writeBody(s: *Session, bytes: []const u8) Error!void {
    if (!s.in_file) return error.SessionStateInvalid;
    if (bytes.len > s.remaining) return error.SessionStateInvalid;
    try s.channel.write(bytes);
    s.remaining -= bytes.len;
}

/// Writes the status byte behind the file and waits for the answer.
pub fn finishFile(s: *Session) Error!void {
    if (!s.in_file) return error.SessionStateInvalid;
    if (s.remaining != 0) return error.PartialFile;
    s.in_file = false;
    try s.sendAck();
    return s.readStatus();
}

/// Writes one `\0`.
fn sendAck(s: *Session) Error!void {
    return s.channel.write(&[_]u8{protocol.ack});
}

/// Reads one status byte and turns a message into a fault.
fn readStatus(s: *Session) Error!void {
    var one: [1]u8 = undefined;
    if (try s.readSome(&one) == 0) return error.PartialFile;
    switch (one[0]) {
        protocol.ack => return,
        protocol.warning, protocol.fatal => {
            const raw = (try s.readLine()) orelse {
                s.message_len = 0;
                return error.RemoteFault;
            };
            s.takeMessage(raw);
            return error.RemoteFault;
        },
        else => return error.StatusUnknown,
    }
}

/// Reads one line, with the newline cut off.
///
/// Null says the channel ended with nothing on it, which is a clean end and
/// not a fault. A line past `protocol.max_line_bytes` is
/// `error.LineTooLong`, and a channel that ends in the middle of a line is
/// `error.PartialFile`.
fn readLine(s: *Session) Error!?[]const u8 {
    var at: usize = 0;
    while (true) {
        if (s.at == s.len) {
            try s.fill();
            if (s.at == s.len) {
                // The channel ended. A line that had started is a line the
                // server never finished.
                if (at != 0) return error.PartialFile;
                return null;
            }
        }
        const byte = s.buffer[s.at];
        s.at += 1;
        if (byte == '\n') return s.line_storage[0..at];
        if (at == s.line_storage.len) return error.LineTooLong;
        s.line_storage[at] = byte;
        at += 1;
    }
}

/// Fills `out` with up to `out.len` bytes, and returns how many.
///
/// Zero says the channel ended.
fn readSome(s: *Session, out: []u8) Error!usize {
    if (out.len == 0) return 0;
    if (s.at == s.len) {
        try s.fill();
        if (s.at == s.len) return 0;
    }
    const take = @min(out.len, s.len - s.at);
    @memcpy(out[0..take], s.buffer[s.at..][0..take]);
    s.at += take;
    return take;
}

/// Reads one round of channel bytes into the staging buffer.
fn fill(s: *Session) Error!void {
    s.at = 0;
    s.len = try s.channel.read(&s.buffer);
}

/// Keeps a bounded copy of a message the peer wrote.
fn takeMessage(s: *Session, text: []const u8) void {
    const take = @min(text.len, s.message_storage.len);
    @memcpy(s.message_storage[0..take], text[0..take]);
    s.message_len = take;
}

const testing = std.testing;

test "the bounds this file keeps are the ones its comment names" {
    try testing.expectEqual(@as(usize, 256), max_message_bytes);
    try testing.expectEqual(@as(usize, 8), max_control_lines);
    // The staging buffer is not a bound on a line: a line longer than the
    // staging buffer still reads, because `readLine` fills again.
    try testing.expect(buffer_bytes > protocol.max_line_bytes);
}

test "the error set names the remote fault apart from the channel faults" {
    // A remote `scp` that wrote `\x02 No such file` is not an SSH channel
    // that broke, and a caller maps the two onto different exit codes.
    const set = @typeInfo(Error).error_set.?;
    var found_remote = false;
    for (set) |member| {
        if (std.mem.eql(u8, member.name, "RemoteFault")) found_remote = true;
    }
    try testing.expect(found_remote);
}

test "the command builder this session runs beside is the only one" {
    // `command.build` is what fills the `exec` request, and this session
    // never builds a command of its own. The reference keeps the two files
    // in one place for a reader.
    var storage: [command.max_command_bytes]u8 = undefined;
    try testing.expectEqualStrings(
        "scp -pf '/a'",
        try command.build(&storage, .download, "/a"),
    );
}
