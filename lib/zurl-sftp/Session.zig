//! The SFTP subsystem over one SSH channel.
//!
//! `zurl_ssh.Channel` carries bytes. This value turns them into packets
//! and back, and it is the only thing between the two.
//!
//! **A channel is a byte stream and SFTP is a packet protocol**, so one
//! `SSH_MSG_CHANNEL_DATA` is not one SFTP packet. A packet can be split
//! across two of them and two packets can arrive in one, so this value
//! frames on the four byte length and never on a channel message
//! boundary. A build that assumed one for the other would work against a
//! server on a fast local socket and fail against the same server over a
//! long link, which is why a fixture cannot prove this and a real
//! `sftp-server` can.
//!
//! **One request is in flight at a time.** OpenSSH's own client pipelines
//! several reads to fill a long link, and this one does not: a reply is
//! matched against the request id and a reply carrying any other id is
//! `error.RequestIdMismatch` rather than a packet applied to the wrong
//! request. The cost is throughput on a link with a large delay, and the
//! gain is that there is no queue to get out of order.
//!
//! **Every length here is the server's.** The packet length decides how
//! many bytes this process then waits for, so it is checked against
//! `Options.max_packet_bytes` before one byte of the body is read.

const Session = @This();

const std = @import("std");
const zurl_ssh = @import("zurl-ssh");

const protocol = @import("protocol.zig");

/// The largest request this build builds.
///
/// A `SSH_FXP_WRITE` is the longest: the head, the handle, the offset, and
/// `protocol.max_write_bytes` of data.
pub const max_request_bytes: usize =
    4 + 1 + 4 + 4 + protocol.max_handle_bytes + 8 + 4 + protocol.max_write_bytes;

/// What one session needs.
pub const Options = struct {
    /// The largest packet this build takes. See
    /// `protocol.max_packet_bytes`.
    max_packet_bytes: u32 = protocol.max_packet_bytes,
};

/// Why a session stopped.
pub const Error =
    zurl_ssh.Channel.Error ||
    protocol.ParseError ||
    protocol.BuildError ||
    error{
        /// The process has no room for the packet buffers.
        OutOfMemory,
        /// The server answered `SSH_FXP_INIT` with a version this build
        /// does not speak.
        VersionUnsupported,
        /// The server's first packet was not `SSH_FXP_VERSION`.
        VersionExpected,
        /// A packet claims a length past `Options.max_packet_bytes`, or a
        /// length of zero, which names no type at all.
        PacketLengthInvalid,
        /// The channel ended in the middle of a packet.
        PacketTruncated,
        /// A reply carries a request id that answers nothing this build
        /// sent.
        RequestIdMismatch,
        /// The server answered with a type that answers nothing this
        /// build asked for.
        UnexpectedReply,
        /// The server reported a fault. `lastStatus` says which.
        ServerFault,
        /// A path or a handle is longer than this build sends.
        PathTooLong,
        /// The server answered a read with more bytes than it was asked
        /// for.
        ReadOverrun,
        /// The server answered a read with a `SSH_FXP_DATA` that carries no
        /// bytes.
        ///
        /// **Only `SSH_FX_EOF` ends a file.** A client that read an empty
        /// data reply as the end would write a piece of the file and report
        /// success, and the server would choose where the file stopped.
        ReadEmpty,
    };

/// What the session did that no caller asked for.
pub const Counters = struct {
    requests: u64 = 0,
    replies: u64 = 0,
    /// How many `SSH_FXP_DATA` replies came back shorter than the read
    /// asked for. The draft allows it and this build takes it, and the
    /// count says how often it happened.
    short_reads: u64 = 0,
    /// How many `SSH_FXP_NAME` replies named no entry at all. Each one
    /// ends a directory walk. See `nameBatch`.
    empty_batches: u64 = 0,
};

/// What the last `SSH_FXP_STATUS` said.
pub const LastStatus = struct {
    status: protocol.Status,
    /// **Untrusted text**, cut to fit.
    message: []const u8,
};

channel: *zurl_ssh.Channel,
gpa: std.mem.Allocator,
options: Options,

/// Holds one request as it is built. Owned.
request_storage: []u8,
/// Holds the bytes read from the channel that no packet has taken yet.
/// Owned, and `4 + max_packet_bytes` long.
frame_storage: []u8,
/// How many bytes of `frame_storage` hold data.
frame_len: usize,
/// Where the next packet starts inside it.
frame_at: usize,

/// The id of the next request.
next_id: u32,
/// What the server answered `SSH_FXP_INIT` with.
server_version: u32,

status_code: ?protocol.Status,
status_storage: [protocol.max_message_bytes]u8,
status_len: usize,

counters: Counters,

/// Starts a session over `channel`.
///
/// Initializes `s` in place, because the packets a caller reads point into
/// this value.
///
/// This writes nothing. `start` does that.
pub fn init(
    s: *Session,
    gpa: std.mem.Allocator,
    channel: *zurl_ssh.Channel,
    options: Options,
) error{ OutOfMemory, PacketLengthInvalid }!void {
    if (options.max_packet_bytes < 1024 or options.max_packet_bytes > protocol.max_packet_bytes) {
        return error.PacketLengthInvalid;
    }
    const request_storage = gpa.alloc(u8, max_request_bytes) catch return error.OutOfMemory;
    errdefer gpa.free(request_storage);
    const frame_storage = gpa.alloc(u8, 4 + @as(usize, options.max_packet_bytes)) catch
        return error.OutOfMemory;

    s.* = .{
        .channel = channel,
        .gpa = gpa,
        .options = options,
        .request_storage = request_storage,
        .frame_storage = frame_storage,
        .frame_len = 0,
        .frame_at = 0,
        .next_id = 1,
        .server_version = 0,
        .status_code = null,
        .status_storage = undefined,
        .status_len = 0,
        .counters = .{},
    };
}

/// Frees the two buffers.
///
/// **Both hold file bytes in the clear**, and so does the status message.
/// `request_storage` holds the last block of an upload and `frame_storage`
/// holds the last packet of a download, so each one is wiped before the
/// memory goes back to the allocator or to the next transfer.
pub fn deinit(s: *Session) void {
    std.crypto.secureZero(u8, s.request_storage);
    std.crypto.secureZero(u8, s.frame_storage);
    std.crypto.secureZero(u8, &s.status_storage);
    s.gpa.free(s.request_storage);
    s.gpa.free(s.frame_storage);
    s.* = undefined;
}

/// What the last `SSH_FXP_STATUS` said, or null when none has arrived.
pub fn lastStatus(s: *const Session) ?LastStatus {
    const status = s.status_code orelse return null;
    return .{ .status = status, .message = s.status_storage[0..s.status_len] };
}

/// The version the server agreed to.
pub fn version(s: *const Session) u32 {
    return s.server_version;
}

/// Sends `SSH_FXP_INIT` and reads the answer.
///
/// **A version that is not 3 stops the session.** The draft says the
/// server answers with the lower of the two, so a server that answers 2
/// speaks a protocol this build does not, and one that answers 4 answered
/// something it was never offered.
pub fn start(s: *Session) Error!void {
    const request = try protocol.writeInit(s.request_storage);
    try s.channel.write(request);
    s.counters.requests += 1;

    const body = try s.readPacket();
    s.counters.replies += 1;
    const kind = protocol.typeOf(body) orelse return error.VersionExpected;
    if (kind != .version) return error.VersionExpected;
    const answer = try protocol.parseVersion(body);
    if (answer.version != protocol.version) return error.VersionUnsupported;
    s.server_version = answer.version;
}

/// A file handle the server gave out.
///
/// **It is opaque.** The draft says a client must not read it, so this
/// keeps the bytes and nothing else.
pub const Handle = struct {
    storage: [protocol.max_handle_bytes]u8 = undefined,
    len: usize = 0,

    pub fn bytes(h: *const Handle) []const u8 {
        return h.storage[0..h.len];
    }
};

/// Opens a file and returns its handle.
pub fn open(s: *Session, path: []const u8, pflags: u32) Error!Handle {
    if (path.len > protocol.max_path_bytes) return error.PathTooLong;
    const id = s.takeId();
    const request = try protocol.writeOpen(s.request_storage, id, path, pflags);
    const body = try s.exchange(request, id);

    const kind = protocol.typeOf(body) orelse return error.UnexpectedReply;
    switch (kind) {
        .handle => {
            const reply = try protocol.parseHandle(body);
            if (reply.handle.len > protocol.max_handle_bytes) return error.PathTooLong;
            var out: Handle = .{};
            @memcpy(out.storage[0..reply.handle.len], reply.handle);
            out.len = reply.handle.len;
            return out;
        },
        .status => return s.recordStatusFault(body),
        else => return error.UnexpectedReply,
    }
}

/// Closes a handle.
///
/// **A close that the server refuses is still a fault.** The draft says a
/// server may report a write it deferred here, so a client that dropped
/// the answer would call a failed upload a good one.
pub fn close(s: *Session, handle: Handle) Error!void {
    const id = s.takeId();
    const request = try protocol.writeClose(s.request_storage, id, handle.bytes());
    const body = try s.exchange(request, id);
    return s.expectOk(body);
}

/// Reads a file's attributes, following a symbolic link.
pub fn stat(s: *Session, path: []const u8) Error!protocol.Attributes {
    if (path.len > protocol.max_path_bytes) return error.PathTooLong;
    const id = s.takeId();
    const request = try protocol.writeStat(s.request_storage, id, path);
    const body = try s.exchange(request, id);

    const kind = protocol.typeOf(body) orelse return error.UnexpectedReply;
    switch (kind) {
        .attrs => return (try protocol.parseAttrs(body)).attributes,
        .status => return s.recordStatusFault(body),
        else => return error.UnexpectedReply,
    }
}

/// Reads an open file's attributes.
pub fn fstat(s: *Session, handle: Handle) Error!protocol.Attributes {
    const id = s.takeId();
    const request = try protocol.writeFstat(s.request_storage, id, handle.bytes());
    const body = try s.exchange(request, id);

    const kind = protocol.typeOf(body) orelse return error.UnexpectedReply;
    switch (kind) {
        .attrs => return (try protocol.parseAttrs(body)).attributes,
        .status => return s.recordStatusFault(body),
        else => return error.UnexpectedReply,
    }
}

/// Fills `out` from `offset` and returns how many bytes it wrote.
///
/// Zero says the file has ended, which the server reports as
/// `SSH_FX_EOF`.
///
/// **A short answer is not an end.** Section 6.4 of the draft lets a
/// server return fewer bytes than were asked for, and only `SSH_FX_EOF`
/// says there are no more. A client that took a short read for an end
/// would truncate a file and report success.
///
/// **An empty answer is not an end either**, and it is the same fault one
/// step further on. A `SSH_FXP_DATA` of zero bytes is `error.ReadEmpty`,
/// so the one way this function returns zero is the `SSH_FX_EOF` the
/// server has to send.
pub fn read(s: *Session, handle: Handle, offset: u64, out: []u8) Error!usize {
    const want: u32 = @intCast(@min(out.len, protocol.max_read_bytes));
    if (want == 0) return 0;

    const id = s.takeId();
    const request = try protocol.writeRead(s.request_storage, id, handle.bytes(), offset, want);
    const body = try s.exchange(request, id);

    const kind = protocol.typeOf(body) orelse return error.UnexpectedReply;
    switch (kind) {
        .data => {
            const reply = try protocol.parseData(body);
            // The server chose this length. A reply longer than the read
            // asked for is a server writing past a buffer this side
            // sized, and it is refused rather than truncated.
            if (reply.bytes.len > want) return error.ReadOverrun;
            // **Zero bytes is not the end of the file.** The caller stops
            // on a zero, so a data reply that carried nothing would cut
            // the download where the server chose and report success. See
            // the doc comment above.
            if (reply.bytes.len == 0) return error.ReadEmpty;
            if (reply.bytes.len < want) s.counters.short_reads += 1;
            @memcpy(out[0..reply.bytes.len], reply.bytes);
            return reply.bytes.len;
        },
        .status => {
            const reply = try protocol.parseStatus(body);
            s.recordStatus(reply);
            if (reply.status == .eof) return 0;
            return error.ServerFault;
        },
        else => return error.UnexpectedReply,
    }
}

/// Writes `data` at `offset`.
pub fn write(s: *Session, handle: Handle, offset: u64, data: []const u8) Error!void {
    if (data.len > protocol.max_write_bytes) return error.PathTooLong;
    const id = s.takeId();
    const request = try protocol.writeWrite(s.request_storage, id, handle.bytes(), offset, data);
    const body = try s.exchange(request, id);
    return s.expectOk(body);
}

/// Opens a directory and returns its handle.
pub fn openDirectory(s: *Session, path: []const u8) Error!Handle {
    if (path.len > protocol.max_path_bytes) return error.PathTooLong;
    const id = s.takeId();
    const request = try protocol.writeOpendir(s.request_storage, id, path);
    const body = try s.exchange(request, id);

    const kind = protocol.typeOf(body) orelse return error.UnexpectedReply;
    switch (kind) {
        .handle => {
            const reply = try protocol.parseHandle(body);
            if (reply.handle.len > protocol.max_handle_bytes) return error.PathTooLong;
            var out: Handle = .{};
            @memcpy(out.storage[0..reply.handle.len], reply.handle);
            out.len = reply.handle.len;
            return out;
        },
        .status => return s.recordStatusFault(body),
        else => return error.UnexpectedReply,
    }
}

/// Reads one batch of directory entries, or null at the end.
///
/// **The names point into this value's own buffer** and are good only
/// until the next call. **They are the server's text**: see
/// `protocol`'s module comment.
///
/// **A batch of no names ends the walk.** See `nameBatch`.
pub fn readDirectory(s: *Session, handle: Handle) Error!?protocol.NameReply {
    const id = s.takeId();
    const request = try protocol.writeReaddir(s.request_storage, id, handle.bytes());
    const body = try s.exchange(request, id);

    const kind = protocol.typeOf(body) orelse return error.UnexpectedReply;
    switch (kind) {
        .name => {
            const batch = try nameBatch(body);
            if (batch == null) s.counters.empty_batches += 1;
            return batch;
        },
        .status => {
            const reply = try protocol.parseStatus(body);
            s.recordStatus(reply);
            if (reply.status == .eof) return null;
            return error.ServerFault;
        },
        else => return error.UnexpectedReply,
    }
}

/// Reads one `SSH_FXP_NAME` batch, or null when it names nothing.
///
/// **A batch of no names is the end of a directory.** Section 6.7 of the
/// draft has a server answer `SSH_FXP_READDIR` with one name or more, or
/// with `SSH_FX_EOF`. A caller reads batches until one of them ends the
/// walk, and it counts names rather than round trips, so a batch that
/// carried no name and did not end the walk would make the caller ask
/// again for as long as a server keeps answering that way.
fn nameBatch(body: []const u8) protocol.ParseError!?protocol.NameReply {
    const reply = try protocol.parseName(body);
    if (reply.count == 0) return null;
    return reply;
}

/// Turns a relative path into the absolute one the server would use.
///
/// The answer points into this value's own buffer and is good until the
/// next call.
pub fn realPath(s: *Session, path: []const u8) Error![]const u8 {
    if (path.len > protocol.max_path_bytes) return error.PathTooLong;
    const id = s.takeId();
    const request = try protocol.writeRealpath(s.request_storage, id, path);
    const body = try s.exchange(request, id);

    const kind = protocol.typeOf(body) orelse return error.UnexpectedReply;
    switch (kind) {
        .name => {
            var reply = try protocol.parseName(body);
            // Section 6.9 says the answer carries exactly one name.
            if (reply.count != 1) return error.UnexpectedReply;
            const first = (try reply.iterator.next()) orelse return error.UnexpectedReply;
            return first.filename;
        },
        .status => return s.recordStatusFault(body),
        else => return error.UnexpectedReply,
    }
}

fn takeId(s: *Session) u32 {
    const id = s.next_id;
    // The id wraps, which is what the draft expects of a long session.
    // Only one request is in flight, so a wrap can never collide with a
    // reply this build is still waiting for.
    s.next_id +%= 1;
    return id;
}

/// Sends one request and reads the reply that answers it.
fn exchange(s: *Session, request: []const u8, id: u32) Error![]const u8 {
    try s.channel.write(request);
    s.counters.requests += 1;

    const body = try s.readPacket();
    s.counters.replies += 1;
    const answered = protocol.requestIdOf(body) orelse return error.UnexpectedReply;
    // **One request is in flight, so the next packet is its reply.** A
    // reply carrying any other id answers nothing this build sent, and a
    // build that skipped past it and read another would let a server steer
    // a later reply onto an earlier request. There is no queue here to get
    // out of order, and that is the whole point of the rule.
    if (answered != id) return error.RequestIdMismatch;
    return body;
}

fn expectOk(s: *Session, body: []const u8) Error!void {
    const kind = protocol.typeOf(body) orelse return error.UnexpectedReply;
    if (kind != .status) return error.UnexpectedReply;
    const reply = try protocol.parseStatus(body);
    s.recordStatus(reply);
    if (reply.status != .ok) return error.ServerFault;
}

fn recordStatusFault(s: *Session, body: []const u8) Error {
    const reply = protocol.parseStatus(body) catch |err| return err;
    s.recordStatus(reply);
    return error.ServerFault;
}

fn recordStatus(s: *Session, reply: protocol.StatusReply) void {
    s.status_code = reply.status;
    const cut = @min(reply.message.len, protocol.max_message_bytes);
    @memcpy(s.status_storage[0..cut], reply.message[0..cut]);
    s.status_len = cut;
}

/// Reads one whole SFTP packet and returns its body, with the length taken
/// off and the type byte first.
///
/// The result points into `frame_storage` and is good until the next call.
fn readPacket(s: *Session) Error![]const u8 {
    try s.fill(4);
    const declared = std.mem.readInt(u32, s.frame_storage[s.frame_at..][0..4], .big);
    // **The length is checked before one byte of the body is waited
    // for.** A server that claims four thousand million bytes costs this
    // process one comparison and no memory.
    if (declared < protocol.min_packet_bytes or declared > s.options.max_packet_bytes) {
        return error.PacketLengthInvalid;
    }
    const whole = 4 + @as(usize, declared);
    try s.fill(whole);
    const body = s.frame_storage[s.frame_at + 4 ..][0..declared];
    s.frame_at += whole;
    return body;
}

/// Reads from the channel until `frame_storage` holds `want` bytes from
/// `frame_at`.
fn fill(s: *Session, want: usize) Error!void {
    while (s.frame_len - s.frame_at < want) {
        // Compact first, so that a packet that started near the end of
        // the buffer still has room to finish in it.
        if (s.frame_at != 0) {
            std.mem.copyForwards(
                u8,
                s.frame_storage[0..],
                s.frame_storage[s.frame_at..s.frame_len],
            );
            s.frame_len -= s.frame_at;
            s.frame_at = 0;
        }
        if (want > s.frame_storage.len) return error.PacketLengthInvalid;
        const taken = try s.channel.read(s.frame_storage[s.frame_len..]);
        // **The channel ended in the middle of a packet.** A server that
        // stops there said nothing about the request, and a client that
        // treated it as an end would report a truncated file as whole.
        if (taken == 0) return error.PacketTruncated;
        s.frame_len += taken;
    }
}

const testing = std.testing;

test "a name reply of no entries ends the walk, and one entry does not" {
    // **A count of zero moves nothing.** A caller bounds a listing by the
    // entries it reads, and a batch with no entry leaves that count where
    // it was, so a walk that asked again would ask for as long as a server
    // kept answering this way. Section 6.7 has a server answer with one
    // name or more, or with `SSH_FX_EOF`.
    const empty = [_]u8{
        104, // SSH_FXP_NAME
        0, 0, 0, 7, // the request id
        0, 0, 0, 0, // the count
    };
    try testing.expectEqual(@as(?protocol.NameReply, null), try nameBatch(&empty));

    const one = [_]u8{
        104, // SSH_FXP_NAME
        0, 0, 0, 7, // the request id
        0, 0, 0, 1, // the count
        0, 0, 0, 5, 'a', '.', 't', 'x', 't', // the file name
        0, 0, 0, 2, 'l', 's', // the longname
        0, 0, 0, 0, // no attribute flags
    };
    var batch = (try nameBatch(&one)) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u32, 1), batch.count);
    const name = (try batch.iterator.next()).?;
    try testing.expectEqualStrings("a.txt", name.filename);
}

test "the request buffer holds the longest request this build builds" {
    var storage: [max_request_bytes]u8 = undefined;
    var handle: [protocol.max_handle_bytes]u8 = @splat('h');
    var data: [protocol.max_write_bytes]u8 = @splat('d');
    _ = try protocol.writeWrite(&storage, 1, &handle, std.math.maxInt(u64), &data);
    _ = try protocol.writeRead(&storage, 1, &handle, std.math.maxInt(u64), protocol.max_read_bytes);
    var path: [protocol.max_path_bytes]u8 = @splat('p');
    _ = try protocol.writeOpen(&storage, 1, &path, protocol.open_read);
}

test "a session refuses a packet bound it could not frame" {
    var channel: zurl_ssh.Channel = undefined;
    var s: Session = undefined;
    try testing.expectError(error.PacketLengthInvalid, s.init(
        testing.allocator,
        &channel,
        .{ .max_packet_bytes = 16 },
    ));
    try testing.expectError(error.PacketLengthInvalid, s.init(
        testing.allocator,
        &channel,
        .{ .max_packet_bytes = protocol.max_packet_bytes + 1 },
    ));
}

test "the request id goes up by one and wraps without colliding" {
    var channel: zurl_ssh.Channel = undefined;
    var s: Session = undefined;
    try s.init(testing.allocator, &channel, .{});
    defer s.deinit();

    try testing.expectEqual(@as(u32, 1), s.takeId());
    try testing.expectEqual(@as(u32, 2), s.takeId());
    s.next_id = std.math.maxInt(u32);
    try testing.expectEqual(std.math.maxInt(u32), s.takeId());
    // One request is in flight, so a wrap can never meet a reply this
    // build is still waiting for.
    try testing.expectEqual(@as(u32, 0), s.takeId());
}

test "a status is kept with its untrusted message cut to fit" {
    var channel: zurl_ssh.Channel = undefined;
    var s: Session = undefined;
    try s.init(testing.allocator, &channel, .{});
    defer s.deinit();

    try testing.expectEqual(@as(?LastStatus, null), s.lastStatus());
    s.recordStatus(.{
        .id = 1,
        .status = .permission_denied,
        .message = "no",
        .language = "",
    });
    const held = s.lastStatus().?;
    try testing.expectEqual(protocol.Status.permission_denied, held.status);
    try testing.expectEqualStrings("no", held.message);

    var long: [protocol.max_message_bytes * 2]u8 = @splat('x');
    s.recordStatus(.{ .id = 2, .status = .failure, .message = &long, .language = "" });
    try testing.expectEqual(protocol.max_message_bytes, s.lastStatus().?.message.len);
}
