//! A loopback RFC 1350 server for the tests of this package.
//!
//! This is a test fixture, not a product. It answers one read request from
//! a script and records what the client sent back. It validates nothing
//! beyond what a test needs to see.
//!
//! **No test in this package reaches the real network.** Every one that
//! needs a peer starts one of these on 127.0.0.1 with a port the operating
//! system assigns.
//!
//! **The fixture answers from a second socket**, as RFC 1350 section 4
//! requires: the request goes to the server's own port, and every datagram
//! after it comes from a port the server picked. A client that answered
//! its acknowledgements to the first port would hang here, which is the
//! point of doing it this way.
//!
//! `Script` names the shapes a test needs: a file, the size of one block,
//! a block to drop once, a block to send twice, an `err` packet instead of
//! the file, an opcode a download cannot use, a `blksize` the request
//! never offered, and a datagram from a third socket that the client must
//! ignore.

const std = @import("std");
const testing = std.testing;
const zurl_core = @import("zurl-core");

const packet = @import("packet.zig");

pub const Server = @This();

const Io = std.Io;

/// How many bytes of the read request this fixture keeps.
pub const capture_bytes = 1024;

/// How many acknowledgements this fixture records. A test reads the whole
/// list, so this bounds the transfers a test may script.
pub const max_acks = 64;

/// What the fixture answers with.
pub const Script = struct {
    /// The bytes the client should end up with.
    file: []const u8,
    /// Whether to answer the request with an `oack`. False is a server
    /// that reads no option and answers with the first block, which RFC
    /// 2347 allows.
    answer_options: bool = true,
    /// How many bytes each block carries. The fixture names this number
    /// in its `oack` and serves the file in blocks of it, so a test that
    /// drives a transfer above 512 bytes a block sets this and the
    /// client's own `block_size` to the same number.
    block_size: u16 = packet.default_block_size,
    /// A `blksize` to name in the `oack` instead of `block_size`.
    ///
    /// This is a server that answers with a size it was never offered.
    /// RFC 2348 lets a server shrink the block and never grow it, so a
    /// client must read this as a fault. The blocks the fixture sends
    /// still carry `block_size` bytes, because the client refuses the
    /// `oack` before it asks for one.
    announce_block_size: ?u16 = null,
    /// A block to leave unsent the first time it is due. The client must
    /// ask for it again.
    drop_block: ?u16 = null,
    /// A block to send twice. The client must acknowledge it twice and
    /// keep one copy.
    duplicate_block: ?u16 = null,
    /// An `err` packet to answer the request with, instead of the file.
    refuse: ?struct { code: u16, message: []const u8 } = null,
    /// An opcode to answer the request with, instead of the file. Used for
    /// a packet a download has no use for.
    send_opcode: ?u16 = null,
    /// Whether to write one `data` packet from a third socket, which is a
    /// peer this transfer never spoke to. The client must drop it.
    inject_foreign_data: bool = false,
    /// Whether to write an `oack` and a `data` packet from another address
    /// **before** this fixture answers the request at all.
    ///
    /// This is the open half of the transfer identifier rule. The client
    /// has no peer yet, so nothing it holds says who may answer. Only the
    /// address the url resolved to says it. The sender uses 127.0.0.2, so
    /// it is a different address on the same loopback interface and no
    /// test reaches the network.
    inject_foreign_first: bool = false,
    /// Whether to answer the request and then send nothing more. This is
    /// a peer that was there and then stopped, which a client must tell
    /// apart from a peer that was never there.
    stall_after_options: bool = false,
};

socket: Io.net.Socket,
task: Io.Future(void),
/// The read request the client wrote.
request_storage: [capture_bytes]u8,
request_len: usize,
/// Set after the task has filled `request_storage`.
request_captured: std.atomic.Value(bool),
/// The block number of each acknowledgement the client wrote, in order.
ack_storage: [max_acks]u16,
ack_count: std.atomic.Value(usize),
/// How many datagrams reached the third socket. A client that answered a
/// peer it never spoke to drives this above zero.
foreign_ack_count: std.atomic.Value(usize),
/// Whether `wait` has already taken the task. `stop` must not cancel a
/// future that was already awaited.
awaited: bool,

/// Starts listening on loopback and starts a task that answers one read
/// request from `script`.
///
/// Initializes `s` in place, rather than returning a `Server` by value, so
/// the task can hold `&s.socket` for its whole life.
///
/// Returns `error.SkipZigTest` in a build with no concurrency at all. The
/// server and its client cannot both make progress on one task.
///
/// `s` and `script` must outlive the server.
pub fn start(s: *Server, script: Script) !void {
    var address = try Io.net.IpAddress.parse("127.0.0.1", 0);
    s.socket = try address.bind(testing.io, .{ .mode = .dgram });
    errdefer s.socket.close(testing.io);

    s.request_len = 0;
    s.request_captured = .init(false);
    s.ack_count = .init(0);
    s.foreign_ack_count = .init(0);
    s.awaited = false;

    s.task = testing.io.concurrent(run, .{ s, script }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
}

/// The read request the client wrote, or an empty slice when the server
/// read none.
pub fn request(s: *const Server) []const u8 {
    if (!s.request_captured.load(.acquire)) return "";
    return s.request_storage[0..s.request_len];
}

/// The block number of each acknowledgement the client wrote, in order.
pub fn acks(s: *const Server) []const u16 {
    return s.ack_storage[0..s.ack_count.load(.acquire)];
}

/// How many datagrams the client wrote to the third socket. A client that
/// keeps the RFC 1350 transfer id rule leaves this at zero.
pub fn foreignAcks(s: *const Server) usize {
    return s.foreign_ack_count.load(.acquire);
}

/// Waits for the server task to finish, so every acknowledgement it read
/// is recorded before a test reads the list.
///
/// **Call this before `acks` on a transfer that ran to its end.** The
/// client returns as soon as it has written its last acknowledgement, and
/// the server has not always read that one by then. Without this wait the
/// list is a race, and a test that asserts on it fails on a loaded machine
/// and passes on an idle one.
///
/// Safe only for a script the client ran to its end. A test whose transfer
/// failed leaves the task waiting for a datagram that never comes, and
/// must read `acks` without this. Such a test reads a list the client
/// finished writing before it gave up, so there is nothing in flight.
///
/// `stop` is still needed afterwards. This waits for the task and releases
/// nothing.
pub fn wait(s: *Server) void {
    if (s.awaited) return;
    s.awaited = true;
    s.task.await(testing.io);
}

/// The port the operating system assigned to the request socket.
pub fn port(s: *const Server) u16 {
    return s.socket.address.getPort();
}

/// Stops the server task and releases the socket. Every test that calls
/// `start` must call this, normally through `defer`.
///
/// The task is canceled, not joined. A test whose client never sends
/// leaves `run` inside `receive`, where a plain join waits forever.
pub fn stop(s: *Server) void {
    if (!s.awaited) {
        s.awaited = true;
        s.task.cancel(testing.io);
    }
    s.socket.close(testing.io);
}

/// How long the fixture waits for one datagram from the client. Well past
/// the retransmission a test scripts, and short enough that a test which
/// goes wrong ends instead of hanging the suite.
const receive_wait: Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } };

fn run(s: *Server, script: Script) void {
    var buffer: [packet.max_datagram_bytes]u8 = undefined;

    const first = s.socket.receive(testing.io, &buffer) catch return;
    const n = @min(s.request_storage.len, first.data.len);
    @memcpy(s.request_storage[0..n], first.data[0..n]);
    s.request_len = n;
    s.request_captured.store(true, .release);
    var client = first.from;

    // RFC 1350 section 4: every datagram after the request comes from a
    // port the server picked, and not from the port the request went to.
    var transfer_address = Io.net.IpAddress.parse("127.0.0.1", 0) catch return;
    const transfer = transfer_address.bind(testing.io, .{ .mode = .dgram }) catch return;
    defer transfer.close(testing.io);

    // A sender at another address, answering before the server does. The
    // client must drop both datagrams and wait for the real answer.
    var early: ?Io.net.Socket = null;
    defer if (early) |socket| socket.close(testing.io);
    if (script.inject_foreign_first) {
        var early_address = Io.net.IpAddress.parse("127.0.0.2", 0) catch return;
        const socket = early_address.bind(testing.io, .{ .mode = .dgram }) catch return;
        early = socket;

        var out: [64]u8 = undefined;
        var w: Io.Writer = .fixed(&out);
        w.writeInt(u16, @intFromEnum(packet.Opcode.oack), .big) catch return;
        w.print("blksize\x00{d}\x00tsize\x00{d}\x00", .{
            packet.default_block_size,
            "INTRUDER".len,
        }) catch return;
        socket.send(testing.io, &client, w.buffered()) catch return;

        var block_out: [16]u8 = undefined;
        std.mem.writeInt(u16, block_out[0..2], @intFromEnum(packet.Opcode.data), .big);
        std.mem.writeInt(u16, block_out[2..4], 1, .big);
        @memcpy(block_out[4..12], "INTRUDER");
        socket.send(testing.io, &client, block_out[0..12]) catch return;

        // Anything the client writes back to this address is a client that
        // took the first sender on the wire as its peer. The wait is short,
        // because the answer is a local datagram and it goes out at once.
        var junk: [64]u8 = undefined;
        const answered: Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake } };
        if (socket.receiveTimeout(testing.io, &junk, answered)) |_| {
            s.foreign_ack_count.store(s.foreign_ack_count.load(.monotonic) + 1, .release);
        } else |_| {}
    }

    if (script.refuse) |refusal| {
        var out: [256]u8 = undefined;
        var w: Io.Writer = .fixed(&out);
        w.writeInt(u16, @intFromEnum(packet.Opcode.err), .big) catch return;
        w.writeInt(u16, refusal.code, .big) catch return;
        w.writeAll(refusal.message) catch return;
        w.writeByte(0) catch return;
        transfer.send(testing.io, &client, w.buffered()) catch return;
        return;
    }

    if (script.send_opcode) |opcode| {
        var out: [4]u8 = undefined;
        std.mem.writeInt(u16, out[0..2], opcode, .big);
        std.mem.writeInt(u16, out[2..4], 1, .big);
        transfer.send(testing.io, &client, &out) catch return;
        return;
    }

    if (script.answer_options) {
        var out: [64]u8 = undefined;
        var w: Io.Writer = .fixed(&out);
        w.writeInt(u16, @intFromEnum(packet.Opcode.oack), .big) catch return;
        w.print("blksize\x00{d}\x00tsize\x00{d}\x00", .{
            script.announce_block_size orelse script.block_size,
            script.file.len,
        }) catch return;
        transfer.send(testing.io, &client, w.buffered()) catch return;
        if (!s.takeAck(transfer, &buffer, 0)) return;
    }

    // A peer that answered and then stopped. Every acknowledgement the
    // client writes after this is read and thrown away, so the client
    // waits for a block that never comes.
    if (script.stall_after_options) return;

    if (script.inject_foreign_data) {
        // A third socket, which this transfer never spoke to. Its
        // datagram must reach the client and be dropped.
        var foreign_address = Io.net.IpAddress.parse("127.0.0.1", 0) catch return;
        const foreign = foreign_address.bind(testing.io, .{ .mode = .dgram }) catch return;
        defer foreign.close(testing.io);

        var out: [16]u8 = undefined;
        std.mem.writeInt(u16, out[0..2], @intFromEnum(packet.Opcode.data), .big);
        std.mem.writeInt(u16, out[2..4], 1, .big);
        @memcpy(out[4..12], "INTRUDER");
        foreign.send(testing.io, &client, out[0..12]) catch return;

        // Anything the client writes back to this socket is a client that
        // answered a peer it never spoke to.
        var junk: [64]u8 = undefined;
        const answered: Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake } };
        if (foreign.receiveTimeout(testing.io, &junk, answered)) |_| {
            s.foreign_ack_count.store(s.foreign_ack_count.load(.monotonic) + 1, .release);
        } else |_| {}
    }

    var block: u16 = 1;
    var dropped_once = false;
    var at: usize = 0;
    while (true) {
        const take = @min(script.block_size, script.file.len - at);
        const bytes = script.file[at..][0..take];

        if (script.drop_block == block and !dropped_once) {
            // Leave the block unsent once. The client waits, writes its
            // last acknowledgement again, and that is what arrives here.
            dropped_once = true;
            if (!s.takeAck(transfer, &buffer, block - 1)) return;
        }

        var out: [packet.max_datagram_bytes]u8 = undefined;
        std.mem.writeInt(u16, out[0..2], @intFromEnum(packet.Opcode.data), .big);
        std.mem.writeInt(u16, out[2..4], block, .big);
        @memcpy(out[4..][0..take], bytes);
        const datagram = out[0 .. 4 + take];

        transfer.send(testing.io, &client, datagram) catch return;
        if (!s.takeAck(transfer, &buffer, block)) return;

        if (script.duplicate_block == block) {
            transfer.send(testing.io, &client, datagram) catch return;
            if (!s.takeAck(transfer, &buffer, block)) return;
        }

        if (take < script.block_size) return;
        at += take;
        block += 1;
    }
}

/// Waits for one acknowledgement, records its block number, and reports
/// whether it names `expected`.
///
/// An acknowledgement of another block is recorded too, because a test
/// that reads the list must see every one the client wrote.
fn takeAck(s: *Server, transfer: Io.net.Socket, buffer: []u8, expected: u16) bool {
    const message = transfer.receiveTimeout(testing.io, buffer, receive_wait) catch return false;
    if (message.data.len < 4) return false;
    const opcode = std.mem.readInt(u16, message.data[0..2], .big);
    const block = std.mem.readInt(u16, message.data[2..4], .big);

    const at = s.ack_count.load(.monotonic);
    if (at < s.ack_storage.len) {
        s.ack_storage[at] = block;
        s.ack_count.store(at + 1, .release);
    }
    return opcode == @intFromEnum(packet.Opcode.ack) and block == expected;
}

test "the fixture serves one file and records every acknowledgement" {
    var server: Server = undefined;
    try server.start(.{ .file = "hello fixture" });
    defer server.stop();

    var fetcher = @import("Fetcher.zig").init(testing.allocator, testing.io);
    defer fetcher.deinit();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "tftp://127.0.0.1:{d}/f.txt", .{server.port()});

    var schemes: zurl_core.url.Schemes = .empty;
    try schemes.add(.{ .name = "tftp", .default_port = 69 });
    const url = try zurl_core.url.parseWith(text, &schemes);

    const body = try fetcher.open(url, .{
        .block_timeout = .{ .duration = .{ .raw = .fromMilliseconds(200), .clock = .awake } },
        .max_retries = 1,
    }, null);

    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("hello fixture", contents);
    server.wait();
    try testing.expectEqualSlices(u16, &.{ 0, 1 }, server.acks());
    try testing.expect(server.request().len > 0);
}
