//! A loopback proxy for tests: an HTTP proxy, a `CONNECT` tunnel, and a
//! SOCKS server.
//!
//! This is a test fixture, not a product. It trusts what the client sends
//! and validates nothing beyond finding the end of each message. No test may
//! reach the real network, and every proxy test in this project starts one
//! of these on 127.0.0.1 with an OS-assigned port.
//!
//! **What each kind records is the point of the fixture.** A test about the
//! two credentials reads the wire on both sides: `handshake` holds what the
//! proxy saw, and `request` holds what the origin saw. The rule under test
//! is that the proxy's credential never appears in the second, and the
//! origin's credential never appears in the first.
//!
//! `.connect` is the one kind that cannot serve a whole transfer. A
//! `CONNECT` tunnel exists to carry TLS, and neither `std` nor `zurl-tls`
//! has a TLS server, so the client's handshake inside the tunnel cannot
//! finish. The fixture answers the `CONNECT`, records the first bytes that
//! arrive inside the tunnel, and lets the transfer fail at the handshake.
//! That is enough for what the tests need: the `CONNECT` head is on record,
//! and the bytes after it prove the tunnel handed straight over to the
//! origin's own handshake.

const std = @import("std");
const testing = std.testing;

/// One scripted reply: the exact bytes the origin side writes back.
pub const Response = []const u8;

/// How large the handshake capture is, in bytes. A `CONNECT` head and a
/// SOCKS handshake are both far smaller than this.
pub const handshake_bytes = 4096;

/// How large the request capture is, in bytes. A request longer than this
/// keeps its first `request_bytes` bytes.
pub const request_bytes = 8192;

/// What the proxy speaks.
pub const Kind = enum {
    /// An HTTP proxy for a cleartext origin. It reads one absolute-form
    /// request and answers it.
    http_proxy,
    /// An HTTP proxy that answers a `CONNECT`. See the file comment for
    /// why it serves no whole transfer.
    connect,
    /// A SOCKS4 server. The origin follows on the same socket.
    socks4,
    /// A SOCKS4a server, which reads a host name.
    socks4a,
    /// A SOCKS5 server. The origin follows on the same socket.
    socks5,
};

pub const Options = struct {
    kind: Kind,
    /// The reply a `.connect` proxy writes to the `CONNECT`.
    connect_reply: []const u8 = "HTTP/1.1 200 Connection established\r\n\r\n",
    /// The user name a `.socks5` proxy demands. Empty demands none, and the
    /// server then answers the greeting with method `00`.
    socks_user: []const u8 = "",
    /// The password a `.socks5` proxy demands.
    socks_password: []const u8 = "",
    /// Whether a `.socks5` proxy accepts the credential it was given. False
    /// answers the RFC 1929 exchange with a non-zero status.
    socks_grant: bool = true,
    /// The result byte a SOCKS reply carries. The default grants the
    /// request: `0x00` for SOCKS5 and `0x5a` for SOCKS4.
    socks_reply: ?u8 = null,
};

server: std.Io.net.Server,
task: std.Io.Future(void),
options: Options,
/// What the proxy itself read before the origin's own bytes: the `CONNECT`
/// head, or the SOCKS handshake.
handshake_storage: [handshake_bytes]u8,
handshake_len: std.atomic.Value(usize),
/// What arrived after the proxy handed over: the origin's request for a
/// SOCKS or an HTTP proxy, and the first bytes inside the tunnel for a
/// `.connect` one.
request_storage: [request_bytes]u8,
request_len: std.atomic.Value(usize),
/// How much of `request_storage` the head fills, the blank line included.
/// Zero for a `.connect` fixture, which never sees a cleartext head.
request_head_len: std.atomic.Value(usize),
/// The origin the SOCKS request named, as text: an address for an address
/// request, and the name itself for a name request.
target_storage: [256]u8,
target_len: std.atomic.Value(usize),
/// The port the SOCKS request named.
target_port: std.atomic.Value(u16),

pub const ProxyTestServer = @This();

/// Starts listening on loopback and starts a task that serves one client.
///
/// Initializes `self` in place, so the task can hold `&self.server` for its
/// whole life.
///
/// Returns `error.SkipZigTest` in a build with no concurrency, exactly as
/// `test_server.TestServer` does: the fixture and its client cannot both
/// make progress on one task.
///
/// `self` and `script` must outlive the server.
pub fn start(self: *ProxyTestServer, options: Options, script: []const Response) !void {
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    self.server = try address.listen(testing.io, .{ .reuse_address = true });
    errdefer self.server.deinit(testing.io);

    self.options = options;
    self.handshake_len = .init(0);
    self.request_len = .init(0);
    self.request_head_len = .init(0);
    self.target_len = .init(0);
    self.target_port = .init(0);

    self.task = testing.io.concurrent(run, .{ self, script }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
}

/// Stops the server task and releases the listening socket.
///
/// The task is canceled, not joined: a fixture whose client never connected
/// sits inside `accept`, where a join waits forever.
pub fn stop(self: *ProxyTestServer) void {
    self.task.cancel(testing.io);
    self.server.deinit(testing.io);
}

/// The OS-assigned port the proxy listens on.
pub fn port(self: *const ProxyTestServer) u16 {
    return self.server.socket.address.getPort();
}

/// What the proxy itself read, or an empty slice when it read nothing yet.
///
/// **This is the proxy's side of the wire.** A test that pins the credential
/// rule reads it and proves the origin's credential is not in it.
pub fn handshake(self: *const ProxyTestServer) []const u8 {
    return self.handshake_storage[0..self.handshake_len.load(.acquire)];
}

/// What arrived after the proxy handed over, or an empty slice when nothing
/// did.
///
/// **This is the origin's side of the wire.** A test that pins the
/// credential rule reads it and proves the proxy's credential is not in it.
pub fn request(self: *const ProxyTestServer) []const u8 {
    return self.request_storage[0..self.request_len.load(.acquire)];
}

/// The request head alone, status line through the blank line.
pub fn requestHead(self: *const ProxyTestServer) []const u8 {
    return self.request_storage[0..self.request_head_len.load(.acquire)];
}

/// The origin host the SOCKS request named.
pub fn target(self: *const ProxyTestServer) []const u8 {
    return self.target_storage[0..self.target_len.load(.acquire)];
}

/// The origin port the SOCKS request named.
pub fn targetPort(self: *const ProxyTestServer) u16 {
    return self.target_port.load(.acquire);
}

fn run(self: *ProxyTestServer, script: []const Response) void {
    const stream = self.server.accept(testing.io) catch return;
    defer stream.close(testing.io);

    var read_buffer: [8192]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    var write_buffer: [8192]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);

    switch (self.options.kind) {
        .http_proxy => self.serveOrigin(&reader, &writer, script),
        .connect => self.serveConnect(&reader, &writer),
        .socks4, .socks4a => {
            if (!self.serveSocks4(&reader, &writer)) return;
            self.serveOrigin(&reader, &writer, script);
        },
        .socks5 => {
            if (!self.serveSocks5(&reader, &writer)) return;
            self.serveOrigin(&reader, &writer, script);
        },
    }
}

/// Reads one HTTP request and writes the first scripted reply.
///
/// The head and the body both land in `request_storage`, so a test can read
/// what the origin side of the exchange saw.
fn serveOrigin(
    self: *ProxyTestServer,
    reader: *std.Io.net.Stream.Reader,
    writer: *std.Io.net.Stream.Writer,
    script: []const Response,
) void {
    var used: usize = 0;
    while (true) {
        const line = reader.interface.takeDelimiterInclusive('\n') catch return;
        appendTo(&self.request_storage, &used, line);
        // "\r\n" is two bytes and "\n" is one, so a short line here is the
        // blank line that ends the head.
        if (line.len <= 2) break;
    }
    self.request_head_len.store(used, .release);

    // The body, framed by the head that just arrived. A fixture that left
    // it on the socket would read it as the next request line.
    const head = self.request_storage[0..used];
    if (contentLength(head)) |length| {
        var left = length;
        while (left > 0) {
            const chunk = reader.interface.peekGreedy(1) catch break;
            const take = @min(chunk.len, left);
            appendTo(&self.request_storage, &used, chunk[0..take]);
            reader.interface.toss(take);
            left -= take;
        }
    }
    self.request_len.store(used, .release);

    if (script.len == 0) return;
    writer.interface.writeAll(script[0]) catch return;
    writer.interface.flush() catch return;
}

/// Reads one `CONNECT` head, answers it, and records the bytes that follow.
///
/// The bytes that follow are the origin's own handshake, and the fixture
/// cannot answer it. See the file comment.
fn serveConnect(
    self: *ProxyTestServer,
    reader: *std.Io.net.Stream.Reader,
    writer: *std.Io.net.Stream.Writer,
) void {
    var used: usize = 0;
    while (true) {
        const line = reader.interface.takeDelimiterInclusive('\n') catch return;
        appendTo(&self.handshake_storage, &used, line);
        if (line.len <= 2) break;
    }
    self.handshake_len.store(used, .release);

    writer.interface.writeAll(self.options.connect_reply) catch return;
    writer.interface.flush() catch return;

    // Whatever the client writes inside the tunnel. One read is enough: a
    // test asserts on the first bytes, which say which protocol took over.
    const inside = reader.interface.peekGreedy(1) catch return;
    var request_used: usize = 0;
    appendTo(&self.request_storage, &request_used, inside);
    self.request_len.store(request_used, .release);
}

/// Runs a SOCKS4 or SOCKS4a handshake, and answers whether it granted.
fn serveSocks4(
    self: *ProxyTestServer,
    reader: *std.Io.net.Stream.Reader,
    writer: *std.Io.net.Stream.Writer,
) bool {
    var used: usize = 0;
    var head: [8]u8 = undefined;
    reader.interface.readSliceAll(&head) catch return false;
    appendTo(&self.handshake_storage, &used, &head);
    self.target_port.store(std.mem.readInt(u16, head[2..4], .big), .release);

    // The user id, ended by a NUL.
    const user_id = reader.interface.takeDelimiterInclusive(0) catch return false;
    appendTo(&self.handshake_storage, &used, user_id);

    var target_used: usize = 0;
    if (self.options.kind == .socks4a) {
        const name = reader.interface.takeDelimiterInclusive(0) catch return false;
        appendTo(&self.handshake_storage, &used, name);
        appendTo(&self.target_storage, &target_used, name[0 .. name.len - 1]);
    } else {
        var text: [16]u8 = undefined;
        const written = std.fmt.bufPrint(&text, "{d}.{d}.{d}.{d}", .{
            head[4], head[5], head[6], head[7],
        }) catch return false;
        appendTo(&self.target_storage, &target_used, written);
    }
    self.target_len.store(target_used, .release);
    self.handshake_len.store(used, .release);

    const granted = self.options.socks_reply orelse 0x5a;
    writer.interface.writeAll(&.{ 0x00, granted, 0, 0, 0, 0, 0, 0 }) catch return false;
    writer.interface.flush() catch return false;
    return granted == 0x5a;
}

/// Runs a SOCKS5 handshake, and answers whether it granted.
fn serveSocks5(
    self: *ProxyTestServer,
    reader: *std.Io.net.Stream.Reader,
    writer: *std.Io.net.Stream.Writer,
) bool {
    var used: usize = 0;
    var greeting: [2]u8 = undefined;
    reader.interface.readSliceAll(&greeting) catch return false;
    appendTo(&self.handshake_storage, &used, &greeting);
    if (greeting[0] != 0x05) return false;

    var methods: [255]u8 = undefined;
    const offered = methods[0..greeting[1]];
    reader.interface.readSliceAll(offered) catch return false;
    appendTo(&self.handshake_storage, &used, offered);

    const wants_credential = self.options.socks_user.len != 0 or
        self.options.socks_password.len != 0;
    const method: u8 = if (wants_credential) 0x02 else 0x00;
    // A fixture that named a credential and was offered none says so, the
    // way a real server does.
    if (std.mem.indexOfScalar(u8, offered, method) == null) {
        writer.interface.writeAll(&.{ 0x05, 0xff }) catch return false;
        writer.interface.flush() catch return false;
        self.handshake_len.store(used, .release);
        return false;
    }
    writer.interface.writeAll(&.{ 0x05, method }) catch return false;
    writer.interface.flush() catch return false;

    if (wants_credential) {
        var header: [2]u8 = undefined;
        reader.interface.readSliceAll(&header) catch return false;
        appendTo(&self.handshake_storage, &used, &header);
        var user: [255]u8 = undefined;
        const user_slice = user[0..header[1]];
        reader.interface.readSliceAll(user_slice) catch return false;
        appendTo(&self.handshake_storage, &used, user_slice);
        var password_len: [1]u8 = undefined;
        reader.interface.readSliceAll(&password_len) catch return false;
        appendTo(&self.handshake_storage, &used, &password_len);
        var password: [255]u8 = undefined;
        const password_slice = password[0..password_len[0]];
        reader.interface.readSliceAll(password_slice) catch return false;
        appendTo(&self.handshake_storage, &used, password_slice);

        const accepted = self.options.socks_grant and
            std.mem.eql(u8, user_slice, self.options.socks_user) and
            std.mem.eql(u8, password_slice, self.options.socks_password);
        writer.interface.writeAll(&.{ 0x01, if (accepted) 0x00 else 0x01 }) catch return false;
        writer.interface.flush() catch return false;
        self.handshake_len.store(used, .release);
        if (!accepted) return false;
    }

    var head: [4]u8 = undefined;
    reader.interface.readSliceAll(&head) catch return false;
    appendTo(&self.handshake_storage, &used, &head);

    var target_used: usize = 0;
    switch (head[3]) {
        0x01 => {
            var bytes: [4]u8 = undefined;
            reader.interface.readSliceAll(&bytes) catch return false;
            appendTo(&self.handshake_storage, &used, &bytes);
            var text: [16]u8 = undefined;
            const written = std.fmt.bufPrint(&text, "{d}.{d}.{d}.{d}", .{
                bytes[0], bytes[1], bytes[2], bytes[3],
            }) catch return false;
            appendTo(&self.target_storage, &target_used, written);
        },
        0x03 => {
            var name_len: [1]u8 = undefined;
            reader.interface.readSliceAll(&name_len) catch return false;
            appendTo(&self.handshake_storage, &used, &name_len);
            var name: [255]u8 = undefined;
            const name_slice = name[0..name_len[0]];
            reader.interface.readSliceAll(name_slice) catch return false;
            appendTo(&self.handshake_storage, &used, name_slice);
            appendTo(&self.target_storage, &target_used, name_slice);
        },
        0x04 => {
            var bytes: [16]u8 = undefined;
            reader.interface.readSliceAll(&bytes) catch return false;
            appendTo(&self.handshake_storage, &used, &bytes);
            appendTo(&self.target_storage, &target_used, "ipv6");
        },
        else => return false,
    }
    self.target_len.store(target_used, .release);

    var port_bytes: [2]u8 = undefined;
    reader.interface.readSliceAll(&port_bytes) catch return false;
    appendTo(&self.handshake_storage, &used, &port_bytes);
    self.target_port.store(std.mem.readInt(u16, &port_bytes, .big), .release);
    self.handshake_len.store(used, .release);

    const result = self.options.socks_reply orelse 0x00;
    // The bound address, which every SOCKS5 reply carries. `0.0.0.0:0` is
    // what a server that has none writes.
    writer.interface.writeAll(&.{ 0x05, result, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }) catch return false;
    writer.interface.flush() catch return false;
    return result == 0x00;
}

/// Appends `bytes` to `storage`, stopping at the end of it.
///
/// A capture that ran out of room keeps what fit. A test reads a header near
/// the front, so a lost tail costs nothing, and a fixture that wrote past
/// its buffer would be a defect in the fixture.
fn appendTo(storage: []u8, used: *usize, bytes: []const u8) void {
    const room = storage.len - used.*;
    const take = @min(room, bytes.len);
    @memcpy(storage[used.*..][0..take], bytes[0..take]);
    used.* += take;
}

/// The `content-length` a request head names, or null when it names none.
fn contentLength(head: []const u8) ?u64 {
    var lines = std.mem.splitScalar(u8, head, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "content-length")) continue;
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        return std.fmt.parseInt(u64, value, 10) catch null;
    }
    return null;
}

/// The first line of `head`, with the line ending taken off.
pub fn firstLine(head: []const u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, head, '\n') orelse head.len;
    return std.mem.trimEnd(u8, head[0..end], "\r");
}

test "the capture stops at the end of its buffer instead of writing past it" {
    var storage: [4]u8 = undefined;
    var used: usize = 0;
    appendTo(&storage, &used, "abcdef");
    try testing.expectEqual(@as(usize, 4), used);
    try testing.expectEqualStrings("abcd", storage[0..used]);

    // And a second append into a full buffer adds nothing rather than
    // wrapping.
    appendTo(&storage, &used, "gh");
    try testing.expectEqual(@as(usize, 4), used);
}

test "the fixture reads the content length a head names" {
    try testing.expectEqual(
        @as(?u64, 5),
        contentLength("POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\n"),
    );
    try testing.expectEqual(
        @as(?u64, 5),
        contentLength("POST / HTTP/1.1\r\ncontent-length:5\r\n\r\n"),
    );
    try testing.expectEqual(@as(?u64, null), contentLength("GET / HTTP/1.1\r\n\r\n"));
}

test "the first line of a head reads without its ending" {
    try testing.expectEqualStrings(
        "CONNECT example.com:443 HTTP/1.1",
        firstLine("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"),
    );
}
