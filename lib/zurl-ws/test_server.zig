//! A loopback RFC 6455 server for the tests of this package.
//!
//! This is a test fixture, not a product. It answers one connection and
//! then closes. **It validates nothing about the client**, and that is on
//! purpose: a test that pins the octets a client wrote has to see those
//! octets as they arrived, and a test that proves a client refuses a bad
//! answer needs a server that will write one.
//!
//! **No test in this package reaches the real network.** Every one that
//! needs a peer starts one of these on 127.0.0.1 with a port the operating
//! system assigns.
//!
//! **This fixture speaks no TLS**, so it serves `ws` and never `wss`. A
//! TLS session needs a certificate and a key, which this repository has no
//! fixture for. The `wss` tests therefore check the options a session
//! opens with, at `Fetcher.tlsOptions`, which is the one function that
//! decides them.
//!
//! The script says what the server writes. `Script.accept` is what makes
//! the wrong-accept test possible: it puts any value at all in the
//! `Sec-WebSocket-Accept` line, and a client that does not check the value
//! upgrades to it.

const std = @import("std");
const zurl_net = @import("zurl-net");
const testing = std.testing;

const frame = @import("frame.zig");
const handshake = @import("handshake.zig");

pub const Server = @This();

/// How many octets of the client's request head this fixture keeps.
pub const capture_bytes = 4096;

/// How many client frames this fixture records.
pub const max_client_frames = 8;

/// How many octets of client frame payload this fixture keeps in total.
pub const payload_capture_bytes = 4096;

/// How long one read of a client frame waits with no octet arriving. A
/// client that writes nothing must not hold the fixture task forever.
const read_stall: std.Io.Timeout = .{
    .duration = .{ .raw = .fromSeconds(10), .clock = .awake },
};

/// What one run of the fixture does.
pub const Script = struct {
    /// The status line, with no line ending.
    status_line: []const u8 = "HTTP/1.1 101 Switching Protocols",
    /// Whether to write the `Upgrade:` and `Connection:` lines.
    write_upgrade_headers: bool = true,
    /// What goes in the `Sec-WebSocket-Accept` line.
    ///
    /// `.correct` computes the value RFC 6455 section 4.2.2 asks for from
    /// the key the client sent. `.text` writes whatever it holds, and
    /// `.none` writes no line at all.
    accept: union(enum) {
        correct,
        text: []const u8,
        none,
    } = .correct,
    /// Extra head lines, each already ending in CRLF.
    extra_headers: []const u8 = "",
    /// The octets to write after the head. A test builds the frames.
    frames: []const u8 = "",
    /// How many frames to read back from the client before closing.
    expect_client_frames: usize = 0,
};

server: std.Io.net.Server,
task: std.Io.Future(void),
script: Script,
/// The request head the client wrote.
capture_storage: [capture_bytes]u8,
capture_len: usize,
/// The opcode of each client frame, in the order they arrived.
client_opcodes: [max_client_frames]u8,
/// Whether each client frame was masked. **A client must mask every
/// frame**, so a test reads this and expects true for every one.
client_masked: [max_client_frames]bool,
/// The mask key of each client frame, so a test can prove two frames did
/// not share one.
client_mask_keys: [max_client_frames][frame.mask_key_bytes]u8,
/// Where each client payload starts in `client_payload_storage`, and how
/// long it is.
client_payload_at: [max_client_frames]usize,
client_payload_len: [max_client_frames]usize,
client_payload_storage: [payload_capture_bytes]u8,
client_payload_used: usize,
/// How many client frames were read. Read through `clientFrames`.
client_frame_count: std.atomic.Value(usize),
/// How many connections the server accepted.
accept_count: std.atomic.Value(usize),
/// Set after the task has filled the capture, so a reader never sees a
/// half-written record.
captured: std.atomic.Value(bool),
/// Set after the task has finished reading client frames.
finished: std.atomic.Value(bool),

/// Starts listening on loopback and starts a task that runs `script`
/// against one connection.
///
/// Initializes `s` in place, rather than returning a `Server` by value, so
/// the task can hold `&s.server` for its whole life.
///
/// Returns `error.SkipZigTest` in a build with no concurrency at all. The
/// server and its client cannot both make progress on one task.
///
/// `s` and every slice in `script` must outlive the server.
pub fn start(s: *Server, script: Script) !void {
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    s.server = try address.listen(testing.io, .{ .reuse_address = true });
    errdefer s.server.deinit(testing.io);

    s.script = script;
    s.capture_len = 0;
    s.client_payload_used = 0;
    s.client_frame_count = .init(0);
    s.accept_count = .init(0);
    s.captured = .init(false);
    s.finished = .init(false);

    s.task = testing.io.concurrent(run, .{s}) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
}

/// The request head the client wrote, or an empty slice when the server
/// has not read one yet.
pub fn received(s: *const Server) []const u8 {
    if (!s.captured.load(.acquire)) return "";
    return s.capture_storage[0..s.capture_len];
}

/// How many frames the client wrote.
pub fn clientFrames(s: *const Server) usize {
    return s.client_frame_count.load(.acquire);
}

/// The opcode of client frame `index`.
pub fn clientOpcode(s: *const Server, index: usize) frame.Opcode {
    std.debug.assert(index < s.clientFrames());
    return @enumFromInt(@as(u4, @truncate(s.client_opcodes[index])));
}

/// Whether client frame `index` was masked.
pub fn clientMasked(s: *const Server, index: usize) bool {
    std.debug.assert(index < s.clientFrames());
    return s.client_masked[index];
}

/// The mask key of client frame `index`.
pub fn clientMaskKey(s: *const Server, index: usize) [frame.mask_key_bytes]u8 {
    std.debug.assert(index < s.clientFrames());
    return s.client_mask_keys[index];
}

/// The unmasked payload of client frame `index`.
pub fn clientPayload(s: *const Server, index: usize) []const u8 {
    std.debug.assert(index < s.clientFrames());
    return s.client_payload_storage[s.client_payload_at[index]..][0..s.client_payload_len[index]];
}

/// How many connections the client opened on this server.
pub fn connections(s: *const Server) usize {
    return s.accept_count.load(.acquire);
}

/// Waits until the server task has read every frame its script asked for.
///
/// **A test that reads `clientFrames` must call this first.** The client
/// returns as soon as it has written its last frame, and the server task
/// is a separate task that still has to read it. Without this wait, a test
/// asserts against a count that is still being filled in, which is a test
/// that passes or fails on the scheduler.
///
/// The wait is bounded. A task that never finishes leaves the count where
/// it was, and the test then fails on the count rather than hang.
pub fn awaitDone(s: *const Server) void {
    const step: std.Io.Timeout = .{
        .duration = .{ .raw = .fromMilliseconds(1), .clock = .awake },
    };
    var steps: usize = 0;
    while (!s.finished.load(.acquire) and steps < 5000) : (steps += 1) {
        step.sleep(testing.io) catch return;
    }
}

/// The port the operating system assigned.
pub fn port(s: *const Server) u16 {
    return s.server.socket.address.getPort();
}

/// Stops the server task and releases the listening socket. Every test
/// that calls `start` must call this, normally through `defer`.
///
/// The task is canceled, not joined. A test that opens no connection
/// leaves `run` inside `accept`, where a plain join waits forever.
pub fn stop(s: *Server) void {
    s.task.cancel(testing.io);
    s.server.deinit(testing.io);
}

fn run(s: *Server) void {
    const stream = s.server.accept(testing.io) catch return;
    defer stream.close(testing.io);
    s.accept_count.store(s.accept_count.load(.monotonic) + 1, .release);

    var read_buffer: [8192]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    var write_buffer: [8192]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);

    readHead(s, &reader.interface);
    s.captured.store(true, .release);

    writeHead(s, &writer.interface) catch return;
    writer.interface.writeAll(s.script.frames) catch return;
    writer.interface.flush() catch return;

    readClientFrames(s, &reader.interface);

    // **The write side closes first, and the read side stays open.** A
    // client answers a ping and a close as it reads, so it may still have
    // a frame in flight when this fixture has said everything it has to
    // say. A fixture that closed both sides here would send a reset, and
    // the client would report a read fault for a session that worked.
    stream.shutdown(testing.io, .send) catch {};
    drain(&reader.interface);

    s.finished.store(true, .release);
}

/// Reads and drops whatever the client still had to write, up to the end
/// of the stream. See `run` for why the fixture must not close on unread
/// octets.
fn drain(reader: *std.Io.Reader) void {
    while (true) {
        zurl_net.bounded.waitForBytes(reader, testing.io, read_stall) catch return;
        const held = reader.buffered().len;
        if (held == 0) return;
        reader.toss(held);
    }
}

/// Reads the request head into the capture, up to and including the empty
/// line that ends it.
fn readHead(s: *Server, reader: *std.Io.Reader) void {
    while (true) {
        const line = zurl_net.bounded.readLine(
            reader,
            testing.io,
            s.capture_storage[s.capture_len..],
            read_stall,
        ) catch return;
        // `readLine` gives the text with the ending off, so the length on
        // the wire is two more for the CRLF the fixture pins.
        const consumed = line.len + 2;
        // Put the ending back, so a test can pin the whole head.
        if (s.capture_len + consumed <= s.capture_storage.len) {
            s.capture_storage[s.capture_len + line.len] = '\r';
            s.capture_storage[s.capture_len + line.len + 1] = '\n';
            s.capture_len += consumed;
        }
        if (line.len == 0) return;
    }
}

/// The `Sec-WebSocket-Key` value the client sent, or an empty slice when
/// it sent none.
fn capturedKey(s: *const Server) []const u8 {
    const head = s.capture_storage[0..s.capture_len];
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "sec-websocket-key")) continue;
        return std.mem.trim(u8, line[colon + 1 ..], " \t");
    }
    return "";
}

fn writeHead(s: *Server, writer: *std.Io.Writer) !void {
    try writer.writeAll(s.script.status_line);
    try writer.writeAll("\r\n");
    if (s.script.write_upgrade_headers) {
        try writer.writeAll("Upgrade: websocket\r\nConnection: Upgrade\r\n");
    }
    switch (s.script.accept) {
        .correct => {
            var value: [handshake.accept_text_len]u8 = undefined;
            handshake.accept(capturedKey(s), &value);
            try writer.writeAll("Sec-WebSocket-Accept: ");
            try writer.writeAll(&value);
            try writer.writeAll("\r\n");
        },
        .text => |text| {
            try writer.writeAll("Sec-WebSocket-Accept: ");
            try writer.writeAll(text);
            try writer.writeAll("\r\n");
        },
        .none => {},
    }
    try writer.writeAll(s.script.extra_headers);
    try writer.writeAll("\r\n");
}

/// Reads `script.expect_client_frames` frames and records each one.
fn readClientFrames(s: *Server, reader: *std.Io.Reader) void {
    const wanted = @min(s.script.expect_client_frames, max_client_frames);
    var read: usize = 0;
    while (read < wanted) : (read += 1) {
        var prefix: [frame.prefix_bytes]u8 = undefined;
        zurl_net.bounded.readExact(reader, testing.io, &prefix, read_stall) catch return;

        var extra: [frame.max_header_bytes - frame.prefix_bytes]u8 = undefined;
        const extra_len = frame.extraBytes(prefix);
        zurl_net.bounded.readExact(reader, testing.io, extra[0..extra_len], read_stall) catch return;

        const header = frame.decode(prefix, extra[0..extra_len]) catch return;
        // The fixture keeps only what fits, so a hostile client cannot
        // make it grow.
        if (header.payload_len > payload_capture_bytes - s.client_payload_used) return;
        const length: usize = @intCast(header.payload_len);
        const at = s.client_payload_used;
        const payload = s.client_payload_storage[at..][0..length];
        zurl_net.bounded.readExact(reader, testing.io, payload, read_stall) catch return;
        if (header.masked) frame.applyMask(payload, header.mask_key, 0);

        s.client_opcodes[read] = @intFromEnum(header.opcode);
        s.client_masked[read] = header.masked;
        s.client_mask_keys[read] = header.mask_key;
        s.client_payload_at[read] = at;
        s.client_payload_len[read] = length;
        s.client_payload_used = at + length;
        s.client_frame_count.store(read + 1, .release);
    }
}

/// Writes an unmasked server frame into `out`, the way a conforming server
/// writes one, and returns the part of `out` that holds it.
///
/// Exported because every test in this package builds its own script, and
/// a second copy of the frame writer in each of them would drift from
/// `frame.encode`.
pub fn serverFrame(
    out: []u8,
    opcode: frame.Opcode,
    payload: []const u8,
    fin: bool,
) []u8 {
    var header_storage: [frame.max_header_bytes]u8 = undefined;
    const header = frame.encode(&header_storage, .{
        .fin = fin,
        .opcode = opcode,
        .masked = false,
        .payload_len = payload.len,
    });
    @memcpy(out[0..header.len], header);
    @memcpy(out[header.len..][0..payload.len], payload);
    return out[0 .. header.len + payload.len];
}

test "the fixture answers a handshake and records the head the client wrote" {
    var server: Server = undefined;
    var frames: [64]u8 = undefined;
    const written = serverFrame(&frames, .close, "\x03\xe8", true);
    try server.start(.{ .frames = written, .expect_client_frames = 0 });
    defer server.stop();

    var address = try std.Io.net.IpAddress.parse("127.0.0.1", server.port());
    const stream = try address.connect(testing.io, .{ .mode = .stream });
    defer stream.close(testing.io);

    var write_buffer: [512]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);
    try writer.interface.writeAll(
        "GET /chat HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
    );
    try writer.interface.flush();

    var read_buffer: [1024]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    const answer = try reader.interface.allocRemaining(testing.allocator, .limited(2048));
    defer testing.allocator.free(answer);

    // The accept value the fixture computed is the one RFC 6455 prints for
    // that key.
    try testing.expect(std.mem.indexOf(
        u8,
        answer,
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
    ) != null);
    try testing.expect(std.mem.endsWith(u8, answer, written));
    try testing.expect(std.mem.startsWith(u8, server.received(), "GET /chat HTTP/1.1\r\n"));
}
