//! A loopback HTTP server for tests.
//!
//! This is a test fixture, not a product. It trusts its own script and does
//! nothing to validate what the client sent beyond finding the end of the
//! request head. No test may reach the real network; every HTTP test in
//! this project should start one of these on 127.0.0.1 with an OS-assigned
//! port instead.
//!
//! `TestServer.start` takes a script of raw responses, served in order on
//! a concurrent task. A caller that wants a redirect followed by a final
//! body passes two scripted responses; a caller that wants one exchange
//! passes one.
//!
//! `start` gives every response a connection of its own, which is what
//! this fixture always did. `startWith` takes
//! `Options.responses_per_connection`, so a test of connection reuse can
//! let one accepted connection serve more than one request. `accepts`
//! reports how many connections the client opened, which is the number a
//! reuse test asserts on.
//!
//! The script and the test do not have to agree on the number of
//! connections. `stop` cancels the task, so a script with one entry more
//! than the test uses ends the test instead of hanging the suite.

const std = @import("std");
const testing = std.testing;

/// One scripted reply: the exact bytes written back to the client, status
/// line through body. The caller is responsible for well-formed HTTP when
/// the test wants a well-formed response, and for whatever shape it wants
/// otherwise.
pub const Response = []const u8;

/// How many request heads a server keeps. One per scripted response is
/// enough: the server stops accepting once the script runs out.
pub const capture_max = 4;

/// How large one captured request, head and body together, may be. A
/// request longer than this keeps its first `capture_bytes` bytes. A test
/// that reads a captured head asserts on a header near the front, so a
/// lost tail costs nothing.
pub const capture_bytes = 8192;

server: std.Io.net.Server,
task: std.Io.Future(void),
/// The request that asked for each scripted response, in order: the head,
/// then the body right behind it. Written by the server task, read by the
/// test through `requestHead` and `requestBody`.
capture_storage: [capture_max][capture_bytes]u8,
/// How much of each slot the head fills, the blank line included.
capture_head_lens: [capture_max]usize,
/// How much of each slot the head and the body fill together.
capture_lens: [capture_max]usize,
/// How many request heads `capture_storage` holds. The server task
/// publishes this with a release store after it fills a slot, and
/// `requestHead` reads it with an acquire load, so a test that reads a
/// head the server already answered sees the whole slot.
capture_count: std.atomic.Value(usize),
/// How many connections the server has accepted. Published with a release
/// store, read through `accepts`.
///
/// This is the number a connection reuse test asserts on. A client that
/// keeps a connection sends its second request on the first one, so the
/// count stays at one; a client that opens a connection for each request
/// drives it up by one for each.
accept_count: std.atomic.Value(usize),
/// How many scripted responses one accepted connection serves before the
/// server closes it. See `Options.responses_per_connection`.
responses_per_connection: ?usize,

pub const TestServer = @This();

/// What `startWith` takes beyond the script.
pub const Options = struct {
    /// Which loopback address to listen on. See `startOn` for why a test
    /// may want a second one.
    host: []const u8 = "127.0.0.1",
    /// How many scripted responses one accepted connection serves before
    /// the server closes it.
    ///
    /// One is the default, and it is what this fixture always did: every
    /// response gets a connection of its own. A larger number lets a
    /// client send a second request on a connection it kept, which is
    /// what a connection pool does. `null` puts no bound on it, so one
    /// connection serves requests until the client stops sending them or
    /// the script runs out.
    ///
    /// The server closes with no warning to the client. A response that
    /// must tell the client to expect a close carries its own
    /// `connection: close` header, and this fixture never adds one. So a
    /// bound of one, over responses that name no such header, is a server
    /// that drops a connection the client believed it could reuse.
    responses_per_connection: ?usize = 1,
};

/// Starts listening on loopback and starts a task that serves `script` in
/// order, one entry per accepted connection, then stops accepting.
///
/// Initializes `self` in place, rather than returning a `TestServer` by
/// value, so the server task can hold `&self.server` for its whole life.
/// A `TestServer` built on the stack and then returned by value would leave
/// that task holding the address of a frame that no longer exists.
///
/// Returns `error.SkipZigTest` in a build with no concurrency at all, which
/// a target with no thread support still gives. The server and its client
/// cannot both make progress on one task, so a test that needs this
/// fixture cannot run there. `zurl-stream`'s `Throttle` degrades the same
/// way.
///
/// A threaded build that cannot get a concurrent task propagates
/// `error.ConcurrencyUnavailable` instead of skipping. That would be a
/// real regression, not an expected limit, and every test in this
/// package that uses this fixture would go quiet if it were hidden here.
///
/// `self` and `script` must outlive the server.
pub fn start(self: *TestServer, script: []const Response) !void {
    return self.startWith(script, .{});
}

/// The same as `start`, on a chosen loopback address.
///
/// A test that needs two different origins can ask for two different host
/// names here, and not only two ports. A rule that compares host names,
/// which is what `std.http.Client.Request.redirect` does, reads
/// `127.0.0.1:1` and `127.0.0.1:2` as one origin, so a port alone proves
/// nothing about such a rule. Every address in 127.0.0.0/8 is loopback, so
/// `127.0.0.2` gives a second host name that reaches this machine and
/// never the network.
///
/// `host` may be an IPv6 address. `::1` is loopback too, so a test of the
/// IPv6 path stays offline like every other test here. A url that names
/// this server then needs the brackets back: the text is
/// `http://[::1]:PORT/` and never `http://::1:PORT/`.
///
/// A machine with the IPv6 stack turned off cannot bind `::1`. The bind
/// reports that, and the caller decides what to do about it, because a
/// missing address family is a fact about the machine and never a fault
/// this fixture found.
pub fn startOn(self: *TestServer, host: []const u8, script: []const Response) !void {
    return self.startWith(script, .{ .host = host });
}

/// The same as `start`, with every choice this fixture offers spelled out.
///
/// `options.responses_per_connection` is the one a connection reuse test
/// needs. Everything else behaves exactly as `start` does.
pub fn startWith(self: *TestServer, script: []const Response, options: Options) !void {
    std.debug.assert(script.len <= capture_max);

    var address = try std.Io.net.IpAddress.parse(options.host, 0);
    self.server = try address.listen(testing.io, .{ .reuse_address = true });
    errdefer self.server.deinit(testing.io);

    self.capture_head_lens = @splat(0);
    self.capture_lens = @splat(0);
    self.capture_count = .init(0);
    self.accept_count = .init(0);
    self.responses_per_connection = options.responses_per_connection;

    self.task = testing.io.concurrent(run, .{ self, script }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
}

/// The request head the client sent on connection `index`, status line
/// through the blank line, or null when the server has not answered that
/// many connections yet.
///
/// Safe to call while the server task still runs. The task fills a slot
/// before it writes the reply for that connection, so a test that already
/// has its response also has the head that asked for it.
pub fn requestHead(self: *const TestServer, index: usize) ?[]const u8 {
    if (index >= self.capture_count.load(.acquire)) return null;
    return self.capture_storage[index][0..self.capture_head_lens[index]];
}

/// The request body the client sent on connection `index`, or null when
/// the server has not answered that many requests yet.
///
/// Empty for a request that carried no body. A chunked body reads exactly
/// as it arrived, the size lines and the terminator included, because this
/// fixture is a record of the wire and not a parser of it: a test of the
/// chunked framing has to see the framing.
pub fn requestBody(self: *const TestServer, index: usize) ?[]const u8 {
    if (index >= self.capture_count.load(.acquire)) return null;
    const slot = &self.capture_storage[index];
    return slot[self.capture_head_lens[index]..self.capture_lens[index]];
}

/// How many connections the client opened on this server.
///
/// Read it after the transfers under test have finished. A client that
/// reuses one connection for two requests leaves this at one; a client
/// that opens one for each request leaves it at two. That difference is
/// the whole subject of a connection reuse test, and no header on the
/// wire shows it.
pub fn accepts(self: *const TestServer) usize {
    return self.accept_count.load(.acquire);
}

/// How many `Authorization` header lines `head` holds.
///
/// RFC 7235 allows one. A second one lets a server read the first and
/// ignore what the client meant to send, so a test that pins credential
/// behaviour must count these, not merely find one.
///
/// Matches the name without regard to case, because the engine writes the
/// headers it owns in lower case and a caller writes its own in whatever
/// case it likes. It does not match `Proxy-Authorization`, which is a
/// different header with its own rule.
pub fn countAuthorizationHeaders(head: []const u8) usize {
    return countHeaders(head, "Authorization");
}

/// How many header lines in `head` carry the field name `name`.
///
/// A test that pins where a secret goes counts the lines rather than
/// searching for the value: a header the client wrote twice, and a header
/// whose value a test guessed wrong, both have to be visible.
///
/// Matches the name without regard to case, because the engine writes the
/// headers it owns in lower case and a caller writes its own in whatever
/// case it likes. The match covers the whole name, so `Authorization` does
/// not count a `Proxy-Authorization` line.
pub fn countHeaders(head: []const u8, name: []const u8) usize {
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, head, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (line.len <= name.len) continue;
        if (line[name.len] != ':') continue;
        if (!std.ascii.startsWithIgnoreCase(line, name)) continue;
        count += 1;
    }
    return count;
}

/// The OS-assigned port the server is listening on.
///
/// `getPort` and not `address.ip4.port`: an IPv6 listener holds the `ip6`
/// member, and reading the wrong member of that union is a fault of this
/// fixture, not of the test that called it.
pub fn port(self: *const TestServer) u16 {
    return self.server.socket.address.getPort();
}

/// Stops the server task and releases the listening socket. Every test that
/// calls `start` must call this, normally via `defer`.
///
/// The task is canceled, not joined. A script with more entries than the
/// test made connections leaves `run` inside `accept`, where a plain join
/// waits forever. `accept` answers the cancel with `error.Canceled`.
pub fn stop(self: *TestServer) void {
    self.task.cancel(testing.io);
    self.server.deinit(testing.io);
}

/// One zstd frame, built here rather than checked in as a binary blob.
///
/// **A test of the zstd path needs zstd octets, and nothing in this
/// project writes them.** `std.compress.zstd` ships a decoder and no
/// encoder, so a test either carries a fixture file that a reviewer has to
/// take on faith, or it builds a frame it can read. This builds one, out of
/// the two block types RFC 8878 lets a writer emit with no entropy coding
/// at all.
///
/// The frame is a `Raw` block for each entry of `literals`, then one `RLE`
/// block for each entry of `runs`, and the last block written carries the
/// last-block flag. `runs` is what a decompression bomb is made of: an
/// `RLE` block costs four octets on the wire and decodes to as many octets
/// as its length names.
///
/// The window is 256 KiB, which every decoder must carry: RFC 8878 section
/// 3.1.1.1.2 puts the ceiling for a content coding at 8 MiB, and this is
/// far under it. No content size and no checksum, both of which that
/// section makes optional.
///
/// The caller owns the octets. `block_len_max` bounds every block, because
/// a decoder may refuse a block larger than that.
pub const zstd_block_len_max: usize = 64 * 1024;

pub fn zstdFrame(
    allocator: std.mem.Allocator,
    /// One `Raw` block for each slice, written in order.
    literals: []const []const u8,
    /// One `RLE` block for each pair, written after the raw blocks. The
    /// first field is the octet, the second is how many times it repeats.
    runs: []const struct { u8, usize },
) ![]u8 {
    std.debug.assert(literals.len + runs.len > 0);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    // Magic_Number, little endian 0xFD2FB528.
    try out.appendSlice(allocator, &.{ 0x28, 0xb5, 0x2f, 0xfd });
    // Frame_Header_Descriptor: no content size, not a single segment, no
    // checksum, no dictionary. Every field of it zero.
    try out.append(allocator, 0x00);
    // Window_Descriptor: Exponent 8 in the top five bits, Mantissa 0. The
    // window is then 1 << (10 + 8), which is 256 KiB.
    try out.append(allocator, 8 << 3);

    const last_index = literals.len + runs.len - 1;
    var index: usize = 0;

    for (literals) |text| {
        std.debug.assert(text.len <= zstd_block_len_max);
        try appendZstdBlockHeader(allocator, &out, 0, text.len, index == last_index);
        try out.appendSlice(allocator, text);
        index += 1;
    }
    for (runs) |each| {
        const octet, const count = each;
        std.debug.assert(count <= zstd_block_len_max);
        try appendZstdBlockHeader(allocator, &out, 1, count, index == last_index);
        try out.append(allocator, octet);
        index += 1;
    }

    return out.toOwnedSlice(allocator);
}

/// One `Block_Header`: three octets, little endian, holding the last-block
/// flag, the block type, and the block size. RFC 8878 section 3.1.1.2.
fn appendZstdBlockHeader(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    block_type: u2,
    size: usize,
    last: bool,
) !void {
    const header: u32 = (@as(u32, @intCast(size)) << 3) |
        (@as(u32, block_type) << 1) |
        @intFromBool(last);
    try out.appendSlice(allocator, &.{
        @truncate(header),
        @truncate(header >> 8),
        @truncate(header >> 16),
    });
}

test "zstdFrame builds a frame the standard library decodes" {
    // The fixture proving itself. A builder that wrote a malformed frame
    // would make every test that uses it fail for the wrong reason.
    const gpa = testing.allocator;
    const frame = try zstdFrame(gpa, &.{ "hello, ", "world" }, &.{.{ '!', 3 }});
    defer gpa.free(frame);

    var input: std.Io.Reader = .fixed(frame);
    const window = try gpa.alloc(
        u8,
        std.compress.zstd.default_window_len + std.compress.zstd.block_size_max,
    );
    defer gpa.free(window);

    var decompress: std.compress.zstd.Decompress = .init(&input, window, .{});
    const decoded = try decompress.reader.allocRemaining(gpa, .limited(1024));
    defer gpa.free(decoded);
    try testing.expectEqualStrings("hello, world!!!", decoded);
}

test "an RLE block is tiny on the wire and large once decoded" {
    // The shape a decompression bomb is made of, stated as an assertion.
    // Four octets on the wire for 64 KiB of output.
    const gpa = testing.allocator;
    const frame = try zstdFrame(gpa, &.{}, &.{.{ 0, zstd_block_len_max }});
    defer gpa.free(frame);

    try testing.expect(frame.len < 16);

    var input: std.Io.Reader = .fixed(frame);
    const window = try gpa.alloc(
        u8,
        std.compress.zstd.default_window_len + std.compress.zstd.block_size_max,
    );
    defer gpa.free(window);

    var decompress: std.compress.zstd.Decompress = .init(&input, window, .{});
    const decoded = try decompress.reader.allocRemaining(gpa, .limited(zstd_block_len_max * 2));
    defer gpa.free(decoded);
    try testing.expectEqual(zstd_block_len_max, decoded.len);
}

/// How many refused ports one process may hold. Each one costs a file
/// descriptor until the process ends, so the count is bounded and a test
/// that asks for more gets a name for it.
pub const closed_ports_max = 64;

var closed_port_sockets: [closed_ports_max]std.Io.net.Socket = undefined;
var closed_port_count: usize = 0;

/// A port on `host` that refuses every connect for as long as the process
/// runs. `host` is a numeric address, "127.0.0.1" or "::1" among them.
///
/// **The socket stays bound, and nothing ever listens on it.** An
/// operating system refuses a connect to a bound socket with no listener
/// behind it, which is the fault a test of a failed dial wants, and it
/// lets no other socket take that port meanwhile.
///
/// A test that binds a port, reads the number, and closes the socket gets
/// the same fault only while the port stays free. Several test binaries
/// run at once under `zig build test`, and one of them can take the freed
/// port between the two steps. The test then reaches a stranger instead of
/// a refusal, and waits for an answer that stranger will never send. That
/// is a hung suite, not a failed assertion, so the port is held instead.
///
/// The socket is never closed. `closed_ports_max` bounds the cost, and the
/// test process ends soon after the last test.
///
/// Called from the test thread alone, which is where every test runs.
pub fn closedPort(host: []const u8) !u16 {
    if (closed_port_count == closed_ports_max) return error.TooManyClosedPorts;
    var address = try std.Io.net.IpAddress.parse(host, 0);
    const socket = try address.bind(testing.io, .{ .mode = .stream });
    closed_port_sockets[closed_port_count] = socket;
    closed_port_count += 1;
    return socket.address.getPort();
}

/// Whether the task that owns `reader` and `writer` has been canceled.
///
/// **A canceled task must return at once.** `std.Io` marks a thread as
/// canceled when one of its system calls answers the cancel. Every system
/// call the thread starts after that is no longer cancelable. So a task
/// that catches `error.Canceled` and then goes back to `accept` blocks
/// there for ever. `stop` blocks with it: the canceling side stops sending
/// signals when the cancel is acknowledged, and its own wait has no bound.
///
/// The cause is read from the reader and the writer, and not from the
/// error, because `std.Io.Reader` reports every failure as
/// `error.ReadFailed` and `std.Io.Writer` reports every failure as
/// `error.WriteFailed`. The name of the fault is behind those two, in
/// `err`.
///
/// Every fixture in this project that serves more than one connection must
/// call this after each swallowed I/O failure. `h2_test_server` calls it
/// too.
pub fn taskCanceled(
    reader: *const std.Io.net.Stream.Reader,
    writer: *const std.Io.net.Stream.Writer,
) bool {
    if (reader.err) |err| if (err == error.Canceled) return true;
    if (writer.err) |err| if (err == error.Canceled) return true;
    return false;
}

fn run(self: *TestServer, script: []const Response) void {
    const server = &self.server;
    // Which scripted response goes out next. It also names the capture
    // slot, so `requestHead(i)` is the head that asked for `script[i]`
    // whether the two requests shared a connection or not.
    var next: usize = 0;
    while (next < script.len) {
        const stream = server.accept(testing.io) catch return;
        defer stream.close(testing.io);
        self.accept_count.store(self.accept_count.load(.monotonic) + 1, .release);

        // One reader and one writer for the whole connection. A second
        // reader would drop whatever the first one had already buffered,
        // which on a reused connection is the front of the next request.
        var read_buffer: [4096]u8 = undefined;
        var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
        var write_buffer: [4096]u8 = undefined;
        var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);

        // How many responses this connection may still serve. The server
        // closes when the count runs out, and says nothing to the client
        // about it. See `Options.responses_per_connection`.
        var left: usize = self.responses_per_connection orelse script.len;
        while (next < script.len and left > 0) : (left -= 1) {
            // `takeDelimiterInclusive` keeps the line ending and consumes
            // it. `takeDelimiterExclusive` leaves the newline in the
            // stream, so the next call gives an empty line and this loop
            // used to stop after the request line. That cost nothing while
            // the head was thrown away, but a capture must hold the whole
            // head.
            //
            // A read that fails here is the client closing the connection
            // between requests, which is ordinary. Go back to `accept`.
            var captured: usize = 0;
            var complete = false;
            while (true) {
                const line = reader.interface.takeDelimiterInclusive('\n') catch break;
                capture(&self.capture_storage[next], &captured, line);
                // "\r\n" is 2 bytes and "\n" is 1. A header line is longer
                // than both, so a short line here is the blank line that
                // ends the head.
                if (line.len <= 2) {
                    complete = true;
                    break;
                }
            }
            if (!complete) break;
            self.capture_head_lens[next] = captured;

            // **The body, right behind the head.** A server that read the
            // head alone left the body on the socket, and the next
            // `takeDelimiterInclusive` on a reused connection then read
            // that body as the request line of the next request. So this
            // has to consume the body whether or not a test reads it back.
            //
            // The framing comes from the head the client just sent. A
            // `content-length` names a count. A `transfer-encoding:
            // chunked` frames itself and ends on a zero-size chunk. A head
            // with neither carries no body.
            const head = self.capture_storage[next][0..captured];
            if (contentLength(head)) |length| {
                var body_left = length;
                while (body_left > 0) {
                    const chunk = reader.interface.peekGreedy(1) catch break;
                    const take = @min(chunk.len, body_left);
                    capture(&self.capture_storage[next], &captured, chunk[0..take]);
                    reader.interface.toss(take);
                    body_left -= take;
                }
            } else if (isChunked(head)) {
                while (true) {
                    const size_line = reader.interface.takeDelimiterInclusive('\n') catch break;
                    capture(&self.capture_storage[next], &captured, size_line);
                    const size = std.fmt.parseInt(
                        usize,
                        std.mem.trim(u8, size_line, "\r\n"),
                        16,
                    ) catch break;
                    // The chunk data and the CRLF behind it. A zero-size
                    // chunk carries no data and ends on the CRLF of the
                    // empty trailer section.
                    var chunk_left: usize = if (size == 0) 2 else size + 2;
                    while (chunk_left > 0) {
                        const chunk = reader.interface.peekGreedy(1) catch break;
                        const take = @min(chunk.len, chunk_left);
                        capture(&self.capture_storage[next], &captured, chunk[0..take]);
                        reader.interface.toss(take);
                        chunk_left -= take;
                    }
                    if (size == 0) break;
                }
            }

            self.capture_lens[next] = captured;
            self.capture_count.store(next + 1, .release);

            writer.interface.writeAll(script[next]) catch return;
            writer.interface.flush() catch return;
            next += 1;
        }

        // Every read above swallows its failure, because a client that
        // goes away between requests is ordinary. A cancel arrives as one
        // of those failures, and it is not ordinary: `taskCanceled` says
        // so, and this task ends instead of going back to `accept`.
        if (taskCanceled(&reader, &writer)) return;
    }
}

/// Appends as much of `text` as fits past `at.*` in `slot`. A head longer
/// than the slot is truncated, not dropped: this is a record for a test to
/// read, not a value anything parses back.
/// The `content-length` `head` announces, or null when it announces none.
///
/// The value is a count of body bytes, so a value this cannot read as a
/// number is the same as no value at all: the fixture then finds no body,
/// which is what a test of a malformed request head wants to see.
fn contentLength(head: []const u8) ?usize {
    var lines = std.mem.splitScalar(u8, head, '\n');
    _ = lines.next();
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "content-length")) continue;
        return std.fmt.parseInt(usize, std.mem.trim(u8, line[colon + 1 ..], " \t"), 10) catch null;
    }
    return null;
}

/// Whether `head` frames its body with the chunked transfer coding.
fn isChunked(head: []const u8) bool {
    var lines = std.mem.splitScalar(u8, head, '\n');
    _ = lines.next();
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "transfer-encoding")) continue;
        return std.mem.indexOf(u8, line[colon + 1 ..], "chunked") != null;
    }
    return false;
}

fn capture(slot: *[capture_bytes]u8, at: *usize, text: []const u8) void {
    const n = @min(slot.len - at.*, text.len);
    @memcpy(slot[at.*..][0..n], text[0..n]);
    at.* += n;
}

test "a script of one response serves one connection and reports its port" {
    var server: TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    try testing.expect(server.port() != 0);

    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(server.port()) };
    const stream = try address.connect(testing.io, .{ .mode = .stream });
    defer stream.close(testing.io);

    var write_buffer: [256]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);
    try writer.interface.writeAll("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    try writer.interface.flush();

    var read_buffer: [256]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    const body = try reader.interface.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(body);

    try testing.expect(std.mem.endsWith(u8, body, "ok"));
}

test "the server keeps the request head the client sent" {
    // Every wire-capture test in this project reads `requestHead`. If the
    // fixture kept nothing, those tests would assert against an empty
    // string and pass for the wrong reason.
    var server: TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(0));

    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(server.port()) };
    const stream = try address.connect(testing.io, .{ .mode = .stream });
    defer stream.close(testing.io);

    var write_buffer: [256]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);
    try writer.interface.writeAll("GET /x HTTP/1.1\r\nHost: x\r\nAuthorization: Basic abc\r\n\r\n");
    try writer.interface.flush();

    var read_buffer: [256]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    const body = try reader.interface.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(body);

    const head = server.requestHead(0).?;
    try testing.expectEqualStrings("GET /x HTTP/1.1\r\nHost: x\r\nAuthorization: Basic abc\r\n\r\n", head);
    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(1));
}

test "the fixture binds ::1 and reports the port of an IPv6 listener" {
    // The IPv6 tests of this project need a peer, and no test may reach
    // the network. `::1` is loopback, so this is that peer. `port` used to
    // read `address.ip4.port` on a listener that holds the `ip6` member,
    // which is the wrong member of a union and never the port.
    var server: TestServer = undefined;
    server.startOn("::1", &.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"}) catch |err| switch (err) {
        error.AddressFamilyUnsupported, error.AddressUnavailable => return error.SkipZigTest,
        else => |e| return e,
    };
    defer server.stop();

    try testing.expect(server.port() != 0);

    const address: std.Io.net.IpAddress = .{ .ip6 = .loopback(server.port()) };
    const stream = try address.connect(testing.io, .{ .mode = .stream });
    defer stream.close(testing.io);

    var write_buffer: [256]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);
    try writer.interface.writeAll("GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n");
    try writer.interface.flush();

    var read_buffer: [256]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    const body = try reader.interface.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(body);

    try testing.expect(std.mem.endsWith(u8, body, "ok"));
    try testing.expectEqualStrings("GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n", server.requestHead(0).?);
}

test "countAuthorizationHeaders counts every case and skips proxy-authorization" {
    const head =
        "GET / HTTP/1.1\r\nhost: x\r\nauthorization: Basic a\r\n" ++
        "Proxy-Authorization: Basic b\r\nAuthorization: Digest c\r\n\r\n";
    try testing.expectEqual(@as(usize, 2), countAuthorizationHeaders(head));
    try testing.expectEqual(@as(usize, 0), countAuthorizationHeaders("GET / HTTP/1.1\r\nhost: x\r\n\r\n"));
}

test "countHeaders matches a whole field name and no longer one" {
    const head =
        "GET / HTTP/1.1\r\nhost: x\r\ncookie: a=1\r\nCookie: b=2\r\n" ++
        "Cookie-Note: not a cookie\r\nProxy-Authorization: Basic b\r\n\r\n";
    try testing.expectEqual(@as(usize, 2), countHeaders(head, "Cookie"));
    try testing.expectEqual(@as(usize, 1), countHeaders(head, "Cookie-Note"));
    try testing.expectEqual(@as(usize, 1), countHeaders(head, "proxy-authorization"));
    try testing.expectEqual(@as(usize, 0), countHeaders(head, "Authorization"));
    try testing.expectEqual(@as(usize, 0), countHeaders(head, "Set-Cookie"));
}

test "a script of two responses serves two connections in order" {
    var server: TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfirst",
    });
    defer server.stop();

    for (0..2) |i| {
        const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(server.port()) };
        const stream = try address.connect(testing.io, .{ .mode = .stream });
        defer stream.close(testing.io);

        var write_buffer: [256]u8 = undefined;
        var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);
        try writer.interface.writeAll("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        try writer.interface.flush();

        var read_buffer: [256]u8 = undefined;
        var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
        const body = try reader.interface.allocRemaining(testing.allocator, .unlimited);
        defer testing.allocator.free(body);

        if (i == 0) {
            try testing.expect(std.mem.indexOf(u8, body, "302") != null);
        } else {
            try testing.expect(std.mem.endsWith(u8, body, "first"));
        }
    }
}

test "stop returns on a script the test never used up, instead of hanging" {
    // The fixture's doc invites reuse, so a script with one entry more
    // than the test makes connections will happen again. `stop` must end
    // the task that is still inside `accept`. Before this, the suite hung
    // with no timeout and no diagnostic.
    var server: TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nunused",
    });
    defer server.stop();

    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(server.port()) };
    const stream = try address.connect(testing.io, .{ .mode = .stream });
    defer stream.close(testing.io);

    var write_buffer: [256]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);
    try writer.interface.writeAll("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    try writer.interface.flush();

    var read_buffer: [256]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    const body = try reader.interface.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(body);

    try testing.expect(std.mem.endsWith(u8, body, "ok"));
}

test "closedPort refuses a connect and keeps the port while the process runs" {
    // The two halves are one rule: a port that refuses is only useful
    // while nothing else can take it. A test that reads the number and
    // releases the socket gets the first half alone, and under a parallel
    // suite the second half is what keeps it deterministic.
    const held = try closedPort("127.0.0.1");

    var target: std.Io.net.IpAddress = .{ .ip4 = .loopback(held) };
    try testing.expectError(
        error.ConnectionRefused,
        target.connect(testing.io, .{ .mode = .stream }),
    );

    var again: std.Io.net.IpAddress = .{ .ip4 = .loopback(held) };
    try testing.expectError(
        error.AddressInUse,
        again.listen(testing.io, .{ .reuse_address = true }),
    );
}
