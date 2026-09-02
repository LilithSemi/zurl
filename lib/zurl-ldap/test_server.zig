//! A loopback RFC 4511 server for the tests of this package.
//!
//! This is a test fixture, not a product. It speaks enough of the protocol
//! to run a bind, a search, and an unbind, and it lets a test bend every
//! answer. It validates almost nothing: a test that pins the bytes a
//! request carries has to see those bytes as they arrived.
//!
//! **No test in this package reaches the real network.** Every one that
//! needs a peer starts one of these on 127.0.0.1, with a port the
//! operating system assigns.
//!
//! **This fixture writes its BER by hand.** It does not use `ber.Writer`,
//! which is the writer the client builds its requests with. A fixture
//! built out of the client's own encoder would agree with a client that
//! framed a message the same wrong way, so the two ends would pass a test
//! that a real server fails. The encoder below is forty lines and it is
//! the second opinion those tests need. `zurl-ssh`'s SFTP service records
//! the same rule.
//!
//! **This fixture speaks no TLS.** A TLS session needs a certificate and a
//! key, and this repository has no fixture for either. So an `ldaps` test
//! here proves what a session opens with, at the one function that
//! decides, and proves that a refused StartTLS sends no credential. It
//! cannot prove a live handshake, and this file says so rather than let a
//! reader think it does.
//!
//! **It keeps every request byte for byte.** A test that wants to know
//! what filter reached the wire reads `requests` and decodes it with
//! `ber.zig`. An escaping rule is worth only what the wire says.

const std = @import("std");
const testing = std.testing;

const ber = @import("ber.zig");
const message = @import("message.zig");

pub const Server = @This();

/// How many bytes of the request log this keeps.
pub const log_bytes = 32 * 1024;

/// One attribute of one entry the fixture returns.
pub const Attribute = struct {
    description: []const u8,
    values: []const []const u8 = &.{},
};

/// One entry the fixture returns.
pub const Entry = struct {
    dn: []const u8,
    attributes: []const Attribute = &.{},
};

/// What the fixture answers.
///
/// Every field has the answer a working server gives, so a test names only
/// the one it wants to bend.
pub const Script = struct {
    /// The `resultCode` of the `BindResponse`. Zero is success.
    bind_code: i32 = 0,
    /// The `diagnosticMessage` of the `BindResponse`.
    bind_diagnostic: []const u8 = "",
    /// The entries the search returns, in order.
    entries: []const Entry = &.{},
    /// The uris of one `SearchResultReference`, sent after
    /// `reference_after` entries. Empty sends none.
    references: []const []const u8 = &.{},
    /// How many entries go out before the reference.
    reference_after: usize = 0,
    /// The `resultCode` of the `SearchResultDone`. Zero is success.
    search_code: i32 = 0,
    /// The `diagnosticMessage` of the `SearchResultDone`.
    search_diagnostic: []const u8 = "",
    /// How many extra entries with one attribute of no values the search
    /// sends before the real ones. A test uses it to drive the bound on
    /// how many messages one search reads.
    flood_entries: usize = 0,
    /// The `resultCode` of the `ExtendedResponse` a StartTLS gets. Zero is
    /// success, and the fixture then says nothing more, because it speaks
    /// no TLS.
    start_tls_code: i32 = 53,
    /// Bytes the fixture writes straight after its StartTLS answer.
    ///
    /// **A test uses this to prove one rule**: a server that writes in the
    /// clear behind its answer has written bytes that no session protects,
    /// and the client must not carry them across the handshake.
    start_tls_trailer: ?[]const u8 = null,
    /// Bytes to write as soon as the connection opens, instead of any
    /// dialogue at all. The fixture then closes.
    ///
    /// This is how a test drives a hostile message: a length that claims
    /// more than the message, an indefinite length, a message that nests
    /// too deep, or an operation nothing here sends.
    raw: ?[]const u8 = null,
    /// Never send a `SearchResultDone`, and hold the connection open. A
    /// test uses it to prove that a search that never ends is bounded by
    /// something.
    omit_done: bool = false,
    /// Answer every message with the message id one higher than the one
    /// that came in.
    wrong_message_id: bool = false,
};

server: std.Io.net.Server,
task: std.Io.Future(void),
script: Script,
/// Every request the client wrote, byte for byte, one after another. Read
/// it through `requests` after `wait`.
log_storage: [log_bytes]u8,
log_len: usize,
/// Where each logged request starts, so `request` can name one.
offsets: [64]usize,
offset_count: usize,
/// Set when the task has finished writing `log_storage`.
done: std.atomic.Value(bool),
/// How many connections the fixture accepted. A test that proves a url was
/// refused before any dial asserts this is zero.
accept_count: std.atomic.Value(usize),

/// Starts listening on loopback and starts a task that runs one session.
///
/// Initializes `s` in place, so the task can hold `&s.server` for its whole
/// life.
///
/// Returns `error.SkipZigTest` in a build with no concurrency at all. The
/// server and its client cannot both make progress on one task.
///
/// `s` and every slice inside `script` must outlive the server.
pub fn start(s: *Server, script: Script) !void {
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    s.server = try address.listen(testing.io, .{ .reuse_address = true });
    errdefer s.server.deinit(testing.io);

    s.script = script;
    s.log_len = 0;
    s.offset_count = 0;
    s.done = .init(false);
    s.accept_count = .init(0);

    s.task = testing.io.concurrent(run, .{s}) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
}

/// Starts a server that accepts one connection, writes nothing at all, and
/// holds the socket open.
///
/// **This is the peer the read bound exists for.** The connect succeeds,
/// so the dial is over, and then the bind answer never arrives.
pub fn startSilent(s: *Server) !void {
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    s.server = try address.listen(testing.io, .{ .reuse_address = true });
    errdefer s.server.deinit(testing.io);

    s.script = .{};
    s.log_len = 0;
    s.offset_count = 0;
    s.done = .init(false);
    s.accept_count = .init(0);

    s.task = testing.io.concurrent(runSilent, .{s}) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
}

/// The port the operating system assigned to the listener.
pub fn port(s: *const Server) u16 {
    return s.server.socket.address.getPort();
}

/// How many connections the client opened.
pub fn connections(s: *const Server) usize {
    return s.accept_count.load(.acquire);
}

/// How many requests the client sent.
pub fn requestCount(s: *const Server) usize {
    if (!s.done.load(.acquire)) return 0;
    return s.offset_count;
}

/// The bytes of request `index`, or an empty slice.
///
/// Call `wait` first for a complete log. Without it this can read a log the
/// task has not finished writing, which is a race that passes on an idle
/// machine and fails on a loaded one.
pub fn request(s: *const Server, index: usize) []const u8 {
    if (!s.done.load(.acquire)) return "";
    if (index >= s.offset_count) return "";
    const from = s.offsets[index];
    const to = if (index + 1 < s.offset_count) s.offsets[index + 1] else s.log_len;
    return s.log_storage[from..to];
}

/// Waits for the session to finish.
pub fn wait(s: *Server) void {
    s.task.await(testing.io);
}

/// Stops the server task and releases the listening socket. Every test that
/// calls `start` must call this, normally through `defer`.
pub fn stop(s: *Server) void {
    s.task.cancel(testing.io);
    s.server.deinit(testing.io);
}

fn runSilent(s: *Server) void {
    const stream = s.server.accept(testing.io) catch return;
    defer stream.close(testing.io);
    _ = s.accept_count.fetchAdd(1, .release);
    s.done.store(true, .release);

    const hold: std.Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(60), .clock = .awake } };
    hold.sleep(testing.io) catch {};
}

fn run(s: *Server) void {
    const stream = s.server.accept(testing.io) catch return;
    defer stream.close(testing.io);
    _ = s.accept_count.fetchAdd(1, .release);

    var read_buffer: [8192]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    var write_buffer: [8192]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);

    var session: Session = .{
        .s = s,
        .reader = &reader.interface,
        .writer = &writer.interface,
    };
    session.serve() catch {};
    s.done.store(true, .release);
}

/// The state one session holds.
const Session = struct {
    s: *Server,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,

    fn serve(session: *Session) !void {
        if (session.s.script.raw) |bytes| {
            try session.writer.writeAll(bytes);
            try session.writer.flush();
            // A test that drives a hostile message wants the client to
            // read it and stop, so the socket stays open behind it rather
            // than end the read with a close the client would report
            // instead.
            const hold: std.Io.Timeout = .{
                .duration = .{ .raw = .fromSeconds(60), .clock = .awake },
            };
            hold.sleep(testing.io) catch {};
            return;
        }

        while (true) {
            var storage: [16 * 1024]u8 = undefined;
            const bytes = try session.readMessage(&storage);
            try session.s.log(bytes);

            const m = parseRequest(bytes) orelse return;
            const id = if (session.s.script.wrong_message_id) m.id + 1 else m.id;

            switch (m.op) {
                message.app_bind_request => try session.writeResult(
                    message.app_bind_response,
                    id,
                    session.s.script.bind_code,
                    session.s.script.bind_diagnostic,
                ),
                message.app_search_request => try session.writeSearch(id),
                message.app_extended_request => {
                    // **The answer and any trailer go out in one write.**
                    // A test that proves the client refuses cleartext
                    // written behind the answer needs both to reach the
                    // client together, and two flushes are two segments.
                    // `zurl-pop3`'s fixture records the same rule, and
                    // this one had the defect it warns about: the test
                    // passed on its own and failed about one run in ten
                    // beside the others.
                    var whole: Encoder = .init();
                    resultEnvelope(
                        &whole,
                        message.app_extended_response,
                        id,
                        session.s.script.start_tls_code,
                        "",
                    );
                    try session.writer.writeAll(whole.written());
                    if (session.s.script.start_tls_trailer) |text| {
                        try session.writer.writeAll(text);
                    }
                    try session.writer.flush();
                    // **This fixture speaks no TLS**, so after a positive
                    // answer it says nothing more. Reading a ClientHello
                    // as BER would answer with bytes no TLS client can
                    // read. Silence is the one answer that is the same
                    // every run, and the bound the client keeps on the
                    // handshake is what the test measures.
                    if (session.s.script.start_tls_code == 0) {
                        const hold: std.Io.Timeout = .{
                            .duration = .{ .raw = .fromSeconds(60), .clock = .awake },
                        };
                        hold.sleep(testing.io) catch {};
                        return;
                    }
                },
                // An `UnbindRequest` gets no answer at all. RFC 4511
                // section 4.3 says the server closes.
                message.app_unbind_request => return,
                else => return,
            }
        }
    }

    /// Reads one whole message into `out` and returns what it holds.
    fn readMessage(session: *Session, out: []u8) ![]const u8 {
        try session.reader.readSliceAll(out[0..2]);
        if (out[0] != 0x30) return error.NotASequence;

        var header: usize = 2;
        var body: usize = out[1];
        if (out[1] >= 0x80) {
            const count: usize = out[1] & 0x7f;
            if (count == 0 or count > 4) return error.BadLength;
            try session.reader.readSliceAll(out[2..][0..count]);
            body = 0;
            for (out[2..][0..count]) |b| body = (body << 8) | b;
            header = 2 + count;
        }
        if (header + body > out.len) return error.TooLarge;
        try session.reader.readSliceAll(out[header..][0..body]);
        return out[0 .. header + body];
    }

    /// Writes an operation holding an `LDAPResult`.
    fn writeSearch(session: *Session, id: i32) !void {
        var sent: usize = 0;
        for (0..session.s.script.flood_entries) |_| {
            try session.writeEntry(id, .{ .dn = "cn=flood", .attributes = &.{} });
        }
        for (session.s.script.entries) |e| {
            if (sent == session.s.script.reference_after and
                session.s.script.references.len != 0)
            {
                try session.writeReference(id);
            }
            try session.writeEntry(id, e);
            sent += 1;
        }
        if (sent <= session.s.script.reference_after and session.s.script.references.len != 0) {
            try session.writeReference(id);
        }
        if (session.s.script.omit_done) {
            try session.writer.flush();
            const hold: std.Io.Timeout = .{
                .duration = .{ .raw = .fromSeconds(60), .clock = .awake },
            };
            hold.sleep(testing.io) catch {};
            return;
        }
        try session.writeResult(
            message.app_search_done,
            id,
            session.s.script.search_code,
            session.s.script.search_diagnostic,
        );
    }

    fn writeResult(
        session: *Session,
        app: u5,
        id: i32,
        code: i32,
        diagnostic: []const u8,
    ) !void {
        var whole: Encoder = .init();
        resultEnvelope(&whole, app, id, code, diagnostic);
        try session.writer.writeAll(whole.written());
        try session.writer.flush();
    }

    fn writeEntry(session: *Session, id: i32, e: Entry) !void {
        var attributes: Encoder = .init();
        for (e.attributes) |a| {
            var values: Encoder = .init();
            for (a.values) |v| values.octetString(v);

            var one: Encoder = .init();
            one.octetString(a.description);
            one.element(0x31, values.written());

            attributes.element(0x30, one.written());
        }

        var op: Encoder = .init();
        op.octetString(e.dn);
        op.element(0x30, attributes.written());

        var body: Encoder = .init();
        body.integer(id);
        body.element(0x40 | 0x20 | @as(u8, message.app_search_entry), op.written());

        try session.writeEnvelope(body.written());
    }

    fn writeReference(session: *Session, id: i32) !void {
        var op: Encoder = .init();
        for (session.s.script.references) |uri| op.octetString(uri);

        var body: Encoder = .init();
        body.integer(id);
        body.element(0x40 | 0x20 | @as(u8, message.app_search_reference), op.written());

        try session.writeEnvelope(body.written());
    }

    fn writeEnvelope(session: *Session, body: []const u8) !void {
        var whole: Encoder = .init();
        whole.element(0x30, body);
        try session.writer.writeAll(whole.written());
        try session.writer.flush();
    }
};

/// Builds one whole `LDAPMessage` holding an operation with an
/// `LDAPResult` in it.
///
/// A function and not a method, because the StartTLS arm needs the bytes
/// rather than a write: it puts the answer and its trailer into one write
/// so both reach the client in one segment.
fn resultEnvelope(out: *Encoder, app: u5, id: i32, code: i32, diagnostic: []const u8) void {
    var op: Encoder = .init();
    op.enumerated(code);
    op.octetString("");
    op.octetString(diagnostic);

    var body: Encoder = .init();
    body.integer(id);
    body.element(0x40 | 0x20 | @as(u8, app), op.written());

    out.element(0x30, body.written());
}

/// The message id and the operation tag of one request.
const Request = struct { id: i32, op: u5 };

/// Reads the message id and the operation tag out of `bytes`.
///
/// This is the one place the fixture parses, and it uses `ber.zig` on
/// purpose: what it reads here is what the client wrote, so a client that
/// wrote a wrong tag would be answered wrongly and the test would say so.
fn parseRequest(bytes: []const u8) ?Request {
    var outer: ber.Cursor = .init(bytes);
    const envelope = outer.expect(ber.sequence) catch return null;
    var fields = outer.enter(envelope) catch return null;
    const id_element = fields.expect(ber.integer) catch return null;
    const id = ber.integerValue(i32, id_element) catch return null;
    const op = fields.next() catch return null;
    if (op.tag.class != .application) return null;
    return .{ .id = id, .op = op.tag.number };
}

/// A BER encoder written for this fixture alone.
///
/// **Not `ber.Writer`.** See the module doc comment: a fixture that shared
/// the client's encoder would agree with a client that framed a message the
/// same wrong way.
const Encoder = struct {
    bytes: [12 * 1024]u8,
    len: usize,

    fn init() Encoder {
        return .{ .bytes = undefined, .len = 0 };
    }

    fn written(e: *const Encoder) []const u8 {
        return e.bytes[0..e.len];
    }

    fn put(e: *Encoder, b: u8) void {
        if (e.len == e.bytes.len) return;
        e.bytes[e.len] = b;
        e.len += 1;
    }

    /// Writes a tag, a length, and `content`. The length uses the short
    /// form under 128 and the long form over it, which is what X.690
    /// clause 8.1.3 asks for.
    fn element(e: *Encoder, tag: u8, content: []const u8) void {
        e.put(tag);
        if (content.len < 0x80) {
            e.put(@intCast(content.len));
        } else if (content.len <= 0xff) {
            e.put(0x81);
            e.put(@intCast(content.len));
        } else {
            e.put(0x82);
            e.put(@truncate(content.len >> 8));
            e.put(@truncate(content.len));
        }
        for (content) |b| e.put(b);
    }

    fn octetString(e: *Encoder, value: []const u8) void {
        e.element(0x04, value);
    }

    /// Writes an `INTEGER` in the minimal two's complement form.
    fn integer(e: *Encoder, value: i32) void {
        var octets: [4]u8 = undefined;
        std.mem.writeInt(i32, &octets, value, .big);
        var at: usize = 0;
        while (at + 1 < octets.len) : (at += 1) {
            const lead = octets[at];
            const next_top = octets[at + 1] & 0x80;
            if (lead == 0x00 and next_top == 0) continue;
            if (lead == 0xff and next_top != 0) continue;
            break;
        }
        e.element(0x02, octets[at..]);
    }

    fn enumerated(e: *Encoder, value: i32) void {
        var octets: [4]u8 = undefined;
        std.mem.writeInt(i32, &octets, value, .big);
        var at: usize = 0;
        while (at + 1 < octets.len) : (at += 1) {
            const lead = octets[at];
            const next_top = octets[at + 1] & 0x80;
            if (lead == 0x00 and next_top == 0) continue;
            if (lead == 0xff and next_top != 0) continue;
            break;
        }
        e.element(0x0a, octets[at..]);
    }
};

fn log(s: *Server, bytes: []const u8) !void {
    if (s.offset_count == s.offsets.len) return;
    if (s.log_len + bytes.len > s.log_storage.len) return;
    s.offsets[s.offset_count] = s.log_len;
    s.offset_count += 1;
    @memcpy(s.log_storage[s.log_len..][0..bytes.len], bytes);
    s.log_len += bytes.len;
}

test "the fixture runs a whole bind, search, and unbind, and keeps every request" {
    var server: Server = undefined;
    try server.start(.{ .entries = &.{
        .{ .dn = "dc=zurl,dc=test", .attributes = &.{
            .{ .description = "dc", .values = &.{"zurl"} },
        } },
    } });
    defer server.stop();

    var address = try std.Io.net.IpAddress.parse("127.0.0.1", server.port());
    const stream = try address.connect(testing.io, .{ .mode = .stream });
    defer stream.close(testing.io);

    var read_buffer: [4096]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    var write_buffer: [4096]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);

    var request_writer: message.RequestWriter = .init();
    try message.writeBind(&request_writer, 1, "", "");
    try writer.interface.writeAll(request_writer.written());
    try writer.interface.flush();

    // The BindResponse arrives, and it is the one slapd sends.
    var incoming: [4096]u8 = undefined;
    try reader.interface.readSliceAll(incoming[0..14]);
    try testing.expectEqualSlices(u8, &.{
        0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07,
        0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
    }, incoming[0..14]);

    var t: @import("target.zig").Target = .empty;
    t.dn = "dc=zurl,dc=test";
    try message.writeSearch(&request_writer, 2, &t, 0, 0);
    try writer.interface.writeAll(request_writer.written());
    try writer.interface.flush();

    // The entry, then the done. Both read back through `message.zig`.
    try reader.interface.readSliceAll(incoming[0..2]);
    const entry_len = 2 + @as(usize, incoming[1]);
    try reader.interface.readSliceAll(incoming[2..entry_len]);
    const entry_message = try message.read(incoming[0..entry_len]);
    try testing.expectEqual(message.Kind.search_entry, entry_message.kind);
    var e = try message.entry(entry_message.op);
    try testing.expectEqualStrings("dc=zurl,dc=test", e.dn);
    const a = (try message.nextAttribute(&e.attributes)).?;
    try testing.expectEqualStrings("dc", a.description);
    var values = a.values;
    try testing.expectEqualStrings("zurl", (try message.nextValue(&values)).?);

    try reader.interface.readSliceAll(incoming[0..14]);
    const done = try message.read(incoming[0..14]);
    try testing.expectEqual(message.Kind.search_done, done.kind);
    try testing.expectEqual(message.ResultCode.success, (try message.result(done.op)).code);

    try message.writeUnbind(&request_writer, 3);
    try writer.interface.writeAll(request_writer.written());
    try writer.interface.flush();

    server.wait();
    try testing.expectEqual(@as(usize, 3), server.requestCount());
    try testing.expectEqual(@as(usize, 1), server.connections());
    // The requests came back byte for byte, which is what a test that pins
    // a filter on the wire needs.
    try testing.expectEqualSlices(u8, &.{
        0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07,
        0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
    }, server.request(0));
    try testing.expectEqualSlices(u8, &.{ 0x30, 0x05, 0x02, 0x01, 0x03, 0x42, 0x00 }, server.request(2));
}

test "the fixture's own encoder writes the lengths X.690 asks for" {
    // The fixture's encoder is a second opinion about the client's, so it
    // is worth a test of its own.
    var e: Encoder = .init();
    e.octetString("abc");
    try testing.expectEqualSlices(u8, &.{ 0x04, 0x03, 'a', 'b', 'c' }, e.written());

    e = .init();
    e.octetString("x" ** 200);
    try testing.expectEqual(@as(u8, 0x81), e.written()[1]);
    try testing.expectEqual(@as(u8, 200), e.written()[2]);
    try testing.expectEqual(@as(usize, 203), e.written().len);

    e = .init();
    e.octetString("y" ** 300);
    try testing.expectEqual(@as(u8, 0x82), e.written()[1]);
    try testing.expectEqual(@as(u8, 0x01), e.written()[2]);
    try testing.expectEqual(@as(u8, 0x2c), e.written()[3]);

    e = .init();
    e.integer(0);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x01, 0x00 }, e.written());
    e = .init();
    e.integer(128);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x02, 0x00, 0x80 }, e.written());
    e = .init();
    e.enumerated(32);
    try testing.expectEqualSlices(u8, &.{ 0x0a, 0x01, 0x20 }, e.written());
}
