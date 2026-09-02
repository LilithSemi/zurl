//! Reads frames off a `std.Io.Reader`, one at a time. RFC 9113 section 4.
//!
//! This is the only file in the package that touches a stream. It reads
//! the 9-octet header, refuses a length above the size this endpoint
//! advertised, reads that many octets into a buffer it owns, runs the
//! `CONTINUATION` order rule, and hands back a parsed frame.
//!
//! This is not a connection engine. It sends nothing, it holds no stream
//! table, it keeps no window, and it never decides to close anything. It
//! reads one frame and tells the caller what it is. Everything a reply
//! needs sits above it.
//!
//! **The payload buffer is the one allocation in this package.** It is
//! sized to the `SETTINGS_MAX_FRAME_SIZE` this endpoint advertised, and
//! it is allocated once. A frame larger than that is refused on its
//! header alone, before one octet of payload is read, so a peer can never
//! make this reader hold more than the size it asked for.
//!
//! **An unknown frame type is not a fault.** RFC 9113 section 4.1 says a
//! receiver must ignore one. This reader reads it, counts it, and returns
//! it as `Payload.unknown`. The caller drops it with one `switch` arm.
//! The reader does not drop it on the caller's behalf, because an unknown
//! frame still counts against the `CONTINUATION` order rule and still
//! costs the caller a read, and hiding it here would hide both.

const std = @import("std");
const Allocator = std.mem.Allocator;

const continuation = @import("continuation.zig");
const errors = @import("errors.zig");
const frame = @import("frame.zig");
const payload = @import("payload.zig");
const settings = @import("settings.zig");

const FrameReader = @This();

/// Every fault `next` can report. The two from `std.Io.Reader` are a
/// stream that ended and a stream that failed. Neither one is a protocol
/// fault, so neither one has an HTTP/2 error code.
pub const NextError = errors.Error || std.Io.Reader.Error;

pub const Options = struct {
    /// The `SETTINGS_MAX_FRAME_SIZE` this endpoint advertises to the
    /// peer. The payload buffer is this big, and a frame above it is
    /// refused.
    max_frame_size: u24 = settings.Settings.initial.max_frame_size,
};

/// Room for one payload. Never larger than `max_frame_size`.
buffer: []u8,

/// The largest payload this reader accepts. It is what this endpoint put
/// in its own `SETTINGS` frame, not what the peer put in its own.
max_frame_size: u24,

/// The `CONTINUATION` order rule of RFC 9113 section 6.10.
sequencer: continuation.Sequencer = .{},

/// How many frames of a type this build does not know have come through.
/// The count makes the ignore path visible, because a peer that sends
/// nothing this build knows is worth reporting.
unknown_frames: u64 = 0,

pub fn init(gpa: Allocator, options: Options) Allocator.Error!FrameReader {
    return .{
        .buffer = try gpa.alloc(u8, options.max_frame_size),
        .max_frame_size = options.max_frame_size,
    };
}

pub fn deinit(self: *FrameReader, gpa: Allocator) void {
    gpa.free(self.buffer);
    self.* = undefined;
}

/// Changes the size this reader accepts, and resizes the buffer with it.
///
/// The engine calls this when it sends a new `SETTINGS_MAX_FRAME_SIZE`.
/// The new size must be inside the range of RFC 9113 section 6.5.2, which
/// is this endpoint's own choice and so an assert.
pub fn setMaxFrameSize(self: *FrameReader, gpa: Allocator, size: u24) Allocator.Error!void {
    std.debug.assert(size >= settings.max_frame_size_min);
    if (size == self.max_frame_size) return;

    const grown = try gpa.realloc(self.buffer, size);
    self.buffer = grown;
    self.max_frame_size = size;
}

/// Reads the next frame.
///
/// The returned frame's slices point into this reader's buffer. They stay
/// valid until the next call to `next`, `setMaxFrameSize`, or `deinit`. A
/// caller that needs a header block fragment past that must copy it.
pub fn next(self: *FrameReader, r: *std.Io.Reader) NextError!payload.Frame {
    const header = try frame.Header.read(r);

    // This is the read bound. It runs before one octet of payload is
    // read, so a peer that names a huge length costs nothing but the 9
    // octets it already spent. The 24-bit field holds up to 16777215,
    // and a negotiated maximum is often 16384, so most of the field's
    // range is refused here.
    if (header.length > self.max_frame_size) return error.FrameTooLarge;

    const bytes = self.buffer[0..header.length];
    try r.readSliceAll(bytes);

    // Section 6.10 runs on the header alone, before the payload rules,
    // so an out-of-order frame is named for being out of order and not
    // for whatever else is wrong with it.
    _ = try self.sequencer.accept(header, header.length);

    const parsed = try payload.Frame.parse(header, bytes);
    if (parsed.payload == .unknown) self.unknown_frames += 1;
    return parsed;
}

const testing = std.testing;

/// Builds a reader over `bytes` with a small negotiated frame size, so a
/// test needs no large buffer and no socket.
fn testReader(gpa: Allocator, max_frame_size: u24) !FrameReader {
    return FrameReader.init(gpa, .{ .max_frame_size = max_frame_size });
}

test "a reader walks a stream of frames and returns each one" {
    const gpa = testing.allocator;
    var fr = try testReader(gpa, 16384);
    defer fr.deinit(gpa);

    var buf: [256]u8 = undefined;
    var used: usize = 0;
    used += (payload.Settings{ .ack = false, .entries = &.{} }).encode(buf[used..]).len;
    used += (payload.Headers{ .block = "\x82", .end_headers = true }).encode(1, buf[used..]).len;
    used += (payload.Data{ .data = "hi", .end_stream = true }).encode(1, buf[used..]).len;

    var r: std.Io.Reader = .fixed(buf[0..used]);

    const first = try fr.next(&r);
    try testing.expectEqual(frame.Type.settings, first.header.type);
    try testing.expectEqual(@as(usize, 0), first.payload.settings.count());

    const second = try fr.next(&r);
    try testing.expectEqualSlices(u8, "\x82", second.payload.headers.block);

    const third = try fr.next(&r);
    try testing.expectEqualSlices(u8, "hi", third.payload.data.data);
    try testing.expect(third.payload.data.end_stream);

    try testing.expectError(error.EndOfStream, fr.next(&r));
}

test "a length above the negotiated maximum is refused before the payload is read" {
    const gpa = testing.allocator;
    var fr = try testReader(gpa, 16384);
    defer fr.deinit(gpa);

    // The header names 16385 octets, and the stream carries none of them.
    // The refusal must come off the header alone.
    const header = [_]u8{ 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    var r: std.Io.Reader = .fixed(&header);
    try testing.expectError(error.FrameTooLarge, fr.next(&r));

    try testing.expectEqual(
        errors.Fault{ .code = .frame_size_error, .scope = .connection },
        errors.classify(error.FrameTooLarge, 1),
    );
}

test "the whole range above the negotiated maximum is refused, up to the 24-bit field" {
    const gpa = testing.allocator;
    var fr = try testReader(gpa, settings.max_frame_size_min);
    defer fr.deinit(gpa);

    // 16777215 is the largest the length field can hold. With a
    // negotiated maximum of 16384, everything from 16385 up is refused,
    // which is most of the field's range.
    const lengths = [_]u24{
        settings.max_frame_size_min + 1,
        1 << 16,
        1 << 20,
        frame.length_max,
    };
    for (lengths) |length| {
        var header: [frame.header_len]u8 = undefined;
        (frame.Header{ .length = length, .type = .data, .flags = 0, .stream_id = 1 })
            .encode(&header);
        var r: std.Io.Reader = .fixed(&header);
        try testing.expectError(error.FrameTooLarge, fr.next(&r));
    }
}

test "a frame exactly at the negotiated maximum is read" {
    const gpa = testing.allocator;
    var fr = try testReader(gpa, 16384);
    defer fr.deinit(gpa);

    const body = try gpa.alloc(u8, 16384);
    defer gpa.free(body);
    @memset(body, 'x');

    const bytes = try gpa.alloc(u8, frame.header_len + body.len);
    defer gpa.free(bytes);
    const written = (payload.Data{ .data = body }).encode(1, bytes);

    var r: std.Io.Reader = .fixed(written);
    const got = try fr.next(&r);
    try testing.expectEqual(@as(usize, 16384), got.payload.data.data.len);
}

test "a stream that ends inside a payload reports the end" {
    const gpa = testing.allocator;
    var fr = try testReader(gpa, 16384);
    defer fr.deinit(gpa);

    // The header names 5 octets and the stream carries 2.
    const bytes = [_]u8{ 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 'a', 'b' };
    var r: std.Io.Reader = .fixed(&bytes);
    try testing.expectError(error.EndOfStream, fr.next(&r));
}

test "an unknown frame type is returned and counted, never refused" {
    const gpa = testing.allocator;
    var fr = try testReader(gpa, 16384);
    defer fr.deinit(gpa);

    // Type 0x0a is past the table of RFC 9113 section 6. Two of them,
    // then a PING, proves the reader kept going.
    const bytes = [_]u8{
        0x00, 0x00, 0x03, 0x0a, 0xff, 0x00, 0x00, 0x00, 0x00, 'x',  'y',  'z',
        0x00, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x08,
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08,
    };
    var r: std.Io.Reader = .fixed(&bytes);

    const first = try fr.next(&r);
    try testing.expectEqualSlices(u8, "xyz", first.payload.unknown);
    const second = try fr.next(&r);
    try testing.expectEqualSlices(u8, "", second.payload.unknown);
    try testing.expectEqual(@as(u64, 2), fr.unknown_frames);

    const third = try fr.next(&r);
    try testing.expectEqual(frame.Type.ping, third.header.type);
    try testing.expectEqual([_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, third.payload.ping.opaque_data);
    try testing.expectEqual(@as(u64, 2), fr.unknown_frames);
}

test "a CONTINUATION sequence reads through, and an interleaved frame does not" {
    const gpa = testing.allocator;
    var fr = try testReader(gpa, 16384);
    defer fr.deinit(gpa);

    var buf: [256]u8 = undefined;
    var used: usize = 0;
    used += (payload.Headers{ .block = "\x82" }).encode(1, buf[used..]).len;
    used += (payload.Continuation{ .block = "\x84", .end_headers = true })
        .encode(1, buf[used..]).len;
    var r: std.Io.Reader = .fixed(buf[0..used]);

    _ = try fr.next(&r);
    try testing.expect(fr.sequencer.isOpen());
    _ = try fr.next(&r);
    try testing.expect(!fr.sequencer.isOpen());

    // The same start, then a DATA where a CONTINUATION must be.
    var other = try testReader(gpa, 16384);
    defer other.deinit(gpa);
    used = 0;
    used += (payload.Headers{ .block = "\x82" }).encode(1, buf[used..]).len;
    used += (payload.Data{ .data = "x" }).encode(1, buf[used..]).len;
    var r2: std.Io.Reader = .fixed(buf[0..used]);

    _ = try other.next(&r2);
    try testing.expectError(error.ContinuationExpected, other.next(&r2));
}

test "a CONTINUATION on another stream is refused by the reader" {
    const gpa = testing.allocator;
    var fr = try testReader(gpa, 16384);
    defer fr.deinit(gpa);

    var buf: [256]u8 = undefined;
    var used: usize = 0;
    used += (payload.Headers{ .block = "\x82" }).encode(1, buf[used..]).len;
    used += (payload.Continuation{ .block = "\x84", .end_headers = true })
        .encode(3, buf[used..]).len;
    var r: std.Io.Reader = .fixed(buf[0..used]);

    _ = try fr.next(&r);
    try testing.expectError(error.ContinuationStreamMismatch, fr.next(&r));
}

test "a CONTINUATION flood stops at the bound, not at the buffer" {
    const gpa = testing.allocator;
    var fr = try testReader(gpa, 16384);
    defer fr.deinit(gpa);

    // A HEADERS with no END_HEADERS, then empty CONTINUATION frames with
    // no end. Each one costs 9 octets and no payload, so nothing but the
    // frame bound stops this.
    const count = continuation.limits.continuation_frames_max + 8;
    const bytes = try gpa.alloc(u8, frame.header_len * (1 + count));
    defer gpa.free(bytes);

    var used: usize = (payload.Headers{ .block = "" }).encode(1, bytes).len;
    var sent: u32 = 0;
    while (sent < count) : (sent += 1) {
        used += (payload.Continuation{ .block = "" }).encode(1, bytes[used..]).len;
    }

    var r: std.Io.Reader = .fixed(bytes[0..used]);
    _ = try fr.next(&r);

    var read: u32 = 0;
    while (read < continuation.limits.continuation_frames_max) : (read += 1) {
        _ = try fr.next(&r);
    }
    try testing.expectError(error.ContinuationFlood, fr.next(&r));

    try testing.expectEqual(
        errors.Fault{ .code = .enhance_your_calm, .scope = .connection },
        errors.classify(error.ContinuationFlood, 1),
    );
}

test "a payload fault comes off the reader with the frame's own name" {
    const gpa = testing.allocator;
    var fr = try testReader(gpa, 16384);
    defer fr.deinit(gpa);

    const cases = [_]struct { bytes: []const u8, want: errors.Error }{
        // SETTINGS of 7 octets.
        .{
            .bytes = &.{
                0x00, 0x00, 0x07, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
                0,    0,    0,    0,    0,    0,    0,
            },
            .want = error.SettingsLengthInvalid,
        },
        // SETTINGS ACK with a payload.
        .{
            .bytes = &.{
                0x00, 0x00, 0x06, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x05, 0x00, 0x00, 0x40, 0x00,
            },
            .want = error.SettingsAckNotEmpty,
        },
        // PING of 7 octets.
        .{
            .bytes = &.{
                0x00, 0x00, 0x07, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
                0,    0,    0,    0,    0,    0,    0,
            },
            .want = error.PingLengthInvalid,
        },
        // WINDOW_UPDATE of zero on stream 1.
        .{
            .bytes = &.{
                0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00,
            },
            .want = error.WindowUpdateZero,
        },
        // RST_STREAM of 3 octets.
        .{
            .bytes = &.{ 0x00, 0x00, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0, 0, 0 },
            .want = error.RstStreamLengthInvalid,
        },
        // PRIORITY of 4 octets.
        .{
            .bytes = &.{ 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0 },
            .want = error.PriorityLengthInvalid,
        },
        // GOAWAY of 7 octets.
        .{
            .bytes = &.{
                0x00, 0x00, 0x07, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
                0,    0,    0,    0,    0,    0,    0,
            },
            .want = error.GoawayLengthInvalid,
        },
        // DATA on stream 0.
        .{
            .bytes = &.{ 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 'x' },
            .want = error.StreamIdZero,
        },
        // PING on stream 1.
        .{
            .bytes = &.{
                0x00, 0x00, 0x08, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01,
                0,    0,    0,    0,    0,    0,    0,    0,
            },
            .want = error.StreamIdNonZero,
        },
        // A DATA whose padding is longer than what is left.
        .{
            .bytes = &.{ 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x05, 'x' },
            .want = error.PadLengthTooLong,
        },
        // A CONTINUATION with no open header block.
        .{
            .bytes = &.{ 0x00, 0x00, 0x00, 0x09, 0x04, 0x00, 0x00, 0x00, 0x01 },
            .want = error.ContinuationUnexpected,
        },
    };

    for (cases) |case| {
        var one = try testReader(gpa, 16384);
        defer one.deinit(gpa);
        var r: std.Io.Reader = .fixed(case.bytes);
        try testing.expectError(case.want, one.next(&r));
    }
}

test "setMaxFrameSize grows the buffer, and the larger frame then reads" {
    const gpa = testing.allocator;
    var fr = try testReader(gpa, settings.max_frame_size_min);
    defer fr.deinit(gpa);

    const body = try gpa.alloc(u8, 20000);
    defer gpa.free(body);
    @memset(body, 'q');
    const bytes = try gpa.alloc(u8, frame.header_len + body.len);
    defer gpa.free(bytes);
    const written = (payload.Data{ .data = body }).encode(1, bytes);

    var before: std.Io.Reader = .fixed(written);
    try testing.expectError(error.FrameTooLarge, fr.next(&before));

    try fr.setMaxFrameSize(gpa, 32768);
    try testing.expectEqual(@as(usize, 32768), fr.buffer.len);

    var after: std.Io.Reader = .fixed(written);
    const got = try fr.next(&after);
    try testing.expectEqual(@as(usize, 20000), got.payload.data.data.len);
}

test "the buffer is the size that was asked for and no more" {
    const gpa = testing.allocator;
    var fr = try testReader(gpa, settings.max_frame_size_min);
    defer fr.deinit(gpa);
    try testing.expectEqual(@as(usize, settings.max_frame_size_min), fr.buffer.len);
    try testing.expectEqual(@as(u24, settings.max_frame_size_min), fr.max_frame_size);

    // The default is the RFC's own default.
    var other = try FrameReader.init(gpa, .{});
    defer other.deinit(gpa);
    try testing.expectEqual(@as(usize, 16384), other.buffer.len);
}

test "a returned frame points into the reader's buffer and is replaced by the next read" {
    const gpa = testing.allocator;
    var fr = try testReader(gpa, 16384);
    defer fr.deinit(gpa);

    var buf: [64]u8 = undefined;
    var used: usize = 0;
    used += (payload.Data{ .data = "first" }).encode(1, buf[used..]).len;
    used += (payload.Data{ .data = "second" }).encode(1, buf[used..]).len;
    var r: std.Io.Reader = .fixed(buf[0..used]);

    const first = try fr.next(&r);
    try testing.expectEqualSlices(u8, "first", first.payload.data.data);
    try testing.expectEqual(@intFromPtr(fr.buffer.ptr), @intFromPtr(first.payload.data.data.ptr));

    _ = try fr.next(&r);
    // The first frame's slice now views the second frame's octets, which
    // is what the doc comment on `next` warns about.
    try testing.expectEqualSlices(u8, "secon", first.payload.data.data);
}
