//! The RFC 9113 checks that need more than one file.
//!
//! Each file in this package tests its own rules. This one tests what
//! only the whole package can show: a client's first flight read back
//! frame by frame, every frame type walked through one round trip in one
//! table, and every hostile case of the frame layer with the error it
//! produces and the code and scope a peer would be told.
//!
//! No test here opens a socket. Every reader is `std.Io.Reader.fixed`
//! over a buffer, and every writer is `std.Io.Writer.fixed` over one.

const std = @import("std");

const continuation = @import("continuation.zig");
const errors = @import("errors.zig");
const frame = @import("frame.zig");
const payload = @import("payload.zig");
const preface = @import("preface.zig");
const settings = @import("settings.zig");
const window = @import("window.zig");
const FrameReader = @import("FrameReader.zig");

const testing = std.testing;
const Header = frame.Header;

test "RFC 9113 section 3.4, a client's first flight reads back as the preface and a SETTINGS" {
    const gpa = testing.allocator;

    var wanted: settings.Settings = .initial;
    wanted.enable_push = false;
    wanted.max_frame_size = 32768;

    var buf: [preface.client_flight_len_max]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try preface.writeClientFlight(&w, wanted);

    var r: std.Io.Reader = .fixed(w.buffered());
    try preface.readClient(&r);

    var fr: FrameReader = try .init(gpa, .{});
    defer fr.deinit(gpa);

    const got = try fr.next(&r);
    try testing.expectEqual(frame.Type.settings, got.header.type);
    try testing.expectEqual(@as(u31, 0), got.header.stream_id);
    try testing.expect(!got.payload.settings.ack);

    var applied: settings.Settings = .initial;
    const result = try got.payload.settings.applyTo(&applied);
    try testing.expectEqual(@as(usize, 2), result.taken);
    try testing.expectEqual(@as(usize, 0), result.ignored);
    try testing.expectEqual(wanted, applied);

    try testing.expectError(error.EndOfStream, fr.next(&r));
}

test "RFC 9113 section 6.5, a SETTINGS is answered with an empty ACK" {
    const gpa = testing.allocator;

    var buf: [frame.header_len]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try preface.writeSettingsAck(&w);

    var fr: FrameReader = try .init(gpa, .{});
    defer fr.deinit(gpa);
    var r: std.Io.Reader = .fixed(w.buffered());

    const got = try fr.next(&r);
    try testing.expect(got.payload.settings.ack);
    try testing.expectEqual(@as(usize, 0), got.payload.settings.count());
    try testing.expectEqual(@as(u32, 0), got.header.length);
}

test "every frame type of RFC 9113 section 6 round-trips through a reader" {
    const gpa = testing.allocator;
    var fr: FrameReader = try .init(gpa, .{});
    defer fr.deinit(gpa);

    var buf: [512]u8 = undefined;
    var used: usize = 0;

    // The order matters in one place only: the HEADERS below carries
    // END_HEADERS, so the CONTINUATION later needs a header block of its
    // own to follow. That one is written just before it.
    used += (payload.Settings{ .ack = false, .entries = &.{
        0x00, 0x05, 0x00, 0x00, 0x40, 0x00,
    } }).encode(buf[used..]).len;
    used += (payload.Ping{ .opaque_data = .{ 1, 2, 3, 4, 5, 6, 7, 8 } })
        .encode(buf[used..]).len;
    used += (payload.WindowUpdate{ .increment = 1024 }).encode(0, buf[used..]).len;
    used += (payload.Priority{ .exclusive = false, .dependency = 1, .weight = 200 })
        .encode(3, buf[used..]).len;
    used += (payload.Headers{
        .block = "\x82\x86\x84",
        .end_headers = true,
        .end_stream = false,
    }).encode(1, buf[used..]).len;
    used += (payload.Data{ .data = "body", .end_stream = true, .padding = 2 })
        .encode(1, buf[used..]).len;
    used += (payload.PushPromise{ .promised_stream_id = 2, .block = "\x82" })
        .encode(1, buf[used..]).len;
    used += (payload.Continuation{ .block = "\x84", .end_headers = true })
        .encode(1, buf[used..]).len;
    used += (payload.RstStream{ .error_code = .cancel }).encode(3, buf[used..]).len;
    used += (payload.Goaway{
        .last_stream_id = 3,
        .error_code = .no_error,
        .debug_data = "done",
    }).encode(buf[used..]).len;

    var r: std.Io.Reader = .fixed(buf[0..used]);

    const settings_frame = try fr.next(&r);
    try testing.expectEqual(@as(usize, 1), settings_frame.payload.settings.count());
    try testing.expectEqual(
        settings.Entry{ .id = .max_frame_size, .value = 16384 },
        settings_frame.payload.settings.get(0),
    );

    const ping = try fr.next(&r);
    try testing.expectEqual([_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, ping.payload.ping.opaque_data);
    try testing.expect(!ping.payload.ping.ack);

    const window_update = try fr.next(&r);
    try testing.expectEqual(@as(u31, 1024), window_update.payload.window_update.increment);
    try testing.expectEqual(@as(u31, 0), window_update.header.stream_id);

    const priority = try fr.next(&r);
    try testing.expectEqual(
        payload.Priority{ .exclusive = false, .dependency = 1, .weight = 200 },
        priority.payload.priority,
    );

    const headers = try fr.next(&r);
    try testing.expectEqualSlices(u8, "\x82\x86\x84", headers.payload.headers.block);
    try testing.expect(headers.payload.headers.end_headers);
    try testing.expect(!headers.payload.headers.end_stream);

    const data = try fr.next(&r);
    try testing.expectEqualSlices(u8, "body", data.payload.data.data);
    try testing.expectEqual(@as(?u8, 2), data.payload.data.padding);
    try testing.expect(data.payload.data.end_stream);

    const push = try fr.next(&r);
    try testing.expectEqual(@as(u31, 2), push.payload.push_promise.promised_stream_id);
    try testing.expectEqualSlices(u8, "\x82", push.payload.push_promise.block);
    try testing.expect(!push.payload.push_promise.end_headers);
    try testing.expect(fr.sequencer.isOpen());

    const cont = try fr.next(&r);
    try testing.expectEqualSlices(u8, "\x84", cont.payload.continuation.block);
    try testing.expect(cont.payload.continuation.end_headers);
    try testing.expect(!fr.sequencer.isOpen());

    const rst = try fr.next(&r);
    try testing.expectEqual(errors.ErrorCode.cancel, rst.payload.rst_stream.error_code);
    try testing.expectEqual(@as(u31, 3), rst.header.stream_id);

    const goaway = try fr.next(&r);
    try testing.expectEqual(@as(u31, 3), goaway.payload.goaway.last_stream_id);
    try testing.expectEqual(errors.ErrorCode.no_error, goaway.payload.goaway.error_code);
    try testing.expectEqualSlices(u8, "done", goaway.payload.goaway.debug_data);

    try testing.expectError(error.EndOfStream, fr.next(&r));
    try testing.expectEqual(@as(u64, 0), fr.unknown_frames);
}

test "a header block split over three frames reads through in order" {
    const gpa = testing.allocator;
    var fr: FrameReader = try .init(gpa, .{});
    defer fr.deinit(gpa);

    var buf: [128]u8 = undefined;
    var used: usize = 0;
    used += (payload.Headers{ .block = "\x82" }).encode(1, buf[used..]).len;
    used += (payload.Continuation{ .block = "\x86" }).encode(1, buf[used..]).len;
    used += (payload.Continuation{ .block = "\x84", .end_headers = true })
        .encode(1, buf[used..]).len;
    used += (payload.Data{ .data = "after", .end_stream = true }).encode(1, buf[used..]).len;

    var r: std.Io.Reader = .fixed(buf[0..used]);

    // The engine above would join the three fragments and hand them to
    // HPACK. This layer proves only that the three arrive in order and
    // that the block closes.
    var joined: [3]u8 = undefined;
    joined[0] = (try fr.next(&r)).payload.headers.block[0];
    try testing.expect(fr.sequencer.isOpen());
    joined[1] = (try fr.next(&r)).payload.continuation.block[0];
    try testing.expect(fr.sequencer.isOpen());
    joined[2] = (try fr.next(&r)).payload.continuation.block[0];
    try testing.expect(!fr.sequencer.isOpen());
    try testing.expectEqualSlices(u8, "\x82\x86\x84", &joined);

    const data = try fr.next(&r);
    try testing.expectEqualSlices(u8, "after", data.payload.data.data);
}

/// One hostile frame and the fault it must produce.
const Hostile = struct {
    what: []const u8,
    bytes: []const u8,
    want: errors.Error,
    code: errors.ErrorCode,
    scope: errors.Scope,
    /// Frames to feed first, so the reader is in the right state.
    prefix: []const u8 = &.{},
};

test "every hostile frame produces its own named fault, its code, and its scope" {
    const gpa = testing.allocator;

    const headers_open = [_]u8{ 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x82 };

    const cases = [_]Hostile{
        .{
            .what = "a length above the negotiated MAX_FRAME_SIZE",
            .bytes = &.{ 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
            .want = error.FrameTooLarge,
            .code = .frame_size_error,
            .scope = .connection,
        },
        .{
            .what = "the largest the 24-bit field holds, with a small negotiated maximum",
            .bytes = &.{ 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
            .want = error.FrameTooLarge,
            .code = .frame_size_error,
            .scope = .connection,
        },
        .{
            .what = "a SETTINGS length that is not a multiple of six",
            .bytes = &.{
                0x00, 0x00, 0x07, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
                0,    0,    0,    0,    0,    0,    0,
            },
            .want = error.SettingsLengthInvalid,
            .code = .frame_size_error,
            .scope = .connection,
        },
        .{
            .what = "a SETTINGS ACK with a payload",
            .bytes = &.{
                0x00, 0x00, 0x06, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x05, 0x00, 0x00, 0x40, 0x00,
            },
            .want = error.SettingsAckNotEmpty,
            .code = .frame_size_error,
            .scope = .connection,
        },
        .{
            .what = "SETTINGS_INITIAL_WINDOW_SIZE above 2^31-1",
            .bytes = &.{
                0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x04, 0x80, 0x00, 0x00, 0x00,
            },
            .want = error.SettingsInitialWindowSizeInvalid,
            .code = .flow_control_error,
            .scope = .connection,
        },
        .{
            .what = "SETTINGS_MAX_FRAME_SIZE below 16384",
            .bytes = &.{
                0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x05, 0x00, 0x00, 0x3f, 0xff,
            },
            .want = error.SettingsMaxFrameSizeInvalid,
            .code = .protocol_error,
            .scope = .connection,
        },
        .{
            .what = "SETTINGS_MAX_FRAME_SIZE above 16777215",
            .bytes = &.{
                0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x05, 0x01, 0x00, 0x00, 0x00,
            },
            .want = error.SettingsMaxFrameSizeInvalid,
            .code = .protocol_error,
            .scope = .connection,
        },
        .{
            .what = "SETTINGS_ENABLE_PUSH that is neither 0 nor 1",
            .bytes = &.{
                0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
            },
            .want = error.SettingsEnablePushInvalid,
            .code = .protocol_error,
            .scope = .connection,
        },
        .{
            .what = "a WINDOW_UPDATE of zero on the connection",
            .bytes = &.{
                0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            },
            .want = error.WindowUpdateZero,
            .code = .protocol_error,
            .scope = .connection,
        },
        .{
            .what = "a WINDOW_UPDATE of zero on a stream",
            .bytes = &.{
                0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00,
            },
            .want = error.WindowUpdateZero,
            .code = .protocol_error,
            .scope = .stream,
        },
        .{
            .what = "a WINDOW_UPDATE that is not four octets",
            .bytes = &.{
                0x00, 0x00, 0x05, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01,
                0,    0,    0,    0,    0,
            },
            .want = error.WindowUpdateLengthInvalid,
            .code = .frame_size_error,
            .scope = .connection,
        },
        .{
            .what = "a PING that is not eight octets",
            .bytes = &.{
                0x00, 0x00, 0x09, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
                0,    0,    0,    0,    0,    0,    0,    0,    0,
            },
            .want = error.PingLengthInvalid,
            .code = .frame_size_error,
            .scope = .connection,
        },
        .{
            .what = "a RST_STREAM that is not four octets",
            .bytes = &.{
                0x00, 0x00, 0x05, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01,
                0,    0,    0,    0,    0,
            },
            .want = error.RstStreamLengthInvalid,
            .code = .frame_size_error,
            .scope = .connection,
        },
        .{
            .what = "a PRIORITY that is not five octets",
            .bytes = &.{
                0x00, 0x00, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
                0,    0,    0,    0,    0,    0,
            },
            .want = error.PriorityLengthInvalid,
            .code = .frame_size_error,
            .scope = .stream,
        },
        .{
            .what = "a GOAWAY shorter than eight octets",
            .bytes = &.{
                0x00, 0x00, 0x04, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
                0,    0,    0,    0,
            },
            .want = error.GoawayLengthInvalid,
            .code = .frame_size_error,
            .scope = .connection,
        },
        .{
            .what = "a DATA on stream 0, which must be on a stream",
            .bytes = &.{ 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 'x' },
            .want = error.StreamIdZero,
            .code = .protocol_error,
            .scope = .connection,
        },
        .{
            .what = "a HEADERS on stream 0, which must be on a stream",
            .bytes = &.{ 0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00 },
            .want = error.StreamIdZero,
            .code = .protocol_error,
            .scope = .connection,
        },
        .{
            .what = "a SETTINGS on a stream, which must be on stream 0",
            .bytes = &.{ 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01 },
            .want = error.StreamIdNonZero,
            .code = .protocol_error,
            .scope = .connection,
        },
        .{
            .what = "a GOAWAY on a stream, which must be on stream 0",
            .bytes = &.{
                0x00, 0x00, 0x08, 0x07, 0x00, 0x00, 0x00, 0x00, 0x01,
                0,    0,    0,    0,    0,    0,    0,    0,
            },
            .want = error.StreamIdNonZero,
            .code = .protocol_error,
            .scope = .connection,
        },
        .{
            .what = "a DATA whose padding is longer than the rest of the payload",
            .bytes = &.{ 0x00, 0x00, 0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x03, 'a', 'b' },
            .want = error.PadLengthTooLong,
            .code = .protocol_error,
            .scope = .connection,
        },
        .{
            .what = "a HEADERS whose padding is longer than the rest of the payload",
            .bytes = &.{ 0x00, 0x00, 0x02, 0x01, 0x0c, 0x00, 0x00, 0x00, 0x01, 0xff, 0x82 },
            .want = error.PadLengthTooLong,
            .code = .protocol_error,
            .scope = .connection,
        },
        .{
            .what = "a PADDED DATA with no room for the Pad Length octet",
            .bytes = &.{ 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01 },
            .want = error.PayloadTruncated,
            .code = .frame_size_error,
            .scope = .connection,
        },
        .{
            .what = "a CONTINUATION with no header block open",
            .bytes = &.{ 0x00, 0x00, 0x00, 0x09, 0x04, 0x00, 0x00, 0x00, 0x01 },
            .want = error.ContinuationUnexpected,
            .code = .protocol_error,
            .scope = .connection,
        },
        .{
            .what = "a DATA where a CONTINUATION must be",
            .prefix = &headers_open,
            .bytes = &.{ 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 'x' },
            .want = error.ContinuationExpected,
            .code = .protocol_error,
            .scope = .connection,
        },
        .{
            .what = "a PING where a CONTINUATION must be, on stream 0",
            .prefix = &headers_open,
            .bytes = &.{
                0x00, 0x00, 0x08, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
                0,    0,    0,    0,    0,    0,    0,    0,
            },
            .want = error.ContinuationExpected,
            .code = .protocol_error,
            .scope = .connection,
        },
        .{
            .what = "an unknown type where a CONTINUATION must be",
            .prefix = &headers_open,
            .bytes = &.{ 0x00, 0x00, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x01 },
            .want = error.ContinuationExpected,
            .code = .protocol_error,
            .scope = .connection,
        },
        .{
            .what = "a CONTINUATION on a stream other than the open one",
            .prefix = &headers_open,
            .bytes = &.{ 0x00, 0x00, 0x00, 0x09, 0x04, 0x00, 0x00, 0x00, 0x03 },
            .want = error.ContinuationStreamMismatch,
            .code = .protocol_error,
            .scope = .connection,
        },
    };

    for (cases) |case| {
        errdefer std.debug.print("hostile case: {s}\n", .{case.what});

        var fr: FrameReader = try .init(gpa, .{});
        defer fr.deinit(gpa);

        var prefix_reader: std.Io.Reader = .fixed(case.prefix);
        while (prefix_reader.bufferedLen() > 0) _ = try fr.next(&prefix_reader);

        var r: std.Io.Reader = .fixed(case.bytes);
        try testing.expectError(case.want, fr.next(&r));

        const fault = errors.classify(case.want, Header.parse(case.bytes[0..9]).stream_id);
        try testing.expectEqual(case.code, fault.code);
        try testing.expectEqual(case.scope, fault.scope);
    }
}

test "a CONTINUATION flood ends with a named fault and nothing is held" {
    const gpa = testing.allocator;
    var fr: FrameReader = try .init(gpa, .{});
    defer fr.deinit(gpa);

    // A HEADERS with no END_HEADERS, then empty CONTINUATION frames
    // without end. This is the shape that has broken several HTTP/2
    // builds, so the bound is proved here as well as in continuation.zig.
    const count = continuation.limits.continuation_frames_max * 4;
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
    const fault = while (read < count) : (read += 1) {
        _ = fr.next(&r) catch |err| break err;
    } else unreachable;

    try testing.expectEqual(errors.Error.ContinuationFlood, fault);
    try testing.expectEqual(continuation.limits.continuation_frames_max, read);
    try testing.expectEqual(
        errors.Fault{ .code = .enhance_your_calm, .scope = .connection },
        errors.classify(error.ContinuationFlood, 1),
    );

    // The reader holds one payload buffer and nothing else, whatever the
    // peer sent.
    try testing.expectEqual(@as(usize, 16384), fr.buffer.len);
}

test "RFC 9113 section 6.9.1, a WINDOW_UPDATE that runs the window past 2^31-1" {
    const gpa = testing.allocator;
    var fr: FrameReader = try .init(gpa, .{});
    defer fr.deinit(gpa);

    // The frame itself is legal, so the frame layer accepts it. The
    // fault only appears once the increment meets a window that has no
    // room for it.
    var out: [frame.header_len + 4]u8 = undefined;
    const bytes = (payload.WindowUpdate{ .increment = 2 }).encode(1, &out);

    var r: std.Io.Reader = .fixed(bytes);
    const got = try fr.next(&r);

    var w: window.Window = .init(window.size_max - 1);
    try testing.expectError(error.WindowOverflow, w.increase(got.payload.window_update.increment));
    try testing.expectEqual(window.size_max - 1, w.available);

    try testing.expectEqual(
        errors.Fault{ .code = .flow_control_error, .scope = .stream },
        errors.classify(error.WindowOverflow, got.header.stream_id),
    );
}

test "RFC 9113 section 4.1, an unknown frame type is ignored and never refused" {
    const gpa = testing.allocator;
    var fr: FrameReader = try .init(gpa, .{});
    defer fr.deinit(gpa);

    // Every type from 0x0a to 0xff is past the table of section 6.
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(gpa);

    var t: u16 = 0x0a;
    while (t <= 0xff) : (t += 1) {
        var head: [frame.header_len]u8 = undefined;
        (Header{
            .length = 1,
            .type = @enumFromInt(@as(u8, @intCast(t))),
            .flags = 0xff,
            .stream_id = 1,
        }).encode(&head);
        try bytes.appendSlice(gpa, &head);
        try bytes.append(gpa, 0x2a);
    }
    // A frame this build does know, after all of them.
    var tail: [frame.header_len + 8]u8 = undefined;
    try bytes.appendSlice(
        gpa,
        (payload.Ping{ .opaque_data = .{ 0, 0, 0, 0, 0, 0, 0, 1 } }).encode(&tail),
    );

    var r: std.Io.Reader = .fixed(bytes.items);
    var seen: u32 = 0;
    while (seen < 0x100 - 0x0a) : (seen += 1) {
        const got = try fr.next(&r);
        try testing.expectEqualSlices(u8, &.{0x2a}, got.payload.unknown);
    }
    try testing.expectEqual(@as(u64, 0x100 - 0x0a), fr.unknown_frames);

    const ping = try fr.next(&r);
    try testing.expectEqual(frame.Type.ping, ping.header.type);
    try testing.expectError(error.EndOfStream, fr.next(&r));
}

test "a stream error leaves the connection up, and a connection error does not" {
    // RFC 9113 section 5.4. The two are separate on purpose: a
    // connection error handled as a stream error leaves a peer that
    // already broke the framing free to keep sending.
    const stream_faults = [_]errors.Error{
        error.WindowUpdateZero,
        error.WindowOverflow,
        error.PriorityLengthInvalid,
        // **The one fault in this set that the peer did not cause.** A
        // send asked for more octets than the flow control window held,
        // and the count came from this side. It takes a scope all the
        // same, because the connection cannot go on either way, and it
        // carries `internal_error` rather than `flow_control_error` so the
        // code does not tell the peer it broke a rule it kept. See
        // `zurl_h2.window.Window.consume`, where this was an assert that
        // the shipped build compiled out.
        error.FlowControlExceeded,
    };
    for (stream_faults) |err| {
        try testing.expectEqual(errors.Scope.stream, errors.classify(err, 1).scope);
    }

    const connection_faults = [_]errors.Error{
        error.FrameTooLarge,
        error.PayloadTruncated,
        error.StreamIdZero,
        error.StreamIdNonZero,
        error.PadLengthTooLong,
        error.SettingsLengthInvalid,
        error.SettingsAckNotEmpty,
        error.SettingsEnablePushInvalid,
        error.SettingsInitialWindowSizeInvalid,
        error.SettingsMaxFrameSizeInvalid,
        error.PingLengthInvalid,
        error.RstStreamLengthInvalid,
        error.GoawayLengthInvalid,
        error.WindowUpdateLengthInvalid,
        error.ContinuationExpected,
        error.ContinuationStreamMismatch,
        error.ContinuationUnexpected,
        error.ContinuationFlood,
        error.HeaderBlockTooLarge,
        error.BadPreface,
    };
    for (connection_faults) |err| {
        try testing.expectEqual(errors.Scope.connection, errors.classify(err, 1).scope);
    }

    // The two lists together are the whole error set, so no fault is
    // left without a scope.
    const total = stream_faults.len + connection_faults.len;
    try testing.expectEqual(@typeInfo(errors.Error).error_set.?.len, total);
}

test "nothing in this package allocates without a bound" {
    const gpa = testing.allocator;

    // The payload buffer is the one allocation, and its size is the
    // frame size this endpoint advertised. A peer cannot change it.
    var fr: FrameReader = try .init(gpa, .{ .max_frame_size = settings.max_frame_size_min });
    defer fr.deinit(gpa);
    try testing.expectEqual(@as(usize, settings.max_frame_size_min), fr.buffer.len);

    // A peer's SETTINGS_MAX_FRAME_SIZE lands in a `Settings` value and
    // changes nothing about this reader. Only this endpoint's own call
    // to `setMaxFrameSize` does that.
    const bytes = [_]u8{
        0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x05, 0x00, 0xff, 0xff, 0xff,
    };
    var r: std.Io.Reader = .fixed(&bytes);
    const got = try fr.next(&r);
    var peer: settings.Settings = .initial;
    _ = try got.payload.settings.applyTo(&peer);
    try testing.expectEqual(@as(u24, 0x00ffffff), peer.max_frame_size);
    try testing.expectEqual(@as(usize, settings.max_frame_size_min), fr.buffer.len);
    try testing.expectEqual(@as(u24, settings.max_frame_size_min), fr.max_frame_size);
}
