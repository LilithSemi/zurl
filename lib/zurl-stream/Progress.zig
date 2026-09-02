//! A reader that counts the bytes that pass through it and tells a reporter.
//!
//! Wrap a body reader in this to get transfer progress. The decorator adds no
//! copy, because it forwards to the source reader.

const Progress = @This();

const std = @import("std");
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const Limit = std.Io.Limit;

/// Something that wants to hear how far a transfer has gone.
///
/// The function pointer is `callconv(.c)` so that the bindings phase can pass
/// a C callback straight through with no shim.
pub const Reporter = struct {
    ctx: *anyopaque,
    /// `total` is zero when the length is not known.
    report: *const fn (ctx: *anyopaque, transferred: u64, total: u64) callconv(.c) void,
};

/// The reader that this decorator wraps.
source: *Reader,
/// Who to tell. A null reporter makes the decorator a plain counter.
reporter: ?Reporter,
/// The expected length, or zero when it is not known.
total: u64,
/// How many bytes have passed through so far.
transferred: u64,
/// The reader that the caller reads from.
interface: Reader,

/// Wraps `source`.
///
/// `buffer` may be empty. The decorator holds no data of its own, so a buffer
/// is only useful when the caller wants to ask for contiguous memory.
pub fn init(source: *Reader, reporter: ?Reporter, total: u64, buffer: []u8) Progress {
    return .{
        .source = source,
        .reporter = reporter,
        .total = total,
        .transferred = 0,
        .interface = .{
            .vtable = &.{ .stream = stream, .discard = discard },
            .buffer = buffer,
            .seek = 0,
            .end = 0,
        },
    };
}

fn stream(r: *Reader, w: *Writer, limit: Limit) Reader.StreamError!usize {
    const p: *Progress = @fieldParentPtr("interface", r);
    const n = try p.source.stream(w, limit);
    p.advance(n);
    return n;
}

fn discard(r: *Reader, limit: Limit) Reader.Error!usize {
    const p: *Progress = @fieldParentPtr("interface", r);
    const n = try p.source.discard(limit);
    p.advance(n);
    return n;
}

/// Adds `n` to the count and tells the reporter.
fn advance(p: *Progress, n: usize) void {
    p.transferred += n;
    const reporter = p.reporter orelse return;
    reporter.report(reporter.ctx, p.transferred, p.total);
}

/// Collects the calls that a test's reporter receives.
const Recorder = struct {
    calls: u32 = 0,
    last_transferred: u64 = 0,
    last_total: u64 = 0,

    fn report(ctx: *anyopaque, transferred: u64, total: u64) callconv(.c) void {
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        self.last_transferred = transferred;
        self.last_total = total;
    }

    fn reporter(self: *Recorder) Reporter {
        return .{ .ctx = self, .report = report };
    }
};

test "the decorator passes the bytes through unchanged" {
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var progress: Progress = .init(&source, null, 7, &buf);

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    const n = try progress.interface.stream(&sink, .limited(7));

    try std.testing.expectEqual(@as(usize, 7), n);
    try std.testing.expectEqualStrings("payload", out[0..7]);
}

test "the decorator counts every byte that it forwards" {
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var progress: Progress = .init(&source, null, 7, &buf);

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    _ = try progress.interface.stream(&sink, .limited(4));
    try std.testing.expectEqual(@as(u64, 4), progress.transferred);
    _ = try progress.interface.stream(&sink, .limited(3));
    try std.testing.expectEqual(@as(u64, 7), progress.transferred);
}

test "the reporter receives the running count and the total" {
    var recorder: Recorder = .{};
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var progress: Progress = .init(&source, recorder.reporter(), 7, &buf);

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    _ = try progress.interface.stream(&sink, .limited(4));

    try std.testing.expectEqual(@as(u32, 1), recorder.calls);
    try std.testing.expectEqual(@as(u64, 4), recorder.last_transferred);
    try std.testing.expectEqual(@as(u64, 7), recorder.last_total);
}

test "a discard counts the same as a read" {
    var recorder: Recorder = .{};
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var progress: Progress = .init(&source, recorder.reporter(), 7, &buf);

    _ = try progress.interface.discard(.limited(4));
    try std.testing.expectEqual(@as(u64, 4), progress.transferred);
    try std.testing.expectEqual(@as(u64, 4), recorder.last_transferred);
}

test "a total of zero means the length is unknown and reaches the reporter as zero" {
    var recorder: Recorder = .{};
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var progress: Progress = .init(&source, recorder.reporter(), 0, &buf);

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    _ = try progress.interface.stream(&sink, .limited(4));
    try std.testing.expectEqual(@as(u64, 0), recorder.last_total);
}

test "the end of the source reaches the caller" {
    var source: Reader = .fixed("ab");
    var buf: [8]u8 = undefined;
    var progress: Progress = .init(&source, null, 2, &buf);

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    _ = try progress.interface.stream(&sink, .limited(2));
    try std.testing.expectError(error.EndOfStream, progress.interface.stream(&sink, .limited(1)));
}

test "a short read counts only the bytes the source actually gave, not the bytes requested" {
    var source: Reader = .fixed("ab");
    var buf: [8]u8 = undefined;
    var progress: Progress = .init(&source, null, 2, &buf);

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    // The source holds only two bytes. Ask for ten anyway.
    const n = try progress.interface.stream(&sink, .limited(10));

    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqual(@as(u64, 2), progress.transferred);
}

// `peek`, `readSliceAll`, and `takeByte` reach `stream` through
// `std.Io.Reader.fill`, which may call `stream` with a `Writer` that views
// this decorator's own `buffer`. Every other test in this file drives
// `stream` and `discard` directly, so none of them exercise that path.
// `Progress.stream` forwards `w` straight to `p.source.stream`, with no
// intermediate copy, so unlike `Hashing` it never had the aliasing bug: the
// tests below pin that the buffered API works and keeps counting correctly,
// so the gap does not reopen unnoticed if `stream` ever grows a copy step.

test "peek forwards through the buffered Reader API and still counts" {
    var source: Reader = .fixed("payload");
    // A buffer sized to exactly what `peek` asks for, so `fill` pulls
    // exactly 3 bytes in one call instead of opportunistically grabbing
    // more of the source into extra buffer capacity.
    var buf: [3]u8 = undefined;
    var progress: Progress = .init(&source, null, 7, &buf);

    const peeked = try progress.interface.peek(3);
    try std.testing.expectEqualStrings("pay", peeked);
    try std.testing.expectEqual(@as(u64, 3), progress.transferred);
}

test "readSliceAll forwards through the buffered Reader API and still counts" {
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var progress: Progress = .init(&source, null, 7, &buf);

    var out: [7]u8 = undefined;
    try progress.interface.readSliceAll(&out);
    try std.testing.expectEqualStrings("payload", &out);
    try std.testing.expectEqual(@as(u64, 7), progress.transferred);
}

test "takeByte forwards through the buffered Reader API and still counts" {
    var source: Reader = .fixed("ab");
    var buf: [4]u8 = undefined;
    var progress: Progress = .init(&source, null, 2, &buf);

    try std.testing.expectEqual(@as(u8, 'a'), try progress.interface.takeByte());
    try std.testing.expectEqual(@as(u8, 'b'), try progress.interface.takeByte());
    try std.testing.expectEqual(@as(u64, 2), progress.transferred);
}

/// A reader whose `stream` and `discard` always fail, standing in for a
/// socket that drops mid-transfer. Every other source in this file is
/// `Reader.fixed`, which can only ever end the stream, never fail it, so
/// nothing else here pins that a failed read leaves `transferred` honest.
const FailingReader = struct {
    reader: Reader,

    fn init() FailingReader {
        return .{ .reader = .{
            .vtable = &.{ .stream = failStream, .discard = failDiscard },
            .buffer = &.{},
            .seek = 0,
            .end = 0,
        } };
    }

    fn failStream(r: *Reader, w: *Writer, limit: Limit) Reader.StreamError!usize {
        _ = r;
        _ = w;
        _ = limit;
        return error.ReadFailed;
    }

    fn failDiscard(r: *Reader, limit: Limit) Reader.Error!usize {
        _ = r;
        _ = limit;
        return error.ReadFailed;
    }
};

test "a failed source stream leaves transferred exactly where it was" {
    var failing: FailingReader = .init();
    var buf: [8]u8 = undefined;
    var progress: Progress = .init(&failing.reader, null, 0, &buf);

    var out: [8]u8 = undefined;
    var sink: Writer = .fixed(&out);
    try std.testing.expectError(error.ReadFailed, progress.interface.stream(&sink, .limited(4)));
    try std.testing.expectEqual(@as(u64, 0), progress.transferred);
}

test "a failed source discard leaves transferred exactly where it was" {
    var failing: FailingReader = .init();
    var buf: [8]u8 = undefined;
    var progress: Progress = .init(&failing.reader, null, 0, &buf);

    try std.testing.expectError(error.ReadFailed, progress.interface.discard(.limited(4)));
    try std.testing.expectEqual(@as(u64, 0), progress.transferred);
}

test "the reporter sees the running total grow across separate calls, not reset" {
    var recorder: Recorder = .{};
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var progress: Progress = .init(&source, recorder.reporter(), 7, &buf);

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    _ = try progress.interface.stream(&sink, .limited(4));
    _ = try progress.interface.stream(&sink, .limited(3));

    try std.testing.expectEqual(@as(u32, 2), recorder.calls);
    try std.testing.expectEqual(@as(u64, 7), recorder.last_transferred);
    try std.testing.expectEqual(@as(u64, 7), recorder.last_total);
}
