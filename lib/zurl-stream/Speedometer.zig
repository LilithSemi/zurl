//! A reader that measures the transfer rate of the bytes that pass through it.
//!
//! Wrap a body reader in this to get a live bytes-per-second figure for a
//! progress meter. The decorator only counts and forwards; `rate` turns a
//! byte count and an elapsed time into bytes per second, with no clock of its
//! own, so the rule has a table test.

const Speedometer = @This();

const std = @import("std");
const Io = std.Io;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const Limit = std.Io.Limit;

const ns_per_s = std.time.ns_per_s;

/// The reader that this decorator wraps.
source: *Reader,
io: Io,
/// How many bytes have passed through so far.
transferred: u64,
/// When the transfer started.
started: Io.Timestamp,
/// The reader that the caller reads from.
interface: Reader,

/// Wraps `source`.
///
/// `buffer` may be empty. The decorator holds no data of its own, so a buffer
/// is only useful when the caller wants to ask for contiguous memory.
pub fn init(source: *Reader, io: Io, buffer: []u8) Speedometer {
    return .{
        .source = source,
        .io = io,
        .transferred = 0,
        .started = Io.Timestamp.now(io, .awake),
        .interface = .{
            .vtable = &.{ .stream = stream, .discard = discard },
            .buffer = buffer,
            .seek = 0,
            .end = 0,
        },
    };
}

fn stream(r: *Reader, w: *Writer, limit: Limit) Reader.StreamError!usize {
    const s: *Speedometer = @alignCast(@fieldParentPtr("interface", r));
    const n = try s.source.stream(w, limit);
    s.transferred += n;
    return n;
}

fn discard(r: *Reader, limit: Limit) Reader.Error!usize {
    const s: *Speedometer = @alignCast(@fieldParentPtr("interface", r));
    const n = try s.source.discard(limit);
    s.transferred += n;
    return n;
}

/// Returns how long the transfer has run, in nanoseconds.
pub fn elapsedNs(s: *const Speedometer) u64 {
    const now = Io.Timestamp.now(s.io, .awake);
    const elapsed = s.started.durationTo(now);
    return @intCast(@max(elapsed.nanoseconds, 0));
}

/// Returns the transfer's average rate so far, in bytes per second.
pub fn bytesPerSecond(s: *const Speedometer) u64 {
    return rate(s.transferred, s.elapsedNs());
}

/// Turns a byte count and an elapsed time into bytes per second.
///
/// An `elapsed_ns` of zero reports zero rather than dividing by zero: no
/// time has passed, so no rate is known yet. The intermediate is wider than
/// `u64`, because `bytes * ns_per_s` overflows a `u64` well before `bytes`
/// reaches `maxInt(u64)`.
///
/// This is a pure function so that the rule has a table test and needs no
/// clock.
pub fn rate(bytes: u64, elapsed_ns: u64) u64 {
    if (elapsed_ns == 0) return 0;
    const scaled: u128 = @as(u128, bytes) * ns_per_s / elapsed_ns;
    return @intCast(@min(scaled, std.math.maxInt(u64)));
}

test "a rate over a whole second is the byte count" {
    try std.testing.expectEqual(@as(u64, 1000), rate(1000, std.time.ns_per_s));
}

test "a rate over half a second is twice the byte count" {
    try std.testing.expectEqual(@as(u64, 2000), rate(1000, std.time.ns_per_s / 2));
}

test "a rate over two seconds is half the byte count" {
    try std.testing.expectEqual(@as(u64, 500), rate(1000, 2 * std.time.ns_per_s));
}

test "no elapsed time reports no rate rather than dividing by zero" {
    try std.testing.expectEqual(@as(u64, 0), rate(1000, 0));
}

test "a very large byte count saturates the rate instead of overflowing it" {
    // The intermediate must be wider than u64. maxInt(u64) bytes in one
    // nanosecond is absurd, and it must still return a number, not trap.
    // The number is the largest a u64 holds, because the real answer is
    // a billion times larger than that.
    const max = std.math.maxInt(u64);
    try std.testing.expectEqual(max, rate(max, 1));
    // The same byte count over a whole second needs no clamping at all,
    // so the two together check the saturation from both sides.
    try std.testing.expectEqual(max, rate(max, std.time.ns_per_s));
    try std.testing.expectEqual(@as(u64, max / 2), rate(max, 2 * std.time.ns_per_s));
}

test "the decorator counts the bytes that pass through it" {
    var source: std.Io.Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var s: Speedometer = .init(&source, std.testing.io, &buf);
    var out: [16]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&out);
    _ = try s.interface.stream(&sink, .limited(7));
    try std.testing.expectEqual(@as(u64, 7), s.transferred);
}

test "the decorator passes the bytes through unchanged" {
    var source: std.Io.Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var s: Speedometer = .init(&source, std.testing.io, &buf);
    var out: [16]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&out);
    const n = try s.interface.stream(&sink, .limited(7));
    try std.testing.expectEqualStrings("payload", out[0..n]);
}

test "a discard counts the same as a read" {
    var source: std.Io.Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var s: Speedometer = .init(&source, std.testing.io, &buf);
    _ = try s.interface.discard(.limited(4));
    try std.testing.expectEqual(@as(u64, 4), s.transferred);
}
