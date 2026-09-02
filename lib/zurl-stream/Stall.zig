//! A reader that stops a transfer which has gone too slow for too long.
//!
//! This is `--speed-limit` and `--speed-time` in curl. The rule is a pure
//! function, so the table below tests it with no clock. The decorator only
//! measures and forwards.
//!
//! A stall is not reported on the call that finds it. The bytes that call
//! already pulled from the source have reached the destination, so this
//! returns them honestly and sets `timed_out`. The next call reports the
//! stall, before it touches the source again. This keeps a decorator
//! stacked above (a `Progress`, say) in agreement with what actually left
//! the source: no byte the source delivered is ever missing from its count.

const Stall = @This();

const std = @import("std");
const Io = std.Io;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const Limit = std.Io.Limit;

const ns_per_s = std.time.ns_per_s;

/// The reader that this decorator wraps.
source: *Reader,
io: Io,
/// The slowest acceptable rate, in bytes each second. Zero turns the watchdog
/// off.
low_speed_limit: u64,
/// How long the rate may stay below the limit, in nanoseconds. Zero turns the
/// watchdog off.
low_speed_time_ns: u64,
/// When the current window opened.
window_start: Io.Timestamp,
/// How many bytes have arrived since the window opened.
window_bytes: u64,
/// True once the watchdog has judged the transfer too slow.
///
/// The call that first finds the stall still delivers the bytes it already
/// read, honestly, and only sets this. The transfer actually stops on the
/// next call, which reports the stall before it reads the source again.
///
/// `interface` can only return `error.ReadFailed`, which says nothing about
/// the reason. The caller reads the reason here. Recovery is never silent.
///
/// This flag latches: once true, it never returns to false. It also gates
/// every call after the one that set it: `stream` and `discard` check it
/// first and fail immediately, without touching `source` again, for the
/// rest of the `Stall`'s life. A caller that stops calling `interface` once
/// this is true will see no further bytes leave `source`. A caller that
/// keeps calling will see `error.ReadFailed` every time, never a byte more,
/// and `timed_out` (and `check`) stay accurate forever after: unlike
/// `Throttle.canceled`, which describes only the most recent wait, no later
/// call can change this answer.
timed_out: bool,
/// The reader that the caller reads from.
interface: Reader,

/// A named error for a caller that wants more than `error.ReadFailed`.
pub const Error = error{
    /// The transfer ran below its rate for longer than its time limit.
    OperationTimedOut,
};

/// Turns a flagged `Stall` into `Error`.
///
/// `interface` cannot return `Error` itself: `std.Io.Reader`'s vtable fixes
/// its error set to `error.ReadFailed`. A caller that wants a named error
/// instead of reading `timed_out` by hand calls this after `interface`
/// fails.
pub fn check(s: *const Stall) Error!void {
    if (s.timed_out) return error.OperationTimedOut;
}

/// Returns true when the transfer has been too slow for too long.
///
/// A window shorter than `low_speed_time_ns` is never stalled, because there
/// is not yet enough evidence. A `low_speed_limit` or a `low_speed_time_ns` of
/// zero turns the watchdog off.
///
/// This is a pure function so that the rule has a table test and needs no
/// clock.
pub fn stalled(
    bytes: u64,
    elapsed_ns: u64,
    low_speed_limit: u64,
    low_speed_time_ns: u64,
) bool {
    if (low_speed_limit == 0) return false;
    if (low_speed_time_ns == 0) return false;
    if (elapsed_ns < low_speed_time_ns) return false;

    // Compare rates without a division, so an integer rate does not round.
    const needed = @as(u128, low_speed_limit) * elapsed_ns / ns_per_s;
    return @as(u128, bytes) < needed;
}

/// Wraps `source` and watches its rate.
///
/// `low_speed_time_s` is in seconds, because that is the unit that
/// `--speed-time` uses.
pub fn init(
    source: *Reader,
    io: Io,
    low_speed_limit: u64,
    low_speed_time_s: u32,
    buffer: []u8,
) Stall {
    return .{
        .source = source,
        .io = io,
        .low_speed_limit = low_speed_limit,
        .low_speed_time_ns = @as(u64, low_speed_time_s) * ns_per_s,
        .window_start = Io.Timestamp.now(io, .awake),
        .window_bytes = 0,
        .timed_out = false,
        .interface = .{
            .vtable = &.{ .stream = stream, .discard = discard },
            .buffer = buffer,
            .seek = 0,
            .end = 0,
        },
    };
}

fn stream(r: *Reader, w: *Writer, limit: Limit) Reader.StreamError!usize {
    const s: *Stall = @alignCast(@fieldParentPtr("interface", r));
    // A stall found on an earlier call is reported here, before the source
    // is read again. See the file comment and `account`.
    if (s.timed_out) return error.ReadFailed;
    const n = try s.source.stream(w, limit);
    s.account(n);
    return n;
}

fn discard(r: *Reader, limit: Limit) Reader.Error!usize {
    const s: *Stall = @alignCast(@fieldParentPtr("interface", r));
    if (s.timed_out) return error.ReadFailed;
    const n = try s.source.discard(limit);
    s.account(n);
    return n;
}

/// Adds `n` to the window and decides whether the transfer has stalled.
///
/// A window that is fast enough restarts, so one slow patch after a fast one
/// does not carry old evidence.
///
/// This never returns an error, even when it finds a stall. `n` bytes have
/// already reached the destination by the time this runs, and `stream` and
/// `discard` have already committed to returning `n` for this call. Setting
/// `timed_out` here, instead of failing here, is what lets those `n` bytes
/// stay in the caller's count. The error comes back on the next call.
fn account(s: *Stall, n: usize) void {
    s.window_bytes += n;

    // Zero on either setting means the watchdog is off. Skip the clock
    // entirely, not only the comparison: `stalled` would say `false` anyway,
    // but there is no reason to pay for a timestamp nobody will use.
    if (s.low_speed_limit == 0 or s.low_speed_time_ns == 0) return;

    const now = Io.Timestamp.now(s.io, .awake);
    const elapsed = s.window_start.durationTo(now);
    const elapsed_ns: u64 = @intCast(@max(elapsed.nanoseconds, 0));

    if (stalled(s.window_bytes, elapsed_ns, s.low_speed_limit, s.low_speed_time_ns)) {
        s.timed_out = true;
        return;
    }

    if (elapsed_ns >= s.low_speed_time_ns) {
        s.window_start = now;
        s.window_bytes = 0;
    }
}

test "a transfer under the time limit never counts as stalled" {
    // Zero bytes, but only five seconds of a thirty second window.
    try std.testing.expectEqual(false, stalled(0, 5 * ns_per_s, 100, 30 * ns_per_s));
}

test "a transfer at the limit for the whole window is not stalled" {
    // 3000 bytes over thirty seconds is exactly 100 each second.
    try std.testing.expectEqual(false, stalled(3000, 30 * ns_per_s, 100, 30 * ns_per_s));
}

test "a transfer under the limit for the whole window is stalled" {
    try std.testing.expectEqual(true, stalled(2999, 30 * ns_per_s, 100, 30 * ns_per_s));
}

test "a limit of zero turns the watchdog off" {
    try std.testing.expectEqual(false, stalled(0, 3600 * ns_per_s, 0, 30 * ns_per_s));
}

test "a time of zero turns the watchdog off" {
    try std.testing.expectEqual(false, stalled(0, 3600 * ns_per_s, 100, 0));
}

test "the decorator passes the bytes through when the transfer is fast enough" {
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var s: Stall = .init(&source, std.testing.io, 1, 30, &buf);

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    const n = try s.interface.stream(&sink, .limited(7));
    try std.testing.expectEqual(@as(usize, 7), n);
    try std.testing.expectEqualStrings("payload", out[0..7]);
}

test "the decorator counts the bytes in its window" {
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    // A thirty second window, so no restart happens during this test.
    var s: Stall = .init(&source, std.testing.io, 1, 30, &buf);

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    _ = try s.interface.stream(&sink, .limited(4));
    try std.testing.expectEqual(@as(u64, 4), s.window_bytes);
    try std.testing.expectEqual(false, s.timed_out);
}

test "the watchdog stops a transfer that has been too slow for its whole window" {
    var source: Reader = .fixed("x");
    var buf: [8]u8 = undefined;
    // A huge limit and a one second window, so a single byte can never keep
    // up.
    var s: Stall = .init(&source, std.testing.io, 1_000_000_000, 1, &buf);
    // Back-date the window by an hour. This is deterministic: the gap
    // dwarfs any wall-clock time the test itself could spend, so the window
    // reads as expired no matter the clock's resolution or the machine's
    // speed, unlike waiting for a real clock tick to land during the read.
    s.window_start = s.window_start.subDuration(.fromNanoseconds(3600 * ns_per_s));

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);

    // The byte that made the window fail its rate still comes through.
    const n = try s.interface.stream(&sink, .limited(1));
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqualStrings("x", out[0..1]);
    try std.testing.expectEqual(true, s.timed_out);

    // Only the next call reports the stall, and it does that without
    // reading the source again, which by now holds nothing left to give.
    try std.testing.expectError(error.ReadFailed, s.interface.stream(&sink, .limited(1)));
    try std.testing.expectEqual(true, s.timed_out);
}

test "check succeeds while the transfer has not stalled" {
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var s: Stall = .init(&source, std.testing.io, 1, 30, &buf);
    try s.check();
}

test "check turns a flagged stall into the named error" {
    var source: Reader = .fixed("x");
    var buf: [8]u8 = undefined;
    var s: Stall = .init(&source, std.testing.io, 1_000_000_000, 1, &buf);
    s.window_start = s.window_start.subDuration(.fromNanoseconds(3600 * ns_per_s));

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    _ = try s.interface.stream(&sink, .limited(1));

    try std.testing.expectError(error.OperationTimedOut, s.check());
}

test "a low_speed_limit of zero turns the decorator's watchdog off" {
    var source: Reader = .fixed("x");
    var buf: [8]u8 = undefined;
    var s: Stall = .init(&source, std.testing.io, 0, 1, &buf);
    // Even a window that looks ancient must not trip the watchdog while it
    // is off.
    s.window_start = s.window_start.subDuration(.fromNanoseconds(3600 * ns_per_s));

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    const n = try s.interface.stream(&sink, .limited(1));
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(false, s.timed_out);
}

test "a low_speed_time of zero turns the decorator's watchdog off" {
    var source: Reader = .fixed("x");
    var buf: [8]u8 = undefined;
    var s: Stall = .init(&source, std.testing.io, 1_000_000_000, 0, &buf);

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    const n = try s.interface.stream(&sink, .limited(1));
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(false, s.timed_out);
}

// `peek`, `readSliceAll`, and `takeByte` reach `stream` through
// `std.Io.Reader.fill`, which may call `stream` with a `Writer` that views
// this decorator's own `buffer`. `Stall.stream` forwards `w` straight to
// `s.source.stream`, with no intermediate copy, so unlike `Hashing` it never
// had the aliasing bug: the tests below pin that the buffered API works and
// keeps counting correctly, so the gap does not reopen unnoticed if
// `stream` ever grows a copy step.

test "peek forwards through the buffered Reader API and still counts" {
    var source: Reader = .fixed("payload");
    // A buffer sized to exactly what `peek` asks for, so `fill` pulls
    // exactly 3 bytes in one call instead of opportunistically grabbing
    // more of the source into extra buffer capacity.
    var buf: [3]u8 = undefined;
    var s: Stall = .init(&source, std.testing.io, 1, 30, &buf);

    const peeked = try s.interface.peek(3);
    try std.testing.expectEqualStrings("pay", peeked);
    try std.testing.expectEqual(@as(u64, 3), s.window_bytes);
}

test "readSliceAll forwards through the buffered Reader API and still counts" {
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var s: Stall = .init(&source, std.testing.io, 1, 30, &buf);

    var out: [7]u8 = undefined;
    try s.interface.readSliceAll(&out);
    try std.testing.expectEqualStrings("payload", &out);
    try std.testing.expectEqual(@as(u64, 7), s.window_bytes);
}

test "takeByte forwards through the buffered Reader API and still counts" {
    var source: Reader = .fixed("ab");
    var buf: [4]u8 = undefined;
    var s: Stall = .init(&source, std.testing.io, 1, 30, &buf);

    try std.testing.expectEqual(@as(u8, 'a'), try s.interface.takeByte());
    try std.testing.expectEqual(@as(u8, 'b'), try s.interface.takeByte());
    try std.testing.expectEqual(@as(u64, 2), s.window_bytes);
}

/// A reader whose `stream` and `discard` always fail, standing in for a
/// socket that drops mid-transfer. Every other source in this file is
/// `Reader.fixed`, which can only ever end the stream, never fail it, so
/// nothing else here pins that a failed read leaves `window_bytes` and
/// `timed_out` honest.
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

test "a failed source stream leaves window_bytes and timed_out exactly where they were" {
    var failing: FailingReader = .init();
    var buf: [8]u8 = undefined;
    var s: Stall = .init(&failing.reader, std.testing.io, 1, 30, &buf);

    var out: [8]u8 = undefined;
    var sink: Writer = .fixed(&out);
    try std.testing.expectError(error.ReadFailed, s.interface.stream(&sink, .limited(4)));
    try std.testing.expectEqual(@as(u64, 0), s.window_bytes);
    try std.testing.expectEqual(false, s.timed_out);
}

test "a failed source discard leaves window_bytes and timed_out exactly where they were" {
    var failing: FailingReader = .init();
    var buf: [8]u8 = undefined;
    var s: Stall = .init(&failing.reader, std.testing.io, 1, 30, &buf);

    try std.testing.expectError(error.ReadFailed, s.interface.discard(.limited(4)));
    try std.testing.expectEqual(@as(u64, 0), s.window_bytes);
    try std.testing.expectEqual(false, s.timed_out);
}

test "a discard counts the same as a stream" {
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var s: Stall = .init(&source, std.testing.io, 1, 30, &buf);

    const n = try s.interface.discard(.limited(4));
    try std.testing.expectEqual(@as(usize, 4), n);
    try std.testing.expectEqual(@as(u64, 4), s.window_bytes);
    try std.testing.expectEqual(false, s.timed_out);
}
