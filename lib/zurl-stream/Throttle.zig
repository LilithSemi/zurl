//! A reader that holds a transfer to a maximum number of bytes each second.
//!
//! This is a token bucket. The bucket holds one second's worth of bytes. It
//! never resets. It only ever refills. A caller can see up to one
//! `bytes_per_second` worth of bytes right away, since the bucket starts
//! full. That is the burst capacity, not a leak. Sustained throughput still
//! settles to `bytes_per_second`.
//!
//! The rule is a pure function, so the table below tests it with no clock. The
//! decorator sleeps and forwards, and one test measures that it really waits.

const Throttle = @This();

const std = @import("std");
const Io = std.Io;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const Limit = std.Io.Limit;

const ns_per_s = std.time.ns_per_s;

/// The reader that this decorator wraps.
source: *Reader,
io: Io,
/// The limit. Zero means no limit.
bytes_per_second: u64,
/// When the window opened. This never changes after `init`: the bucket
/// refills for the life of the decorator instead of resetting.
window_start: Io.Timestamp,
/// How many bytes have gone out since the window opened.
window_bytes: u64,
/// True when the wait of the most recent read was canceled.
///
/// `interface` can only return `error.ReadFailed`, which says nothing about
/// the reason. The caller reads the reason here. Recovery is never silent.
///
/// **This flag describes one call, not the whole transfer.** `wait` sets it
/// true when a cancel ends the sleep, and false as soon as a later `wait`
/// finishes on its own. It does not latch, and it does not gate later
/// calls: `stream` and `discard` never check it before reading `source`
/// again, so a call made after a cancellation can still succeed, and that
/// call clears the flag.
///
/// It said the opposite here for two phases. The doc said the flag latched
/// and never returned to false, and `zurl.body.Stack` cleared it at four
/// places to stop a stale `true` from outranking a later, unrelated
/// failure. The code was right and the doc was wrong: a `canceled` that
/// latches makes every failure for the rest of the transfer read as
/// `AbortedByCallback`. The rule now lives here, beside the wait that is
/// the only thing able to decide it, instead of in four places one layer
/// up.
///
/// A caller still reads `canceled`, or calls `check`, right after
/// `interface` returns `error.ReadFailed`, and not as a general poll: the
/// next read overwrites the answer.
canceled: bool,
/// The reader that the caller reads from.
interface: Reader,

/// A named error for a caller that wants more than `error.ReadFailed`.
pub const Error = error{
    /// A wait for the bucket to refill was canceled.
    Canceled,
};

/// Turns a flagged `Throttle` into `Error`.
///
/// `interface` cannot return `Error` itself: `std.Io.Reader`'s vtable fixes
/// its error set to `error.ReadFailed`. A caller that wants a named error
/// instead of reading `canceled` by hand calls this after `interface` fails.
///
/// See `canceled`'s doc comment: this must be called right after `interface`
/// returns `error.ReadFailed`, not as a general poll. `canceled` describes
/// the most recent wait only, so the next read overwrites the answer this
/// would give.
pub fn check(t: *const Throttle) Error!void {
    if (t.canceled) return error.Canceled;
}

/// Returns how many more bytes the window allows right now.
///
/// This is a token bucket. The bucket holds `bytes_per_second` tokens and
/// refills at `bytes_per_second` tokens each second, without limit, for as
/// long as the window has been open. `elapsed_ns` is that time. `sent` is
/// the number of bytes that have gone out since the window opened. A rate
/// of zero means no limit.
///
/// The bucket starts full, so a caller can see up to one `bytes_per_second`
/// worth of bytes immediately. That is the burst capacity, not a bug: it is
/// the one-time cost of starting with a full bucket. The result is capped
/// at `bytes_per_second` so that a caller can never see more than one
/// second's burst in a single answer, even after a long idle spell has let
/// the bucket earn a large surplus.
///
/// This is a pure function so that the rule has a table test and needs no
/// clock.
pub fn allowance(bytes_per_second: u64, elapsed_ns: u64, sent: u64) u64 {
    if (bytes_per_second == 0) return std.math.maxInt(u64);

    // What the elapsed time has earned. Not capped: the window never
    // resets, so the bucket keeps refilling for as long as it has been
    // open. Capping this is what forced the window reset to exist.
    const earned: u128 = @as(u128, bytes_per_second) * elapsed_ns / ns_per_s;

    // The budget is the starting bucket plus everything earned since.
    const budget: u128 = @as(u128, bytes_per_second) + earned;

    if (budget <= @as(u128, sent)) return 0;
    return @intCast(@min(budget - @as(u128, sent), bytes_per_second));
}

/// Wraps `source` and holds it to `bytes_per_second`.
///
/// A `bytes_per_second` of zero means no limit, which is what curl does with
/// `--limit-rate 0`.
pub fn init(source: *Reader, io: Io, bytes_per_second: u64, buffer: []u8) Throttle {
    return .{
        .source = source,
        .io = io,
        .bytes_per_second = bytes_per_second,
        .window_start = Io.Timestamp.now(io, .awake),
        .window_bytes = 0,
        .canceled = false,
        .interface = .{
            .vtable = &.{ .stream = stream, .discard = discard },
            .buffer = buffer,
            .seek = 0,
            .end = 0,
        },
    };
}

fn stream(r: *Reader, w: *Writer, limit: Limit) Reader.StreamError!usize {
    const t: *Throttle = @alignCast(@fieldParentPtr("interface", r));
    const allowed = t.wait(limit) catch {
        // The reader interface has one read error. The caller reads the real
        // reason from the `Throttle` itself.
        t.canceled = true;
        return error.ReadFailed;
    };
    // The wait finished on its own, so nothing canceled this call. See
    // `canceled`: the flag describes the most recent wait, and this is now
    // the most recent wait.
    t.canceled = false;
    const n = try t.source.stream(w, allowed);
    t.window_bytes += n;
    return n;
}

fn discard(r: *Reader, limit: Limit) Reader.Error!usize {
    const t: *Throttle = @alignCast(@fieldParentPtr("interface", r));
    const allowed = t.wait(limit) catch {
        t.canceled = true;
        return error.ReadFailed;
    };
    // See `stream`'s matching comment.
    t.canceled = false;
    const n = try t.source.discard(allowed);
    t.window_bytes += n;
    return n;
}

/// Sleeps until the bucket allows at least one byte, then returns the limit
/// to use for this read.
///
/// The bucket never resets. When it is empty, this sleeps only long enough
/// to earn one more byte, then checks again, rather than waiting out a
/// fixed remainder of a second.
fn wait(t: *Throttle, limit: Limit) Io.Cancelable!Limit {
    if (t.bytes_per_second == 0) return limit;

    while (true) {
        const now = Io.Timestamp.now(t.io, .awake);
        const elapsed = t.window_start.durationTo(now);
        const elapsed_ns: u64 = @intCast(@max(elapsed.nanoseconds, 0));

        const allowed = allowance(t.bytes_per_second, elapsed_ns, t.window_bytes);
        if (allowed > 0) return limit.min(.limited64(allowed));

        // Nothing is available yet. The window never resets, so there is no
        // fixed remainder to sleep out. Sleep only long enough to earn one
        // more byte, then re-check.
        const ns_per_byte = (ns_per_s + t.bytes_per_second - 1) / t.bytes_per_second;
        try Io.sleep(t.io, .{ .nanoseconds = @intCast(ns_per_byte) }, .awake);
    }
}

test "a fresh window allows the whole rate" {
    try std.testing.expectEqual(@as(u64, 1000), allowance(1000, 0, 0));
}

test "the allowance falls as the window fills" {
    try std.testing.expectEqual(@as(u64, 400), allowance(1000, 0, 600));
}

test "a full window allows nothing" {
    try std.testing.expectEqual(@as(u64, 0), allowance(1000, 0, 1000));
}

test "an over-full window allows nothing rather than going below zero" {
    try std.testing.expectEqual(@as(u64, 0), allowance(1000, 0, 1500));
}

test "elapsed time adds back to the allowance" {
    // Half a second at 1000 bytes per second earns 500 bytes back.
    try std.testing.expectEqual(@as(u64, 500), allowance(1000, ns_per_s / 2, 1000));
}

test "a full second clears the window" {
    try std.testing.expectEqual(@as(u64, 1000), allowance(1000, ns_per_s, 1000));
}

test "more than a full second does not earn more than the rate" {
    try std.testing.expectEqual(@as(u64, 1000), allowance(1000, ns_per_s * 5, 1000));
}

test "a rate of zero means no limit" {
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), allowance(0, 0, 999_999));
}

test "the decorator passes the bytes through unchanged" {
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var t: Throttle = .init(&source, std.testing.io, 0, &buf);

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    const n = try t.interface.stream(&sink, .limited(7));
    try std.testing.expectEqual(@as(usize, 7), n);
    try std.testing.expectEqualStrings("payload", out[0..7]);
}

test "the decorator waits when the window is full" {
    const io = std.testing.io;
    var source: Reader = .fixed("aaaaaaaaaa");
    var buf: [16]u8 = undefined;
    // Five bytes each second. The bucket starts full, so the first read
    // takes the whole five-byte burst right away. That empties the bucket,
    // so the second read must wait about 200ms to earn one byte back.
    var t: Throttle = .init(&source, io, 5, &buf);

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);

    const started = Io.Timestamp.now(io, .awake);
    _ = try t.interface.stream(&sink, .limited(5));
    _ = try t.interface.stream(&sink, .limited(5));
    const elapsed = started.durationTo(Io.Timestamp.now(io, .awake));

    // A floor only, well under the real ~200ms wait, so a slow machine must
    // not fail this test. It still proves the decorator slept instead of
    // returning the second read immediately.
    try std.testing.expect(elapsed.nanoseconds >= @as(i96, 150 * std.time.ns_per_ms));
}

test "sustained reads never exceed the configured rate" {
    const io = std.testing.io;

    // A reader that asks for 40 bytes every 10ms, against a 1000 byte per
    // second limit, wants close to four times the allowed rate. A window
    // that resets and double-grants sustains close to double the configured
    // rate under this load. A real token bucket settles back down toward
    // it. This crosses at least one window boundary on purpose: the old
    // bug and the fix agree within a single window (see the fixed table
    // tests), and only diverge once the window would have reset.
    const bytes_per_second: u64 = 1000;
    const chunk: usize = 40;
    const total: usize = 3000;

    var payload: [total]u8 = undefined;
    @memset(&payload, 'a');
    var source: Reader = .fixed(&payload);
    var buf: [64]u8 = undefined;
    var t: Throttle = .init(&source, io, bytes_per_second, &buf);

    var out: [total]u8 = undefined;
    var sink: Writer = .fixed(&out);

    const started = Io.Timestamp.now(io, .awake);
    var delivered: usize = 0;
    while (delivered < total) {
        delivered += try t.interface.stream(&sink, .limited(chunk));
        try Io.sleep(io, .{ .nanoseconds = 10 * std.time.ns_per_ms }, .awake);
    }
    const elapsed = started.durationTo(Io.Timestamp.now(io, .awake));
    const elapsed_ns: u64 = @intCast(@max(elapsed.nanoseconds, 0));

    // delivered <= rate * (1 + elapsed_seconds), plus a small margin for
    // timing jitter. Anything over that means the limiter overshot.
    const bound_wide = @as(u128, bytes_per_second) * (ns_per_s + elapsed_ns) / ns_per_s + 100;
    const bound: u64 = @intCast(bound_wide);
    try std.testing.expect(delivered <= bound);
}

/// Runs the second read in its own task, so the test can cancel it while it
/// is blocked inside `wait`.
fn readSecondByte(t: *Throttle, sink: *Writer) Reader.StreamError!usize {
    return t.interface.stream(sink, .limited(1));
}

test "check succeeds while no wait has been canceled" {
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var t: Throttle = .init(&source, std.testing.io, 0, &buf);
    try t.check();
}

test "check turns a flagged cancellation into the named error" {
    const io = std.testing.io;
    var source: Reader = .fixed("xy");
    var buf: [8]u8 = undefined;
    // One byte each second. The first byte fills the window, so the second
    // byte must wait about a second before `wait` would let it through.
    var t: Throttle = .init(&source, io, 1, &buf);

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    _ = try t.interface.stream(&sink, .limited(1));

    var future = io.concurrent(readSecondByte, .{ &t, &sink }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            // A build with no threads genuinely cannot run this. A threaded
            // build reaching here is a regression, so let it fail loudly
            // instead of hiding behind a skip.
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
    try std.testing.expectError(error.ReadFailed, future.cancel(io));

    try std.testing.expectError(error.Canceled, t.check());
}

// `peek`, `readSliceAll`, and `takeByte` reach `stream` through
// `std.Io.Reader.fill`, which may call `stream` with a `Writer` that views
// this decorator's own `buffer`. `Throttle.stream` forwards `w` straight to
// `t.source.stream`, with no intermediate copy, so unlike `Hashing` it never
// had the aliasing bug: the tests below pin that the buffered API works and
// keeps counting correctly, so the gap does not reopen unnoticed if
// `stream` ever grows a copy step.

test "peek forwards through the buffered Reader API and still counts" {
    var source: Reader = .fixed("payload");
    // A buffer sized to exactly what `peek` asks for, so `fill` pulls
    // exactly 3 bytes in one call instead of opportunistically grabbing
    // more of the source into extra buffer capacity.
    var buf: [3]u8 = undefined;
    var t: Throttle = .init(&source, std.testing.io, 0, &buf);

    const peeked = try t.interface.peek(3);
    try std.testing.expectEqualStrings("pay", peeked);
    try std.testing.expectEqual(@as(u64, 3), t.window_bytes);
}

test "readSliceAll forwards through the buffered Reader API and still counts" {
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var t: Throttle = .init(&source, std.testing.io, 0, &buf);

    var out: [7]u8 = undefined;
    try t.interface.readSliceAll(&out);
    try std.testing.expectEqualStrings("payload", &out);
    try std.testing.expectEqual(@as(u64, 7), t.window_bytes);
}

test "takeByte forwards through the buffered Reader API and still counts" {
    var source: Reader = .fixed("ab");
    var buf: [4]u8 = undefined;
    var t: Throttle = .init(&source, std.testing.io, 0, &buf);

    try std.testing.expectEqual(@as(u8, 'a'), try t.interface.takeByte());
    try std.testing.expectEqual(@as(u8, 'b'), try t.interface.takeByte());
    try std.testing.expectEqual(@as(u64, 2), t.window_bytes);
}

/// A reader whose `stream` and `discard` always fail, standing in for a
/// socket that drops mid-transfer. Every other source in this file is
/// `Reader.fixed`, which can only ever end the stream, never fail it, so
/// nothing else here pins that a failed read leaves `window_bytes` honest.
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

test "a failed source stream leaves window_bytes exactly where it was" {
    var failing: FailingReader = .init();
    var buf: [8]u8 = undefined;
    var t: Throttle = .init(&failing.reader, std.testing.io, 0, &buf);

    var out: [8]u8 = undefined;
    var sink: Writer = .fixed(&out);
    try std.testing.expectError(error.ReadFailed, t.interface.stream(&sink, .limited(4)));
    try std.testing.expectEqual(@as(u64, 0), t.window_bytes);
    // The source failed on its own; the wait was never canceled.
    try std.testing.expectEqual(false, t.canceled);
}

test "a failed source discard leaves window_bytes exactly where it was" {
    var failing: FailingReader = .init();
    var buf: [8]u8 = undefined;
    var t: Throttle = .init(&failing.reader, std.testing.io, 0, &buf);

    try std.testing.expectError(error.ReadFailed, t.interface.discard(.limited(4)));
    try std.testing.expectEqual(@as(u64, 0), t.window_bytes);
    try std.testing.expectEqual(false, t.canceled);
}

test "a canceled wait sets canceled rather than reporting a plain read failure" {
    const io = std.testing.io;
    var source: Reader = .fixed("xy");
    var buf: [8]u8 = undefined;
    // One byte each second. The first byte fills the window, so the second
    // byte must wait about a second before `wait` would let it through.
    var t: Throttle = .init(&source, io, 1, &buf);

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    _ = try t.interface.stream(&sink, .limited(1));

    // The second read runs in a concurrent task so that the test can cancel
    // it while it is asleep, the same way `std.Io.RwLock`'s own "lock
    // canceling" test cancels a task blocked inside a wait.
    var future = io.concurrent(readSecondByte, .{ &t, &sink }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            // A build with no threads genuinely cannot run this. A threaded
            // build reaching here is a regression, so let it fail loudly
            // instead of hiding behind a skip.
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
    try std.testing.expectError(error.ReadFailed, future.cancel(io));
    try std.testing.expectEqual(true, t.canceled);
}

test "a wait that finishes clears a cancellation from an earlier one" {
    // The rule `canceled`'s doc comment states, pinned from both sides.
    // The doc used to say the flag latched while `zurl.body.Stack` cleared
    // it, and neither side had a test, so the two drifted apart for two
    // phases. This test fails if either side moves again.
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var t: Throttle = .init(&source, std.testing.io, 0, &buf);

    // A cancellation from earlier in the transfer.
    t.canceled = true;
    try std.testing.expectError(error.Canceled, t.check());

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    const n = try t.interface.stream(&sink, .limited(4));
    try std.testing.expectEqual(@as(usize, 4), n);

    // The wait for this read finished on its own, so the flag now
    // describes this read and not the earlier one.
    try std.testing.expectEqual(false, t.canceled);
    try t.check();
}

test "a wait that finishes clears the flag on the discard path too" {
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var t: Throttle = .init(&source, std.testing.io, 0, &buf);

    t.canceled = true;
    const n = try t.interface.discard(.limited(4));
    try std.testing.expectEqual(@as(usize, 4), n);
    try std.testing.expectEqual(false, t.canceled);
}

test "a source that fails after a canceled wait does not report the cancellation" {
    // The failure `zurl.body.Stack.resolve` reads. A wait that finished
    // clears the flag before the source is touched, so a source fault that
    // follows an earlier cancellation reports itself and not the
    // cancellation.
    var failing: FailingReader = .init();
    var buf: [8]u8 = undefined;
    var t: Throttle = .init(&failing.reader, std.testing.io, 0, &buf);

    t.canceled = true;

    var out: [8]u8 = undefined;
    var sink: Writer = .fixed(&out);
    try std.testing.expectError(error.ReadFailed, t.interface.stream(&sink, .limited(4)));
    try std.testing.expectEqual(false, t.canceled);
    try t.check();
}
