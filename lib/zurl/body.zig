//! Stacks the transfer decorators onto a response body.
//!
//! The order, from the source upward, is `Throttle`, `Stall`, then
//! `Progress`. `Transfer.Options.max_size` sits above `Progress`, enforced
//! with `std.Io.Reader.Limited` from the standard library, not a decorator
//! of our own.
//!
//! `std.Io.Reader`'s vtable fixes every layer's own error to
//! `error.ReadFailed`. `resolve` is what turns that bare signal into the
//! named fault a caller can act on. See its doc comment for the order it
//! checks.
//!
//! `Stack` holds three decorators, not the four the brief names. The
//! fourth, `Hashing`, is deferred to Task 10's download path: only a
//! caller that wants a digest pays for hashing, and `Response.body` is a
//! plain `*std.Io.Reader`, so that caller can wrap it directly with no
//! change needed here.

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_stream = @import("zurl-stream");
const zurl_http = @import("zurl-http");
const Transfer = @import("Transfer.zig");

const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const Limit = std.Io.Limit;
const Io = std.Io;
const Error = zurl_core.Error;
const Diagnostics = zurl_core.Diagnostics;

/// The assembled decorator stack over one response body.
///
/// `Stack` holds every layer as a value field, and each layer above the
/// first points into the `interface` of the layer beneath it. That makes
/// `Stack` self-referential once built, so `init` writes into a
/// caller-owned `*Stack` instead of returning one: a struct returned by
/// value could be copied to its final location after the internal
/// pointers were computed, which would leave them aimed at the old
/// address. `compose_test.zig` sidesteps the same hazard by giving each
/// layer its own separately addressed local variable; `Stack` cannot do
/// that, because it must hand a caller one `*std.Io.Reader` for the whole
/// chain.
pub const Stack = struct {
    throttle: zurl_stream.Throttle,
    stall: zurl_stream.Stall,
    progress: zurl_stream.Progress,
    limited: Reader.Limited,
    /// Bytes allowed through before the transfer counts as exceeding
    /// `--max-filesize`. Zero means no limit.
    max_size: u64,
    /// True once a read has been found to cross `max_size`. Latches, and
    /// gates every call after the one that set it, the same way
    /// `Stall.timed_out` gates `Stall`.
    size_exceeded: bool,
    /// The reader the caller reads from.
    interface: Reader,

    /// Scratch space for `Stack`'s own top reader, the one `reader()`
    /// returns.
    ///
    /// `Throttle`, `Stall`, and `Progress` each forward `stream` and
    /// `discard` straight to the layer below with no copy of their own,
    /// so none of them ever needs a buffer: every real call to `reader()`
    /// streams or discards. `top` is different. It backs `Stack`'s own
    /// `interface`, and is load-bearing: `peek`, `takeByte`, and similar
    /// calls that ask `reader()` for contiguous memory go through it.
    pub const Buffers = struct {
        top: []u8,
    };

    const top_vtable: Reader.VTable = .{ .stream = topStream, .discard = topDiscard };

    /// Builds the stack in place at `s`, wrapping `source`.
    ///
    /// `content_length` is the peer's announced length, or zero when it is
    /// not known; it becomes `Progress`'s `total`. `source`, `io`, and
    /// every slice in `buffers` must outlive `s`.
    pub fn init(
        s: *Stack,
        source: *Reader,
        io: Io,
        options: Transfer.Options,
        content_length: u64,
        buffers: Buffers,
    ) void {
        // `&.{}` is correct, not a placeholder: none of these three ever
        // reads from or writes to a buffer of its own. See `Buffers`'s doc
        // comment.
        s.throttle = .init(source, io, options.max_bytes_per_second, &.{});
        s.stall = .init(
            &s.throttle.interface,
            io,
            options.low_speed_limit,
            options.low_speed_time_s,
            &.{},
        );
        s.progress = .init(&s.stall.interface, options.reporter, content_length, &.{});

        // One byte of headroom over the limit. A transfer that stops
        // exactly at `max_size` never earns that extra byte, so `exceeded`
        // can tell "the body was exactly this long" from "the body kept
        // going" by whether `limited.remaining` ever ran out.
        //
        // `Limit` is backed by `usize` and reserves `math.maxInt(usize)` as
        // its own `.unlimited` sentinel. On a target where `usize` is
        // narrower than `u64`, a `max_size` at or above that sentinel
        // cannot get its one byte of headroom without `limited64` clamping
        // the sum right back down to `.unlimited`, which would silently
        // stop limiting. Capping the headroom one byte short of the
        // sentinel keeps that from happening: such a transfer still stops,
        // just up to one byte later than an exact `max_size` would ask
        // for.
        const usize_max = std.math.maxInt(usize);
        const limit: Limit = if (options.max_size == 0)
            .unlimited
        else
            .limited64(@min(options.max_size +| 1, usize_max - 1));
        s.limited = .init(&s.progress.interface, limit, &.{});

        s.max_size = options.max_size;
        s.size_exceeded = false;
        s.interface = .{
            .vtable = &top_vtable,
            .buffer = buffers.top,
            .seek = 0,
            .end = 0,
        };
    }

    /// The reader the caller reads the body from.
    pub fn reader(s: *Stack) *Reader {
        return &s.interface;
    }

    /// True once `limited` has used up the one byte of headroom `init`
    /// gave it over `max_size`. `max_size` zero means no limit and is
    /// never exceeded.
    ///
    /// Reads `limited.remaining` rather than `progress.transferred`: the
    /// two agree only because `Progress` sits directly under `limited`
    /// today, and `limited.remaining` says the same thing without
    /// depending on that order.
    fn exceeded(s: *const Stack) bool {
        return s.max_size != 0 and s.limited.remaining == .nothing;
    }

    fn topStream(r: *Reader, w: *Writer, limit: Limit) Reader.StreamError!usize {
        const s: *Stack = @alignCast(@fieldParentPtr("interface", r));
        if (s.size_exceeded) return error.ReadFailed;
        const n = s.limited.interface.stream(w, limit) catch |err| switch (err) {
            error.EndOfStream => {
                // `Limited` reports its own cap the same way a source that
                // legitimately ended there would: a plain `EndOfStream`.
                // The one byte of headroom in `init` is what lets this
                // tell the two apart: reaching it means the body kept
                // going past `max_size`, not that it ended there.
                if (s.exceeded()) {
                    s.size_exceeded = true;
                    return error.ReadFailed;
                }
                return error.EndOfStream;
            },
            else => |e| return e,
        };
        // The call that first uses up `limited`'s headroom still delivers
        // its bytes honestly, the same deferral `Stall` uses: `w` already
        // has them, and `n` bytes really did leave the source. The next
        // call sees the latch above and fails before it reads anything
        // more.
        if (s.exceeded()) s.size_exceeded = true;
        return n;
    }

    fn topDiscard(r: *Reader, limit: Limit) Reader.Error!usize {
        const s: *Stack = @alignCast(@fieldParentPtr("interface", r));
        if (s.size_exceeded) return error.ReadFailed;
        const n = s.limited.interface.discard(limit) catch |err| switch (err) {
            error.EndOfStream => {
                if (s.exceeded()) {
                    s.size_exceeded = true;
                    return error.ReadFailed;
                }
                return error.EndOfStream;
            },
            else => |e| return e,
        };
        if (s.exceeded()) s.size_exceeded = true;
        return n;
    }

    /// Turns a bare `error.ReadFailed` from `reader()` into the named
    /// fault that caused it, and records that fault in `d`.
    ///
    /// Call this right after `reader()` returns `error.ReadFailed`, not as
    /// a general poll. `Stall.timed_out` and this stack's own
    /// `size_exceeded` latch and gate every later call, so neither can go
    /// stale. `Throttle.canceled` does not latch: it describes the most
    /// recent wait, and a wait that finishes on its own clears it, so a
    /// cancellation from earlier in the transfer cannot outrank a later,
    /// unrelated failure. `Throttle` owns that rule, because the wait is
    /// the only thing able to decide it. This stack once cleared the flag
    /// itself, at four places, which is how the rule and the doc comment
    /// on `Throttle.canceled` came to disagree. Calling right away still
    /// matters: a flag this function has not yet read is overwritten by
    /// whatever read happens next.
    ///
    /// Checks, in order: `throttle`, `stall`, `max_size`, then `exchange`
    /// when given. `exchange` comes last, not because it matters least,
    /// but because it is the only one of the four that means the read
    /// truly reached the peer and came back short: a decorator flag above
    /// it would only ever be set by this stack's own bookkeeping, so a
    /// caller that checked `exchange` first could report `PartialFile` for
    /// a stall or a canceled rate limit that never touched the source
    /// again. Nothing here masks `exchange.check()`: it always runs when
    /// no earlier flag fired, so a short body still surfaces as
    /// `PartialFile`, not the generic `ReadError` fallback.
    pub fn resolve(
        s: *const Stack,
        exchange: ?*const zurl_http.engine.Exchange,
        d: ?*Diagnostics,
    ) Error {
        s.throttle.check() catch return Diagnostics.record(d, error.AbortedByCallback, .{
            .message = "the rate limit wait was canceled",
        });
        s.stall.check() catch return Diagnostics.record(d, error.OperationTimedOut, .{
            .message = "the transfer ran below the configured rate for too long",
        });
        if (s.size_exceeded) {
            return Diagnostics.record(d, error.FileSizeExceeded, .{
                .message = "the transfer grew past its configured size limit",
            });
        }
        if (exchange) |ex| {
            // **A peer that went quiet is not a peer that stopped short.**
            // A read that reached its bound says nothing about how many
            // octets were promised, so reporting a short body would name
            // the wrong fault and the wrong exit code. curl 8.21.0 answers
            // a peer that stops sending with 28, measured, and 18 is what
            // a truncated body gets.
            ex.check() catch |err| switch (err) {
                error.OperationTimedOut => return Diagnostics.record(d, error.OperationTimedOut, .{
                    .message = "the server stopped sending, and the read went past its bound",
                }),
                else => return Diagnostics.record(d, error.PartialFile, .{
                    .message = "the response body stopped short of its announced length",
                }),
            };
        }
        return Diagnostics.record(d, error.ReadError, .{});
    }
};

const testing = std.testing;

/// A reader whose `stream` and `discard` always fail, standing in for a
/// socket that drops mid-transfer with neither `Throttle` nor `Stall`
/// having anything to say about why.
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

/// A reader that serves one byte, then fails every call after, standing in
/// for a source that briefly recovers before dropping for good.
const SucceedOnceThenFailReader = struct {
    reader: Reader,
    served: bool = false,

    fn init() SucceedOnceThenFailReader {
        return .{ .reader = .{
            .vtable = &.{ .stream = stream, .discard = discard },
            .buffer = &.{},
            .seek = 0,
            .end = 0,
        } };
    }

    fn stream(r: *Reader, w: *Writer, limit: Limit) Reader.StreamError!usize {
        _ = limit;
        const self: *SucceedOnceThenFailReader = @alignCast(@fieldParentPtr("reader", r));
        if (self.served) return error.ReadFailed;
        self.served = true;
        return try w.write("x");
    }

    fn discard(r: *Reader, limit: Limit) Reader.Error!usize {
        _ = limit;
        const self: *SucceedOnceThenFailReader = @alignCast(@fieldParentPtr("reader", r));
        if (self.served) return error.ReadFailed;
        self.served = true;
        return 1;
    }
};

/// Every buffer a test needs to build a `Stack`. Kept in one struct so a
/// test can declare one local and hand out slices from it.
const TestBuffers = struct {
    top: [16]u8 = undefined,

    fn slices(self: *TestBuffers) Stack.Buffers {
        return .{
            .top = &self.top,
        };
    }
};

test "a stalled transfer surfaces as OperationTimedOut with diagnostics" {
    const io = testing.io;
    var source: Reader = .fixed("x");
    var bufs: TestBuffers = .{};

    var options: Transfer.Options = .{};
    // A huge limit and a one second window, so a single byte can never
    // keep up.
    options.low_speed_limit = 1_000_000_000;
    options.low_speed_time_s = 1;

    var stack: Stack = undefined;
    Stack.init(&stack, &source, io, options, 1, bufs.slices());
    // Back-date the window by an hour, the same technique `Stall`'s own
    // tests use, so the window reads as expired no matter the clock's
    // resolution or the machine's speed.
    stack.stall.window_start = stack.stall.window_start.subDuration(.fromNanoseconds(3600 * std.time.ns_per_s));

    var out: [8]u8 = undefined;
    var sink: Writer = .fixed(&out);

    // The byte that made the window fail its rate still arrives.
    const n = try stack.reader().stream(&sink, .limited(1));
    try testing.expectEqual(@as(usize, 1), n);

    // Only the next call reports the stall.
    try testing.expectError(error.ReadFailed, stack.reader().stream(&sink, .limited(1)));

    var d: Diagnostics = .{};
    try testing.expectEqual(error.OperationTimedOut, stack.resolve(null, &d));
    try testing.expect(d.message != null);
}

fn readOneByte(r: *Reader, sink: *Writer) Reader.StreamError!usize {
    return r.stream(sink, .limited(1));
}

test "a cancelled rate limit surfaces as AbortedByCallback" {
    const io = testing.io;
    var source: Reader = .fixed("xy");
    var bufs: TestBuffers = .{};

    var options: Transfer.Options = .{};
    // One byte each second. The first byte fills the window, so the
    // second byte must wait about a second before the window would let it
    // through.
    options.max_bytes_per_second = 1;
    options.low_speed_limit = 0;
    options.low_speed_time_s = 0;

    var stack: Stack = undefined;
    Stack.init(&stack, &source, io, options, 2, bufs.slices());

    var out: [8]u8 = undefined;
    var sink: Writer = .fixed(&out);
    _ = try stack.reader().stream(&sink, .limited(1));

    // The second read runs in its own task so the test can cancel it
    // while it is asleep inside `Throttle.wait`, the same way
    // `Throttle.zig`'s own cancellation test does.
    var future = io.concurrent(readOneByte, .{ stack.reader(), &sink }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
    try testing.expectError(error.ReadFailed, future.cancel(io));

    var d: Diagnostics = .{};
    try testing.expectEqual(error.AbortedByCallback, stack.resolve(null, &d));
}

test "a stale cancellation does not outrank a fresh source failure after a successful read" {
    const io = testing.io;
    var source: SucceedOnceThenFailReader = .init();
    var bufs: TestBuffers = .{};

    var stack: Stack = undefined;
    Stack.init(&stack, &source.reader, io, .{}, 0, bufs.slices());

    // A cancellation left over from earlier in the transfer. Nothing gates
    // reads on it, so a real transfer can still carry this `true` here,
    // after the wait it came from.
    stack.throttle.canceled = true;

    var out: [8]u8 = undefined;
    var sink: Writer = .fixed(&out);

    // The wait for this read finishes on its own, so `Throttle` clears the
    // flag before it touches the source. See `Throttle.canceled`.
    const n = try stack.reader().stream(&sink, .limited(1));
    try testing.expectEqual(@as(usize, 1), n);

    // The next read fails at the source itself, with no fresh
    // cancellation.
    try testing.expectError(error.ReadFailed, stack.reader().stream(&sink, .limited(1)));

    // The true cause is a plain source failure, not the stale
    // cancellation from before the successful read.
    try testing.expectEqual(error.ReadError, stack.resolve(null, null));
}

test "a source failure with neither flag set surfaces as ReadError" {
    const io = testing.io;
    var failing: FailingReader = .init();
    var bufs: TestBuffers = .{};

    var stack: Stack = undefined;
    Stack.init(&stack, &failing.reader, io, .{}, 0, bufs.slices());

    var out: [8]u8 = undefined;
    var sink: Writer = .fixed(&out);
    try testing.expectError(error.ReadFailed, stack.reader().stream(&sink, .limited(4)));

    try testing.expectEqual(error.ReadError, stack.resolve(null, null));
}

test "max_size stops a transfer that grows past its limit" {
    const io = testing.io;
    var source: Reader = .fixed("0123456789");
    var bufs: TestBuffers = .{};

    var options: Transfer.Options = .{};
    options.max_size = 4;

    var stack: Stack = undefined;
    Stack.init(&stack, &source, io, options, 0, bufs.slices());

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    try testing.expectError(error.ReadFailed, stack.reader().streamRemaining(&sink));

    try testing.expectEqual(error.FileSizeExceeded, stack.resolve(null, null));
}

test "a transfer that ends exactly at max_size is not exceeded" {
    const io = testing.io;
    var source: Reader = .fixed("0123");
    var bufs: TestBuffers = .{};

    var options: Transfer.Options = .{};
    options.max_size = 4;

    var stack: Stack = undefined;
    Stack.init(&stack, &source, io, options, 0, bufs.slices());

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    const n = try stack.reader().streamRemaining(&sink);
    try testing.expectEqual(@as(usize, 4), n);
    try testing.expectEqualStrings("0123", out[0..n]);
}

test "the reporter sees the running total and the announced length" {
    const io = testing.io;
    var source: Reader = .fixed("payload");
    var bufs: TestBuffers = .{};

    const Recorder = struct {
        calls: u32 = 0,
        last_transferred: u64 = 0,
        last_total: u64 = 0,

        fn report(ctx: *anyopaque, transferred: u64, total: u64) callconv(.c) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
            self.last_transferred = transferred;
            self.last_total = total;
        }
    };
    var recorder: Recorder = .{};

    const options: Transfer.Options = .{ .reporter = .{ .ctx = &recorder, .report = Recorder.report } };
    var stack: Stack = undefined;
    Stack.init(&stack, &source, io, options, 7, bufs.slices());

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    _ = try stack.reader().stream(&sink, .limited(4));

    try testing.expectEqual(@as(u32, 1), recorder.calls);
    try testing.expectEqual(@as(u64, 4), recorder.last_transferred);
    try testing.expectEqual(@as(u64, 7), recorder.last_total);
}
