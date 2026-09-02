//! Proof that the decorators stack.
//!
//! This is the stack that a cached download uses: a rate limit, a stall
//! watchdog, a progress count, and a hash, all over one body reader. This test
//! lives in its own file because it belongs to no single decorator.

const std = @import("std");
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

const Progress = @import("Progress.zig");
const Stall = @import("Stall.zig");
const Throttle = @import("Throttle.zig");
const hashing = @import("hashing.zig");

test "a hash over a progress count over a watchdog over a rate limit" {
    const io = std.testing.io;
    const body = "the quick brown fox";

    var source: Reader = .fixed(body);

    var throttle_buf: [32]u8 = undefined;
    var throttle: Throttle = .init(&source, io, 0, &throttle_buf);

    var stall_buf: [32]u8 = undefined;
    var stall: Stall = .init(&throttle.interface, io, 0, 0, &stall_buf);

    var progress_buf: [32]u8 = undefined;
    var progress: Progress = .init(&stall.interface, null, body.len, &progress_buf);

    var hash_buf: [32]u8 = undefined;
    var hash: hashing.Sha256 = .init(&progress.interface, &hash_buf);

    var out: [64]u8 = undefined;
    var sink: Writer = .fixed(&out);
    const n = try hash.interface.stream(&sink, .limited(body.len));

    try std.testing.expectEqual(body.len, n);
    try std.testing.expectEqualStrings(body, out[0..n]);
    try std.testing.expectEqual(@as(u64, body.len), progress.transferred);

    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &hash.final());
}

test "the stack forwards the end of the source to the top" {
    const io = std.testing.io;
    var source: Reader = .fixed("ab");

    var throttle_buf: [8]u8 = undefined;
    var throttle: Throttle = .init(&source, io, 0, &throttle_buf);

    var progress_buf: [8]u8 = undefined;
    var progress: Progress = .init(&throttle.interface, null, 2, &progress_buf);

    var out: [8]u8 = undefined;
    var sink: Writer = .fixed(&out);
    _ = try progress.interface.stream(&sink, .limited(2));
    try std.testing.expectError(
        error.EndOfStream,
        progress.interface.stream(&sink, .limited(1)),
    );
}

test "the digest matches a one-shot hash when the whole stack forwards it in pieces" {
    const io = std.testing.io;
    const body = "the quick brown fox jumps over the lazy dog, thirty-seven bytes";

    var source: Reader = .fixed(body);

    var throttle_buf: [6]u8 = undefined;
    var throttle: Throttle = .init(&source, io, 0, &throttle_buf);

    var stall_buf: [6]u8 = undefined;
    var stall: Stall = .init(&throttle.interface, io, 0, 0, &stall_buf);

    var progress_buf: [6]u8 = undefined;
    var progress: Progress = .init(&stall.interface, null, body.len, &progress_buf);

    var hash_buf: [6]u8 = undefined;
    var hash: hashing.Sha256 = .init(&progress.interface, &hash_buf);

    var out: [body.len]u8 = undefined;
    var sink: Writer = .fixed(&out);

    // Every buffer in the stack is smaller than the payload, so the whole
    // chain must be driven around more than once to move it all.
    var delivered: usize = 0;
    while (delivered < body.len) {
        const n = try hash.interface.stream(&sink, .limited(body.len - delivered));
        delivered += n;
    }

    try std.testing.expectEqualStrings(body, out[0..delivered]);
    try std.testing.expectEqual(@as(u64, body.len), progress.transferred);

    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &hash.final());
}

test "a stall below hashing and progress reports honestly, then fails the next call" {
    const io = std.testing.io;
    var source: Reader = .fixed("x");

    var throttle_buf: [8]u8 = undefined;
    var throttle: Throttle = .init(&source, io, 0, &throttle_buf);

    var stall_buf: [8]u8 = undefined;
    // A huge limit and a one second window, so a single byte can never keep
    // up.
    var stall: Stall = .init(&throttle.interface, io, 1_000_000_000, 1, &stall_buf);
    // Back-date the window by an hour, well past any wall-clock time this
    // test itself could spend, so the window reads as expired no matter the
    // clock's resolution or the machine's speed.
    stall.window_start = stall.window_start.subDuration(.fromNanoseconds(3600 * std.time.ns_per_s));

    var progress_buf: [8]u8 = undefined;
    var progress: Progress = .init(&stall.interface, null, 1, &progress_buf);

    var hash_buf: [8]u8 = undefined;
    var hash: hashing.Sha256 = .init(&progress.interface, &hash_buf);

    var out: [8]u8 = undefined;
    var sink: Writer = .fixed(&out);

    // The byte that made the window fail its rate still arrives at the top,
    // and Progress still shows it as transferred.
    const n = try hash.interface.stream(&sink, .limited(1));
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqualStrings("x", out[0..1]);
    try std.testing.expectEqual(@as(u64, 1), progress.transferred);
    try std.testing.expectEqual(true, stall.timed_out);

    // The next call reports the stall through every layer above it, as
    // error.ReadFailed, and Stall.check turns it into the named error.
    try std.testing.expectError(
        error.ReadFailed,
        hash.interface.stream(&sink, .limited(1)),
    );
    try std.testing.expectError(error.OperationTimedOut, stall.check());

    // No byte the source never gave counts as transferred.
    try std.testing.expectEqual(@as(u64, 1), progress.transferred);
}

test "putting progress outside the hash instead of inside still counts every byte and hashes correctly" {
    // The main stack test wraps hashing around progress: Hash(Progress(...)).
    // This test wraps it the other way round, Progress(Hash(...)), to check
    // that a caller who picks the opposite order is not punished for it. The
    // byte count and the digest both still cover the whole payload either
    // way. This is not a claim that every ordering is equally sensible for a
    // real download (a rate limit above a hash would count the hash's own
    // CPU time as transfer time), only that Progress and Hashing do not
    // corrupt each other's view of the data no matter which wraps which.
    const body = "order does not corrupt the bytes";

    var source: Reader = .fixed(body);

    var hash_buf: [8]u8 = undefined;
    var hash: hashing.Sha256 = .init(&source, &hash_buf);

    var progress_buf: [8]u8 = undefined;
    var progress: Progress = .init(&hash.interface, null, body.len, &progress_buf);

    var out: [body.len]u8 = undefined;
    var sink: Writer = .fixed(&out);

    var delivered: usize = 0;
    while (delivered < body.len) {
        const n = try progress.interface.stream(&sink, .limited(body.len - delivered));
        delivered += n;
    }

    try std.testing.expectEqualStrings(body, out[0..delivered]);
    try std.testing.expectEqual(@as(u64, body.len), progress.transferred);

    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &hash.final());
}
