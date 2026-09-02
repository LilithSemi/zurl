//! A reader that hashes the bytes that pass through it.
//!
//! Wrap a body reader in this to get the digest of a download without a second
//! pass over the file and without the body in memory at once.

const std = @import("std");
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const Limit = std.Io.Limit;
const assert = std.debug.assert;

/// A reader that hashes the bytes that pass through it.
///
/// `Hash` is any type from `std.crypto.hash`. It must have `init`, `update`,
/// `final`, and `digest_length`.
pub fn Hashing(comptime Hash: type) type {
    return struct {
        const Self = @This();

        /// The reader that this decorator wraps.
        source: *Reader,
        /// The hash state. Read it if you want to add bytes of your own.
        hasher: Hash,
        /// The reader that the caller reads from.
        interface: Reader,

        /// Wraps `source`.
        ///
        /// `buffer` must not be empty. `discard` has no destination writer to
        /// read into, so it reads into `buffer` before hashing the bytes it
        /// is about to throw away. A zero-length `buffer` makes `discard`
        /// report `error.EndOfStream` right away instead of consuming
        /// anything. `stream` does not use `buffer`: it hashes bytes after
        /// reading them straight into the destination writer's own memory.
        ///
        /// A destination writer passed to `stream` may itself have an empty
        /// buffer. `writableSliceGreedy` needs room to grow into and cannot
        /// serve such a writer, so `stream` reads into this decorator's own
        /// `buffer` instead and forwards with `writeAll` in that case. This
        /// cannot alias `buffer`, because `buffer` is never empty, so it is
        /// never the writer being read into.
        pub fn init(source: *Reader, buffer: []u8) Self {
            assert(buffer.len != 0);
            return .{
                .source = source,
                .hasher = .init(.{}),
                .interface = .{
                    .vtable = &.{ .stream = stream, .discard = discard },
                    .buffer = buffer,
                    .seek = 0,
                    .end = 0,
                },
            };
        }

        /// Returns the digest of everything that has passed through so far.
        ///
        /// `Hash.final` consumes the state, so call this once.
        pub fn final(self: *Self) [Hash.digest_length]u8 {
            var digest: [Hash.digest_length]u8 = undefined;
            self.hasher.final(&digest);
            return digest;
        }

        // `stream` is not only called with an empty `w`: `std.Io.Reader`'s
        // vtable doc comment says it is also called when the API user asked
        // for contiguous memory, and then `w` may be a view over this
        // decorator's own `r.buffer`. Reading into `r.buffer` as scratch and
        // then forwarding with `w.writeAll` would make `dest` and `w`'s
        // memory the same allocation, so `writeAll`'s copy would alias
        // itself. Asking `w` for its own writable region instead, and
        // reading straight into that, never has this problem: there is only
        // ever one place the bytes get written.
        //
        // That approach needs `w` to have room to grow into. A `w` with a
        // zero-length buffer, such as `std.Io.Writer.Discarding.init(&.{})`,
        // cannot grow, so `writableSliceGreedy` would reach
        // `Writer.defaultRebase` and either panic or loop forever depending
        // on build mode. This case cannot alias `r.buffer` (`init` asserts
        // `buffer` is never empty, so `w` and `r.buffer` cannot be the same
        // memory), so it is safe to fall back to the pre-fix path: read into
        // `r.buffer` and forward with `writeAll`.
        fn stream(r: *Reader, w: *Writer, limit: Limit) Reader.StreamError!usize {
            const self: *Self = @alignCast(@fieldParentPtr("interface", r));
            if (limit == .nothing) return 0;
            if (w.buffer.len == 0) {
                const dest = limit.slice(r.buffer);
                const n = self.source.readSliceShort(dest) catch |err| switch (err) {
                    error.ReadFailed => return error.ReadFailed,
                };
                if (n == 0) return error.EndOfStream;
                // Commit the write first, hash only after delivery is
                // confirmed, matching the ordering below.
                try w.writeAll(dest[0..n]);
                self.hasher.update(dest[0..n]);
                return n;
            }
            const dest = limit.slice(try w.writableSliceGreedy(1));
            const n = self.source.readSliceShort(dest) catch |err| switch (err) {
                error.ReadFailed => return error.ReadFailed,
            };
            if (n == 0) return error.EndOfStream;
            // Commit the write first, hash only after delivery is confirmed.
            // The bytes already sit in `w`'s own memory, so `advance` is the
            // point of no return: it cannot fail, and once `w.end` has moved
            // past them the write cannot un-happen.
            w.advance(n);
            self.hasher.update(dest[0..n]);
            return n;
        }

        fn discard(r: *Reader, limit: Limit) Reader.Error!usize {
            const self: *Self = @alignCast(@fieldParentPtr("interface", r));
            // A discard throws the bytes away, so read them into the interface
            // buffer and hash them there instead of dropping them.
            var remaining = limit;
            var total: usize = 0;
            while (remaining.nonzero()) {
                const dest = remaining.slice(r.buffer);
                if (dest.len == 0) break;
                const n = self.source.readSliceShort(dest) catch |err| switch (err) {
                    error.ReadFailed => return error.ReadFailed,
                };
                if (n == 0) break;
                self.hasher.update(dest[0..n]);
                total += n;
                remaining = remaining.subtract(n).?;
            }
            if (total == 0) return error.EndOfStream;
            return total;
        }
    };
}

/// The hash that a content-addressed cache uses.
pub const Sha256 = Hashing(std.crypto.hash.sha2.Sha256);

test "the digest matches a hash of the same bytes in one call" {
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var h: Sha256 = .init(&source, &buf);

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    _ = try h.interface.stream(&sink, .limited(7));

    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("payload", &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &h.final());
}

test "the decorator passes the bytes through unchanged" {
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var h: Sha256 = .init(&source, &buf);

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    const n = try h.interface.stream(&sink, .limited(7));
    try std.testing.expectEqual(@as(usize, 7), n);
    try std.testing.expectEqualStrings("payload", out[0..7]);
}

test "reads in several parts give the same digest as one read" {
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var h: Sha256 = .init(&source, &buf);

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    _ = try h.interface.stream(&sink, .limited(3));
    _ = try h.interface.stream(&sink, .limited(4));

    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("payload", &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &h.final());
}

test "a discard hashes the bytes that it drops" {
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var h: Sha256 = .init(&source, &buf);

    _ = try h.interface.discard(.limited(7));

    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("payload", &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &h.final());
}

test "the decorator works with a hash other than SHA-256" {
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var h: Hashing(std.crypto.hash.Md5) = .init(&source, &buf);

    _ = try h.interface.discard(.limited(7));

    var expected: [16]u8 = undefined;
    std.crypto.hash.Md5.hash("payload", &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &h.final());
}

/// A writer with a tiny buffer that must drain more than once, standing in
/// for a file or socket writer. `Writer.VTable.drain` is free to send bytes
/// straight to the sink instead of keeping them in `writer.buffer`, and this
/// test writer does exactly that, copying drained bytes into `sink`.
const SmallDrainWriter = struct {
    sink: []u8,
    written: usize = 0,
    writer: Writer,

    fn init(buffer: []u8, sink: []u8) SmallDrainWriter {
        return .{
            .sink = sink,
            .writer = .{ .vtable = &.{ .drain = drain }, .buffer = buffer },
        };
    }

    fn drain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        const self: *SmallDrainWriter = @alignCast(@fieldParentPtr("writer", w));
        @memcpy(self.sink[self.written..][0..w.end], w.buffer[0..w.end]);
        self.written += w.end;
        w.end = 0;

        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |bytes| {
            @memcpy(self.sink[self.written..][0..bytes.len], bytes);
            self.written += bytes.len;
            consumed += bytes.len;
        }
        const pattern = data[data.len - 1];
        for (0..splat) |_| {
            @memcpy(self.sink[self.written..][0..pattern.len], pattern);
            self.written += pattern.len;
            consumed += pattern.len;
        }
        return consumed;
    }
};

test "a writer that must drain mid-stream still gets the right digest" {
    const payload = "the quick brown fox jumps over the lazy dog, thirty-seven";
    var source: Reader = .fixed(payload);
    // The decorator's own buffer is smaller than the payload, so more than
    // one `stream` call is needed to forward it all.
    var buf: [6]u8 = undefined;
    var h: Sha256 = .init(&source, &buf);

    // The sink writer's buffer is smaller still, so every forwarded chunk
    // forces at least one `drain` call.
    var sink_storage: [payload.len]u8 = undefined;
    var writer_buf: [4]u8 = undefined;
    var sw: SmallDrainWriter = .init(&writer_buf, &sink_storage);

    var streamed: usize = 0;
    while (streamed < payload.len) {
        const n = try h.interface.stream(&sw.writer, .limited(payload.len - streamed));
        streamed += n;
    }
    // Bytes accepted into the writer's own buffer are not on the sink until
    // a flush pushes them out. Without this, the last few bytes would still
    // look correct here even though `stream` never truly forwarded them.
    try sw.writer.flush();

    try std.testing.expectEqualStrings(payload, sink_storage[0..sw.written]);

    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &h.final());
}

/// A writer whose `drain` always fails, standing in for a socket that resets
/// mid-write. `Writer.write` only calls `drain` when the bytes do not fit in
/// `buffer`, so a zero-length buffer forces every write through it.
const AlwaysFailWriter = struct {
    writer: Writer,

    fn init(buffer: []u8) AlwaysFailWriter {
        return .{ .writer = .{ .vtable = &.{ .drain = drain }, .buffer = buffer } };
    }

    fn drain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        _ = w;
        _ = data;
        _ = splat;
        return error.WriteFailed;
    }
};

test "a failed forward write leaves the digest covering only the bytes actually delivered" {
    const payload = "overflow";
    var source: Reader = .fixed(payload);
    var buf: [8]u8 = undefined;
    var h: Sha256 = .init(&source, &buf);

    var no_buf: [0]u8 = .{};
    var fw: AlwaysFailWriter = .init(&no_buf);
    try std.testing.expectError(
        error.WriteFailed,
        h.interface.stream(&fw.writer, .limited(payload.len)),
    );

    // None of the payload reached the sink, so the digest must match the
    // empty string, not the payload the hasher would have absorbed under
    // the old hash-before-write order.
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("", &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &h.final());
}

/// A writer that is legal but adversarial: `drain` accepts at most two new
/// bytes per call and then overwrites its own buffer with a sentinel byte,
/// instead of leaving the flushed bytes there. Both moves are legal.
/// `VTable.drain`'s caller must accept a short write ("a subsequent call may
/// return nonzero"), and the same doc comment says `drain` may modify
/// `buffer` and `end` in an implementation-defined manner. The short write
/// matters: a `drain` that accepted a whole large chunk in one call and then
/// read back a slice of `w.buffer` wider than `w.buffer` itself would panic
/// with an out-of-bounds index before the sentinel was ever read, the same
/// crash `SmallDrainWriter` pins below. Taking only a couple of bytes per
/// call keeps every such read-back inside `w.buffer`'s bounds, so a decorator
/// that hashed `w.buffer` after calling `drain`, instead of the bytes it
/// read from the source, would silently hash the sentinel instead of the
/// payload, with no crash to reveal it.
const SentinelDrainWriter = struct {
    sink: []u8,
    written: usize = 0,
    writer: Writer,

    fn init(buffer: []u8, sink: []u8) SentinelDrainWriter {
        return .{
            .sink = sink,
            .writer = .{ .vtable = &.{ .drain = drain }, .buffer = buffer },
        };
    }

    fn drain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        const self: *SentinelDrainWriter = @alignCast(@fieldParentPtr("writer", w));
        @memcpy(self.sink[self.written..][0..w.end], w.buffer[0..w.end]);
        self.written += w.end;

        // Take at most two bytes of new data, a legal short write. `write`
        // only calls `drain` with one slice and a splat of one, so the last
        // element of `data` is the only one that matters here.
        _ = splat;
        const pattern = data[data.len - 1];
        const take = @min(@as(usize, 2), pattern.len);
        @memcpy(self.sink[self.written..][0..take], pattern[0..take]);
        self.written += take;

        // Legal per `VTable.drain`'s contract: it may leave `buffer` in any
        // state. This sentinel is the state most likely to expose a decorator
        // that hashes `w.buffer` after the call instead of the bytes it read.
        @memset(w.buffer, 0xEE);
        w.end = 0;
        return take;
    }
};

test "a writer whose drain overwrites its buffer with a sentinel still gets the right digest" {
    const payload = "the quick brown fox jumps over the lazy dog, thirty-seven";
    var source: Reader = .fixed(payload);
    // The decorator's own buffer is smaller than the payload, so more than
    // one `stream` call is needed to forward it all.
    var buf: [6]u8 = undefined;
    var h: Sha256 = .init(&source, &buf);

    // The sink writer's buffer is smaller still, so every forwarded chunk
    // forces at least one `drain` call, which overwrites it with the
    // sentinel.
    var sink_storage: [payload.len]u8 = undefined;
    var writer_buf: [4]u8 = undefined;
    var sw: SentinelDrainWriter = .init(&writer_buf, &sink_storage);

    var streamed: usize = 0;
    while (streamed < payload.len) {
        const n = try h.interface.stream(&sw.writer, .limited(payload.len - streamed));
        streamed += n;
    }
    try sw.writer.flush();

    try std.testing.expectEqualStrings(payload, sink_storage[0..sw.written]);

    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &h.final());
}

// `peek`, `readSliceAll`, and `takeByte` all reach `stream` through
// `std.Io.Reader.fill`, which may call `stream` with a `Writer` that views
// this decorator's own `buffer` (see `stream`'s doc comment). Every other
// test in this file drives `stream` and `discard` directly, so none of them
// exercise that path. Before the fix, each of these three panicked with
// "@memcpy arguments alias" in Debug and passed silently under
// `-Doptimize=ReleaseFast`, because `writeAll` degenerated into a
// self-overlapping copy.

test "peek hashes real content without aliasing the reader's own buffer" {
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var h: Sha256 = .init(&source, &buf);

    const peeked = try h.interface.peek(3);
    try std.testing.expectEqualStrings("pay", peeked);

    var out: [7]u8 = undefined;
    try h.interface.readSliceAll(&out);
    try std.testing.expectEqualStrings("payload", &out);

    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("payload", &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &h.final());
}

test "readSliceAll hashes real content without aliasing the reader's own buffer" {
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var h: Sha256 = .init(&source, &buf);

    var out: [7]u8 = undefined;
    try h.interface.readSliceAll(&out);
    try std.testing.expectEqualStrings("payload", &out);

    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("payload", &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &h.final());
}

test "takeByte hashes real content one byte at a time without aliasing the reader's own buffer" {
    var source: Reader = .fixed("ab");
    var buf: [4]u8 = undefined;
    var h: Sha256 = .init(&source, &buf);

    try std.testing.expectEqual(@as(u8, 'a'), try h.interface.takeByte());
    try std.testing.expectEqual(@as(u8, 'b'), try h.interface.takeByte());
    try std.testing.expectError(error.EndOfStream, h.interface.takeByte());

    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("ab", &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &h.final());
}

test "a zero-byte limit forwards nothing and hashes nothing" {
    var source: Reader = .fixed("payload");
    var buf: [8]u8 = undefined;
    var h: Sha256 = .init(&source, &buf);

    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    const n = try h.interface.stream(&sink, .limited(0));
    try std.testing.expectEqual(@as(usize, 0), n);

    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("", &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &h.final());
}

/// A writer with no buffer of its own, standing in for
/// `std.Io.Writer.Discarding.init(&.{})`, which has none either. `write`
/// sends bytes straight to `drain` when `buffer` is empty (see
/// `Writer.write`), so this stands in for that path and records what it
/// receives instead of discarding it, to prove the forwarded bytes are the
/// real payload and not a view over the decorator's own buffer.
const NoBufferWriter = struct {
    sink: []u8,
    written: usize = 0,
    writer: Writer,

    fn init(sink: []u8) NoBufferWriter {
        return .{ .sink = sink, .writer = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} } };
    }

    fn drain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        const self: *NoBufferWriter = @alignCast(@fieldParentPtr("writer", w));
        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |bytes| {
            @memcpy(self.sink[self.written..][0..bytes.len], bytes);
            self.written += bytes.len;
            consumed += bytes.len;
        }
        const pattern = data[data.len - 1];
        for (0..splat) |_| {
            @memcpy(self.sink[self.written..][0..pattern.len], pattern);
            self.written += pattern.len;
            consumed += pattern.len;
        }
        return consumed;
    }
};

// Before the fallback, a destination writer with no buffer of its own
// panicked under Debug and ReleaseSafe, and looped forever under
// ReleaseFast, inside `writableSliceGreedy`. This test pins the fix: such a
// writer now streams correctly instead.
test "a destination writer with no buffer of its own streams correctly instead of hanging" {
    const payload = "the quick brown fox jumps over the lazy dog, thirty-seven";
    var source: Reader = .fixed(payload);
    var buf: [8]u8 = undefined;
    var h: Sha256 = .init(&source, &buf);

    var sink_storage: [payload.len]u8 = undefined;
    var nw: NoBufferWriter = .init(&sink_storage);

    var streamed: usize = 0;
    while (streamed < payload.len) {
        const n = try h.interface.stream(&nw.writer, .limited(payload.len - streamed));
        streamed += n;
    }

    try std.testing.expectEqualStrings(payload, sink_storage[0..nw.written]);

    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &h.final());
}
