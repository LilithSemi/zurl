//! The two request-body sources zurl itself needs.
//!
//! `Transfer.Options.body` is a `zurl_http.engine.Body`: a `*anyopaque`
//! and two `callconv(.c)` function pointers, so a later C ABI can pass a
//! `CURLOPT_READFUNCTION` straight through. That shape is right for the
//! seam and wrong to write out by hand at every call, so this file holds
//! the two sources a caller needs in practice.
//!
//! `Memory` sends bytes the caller already has. `-d`, `--data-binary`,
//! `--data-urlencode`, and `--json` all build their body in memory, so all
//! four end here. The caller owns the bound on that memory; see
//! `src/cli/body.zig`, which holds zurl's own.
//!
//! `File` sends an open file, in pieces the engine sizes, so an upload
//! costs the memory of one piece however large the file is. `-T` ends
//! here. A file that can be read at an offset can also start over, which
//! is what a `307` and a `401` both need; a pipe cannot, and `File.source`
//! reports that by giving the body no `rewind`.
//!
//! Neither type reads the network and neither allocates. Both must not
//! move once `source` has run: the `Body` it returns holds the address of
//! the value it came from.

const std = @import("std");
const Transfer = @import("Transfer.zig");

const Io = std.Io;

/// A request body the caller already holds in memory.
///
/// `bytes` is borrowed and must outlive the transfer. The value must not
/// move once `source` has run.
pub const Memory = struct {
    /// The whole body, from its first byte to its last.
    bytes: []const u8,
    /// The `content-type` this body carries, or null for none. It goes out
    /// with the body and a redirect that drops the body drops it too. See
    /// `Transfer.Body.content_type`.
    content_type: ?[]const u8 = null,
    /// How much of `bytes` has been read. `rewind` puts this back to zero.
    at: usize = 0,

    /// The `Transfer.Options.body` for this source.
    ///
    /// The length is known, so the request goes out with a
    /// `content-length` and no chunked framing.
    pub fn source(self: *Memory) Transfer.Body {
        return .{
            .len = self.bytes.len,
            .ctx = self,
            .read = readImpl,
            .rewind = rewindImpl,
            .content_type = self.content_type,
        };
    }

    fn readImpl(ctx: *anyopaque, buffer: [*]u8, len: usize) callconv(.c) isize {
        const self: *Memory = @ptrCast(@alignCast(ctx));
        const take = @min(len, self.bytes.len - self.at);
        @memcpy(buffer[0..take], self.bytes[self.at..][0..take]);
        self.at += take;
        // A `usize` past `maxInt(isize)` cannot come from here: `take` is
        // bounded by `len`, which the engine sizes from a buffer on its
        // own stack.
        return @intCast(take);
    }

    fn rewindImpl(ctx: *anyopaque) callconv(.c) bool {
        const self: *Memory = @ptrCast(@alignCast(ctx));
        self.at = 0;
        return true;
    }
};

/// A request body streamed from an open file.
///
/// `file` stays open for the whole transfer, and the caller closes it. The
/// value must not move once `source` has run.
///
/// **A seekable file and a pipe are two different sources.** `init` reads
/// which one it has from the `stat`, because only a seekable one can be
/// read again from its first byte and only a seekable one has a length to
/// announce. `-T file` gives the first and `-T -` on a pipe gives the
/// second.
pub const File = struct {
    io: Io,
    file: Io.File,
    /// The offset of the first body byte, and where `rewind` goes back to.
    /// Zero for a whole file.
    start: u64,
    /// How many bytes the body holds, or null when the count is not known
    /// before the body goes out. Null makes the request chunked.
    len: ?u64,
    /// How many bytes have been read so far, counted from `start`.
    at: u64,
    /// Whether the file can be read at an offset. False for a pipe, and a
    /// pipe is read with plain streaming reads instead.
    seekable: bool,
    /// The `content-type` this body carries, or null for none. `-T` names
    /// none: measured, `curl -T file URL` sends a `Content-Length` and no
    /// `Content-Type` at all.
    content_type: ?[]const u8 = null,

    /// Opens `handle` as a request body, and reads from the `stat` which
    /// kind of source it is.
    ///
    /// A regular file has a size, so the body announces a
    /// `content-length`. Anything else, which a pipe and a character
    /// device both are, has no size to announce and no way back to its
    /// first byte: the body is chunked, and it may go out once.
    ///
    /// A `stat` that fails is not a fault here. The file is still
    /// readable; only its length is unknown. So the body falls back to the
    /// chunked, one-send shape, which is correct for any source at all.
    pub fn init(io: Io, handle: Io.File) File {
        const info = handle.stat(io) catch return .{
            .io = io,
            .file = handle,
            .start = 0,
            .len = null,
            .at = 0,
            .seekable = false,
        };
        const regular = info.kind == .file;
        return .{
            .io = io,
            .file = handle,
            .start = 0,
            .len = if (regular) info.size else null,
            .at = 0,
            .seekable = regular,
        };
    }

    /// The `Transfer.Options.body` for this source.
    ///
    /// A source that cannot be read at an offset gets no `rewind`, so the
    /// engine refuses to send it twice rather than send a body that starts
    /// in the middle.
    pub fn source(self: *File) Transfer.Body {
        return .{
            .len = self.len,
            .ctx = self,
            .read = readImpl,
            .rewind = if (self.seekable) rewindImpl else null,
            .content_type = self.content_type,
        };
    }

    fn readImpl(ctx: *anyopaque, buffer: [*]u8, len: usize) callconv(.c) isize {
        const self: *File = @ptrCast(@alignCast(ctx));
        const out = buffer[0..len];

        // A positional read leaves the file's own offset alone, so nothing
        // else that holds this handle is disturbed and `rewind` is one
        // assignment. A pipe cannot be read that way at all, so it takes
        // the streaming path instead.
        const count = if (self.seekable)
            // A positional read past the end returns zero, which is
            // already the answer this callback owes for an ended body.
            self.file.readPositionalAll(self.io, out, self.start + self.at) catch return -1
        else
            // A streaming read reports the end of the stream by name, and
            // the end of a body is not a fault. Answer zero for it, the
            // way the positional read already does.
            self.file.readStreaming(self.io, &.{out}) catch |err| switch (err) {
                error.EndOfStream => 0,
                else => return -1,
            };

        self.at += count;
        return @intCast(count);
    }

    fn rewindImpl(ctx: *anyopaque) callconv(.c) bool {
        const self: *File = @ptrCast(@alignCast(ctx));
        self.at = 0;
        return true;
    }
};

const testing = std.testing;

test "a memory source gives every byte once, and again after a rewind" {
    var body: Memory = .{ .bytes = "a=1&b=2" };
    const source = body.source();

    try testing.expectEqual(@as(?u64, 7), source.len);
    try testing.expect(source.rewind != null);

    var buffer: [4]u8 = undefined;
    try testing.expectEqual(@as(isize, 4), source.read(source.ctx, &buffer, 4));
    try testing.expectEqualStrings("a=1&", buffer[0..4]);
    try testing.expectEqual(@as(isize, 3), source.read(source.ctx, &buffer, 4));
    try testing.expectEqualStrings("b=2", buffer[0..3]);
    // The end of the body, and it stays the end.
    try testing.expectEqual(@as(isize, 0), source.read(source.ctx, &buffer, 4));

    try testing.expect(source.rewind.?(source.ctx));
    try testing.expectEqual(@as(isize, 4), source.read(source.ctx, &buffer, 4));
    try testing.expectEqualStrings("a=1&", buffer[0..4]);
}

test "a memory source of no bytes reads as an ended body" {
    // `-d ''` builds exactly this, and curl sends `Content-Length: 0` for
    // it. A source that answered anything but zero would frame a body it
    // does not have.
    var body: Memory = .{ .bytes = "" };
    const source = body.source();
    try testing.expectEqual(@as(?u64, 0), source.len);

    var buffer: [4]u8 = undefined;
    try testing.expectEqual(@as(isize, 0), source.read(source.ctx, &buffer, 4));
}

test "a file source announces the file size and starts over on a rewind" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(testing.io, .{ .sub_path = "up.txt", .data = "hello world\n" });
    const handle = try tmp.dir.openFile(testing.io, "up.txt", .{});
    defer handle.close(testing.io);

    var body: File = .init(testing.io, handle);
    const source = body.source();

    try testing.expectEqual(@as(?u64, 12), source.len);
    try testing.expect(source.rewind != null);

    var buffer: [5]u8 = undefined;
    try testing.expectEqual(@as(isize, 5), source.read(source.ctx, &buffer, 5));
    try testing.expectEqualStrings("hello", buffer[0..5]);

    try testing.expect(source.rewind.?(source.ctx));
    try testing.expectEqual(@as(isize, 5), source.read(source.ctx, &buffer, 5));
    try testing.expectEqualStrings("hello", buffer[0..5]);
}

test "a file source reads a whole file in pieces smaller than it" {
    // The engine reads in pieces of its own size, so a body larger than
    // one piece must come back whole and in order.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var written: [1000]u8 = undefined;
    for (&written, 0..) |*byte, i| byte.* = @intCast(i % 251);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "big.bin", .data = &written });

    const handle = try tmp.dir.openFile(testing.io, "big.bin", .{});
    defer handle.close(testing.io);

    var body: File = .init(testing.io, handle);
    const source = body.source();
    try testing.expectEqual(@as(?u64, 1000), source.len);

    var read_back: [1000]u8 = undefined;
    var at: usize = 0;
    while (true) {
        const n = source.read(source.ctx, read_back[at..].ptr, @min(64, read_back.len - at));
        try testing.expect(n >= 0);
        if (n == 0) break;
        at += @intCast(n);
    }
    try testing.expectEqual(@as(usize, 1000), at);
    try testing.expectEqualSlices(u8, &written, &read_back);
}
