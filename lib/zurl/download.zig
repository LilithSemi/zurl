//! The download path: fetch a url, hash the decoded body while writing it
//! to disk, and publish the result only once the transfer succeeds.
//!
//! Mirrors `download` and `fileDigest` from the psyclyx/fix evaluator's
//! `curl_transport.zig`, the file this package replaces. That transport
//! left publication to its caller, and relied on libcurl to decode the body
//! before hashing it. `toFile` does both itself: it writes the body to an
//! unnamed staging file and renames it into place only once the transfer
//! finishes with no error, and it hashes `Client.perform`'s already-decoded
//! `Response.body`, so the digest a cache stores never depends on which
//! compression the peer happened to pick.

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_stream = @import("zurl-stream");
const Client = @import("Client.zig");
const Transfer = @import("Transfer.zig");

const Io = std.Io;
const Error = zurl_core.Error;
const Diagnostics = zurl_core.Diagnostics;

/// What one download produced.
pub const Result = struct {
    /// The SHA-256 digest of the decoded response body: the same bytes
    /// written to `sub_path`, and the same bytes `fileDigest` finds when it
    /// reads them back.
    digest: [32]u8,
    /// How many decoded bytes the body held.
    size: u64,
    /// The final response's HTTP status.
    status: u16,
};

/// Scratch space for `hashing.Sha256`'s own buffer, in both `toFile` and
/// `fileDigest`.
const hash_buffer_len = 8192;

/// Scratch space for the staging file's writer.
const write_buffer_len = 8192;

/// Scratch space for `fileDigest`'s file reader.
const read_buffer_len = 64 * 1024;

/// Fetches `url_text` and writes its decoded body to `sub_path` inside
/// `dir`, returning its digest, size, and status.
///
/// Writes the body to an unnamed temporary file in `dir` first, and
/// renames it over `sub_path` only once the whole body has arrived with no
/// error. A transfer that fails partway, for any reason, leaves whatever
/// already sat at `sub_path` untouched: the caller never sees a partial
/// download, and a `sub_path` that named nothing before the call still
/// names nothing after a failed one.
///
/// The digest covers the body after content decoding: the same bytes this
/// function writes to `sub_path`, and the same bytes `options.reporter` and
/// `options.max_size` measure. See `Transfer.Options.max_size` for why.
///
/// **A 4xx or 5xx response is hashed and published like any other, unless
/// `options.fail_on_error` is true.** With the default options, an error
/// page a server sends back still ends up at `sub_path`, with a digest
/// computed over it and `result.status` naming the real code. A cache that
/// wants no such page published under a confident digest must set
/// `Transfer.Options.fail_on_error`; see that field's doc comment.
pub fn toFile(
    c: *Client,
    url_text: []const u8,
    dir: Io.Dir,
    sub_path: []const u8,
    options: Transfer.Options,
    d: ?*Diagnostics,
) Error!Result {
    const response = try c.perform(url_text, options, d);

    var staging = dir.createFileAtomic(c.io, sub_path, .{ .replace = true }) catch |err|
        return Diagnostics.record(d, error.WriteError, .{ .message = @errorName(err) });
    // Runs whether the transfer below succeeds or fails. `staging.replace`
    // clears the fields that make this a no-op on the success path, so this
    // is what deletes the temporary file on every failure path instead: the
    // reason `sub_path` never gains a partial file.
    defer staging.deinit(c.io);

    var write_buf: [write_buffer_len]u8 = undefined;
    var file_writer = staging.file.writer(c.io, &write_buf);

    var hash_buf: [hash_buffer_len]u8 = undefined;
    var hashed: zurl_stream.hashing.Sha256 = .init(response.body, &hash_buf);

    const size = hashed.interface.streamRemaining(&file_writer.interface) catch |err| switch (err) {
        // The peer, not the disk: `Response.body`'s decorator stack failed.
        // `resolveBodyError` turns the bare signal into the named fault.
        error.ReadFailed => return c.resolveBodyError(d),
        // The disk, not the peer: `file_writer.err` holds the real cause,
        // such as a full disk or a path that does not resolve.
        error.WriteFailed => return Diagnostics.record(d, error.WriteError, .{
            .message = @errorName(file_writer.err.?),
        }),
    };

    // Bytes the last `stream` call accepted into `file_writer`'s own buffer
    // are not on disk until this runs.
    file_writer.flush() catch |err|
        return Diagnostics.record(d, error.WriteError, .{ .message = @errorName(err) });

    staging.replace(c.io) catch |err|
        return Diagnostics.record(d, error.WriteError, .{ .message = @errorName(err) });

    return .{ .digest = hashed.final(), .size = size, .status = response.status };
}

/// Returns the SHA-256 digest of the file at `sub_path` inside `dir`,
/// hashed by the same rule `toFile` uses to hash a body while writing it.
/// A cache that stores `toFile`'s digest can call this later to check that
/// the file it kept still matches what it recorded.
///
/// Every fault this function can hit, a missing file, a permission denial,
/// or a failure partway through the read, reports as `error.ReadError`:
/// `zurl_core.Error` names no local-file fault of its own, and
/// `error.RemoteFileNotFound` names a fault on the *server*, which this is
/// not. Pass `d` to tell the three apart: `Diagnostics.message` carries the
/// real cause's name, such as `"FileNotFound"` or `"AccessDenied"`, the same
/// way `toFile` already reports a disk fault. A cache that retries a missing
/// file and a permission denial differently needs `d` for that; a caller
/// that only wants the digest can still pass `null`.
pub fn fileDigest(io: Io, dir: Io.Dir, sub_path: []const u8, d: ?*Diagnostics) Error![32]u8 {
    var file = dir.openFile(io, sub_path, .{}) catch |err|
        return Diagnostics.record(d, error.ReadError, .{ .message = @errorName(err) });
    defer file.close(io);

    var read_buf: [read_buffer_len]u8 = undefined;
    var file_reader = file.reader(io, &read_buf);

    var hash_buf: [hash_buffer_len]u8 = undefined;
    var hashed: zurl_stream.hashing.Sha256 = .init(&file_reader.interface, &hash_buf);

    // Discards every byte after hashing it, so this never holds the file in
    // memory at once. An empty buffer is correct: `Hashing.stream` only
    // reads through its own buffer when the destination has none of its
    // own, which is exactly this sink's shape.
    var sink: std.Io.Writer.Discarding = .init(&.{});
    _ = hashed.interface.streamRemaining(&sink.writer) catch |err| switch (err) {
        // `file_reader.err` holds the real cause of a mid-read failure, the
        // same way `file_writer.err` holds `toFile`'s.
        error.ReadFailed => return Diagnostics.record(d, error.ReadError, .{
            .message = @errorName(file_reader.err orelse error.Unexpected),
        }),
        // `Discarding.drain` has no failure path: it only counts bytes and
        // resets its own buffer.
        error.WriteFailed => unreachable,
    };

    return hashed.final();
}

const testing = std.testing;
const test_server = @import("zurl-http").test_server;

fn sha256(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

/// Gzip-compresses `decoded_len` zero bytes and returns the compressed
/// bytes, caller-owned.
///
/// Built at test time with `std.compress.flate`, not checked in as a binary
/// blob: a run of zero bytes compresses to a few thousand bytes no matter
/// how large `decoded_len` is, which is exactly the shape a gzip bomb test
/// needs, and building it here means the test carries no fixture file for a
/// reviewer to take on faith.
fn gzipZeros(allocator: std.mem.Allocator, decoded_len: usize) ![]u8 {
    var output: std.Io.Writer.Allocating = try .initCapacity(allocator, 8192);
    defer output.deinit();

    const window = try allocator.alloc(u8, std.compress.flate.max_window_len);
    defer allocator.free(window);

    var compress = try std.compress.flate.Compress.init(&output.writer, window, .gzip, .best);

    var zeros: [8192]u8 = @splat(0);
    var remaining = decoded_len;
    while (remaining > 0) {
        const n = @min(remaining, zeros.len);
        try compress.writer.writeAll(zeros[0..n]);
        remaining -= n;
    }
    try compress.finish();

    return output.toOwnedSlice();
}

test "a download writes the body and returns its digest, size, and status" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    const result = try toFile(&client, url_text, tmp.dir, "output", .{}, null);
    try testing.expectEqual(@as(u64, 7), result.size);
    try testing.expectEqual(@as(u16, 200), result.status);
    try testing.expectEqualSlices(u8, &sha256("payload"), &result.digest);

    const contents = try tmp.dir.readFileAlloc(testing.io, "output", testing.allocator, .limited(64));
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("payload", contents);
}

test "a download follows a redirect and hashes only the final body" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /body\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/start", .{server.port()});
    defer testing.allocator.free(url_text);

    const result = try toFile(&client, url_text, tmp.dir, "output", .{}, null);
    try testing.expectEqual(@as(u64, 7), result.size);
    try testing.expectEqualSlices(u8, &sha256("payload"), &result.digest);

    const contents = try tmp.dir.readFileAlloc(testing.io, "output", testing.allocator, .limited(64));
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("payload", contents);
}

test "a failed transfer leaves no file at the destination path" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhi",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    var d: Diagnostics = .{};
    try testing.expectError(error.PartialFile, toFile(&client, url_text, tmp.dir, "output", .{}, &d));
    try testing.expectError(error.FileNotFound, tmp.dir.access(testing.io, "output", .{}));
}

test "fileDigest of a written file matches the download's digest" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    const result = try toFile(&client, url_text, tmp.dir, "output", .{}, null);
    const digest = try fileDigest(testing.io, tmp.dir, "output", null);
    try testing.expectEqualSlices(u8, &result.digest, &digest);
}

test "fileDigest reports the real fault through Diagnostics, not a bare ReadError" {
    // `error.ReadError` alone does not say whether the file was missing, was
    // unreadable, or failed partway through. A cache that cannot tell those
    // apart retries the wrong one. `d.message` carries the real cause.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var d: Diagnostics = .{};
    try testing.expectError(error.ReadError, fileDigest(testing.io, tmp.dir, "does-not-exist", &d));
    try testing.expectEqualStrings("FileNotFound", d.message.?);
}

test "a download reports progress to the reporter" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

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
    const result = try toFile(&client, url_text, tmp.dir, "output", options, null);

    try testing.expect(recorder.calls > 0);
    try testing.expectEqual(result.size, recorder.last_transferred);
    try testing.expectEqual(@as(u64, 7), recorder.last_total);
}

test "the digest covers decoded bytes, not compressed bytes" {
    // gzip("payload"), produced with `gzip -n -9` so the test does not
    // depend on this project's own compressor. Content-Length names the
    // compressed length on the wire; the decoded payload is 7 bytes.
    const gzip_body = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 27\r\n" ++
        "Connection: close\r\n\r\n" ++
        "\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x03\x2b\x48\xac\xcc\xc9\x4f\x4c\x01\x00\x15\x6a\x2c\x42\x07\x00\x00\x00";

    var server: test_server.TestServer = undefined;
    try server.start(&.{gzip_body});
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    // Task 10 changed `Progress.total` to report 0 (unknown) for a decoded
    // body, rather than 27, the peer's pre-decoding `Content-Length`: a
    // reporter must never see a `total` the transfer cannot reach. Attaching
    // a reporter here is what proves that fix instead of leaving it
    // unpinned.
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
    const options: Transfer.Options = .{
        .reporter = .{ .ctx = &recorder, .report = Recorder.report },
        // **The offer, which the default no longer makes.** A request with
        // no `Accept-Encoding` header reads `identity` and nothing else, so
        // this gzip answer would be `error.BadContentEncoding` without the
        // flag. That is what `--compressed` chooses, and this test is about
        // what happens after the answer arrives compressed.
        .accept_encoding = true,
    };

    const result = try toFile(&client, url_text, tmp.dir, "output", options, null);
    try testing.expectEqual(@as(u64, 7), result.size);
    try testing.expectEqualSlices(u8, &sha256("payload"), &result.digest);

    const contents = try tmp.dir.readFileAlloc(testing.io, "output", testing.allocator, .limited(64));
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("payload", contents);

    try testing.expect(recorder.calls > 0);
    // total == 0 (unknown), not 27 (the compressed Content-Length): the
    // decoded body will never reach that count, so reporting it would be a
    // lie the reporter cannot detect on its own.
    try testing.expectEqual(@as(u64, 0), recorder.last_total);
    try testing.expectEqual(@as(u64, 7), recorder.last_transferred);
}

test "max_size measures decoded bytes, so a gzip bomb is stopped before it grows" {
    // A body that stays small on the wire and grows huge once decoded is
    // the whole reason `max_size` measures decoded bytes and not wire
    // bytes. If it measured wire bytes, this transfer would sail through:
    // `compressed.len` sits far under `max_size`, and only the decoded size
    // ever crosses it.
    const decoded_len: usize = 4 * 1024 * 1024;
    const max_size: u64 = 64 * 1024;

    const compressed = try gzipZeros(testing.allocator, decoded_len);
    defer testing.allocator.free(compressed);

    // The property this test exists to pin, stated as an assertion and not
    // left implicit: wire bytes under the limit, decoded bytes over it.
    try testing.expect(compressed.len < max_size);
    try testing.expect(decoded_len > max_size);

    const header = try std.fmt.allocPrint(
        testing.allocator,
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
        .{compressed.len},
    );
    defer testing.allocator.free(header);

    const response = try std.mem.concat(testing.allocator, u8, &.{ header, compressed });
    defer testing.allocator.free(response);

    var server: test_server.TestServer = undefined;
    try server.start(&.{response});
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    // `iterate = true`, so the check below can scan the directory for a
    // leftover staging file, not only ask whether `sub_path` itself exists.
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    var d: Diagnostics = .{};
    try testing.expectError(
        error.FileSizeExceeded,
        toFile(&client, url_text, tmp.dir, "output", .{
            .max_size = max_size,
            // The bomb has to reach the decoder to be a bomb, so the
            // request offers gzip. `--compressed` is what a user types for
            // this, and the bound still measures decoded octets.
            .accept_encoding = true,
        }, &d),
    );

    // No published file, and no staging file left behind either: the
    // destination directory holds nothing at all.
    var it = tmp.dir.iterate();
    try testing.expectEqual(@as(?std.Io.Dir.Entry, null), try it.next(testing.io));
}

test "max_size stops a zstd bomb the same way it stops a gzip one" {
    // **A decompressor takes attacker-controlled octets, and the coding
    // this change added is no exception.** One zstd `RLE` block costs four
    // octets on the wire and decodes to as many as its length names, so a
    // few hundred octets of frame decode to megabytes. The answer is the
    // bound that already holds gzip, and the name it already reports.
    //
    // **Nothing here allocates for the decoded octets.** The decoder
    // streams into a window this engine sized before the first octet
    // arrived, and the bound counts what comes out of it. So the fault is
    // `error.FileSizeExceeded` and not an allocation the peer chose the
    // size of.
    const gpa = testing.allocator;
    const max_size: u64 = 64 * 1024;

    // Sixty-four blocks of 64 KiB each: 4 MiB decoded, far over the cap.
    const run_count = 64;
    var runs: [run_count]struct { u8, usize } = undefined;
    for (&runs) |*each| each.* = .{ 0, test_server.zstd_block_len_max };

    const frame = try test_server.zstdFrame(gpa, &.{}, &runs);
    defer gpa.free(frame);

    const decoded_len: u64 = run_count * test_server.zstd_block_len_max;

    // The property this test exists to pin, stated and not left implicit:
    // wire octets far under the cap, decoded octets far over it.
    try testing.expect(frame.len < max_size);
    try testing.expect(decoded_len > max_size);

    const header = try std.fmt.allocPrint(
        gpa,
        "HTTP/1.1 200 OK\r\nContent-Encoding: zstd\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
        .{frame.len},
    );
    defer gpa.free(header);

    const response = try std.mem.concat(gpa, u8, &.{ header, frame });
    defer gpa.free(response);

    var server: test_server.TestServer = undefined;
    try server.start(&.{response});
    defer server.stop();

    var client: Client = .init(gpa, testing.io);
    defer client.deinit();

    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const url_text = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/", .{server.port()});
    defer gpa.free(url_text);

    var d: Diagnostics = .{};
    try testing.expectError(
        error.FileSizeExceeded,
        toFile(&client, url_text, tmp.dir, "output", .{
            .max_size = max_size,
            .accept_encoding = true,
        }, &d),
    );

    // And nothing was written: no published file and no staging file.
    var it = tmp.dir.iterate();
    try testing.expectEqual(@as(?std.Io.Dir.Entry, null), try it.next(testing.io));
}

test "a zstd body is decoded, and the digest covers the decoded octets" {
    // The coding `--compressed` adds beside gzip and deflate. The size and
    // the digest describe what a reader of the file sees, which is the
    // rule the gzip test above holds for its own coding.
    const gpa = testing.allocator;
    const frame = try test_server.zstdFrame(gpa, &.{"payload"}, &.{});
    defer gpa.free(frame);

    const header = try std.fmt.allocPrint(
        gpa,
        "HTTP/1.1 200 OK\r\nContent-Encoding: zstd\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
        .{frame.len},
    );
    defer gpa.free(header);

    const response = try std.mem.concat(gpa, u8, &.{ header, frame });
    defer gpa.free(response);

    var server: test_server.TestServer = undefined;
    try server.start(&.{response});
    defer server.stop();

    var client: Client = .init(gpa, testing.io);
    defer client.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const url_text = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/", .{server.port()});
    defer gpa.free(url_text);

    const result = try toFile(
        &client,
        url_text,
        tmp.dir,
        "output",
        .{ .accept_encoding = true },
        null,
    );
    try testing.expectEqual(@as(u64, 7), result.size);
    try testing.expectEqualSlices(u8, &sha256("payload"), &result.digest);

    const contents = try tmp.dir.readFileAlloc(testing.io, "output", gpa, .limited(64));
    defer gpa.free(contents);
    try testing.expectEqualStrings("payload", contents);
}

test "an unsolicited coding is passed through, and the digest covers what was written" {
    // **A request that asked for no decoding gets the peer's own
    // octets.** Measured against curl 8.21.0 on a loopback listener: a
    // plain `curl -o file` answered `Content-Encoding: gzip` wrote the 27
    // compressed octets and exited 0. Real servers do send an unsolicited
    // `Content-Encoding`, and refusing it broke commands that work under
    // curl.
    //
    // The digest and the size then describe the octets that were written,
    // which is the rule this file exists to keep. They describe the
    // compressed octets here because those are the octets in the file.
    const gpa = testing.allocator;
    const member = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x03\x2b\x48\xac\xcc\xc9\x4f\x4c" ++
        "\x01\x00\x15\x6a\x2c\x42\x07\x00\x00\x00";
    const gzip_body = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 27\r\n" ++
        "Connection: close\r\n\r\n" ++ member;

    var server: test_server.TestServer = undefined;
    try server.start(&.{gzip_body});
    defer server.stop();

    var client: Client = .init(gpa, testing.io);
    defer client.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const url_text = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/", .{server.port()});
    defer gpa.free(url_text);

    const result = try toFile(&client, url_text, tmp.dir, "output", .{}, null);
    // 27, the wire count, and not the 7 octets it would decode to.
    try testing.expectEqual(@as(u64, 27), result.size);
    try testing.expectEqualSlices(u8, &sha256(member), &result.digest);

    const contents = try tmp.dir.readFileAlloc(testing.io, "output", gpa, .limited(64));
    defer gpa.free(contents);
    try testing.expectEqualStrings(member, contents);
}

test "a coding with no decoder is refused only where the request asked to decode" {
    // **`--compressed` is a promise to hand back the body, and a coding
    // this build cannot decode breaks it.** Measured against curl 8.21.0:
    // `curl --compressed` answered in a coding curl has no decoder for
    // exits 61 with `Unrecognized content encoding type`, and the same
    // answer to a plain `curl` exits 0 with the octets written out.
    //
    // `br` is to zurl what that coding is to curl. A curl built without
    // brotli gives 61 for `br` for the same reason, so 61 here is the
    // faithful answer and not a stricter one.
    const gpa = testing.allocator;
    const body = "HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nContent-Length: 4\r\n" ++
        "Connection: close\r\n\r\nABCD";

    // With the offer: refused, and nothing is published.
    {
        var server: test_server.TestServer = undefined;
        try server.start(&.{body});
        defer server.stop();

        var client: Client = .init(gpa, testing.io);
        defer client.deinit();

        var tmp = testing.tmpDir(.{ .iterate = true });
        defer tmp.cleanup();

        const url_text = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/", .{server.port()});
        defer gpa.free(url_text);

        var d: Diagnostics = .{};
        try testing.expectError(
            error.BadContentEncoding,
            toFile(&client, url_text, tmp.dir, "output", .{ .accept_encoding = true }, &d),
        );
        // curl answers the same shape with exit 61,
        // `CURLE_BAD_CONTENT_ENCODING`.
        try testing.expectEqual(@as(?u32, 61), d.curl_code);

        var it = tmp.dir.iterate();
        try testing.expectEqual(@as(?std.Io.Dir.Entry, null), try it.next(testing.io));
    }

    // Without it: the four octets are written out, exactly as curl writes
    // them.
    {
        var server: test_server.TestServer = undefined;
        try server.start(&.{body});
        defer server.stop();

        var client: Client = .init(gpa, testing.io);
        defer client.deinit();

        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();

        const url_text = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/", .{server.port()});
        defer gpa.free(url_text);

        const result = try toFile(&client, url_text, tmp.dir, "output", .{}, null);
        try testing.expectEqual(@as(u64, 4), result.size);

        const contents = try tmp.dir.readFileAlloc(testing.io, "output", gpa, .limited(64));
        defer gpa.free(contents);
        try testing.expectEqualStrings("ABCD", contents);
    }
}
