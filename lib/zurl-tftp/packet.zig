//! The five TFTP packets, RFC 1350, and the option extension of RFC 2347.
//!
//! This file reads bytes and writes bytes. It opens no socket and holds no
//! state, so every rule here is testable with a table.
//!
//! What it does not own: the socket, the block acknowledgement, the
//! retransmission, and the bound on the whole transfer. `Fetcher.zig` owns
//! all four.
//!
//! **Every request shape here was measured against curl 8.21.0**, with a
//! `socat` listener on UDP that captured the first datagram and answered
//! nothing. The captures are in the doc comment of each function.

const std = @import("std");
const zurl_core = @import("zurl-core");

/// The two-byte opcode every TFTP packet starts with. RFC 1350 section 5,
/// and RFC 2347 for `oack`.
pub const Opcode = enum(u16) {
    read_request = 1,
    write_request = 2,
    data = 3,
    ack = 4,
    err = 5,
    /// RFC 2347. A server that reads the options in a request answers with
    /// this instead of the first `data` packet.
    oack = 6,
    _,
};

/// The transfer modes RFC 1350 names.
///
/// `octet` is what a download wants and what curl sends by default,
/// measured. `netascii` is curl's `-B`/`--use-ascii`, measured on
/// `curl -B tftp://h/f.txt`, which sends `netascii` in the same field.
/// This build has no such flag, so nothing here writes the second name
/// yet. It is named so a reader knows which byte string the field carries.
pub const Mode = enum {
    octet,
    netascii,

    pub fn text(m: Mode) []const u8 {
        return @tagName(m);
    }
};

/// The error codes an `err` packet can carry. RFC 1350 section 4.
///
/// Each one maps to a `zurl_core.Error` of its own, so a script reads the
/// same exit code curl gives. See `errorFor`.
pub const ErrorCode = enum(u16) {
    /// Not defined. The message beside it says what happened.
    undefined_error = 0,
    file_not_found = 1,
    access_violation = 2,
    disk_full = 3,
    illegal_operation = 4,
    unknown_transfer_id = 5,
    file_already_exists = 6,
    no_such_user = 7,
    /// RFC 2347. The server refused the options in the request.
    option_negotiation_failed = 8,
    _,
};

/// The `zurl_core.Error` an `err` packet's code means.
///
/// curl 8.21.0 gives each RFC 1350 code an exit code of its own, listed in
/// its own manual page: 68 for file not found, 69 for a permission
/// problem, 70 for out of disk space, 71 for an illegal operation, 72 for
/// an unknown transfer id, 73 for a file that already exists, and 74 for
/// no such user. `zurl_core.errors` carries the same seven numbers, so a
/// script that branches on curl's number reads the same one here.
///
/// A code outside that list, code 0 and code 8 included, is
/// `error.TftpIllegalOperation`, exit 71. curl has no number of its own
/// for either, and 71 is the code it uses for a request the server would
/// not run.
pub fn errorFor(code: ErrorCode) zurl_core.Error {
    return switch (code) {
        .file_not_found => error.TftpNotFound,
        .access_violation => error.TftpPermission,
        .disk_full => error.TftpDiskFull,
        .illegal_operation => error.TftpIllegalOperation,
        .unknown_transfer_id => error.TftpUnknownId,
        .file_already_exists => error.TftpFileExists,
        .no_such_user => error.TftpNoSuchUser,
        .undefined_error, .option_negotiation_failed, _ => error.TftpIllegalOperation,
    };
}

/// How many bytes of data one block carries, with no option negotiation.
/// RFC 1350 fixes this at 512.
pub const default_block_size: u16 = 512;

/// How long the request asks the **server** to wait before it sends a
/// block again. RFC 2349.
///
/// Six seconds, which is what curl 8.21.0 asks for with no flag beside it,
/// measured against a TFTP server that captured the request. curl derives
/// the number from its own timeouts, so a `curl --max-time 2` asks for one
/// second instead. This is the number of the plain case.
///
/// This is the server's wait and not the client's. `Fetcher.Options`
/// carries the client's own, which is shorter: the client asks for a block
/// again before the server would send it, so the recovery is the client's
/// and the server's answer is a second line of defence.
pub const default_server_timeout_seconds: u16 = 6;

/// The smallest block a request may ask for. RFC 2348 fixes this at 8.
///
/// A request that names less is refused by name. Nothing is clamped: a
/// number the user wrote is either the number that goes on the wire or a
/// fault the user reads about.
pub const min_block_size: u16 = 8;

/// The largest block a request may ask for, and the largest this package
/// reads.
///
/// **RFC 2348 permits 65464, and this package holds 8192.** The read
/// buffer is a field of `Fetcher` and `max_datagram_bytes` is built from
/// this number, so this number is the size of every `Fetcher` a program
/// holds. The RFC's own top would make each one 64 KiB of buffer that
/// almost no transfer uses.
///
/// 8192 is the largest power of two whose datagram, 8196 bytes, still
/// fits inside a 9000 byte jumbo frame. A larger block is fragmented by
/// IP on every path, and one lost fragment loses the whole block, so the
/// larger number costs a transfer more than it gives it.
///
/// A request above this is refused by name and never clamped. See
/// `writeReadRequest`.
pub const max_block_size: u16 = 8192;

/// How large a datagram this package reads: the four byte header of a
/// `data` packet, and one block behind it.
pub const max_datagram_bytes: usize = 4 + max_block_size;

/// How many bytes of file name this package sends.
///
/// The name goes into one datagram beside the mode and the options, so it
/// is bounded by what a datagram holds. curl keeps no bound of its own.
pub const max_filename_bytes: usize = 512;

/// How large a request datagram this package writes: the opcode, the name,
/// the mode, and the three options.
pub const max_request_bytes: usize = max_filename_bytes + 128;

/// Writes the `read_request` for `filename` into `out`.
///
/// **These are curl's own default bytes**, measured with
/// `curl tftp://127.0.0.1:PORT/hello.txt` against a listener that
/// captured the datagram:
///
/// ```
/// 00 01 'hello.txt' 00 'octet' 00
/// 'tsize' 00 '0' 00 'blksize' 00 '512' 00 'timeout' 00 '6' 00
/// ```
///
/// `send_options` false writes the first line alone, which is what
/// `curl --tftp-no-options` sends, measured:
///
/// ```
/// 00 01 'hello.txt' 00 'octet' 00
/// ```
///
/// The three options are RFC 2347 through RFC 2349. `tsize 0` asks the
/// server for the size of the file, `blksize` names the block size this
/// package reads, and `timeout 6` asks the server to wait six seconds
/// before it sends a block again. A server that reads none of them answers
/// with the first `data` packet and the transfer runs anyway, which is
/// what RFC 2347 requires of it.
///
/// `block_size` is the number the `blksize` option carries, which is what
/// `curl --tftp-blksize` names. It must lie between `min_block_size` and
/// `max_block_size`, and a number outside that range is
/// `error.BlockSizeOutOfRange`. **The number is never clamped**, and the
/// range is read even when `send_options` is false, so one value gives
/// one answer whichever request goes out.
///
/// **The name carries no NUL, no CR, and no LF.** A NUL would end the name
/// field early and turn the rest of the name into the mode, so the caller
/// holds the name to `zurl_core.url.hasFramingByte` before it reaches
/// here. `writeReadRequest` asserts nothing about that: it returns
/// `error.NameHasFramingByte` so a build with the assert removed still
/// refuses.
pub fn writeReadRequest(
    out: []u8,
    filename: []const u8,
    mode: Mode,
    send_options: bool,
    block_size: u16,
) error{ RequestTooLong, NameHasFramingByte, BlockSizeOutOfRange }![]const u8 {
    if (zurl_core.url.hasFramingByte(filename)) return error.NameHasFramingByte;
    if (block_size < min_block_size or block_size > max_block_size) {
        return error.BlockSizeOutOfRange;
    }

    var w: std.Io.Writer = .fixed(out);
    writeBody(&w, filename, mode, send_options, block_size) catch return error.RequestTooLong;
    return w.buffered();
}

fn writeBody(
    w: *std.Io.Writer,
    filename: []const u8,
    mode: Mode,
    send_options: bool,
    block_size: u16,
) std.Io.Writer.Error!void {
    try w.writeInt(u16, @intFromEnum(Opcode.read_request), .big);
    try w.writeAll(filename);
    try w.writeByte(0);
    try w.writeAll(mode.text());
    try w.writeByte(0);
    if (!send_options) return;
    // The order is curl's own order, measured. Nothing on the wire depends
    // on it, and matching it keeps the two captures comparable byte for
    // byte.
    try w.writeAll("tsize\x000\x00");
    try w.print("blksize\x00{d}\x00", .{block_size});
    try w.writeAll(std.fmt.comptimePrint(
        "timeout\x00{d}\x00",
        .{default_server_timeout_seconds},
    ));
}

/// Writes the `ack` for block `block` into `out`.
///
/// Four bytes: the opcode 4, then the block number, both big endian. RFC
/// 1350 section 5.
pub fn writeAck(out: *[4]u8, block: u16) []const u8 {
    std.mem.writeInt(u16, out[0..2], @intFromEnum(Opcode.ack), .big);
    std.mem.writeInt(u16, out[2..4], block, .big);
    return out;
}

/// What one datagram from the server holds.
pub const Incoming = union(enum) {
    /// One block of the file, and the number that names it.
    data: struct { block: u16, bytes: []const u8 },
    /// The server refused. The message is the server's own text, which may
    /// be empty.
    err: struct { code: ErrorCode, message: []const u8 },
    /// The server read the options in the request. RFC 2347.
    oack: Options,
    /// An `ack`, which a download never expects, or an opcode nobody
    /// named. Both are the same answer to the caller: the peer sent
    /// something this transfer cannot use.
    unusable: Opcode,
};

/// The options a server answered with. A null field is an option the
/// server did not name, which leaves that option at its default.
pub const Options = struct {
    /// The block size the server will send, from RFC 2348. Never above the
    /// number the request asked for.
    block_size: ?u16 = null,
    /// The size of the file, from RFC 2349's `tsize`.
    total_size: ?u64 = null,
};

pub const ParseError = error{
    /// The datagram is shorter than the header its opcode needs.
    Truncated,
    /// An `oack` named a block size above the one the request asked for,
    /// or one no `blksize` may carry. RFC 2348 lets a server answer with
    /// the number it was offered or less, never more.
    BlockSizeTooLarge,
};

/// Reads one datagram from the server.
///
/// `requested_block_size` is the number the request asked for, which
/// bounds what an `oack` may answer. A caller that sent no options passes
/// `default_block_size`.
///
/// The returned slices borrow from `datagram`, so it must outlive the
/// result.
pub fn parse(datagram: []const u8, requested_block_size: u16) ParseError!Incoming {
    if (datagram.len < 2) return error.Truncated;
    const opcode: Opcode = @enumFromInt(std.mem.readInt(u16, datagram[0..2], .big));
    switch (opcode) {
        .data => {
            if (datagram.len < 4) return error.Truncated;
            return .{ .data = .{
                .block = std.mem.readInt(u16, datagram[2..4], .big),
                .bytes = datagram[4..],
            } };
        },
        .err => {
            if (datagram.len < 4) return error.Truncated;
            const code: ErrorCode = @enumFromInt(std.mem.readInt(u16, datagram[2..4], .big));
            // The message is NUL terminated. A server that left the NUL
            // off is still a server whose message a user should read, so
            // the rest of the datagram is the message in that case.
            const rest = datagram[4..];
            const end = std.mem.indexOfScalar(u8, rest, 0) orelse rest.len;
            return .{ .err = .{ .code = code, .message = rest[0..end] } };
        },
        .oack => return .{ .oack = try parseOptions(datagram[2..], requested_block_size) },
        else => return .{ .unusable = opcode },
    }
}

/// Reads the NUL separated name and value pairs of an `oack`.
///
/// A name this package did not ask for is skipped. RFC 2347 says a server
/// answers only with options the client offered, and a server that answers
/// with another one is naming something the transfer never asked about, so
/// leaving it alone changes nothing about the transfer.
///
/// A value that does not read as a number leaves that option unset, which
/// is the same as a server that did not answer the option at all. That is
/// the safe reading: an option the server did not accept keeps the value
/// RFC 1350 fixes, so an unset `blksize` leaves the transfer at 512 and
/// never above the number the request offered.
fn parseOptions(body: []const u8, requested_block_size: u16) ParseError!Options {
    var out: Options = .{};
    var rest = body;
    while (rest.len > 0) {
        const name_end = std.mem.indexOfScalar(u8, rest, 0) orelse return out;
        const name = rest[0..name_end];
        rest = rest[name_end + 1 ..];
        const value_end = std.mem.indexOfScalar(u8, rest, 0) orelse rest.len;
        const value = rest[0..value_end];
        rest = rest[@min(value_end + 1, rest.len)..];

        if (std.ascii.eqlIgnoreCase(name, "blksize")) {
            const size = std.fmt.parseInt(u16, value, 10) catch continue;
            // RFC 2348 lets a server shrink the block and never grow it.
            // A larger number would be a server choosing a datagram this
            // package's buffer cannot hold, so it is a fault and never a
            // size to grow into.
            if (size > requested_block_size or size == 0) return error.BlockSizeTooLarge;
            out.block_size = size;
        } else if (std.ascii.eqlIgnoreCase(name, "tsize")) {
            out.total_size = std.fmt.parseInt(u64, value, 10) catch continue;
        }
    }
    return out;
}

const testing = std.testing;

test "the read request is byte for byte what curl 8.21.0 sends" {
    var out: [max_request_bytes]u8 = undefined;
    const request = try writeReadRequest(&out, "hello.txt", .octet, true, default_block_size);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01 } ++
        "hello.txt\x00octet\x00tsize\x000\x00blksize\x00512\x00timeout\x006\x00".*, request);
}

test "the option free request is what curl --tftp-no-options sends" {
    var out: [max_request_bytes]u8 = undefined;
    const request = try writeReadRequest(&out, "hello.txt", .octet, false, default_block_size);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01 } ++ "hello.txt\x00octet\x00".*, request);

    // A block size beside the option free request changes nothing on the
    // wire. The request carries no option block at all, so there is no
    // `blksize` for the number to reach, and the transfer runs at the 512
    // bytes RFC 1350 fixes.
    const asked = try writeReadRequest(&out, "hello.txt", .octet, false, 4096);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01 } ++ "hello.txt\x00octet\x00".*, asked);
}

test "the read request carries the block size it was asked for" {
    // **This is `--tftp-blksize` on the wire.** RFC 2348 puts the number
    // in the request, so the whole flag is these digits and nothing else.
    var out: [max_request_bytes]u8 = undefined;
    const request = try writeReadRequest(&out, "hello.txt", .octet, true, 1428);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01 } ++
        "hello.txt\x00octet\x00tsize\x000\x00blksize\x001428\x00timeout\x006\x00".*, request);

    // The two ends of the range write their own digits as well, so no
    // number inside the range is turned into another one.
    const smallest = try writeReadRequest(&out, "f", .octet, true, min_block_size);
    try testing.expect(std.mem.indexOf(u8, smallest, "blksize\x008\x00") != null);

    const largest = try writeReadRequest(&out, "f", .octet, true, max_block_size);
    try testing.expect(std.mem.indexOf(u8, largest, "blksize\x008192\x00") != null);
}

test "a block size outside the range is refused by name and never clamped" {
    // RFC 2348 floors the option at 8, and this package holds a ceiling
    // of its own because the read buffer is sized from it. A number
    // outside either bound is a fault the user reads about, because a
    // clamp would send digits the user never wrote and the transfer would
    // then run at a size nobody asked for.
    var out: [max_request_bytes]u8 = undefined;
    for ([_]u16{ 0, 1, 7, max_block_size + 1, 16384, 65464, 65535 }) |size| {
        try testing.expectError(
            error.BlockSizeOutOfRange,
            writeReadRequest(&out, "f.txt", .octet, true, size),
        );
    }

    // And the range is read for the option free request too, so one
    // number gives one answer whichever request goes out.
    try testing.expectError(
        error.BlockSizeOutOfRange,
        writeReadRequest(&out, "f.txt", .octet, false, 7),
    );

    // Both ends of the range are inside it.
    try testing.expect((try writeReadRequest(&out, "f", .octet, true, min_block_size)).len > 0);
    try testing.expect((try writeReadRequest(&out, "f", .octet, true, max_block_size)).len > 0);
}

test "the netascii mode writes curl's own second name" {
    // Measured: `curl -B tftp://h/f.txt` sends `netascii` in this field.
    var out: [max_request_bytes]u8 = undefined;
    const request = try writeReadRequest(&out, "f.txt", .netascii, false, default_block_size);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01 } ++ "f.txt\x00netascii\x00".*, request);
}

test "a name with a framing byte is refused, where curl sends it" {
    // **The injection proof for this package.** A NUL ends the name field,
    // so `a\x00b` would name the file `a` and read `b` as the mode. curl
    // refuses a NUL too: `tftp://h/a%00b` exits 3, measured.
    //
    // A CR and an LF are refused as well, and curl sends both:
    // `tftp://h/a%0d%0ab` reaches the wire from curl with the two bytes
    // inside the name, measured. A file name that carries a line ending
    // is not a name any server holds, and one rule over the three bytes
    // is what keeps this package and `zurl-gopher` reading the same rule.
    var out: [max_request_bytes]u8 = undefined;
    for ([_][]const u8{ "a\x00b", "a\rb", "a\nb", "a\r\nb" }) |name| {
        try testing.expectError(
            error.NameHasFramingByte,
            writeReadRequest(&out, name, .octet, true, default_block_size),
        );
    }

    // And nothing else is refused. A space and a high byte are both parts
    // of real file names, and curl sends each.
    const spaced = try writeReadRequest(&out, "a b.txt", .octet, false, default_block_size);
    try testing.expect(spaced.len > 0);
    const high = try writeReadRequest(&out, "\xc3\xa9.txt", .octet, false, default_block_size);
    try testing.expect(high.len > 0);
}

test "a request longer than the datagram is refused rather than cut" {
    var out: [16]u8 = undefined;
    try testing.expectError(
        error.RequestTooLong,
        writeReadRequest(&out, "a-name-longer-than-the-buffer.txt", .octet, true, default_block_size),
    );
}

test "an ack is the opcode and the block, big endian" {
    var out: [4]u8 = undefined;
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 4, 0, 1 }, writeAck(&out, 1));
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 4, 0, 0 }, writeAck(&out, 0));
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 4, 0xff, 0xff }, writeAck(&out, 65535));
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 4, 0x01, 0x00 }, writeAck(&out, 256));
}

test "a data packet reads its block number and its bytes" {
    const datagram = [_]u8{ 0, 3, 0, 1 } ++ "payload".*;
    const packet = try parse(&datagram, default_block_size);
    try testing.expectEqual(@as(u16, 1), packet.data.block);
    try testing.expectEqualStrings("payload", packet.data.bytes);

    // A block of no bytes is the last block of a file whose size is a
    // whole number of blocks. It is not a fault.
    const empty = [_]u8{ 0, 3, 0, 2 };
    const last = try parse(&empty, default_block_size);
    try testing.expectEqual(@as(u16, 2), last.data.block);
    try testing.expectEqual(@as(usize, 0), last.data.bytes.len);
}

test "an error packet reads its code and its message" {
    const datagram = [_]u8{ 0, 5, 0, 1 } ++ "File not found\x00".*;
    const packet = try parse(&datagram, default_block_size);
    try testing.expectEqual(ErrorCode.file_not_found, packet.err.code);
    try testing.expectEqualStrings("File not found", packet.err.message);

    // A message with no NUL is still a message a user should read.
    const no_nul = [_]u8{ 0, 5, 0, 2 } ++ "no room".*;
    try testing.expectEqualStrings("no room", (try parse(&no_nul, default_block_size)).err.message);

    // And a message of no bytes is not a fault.
    const bare = [_]u8{ 0, 5, 0, 3 };
    try testing.expectEqualStrings("", (try parse(&bare, default_block_size)).err.message);
}

test "every RFC 1350 error code carries curl's own exit code" {
    // curl's manual page lists 68 through 74 for these seven, in order.
    const rows = [_]struct { code: ErrorCode, want: u32 }{
        .{ .code = .file_not_found, .want = 68 },
        .{ .code = .access_violation, .want = 69 },
        .{ .code = .disk_full, .want = 70 },
        .{ .code = .illegal_operation, .want = 71 },
        .{ .code = .unknown_transfer_id, .want = 72 },
        .{ .code = .file_already_exists, .want = 73 },
        .{ .code = .no_such_user, .want = 74 },
    };
    for (rows) |row| {
        try testing.expectEqual(row.want, zurl_core.errors.curlCode(errorFor(row.code)));
    }

    // A code curl has no number for reads as the code it uses for a
    // request the server would not run.
    try testing.expectEqual(@as(u32, 71), zurl_core.errors.curlCode(errorFor(.undefined_error)));
    try testing.expectEqual(
        @as(u32, 71),
        zurl_core.errors.curlCode(errorFor(.option_negotiation_failed)),
    );
    try testing.expectEqual(@as(u32, 71), zurl_core.errors.curlCode(errorFor(@enumFromInt(99))));
}

test "an oack reads the options it names and skips the rest" {
    const datagram = [_]u8{ 0, 6 } ++ "blksize\x00512\x00tsize\x001234\x00".*;
    const options = (try parse(&datagram, default_block_size)).oack;
    try testing.expectEqual(@as(?u16, 512), options.block_size);
    try testing.expectEqual(@as(?u64, 1234), options.total_size);

    // An option nobody asked about changes nothing.
    const extra = [_]u8{ 0, 6 } ++ "windowsize\x004\x00tsize\x007\x00".*;
    const skipped = (try parse(&extra, default_block_size)).oack;
    try testing.expectEqual(@as(?u16, null), skipped.block_size);
    try testing.expectEqual(@as(?u64, 7), skipped.total_size);

    // An empty `oack` is a server that answered no option at all.
    const bare = [_]u8{ 0, 6 };
    const none = (try parse(&bare, default_block_size)).oack;
    try testing.expectEqual(@as(?u16, null), none.block_size);
    try testing.expectEqual(@as(?u64, null), none.total_size);

    // A value that is not a number leaves the option where it was, which
    // is what a server that never answered it leaves it at.
    const junk = [_]u8{ 0, 6 } ++ "tsize\x00big\x00".*;
    try testing.expectEqual(@as(?u64, null), (try parse(&junk, default_block_size)).oack.total_size);
}

test "an oack may shrink the block and may never grow it" {
    // RFC 2348. A larger number names a datagram this package's buffer
    // cannot hold, so it is a fault and never a size to grow into.
    const smaller = [_]u8{ 0, 6 } ++ "blksize\x00128\x00".*;
    try testing.expectEqual(
        @as(?u16, 128),
        (try parse(&smaller, default_block_size)).oack.block_size,
    );

    const larger = [_]u8{ 0, 6 } ++ "blksize\x001024\x00".*;
    try testing.expectError(error.BlockSizeTooLarge, parse(&larger, default_block_size));

    // Zero is no block at all, so it is refused for the same reason.
    const zero = [_]u8{ 0, 6 } ++ "blksize\x000\x00".*;
    try testing.expectError(error.BlockSizeTooLarge, parse(&zero, default_block_size));
}

test "the rule holds against the block size the request asked for" {
    // A request that asked for more than 512 moves the line, and it moves
    // it to the number that request named. The buffer holds one block of
    // the size the request asked for, so a server that answers with more
    // than that names a datagram this package cannot read whole.
    const same = [_]u8{ 0, 6 } ++ "blksize\x004096\x00".*;
    try testing.expectEqual(@as(?u16, 4096), (try parse(&same, 4096)).oack.block_size);

    // A server may still shrink from a larger request.
    const smaller = [_]u8{ 0, 6 } ++ "blksize\x00512\x00".*;
    try testing.expectEqual(@as(?u16, 512), (try parse(&smaller, 4096)).oack.block_size);

    // And a number above the request is a fault, whatever the request
    // asked for.
    const grown = [_]u8{ 0, 6 } ++ "blksize\x008192\x00".*;
    try testing.expectError(error.BlockSizeTooLarge, parse(&grown, 4096));

    // A request at the package ceiling still refuses a number above it,
    // so no `oack` can name a datagram larger than the read buffer.
    const past_ceiling = [_]u8{ 0, 6 } ++ "blksize\x0065464\x00".*;
    try testing.expectError(error.BlockSizeTooLarge, parse(&past_ceiling, max_block_size));
}

test "a datagram shorter than its own header is refused" {
    try testing.expectError(error.Truncated, parse(&[_]u8{}, default_block_size));
    try testing.expectError(error.Truncated, parse(&[_]u8{0}, default_block_size));
    try testing.expectError(error.Truncated, parse(&[_]u8{ 0, 3 }, default_block_size));
    try testing.expectError(error.Truncated, parse(&[_]u8{ 0, 3, 0 }, default_block_size));
    try testing.expectError(error.Truncated, parse(&[_]u8{ 0, 5, 0 }, default_block_size));
}

test "an opcode a download cannot use is named and not guessed at" {
    // An `ack` from a server, and an opcode nobody defined. Both are the
    // peer sending something this transfer has no use for, and neither
    // may be read as a block of the file.
    const ack = [_]u8{ 0, 4, 0, 1 };
    try testing.expectEqual(Opcode.ack, (try parse(&ack, default_block_size)).unusable);

    const unknown = [_]u8{ 0, 99, 0, 1 };
    try testing.expectEqual(
        @as(u16, 99),
        @intFromEnum((try parse(&unknown, default_block_size)).unusable),
    );

    // A `read_request` from a server is the same answer.
    const rrq = [_]u8{ 0, 1, 'a', 0 };
    try testing.expectEqual(Opcode.read_request, (try parse(&rrq, default_block_size)).unusable);
}

test "the datagram bound holds one whole block of the largest size" {
    // The buffer is built from the ceiling, so the ceiling is what bounds
    // every read this package makes. An unbounded ceiling would be an
    // unbounded buffer in every `Fetcher` a program holds.
    try testing.expectEqual(@as(usize, 4 + 8192), max_datagram_bytes);
    try testing.expectEqual(@as(usize, 4 + @as(usize, max_block_size)), max_datagram_bytes);

    // The range holds RFC 2348's floor, holds the default a request asks
    // for with no flag beside it, and stays under RFC 2348's own top.
    try testing.expectEqual(@as(u16, 8), min_block_size);
    try testing.expect(min_block_size <= default_block_size);
    try testing.expect(max_block_size > default_block_size);
    try testing.expect(max_block_size <= 65464);
}
