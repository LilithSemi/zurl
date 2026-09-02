//! A read position inside one QUIC datagram.
//!
//! **This is where a number the peer chose meets the bytes that are really
//! there.** `varint.zig` reads a length and can hand back 2^62. Every
//! `take` here checks that number against the bytes left in this datagram
//! **before** it makes a slice, so a peer that writes an enormous length
//! gets `error.Truncated` and this process reads nothing it was not sent.
//!
//! **Nothing here allocates, so no peer number can ask for memory.** A
//! QUIC packet arrives whole, in one datagram, and every field of it is
//! already in the caller's buffer. So a decoded frame borrows the bytes it
//! points at and copies none of them. That is the whole answer to "never
//! allocate from a peer's number": there is no allocator in this package.
//!
//! **This is not a second bounded reader.** `zurl_net.bounded` bounds a
//! wait on a socket, which is a clock question. This bounds an index into
//! a slice that is already in memory, which is an arithmetic question. The
//! two have no code in common and this one does no I/O at all.
//!
//! The one rule a caller must keep: a slice this returns lives exactly as
//! long as the datagram buffer does. Nothing here copies.

const std = @import("std");

const varint = @import("varint.zig");

const Cursor = @This();

/// The datagram, or the part of one this cursor may read.
bytes: []const u8,
/// How many bytes have been read.
at: usize = 0,

/// Starts a cursor at the front of `bytes`.
pub fn init(bytes: []const u8) Cursor {
    return .{ .bytes = bytes, .at = 0 };
}

/// Why a read could not be served.
pub const Error = error{
    /// Fewer bytes are left than the read asked for. A field that runs
    /// past the end of the datagram lands here, and so does a
    /// varint-declared length that names more bytes than arrived.
    Truncated,
};

/// How many bytes are left.
pub fn remaining(self: Cursor) usize {
    return self.bytes.len - self.at;
}

/// True when nothing is left.
pub fn isEmpty(self: Cursor) bool {
    return self.remaining() == 0;
}

/// Every byte that is left, without reading any of them.
pub fn rest(self: Cursor) []const u8 {
    return self.bytes[self.at..];
}

/// Reads `n` bytes.
///
/// **`n` may come from the peer, and this is the check that makes that
/// safe.** The comparison is on `remaining`, which is a count of bytes
/// that arrived, so no arithmetic on `n` can overflow into a larger
/// slice.
pub fn take(self: *Cursor, n: usize) Error![]const u8 {
    if (n > self.remaining()) return error.Truncated;
    const out = self.bytes[self.at..][0..n];
    self.at += n;
    return out;
}

/// Reads `n` bytes named by a varint.
///
/// **`n` is 64 bits wide and `usize` may be 32.** The comparison runs at
/// the wider width, so a length no `usize` can hold is refused here, and
/// the narrowing after it can only see a number that is at or below the
/// bytes that arrived.
pub fn takeVarintLength(self: *Cursor, n: u64) Error![]const u8 {
    if (n > self.remaining()) return error.Truncated;
    return self.take(@intCast(n));
}

/// Reads one byte.
pub fn takeByte(self: *Cursor) Error!u8 {
    return (try self.take(1))[0];
}

/// Reads `n` bytes as an array, which a caller can index at comptime.
pub fn takeArray(self: *Cursor, comptime n: usize) Error!*const [n]u8 {
    return (try self.take(n))[0..n];
}

/// Reads one variable-length integer. RFC 9000 section 16.
pub fn takeVarint(self: *Cursor) Error!u64 {
    const read = varint.decode(self.rest()) catch return error.Truncated;
    self.at += read.len;
    return read.value;
}

/// Reads one variable-length integer and says how it was spelled.
///
/// Only the Frame Type field of RFC 9000 section 12.4 needs the spelling.
pub fn takeVarintDecoded(self: *Cursor) Error!varint.Decoded {
    const read = varint.decode(self.rest()) catch return error.Truncated;
    self.at += read.len;
    return read;
}

/// Moves past `n` bytes without returning them.
pub fn skip(self: *Cursor, n: usize) Error!void {
    _ = try self.take(n);
}

const testing = std.testing;

test "take reads the bytes it was asked for and moves the position" {
    var c: Cursor = .init(&.{ 1, 2, 3, 4, 5 });
    try testing.expectEqual(@as(usize, 5), c.remaining());
    try testing.expectEqualSlices(u8, &.{ 1, 2 }, try c.take(2));
    try testing.expectEqual(@as(usize, 2), c.at);
    try testing.expectEqualSlices(u8, &.{ 3, 4, 5 }, c.rest());
    try testing.expect(!c.isEmpty());
    try testing.expectEqualSlices(u8, &.{ 3, 4, 5 }, try c.take(3));
    try testing.expect(c.isEmpty());
}

test "a read past the end takes nothing and leaves the position alone" {
    // A cursor that moved on a refused read would let the next field be
    // read from the wrong place, so the position must not change.
    var c: Cursor = .init(&.{ 1, 2, 3 });
    try testing.expectError(error.Truncated, c.take(4));
    try testing.expectEqual(@as(usize, 0), c.at);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, try c.take(3));
    try testing.expectError(error.Truncated, c.take(1));
}

test "a varint length of 2^62 is refused against the bytes that arrived" {
    // **The hazard this file exists for.** The peer writes the largest
    // number QUIC can spell as a length, and three bytes follow it. A
    // reader with no bound here would make a slice of four exabytes.
    const claim = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 2, 3 };
    var c: Cursor = .init(&claim);
    const n = try c.takeVarint();
    try testing.expectEqual(varint.max_value, n);
    try testing.expectError(error.Truncated, c.takeVarintLength(n));
    // Nothing was read, so the three bytes are still there.
    try testing.expectEqual(@as(usize, 3), c.remaining());
}

test "a varint length of exactly the bytes left is read whole" {
    // The bound counts the bytes that arrived, so a length that names all
    // of them is legal and a length one larger is not.
    const bytes = [_]u8{ 0x03, 'a', 'b', 'c' };
    var c: Cursor = .init(&bytes);
    const n = try c.takeVarint();
    try testing.expectEqualStrings("abc", try c.takeVarintLength(n));
    try testing.expect(c.isEmpty());

    var short: Cursor = .init(&.{ 0x04, 'a', 'b', 'c' });
    const too_many = try short.takeVarint();
    try testing.expectError(error.Truncated, short.takeVarintLength(too_many));
}

test "takeVarint reports a number that stops inside itself as Truncated" {
    var c: Cursor = .init(&.{0xc0});
    try testing.expectError(error.Truncated, c.takeVarint());
    var empty: Cursor = .init(&.{});
    try testing.expectError(error.Truncated, empty.takeVarint());
}

test "takeVarintDecoded says how a number was spelled" {
    // `0x4025` and `0x25` are both 37, and only the Frame Type field
    // cares which one arrived.
    var long: Cursor = .init(&.{ 0x40, 0x25 });
    const spelled_long = try long.takeVarintDecoded();
    try testing.expectEqual(@as(u64, 37), spelled_long.value);
    try testing.expect(!spelled_long.isMinimal());

    var short: Cursor = .init(&.{0x25});
    const spelled_short = try short.takeVarintDecoded();
    try testing.expectEqual(@as(u64, 37), spelled_short.value);
    try testing.expect(spelled_short.isMinimal());
}

test "takeArray gives a fixed-size view a caller can index at comptime" {
    var c: Cursor = .init(&.{ 0xde, 0xad, 0xbe, 0xef, 0x00 });
    const four = try c.takeArray(4);
    try testing.expectEqual(@as(u32, 0xdeadbeef), std.mem.readInt(u32, four, .big));
    try testing.expectEqual(@as(u8, 0), try c.takeByte());
    try testing.expectError(error.Truncated, c.takeArray(1));
}

test "skip moves past bytes and still keeps the bound" {
    var c: Cursor = .init(&.{ 1, 2, 3, 4 });
    try c.skip(3);
    try testing.expectEqual(@as(usize, 1), c.remaining());
    try testing.expectError(error.Truncated, c.skip(2));
}
