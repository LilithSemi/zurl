//! The SFTP wire format, version 3. Pure bytes, and testable with a table.
//!
//! Version 3 is `draft-ietf-secsh-filexfer-02`, and it is what OpenSSH
//! speaks. The draft expired and the working group went on to versions 4
//! through 6, and OpenSSH implements none of them: `sftp-server.c` answers
//! `SSH2_FILEXFER_VERSION 3` and nothing else. A client that offered a
//! later version would negotiate down to 3 against every server it will
//! ever meet, so this build offers 3.
//!
//! A packet is
//!
//! ```
//! uint32  length          the bytes after this field
//! byte    type
//! uint32  request id      every type but INIT and VERSION
//! ...     the type's own fields
//! ```
//!
//! **Every length in it is the peer's.** A `string` length, an attribute
//! flag word, a name count, and a file size are all fields the server
//! chose. `zurl_ssh.wire.Reader` checks each string against what is left
//! of the packet before it takes a byte, and `max_packet_bytes` is the
//! bound on the packet itself. `Session` is where the packet bound is
//! applied, because only it holds the buffer.
//!
//! **A file name in a `SSH_FXP_NAME` reply is the server's text.** It can
//! hold a path separator, a control byte, or `..`. Nothing here writes one
//! to disk, and a caller that turns one into an output file name puts it
//! through `src/cli/output.zig`'s `checkName`, which is the one function
//! in this repository that judges such a name.

const std = @import("std");
const zurl_ssh = @import("zurl-ssh");

const wire = zurl_ssh.wire;

/// The version this build speaks. See the module comment.
pub const version: u32 = 3;

/// The subsystem name RFC 4254 section 6.5 carries for this protocol.
pub const subsystem_name = "sftp";

/// The largest packet this build sends or takes.
///
/// 256 KiB, which is what OpenSSH's `sftp-server` allows
/// (`SFTP_MAX_MSG_LENGTH`). A larger claim is refused before one byte of
/// the body is read.
pub const max_packet_bytes: u32 = 256 * 1024;

/// The smallest packet the grammar has: one type byte.
pub const min_packet_bytes: u32 = 1;

/// The largest `SSH_FXP_READ` this build asks for in one request.
///
/// 32 KiB. OpenSSH's own client asks for the same, and a server may answer
/// with less, which section 6.4 of the draft allows and which this build
/// takes.
pub const max_read_bytes: u32 = 32 * 1024;

/// The largest `SSH_FXP_WRITE` payload this build sends in one request.
pub const max_write_bytes: u32 = 32 * 1024;

/// The largest path this build sends.
pub const max_path_bytes: usize = 4096;

/// The largest handle this build keeps.
///
/// The draft says a handle is at most 256 bytes.
pub const max_handle_bytes: usize = 256;

/// The largest status message this build keeps, in bytes.
pub const max_message_bytes: usize = 1024;

/// The packet types of version 3.
///
/// Non-exhaustive, because the peer writes this byte.
pub const Type = enum(u8) {
    init = 1,
    version = 2,
    open = 3,
    close = 4,
    read = 5,
    write = 6,
    lstat = 7,
    fstat = 8,
    setstat = 9,
    fsetstat = 10,
    opendir = 11,
    readdir = 12,
    remove = 13,
    mkdir = 14,
    rmdir = 15,
    realpath = 16,
    stat = 17,
    rename = 18,
    readlink = 19,
    symlink = 20,
    status = 101,
    handle = 102,
    data = 103,
    name = 104,
    attrs = 105,
    extended = 200,
    extended_reply = 201,
    _,
};

/// The `pflags` of `SSH_FXP_OPEN`, section 6.3 of the draft.
pub const open_read: u32 = 0x0000_0001;
pub const open_write: u32 = 0x0000_0002;
pub const open_append: u32 = 0x0000_0004;
pub const open_create: u32 = 0x0000_0008;
pub const open_truncate: u32 = 0x0000_0010;
pub const open_exclusive: u32 = 0x0000_0020;

/// The `flags` of an ATTRS structure, section 5 of the draft.
pub const attr_size: u32 = 0x0000_0001;
pub const attr_uidgid: u32 = 0x0000_0002;
pub const attr_permissions: u32 = 0x0000_0004;
pub const attr_acmodtime: u32 = 0x0000_0008;
pub const attr_extended: u32 = 0x8000_0000;

/// How many extended attribute pairs this build reads before it refuses.
///
/// The count is a `uint32` the server writes, and it decides how many
/// strings a reader then walks. It is checked **before one pair is read**.
pub const max_extended_pairs: u32 = 64;

/// How many names one `SSH_FXP_NAME` may carry.
pub const max_names: u32 = 4096;

/// The status codes of version 3, section 7 of the draft.
///
/// Non-exhaustive, because the field is a `uint32` and a server may write
/// a code a later version assigned.
pub const Status = enum(u32) {
    ok = 0,
    eof = 1,
    no_such_file = 2,
    permission_denied = 3,
    failure = 4,
    bad_message = 5,
    no_connection = 6,
    connection_lost = 7,
    op_unsupported = 8,
    _,

    /// zurl's own sentence for a code, or null for one it does not name.
    ///
    /// The server sends its own message too, and that text is untrusted.
    /// This is what zurl says about the number beside it.
    pub fn text(status: Status) ?[]const u8 {
        return switch (status) {
            .ok => "the server reported no fault",
            .eof => "there is nothing more to read",
            .no_such_file => "the server has no such file",
            .permission_denied => "the server refused permission",
            .failure => "the server reported a failure",
            .bad_message => "the server could not read the request",
            .no_connection => "the server has no connection",
            .connection_lost => "the server lost its connection",
            .op_unsupported => "the server does not carry out this request",
            _ => null,
        };
    }
};

/// Why a packet could not be read.
pub const ParseError = wire.ReadError || error{
    /// The type byte is not the one asked for.
    WrongPacketType,
    /// A count field claims more than this build reads.
    CountTooLarge,
    /// The packet carried bytes after its last field.
    TrailingBytes,
};

/// Why a packet could not be built.
pub const BuildError = wire.WriteError;

/// Writes `SSH_FXP_INIT`, section 4 of the draft.
///
/// It carries the version and no request id, which is the one packet
/// besides `SSH_FXP_VERSION` that does not.
pub fn writeInit(out: []u8) BuildError![]u8 {
    var w: wire.Writer = .init(out);
    try w.uint32(1 + 4);
    try w.byte(@intFromEnum(Type.init));
    try w.uint32(version);
    return w.written();
}

/// Writes `SSH_FXP_OPEN`, section 6.3.
///
/// The attributes are empty, so the server picks the mode for a file it
/// creates. OpenSSH's own client does the same for a plain upload.
pub fn writeOpen(out: []u8, id: u32, path: []const u8, pflags: u32) BuildError![]u8 {
    var body: wire.Writer = .init(try afterLength(out));
    try body.byte(@intFromEnum(Type.open));
    try body.uint32(id);
    try body.string(path);
    try body.uint32(pflags);
    // An ATTRS with no flag set, which is four zero bytes.
    try body.uint32(0);
    return finish(out, body.at);
}

/// Writes `SSH_FXP_CLOSE`, section 6.3.
pub fn writeClose(out: []u8, id: u32, handle: []const u8) BuildError![]u8 {
    return writeHandleOnly(out, .close, id, handle);
}

/// Writes `SSH_FXP_READ`, section 6.4.
pub fn writeRead(
    out: []u8,
    id: u32,
    handle: []const u8,
    offset: u64,
    len: u32,
) BuildError![]u8 {
    var body: wire.Writer = .init(try afterLength(out));
    try body.byte(@intFromEnum(Type.read));
    try body.uint32(id);
    try body.string(handle);
    try body.uint64(offset);
    try body.uint32(len);
    return finish(out, body.at);
}

/// Writes `SSH_FXP_WRITE`, section 6.4.
pub fn writeWrite(
    out: []u8,
    id: u32,
    handle: []const u8,
    offset: u64,
    data: []const u8,
) BuildError![]u8 {
    var body: wire.Writer = .init(try afterLength(out));
    try body.byte(@intFromEnum(Type.write));
    try body.uint32(id);
    try body.string(handle);
    try body.uint64(offset);
    try body.string(data);
    return finish(out, body.at);
}

/// Writes `SSH_FXP_STAT`, section 6.8.
///
/// `SSH_FXP_STAT` follows a symbolic link and `SSH_FXP_LSTAT` does not.
/// A download of a link should read what the link names, which is what
/// curl and OpenSSH's client both do, so this build sends `STAT`.
pub fn writeStat(out: []u8, id: u32, path: []const u8) BuildError![]u8 {
    return writePathOnly(out, .stat, id, path);
}

/// Writes `SSH_FXP_FSTAT`, section 6.8, which stats an open handle.
pub fn writeFstat(out: []u8, id: u32, handle: []const u8) BuildError![]u8 {
    return writeHandleOnly(out, .fstat, id, handle);
}

/// Writes `SSH_FXP_OPENDIR`, section 6.7.
pub fn writeOpendir(out: []u8, id: u32, path: []const u8) BuildError![]u8 {
    return writePathOnly(out, .opendir, id, path);
}

/// Writes `SSH_FXP_READDIR`, section 6.7.
pub fn writeReaddir(out: []u8, id: u32, handle: []const u8) BuildError![]u8 {
    return writeHandleOnly(out, .readdir, id, handle);
}

/// Writes `SSH_FXP_REALPATH`, section 6.9.
///
/// It turns a relative path into an absolute one, which is how a url with
/// no leading slash names a file under the login directory.
pub fn writeRealpath(out: []u8, id: u32, path: []const u8) BuildError![]u8 {
    return writePathOnly(out, .realpath, id, path);
}

fn writePathOnly(out: []u8, kind: Type, id: u32, path: []const u8) BuildError![]u8 {
    var body: wire.Writer = .init(try afterLength(out));
    try body.byte(@intFromEnum(kind));
    try body.uint32(id);
    try body.string(path);
    return finish(out, body.at);
}

fn writeHandleOnly(out: []u8, kind: Type, id: u32, handle: []const u8) BuildError![]u8 {
    var body: wire.Writer = .init(try afterLength(out));
    try body.byte(@intFromEnum(kind));
    try body.uint32(id);
    try body.string(handle);
    return finish(out, body.at);
}

/// The room after the four length bytes.
///
/// **A buffer smaller than the length field is a refusal and never a
/// slice.** `out[4..]` on a shorter buffer is out of bounds, so a caller
/// that passed a tiny buffer would take the process down rather than get
/// an error back, and a caller can pass any buffer it likes.
fn afterLength(out: []u8) BuildError![]u8 {
    if (out.len < 4) return error.NoSpaceLeft;
    return out[4..];
}

/// Writes the length in front of a body and returns the whole packet.
fn finish(out: []u8, body_len: usize) BuildError![]u8 {
    if (out.len < 4) return error.NoSpaceLeft;
    if (body_len > max_packet_bytes) return error.NoSpaceLeft;
    std.mem.writeInt(u32, out[0..4], @intCast(body_len), .big);
    return out[0 .. 4 + body_len];
}

/// The type byte of a packet body, or null for an empty body.
pub fn typeOf(body: []const u8) ?Type {
    if (body.len == 0) return null;
    return @enumFromInt(body[0]);
}

/// The request id of a packet body, or null for a type that carries none.
///
/// `SSH_FXP_INIT` and `SSH_FXP_VERSION` carry no id. Every other type
/// does, and a reply is matched against the request by this number.
pub fn requestIdOf(body: []const u8) ?u32 {
    const kind = typeOf(body) orelse return null;
    switch (kind) {
        .init, .version => return null,
        else => {},
    }
    if (body.len < 5) return null;
    return std.mem.readInt(u32, body[1..5], .big);
}

/// What a `SSH_FXP_VERSION` carries, section 4.
pub const Version = struct {
    version: u32,
    /// The extension pairs, unread. **Untrusted text.** This build uses
    /// none of them.
    extensions: []const u8,
};

/// Reads a `SSH_FXP_VERSION`.
pub fn parseVersion(body: []const u8) ParseError!Version {
    var r: wire.Reader = .init(body);
    if (try r.byte() != @intFromEnum(Type.version)) return error.WrongPacketType;
    return .{ .version = try r.uint32(), .extensions = r.rest() };
}

/// What a `SSH_FXP_STATUS` carries, section 7.
pub const StatusReply = struct {
    id: u32,
    status: Status,
    /// **Untrusted text**, and it may be empty: version 3 of the draft
    /// added the message and language fields, and an early server writes
    /// neither.
    message: []const u8,
    language: []const u8,
};

/// Reads a `SSH_FXP_STATUS`.
///
/// **The message and the language are optional.** The draft added them in
/// version 3, and OpenSSH writes them, but a reader that required them
/// would refuse a status packet from a server that does not. A missing
/// pair reads as two empty strings.
pub fn parseStatus(body: []const u8) ParseError!StatusReply {
    var r: wire.Reader = .init(body);
    if (try r.byte() != @intFromEnum(Type.status)) return error.WrongPacketType;
    const id = try r.uint32();
    const status: Status = @enumFromInt(try r.uint32());
    if (r.atEnd()) return .{ .id = id, .status = status, .message = "", .language = "" };
    const message = try r.string();
    const language = if (r.atEnd()) "" else try r.string();
    return .{ .id = id, .status = status, .message = message, .language = language };
}

/// What a `SSH_FXP_HANDLE` carries, section 6.2.
pub const HandleReply = struct {
    id: u32,
    /// Points into the body it was read from. **It is an opaque string
    /// and never a name**: the draft says a client must not read it.
    handle: []const u8,
};

/// Reads a `SSH_FXP_HANDLE`.
pub fn parseHandle(body: []const u8) ParseError!HandleReply {
    var r: wire.Reader = .init(body);
    if (try r.byte() != @intFromEnum(Type.handle)) return error.WrongPacketType;
    const out: HandleReply = .{ .id = try r.uint32(), .handle = try r.string() };
    if (!r.atEnd()) return error.TrailingBytes;
    return out;
}

/// What a `SSH_FXP_DATA` carries, section 6.4.
pub const DataReply = struct {
    id: u32,
    /// Points into the body it was read from.
    bytes: []const u8,
};

/// Reads a `SSH_FXP_DATA`.
pub fn parseData(body: []const u8) ParseError!DataReply {
    var r: wire.Reader = .init(body);
    if (try r.byte() != @intFromEnum(Type.data)) return error.WrongPacketType;
    const out: DataReply = .{ .id = try r.uint32(), .bytes = try r.string() };
    if (!r.atEnd()) return error.TrailingBytes;
    return out;
}

/// A file's attributes, section 5.
///
/// Every field is optional, because the flag word says which ones the
/// server wrote. A field that is not there is null, and **null is not
/// zero**: a server that sent no size said nothing about the size, and a
/// client that read it as zero would report an empty file.
pub const Attributes = struct {
    flags: u32,
    size: ?u64 = null,
    uid: ?u32 = null,
    gid: ?u32 = null,
    permissions: ?u32 = null,
    atime: ?u32 = null,
    mtime: ?u32 = null,

    /// Whether the permissions say this is a directory.
    ///
    /// `S_IFDIR`, which is 0o040000. A download of a directory is a
    /// different transfer from a download of a file, and a server answers
    /// a `READ` on a directory handle with a failure rather than the
    /// listing.
    pub fn isDirectory(a: Attributes) bool {
        const mode = a.permissions orelse return false;
        return mode & 0o170000 == 0o040000;
    }

    /// Whether the permissions say this is an ordinary file.
    pub fn isRegular(a: Attributes) bool {
        const mode = a.permissions orelse return false;
        return mode & 0o170000 == 0o100000;
    }
};

/// Reads an ATTRS out of `r`.
///
/// **The extended pair count is checked before one pair is read**, so a
/// server that claims four thousand million pairs costs one comparison.
pub fn readAttributes(r: *wire.Reader) ParseError!Attributes {
    var out: Attributes = .{ .flags = try r.uint32() };
    if (out.flags & attr_size != 0) out.size = try r.uint64();
    if (out.flags & attr_uidgid != 0) {
        out.uid = try r.uint32();
        out.gid = try r.uint32();
    }
    if (out.flags & attr_permissions != 0) out.permissions = try r.uint32();
    if (out.flags & attr_acmodtime != 0) {
        out.atime = try r.uint32();
        out.mtime = try r.uint32();
    }
    if (out.flags & attr_extended != 0) {
        const count = try r.uint32();
        if (count > max_extended_pairs) return error.CountTooLarge;
        var i: u32 = 0;
        while (i < count) : (i += 1) {
            _ = try r.string();
            _ = try r.string();
        }
    }
    return out;
}

/// What a `SSH_FXP_ATTRS` carries, section 6.8.
pub const AttrsReply = struct {
    id: u32,
    attributes: Attributes,
};

/// Reads a `SSH_FXP_ATTRS`.
pub fn parseAttrs(body: []const u8) ParseError!AttrsReply {
    var r: wire.Reader = .init(body);
    if (try r.byte() != @intFromEnum(Type.attrs)) return error.WrongPacketType;
    const id = try r.uint32();
    const attributes = try readAttributes(&r);
    if (!r.atEnd()) return error.TrailingBytes;
    return .{ .id = id, .attributes = attributes };
}

/// One entry of a `SSH_FXP_NAME`, section 6.7.
pub const Name = struct {
    /// **The server's text.** It can hold a path separator, a control
    /// byte, or `..`. See the module comment.
    filename: []const u8,
    /// The `ls -l` line the server built. **Untrusted text.**
    longname: []const u8,
    attributes: Attributes,
};

/// Walks the entries of a `SSH_FXP_NAME` one at a time.
///
/// An iterator and not a slice, because the entries are variable length
/// and a slice would need an allocation this module does not make.
pub const NameIterator = struct {
    reader: wire.Reader,
    left: u32,

    /// The next entry, or null at the end.
    pub fn next(it: *NameIterator) ParseError!?Name {
        if (it.left == 0) return null;
        it.left -= 1;
        return .{
            .filename = try it.reader.string(),
            .longname = try it.reader.string(),
            .attributes = try readAttributes(&it.reader),
        };
    }
};

/// What a `SSH_FXP_NAME` carries.
pub const NameReply = struct {
    id: u32,
    count: u32,
    iterator: NameIterator,
};

/// Reads the head of a `SSH_FXP_NAME`.
///
/// **The count is checked before one entry is read.**
pub fn parseName(body: []const u8) ParseError!NameReply {
    var r: wire.Reader = .init(body);
    if (try r.byte() != @intFromEnum(Type.name)) return error.WrongPacketType;
    const id = try r.uint32();
    const count = try r.uint32();
    if (count > max_names) return error.CountTooLarge;
    return .{ .id = id, .count = count, .iterator = .{ .reader = r, .left = count } };
}

const testing = std.testing;

test "an init packet names version 3 and carries no request id" {
    var storage: [16]u8 = undefined;
    const built = try writeInit(&storage);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 5, 1, 0, 0, 0, 3 }, built);
    try testing.expectEqual(@as(?u32, null), requestIdOf(built[4..]));
}

test "an open for reading carries the path, the flags, and an empty attrs" {
    var storage: [64]u8 = undefined;
    const built = try writeOpen(&storage, 7, "/a", open_read);
    try testing.expectEqualSlices(u8, &.{
        0, 0,   0,   19,
        3, 0,   0,   0,
        7, 0,   0,   0,
        2, '/', 'a', 0,
        0, 0,   1,   0,
        0, 0,   0,
    }, built);
    try testing.expectEqual(@as(?u32, 7), requestIdOf(built[4..]));
}

test "the length in front of a packet is the bytes after it" {
    var storage: [128]u8 = undefined;
    const built = try writeRead(&storage, 1, "handle", 4096, 32768);
    const declared = std.mem.readInt(u32, built[0..4], .big);
    try testing.expectEqual(@as(usize, 4 + declared), built.len);
}

test "a write carries the offset and the data as one string" {
    var storage: [64]u8 = undefined;
    const built = try writeWrite(&storage, 2, "h", 0, "abc");
    try testing.expectEqualSlices(u8, &.{
        0,   0,   0,   25,
        6,   0,   0,   0,
        2,   0,   0,   0,
        1,   'h', 0,   0,
        0,   0,   0,   0,
        0,   0,   0,   0,
        0,   3,   'a', 'b',
        'c',
    }, built);
}

test "a status with no message reads as one with two empty strings" {
    // Version 3 of the draft added the message and the language. A reader
    // that required them would refuse a status from a server that writes
    // neither, and there are such servers.
    const short = [_]u8{ 101, 0, 0, 0, 1, 0, 0, 0, 2 };
    const parsed = try parseStatus(&short);
    try testing.expectEqual(Status.no_such_file, parsed.status);
    try testing.expectEqualStrings("", parsed.message);

    const full = [_]u8{
        101,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        2,
        0,
        0,
        0,
        2,
        'n',
        'o',
        0,
        0,
        0,
        0,
    };
    const whole = try parseStatus(&full);
    try testing.expectEqualStrings("no", whole.message);
    try testing.expectEqualStrings(
        "the server has no such file",
        Status.no_such_file.text().?,
    );
}

test "a status code the draft does not assign parses and has no sentence" {
    const private: Status = @enumFromInt(1000);
    try testing.expectEqual(@as(?[]const u8, null), private.text());
}

test "a handle is opaque and a tail after it is a refusal" {
    const body = [_]u8{ 102, 0, 0, 0, 1, 0, 0, 0, 3, 'a', 'b', 'c' };
    const parsed = try parseHandle(&body);
    try testing.expectEqualStrings("abc", parsed.handle);
    const trailing = body ++ [_]u8{0};
    try testing.expectError(error.TrailingBytes, parseHandle(&trailing));
}

test "a data reply hands back a slice inside the packet it came from" {
    const body = [_]u8{ 103, 0, 0, 0, 5, 0, 0, 0, 2, 'h', 'i' };
    const parsed = try parseData(&body);
    try testing.expectEqual(@as(u32, 5), parsed.id);
    try testing.expectEqualStrings("hi", parsed.bytes);

    // A length the packet cannot back is refused before a byte is taken.
    const lying = [_]u8{ 103, 0, 0, 0, 5, 0, 0, 0x10, 0, 'h', 'i' };
    try testing.expectError(error.LengthOutOfRange, parseData(&lying));
}

test "an attribute that the flags do not name is null and never zero" {
    // A server that sent no size said nothing about the size. A build
    // that read it as zero would report an empty file for every server
    // that answers a stat with permissions alone.
    const body = [_]u8{
        105,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        4,
        0,
        0,
        0x81,
        0xa4,
    };
    const parsed = try parseAttrs(&body);
    try testing.expectEqual(@as(?u64, null), parsed.attributes.size);
    try testing.expectEqual(@as(?u32, 0o100644), parsed.attributes.permissions);
    try testing.expect(parsed.attributes.isRegular());
    try testing.expect(!parsed.attributes.isDirectory());
}

test "a size and a mode are read in the order the flag word names them" {
    const body = [_]u8{
        105,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        0x0d,
        0,
        0,
        0,
        0,
        0,
        0,
        0x04,
        0x00,
        0,
        0,
        0x41,
        0xed,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        2,
    };
    const parsed = try parseAttrs(&body);
    try testing.expectEqual(@as(?u64, 1024), parsed.attributes.size);
    try testing.expectEqual(@as(?u32, 0o40755), parsed.attributes.permissions);
    try testing.expectEqual(@as(?u32, 1), parsed.attributes.atime);
    try testing.expectEqual(@as(?u32, 2), parsed.attributes.mtime);
    try testing.expect(parsed.attributes.isDirectory());
}

test "an extended attribute count past the bound is refused before a pair is read" {
    const body = [_]u8{
        105,
        0,
        0,
        0,
        1,
        0x80,
        0,
        0,
        0,
        0xff,
        0xff,
        0xff,
        0xff,
    };
    try testing.expectError(error.CountTooLarge, parseAttrs(&body));
}

test "a name reply walks its entries and refuses a count past the bound" {
    const body = [_]u8{
        104,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        2,
        0,
        0,
        0,
        1,
        'a',
        0,
        0,
        0,
        2,
        'l',
        'a',
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
        'b',
        0,
        0,
        0,
        2,
        'l',
        'b',
        0,
        0,
        0,
        0,
    };
    var reply = try parseName(&body);
    try testing.expectEqual(@as(u32, 2), reply.count);
    const first = (try reply.iterator.next()).?;
    try testing.expectEqualStrings("a", first.filename);
    try testing.expectEqualStrings("la", first.longname);
    const second = (try reply.iterator.next()).?;
    try testing.expectEqualStrings("b", second.filename);
    try testing.expectEqual(@as(?Name, null), try reply.iterator.next());

    const lying = [_]u8{ 104, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff };
    try testing.expectError(error.CountTooLarge, parseName(&lying));
}

test "a count inside the bound that the packet cannot back is caught one entry at a time" {
    const body = [_]u8{ 104, 0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 1, 'a' };
    var reply = try parseName(&body);
    try testing.expectError(error.Truncated, reply.iterator.next());
}

test "a reply of the wrong type is refused by name" {
    const status = [_]u8{ 101, 0, 0, 0, 1, 0, 0, 0, 0 };
    try testing.expectError(error.WrongPacketType, parseData(&status));
    try testing.expectError(error.WrongPacketType, parseHandle(&status));
    try testing.expectError(error.WrongPacketType, parseAttrs(&status));
    try testing.expectError(error.WrongPacketType, parseName(&status));
    try testing.expectError(error.WrongPacketType, parseVersion(&status));
}

test "the request id sits in the same place in every type that has one" {
    var storage: [128]u8 = undefined;
    try testing.expectEqual(
        @as(?u32, 42),
        requestIdOf((try writeStat(&storage, 42, "/a"))[4..]),
    );
    try testing.expectEqual(
        @as(?u32, 42),
        requestIdOf((try writeClose(&storage, 42, "h"))[4..]),
    );
    try testing.expectEqual(
        @as(?u32, 42),
        requestIdOf((try writeReaddir(&storage, 42, "h"))[4..]),
    );
    try testing.expectEqual(
        @as(?u32, 42),
        requestIdOf((try writeRealpath(&storage, 42, "."))[4..]),
    );
}

test "a builder that runs out of room says so and never writes past the buffer" {
    var storage: [8]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, writeOpen(&storage, 1, "/a/long/path", open_read));
    try testing.expectError(error.NoSpaceLeft, writeWrite(&storage, 1, "h", 0, "abcdefgh"));
    // A buffer shorter than the length field itself. `out[4..]` on this
    // would be out of bounds, so the guard is a real one and not a
    // formality.
    var tiny: [2]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, writeStat(&tiny, 1, "/a"));
    try testing.expectError(error.NoSpaceLeft, writeInit(&tiny));
    try testing.expectError(error.NoSpaceLeft, writeRead(&tiny, 1, "h", 0, 1));
    try testing.expectError(error.NoSpaceLeft, writeClose(&tiny, 1, "h"));
    try testing.expectError(error.NoSpaceLeft, writeOpen(&tiny, 1, "/a", open_read));
    try testing.expectError(error.NoSpaceLeft, writeWrite(&tiny, 1, "h", 0, "a"));
}

test "version 3 is what this build offers, and the reason is written down" {
    // OpenSSH's `sftp-server` answers 3 and nothing else, so a client
    // that offered 6 would negotiate down to 3 against every server it
    // will meet.
    try testing.expectEqual(@as(u32, 3), version);
    var storage: [16]u8 = undefined;
    const built = try writeInit(&storage);
    const parsed_version = std.mem.readInt(u32, built[5..9], .big);
    try testing.expectEqual(@as(u32, 3), parsed_version);
}
