//! The `multipart/form-data` request body, the one `-F` builds.
//!
//! `request_body.zig` holds the two simple sources: bytes the caller
//! already has, and one open file. A form body is neither. It is a list of
//! parts, each with its own MIME header block, joined by a delimiter that
//! must not appear in any part's content. This file builds that list and
//! hands the engine one `Transfer.Body` over it.
//!
//! **Three texts from the command line land in a MIME header here.** A
//! field name, a file name, and a content type. Each is untrusted, and a
//! CR or an LF in any of them would close the header block early and let
//! the rest of the text write header lines of its own. `escapeInto` and
//! `checkContentType` are the two places that stop it, and neither has a
//! path that lets a CR or an LF through. See the "Header injection" note
//! below.
//!
//! **The body streams.** A part whose content is a file is read in the
//! pieces the engine sizes, so a form that carries a file larger than this
//! machine's memory costs the same memory as one that carries no file at
//! all. Only the framing text and the literal values live in memory, and
//! the caller bounds those.
//!
//! **The length is always known.** Every part is a literal, whose length
//! is its byte count, or a file, whose length comes from the `stat` the
//! caller already did. So the total is a sum, the request goes out with a
//! `content-length`, and it is never chunked. curl 8.21.0 frames the same
//! body the same way, measured with a 200 KB file.
//!
//! The value must not move once `source` has run. The `Body` it returns
//! holds the address of the value it came from, and the content type it
//! reports points into the value too.

const std = @import("std");
const Transfer = @import("Transfer.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

/// How many `-` characters start a boundary. curl writes 24, measured
/// from the wire, and a boundary of the same shape keeps a peer that
/// pattern-matches on curl happy.
pub const boundary_dashes = 24;

/// How many random characters end a boundary. curl writes 22, measured.
/// Each is one of 62, so a boundary carries about 131 bits. See
/// `drawBoundary` for what that number is doing.
pub const boundary_random_len = 22;

/// The whole boundary, dashes and random characters together.
pub const boundary_len = boundary_dashes + boundary_random_len;

/// The characters `drawBoundary` picks from. 62 of them, and every one is
/// legal in a boundary and needs no quoting in the `Content-Type` header.
const boundary_alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// How many boundaries `init` may draw before it gives up.
///
/// A redraw happens only when a part's content already holds the boundary
/// this draw produced. That has a chance of about one in 2^131 per
/// position, so a second draw is already unreachable in practice. The
/// bound is here because a loop with no bound is a hang, and a hang is
/// worse than a refusal.
const max_boundary_draws = 8;

/// How many parts one body may carry.
///
/// A form is written by hand on a command line, so 64 is far past any real
/// use. The bound exists because each part costs a header block in memory
/// and an open file handle, and neither may grow with untrusted input.
pub const max_parts = 64;

/// How long a field name may be.
pub const max_name_bytes = 1024;

/// How long a file name may be.
pub const max_filename_bytes = 1024;

/// How long a content type may be.
pub const max_type_bytes = 256;

/// How the two quoted header parameters escape a character that would
/// otherwise end the quoted string.
///
/// **Measured against curl 8.21.0.** The default is what the WHATWG HTML
/// standard asks for, and it is what curl sends with no `--form-escape`:
///
/// ```
/// -F 'na"me=v'                  name="na%22me"
/// -F $'na\nme=v'                name="na%0Ame"
/// -F $'na\rme=v'                name="na%0Dme"
/// --form-escape -F 'na"me=v'    name="na\"me"
/// --form-escape -F 'na\me=v'    name="na\\me"
/// ```
///
/// **zurl diverges from curl on one row, on purpose.** curl under
/// `--form-escape` writes a CR and an LF into the header unchanged, so a
/// field name with a newline in it forges a part header. Measured:
/// `curl --form-escape -F $'na\nme=v'` put a bare LF inside
/// `Content-Disposition`. zurl percent-encodes a CR and an LF under both
/// settings. `--form-escape` chooses how a quote and a backslash are
/// written and nothing else.
pub const Escape = enum {
    /// `"` becomes `%22`. This is curl with no `--form-escape`.
    percent,
    /// `"` becomes `\"` and `\` becomes `\\`. This is `--form-escape`.
    backslash,
};

/// Where one part's content comes from.
pub const Content = union(enum) {
    /// Bytes the caller already holds. They must outlive the transfer.
    memory: []const u8,
    /// An open file, read from its first byte. The caller closes it.
    file: File,

    /// One open file, and the length the caller measured with a `stat`.
    pub const File = struct {
        handle: Io.File,
        /// How many bytes of the file go out. The `content-length` of the
        /// whole request counts this, so a file that is shorter than this
        /// when the body goes out fails the send rather than frame a lie.
        len: u64,
    };
};

/// One part of a form body.
pub const Part = struct {
    /// The field name. An empty name writes no `name=` parameter at all,
    /// which is what `curl -F '=value'` sends.
    name: []const u8,
    /// The `filename` parameter, or null for a part that carries none. A
    /// `-F 'n=@path'` fills this and a `-F 'n=<path'` leaves it null.
    filename: ?[]const u8 = null,
    /// The part's own `Content-Type`, or null for a part that carries
    /// none.
    content_type: ?[]const u8 = null,
    content: Content,
};

/// Why a form body could not be built.
pub const BuildError = error{
    /// More than `max_parts` parts.
    TooManyParts,
    /// A field name longer than `max_name_bytes`.
    FieldNameTooLong,
    /// A file name longer than `max_filename_bytes`.
    FileNameTooLong,
    /// A content type longer than `max_type_bytes`.
    ContentTypeTooLong,
    /// A content type that holds a byte outside printable ASCII.
    ///
    /// **This is the check that keeps a CR and an LF out of the one header
    /// value this file does not quote.** A content type goes into
    /// `Content-Type: ` as it stands, so a CR or an LF in it would end the
    /// line and start a header of the caller's choosing.
    ContentTypeMalformed,
    /// Every boundary this call drew already appears in a part's content.
    ///
    /// Unreachable with a working entropy source. See `max_boundary_draws`.
    BoundaryUnavailable,
} || Io.RandomSecureError || Allocator.Error;

/// A `multipart/form-data` request body.
///
/// `init` renders every part's framing text into the arena and records
/// where each part's content comes from. Nothing is read from a file until
/// the engine asks for it.
pub const Body = struct {
    io: Io,
    /// The pieces of the body, in order. Every other one is framing text
    /// this file wrote, and the ones between are the parts' content.
    segments: []const Segment,
    /// How many bytes the whole body holds. The `content-length`.
    total: u64,
    /// `multipart/form-data; boundary=...`, ready for the request header.
    /// Held here, not in the arena, so the value owns every byte it lends
    /// out.
    type_buf: [type_prefix.len + boundary_len]u8,
    /// The boundary alone, which is what the collision check searches for.
    boundary: [boundary_len]u8,
    /// Which segment the next read starts in.
    index: usize,
    /// How many bytes of that segment have gone out.
    offset: u64,
    /// The tail of the file bytes already sent from the current segment.
    ///
    /// A boundary that a file's content holds could straddle two reads, so
    /// the search runs over this and the new bytes together. Reset when
    /// the segment changes, because two content segments are always
    /// separated by framing text and no boundary can span the two.
    carry: [boundary_len - 1]u8,
    carry_len: usize,

    const type_prefix = "multipart/form-data; boundary=";

    /// One piece of the body.
    pub const Segment = union(enum) {
        /// Framing text, or a literal value. Held in the arena.
        bytes: []const u8,
        /// A file's content, read as the engine asks for it.
        file: Content.File,
    };

    /// Builds the body for `parts`.
    ///
    /// `arena` holds the framing text and lives until the last transfer of
    /// the run has ended. `parts` is read here and never held: the names,
    /// the file names, and the types are copied into the framing text, and
    /// only the content slices and file handles are kept.
    pub fn init(
        self: *Body,
        arena: Allocator,
        io: Io,
        parts: []const Part,
        escape: Escape,
    ) BuildError!void {
        if (parts.len > max_parts) return error.TooManyParts;

        // The bounds first, so a part that is refused is refused before
        // any entropy is drawn and before anything is rendered.
        for (parts) |part| {
            if (part.name.len > max_name_bytes) return error.FieldNameTooLong;
            if (part.filename) |name| {
                if (name.len > max_filename_bytes) return error.FileNameTooLong;
            }
            if (part.content_type) |value| try checkContentType(value);
        }

        self.io = io;
        try self.drawUnusedBoundary(parts);

        @memcpy(self.type_buf[0..type_prefix.len], type_prefix);
        @memcpy(self.type_buf[type_prefix.len..], &self.boundary);

        // One framing segment in front of each part, one content segment
        // for each part, and one framing segment to close the body.
        var segments: std.ArrayList(Segment) = .empty;
        try segments.ensureTotalCapacityPrecise(arena, parts.len * 2 + 1);

        for (parts, 0..) |part, i| {
            var head: std.ArrayList(u8) = .empty;
            // A part that is not the first ends the one before it. The
            // CRLF belongs to the delimiter, not to the content, so a
            // part's content goes out byte for byte.
            if (i != 0) try head.appendSlice(arena, "\r\n");
            try head.appendSlice(arena, "--");
            try head.appendSlice(arena, &self.boundary);
            try head.appendSlice(arena, "\r\n");
            try writePartHeaders(arena, &head, part, escape);
            try head.appendSlice(arena, "\r\n");
            segments.appendAssumeCapacity(.{ .bytes = head.items });

            segments.appendAssumeCapacity(switch (part.content) {
                .memory => |bytes| .{ .bytes = bytes },
                .file => |file| .{ .file = file },
            });
        }

        var tail: std.ArrayList(u8) = .empty;
        if (parts.len != 0) try tail.appendSlice(arena, "\r\n");
        try tail.appendSlice(arena, "--");
        try tail.appendSlice(arena, &self.boundary);
        try tail.appendSlice(arena, "--\r\n");
        segments.appendAssumeCapacity(.{ .bytes = tail.items });

        self.segments = segments.items;
        self.total = 0;
        for (self.segments) |segment| self.total += switch (segment) {
            .bytes => |bytes| bytes.len,
            .file => |file| file.len,
        };

        self.index = 0;
        self.offset = 0;
        self.carry_len = 0;
    }

    /// The `Transfer.Options.body` for this source.
    ///
    /// The length is known, so the request carries a `content-length` and
    /// never the chunked coding. Every source rewinds: a literal starts
    /// over at its first byte and a file is read at an offset. So a `307`
    /// hop and a `401` retry both send the same body again.
    pub fn source(self: *Body) Transfer.Body {
        return .{
            .len = self.total,
            .ctx = self,
            .read = readImpl,
            .rewind = rewindImpl,
            .content_type = &self.type_buf,
        };
    }

    /// The boundary this body uses, without the leading dashes a delimiter
    /// adds. For a test and for a report, not for the wire.
    pub fn boundaryText(self: *const Body) []const u8 {
        return &self.boundary;
    }

    /// Draws boundaries until one appears in no part's content.
    ///
    /// **A file's content is not searched here, and cannot be.** A search
    /// would have to read the whole file, which is the memory cost this
    /// file exists to avoid. `holdsBoundary` searches a file's bytes as
    /// they go out instead, and fails the send before a peer can read a
    /// whole forged body.
    fn drawUnusedBoundary(self: *Body, parts: []const Part) BuildError!void {
        var draws: usize = 0;
        while (draws < max_boundary_draws) : (draws += 1) {
            try drawBoundary(self.io, &self.boundary);
            var clash = false;
            for (parts) |part| switch (part.content) {
                .memory => |bytes| {
                    if (std.mem.indexOf(u8, bytes, &self.boundary) != null) clash = true;
                },
                .file => {},
            };
            if (!clash) return;
        }
        return error.BoundaryUnavailable;
    }

    /// Whether `fresh`, read behind the bytes in `carry`, holds the
    /// boundary.
    ///
    /// The carry is what makes this correct across two reads. A boundary
    /// that starts in one read and ends in the next is found here, and a
    /// search of `fresh` alone would miss it.
    fn holdsBoundary(self: *Body, fresh: []const u8) bool {
        var window: [boundary_len - 1 + 4096]u8 = undefined;
        var at: usize = 0;
        var found = false;

        var rest = fresh;
        while (rest.len != 0) {
            const room = window.len - self.carry_len;
            const take = @min(room, rest.len);
            @memcpy(window[0..self.carry_len], self.carry[0..self.carry_len]);
            @memcpy(window[self.carry_len..][0..take], rest[0..take]);
            at = self.carry_len + take;
            if (std.mem.indexOf(u8, window[0..at], &self.boundary) != null) found = true;

            // Keep the last bytes a boundary could start in, so the next
            // pass sees a boundary that straddles the two.
            const keep = @min(at, self.carry.len);
            @memcpy(self.carry[0..keep], window[at - keep ..][0..keep]);
            self.carry_len = keep;
            rest = rest[take..];
        }

        return found;
    }

    fn readImpl(ctx: *anyopaque, buffer: [*]u8, len: usize) callconv(.c) isize {
        const self: *Body = @ptrCast(@alignCast(ctx));

        while (self.index < self.segments.len) {
            switch (self.segments[self.index]) {
                .bytes => |bytes| {
                    const left = bytes.len - self.offset;
                    if (left == 0) {
                        self.index += 1;
                        self.offset = 0;
                        self.carry_len = 0;
                        continue;
                    }
                    if (len == 0) return 0;
                    const take = @min(len, left);
                    @memcpy(buffer[0..take], bytes[@intCast(self.offset)..][0..take]);
                    self.offset += take;
                    // `take` is bounded by `len`, which the engine sizes
                    // from a buffer on its own stack, so this fits.
                    return @intCast(take);
                },
                .file => |file| {
                    const left = file.len - self.offset;
                    if (left == 0) {
                        self.index += 1;
                        self.offset = 0;
                        self.carry_len = 0;
                        continue;
                    }
                    if (len == 0) return 0;
                    const want: usize = @intCast(@min(@as(u64, len), left));
                    // A positional read leaves the file's own offset
                    // alone, so `rewind` is one assignment and nothing
                    // else that holds this handle is disturbed.
                    const count = file.handle.readPositionalAll(
                        self.io,
                        buffer[0..want],
                        self.offset,
                    ) catch return -1;
                    // The `content-length` already announced `file.len`. A
                    // file that ended early cannot fill it, so the request
                    // fails here rather than frame a body it does not
                    // have.
                    if (count == 0) return -1;
                    // **The one check a build-time search cannot do.** A
                    // file whose content holds the boundary would split
                    // its own part at the peer and let the tail read as a
                    // part of its own. The send fails instead, and the
                    // peer never reads a whole body.
                    if (self.holdsBoundary(buffer[0..count])) return -1;
                    self.offset += count;
                    return @intCast(count);
                },
            }
        }

        return 0;
    }

    fn rewindImpl(ctx: *anyopaque) callconv(.c) bool {
        const self: *Body = @ptrCast(@alignCast(ctx));
        self.index = 0;
        self.offset = 0;
        self.carry_len = 0;
        return true;
    }
};

/// Writes one part's header lines, up to but not including the blank line
/// that ends the block.
///
/// The order is curl's, measured: the disposition first, with `name` in
/// front of `filename`, and the content type behind it.
fn writePartHeaders(
    arena: Allocator,
    out: *std.ArrayList(u8),
    part: Part,
    escape: Escape,
) Allocator.Error!void {
    try out.appendSlice(arena, "Content-Disposition: form-data");
    // An empty name writes no parameter at all. Measured:
    // `curl -F '=value'` sends `Content-Disposition: form-data` alone.
    if (part.name.len != 0) {
        try out.appendSlice(arena, "; name=\"");
        try escapeInto(arena, out, part.name, escape);
        try out.append(arena, '"');
    }
    if (part.filename) |name| {
        try out.appendSlice(arena, "; filename=\"");
        try escapeInto(arena, out, name, escape);
        try out.append(arena, '"');
    }
    try out.appendSlice(arena, "\r\n");

    if (part.content_type) |value| {
        // `checkContentType` already refused every byte that could end
        // this line. Nothing is escaped here, because curl writes the type
        // as it stands and a peer reads a media type, not a quoted string.
        try out.appendSlice(arena, "Content-Type: ");
        try out.appendSlice(arena, value);
        try out.appendSlice(arena, "\r\n");
    }
}

/// Appends `text` to `out`, escaped for a quoted header parameter.
///
/// **This function is total, and that is the point.** Every one of the 256
/// byte values maps to something, and the four bytes that could end the
/// quoted string or the header line map to a replacement that holds
/// neither a CR, an LF, nor a bare quote. So no input can add a header
/// line, whichever `Escape` is in force. `every byte in a field name is
/// safe in the header it lands in` tests all 256.
fn escapeInto(
    arena: Allocator,
    out: *std.ArrayList(u8),
    text: []const u8,
    escape: Escape,
) Allocator.Error!void {
    for (text) |byte| switch (byte) {
        // A CR and an LF are percent-encoded under both settings. curl
        // leaves them alone under `--form-escape`, which forges a part
        // header. See `Escape`.
        '\r' => try out.appendSlice(arena, "%0D"),
        '\n' => try out.appendSlice(arena, "%0A"),
        '"' => switch (escape) {
            .percent => try out.appendSlice(arena, "%22"),
            .backslash => try out.appendSlice(arena, "\\\""),
        },
        '\\' => switch (escape) {
            // curl leaves a backslash alone with no `--form-escape`,
            // measured: `-F 'na\me=v'` sends `name="na\me"`.
            .percent => try out.append(arena, '\\'),
            .backslash => try out.appendSlice(arena, "\\\\"),
        },
        else => try out.append(arena, byte),
    };
}

/// Refuses a content type that could not go into a header value as it
/// stands.
///
/// Printable ASCII and nothing else. That keeps out a CR and an LF, which
/// would end the line and let the rest write headers, and it keeps out
/// every other control byte, which a peer may read in its own way. A media
/// type holds no byte above 126 anyway.
fn checkContentType(value: []const u8) BuildError!void {
    if (value.len > max_type_bytes) return error.ContentTypeTooLong;
    for (value) |byte| {
        if (byte < 0x20 or byte > 0x7e) return error.ContentTypeMalformed;
    }
}

/// Fills `out` with a fresh boundary: `boundary_dashes` dashes, then
/// `boundary_random_len` characters from `boundary_alphabet`.
///
/// **The entropy comes from `io.randomSecure`, which makes a syscall and
/// has no fallback.** `io.random` is documented to fall back to a weaker
/// source without saying so, and a boundary a peer could guess is a
/// boundary a peer could plant in content it controls. This project
/// rejected `io.random` for the TLS client random for the same reason.
///
/// The draw is rejection sampling and not a modulo. 248 is 4 times 62, so
/// each accepted byte names one of the 62 characters with the same chance.
/// A plain `% 62` over 256 values would make the first 8 characters more
/// likely, which costs real entropy for nothing.
///
/// 22 characters of 62 is about 131 bits. That is the whole argument that
/// a boundary does not appear in a file this call cannot read: the chance
/// is about the length of the file over 2^131.
fn drawBoundary(io: Io, out: *[boundary_len]u8) Io.RandomSecureError!void {
    @memset(out[0..boundary_dashes], '-');

    var filled: usize = 0;
    var draws: usize = 0;
    while (filled < boundary_random_len) {
        // A rejection loop with no bound is a hang if the source ever
        // answers with the same rejected byte. 64 bytes give 22 accepted
        // ones with all but vanishing chance, so 8 refills is generous.
        if (draws == max_boundary_draws) return error.EntropyUnavailable;
        draws += 1;

        var raw: [64]u8 = undefined;
        defer std.crypto.secureZero(u8, &raw);
        try io.randomSecure(&raw);

        for (raw) |byte| {
            if (filled == boundary_random_len) break;
            if (byte >= 248) continue;
            out[boundary_dashes + filled] = boundary_alphabet[byte % 62];
            filled += 1;
        }
    }
}

const testing = std.testing;

/// Reads the whole body out of `body`, in pieces of `piece`, and returns
/// it. The caller frees it.
fn drain(body: *Body, piece: usize, allocator: Allocator) ![]u8 {
    const src = body.source();
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var buffer: [8192]u8 = undefined;
    while (true) {
        const n = src.read(src.ctx, &buffer, @min(piece, buffer.len));
        try testing.expect(n >= 0);
        if (n == 0) break;
        try out.appendSlice(allocator, buffer[0..@intCast(n)]);
    }
    return out.toOwnedSlice(allocator);
}

test "one literal part matches the shape curl puts on the wire" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var body: Body = undefined;
    try body.init(arena.allocator(), testing.io, &.{
        .{ .name = "name", .content = .{ .memory = "value" } },
    }, .percent);

    const bytes = try drain(&body, 8192, testing.allocator);
    defer testing.allocator.free(bytes);

    const b = body.boundaryText();
    const want = try std.fmt.allocPrint(
        testing.allocator,
        "--{s}\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nvalue\r\n--{s}--\r\n",
        .{ b, b },
    );
    defer testing.allocator.free(want);

    try testing.expectEqualStrings(want, bytes);
    // The announced length is the length that went out. A body that
    // framed a different number would leave the peer reading the next
    // request as the tail of this one.
    try testing.expectEqual(bytes.len, body.total);
}

test "the content type names the boundary the body really uses" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var body: Body = undefined;
    try body.init(arena.allocator(), testing.io, &.{
        .{ .name = "a", .content = .{ .memory = "1" } },
    }, .percent);

    const source = body.source();
    const value = source.content_type.?;
    try testing.expect(std.mem.startsWith(u8, value, "multipart/form-data; boundary="));
    try testing.expectEqualStrings(body.boundaryText(), value["multipart/form-data; boundary=".len..]);
    try testing.expectEqual(@as(usize, boundary_len), body.boundaryText().len);
}

test "a boundary is 24 dashes and 22 characters of the alphabet, and two draws differ" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var first: Body = undefined;
    try first.init(arena.allocator(), testing.io, &.{}, .percent);
    var second: Body = undefined;
    try second.init(arena.allocator(), testing.io, &.{}, .percent);

    const text = first.boundaryText();
    for (text[0..boundary_dashes]) |byte| try testing.expectEqual(@as(u8, '-'), byte);
    for (text[boundary_dashes..]) |byte| {
        try testing.expect(std.mem.indexOfScalar(u8, boundary_alphabet, byte) != null);
    }
    // Two boundaries from one process must not match. A fixed boundary
    // would let a peer that saw one request plant it in the next.
    try testing.expect(!std.mem.eql(u8, text, second.boundaryText()));
}

test "an empty form still closes its body" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var body: Body = undefined;
    try body.init(arena.allocator(), testing.io, &.{}, .percent);

    const bytes = try drain(&body, 8192, testing.allocator);
    defer testing.allocator.free(bytes);

    const want = try std.fmt.allocPrint(testing.allocator, "--{s}--\r\n", .{body.boundaryText()});
    defer testing.allocator.free(want);
    try testing.expectEqualStrings(want, bytes);
}

test "every byte in a field name is safe in the header it lands in" {
    // **The injection proof for a field name.** Every one of the 256 byte
    // values goes into a name, and the rendered part header must hold
    // exactly the CRLFs this file wrote and no other CR and no other LF.
    // A byte that could add a header line would show up as a third CRLF or
    // as a bare CR or LF.
    for (0..256) |value| {
        const byte: u8 = @intCast(value);
        inline for (.{ Escape.percent, Escape.backslash }) |escape| {
            var arena: std.heap.ArenaAllocator = .init(testing.allocator);
            defer arena.deinit();

            const name = [_]u8{ 'a', byte, 'b' };
            var body: Body = undefined;
            try body.init(arena.allocator(), testing.io, &.{
                .{ .name = &name, .content = .{ .memory = "v" } },
            }, escape);

            const bytes = try drain(&body, 8192, testing.allocator);
            defer testing.allocator.free(bytes);

            const head_end = std.mem.indexOf(u8, bytes, "\r\n\r\n").?;
            // The header block holds the delimiter line and the
            // disposition line, so two CRLFs and nothing else.
            const head = bytes[0..head_end];
            try testing.expectEqual(@as(usize, 1), std.mem.count(u8, head, "\r\n"));
            try testing.expectEqual(std.mem.count(u8, head, "\r"), std.mem.count(u8, head, "\r\n"));
            try testing.expectEqual(std.mem.count(u8, head, "\n"), std.mem.count(u8, head, "\r\n"));
        }
    }
}

test "every byte in a file name is safe in the header it lands in" {
    // The same proof for the second untrusted text. A file name is the one
    // an attacker reaches through a directory listing rather than through
    // the command line, so it gets the same treatment.
    for (0..256) |value| {
        const byte: u8 = @intCast(value);
        inline for (.{ Escape.percent, Escape.backslash }) |escape| {
            var arena: std.heap.ArenaAllocator = .init(testing.allocator);
            defer arena.deinit();

            const name = [_]u8{ 'a', byte, 'b' };
            var body: Body = undefined;
            try body.init(arena.allocator(), testing.io, &.{
                .{ .name = "f", .filename = &name, .content = .{ .memory = "v" } },
            }, escape);

            const bytes = try drain(&body, 8192, testing.allocator);
            defer testing.allocator.free(bytes);

            const head_end = std.mem.indexOf(u8, bytes, "\r\n\r\n").?;
            const head = bytes[0..head_end];
            try testing.expectEqual(@as(usize, 1), std.mem.count(u8, head, "\r\n"));
            try testing.expectEqual(std.mem.count(u8, head, "\r"), std.mem.count(u8, head, "\r\n"));
            try testing.expectEqual(std.mem.count(u8, head, "\n"), std.mem.count(u8, head, "\r\n"));
        }
    }
}

test "a content type with any byte outside printable ASCII is refused" {
    // **The injection proof for the third untrusted text.** A content type
    // is not quoted, so it is refused rather than escaped. Every byte
    // outside 0x20 to 0x7e must fail the build, the CR and the LF among
    // them, and every byte inside must pass.
    for (0..256) |value| {
        const byte: u8 = @intCast(value);
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();

        const value_text = [_]u8{ 't', byte, 'x' };
        var body: Body = undefined;
        const result = body.init(arena.allocator(), testing.io, &.{
            .{ .name = "f", .content_type = &value_text, .content = .{ .memory = "v" } },
        }, .percent);

        if (byte >= 0x20 and byte <= 0x7e) {
            try result;
        } else {
            try testing.expectError(error.ContentTypeMalformed, result);
        }
    }
}

test "the escapes match what curl writes for a quote, a backslash, a CR and an LF" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var out: std.ArrayList(u8) = .empty;
    try escapeInto(a, &out, "q\"b\\r\rn\n", .percent);
    // Measured: curl with no `--form-escape` sends `%22` for a quote,
    // `%0D` for a CR, `%0A` for an LF, and leaves a backslash alone.
    try testing.expectEqualStrings("q%22b\\r%0Dn%0A", out.items);

    var escaped: std.ArrayList(u8) = .empty;
    try escapeInto(a, &escaped, "q\"b\\r\rn\n", .backslash);
    // Measured: curl with `--form-escape` sends `\"` and `\\`. It leaves a
    // CR and an LF alone, which forges a header line, so zurl keeps the
    // percent form for those two.
    try testing.expectEqualStrings("q\\\"b\\\\r%0Dn%0A", escaped.items);
}

test "two parts join with one delimiter and the second content is untouched" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var body: Body = undefined;
    try body.init(arena.allocator(), testing.io, &.{
        .{ .name = "x", .filename = "a.txt", .content_type = "text/plain", .content = .{ .memory = "hello\nworld\n" } },
        .{ .name = "y", .content = .{ .memory = "BBB\n" } },
    }, .percent);

    const bytes = try drain(&body, 8192, testing.allocator);
    defer testing.allocator.free(bytes);

    const b = body.boundaryText();
    const want = try std.fmt.allocPrint(
        testing.allocator,
        "--{s}\r\n" ++
            "Content-Disposition: form-data; name=\"x\"; filename=\"a.txt\"\r\n" ++
            "Content-Type: text/plain\r\n\r\nhello\nworld\n\r\n" ++
            "--{s}\r\nContent-Disposition: form-data; name=\"y\"\r\n\r\nBBB\n\r\n" ++
            "--{s}--\r\n",
        .{ b, b, b },
    );
    defer testing.allocator.free(want);
    try testing.expectEqualStrings(want, bytes);
    try testing.expectEqual(bytes.len, body.total);
}

test "a file part streams, and the body reads the same in one piece and in many" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var written: [5000]u8 = undefined;
    for (&written, 0..) |*byte, i| byte.* = @intCast(i % 251);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "big.bin", .data = &written });
    const handle = try tmp.dir.openFile(testing.io, "big.bin", .{});
    defer handle.close(testing.io);

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var body: Body = undefined;
    try body.init(arena.allocator(), testing.io, &.{
        .{
            .name = "f",
            .filename = "big.bin",
            .content_type = "application/octet-stream",
            .content = .{ .file = .{ .handle = handle, .len = written.len } },
        },
    }, .percent);

    const whole = try drain(&body, 8192, testing.allocator);
    defer testing.allocator.free(whole);
    try testing.expectEqual(whole.len, body.total);
    try testing.expect(std.mem.indexOf(u8, whole, &written) != null);

    // The engine reads in pieces of its own size, so a read of 7 bytes at
    // a time must give the same bytes as one read of the whole body.
    try testing.expect(body.source().rewind.?(body.source().ctx));
    const pieces = try drain(&body, 7, testing.allocator);
    defer testing.allocator.free(pieces);
    try testing.expectEqualSlices(u8, whole, pieces);
}

test "a boundary is drawn again when a literal value already holds one" {
    // A value that holds the boundary would split its own part at the
    // peer. `init` draws again, so the body that goes out never carries a
    // delimiter it did not write.
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var first: Body = undefined;
    try first.init(arena.allocator(), testing.io, &.{}, .percent);
    const planted = try arena.allocator().dupe(u8, first.boundaryText());

    var body: Body = undefined;
    try body.init(arena.allocator(), testing.io, &.{
        .{ .name = "n", .content = .{ .memory = planted } },
    }, .percent);

    try testing.expect(!std.mem.eql(u8, planted, body.boundaryText()));

    const bytes = try drain(&body, 8192, testing.allocator);
    defer testing.allocator.free(bytes);
    // Exactly two delimiters, the opening one and the closing one. A third
    // would mean the content forged a part.
    const delimiter = try std.fmt.allocPrint(testing.allocator, "--{s}", .{body.boundaryText()});
    defer testing.allocator.free(delimiter);
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, bytes, delimiter));
}

test "a file whose content holds the boundary fails the send instead of forging a part" {
    // The check a build-time search cannot do. The file is written with
    // the boundary in it after the body was built, which is the only way
    // to reach this path on purpose.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(testing.io, .{ .sub_path = "f.bin", .data = "x" ** 4096 });
    const handle = try tmp.dir.openFile(testing.io, "f.bin", .{});
    defer handle.close(testing.io);

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var body: Body = undefined;
    try body.init(arena.allocator(), testing.io, &.{
        .{ .name = "f", .filename = "f.bin", .content = .{ .file = .{ .handle = handle, .len = 4096 } } },
    }, .percent);

    // Plant the boundary that this body drew, straddling two of the reads
    // below, so the carry is what finds it.
    var planted: [4096]u8 = undefined;
    @memset(&planted, 'x');
    @memcpy(planted[100..][0..boundary_len], body.boundaryText());
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "f.bin", .data = &planted });

    const source = body.source();
    var buffer: [64]u8 = undefined;
    var failed = false;
    var reads: usize = 0;
    while (reads < 200) : (reads += 1) {
        const n = source.read(source.ctx, &buffer, buffer.len);
        if (n < 0) {
            failed = true;
            break;
        }
        if (n == 0) break;
    }
    try testing.expect(failed);
}

test "a file that ends before its announced length fails the send" {
    // The `content-length` counted the `stat`. A file that shrank after it
    // cannot fill that count, and a short body leaves the peer reading the
    // next request as the tail of this one.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(testing.io, .{ .sub_path = "s.bin", .data = "12345678" });
    const handle = try tmp.dir.openFile(testing.io, "s.bin", .{});
    defer handle.close(testing.io);

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var body: Body = undefined;
    try body.init(arena.allocator(), testing.io, &.{
        .{ .name = "f", .content = .{ .file = .{ .handle = handle, .len = 64 } } },
    }, .percent);

    const source = body.source();
    var buffer: [256]u8 = undefined;
    var failed = false;
    var reads: usize = 0;
    while (reads < 50) : (reads += 1) {
        const n = source.read(source.ctx, &buffer, buffer.len);
        if (n < 0) {
            failed = true;
            break;
        }
        if (n == 0) break;
    }
    try testing.expect(failed);
}

test "the bounds refuse a form that is too large to render" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const long = try a.alloc(u8, max_name_bytes + 1);
    @memset(long, 'n');

    var body: Body = undefined;
    try testing.expectError(error.FieldNameTooLong, body.init(a, testing.io, &.{
        .{ .name = long, .content = .{ .memory = "v" } },
    }, .percent));

    try testing.expectError(error.FileNameTooLong, body.init(a, testing.io, &.{
        .{ .name = "n", .filename = long, .content = .{ .memory = "v" } },
    }, .percent));

    const long_type = try a.alloc(u8, max_type_bytes + 1);
    @memset(long_type, 't');
    try testing.expectError(error.ContentTypeTooLong, body.init(a, testing.io, &.{
        .{ .name = "n", .content_type = long_type, .content = .{ .memory = "v" } },
    }, .percent));

    const many = try a.alloc(Part, max_parts + 1);
    for (many) |*part| part.* = .{ .name = "n", .content = .{ .memory = "v" } };
    try testing.expectError(error.TooManyParts, body.init(a, testing.io, many, .percent));
}

test "a rewind sends the same body again, which is what a 307 needs" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var body: Body = undefined;
    try body.init(arena.allocator(), testing.io, &.{
        .{ .name = "a", .content = .{ .memory = "1" } },
        .{ .name = "b", .content = .{ .memory = "2" } },
    }, .percent);

    const first = try drain(&body, 13, testing.allocator);
    defer testing.allocator.free(first);

    const source = body.source();
    try testing.expect(source.rewind != null);
    try testing.expect(source.rewind.?(source.ctx));

    const second = try drain(&body, 8192, testing.allocator);
    defer testing.allocator.free(second);
    try testing.expectEqualSlices(u8, first, second);
}
