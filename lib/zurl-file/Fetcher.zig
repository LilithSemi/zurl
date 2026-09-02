//! Reads one local file for one `file://` transfer.
//!
//! A `Fetcher` owns the open file and the buffer its reader fills, so both
//! outlive the call that opened them and the caller can stream the body
//! afterwards. One `Fetcher` serves one transfer at a time: `open` closes
//! whatever the last call left open, the same rule `zurl.Client` keeps for
//! its own HTTP exchange.
//!
//! **A `Fetcher` must not move once `open` has run.** The body reader it
//! hands back points into this value, and the file reader inside it points
//! at this value's own buffer. Keep one where it will stay, and pass a
//! pointer.
//!
//! **What a `file://` url can reach.** Whatever the user running zurl can
//! read, and nothing more: the path goes to the operating system, which
//! applies the same permissions any other program gets. There is no root
//! to escape from and no jail to keep, so this package adds no path rule
//! of its own beyond refusing a host that is not this machine. curl works
//! the same way. Note this is not the hazard `-O` has: there the *server*
//! chooses the name, so a name that climbs out of the working directory is
//! the server writing where it likes. Here the user names the path
//! themselves, and a user who can type a path can already read it.
//!
//! **A server can never choose that path.** `zurl_core.redirect` refuses a
//! redirect into `file`, so the only way to a local read is a url the user
//! wrote. Without that rule any http server could name a file and, under
//! `-o`, have zurl write it back where the user could be made to send it
//! on.
//!
//! **`--resolve` and `--connect-to` do not apply here, and that is not an
//! omission.** Both flags say where a transfer dials. This package opens
//! no socket at all: a `file` url names this machine and a path, and the
//! read goes to the operating system. There is no peer to move, so there
//! is nothing for either flag to say. Every other protocol package reads
//! `zurl_net.override` at its dial. curl takes the same view: a `file`
//! url is served from disk whatever either flag holds.

const Fetcher = @This();

const std = @import("std");
const zurl_core = @import("zurl-core");

const Io = std.Io;
const Error = zurl_core.Error;
const Diagnostics = zurl_core.Diagnostics;

/// The scheme this package handles.
pub const scheme = "file";

/// The port a `file` url uses, which is none at all.
///
/// This reads no socket, so there is no number to name. `zurl_core.url`
/// reads a null here as "this scheme names no peer", which is what lets
/// `file:///a/b` parse with an empty host. See `Scheme.default_port`
/// there.
pub const default_port: ?u16 = null;

/// The status a `file://` transfer reports.
///
/// Zero, because no server answered. curl 8.21.0 prints `000` for
/// `%{http_code}` on a `file://` url that worked, measured with
/// `curl -w '%{http_code}' -o /dev/null file:///tmp/f.txt`, so a script
/// that reads the status gets curl's own answer.
pub const status: u16 = 0;

/// How many bytes one read of the file asks for. Matches the transfer
/// buffer `zurl-http` uses for a response body, so a `file://` transfer
/// and an `http://` transfer move the same size of block.
pub const read_buffer_len = 8192;

/// The host names a `file` url may carry, beside an empty one.
///
/// RFC 8089 gives `file://localhost/a` and `file:///a` the same meaning.
/// curl 8.21.0 accepts exactly these two and refuses every other host
/// with exit 3, measured on `file://otherhost/tmp/f.txt`.
pub const this_machine = "localhost";

io: Io,
/// The file the transfer in play reads, or null when none is open.
/// `open` closes this before it opens another, and `deinit` closes it if
/// the caller opened nothing more.
file: ?Io.File,
/// Reads `file`. Valid only while `file` holds something, and read only
/// through `&file_reader.interface`.
file_reader: Io.File.Reader,
/// The body of a directory, which is no bytes at all. See `open`.
empty: Io.Reader,
/// Backs `file_reader`. Must outlive every read of the body, which is why
/// it is a field and not a stack buffer inside `open`.
buffer: [read_buffer_len]u8,
/// Holds the percent-decoded path. A field for the same reason `buffer`
/// is: the open call reads it, and a caller may look at the diagnostic
/// message that names it afterwards.
path_storage: [Io.Dir.max_path_bytes]u8,

/// A `Fetcher` that holds no file yet.
pub fn init(io: Io) Fetcher {
    return .{
        .io = io,
        .file = null,
        .file_reader = undefined,
        .empty = undefined,
        .buffer = undefined,
        .path_storage = undefined,
    };
}

/// Closes whatever file is open. Safe to call more than once, and safe on
/// a `Fetcher` that never opened anything.
pub fn deinit(f: *Fetcher) void {
    f.close();
}

fn close(f: *Fetcher) void {
    const file = f.file orelse return;
    file.close(f.io);
    f.file = null;
}

/// The body of one `file://` transfer.
pub const Body = struct {
    /// Streams the file. Valid until the next `open` on this `Fetcher`, or
    /// until `deinit`, whichever comes first.
    reader: *Io.Reader,
    /// How many bytes the file holds, or null when the thing opened is
    /// not a plain file and its size says nothing about how much it
    /// gives. A named pipe and most of `/proc` are that shape: they stat
    /// as zero bytes and still stream content.
    length: ?u64,
};

/// Opens what `url` names and returns its body.
///
/// Closes whatever the previous call opened first, so a `Fetcher` never
/// holds two files at once.
///
/// The five answers, each measured against curl 8.21.0:
///
/// - `file:///path/to/f.txt` reads the file.
/// - `file://localhost/path/to/f.txt` reads the same file.
/// - `file://otherhost/path/to/f.txt` is `error.InvalidUrl`, exit 3.
/// - `file:///nonexistent/x` is `error.FileCouldNotReadFile`, exit 37.
/// - a directory reads as a body of no bytes, and the transfer works.
///
/// A query and a fragment are ignored, which is what curl does:
/// `file:///tmp/f.txt?q=1` and `file:///tmp/f.txt#top` both read
/// `/tmp/f.txt`. `zurl_core.url.parse` has already cut both off the path.
pub fn open(f: *Fetcher, url: zurl_core.Url, d: ?*Diagnostics) Error!Body {
    f.close();

    // A `file` url names this machine or it names nothing zurl can
    // reach. A host that is neither is the url being wrong, not the file
    // being missing, so this is exit 3 and not exit 37, as curl has it.
    if (url.host.len != 0 and !std.ascii.eqlIgnoreCase(url.host, this_machine)) {
        return fail(d, error.InvalidUrl, &.{
            "a file url reads this machine only, so its host must be empty or ",
            this_machine,
            ", and this one is ",
            url.host,
        });
    }

    const path = try f.decodePath(url.path, d);

    // The operating system reads a path as bytes up to the first zero, so
    // a `%00` in the url would name a shorter path than the url shows.
    // Refused by name rather than passed on, because a user reading the
    // failure must see the same path they typed.
    if (std.mem.indexOfScalar(u8, path, 0) != null) {
        return fail(d, error.FileCouldNotReadFile, &.{"the path holds a zero byte"});
    }

    // `allow_directory`, because curl answers a directory with an empty
    // body and exit 0 rather than a failure. The stat below is what tells
    // the two apart.
    var file = Io.Dir.cwd().openFile(f.io, path, .{ .allow_directory = true }) catch |err|
        return fail(d, error.FileCouldNotReadFile, &.{
            "zurl did not open ",
            path,
            ": ",
            @errorName(err),
        });
    errdefer file.close(f.io);

    const info = file.stat(f.io) catch |err| return fail(d, error.FileCouldNotReadFile, &.{
        "zurl did not read ",
        path,
        ": ",
        @errorName(err),
    });

    if (info.kind == .directory) {
        // curl 8.21.0 exits 0 and writes nothing for a directory. The
        // handle has nothing to give, so it closes here and the body is a
        // reader over no bytes.
        file.close(f.io);
        f.empty = .fixed("");
        return .{ .reader = &f.empty, .length = 0 };
    }

    f.file = file;
    f.file_reader = file.reader(f.io, &f.buffer);
    // **Plain reads, and never the kernel's file-to-file copy.**
    //
    // A `std.Io.File.Reader` in the `positional` mode streams itself with
    // `copy_file_range` when the destination is also a file. Linux
    // answers that call with `EBADF` when the destination was opened with
    // `O_APPEND`, and `std.Io.Threaded` reads `EBADF` as a programmer
    // bug and panics. `zurl file:///etc/hosts >> log` is exactly that
    // shape, and it took the whole program down. Measured: the same
    // command with `>` or with a pipe worked, and with `>>` it aborted.
    //
    // A protocol package must not decide the program's fate from the
    // shape of a file descriptor it never opened. `positional_simple`
    // reads with `pread` alone, which works for every destination, and
    // costs one copy through the buffer. curl reads and writes the same
    // way, so nothing is lost against it.
    f.file_reader.mode = .positional_simple;
    return .{
        .reader = &f.file_reader.interface,
        // Only a plain file has a size that says how much it gives.
        .length = if (info.kind == .file) info.size else null,
    };
}

/// Percent-decodes `escaped` into this `Fetcher`'s own path storage.
///
/// An escape that does not decode leaves the text alone. curl 8.21.0 does
/// the same: `file:///tmp/f%zz.txt` reaches its "Could not open file"
/// message with the `%zz` still in it, so the raw text is the path and the
/// open decides.
fn decodePath(f: *Fetcher, escaped: []const u8, d: ?*Diagnostics) Error![]const u8 {
    const out: []u8 = &f.path_storage;
    if (escaped.len > out.len) return fail(d, error.FileCouldNotReadFile, &.{
        "the path is longer than the ",
        std.fmt.comptimePrint("{d}", .{Io.Dir.max_path_bytes}),
        " bytes zurl reads",
    });

    return zurl_core.url.percentDecode(out, escaped) catch |err| switch (err) {
        error.InvalidEscape => escape: {
            @memcpy(out[0..escaped.len], escaped);
            break :escape out[0..escaped.len];
        },
        // The decoded form is never longer than the escaped form, and the
        // check above already refused a text that does not fit. This arm
        // is here so the refusal is a named fault and not an `unreachable`
        // that a ReleaseFast build turns into undefined behaviour.
        error.NoSpaceLeft => fail(d, error.FileCouldNotReadFile, &.{
            "the path is longer than zurl reads",
        }),
    };
}

/// Writes `parts`, one after another, into `d`'s own message storage,
/// records `err` with that message, and returns `err`.
///
/// The text goes into `Diagnostics.message_storage` for the reason
/// `zurl.Client.caFailureMessage` puts its own text there: the sentence
/// names a path this package holds in a buffer it reuses, so a borrowed
/// message would read the next transfer's path. A message longer than the
/// storage loses its tail, because a diagnostic that says less is a cost
/// and one that is not written at all is a fault.
///
/// Every part is copied under the bound, so a path of any length still
/// leaves one line.
fn fail(d: ?*Diagnostics, err: Error, parts: []const []const u8) Error {
    const target = d orelse return err;
    const out: []u8 = &target.message_storage;
    var at: usize = 0;
    for (parts) |part| {
        const n = @min(out.len - at, part.len);
        @memcpy(out[at..][0..n], part[0..n]);
        at += n;
    }
    return Diagnostics.record(d, err, .{ .message = out[0..at] });
}

const testing = std.testing;

/// A temporary directory with a file, a directory, and nothing else, and
/// the absolute path of each.
///
/// Every test here reads a real path, because the whole package is about
/// what the operating system answers. `std.testing.tmpDir` gives a
/// directory under the cache that the test runner removes afterwards.
const Sandbox = struct {
    tmp: testing.TmpDir,
    root_storage: [Io.Dir.max_path_bytes]u8,
    root_len: usize,

    fn init(s: *Sandbox) !void {
        s.tmp = testing.tmpDir(.{});
        errdefer s.tmp.cleanup();

        try s.tmp.dir.writeFile(testing.io, .{ .sub_path = "f.txt", .data = "hello file body\n" });
        try s.tmp.dir.writeFile(testing.io, .{ .sub_path = "a b.txt", .data = "space name\n" });
        try s.tmp.dir.createDirPath(testing.io, "sub");

        s.root_len = try s.tmp.dir.realPath(testing.io, &s.root_storage);
    }

    fn deinit(s: *Sandbox) void {
        s.tmp.cleanup();
    }

    fn root(s: *const Sandbox) []const u8 {
        return s.root_storage[0..s.root_len];
    }

    /// The url text for `sub_path` inside this sandbox, with `host`
    /// between the `file://` and the path.
    fn url(s: *const Sandbox, out: []u8, host: []const u8, sub_path: []const u8) ![]const u8 {
        return std.fmt.bufPrint(out, "file://{s}{s}/{s}", .{ host, s.root(), sub_path });
    }
};

/// Parses `text` the way `zurl.Client` does, with `file` registered.
fn parseFileUrl(text: []const u8) !zurl_core.Url {
    var schemes: zurl_core.url.Schemes = .empty;
    try schemes.add(.{ .name = scheme, .default_port = default_port });
    return zurl_core.url.parseWith(text, &schemes);
}

test "an empty host reads the file, matching curl" {
    var sandbox: Sandbox = undefined;
    try sandbox.init();
    defer sandbox.deinit();

    var url_buffer: [Io.Dir.max_path_bytes + 64]u8 = undefined;
    const text = try sandbox.url(&url_buffer, "", "f.txt");

    var fetcher: Fetcher = .init(testing.io);
    defer fetcher.deinit();

    const body = try fetcher.open(try parseFileUrl(text), null);
    try testing.expectEqual(@as(?u64, 16), body.length);

    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("hello file body\n", contents);
}

test "the body reader never asks the kernel to copy file to file" {
    // The defect: a body in the `positional` mode streams itself with
    // `copy_file_range`, Linux answers `EBADF` when the destination was
    // opened with `O_APPEND`, and `std.Io.Threaded` panics on that errno.
    // `zurl file:///etc/hosts >> log` aborted the whole program.
    //
    // The mode is asserted, and not the syscall, because no portable
    // `std.Io` call opens a file with `O_APPEND` for a test to write to.
    var sandbox: Sandbox = undefined;
    try sandbox.init();
    defer sandbox.deinit();

    var url_buffer: [Io.Dir.max_path_bytes + 64]u8 = undefined;
    const text = try sandbox.url(&url_buffer, "", "f.txt");

    var fetcher: Fetcher = .init(testing.io);
    defer fetcher.deinit();

    const body = try fetcher.open(try parseFileUrl(text), null);
    try testing.expectEqual(Io.File.Reader.Mode.positional_simple, fetcher.file_reader.mode);

    // And the whole body still arrives through that mode.
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    _ = try body.reader.streamRemaining(&out.writer);
    try testing.expectEqualStrings("hello file body\n", out.written());
}

test "the host localhost reads the same file, matching curl" {
    var sandbox: Sandbox = undefined;
    try sandbox.init();
    defer sandbox.deinit();

    var url_buffer: [Io.Dir.max_path_bytes + 64]u8 = undefined;
    const text = try sandbox.url(&url_buffer, this_machine, "f.txt");

    var fetcher: Fetcher = .init(testing.io);
    defer fetcher.deinit();

    const body = try fetcher.open(try parseFileUrl(text), null);
    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("hello file body\n", contents);

    // RFC 3986 makes a host case-insensitive, and curl accepts either
    // spelling.
    const upper = try sandbox.url(&url_buffer, "LOCALHOST", "f.txt");
    _ = try fetcher.open(try parseFileUrl(upper), null);
}

test "a host that is not this machine is a bad url, not a missing file" {
    var sandbox: Sandbox = undefined;
    try sandbox.init();
    defer sandbox.deinit();

    var url_buffer: [Io.Dir.max_path_bytes + 64]u8 = undefined;
    const text = try sandbox.url(&url_buffer, "otherhost", "f.txt");

    var fetcher: Fetcher = .init(testing.io);
    defer fetcher.deinit();

    var d: Diagnostics = .{};
    // curl 8.21.0 answers `file://otherhost/...` with exit 3, `URL
    // rejected: Bad file:// URL`. Exit 3 is `InvalidUrl` and not the 37
    // a missing file gets, because the url is what is wrong.
    try testing.expectError(error.InvalidUrl, fetcher.open(try parseFileUrl(text), &d));
    try testing.expectEqual(@as(u32, 3), d.curl_code.?);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "otherhost") != null);
}

test "a path that is not there is curl's own file code" {
    var sandbox: Sandbox = undefined;
    try sandbox.init();
    defer sandbox.deinit();

    var url_buffer: [Io.Dir.max_path_bytes + 64]u8 = undefined;
    const text = try sandbox.url(&url_buffer, "", "nonexistent/x");

    var fetcher: Fetcher = .init(testing.io);
    defer fetcher.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(error.FileCouldNotReadFile, fetcher.open(try parseFileUrl(text), &d));
    // curl 8.21.0 exits 37, `CURLE_FILE_COULDNT_READ_FILE`.
    try testing.expectEqual(@as(u32, 37), d.curl_code.?);
    // Recovery is never silent: the message names the path and the
    // operating system's own reason, which curl's own sentence drops.
    try testing.expect(std.mem.indexOf(u8, d.message.?, "nonexistent/x") != null);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "FileNotFound") != null);
}

test "a directory reads as an empty body and not as a failure" {
    var sandbox: Sandbox = undefined;
    try sandbox.init();
    defer sandbox.deinit();

    var url_buffer: [Io.Dir.max_path_bytes + 64]u8 = undefined;
    const text = try sandbox.url(&url_buffer, "", "sub");

    var fetcher: Fetcher = .init(testing.io);
    defer fetcher.deinit();

    // curl 8.21.0 exits 0 and writes nothing at all for a directory.
    const body = try fetcher.open(try parseFileUrl(text), null);
    try testing.expectEqual(@as(?u64, 0), body.length);

    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("", contents);
}

test "an escape in the path names the file the escape spells" {
    var sandbox: Sandbox = undefined;
    try sandbox.init();
    defer sandbox.deinit();

    var url_buffer: [Io.Dir.max_path_bytes + 64]u8 = undefined;
    const text = try sandbox.url(&url_buffer, "", "a%20b.txt");

    var fetcher: Fetcher = .init(testing.io);
    defer fetcher.deinit();

    const body = try fetcher.open(try parseFileUrl(text), null);
    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("space name\n", contents);
}

test "an escape that does not decode stays in the path, matching curl" {
    var sandbox: Sandbox = undefined;
    try sandbox.init();
    defer sandbox.deinit();

    var url_buffer: [Io.Dir.max_path_bytes + 64]u8 = undefined;
    const text = try sandbox.url(&url_buffer, "", "f%zz.txt");

    var fetcher: Fetcher = .init(testing.io);
    defer fetcher.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(error.FileCouldNotReadFile, fetcher.open(try parseFileUrl(text), &d));
    // curl 8.21.0 reports `Could not open file .../f%zz.txt`, with the
    // escape still there, so the raw text is the name it looked for.
    try testing.expect(std.mem.indexOf(u8, d.message.?, "f%zz.txt") != null);
}

test "a zero byte in the path is refused by name" {
    // `%00` decodes to a byte the operating system reads as the end of
    // the path, so the url would name a shorter path than it shows.
    var sandbox: Sandbox = undefined;
    try sandbox.init();
    defer sandbox.deinit();

    var url_buffer: [Io.Dir.max_path_bytes + 64]u8 = undefined;
    const text = try sandbox.url(&url_buffer, "", "f.txt%00.png");

    var fetcher: Fetcher = .init(testing.io);
    defer fetcher.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(error.FileCouldNotReadFile, fetcher.open(try parseFileUrl(text), &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "zero byte") != null);
}

test "a second open closes the file the first one left" {
    var sandbox: Sandbox = undefined;
    try sandbox.init();
    defer sandbox.deinit();

    // Two buffers, because both url texts stay in play at once.
    var url_buffer: [Io.Dir.max_path_bytes + 64]u8 = undefined;
    var missing_buffer: [Io.Dir.max_path_bytes + 64]u8 = undefined;
    const text = try sandbox.url(&url_buffer, "", "f.txt");

    var fetcher: Fetcher = .init(testing.io);
    defer fetcher.deinit();

    _ = try fetcher.open(try parseFileUrl(text), null);
    try testing.expect(fetcher.file != null);

    // A transfer that fails still leaves no handle behind.
    const missing = try sandbox.url(&missing_buffer, "", "nonexistent/x");
    try testing.expectError(
        error.FileCouldNotReadFile,
        fetcher.open(try parseFileUrl(missing), null),
    );
    try testing.expectEqual(@as(?Io.File, null), fetcher.file);

    // And a second working transfer reads the whole file again, not the
    // tail of the first read.
    const body = try fetcher.open(try parseFileUrl(text), null);
    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("hello file body\n", contents);
}

test "a failure with no diagnostics still reports the error" {
    var fetcher: Fetcher = .init(testing.io);
    defer fetcher.deinit();

    try testing.expectError(
        error.FileCouldNotReadFile,
        fetcher.open(try parseFileUrl("file:///nonexistent/zurl-test/x"), null),
    );
    try testing.expectError(
        error.InvalidUrl,
        fetcher.open(try parseFileUrl("file://otherhost/x"), null),
    );
}

/// The smallest front package that `protocol` can build against.
///
/// This is a stub of the shape `zurl` exports, and it is here to prove one
/// thing: `protocol` needs the shape and never the package. This file must
/// build with no `zurl` in its import table at all, because a protocol
/// package that imports the front package cannot be left out of a build
/// that does not want it.
///
/// A change to `zurl.protocol.Protocol` that this stub does not follow is
/// a compile error at the call in `src/cli/run.zig`, which is where the
/// real types meet.
const StubFront = struct {
    const Client = struct {};

    const Transfer = struct {
        const Options = struct {};
    };

    const Response = struct {
        status: u16,
        content_length: ?u64,
        transfer_encoding: std.http.TransferEncoding,
        body: *Io.Reader,
        effective_url: []const u8 = "",
    };

    const protocol = struct {
        // The stub keeps the shape of `zurl.protocol.Unread`. A stub that
        // dropped a field would let this package compile against a front
        // it no longer fits.
        const Unread = struct {
            proxy: bool = false,
            credentials: bool = false,
        };

        const Protocol = struct {
            scheme: []const u8,
            default_port: ?u16,
            ptr: ?*anyopaque,
            vtable: *const VTable,
            unread: Unread = .{},

            const VTable = struct {
                perform: *const fn (
                    ptr: ?*anyopaque,
                    c: *Client,
                    url: zurl_core.Url,
                    options: Transfer.Options,
                    d: ?*Diagnostics,
                ) Error!Response,
            };
        };
    };
};

test "protocol builds a dispatch entry that reads the file" {
    var sandbox: Sandbox = undefined;
    try sandbox.init();
    defer sandbox.deinit();

    var url_buffer: [Io.Dir.max_path_bytes + 64]u8 = undefined;
    const text = try sandbox.url(&url_buffer, "", "f.txt");

    var fetcher: Fetcher = .init(testing.io);
    defer fetcher.deinit();

    const entry = fetcher.protocol(StubFront);
    try testing.expectEqualStrings("file", entry.scheme);
    try testing.expectEqual(@as(?u16, null), entry.default_port);

    var client: StubFront.Client = .{};
    const response = try entry.vtable.perform(
        entry.ptr,
        &client,
        try parseFileUrl(text),
        .{},
        null,
    );
    // Zero, the way curl reports `%{http_code}` for a `file://` transfer.
    try testing.expectEqual(@as(u16, 0), response.status);
    try testing.expectEqual(@as(?u64, 16), response.content_length);

    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("hello file body\n", contents);
}

/// Returns the dispatch entry that registers this fetcher with a client.
///
/// `Front` is the front package's own namespace, taken as a comptime
/// parameter. Passing the namespace rather than importing it is what keeps
/// this package free of a `zurl` import: the front package imports no
/// protocol package, and no protocol package imports the front package, so
/// a build can leave any protocol out and a program outside this
/// repository can bring its own in.
///
/// The caller registers the result:
///
///     var fetcher: zurl_file.Fetcher = .init(io);
///     defer fetcher.deinit();
///     try client.registerProtocol(fetcher.protocol(zurl));
///
/// `registerProtocol` teaches the url parser the scheme at the same time,
/// so `file:///a/b` parses after that one call and not before.
///
/// **`f` must outlive every transfer the client runs on this scheme**, and
/// must not move: the entry carries `f` as its opaque pointer, and the
/// body reader points inside it.
pub fn protocol(f: *Fetcher, comptime Front: type) Front.protocol.Protocol {
    return .{
        .scheme = scheme,
        .default_port = default_port,
        .ptr = f,
        .vtable = &Dispatch(Front).vtable,
        // **Nothing is named unread here, and that is the right answer.**
        // A `file://` url reaches no peer at all, so a proxy has nothing
        // to carry and a credential has nobody to send to. curl runs a
        // `file://` url beside a `-x` flag too. See
        // `Front.protocol.Unread`.
        .unread = .{},
    };
}

/// The vtable for one front package. One instantiation for each `Front`,
/// and each one holds a single comptime constant, so the table lives in
/// the binary's own read-only data and never on a stack.
fn Dispatch(comptime Front: type) type {
    return struct {
        const vtable: Front.protocol.Protocol.VTable = .{ .perform = performFile };

        /// Runs one `file://` transfer.
        ///
        /// `c` and `options` go unread. The client holds a connection pool
        /// and a trust store, and this reads neither. Every option a
        /// transfer carries is either about a peer, which there is none
        /// of, or about the body stack, which the front package decorates
        /// around the reader this returns.
        fn performFile(
            ptr: ?*anyopaque,
            c: *Front.Client,
            url: zurl_core.Url,
            options: Front.Transfer.Options,
            d: ?*Diagnostics,
        ) Error!Front.Response {
            _ = c;
            _ = options;
            const f: *Fetcher = @ptrCast(@alignCast(ptr.?));
            const body = try f.open(url, d);
            return .{
                .status = status,
                .content_length = body.length,
                .transfer_encoding = .none,
                .body = body.reader,
            };
        }
    };
}
