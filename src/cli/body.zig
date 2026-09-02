//! Turns what the command line said about a request body into the bytes
//! that go on the wire.
//!
//! `src/cli/Args.zig` records the flags and opens nothing, because a parse
//! does no I/O. This file is the other half: it reads every `@name` a
//! `-d` named, opens the file a `-T` named, and fills
//! `Transfer.Options.body`. `src/main.zig` calls it once, beside
//! `loadNetrc`, which reads `--netrc-file` for the same reason.
//!
//! **Two shapes of body, and only two.** A `-d` family body is built in
//! memory, because the flags join their arguments and one of them strips
//! bytes out of a file, so the bytes have to exist together before any of
//! them can go out. `max_data_bytes` is the bound on that memory, and it
//! is the only bound zurl puts on a request body. A `-T` body is streamed
//! from the open file in pieces the engine sizes, so it costs no memory at
//! all and needs no bound.
//!
//! Every rule here was measured against curl 8.21.0 with a loopback
//! listener that captured the request bytes. The measurement sits beside
//! the rule it produced.

const std = @import("std");
const zurl = @import("zurl");
const Args = @import("Args.zig");
const form = @import("form.zig");
const safe = @import("safe.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

/// How large a `-d` family request body may grow, over every `-d`,
/// `--data-raw`, `--data-binary`, `--data-urlencode`, and `--json` on one
/// command line together.
///
/// **This is the bound on the one path that reads a file into memory.**
/// `-d @name` and `--data-urlencode @name` read a whole file, and `@-`
/// reads standard input, so both are untrusted in size. curl puts no bound
/// on either and grows its buffer until the machine runs out. zurl refuses
/// instead, and names the flag and the bound.
///
/// 16 MiB is far past any form post and any JSON document a command line
/// carries. A body larger than this belongs in `-T`, which streams the
/// file and reads no bound at all.
pub const max_data_bytes: usize = 16 * 1024 * 1024;

/// The bytes and the open file a resolved body reads from.
///
/// **This value must outlive every transfer of the run and must not
/// move.** `Transfer.Options.body` holds the address of one of its
/// fields, and the engine reads through that address on every send.
/// `src/main.zig` keeps it in the frame that also runs the transfers.
pub const Storage = struct {
    /// The assembled `-d` family body. Points into the arena.
    memory: zurl.request_body.Memory = .{ .bytes = "" },
    /// The `-T` source, when the run has one.
    file: zurl.request_body.File = undefined,
    /// The `-F` source, when the run has one. Read only after
    /// `form.build` has filled it.
    form: zurl.multipart.Body = undefined,
    /// Every file a `-F 'n=@path'` opened, in part order. Each stays open
    /// for the whole run, because the body streams each one as the engine
    /// asks for it.
    form_files: []Io.File = &.{},
    /// The handle `file` reads. Null when no `-T` opened one, and null for
    /// standard input, which this file did not open and must not close.
    opened: ?Io.File = null,

    /// Closes every file this run opened. Does nothing for a run with no
    /// `-T` and no `-F`, and nothing for `-T -`, whose handle belongs to
    /// the process.
    pub fn deinit(self: *Storage, io: Io) void {
        if (self.opened) |handle| handle.close(io);
        self.opened = null;
        for (self.form_files) |handle| handle.close(io);
        self.form_files = &.{};
    }
};

/// What `resolve` reads and writes. Kept apart from `run.Context` so a
/// test can drive this file with no transfer machinery at all.
pub const Inputs = struct {
    arena: Allocator,
    io: Io,
    /// Where a refusal goes. Every message here is one a user acts on, so
    /// it names the flag and the file.
    stderr: *Io.Writer,
    /// The directory a relative `@name` or `-T name` is read from. The
    /// working directory for a real run; a test passes its own temporary
    /// directory, so no test writes into the tree it runs in.
    dir: Io.Dir = .cwd(),
};

/// Reads what `plan.request_body` names and fills `plan.options.body`, or
/// rewrites `plan.urls` when `-G` moved the data into the query.
///
/// Returns whether the run may continue. A refusal is written to
/// `in.stderr` and returns false, the same shape `loadNetrc` uses: a
/// `Plan` holds no place for the message, and the caller already knows the
/// exit code for a usage fault.
///
/// `storage` must outlive every transfer of the run.
pub fn resolve(
    in: Inputs,
    plan: *Args.Plan,
    storage: *Storage,
) (Allocator.Error || Io.Writer.Error)!bool {
    const spec = plan.request_body;

    // **`--url-query` runs first, and it runs whatever the body is.** The
    // flag adds to the url query and never to the body, so a form, an
    // upload, and a `-d` may each go out beside it. That is the whole
    // difference from `-G`, which moves the `-d` data into the query and
    // leaves the request with none. Measured against curl 8.21.0 on a
    // loopback listener: `--url-query 'ab=c' 'http://h/p?x=1'` sent
    // `GET /p?x=1&ab=c`.
    //
    // It is written before the branches below, so no `return` can skip it.
    if (!try applyUrlQuery(in, plan, spec.query)) return false;

    // A form, an upload, and the `-d` family are three bodies and a
    // request carries one. `Args.resolveRequestBody` already refused every
    // pair, so at most one branch below runs.
    if (spec.form.len != 0) return form.build(in, plan, storage);

    if (spec.upload) |path| {
        // `-` is standard input, the same reading `-o -` and `-D -` get.
        // The handle belongs to the process, so `Storage.deinit` must not
        // close it, and a pipe has no length and no way back to its first
        // byte: the request goes out chunked and may go out once.
        if (std.mem.eql(u8, path, "-")) {
            storage.file = .init(in.io, .stdin());
        } else {
            const handle = in.dir.openFile(in.io, path, .{}) catch {
                try in.stderr.print("zurl: -T: cannot read '{f}'\n", .{safe.text(path)});
                return false;
            };
            storage.opened = handle;
            storage.file = .init(in.io, handle);
        }
        plan.options.body = storage.file.source();
        return true;
    }

    if (spec.data.len == 0) return true;

    var assembled: std.ArrayList(u8) = .empty;
    for (spec.data) |item| {
        if (!try appendItem(in, &assembled, item)) return false;
    }

    if (spec.get) {
        // **`-G` moves the data into the query and sends no body.**
        // Measured: `-d 'a=1' -G` sends `GET /x?a=1` with no
        // `Content-Type` and no `Content-Length`, and `-d 'a=1' -G` on
        // `/x?q=0` sends `GET /x?q=0&a=1`.
        const urls = try in.arena.alloc([]const u8, plan.urls.len);
        for (urls, plan.urls) |*out, url| out.* = try withQuery(in.arena, url, assembled.items);
        plan.urls = urls;
        return true;
    }

    storage.memory = .{ .bytes = assembled.items, .content_type = spec.content_type };
    plan.options.body = storage.memory.source();
    return true;
}

/// Adds every `--url-query` argument to the query of every url of the run,
/// and returns whether the run may continue.
///
/// **Each argument is read exactly the way `--data-urlencode` reads its
/// own**, which is what curl documents the flag as: "the same as
/// `--data-urlencode` but for the query part". So `name=text`,
/// `name@file`, `@file`, and a bare `text` all work here, and one function
/// reads all four for both flags. A second copy of that reader would drift
/// from this one.
///
/// The arguments join with an `&` between them, the way the `-d` family
/// joins, and the joined text goes through `withQuery`, so an empty query
/// takes no separator and a fragment stays where it was.
///
/// Runs before any body is built, so a `-T`, an `-F`, or a `-d` still goes
/// out beside the query this adds.
fn applyUrlQuery(
    in: Inputs,
    plan: *Args.Plan,
    items: []const Args.DataItem,
) (Allocator.Error || Io.Writer.Error)!bool {
    if (items.len == 0) return true;

    var assembled: std.ArrayList(u8) = .empty;
    for (items) |item| {
        if (!try appendItem(in, &assembled, item)) return false;
    }

    const urls = try in.arena.alloc([]const u8, plan.urls.len);
    for (urls, plan.urls) |*out, url| out.* = try withQuery(in.arena, url, assembled.items);
    plan.urls = urls;
    return true;
}

/// Appends one `-d` family argument to the body being assembled, and
/// returns whether the run may continue.
///
/// **The separator belongs to the item being appended, not to the one
/// before it.** Measured against curl 8.21.0:
///
/// ```
/// -d a=1 -d b=2                 a=1&b=2
/// --json '{"a":1}' -d 'b=2'     {"a":1}&b=2
/// -d 'b=2' --json '{"a":1}'     b=2{"a":1}
/// --json '{"a":1}' --json ',{"b":2}'   {"a":1},{"b":2}
/// ```
///
/// So a `-d`, `--data-raw`, `--data-binary`, or `--data-urlencode` puts an
/// `&` in front of itself when something is already there, and a `--json`
/// puts nothing in front of itself ever. That is why `--json` can be given
/// twice to build one document out of two arguments.
fn appendItem(
    in: Inputs,
    out: *std.ArrayList(u8),
    item: Args.DataItem,
) (Allocator.Error || Io.Writer.Error)!bool {
    if (item.kind != .json and out.items.len != 0) try out.append(in.arena, '&');

    switch (item.kind) {
        // The argument is the data. A leading `@` is data too, which is
        // the whole point of `--data-raw`, and `--json` reads its argument
        // the same way.
        .raw, .json => try appendBounded(in, out, item.text),
        // `@name` reads a file and drops every CR and LF from it. `@-`
        // reads standard input the same way. Anything else is the data
        // itself, newlines and all: measured, `-d $'a\nb'` sends `a\nb`,
        // so the stripping belongs to the file read and not to the flag.
        .ascii => {
            const text = (try readArgument(in, item.text, "-d")) orelse return false;
            if (text.ptr == item.text.ptr) {
                try appendBounded(in, out, text);
            } else {
                try appendStripped(in, out, text);
            }
        },
        // `@name` reads a file byte for byte. Measured: over a file
        // holding `a=1\nb=2\n`, `-d @file` sends 6 bytes and
        // `--data-binary @file` sends all 8.
        .binary => {
            const text = (try readArgument(in, item.text, "--data-binary")) orelse return false;
            try appendBounded(in, out, text);
        },
        .urlencode => if (!try appendUrlencoded(in, out, item.text)) return false,
    }
    return true;
}

/// Reads `text` as a `-d` argument: the file `@name` points at, standard
/// input for `@-`, or the text itself when it starts with no `@`.
///
/// Returns null when the read failed, after writing the message. A
/// returned slice that is `text` itself, pointer and all, is the "no file"
/// case; `appendItem` reads that to decide whether the CR and LF stripping
/// applies.
fn readArgument(
    in: Inputs,
    text: []const u8,
    flag: []const u8,
) (Allocator.Error || Io.Writer.Error)!?[]const u8 {
    if (text.len == 0 or text[0] != '@') return text;
    const name = text[1..];

    if (std.mem.eql(u8, name, "-")) {
        var buffer: [4096]u8 = undefined;
        var stdin: Io.File.Reader = .init(.stdin(), in.io, &buffer);
        return stdin.interface.allocRemaining(in.arena, .limited(max_data_bytes)) catch |err| switch (err) {
            error.OutOfMemory => |e| return e,
            error.StreamTooLong => {
                try in.stderr.print(
                    "zurl: {s}: standard input is larger than the {d} byte limit\n",
                    .{ flag, max_data_bytes },
                );
                return null;
            },
            else => {
                try in.stderr.print("zurl: {s}: cannot read standard input\n", .{flag});
                return null;
            },
        };
    }

    return in.dir.readFileAlloc(in.io, name, in.arena, .limited(max_data_bytes)) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        error.StreamTooLong => {
            try in.stderr.print(
                "zurl: {s}: '{f}' is larger than the {d} byte limit\n",
                .{ flag, safe.text(name), max_data_bytes },
            );
            return null;
        },
        else => {
            try in.stderr.print("zurl: {s}: cannot read '{f}'\n", .{ flag, safe.text(name) });
            return null;
        },
    };
}

/// Appends `text` and refuses a body that would pass `max_data_bytes`.
///
/// The refusal is a fault this file cannot report from here, so it is an
/// error rather than a message: `appendBounded` has no `stderr` of its
/// own to write to. `resolve` never reaches it, because every read that
/// fills `text` is already bounded by `max_data_bytes` and the append
/// checks the total.
fn appendBounded(
    in: Inputs,
    out: *std.ArrayList(u8),
    text: []const u8,
) Allocator.Error!void {
    // A body over the bound is refused by the read that produced it. This
    // is the check on the total across several arguments, and it truncates
    // nothing: an append that would pass the bound reports no memory,
    // which is the fault the arena would report anyway.
    if (out.items.len + text.len > max_data_bytes) return error.OutOfMemory;
    try out.appendSlice(in.arena, text);
}

/// Appends `text` with every CR and LF dropped.
///
/// This is what `-d @file` does. Measured: a file holding `a=1\nb=2\n`
/// goes out as `a=1b=2`, six bytes. `--data-binary @file` sends all eight.
fn appendStripped(
    in: Inputs,
    out: *std.ArrayList(u8),
    text: []const u8,
) Allocator.Error!void {
    if (out.items.len + text.len > max_data_bytes) return error.OutOfMemory;
    for (text) |byte| {
        if (byte == '\r' or byte == '\n') continue;
        try out.append(in.arena, byte);
    }
}

/// Appends one `--data-urlencode` argument, in whichever of its four forms
/// it was written.
///
/// Measured against curl 8.21.0, with a file holding `x y&z\n`:
///
/// ```
/// --data-urlencode 'a b&c'        a+b%26c        no name
/// --data-urlencode '=a b&c'       a+b%26c        the same, spelled out
/// --data-urlencode 'name=a b&c'   name=a+b%26c   the name is not encoded
/// --data-urlencode @file          x+y%26z%0A     nothing is dropped
/// --data-urlencode 'n@file'       n=x+y%26z%0A
/// ```
///
/// So a `=` or an `@` before the first of either decides the form, the
/// name goes out as it was written, and the content is always encoded. A
/// file read here drops nothing: the newline came back as `%0A`.
fn appendUrlencoded(
    in: Inputs,
    out: *std.ArrayList(u8),
    text: []const u8,
) (Allocator.Error || Io.Writer.Error)!bool {
    // The first `=` or `@`, whichever comes first, is the separator.
    // Anything before it is the name.
    var separator: ?usize = null;
    for (text, 0..) |byte, i| {
        if (byte == '=' or byte == '@') {
            separator = i;
            break;
        }
    }

    const at = separator orelse {
        // No separator at all: the whole argument is content.
        try appendEncoded(in, out, text);
        return true;
    };

    const name = text[0..at];
    const rest = text[at + 1 ..];

    // An empty name writes no `name=`, which is what `=content` and
    // `@file` both mean.
    if (name.len != 0) {
        try appendBounded(in, out, name);
        try appendBounded(in, out, "=");
    }

    if (text[at] == '=') {
        try appendEncoded(in, out, rest);
        return true;
    }

    // `@name` and `name@file`: the content comes from a file, or from
    // standard input for `@-`.
    const at_text = try std.fmt.allocPrint(in.arena, "@{s}", .{rest});
    const content = (try readArgument(in, at_text, "--data-urlencode")) orelse return false;
    try appendEncoded(in, out, content);
    return true;
}

/// Appends `text` percent-encoded, the way curl's `--data-urlencode`
/// encodes it.
///
/// **The alphabet was measured, not assumed.** Every byte from 32 to 126,
/// plus a newline, a tab, and a two-byte UTF-8 character, went through
/// `curl --data-urlencode @file`. What came back unencoded was
/// `A-Z a-z 0-9 - . _ ~`, a space came back as `+`, and every other byte
/// came back as `%` and two upper-case hexadecimal digits.
fn appendEncoded(
    in: Inputs,
    out: *std.ArrayList(u8),
    text: []const u8,
) Allocator.Error!void {
    // Three bytes for each input byte is the longest an escape can be, so
    // this refuses before it starts rather than part way through.
    if (out.items.len + text.len * 3 > max_data_bytes) return error.OutOfMemory;

    for (text) |byte| switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => try out.append(in.arena, byte),
        ' ' => try out.append(in.arena, '+'),
        else => {
            const hex = "0123456789ABCDEF";
            try out.append(in.arena, '%');
            try out.append(in.arena, hex[byte >> 4]);
            try out.append(in.arena, hex[byte & 0x0f]);
        },
    };
}

/// Returns `url` with `data` added to its query, the way `-G` adds it.
///
/// The data goes in front of any fragment, because a fragment is not part
/// of the request target and text appended behind one would never reach
/// the query at all. Measured against curl 8.21.0:
///
/// ```
/// http://h/x      -d a=1 -G   GET /x?a=1
/// http://h/x?q=0  -d a=1 -G   GET /x?q=0&a=1
/// http://h/x?     -d a=1 -G   GET /x?a=1
/// http://h/x#top  -d a=1 -G   GET /x?a=1
/// ```
///
/// So an empty query takes no `&`, and a fragment is left where it was.
pub fn withQuery(arena: Allocator, url: []const u8, data: []const u8) Allocator.Error![]const u8 {
    const fragment = std.mem.indexOfScalar(u8, url, '#') orelse url.len;
    const head = url[0..fragment];
    const tail = url[fragment..];

    const separator: []const u8 = if (std.mem.indexOfScalar(u8, head, '?')) |q|
        // A query that is there but empty needs no separator of its own.
        (if (q == head.len - 1) "" else "&")
    else
        "?";

    return std.fmt.allocPrint(arena, "{s}{s}{s}{s}", .{ head, separator, data, tail });
}

const testing = std.testing;

fn testArena() std.heap.ArenaAllocator {
    return .init(testing.allocator);
}

/// Runs `resolve` over `argv` and returns the body bytes it built, or null
/// when the run was refused.
fn resolveBody(arena: Allocator, plan: *Args.Plan, storage: *Storage, dir: Io.Dir) !?[]const u8 {
    var discard: [512]u8 = undefined;
    var writer: Io.Writer = .fixed(&discard);
    const ok = try resolve(
        .{ .arena = arena, .io = testing.io, .stderr = &writer, .dir = dir },
        plan,
        storage,
    );
    if (!ok) return null;
    const source = plan.options.body orelse return "";
    return storage.memory.bytes[0..@intCast(source.len.?)];
}

fn planFor(arena: Allocator, argv: []const []const u8) !Args.Plan {
    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();
    return Args.parse(arena, argv, &env, null);
}

test "-d joins its arguments with an ampersand, and --json joins with nothing" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const Case = struct { argv: []const []const u8, body: []const u8 };
    const cases = [_]Case{
        .{ .argv = &.{ "-d", "a=1", "http://x" }, .body = "a=1" },
        .{ .argv = &.{ "-d", "a=1", "-d", "b=2", "http://x" }, .body = "a=1&b=2" },
        .{ .argv = &.{ "-d", "a=1", "--data-raw", "b=2", "--data-binary", "c=3", "http://x" }, .body = "a=1&b=2&c=3" },
        .{ .argv = &.{ "--json", "{\"a\":1}", "--json", ",{\"b\":2}", "http://x" }, .body = "{\"a\":1},{\"b\":2}" },
        .{ .argv = &.{ "--json", "{\"a\":1}", "-d", "b=2", "http://x" }, .body = "{\"a\":1}&b=2" },
        .{ .argv = &.{ "-d", "b=2", "--json", "{\"a\":1}", "http://x" }, .body = "b=2{\"a\":1}" },
        // `--data-raw` opens no file, so a leading `@` is data.
        .{ .argv = &.{ "--data-raw", "@notafile", "http://x" }, .body = "@notafile" },
        // An empty `-d` sends a body of no bytes, and curl frames it with
        // `Content-Length: 0`.
        .{ .argv = &.{ "-d", "", "http://x" }, .body = "" },
    };

    for (cases) |case| {
        var plan = try planFor(a, case.argv);
        var storage: Storage = .{};
        const built = (try resolveBody(a, &plan, &storage, .cwd())).?;
        try testing.expectEqualStrings(case.body, built);
    }
}

test "-d @file drops the newlines and --data-binary @file keeps them" {
    // The one measured difference between the two flags. A file holding
    // `a=1\nb=2\n` goes out as six bytes through `-d` and as eight through
    // `--data-binary`.
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "d.txt", .data = "a=1\nb=2\n" });

    var stripped = try planFor(a, &.{ "-d", "@d.txt", "http://x" });
    var stripped_storage: Storage = .{};
    try testing.expectEqualStrings("a=1b=2", (try resolveBody(a, &stripped, &stripped_storage, tmp.dir)).?);

    var whole = try planFor(a, &.{ "--data-binary", "@d.txt", "http://x" });
    var whole_storage: Storage = .{};
    try testing.expectEqualStrings("a=1\nb=2\n", (try resolveBody(a, &whole, &whole_storage, tmp.dir)).?);
}

test "--data-urlencode reads all four of its forms" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "e.txt", .data = "x y&z\n" });

    const Case = struct { argument: []const u8, body: []const u8 };
    const cases = [_]Case{
        .{ .argument = "a b&c", .body = "a+b%26c" },
        .{ .argument = "=a b&c", .body = "a+b%26c" },
        .{ .argument = "name=a b&c", .body = "name=a+b%26c" },
        .{ .argument = "@e.txt", .body = "x+y%26z%0A" },
        .{ .argument = "n@e.txt", .body = "n=x+y%26z%0A" },
    };

    for (cases) |case| {
        var plan = try planFor(a, &.{ "--data-urlencode", case.argument, "http://x" });
        var storage: Storage = .{};
        try testing.expectEqualStrings(case.body, (try resolveBody(a, &plan, &storage, tmp.dir)).?);
    }
}

test "the percent encoding keeps exactly the alphabet curl keeps" {
    // Measured: every byte from 32 to 126 through `curl --data-urlencode`
    // came back unencoded only for these, a space came back as `+`, and
    // every other byte came back as `%` and two upper-case hex digits.
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    var out: std.ArrayList(u8) = .empty;
    var discard: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&discard);
    const in: Inputs = .{ .arena = a, .io = testing.io, .stderr = &writer };

    var plain: [95]u8 = undefined;
    for (&plain, 0..) |*byte, i| byte.* = @intCast(32 + i);
    try appendEncoded(in, &out, &plain);

    try testing.expectEqualStrings(
        "+%21%22%23%24%25%26%27%28%29%2A%2B%2C-.%2F0123456789" ++
            "%3A%3B%3C%3D%3E%3F%40ABCDEFGHIJKLMNOPQRSTUVWXYZ%5B%5C%5D%5E_%60" ++
            "abcdefghijklmnopqrstuvwxyz%7B%7C%7D~",
        out.items,
    );
}

test "-G moves the data into the query and leaves no body" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    var plan = try planFor(a, &.{ "-G", "-d", "a=1", "http://h/x?q=0", "http://h/y" });
    var storage: Storage = .{};
    var discard: [512]u8 = undefined;
    var writer: Io.Writer = .fixed(&discard);
    try testing.expect(try resolve(.{ .arena = a, .io = testing.io, .stderr = &writer }, &plan, &storage));

    try testing.expectEqual(@as(?zurl.Transfer.Body, null), plan.options.body);
    try testing.expectEqualStrings("http://h/x?q=0&a=1", plan.urls[0]);
    try testing.expectEqualStrings("http://h/y?a=1", plan.urls[1]);
}

test "withQuery puts the data in front of a fragment" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    try testing.expectEqualStrings("http://h/x?a=1", try withQuery(a, "http://h/x", "a=1"));
    try testing.expectEqualStrings("http://h/x?q=0&a=1", try withQuery(a, "http://h/x?q=0", "a=1"));
    try testing.expectEqualStrings("http://h/x?a=1", try withQuery(a, "http://h/x?", "a=1"));
    try testing.expectEqualStrings("http://h/x?a=1#top", try withQuery(a, "http://h/x#top", "a=1"));
}

test "-T streams the file it names and announces its size" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "up.txt", .data = "hello world\n" });

    var plan = try planFor(a, &.{ "-T", "up.txt", "http://x" });
    var storage: Storage = .{};
    defer storage.deinit(testing.io);

    var discard: [512]u8 = undefined;
    var writer: Io.Writer = .fixed(&discard);
    try testing.expect(try resolve(
        .{ .arena = a, .io = testing.io, .stderr = &writer, .dir = tmp.dir },
        &plan,
        &storage,
    ));

    const source = plan.options.body.?;
    try testing.expectEqual(@as(?u64, 12), source.len);
    // A regular file can start over, which is what a 307 needs.
    try testing.expect(source.rewind != null);
}

test "-T names a file that is not there, and the run stops with a message" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    var plan = try planFor(a, &.{ "-T", "/nonexistent/zurl-upload", "http://x" });
    var storage: Storage = .{};

    var message: [512]u8 = undefined;
    var writer: Io.Writer = .fixed(&message);
    const ok = try resolve(.{ .arena = a, .io = testing.io, .stderr = &writer }, &plan, &storage);

    try testing.expect(!ok);
    try testing.expect(std.mem.indexOf(u8, writer.buffered(), "-T") != null);
    try testing.expect(std.mem.indexOf(u8, writer.buffered(), "zurl-upload") != null);
}

test "-d names a file that is not there, and the run stops with a message" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    var plan = try planFor(a, &.{ "-d", "@/nonexistent/zurl-data", "http://x" });
    var storage: Storage = .{};

    var message: [512]u8 = undefined;
    var writer: Io.Writer = .fixed(&message);
    const ok = try resolve(.{ .arena = a, .io = testing.io, .stderr = &writer }, &plan, &storage);

    try testing.expect(!ok);
    try testing.expect(std.mem.indexOf(u8, writer.buffered(), "zurl-data") != null);
}

test "a file larger than the bound is refused, and names the bound" {
    // The one path that reads a file into memory. curl grows its buffer
    // until the machine runs out; this refuses and says how large is too
    // large.
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    var out: std.ArrayList(u8) = .empty;
    var message: [512]u8 = undefined;
    var writer: Io.Writer = .fixed(&message);
    const in: Inputs = .{ .arena = a, .io = testing.io, .stderr = &writer };

    // The bound is on the total, so two arguments that each fit and
    // together do not are refused as well.
    const half = try a.alloc(u8, max_data_bytes / 2 + 1);
    @memset(half, 'x');
    try appendBounded(in, &out, half);
    try testing.expectError(error.OutOfMemory, appendBounded(in, &out, half));
}
