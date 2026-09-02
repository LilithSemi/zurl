//! Turns what `-F` and `--form-string` said into the parts of a
//! `multipart/form-data` body.
//!
//! `src/cli/Args.zig` records each argument and opens nothing, because a
//! parse does no I/O. This file reads the syntax, opens every file a `@`
//! or a `<` named, and fills `zurl.multipart.Body`. `src/cli/body.zig`
//! calls it, beside the `-d` family it already handles.
//!
//! **The syntax is larger than it looks.** Every rule below was measured
//! against curl 8.21.0 with a loopback listener that captured the request
//! bytes, and the measurement sits beside the rule it produced.
//!
//! ```
//! -F 'n=value'              a literal value
//! -F 'n=@path'              the file, with a filename and a guessed type
//! -F 'n=<path'              the file's content, with no filename
//! -F 'n=@path;type=t/x'     the type, written out
//! -F 'n=@path;filename=o'   the filename, written out
//! -F 'n="va;lue"'           a quoted word, so the ; is data
//! --form-string 'n=@path'   the text @path itself, and no file is opened
//! ```
//!
//! **Three texts from here land in a MIME header**: the field name, the
//! file name, and the type. `zurl.multipart` escapes the first two and
//! refuses a bad third, so no CR and no LF from a command line can write a
//! header line of its own. This file adds nothing to that and takes
//! nothing away.

const std = @import("std");
const zurl = @import("zurl");
const Args = @import("Args.zig");
const body = @import("body.zig");
const safe = @import("safe.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const multipart = zurl.multipart;

/// What a file with no known extension is sent as, and what curl sends.
/// Measured: a file named `noext`, one named `x.unknownext`, and one named
/// `n.json` all went out as this.
pub const default_content_type = "application/octet-stream";

/// The extensions curl guesses a content type from, and nothing else.
///
/// **This table is curl's whole table, measured one row at a time.** Every
/// extension below went through `curl -F 'n=@file'` and came back with the
/// type beside it. `.json`, `.bin`, `.unknownext`, and a name with no dot
/// at all each came back as `application/octet-stream`, so the table is
/// closed and short on purpose. The match ignores case: `t.JPG` came back
/// as `image/jpeg`.
const content_types = [_]struct { ext: []const u8, type: []const u8 }{
    .{ .ext = "gif", .type = "image/gif" },
    .{ .ext = "jpg", .type = "image/jpeg" },
    .{ .ext = "jpeg", .type = "image/jpeg" },
    .{ .ext = "png", .type = "image/png" },
    .{ .ext = "svg", .type = "image/svg+xml" },
    .{ .ext = "txt", .type = "text/plain" },
    .{ .ext = "htm", .type = "text/html" },
    .{ .ext = "html", .type = "text/html" },
    .{ .ext = "pdf", .type = "application/pdf" },
    .{ .ext = "xml", .type = "application/xml" },
};

/// The parameter names this file reads. A `;` in front of one of these
/// ends the word before it, and a `;` in front of anything else does not.
/// See `readTypeWord`.
const parameter_names = [_][]const u8{ "filename", "type" };

/// Reads every `-F` and `--form-string`, opens what they name, and fills
/// `plan.options.body`.
///
/// Returns whether the run may continue. A refusal is written to
/// `in.stderr` and returns false, the shape `body.resolve` already uses.
///
/// `storage` must outlive every transfer of the run and must not move.
pub fn build(
    in: body.Inputs,
    plan: *Args.Plan,
    storage: *body.Storage,
) (Allocator.Error || Io.Writer.Error)!bool {
    const items = plan.request_body.form;
    if (items.len > multipart.max_parts) {
        try in.stderr.print(
            "zurl: -F: {d} parts is past the {d} part limit\n",
            .{ items.len, multipart.max_parts },
        );
        return false;
    }

    const parts = try in.arena.alloc(multipart.Part, items.len);
    var handles: std.ArrayList(Io.File) = .empty;
    // Every handle opened here is closed by `body.Storage.deinit`, whether
    // the build finished or a later part refused the run.
    errdefer storage.form_files = handles.items;

    // How many bytes this form holds in memory, over every literal value,
    // every `<file` read, and every `@-` read together. A file a `@`
    // named is streamed and counts nothing.
    var in_memory: usize = 0;

    for (items, parts) |item, *part| {
        const parsed = (try parse(in, item)) orelse {
            storage.form_files = handles.items;
            return false;
        };
        part.* = (try open(in, parsed, &handles, &in_memory)) orelse {
            storage.form_files = handles.items;
            return false;
        };
    }
    storage.form_files = handles.items;

    const escape: multipart.Escape = if (plan.request_body.form_escape) .backslash else .percent;
    storage.form.init(in.arena, in.io, parts, escape) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        error.EntropyUnavailable => {
            // The boundary must be one a peer cannot guess. A weaker
            // source is not an answer, so the run stops here. See
            // `zurl.multipart.drawBoundary`.
            try in.stderr.writeAll("zurl: -F: the system gave no entropy for a form boundary\n");
            return false;
        },
        error.BoundaryUnavailable => {
            try in.stderr.writeAll("zurl: -F: no form boundary is free of the content of a part\n");
            return false;
        },
        error.Canceled => {
            try in.stderr.writeAll("zurl: -F: the run was cancelled while a form boundary was drawn\n");
            return false;
        },
        error.TooManyParts => {
            try in.stderr.print(
                "zurl: -F: {d} parts is past the {d} part limit\n",
                .{ items.len, multipart.max_parts },
            );
            return false;
        },
        error.FieldNameTooLong => {
            try in.stderr.print(
                "zurl: -F: a field name is longer than the {d} byte limit\n",
                .{multipart.max_name_bytes},
            );
            return false;
        },
        error.FileNameTooLong => {
            try in.stderr.print(
                "zurl: -F: a file name is longer than the {d} byte limit\n",
                .{multipart.max_filename_bytes},
            );
            return false;
        },
        error.ContentTypeTooLong => {
            try in.stderr.print(
                "zurl: -F: a type is longer than the {d} byte limit\n",
                .{multipart.max_type_bytes},
            );
            return false;
        },
        error.ContentTypeMalformed => {
            try in.stderr.writeAll("zurl: -F: a type holds a byte that cannot go in a header\n");
            return false;
        },
    };

    plan.options.body = storage.form.source();
    return true;
}

/// One `-F` argument, read but not opened.
const Parsed = struct {
    /// The text in front of the first `=`.
    name: []const u8,
    source: Source,
    /// What `;filename=` named, or null when the argument named none.
    filename: ?[]const u8,
    /// What `;type=` named, or null when the argument named none.
    content_type: ?[]const u8,
};

/// Where one part's content comes from.
const Source = union(enum) {
    /// The value stands in the argument. `--form-string` always lands
    /// here, and so does a `-F` whose value starts with no `@` and no `<`.
    literal: []const u8,
    /// `@path`: upload the file. The part carries a file name and a type.
    upload: []const u8,
    /// `<path`: the file's content is the value. The part carries neither
    /// a file name nor a type unless the argument named one.
    contents: []const u8,
};

/// Reads one `-F` or `--form-string` argument.
///
/// Returns null when the argument is malformed, after writing the message.
fn parse(in: body.Inputs, item: Args.FormItem) (Allocator.Error || Io.Writer.Error)!?Parsed {
    const flag: []const u8 = if (item.kind == .form) "-F" else "--form-string";

    const equals = std.mem.indexOfScalar(u8, item.text, '=') orelse {
        // Measured: `curl -F 'name'` and `curl --form-string 'name'` both
        // exit 2 with `option -F: is badly used here`.
        try in.stderr.print(
            "zurl: {s}: '{f}' has no = between the field name and the value\n",
            .{ flag, safe.text(item.text) },
        );
        return null;
    };

    const name = item.text[0..equals];
    const rest = item.text[equals + 1 ..];

    // **`--form-string` reads nothing at all.** Measured:
    // `--form-string 'n=@a.txt'` sends the six characters `@a.txt`, and
    // `--form-string 'n=va;lue'` sends `va;lue`. That is the whole reason
    // the flag exists, so this returns before any of the syntax below.
    if (item.kind == .string) {
        return .{ .name = name, .source = .{ .literal = rest }, .filename = null, .content_type = null };
    }

    var at: usize = 0;
    const marker: u8 = if (rest.len == 0) 0 else rest[0];
    // A `@` or a `<` counts only as the first byte of the value. Measured:
    // `-F 'n=x@a.txt'` sends the literal `x@a.txt`.
    if (marker == '@' or marker == '<') at = 1;

    const word = try readWord(in.arena, rest, at);
    at = word.next;

    var parsed: Parsed = .{
        .name = name,
        .source = switch (marker) {
            '@' => .{ .upload = word.text },
            '<' => .{ .contents = word.text },
            else => .{ .literal = word.text },
        },
        .filename = null,
        .content_type = null,
    };

    while (at < rest.len) {
        // The word reader stops at a `;` or at the end, so anything left
        // starts with one.
        std.debug.assert(rest[at] == ';');
        at += 1;
        at = skipSpace(rest, at);

        const key_end = std.mem.indexOfScalarPos(u8, rest, at, '=') orelse {
            try in.stderr.print(
                "zurl: -F: the form parameter '{f}' has no value\n",
                .{safe.text(rest[at..])},
            );
            return null;
        };
        const key = rest[at..key_end];
        at = key_end + 1;

        if (std.ascii.eqlIgnoreCase(key, "filename")) {
            const value = try readWord(in.arena, rest, at);
            at = value.next;
            parsed.filename = value.text;
        } else if (std.ascii.eqlIgnoreCase(key, "type")) {
            const value = readTypeWord(rest, at);
            at = value.next;
            if (value.text.len == 0) {
                // curl sends a bare `Content-Type: ` line for this, which
                // no peer can read. zurl refuses instead. A user who meant
                // "no type" writes no `type=` at all.
                try in.stderr.writeAll("zurl: -F: the form parameter 'type' has an empty value\n");
                return null;
            }
            parsed.content_type = value.text;
        } else {
            // **curl drops a parameter it does not know, without a word.**
            // Measured: `-F 'n=@a.txt;bogus=1'` sent the part as if the
            // parameter were not there. A dropped `encoder=base64` or a
            // dropped `headers=` sends a body that is not the one the user
            // asked for, so zurl names it and stops.
            try in.stderr.print(
                "zurl: -F: '{f}' is not a form parameter this build reads\n",
                .{safe.text(key)},
            );
            return null;
        }
    }

    return parsed;
}

/// A word read out of a `-F` argument, and where the reader stopped.
const Word = struct {
    text: []const u8,
    /// The index of the `;` that ended the word, or the length of the
    /// argument.
    next: usize,
};

/// Reads one word of a `-F` argument, starting at `at`.
///
/// **A word ends at a `;` or at the end of the argument.** Measured:
/// `-F 'n=va;lue'` sent `va`, and `-F 'n=value ; type=text/plain'` sent
/// `value` with the space gone, so the trailing blanks come off.
///
/// **A word may be quoted.** Measured: `-F 'n="va;lue"'` sent `va;lue`,
/// `-F 'n="va\"lue"'` sent `va"lue`, and `-F 'n=@"a.txt"'` opened `a.txt`.
/// So a `"` at the front runs the word to the next unescaped `"`, and a
/// `\` inside a quoted word takes the byte behind it as data.
fn readWord(arena: Allocator, text: []const u8, at: usize) Allocator.Error!Word {
    if (at < text.len and text[at] == '"') {
        var out: std.ArrayList(u8) = .empty;
        var i = at + 1;
        while (i < text.len) : (i += 1) {
            if (text[i] == '\\' and i + 1 < text.len) {
                try out.append(arena, text[i + 1]);
                i += 1;
                continue;
            }
            if (text[i] == '"') {
                i += 1;
                break;
            }
            try out.append(arena, text[i]);
        }
        // Whatever stands between the closing quote and the next `;` is
        // not part of the word. A quoted word that runs to the end of the
        // argument ends there.
        const stop = std.mem.indexOfScalarPos(u8, text, i, ';') orelse text.len;
        return .{ .text = out.items, .next = stop };
    }

    const stop = std.mem.indexOfScalarPos(u8, text, at, ';') orelse text.len;
    var end = stop;
    while (end > at and (text[end - 1] == ' ' or text[end - 1] == '\t')) end -= 1;
    return .{ .text = text[at..end], .next = stop };
}

/// Reads the word of a `type=` parameter, starting at `at`.
///
/// **A media type may hold a `;` of its own, and curl keeps it.** Measured:
///
/// ```
/// ;type=text/plain;charset=UTF-8            text/plain;charset=UTF-8
/// ;type=text/plain;bogus=1                  text/plain;bogus=1
/// ;type=text/plain;filename=z.bin           text/plain, filename z.bin
/// ```
///
/// So the word runs past a `;` unless what follows it names a form
/// parameter. That is the rule, and `parameter_names` is the list it
/// reads.
///
/// The word is never quoted here, and never unescaped. A quote is one of
/// the bytes `zurl.multipart.checkContentType` refuses, so a type that
/// held one would be refused with a message rather than sent.
fn readTypeWord(text: []const u8, at: usize) Word {
    var stop = at;
    while (true) {
        const semi = std.mem.indexOfScalarPos(u8, text, stop, ';') orelse {
            stop = text.len;
            break;
        };
        const after = skipSpace(text, semi + 1);
        if (namesParameter(text[after..])) {
            stop = semi;
            break;
        }
        stop = semi + 1;
        if (stop >= text.len) {
            stop = text.len;
            break;
        }
    }

    var end = stop;
    while (end > at and (text[end - 1] == ' ' or text[end - 1] == '\t')) end -= 1;
    return .{ .text = text[at..end], .next = stop };
}

/// Whether `text` starts with a form parameter name and its `=`.
fn namesParameter(text: []const u8) bool {
    for (parameter_names) |name| {
        if (text.len > name.len and
            std.ascii.eqlIgnoreCase(text[0..name.len], name) and
            text[name.len] == '=') return true;
    }
    return false;
}

/// Returns the first index at or behind `at` that is neither a space nor a
/// tab.
fn skipSpace(text: []const u8, at: usize) usize {
    var i = at;
    while (i < text.len and (text[i] == ' ' or text[i] == '\t')) i += 1;
    return i;
}

/// Opens what one parsed argument named and returns the part it makes.
///
/// Returns null when the file could not be read, after writing the
/// message. `handles` collects every file this opens, so the caller closes
/// each one.
fn open(
    in: body.Inputs,
    parsed: Parsed,
    handles: *std.ArrayList(Io.File),
    in_memory: *usize,
) (Allocator.Error || Io.Writer.Error)!?multipart.Part {
    switch (parsed.source) {
        .literal => |value| {
            if (!try chargeMemory(in, in_memory, value.len)) return null;
            return .{
                .name = parsed.name,
                .filename = parsed.filename,
                .content_type = parsed.content_type,
                .content = .{ .memory = value },
            };
        },
        // `<path` reads the file and sends its content as the value.
        // Measured: the part carries no `filename` and no `Content-Type`
        // unless the argument named one. The whole file goes in memory,
        // because the value has no framing of its own to stream into, so
        // the read is bounded.
        .contents => |path| {
            const text = (try readWhole(in, path, in_memory)) orelse return null;
            return .{
                .name = parsed.name,
                .filename = parsed.filename,
                .content_type = parsed.content_type,
                .content = .{ .memory = text },
            };
        },
        .upload => |path| {
            // **Standard input has no length to `stat`.** curl reads it
            // whole and frames the request with a `content-length`,
            // measured over a 200 KB pipe. zurl reads it whole too, and
            // bounds the read where curl does not. The part carries the
            // file name `-` and no type at all, both measured.
            if (std.mem.eql(u8, path, "-")) {
                const text = (try readWhole(in, path, in_memory)) orelse return null;
                return .{
                    .name = parsed.name,
                    .filename = parsed.filename orelse "-",
                    .content_type = parsed.content_type,
                    .content = .{ .memory = text },
                };
            }

            // **A comma in a path is a file list to curl, and this build
            // sends no list.** Measured: `-F 'n=@a.txt,b.txt'` builds a
            // nested `multipart/mixed` part, and `-F 'n=@we,ird.txt'`
            // fails with exit 26 because curl reads it as two files. A
            // path with a comma in it is refused here rather than opened
            // under a name the user did not write.
            if (std.mem.indexOfScalar(u8, path, ',') != null) {
                try in.stderr.print(
                    "zurl: -F: '{f}' holds a comma, and this build sends no file list\n",
                    .{safe.text(path)},
                );
                return null;
            }

            // The room for the handle comes first, so there is no window
            // where a file is open and no list holds it. A handle that
            // reached neither the list nor a `close` would stay open for
            // the whole run.
            try handles.ensureUnusedCapacity(in.arena, 1);
            const handle = in.dir.openFile(in.io, path, .{}) catch {
                try in.stderr.print("zurl: -F: cannot read '{f}'\n", .{safe.text(path)});
                return null;
            };
            handles.appendAssumeCapacity(handle);

            const info = handle.stat(in.io) catch {
                try in.stderr.print("zurl: -F: cannot measure '{f}'\n", .{safe.text(path)});
                return null;
            };
            if (info.kind != .file) {
                // A pipe or a device has no length, and the request
                // announces one. Reading it whole to find the length is
                // the unbounded read this file avoids, so it is refused
                // and `@-` is named as the way to send standard input.
                try in.stderr.print(
                    "zurl: -F: '{f}' is not a regular file, so it has no length to send. Use @- for standard input\n",
                    .{safe.text(path)},
                );
                return null;
            }

            // **The file name is the last segment, and never the path.**
            // Measured: `curl -F 'n=@/etc/hostname'` sent
            // `filename="hostname"`. A `;filename=` written out is used as
            // it stands, path and all: measured,
            // `;filename=/etc/passwd` sent that whole text.
            const filename = parsed.filename orelse std.fs.path.basename(path);
            return .{
                .name = parsed.name,
                .filename = filename,
                .content_type = parsed.content_type orelse guessContentType(path),
                .content = .{ .file = .{ .handle = handle, .len = info.size } },
            };
        },
    }
}

/// Reads the whole of `path`, or of standard input for `-`, into the
/// arena, and charges it against the bound.
///
/// Returns null when the read failed or the bound was passed, after
/// writing the message.
fn readWhole(
    in: body.Inputs,
    path: []const u8,
    in_memory: *usize,
) (Allocator.Error || Io.Writer.Error)!?[]const u8 {
    const left = body.max_data_bytes - in_memory.*;

    const text = if (std.mem.eql(u8, path, "-")) text: {
        var buffer: [4096]u8 = undefined;
        var stdin: Io.File.Reader = .init(.stdin(), in.io, &buffer);
        break :text stdin.interface.allocRemaining(in.arena, .limited(left)) catch |err| switch (err) {
            error.OutOfMemory => |e| return e,
            error.StreamTooLong => {
                try in.stderr.print(
                    "zurl: -F: standard input is larger than the {d} byte limit\n",
                    .{body.max_data_bytes},
                );
                return null;
            },
            else => {
                try in.stderr.writeAll("zurl: -F: cannot read standard input\n");
                return null;
            },
        };
    } else in.dir.readFileAlloc(in.io, path, in.arena, .limited(left)) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        error.StreamTooLong => {
            try in.stderr.print(
                "zurl: -F: '{f}' is larger than the {d} byte limit\n",
                .{ safe.text(path), body.max_data_bytes },
            );
            return null;
        },
        else => {
            try in.stderr.print("zurl: -F: cannot read '{f}'\n", .{safe.text(path)});
            return null;
        },
    };

    in_memory.* += text.len;
    return text;
}

/// Counts `len` more bytes against the bound on what a form holds in
/// memory, and returns whether the run may continue.
fn chargeMemory(
    in: body.Inputs,
    in_memory: *usize,
    len: usize,
) Io.Writer.Error!bool {
    if (len > body.max_data_bytes - in_memory.*) {
        try in.stderr.print(
            "zurl: -F: the form holds more than the {d} byte limit in memory\n",
            .{body.max_data_bytes},
        );
        return false;
    }
    in_memory.* += len;
    return true;
}

/// Returns the content type curl guesses for `path`.
///
/// The extension decides, the match ignores case, and everything the table
/// does not name is `application/octet-stream`. See `content_types`.
pub fn guessContentType(path: []const u8) []const u8 {
    const base = std.fs.path.basename(path);
    const dot = std.mem.lastIndexOfScalar(u8, base, '.') orelse return default_content_type;
    const ext = base[dot + 1 ..];
    for (content_types) |row| {
        if (std.ascii.eqlIgnoreCase(ext, row.ext)) return row.type;
    }
    return default_content_type;
}

const testing = std.testing;

/// Drives `parse` with one argument, and returns what it read.
fn testParse(arena: Allocator, kind: Args.FormKind, text: []const u8) !?Parsed {
    var discard: [512]u8 = undefined;
    var writer: Io.Writer = .fixed(&discard);
    return parse(.{
        .arena = arena,
        .io = testing.io,
        .stderr = &writer,
    }, .{ .kind = kind, .text = text });
}

test "a plain part, a file part and a contents part read the three sources apart" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const plain = (try testParse(a, .form, "name=value")).?;
    try testing.expectEqualStrings("name", plain.name);
    try testing.expectEqualStrings("value", plain.source.literal);

    const file = (try testParse(a, .form, "name=@a.txt")).?;
    try testing.expectEqualStrings("a.txt", file.source.upload);

    const contents = (try testParse(a, .form, "name=<a.txt")).?;
    try testing.expectEqualStrings("a.txt", contents.source.contents);

    // Measured: `-F 'n=x@a.txt'` sends the literal text. The marker counts
    // only as the first byte of the value.
    const mid = (try testParse(a, .form, "name=x@a.txt")).?;
    try testing.expectEqualStrings("x@a.txt", mid.source.literal);

    // Measured: only the first `=` divides the name from the value.
    const two = (try testParse(a, .form, "name=a=b")).?;
    try testing.expectEqualStrings("name", two.name);
    try testing.expectEqualStrings("a=b", two.source.literal);
}

test "--form-string reads no marker and no parameter" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // All three measured against curl 8.21.0.
    const at = (try testParse(a, .string, "name=@a.txt")).?;
    try testing.expectEqualStrings("@a.txt", at.source.literal);

    const semi = (try testParse(a, .string, "name=va;lue")).?;
    try testing.expectEqualStrings("va;lue", semi.source.literal);
    try testing.expectEqual(@as(?[]const u8, null), semi.content_type);

    const quote = (try testParse(a, .string, "name=va\"lue")).?;
    try testing.expectEqualStrings("va\"lue", quote.source.literal);

    const newline = (try testParse(a, .string, "name=a\nb")).?;
    try testing.expectEqualStrings("a\nb", newline.source.literal);
}

test "a semicolon ends a value, and a quoted value keeps it" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Measured: `-F 'name=va;lue'` sent `va` and nothing else, because the
    // `;` starts a parameter. zurl cuts the value at the same place.
    const cut = (try testParse(a, .form, "name=va;type=text/plain")).?;
    try testing.expectEqualStrings("va", cut.source.literal);
    try testing.expectEqualStrings("text/plain", cut.content_type.?);

    // curl drops `lue` here without a word. zurl refuses, because a
    // parameter with no value is a typo and a dropped one sends a body the
    // user did not ask for.
    try testing.expectEqual(@as(?Parsed, null), try testParse(a, .form, "name=va;lue"));

    const quoted = (try testParse(a, .form, "name=\"va;lue\"")).?;
    try testing.expectEqualStrings("va;lue", quoted.source.literal);

    const escaped = (try testParse(a, .form, "name=\"va\\\"lue\"")).?;
    try testing.expectEqualStrings("va\"lue", escaped.source.literal);

    const quoted_path = (try testParse(a, .form, "name=@\"a.txt\"")).?;
    try testing.expectEqualStrings("a.txt", quoted_path.source.upload);

    // Measured: the blanks in front of a `;` come off the word.
    const trimmed = (try testParse(a, .form, "name=value  ;  type=text/plain")).?;
    try testing.expectEqualStrings("value", trimmed.source.literal);
    try testing.expectEqualStrings("text/plain", trimmed.content_type.?);
}

test "a type parameter keeps its own semicolon and stops at a form parameter" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // All three rows measured against curl 8.21.0.
    const charset = (try testParse(a, .form, "n=@a.txt;type=text/plain;charset=UTF-8")).?;
    try testing.expectEqualStrings("text/plain;charset=UTF-8", charset.content_type.?);

    const with_filename = (try testParse(a, .form, "n=@a.txt;type=text/plain;filename=z.bin")).?;
    try testing.expectEqualStrings("text/plain", with_filename.content_type.?);
    try testing.expectEqualStrings("z.bin", with_filename.filename.?);

    const both = (try testParse(a, .form, "n=@a.txt;type=text/plain;charset=UTF-8;filename=z.bin")).?;
    try testing.expectEqualStrings("text/plain;charset=UTF-8", both.content_type.?);
    try testing.expectEqualStrings("z.bin", both.filename.?);

    // The order of the two parameters does not matter, measured.
    const reversed = (try testParse(a, .form, "n=@a.txt;filename=z.bin;type=text/plain")).?;
    try testing.expectEqualStrings("text/plain", reversed.content_type.?);
    try testing.expectEqualStrings("z.bin", reversed.filename.?);

    // The parameter name ignores case, measured with `TYPE=`.
    const upper = (try testParse(a, .form, "n=@a.txt;TYPE=text/plain")).?;
    try testing.expectEqualStrings("text/plain", upper.content_type.?);
}

test "an argument with no equals, an unknown parameter and an empty type are refused" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Measured: `curl -F 'name'` exits 2.
    try testing.expectEqual(@as(?Parsed, null), try testParse(a, .form, "name"));
    try testing.expectEqual(@as(?Parsed, null), try testParse(a, .form, ""));
    try testing.expectEqual(@as(?Parsed, null), try testParse(a, .string, "name"));

    // curl drops these two without a word. zurl names them, because a
    // dropped `encoder` sends a body the user did not ask for.
    try testing.expectEqual(@as(?Parsed, null), try testParse(a, .form, "n=@a.txt;bogus=1"));
    try testing.expectEqual(@as(?Parsed, null), try testParse(a, .form, "n=@a.txt;encoder=base64"));
    try testing.expectEqual(@as(?Parsed, null), try testParse(a, .form, "n=@a.txt;headers=X: 1"));
    try testing.expectEqual(@as(?Parsed, null), try testParse(a, .form, "n=@a.txt;filename"));
    try testing.expectEqual(@as(?Parsed, null), try testParse(a, .form, "n=@a.txt;type="));
}

test "the content type table is curl's, row for row" {
    // Every row was measured with `curl -F 'n=@file'` over a file of that
    // name. The four at the end came back as the default.
    try testing.expectEqualStrings("image/gif", guessContentType("t.gif"));
    try testing.expectEqualStrings("image/jpeg", guessContentType("t.jpg"));
    try testing.expectEqualStrings("image/jpeg", guessContentType("t.jpeg"));
    try testing.expectEqualStrings("image/png", guessContentType("t.png"));
    try testing.expectEqualStrings("image/svg+xml", guessContentType("t.svg"));
    try testing.expectEqualStrings("text/plain", guessContentType("t.txt"));
    try testing.expectEqualStrings("text/html", guessContentType("t.htm"));
    try testing.expectEqualStrings("text/html", guessContentType("t.html"));
    try testing.expectEqualStrings("application/pdf", guessContentType("t.pdf"));
    try testing.expectEqualStrings("application/xml", guessContentType("t.xml"));

    // Measured: `.JPG` came back as `image/jpeg`, so the match ignores
    // case.
    try testing.expectEqualStrings("image/jpeg", guessContentType("t.JPG"));
    try testing.expectEqualStrings("text/plain", guessContentType("/a/b/t.TXT"));

    // Measured: each of these came back as the default.
    try testing.expectEqualStrings(default_content_type, guessContentType("n.json"));
    try testing.expectEqualStrings(default_content_type, guessContentType("x.unknownext"));
    try testing.expectEqualStrings(default_content_type, guessContentType("noext"));
    try testing.expectEqualStrings(default_content_type, guessContentType("/etc/hostname"));
}

/// Runs `build` over one command line, in `dir`, and returns the body
/// bytes it would send. The caller frees them.
fn testBuild(
    arena: Allocator,
    dir: Io.Dir,
    argv: []const []const u8,
    storage: *body.Storage,
    message: *[]const u8,
) !?[]u8 {
    var buffer: [1024]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);

    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();
    var plan = try Args.parse(arena, argv, &env, null);

    const in: body.Inputs = .{ .arena = arena, .io = testing.io, .stderr = &writer, .dir = dir };
    const ok = try build(in, &plan, storage);
    message.* = try arena.dupe(u8, writer.buffered());
    if (!ok) return null;

    const source = plan.options.body.?;
    var out: std.ArrayList(u8) = .empty;
    var piece: [512]u8 = undefined;
    while (true) {
        const n = source.read(source.ctx, &piece, piece.len);
        try testing.expect(n >= 0);
        if (n == 0) break;
        try out.appendSlice(arena, piece[0..@intCast(n)]);
    }
    return out.items;
}

test "a file part carries the last path segment and the guessed type" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "a.txt", .data = "hello\nworld\n" });

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var storage: body.Storage = .{};
    defer storage.deinit(testing.io);
    var message: []const u8 = "";
    const bytes = (try testBuild(
        arena.allocator(),
        tmp.dir,
        &.{ "-F", "name=@a.txt", "http://x" },
        &storage,
        &message,
    )).?;

    const boundary = storage.form.boundaryText();
    const want = try std.fmt.allocPrint(
        arena.allocator(),
        "--{s}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"a.txt\"\r\n" ++
            "Content-Type: text/plain\r\n\r\nhello\nworld\n\r\n--{s}--\r\n",
        .{ boundary, boundary },
    );
    try testing.expectEqualStrings(want, bytes);
}

test "a contents part sends the file with no filename and no type" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "a.txt", .data = "hello\nworld\n" });

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var storage: body.Storage = .{};
    defer storage.deinit(testing.io);
    var message: []const u8 = "";
    const bytes = (try testBuild(
        arena.allocator(),
        tmp.dir,
        &.{ "-F", "name=<a.txt", "http://x" },
        &storage,
        &message,
    )).?;

    const boundary = storage.form.boundaryText();
    const want = try std.fmt.allocPrint(
        arena.allocator(),
        "--{s}\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\n" ++
            "hello\nworld\n\r\n--{s}--\r\n",
        .{ boundary, boundary },
    );
    try testing.expectEqualStrings(want, bytes);
}

test "two -F arguments build two parts, in the order they were written" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "a.txt", .data = "hello\nworld\n" });
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "b.txt", .data = "BBB\n" });

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var storage: body.Storage = .{};
    defer storage.deinit(testing.io);
    var message: []const u8 = "";
    const bytes = (try testBuild(
        arena.allocator(),
        tmp.dir,
        &.{ "-F", "x=@a.txt", "-F", "y=@b.txt", "http://x" },
        &storage,
        &message,
    )).?;

    const boundary = storage.form.boundaryText();
    const want = try std.fmt.allocPrint(
        arena.allocator(),
        "--{s}\r\nContent-Disposition: form-data; name=\"x\"; filename=\"a.txt\"\r\n" ++
            "Content-Type: text/plain\r\n\r\nhello\nworld\n\r\n" ++
            "--{s}\r\nContent-Disposition: form-data; name=\"y\"; filename=\"b.txt\"\r\n" ++
            "Content-Type: text/plain\r\n\r\nBBB\n\r\n" ++
            "--{s}--\r\n",
        .{ boundary, boundary, boundary },
    );
    try testing.expectEqualStrings(want, bytes);
}

test "a field name with a newline in it writes no header line of its own" {
    // **The injection proof, through the command line.** `zurl.multipart`
    // proves it for every byte; this proves the CLI reaches that code and
    // adds nothing that undoes it.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var storage: body.Storage = .{};
    defer storage.deinit(testing.io);
    var message: []const u8 = "";
    const bytes = (try testBuild(
        arena.allocator(),
        tmp.dir,
        &.{ "-F", "a\r\nX-Evil: 1\r\n\r\nb=value", "http://x" },
        &storage,
        &message,
    )).?;

    try testing.expect(std.mem.indexOf(u8, bytes, "X-Evil") != null);
    // The text is there, and it is inside the quoted name, percent
    // encoded. No header line was forged.
    try testing.expect(std.mem.indexOf(u8, bytes, "\r\nX-Evil") == null);
    try testing.expect(std.mem.indexOf(u8, bytes, "name=\"a%0D%0AX-Evil: 1%0D%0A%0D%0Ab\"") != null);
}

test "a file name with a newline in it writes no header line of its own" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "a.txt", .data = "x" });

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var storage: body.Storage = .{};
    defer storage.deinit(testing.io);
    var message: []const u8 = "";
    const bytes = (try testBuild(
        arena.allocator(),
        tmp.dir,
        &.{ "-F", "n=@a.txt;filename=\"o\r\nX-Evil: 1\"", "http://x" },
        &storage,
        &message,
    )).?;

    try testing.expect(std.mem.indexOf(u8, bytes, "\r\nX-Evil") == null);
    try testing.expect(std.mem.indexOf(u8, bytes, "filename=\"o%0D%0AX-Evil: 1\"") != null);
}

test "--form-escape changes the quote and leaves a newline encoded" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var storage: body.Storage = .{};
    defer storage.deinit(testing.io);
    var message: []const u8 = "";
    const bytes = (try testBuild(
        arena.allocator(),
        tmp.dir,
        &.{ "--form-escape", "-F", "a\"b\r\nc=value", "http://x" },
        &storage,
        &message,
    )).?;

    // Measured: curl with `--form-escape` writes `\"` for a quote. It
    // writes a CR and an LF unchanged, which forges a header line, so zurl
    // keeps those two percent encoded.
    try testing.expect(std.mem.indexOf(u8, bytes, "name=\"a\\\"b%0D%0Ac\"") != null);
    try testing.expect(std.mem.indexOf(u8, bytes, "\r\nc=") == null);
}

test "a comma in a path, a missing file and a directory are each refused by name" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(testing.io, "sub");

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var message: []const u8 = "";
    var one: body.Storage = .{};
    defer one.deinit(testing.io);
    try testing.expectEqual(
        @as(?[]u8, null),
        try testBuild(a, tmp.dir, &.{ "-F", "n=@a.txt,b.txt", "http://x" }, &one, &message),
    );
    try testing.expect(std.mem.indexOf(u8, message, "holds a comma") != null);

    var two: body.Storage = .{};
    defer two.deinit(testing.io);
    try testing.expectEqual(
        @as(?[]u8, null),
        try testBuild(a, tmp.dir, &.{ "-F", "n=@nosuch.txt", "http://x" }, &two, &message),
    );
    try testing.expect(std.mem.indexOf(u8, message, "cannot read 'nosuch.txt'") != null);

    var three: body.Storage = .{};
    defer three.deinit(testing.io);
    try testing.expectEqual(
        @as(?[]u8, null),
        try testBuild(a, tmp.dir, &.{ "-F", "n=@sub", "http://x" }, &three, &message),
    );
    // A directory has no length to announce. The message names `@-` as
    // the way to send something with no length.
    try testing.expect(std.mem.indexOf(u8, message, "sub") != null);
}

test "a form larger than the memory bound is refused before it is sent" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // One literal past the bound. The value is built here rather than read
    // from a file, so the test costs one allocation and no disk.
    const huge = try a.alloc(u8, body.max_data_bytes + 1);
    @memset(huge, 'v');
    const argument = try std.fmt.allocPrint(a, "n={s}", .{huge});

    var storage: body.Storage = .{};
    defer storage.deinit(testing.io);
    var message: []const u8 = "";
    try testing.expectEqual(
        @as(?[]u8, null),
        try testBuild(a, tmp.dir, &.{ "-F", argument, "http://x" }, &storage, &message),
    );
    try testing.expect(std.mem.indexOf(u8, message, "byte limit in memory") != null);
}

test "a form past the part limit is refused, and one at the limit is not" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var argv: std.ArrayList([]const u8) = .empty;
    for (0..multipart.max_parts) |i| {
        try argv.append(a, "-F");
        try argv.append(a, try std.fmt.allocPrint(a, "n{d}=v", .{i}));
    }
    try argv.append(a, "http://x");

    var at_limit: body.Storage = .{};
    defer at_limit.deinit(testing.io);
    var message: []const u8 = "";
    try testing.expect(try testBuild(a, tmp.dir, argv.items, &at_limit, &message) != null);

    // One more than the limit, and the whole run stops.
    var over = try a.alloc([]const u8, argv.items.len + 2);
    @memcpy(over[0 .. argv.items.len - 1], argv.items[0 .. argv.items.len - 1]);
    over[argv.items.len - 1] = "-F";
    over[argv.items.len] = "extra=v";
    over[argv.items.len + 1] = "http://x";

    var past: body.Storage = .{};
    defer past.deinit(testing.io);
    try testing.expectEqual(
        @as(?[]u8, null),
        try testBuild(a, tmp.dir, over, &past, &message),
    );
    try testing.expect(std.mem.indexOf(u8, message, "part limit") != null);
}
