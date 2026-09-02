//! Checks that `build.zig.zon` ships the directories the exported modules
//! are built from.
//!
//! **Why this exists.** zurl is imported by another project through
//! `build.zig.zon`. A directory that is left out of the `.paths` tuple is
//! not copied into the package a consumer fetches, so the consumer's build
//! fails on a file that is not there. Every test in this repository still
//! passes, because a test builds from the working tree where the file is.
//! Nothing but this tool reads the tuple.
//!
//! `build.zig` passes the first path component of the root source file of
//! every module it exports, plus the two build files. So a new module in a
//! new directory fails this check until its directory is in the tuple.
//!
//! Usage: `check-package <build.zig.zon> <required path>...`

const std = @import("std");
const Io = std.Io;

/// The largest `build.zig.zon` this tool reads. A manifest is a few
/// kilobytes, so this refuses a file that is not one.
const max_input_bytes: usize = 1024 * 1024;

/// The most entries the `.paths` tuple may hold. The scan stops here
/// rather than running on over a malformed file.
const paths_max: usize = 256;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;

    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 3) {
        printLine(io, "usage: {s} <build.zig.zon> <required path>...\n", .{if (args.len > 0) args[0] else "check-package"});
        return error.MissingArguments;
    }
    const manifest_path = args[1];
    const required = args[2..];
    const cwd: Io.Dir = .cwd();

    const text = try cwd.readFileAlloc(io, manifest_path, arena, .limited(max_input_bytes));
    const declared = try declaredPaths(arena, text);

    var missing: usize = 0;
    for (required) |want| {
        if (covers(declared, want)) continue;
        missing += 1;
        printLine(io, "check-package: '{s}' is not in the .paths of {s}\n", .{ want, manifest_path });
    }
    if (missing != 0) {
        printLine(io, "check-package: {d} path(s) missing, so a consumer of this package would not get them\n", .{missing});
        return error.PackagePathsIncomplete;
    }

    printLine(io, "check-package: {d} path(s) declared, {d} checked\n", .{ declared.len, required.len });
}

/// Prints one line to stdout, never to stderr.
///
/// The build runner surfaces anything a run step writes to stderr as
/// "failed command:" noise, even on success. A failure here also returns
/// an error, so the build still stops.
fn printLine(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
    Io.File.stdout().writeStreamingAll(io, msg) catch {};
}

/// What a manifest cannot say.
pub const Error = error{
    /// The manifest holds no `.paths` field. Zig then ships nothing, so
    /// every consumer gets an empty package.
    PathsNotFound,
    /// The `.paths` field is there and this tool cannot read it.
    PathsMalformed,
    /// The `.paths` tuple is empty. Zig then ships nothing.
    PathsEmpty,
} || std.mem.Allocator.Error;

/// Whether `declared` ships `want`.
///
/// An entry of `""` names the whole project directory, which ships
/// everything, so it covers every path.
pub fn covers(declared: []const []const u8, want: []const u8) bool {
    for (declared) |entry| {
        if (entry.len == 0) return true;
        if (std.mem.eql(u8, entry, want)) return true;
    }
    return false;
}

/// Reads the entries of the `.paths` tuple of `text`.
///
/// This is a scan and not a parse of the whole manifest. It finds the
/// `.paths` field, then reads the string literals of the tuple that
/// follows. A manifest shape it cannot read is an error, never an empty
/// answer: an empty answer would read as a manifest that ships nothing and
/// would fail every later check for the wrong reason.
pub fn declaredPaths(allocator: std.mem.Allocator, text: []const u8) Error![][]const u8 {
    const field = findField(text, ".paths") orelse return error.PathsNotFound;

    var at = skipSpace(text, field);
    if (at >= text.len or text[at] != '=') return error.PathsMalformed;
    at = skipSpace(text, at + 1);
    if (at + 1 >= text.len or text[at] != '.' or text[at + 1] != '{') return error.PathsMalformed;
    at += 2;

    var out: std.ArrayList([]const u8) = .empty;
    errdefer out.deinit(allocator);

    while (at < text.len) {
        at = skipSpace(text, at);
        if (at >= text.len) return error.PathsMalformed;
        switch (text[at]) {
            '}' => {
                if (out.items.len == 0) return error.PathsEmpty;
                return out.toOwnedSlice(allocator);
            },
            ',' => at += 1,
            '"' => {
                if (out.items.len >= paths_max) return error.PathsMalformed;
                const end = endOfString(text, at) orelse return error.PathsMalformed;
                try out.append(allocator, text[at + 1 .. end]);
                at = end + 1;
            },
            else => return error.PathsMalformed,
        }
    }
    return error.PathsMalformed;
}

/// The offset just past `name`, when `name` is a field of the manifest.
///
/// A field starts a line, so the byte in front of it must be a space, a
/// tab, or a newline. That keeps the scan off a `.paths` inside a comment
/// that runs on from code, and off one inside a longer name.
fn findField(text: []const u8, name: []const u8) ?usize {
    var at: usize = 0;
    while (std.mem.indexOfPos(u8, text, at, name)) |found| {
        at = found + name.len;
        if (found == 0) continue;
        switch (text[found - 1]) {
            ' ', '\t', '\n', '\r' => {},
            else => continue,
        }
        // The name must end here and not run on into a longer one.
        if (at < text.len) {
            switch (text[at]) {
                'a'...'z', 'A'...'Z', '0'...'9', '_' => continue,
                else => {},
            }
        }
        // A line comment before the field does not declare it.
        if (lineIsComment(text, found)) continue;
        return at;
    }
    return null;
}

/// Whether the line that holds `at` starts with `//`.
fn lineIsComment(text: []const u8, at: usize) bool {
    const start = if (std.mem.lastIndexOfScalar(u8, text[0..at], '\n')) |nl| nl + 1 else 0;
    const line = std.mem.trimStart(u8, text[start..at], " \t");
    return std.mem.startsWith(u8, line, "//");
}

/// The offset of the byte after the last space, tab, newline, or comment
/// line at or after `at`.
fn skipSpace(text: []const u8, at: usize) usize {
    var index = at;
    while (index < text.len) {
        switch (text[index]) {
            ' ', '\t', '\n', '\r' => index += 1,
            '/' => {
                if (index + 1 >= text.len or text[index + 1] != '/') return index;
                const nl = std.mem.indexOfScalarPos(u8, text, index, '\n') orelse return text.len;
                index = nl + 1;
            },
            else => return index,
        }
    }
    return index;
}

/// The offset of the closing quote of the string that starts at `at`.
fn endOfString(text: []const u8, at: usize) ?usize {
    var index = at + 1;
    while (index < text.len) : (index += 1) {
        if (text[index] == '\\') {
            index += 1;
            continue;
        }
        if (text[index] == '"') return index;
        if (text[index] == '\n') return null;
    }
    return null;
}

const testing = std.testing;

const good_manifest =
    \\.{
    \\    .name = .zurl,
    \\    .paths = .{
    \\        "build.zig",
    \\        "build.zig.zon",
    \\        "lib",
    \\        "src",
    \\        "tools",
    \\    },
    \\}
;

test "the declared paths are read in the order the manifest names them" {
    const paths = try declaredPaths(testing.allocator, good_manifest);
    defer testing.allocator.free(paths);

    try testing.expectEqual(@as(usize, 5), paths.len);
    try testing.expectEqualStrings("build.zig", paths[0]);
    try testing.expectEqualStrings("tools", paths[4]);
}

test "a path the manifest names is covered and one it leaves out is not" {
    const paths = try declaredPaths(testing.allocator, good_manifest);
    defer testing.allocator.free(paths);

    try testing.expect(covers(paths, "lib"));
    try testing.expect(covers(paths, "src"));
    // This is the failure the tool exists to catch: a module built from a
    // directory the package does not ship.
    try testing.expect(!covers(paths, "vendor"));
    try testing.expect(!covers(paths, "li"));
}

test "an empty entry ships everything and covers every path" {
    const manifest =
        \\.{ .paths = .{""} }
    ;
    const paths = try declaredPaths(testing.allocator, manifest);
    defer testing.allocator.free(paths);
    try testing.expect(covers(paths, "anything"));
}

test "a manifest with no paths, or an empty tuple, is an error and not an empty answer" {
    try testing.expectError(
        error.PathsNotFound,
        declaredPaths(testing.allocator, ".{ .name = .zurl }"),
    );
    try testing.expectError(
        error.PathsEmpty,
        declaredPaths(testing.allocator, ".{ .paths = .{} }"),
    );
    try testing.expectError(
        error.PathsMalformed,
        declaredPaths(testing.allocator, ".{ .paths = 3 }"),
    );
    try testing.expectError(
        error.PathsMalformed,
        declaredPaths(testing.allocator, ".{ .paths = .{ \"lib\" "),
    );
}

test "a paths field inside a comment does not count as the field" {
    const manifest =
        \\.{
        \\    // .paths = .{ "nothing" },
        \\    .paths = .{ "lib" },
        \\}
    ;
    const paths = try declaredPaths(testing.allocator, manifest);
    defer testing.allocator.free(paths);
    try testing.expectEqual(@as(usize, 1), paths.len);
    try testing.expectEqualStrings("lib", paths[0]);
}

test "a comment between the field and the tuple is stepped over" {
    const manifest =
        \\.{
        \\    .paths = .{
        \\        // the library
        \\        "lib",
        \\    },
        \\}
    ;
    const paths = try declaredPaths(testing.allocator, manifest);
    defer testing.allocator.free(paths);
    try testing.expectEqual(@as(usize, 1), paths.len);
    try testing.expectEqualStrings("lib", paths[0]);
}

test "this repository's own manifest ships every directory its modules use" {
    const paths = try declaredPaths(testing.allocator, @embedFile("zurl_manifest"));
    defer testing.allocator.free(paths);

    for ([_][]const u8{ "build.zig", "build.zig.zon", "lib", "src", "tools" }) |want| {
        try testing.expect(covers(paths, want));
    }
}
