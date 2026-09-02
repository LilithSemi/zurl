//! Checks that a vendored file differs from its upstream copy only where a
//! `ZURL PATCH` comment says that it does.
//!
//! The fork in `lib/zurl-tls/Client.zig` is a delta and not a rewrite. It
//! stays one only while every re-sync is mechanical: copy the new upstream file,
//! then put the marked lines back. A line that changed and carries no marker
//! breaks that, because the next person to re-sync has no way to tell the
//! patch from a change that somebody made and forgot to record.
//!
//! Usage:
//!
//!     check_vendor <upstream-path> <vendored-path>
//!
//! The status is 0 when a marker accounts for every changed line, and 1 when
//! one line changed and no marker accounts for it. The build resolves the
//! upstream path from the Zig that runs the build, so no path of a package
//! store is written down anywhere.
const std = @import("std");

/// The comment that marks a line as part of the patch.
const marker = "ZURL PATCH";

/// The comment that opens the one block a copy may append at its end.
///
/// Everything after it is new, so the lines in it need no marker of their
/// own. The line itself carries one, and `appendedBlock` accepts the block
/// only where it runs to the end of the file, so this text cannot let a
/// change into the middle of the copy.
const appended_marker = marker ++ ": everything below this line is not upstream";

/// The largest file this tool reads. The vendored client is about 90 kB, so
/// this is far above it and still refuses a path that names something else.
const max_file_bytes: usize = 4 * 1024 * 1024;

/// The largest table `changedHunks` builds, counted in cells.
///
/// The comparison is quadratic in the number of lines, so a large pair of
/// files would ask for memory that this tool must not take. Sixteen million
/// cells is 64 MB and holds two files of about 4000 lines each, which is more
/// than twice the size of the file this tool was written for.
const max_table_cells: usize = 16 * 1024 * 1024;

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();

    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 3) {
        std.debug.print("usage: check_vendor <upstream-path> <vendored-path>\n", .{});
        return 2;
    }
    const upstream_path = args[1];
    const vendored_path = args[2];

    const cwd: std.Io.Dir = .cwd();
    const upstream = cwd.readFileAlloc(io, upstream_path, gpa, .limited(max_file_bytes)) catch |err| {
        std.debug.print("check-vendor: cannot read the upstream file {s}: {t}\n", .{ upstream_path, err });
        return 2;
    };
    defer gpa.free(upstream);
    const vendored = cwd.readFileAlloc(io, vendored_path, gpa, .limited(max_file_bytes)) catch |err| {
        std.debug.print("check-vendor: cannot read the vendored file {s}: {t}\n", .{ vendored_path, err });
        return 2;
    };
    defer gpa.free(vendored);

    var upstream_lines = try splitLines(gpa, upstream);
    defer upstream_lines.deinit(gpa);
    var vendored_lines = try splitLines(gpa, vendored);
    defer vendored_lines.deinit(gpa);

    var hunks = changedHunks(gpa, upstream_lines.items, vendored_lines.items) catch |err| switch (err) {
        error.OutOfMemory => return err,
        error.FilesTooLarge => {
            std.debug.print(
                "check-vendor: {d} and {d} lines need a better comparison than this tool has\n",
                .{ upstream_lines.items.len, vendored_lines.items.len },
            );
            return 2;
        },
    };
    defer hunks.deinit(gpa);

    var unmarked: usize = 0;
    for (hunks.items) |hunk| {
        const fault = account(hunk, upstream_lines.items, vendored_lines.items) orelse continue;
        unmarked += 1;
        switch (fault) {
            .unmarked_line => |index| std.debug.print(
                "check-vendor: line {d} of {s} changed and carries no `{s}` comment:\n" ++
                    "    vendored: {s}\n",
                .{ index + 1, vendored_path, marker, vendored_lines.items[index] },
            ),
            .unmarked_removal => |counts| std.debug.print(
                "check-vendor: the hunk at line {d} of {s} drops {d} upstream lines and " ++
                    "puts back {d} marked ones\n",
                .{ hunk.new_start + 1, vendored_path, counts.removed, counts.marked },
            ),
        }
        report("upstream", upstream_lines.items[hunk.old_start..hunk.old_end]);
        report("vendored", vendored_lines.items[hunk.new_start..hunk.new_end]);
    }

    if (unmarked != 0) {
        std.debug.print(
            "check-vendor: {d} of {d} hunks hold a change that no `{s}` comment accounts for. " ++
                "Mark it or put the upstream text back.\n",
            .{ unmarked, hunks.items.len, marker },
        );
        return 1;
    }

    std.debug.print(
        "check-vendor: {s} differs from upstream in {d} hunks, and a marker accounts for every " ++
            "changed line.\n",
        .{ vendored_path, hunks.items.len },
    );
    return 0;
}

/// Prints one side of a hunk, and stops after a few lines so that a whole
/// rewritten file does not fill the terminal.
fn report(side: []const u8, lines: []const []const u8) void {
    const shown = @min(lines.len, 6);
    for (lines[0..shown]) |line| std.debug.print("    {s}: {s}\n", .{ side, line });
    if (lines.len > shown) {
        std.debug.print("    {s}: and {d} more lines\n", .{ side, lines.len - shown });
    }
}

/// What a hunk holds that no marker accounts for, if anything.
const Fault = union(enum) {
    /// The index into the vendored file of a changed line with no marker.
    unmarked_line: usize,
    /// The hunk drops more upstream lines than it puts marked ones back.
    unmarked_removal: struct { removed: usize, marked: usize },
};

/// Says what a hunk holds that no marker accounts for, and gives null for a
/// hunk that the patch accounts for line by line.
///
/// The rule is per line and not per hunk. A hunk is a run of lines that the
/// comparison could not match, so two edits with no shared line between them
/// are one hunk. A rule that accepted a hunk because one line in it carries a
/// marker would therefore accept any change written next to the patch, which
/// is the easiest place to put one.
///
/// Three things need no marker of their own:
///
/// * An empty line, which cannot carry a comment and cannot change what the
///   code does.
/// * A line of a comment whose run holds a marker. Zig has line comments and
///   no block comments, so such a line changes nothing that runs, and a
///   comment of several lines says one thing and carries the marker once.
/// * The one appended block at the end of the file, which `appendedBlock`
///   reads. Every line of it is new, so a marker on each would say nothing
///   that the block's first line does not say already.
///
/// The count of removed lines is what stops a marked line from covering the
/// removal of the line beside it. A comment put in place of an upstream check
/// removes a line and puts back no marked one, so it reports.
///
/// **Only a line that runs pays for a removal.** A comment line changes
/// nothing that runs, so it cannot stand in for an upstream line that ran. An
/// earlier rule counted every marked line, comments included, and one patch
/// carried nine marked comment lines against one removal. That slack paid for
/// nine more deletions: dropping the TLS 1.3 `legacy_session_id_echo` check
/// still gave exit 0. The count now reads only the lines that carry code.
fn account(hunk: Hunk, old: []const []const u8, new: []const []const u8) ?Fault {
    if (appendedBlock(hunk, old, new)) return null;

    const lines = new[hunk.new_start..hunk.new_end];
    var marked_lines: usize = 0;
    for (lines, 0..) |line, index| {
        if (comment(line)) {
            // A comment needs a marker of its own or a marked comment beside
            // it, and it pays for no removal either way.
            if (holdsMarker(line) or commentRunHoldsMarker(lines, index)) continue;
            return .{ .unmarked_line = hunk.new_start + index };
        }
        if (holdsMarker(line)) {
            marked_lines += 1;
            continue;
        }
        if (blank(line)) continue;
        return .{ .unmarked_line = hunk.new_start + index };
    }

    const removed = hunk.old_end - hunk.old_start;
    if (marked_lines < removed) {
        return .{ .unmarked_removal = .{ .removed = removed, .marked = marked_lines } };
    }
    return null;
}

/// True when the hunk is the one block that the copy appends at its end.
///
/// The block adds lines and touches no upstream line, it runs to the end of
/// the file, and its first line that holds text opens it with the marker
/// below. So a change anywhere above it is not part of it, and nothing can be
/// added to the file after it without a marker.
fn appendedBlock(hunk: Hunk, old: []const []const u8, new: []const []const u8) bool {
    if (hunk.old_start != old.len or hunk.old_end != old.len) return false;
    if (hunk.new_end != new.len) return false;

    for (new[hunk.new_start..hunk.new_end]) |line| {
        if (blank(line)) continue;
        return std.mem.indexOf(u8, line, appended_marker) != null;
    }
    return false;
}

/// True when the line carries the marker.
fn holdsMarker(line: []const u8) bool {
    return std.mem.indexOf(u8, line, marker) != null;
}

/// True when the line holds no text.
fn blank(line: []const u8) bool {
    return std.mem.trim(u8, line, " \t\r").len == 0;
}

/// True when the whole line is a comment. Zig has no block comment, so a line
/// that starts with two slashes changes nothing that runs.
fn comment(line: []const u8) bool {
    return std.mem.startsWith(u8, std.mem.trim(u8, line, " \t\r"), "//");
}

/// True when the run of comment lines that holds `index` carries the marker.
///
/// The run stops at the ends of the hunk, so only a comment line that changed
/// can account for another one. A comment that upstream already had is not in
/// the hunk and vouches for nothing.
fn commentRunHoldsMarker(lines: []const []const u8, index: usize) bool {
    var start = index;
    while (start > 0 and comment(lines[start - 1])) start -= 1;
    var end = index + 1;
    while (end < lines.len and comment(lines[end])) end += 1;

    for (lines[start..end]) |line| {
        if (holdsMarker(line)) return true;
    }
    return false;
}

/// Cuts a file into lines. A trailing newline does not make an empty last
/// line, because a file that ends with one and a file that does not are the
/// same text everywhere else.
fn splitLines(gpa: std.mem.Allocator, text: []const u8) !std.ArrayList([]const u8) {
    var lines: std.ArrayList([]const u8) = .empty;
    errdefer lines.deinit(gpa);

    var rest = text;
    if (rest.len != 0 and rest[rest.len - 1] == '\n') rest = rest[0 .. rest.len - 1];
    if (rest.len == 0) return lines;

    var it = std.mem.splitScalar(u8, rest, '\n');
    while (it.next()) |line| try lines.append(gpa, line);
    return lines;
}

/// One run of lines that the two files do not share.
///
/// A hunk holds the lines the upstream file has and the vendored one does
/// not, then the lines the vendored file has and the upstream one does not.
/// Either range can be empty, and both are never empty at once.
const Hunk = struct {
    old_start: usize,
    old_end: usize,
    new_start: usize,
    new_end: usize,
};

/// Finds every run of lines that the two files do not share.
///
/// The longest common subsequence is what decides which lines are shared. A
/// comparison that only walked both files together would call every line
/// after an inserted one a change, and each hunk would then need a marker it
/// has no reason to carry.
fn changedHunks(
    gpa: std.mem.Allocator,
    old: []const []const u8,
    new: []const []const u8,
) error{ OutOfMemory, FilesTooLarge }!std.ArrayList(Hunk) {
    const rows = old.len + 1;
    const columns = new.len + 1;
    if (rows > max_table_cells / columns) return error.FilesTooLarge;

    // `table[i * columns + j]` is the length of the longest common
    // subsequence of `old[i..]` and `new[j..]`. It is filled from the end, so
    // the walk below can start at the front and read each choice once.
    const table = try gpa.alloc(u32, rows * columns);
    defer gpa.free(table);
    @memset(table, 0);

    var i = old.len;
    while (i > 0) {
        i -= 1;
        var j = new.len;
        while (j > 0) {
            j -= 1;
            table[i * columns + j] = if (std.mem.eql(u8, old[i], new[j]))
                table[(i + 1) * columns + j + 1] + 1
            else
                @max(table[(i + 1) * columns + j], table[i * columns + j + 1]);
        }
    }

    var hunks: std.ArrayList(Hunk) = .empty;
    errdefer hunks.deinit(gpa);

    var old_index: usize = 0;
    var new_index: usize = 0;
    while (old_index < old.len or new_index < new.len) {
        if (old_index < old.len and new_index < new.len and
            std.mem.eql(u8, old[old_index], new[new_index]))
        {
            old_index += 1;
            new_index += 1;
            continue;
        }

        const old_start = old_index;
        const new_start = new_index;
        while (old_index < old.len or new_index < new.len) {
            if (old_index < old.len and new_index < new.len and
                std.mem.eql(u8, old[old_index], new[new_index])) break;

            if (new_index == new.len) {
                old_index += 1;
            } else if (old_index == old.len) {
                new_index += 1;
            } else if (table[(old_index + 1) * columns + new_index] >=
                table[old_index * columns + new_index + 1])
            {
                old_index += 1;
            } else {
                new_index += 1;
            }
        }

        try hunks.append(gpa, .{
            .old_start = old_start,
            .old_end = old_index,
            .new_start = new_start,
            .new_end = new_index,
        });
    }

    return hunks;
}

const testing = std.testing;

test "two files that are the same have no hunks" {
    const old = [_][]const u8{ "a", "b", "c" };
    var hunks = try changedHunks(testing.allocator, &old, &old);
    defer hunks.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), hunks.items.len);
}

test "an inserted block is one hunk and the lines after it stay shared" {
    // A comparison that walked both files together would call every line
    // after the insertion a change, so this is the fact that keeps a marker
    // needed only where somebody edited something.
    const old = [_][]const u8{ "a", "b", "c" };
    const new = [_][]const u8{ "a", "x", "y", "b", "c" };

    var hunks = try changedHunks(testing.allocator, &old, &new);
    defer hunks.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), hunks.items.len);
    const hunk = hunks.items[0];
    try testing.expectEqual(@as(usize, 1), hunk.old_start);
    try testing.expectEqual(@as(usize, 1), hunk.old_end);
    try testing.expectEqualStrings("x", new[hunk.new_start]);
    try testing.expectEqual(@as(usize, 3), hunk.new_end);
}

/// Compares two files the way `main` does and gives the first thing no marker
/// accounts for.
fn firstFault(old: []const []const u8, new: []const []const u8) !?Fault {
    var hunks = try changedHunks(testing.allocator, old, new);
    defer hunks.deinit(testing.allocator);

    for (hunks.items) |hunk| {
        if (account(hunk, old, new)) |fault| return fault;
    }
    return null;
}

test "a removed line is a hunk with no vendored line to hold a marker" {
    // A line that upstream has and the copy does not cannot carry a comment,
    // so it always reports. That is the answer this tool should give: a
    // deletion has to be written down in `UPSTREAM` instead.
    const old = [_][]const u8{ "a", "b", "c" };
    const new = [_][]const u8{ "a", "c" };

    const fault = (try firstFault(&old, &new)).?;
    try testing.expectEqual(@as(usize, 1), fault.unmarked_removal.removed);
    try testing.expectEqual(@as(usize, 0), fault.unmarked_removal.marked);
}

test "a change beside a marked line carries no marker of its own" {
    // The hole this tool had, and the reason the rule is per line. The two
    // changes below have no shared line between them, so they are one hunk.
    // A rule that asked whether the hunk held a marker anywhere accepted the
    // second change as well, and the easiest place to put a change is beside
    // the patch.
    const old = [_][]const u8{ "a", "} else {", "try verify();", "z" };
    const new = [_][]const u8{
        "a",
        "keep(); // ZURL PATCH",
        "} else { //",
        "verify() catch {};",
        "z",
    };

    const fault = (try firstFault(&old, &new)).?;
    try testing.expectEqual(@as(usize, 2), fault.unmarked_line);
    try testing.expectEqualStrings("} else { //", new[fault.unmarked_line]);
}

test "a comment of several lines carries the marker once" {
    const old = [_][]const u8{ "a", "z" };
    const new = [_][]const u8{
        "a",
        "// ZURL PATCH: what the line below keeps",
        "// and why it has to be kept here.",
        "keep(); // ZURL PATCH",
        "z",
    };

    try testing.expect(try firstFault(&old, &new) == null);
}

test "a comment that no marked comment stands beside reports" {
    // A comment changes nothing that runs, so it needs no marker of its own.
    // One that no marked comment stands beside is nobody's patch, so it is
    // drift and it reports.
    const old = [_][]const u8{ "a", "z" };
    const new = [_][]const u8{ "a", "// somebody's note", "z" };

    const fault = (try firstFault(&old, &new)).?;
    try testing.expectEqual(@as(usize, 1), fault.unmarked_line);
}

test "a marked line does not cover the removal of the line beside it" {
    // Zig has no block comment, so a comment cannot swallow the line under
    // it. Dropping the line is how that is done instead, and the count of
    // marked lines against removed ones is what reports it.
    const old = [_][]const u8{ "a", "keep();", "try verify();", "z" };
    const new = [_][]const u8{ "a", "keep(); // ZURL PATCH", "z" };

    const fault = (try firstFault(&old, &new)).?;
    try testing.expectEqual(@as(usize, 2), fault.unmarked_removal.removed);
    try testing.expectEqual(@as(usize, 1), fault.unmarked_removal.marked);
}

test "a marked comment does not pay for a removed upstream line" {
    // The hole the guard had. A patch that carries a paragraph of marked
    // comment used to bank one credit for each comment line, and the credits
    // paid for deletions somewhere else in the same hunk. Deleting the TLS
    // 1.3 `legacy_session_id_echo` check beside such a paragraph gave exit 0
    // and the message "a marker accounts for every changed line".
    //
    // A comment changes nothing that runs, so it can pay for nothing that
    // ran. Here the patch keeps one marked comment and one marked line of
    // code, and drops two upstream checks. One line of code cannot cover two
    // removals.
    const old = [_][]const u8{
        "a",
        "keep();",
        "try verifyOne();",
        "try verifyTwo();",
        "z",
    };
    const new = [_][]const u8{
        "a",
        "// ZURL PATCH: why the line below reads the way it does.",
        "// A second line of the same comment.",
        "keep(); // ZURL PATCH",
        "z",
    };

    const fault = (try firstFault(&old, &new)).?;
    try testing.expectEqual(@as(usize, 3), fault.unmarked_removal.removed);
    // Two comment lines carry the marker and neither one counts.
    try testing.expectEqual(@as(usize, 1), fault.unmarked_removal.marked);
}

test "the appended block needs no marker on each of its lines" {
    const old = [_][]const u8{ "a", "z" };
    const new = [_][]const u8{
        "a",
        "z",
        "",
        "// ZURL PATCH: everything below this line is not upstream.",
        "fn extra() void {}",
    };

    try testing.expect(try firstFault(&old, &new) == null);
}

test "a block appended with no opening marker reports" {
    const old = [_][]const u8{ "a", "z" };
    const new = [_][]const u8{ "a", "z", "fn extra() void {}" };

    const fault = (try firstFault(&old, &new)).?;
    try testing.expectEqual(@as(usize, 2), fault.unmarked_line);
}

test "the appended block accounts for nothing above itself" {
    // The block runs to the end of the file and touches no upstream line, so
    // a change in the middle of the copy is its own hunk and reports whether
    // or not the file ends with a marked block.
    const old = [_][]const u8{ "a", "middle", "z" };
    const new = [_][]const u8{
        "a",
        "changed",
        "z",
        "// ZURL PATCH: everything below this line is not upstream.",
        "fn extra() void {}",
    };

    const fault = (try firstFault(&old, &new)).?;
    try testing.expectEqual(@as(usize, 1), fault.unmarked_line);
}

test "two separate edits are two hunks" {
    const old = [_][]const u8{ "a", "b", "c", "d", "e" };
    const new = [_][]const u8{ "a", "B", "c", "d", "E" };

    var hunks = try changedHunks(testing.allocator, &old, &new);
    defer hunks.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), hunks.items.len);
}

test "splitLines gives the same lines whether or not the file ends with a newline" {
    var with = try splitLines(testing.allocator, "a\nb\n");
    defer with.deinit(testing.allocator);
    var without = try splitLines(testing.allocator, "a\nb");
    defer without.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 2), with.items.len);
    try testing.expectEqual(with.items.len, without.items.len);
    try testing.expectEqualStrings("b", with.items[1]);
}

test "changedHunks refuses a pair of files too large for its table" {
    const many = try testing.allocator.alloc([]const u8, 5000);
    defer testing.allocator.free(many);
    @memset(many, "line");
    try testing.expectError(error.FilesTooLarge, changedHunks(testing.allocator, many, many));
}
