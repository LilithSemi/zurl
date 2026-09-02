//! The HPACK dynamic table, RFC 7541 section 2.3.2 and section 4.
//!
//! A first in, last out list of header fields that a peer builds as it
//! sends, and that this side rebuilds as it reads. This file owns the
//! list, the copies of the names and values in it, the size accounting of
//! RFC 7541 section 4.1, and the eviction of section 4.4. It owns nothing
//! above that: it does not parse a header block, and it does not know that
//! index 62 of the wire is index 1 of this table.
//!
//! **Every entry here came from a peer.** So the table has a ceiling that
//! the peer cannot raise. `capacity` is what the peer asked for, and
//! `capacity_max` is what this side agreed to in its own SETTINGS. A size
//! update above `capacity_max` is a fault, not a larger table.
//!
//! Entry 1 is the newest, which is what the RFC's own index numbering
//! says. **The storage runs the other way round.** `entries` holds the
//! live entries oldest first, at `entries.items[first..]`, so an add is an
//! append and an eviction moves `first` forward. Both cost the same
//! whatever the table holds, and `get` is still one subtraction.
//!
//! An insert at index 0 would read the same and cost O(count) for each
//! add. At the shipped settings a peer may send 9600 fields in one header
//! block against a table holding 128 entries, which was about 38 MB of
//! copying for 28800 octets on the wire, once for every response of a
//! connection that stays open. The peer picks both factors inside their
//! own caps, so the amplification is the peer's to choose.
//!
//! `compact` is what keeps the append constant on average: it moves the
//! live entries down only after the evicted prefix has grown as long as
//! the live run, so its cost is spread over that many adds. The list never
//! holds more than twice the live entries.

const std = @import("std");

const field = @import("field.zig");

const Allocator = std.mem.Allocator;
const DynamicTable = @This();

/// The bytes RFC 7541 adds to a name and a value to size one entry.
pub const entry_overhead = field.entry_overhead;

/// The table size HTTP/2 assumes before either peer says otherwise, from
/// the SETTINGS_HEADER_TABLE_SIZE default of RFC 9113 section 6.5.2.
pub const capacity_default: usize = 4096;

/// The largest `capacity_max` this build will take.
///
/// A caller sets its own ceiling in `Options`, and this bounds that
/// choice, so no caller can ask for a table larger than this however it
/// was configured. At the smallest entry of 32 bytes this is 2048 entries.
pub const capacity_max_limit: usize = 64 * 1024;

pub const Error = error{
    /// A dynamic table size update named a size above `capacity_max`. RFC
    /// 7541 section 6.3 says a decoder must treat that as a fault.
    TableSizeTooLarge,
    OutOfMemory,
};

/// One entry, with its own copies of the name and the value.
pub const Entry = struct {
    name: []u8,
    value: []u8,

    /// The size of this entry under RFC 7541 section 4.1.
    pub fn size(self: Entry) usize {
        return self.name.len + self.value.len + entry_overhead;
    }
};

pub const Options = struct {
    /// The largest size this side will let the peer set, which is what
    /// this side sent as SETTINGS_HEADER_TABLE_SIZE.
    capacity_max: usize = capacity_default,
};

/// The live entries, oldest first, at `entries.items[first..]`. Everything
/// before `first` was evicted and freed.
entries: std.ArrayList(Entry) = .empty,
/// Where the live entries start. See `compact` for what keeps this from
/// growing without end.
first: usize = 0,
size: usize = 0,
capacity: usize,
capacity_max: usize,

/// A table that starts at its ceiling, which is where HTTP/2 starts.
pub fn init(options: Options) DynamicTable {
    std.debug.assert(options.capacity_max <= capacity_max_limit);
    return .{ .capacity = options.capacity_max, .capacity_max = options.capacity_max };
}

pub fn deinit(self: *DynamicTable, gpa: Allocator) void {
    // Only the live entries own memory. An entry before `first` was freed
    // when it was evicted.
    for (self.entries.items[self.first..]) |entry| {
        gpa.free(entry.name);
        gpa.free(entry.value);
    }
    self.entries.deinit(gpa);
    self.* = undefined;
}

/// How many entries the table holds.
pub fn count(self: DynamicTable) u32 {
    return @intCast(self.entries.items.len - self.first);
}

/// The entry at `index`, or null when `index` names none.
///
/// `index` counts from 1 at the newest entry, which is the order RFC 7541
/// section 2.3.3 gives the dynamic table inside the shared index space.
/// The storage runs oldest first, so index 1 is the last item.
pub fn get(self: DynamicTable, index: u32) ?Entry {
    if (index == 0 or index > self.count()) return null;
    return self.entries.items[self.entries.items.len - index];
}

/// Takes the size the peer asked for, RFC 7541 section 6.3.
///
/// A size below what the table holds evicts until it fits, which is the
/// one place a size update drops an entry.
pub fn setCapacity(self: *DynamicTable, gpa: Allocator, capacity: usize) Error!void {
    if (capacity > self.capacity_max) return error.TableSizeTooLarge;
    self.capacity = capacity;
    self.evictTo(gpa, capacity);
}

/// Copies `name` and `value` into a new entry, and evicts the oldest
/// entries until the table fits.
///
/// RFC 7541 section 4.4: an entry larger than the whole capacity empties
/// the table and is not added. That is not a fault. The peer is allowed to
/// send such a field, and both sides then agree the table is empty.
pub fn add(self: *DynamicTable, gpa: Allocator, name: []const u8, value: []const u8) Error!void {
    const wanted = name.len + value.len + entry_overhead;
    if (wanted > self.capacity) {
        self.evictTo(gpa, 0);
        return;
    }
    self.evictTo(gpa, self.capacity - wanted);

    const name_copy = try gpa.dupe(u8, name);
    errdefer gpa.free(name_copy);
    const value_copy = try gpa.dupe(u8, value);
    errdefer gpa.free(value_copy);

    self.compact();
    try self.entries.append(gpa, .{ .name = name_copy, .value = value_copy });
    self.size += wanted;
}

/// Drops the oldest entries until the table is `target` bytes or less.
fn evictTo(self: *DynamicTable, gpa: Allocator, target: usize) void {
    while (self.size > target) {
        // `size` counts only the live entries, so an empty table is a size
        // of zero and this loop has already stopped.
        const evicted = self.entries.items[self.first];
        self.first += 1;
        self.size -= evicted.size();
        gpa.free(evicted.name);
        gpa.free(evicted.value);
    }

    // An empty table starts over at the front, so a table that empties
    // often never grows a dead prefix at all.
    if (self.first == self.entries.items.len) {
        self.entries.clearRetainingCapacity();
        self.first = 0;
    }
}

/// Moves the live entries to the front of the list, when the evicted
/// prefix has grown as long as the live run.
///
/// The move copies one `Entry` for each live entry. It cannot run again
/// until that many more entries have been evicted, so the cost of one
/// `add` stays constant on average. The list therefore never holds more
/// than twice the live entries, which is at most
/// `2 * capacity_max / entry_overhead`.
fn compact(self: *DynamicTable) void {
    if (self.first == 0) return;
    const live = self.entries.items.len - self.first;
    if (self.first < live) return;

    std.mem.copyForwards(
        Entry,
        self.entries.items[0..live],
        self.entries.items[self.first..],
    );
    self.entries.shrinkRetainingCapacity(live);
    self.first = 0;
}

const testing = std.testing;

test "a new table is empty and starts at the capacity it was given" {
    var table: DynamicTable = .init(.{ .capacity_max = 256 });
    defer table.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 0), table.size);
    try testing.expectEqual(@as(u32, 0), table.count());
    try testing.expectEqual(@as(usize, 256), table.capacity);
    try testing.expectEqual(@as(?Entry, null), table.get(1));
}

test "the default capacity is the one HTTP/2 assumes" {
    var table: DynamicTable = .init(.{});
    defer table.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 4096), table.capacity);
}

test "an entry costs its name, its value, and the 32 bytes the RFC adds" {
    const gpa = testing.allocator;
    var table: DynamicTable = .init(.{});
    defer table.deinit(gpa);

    try table.add(gpa, "custom-key", "custom-header");
    try testing.expectEqual(@as(usize, 55), table.size);
    try testing.expectEqual(@as(u32, 1), table.count());
    try testing.expectEqualStrings("custom-key", table.get(1).?.name);
    try testing.expectEqualStrings("custom-header", table.get(1).?.value);
}

test "the newest entry is index 1 and the oldest is the last index" {
    const gpa = testing.allocator;
    var table: DynamicTable = .init(.{});
    defer table.deinit(gpa);

    try table.add(gpa, "first", "1");
    try table.add(gpa, "second", "2");
    try table.add(gpa, "third", "3");

    try testing.expectEqualStrings("third", table.get(1).?.name);
    try testing.expectEqualStrings("second", table.get(2).?.name);
    try testing.expectEqualStrings("first", table.get(3).?.name);
    try testing.expectEqual(@as(?Entry, null), table.get(0));
    try testing.expectEqual(@as(?Entry, null), table.get(4));
}

test "the table owns its copies, so the caller may free what it passed" {
    const gpa = testing.allocator;
    var table: DynamicTable = .init(.{});
    defer table.deinit(gpa);

    const name = try gpa.dupe(u8, "borrowed");
    const value = try gpa.dupe(u8, "value");
    try table.add(gpa, name, value);
    gpa.free(name);
    gpa.free(value);

    try testing.expectEqualStrings("borrowed", table.get(1).?.name);
    try testing.expectEqualStrings("value", table.get(1).?.value);
}

test "adding past the capacity evicts the oldest entries first" {
    const gpa = testing.allocator;
    // Room for two entries of 33 bytes and no more.
    var table: DynamicTable = .init(.{ .capacity_max = 70 });
    defer table.deinit(gpa);

    try table.add(gpa, "a", "");
    try table.add(gpa, "b", "");
    try testing.expectEqual(@as(u32, 2), table.count());
    try testing.expectEqual(@as(usize, 66), table.size);

    try table.add(gpa, "c", "");
    try testing.expectEqual(@as(u32, 2), table.count());
    try testing.expectEqualStrings("c", table.get(1).?.name);
    try testing.expectEqualStrings("b", table.get(2).?.name);
}

test "an entry larger than the whole capacity empties the table and is not added" {
    const gpa = testing.allocator;
    var table: DynamicTable = .init(.{ .capacity_max = 64 });
    defer table.deinit(gpa);

    try table.add(gpa, "kept", "");
    try testing.expectEqual(@as(u32, 1), table.count());

    // RFC 7541 section 4.4. This is not a fault.
    try table.add(gpa, "far-too-long-a-name-for-this-table", "and-a-value");
    try testing.expectEqual(@as(u32, 0), table.count());
    try testing.expectEqual(@as(usize, 0), table.size);
}

test "a smaller capacity evicts on the spot" {
    const gpa = testing.allocator;
    var table: DynamicTable = .init(.{ .capacity_max = 256 });
    defer table.deinit(gpa);

    try table.add(gpa, "a", "");
    try table.add(gpa, "b", "");
    try table.add(gpa, "c", "");
    try testing.expectEqual(@as(usize, 99), table.size);

    try table.setCapacity(gpa, 40);
    try testing.expectEqual(@as(u32, 1), table.count());
    try testing.expectEqualStrings("c", table.get(1).?.name);
    try testing.expectEqual(@as(usize, 33), table.size);

    try table.setCapacity(gpa, 0);
    try testing.expectEqual(@as(u32, 0), table.count());
    try testing.expectEqual(@as(usize, 0), table.size);
}

test "a capacity above the agreed ceiling is a fault, not a larger table" {
    const gpa = testing.allocator;
    var table: DynamicTable = .init(.{ .capacity_max = 256 });
    defer table.deinit(gpa);

    try testing.expectError(error.TableSizeTooLarge, table.setCapacity(gpa, 257));
    try testing.expectError(error.TableSizeTooLarge, table.setCapacity(gpa, std.math.maxInt(u32)));
    try testing.expectEqual(@as(usize, 256), table.capacity);

    try table.setCapacity(gpa, 256);
    try testing.expectEqual(@as(usize, 256), table.capacity);
}

test "a table of zero capacity keeps nothing and faults on nothing" {
    const gpa = testing.allocator;
    var table: DynamicTable = .init(.{ .capacity_max = 0 });
    defer table.deinit(gpa);

    try table.add(gpa, "a", "b");
    try testing.expectEqual(@as(u32, 0), table.count());
    try testing.expectEqual(@as(usize, 0), table.size);
}

test "a full table under churn keeps its order and bounds its storage" {
    // The cost of one add. Each add here evicts one entry, which is the
    // shape a peer drives with a long header block against a full table.
    // The storage may never grow past twice the live entries, however many
    // adds run, and the order the RFC gives must hold at every step.
    const gpa = testing.allocator;
    // Four entries of a two-byte name and a one-byte value, and no room
    // for a fifth.
    var table: DynamicTable = .init(.{ .capacity_max = 4 * (entry_overhead + 3) });
    defer table.deinit(gpa);

    var name_buffer: [8]u8 = undefined;
    var i: usize = 0;
    while (i < 400) : (i += 1) {
        const name = try std.fmt.bufPrint(&name_buffer, "{d:0>2}", .{i % 100});
        try table.add(gpa, name, "v");

        // Index 1 is the entry that just arrived, and the last index is
        // the oldest one the table still holds.
        try testing.expectEqualStrings(name, table.get(1).?.name);
        try testing.expect(table.get(table.count()) != null);
        try testing.expectEqual(@as(?Entry, null), table.get(table.count() + 1));

        // The evicted prefix is never longer than the live run, so the
        // list holds at most twice what the table does.
        try testing.expect(table.entries.items.len <= 2 * @as(usize, table.count()));
    }

    try testing.expectEqual(@as(u32, 4), table.count());
}
