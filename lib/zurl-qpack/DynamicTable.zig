//! The QPACK dynamic table, RFC 9204 section 3.2.
//!
//! A first in, first out list of field lines that a peer builds on its
//! encoder stream, and that this side rebuilds as it reads that stream.
//! This file owns the list, the copies of the names and values in it, the
//! size accounting of section 3.2.1, the eviction of section 3.2.2, and
//! the three index forms of sections 3.2.4 through 3.2.6. It owns nothing
//! above that: it parses no instruction and it decodes no field section.
//!
//! **The index that never moves is the absolute one.** RFC 9204 section
//! 3.2.4 gives the first entry ever inserted absolute index 0, and every
//! later insert the next number up. `inserted` is how many inserts have
//! happened, so it is also the absolute index the next one will take, and
//! `dropped` is how many the front has lost. An entry is live when its
//! absolute index is at least `dropped` and below `inserted`. Every
//! relative and post-base form in the RFC turns into an absolute index
//! here, and only then is the table asked for an entry.
//!
//! **Every entry here came from a peer.** So the table has a ceiling the
//! peer cannot raise. `capacity` is what the peer asked for, and
//! `capacity_max` is what this side agreed to in its own SETTINGS. A
//! capacity above `capacity_max` is a fault, not a larger table, and so is
//! an entry larger than the capacity: RFC 9204 section 3.2.2 calls the
//! second one a QPACK_ENCODER_STREAM_ERROR, where HPACK instead lets an
//! oversized entry empty the table.
//!
//! **The table starts empty and at a capacity of zero.** RFC 9204 section
//! 3.2.2 says so. The peer must send Set Dynamic Table Capacity before it
//! can insert anything, where HTTP/2 starts a table at 4096.
//!
//! The storage runs oldest first, at `entries.items[first..]`, so an
//! insert is an append and an eviction moves `first` forward. Both cost
//! the same whatever the table holds. `compact` is what keeps the append
//! constant on average: it moves the live entries down only after the
//! evicted prefix has grown as long as the live run, so its cost is spread
//! over that many inserts. The list never holds more than twice the live
//! entries.

const std = @import("std");

const field = @import("field.zig");

const Allocator = std.mem.Allocator;
const DynamicTable = @This();

/// The bytes RFC 9204 section 3.2.1 adds to a name and a value to size one
/// entry.
pub const entry_overhead = field.entry_overhead;

/// The type of `capacity_max`, and the ceiling itself.
///
/// The ceiling is the type on purpose. `capacity_max` is a build's own
/// choice and never a peer's, so a check on it is a build fault and not a
/// wire fault, and a `std.debug.assert` on a `usize` field is stripped
/// from the shipping build. `encoder_stream.Limits.forCapacity` then
/// multiplies the value by four, so a wrong build wrapped `usize` and gave
/// every encoder instruction a bound of almost nothing. A value past this
/// type is a compile error at the call site, and no build can carry one.
pub const CapacityMax = u16;

/// The largest `capacity_max` this build will take, one octet short of 64
/// KiB.
///
/// A caller sets its own ceiling in `Options`, and this bounds that
/// choice, so no caller can ask for a table larger than this however it
/// was configured. At the smallest entry of 32 bytes this is 2047 entries.
pub const capacity_max_limit: usize = std.math.maxInt(CapacityMax);

pub const Error = error{
    /// A Set Dynamic Table Capacity named a size above `capacity_max`. RFC
    /// 9204 section 4.3.1 says that is a QPACK_ENCODER_STREAM_ERROR.
    TableCapacityTooLarge,
    /// An insert named an entry larger than the whole capacity. RFC 9204
    /// section 3.2.2 says that is a QPACK_ENCODER_STREAM_ERROR.
    EntryTooLarge,
    /// The table has held as many inserts as this build counts.
    TableInsertCountOverflow,
    OutOfMemory,
};

/// One entry, with its own copies of the name and the value.
pub const Entry = struct {
    name: []u8,
    value: []u8,

    /// The size of this entry under RFC 9204 section 3.2.1.
    pub fn size(self: Entry) usize {
        return self.name.len + self.value.len + entry_overhead;
    }
};

pub const Options = struct {
    /// The largest capacity this side will let the peer set, which is what
    /// this side sent as SETTINGS_QPACK_MAX_TABLE_CAPACITY.
    capacity_max: CapacityMax = 0,
};

/// The live entries, oldest first, at `entries.items[first..]`. Everything
/// before `first` was evicted and freed.
entries: std.ArrayList(Entry) = .empty,
/// Where the live entries start. See `compact` for what keeps this from
/// growing without end.
first: usize = 0,
/// How many inserts have happened, which is the absolute index the next
/// insert takes. RFC 9204 calls this the insert count.
inserted: u64 = 0,
/// How many entries have been evicted, which is the absolute index of the
/// oldest entry the table still holds.
dropped: u64 = 0,
size: usize = 0,
capacity: usize = 0,
capacity_max: CapacityMax,

/// A table that starts empty and at a capacity of zero, RFC 9204 section
/// 3.2.2.
///
/// There is no ceiling check here. `CapacityMax` is the ceiling, so a
/// value past it never reaches this function.
pub fn init(options: Options) DynamicTable {
    return .{ .capacity_max = options.capacity_max };
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
pub fn count(self: DynamicTable) u64 {
    return self.inserted - self.dropped;
}

/// MaxEntries of RFC 9204 section 4.5.1.1: how many entries a table of
/// `capacity_max` could hold if every one were the smallest an entry can
/// be.
///
/// The field section prefix folds the required insert count modulo twice
/// this, so both sides must work it out the same way. It comes from
/// `capacity_max` and not from `capacity`, because it is the decoder's
/// SETTINGS value that the encoder knows.
pub fn maxEntries(self: DynamicTable) u64 {
    return @as(u64, self.capacity_max) / entry_overhead;
}

/// The entry at absolute index `index`, or null when that entry is gone or
/// was never inserted.
pub fn get(self: DynamicTable, index: u64) ?Entry {
    if (index < self.dropped or index >= self.inserted) return null;
    return self.entries.items[self.first + @as(usize, @intCast(index - self.dropped))];
}

/// The absolute index a relative index names on the encoder stream, RFC
/// 9204 section 3.2.5, or null when it names no live entry.
///
/// A relative index of 0 is the entry inserted last. The answer moves
/// while the encoder stream is read, which is what the RFC says and why a
/// field line representation uses the Base instead.
pub fn absoluteFromEncoderRelative(self: DynamicTable, index: u64) ?u64 {
    if (index >= self.inserted) return null;
    const absolute = self.inserted - index - 1;
    if (absolute < self.dropped) return null;
    return absolute;
}

/// Takes the capacity the peer asked for, RFC 9204 section 4.3.1.
///
/// A capacity below what the table holds evicts until it fits.
pub fn setCapacity(self: *DynamicTable, gpa: Allocator, capacity: u64) Error!void {
    if (capacity > self.capacity_max) return error.TableCapacityTooLarge;
    self.capacity = @intCast(capacity);
    self.evictTo(gpa, self.capacity);
}

/// Copies `name` and `value` into a new entry at the next absolute index,
/// and evicts the oldest entries until the table fits.
///
/// RFC 9204 section 3.2.2: an entry larger than the whole capacity is a
/// fault. That is the opposite of RFC 7541 section 4.4, where the same
/// input empties the table and is not an error.
pub fn insert(self: *DynamicTable, gpa: Allocator, name: []const u8, value: []const u8) Error!void {
    const wanted = name.len + value.len + entry_overhead;
    if (wanted > self.capacity) return error.EntryTooLarge;
    if (self.inserted == std.math.maxInt(u64)) return error.TableInsertCountOverflow;

    // The copies come first. The name or the value may be borrowed from an
    // entry this very insert is about to evict, which RFC 9204 section
    // 3.2.2 warns about by name.
    const name_copy = try gpa.dupe(u8, name);
    errdefer gpa.free(name_copy);
    const value_copy = try gpa.dupe(u8, value);
    errdefer gpa.free(value_copy);

    // Room for one more entry has to exist before the append, because
    // `compact` may move the live run and the append may allocate.
    try self.entries.ensureUnusedCapacity(gpa, 1);

    self.evictTo(gpa, self.capacity - wanted);
    self.compact();
    self.entries.appendAssumeCapacity(.{ .name = name_copy, .value = value_copy });
    self.size += wanted;
    self.inserted += 1;
}

/// Inserts a copy of the live entry at absolute index `index`, RFC 9204
/// section 4.3.4.
///
/// `index` must name a live entry, which the caller reads out of the wire
/// and checks with `get`. A duplicate of an evicted entry is a peer fault
/// and belongs to `encoder_stream.zig`, which has the error name for it.
pub fn duplicate(self: *DynamicTable, gpa: Allocator, index: u64) Error!void {
    const entry = self.get(index).?;
    return self.insert(gpa, entry.name, entry.value);
}

/// Drops the oldest entries until the table is `target` bytes or less.
fn evictTo(self: *DynamicTable, gpa: Allocator, target: usize) void {
    while (self.size > target) {
        // `size` counts only the live entries, so an empty table is a size
        // of zero and this loop has already stopped.
        const evicted = self.entries.items[self.first];
        self.first += 1;
        self.dropped += 1;
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
/// insert stays constant on average. The list therefore never holds more
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

test "the ceiling on capacity_max is the type, so no build can get past it" {
    // `Options.capacity_max` is `CapacityMax`, so
    // `.init(.{ .capacity_max = capacity_max_limit + 1 })` is a compile
    // error and not a `std.debug.assert` a release build strips.
    try testing.expectEqual(@as(usize, std.math.maxInt(CapacityMax)), capacity_max_limit);
    try testing.expectEqual(@as(usize, 65535), capacity_max_limit);

    const gpa = testing.allocator;
    var table: DynamicTable = .init(.{ .capacity_max = capacity_max_limit });
    defer table.deinit(gpa);

    try testing.expectEqual(@as(u64, 2047), table.maxEntries());
    try table.setCapacity(gpa, capacity_max_limit);
    try testing.expectEqual(capacity_max_limit, table.capacity);
    try testing.expectError(
        error.TableCapacityTooLarge,
        table.setCapacity(gpa, capacity_max_limit + 1),
    );
}

test "a new table is empty, at a capacity of zero, and takes no insert" {
    const gpa = testing.allocator;
    var table: DynamicTable = .init(.{ .capacity_max = 4096 });
    defer table.deinit(gpa);

    try testing.expectEqual(@as(usize, 0), table.size);
    try testing.expectEqual(@as(u64, 0), table.count());
    try testing.expectEqual(@as(usize, 0), table.capacity);
    try testing.expectEqual(@as(?Entry, null), table.get(0));

    // RFC 9204 section 3.2.2: the encoder must set a capacity first.
    try testing.expectError(error.EntryTooLarge, table.insert(gpa, "a", "b"));
}

test "the first entry inserted has absolute index 0 and the next one has 1" {
    const gpa = testing.allocator;
    var table: DynamicTable = .init(.{ .capacity_max = 4096 });
    defer table.deinit(gpa);
    try table.setCapacity(gpa, 4096);

    try table.insert(gpa, ":authority", "www.example.com");
    try table.insert(gpa, ":path", "/sample/path");

    try testing.expectEqual(@as(u64, 2), table.inserted);
    try testing.expectEqual(@as(u64, 0), table.dropped);
    try testing.expectEqualStrings(":authority", table.get(0).?.name);
    try testing.expectEqualStrings("www.example.com", table.get(0).?.value);
    try testing.expectEqualStrings(":path", table.get(1).?.name);
    try testing.expectEqual(@as(?Entry, null), table.get(2));
    try testing.expectEqual(@as(usize, 106), table.size);
}

test "a relative index on the encoder stream counts back from the last insert" {
    const gpa = testing.allocator;
    var table: DynamicTable = .init(.{ .capacity_max = 4096 });
    defer table.deinit(gpa);
    try table.setCapacity(gpa, 4096);

    try table.insert(gpa, "first", "1");
    try table.insert(gpa, "second", "2");
    try table.insert(gpa, "third", "3");

    try testing.expectEqual(@as(?u64, 2), table.absoluteFromEncoderRelative(0));
    try testing.expectEqual(@as(?u64, 1), table.absoluteFromEncoderRelative(1));
    try testing.expectEqual(@as(?u64, 0), table.absoluteFromEncoderRelative(2));
    try testing.expectEqual(@as(?u64, null), table.absoluteFromEncoderRelative(3));
    try testing.expectEqual(
        @as(?u64, null),
        table.absoluteFromEncoderRelative(std.math.maxInt(u64)),
    );
}

test "the table owns its copies, so the caller may free what it passed" {
    const gpa = testing.allocator;
    var table: DynamicTable = .init(.{ .capacity_max = 4096 });
    defer table.deinit(gpa);
    try table.setCapacity(gpa, 4096);

    const name = try gpa.dupe(u8, "borrowed");
    const value = try gpa.dupe(u8, "value");
    try table.insert(gpa, name, value);
    gpa.free(name);
    gpa.free(value);

    try testing.expectEqualStrings("borrowed", table.get(0).?.name);
    try testing.expectEqualStrings("value", table.get(0).?.value);
}

test "inserting past the capacity evicts the oldest entries first" {
    const gpa = testing.allocator;
    // Room for two entries of 33 bytes and no more.
    var table: DynamicTable = .init(.{ .capacity_max = 70 });
    defer table.deinit(gpa);
    try table.setCapacity(gpa, 70);

    try table.insert(gpa, "a", "");
    try table.insert(gpa, "b", "");
    try testing.expectEqual(@as(u64, 2), table.count());
    try testing.expectEqual(@as(usize, 66), table.size);

    try table.insert(gpa, "c", "");
    try testing.expectEqual(@as(u64, 2), table.count());
    try testing.expectEqual(@as(u64, 1), table.dropped);
    try testing.expectEqual(@as(?Entry, null), table.get(0));
    try testing.expectEqualStrings("b", table.get(1).?.name);
    try testing.expectEqualStrings("c", table.get(2).?.name);
}

test "an entry larger than the whole capacity is a fault, not an empty table" {
    const gpa = testing.allocator;
    var table: DynamicTable = .init(.{ .capacity_max = 64 });
    defer table.deinit(gpa);
    try table.setCapacity(gpa, 64);

    try table.insert(gpa, "kept", "");
    try testing.expectEqual(@as(u64, 1), table.count());

    // RFC 9204 section 3.2.2. RFC 7541 section 4.4 says the opposite for
    // HPACK, so this is the line a port from HPACK gets wrong.
    try testing.expectError(
        error.EntryTooLarge,
        table.insert(gpa, "far-too-long-a-name-for-this-table", "and-a-value"),
    );
    try testing.expectEqual(@as(u64, 1), table.count());
    try testing.expectEqualStrings("kept", table.get(0).?.name);
}

test "a smaller capacity evicts on the spot and keeps the absolute indices" {
    const gpa = testing.allocator;
    var table: DynamicTable = .init(.{ .capacity_max = 256 });
    defer table.deinit(gpa);
    try table.setCapacity(gpa, 256);

    try table.insert(gpa, "a", "");
    try table.insert(gpa, "b", "");
    try table.insert(gpa, "c", "");
    try testing.expectEqual(@as(usize, 99), table.size);

    try table.setCapacity(gpa, 40);
    try testing.expectEqual(@as(u64, 1), table.count());
    try testing.expectEqualStrings("c", table.get(2).?.name);
    try testing.expectEqual(@as(?Entry, null), table.get(1));
    try testing.expectEqual(@as(usize, 33), table.size);

    // RFC 9204 section 3.2.2: a capacity of zero clears the table, and the
    // capacity can go back up afterwards.
    try table.setCapacity(gpa, 0);
    try testing.expectEqual(@as(u64, 0), table.count());
    try testing.expectEqual(@as(usize, 0), table.size);
    try testing.expectEqual(@as(u64, 3), table.inserted);

    try table.setCapacity(gpa, 256);
    try table.insert(gpa, "d", "");
    try testing.expectEqualStrings("d", table.get(3).?.name);
}

test "a capacity above the agreed ceiling is a fault, not a larger table" {
    const gpa = testing.allocator;
    var table: DynamicTable = .init(.{ .capacity_max = 256 });
    defer table.deinit(gpa);

    try testing.expectError(error.TableCapacityTooLarge, table.setCapacity(gpa, 257));
    try testing.expectError(
        error.TableCapacityTooLarge,
        table.setCapacity(gpa, std.math.maxInt(u64)),
    );
    try testing.expectEqual(@as(usize, 0), table.capacity);

    try table.setCapacity(gpa, 256);
    try testing.expectEqual(@as(usize, 256), table.capacity);
}

test "MaxEntries comes from the agreed ceiling and not from the set capacity" {
    const gpa = testing.allocator;
    var table: DynamicTable = .init(.{ .capacity_max = 220 });
    defer table.deinit(gpa);

    try testing.expectEqual(@as(u64, 6), table.maxEntries());
    try table.setCapacity(gpa, 64);
    try testing.expectEqual(@as(u64, 6), table.maxEntries());

    var none: DynamicTable = .init(.{});
    defer none.deinit(gpa);
    try testing.expectEqual(@as(u64, 0), none.maxEntries());
}

test "a duplicate copies a live entry to the next absolute index" {
    const gpa = testing.allocator;
    var table: DynamicTable = .init(.{ .capacity_max = 4096 });
    defer table.deinit(gpa);
    try table.setCapacity(gpa, 4096);

    try table.insert(gpa, "a", "1");
    try table.insert(gpa, "b", "2");
    try table.duplicate(gpa, 0);

    try testing.expectEqual(@as(u64, 3), table.inserted);
    try testing.expectEqualStrings("a", table.get(2).?.name);
    try testing.expectEqualStrings("1", table.get(2).?.value);

    // RFC 9204 section 3.2: a duplicate entry is not an error.
    try testing.expectEqualStrings("a", table.get(0).?.name);
    try testing.expectEqual(@as(?Entry, null), table.get(7));
}

test "an insert may name the entry it evicts" {
    const gpa = testing.allocator;
    // Room for one entry of 34 bytes and no more.
    var table: DynamicTable = .init(.{ .capacity_max = 34 });
    defer table.deinit(gpa);
    try table.setCapacity(gpa, 34);

    try table.insert(gpa, "a", "1");
    const borrowed = table.get(0).?;

    // RFC 9204 section 3.2.2 warns about exactly this: the name comes from
    // the entry that adding this one evicts.
    try table.insert(gpa, borrowed.name, "2");
    try testing.expectEqual(@as(u64, 1), table.count());
    try testing.expectEqualStrings("a", table.get(1).?.name);
    try testing.expectEqualStrings("2", table.get(1).?.value);
}

test "a duplicate may name the entry it evicts" {
    const gpa = testing.allocator;
    var table: DynamicTable = .init(.{ .capacity_max = 34 });
    defer table.deinit(gpa);
    try table.setCapacity(gpa, 34);

    try table.insert(gpa, "a", "1");
    try table.duplicate(gpa, 0);

    try testing.expectEqual(@as(u64, 1), table.count());
    try testing.expectEqual(@as(u64, 1), table.dropped);
    try testing.expectEqualStrings("a", table.get(1).?.name);
    try testing.expectEqualStrings("1", table.get(1).?.value);
}

test "a full table under churn keeps its indices and bounds its storage" {
    // The cost of one insert. Each insert here evicts one entry, which is
    // the shape a peer drives with a long encoder stream against a full
    // table. The storage may never grow past twice the live entries,
    // however many inserts run, and the absolute index of every live entry
    // must hold at every step.
    const gpa = testing.allocator;
    // Four entries of a two-byte name and a one-byte value, and no room
    // for a fifth.
    var table: DynamicTable = .init(.{ .capacity_max = 4 * (entry_overhead + 3) });
    defer table.deinit(gpa);
    try table.setCapacity(gpa, table.capacity_max);

    var name_buffer: [8]u8 = undefined;
    var i: usize = 0;
    while (i < 400) : (i += 1) {
        const name = try std.fmt.bufPrint(&name_buffer, "{d:0>2}", .{i % 100});
        try table.insert(gpa, name, "v");

        try testing.expectEqual(@as(u64, i + 1), table.inserted);
        try testing.expectEqualStrings(name, table.get(table.inserted - 1).?.name);
        try testing.expectEqual(@as(?Entry, null), table.get(table.inserted));
        try testing.expect(table.get(table.dropped) != null);
        if (table.dropped > 0) {
            try testing.expectEqual(@as(?Entry, null), table.get(table.dropped - 1));
        }

        // The evicted prefix is never longer than the live run, so the
        // list holds at most twice what the table does.
        try testing.expect(table.entries.items.len <= 2 * @as(usize, @intCast(table.count())));
    }

    try testing.expectEqual(@as(u64, 4), table.count());
}
