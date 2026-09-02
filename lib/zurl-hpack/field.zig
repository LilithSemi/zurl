//! The header field a decode gives back and an encode takes in, and the
//! size rule that both the dynamic table and the decoded list count with.
//!
//! This file holds the shape and the arithmetic. It owns no table, it
//! parses nothing, and it opens no socket. `DynamicTable.zig` uses
//! `entry_overhead` for its own accounting, and `Decoder.zig` uses it for
//! the bound on a decoded header list, so the rule is written once.

const std = @import("std");

const Allocator = std.mem.Allocator;

/// The bytes RFC 7541 section 4.1 adds to a name and a value to get the
/// size of one entry.
///
/// The number is an estimate of the per-entry cost of a real
/// implementation, and the RFC fixes it at 32 so that two peers agree on
/// how full a table is without either one describing its own memory
/// layout. It is not the size of anything in this package.
pub const entry_overhead: usize = 32;

/// One header field.
///
/// `name` and `value` are borrowed by every function in this package that
/// takes a `Field`. A `List` is the one place that owns them.
pub const Field = struct {
    name: []const u8,
    value: []const u8,

    /// On a decode, true when the peer sent this field as "literal header
    /// field never indexed", RFC 7541 section 6.2.3. On an encode, a
    /// request to send it that way.
    ///
    /// The representation is how a peer says "do not put this in a table,
    /// and do not let an intermediary put it in one either". A password or
    /// a bearer token comes back with this set, and a caller that
    /// re-encodes the field must keep it set.
    never_indexed: bool = false,

    /// The size of this field under RFC 7541 section 4.1.
    pub fn size(self: Field) usize {
        return self.name.len + self.value.len + entry_overhead;
    }
};

/// A decoded header list, and the memory under it.
///
/// Every `name` and every `value` in `fields` is owned by this list and is
/// freed by `deinit`. A field borrowed out of a `List` stays valid until
/// `deinit` runs, and no decode of a later block moves it. That is on
/// purpose: a dynamic table entry can be evicted by the very block that
/// followed it, so a decoded list that pointed into the table would go
/// stale without any call saying so.
pub const List = struct {
    fields: std.ArrayList(Field) = .empty,

    /// The sum of `Field.size` over `fields`.
    ///
    /// `Decoder` bounds this while it decodes, so a caller can read it to
    /// learn how much of its budget one block used.
    size: usize = 0,

    pub const empty: List = .{};

    pub fn deinit(self: *List, gpa: Allocator) void {
        for (self.fields.items) |field| {
            gpa.free(field.name);
            gpa.free(field.value);
        }
        self.fields.deinit(gpa);
        self.* = undefined;
    }

    /// Takes ownership of `name` and `value`, which must both come from
    /// `gpa`. On any error the two are still the caller's to free.
    pub fn append(
        self: *List,
        gpa: Allocator,
        name: []u8,
        value: []u8,
        never_indexed: bool,
    ) Allocator.Error!void {
        const field: Field = .{ .name = name, .value = value, .never_indexed = never_indexed };
        try self.fields.append(gpa, field);
        self.size += field.size();
    }

    /// The value of the first field named `name`, or null.
    ///
    /// The comparison is byte for byte. HTTP/2 field names are lowercase
    /// on the wire, so a caller that lowercases its own argument gets the
    /// match it expects.
    pub fn get(self: List, name: []const u8) ?[]const u8 {
        for (self.fields.items) |field| {
            if (std.mem.eql(u8, field.name, name)) return field.value;
        }
        return null;
    }
};

test "a field size counts the name, the value, and the 32 bytes the RFC adds" {
    const field: Field = .{ .name = "custom-key", .value = "custom-header" };
    try std.testing.expectEqual(@as(usize, 55), field.size());
}

test "an empty name and an empty value still cost the overhead" {
    const field: Field = .{ .name = "", .value = "" };
    try std.testing.expectEqual(@as(usize, 32), field.size());
}

test "a list owns what it appends and frees all of it" {
    const gpa = std.testing.allocator;
    var list: List = .empty;
    defer list.deinit(gpa);

    try list.append(gpa, try gpa.dupe(u8, ":method"), try gpa.dupe(u8, "GET"), false);
    try list.append(gpa, try gpa.dupe(u8, "accept"), try gpa.dupe(u8, "*/*"), true);

    try std.testing.expectEqual(@as(usize, 2), list.fields.items.len);
    try std.testing.expectEqualStrings("GET", list.get(":method").?);
    try std.testing.expect(list.fields.items[1].never_indexed);
    try std.testing.expectEqual(@as(?[]const u8, null), list.get("host"));
    try std.testing.expectEqual(@as(usize, 7 + 3 + 32 + 6 + 3 + 32), list.size);
}
