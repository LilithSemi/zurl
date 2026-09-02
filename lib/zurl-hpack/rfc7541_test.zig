//! RFC 7541 Appendix C, worked example by worked example.
//!
//! The RFC gives the octets of every example, the header list each one
//! decodes to, and the state of the dynamic table after each step. This
//! file checks all three, byte for byte and entry for entry, for C.2
//! through C.6. It holds no implementation of its own.
//!
//! The examples in C.3 through C.6 are consecutive blocks on one
//! connection, so each group runs on one decoder in order. A block decoded
//! on its own decodes to something else, which is the point of the dynamic
//! table and the reason the table state is checked at every step.
//!
//! **Every octet here is the RFC's own.** The hex dumps are copied from
//! the appendix and read by `hex` at compile time, so what these tests
//! compare against is what the document says and not what this package
//! produces.
//!
//! This file also holds the round trip property: what `encoder` writes,
//! `Decoder` reads back as the same header list.

const std = @import("std");

const Decoder = @import("Decoder.zig");
const encoder = @import("encoder.zig");
const field = @import("field.zig");
const string = @import("string.zig");

const Allocator = std.mem.Allocator;
const testing = std.testing;

/// Reads a hex dump copied out of the appendix. Spaces and newlines are
/// the RFC's own layout and carry nothing.
///
/// Every use of this is a container level `const`, which Zig evaluates at
/// compile time. A hex dump that is not one is a build failure and not a
/// test failure.
fn hex(comptime text: []const u8) []const u8 {
    var octets: [text.len / 2]u8 = undefined;
    var len: usize = 0;
    var high: ?u8 = null;
    for (text) |character| {
        const digit: u8 = switch (character) {
            '0'...'9' => character - '0',
            'a'...'f' => character - 'a' + 10,
            ' ', '\n' => continue,
            else => @compileError("a hex dump holds only hex digits and layout"),
        };
        if (high) |top| {
            octets[len] = top * 16 + digit;
            len += 1;
            high = null;
        } else {
            high = digit;
        }
    }
    if (high != null) @compileError("a hex dump holds an even number of digits");
    const final = octets[0..len].*;
    return &final;
}

/// One row of a "Dynamic Table (after decoding)" listing.
const Row = struct {
    /// The `(s = n)` column, which is `Field.size`.
    size: usize,
    name: []const u8,
    value: []const u8,
};

/// Decodes one block and checks the header list and the dynamic table
/// against what the RFC says they are after that step.
fn expectStep(
    gpa: Allocator,
    decoder: *Decoder,
    block: []const u8,
    want_fields: []const field.Field,
    want_table: []const Row,
    want_table_size: usize,
) !void {
    var list = try decoder.decode(gpa, block);
    defer list.deinit(gpa);

    try testing.expectEqual(want_fields.len, list.fields.items.len);
    for (want_fields, list.fields.items) |want, got| {
        try testing.expectEqualStrings(want.name, got.name);
        try testing.expectEqualStrings(want.value, got.value);
        try testing.expectEqual(want.never_indexed, got.never_indexed);
    }

    try testing.expectEqual(@as(u32, @intCast(want_table.len)), decoder.table.count());
    for (want_table, 1..) |want, index| {
        const got = decoder.table.get(@intCast(index)).?;
        try testing.expectEqualStrings(want.name, got.name);
        try testing.expectEqualStrings(want.value, got.value);
        try testing.expectEqual(want.size, got.size());
    }
    try testing.expectEqual(want_table_size, decoder.table.size);
}

// C.2, the four header field representations, each on its own.

const c2_1 = hex(
    \\400a 6375 7374 6f6d 2d6b 6579 0d63 7573
    \\746f 6d2d 6865 6164 6572
);
const c2_2 = hex("040c 2f73 616d 706c 652f 7061 7468");
const c2_3 = hex(
    \\1008 7061 7373 776f 7264 0673 6563 7265
    \\74
);
const c2_4 = hex("82");

test "RFC 7541 C.2.1, literal header field with incremental indexing" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{});
    defer decoder.deinit(gpa);

    try expectStep(
        gpa,
        &decoder,
        c2_1,
        &.{.{ .name = "custom-key", .value = "custom-header" }},
        &.{.{ .size = 55, .name = "custom-key", .value = "custom-header" }},
        55,
    );
}

test "RFC 7541 C.2.2, literal header field without indexing" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{});
    defer decoder.deinit(gpa);

    try expectStep(gpa, &decoder, c2_2, &.{.{ .name = ":path", .value = "/sample/path" }}, &.{}, 0);
}

test "RFC 7541 C.2.3, literal header field never indexed" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{});
    defer decoder.deinit(gpa);

    try expectStep(
        gpa,
        &decoder,
        c2_3,
        &.{.{ .name = "password", .value = "secret", .never_indexed = true }},
        &.{},
        0,
    );
}

test "RFC 7541 C.2.4, indexed header field" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{});
    defer decoder.deinit(gpa);

    try expectStep(gpa, &decoder, c2_4, &.{.{ .name = ":method", .value = "GET" }}, &.{}, 0);
}

// C.3 and C.4, the same three requests without and with Huffman coding.

const c3_1 = hex(
    \\8286 8441 0f77 7777 2e65 7861 6d70 6c65
    \\2e63 6f6d
);
const c3_2 = hex("8286 84be 5808 6e6f 2d63 6163 6865");
const c3_3 = hex(
    \\8287 85bf 400a 6375 7374 6f6d 2d6b 6579
    \\0c63 7573 746f 6d2d 7661 6c75 65
);

const c4_1 = hex(
    \\8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4
    \\ff
);
const c4_2 = hex("8286 84be 5886 a8eb 1064 9cbf");
const c4_3 = hex(
    \\8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925
    \\a849 e95b b8e8 b4bf
);

const request_1 = [_]field.Field{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":authority", .value = "www.example.com" },
};
const request_2 = request_1 ++ [_]field.Field{
    .{ .name = "cache-control", .value = "no-cache" },
};
const request_3 = [_]field.Field{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":authority", .value = "www.example.com" },
    .{ .name = "custom-key", .value = "custom-value" },
};

const request_table_1 = [_]Row{
    .{ .size = 57, .name = ":authority", .value = "www.example.com" },
};
const request_table_2 = [_]Row{
    .{ .size = 53, .name = "cache-control", .value = "no-cache" },
    .{ .size = 57, .name = ":authority", .value = "www.example.com" },
};
const request_table_3 = [_]Row{
    .{ .size = 54, .name = "custom-key", .value = "custom-value" },
    .{ .size = 53, .name = "cache-control", .value = "no-cache" },
    .{ .size = 57, .name = ":authority", .value = "www.example.com" },
};

test "RFC 7541 C.3, three requests without Huffman coding on one connection" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{});
    defer decoder.deinit(gpa);

    try expectStep(gpa, &decoder, c3_1, &request_1, &request_table_1, 57);
    // 0xbe in the second block is the authority, out of the table.
    try expectStep(gpa, &decoder, c3_2, &request_2, &request_table_2, 110);
    try expectStep(gpa, &decoder, c3_3, &request_3, &request_table_3, 164);
}

test "RFC 7541 C.4, the same three requests with Huffman coding" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{});
    defer decoder.deinit(gpa);

    try expectStep(gpa, &decoder, c4_1, &request_1, &request_table_1, 57);
    try expectStep(gpa, &decoder, c4_2, &request_2, &request_table_2, 110);
    try expectStep(gpa, &decoder, c4_3, &request_3, &request_table_3, 164);
}

test "the Huffman requests of C.4 decode to the same lists as the raw ones of C.3" {
    // The RFC says the two sections are the same examples. This pins that,
    // so a fault in the Huffman path cannot look like a different request.
    const gpa = testing.allocator;
    var raw: Decoder = .init(.{});
    defer raw.deinit(gpa);
    var coded: Decoder = .init(.{});
    defer coded.deinit(gpa);

    for ([_][]const u8{ c3_1, c3_2, c3_3 }, [_][]const u8{ c4_1, c4_2, c4_3 }) |a, b| {
        var from_raw = try raw.decode(gpa, a);
        defer from_raw.deinit(gpa);
        var from_coded = try coded.decode(gpa, b);
        defer from_coded.deinit(gpa);

        try testing.expectEqual(from_raw.size, from_coded.size);
        try testing.expectEqual(from_raw.fields.items.len, from_coded.fields.items.len);
        for (from_raw.fields.items, from_coded.fields.items) |one, other| {
            try testing.expectEqualStrings(one.name, other.name);
            try testing.expectEqualStrings(one.value, other.value);
        }
        try testing.expectEqual(raw.table.size, coded.table.size);
    }
}

// C.5 and C.6, the same three responses without and with Huffman coding.
// The RFC sets SETTINGS_HEADER_TABLE_SIZE to 256 for both, which is what
// makes these examples evict.

const c5_1 = hex(
    \\4803 3330 3258 0770 7269 7661 7465 611d
    \\4d6f 6e2c 2032 3120 4f63 7420 3230 3133
    \\2032 303a 3133 3a32 3120 474d 546e 1768
    \\7474 7073 3a2f 2f77 7777 2e65 7861 6d70
    \\6c65 2e63 6f6d
);
const c5_2 = hex("4803 3330 37c1 c0bf");
const c5_3 = hex(
    \\88c1 611d 4d6f 6e2c 2032 3120 4f63 7420
    \\3230 3133 2032 303a 3133 3a32 3220 474d
    \\54c0 5a04 677a 6970 7738 666f 6f3d 4153
    \\444a 4b48 514b 425a 584f 5157 454f 5049
    \\5541 5851 5745 4f49 553b 206d 6178 2d61
    \\6765 3d33 3630 303b 2076 6572 7369 6f6e
    \\3d31
);

const c6_1 = hex(
    \\4882 6402 5885 aec3 771a 4b61 96d0 7abe
    \\9410 54d4 44a8 2005 9504 0b81 66e0 82a6
    \\2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8
    \\e9ae 82ae 43d3
);
const c6_2 = hex("4883 640e ffc1 c0bf");
const c6_3 = hex(
    \\88c1 6196 d07a be94 1054 d444 a820 0595
    \\040b 8166 e084 a62d 1bff c05a 839b d9ab
    \\77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b
    \\3960 d5af 2708 7f36 72c1 ab27 0fb5 291f
    \\9587 3160 65c0 03ed 4ee5 b106 3d50 07
);

const set_cookie_value = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1";

const response_1 = [_]field.Field{
    .{ .name = ":status", .value = "302" },
    .{ .name = "cache-control", .value = "private" },
    .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
    .{ .name = "location", .value = "https://www.example.com" },
};
const response_2 = [_]field.Field{
    .{ .name = ":status", .value = "307" },
    .{ .name = "cache-control", .value = "private" },
    .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
    .{ .name = "location", .value = "https://www.example.com" },
};
const response_3 = [_]field.Field{
    .{ .name = ":status", .value = "200" },
    .{ .name = "cache-control", .value = "private" },
    .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" },
    .{ .name = "location", .value = "https://www.example.com" },
    .{ .name = "content-encoding", .value = "gzip" },
    .{ .name = "set-cookie", .value = set_cookie_value },
};

/// The RFC says the eviction is the same with and without Huffman coding,
/// because the table counts the decoded length and not the coded one.
const response_table_1 = [_]Row{
    .{ .size = 63, .name = "location", .value = "https://www.example.com" },
    .{ .size = 65, .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
    .{ .size = 52, .name = "cache-control", .value = "private" },
    .{ .size = 42, .name = ":status", .value = "302" },
};
const response_table_2 = [_]Row{
    .{ .size = 42, .name = ":status", .value = "307" },
    .{ .size = 63, .name = "location", .value = "https://www.example.com" },
    .{ .size = 65, .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
    .{ .size = 52, .name = "cache-control", .value = "private" },
};
const response_table_3 = [_]Row{
    .{ .size = 98, .name = "set-cookie", .value = set_cookie_value },
    .{ .size = 52, .name = "content-encoding", .value = "gzip" },
    .{ .size = 65, .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" },
};

const response_options: Decoder.Options = .{ .table_capacity_max = 256 };

test "RFC 7541 C.5, three responses without Huffman coding, with eviction" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(response_options);
    defer decoder.deinit(gpa);

    try expectStep(gpa, &decoder, c5_1, &response_1, &response_table_1, 222);
    // ":status: 302" is evicted to make room for ":status: 307".
    try expectStep(gpa, &decoder, c5_2, &response_2, &response_table_2, 222);
    // Several entries are evicted while the third block is read.
    try expectStep(gpa, &decoder, c5_3, &response_3, &response_table_3, 215);
}

test "RFC 7541 C.6, the same three responses with Huffman coding" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(response_options);
    defer decoder.deinit(gpa);

    try expectStep(gpa, &decoder, c6_1, &response_1, &response_table_1, 222);
    try expectStep(gpa, &decoder, c6_2, &response_2, &response_table_2, 222);
    try expectStep(gpa, &decoder, c6_3, &response_3, &response_table_3, 215);
}

test "a block decoded on a fresh decoder is not the block that follows one" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(.{});
    defer decoder.deinit(gpa);

    // C.3.2 needs the table C.3.1 built. On its own its 0xbe names an
    // index the table does not hold.
    try testing.expectError(error.InvalidIndex, decoder.decode(gpa, c3_2));
}

/// Encodes `fields`, decodes what came out, and checks the two lists
/// match.
fn expectRoundTrip(gpa: Allocator, fields: []const field.Field, options: encoder.Options) !void {
    const block = try encoder.encodeAlloc(gpa, fields, options);
    defer gpa.free(block);

    var decoder: Decoder = .init(.{});
    defer decoder.deinit(gpa);

    var list = try decoder.decode(gpa, block);
    defer list.deinit(gpa);

    try testing.expectEqual(fields.len, list.fields.items.len);
    for (fields, list.fields.items) |want, got| {
        try testing.expectEqualStrings(want.name, got.name);
        try testing.expectEqualStrings(want.value, got.value);
        try testing.expectEqual(want.never_indexed, got.never_indexed);
    }
}

test "what the encoder writes, the decoder reads back as the same header list" {
    const gpa = testing.allocator;
    const sets = [_][]const field.Field{
        &.{},
        &request_1,
        &request_2,
        &request_3,
        &response_1,
        &response_2,
        &response_3,
        &.{.{ .name = "custom-key", .value = "custom-value" }},
        &.{.{ .name = "authorization", .value = "Bearer abc", .never_indexed = true }},
        &.{.{ .name = "empty-value", .value = "" }},
        &.{ .{ .name = "a", .value = "1" }, .{ .name = "a", .value = "2" } },
    };
    const codings = [_]string.Coding{ .raw, .huffman_when_shorter };
    const updates = [_]?u32{ null, 0, 4096 };

    for (sets) |fields| {
        for (codings) |coding| {
            for (updates) |update| {
                try expectRoundTrip(gpa, fields, .{ .coding = coding, .table_size_update = update });
            }
        }
    }
}

test "a header set of every octet value round-trips whole" {
    const gpa = testing.allocator;
    var value: [256]u8 = undefined;
    for (&value, 0..) |*slot, index| slot.* = @intCast(index);

    const fields = [_]field.Field{.{ .name = "binary", .value = &value }};
    try expectRoundTrip(gpa, &fields, .{ .coding = .raw });
    try expectRoundTrip(gpa, &fields, .{ .coding = .huffman_when_shorter });
}

test "a header set as long as the field count bound round-trips whole" {
    const gpa = testing.allocator;
    var fields: [Decoder.field_count_max]field.Field = undefined;
    for (&fields) |*slot| slot.* = .{ .name = "x-repeat", .value = "value" };

    try expectRoundTrip(gpa, &fields, .{});
}
